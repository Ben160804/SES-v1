"""
testbed/runner/runner.py
========================
Automated End-to-End Testbed Scenario Runner (Milestone 3).

Architecture:
-------------
Executes the proven end-to-end scenario pipeline:
    ScenarioSpec (matrix row)
            ↓
    SMTPStager (stage artifacts to testbed/active/)
            ↓
    Postfix Deployment (apply staged main.cf & postfix reload)
            ↓
    Network Packet Capture (tshark on dynamic docker bridge)
            ↓
    SMTPClient (drive deterministic protocol interaction)
            ↓
    PCAP Materialization (testbed/captures/<scenario_id>.pcap)
            ↓
    PCAPAnalyzer (offline forensic analysis of captured packets)
            ↓
    Evidence & Sidecar Generation (testbed/captures/<scenario_id>.json)
"""

from dataclasses import dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import jsonschema

# Ensure project root is accessible
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from analysis.parser import PCAPAnalyzer
from testbed.pki.generator.make_certs import PKIFactory
from testbed.runner.client import ClientResult, SMTPClient, IMAPClient, POP3Client
from testbed.runner.resolver import UnresolvableScenarioError
from testbed.runner.spec import ScenarioSpec, load_matrix
from testbed.runner.stager import SMTPStager, IMAPStager, POP3Stager, StagedScenario


def discover_docker_bridge(network_name: str = "testbed_mailtest_net") -> str:
    """
    Dynamically discover the Linux bridge network interface for the Docker network.
    Avoids hardcoded interface names like 'br-87a3125207be'.
    """
    try:
        proc = subprocess.run(
            ["docker", "network", "inspect", network_name, "-f", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        network_id = proc.stdout.strip()
        if not network_id:
            raise RuntimeError(f"Empty network ID returned for {network_name}")
        
        # Docker names bridge interfaces as 'br-' + first 12 characters of network ID
        bridge_name = f"br-{network_id[:12]}"
        
        # Verify bridge exists in Linux sysfs or via ip link
        if Path(f"/sys/class/net/{bridge_name}").exists():
            return bridge_name
        
        # Fallback verification with ip link
        check_link = subprocess.run(
            ["ip", "link", "show", bridge_name],
            capture_output=True,
            text=True,
        )
        if check_link.returncode == 0:
            return bridge_name
        
        raise RuntimeError(f"Bridge interface '{bridge_name}' discovered for network '{network_name}' does not exist on host")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to inspect Docker network '{network_name}': {exc.stderr.strip()}") from exc


@dataclass
class ScenarioExecutionResult:
    """
    Structured outcome of an automated scenario run from stager through analyzer.
    """
    scenario_id: str
    success: bool
    pcap_path: Path
    sidecar_path: Path
    evidence_path: Optional[Path] = None
    client_result: Optional[ClientResult] = None
    analyzer_results: Dict[int, Any] = field(default_factory=dict)
    sidecar_data: Dict[str, Any] = field(default_factory=dict)
    manifest: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    status: str = "FAILED"


def serialize_evidence(obj: Any) -> Any:
    """
    Recursively transforms PCAPAnalyzer results into a deterministically JSON-serializable
    representation without information loss:
      - dict keys converted to strings (JSON standard requirement for integer stream IDs)
      - bytes converted to standard hexadecimal strings (preserving full binary entropy)
      - datetime / date converted to ISO 8601 UTC strings
      - Enum converted to value (or name if value non-primitive)
      - set / frozenset converted to sorted lists
      - Path converted to str
    """
    if isinstance(obj, dict):
        return {str(k): serialize_evidence(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_evidence(item) for item in obj]
    elif isinstance(obj, (set, frozenset)):
        return sorted([serialize_evidence(item) for item in obj])
    elif isinstance(obj, bytes):
        return obj.hex()
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    elif isinstance(obj, Enum):
        return obj.value if isinstance(obj.value, (str, int, float, bool)) else obj.name
    elif isinstance(obj, Path):
        return str(obj)
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def build_canonical_sidecar(
    spec: ScenarioSpec,
    analyzer_results: Dict[int, Any],
    client_result: Optional[ClientResult],
) -> Dict[str, Any]:
    """
    Construct the canonical ground-truth sidecar dictionary adhering strictly
    to data/sidecar_schema.json using real evidence from analyzer, client, and spec.
    """
    stream0 = analyzer_results.get(0, {})
    stls = stream0.get("starttls") or {}
    tls_info = stream0.get("tls") or {}
    handshake = stream0.get("handshake") or {}
    cert_info = stream0.get("certificate") or {}

    # 1. Protocol
    protocol = stream0.get("protocol") or spec.protocol.upper()

    # 2. TLS presence
    stls_status = stls.get("status")
    if stls_status == "UPGRADED":
        tls_presence = "STARTTLS-upgraded"
    elif stls_status == "IMPLICIT_TLS" or (tls_info and not stls):
        tls_presence = "implicit-TLS"
    elif stls_status == "CLEARTEXT_NO_ENCRYPTION" or not tls_info:
        tls_presence = "none"
    else:
        tls_presence = spec.server.tls_presence

    # 3. STARTTLS integrity
    if tls_presence == "none":
        starttls_integrity = spec.raw_row.get("starttls_integrity") or "N/A"
    elif stls.get("starttls_rejected"):
        starttls_integrity = "rejected"
    elif stls_status == "STARTTLS_WITHOUT_ADVERTISEMENT":
        starttls_integrity = "no-advertisement"
    elif stls_status == "UPGRADED":
        starttls_integrity = "normal"
    else:
        starttls_integrity = spec.raw_row.get("starttls_integrity") or "normal"

    # 4. TLS version
    if tls_info and tls_info.get("tls_version"):
        ver_raw = tls_info["tls_version"].replace("TLS ", "").strip()
        tls_version = ver_raw if ver_raw in ["1.0", "1.1", "1.2", "1.3"] else "N/A"
    else:
        tls_version = "N/A"

    # 5. Cipher strength
    if tls_info and tls_info.get("cipher_strength"):
        cipher_strength = tls_info["cipher_strength"]
    else:
        cipher_strength = "N/A"

    # 6. Certificate validity
    if cert_info and cert_info.get("trust_status"):
        t_st = cert_info["trust_status"]
        if t_st == "EXPIRED":
            cert_validity = "expired"
        elif t_st == "NOT_YET_VALID":
            cert_validity = "not-yet-valid"
        elif t_st == "N/A":
            cert_validity = "N/A"
        else:
            cert_validity = "valid"
    elif tls_presence == "none":
        cert_validity = "N/A"
    elif spec.pki:
        val = spec.pki.validity
        cert_validity = "expired" if val == "expired" else ("not-yet-valid" if val == "not_yet_valid" else "valid")
    else:
        cert_validity = spec.raw_row.get("cert_validity") or "N/A"

    # 7. Certificate chain shape
    if cert_info and cert_info.get("is_self_signed"):
        if cert_info.get("trust_status") == "TRUSTED_SELF_SIGNED":
            cert_chain_shape = "self-signed-trusted"
        elif cert_info.get("trust_status") == "UNTRUSTED_SELF_SIGNED":
            cert_chain_shape = "self-signed-untrusted"
        else:
            cert_chain_shape = spec.raw_row.get("cert_chain_shape") or "complete-chain"
    elif tls_presence == "none":
        cert_chain_shape = "N/A"
    else:
        cert_chain_shape = spec.raw_row.get("cert_chain_shape") or "complete-chain"

    # 8. Certificate signature algorithm
    if cert_info and cert_info.get("leaf_cert"):
        leaf = cert_info["leaf_cert"]
        sig_param = leaf.get("signature_algorithm_parameters")
        sig_name = (leaf.get("signature_algorithm_name") or "").lower()
        if "ed25519" in sig_name:
            cert_sig_algo = "Ed25519"
        elif "ecdsa" in sig_name:
            cert_sig_algo = "ECDSA"
        elif sig_param == "PSS" or "pss" in sig_name:
            cert_sig_algo = "RSA-PSS"
        elif sig_param == "PKCS1v15" or "rsa" in sig_name:
            cert_sig_algo = "RSA-PKCS1v15"
        else:
            cert_sig_algo = spec.raw_row.get("cert_sig_algo") or "N/A"
    elif tls_presence == "none":
        cert_sig_algo = "N/A"
    else:
        cert_sig_algo = spec.raw_row.get("cert_sig_algo") or "N/A"

    # 9. Hostname match
    if cert_info and cert_info.get("hostname_match"):
        hm = str(cert_info["hostname_match"]).lower()
        hostname_match = hm if hm in ["matched", "mismatched"] else "N/A"
    elif tls_presence == "none":
        hostname_match = "N/A"
    else:
        hostname_match = spec.raw_row.get("hostname_match") or "matched"

    # 10. Auth outcome
    if stls.get("plaintext_auth_attempted"):
        auth_outcome = "plaintext-attempted"
    elif client_result and client_result.success and tls_presence != "none" and spec.client.auth_outcome != "none":
        auth_outcome = spec.client.auth_outcome
    else:
        auth_outcome = spec.client.auth_outcome or "none"

    # 11 & 12: Oracles
    expected_starttls_status = spec.oracle.expected_starttls_status
    expected_trust_status = spec.oracle.expected_trust_status

    sidecar = {
        "scenario_id": spec.scenario_id,
        "protocol": protocol,
        "tls_presence": tls_presence,
        "starttls_integrity": starttls_integrity,
        "tls_version": tls_version,
        "cipher_strength": cipher_strength,
        "cert_validity": cert_validity,
        "cert_chain_shape": cert_chain_shape,
        "cert_sig_algo": cert_sig_algo,
        "hostname_match": hostname_match,
        "auth_outcome": auth_outcome,
        "expected_starttls_status": expected_starttls_status,
        "expected_trust_status": expected_trust_status,
    }

    # Optional fields permitted by schema
    if spec.layer:
        sidecar["layer"] = spec.layer
    if spec.description:
        sidecar["description"] = spec.description

    if spec.raw_row.get("strip_cause"):
        sidecar["strip_cause"] = spec.raw_row["strip_cause"]

    port_type = spec.network.port_type or spec.raw_row.get("port_type")
    if port_type:
        sidecar["port_type"] = port_type

    expected_proto = spec.oracle.expected_protocol or spec.raw_row.get("expected_protocol")
    if expected_proto:
        sidecar["expected_protocol"] = expected_proto

    # TLS 1.3 / 1.2 KEX
    if tls_version == "1.3":
        kex_mode = tls_info.get("tls13_key_exchange_mode") or spec.raw_row.get("tls13_kex_mode")
        if kex_mode in ["ECDHE", "PSK_ONLY", "PSK_DHE"]:
            sidecar["tls13_kex_mode"] = kex_mode
    elif tls_version == "1.2":
        kex_type = tls_info.get("key_exchange") or spec.raw_row.get("tls12_kex_type")
        if kex_type in ["ECDHE", "DHE"]:
            sidecar["tls12_kex_type"] = kex_type

    if "forward_secrecy" in tls_info and tls_info["forward_secrecy"] is not None:
        sidecar["forward_secrecy"] = bool(tls_info["forward_secrecy"])
    elif spec.raw_row.get("forward_secrecy"):
        sidecar["forward_secrecy"] = spec.raw_row["forward_secrecy"].lower() in ("true", "1", "yes")

    if "hello_retry_request" in tls_info and tls_info["hello_retry_request"] is not None:
        sidecar["hello_retry_request"] = bool(tls_info["hello_retry_request"])

    if handshake.get("server_negotiation", {}).get("downgrade_sentinel", {}).get("sentinel_detected"):
        downgrade_sig = handshake.get("forensic_analysis", {}).get("version_downgrade", {}).get("downgrade_signal_detected", False)
        sidecar["downgrade_sentinel"] = "protection-signal" if downgrade_sig else "benign"
    elif tls_presence != "none":
        sidecar["downgrade_sentinel"] = "none"

    if stls.get("starttls_accepted"):
        sidecar["starttls_outcome"] = "accepted"
    elif stls.get("starttls_rejected"):
        sidecar["starttls_outcome"] = "rejected"
    elif stls.get("starttls_offered") is False and stls.get("starttls_requested"):
        sidecar["starttls_outcome"] = "no_advertisement"

    if handshake.get("client_hello"):
        ch = handshake["client_hello"]
        sidecar["sig_alg_cert_present"] = bool(ch.get("signature_algorithms_cert_present", False))

    if cert_info and cert_info.get("leaf_cert"):
        leaf = cert_info["leaf_cert"]
        sidecar["cert_has_san"] = bool(leaf.get("san_dns") or leaf.get("san_ip"))
    elif spec.pki:
        sidecar["cert_has_san"] = spec.pki.san_type in ("matched_dns", "mismatched_dns", "wildcard", "ip_san")

    if spec.pki:
        if spec.pki.san_type in ("matched_dns", "mismatched_dns"):
            sidecar["hostname_type"] = "dns"
        elif spec.pki.san_type == "ip_san":
            sidecar["hostname_type"] = "ip"
        elif spec.pki.san_type == "wildcard":
            sidecar["hostname_type"] = "wildcard"

    if tls_presence == "none":
        sidecar["certificate_observable"] = "NOT_PRESENT"
    elif tls_version == "1.3":
        sidecar["certificate_observable"] = "ENCRYPTED"
    elif cert_info and cert_info.get("leaf_cert"):
        sidecar["certificate_observable"] = "VISIBLE"
    else:
        sidecar["certificate_observable"] = "NOT_PRESENT"

    if spec.generator_requirement:
        sidecar["generator_requirement"] = spec.generator_requirement

    return sidecar


class ScenarioRunner:
    """
    Orchestrates the deterministic execution of scenarios against the containerized testbed.
    """

    def __init__(
        self,
        pki_dir: Optional[Path | str] = None,
        active_dir: Optional[Path | str] = None,
        captures_dir: Optional[Path | str] = None,
        network_name: str = "testbed_mailtest_net",
        postfix_container: str = "mailtest-postfix",
        dovecot_container: str = "mailtest-dovecot",
    ):
        self.pki_dir = Path(pki_dir) if pki_dir else (_project_root / "testbed" / "pki")
        self.active_dir = Path(active_dir) if active_dir else (_project_root / "testbed" / "active")
        self.captures_dir = Path(captures_dir) if captures_dir else (_project_root / "testbed" / "captures")
        self.network_name = network_name
        self.postfix_container = postfix_container
        self.dovecot_container = dovecot_container
        self.mitm_container = "mailtest-mitm"

        self.active_dir.mkdir(parents=True, exist_ok=True)
        self.captures_dir.mkdir(parents=True, exist_ok=True)

        self.schema_path = _project_root / "data" / "sidecar_schema.json"
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Sidecar schema not found at {self.schema_path}")
        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.sidecar_schema = json.load(f)

        self.bridge_interface = discover_docker_bridge(self.network_name)
        self.pki_factory = PKIFactory(pki_dir=str(self.pki_dir))
        self.stager = SMTPStager(pki_factory=self.pki_factory)
        self.imap_stager = IMAPStager(pki_factory=self.pki_factory)
        self.pop3_stager = POP3Stager(pki_factory=self.pki_factory)
        self.client = SMTPClient()
        self.imap_client = IMAPClient()
        self.pop3_client = POP3Client()

    def ensure_mitm_container(self) -> str:
        """
        Ensure the mailtest-mitm container is running on the docker network.
        Returns the MITM IP address (defaults to 172.28.0.30).
        """
        mitm_ip = "172.28.0.30"
        try:
            res = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.mitm_container],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip() == "true":
                ip_res = subprocess.run(
                    ["docker", "inspect", self.mitm_container, "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if ip_res.returncode == 0 and ip_res.stdout.strip():
                    return ip_res.stdout.strip()
                return mitm_ip
            # Not running, attempt to start
            start_res = subprocess.run(
                ["docker", "start", self.mitm_container],
                capture_output=True,
                text=True,
                check=False,
            )
            if start_res.returncode == 0:
                time.sleep(0.5)
                return mitm_ip
            # Try docker compose up -d mitm
            compose_file = _project_root / "testbed" / "docker-compose.yml"
            subprocess.check_call(
                ["docker", "compose", "-f", str(compose_file), "up", "-d", "mitm"]
            )
            time.sleep(0.5)
            return mitm_ip
        except Exception as exc:
            print(f"[runner] Warning: Could not verify/start {self.mitm_container}: {exc}")
            return mitm_ip


    def deploy_postfix_configuration(self) -> None:
        """
        Deploy the staged main.cf into the Postfix container and reload the daemon.
        """
        # 1. Copy staged main.cf into Postfix configuration path
        subprocess.check_call(
            ["docker", "exec", self.postfix_container, "cp", "/etc/mailtest/active/main.cf", "/etc/postfix/main.cf"]
        )
        # 2. Instruct Postfix daemon to reload configuration
        subprocess.check_call(
            ["docker", "exec", self.postfix_container, "postfix", "reload"]
        )
        # Allow daemon time to refresh internal listeners/parameters
        time.sleep(0.8)

    def deploy_dovecot_configuration(self) -> None:
        """
        Deploy the staged dovecot.conf into the Dovecot container and reload the daemon.
        """
        # 1. Copy staged dovecot.conf into Dovecot configuration path
        subprocess.check_call(
            ["docker", "exec", self.dovecot_container, "cp", "/etc/mailtest/active/dovecot.conf", "/etc/dovecot/dovecot.conf"]
        )
        # 2. Instruct Dovecot daemon to reload configuration
        subprocess.check_call(
            ["docker", "exec", self.dovecot_container, "dovecot", "reload"]
        )
        time.sleep(0.5)


    def start_capture(self, port: int, pcap_path: Path, readiness_timeout: float = 5.0) -> subprocess.Popen:
        """
        Start tshark and wait until libpcap has activated the capture interface.
        """
        capture_start_ns = time.time_ns()
        cap_proc = subprocess.Popen(
            [
                "tshark",
                "-i", self.bridge_interface,
                "-f", f"tcp port {port}",
                "-w", str(pcap_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stderr_lines: List[str] = []
        deadline = time.monotonic() + readiness_timeout
        capture_announced = False

        while time.monotonic() < deadline:
            if cap_proc.poll() is not None:
                if cap_proc.stderr:
                    remainder = cap_proc.stderr.read()
                    if remainder:
                        stderr_lines.append(remainder)
                stderr_text = "".join(stderr_lines).strip()
                raise RuntimeError(
                    f"tshark exited before capture became ready"
                    + (f": {stderr_text}" if stderr_text else "")
                )

            if cap_proc.stderr:
                ready, _, _ = select.select([cap_proc.stderr], [], [], 0.05)
                if ready:
                    line = cap_proc.stderr.readline()
                    if line:
                        stderr_lines.append(line)
                        if line.startswith("Capturing on "):
                            capture_announced = True
                    continue

            if capture_announced and pcap_path.exists():
                pcap_stat = pcap_path.stat()
                if pcap_stat.st_size > 0 and pcap_stat.st_mtime_ns >= capture_start_ns:
                    return cap_proc

            time.sleep(0.02)

        cap_proc.terminate()
        try:
            cap_proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            cap_proc.kill()
            cap_proc.wait()

        stderr_text = "".join(stderr_lines).strip()
        raise TimeoutError(
            f"tshark did not report capture readiness within {readiness_timeout:.1f}s"
            + (f": {stderr_text}" if stderr_text else "")
        )

    def run_scenario(
        self,
        spec: ScenarioSpec,
        capture_timeout: float = 6.0,
    ) -> ScenarioExecutionResult:
        """
        Execute a single scenario end-to-end:
        Stage -> Deploy -> Capture -> Client -> PCAP -> Analyze -> Sidecar.
        """
        scenario_id = spec.scenario_id
        port = spec.network.port
        server_ip = spec.network.server_ip
        pcap_path = self.captures_dir / f"{scenario_id}.pcap"
        sidecar_path = self.captures_dir / f"{scenario_id}.json"
        evidence_path = self.captures_dir / f"{scenario_id}.evidence.json"

        # 1. Stage scenario configuration and PKI artifacts
        try:
            if spec.is_smtp:
                staged = self.stager.stage(spec, output_dir=self.active_dir)
            elif spec.is_imap:
                staged = self.imap_stager.stage(spec, output_dir=self.active_dir)
            elif spec.is_pop3:
                staged = self.pop3_stager.stage(spec, output_dir=self.active_dir)
            else:
                raise NotImplementedError(f"Protocol '{spec.protocol}' stager not yet implemented")
        except UnresolvableScenarioError as unres_err:
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                success=False,
                pcap_path=pcap_path,
                sidecar_path=sidecar_path,
                evidence_path=evidence_path,
                status="BLOCKED",
                error=f"BLOCKED: {unres_err}",
            )

        # 2. Deploy active configuration to the daemon
        if spec.is_smtp:
            self.deploy_postfix_configuration()
        elif spec.is_imap or spec.is_pop3:
            self.deploy_dovecot_configuration()
        else:
            raise NotImplementedError(f"Protocol '{spec.protocol}' runner not yet implemented")

        # 3. Start live packet capture on the bridge interface
        try:
            cap_proc = self.start_capture(port, pcap_path, readiness_timeout=capture_timeout)
        except Exception as exc:
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                success=False,
                pcap_path=pcap_path,
                sidecar_path=sidecar_path,
                evidence_path=evidence_path,
                client_result=ClientResult(
                    scenario_id=scenario_id,
                    success=False,
                    tls_negotiated=False,
                    error="Capture did not become ready",
                ),
                error=f"Packet capture failed before client execution: {exc}",
                status="FAILED",
            )

        client_res: Optional[ClientResult] = None
        analyzer_results: Dict[int, Any] = {}
        error_msg: Optional[str] = None

        try:
            # 4. Drive protocol interactions
            if spec.is_smtp:
                target_host = server_ip
                if getattr(spec.client, "mitm_action", None) == "strip_starttls":
                    target_host = self.ensure_mitm_container()
                client_res = self.client.execute(
                    scenario=staged,
                    host_override=target_host,
                    port_override=port,
                )
            elif spec.is_imap:
                client_res = self.imap_client.execute(
                    scenario=staged,
                    host_override=server_ip,
                    port_override=port,
                )
            elif spec.is_pop3:
                target_host = server_ip
                if getattr(spec.client, "mitm_action", None) == "strip_starttls":
                    target_host = self.ensure_mitm_container()
                client_res = self.pop3_client.execute(
                    scenario=staged,
                    host_override=target_host,
                    port_override=port,
                )
            else:
                raise NotImplementedError(f"Protocol '{spec.protocol}' client not yet implemented")
            if not client_res.success:
                error_msg = client_res.error or "Client interaction did not succeed"
        except Exception as exc:
            error_msg = f"Client execution failed with exception: {exc}"
        finally:
            # 5. Flush and terminate packet capture
            time.sleep(0.5)
            cap_proc.terminate()
            try:
                cap_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                cap_proc.kill()
                cap_proc.wait()

        # Validate PCAP creation
        if not pcap_path.exists() or pcap_path.stat().st_size == 0:
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                success=False,
                pcap_path=pcap_path,
                sidecar_path=sidecar_path,
                evidence_path=evidence_path,
                client_result=client_res or ClientResult(scenario_id=scenario_id, success=False, tls_negotiated=False, error="No PCAP"),
                error="Packet capture file was not created or is empty",
                status="FAILED",
            )

        # 6. Analyze captured PCAP using PCAPAnalyzer
        try:
            analyzer = PCAPAnalyzer(str(pcap_path), trust_store="testbed")
            analyzer_results = analyzer.analyze()
        except Exception as exc:
            error_msg = f"Analyzer failed on PCAP: {exc}"

        # 7. Generate Full-Fidelity Evidence Artifact (<scenario_id>.evidence.json)
        evidence_data: Dict[str, Any] = {}
        evidence_error: Optional[str] = None
        try:
            evidence_data = serialize_evidence(analyzer_results)
            evidence_json = json.dumps(evidence_data, indent=2)
            evidence_path.write_text(evidence_json)

            # Reload and independently verify fidelity
            reloaded_evidence = json.loads(evidence_path.read_text())
            if reloaded_evidence != evidence_data:
                raise ValueError(f"Evidence reload verification mismatch for {scenario_id}")
        except Exception as exc:
            evidence_error = f"Evidence artifact generation/verification failed: {exc}"
            if error_msg is None:
                error_msg = evidence_error

        # Verify negative TLS handshake failure alert requirement
        if spec.generator_requirement == "server_sends_fatal_alert":
            stream0_alerts = (
                analyzer_results.get(0, {})
                .get("handshake", {})
                .get("flight", {})
                .get("alerts", [])
                if analyzer_results.get(0, {}).get("handshake") else []
            )
            fatal_alerts = [a for a in stream0_alerts if a.get("level") == "FATAL"]
            if not fatal_alerts:
                alert_err = f"Scenario {scenario_id} expected fatal TLS alert on wire, but none found in capture"
                if error_msg is None:
                    error_msg = alert_err

        # 8. Generate Canonical Sidecar JSON conforming to data/sidecar_schema.json
        sidecar_data = build_canonical_sidecar(spec, analyzer_results, client_res)

        # 9. Actual schema validation - failure must fail the run
        schema_validation_error: Optional[str] = None
        try:
            jsonschema.validate(instance=sidecar_data, schema=self.sidecar_schema)
        except jsonschema.ValidationError as val_err:
            schema_validation_error = f"Sidecar schema validation failed: {val_err.message}"
            if error_msg is None:
                error_msg = schema_validation_error

        # Write canonical sidecar
        sidecar_path.write_text(json.dumps(sidecar_data, indent=2))

        overall_success = (
            client_res is not None
            and client_res.success
            and error_msg is None
            and schema_validation_error is None
            and evidence_error is None
        )

        return ScenarioExecutionResult(
            scenario_id=scenario_id,
            success=overall_success,
            pcap_path=pcap_path,
            sidecar_path=sidecar_path,
            evidence_path=evidence_path,
            client_result=client_res,
            analyzer_results=analyzer_results,
            sidecar_data=sidecar_data,
            manifest=staged.manifest,
            error=error_msg,
            status="SUCCESS" if overall_success else "FAILED",
        )



    def run_scenarios(self, scenario_ids: List[str]) -> Dict[str, ScenarioExecutionResult]:
        """
        Run a sequence of scenarios by their IDs.
        """
        matrix = {s.scenario_id: s for s in load_matrix()}
        results: Dict[str, ScenarioExecutionResult] = {}

        for sc_id in scenario_ids:
            if sc_id not in matrix:
                raise KeyError(f"Scenario '{sc_id}' not found in matrix")
            spec = matrix[sc_id]
            print(f"[runner] Running scenario {sc_id} ({spec.description or spec.generator_requirement or spec.protocol})...")
            res = self.run_scenario(spec)
            results[sc_id] = res
            status = res.status if res.status == "SUCCESS" else f"{res.status} ({res.error})"
            print(f"[runner] Scenario {sc_id} completed: {status}")

        return results


def main():
    """
    CLI entrypoint for running testbed scenarios.
    Usage:
        python3 -m testbed.runner.runner PCAP-004 PCAP-005 PCAP-001 PCAP-112
    """
    import argparse

    parser = argparse.ArgumentParser(description="SecureMailScope Testbed Scenario Runner")
    parser.add_argument(
        "scenarios",
        nargs="*",
        default=["PCAP-004", "PCAP-005", "PCAP-001", "PCAP-112"],
        help="Scenario IDs to execute (default: baseline archetypes PCAP-004, PCAP-005, PCAP-001, PCAP-112)",
    )
    args = parser.parse_args()

    runner = ScenarioRunner()
    print(f"[runner] Using Docker bridge interface: {runner.bridge_interface}")
    results = runner.run_scenarios(args.scenarios)

    print("\n" + "=" * 80)
    print(" SUMMARY OF EXECUTION RESULTS")
    print("=" * 80)
    all_passed = True
    for sc_id, res in results.items():
        if res.status == "SUCCESS":
            status = "PASSED"
        elif res.status == "BLOCKED":
            status = f"BLOCKED: {res.error}"
        else:
            status = f"FAILED: {res.error}"
        stream0 = res.analyzer_results.get(0, {})
        proto = stream0.get("protocol", "Unknown")
        stls = stream0.get("starttls", {}).get("status", "N/A")
        tls = stream0.get("tls", {}).get("tls_version", "None") if stream0.get("tls") else "None"
        cipher = stream0.get("tls", {}).get("cipher_name", "None") if stream0.get("tls") else "None"
        print(f"  {sc_id}: {status} | Wire Facts: Proto={proto}, STARTTLS={stls}, TLS={tls}, Cipher={cipher}")
        if not res.success and res.status != "BLOCKED":
            all_passed = False

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
