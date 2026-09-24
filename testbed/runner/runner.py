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
from testbed.runner.comparator import compare
from testbed.runner.observed import build_observed_artifact, serialize_evidence
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


class StaleArtifactCleanupError(RuntimeError):
    """Raised when deletion of stale scenario artifacts fails."""
    pass


def cleanup_scenario_artifacts(captures_dir: Path, scenario_id: str) -> None:
    """
    Remove any pre-existing generation artifacts for the given scenario_id.
    Does not swallow OSError: if deletion fails, raises StaleArtifactCleanupError.
    """
    errors: List[str] = []
    for suffix in (
        ".pcap",
        ".expected.json",
        ".observed.json",
        ".comparison.json",
        ".evidence.json",
        ".batch.json",
    ):
        target = captures_dir / f"{scenario_id}{suffix}"
        if target.exists():
            try:
                target.unlink()
            except OSError as exc:
                errors.append(f"{target.name}: {exc}")
    if errors:
        raise StaleArtifactCleanupError(
            f"Stale artifact cleanup failed for {scenario_id}: {'; '.join(errors)}"
        )


@dataclass
class ScenarioExecutionResult:
    """
    Structured outcome of an automated scenario run from stager through analyzer.
    """
    scenario_id: str
    execution_success: bool
    comparison_status: str  # "PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"
    pcap_path: Path
    expected_path: Path
    observed_path: Path
    comparison_path: Path
    evidence_path: Optional[Path] = None
    client_result: Optional[ClientResult] = None
    analyzer_results: Dict[int, Any] = field(default_factory=dict)
    expected_data: Dict[str, Any] = field(default_factory=dict)
    observed_data: Dict[str, Any] = field(default_factory=dict)
    comparison_data: Dict[str, Any] = field(default_factory=dict)
    manifest: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    status: str = "FAILED"
    success: bool = False

    def __post_init__(self):
        # Backward-compatible property behavior: True iff execution succeeded and comparison PASSED
        if not self.success and self.execution_success and self.comparison_status == "PASS":
            self.success = True


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

        self.expected_schema_path = _project_root / "data" / "expected_schema.json"
        self.observed_schema_path = _project_root / "data" / "observed_schema.json"
        self.comparison_schema_path = _project_root / "data" / "comparison_schema.json"

        if not self.expected_schema_path.exists():
            raise FileNotFoundError(f"Expected schema not found at {self.expected_schema_path}")
        if not self.observed_schema_path.exists():
            raise FileNotFoundError(f"Observed schema not found at {self.observed_schema_path}")
        if not self.comparison_schema_path.exists():
            raise FileNotFoundError(f"Comparison schema not found at {self.comparison_schema_path}")

        with open(self.expected_schema_path, "r", encoding="utf-8") as f:
            self.expected_schema = json.load(f)
        with open(self.observed_schema_path, "r", encoding="utf-8") as f:
            self.observed_schema = json.load(f)
        with open(self.comparison_schema_path, "r", encoding="utf-8") as f:
            self.comparison_schema = json.load(f)

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
        expected_path = self.captures_dir / f"{scenario_id}.expected.json"
        observed_path = self.captures_dir / f"{scenario_id}.observed.json"
        comparison_path = self.captures_dir / f"{scenario_id}.comparison.json"
        evidence_path = self.captures_dir / f"{scenario_id}.evidence.json"

        # Remove stale generation artifacts for this scenario before execution
        cleanup_scenario_artifacts(self.captures_dir, scenario_id)

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
            expected_data = spec.to_expected_dict(selected_cipher=None)
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                execution_success=False,
                comparison_status="NOT_RUN",
                pcap_path=pcap_path,
                expected_path=expected_path,
                observed_path=observed_path,
                comparison_path=comparison_path,
                evidence_path=evidence_path,
                expected_data=expected_data,
                status="BLOCKED",
                error=f"BLOCKED: {unres_err}",
                success=False,
            )
        except Exception as stage_err:
            expected_data = spec.to_expected_dict(selected_cipher=None)
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                execution_success=False,
                comparison_status="NOT_RUN",
                pcap_path=pcap_path,
                expected_path=expected_path,
                observed_path=observed_path,
                comparison_path=comparison_path,
                evidence_path=evidence_path,
                expected_data=expected_data,
                status="FAILED",
                error=f"Staging failed: {stage_err}",
                success=False,
            )

        # 2. Deploy active configuration to the daemon
        if spec.is_smtp:
            self.deploy_postfix_configuration()
        elif spec.is_imap or spec.is_pop3:
            self.deploy_dovecot_configuration()
        else:
            raise NotImplementedError(f"Protocol '{spec.protocol}' runner not yet implemented")

        # For TLS 1.3 PSK resumption scenarios: obtain NewSessionTicket in a prerequisite
        # handshake outside the capture window, so the PCAP isolates the resumed stream.
        saved_session = None
        reusable_ctx = None
        if spec.generator_requirement in (
            "psk_dhe_resumption_without_cert",
            "psk_resumption_without_cert",
        ):
            saved_session, reusable_ctx = self.client.establish_resumption_ticket(
                host=server_ip,
                port=port,
                sni=spec.client.sni,
                client_tls=staged.manifest.get("client_tls", {}),
            )

        # 3. Start live packet capture on the bridge interface
        try:
            cap_proc = self.start_capture(port, pcap_path, readiness_timeout=capture_timeout)
        except Exception as exc:
            expected_data = spec.to_expected_dict(selected_cipher=getattr(staged, "selected_cipher", None))
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                execution_success=False,
                comparison_status="NOT_RUN",
                pcap_path=pcap_path,
                expected_path=expected_path,
                observed_path=observed_path,
                comparison_path=comparison_path,
                evidence_path=evidence_path,
                expected_data=expected_data,
                client_result=ClientResult(
                    scenario_id=scenario_id,
                    success=False,
                    tls_negotiated=False,
                    error="Capture did not become ready",
                ),
                error=f"Packet capture failed before client execution: {exc}",
                status="FAILED",
                success=False,
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
                    session=saved_session,
                    ssl_context=reusable_ctx,
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
            expected_data = spec.to_expected_dict(selected_cipher=getattr(staged, "selected_cipher", None))
            return ScenarioExecutionResult(
                scenario_id=scenario_id,
                execution_success=False,
                comparison_status="NOT_RUN",
                pcap_path=pcap_path,
                expected_path=expected_path,
                observed_path=observed_path,
                comparison_path=comparison_path,
                evidence_path=evidence_path,
                expected_data=expected_data,
                client_result=client_res or ClientResult(scenario_id=scenario_id, success=False, tls_negotiated=False, error="No PCAP"),
                error="Packet capture file was not created or is empty",
                status="FAILED",
                success=False,
            )

        # 6. Analyze captured PCAP using PCAPAnalyzer
        try:
            effective_ts = (
                str(staged.trust_store_path)
                if staged.trust_store_path and staged.trust_store_path.exists()
                else "testbed"
            )
            analyzer = PCAPAnalyzer(str(pcap_path), trust_store=effective_ts)
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

        # Verify negative TLS handshake failure alert requirement across all analyzed streams
        if spec.generator_requirement == "server_sends_fatal_alert":
            has_fatal = False
            for session in analyzer_results.values():
                alerts = (session.get("handshake") or {}).get("flight", {}).get("alerts", [])
                if any(str(a.get("level")).upper() == "FATAL" for a in alerts):
                    has_fatal = True
                    break
            if not has_fatal:
                alert_err = f"Scenario {scenario_id} expected fatal TLS alert on wire, but none found in capture"
                if error_msg is None:
                    error_msg = alert_err

        # 8. Generate Expected Artifact (<scenario_id>.expected.json)
        expected_data: Dict[str, Any] = {}
        try:
            expected_data = spec.to_expected_dict(selected_cipher=getattr(staged, "selected_cipher", None))
            jsonschema.validate(instance=expected_data, schema=self.expected_schema)
            expected_path.write_text(json.dumps(expected_data, indent=2))
        except Exception as exc:
            exp_err = f"Expected artifact generation/validation failed: {exc}"
            if error_msg is None:
                error_msg = exp_err

        # 9. Generate Pure Observed Artifact (<scenario_id>.observed.json)
        observed_data: Dict[str, Any] = {}
        try:
            observed_data = build_observed_artifact(scenario_id, analyzer_results)
            jsonschema.validate(instance=observed_data, schema=self.observed_schema)
            observed_path.write_text(json.dumps(observed_data, indent=2))
        except Exception as exc:
            obs_err = f"Observed artifact generation/validation failed: {exc}"
            if error_msg is None:
                error_msg = obs_err

        # 10. Generate Deterministic Comparison Artifact (<scenario_id>.comparison.json)
        comparison_data: Dict[str, Any] = {}
        comparison_status = "FAIL"
        try:
            comparison_data = compare(expected_data, observed_data)
            jsonschema.validate(instance=comparison_data, schema=self.comparison_schema)
            comparison_path.write_text(json.dumps(comparison_data, indent=2))
            comparison_status = comparison_data.get("status", "FAIL")
        except Exception as exc:
            comp_err = f"Comparison artifact generation/validation failed: {exc}"
            if error_msg is None:
                error_msg = comp_err

        execution_success = (
            client_res is not None
            and client_res.success
            and error_msg is None
            and evidence_error is None
        )
        overall_success = execution_success and (comparison_status == "PASS")

        return ScenarioExecutionResult(
            scenario_id=scenario_id,
            execution_success=execution_success,
            comparison_status=comparison_status,
            pcap_path=pcap_path,
            expected_path=expected_path,
            observed_path=observed_path,
            comparison_path=comparison_path,
            evidence_path=evidence_path,
            client_result=client_res,
            analyzer_results=analyzer_results,
            expected_data=expected_data,
            observed_data=observed_data,
            comparison_data=comparison_data,
            manifest=staged.manifest,
            error=error_msg,
            status="SUCCESS" if (execution_success and comparison_status in ("PASS", "INCONCLUSIVE")) else "FAILED",
            success=overall_success,
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
            status_desc = f"{res.status} [Comparison: {res.comparison_status}]" if res.execution_success else f"{res.status} ({res.error})"
            print(f"[runner] Scenario {sc_id} completed: {status_desc}")

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
        if res.execution_success:
            status = f"PASSED (Comparison: {res.comparison_status})"
        elif res.status == "BLOCKED":
            status = f"BLOCKED: {res.error}"
        else:
            status = f"FAILED: {res.error}"

        eval_stream = res.comparison_data.get("evaluated_stream")
        eval_session = (
            res.analyzer_results.get(eval_stream, {})
            if eval_stream is not None
            else (res.analyzer_results.get(0, {}) if res.analyzer_results else {})
        )
        proto = eval_session.get("protocol", "Unknown")
        stls = eval_session.get("starttls", {}).get("status", "N/A")
        tls = eval_session.get("tls", {}).get("tls_version", "None") if eval_session.get("tls") else "None"
        cipher = eval_session.get("tls", {}).get("cipher_name", "None") if eval_session.get("tls") else "None"
        print(f"  {sc_id}: {status} | Evaluated Stream {eval_stream} Wire Facts: Proto={proto}, STARTTLS={stls}, TLS={tls}, Cipher={cipher}")
        if not (res.execution_success and res.comparison_status in ("PASS", "INCONCLUSIVE")):
            all_passed = False

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
