"""
testbed/runner/stager.py
========================
Deterministic, Side-Effect-Free SMTP Scenario Stager (Milestone 1).

Architecture:
-------------
Transforms a normalized ScenarioSpec into a self-contained, reproducible
runtime staging directory:
    testbed/staged/<scenario_id>/
        ├── chain.pem      (X.509 certificate chain, if spec.needs_pki)
        ├── key.pem        (Private key, if spec.needs_pki)
        ├── main.cf        (Rendered Postfix configuration)
        └── manifest.json  (Reproducible metadata capturing scenario expectations)

RFC References:
  - RFC 5321: Simple Mail Transfer Protocol (SMTP)
  - RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security (STARTTLS)
  - RFC 8314: Cleartext Considered Obsolete (Implicit TLS port 465 / smtps)
  - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
  - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure project root is accessible
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent

from analysis.ciphers import iana_to_openssl
from testbed.pki.generator.make_certs import PKIFactory
from testbed.runner.resolver import (
    ResolutionStatus,
    RuntimeStatus,
    UnresolvableScenarioError,
    resolve_scenario,
)
from testbed.runner.spec import ScenarioSpec


@dataclass(frozen=True)
class StagedScenario:
    """
    Structured representation of a staged scenario ready for deployment.
    """
    scenario_id: str
    root_dir: Path
    files: Dict[str, Path]
    service: str = "postfix"
    manifest: Dict[str, Any] = field(default_factory=dict)


PROVEN_BASELINES = {"PCAP-004", "PCAP-005", "PCAP-001", "PCAP-112"}
PROVEN_IMAP_BASELINES = {"PCAP-002", "PCAP-024"}
PROVEN_POP3_BASELINES = {"PCAP-042", "PCAP-063", "PCAP-003", "PCAP-043"}


def derive_client_tls_config(spec: ScenarioSpec) -> Dict[str, Any]:
    """
    Derive the deterministic TLS configuration required for the client handshake.
    Single authoritative source of truth for both SMTPStager and SMTPClient.
    """
    kex12 = spec.raw_row.get("tls12_kex_type", "")
    proto_ver = spec.server.tls_version
    req = spec.generator_requirement

    # Client offered version
    if req == "server_downgrade_with_sentinel":
        client_version = "TLS 1.3"
    elif req == "legacy_client_server_with_sentinel":
        client_version = "TLS 1.2"
    elif proto_ver == "1.0":
        client_version = "TLS 1.0"
    elif proto_ver == "1.1":
        client_version = "TLS 1.1"
    elif proto_ver == "1.2":
        client_version = "TLS 1.2"
    elif proto_ver == "1.3":
        client_version = "TLS 1.3"
    else:
        client_version = "TLS 1.3" if spec.server.tls_presence != "none" else None

    # Derive ciphers traceably from TLSCipherResolver without heuristic mappings
    resolver_res = resolve_scenario(spec)
    if resolver_res.cipher_resolution_status == ResolutionStatus.NOT_APPLICABLE:
        offered_ciphers = []
    elif resolver_res.cipher_resolution_status == ResolutionStatus.UNIQUE:
        offered_ciphers = [resolver_res.selected_cipher]
    elif resolver_res.cipher_resolution_status == ResolutionStatus.MULTIPLE_CANDIDATES:
        # Critical Phase 1B correction: never offer all candidates as an implicit wire fallback
        offered_ciphers = []
    elif spec.generator_requirement == "server_sends_fatal_alert":
        # Disjoint cipher suite from server: client offers ECDHE-RSA-AES128-GCM-SHA256,
        # server only enables ECDHE-RSA-AES256-GCM-SHA384 -> intersection is empty,
        # triggering RFC 5246 fatal alert 40 (handshake_failure).
        offered_ciphers = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
    else:
        offered_ciphers = []

    return {
        "sni": spec.client.sni,
        "tls_presence": spec.client.tls_presence,
        "offered_version": client_version,
        "offered_ciphers": offered_ciphers,
        "starttls_enforcement": spec.client.starttls_enforcement,
        "auth_outcome": spec.client.auth_outcome,
        "client_behavior": spec.client.client_behavior,
        "resolver_result": resolver_res.to_dict(),
    }


class SMTPStager:
    """
    Stager responsible for translating an SMTP ScenarioSpec into concrete
    Postfix configurations and PKI artifacts.
    """

    def __init__(
        self,
        pki_factory: Optional[PKIFactory] = None,
        base_staged_dir: Optional[Path | str] = None,
    ):
        pki_dir = _project_root / "testbed" / "pki"
        self.pki_factory = pki_factory or PKIFactory(pki_dir=str(pki_dir))
        self.base_staged_dir = Path(base_staged_dir) if base_staged_dir else _project_root / "testbed" / "staged"

    def render_main_cf(self, spec: ScenarioSpec, has_pki: bool = True) -> str:
        """
        Render Postfix main.cf reflecting the scenario's server TLS configuration.
        """
        lines = [
            "# ==============================================================================",
            f"# SECUREMAILSCOPE TESTBED - RENDERED MAIN.CF FOR {spec.scenario_id}",
            "# ==============================================================================",
            f"# Description: {spec.description or 'N/A'}",
            "# ==============================================================================",
            "",
            "# Hostname & Network Identity",
            f"myhostname = {spec.server.hostname}",
            "mydomain = test.local",
            "myorigin = $mydomain",
            "mydestination = $myhostname, localhost.$mydomain, localhost",
            "mynetworks = 127.0.0.0/8, 172.28.0.0/16",
            "inet_interfaces = all",
            "inet_protocols = ipv4",
            "",
            "# Prevent Reverse DNS lookup delays on Docker network",
            "disable_dns_lookups = yes",
            "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination",
            "",
            "# Native container stdout logging",
            "maillog_file = /dev/stdout",
            "",
            "# TLS Logging (Level 2 = log TLS cipher suite, protocol, and peer cert details)",
            "smtpd_tls_loglevel = 2",
            "smtpd_tls_received_header = yes",
            "compatibility_level = 3.6",
            "",
            "# ------------------------------------------------------------------------------",
            "# TLS Presence & Security Level",
            "# ------------------------------------------------------------------------------",
        ]

        # 1. TLS Presence / Enforcement (RFC 3207 §4.1 / RFC 8314)
        if spec.server.tls_presence == "none" or spec.server.starttls_banner_response == "suppressed":
            lines.append("smtpd_tls_security_level = none")
        elif spec.server.tls_presence == "STARTTLS-upgraded":
            if spec.server.starttls_enforcement == "mandatory":
                lines.append("smtpd_tls_security_level = encrypt")
            else:
                lines.append("smtpd_tls_security_level = may")
        elif spec.server.tls_presence == "implicit-TLS":
            lines.append("smtpd_tls_security_level = encrypt")

        # 2. Certificate and Key Paths (Postfix 3.4+ smtpd_tls_chain_files)
        # ponytail: omit cert chain files completely if scenario has no PKI (e.g. cleartext)
        if has_pki:
            lines.append("")
            lines.append("# Certificate Chain & Key Injection")
            lines.append("smtpd_tls_chain_files = /etc/mailtest/active/key.pem, /etc/mailtest/active/chain.pem")
        elif spec.client.mitm_action == "strip_starttls" or spec.generator_requirement == "server_sends_fatal_alert":
            lines.append("")
            lines.append("# Baseline Server Certificate")
            lines.append("smtpd_tls_cert_file = /etc/postfix/baseline_cert.pem")
            lines.append("smtpd_tls_key_file = /etc/postfix/baseline_key.pem")

        # 3. Protocol & Version Constraints
        proto_ver = spec.server.tls_version
        req = spec.generator_requirement
        lines.append("")
        lines.append("# TLS Protocol Restrictions")
        if proto_ver == "1.0":
            lines.append("smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1.1, !TLSv1.2, !TLSv1.3, TLSv1")
            lines.append("smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1.1, !TLSv1.2, !TLSv1.3, TLSv1")
        elif proto_ver == "1.1":
            lines.append("smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.2, !TLSv1.3, TLSv1.1")
            lines.append("smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.2, !TLSv1.3, TLSv1.1")
        elif proto_ver == "1.2":
            if req in ("server_downgrade_with_sentinel", "legacy_client_server_with_sentinel"):
                # Server supports TLS 1.3, client requests TLS 1.2, triggering downgrade sentinel (RFC 8446 §4.1.3)
                lines.append("smtpd_tls_protocols = >=TLSv1.2")
                lines.append("smtpd_tls_mandatory_protocols = >=TLSv1.2")
            else:
                lines.append("smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.3, TLSv1.2")
                lines.append("smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.3, TLSv1.2")
        elif proto_ver == "1.3":
            lines.append("smtpd_tls_protocols = >=TLSv1.3")
            lines.append("smtpd_tls_mandatory_protocols = >=TLSv1.3")
        else:
            # Cleartext or unconstrained default
            lines.append("smtpd_tls_protocols = >=TLSv1.2")
            lines.append("smtpd_tls_mandatory_protocols = >=TLSv1.2")

        # 4. Cipher Suite Configurations
        lines.append("")
        lines.append("# Cipher Suite Configuration")

        if spec.server.tls_presence != "none":
            resolver_res = resolve_scenario(spec)
            status = resolver_res.cipher_resolution_status

            # Baseline scenarios have wire-proven configurations in repository
            if spec.scenario_id in PROVEN_BASELINES:
                kex12 = spec.raw_row.get("tls12_kex_type", "")
                if kex12 == "DHE" or "dhe" in req.lower():
                    lines.append("tls_high_cipherlist = DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256")
                lines.append("smtpd_tls_ciphers = high")
                lines.append("smtpd_tls_mandatory_ciphers = high")
            elif spec.client.mitm_action == "strip_starttls":
                lines.append("smtpd_tls_ciphers = high")
            elif spec.generator_requirement == "server_sends_fatal_alert":
                # Deliberate disjoint cipher suite for negative TLS handshake test (PCAP-121)
                lines.append("tls_high_cipherlist = ECDHE-RSA-AES256-GCM-SHA384")
                lines.append("smtpd_tls_ciphers = high")
                lines.append("smtpd_tls_mandatory_ciphers = high")
            elif resolver_res.special_harness_requirement == "mitm_starttls_strip":
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} requires MITM proxy harness "
                    f"({resolver_res.special_harness_requirement}); cannot be staged on standard Postfix"
                )
            elif status == ResolutionStatus.UNIQUE:
                ossl_cipher = iana_to_openssl(resolver_res.selected_cipher)
                if ossl_cipher:
                    lines.append(f"tls_high_cipherlist = {ossl_cipher}")
                lines.append("smtpd_tls_ciphers = high")
                lines.append("smtpd_tls_mandatory_ciphers = high")
            elif status == ResolutionStatus.MULTIPLE_CANDIDATES:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: multiple candidates "
                    f"({resolver_res.current_runtime_candidate_count} runtime-supported, "
                    f"{resolver_res.iana_candidate_count} IANA-defined) exist without deterministic specification. "
                    f"Missing: {resolver_res.missing_information}"
                )
            elif status == ResolutionStatus.NO_CANDIDATE_UNDER_CURRENT_PROJECT_MODEL:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: no candidate under project model ({resolver_res.reason})"
                )
            elif status == ResolutionStatus.PROTOCOL_IMPOSSIBILITY:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: RFC protocol impossibility ({resolver_res.reason})"
                )
            elif status == ResolutionStatus.NO_CANDIDATE:
                if resolver_res.runtime_status == RuntimeStatus.REQUIRES_LEGACY_RUNTIME:
                    raise UnresolvableScenarioError(
                        f"Scenario {spec.scenario_id} cannot be staged: requires legacy runtime ({resolver_res.reason})"
                    )
                else:
                    raise UnresolvableScenarioError(
                        f"Scenario {spec.scenario_id} cannot be staged: {resolver_res.reason}"
                    )
            elif status == ResolutionStatus.SPECIAL_SCENARIO:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} is a special/negative scenario "
                    f"({resolver_res.special_harness_requirement}); cannot be staged as ordinary TLS"
                )

        return "\n".join(lines) + "\n"

    def get_listener_postconf_cmd(self, spec: ScenarioSpec) -> str:
        """
        Derive the postconf -M command argument to dynamically configure or ensure
        the scenario-specific listener in Postfix without rewriting master.cf.
        """
        port = spec.network.port
        is_implicit = (spec.server.tls_presence == "implicit-TLS")

        if port == 25:
            return "smtp/inet=smtp inet n - n - - smtpd"
        elif port == 465 and is_implicit:
            return "smtps/inet=smtps inet n - n - - smtpd -o smtpd_tls_wrappermode=yes -o smtpd_tls_security_level=encrypt -o smtpd_sasl_auth_enable=no"
        elif port == 587:
            return "submission/inet=submission inet n - n - - smtpd"
        else:
            # Custom / Non-standard port listener (e.g. 2525, 2526)
            extra = " -o smtpd_tls_wrappermode=yes -o smtpd_tls_security_level=encrypt -o smtpd_sasl_auth_enable=no" if is_implicit else ""
            return f"{port}/inet={port} inet n - n - - smtpd{extra}"

    def render_client_tls_config(self, spec: ScenarioSpec) -> Dict[str, Any]:
        """
        Derive the client TLS execution configuration to pair with server configuration.
        Delegates to derive_client_tls_config.
        """
        return derive_client_tls_config(spec)

    def render_manifest(
        self,
        spec: ScenarioSpec,
        staged_files: Dict[str, str],
        client_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Construct reproducible manifest containing source scenario expectations.
        """
        pki_manifest = None
        if spec.needs_pki:
            pki_manifest = {
                "sig_algo": spec.pki.sig_algo,
                "validity": spec.pki.validity,
                "chain_shape": spec.pki.chain_shape,
                "san_type": spec.pki.san_type,
                "weak_key": spec.pki.weak_key,
            }

        return {
            "scenario_id": spec.scenario_id,
            "layer": spec.layer,
            "description": spec.description,
            "protocol": spec.protocol,
            "service": "postfix",
            "network": {
                "port": spec.network.port,
                "port_type": spec.network.port_type,
                "server_ip": spec.network.server_ip,
                "client_ip": spec.network.client_ip,
            },
            "server_tls": {
                "tls_presence": spec.server.tls_presence,
                "tls_version": spec.server.tls_version,
                "cipher_strength": spec.server.cipher_strength,
                "starttls_enforcement": spec.server.starttls_enforcement,
                "hostname": spec.server.hostname,
                "listener_postconf_cmd": self.get_listener_postconf_cmd(spec),
            },
            "client_tls": client_config,
            "pki": pki_manifest,
            "oracle": {
                "expected_trust_status": spec.oracle.expected_trust_status,
                "expected_starttls_status": spec.oracle.expected_starttls_status,
                "expected_protocol": spec.oracle.expected_protocol,
            },
            "staged_files": staged_files,
        }

    def stage(
        self,
        spec: ScenarioSpec,
        output_dir: Optional[Path | str] = None,
    ) -> StagedScenario:
        """
        Stage an SMTP scenario into a self-contained directory.
        Deterministic, idempotent, side-effect-free.
        """
        if not spec.is_smtp:
            raise ValueError(f"SMTPStager only supports SMTP scenarios; got protocol={spec.protocol!r}")

        target_dir = Path(output_dir) if output_dir else (self.base_staged_dir / spec.scenario_id)
        target_dir.mkdir(parents=True, exist_ok=True)

        staged_files: Dict[str, Path] = {}
        staged_relative: Dict[str, str] = {}

        # 1. Materialize PKI artifacts if required by scenario
        has_pki = spec.needs_pki
        if has_pki:
            # ponytail: call pki_factory.materialize to keep PKI generation decoupled
            pki_res = self.pki_factory.materialize(spec.pki, target_dir)
            chain_path = pki_res["chain_file"]
            key_path = pki_res["key_file"]
            staged_files["chain"] = chain_path
            staged_files["key"] = key_path
            staged_relative["chain.pem"] = str(chain_path.name)
            staged_relative["key.pem"] = str(key_path.name)

        # 2. Render and write main.cf
        main_cf_content = self.render_main_cf(spec, has_pki=has_pki)
        main_cf_path = target_dir / "main.cf"
        main_cf_path.write_text(main_cf_content)
        staged_files["main_cf"] = main_cf_path
        staged_relative["main.cf"] = "main.cf"

        # 3. Render client TLS configuration
        client_config = self.render_client_tls_config(spec)

        # 4. Render and write manifest.json
        manifest_data = self.render_manifest(spec, staged_relative, client_config)
        manifest_path = target_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data, indent=2))
        staged_files["manifest"] = manifest_path

        return StagedScenario(
            scenario_id=spec.scenario_id,
            root_dir=target_dir,
            files=staged_files,
            service="postfix",
            manifest=manifest_data,
        )


class IMAPStager:
    """
    Stager responsible for translating an IMAP ScenarioSpec into concrete
    Dovecot configurations and PKI artifacts.
    """

    def __init__(
        self,
        pki_factory: Optional[PKIFactory] = None,
        base_staged_dir: Optional[Path | str] = None,
    ):
        pki_dir = _project_root / "testbed" / "pki"
        self.pki_factory = pki_factory or PKIFactory(pki_dir=str(pki_dir))
        self.base_staged_dir = Path(base_staged_dir) if base_staged_dir else _project_root / "testbed" / "staged"

    def render_dovecot_conf(self, spec: ScenarioSpec, has_pki: bool = True) -> str:
        """
        Render Dovecot dovecot.conf reflecting the scenario's server TLS configuration.
        """
        lines = [
            "# ==============================================================================",
            f"# SECUREMAILSCOPE TESTBED - RENDERED DOVECOT.CONF FOR {spec.scenario_id}",
            "# ==============================================================================",
            f"# Description: {spec.description or 'N/A'}",
            "# ==============================================================================",
            "",
            "protocols = imap",
            "listen = *",
            "",
            "# Native container stdout logging",
            "log_path = /dev/stdout",
            "info_log_path = /dev/stdout",
            "debug_log_path = /dev/stdout",
            "verbose_ssl = yes",
            "auth_verbose = yes",
            "",
            "# Authentication & Spool",
            "disable_plaintext_auth = no",
            "auth_mechanisms = plain login",
            "",
            "passdb {",
            "  driver = passwd-file",
            "  args = scheme=PLAIN username_format=%u /etc/dovecot/users",
            "}",
            "",
            "userdb {",
            "  driver = static",
            "  args = uid=vmail gid=vmail home=/var/mail/%u",
            "}",
            "",
            "mail_location = maildir:/var/mail/%u/Maildir",
            "",
            "# ------------------------------------------------------------------------------",
            "# TLS Presence & Security Level",
            "# ------------------------------------------------------------------------------",
        ]

        # 1. TLS Presence & Enforcement
        if spec.server.tls_presence == "none":
            lines.append("ssl = no")
        elif spec.server.tls_presence == "STARTTLS-upgraded":
            if spec.server.starttls_enforcement == "mandatory":
                lines.append("ssl = required")
            else:
                lines.append("ssl = yes")
        elif spec.server.tls_presence == "implicit-TLS":
            lines.append("ssl = required")
        else:
            lines.append("ssl = yes")

        # 2. Certificate and Key Paths
        if has_pki:
            lines.append("")
            lines.append("# Certificate Chain & Key Injection")
            lines.append("ssl_cert = </etc/mailtest/active/chain.pem")
            lines.append("ssl_key = </etc/mailtest/active/key.pem")

        # 3. Protocol & Version Constraints
        proto_ver = spec.server.tls_version
        if spec.server.tls_presence != "none":
            lines.append("")
            lines.append("# TLS Protocol Restrictions")
            if proto_ver == "1.0":
                lines.append("ssl_min_protocol = TLSv1")
            elif proto_ver == "1.1":
                lines.append("ssl_min_protocol = TLSv1.1")
            elif proto_ver == "1.2":
                lines.append("ssl_min_protocol = TLSv1.2")
            elif proto_ver == "1.3":
                lines.append("ssl_min_protocol = TLSv1.3")
            else:
                lines.append("ssl_min_protocol = TLSv1.2")

        # 4. Cipher Suite & Scenario Validation
        if spec.server.tls_presence != "none":
            resolver_res = resolve_scenario(spec)
            status = resolver_res.cipher_resolution_status

            if spec.scenario_id in PROVEN_IMAP_BASELINES:
                # Baseline scenarios have wire-proven configurations
                pass
            elif resolver_res.special_harness_requirement == "mitm_starttls_strip":
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} requires MITM proxy harness "
                    f"({resolver_res.special_harness_requirement}); cannot be staged on standard Dovecot"
                )
            elif status == ResolutionStatus.UNIQUE:
                ossl_cipher = iana_to_openssl(resolver_res.selected_cipher)
                if ossl_cipher:
                    lines.append(f"ssl_cipher_list = {ossl_cipher}")
            elif status == ResolutionStatus.MULTIPLE_CANDIDATES:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: multiple candidates "
                    f"({resolver_res.current_runtime_candidate_count} runtime-supported, "
                    f"{resolver_res.iana_candidate_count} IANA-defined) exist without deterministic specification. "
                    f"Missing: {resolver_res.missing_information}"
                )
            elif status == ResolutionStatus.NO_CANDIDATE_UNDER_CURRENT_PROJECT_MODEL:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: no candidate under project model ({resolver_res.reason})"
                )
            elif status == ResolutionStatus.PROTOCOL_IMPOSSIBILITY:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: RFC protocol impossibility ({resolver_res.reason})"
                )
            elif status == ResolutionStatus.NO_CANDIDATE:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: {resolver_res.reason}"
                )
            elif status == ResolutionStatus.SPECIAL_SCENARIO:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} is a special/negative scenario "
                    f"({resolver_res.special_harness_requirement}); cannot be staged as ordinary TLS"
                )

        # 5. Service & Listener Definitions
        lines.append("")
        lines.append("# Service & Listener Definitions")
        lines.append("service imap-login {")

        port = spec.network.port
        is_implicit = (spec.server.tls_presence == "implicit-TLS")

        if spec.server.tls_presence == "none":
            # For cleartext, define listener without ssl
            lines.append("  inet_listener imap {")
            lines.append(f"    port = {port}")
            lines.append("  }")
        else:
            # Always ensure standard listeners exist
            lines.append("  inet_listener imap {")
            lines.append("    port = 143")
            lines.append("  }")
            lines.append("  inet_listener imaps {")
            lines.append("    port = 993")
            lines.append("    ssl = yes")
            lines.append("  }")
            if port not in (143, 993):
                lines.append(f"  inet_listener imap_{port} {{")
                lines.append(f"    port = {port}")
                if is_implicit:
                    lines.append("    ssl = yes")
                lines.append("  }")

        lines.append("}")
        return "\n".join(lines) + "\n"

    def render_client_tls_config(self, spec: ScenarioSpec) -> Dict[str, Any]:
        return derive_client_tls_config(spec)

    def render_manifest(
        self,
        spec: ScenarioSpec,
        staged_files: Dict[str, str],
        client_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        pki_manifest = None
        if spec.needs_pki:
            pki_manifest = {
                "sig_algo": spec.pki.sig_algo,
                "validity": spec.pki.validity,
                "chain_shape": spec.pki.chain_shape,
                "san_type": spec.pki.san_type,
                "weak_key": spec.pki.weak_key,
            }

        return {
            "scenario_id": spec.scenario_id,
            "layer": spec.layer,
            "description": spec.description,
            "protocol": spec.protocol,
            "service": "dovecot",
            "network": {
                "port": spec.network.port,
                "port_type": spec.network.port_type,
                "server_ip": spec.network.server_ip,
                "client_ip": spec.network.client_ip,
            },
            "server_tls": {
                "tls_presence": spec.server.tls_presence,
                "tls_version": spec.server.tls_version,
                "cipher_strength": spec.server.cipher_strength,
                "starttls_enforcement": spec.server.starttls_enforcement,
                "hostname": spec.server.hostname,
            },
            "client_tls": client_config,
            "pki": pki_manifest,
            "oracle": {
                "expected_trust_status": spec.oracle.expected_trust_status,
                "expected_starttls_status": spec.oracle.expected_starttls_status,
                "expected_protocol": spec.oracle.expected_protocol,
            },
            "staged_files": staged_files,
        }

    def stage(
        self,
        spec: ScenarioSpec,
        output_dir: Optional[Path | str] = None,
    ) -> StagedScenario:
        """
        Stage an IMAP scenario into a self-contained directory.
        Deterministic, idempotent, side-effect-free.
        """
        if not spec.is_imap:
            raise ValueError(f"IMAPStager only supports IMAP scenarios; got protocol={spec.protocol!r}")

        target_dir = Path(output_dir) if output_dir else (self.base_staged_dir / spec.scenario_id)
        target_dir.mkdir(parents=True, exist_ok=True)

        staged_files: Dict[str, Path] = {}
        staged_relative: Dict[str, str] = {}

        # 1. Materialize PKI artifacts if required by scenario
        has_pki = spec.needs_pki
        if has_pki:
            pki_res = self.pki_factory.materialize(spec.pki, target_dir)
            chain_path = pki_res["chain_file"]
            key_path = pki_res["key_file"]
            staged_files["chain"] = chain_path
            staged_files["key"] = key_path
            staged_relative["chain.pem"] = str(chain_path.name)
            staged_relative["key.pem"] = str(key_path.name)

        # 2. Render and write dovecot.conf
        dovecot_conf_content = self.render_dovecot_conf(spec, has_pki=has_pki)
        dovecot_conf_path = target_dir / "dovecot.conf"
        dovecot_conf_path.write_text(dovecot_conf_content)
        staged_files["dovecot_conf"] = dovecot_conf_path
        staged_relative["dovecot.conf"] = "dovecot.conf"

        # 3. Render client TLS configuration
        client_config = self.render_client_tls_config(spec)

        # 4. Render and write manifest.json
        manifest_data = self.render_manifest(spec, staged_relative, client_config)
        manifest_path = target_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data, indent=2))
        staged_files["manifest"] = manifest_path

        return StagedScenario(
            scenario_id=spec.scenario_id,
            root_dir=target_dir,
            files=staged_files,
            service="dovecot",
            manifest=manifest_data,
        )


class POP3Stager:
    """
    Stager responsible for translating a POP3 ScenarioSpec into concrete
    Dovecot configurations and PKI artifacts.
    """

    def __init__(
        self,
        pki_factory: Optional[PKIFactory] = None,
        base_staged_dir: Optional[Path | str] = None,
    ):
        pki_dir = _project_root / "testbed" / "pki"
        self.pki_factory = pki_factory or PKIFactory(pki_dir=str(pki_dir))
        self.base_staged_dir = Path(base_staged_dir) if base_staged_dir else _project_root / "testbed" / "staged"

    def render_dovecot_conf(self, spec: ScenarioSpec, has_pki: bool = True) -> str:
        """
        Render Dovecot configuration reflecting the scenario's server POP3 TLS configuration.
        """
        lines = [
            "# ==============================================================================",
            f"# SECUREMAILSCOPE TESTBED - RENDERED DOVECOT.CONF FOR {spec.scenario_id}",
            "# ==============================================================================",
            f"# Description: {spec.description or 'N/A'}",
            "# ==============================================================================",
            "",
            "protocols = pop3",
            "listen = *",
            "",
            "# Native container stdout logging",
            "log_path = /dev/stdout",
            "info_log_path = /dev/stdout",
            "debug_log_path = /dev/stdout",
            "verbose_ssl = yes",
            "auth_verbose = yes",
            "",
            "# Authentication & Spool",
            "disable_plaintext_auth = no",
            "auth_mechanisms = plain login",
            "",
            "passdb {",
            "  driver = passwd-file",
            "  args = scheme=PLAIN username_format=%u /etc/dovecot/users",
            "}",
            "",
            "userdb {",
            "  driver = static",
            "  args = uid=vmail gid=vmail home=/var/mail/%u",
            "}",
            "",
            "mail_location = maildir:/var/mail/%u/Maildir",
            "",
            "# ------------------------------------------------------------------------------",
            "# TLS Presence & Security Level",
            "# ------------------------------------------------------------------------------",
        ]

        # 1. TLS Presence & Enforcement
        if spec.server.tls_presence == "none":
            lines.append("ssl = no")
        elif spec.server.tls_presence == "STARTTLS-upgraded":
            if spec.server.starttls_enforcement == "mandatory":
                lines.append("ssl = required")
            else:
                lines.append("ssl = yes")
        elif spec.server.tls_presence == "implicit-TLS":
            lines.append("ssl = required")
        else:
            lines.append("ssl = yes")

        # 2. Certificate and Key Paths
        if has_pki:
            lines.append("")
            lines.append("# Certificate Chain & Key Injection")
            lines.append("ssl_cert = </etc/mailtest/active/chain.pem")
            lines.append("ssl_key = </etc/mailtest/active/key.pem")
        elif spec.client.mitm_action == "strip_starttls":
            lines.append("")
            lines.append("# Baseline Server Certificate (for STLS advertisement)")
            lines.append("ssl_cert = </etc/dovecot/baseline_cert.pem")
            lines.append("ssl_key = </etc/dovecot/baseline_key.pem")

        # 3. Protocol & Version Constraints
        proto_ver = spec.server.tls_version
        if spec.server.tls_presence != "none":
            lines.append("")
            lines.append("# TLS Protocol Restrictions")
            if proto_ver == "1.0":
                lines.append("ssl_min_protocol = TLSv1")
            elif proto_ver == "1.1":
                lines.append("ssl_min_protocol = TLSv1.1")
            elif proto_ver == "1.2":
                lines.append("ssl_min_protocol = TLSv1.2")
            elif proto_ver == "1.3":
                lines.append("ssl_min_protocol = TLSv1.3")
            else:
                lines.append("ssl_min_protocol = TLSv1.2")

        # 4. Cipher Suite & Scenario Validation
        if spec.server.tls_presence != "none":
            resolver_res = resolve_scenario(spec)
            status = resolver_res.cipher_resolution_status

            if spec.scenario_id in PROVEN_POP3_BASELINES:
                # Baseline scenarios have wire-proven configurations
                pass
            elif spec.client.mitm_action == "strip_starttls":
                # Special MITM STLS stripping scenario - Dovecot uses baseline SSL
                pass
            elif resolver_res.special_harness_requirement == "mitm_starttls_strip":
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} requires MITM proxy harness "
                    f"({resolver_res.special_harness_requirement}); cannot be staged on standard Dovecot"
                )
            elif status == ResolutionStatus.UNIQUE:
                ossl_cipher = iana_to_openssl(resolver_res.selected_cipher)
                if ossl_cipher:
                    lines.append(f"ssl_cipher_list = {ossl_cipher}")
            elif status == ResolutionStatus.MULTIPLE_CANDIDATES:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: multiple candidates "
                    f"({resolver_res.current_runtime_candidate_count} runtime-supported, "
                    f"{resolver_res.iana_candidate_count} IANA-defined) exist without deterministic specification. "
                    f"Missing: {resolver_res.missing_information}"
                )
            elif status == ResolutionStatus.NO_CANDIDATE_UNDER_CURRENT_PROJECT_MODEL:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: no candidate under project model ({resolver_res.reason})"
                )
            elif status == ResolutionStatus.PROTOCOL_IMPOSSIBILITY:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: RFC protocol impossibility ({resolver_res.reason})"
                )
            elif status == ResolutionStatus.NO_CANDIDATE:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} cannot be staged: {resolver_res.reason}"
                )
            elif status == ResolutionStatus.SPECIAL_SCENARIO:
                raise UnresolvableScenarioError(
                    f"Scenario {spec.scenario_id} is a special/negative scenario "
                    f"({resolver_res.special_harness_requirement}); cannot be staged as ordinary TLS"
                )

        # 5. Service & Listener Definitions
        lines.append("")
        lines.append("# Service & Listener Definitions")
        lines.append("service pop3-login {")

        port = spec.network.port
        is_implicit = (spec.server.tls_presence == "implicit-TLS")

        if spec.server.tls_presence == "none":
            # For cleartext, define listener without ssl
            lines.append("  inet_listener pop3 {")
            lines.append(f"    port = {port}")
            lines.append("  }")
        else:
            # Always ensure standard listeners exist
            lines.append("  inet_listener pop3 {")
            lines.append("    port = 110")
            lines.append("  }")
            lines.append("  inet_listener pop3s {")
            lines.append("    port = 995")
            lines.append("    ssl = yes")
            lines.append("  }")
            if port not in (110, 995):
                lines.append(f"  inet_listener pop3_{port} {{")
                lines.append(f"    port = {port}")
                if is_implicit:
                    lines.append("    ssl = yes")
                lines.append("  }")

        lines.append("}")
        return "\n".join(lines) + "\n"

    def render_client_tls_config(self, spec: ScenarioSpec) -> Dict[str, Any]:
        return derive_client_tls_config(spec)

    def render_manifest(
        self,
        spec: ScenarioSpec,
        staged_files: Dict[str, str],
        client_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        pki_manifest = None
        if spec.needs_pki:
            pki_manifest = {
                "sig_algo": spec.pki.sig_algo,
                "validity": spec.pki.validity,
                "chain_shape": spec.pki.chain_shape,
                "san_type": spec.pki.san_type,
                "weak_key": spec.pki.weak_key,
            }

        return {
            "scenario_id": spec.scenario_id,
            "layer": spec.layer,
            "description": spec.description,
            "protocol": spec.protocol,
            "service": "dovecot",
            "network": {
                "port": spec.network.port,
                "port_type": spec.network.port_type,
                "server_ip": spec.network.server_ip,
                "client_ip": spec.network.client_ip,
            },
            "server_tls": {
                "tls_presence": spec.server.tls_presence,
                "tls_version": spec.server.tls_version,
                "cipher_strength": spec.server.cipher_strength,
                "starttls_enforcement": spec.server.starttls_enforcement,
                "hostname": spec.server.hostname,
            },
            "client_tls": client_config,
            "pki": pki_manifest,
            "oracle": {
                "expected_trust_status": spec.oracle.expected_trust_status,
                "expected_starttls_status": spec.oracle.expected_starttls_status,
                "expected_protocol": spec.oracle.expected_protocol,
            },
            "staged_files": staged_files,
        }

    def stage(
        self,
        spec: ScenarioSpec,
        output_dir: Optional[Path | str] = None,
    ) -> StagedScenario:
        """
        Stage a POP3 scenario into a self-contained directory.
        Deterministic, idempotent, side-effect-free.
        """
        if not spec.is_pop3:
            raise ValueError(f"POP3Stager only supports POP3 scenarios; got protocol={spec.protocol!r}")

        target_dir = Path(output_dir) if output_dir else (self.base_staged_dir / spec.scenario_id)
        target_dir.mkdir(parents=True, exist_ok=True)

        staged_files: Dict[str, Path] = {}
        staged_relative: Dict[str, str] = {}

        # 1. Materialize PKI artifacts if required by scenario
        has_pki = spec.needs_pki
        if has_pki:
            pki_res = self.pki_factory.materialize(spec.pki, target_dir)
            chain_path = pki_res["chain_file"]
            key_path = pki_res["key_file"]
            staged_files["chain"] = chain_path
            staged_files["key"] = key_path
            staged_relative["chain.pem"] = str(chain_path.name)
            staged_relative["key.pem"] = str(key_path.name)

        # 2. Render and write dovecot.conf
        dovecot_conf_content = self.render_dovecot_conf(spec, has_pki=has_pki)
        dovecot_conf_path = target_dir / "dovecot.conf"
        dovecot_conf_path.write_text(dovecot_conf_content)
        staged_files["dovecot_conf"] = dovecot_conf_path
        staged_relative["dovecot.conf"] = "dovecot.conf"

        # 3. Render client TLS configuration
        client_config = self.render_client_tls_config(spec)

        # 4. Render and write manifest.json
        manifest_data = self.render_manifest(spec, staged_relative, client_config)
        manifest_path = target_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data, indent=2))
        staged_files["manifest"] = manifest_path

        return StagedScenario(
            scenario_id=spec.scenario_id,
            root_dir=target_dir,
            files=staged_files,
            service="dovecot",
            manifest=manifest_data,
        )


