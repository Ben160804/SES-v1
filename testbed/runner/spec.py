"""
Scenario Specification & Normalization Layer (SecureMailScope Testbed)
=====================================================================

RFC & Specification Citations:
- RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 6125: Representation and Verification of Domain-Based Application Service
            Identity within Internet Public Key Infrastructure Using X.509
- RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions (SNI)
- RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security
- RFC 2595: Using TLS with IMAP, POP3 and ACAP
- RFC 8314: Cleartext Considered Obsolete: Use of Transport Layer Security (TLS)
            for Email Submission and Access (Implicit TLS ports 465, 993, 995)

Architectural Role:
Decouples raw CSV matrix rows (data/pcap_generation_matrix.csv) from concrete
infrastructure engines (PKIFactory, Postfix, Dovecot, Client, MITM).
Every row normalizes into a typed, frozen ScenarioSpec object.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import csv


# ---------------------------------------------------------------------------
# Value normalization lookup tables
# ---------------------------------------------------------------------------

SIG_ALGO_MAP = {
    "ECDSA": "ecdsa",
    "RSA-PKCS1v15": "rsa_pkcs",
    "RSA-PSS": "rsa_pss",
    "Ed25519": "ed25519",
}

VALIDITY_MAP = {
    "valid": "valid",
    "expired": "expired",
    "not-yet-valid": "not_yet_valid",
}

CHAIN_SHAPE_MAP = {
    "complete-chain": "complete",
    "self-signed-trusted": "self_signed_trusted",
    "self-signed-untrusted": "self_signed_untrusted",
    "complete-chain-untrusted-root": "unknown_root",
    "leaf-only": "leaf_only",
    "intermediate-not-ca": "bad_constraint",
    "chain-tampered-intermediate-sig": "tampered_sig",
}

# Standard email ports per RFC 8314 & legacy standards
STANDARD_PORTS = {
    ("smtp", "implicit-TLS"): 465,       # RFC 8314 §7.3 submissions
    ("smtp", "STARTTLS-upgraded"): 25,   # RFC 5321 / RFC 3207
    ("smtp", "none"): 25,                # RFC 5321 cleartext
    ("imap", "implicit-TLS"): 993,       # RFC 8314 §7.1 imaps
    ("imap", "STARTTLS-upgraded"): 143,  # RFC 3501 / RFC 2595
    ("imap", "none"): 143,               # RFC 3501 cleartext
    ("pop3", "implicit-TLS"): 995,       # RFC 8314 §7.2 pop3s
    ("pop3", "STARTTLS-upgraded"): 110,  # RFC 1939 / RFC 2595
    ("pop3", "none"): 110,               # RFC 1939 cleartext
}

# Non-standard ports for DPI evasion / anomaly testing (PCAP-070, 071, 072)
NON_STANDARD_PORTS = {
    "smtp": 2526,
    "imap": 1143,
    "pop3": 1110,
}

# Centralized testbed service endpoint address map
DEFAULT_SERVICE_ENDPOINTS = {
    "postfix": "172.28.0.10",
    "dovecot": "172.28.0.11",
    "client": "172.28.0.20",
    "mitm": "172.28.0.30",
}


@dataclass(frozen=True)
class PKISpec:
    """
    PKI artifacts required for a TLS scenario.
    Directly feeds PKIFactory.generate_cert_profile().
    """
    sig_algo: str       # ecdsa, rsa_pkcs, rsa_pss, ed25519
    validity: str       # valid, expired, not_yet_valid
    chain_shape: str    # complete, self_signed_trusted, etc.
    san_type: str       # matched_dns, mismatched_dns, wildcard, ip_san, no_san
    weak_key: bool = False  # True for RSA-1024 (PCAP-126)
    leaf_key_algo: Optional[str] = None  # rsa, ecdsa, ed25519 (decoupled from sig_algo per RFC 5280)
    leaf_key_size: Optional[int] = None  # 2048, 1024, 256


@dataclass(frozen=True)
class ServerSpec:
    """Server daemon runtime configuration (Postfix / Dovecot)."""
    server_app: str                 # "postfix" | "dovecot"
    protocol: str                   # "smtp" | "imap" | "pop3"
    port: int
    tls_presence: str               # "none" | "implicit-TLS" | "STARTTLS-upgraded"
    tls_version: str                # "1.0", "1.1", "1.2", "1.3", "N/A"
    cipher_strength: str            # "HIGH", "MEDIUM", "WEAK", "BROKEN", "N/A"
    starttls_enforcement: str       # "optional", "mandatory", "rejected", "implicit", "none"
    starttls_banner_response: str   # "250-STARTTLS", "454", "suppressed", "none"
    hostname: str = "mail.test.local"


@dataclass(frozen=True)
class ClientSpec:
    """Client connection and verification behavior."""
    sni: Optional[str]              # Expected SNI in ClientHello (RFC 6066 §3)
    tls_presence: str
    starttls_enforcement: str       # "mandatory", "opportunistic_downgrade", "mandatory_abort", "implicit", "none"
    mitm_action: str                # "none", "strip_starttls"
    auth_outcome: str               # "post-TLS-encrypted", "plaintext-attempted", "none"
    client_behavior: str            # Special requirement tag (e.g. resumption, sentinel)


@dataclass(frozen=True)
class NetworkSpec:
    """Network transport and addressing configuration."""
    port: int
    port_type: str                  # "standard" | "non-standard-unknown"
    server_app: str = "postfix"     # "postfix" | "dovecot"
    server_ip: str = "172.28.0.10"
    client_ip: str = "172.28.0.20"


@dataclass(frozen=True)
class OracleSpec:
    """Ground truth expectations used to validate analysis engine output."""
    expected_trust_status: str      # e.g. "TRUSTED_CHAIN", "EXPIRED", "N/A"
    expected_starttls_status: str   # e.g. "UPGRADED", "CLEARTEXT_NO_ENCRYPTION"
    expected_protocol: str          # e.g. "SMTP", "IMAP", "POP3", "Unknown"


@dataclass(frozen=True)
class ScenarioSpec:
    """Complete, decoupled scenario specification."""
    scenario_id: str
    layer: str
    description: str
    protocol: str
    server: ServerSpec
    client: ClientSpec
    network: NetworkSpec
    oracle: OracleSpec
    pki: Optional[PKISpec] = None
    generator_requirement: str = ""
    raw_row: Dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def needs_pki(self) -> bool:
        return self.pki is not None

    @property
    def is_smtp(self) -> bool:
        return self.protocol == "smtp"

    @property
    def is_imap(self) -> bool:
        return self.protocol == "imap"

    @property
    def is_pop3(self) -> bool:
        return self.protocol == "pop3"

    def to_expected_dict(self, selected_cipher: Optional[str] = None) -> Dict[str, Any]:
        """
        Project ScenarioSpec and matrix expectations into a pure expected artifact.
        Deterministic, standalone representation of scenario intent with zero analyzer leakage.
        """
        def _parse_bool(val: Optional[str]) -> Optional[bool]:
            if not val or val.strip() in ("", "N/A"):
                return None
            return val.strip().lower() in ("true", "1", "yes")

        fwd_sec = _parse_bool(self.raw_row.get("forward_secrecy"))
        hrr = _parse_bool(self.raw_row.get("hello_retry_request"))
        sig_alg_cert_present = _parse_bool(self.raw_row.get("sig_alg_cert_present"))
        cert_has_san = _parse_bool(self.raw_row.get("cert_has_san"))

        tls_ver = self.server.tls_version
        tls_ver_str = f"TLS {tls_ver}" if tls_ver not in ("N/A", "", None) else None

        raw_cert_obs = self.raw_row.get("certificate_observable", "").strip()
        if raw_cert_obs:
            cert_obs = raw_cert_obs
        elif self.server.tls_presence == "none":
            cert_obs = "NOT_PRESENT"
        elif self.server.tls_version == "1.3":
            cert_obs = "ENCRYPTED"
        elif self.needs_pki:
            cert_obs = "VISIBLE"
        else:
            cert_obs = "NOT_PRESENT"

        is_fatal_alert = (self.generator_requirement == "server_sends_fatal_alert")
        is_tls = (self.server.tls_presence != "none") and not is_fatal_alert
        has_cert = (self.needs_pki or cert_obs in ("VISIBLE", "ENCRYPTED")) and not is_fatal_alert
        cert_observability = "conditional" if cert_obs == "ENCRYPTED" else ("always" if (cert_obs == "VISIBLE" and not is_fatal_alert) else "not_applicable")

        # Resolve exact cipher if not explicitly provided
        if selected_cipher is None and is_tls:
            try:
                from testbed.runner.resolver import resolve_scenario, ResolutionStatus
                res = resolve_scenario(self)
                if res.cipher_resolution_status in (ResolutionStatus.CONFIGURABLE_CANDIDATE_SELECTED, ResolutionStatus.RESOLVED):
                    selected_cipher = res.selected_cipher
            except Exception:
                selected_cipher = None

        exact_cipher_val = selected_cipher if (is_tls and selected_cipher) else None

        expected_data: Dict[str, Any] = {
            "protocol": self.protocol.upper(),
            "tls_presence": self.server.tls_presence,
            "starttls_integrity": self.raw_row.get("starttls_integrity", "N/A"),
            "tls_version": self.server.tls_version,
            "cipher_strength": self.server.cipher_strength,
            "cert_validity": self.raw_row.get("cert_validity", "N/A"),
            "cert_chain_shape": self.raw_row.get("cert_chain_shape", "N/A"),
            "cert_sig_algo": self.raw_row.get("cert_sig_algo", "N/A"),
            "hostname_match": self.raw_row.get("hostname_match", "N/A"),
            "auth_outcome": self.client.auth_outcome,
            "expected_starttls_status": self.oracle.expected_starttls_status,
            "expected_trust_status": self.oracle.expected_trust_status,
            "tls13_kex_mode": self.raw_row.get("tls13_kex_mode", ""),
            "tls12_kex_type": self.raw_row.get("tls12_kex_type", ""),
            "forward_secrecy": fwd_sec,
            "hello_retry_request": hrr,
            "downgrade_sentinel": self.raw_row.get("downgrade_sentinel", "none"),
            "starttls_outcome": self.raw_row.get("starttls_outcome", ""),
            "sig_alg_cert_present": sig_alg_cert_present,
            "cert_has_san": cert_has_san,
            "hostname_type": self.raw_row.get("hostname_type", ""),
            "path_selection": self.raw_row.get("path_selection", ""),
            "certificate_observable": cert_obs,
            "generator_requirement": self.generator_requirement,
            "exact_cipher": exact_cipher_val,
        }

        if self.layer:
            expected_data["layer"] = self.layer
        if self.description:
            expected_data["description"] = self.description

        assertions: Dict[str, Any] = {
            "protocol": {
                "expected": self.protocol.upper(),
                "required": True,
                "observability": "always",
            },
            "starttls_status": {
                "expected": self.oracle.expected_starttls_status if not is_fatal_alert else None,
                "required": not is_fatal_alert,
                "observability": "always" if not is_fatal_alert else "not_applicable",
            },
            "tls_presence": {
                "expected": self.server.tls_presence,
                "required": True,
                "observability": "always",
            },
            "tls.fatal_alert": {
                "expected": True if is_fatal_alert else False,
                "required": is_fatal_alert,
                "observability": "always" if is_fatal_alert else "not_applicable",
            },
            "tls.version": {
                "expected": tls_ver_str if not is_fatal_alert else None,
                "required": is_tls,
                "observability": "always" if is_tls else "not_applicable",
            },
            "tls.cipher_strength": {
                "expected": (self.server.cipher_strength if self.server.cipher_strength not in ("N/A", "", None) else None) if not is_fatal_alert else None,
                "required": is_tls,
                "observability": "always" if is_tls else "not_applicable",
            },
            "tls.cipher_name": {
                "expected": exact_cipher_val,
                "required": is_tls and (exact_cipher_val is not None),
                "observability": "always" if (is_tls and exact_cipher_val is not None) else "not_applicable",
            },
            "tls.forward_secrecy": {
                "expected": fwd_sec if not is_fatal_alert else None,
                "required": is_tls and fwd_sec is not None,
                "observability": "always" if is_tls else "not_applicable",
            },
            "certificate.observable": {
                "expected": "NOT_PRESENT" if is_fatal_alert else cert_obs,
                "required": True,
                "observability": "always",
            },
            "certificate.signature_algorithm": {
                "expected": (self.raw_row.get("cert_sig_algo") if self.raw_row.get("cert_sig_algo") not in ("N/A", "", None) else None) if not is_fatal_alert else None,
                "required": has_cert,
                "observability": cert_observability,
            },
            "certificate.validity": {
                "expected": (self.raw_row.get("cert_validity") if self.raw_row.get("cert_validity") not in ("N/A", "", None) else None) if not is_fatal_alert else None,
                "required": has_cert,
                "observability": cert_observability,
            },
            "certificate.hostname_match": {
                "expected": (self.raw_row.get("hostname_match") if self.raw_row.get("hostname_match") not in ("N/A", "", None) else None) if not is_fatal_alert else None,
                "required": has_cert,
                "observability": cert_observability,
            },
            "certificate.trust_status": {
                "expected": (self.oracle.expected_trust_status if self.oracle.expected_trust_status not in ("N/A", "", None) else None) if not is_fatal_alert else None,
                "required": has_cert,
                "observability": cert_observability,
            },
        }

        return {
            "schema_version": "1.0",
            "scenario_id": self.scenario_id,
            "expected": expected_data,
            "assertions": assertions,
        }


def parse_scenario_row(row: Dict[str, str]) -> ScenarioSpec:
    """
    Parse a single matrix CSV row into a strongly-typed ScenarioSpec.
    """
    scenario_id = row["scenario_id"]
    proto_raw = row["protocol"]
    protocol = proto_raw.lower()
    tls_presence = row["tls_presence"]
    req = row.get("generator_requirement", "")
    hn_type = row.get("hostname_type", "")
    hn_match = row.get("hostname_match", "")
    port_type_raw = row.get("port_type", "")
    port_type = port_type_raw if port_type_raw else "standard"
    starttls_integrity = row.get("starttls_integrity", "N/A")

    # 1. Port derivation
    if port_type == "non-standard-unknown":
        port = NON_STANDARD_PORTS[protocol]
    else:
        port = STANDARD_PORTS.get((protocol, tls_presence), 25)

    # 2. Server application derivation
    server_app = "postfix" if protocol == "smtp" else "dovecot"

    # 3. PKI & SNI derivation
    pki = None
    sni = None

    # Early exit guard: If cert fields are N/A (cleartext rows, PSK-only resumption,
    # stripped STARTTLS where no TLS occurs on the wire), no PKI profile is generated.
    # ponytail: check cert_sig_algo / cert_chain_shape rather than tls_presence
    # because PSK and stripped rows also have N/A cert attributes.
    has_cert_spec = (
        row.get("cert_chain_shape", "N/A") != "N/A"
        and row.get("cert_sig_algo", "N/A") != "N/A"
    )

    if has_cert_spec:
        sig_algo = SIG_ALGO_MAP[row["cert_sig_algo"]]
        validity = VALIDITY_MAP[row["cert_validity"]]
        chain_shape = CHAIN_SHAPE_MAP[row["cert_chain_shape"]]
        weak_key = "cert_rsa1024" in req

        # SAN & SNI resolution per RFC 6125 and matrix requirements
        if req == "cert_no_san_cn_only":
            # RFC 6125 §6.4.4 fallback to Common Name
            san_type = "no_san"
            sni = "mail.test.local"
        elif hn_type == "ip" or req == "cert_ip_address_san":
            # RFC 5280 §4.2.1.6 iPAddress SAN
            san_type = "ip_san"
            sni = "172.28.0.10"
        elif hn_type == "wildcard" or "wildcard" in req:
            # RFC 6125 §6.4.3 wildcard match / multi-label mismatch
            san_type = "wildcard"
            sni = "a.mail.example.com" if hn_match == "mismatched" else "mail.example.com"
        else:
            # Standard dNSName SAN
            if hn_match == "mismatched":
                san_type = "mismatched_dns"
                sni = "mail.test.local"
            else:
                san_type = "matched_dns"
                sni = "mail.test.local"

        # Leaf key derivation decoupled from sig_algo (RFC 5280)
        explicit_leaf_type = row.get("server_leaf_key_type")
        if explicit_leaf_type:
            leaf_key_algo = explicit_leaf_type.lower().strip()
            leaf_key_size = 1024 if (weak_key or "1024" in req) else (256 if leaf_key_algo == "ecdsa" else 2048)
        elif weak_key or "1024" in req:
            leaf_key_algo = "rsa"
            leaf_key_size = 1024
        else:
            leaf_key_algo = None
            leaf_key_size = None

        pki = PKISpec(
            sig_algo=sig_algo,
            validity=validity,
            chain_shape=chain_shape,
            san_type=san_type,
            weak_key=weak_key,
            leaf_key_algo=leaf_key_algo,
            leaf_key_size=leaf_key_size,
        )
    elif tls_presence != "none":
        # Scenarios where TLS is negotiated or attempted without a certificate profile in the matrix
        # (e.g. PSK resumption PCAP-106/107, fatal alert PCAP-121, stripped STARTTLS PCAP-064..069)
        if hn_type == "ip":
            sni = "172.28.0.10"
        elif hn_type == "wildcard":
            sni = "a.mail.example.com" if hn_match == "mismatched" else "mail.example.com"
        else:
            sni = "mail.test.local"

    # 4. Server configuration derivation
    if tls_presence == "STARTTLS-upgraded":
        if starttls_integrity == "rejected" or req == "server_rejects_starttls":
            server_starttls_enforcement = "rejected"
            server_banner = "454"
        elif starttls_integrity == "no-advertisement":
            server_starttls_enforcement = "optional"
            server_banner = "suppressed"
        else:
            server_starttls_enforcement = "optional"
            server_banner = "250-STARTTLS"
    elif tls_presence == "implicit-TLS":
        server_starttls_enforcement = "implicit"
        server_banner = "none"
    else:
        server_starttls_enforcement = "none"
        server_banner = "none"

    server_spec = ServerSpec(
        server_app=server_app,
        protocol=protocol,
        port=port,
        tls_presence=tls_presence,
        tls_version=row.get("tls_version", "N/A"),
        cipher_strength=row.get("cipher_strength", "N/A"),
        starttls_enforcement=server_starttls_enforcement,
        starttls_banner_response=server_banner,
        hostname="mail.test.local",
    )

    # 5. Client behavior & MITM action derivation
    if starttls_integrity in ("stripped-broken-client", "stripped-broken-server"):
        mitm_action = "strip_starttls"
    else:
        mitm_action = "none"

    if tls_presence == "STARTTLS-upgraded":
        if starttls_integrity == "stripped-broken-client":
            client_starttls_enforcement = "opportunistic_downgrade"
        elif starttls_integrity == "stripped-broken-server":
            client_starttls_enforcement = "mandatory_abort"
        else:
            client_starttls_enforcement = "mandatory"
    elif tls_presence == "implicit-TLS":
        client_starttls_enforcement = "implicit"
    else:
        client_starttls_enforcement = "none"

    client_spec = ClientSpec(
        sni=sni,
        tls_presence=tls_presence,
        starttls_enforcement=client_starttls_enforcement,
        mitm_action=mitm_action,
        auth_outcome=row.get("auth_outcome", "none"),
        client_behavior=req,
    )

    # 6. Network configuration
    server_ip = DEFAULT_SERVICE_ENDPOINTS.get(server_app, "172.28.0.10")
    client_ip = DEFAULT_SERVICE_ENDPOINTS.get("client", "172.28.0.20")
    network_spec = NetworkSpec(
        port=port,
        port_type=port_type,
        server_app=server_app,
        server_ip=server_ip,
        client_ip=client_ip,
    )

    # 7. Oracle expectations
    oracle_spec = OracleSpec(
        expected_trust_status=row["expected_trust_status"],
        expected_starttls_status=row["expected_starttls_status"],
        expected_protocol=row.get("expected_protocol") or proto_raw,
    )

    return ScenarioSpec(
        scenario_id=scenario_id,
        layer=row.get("layer", ""),
        description=row.get("description", ""),
        protocol=protocol,
        server=server_spec,
        client=client_spec,
        network=network_spec,
        oracle=oracle_spec,
        pki=pki,
        generator_requirement=req,
        raw_row=dict(row),
    )


def load_matrix(csv_path: str | Path = "data/pcap_generation_matrix.csv") -> List[ScenarioSpec]:
    """Load and normalize all rows from the PCAP generation matrix CSV."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Matrix file not found: {path}")

    specs: List[ScenarioSpec] = []
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            spec = parse_scenario_row(row)
            specs.append(spec)
    return specs
