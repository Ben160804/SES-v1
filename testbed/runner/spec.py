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
from typing import Dict, List, Optional
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
    server_ip: str = "172.28.0.10"
    client_ip: str = "172.28.0.1"


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

        pki = PKISpec(
            sig_algo=sig_algo,
            validity=validity,
            chain_shape=chain_shape,
            san_type=san_type,
            weak_key=weak_key,
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
    network_spec = NetworkSpec(
        port=port,
        port_type=port_type,
        server_ip="172.28.0.10",
        client_ip="172.28.0.1",
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
