"""
SecureMailScope Cryptographic Policy & Forensic Rule Engine — Core Schema.

Defines the result models, evidence atoms, and input specification for
evaluating passive email PCAP traffic against independent cryptographic standards
(NIST SP 800-52r2, NIST SP 800-131Ar2, Mozilla Modern/Intermediate) and
policy-neutral forensic observations.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional, TypedDict, Union


@dataclass(frozen=True)
class EvidenceItem:
    """
    Discrete, provenance-tracked evidence atom supporting a policy verdict.
    """
    stream_id: int
    field: str
    value: Any
    source: str
    frame: Optional[int] = None
    context: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if isinstance(d.get("value"), datetime):
            d["value"] = d["value"].isoformat()
        return d


@dataclass(frozen=True)
class PolicyResult:
    """
    Evaluated verdict for a specific normative policy rule.
    Zero cross-contamination between policy standards.
    """
    policy: str               # "NIST-52R2" | "NIST-131A" | "MOZ-MODERN" | "MOZ-INTERM"
    rule_id: str              # e.g. "N52-TLS-01"
    name: str                 # Human-readable title
    source_id: str            # Authoritative extraction ID (e.g. "SP800-52R2-S07")
    source_section: str       # Document section (e.g. "3.1")
    source_text: str          # Verbatim normative text clause
    normative_term: str       # "SHALL" | "SHALL NOT" | "SHOULD" | "SHOULD NOT" | "DISALLOWED" | "PROFILE_REQ"
    applicability_scope: str   # "NIST-GOV-ONLY" | "NIST-CITIZEN-FACING" | "NIST-DEFAULT-PROFILE" | "NIST-131A-GENERAL" | "MOZ-MODERN" | "MOZ-INTERMEDIATE"
    verdict: str              # "PASS" | "FAIL" | "OBSERVATION" | "NOT_OBSERVABLE" | "NOT_APPLICABLE"
    evidence: list[EvidenceItem] = field(default_factory=list)
    finding: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "rule_id": self.rule_id,
            "name": self.name,
            "source_id": self.source_id,
            "source_section": self.source_section,
            "source_text": self.source_text,
            "normative_term": self.normative_term,
            "applicability_scope": self.applicability_scope,
            "verdict": self.verdict,
            "evidence": [e.to_dict() for e in self.evidence],
            "finding": self.finding,
        }


@dataclass(frozen=True)
class ObservationResult:
    """
    Policy-neutral forensic observation describing observable wire protocol phenomena.
    """
    obs_id: str               # e.g. "OBS-STARTTLS-ADVERTISED-NOT-USED"
    name: str                 # Human-readable observation title
    category: str             # "Framing" | "Identity" | "Handshake" | "Trust" | "Observability" | "Security"
    detected: bool            # True if condition was observed
    evidence: list[EvidenceItem] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "obs_id": self.obs_id,
            "name": self.name,
            "category": self.category,
            "detected": self.detected,
            "evidence": [e.to_dict() for e in self.evidence],
            "description": self.description,
        }


@dataclass(frozen=True)
class StreamRuleReport:
    """
    Forensic evaluation report for a single TCP stream.
    """
    stream_id: int
    protocol: str
    policy_results: dict[str, list[PolicyResult]]  # policy_pack_name -> list[PolicyResult]
    observations: list[ObservationResult]
    input_snapshot: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        def _serialize_val(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, dict):
                return {k: _serialize_val(sub_v) for k, sub_v in v.items()}
            if isinstance(v, list):
                return [_serialize_val(item) for item in v]
            return v

        return {
            "stream_id": self.stream_id,
            "protocol": self.protocol,
            "policy_results": {
                pack: [r.to_dict() for r in results]
                for pack, results in self.policy_results.items()
            },
            "observations": [o.to_dict() for o in self.observations],
            "input_snapshot": _serialize_val(self.input_snapshot),
        }


@dataclass(frozen=True)
class SessionReport:
    """
    Aggregate forensic report across all evaluated streams in a PCAP session.
    """
    stream_reports: dict[int, StreamRuleReport]
    total_streams: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_streams": self.total_streams,
            "stream_reports": {
                sid: report.to_dict()
                for sid, report in self.stream_reports.items()
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# Canonical TypedDict Definitions for RuleInput
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzerTrustStoreInfo(TypedDict, total=False):
    active_store: str
    description: str
    ca_file_path: Optional[str]
    anchored: bool
    verification_error: Optional[str]


class DowngradeSentinelInfo(TypedDict, total=False):
    detected: bool
    type: Optional[str]


class LeafCertFacts(TypedDict, total=False):
    subject_dn: str
    issuer_dn: str
    is_self_signed: bool
    san_dns: list[str]
    san_ip: list[str]
    has_san: bool
    public_key_algorithm: str
    public_key_size: int
    signature_algorithm_name: str
    signature_hash_algorithm: Optional[str]
    signature_params: Optional[str]
    basic_constraints: Optional[dict[str, Any]]
    key_usage: Optional[dict[str, bool]]
    extended_key_usage: list[str]
    has_eku_extension: bool
    has_server_auth_eku: bool
    has_any_eku: bool
    not_before: datetime
    not_after: datetime
    lifespan_days: int
    is_expired_at_capture: Optional[bool]
    not_yet_valid_at_capture: Optional[bool]


class NonAnchorCertFacts(TypedDict, total=False):
    path_basis: str
    certs: list[dict[str, Any]]
    min_rsa_key_size: Optional[int]
    min_ec_key_size: Optional[int]
    weak_signature_hashes: list[str]
    any_cert_expired_at_capture: Optional[bool]
    any_cert_not_yet_valid_at_capture: Optional[bool]
    ca_constraint_violated: bool


class HeuristicsInfo(TypedDict, total=False):
    h_cipher_strength: str
    h_forward_secrecy: bool
    h_kex_type: str


class RuleInput(TypedDict, total=False):
    stream_id: int
    protocol: str
    capture_time: Optional[datetime]
    application_data_observed: Union[bool, str]
    analyzer_trust_store: AnalyzerTrustStoreInfo

    raw_version: Optional[str]
    tls_version: Optional[str]
    raw_cipher_suite: Optional[str]
    cipher_name: Optional[str]
    tls13_psk_selected: Optional[bool]
    tls13_key_exchange_group: Optional[str]
    tls13_key_exchange_mode: Optional[str]
    hello_retry_request: bool

    tls12_kex_type: Optional[str]
    tls12_named_curve: Optional[str]
    tls12_dh_prime_bits: Optional[int]
    tls12_wire_sig_alg: Optional[str]

    downgrade_sentinel: DowngradeSentinelInfo
    early_data_offered: bool
    early_data_observed: bool
    handshake_status: Optional[str]
    flight_alerts: list[dict[str, Any]]
    client_aborted_with_alert: bool
    server_aborted_with_alert: bool

    client_offered_versions: list[str]
    client_offered_ciphers: list[str]
    client_supported_groups: list[str]
    client_signature_algorithms: list[str]
    client_sni: Optional[str]
    client_alpn: list[str]

    starttls_offered: bool
    starttls_requested: bool
    starttls_accepted: bool
    starttls_rejected: bool
    plaintext_auth_attempted: bool
    starttls_status: str

    cert_observable: bool
    cert_unobservable_reason: Optional[str]
    chain_length: int
    hostname_match: str
    revocation_status: str

    leaf_cert: Optional[LeafCertFacts]
    non_anchor_cert_facts: Optional[NonAnchorCertFacts]
    heuristics: HeuristicsInfo
