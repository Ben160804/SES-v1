"""
testbed/runner/resolver.py
==========================
Authoritative, Traceable, Zero-Invention TLS Cipher Resolver.

Architecture:
-------------
Derives cipher suite candidate sets, runtime supportability, and resolution
status strictly from repository sources of truth:
  1. Scenario specifications from data/pcap_generation_matrix.csv
  2. Official IANA TLS Parameters database from data/tls_ciphers.csv
  3. Classification models in analysis/ciphers.py
  4. Dynamically measured OpenSSL / Postfix runtime capabilities
  5. RFC protocol compatibility constraints

Critical Rules (Zero Invention & Anti-Hardcoding):
--------------------------------------------------
  - No synthetic project policies (e.g. HIGH -> AES-256-GCM).
  - No heuristic cipher mappings (e.g. WEAK -> 3DES, BROKEN -> RC4).
  - No fallback selections (e.g. choosing first candidate when multiple remain).
  - If multiple runtime candidates remain, selected_cipher is None and status is MULTIPLE_CANDIDATES.
  - Every candidate reduction step is recorded in traceable_constraints.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure project root is on sys.path
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from analysis.ciphers import (
    load_iana_cipher_database,
    iana_to_openssl,
    openssl_to_iana,
    get_cipher_info,
)
from testbed.runner.spec import ScenarioSpec


class UnresolvableScenarioError(RuntimeError):
    """Raised when a scenario cannot be staged due to missing/contradictory cipher constraints."""
    pass


class ResolutionStatus(str, Enum):
    """Categorical outcome of cipher suite constraint solving."""
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNIQUE = "UNIQUE"
    MULTIPLE_CANDIDATES = "MULTIPLE_CANDIDATES"
    NO_CANDIDATE = "NO_CANDIDATE"
    NO_CANDIDATE_UNDER_CURRENT_PROJECT_MODEL = "NO_CANDIDATE_UNDER_CURRENT_PROJECT_MODEL"
    PROTOCOL_IMPOSSIBILITY = "PROTOCOL_IMPOSSIBILITY"
    SPECIAL_SCENARIO = "SPECIAL_SCENARIO"


class RuntimeStatus(str, Enum):
    """Compatibility status against measured target runtime."""
    SUPPORTED = "SUPPORTED"
    REQUIRES_LEGACY_RUNTIME = "REQUIRES_LEGACY_RUNTIME"
    CURRENT_RUNTIME_UNSUPPORTED = "CURRENT_RUNTIME_UNSUPPORTED"
    NO_RUNTIME_CANDIDATE = "NO_RUNTIME_CANDIDATE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"


class SelectionBasis(str, Enum):
    """Documented rationale for cipher selection."""
    UNIQUE = "UNIQUE"
    NONE = "NONE"
    EXPLICIT_REPOSITORY_POLICY = "EXPLICIT_REPOSITORY_POLICY"


@dataclass(frozen=True)
class ResolutionResult:
    """
    Complete, traceable resolution record for a scenario's cryptographic intent.
    """
    scenario_id: str
    intent: str
    tls_version: str
    matrix_kex: str
    cert_auth_intent: str
    matrix_cipher_strength: str

    iana_candidates: List[str]
    iana_candidate_count: int

    current_runtime_candidates: List[str]
    current_runtime_candidate_count: int

    selected_cipher: Optional[str]
    selection_basis: SelectionBasis

    cipher_resolution_status: ResolutionStatus
    runtime_status: RuntimeStatus

    reason: str
    missing_information: Optional[str] = None
    traceable_constraints: Dict[str, Any] = field(default_factory=dict)
    strength_discrepancy: Optional[str] = None
    special_harness_requirement: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to serializable dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "intent": self.intent,
            "tls_version": self.tls_version,
            "matrix_kex": self.matrix_kex,
            "cert_auth_intent": self.cert_auth_intent,
            "matrix_cipher_strength": self.matrix_cipher_strength,
            "iana_candidates": self.iana_candidates,
            "iana_candidate_count": self.iana_candidate_count,
            "current_runtime_candidates": self.current_runtime_candidates,
            "current_runtime_candidate_count": self.current_runtime_candidate_count,
            "selected_cipher": self.selected_cipher,
            "selection_basis": self.selection_basis.value,
            "cipher_resolution_status": self.cipher_resolution_status.value,
            "runtime_status": self.runtime_status.value,
            "reason": self.reason,
            "missing_information": self.missing_information,
            "traceable_constraints": self.traceable_constraints,
            "strength_discrepancy": self.strength_discrepancy,
            "special_harness_requirement": self.special_harness_requirement,
        }


# ==============================================================================
# Runtime Capability Abstraction
# ==============================================================================

class RuntimeCapabilityInspector(ABC):
    """Abstract interface for inspecting target runtime TLS cipher capabilities."""

    @property
    @abstractmethod
    def runtime_name(self) -> str:
        """Identifying name of the runtime environment."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if target runtime environment is accessible."""
        pass

    @abstractmethod
    def probe_supported_ciphers(self) -> Set[str]:
        """
        Probe runtime to discover all natively supported cipher suites across
        TLS <= 1.2 and TLS 1.3.
        Returns a set of normalized 4-character hex strings (e.g. {'0x1301', '0xc030'}).
        """
        pass


class ContainerRuntimeInspector(RuntimeCapabilityInspector):
    """
    Probes cipher capabilities directly inside a running Docker container
    (e.g. mailtest-postfix container running Debian Bookworm with OpenSSL 3.0.20).
    """

    def __init__(self, container_name: str = "mailtest-postfix"):
        self._container_name = container_name

    @property
    def runtime_name(self) -> str:
        return f"docker:{self._container_name}"

    def is_available(self) -> bool:
        try:
            res = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self._container_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0 and res.stdout.strip() == "true"
        except Exception:
            return False

    def probe_supported_ciphers(self) -> Set[str]:
        if not self.is_available():
            raise RuntimeError(f"Target container '{self._container_name}' is not running or accessible")

        supported_hex: Set[str] = set()
        cmd = [
            "docker", "exec", self._container_name,
            "openssl", "ciphers", "-V",
            "-ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256",
            "ALL:COMPLEMENTOFALL:@SECLEVEL=0",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "-":
                hex_part = parts[0]
                if "," in hex_part:
                    b1, b2 = hex_part.split(",")
                    hex_id = f"0x{int(b1, 16):02x}{int(b2, 16):02x}".lower()
                    supported_hex.add(hex_id)

        return supported_hex


class StaticRuntimeInspector(RuntimeCapabilityInspector):
    """
    Deterministic inspector using an explicitly provided set of cipher hex codes.
    Used for unit testing and offline verification.
    """

    def __init__(self, ciphers: Set[str], name: str = "static"):
        self._ciphers = set(ciphers)
        self._name = name

    @property
    def runtime_name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return True

    def probe_supported_ciphers(self) -> Set[str]:
        return set(self._ciphers)


# ==============================================================================
# Authoritative TLS Cipher Resolver
# ==============================================================================

class TLSCipherResolver:
    """
    Zero-invention cipher resolver evaluating scenarios against IANA and runtime evidence.
    """

    def __init__(
        self,
        iana_db: Optional[Dict[str, Dict[str, Any]]] = None,
        runtime_inspector: Optional[RuntimeCapabilityInspector] = None,
        runtime_supported_hex: Optional[Set[str]] = None,
    ):
        self.iana_db = iana_db if iana_db is not None else load_iana_cipher_database()

        if runtime_supported_hex is not None:
            self.runtime_inspector: RuntimeCapabilityInspector = StaticRuntimeInspector(runtime_supported_hex)
            self.runtime_available = True
            self.runtime_supported_hex = set(runtime_supported_hex)
        else:
            self.runtime_inspector = runtime_inspector or ContainerRuntimeInspector()
            if self.runtime_inspector.is_available():
                try:
                    self.runtime_supported_hex = self.runtime_inspector.probe_supported_ciphers()
                    self.runtime_available = True
                except Exception:
                    self.runtime_supported_hex = set()
                    self.runtime_available = False
            else:
                self.runtime_supported_hex = set()
                self.runtime_available = False

    def resolve(self, spec: ScenarioSpec | Dict[str, Any]) -> ResolutionResult:
        """
        Traceably resolve cipher suite constraints for a scenario.
        """
        if isinstance(spec, ScenarioSpec):
            sid = spec.scenario_id
            pres = spec.server.tls_presence
            ver = spec.server.tls_version
            matrix_strength = spec.server.cipher_strength
            kex12 = spec.raw_row.get("tls12_kex_type", "")
            kex13 = spec.raw_row.get("tls13_kex_mode", "")
            sig = spec.raw_row.get("cert_sig_algo", "N/A")
            leaf_key_type = spec.raw_row.get("server_leaf_key_type")
            req = spec.generator_requirement
            intg = spec.raw_row.get("starttls_integrity", "N/A")
            proto = spec.protocol
            layer = spec.layer
            desc = spec.description
        else:
            sid = spec.get("scenario_id", "")
            pres = spec.get("tls_presence", "none")
            ver = spec.get("tls_version", "N/A")
            matrix_strength = spec.get("cipher_strength", "N/A")
            kex12 = spec.get("tls12_kex_type", "")
            kex13 = spec.get("tls13_kex_mode", "")
            sig = spec.get("cert_sig_algo", "N/A")
            leaf_key_type = spec.get("server_leaf_key_type")
            req = spec.get("generator_requirement", "")
            intg = spec.get("starttls_integrity", "N/A")
            proto = spec.get("protocol", "SMTP")
            layer = spec.get("layer", "")
            desc = spec.get("description", "")

        matrix_kex = kex13 if kex13 else (kex12 if kex12 else "(none)")
        cert_auth_intent = sig if sig else "N/A"
        intent = desc if desc else f"{proto} {pres} ({layer})".strip()

        # -------------------------------------------------------------------
        # Phase 1: Pre-TLS / Special / Negative Evaluation
        # -------------------------------------------------------------------
        if pres == "none":
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                iana_candidates=[],
                iana_candidate_count=0,
                current_runtime_candidates=[],
                current_runtime_candidate_count=0,
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                cipher_resolution_status=ResolutionStatus.NOT_APPLICABLE,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                reason="Cleartext SMTP protocol interaction; no TLS negotiation occurs on wire",
                missing_information=None,
                traceable_constraints={"protocol_mode": "cleartext_no_tls"},
            )

        if intg in ("stripped-broken-client", "stripped-broken-server"):
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                iana_candidates=[],
                iana_candidate_count=0,
                current_runtime_candidates=[],
                current_runtime_candidate_count=0,
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                cipher_resolution_status=ResolutionStatus.NOT_APPLICABLE,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                reason=f"Adversarial network tampering ({intg}) suppresses STARTTLS; TLS handshake is not reached",
                missing_information=None,
                traceable_constraints={"starttls_integrity": intg},
                special_harness_requirement="mitm_starttls_strip",
            )

        if req == "server_rejects_starttls":
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                iana_candidates=[],
                iana_candidate_count=0,
                current_runtime_candidates=[],
                current_runtime_candidate_count=0,
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                cipher_resolution_status=ResolutionStatus.NOT_APPLICABLE,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                reason="Server returns 454 rejection to STARTTLS; protocol terminates before TLS ClientHello",
                missing_information=None,
                traceable_constraints={"generator_requirement": req},
                special_harness_requirement="server_rejects_starttls",
            )

        if req == "protocol_proxy_or_modified_server" or intg == "no-advertisement":
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                iana_candidates=[],
                iana_candidate_count=0,
                current_runtime_candidates=[],
                current_runtime_candidate_count=0,
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                cipher_resolution_status=ResolutionStatus.NOT_APPLICABLE,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                reason="STARTTLS not advertised by server; client sends unadvertised STARTTLS; TLS cipher selection is not applicable at this stage",
                missing_information="Protocol execution requirement: testbed harness must simulate unadvertised STARTTLS command handling without TLS negotiation",
                traceable_constraints={"generator_requirement": req, "starttls_integrity": intg},
                special_harness_requirement="unadvertised_starttls",
            )

        # Negative TLS scenario (deliberate cipher mismatch / fatal alert)
        if req == "server_sends_fatal_alert":
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                iana_candidates=[],
                iana_candidate_count=0,
                current_runtime_candidates=[],
                current_runtime_candidate_count=0,
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                cipher_resolution_status=ResolutionStatus.SPECIAL_SCENARIO,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                reason="Negative TLS handshake test: deliberate client/server cipher suite mismatch causing handshake failure (fatal alert); ordinary positive cipher-suite resolution is not applicable",
                missing_information="Negative test harness requirement: client_offered_set ∩ server_enabled_set = empty to trigger fatal alert",
                traceable_constraints={"generator_requirement": req},
                special_harness_requirement="server_sends_fatal_alert",
            )

        # -------------------------------------------------------------------
        # Phase 2: Structural Filtering against IANA Database
        # -------------------------------------------------------------------
        trace: Dict[str, Any] = {
            "initial_iana_universe": len(self.iana_db),
        }

        # Step 2a: Version Filtering
        version_pool: List[Tuple[str, Dict[str, Any]]] = []
        if ver == "1.3":
            # RFC 8446 §1.2 & §B.4: Only suites defined for TLS 1.3
            version_pool = [
                (hid, d) for hid, d in self.iana_db.items()
                if d["kex"] == "TLS13_EPHEMERAL"
            ]
            trace["version_filter"] = {
                "rule": "RFC 8446 TLS 1.3 symmetric-only suites (kex=TLS13_EPHEMERAL)",
                "count": len(version_pool),
            }
        elif ver == "1.2":
            # RFC 5246: Exclude TLS 1.3-only suites
            version_pool = [
                (hid, d) for hid, d in self.iana_db.items()
                if d["kex"] != "TLS13_EPHEMERAL"
            ]
            trace["version_filter"] = {
                "rule": "RFC 5246 TLS 1.2 suites (excluding TLS 1.3)",
                "count": len(version_pool),
            }
        elif ver in ("1.0", "1.1"):
            # Limitation note: data/tls_ciphers.csv contains no authoritative version metadata.
            # Excluding TLS 1.3 (kex=TLS13_EPHEMERAL), AEAD (GCM/CCM/Poly1305), and SHA-256/384 PRF
            # is an external RFC-knowledge heuristic (RFC 2246 / RFC 4346 / RFC 5246),
            # not an authoritative attribute in the IANA registry database.
            for hid, d in self.iana_db.items():
                if d["kex"] == "TLS13_EPHEMERAL":
                    continue
                name = d["name"]
                if any(a in name for a in ("_GCM_", "_POLY1305", "_CCM", "_SHA256", "_SHA384")):
                    continue
                version_pool.append((hid, d))
            trace["version_filter"] = {
                "rule": f"RFC 2246/4346 TLS {ver} suites (heuristic exclusion of AEAD, SHA256/384 PRF, and TLS 1.3)",
                "count": len(version_pool),
                "limitation": "data/tls_ciphers.csv lacks version metadata; version boundaries are heuristic approximations",
            }
        else:
            version_pool = list(self.iana_db.items())
            trace["version_filter"] = {"rule": "Unconstrained", "count": len(version_pool)}

        # Step 2b: Key Exchange (KEX) Filtering
        kex_pool: List[Tuple[str, Dict[str, Any]]] = []
        if ver in ("1.0", "1.1", "1.2"):
            if kex12 == "DHE":
                kex_pool = [
                    (hid, d) for hid, d in version_pool
                    if "DHE_RSA" in d["name"] or "DHE_DSS" in d["name"] or "DHE_PSK" in d["name"]
                ]
                trace["kex_filter"] = {"rule": "Explicit DHE key exchange", "count": len(kex_pool)}
            elif kex12 == "ECDHE":
                kex_pool = [
                    (hid, d) for hid, d in version_pool
                    if "ECDHE_RSA" in d["name"] or "ECDHE_ECDSA" in d["name"] or "ECDHE_PSK" in d["name"]
                ]
                trace["kex_filter"] = {"rule": "Explicit ECDHE key exchange", "count": len(kex_pool)}
            else:
                kex_pool = list(version_pool)
                trace["kex_filter"] = {"rule": "Matrix KEX omitted (retaining static RSA, DHE, ECDHE)", "count": len(kex_pool)}
        else:
            # TLS 1.3: RFC 8446 cipher suites do not encode KEX
            kex_pool = list(version_pool)
            trace["kex_filter"] = {
                "rule": "RFC 8446 KEX decoupled from cipher suites (governed by supported_groups/key_share extensions)",
                "count": len(kex_pool),
            }

        # Step 2c: Certificate & Signature Authentication Analysis
        # Semantic Contract Audit:
        # `cert_sig_algo` in data/pcap_generation_matrix.csv and data/sidecar_schema.json
        # represents the X.509 certificate signature algorithm (how the issuing CA signed
        # the leaf certificate), NOT the server's leaf public-key / TLS authentication type.
        # In TLS (RFC 5246 §7.4.2, RFC 8446 §1.2), the certificate's signature algorithm
        # does not constrain the wire cipher suite. The cipher suite specifies the server's
        # authentication method based on the leaf's SubjectPublicKeyInfo, not its signatureAlgorithm.
        # If server_leaf_key_type is explicitly modeled, it constrains TLS 1.2 authentication.
        # If omitted (as in current matrix rows), cipher suites are NOT filtered by cert_sig_algo.
        auth_pool: List[Tuple[str, Dict[str, Any]]] = []
        rfc_impossible = False
        rfc_prohibition_reason = ""

        if ver in ("1.0", "1.1"):
            if leaf_key_type == "Ed25519":
                # RFC 2246 §4.7 / RFC 4346 §4.7 only define RSA and DSA signatures (and RFC 4492 for ECDSA).
                # Ed25519 leaf key authentication is defined for TLS 1.2+ using the signature_algorithms extension
                # (RFC 8410 for SubjectPublicKeyInfo; RFC 8446 §4.2.3 SignatureScheme 0x0807; RFC 5246 §7.4.1.4.1).
                # Only when an explicit Ed25519 leaf key is configured does the server have no shared cipher suites
                # and cannot negotiate TLS 1.0 or 1.1 on the wire.
                rfc_impossible = True
                rfc_prohibition_reason = (
                    f"RFC protocol impossibility: Ed25519 leaf key authentication is not defined in TLS {ver} "
                    f"(RFC 2246 / RFC 4346 §4.7; RFC 8410; RFC 8446 §4.2.3; RFC 5246 §7.4.1.4.1)"
                )
                auth_pool = []
                trace["auth_filter"] = {
                    "rule": f"Explicit server_leaf_key_type=Ed25519 is undefined in TLS {ver} (RFC 2246/4346 §4.7; RFC 8446 §4.2.3)",
                    "count": 0,
                }
            else:
                # cert_sig_algo represents the X.509 certificate signature algorithm (how the CA signed the leaf)
                # and does not constrain TLS cipher suites (RFC 5246 §7.4.2). An Ed25519 CA can issue an RSA leaf.
                auth_pool = list(kex_pool)
                trace["auth_filter"] = {
                    "rule": f"cert_sig_algo={sig} represents X.509 certificate signature algorithm; does not constrain TLS {ver} cipher suites",
                    "count": len(auth_pool),
                }
        elif ver == "1.2" and leaf_key_type:
            if leaf_key_type == "ECDSA":
                auth_pool = [(hid, d) for hid, d in kex_pool if "ECDSA" in d["name"]]
                trace["auth_filter"] = {
                    "rule": "Explicit server_leaf_key_type=ECDSA requires ECDSA authentication (RFC 5246 §7.4.2)",
                    "count": len(auth_pool),
                }
            elif leaf_key_type == "RSA":
                auth_pool = [(hid, d) for hid, d in kex_pool if "RSA" in d["name"]]
                trace["auth_filter"] = {
                    "rule": "Explicit server_leaf_key_type=RSA requires RSA authentication (RFC 5246 §7.4.2)",
                    "count": len(auth_pool),
                }
            else:
                auth_pool = list(kex_pool)
                trace["auth_filter"] = {
                    "rule": f"Explicit server_leaf_key_type={leaf_key_type}",
                    "count": len(auth_pool),
                }
        else:
            # TLS 1.2 (unspecified leaf_key_type) and TLS 1.3:
            # TLS 1.3 cipher suites are decoupled from authentication (RFC 8446 §1.2).
            # TLS 1.2 cipher suites specify server public-key auth, but the matrix does not specify
            # server leaf public-key type (cert_sig_algo is only the CA signature algorithm).
            auth_pool = list(kex_pool)
            trace["auth_filter"] = {
                "rule": f"TLS {ver} cipher suites unconstrained by cert_sig_algo={sig} (X.509 issuer signature algorithm)",
                "count": len(auth_pool),
            }

        # Step 2d: IANA Candidate Pool (Strictly Structural Constraints)
        # cipher_strength is NOT a generator input; candidates are derived purely
        # from protocol version, KEX, and certificate/signature authentication.
        iana_candidates = [d["name"] for hid, d in auth_pool]
        trace["iana_candidate_count"] = len(iana_candidates)

        # Oracle / Expected Attribute Evaluation: cipher_strength
        cand_strengths = {d["strength"] for hid, d in auth_pool}
        strength_discrepancy = None
        if matrix_strength not in ("N/A", "") and auth_pool:
            if matrix_strength not in cand_strengths:
                strength_discrepancy = (
                    f"Oracle expectation mismatch: matrix specifies cipher_strength='{matrix_strength}', "
                    f"but structural candidates only achieve {sorted(cand_strengths)} in analysis/ciphers.py"
                )
        trace["oracle_cipher_strength"] = {
            "expected_strength": matrix_strength,
            "candidate_achievable_strengths": sorted(cand_strengths),
            "discrepancy": strength_discrepancy,
        }

        # -------------------------------------------------------------------
        # Phase 3: Runtime Intersection
        # -------------------------------------------------------------------
        if not self.runtime_available:
            runtime_cands: List[str] = []
        else:
            runtime_cands = [
                d["name"] for hid, d in auth_pool
                if hid in self.runtime_supported_hex
            ]
        trace["runtime_supported_count"] = len(runtime_cands)

        # Detect special harness requirements
        special_harness = None
        if req == "psk_resumption_without_cert":
            special_harness = "psk_resumption"
        elif req == "psk_dhe_resumption_without_cert":
            special_harness = "psk_dhe_resumption"
        elif req == "client_group_mismatch_then_retry":
            special_harness = "hello_retry_request"
        elif req == "server_downgrade_with_sentinel":
            special_harness = "downgrade_sentinel"
        elif req == "legacy_client_server_with_sentinel":
            special_harness = "legacy_client_sentinel"
        elif req == "server_downgrade_without_sentinel":
            special_harness = "sentinel_suppression"
        elif req == "client_cert_sig_alg_ext50":
            special_harness = "custom_extension_50"
        elif req == "custom_multi_issuer_pki":
            special_harness = "dag_pki"
        elif req == "psk_resumption_with_early_data":
            special_harness = "early_data_0rtt"
        elif req == "cert_rsa1024":
            special_harness = "rsa1024_seclevel0"

        # -------------------------------------------------------------------
        # Phase 4: Zero-Invention Resolution Decision
        # -------------------------------------------------------------------
        if rfc_impossible:
            status = ResolutionStatus.PROTOCOL_IMPOSSIBILITY
            selected_cipher = None
            basis = SelectionBasis.NONE
            rt_status = RuntimeStatus.NO_RUNTIME_CANDIDATE
            reason = rfc_prohibition_reason
            missing_info = f"RFC specification conflict: {sig} leaf authentication is not defined in TLS {ver} (RFC 2246/4346 §4.7; RFC 8410; RFC 8446 §4.2.3)"

        elif len(iana_candidates) == 0:
            status = ResolutionStatus.NO_CANDIDATE
            selected_cipher = None
            basis = SelectionBasis.NONE
            rt_status = RuntimeStatus.NO_RUNTIME_CANDIDATE
            reason = (
                f"No IANA cipher suite satisfies combined structural constraints "
                f"(TLS {ver}, KEX={matrix_kex})"
            )
            missing_info = "No matching IANA cipher suite defined in RFC registry"

        elif not self.runtime_available:
            status = ResolutionStatus.MULTIPLE_CANDIDATES if len(iana_candidates) > 1 else ResolutionStatus.UNIQUE
            selected_cipher = None
            basis = SelectionBasis.NONE
            rt_status = RuntimeStatus.RUNTIME_UNAVAILABLE
            reason = f"Target runtime '{self.runtime_inspector.runtime_name}' is unreachable; cannot probe cipher capabilities"
            missing_info = "Runtime probe unavailable: container unreachable"

        elif len(runtime_cands) == 0:
            status = ResolutionStatus.NO_CANDIDATE
            selected_cipher = None
            basis = SelectionBasis.NONE
            has_legacy = any(
                any(bad in c for bad in ("3DES", "RC4", "DES")) or "ECDH_" in c
                for c in iana_candidates
            )
            if has_legacy:
                rt_status = RuntimeStatus.REQUIRES_LEGACY_RUNTIME
                reason = (
                    f"Structural candidates exist in IANA ({len(iana_candidates)} suites) but require "
                    f"legacy runtime support (3DES/RC4/DES/static ECDH) disabled in current OpenSSL build"
                )
                missing_info = "Runtime capability: requires legacy OpenSSL provider or legacy mail server runtime"
            else:
                rt_status = RuntimeStatus.CURRENT_RUNTIME_UNSUPPORTED
                reason = (
                    f"Structural candidates exist in IANA ({len(iana_candidates)} suites) but are "
                    f"unsupported by current OpenSSL runtime"
                )
                missing_info = "Runtime capability: unsupported by current OpenSSL runtime"

        elif len(runtime_cands) == 1:
            status = ResolutionStatus.UNIQUE
            selected_cipher = runtime_cands[0]
            basis = SelectionBasis.UNIQUE
            rt_status = RuntimeStatus.SUPPORTED
            reason = "Exactly one candidate suite satisfies all repository structural constraints and runtime support"
            if strength_discrepancy:
                reason += f" [{strength_discrepancy}]"
            missing_info = None

        else:
            status = ResolutionStatus.MULTIPLE_CANDIDATES
            selected_cipher = None
            basis = SelectionBasis.NONE
            rt_status = RuntimeStatus.SUPPORTED
            reason = (
                f"Multiple candidates ({len(runtime_cands)} runtime-supported, "
                f"{len(iana_candidates)} IANA-defined) satisfy structural constraints without further specification"
            )
            if strength_discrepancy:
                reason += f" [{strength_discrepancy}]"

            ed25519_note = ""
            if sig == "Ed25519" and ver == "1.2":
                ed25519_note = " (Note: Ed25519 in TLS 1.2 is decoupled from cipher suite name in RFC 8422)"
            missing_info = (
                f"Matrix does not specify concrete cipher suite; {len(runtime_cands)} candidate suites satisfy "
                f"structural constraints (TLS {ver}, KEX={matrix_kex}, auth={cert_auth_intent}){ed25519_note}"
            )
            if strength_discrepancy:
                missing_info += f"; {strength_discrepancy}"

        return ResolutionResult(
            scenario_id=sid,
            intent=intent,
            tls_version=ver,
            matrix_kex=matrix_kex,
            cert_auth_intent=cert_auth_intent,
            matrix_cipher_strength=matrix_strength,
            iana_candidates=iana_candidates,
            iana_candidate_count=len(iana_candidates),
            current_runtime_candidates=runtime_cands,
            current_runtime_candidate_count=len(runtime_cands),
            selected_cipher=selected_cipher,
            selection_basis=basis,
            cipher_resolution_status=status,
            runtime_status=rt_status,
            reason=reason,
            missing_information=missing_info,
            traceable_constraints=trace,
            strength_discrepancy=strength_discrepancy,
            special_harness_requirement=special_harness,
        )


def resolve_scenario(
    spec: ScenarioSpec | Dict[str, Any],
    resolver: Optional[TLSCipherResolver] = None,
) -> ResolutionResult:
    """Convenience functional interface for resolving a scenario."""
    res = resolver or TLSCipherResolver()
    return res.resolve(spec)
