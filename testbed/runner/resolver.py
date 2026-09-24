"""
testbed/runner/resolver.py
==========================
Authoritative, Traceable, Deterministic TLS Cipher & Scenario Contract Resolver.

Architecture:
-------------
Derives cipher suite candidates, runtime supportability, and deterministic
resolution status strictly from repository sources of truth:
  1. Scenario contracts from data/scenario_contracts.json
  2. Scenario specifications from data/pcap_generation_matrix.csv
  3. Official IANA TLS Parameters database from data/tls_ciphers.csv
  4. Classification models in analysis/ciphers.py (HIGH, MEDIUM, WEAK, BROKEN)
  5. Dynamically measured OpenSSL / Postfix runtime capabilities
  6. RFC protocol compatibility constraints

Generation Modes:
-----------------
  - STANDARD: Concrete cryptographic construction (CLASS or EXACT)
  - DEDICATED_HARNESS: Dedicated protocol/MITM/TLS testbed harness
  - UNRESOLVABLE: Contradictory or missing specification preserved explicitly

Deterministic Class Selection Policy:
-------------------------------------
  1. IANA Recommended = 'Y'
  2. IANA Recommended = 'N'
  3. IANA Recommended = 'D' (Deprecated)
  4. Name Ascending (Alphabetical tie-breaker)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import json
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
from testbed.runner.scenario_contract import (
    load_scenario_contracts,
    ScenarioContract,
    GenerationMode,
    CipherMode,
)
from testbed.runner.spec import ScenarioSpec


class UnresolvableScenarioError(RuntimeError):
    """Raised when a scenario cannot be staged due to missing/contradictory cipher constraints."""
    pass


class ResolutionStatus(str, Enum):
    """Categorical outcome of cipher suite and scenario contract resolution."""
    CONFIGURABLE_CANDIDATE_SELECTED = "CONFIGURABLE_CANDIDATE_SELECTED"
    DAEMON_CANNOT_ENFORCE = "DAEMON_CANNOT_ENFORCE"
    UNRESOLVABLE = "UNRESOLVABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SPECIAL_HARNESS = "SPECIAL_HARNESS"

    # Backward compatibility aliases
    RESOLVED = "CONFIGURABLE_CANDIDATE_SELECTED"
    UNIQUE = "CONFIGURABLE_CANDIDATE_SELECTED"
    SPECIAL_SCENARIO = "SPECIAL_HARNESS"
    MULTIPLE_CANDIDATES = "UNRESOLVABLE"
    NO_CANDIDATE = "UNRESOLVABLE"
    NO_CANDIDATE_UNDER_CURRENT_PROJECT_MODEL = "UNRESOLVABLE"
    PROTOCOL_IMPOSSIBILITY = "UNRESOLVABLE"


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
    EXACT_CONTRACT = "EXACT_CONTRACT"


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

    generation_mode: str
    cipher_mode: str

    iana_candidates: List[str]
    iana_candidate_count: int

    runtime_candidates: List[str]
    runtime_candidate_count: int

    daemon_configurable_candidates: List[str]
    daemon_configurable_candidate_count: int

    candidate_count_before_selection: int
    candidate_names_after_all_filters: List[str]

    selected_cipher: Optional[str]
    selection_basis: SelectionBasis
    selection_rank: Optional[int]

    cipher_resolution_status: ResolutionStatus
    runtime_status: RuntimeStatus

    leaf_key_algorithm: Optional[str] = None
    leaf_key_size: Optional[int] = None

    special_harness: Optional[str] = None
    special_harness_parameters: Dict[str, Any] = field(default_factory=dict)
    cipher_telemetry: Dict[str, Any] = field(default_factory=dict)

    reason: str = ""
    missing_information: Optional[str] = None
    traceable_constraints: Dict[str, Any] = field(default_factory=dict)
    strength_discrepancy: Optional[str] = None
    special_harness_requirement: Optional[str] = None

    @property
    def current_runtime_candidates(self) -> List[str]:
        return self.runtime_candidates

    @property
    def current_runtime_candidate_count(self) -> int:
        return self.runtime_candidate_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to serializable dictionary in canonical key order."""
        return {
            "scenario_id": self.scenario_id,
            "intent": self.intent,
            "tls_version": self.tls_version,
            "matrix_kex": self.matrix_kex,
            "cert_auth_intent": self.cert_auth_intent,
            "matrix_cipher_strength": self.matrix_cipher_strength,
            "generation_mode": self.generation_mode,
            "cipher_mode": self.cipher_mode,
            "iana_candidates": self.iana_candidates,
            "iana_candidate_count": self.iana_candidate_count,
            "runtime_candidates": self.runtime_candidates,
            "runtime_candidate_count": self.runtime_candidate_count,
            "current_runtime_candidates": self.runtime_candidates,
            "current_runtime_candidate_count": self.runtime_candidate_count,
            "daemon_configurable_candidates": self.daemon_configurable_candidates,
            "daemon_configurable_candidate_count": self.daemon_configurable_candidate_count,
            "candidate_count_before_selection": self.candidate_count_before_selection,
            "candidate_names_after_all_filters": self.candidate_names_after_all_filters,
            "selected_cipher": self.selected_cipher,
            "selection_basis": self.selection_basis.value,
            "selection_rank": self.selection_rank,
            "cipher_resolution_status": self.cipher_resolution_status.value,
            "runtime_status": self.runtime_status.value,
            "leaf_key_algorithm": self.leaf_key_algorithm,
            "leaf_key_size": self.leaf_key_size,
            "special_harness": self.special_harness,
            "special_harness_requirement": self.special_harness_requirement or self.special_harness,
            "special_harness_parameters": self.special_harness_parameters,
            "cipher_telemetry": self.cipher_telemetry,
            "reason": self.reason,
            "missing_information": self.missing_information,
            "traceable_constraints": self.traceable_constraints,
            "strength_discrepancy": self.strength_discrepancy,
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

    def __init__(
        self,
        container_name: str = "mailtest-postfix",
        iana_db: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self._container_name = container_name
        self._iana_db = iana_db

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
        iana_db = self._iana_db if self._iana_db is not None else load_iana_cipher_database()
        name_to_hex = {d["name"]: hid for hid, d in iana_db.items()}

        # 1. Native TLS 1.3 probe: openssl ciphers -tls1_3 -v
        try:
            cmd_13 = ["docker", "exec", self._container_name, "openssl", "ciphers", "-tls1_3", "-v"]
            proc_13 = subprocess.run(cmd_13, capture_output=True, text=True, check=True, timeout=10)
            for line in proc_13.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    cipher_name = parts[0]
                    if cipher_name in name_to_hex:
                        supported_hex.add(name_to_hex[cipher_name])
        except Exception:
            pass

        # 2. Native TLS <= 1.2 probe: openssl ciphers -V ALL:COMPLEMENTOFALL:@SECLEVEL=0
        cmd_legacy = [
            "docker", "exec", self._container_name,
            "openssl", "ciphers", "-V",
            "ALL:COMPLEMENTOFALL:@SECLEVEL=0",
        ]
        proc = subprocess.run(cmd_legacy, capture_output=True, text=True, check=True, timeout=10)
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
# Authoritative TLS Cipher & Scenario Contract Resolver
# ==============================================================================

class TLSCipherResolver:
    """
    Deterministic scenario contract and cipher resolver.
    """

    def __init__(
        self,
        iana_db: Optional[Dict[str, Dict[str, Any]]] = None,
        runtime_inspector: Optional[RuntimeCapabilityInspector] = None,
        runtime_supported_hex: Optional[Set[str]] = None,
        contracts: Optional[Dict[str, ScenarioContract]] = None,
    ):
        self.iana_db = iana_db if iana_db is not None else load_iana_cipher_database()

        if runtime_supported_hex is not None:
            self.runtime_inspector: RuntimeCapabilityInspector = StaticRuntimeInspector(runtime_supported_hex)
            self.runtime_available = True
            self.runtime_supported_hex = set(runtime_supported_hex)
        else:
            self.runtime_inspector = runtime_inspector or ContainerRuntimeInspector(iana_db=self.iana_db)
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

        if contracts is not None:
            self.contracts = dict(contracts)
        else:
            try:
                self.contracts = load_scenario_contracts()
            except Exception:
                self.contracts = {}

    def resolve(self, spec: ScenarioSpec | Dict[str, Any]) -> ResolutionResult:
        """
        Traceably and deterministically resolve cryptographic constraints for a scenario.
        """
        if isinstance(spec, ScenarioSpec):
            sid = spec.scenario_id
            pres = spec.server.tls_presence
            ver = spec.server.tls_version
            matrix_strength = spec.server.cipher_strength
            kex12 = spec.raw_row.get("tls12_kex_type", "")
            kex13 = spec.raw_row.get("tls13_kex_mode", "")
            sig = spec.raw_row.get("cert_sig_algo", "N/A")
            explicit_leaf_key = spec.raw_row.get("server_leaf_key_type")
            req = spec.generator_requirement
            intg = spec.raw_row.get("starttls_integrity", "N/A")
            proto = spec.protocol
            layer = spec.layer
            desc = spec.description
            needs_pki = spec.needs_pki
        else:
            sid = spec.get("scenario_id", "")
            pres = spec.get("tls_presence", "none")
            ver = spec.get("tls_version", "N/A")
            matrix_strength = spec.get("cipher_strength", "N/A")
            kex12 = spec.get("tls12_kex_type", "")
            kex13 = spec.get("tls13_kex_mode", "")
            sig = spec.get("cert_sig_algo", "N/A")
            explicit_leaf_key = spec.get("server_leaf_key_type")
            req = spec.get("generator_requirement", "")
            intg = spec.get("starttls_integrity", "N/A")
            proto = spec.get("protocol", "SMTP")
            layer = spec.get("layer", "")
            desc = spec.get("description", "")
            needs_pki = (
                spec.get("cert_chain_shape", "N/A") != "N/A"
                and spec.get("cert_sig_algo", "N/A") != "N/A"
            )

        matrix_kex = kex13 if kex13 else (kex12 if kex12 else "(none)")
        cert_auth_intent = sig if sig else "N/A"
        intent = desc if desc else f"{proto} {pres} ({layer})".strip()

        # Contract lookup with fallback for dynamic/test specifications
        contract = self.contracts.get(sid)
        if contract is None:
            if pres == "none":
                contract = ScenarioContract(
                    scenario_id=sid,
                    generation_mode=GenerationMode.STANDARD,
                    cipher_mode=CipherMode.NONE,
                )
            elif req == "server_sends_fatal_alert":
                contract = ScenarioContract(
                    scenario_id=sid,
                    generation_mode=GenerationMode.DEDICATED_HARNESS,
                    cipher_mode=CipherMode.CLASS,
                    special_harness="server_sends_fatal_alert",
                    harness_status="IMPLEMENTED",
                )
            elif req == "server_rejects_starttls":
                contract = ScenarioContract(
                    scenario_id=sid,
                    generation_mode=GenerationMode.DEDICATED_HARNESS,
                    cipher_mode=CipherMode.CLASS,
                    special_harness="server_rejects_starttls",
                    harness_status="IMPLEMENTED",
                )
            elif intg in ("stripped-broken-client", "stripped-broken-server"):
                contract = ScenarioContract(
                    scenario_id=sid,
                    generation_mode=GenerationMode.DEDICATED_HARNESS,
                    cipher_mode=CipherMode.CLASS,
                    special_harness="mitm_starttls_strip",
                    harness_status="IMPLEMENTED",
                )
            elif req == "protocol_proxy_or_modified_server" or intg == "no-advertisement":
                contract = ScenarioContract(
                    scenario_id=sid,
                    generation_mode=GenerationMode.DEDICATED_HARNESS,
                    cipher_mode=CipherMode.CLASS,
                    special_harness="unadvertised_starttls",
                    harness_status="IMPLEMENTED",
                )
            else:
                contract = ScenarioContract(
                    scenario_id=sid,
                    generation_mode=GenerationMode.STANDARD,
                    cipher_mode=CipherMode.CLASS,
                    cipher_class=matrix_strength,
                    leaf_key_algorithm=explicit_leaf_key.lower() if explicit_leaf_key else None,
                )

        # ----------------------------------------------------------------------
        # Case 1: Cleartext Protocol (No TLS on Wire)
        # ----------------------------------------------------------------------
        if pres == "none" or contract.cipher_mode == CipherMode.NONE:
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.STANDARD.value,
                cipher_mode=CipherMode.NONE.value,
                iana_candidates=[],
                iana_candidate_count=0,
                runtime_candidates=[],
                runtime_candidate_count=0,
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.NOT_APPLICABLE,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                leaf_key_algorithm=None,
                leaf_key_size=None,
                special_harness=None,
                special_harness_parameters={},
                cipher_telemetry={},
                reason="Cleartext protocol interaction; no TLS negotiation occurs on wire",
                missing_information=None,
                traceable_constraints={"protocol_mode": "cleartext_no_tls"},
            )

        # ----------------------------------------------------------------------
        # Case 2: Formally Unresolvable Scenario (Matrix Inconsistency)
        # ----------------------------------------------------------------------
        if contract.generation_mode == GenerationMode.UNRESOLVABLE:
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.UNRESOLVABLE.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=[],
                iana_candidate_count=0,
                runtime_candidates=[],
                runtime_candidate_count=0,
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.UNRESOLVABLE,
                runtime_status=RuntimeStatus.NO_RUNTIME_CANDIDATE,
                leaf_key_algorithm=None,
                leaf_key_size=None,
                special_harness=None,
                special_harness_parameters={},
                cipher_telemetry={},
                reason=contract.unresolvable_reason or "Scenario specification is contradictory or missing required information",
                missing_information=contract.missing_information,
                traceable_constraints={"status": "MATRIX_ORACLE_INCONSISTENT"},
                strength_discrepancy=contract.unresolvable_reason,
            )

        # ----------------------------------------------------------------------
        # Case 3: Dedicated Testbed / Protocol Harness
        # ----------------------------------------------------------------------
        if contract.generation_mode == GenerationMode.DEDICATED_HARNESS:
            harness_name = contract.special_harness or req
            is_implemented = contract.harness_status == "IMPLEMENTED"
            missing_info = None if is_implemented else f"Dedicated harness not yet implemented: {harness_name}"
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.DEDICATED_HARNESS.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=[],
                iana_candidate_count=0,
                runtime_candidates=[],
                runtime_candidate_count=0,
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.SPECIAL_HARNESS,
                runtime_status=RuntimeStatus.NOT_APPLICABLE,
                leaf_key_algorithm=contract.leaf_key_algorithm,
                leaf_key_size=contract.leaf_key_size,
                special_harness=harness_name,
                special_harness_requirement=harness_name,
                special_harness_parameters=contract.special_harness_parameters,
                cipher_telemetry={},
                reason=f"Dedicated test harness required: {harness_name} (status: {contract.harness_status})",
                missing_information=missing_info,
                traceable_constraints={"dedicated_harness": harness_name},
            )

        # ----------------------------------------------------------------------
        # Case 4: Standard Scenario (CLASS or EXACT Mode)
        # ----------------------------------------------------------------------
        trace: Dict[str, Any] = {
            "initial_iana_universe": len(self.iana_db),
        }

        # Step 4a: Version Filtering
        version_pool: List[Tuple[str, Dict[str, Any]]] = []
        if ver == "1.3":
            version_pool = [
                (hid, d) for hid, d in self.iana_db.items()
                if d.get("kex") == "TLS13_EPHEMERAL"
            ]
            trace["version_filter"] = {
                "rule": "RFC 8446 TLS 1.3 symmetric-only suites (kex=TLS13_EPHEMERAL)",
                "count": len(version_pool),
            }
        elif ver == "1.2":
            version_pool = [
                (hid, d) for hid, d in self.iana_db.items()
                if d.get("kex") != "TLS13_EPHEMERAL"
            ]
            trace["version_filter"] = {
                "rule": "RFC 5246 TLS 1.2 suites (excluding TLS 1.3)",
                "count": len(version_pool),
            }
        elif ver in ("1.0", "1.1"):
            for hid, d in self.iana_db.items():
                if d.get("kex") == "TLS13_EPHEMERAL":
                    continue
                name = d["name"]
                if any(a in name for a in ("_GCM_", "_POLY1305", "_CCM", "_SHA256", "_SHA384")):
                    continue
                version_pool.append((hid, d))
            trace["version_filter"] = {
                "rule": f"RFC 2246/4346 TLS {ver} suites (excluding AEAD, SHA256/384 PRF, and TLS 1.3)",
                "count": len(version_pool),
            }
        else:
            version_pool = list(self.iana_db.items())
            trace["version_filter"] = {"rule": "Unconstrained", "count": len(version_pool)}

        # Step 4b: Key Exchange (KEX) Filtering
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
                trace["kex_filter"] = {"rule": "Matrix KEX omitted", "count": len(kex_pool)}
        else:
            # TLS 1.3: RFC 8446 cipher suites decouple KEX from cipher name
            kex_pool = list(version_pool)
            trace["kex_filter"] = {"rule": "RFC 8446 KEX decoupled from cipher suites", "count": len(kex_pool)}

        # Step 4c: Strength Class Filtering
        target_strength = contract.cipher_class or matrix_strength
        if target_strength not in ("N/A", "", None):
            strength_pool = [
                (hid, d) for hid, d in kex_pool
                if d.get("strength") == target_strength
            ]
            trace["strength_filter"] = {
                "rule": f"Target cipher strength: {target_strength}",
                "count": len(strength_pool),
            }
        else:
            strength_pool = list(kex_pool)
            trace["strength_filter"] = {"rule": "Unconstrained strength", "count": len(strength_pool)}

        # Step 4d: Certificate Authentication Filtering
        # In TLS <= 1.2 scenarios using X.509 PKI certificates, cipher suites must
        # perform certificate authentication (RSA or ECDSA) and exclude PSK/anon/SRP.
        auth_pool: List[Tuple[str, Dict[str, Any]]] = []
        rfc_impossible = False
        rfc_reason = ""

        # Determine effective leaf key algorithm: use contract.leaf_key_algorithm when matrix server_leaf_key_type is absent
        effective_leaf_key = (
            explicit_leaf_key.lower().strip()
            if explicit_leaf_key
            else (contract.leaf_key_algorithm.lower().strip() if (contract and contract.leaf_key_algorithm) else None)
        )

        # Check for TLS 1.0/1.1 + Ed25519 runtime incompatibility: current Docker/OpenSSL testbed runtime has no executable path
        if ver in ("1.0", "1.1") and effective_leaf_key == "ed25519":
            rfc_impossible = True
            rfc_reason = (
                f"Current-runtime/testbed unsupported: OpenSSL/Postfix runtime cannot negotiate TLS {ver} "
                f"with Ed25519 leaf certificate"
            )
            auth_pool = []
        elif ver in ("1.0", "1.1", "1.2") and (needs_pki or effective_leaf_key):
            leaf_filter = effective_leaf_key
            for hid, d in strength_pool:
                name = d["name"]
                # Must not be unauthenticated or PSK/SRP
                if any(x in name for x in ("_anon_", "ANON", "PSK", "SRP", "KRB5")):
                    continue
                if leaf_filter == "rsa":
                    if "RSA" in name:
                        auth_pool.append((hid, d))
                elif leaf_filter == "ecdsa":
                    if "ECDSA" in name:
                        auth_pool.append((hid, d))
                elif leaf_filter == "ed25519":
                    # In TLS 1.2, Ed25519 authentication uses ECDHE-ECDSA suites per RFC 8422
                    if "ECDSA" in name:
                        auth_pool.append((hid, d))
                else:
                    if "RSA" in name or "ECDSA" in name:
                        auth_pool.append((hid, d))
            trace["auth_filter"] = {
                "rule": f"X.509 PKI certificate authentication (leaf_filter={leaf_filter})",
                "count": len(auth_pool),
            }
        else:
            auth_pool = list(strength_pool)
            trace["auth_filter"] = {"rule": "TLS 1.3 or non-cert decoupled authentication", "count": len(auth_pool)}

        iana_candidates = [d["name"] for hid, d in auth_pool]
        trace["iana_candidate_count"] = len(iana_candidates)

        # Step 4e: Runtime Intersection (Tier 2)
        if not self.runtime_available:
            runtime_cands = []
        else:
            runtime_cands = [
                (hid, d) for hid, d in auth_pool
                if hid in self.runtime_supported_hex
            ]
        runtime_candidates = [d["name"] for hid, d in runtime_cands]
        trace["runtime_supported_count"] = len(runtime_cands)

        # Step 4f: Daemon-Configurable Filtering (Tier 3)
        proto_lower = proto.lower()
        if ver == "1.3":
            if proto_lower == "smtp":
                # Postfix cannot configure TLS 1.3 ciphersuites via main.cf.
                # It delegates negotiation to OpenSSL default server preference, which negotiates TLS_AES_256_GCM_SHA384.
                if target_strength == "HIGH" or contract.exact_cipher_suite == "TLS_AES_256_GCM_SHA384":
                    daemon_cands = [d for d in runtime_cands if d[1]["name"] == "TLS_AES_256_GCM_SHA384"]
                else:
                    daemon_cands = []
            elif proto_lower in ("imap", "pop3"):
                # Dovecot natively supports ssl_cipher_suites = <ciphersuites>
                daemon_cands = list(runtime_cands)
            else:
                daemon_cands = list(runtime_cands)
        else:
            # TLS <= 1.2: Postfix uses smtpd_tls_cipherlist, Dovecot uses ssl_cipher_list
            daemon_cands = list(runtime_cands)

        daemon_configurable_candidates = [d["name"] for hid, d in daemon_cands]
        trace["daemon_configurable_count"] = len(daemon_cands)

        # ----------------------------------------------------------------------
        # Step 4g: Resolution Decision & Deterministic Policy
        # ----------------------------------------------------------------------
        if rfc_impossible:
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.STANDARD.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=[],
                iana_candidate_count=0,
                runtime_candidates=[],
                runtime_candidate_count=0,
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.UNRESOLVABLE,
                runtime_status=RuntimeStatus.NO_RUNTIME_CANDIDATE,
                leaf_key_algorithm=None,
                leaf_key_size=None,
                reason=rfc_reason,
                missing_information="RFC specification conflict: Ed25519 leaf authentication undefined in TLS 1.0/1.1",
                traceable_constraints=trace,
            )

        if not self.runtime_available:
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.STANDARD.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=iana_candidates,
                iana_candidate_count=len(iana_candidates),
                runtime_candidates=[],
                runtime_candidate_count=0,
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.UNRESOLVABLE,
                runtime_status=RuntimeStatus.RUNTIME_UNAVAILABLE,
                reason=f"Target runtime '{self.runtime_inspector.runtime_name}' is unreachable",
                missing_information="Runtime capability probe unavailable",
                traceable_constraints=trace,
            )

        # Scenarios where daemon cannot configure/enforce requested suites
        if ver == "1.3" and (target_strength == "WEAK" or (proto_lower == "smtp" and target_strength != "HIGH")):
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.STANDARD.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=iana_candidates,
                iana_candidate_count=len(iana_candidates),
                runtime_candidates=runtime_candidates,
                runtime_candidate_count=len(runtime_candidates),
                daemon_configurable_candidates=daemon_configurable_candidates,
                daemon_configurable_candidate_count=len(daemon_configurable_candidates),
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.DAEMON_CANNOT_ENFORCE,
                runtime_status=RuntimeStatus.CURRENT_RUNTIME_UNSUPPORTED if len(runtime_cands) == 0 else RuntimeStatus.SUPPORTED,
                reason=f"Target daemon ({proto_lower}) cannot configure/enforce TLS 1.3 cipher suite for strength '{target_strength}'",
                missing_information="Daemon enforcement capability for TLS 1.3 suite",
                traceable_constraints=trace,
            )

        if len(runtime_cands) == 0:
            has_legacy = any(
                any(bad in c for bad in ("3DES", "RC4", "DES")) or "ECDH_" in c
                for c in iana_candidates
            )
            rt_status = RuntimeStatus.REQUIRES_LEGACY_RUNTIME if has_legacy else RuntimeStatus.CURRENT_RUNTIME_UNSUPPORTED
            reason = (
                f"Structural candidates exist in IANA ({len(iana_candidates)} suites) but require "
                f"legacy runtime support disabled in current OpenSSL build"
                if has_legacy else
                f"No IANA candidate satisfies structural constraints and current OpenSSL runtime capabilities"
            )
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.STANDARD.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=iana_candidates,
                iana_candidate_count=len(iana_candidates),
                runtime_candidates=[],
                runtime_candidate_count=0,
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.UNRESOLVABLE,
                runtime_status=rt_status,
                reason=reason,
                missing_information="Runtime capability: unsupported by current OpenSSL runtime",
                traceable_constraints=trace,
            )

        if len(daemon_cands) == 0:
            return ResolutionResult(
                scenario_id=sid,
                intent=intent,
                tls_version=ver,
                matrix_kex=matrix_kex,
                cert_auth_intent=cert_auth_intent,
                matrix_cipher_strength=matrix_strength,
                generation_mode=GenerationMode.STANDARD.value,
                cipher_mode=contract.cipher_mode.value,
                iana_candidates=iana_candidates,
                iana_candidate_count=len(iana_candidates),
                runtime_candidates=runtime_candidates,
                runtime_candidate_count=len(runtime_candidates),
                daemon_configurable_candidates=[],
                daemon_configurable_candidate_count=0,
                candidate_count_before_selection=0,
                candidate_names_after_all_filters=[],
                selected_cipher=None,
                selection_basis=SelectionBasis.NONE,
                selection_rank=None,
                cipher_resolution_status=ResolutionStatus.DAEMON_CANNOT_ENFORCE,
                runtime_status=RuntimeStatus.SUPPORTED,
                reason=f"Target daemon ({proto_lower}) cannot configure/enforce any candidate cipher suites",
                missing_information="Daemon configuration mechanism for candidate ciphers",
                traceable_constraints=trace,
            )

        # EXACT mode: validate exact requested cipher
        if contract.cipher_mode == CipherMode.EXACT:
            exact_name = contract.exact_cipher_suite
            matching = [d for hid, d in daemon_cands if d["name"] == exact_name]
            if matching:
                selected_cipher = exact_name
                selection_basis = SelectionBasis.EXACT_CONTRACT
                selection_rank = 1
                sorted_cands = [d for hid, d in daemon_cands]
            else:
                return ResolutionResult(
                    scenario_id=sid,
                    intent=intent,
                    tls_version=ver,
                    matrix_kex=matrix_kex,
                    cert_auth_intent=cert_auth_intent,
                    matrix_cipher_strength=matrix_strength,
                    generation_mode=GenerationMode.STANDARD.value,
                    cipher_mode=CipherMode.EXACT.value,
                    iana_candidates=iana_candidates,
                    iana_candidate_count=len(iana_candidates),
                    runtime_candidates=runtime_candidates,
                    runtime_candidate_count=len(runtime_candidates),
                    daemon_configurable_candidates=daemon_configurable_candidates,
                    daemon_configurable_candidate_count=len(daemon_configurable_candidates),
                    candidate_count_before_selection=len(daemon_cands),
                    candidate_names_after_all_filters=[d["name"] for hid, d in daemon_cands],
                    selected_cipher=None,
                    selection_basis=SelectionBasis.NONE,
                    selection_rank=None,
                    cipher_resolution_status=ResolutionStatus.DAEMON_CANNOT_ENFORCE if any(d["name"] == exact_name for hid, d in runtime_cands) else ResolutionStatus.UNRESOLVABLE,
                    runtime_status=RuntimeStatus.CURRENT_RUNTIME_UNSUPPORTED,
                    reason=f"Exact requested cipher '{exact_name}' cannot be enforced by daemon/runtime",
                    missing_information=f"Runtime/daemon support for {exact_name}",
                    traceable_constraints=trace,
                )
        else:
            # Deterministic Class Ranking Policy:
            # 1. IANA Rec = 'Y' (rank 0)
            # 2. IANA Rec = 'N' (rank 1)
            # 3. IANA Rec = 'D' (rank 2)
            # 4. Name Ascending (Alphabetical)
            def rank_key(item: Tuple[str, Dict[str, Any]]) -> Tuple[int, str]:
                hid, d = item
                rec = d.get("iana_recommended_status", "N")
                rec_rank = 0 if rec == "Y" else (1 if rec == "N" else 2)
                return (rec_rank, d["name"])

            sorted_cands = [d for hid, d in sorted(daemon_cands, key=rank_key)]
            selected_cipher = sorted_cands[0]["name"]
            selection_basis = SelectionBasis.UNIQUE if len(sorted_cands) == 1 else SelectionBasis.EXPLICIT_REPOSITORY_POLICY
            selection_rank = 1

        candidate_names = [d["name"] for d in sorted_cands]

        # Step 4h: Leaf Key Derivation & Consistency Validation
        # Invariant 1: Certificate signature algorithm is independent from leaf public-key algorithm.
        # Invariant 2: TLS 1.2 leaf-key compatibility is derived from actual selected auth construction.
        # Invariant 3: TLS 1.3 does not receive a fabricated ECDSA default.
        if contract.leaf_key_algorithm:
            leaf_algo = contract.leaf_key_algorithm
            leaf_size = contract.leaf_key_size or (1024 if ("cert_rsa1024" in req or "1024" in req) else (256 if leaf_algo == "ecdsa" else 2048))
            # Validate mutual compatibility
            if ver in ("1.0", "1.1", "1.2"):
                if leaf_algo == "rsa" and "ECDSA" in selected_cipher:
                    return ResolutionResult(
                        scenario_id=sid,
                        intent=intent,
                        tls_version=ver,
                        matrix_kex=matrix_kex,
                        cert_auth_intent=cert_auth_intent,
                        matrix_cipher_strength=matrix_strength,
                        generation_mode=GenerationMode.STANDARD.value,
                        cipher_mode=contract.cipher_mode.value,
                        iana_candidates=iana_candidates,
                        iana_candidate_count=len(iana_candidates),
                        runtime_candidates=runtime_candidates,
                        runtime_candidate_count=len(runtime_candidates),
                        daemon_configurable_candidates=daemon_configurable_candidates,
                        daemon_configurable_candidate_count=len(daemon_configurable_candidates),
                        candidate_count_before_selection=len(candidate_names),
                        candidate_names_after_all_filters=candidate_names,
                        selected_cipher=None,
                        selection_basis=SelectionBasis.NONE,
                        selection_rank=None,
                        cipher_resolution_status=ResolutionStatus.UNRESOLVABLE,
                        runtime_status=RuntimeStatus.SUPPORTED,
                        reason=f"Incompatible leaf key '{leaf_algo}' with selected cipher '{selected_cipher}'",
                        missing_information="Mutual compatibility failure between leaf key and cipher suite",
                        traceable_constraints=trace,
                    )
                elif leaf_algo == "ecdsa" and "RSA" in selected_cipher:
                    return ResolutionResult(
                        scenario_id=sid,
                        intent=intent,
                        tls_version=ver,
                        matrix_kex=matrix_kex,
                        cert_auth_intent=cert_auth_intent,
                        matrix_cipher_strength=matrix_strength,
                        generation_mode=GenerationMode.STANDARD.value,
                        cipher_mode=contract.cipher_mode.value,
                        iana_candidates=iana_candidates,
                        iana_candidate_count=len(iana_candidates),
                        runtime_candidates=runtime_candidates,
                        runtime_candidate_count=len(runtime_candidates),
                        daemon_configurable_candidates=daemon_configurable_candidates,
                        daemon_configurable_candidate_count=len(daemon_configurable_candidates),
                        candidate_count_before_selection=len(candidate_names),
                        candidate_names_after_all_filters=candidate_names,
                        selected_cipher=None,
                        selection_basis=SelectionBasis.NONE,
                        selection_rank=None,
                        cipher_resolution_status=ResolutionStatus.UNRESOLVABLE,
                        runtime_status=RuntimeStatus.SUPPORTED,
                        reason=f"Incompatible leaf key '{leaf_algo}' with selected cipher '{selected_cipher}'",
                        missing_information="Mutual compatibility failure between leaf key and cipher suite",
                        traceable_constraints=trace,
                    )
        elif ver == "1.3":
            # TLS 1.3 does not receive a fabricated ECDSA default; standard RSA-2048 leaf
            leaf_algo = "rsa"
            leaf_size = 1024 if "cert_rsa1024" in req else 2048
        elif ver in ("1.0", "1.1", "1.2"):
            # Derived from selected cipher's authentication construction
            if "ECDSA" in selected_cipher:
                leaf_algo = "ecdsa"
                leaf_size = 256
            else:
                leaf_algo = "rsa"
                leaf_size = 1024 if "cert_rsa1024" in req else 2048
        else:
            leaf_algo = "rsa"
            leaf_size = 2048

        # Step 4i: Cipher Telemetry
        ossl_name = iana_to_openssl(selected_cipher)
        telemetry = {
            "selected_cipher": selected_cipher,
            "openssl_name": ossl_name,
            "selection_rank": selection_rank,
            "total_runtime_candidates": len(runtime_candidates),
            "total_daemon_configurable_candidates": len(daemon_configurable_candidates),
            "leaf_key_algorithm": leaf_algo,
            "leaf_key_size": leaf_size,
            "policy": "1. IANA Rec=Y, 2. Rec=N, 3. Rec=D, 4. Name ASC",
        }

        return ResolutionResult(
            scenario_id=sid,
            intent=intent,
            tls_version=ver,
            matrix_kex=matrix_kex,
            cert_auth_intent=cert_auth_intent,
            matrix_cipher_strength=matrix_strength,
            generation_mode=GenerationMode.STANDARD.value,
            cipher_mode=contract.cipher_mode.value,
            iana_candidates=iana_candidates,
            iana_candidate_count=len(iana_candidates),
            runtime_candidates=runtime_candidates,
            runtime_candidate_count=len(runtime_candidates),
            daemon_configurable_candidates=daemon_configurable_candidates,
            daemon_configurable_candidate_count=len(daemon_configurable_candidates),
            candidate_count_before_selection=len(candidate_names),
            candidate_names_after_all_filters=candidate_names,
            selected_cipher=selected_cipher,
            selection_basis=selection_basis,
            selection_rank=selection_rank,
            cipher_resolution_status=ResolutionStatus.CONFIGURABLE_CANDIDATE_SELECTED,
            runtime_status=RuntimeStatus.SUPPORTED,
            leaf_key_algorithm=leaf_algo,
            leaf_key_size=leaf_size,
            special_harness=None,
            special_harness_parameters={},
            cipher_telemetry=telemetry,
            reason=f"Deterministically resolved via repository policy ({len(candidate_names)} daemon-configurable candidates)",
            missing_information=None,
            traceable_constraints=trace,
        )


def resolve_scenario(
    spec: ScenarioSpec | Dict[str, Any],
    resolver: Optional[TLSCipherResolver] = None,
) -> ResolutionResult:
    """Convenience functional interface for resolving a scenario."""
    res = resolver or TLSCipherResolver()
    return res.resolve(spec)
