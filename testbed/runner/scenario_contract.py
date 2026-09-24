"""
testbed/runner/scenario_contract.py
===================================
Authoritative Executable Scenario Contract Definition and Validator.

Decouples high-level scenario intent (data/pcap_generation_matrix.csv) from
concrete execution plans and deterministic generation policies.

Stored persistently as:
    data/scenario_contracts.json (exactly 126 entries)
"""

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

_project_root = Path(__file__).resolve().parent.parent.parent


class GenerationMode(str, Enum):
    """Broad generation architecture required for the scenario."""
    STANDARD = "STANDARD"                    # Standard Postfix/Dovecot + client runner
    DEDICATED_HARNESS = "DEDICATED_HARNESS"  # Dedicated protocol/MITM/TLS packet harness
    UNRESOLVABLE = "UNRESOLVABLE"            # Contradictory or missing specification


class CipherMode(str, Enum):
    """Cryptographic cipher suite selection mechanism."""
    CLASS = "CLASS"                          # Security class + deterministic ranking policy
    EXACT = "EXACT"                          # Explicit IANA cipher suite name
    NONE = "NONE"                            # Cleartext protocol; no TLS cipher


@dataclass(frozen=True)
class ScenarioContract:
    """
    Formal, deterministic execution contract for a single scenario.
    """
    scenario_id: str
    generation_mode: GenerationMode
    cipher_mode: CipherMode

    # Class-mode fields
    cipher_class: Optional[str] = None       # "HIGH", "MEDIUM", "WEAK", "BROKEN"

    # Exact-mode fields
    exact_cipher_suite: Optional[str] = None # Canonical IANA name (e.g. "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384")

    # X.509 Leaf key parameters (independent from CA cert_sig_algo)
    leaf_key_algorithm: Optional[str] = None # "rsa", "ecdsa", "ed25519"
    leaf_key_size: Optional[int] = None      # 2048, 1024, 256

    # Dedicated harness fields
    special_harness: Optional[str] = None    # e.g. "mitm_starttls_strip", "hello_retry_request"
    harness_status: Optional[str] = None     # "IMPLEMENTED", "NOT_IMPLEMENTED"
    special_harness_parameters: Dict[str, Any] = field(default_factory=dict)

    # Unresolvable / Discrepancy telemetry
    unresolvable_reason: Optional[str] = None
    missing_information: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize contract to dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "generation_mode": self.generation_mode.value,
            "cipher_mode": self.cipher_mode.value,
            "cipher_class": self.cipher_class,
            "exact_cipher_suite": self.exact_cipher_suite,
            "leaf_key_algorithm": self.leaf_key_algorithm,
            "leaf_key_size": self.leaf_key_size,
            "special_harness": self.special_harness,
            "harness_status": self.harness_status,
            "special_harness_parameters": dict(self.special_harness_parameters),
            "unresolvable_reason": self.unresolvable_reason,
            "missing_information": self.missing_information,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScenarioContract":
        """Deserialize contract from dictionary."""
        return cls(
            scenario_id=d["scenario_id"],
            generation_mode=GenerationMode(d["generation_mode"]),
            cipher_mode=CipherMode(d["cipher_mode"]),
            cipher_class=d.get("cipher_class"),
            exact_cipher_suite=d.get("exact_cipher_suite"),
            leaf_key_algorithm=d.get("leaf_key_algorithm"),
            leaf_key_size=d.get("leaf_key_size"),
            special_harness=d.get("special_harness"),
            harness_status=d.get("harness_status"),
            special_harness_parameters=d.get("special_harness_parameters") or {},
            unresolvable_reason=d.get("unresolvable_reason"),
            missing_information=d.get("missing_information"),
            notes=d.get("notes") or [],
        )


def load_scenario_contracts(
    contracts_path: Optional[Path | str] = None,
) -> Dict[str, ScenarioContract]:
    """
    Load and parse all scenario contracts from data/scenario_contracts.json.
    """
    path = Path(contracts_path) if contracts_path else (_project_root / "data" / "scenario_contracts.json")
    if not path.exists():
        raise FileNotFoundError(f"Scenario contracts file not found at {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    contracts: Dict[str, ScenarioContract] = {}
    for sid, entry in data.items():
        contracts[sid] = ScenarioContract.from_dict(entry)

    return contracts


def validate_scenario_contracts(
    contracts: Dict[str, ScenarioContract],
    expected_count: int = 126,
) -> List[str]:
    """
    Validate contract invariants. Returns a list of error strings (empty if valid).
    """
    errors: List[str] = []

    if len(contracts) != expected_count:
        errors.append(f"Expected exactly {expected_count} contracts, found {len(contracts)}")

    for sid, c in contracts.items():
        if sid != c.scenario_id:
            errors.append(f"Contract key '{sid}' does not match scenario_id '{c.scenario_id}'")

        if c.generation_mode == GenerationMode.STANDARD:
            if c.cipher_mode == CipherMode.CLASS:
                if not c.cipher_class:
                    errors.append(f"Scenario {sid} is STANDARD CLASS but missing cipher_class")
            elif c.cipher_mode == CipherMode.EXACT:
                if not c.exact_cipher_suite:
                    errors.append(f"Scenario {sid} is STANDARD EXACT but missing exact_cipher_suite")
        elif c.generation_mode == GenerationMode.DEDICATED_HARNESS:
            if not c.special_harness:
                errors.append(f"Scenario {sid} is DEDICATED_HARNESS but missing special_harness")
            if not c.harness_status:
                errors.append(f"Scenario {sid} is DEDICATED_HARNESS but missing harness_status")
        elif c.generation_mode == GenerationMode.UNRESOLVABLE:
            if not c.unresolvable_reason:
                errors.append(f"Scenario {sid} is UNRESOLVABLE but missing unresolvable_reason")

    return errors
