"""
Policy loader for NIST SP 800-52 Rev. 2 and NIST SP 800-131A Rev. 2.
"""

import json
import os
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_DATA_DIR = os.path.join(_BASE_DIR, "data")

_RULES_CACHE: Optional[list[dict[str, Any]]] = None
_CIPHERS_CACHE: Optional[dict[str, Any]] = None


def load_nist_52r2_rules(data_dir: Optional[str] = None) -> list[dict[str, Any]]:
    """Loads all rule clauses from data/nist_sp800_52_r2_rules.json."""
    global _RULES_CACHE
    if _RULES_CACHE is not None and data_dir is None:
        return _RULES_CACHE

    target_dir = data_dir or _DATA_DIR
    json_path = os.path.join(target_dir, "nist_sp800_52_r2_rules.json")
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"NIST 800-52r2 rules JSON not found at: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data_dir is None:
        _RULES_CACHE = data
    return data


def load_nist_52r2_ciphers(data_dir: Optional[str] = None) -> dict[str, list[str]]:
    """Loads machine-readable cipher lists from data/nist_sp800_52_r2_ciphers.json."""
    global _CIPHERS_CACHE
    if _CIPHERS_CACHE is not None and data_dir is None:
        return _CIPHERS_CACHE

    target_dir = data_dir or _DATA_DIR
    json_path = os.path.join(target_dir, "nist_sp800_52_r2_ciphers.json")
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"NIST 800-52r2 ciphers JSON not found at: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data_dir is None:
        _CIPHERS_CACHE = data
    return data


# Pre-load cipher sets
_ciphers_data = load_nist_52r2_ciphers()

NIST_SEC_3311_TLS12_CIPHERS: set[str] = set(_ciphers_data.get("section_3311_tls12_ciphers", []))
NIST_SEC_3312_TLS13_CIPHERS: set[str] = set(_ciphers_data.get("section_3312_tls13_ciphers", []))
NIST_APP_C_PSK_CIPHERS: set[str] = set(_ciphers_data.get("appendix_c_psk_ciphers", []))
NIST_APP_D_RSA_CIPHERS: set[str] = set(_ciphers_data.get("appendix_d_rsa_ciphers", []))

# Approved curves per NIST SP 800-52r2 §3.4.2.2 (S54)
NIST_APPROVED_CURVES: set[str] = {
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "prime256v1",  # Standard OpenSSL/IANA alias of secp256r1
}
