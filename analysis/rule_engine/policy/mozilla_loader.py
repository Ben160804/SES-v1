"""
Policy loader for Mozilla TLS Reference 6.0 (Modern and Intermediate profiles).
"""

import json
import os
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_DATA_DIR = os.path.join(_BASE_DIR, "data")

_MOZILLA_CACHE: Optional[dict[str, Any]] = None


def load_mozilla_guidelines(data_dir: Optional[str] = None) -> dict[str, Any]:
    """Loads guidelines from data/tls_ref_6.0.json."""
    global _MOZILLA_CACHE
    if _MOZILLA_CACHE is not None and data_dir is None:
        return _MOZILLA_CACHE

    target_dir = data_dir or _DATA_DIR
    json_path = os.path.join(target_dir, "tls_ref_6.0.json")
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Mozilla guidelines JSON not found at: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data_dir is None:
        _MOZILLA_CACHE = data
    return data


def _normalize_tls_version(v: str) -> str:
    """Normalizes 'TLSv1.3' -> 'TLS 1.3', 'TLSv1.2' -> 'TLS 1.2'."""
    v_clean = v.strip().replace("TLSv", "TLS ")
    return v_clean


class MozillaModernProfile:
    def __init__(self, raw_cfg: dict[str, Any]):
        self.raw = raw_cfg
        self.tls_versions = {_normalize_tls_version(v) for v in raw_cfg.get("tls_versions", [])}
        self.ciphersuites = set(raw_cfg.get("ciphersuites", []))
        self.tls_curves = {c.lower() for c in raw_cfg.get("tls_curves", [])}
        # Include secp256r1 alias for prime256v1
        if "prime256v1" in self.tls_curves:
            self.tls_curves.add("secp256r1")
        self.maximum_certificate_lifespan = int(raw_cfg.get("maximum_certificate_lifespan", 90))
        self.certificate_types = {t.lower() for t in raw_cfg.get("certificate_types", [])}
        self.certificate_signatures = set(raw_cfg.get("certificate_signatures", []))


class MozillaIntermediateProfile:
    def __init__(self, raw_cfg: dict[str, Any]):
        self.raw = raw_cfg
        self.tls_versions = {_normalize_tls_version(v) for v in raw_cfg.get("tls_versions", [])}
        ciphers_block = raw_cfg.get("ciphers", {})
        iana_ciphers = set(ciphers_block.get("iana", []))
        ciphersuites = set(raw_cfg.get("ciphersuites", []))
        self.approved_ciphers = iana_ciphers | ciphersuites
        self.tls_curves = {c.lower() for c in raw_cfg.get("tls_curves", [])}
        if "prime256v1" in self.tls_curves:
            self.tls_curves.add("secp256r1")
        self.maximum_certificate_lifespan = int(raw_cfg.get("maximum_certificate_lifespan", 366))
        self.certificate_types = {t.lower() for t in raw_cfg.get("certificate_types", [])}
        self.certificate_signatures = set(raw_cfg.get("certificate_signatures", []))


_guidelines_data = load_mozilla_guidelines()
_configs = _guidelines_data.get("configurations", {})

MOZILLA_MODERN = MozillaModernProfile(_configs.get("modern", {}))
MOZILLA_INTERMEDIATE = MozillaIntermediateProfile(_configs.get("intermediate", {}))


def get_mozilla_modern_profile() -> MozillaModernProfile:
    return MOZILLA_MODERN


def get_mozilla_intermediate_profile() -> MozillaIntermediateProfile:
    return MOZILLA_INTERMEDIATE
