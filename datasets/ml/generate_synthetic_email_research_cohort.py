"""Generate a reproducible 10,000-row synthetic email-session cohort.

Rows are simulated feature observations, not real traffic or PCAP captures.
The label describes a generated server profile; features describe one client
negotiation with that profile. This creates a controlled partial-observation
classification task rather than copying Rule Engine output.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.ml_runtime import _email_risk_features  # noqa: E402

SEED = 20261001
PROFILES_PER_TIER = 500
SESSIONS_PER_PROFILE = 5
TIERS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
PROTOCOLS = ("SMTP", "IMAP", "POP3")
OUT_DIR = ROOT / "datasets/ml/synthetic"
DATA_PATH = OUT_DIR / "synthetic_email_research_cohort_v1.csv"
META_PATH = OUT_DIR / "synthetic_email_research_cohort_v1.json"
PROFILE_PATH = OUT_DIR / "synthetic_email_research_profiles_v1.csv"
VERSIONS = {"TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303, "TLSv1.3": 0x0304}

CIPHERS = {
    "TLS_AES_128_GCM_SHA256": ("HIGH", "AEAD", "ECDHE"),
    "TLS_AES_256_GCM_SHA384": ("HIGH", "AEAD", "ECDHE"),
    "TLS_CHACHA20_POLY1305_SHA256": ("HIGH", "AEAD", "ECDHE"),
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": ("HIGH", "AEAD", "ECDHE"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": ("HIGH", "AEAD", "ECDHE"),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": ("HIGH", "AEAD", "ECDHE"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": ("MEDIUM", "CBC", "ECDHE"),
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": ("MEDIUM", "CBC", "ECDHE"),
    "TLS_RSA_WITH_AES_128_GCM_SHA256": ("WEAK", "AEAD", "RSA"),
    "TLS_RSA_WITH_AES_128_CBC_SHA": ("WEAK", "CBC", "RSA"),
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": ("WEAK", "CBC", "RSA"),
    "TLS_RSA_WITH_RC4_128_SHA": ("BROKEN", "BROKEN", "RSA"),
    "TLS_RSA_WITH_NULL_SHA256": ("BROKEN", "BROKEN", "RSA"),
}

FAMILY_FOR_TIER = {
    "LOW": ("modern_aead", "modern_tls13"),
    "MEDIUM": ("ecdhe_cbc_compatible", "long_lived_certificate"),
    "HIGH": ("legacy_protocol", "static_rsa_compatible"),
    "CRITICAL": ("cleartext_service", "broken_cipher_enabled"),
}


def _make_profile(tier: str, family: str, index: int, rng: random.Random) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "server_id": f"sim-{tier.lower()}-{index:04d}",
        "tier": tier,
        "family": family,
        "tls_enabled": True,
        "starttls_enabled": True,
        "minimum_version": "TLSv1.2",
        "supported_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_preference": [],
        "key_algorithm": "RSA",
        "key_size": 2048,
        "signature": "sha256WithRSAEncryption",
        "trust": "TRUSTED",
        "hostname_match": "MATCH",
        "validity_days": 398,
        "self_signed": False,
        "san_count": 1,
        "chain_length": 2,
    }
    if family == "modern_aead":
        profile["supported_versions"] = rng.choice((["TLSv1.2"], ["TLSv1.2", "TLSv1.3"], ["TLSv1.3"]))
        profile["minimum_version"] = profile["supported_versions"][0]
        profile["cipher_preference"] = rng.sample([
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ], k=3)
        profile["key_algorithm"] = rng.choice(("RSA", "EC", "Ed25519"))
        profile["key_size"] = {"RSA": rng.choice((2048, 3072, 4096)), "EC": 256, "Ed25519": 256}[profile["key_algorithm"]]
        profile["signature"] = "sha256WithRSAEncryption" if profile["key_algorithm"] == "RSA" else "ecdsa-with-SHA256"
        profile["validity_days"] = rng.choice((90, 180, 365, 398))
    elif family == "modern_tls13":
        profile["minimum_version"] = "TLSv1.3"
        profile["supported_versions"] = ["TLSv1.3"]
        profile["cipher_preference"] = rng.sample([
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
        ], k=2)
        profile["key_algorithm"] = rng.choice(("EC", "Ed25519"))
        profile["key_size"] = 256
        profile["signature"] = "ecdsa-with-SHA256" if profile["key_algorithm"] == "EC" else "ED25519"
        profile["validity_days"] = rng.choice((90, 180, 365))
    elif family == "ecdhe_cbc_compatible":
        profile["cipher_preference"] = rng.sample([
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
        ], k=3)
        profile["validity_days"] = rng.choice((365, 398, 730))
    elif family == "long_lived_certificate":
        profile["cipher_preference"] = rng.sample([
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ], k=3)
        profile["validity_days"] = rng.choice((1095, 1825, 3650))
    elif family == "legacy_protocol":
        profile["minimum_version"] = rng.choice(("TLSv1.0", "TLSv1.1"))
        profile["supported_versions"] = [profile["minimum_version"], "TLSv1.2"]
        profile["cipher_preference"] = rng.sample([
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA",
        ], k=3)
    elif family == "static_rsa_compatible":
        profile["cipher_preference"] = rng.sample([
            "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
        ], k=3)
    elif family == "cleartext_service":
        profile["tls_enabled"] = False
        profile["starttls_enabled"] = False
        profile["supported_versions"] = []
    elif family == "broken_cipher_enabled":
        profile["cipher_preference"] = rng.sample([
            "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_NULL_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256",
        ], k=3)
    return profile


def _profile_label(profile: dict[str, Any]) -> str:
    """Label the complete simulated endpoint configuration, not rule output."""
    suites = set(profile["cipher_preference"])
    if not profile["tls_enabled"] or suites & {"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_NULL_SHA256"}:
        return "CRITICAL"
    if (
        VERSIONS[profile["minimum_version"]] < VERSIONS["TLSv1.2"]
        or any(CIPHERS[name][2] == "RSA" for name in suites)
        or profile["key_algorithm"] == "RSA" and profile["key_size"] < 2048
        or profile["signature"].lower().startswith("sha1")
        or profile["trust"] != "TRUSTED"
        or profile["hostname_match"] != "MATCH"
    ):
        return "HIGH"
    if any(CIPHERS[name][1] == "CBC" for name in suites) or profile["validity_days"] > 825:
        return "MEDIUM"
    return "LOW"


def _negotiate(profile: dict[str, Any], client: dict[str, Any]) -> tuple[str | None, str | None]:
    if not profile["tls_enabled"]:
        return None, None
    versions = [v for v in client["versions"] if v in profile["supported_versions"]]
    if not versions:
        return None, None
    version = max(versions, key=VERSIONS.get)
    eligible = [c for c in profile["cipher_preference"] if c in client["ciphers"]]
    if version == "TLSv1.3":
        eligible = [c for c in eligible if c.startswith("TLS_AES_") or c.startswith("TLS_CHACHA20_")]
    else:
        eligible = [c for c in eligible if not c.startswith("TLS_AES_") and not c.startswith("TLS_CHACHA20_")]
    return (version, eligible[0]) if eligible else (None, None)


def _session(profile: dict[str, Any], protocol: str, client: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    version, cipher = _negotiate(profile, client)
    implicit = rng.random() < 0.18
    starttls_status = "IMPLICIT_TLS" if implicit else "UPGRADED" if profile["starttls_enabled"] and version else "CLEARTEXT_NO_ENCRYPTION"
    if not version:
        return {"protocol": protocol, "starttls": {"status": starttls_status}, "tls": None, "handshake": {}, "certificate": None}
    strength, _, kex = CIPHERS[cipher]
    tls = {
        "tls_version": version,
        "raw_version": f"0x{VERSIONS[version]:04x}",
        "cipher_name": cipher,
        "cipher_strength": strength,
        "key_exchange": kex,
        "tls_extension_count": rng.randint(6, 18),
    }
    cert = None
    # Model passive TLS 1.3 certificate invisibility; it is not evidence of a
    # certificate-free endpoint.
    if version != "TLSv1.3":
        leaf = {
            "public_key_algorithm": profile["key_algorithm"],
            "public_key_size": profile["key_size"],
            "signature_algorithm_name": profile["signature"],
            "is_expired": False,
            "not_yet_valid": False,
            "san_dns": [f"mx-{profile['server_id']}.example.invalid"] * profile["san_count"],
            "san_ip": [],
        }
        cert = {
            "trust_status": profile["trust"],
            "hostname_match": profile["hostname_match"],
            "chain_length": profile["chain_length"],
            "leaf_cert": leaf,
        }
    return {
        "protocol": protocol,
        "starttls": {"status": starttls_status},
        "tls": tls,
        "handshake": {"server_negotiation": {"selected_tls_version": version}},
        "certificate": cert,
    }


def generate() -> dict[str, Any]:
    rng = random.Random(SEED)
    # Each client has a different offer set; endpoints therefore reveal only a
    # negotiated slice of the profile's full supported configuration.
    clients = (
        {"versions": ["TLSv1.3", "TLSv1.2"], "ciphers": list(CIPHERS)[:6]},
        {"versions": ["TLSv1.2"], "ciphers": list(CIPHERS)[3:11]},
        {"versions": ["TLSv1.2", "TLSv1.1", "TLSv1.0"], "ciphers": list(CIPHERS)[3:]},
        {"versions": ["TLSv1.2"], "ciphers": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA"]},
        {"versions": ["TLSv1.3", "TLSv1.2"], "ciphers": ["TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]},
    )
    rows: list[dict[str, Any]] = []
    profile_groups: dict[str, dict[str, Any]] = {}
    profile_records: list[dict[str, Any]] = []
    per_tier_index = Counter()
    for tier in TIERS:
        families = FAMILY_FOR_TIER[tier]
        for local_index in range(PROFILES_PER_TIER):
            family = families[local_index % len(families)]
            profile = _make_profile(tier, family, local_index, rng)
            target = _profile_label(profile)
            if target != tier:
                raise ValueError(f"Generated profile {family} mapped to {target}, expected {tier}")
            signature = {k: v for k, v in profile.items() if k != "server_id"}
            group_id = hashlib.sha256(json.dumps(signature, sort_keys=True).encode()).hexdigest()[:20]
            profile_groups[group_id] = {"target": target, "family": family}
            profile_records.append({
                "server_id": profile["server_id"],
                "configuration_group_id": group_id,
                "profile_family": family,
                "data_source": "synthetic_simulation",
                "target": target,
                "tls_enabled": profile["tls_enabled"],
                "starttls_enabled": profile["starttls_enabled"],
                "minimum_version": profile["minimum_version"],
                "supported_versions_json": json.dumps(profile["supported_versions"], separators=(",", ":")),
                "supported_ciphers_json": json.dumps(profile["cipher_preference"], separators=(",", ":")),
                "certificate_key_algorithm": profile["key_algorithm"],
                "certificate_key_size": profile["key_size"],
                "certificate_signature_algorithm": profile["signature"],
                "certificate_trust": profile["trust"],
                "certificate_hostname_match": profile["hostname_match"],
                "certificate_validity_days": profile["validity_days"],
            })
            for session_index in range(SESSIONS_PER_PROFILE):
                protocol = PROTOCOLS[(session_index + local_index) % len(PROTOCOLS)]
                client = clients[(session_index + rng.randrange(len(clients))) % len(clients)]
                session = _session(profile, protocol, client, rng)
                rows.append({
                    "sample_id": f"syn-{tier.lower()}-{local_index:04d}-{session_index}",
                    "configuration_group_id": group_id,
                    "profile_family": family,
                    "protocol": protocol,
                    "data_source": "synthetic_simulation",
                    "target": target,
                    "features": _email_risk_features(session),
                })
            per_tier_index[tier] += 1
    if len(rows) != 10_000:
        raise AssertionError(f"Expected 10,000 observations; generated {len(rows)}")

    # Assign entire endpoint-configuration groups to one split, stratified by
    # the independently derived full-profile target.
    grouped: dict[str, list[str]] = {tier: [] for tier in TIERS}
    for group, data in profile_groups.items():
        grouped[data["target"]].append(group)
    split_by_group: dict[str, str] = {}
    for tier, groups in grouped.items():
        rng.shuffle(groups)
        n = len(groups)
        train_end = int(n * 0.60)
        val_end = int(n * 0.80)
        split_by_group.update({g: "train" for g in groups[:train_end]})
        split_by_group.update({g: "validation" for g in groups[train_end:val_end]})
        split_by_group.update({g: "test" for g in groups[val_end:]})
    for row in rows:
        row["split"] = split_by_group[row["configuration_group_id"]]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = ("sample_id", "configuration_group_id", "profile_family", "protocol", "data_source", "target", "split", "features_json")
    with DATA_PATH.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{k: row[k] for k in fields[:-1]}, "features_json": json.dumps(row["features"], sort_keys=True, separators=(",", ":"))})
    with PROFILE_PATH.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=tuple(profile_records[0]))
        writer.writeheader()
        writer.writerows(profile_records)

    metadata = {
        "dataset_id": "securemailscope_synthetic_email_research_v1",
        "dataset_version": "1.0.0",
        "data_source": "synthetic_simulation",
        "is_real_observation": False,
        "sample_count": len(rows),
        "server_profile_count": sum(per_tier_index.values()),
        "sessions_per_profile": SESSIONS_PER_PROFILE,
        "protocol_counts": dict(Counter(row["protocol"] for row in rows)),
        "class_counts": dict(Counter(row["target"] for row in rows)),
        "split_sizes": dict(Counter(row["split"] for row in rows)),
        "split_class_counts": {split: dict(Counter(r["target"] for r in rows if r["split"] == split)) for split in ("train", "validation", "test")},
        "split_group_counts": {split: len({r["configuration_group_id"] for r in rows if r["split"] == split}) for split in ("train", "validation", "test")},
        "label_semantics": "Project-defined simulated endpoint posture rubric derived from the endpoint's full supported configuration; each feature row contains only one simulated client negotiation.",
        "label_rubric": {
            "CRITICAL": "TLS unavailable or endpoint permits NULL/RC4 suites.",
            "HIGH": "Endpoint permits TLS below 1.2, static RSA key exchange, weak RSA key, untrusted/mismatched certificate, or SHA-1 signature.",
            "MEDIUM": "No higher-tier condition, but endpoint permits CBC or uses a certificate lifetime above 825 days.",
            "LOW": "TLS 1.2 or newer; AEAD/ECDHE-capable suite set; strong, trusted, matching certificate; no higher-tier condition.",
        },
        "profile_families": dict(Counter(row["profile_family"] for row in rows)),
        "feature_schema": "analysis.ml_runtime._email_risk_features; same function is used in runtime inference.",
        "packet_capture_status": "FEATURE_LEVEL_SIMULATION_NOT_PCAP; 110 existing PCAP scenarios remain the packet-level integration test corpus.",
        "limitations": [
            "This is programmatically simulated feature-session data, not captured or observed network traffic and not generated by an LLM.",
            "The endpoint-posture target is a project rubric over simulated full endpoint configurations, not externally reviewed or real-world security truth.",
            "The generator covers a designed configuration space; unmodeled software behavior, negotiation edge cases, and real-world prevalence are not represented.",
            "Performance on this cohort is controlled simulator performance and does not establish real SMTP/IMAP/POP3 effectiveness.",
            "No IP, hostname, sample identifier, or raw profile-family name is in the predictive feature vector.",
        ],
        "seed": SEED,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    metadata["dataset_sha256"] = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    metadata["profile_manifest"] = PROFILE_PATH.name
    metadata["profile_manifest_sha256"] = hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()
    META_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2, sort_keys=True))
