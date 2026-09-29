"""Audit synthetic PCAP/sidecar integrity and emit a scenario-family manifest."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT = Path(__file__).resolve().parents[2]
ROOT = PROJECT / "datasets" / "ml"
sys.path.insert(0, str(PROJECT))

import dpkt  # noqa: E402
from testbed.runner.comparator import compare  # noqa: E402
from testbed.runner.scenario_contract import load_scenario_contracts  # noqa: E402

CAPTURES = PROJECT / "testbed" / "captures"
FAMILY_FIELDS = (
    "protocol", "tls_presence", "tls_version", "cipher_strength",
    "cert_validity", "cert_chain_shape", "cert_sig_algo", "starttls_integrity",
)
AUDIT_PATH = ROOT / "metadata" / "synthetic_sidecar_integrity_v1.json"
MANIFEST_PATH = ROOT / "splits" / "synthetic_family_manifest_v1.csv"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _family_id(expected: dict[str, Any]) -> tuple[str, dict[str, str]]:
    factors = {key: str(expected.get(key) or "N/A") for key in FAMILY_FIELDS}
    canonical = json.dumps(factors, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16], factors


def _certificate_identity_group(observed: dict[str, Any]) -> str:
    identities = []
    for session in (observed.get("sessions") or {}).values():
        certificate = session.get("certificate") or {}
        leaf = certificate.get("leaf_cert") or {}
        if not leaf:
            continue
        identity = {
            "subject_dn": str(leaf.get("subject_dn") or "").strip().lower(),
            "san_dns": sorted(str(name).strip().lower() for name in (leaf.get("san_dns") or [])),
            "san_ip": sorted(str(name).strip().lower() for name in (leaf.get("san_ip") or [])),
        }
        if identity["subject_dn"] or identity["san_dns"] or identity["san_ip"]:
            identities.append(json.dumps(identity, sort_keys=True, separators=(",", ":")))
    if not identities:
        return "UNOBSERVED"
    return hashlib.sha256("\n".join(sorted(set(identities))).encode("utf-8")).hexdigest()[:16]


def audit() -> dict[str, Any]:
    contracts = load_scenario_contracts()
    expected_paths = sorted(CAPTURES.glob("*.expected.json"))
    findings: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []
    outcomes: Counter[str] = Counter()
    families: Counter[str] = Counter()
    certificate_groups: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    total_packets = 0

    for expected_path in expected_paths:
        scenario_id = expected_path.name.removesuffix(".expected.json")
        observed_path = CAPTURES / f"{scenario_id}.observed.json"
        comparison_path = CAPTURES / f"{scenario_id}.comparison.json"
        pcap_path = CAPTURES / f"{scenario_id}.pcap"
        if scenario_id not in contracts:
            findings.append({"scenario_id": scenario_id, "issue": "no_matching_scenario_contract"})
        if not observed_path.is_file() or not comparison_path.is_file() or not pcap_path.is_file():
            for kind, path in (("observed", observed_path), ("comparison", comparison_path), ("pcap", pcap_path)):
                if not path.is_file():
                    findings.append({"scenario_id": scenario_id, "issue": f"missing_{kind}"})
            continue

        expected_artifact = _read_json(expected_path)
        observed_artifact = _read_json(observed_path)
        stored_comparison = _read_json(comparison_path)
        for kind, artifact in (("expected", expected_artifact), ("observed", observed_artifact), ("comparison", stored_comparison)):
            if artifact.get("scenario_id") != scenario_id:
                findings.append({"scenario_id": scenario_id, "issue": f"{kind}_scenario_id_mismatch"})

        try:
            with pcap_path.open("rb") as stream:
                packet_count = sum(1 for _ in dpkt.pcapng.Reader(stream))
        except (OSError, ValueError, dpkt.dpkt.NeedData) as exc:
            findings.append({"scenario_id": scenario_id, "issue": f"pcapng_invalid:{type(exc).__name__}"})
            packet_count = 0
        if packet_count == 0:
            findings.append({"scenario_id": scenario_id, "issue": "pcapng_empty"})
        total_packets += packet_count

        try:
            recomputed = compare(expected_artifact, observed_artifact)
            comparison_matches = recomputed == stored_comparison
        except Exception as exc:
            findings.append({"scenario_id": scenario_id, "issue": f"comparison_replay_error:{type(exc).__name__}"})
            recomputed = {}
            comparison_matches = False
        if not comparison_matches:
            findings.append({"scenario_id": scenario_id, "issue": "stored_comparison_differs_from_replay"})

        expected = expected_artifact.get("expected") or {}
        family_id, factors = _family_id(expected)
        certificate_group_id = _certificate_identity_group(observed_artifact)
        protocol = str(expected.get("protocol") or "UNKNOWN").upper()
        status = str(recomputed.get("status") or "UNKNOWN")
        protocols[protocol] += 1
        outcomes[status] += 1
        families[family_id] += 1
        if certificate_group_id != "UNOBSERVED":
            certificate_groups[certificate_group_id] += 1
        rows.append({
            "scenario_id": scenario_id,
            "data_source": "synthetic",
            "protocol": protocol,
            "scenario_family_id": family_id,
            "certificate_identity_group_id": certificate_group_id,
            "expected_cipher_strength_context": str(expected.get("cipher_strength") or "N/A"),
            "comparator_status": status,
            "pcap_path": str(pcap_path.relative_to(PROJECT)),
            "pcap_sha256": _sha256(pcap_path),
            "expected_sidecar_sha256": _sha256(expected_path),
            "observed_sidecar_sha256": _sha256(observed_path),
            "comparison_sidecar_sha256": _sha256(comparison_path),
            "pcap_packet_count": packet_count,
            "comparison_replay_matches": comparison_matches,
            "family_factors": json.dumps(factors, sort_keys=True, separators=(",", ":")),
        })

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "scenario_id", "data_source", "protocol", "scenario_family_id",
        "certificate_identity_group_id",
        "expected_cipher_strength_context", "comparator_status", "pcap_path",
        "pcap_sha256", "expected_sidecar_sha256", "observed_sidecar_sha256",
        "comparison_sidecar_sha256", "pcap_packet_count", "comparison_replay_matches",
        "family_factors",
    )
    with MANIFEST_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    repeated_groups = sum(count > 1 for count in families.values())
    return {
        "audit_id": "synthetic_sidecar_integrity_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Structural pairing, capture validity, deterministic comparator replay, and grouped-split metadata.",
        "limitations": [
            "Matching filenames/IDs and comparator replay establish structural consistency, not proof the observed sidecar was freshly derived from that PCAP.",
            "Direct PCAP re-analysis is still needed to prove capture-to-observation provenance; run with the full parser/TShark environment.",
            "Family IDs group scenarios by protocol, TLS mode/version, cipher strength, certificate validity/chain/signature, and STARTTLS integrity; review this grouping before any train/test split.",
            "Expected cipher strength is scenario context, not independent ML anomaly or risk ground truth.",
        ],
        "counts": {
            "scenario_contracts": len(contracts),
            "expected_sidecars": len(expected_paths),
            "fully_audited_pairs": len(rows),
            "valid_pcapng_captures": sum(row["pcap_packet_count"] > 0 for row in rows),
            "total_pcap_packets": total_packets,
            "protocol_counts": dict(sorted(protocols.items())),
            "comparator_replay_status": dict(sorted(outcomes.items())),
            "scenario_family_count": len(families),
            "repeated_scenario_family_count": repeated_groups,
            "rows_in_repeated_families": sum(count for count in families.values() if count > 1),
            "largest_family_size": max(families.values(), default=0),
            "certificate_bearing_scenarios": sum(certificate_groups.values()),
            "distinct_certificate_identity_groups": len(certificate_groups),
            "integrity_issue_count": len(findings),
        },
        "integrity_findings": findings,
        "scenario_family_sizes": dict(sorted(families.items())),
        "manifest_path": str(MANIFEST_PATH.relative_to(PROJECT)),
        "manifest_sha256": _sha256(MANIFEST_PATH),
    }


def main() -> None:
    result = audit()
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(AUDIT_PATH.relative_to(PROJECT)), "counts": result["counts"]}, indent=2))


if __name__ == "__main__":
    main()
