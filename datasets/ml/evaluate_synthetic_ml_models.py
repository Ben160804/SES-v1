"""Run descriptive ML transfer checks against labeled synthetic email sidecars.

The sidecar labels are used only to stratify observed model behavior. They are
not treated as independent anomaly or risk ground truth.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.ml_runtime import analyze_ml_session  # noqa: E402
from testbed.runner.comparator import select_evaluated_session  # noqa: E402

CAPTURES = ROOT / "testbed" / "captures"
INTEGRITY_AUDIT = ROOT / "datasets" / "ml" / "metadata" / "synthetic_sidecar_integrity_v1.json"
FAMILY_MANIFEST = ROOT / "datasets" / "ml" / "splits" / "synthetic_family_manifest_v1.csv"
MODEL_IDS = (
    "synthetic_email_risk_classifier_v1",
    "synthetic_email_posture_classifier_v2",
    "zgrab_evidence_risk_classifier_v1",
    "zgrab_runtime_rule_flag_proxy_v2",
    "zgrab_runtime_risk_tier_v1",
    "zgrab_smtp_anomaly_v1",
    "zgrab_smtp_negotiation_anomaly_v1",
    "mta_sts_cert_anomaly_v1",
)


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def audit() -> dict[str, Any]:
    integrity = _load(INTEGRITY_AUDIT)
    if integrity.get("counts", {}).get("integrity_issue_count") != 0:
        raise ValueError("Synthetic sidecar integrity audit is missing or reports issues; rerun audit_synthetic_sidecars.py first.")
    with FAMILY_MANIFEST.open(newline="", encoding="utf-8") as stream:
        family_rows = {row["scenario_id"]: row for row in csv.DictReader(stream)}
    if len(family_rows) != len(list(CAPTURES.glob("*.expected.json"))):
        raise ValueError("Family manifest does not cover the current expected-sidecar set.")

    rows: list[dict[str, Any]] = []
    skip_counts: Counter[str] = Counter()
    classifier_by_strength: dict[str, Counter[str]] = defaultdict(Counter)
    risk_tier_by_strength: dict[str, Counter[str]] = defaultdict(Counter)
    smtp_anomaly_by_strength: dict[str, dict[str, Counter[str]]] = {
        model_id: defaultdict(Counter)
        for model_id in ("zgrab_smtp_anomaly_v1", "zgrab_smtp_negotiation_anomaly_v1")
    }
    rarity_support_by_strength: dict[str, Counter[str]] = defaultdict(Counter)
    certificate_by_protocol: dict[str, Counter[str]] = defaultdict(Counter)
    synthetic_risk_by_protocol: dict[str, Counter[str]] = defaultdict(Counter)
    zgrab_evidence_by_protocol: dict[str, Counter[str]] = defaultdict(Counter)

    for expected_path in sorted(CAPTURES.glob("*.expected.json")):
        scenario_id = expected_path.name.removesuffix(".expected.json")
        manifest_row = family_rows.get(scenario_id)
        if manifest_row is None or manifest_row.get("comparison_replay_matches") != "True":
            raise ValueError(f"Scenario {scenario_id} is absent from the verified family manifest.")
        observed_path = CAPTURES / f"{scenario_id}.observed.json"
        if not observed_path.exists():
            skip_counts["missing_observed_sidecar"] += 1
            continue
        comparison_path = CAPTURES / f"{scenario_id}.comparison.json"
        pcap_path = CAPTURES / f"{scenario_id}.pcap"
        expected_hashes = {
            "expected_sidecar_sha256": expected_path,
            "observed_sidecar_sha256": observed_path,
            "comparison_sidecar_sha256": comparison_path,
            "pcap_sha256": pcap_path,
        }
        for field, path in expected_hashes.items():
            if not path.is_file() or _digest(path) != manifest_row.get(field):
                raise ValueError(f"Audited input changed or is missing for {scenario_id}: {field}.")
        expected = _load(expected_path).get("expected", {})
        protocol = str(expected.get("protocol") or "Unknown").upper()
        observed = _load(observed_path).get("sessions", {})
        stream_id, session, error = select_evaluated_session(protocol, observed)
        if error or session is None:
            skip_counts["stream_selection_inconclusive"] += 1
            rows.append({
                "scenario_id": scenario_id,
                "scenario_family_id": manifest_row["scenario_family_id"],
                "certificate_identity_group_id": manifest_row["certificate_identity_group_id"],
                "protocol": protocol,
                "status": "INCONCLUSIVE",
                "reason": error or "no_session",
            })
            continue

        strength = str(expected.get("cipher_strength") or "UNKNOWN").upper()
        negotiation_id = "zgrab_smtp_negotiation_anomaly_v1"
        current = analyze_ml_session(session, smtp_model_id=negotiation_id)
        original = analyze_ml_session(session, smtp_model_id="zgrab_smtp_anomaly_v1") if protocol == "SMTP" else None
        row: dict[str, Any] = {
            "scenario_id": scenario_id,
            "scenario_family_id": manifest_row["scenario_family_id"],
            "certificate_identity_group_id": manifest_row["certificate_identity_group_id"],
            "stream_id": stream_id,
            "protocol": protocol,
            "expected_cipher_strength_context": strength,
            "tls_observed": bool(session.get("tls")),
            "classifier": current.get("classifier"),
            "classifier_risk_tier": current.get("classifier_risk_tier"),
            "synthetic_email_risk_classifier": current.get("synthetic_email_risk_classifier"),
            "zgrab_evidence_risk_classifier": current.get("zgrab_evidence_risk_classifier"),
            "smtp_negotiation_anomaly": current.get("smtp_configuration_anomaly"),
            "smtp_configuration_rarity": current.get("smtp_configuration_rarity"),
            "certificate_novelty": current.get("certificate_novelty"),
        }
        if original is not None:
            row["smtp_certificate_aware_anomaly"] = original.get("smtp_configuration_anomaly")

        classifier = row["classifier"] or {}
        classifier_by_strength[strength][classifier.get("status", "UNKNOWN")] += 1
        if classifier.get("predicted_class"):
            classifier_by_strength[strength][classifier["predicted_class"]] += 1
        risk_tier = row["classifier_risk_tier"] or {}
        risk_tier_by_strength[strength][risk_tier.get("status", "UNKNOWN")] += 1
        if risk_tier.get("predicted_tier_proxy"):
            risk_tier_by_strength[strength][risk_tier["predicted_tier_proxy"]] += 1
        synthetic_risk = row["synthetic_email_risk_classifier"] or {}
        synthetic_risk_by_protocol[protocol][synthetic_risk.get("status", "UNKNOWN")] += 1
        if synthetic_risk.get("predicted_risk_tier"):
            synthetic_risk_by_protocol[protocol][synthetic_risk["predicted_risk_tier"]] += 1
        zgrab_risk = row["zgrab_evidence_risk_classifier"] or {}
        zgrab_evidence_by_protocol[protocol][zgrab_risk.get("status", "UNKNOWN")] += 1
        if zgrab_risk.get("predicted_risk_tier"):
            zgrab_evidence_by_protocol[protocol][zgrab_risk["predicted_risk_tier"]] += 1

        if protocol == "SMTP":
            rarity = row.get("smtp_configuration_rarity") or {}
            rarity_support_by_strength[strength][rarity.get("status", "UNKNOWN")] += 1
            if rarity.get("status") == "COMPLETED_EXPLORATORY":
                rarity_support_by_strength[strength][rarity.get("support_status", "UNKNOWN")] += 1
            for model_id, result in (
                ("zgrab_smtp_anomaly_v1", row.get("smtp_certificate_aware_anomaly") or {}),
                (negotiation_id, row.get("smtp_negotiation_anomaly") or {}),
            ):
                bucket = smtp_anomaly_by_strength[model_id][strength]
                bucket[result.get("status", "UNKNOWN")] += 1
                if result.get("status") == "COMPLETED_EXPLORATORY":
                    bucket["UNUSUAL" if result.get("unusual_relative_to_reference") else "NOT_FLAGGED"] += 1
                    bucket["CONFIGURATION_UNSEEN" if result.get("configuration_seen_in_reference") is False else "CONFIGURATION_SEEN"] += 1

        cert_result = row["certificate_novelty"] or {}
        certificate_by_protocol[protocol][cert_result.get("status", "UNKNOWN")] += 1
        if cert_result.get("status") == "COMPLETED_EXPLORATORY":
            certificate_by_protocol[protocol]["UNUSUAL"] += bool(cert_result.get("unusual_relative_to_reference"))
        rows.append(row)

    model_hashes = {}
    for model_id in MODEL_IDS:
        artifact = ROOT / "datasets" / "ml" / "models" / f"{model_id}.joblib"
        model_hashes[model_id] = _digest(artifact) if artifact.is_file() else None

    return {
        "audit_id": "synthetic_email_ml_descriptive_audit_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "evaluation_cohort": "synthetic email PCAP testbed observed sidecars",
        "purpose": "descriptive model coverage and cross-cohort behavior; not accuracy measurement",
        "sidecar_integrity_audit": {
            "audit_id": integrity.get("audit_id"),
            "integrity_issue_count": integrity.get("counts", {}).get("integrity_issue_count"),
            "manifest_sha256": integrity.get("manifest_sha256"),
            "scenario_family_count": integrity.get("counts", {}).get("scenario_family_count"),
            "certificate_bearing_scenarios": integrity.get("counts", {}).get("certificate_bearing_scenarios"),
            "distinct_certificate_identity_groups": integrity.get("counts", {}).get("distinct_certificate_identity_groups"),
            "direct_pcap_reanalysis_status": "NOT_PERFORMED",
        },
        "limitations": [
            "The legacy synthetic model's expected-scenario labels and the v2 simulator's full-profile labels are independent of Rule Engine outputs but are not independent human-reviewed security ground truth.",
            "Classifier target is agreement with seven deterministic ZGrab rule flags; expected cipher strength is not that target.",
            "SMTP reference models transfer from active ZGrab observations to generated passive-PCAP scenarios; transfer is not validated.",
            "Certificate novelty compares synthetic certificates to the MTA-STS scan-certificate cohort; it does not indicate vulnerability.",
            "Filename/ID pairing, PCAPNG validity, and comparator replay were structurally audited; the parser has not freshly re-derived each observed sidecar from its PCAP.",
            "This sidecar audit is a runtime behavior/coverage test, not the v2 grouped model evaluation; see its training metadata for that evaluation.",
            "The 33 certificate-bearing streams share one observed subject/SAN identity group, so they cannot support hostname-held-out certificate generalization claims.",
            "The HTTPS TLS model is intentionally excluded because this testbed is email protocol traffic, not HTTPS.",
        ],
        "counts": {
            "expected_sidecars": len(list(CAPTURES.glob("*.expected.json"))),
            "scored_sidecar_rows": len(rows),
            "protocol_counts": dict(Counter(row.get("protocol", "Unknown") for row in rows)),
            "selection_skip_counts": dict(skip_counts),
        },
        "classifier_by_expected_cipher_strength_context": {
            key: dict(counts) for key, counts in sorted(classifier_by_strength.items())
        },
        "risk_tier_classifier_by_expected_cipher_strength_context": {
            key: dict(counts) for key, counts in sorted(risk_tier_by_strength.items())
        },
        "synthetic_email_risk_classifier_by_protocol": {
            key: dict(counts) for key, counts in sorted(synthetic_risk_by_protocol.items())
        },
        "zgrab_evidence_risk_classifier_by_protocol": {
            key: dict(counts) for key, counts in sorted(zgrab_evidence_by_protocol.items())
        },
        "smtp_anomaly_by_expected_cipher_strength_context": {
            model_id: {key: dict(counts) for key, counts in sorted(by_strength.items())}
            for model_id, by_strength in smtp_anomaly_by_strength.items()
        },
        "smtp_configuration_rarity_by_expected_cipher_strength_context": {
            key: dict(counts) for key, counts in sorted(rarity_support_by_strength.items())
        },
        "certificate_novelty_by_protocol": {
            protocol: dict(counts) for protocol, counts in sorted(certificate_by_protocol.items())
        },
        "model_artifact_sha256": model_hashes,
        "scenario_results": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path,
        default=ROOT / "datasets" / "ml" / "models" / "synthetic_email_ml_audit_v1.json",
    )
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output.relative_to(ROOT) if args.output.is_relative_to(ROOT) else args.output),
        "counts": result["counts"],
        "classifier_by_expected_cipher_strength_context": result["classifier_by_expected_cipher_strength_context"],
        "risk_tier_classifier_by_expected_cipher_strength_context": result["risk_tier_classifier_by_expected_cipher_strength_context"],
        "synthetic_email_risk_classifier_by_protocol": result["synthetic_email_risk_classifier_by_protocol"],
        "zgrab_evidence_risk_classifier_by_protocol": result["zgrab_evidence_risk_classifier_by_protocol"],
        "smtp_anomaly_by_expected_cipher_strength_context": result["smtp_anomaly_by_expected_cipher_strength_context"],
        "smtp_configuration_rarity_by_expected_cipher_strength_context": result["smtp_configuration_rarity_by_expected_cipher_strength_context"],
        "certificate_novelty_by_protocol": result["certificate_novelty_by_protocol"],
    }, indent=2))


if __name__ == "__main__":
    main()
