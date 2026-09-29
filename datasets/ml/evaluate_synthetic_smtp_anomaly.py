"""Audit real-ZGrab SMTP novelty outputs on labeled synthetic SMTP scenarios.

This is a cross-cohort behavior audit, not an anomaly-accuracy evaluation:
scenario TLS/cipher labels are not independent attack/anomaly ground truth.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.ml_runtime import analyze_ml_session  # noqa: E402
from testbed.runner.comparator import select_evaluated_session  # noqa: E402


CAPTURES = ROOT / "testbed" / "captures"
def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit(model_id: str = "zgrab_smtp_negotiation_anomaly_v1") -> dict:
    rows = []
    scored_model_id = None
    skip_reasons = Counter()
    for expected_path in sorted(CAPTURES.glob("*.expected.json")):
        scenario_id = expected_path.name.removesuffix(".expected.json")
        observed_path = CAPTURES / f"{scenario_id}.observed.json"
        if not observed_path.exists():
            skip_reasons["missing_observed_sidecar"] += 1
            continue
        expected_artifact = _load(expected_path)
        observed = _load(observed_path)
        expected = expected_artifact.get("expected", {})
        sessions = observed.get("sessions", {})
        if str(expected.get("protocol", "")).upper() != "SMTP":
            skip_reasons["non_smtp_scenario"] += 1
            continue
        stream_id, session, error = select_evaluated_session("SMTP", sessions)
        if error or session is None:
            skip_reasons["stream_selection_inconclusive"] += 1
            rows.append({
                "scenario_id": scenario_id,
                "status": "INCONCLUSIVE",
                "reason": error or "no_session",
                "expected_tls_version": expected.get("tls_version"),
                "expected_cipher_strength": expected.get("cipher_strength"),
            })
            continue

        result = analyze_ml_session(session, smtp_model_id=model_id)["smtp_configuration_anomaly"]
        scored_model_id = scored_model_id or result.get("model_id")
        row = {
            "scenario_id": scenario_id,
            "stream_id": stream_id,
            "status": result.get("status", "UNKNOWN"),
            "expected_tls_presence": expected.get("tls_presence"),
            "expected_tls_version": expected.get("tls_version"),
            "expected_cipher_strength": expected.get("cipher_strength"),
            "observed_tls_version": (session.get("tls") or {}).get("tls_version"),
            "observed_cipher": (session.get("tls") or {}).get("cipher_name"),
            "unusual_relative_to_reference": result.get("unusual_relative_to_reference"),
            "primary_rarity_flag": result.get("anomaly_flag"),
            "primary_prediction": result.get("prediction"),
            "isolation_forest_score": result.get("isolation_forest_score"),
            "isolation_forest_flag": result.get("isolation_forest_flag"),
            "configuration_seen_in_reference": result.get("configuration_seen_in_reference"),
            "configuration_rarity_bits": result.get("configuration_rarity_bits"),
        }
        rows.append(row)
        if row["status"] != "COMPLETED_EXPLORATORY":
            skip_reasons[row["status"]] += 1

    grouped: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if row["status"] != "COMPLETED_EXPLORATORY":
            continue
        strength = str(row.get("expected_cipher_strength") or "UNKNOWN").upper()
        grouped[strength]["scored"] += 1
        grouped[strength]["unusual"] += bool(row.get("unusual_relative_to_reference"))
        grouped[strength]["primary_rarity_flags"] += bool(row.get("primary_rarity_flag"))
        grouped[strength]["isolation_forest_flags"] += bool(row.get("isolation_forest_flag"))
        grouped[strength]["configuration_unseen"] += row.get("configuration_seen_in_reference") is False

    return {
        "audit_id": f"{scored_model_id or 'unknown'}_synthetic_transfer_audit",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_id": scored_model_id,
        "model_artifact_sha256": (
            _sha256(ROOT / "datasets" / "ml" / "models" / f"{scored_model_id}.joblib")
            if scored_model_id and (ROOT / "datasets" / "ml" / "models" / f"{scored_model_id}.joblib").is_file()
            else None
        ),
        "reference_cohort": "real active ZGrab SMTP TLS negotiation features without current rule flags",
        "evaluation_cohort": "controlled synthetic SMTP PCAP testbed sidecars",
        "purpose": "descriptive cross-cohort novelty behavior and evaluation coverage audit",
        "limitations": [
            "The primary rarity flag means an exact negotiated tuple was not seen in the real ZGrab SMTP reference cohort; it is not an insecurity or attack label.",
            "Synthetic expected TLS/cipher labels are not independent anomaly or attack ground truth.",
            "Counts by expected cipher strength are descriptive; they are not precision, recall, or detector accuracy.",
            "The ZGrab reference and synthetic PCAP cohort differ in collection and generation process.",
            "Scenario labels are kept at scenario level; no labels are copied to unrelated streams.",
            "Isolation Forest is reported separately because the prior transfer audit showed poor sensitivity to controlled weak/broken tuples.",
        ],
        "counts": {
            "smtp_scenarios_with_sidecars": len(rows),
            "scored": sum(row["status"] == "COMPLETED_EXPLORATORY" for row in rows),
            "not_evaluable_or_inconclusive": sum(row["status"] != "COMPLETED_EXPLORATORY" for row in rows),
            "skipped_non_smtp_scenarios": skip_reasons.pop("non_smtp_scenario", 0),
            "missing_observed_sidecars": skip_reasons.pop("missing_observed_sidecar", 0),
        },
        "unscored_status_counts": dict(sorted(skip_reasons.items())),
        "descriptive_by_expected_cipher_strength": {
            key: dict(value) for key, value in sorted(grouped.items())
        },
        "scenario_results": rows,
        "input_sha256": {
            "expected_sidecars": {p.name: _sha256(p) for p in sorted(CAPTURES.glob("*.expected.json"))},
            "observed_sidecars": {p.name: _sha256(p) for p in sorted(CAPTURES.glob("*.observed.json"))},
        },
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-id", choices=(
        "zgrab_smtp_anomaly_v1", "zgrab_smtp_negotiation_anomaly_v1"
    ), default="zgrab_smtp_negotiation_anomaly_v1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.model_id)
    output = args.output or ROOT / "datasets" / "ml" / "models" / f"{args.model_id}_synthetic_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        output_label = str(output.relative_to(ROOT))
    except ValueError:
        output_label = str(output)
    print(json.dumps({"output": output_label, "counts": result["counts"], "by_cipher_strength": result["descriptive_by_expected_cipher_strength"]}, indent=2))
