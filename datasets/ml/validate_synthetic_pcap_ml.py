"""Freshly parse synthetic email PCAPs and summarize per-model runtime coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analysis.rule_engine.engine import RuleEngine  # noqa: E402

CAPTURES = ROOT / "testbed" / "captures"
DEFAULT_OUTPUT = ROOT / "datasets" / "ml" / "models" / "synthetic_pcap_runtime_coverage_v1.json"
MODEL_FIELDS = (
    "synthetic_email_risk_classifier",
    "zgrab_evidence_risk_classifier",
    "classifier",
    "classifier_risk_tier",
    "smtp_configuration_anomaly",
    "smtp_configuration_rarity",
    "certificate_novelty",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def audit(limit: int | None = None) -> dict[str, Any]:
    captures = sorted(CAPTURES.glob("*.pcap"))
    if limit is not None:
        captures = captures[:limit]
    protocol_counts: Counter[str] = Counter()
    tls_version_counts: Counter[str] = Counter()
    starttls_status_counts: Counter[str] = Counter()
    cipher_strength_counts: Counter[str] = Counter()
    observability_counts: dict[str, Counter[str]] = defaultdict(Counter)
    coverage: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    rows: list[dict[str, Any]] = []

    for capture in captures:
        scenario_id = capture.stem
        expected_path = CAPTURES / f"{scenario_id}.expected.json"
        expected = _read_json(expected_path).get("expected", {}) if expected_path.is_file() else {}
        try:
            report = RuleEngine(enable_ml=True).evaluate_pcap(str(capture))
            for stream_id, stream in report.stream_reports.items():
                protocol = str(stream.protocol or "Unknown").upper()
                protocol_counts[protocol] += 1
                model_results = stream.ml_results or {}
                snapshot = stream.input_snapshot or {}
                tls_version = str(snapshot.get("tls_version") or "NOT_OBSERVED")
                starttls_status = str(snapshot.get("starttls_status") or "UNKNOWN")
                cipher_strength = str((snapshot.get("heuristics") or {}).get("h_cipher_strength") or "UNKNOWN")
                tls_version_counts[tls_version] += 1
                starttls_status_counts[starttls_status] += 1
                cipher_strength_counts[cipher_strength] += 1
                observability_counts[protocol]["TLS_OBSERVED" if snapshot.get("tls_version") else "NO_TLS_VERSION"] += 1
                observability_counts[protocol]["CERT_OBSERVABLE" if snapshot.get("cert_observable") else "CERT_NOT_OBSERVABLE"] += 1
                row = {
                    "scenario_id": scenario_id,
                    "capture_sha256": _sha256(capture),
                    "stream_id": stream_id,
                    "expected_protocol_context": expected.get("protocol"),
                    "expected_cipher_strength_context": expected.get("cipher_strength"),
                    "observed_protocol": protocol,
                    "observed_tls_version": tls_version,
                    "observed_starttls_status": starttls_status,
                    "observed_cipher_strength_context": cipher_strength,
                    "certificate_observable": bool(snapshot.get("cert_observable")),
                    "ml_results": {},
                }
                for field in MODEL_FIELDS:
                    result = model_results.get(field) or {"status": "MISSING_OUTPUT"}
                    status = str(result.get("status", "UNKNOWN"))
                    coverage[protocol][field][status] += 1
                    row["ml_results"][field] = {
                        key: result.get(key)
                        for key in (
                            "status", "evaluation_status", "model_id", "model_name", "model_version", "baseline_id",
                            "reason", "prediction", "predicted_class", "predicted_tier_proxy", "predicted_risk_tier",
                            "confidence_score_uncalibrated", "anomaly_score", "anomaly_flag",
                            "certificate_novelty_score", "novelty_flag", "unusual_relative_to_reference",
                            "support_status", "cohort", "data_source", "feature_coverage",
                            "feature_observability",
                        )
                        if key in result
                    }
                rows.append(row)
            if not report.stream_reports:
                rows.append({"scenario_id": scenario_id, "capture_sha256": _sha256(capture), "status": "NO_STREAMS"})
        except Exception as exc:
            rows.append({
                "scenario_id": scenario_id,
                "capture_sha256": _sha256(capture),
                "status": "ANALYSIS_ERROR",
                "error_type": type(exc).__name__,
            })

    summary = {
        protocol: {model: dict(counts) for model, counts in sorted(models.items())}
        for protocol, models in sorted(coverage.items())
    }
    failed = Counter(row.get("status", "ANALYZED") for row in rows if row.get("status") != "ANALYZED")
    return {
        "audit_id": "synthetic_pcap_runtime_coverage_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "data_source": "synthetic_email_testbed",
        "purpose": "Fresh parser-to-rule-and-ML runtime coverage; not model accuracy or real-world validation.",
        "parser": "PCAPAnalyzer via RuleEngine.evaluate_pcap; TShark is required.",
        "scope": {"capture_count": len(captures), "stream_count": sum(protocol_counts.values()), "protocol_stream_counts": dict(protocol_counts)},
        "observability": {
            "tls_version_distribution": dict(tls_version_counts),
            "starttls_status_distribution": dict(starttls_status_counts),
            "parsed_cipher_strength_distribution": dict(cipher_strength_counts),
            "protocol_observability": {protocol: dict(counts) for protocol, counts in sorted(observability_counts.items())},
        },
        "outcome_counts": dict(failed),
        "model_status_by_observed_protocol": summary,
        "limitations": [
            "Synthetic captures are controlled test inputs, not representative production traffic.",
            "Statuses measure whether a model ran or abstained, not its predictive accuracy.",
            "Expected protocol and cipher-strength fields are context only; they are not fed to runtime models.",
            "SMTP anomaly and rarity outputs are cohort-relative. The real-ZGrab classifier target is a deterministic-rule proxy; the shared email classifier uses synthetic expected-scenario rubric labels and has poor family-heldout effectiveness.",
        ],
        "capture_results": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="Audit only the first N captures (smoke test).")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    result = audit(args.limit)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output.relative_to(ROOT) if output.is_relative_to(ROOT) else output),
        "scope": result["scope"],
        "observability": result["observability"],
        "outcome_counts": result["outcome_counts"],
        "model_status_by_observed_protocol": result["model_status_by_observed_protocol"],
    }, indent=2))


if __name__ == "__main__":
    main()
