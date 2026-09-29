"""Train a negotiation-only SMTP novelty model for passive-PCAP feature parity."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

DATA = ROOT / "datasets/ml/processed/zgrab_smtp_v1.csv"
LABELS = ROOT / "datasets/ml/labels/zgrab_risk_proxy_v1.csv"
MODEL_DIR = ROOT / "datasets/ml/models"
MODEL_PATH = MODEL_DIR / "zgrab_smtp_negotiation_anomaly_v1.joblib"
METADATA_PATH = MODEL_DIR / "zgrab_smtp_negotiation_anomaly_v1.json"
SCORES_PATH = ROOT / "datasets/ml/processed/zgrab_smtp_negotiation_anomaly_scores_v2.csv"
SEED = 20260929
CONTAMINATION = 0.05
CATEGORICAL = ("tls_negotiated_version", "cipher_suite", "key_exchange")


def feature_row(row: dict[str, str]) -> dict[str, Any]:
    return {
        "tls_negotiated_version": row.get("tls_selected_version") or row.get("tls_version") or "__MISSING__",
        "cipher_suite": row.get("cipher_suite") or "__MISSING__",
        "key_exchange": row.get("key_exchange") or "__MISSING__",
    }


def configuration_key(row: dict[str, str]) -> str:
    return json.dumps([
        row.get("tls_selected_version") or row.get("tls_version"),
        row.get("cipher_suite"),
        row.get("key_exchange"),
    ], separators=(",", ":"))


def train() -> dict[str, Any]:
    try:
        import joblib
        import sklearn
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction import DictVectorizer
    except ImportError as exc:
        raise RuntimeError("Install datasets/ml/requirements.txt before training.") from exc

    with DATA.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    with LABELS.open(newline="", encoding="utf-8") as source:
        labels = {row["record_id"]: row["label"] for row in csv.DictReader(source)}
    eligible = [row for row in rows if row["tls_observation_state"] == "HANDSHAKE_SUCCEEDED"]
    reference = [row for row in eligible if labels[row["record_id"]] == "NO_CURRENT_RULE_FLAG"]
    if len(reference) < 30:
        raise ValueError(f"Reference cohort too small: {len(reference)}")
    configuration_counts = Counter(configuration_key(row) for row in reference)

    vectorizer = DictVectorizer(sparse=True)
    train_matrix = vectorizer.fit_transform([feature_row(row) for row in reference])
    model = IsolationForest(
        n_estimators=300,
        max_samples=min(256, len(reference)),
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=1,
    ).fit(train_matrix)

    # Country-held-out scores characterize cohort stability, not anomaly accuracy.
    grouped_scores: dict[str, tuple[float, bool]] = {}
    for country in sorted({row.get("country", "") for row in eligible}):
        fold_reference = [row for row in reference if row.get("country", "") != country]
        fold_test = [row for row in eligible if row.get("country", "") == country]
        if len(fold_reference) < 30 or not fold_test:
            continue
        fold_vectorizer = DictVectorizer(sparse=True)
        fold_train = fold_vectorizer.fit_transform([feature_row(row) for row in fold_reference])
        fold_model = IsolationForest(
            n_estimators=300,
            max_samples=min(256, len(fold_reference)),
            contamination=CONTAMINATION,
            random_state=SEED,
            n_jobs=1,
        ).fit(fold_train)
        matrix = fold_vectorizer.transform([feature_row(row) for row in fold_test])
        scores = -fold_model.decision_function(matrix)
        flags = fold_model.predict(matrix)
        for row, score, flag in zip(fold_test, scores, flags):
            grouped_scores[row["record_id"]] = (float(score), int(flag) == -1)

    model_rows = []
    for row in rows:
        item = {
            "record_id": row["record_id"],
            "data_source": row["data_source"],
            "country": row.get("country", ""),
            "status": "NOT_EVALUABLE",
            "isolation_forest_score": "",
            "crossfit_score": "",
            "crossfit_unusual": "",
        }
        if row["tls_observation_state"] == "HANDSHAKE_SUCCEEDED":
            matrix = vectorizer.transform([feature_row(row)])
            item["status"] = "SCORED_IN_SAMPLE"
            item["isolation_forest_score"] = f"{-float(model.decision_function(matrix)[0]):.8f}"
            if row["record_id"] in grouped_scores:
                score, flag = grouped_scores[row["record_id"]]
                item["crossfit_score"] = f"{score:.8f}"
                item["crossfit_unusual"] = str(flag).lower()
        model_rows.append(item)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    SCORES_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "model": model}, MODEL_PATH)
    artifact_hash = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with SCORES_PATH.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(model_rows[0]))
        writer.writeheader()
        writer.writerows(model_rows)

    counts = Counter(row["crossfit_unusual"] for row in model_rows if row["crossfit_unusual"])
    metadata = {
        "model_id": "zgrab_smtp_negotiation_anomaly_v1",
        "model_version": "2.0",
        "feature_schema_version": "zgrab_smtp_negotiation_v2",
        "algorithm": "Empirical configuration rarity (primary); IsolationForest (secondary)",
        "primary_novelty_method": "Exact tuple support over negotiated TLS version, cipher suite, and key exchange in the named reference cohort; an unseen tuple is novel relative to that cohort.",
        "secondary_algorithm": "IsolationForest",
        "reference_cohort": "ZGrab SMTP TLS handshakes without current deterministic rule flags; not verified benign.",
        "reference_count": len(reference),
        "reference_configuration_count": len(configuration_counts),
        "rarity_reference_counts": [
            {"configuration": json.loads(key), "count": count}
            for key, count in sorted(configuration_counts.items())
        ],
        "scored_handshakes": len(eligible),
        "not_evaluable_records": len(rows) - len(eligible),
        "contamination_assumption": CONTAMINATION,
        "features": list(CATEGORICAL),
        "tls_version_normalization": "tls_selected_version preferred; legacy tls_version fallback when no negotiated value is available",
        "feature_selection_note": "Negotiated TLS version, cipher, and key exchange are retained; certificate and extension-count features are excluded because they are not consistently observable in the passive-PCAP adapter.",
        "country_held_out": {
            "method": "leave-one-country-out",
            "scored": len(grouped_scores),
            "flagged": counts["true"],
            "limitation": "Unlabeled cohort-stability audit, not performance evaluation.",
        },
        "limitations": [
            "Novelty is relative to an active ZGrab SMTP reference cohort, not attack likelihood or vulnerability.",
            "The reference cohort is selected by no current deterministic flags; it is not verified benign.",
            "The five-percent contamination parameter applies only to the secondary Isolation Forest and is not a measured false-positive rate.",
            "The primary exact-support novelty flag is intentionally sensitive to cohort shift; unseen does not mean insecure.",
            "In the controlled synthetic transfer audit, exact support marked all 8 BROKEN and 6 WEAK tuples unseen; this is a novelty coverage check, not anomaly precision/recall.",
            "Certificate fields are intentionally excluded because passive PCAPs often cannot observe TLS 1.3 certificates.",
            "The model is not yet validated for operational use on passive-PCAP populations; consult reference support and transfer audit.",
            "No independent labeled real anomalies are available; precision/recall are not reported.",
        ],
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "label_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
        "artifact_sha256": artifact_hash,
        "scores_path": str(SCORES_PATH.relative_to(ROOT)),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"metadata": metadata, "model_path": str(MODEL_PATH.relative_to(ROOT))}


if __name__ == "__main__":
    result = train()
    print(json.dumps({
        "model_id": result["metadata"]["model_id"],
        "reference_count": result["metadata"]["reference_count"],
        "scored_handshakes": result["metadata"]["scored_handshakes"],
        "country_held_out": result["metadata"]["country_held_out"],
    }, indent=2))
