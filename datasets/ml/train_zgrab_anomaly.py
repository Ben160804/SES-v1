"""Fit an SMTP-only Isolation Forest with a rarity reference baseline."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "ml" / "processed" / "zgrab_smtp_v1.csv"
LABELS = ROOT / "datasets" / "ml" / "labels" / "zgrab_risk_proxy_v1.csv"
MODEL_DIR = ROOT / "datasets" / "ml" / "models"
MODEL_PATH = MODEL_DIR / "zgrab_smtp_anomaly_v1.joblib"
METADATA_PATH = MODEL_DIR / "zgrab_smtp_anomaly_v1.json"
SCORES_PATH = ROOT / "datasets" / "ml" / "processed" / "zgrab_smtp_anomaly_scores_v1.csv"
SEED = 20260929
CONTAMINATION = 0.05

CATEGORICAL_FEATURES = (
    "tls_version",
    "cipher_suite",
    "key_exchange",
    "cert_key_algorithm",
    "cert_ecdsa_curve",
    "cert_signature_algorithm",
)
NUMERIC_FEATURES = (
    "tls_extension_count",
    "cert_rsa_key_size",
    "cert_ecdsa_key_size",
    "cert_chain_length",
)


def _features(row: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        name: row.get(name) or "__MISSING__"
        for name in CATEGORICAL_FEATURES
    }
    for name in NUMERIC_FEATURES:
        value = row.get(name, "")
        try:
            result[name] = float(value) if value else 0.0
            result[f"{name}__missing"] = 0.0 if value else 1.0
        except ValueError:
            result[name] = 0.0
            result[f"{name}__missing"] = 1.0
    return result


def _configuration_key(row: dict[str, str]) -> str:
    return json.dumps(
        [row.get("tls_version"), row.get("cipher_suite"), row.get("key_exchange")],
        separators=(",", ":"),
    )


def train() -> None:
    try:
        import joblib
        import sklearn
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction import DictVectorizer
    except ImportError as exc:
        raise RuntimeError(
            "ML dependency missing. Install with: "
            "python -m pip install -r datasets/ml/requirements.txt"
        ) from exc

    with DATA.open(newline="", encoding="utf-8") as source:
        observations = list(csv.DictReader(source))
    with LABELS.open(newline="", encoding="utf-8") as source:
        label_by_id = {r["record_id"]: r for r in csv.DictReader(source)}

    eligible = [
        row for row in observations
        if row["tls_observation_state"] == "HANDSHAKE_SUCCEEDED"
    ]
    reference = [
        row for row in eligible
        if label_by_id[row["record_id"]]["label"] == "NO_CURRENT_RULE_FLAG"
    ]
    if len(reference) < 30:
        raise ValueError(f"Reference cohort too small: {len(reference)}")

    vectorizer = DictVectorizer(sparse=True)
    reference_matrix = vectorizer.fit_transform([_features(r) for r in reference])
    model = IsolationForest(
        n_estimators=300,
        max_samples=min(256, len(reference)),
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=1,
    )
    model.fit(reference_matrix)

    # Score each country against a reference that excludes that entire country.
    # This is still cohort-relative, but avoids reporting training-set scores as
    # if they were an evaluation of unseen observations.
    crossfit_by_id: dict[str, tuple[float, bool]] = {}
    crossfit_rarity_by_id: dict[str, tuple[float, int, int]] = {}
    countries = sorted({row.get("country", "") for row in eligible})
    for country in countries:
        fold_reference = [
            row for row in reference if row.get("country", "") != country
        ]
        fold_test = [row for row in eligible if row.get("country", "") == country]
        if len(fold_reference) < 30 or not fold_test:
            continue
        fold_vectorizer = DictVectorizer(sparse=True)
        fold_train_matrix = fold_vectorizer.fit_transform(
            [_features(r) for r in fold_reference]
        )
        fold_model = IsolationForest(
            n_estimators=300,
            max_samples=min(256, len(fold_reference)),
            contamination=CONTAMINATION,
            random_state=SEED,
            n_jobs=1,
        )
        fold_model.fit(fold_train_matrix)
        fold_matrix = fold_vectorizer.transform([_features(r) for r in fold_test])
        decisions = fold_model.decision_function(fold_matrix)
        flags = fold_model.predict(fold_matrix)
        fold_config_counts = Counter(_configuration_key(row) for row in fold_reference)
        fold_config_count = len(fold_config_counts)
        fold_reference_count = len(fold_reference)
        for row, decision, flag in zip(fold_test, decisions, flags):
            crossfit_by_id[row["record_id"]] = (float(-decision), int(flag) == -1)
            count = fold_config_counts[_configuration_key(row)]
            probability = (count + 1) / (fold_reference_count + fold_config_count)
            crossfit_rarity_by_id[row["record_id"]] = (
                -math.log2(probability), count, fold_reference_count
            )

    config_counts = Counter(_configuration_key(row) for row in reference)
    reference_count = len(reference)
    distinct_configurations = len(config_counts)
    reference_ids = {row["record_id"] for row in reference}
    scored = []
    model_flagged_reference = 0
    for row in observations:
        base = {
            "record_id": row["record_id"],
            "data_source": row["data_source"],
            "status": "NOT_EVALUABLE",
            "reference_cohort": "zgrab_smtp_no_current_rule_flag_v1",
            "anomaly_status": "NOT_EVALUABLE",
            "isolation_forest_score": "",
            "crossfit_isolation_forest_score": "",
            "crossfit_anomaly_status": "NOT_EVALUABLE",
            "crossfit_rarity_score_bits": "",
            "crossfit_configuration_count": "",
            "crossfit_reference_count": "",
            "crossfit_rarity_status": "NOT_EVALUABLE",
            "rarity_score_bits": "",
            "reference_configuration_count": "",
            "reference_configuration_frequency": "",
        }
        if row["tls_observation_state"] == "HANDSHAKE_SUCCEEDED":
            matrix = vectorizer.transform([_features(row)])
            decision = float(model.decision_function(matrix)[0])
            is_outlier = int(model.predict(matrix)[0]) == -1
            key = _configuration_key(row)
            count = config_counts[key]
            smoothed_probability = (count + 1) / (reference_count + distinct_configurations)
            rarity_bits = -math.log2(smoothed_probability)
            base.update({
                "status": "COMPLETED",
                "anomaly_status": (
                    "UNUSUAL_RELATIVE_TO_REFERENCE" if is_outlier
                    else "WITHIN_MODEL_REFERENCE"
                ),
                "isolation_forest_score": f"{-decision:.8f}",
                "rarity_score_bits": f"{rarity_bits:.6f}",
                "reference_configuration_count": count,
                "reference_configuration_frequency": f"{count / reference_count:.8f}",
            })
            if row["record_id"] in crossfit_by_id:
                crossfit_score, crossfit_flag = crossfit_by_id[row["record_id"]]
                base["crossfit_isolation_forest_score"] = f"{crossfit_score:.8f}"
                base["crossfit_anomaly_status"] = (
                    "UNUSUAL_RELATIVE_TO_HELDOUT_COUNTRY_REFERENCE"
                    if crossfit_flag else "WITHIN_HELDOUT_COUNTRY_REFERENCE"
                )
            if row["record_id"] in crossfit_rarity_by_id:
                rarity_bits, count, fold_n = crossfit_rarity_by_id[row["record_id"]]
                base["crossfit_rarity_score_bits"] = f"{rarity_bits:.6f}"
                base["crossfit_configuration_count"] = count
                base["crossfit_reference_count"] = fold_n
                base["crossfit_rarity_status"] = (
                    "UNSEEN_CONFIGURATION" if count == 0
                    else "SEEN_CONFIGURATION"
                )
            if row["record_id"] in reference_ids and is_outlier:
                model_flagged_reference += 1
        scored.append(base)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    SCORES_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "model": model}, MODEL_PATH)
    artifact_sha256 = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with SCORES_PATH.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(scored[0]))
        writer.writeheader()
        writer.writerows(scored)

    metadata = {
        "model_id": "zgrab_smtp_anomaly_v1",
        "model_version": "1.0",
        "feature_schema_version": "zgrab_smtp_v1",
        "algorithm": "IsolationForest",
        "cohort": "Real-world active ZGrab SMTP TLS handshakes with no current rule flags; not a claim of benignity.",
        "reference_count": reference_count,
        "scored_tls_handshakes": len(eligible),
        "not_evaluable_records": len(observations) - len(eligible),
        "reference_configuration_count": distinct_configurations,
        "contamination_assumption": CONTAMINATION,
        "reference_inliers_flagged_in_sample": model_flagged_reference,
        "grouped_crossfit": {
            "method": "leave-one-country-out",
            "countries": countries,
            "scored_records": len(crossfit_by_id),
            "unscored_records": len(eligible) - len(crossfit_by_id),
            "flagged_records": sum(flag for _, flag in crossfit_by_id.values()),
            "rarity_scored_records": len(crossfit_rarity_by_id),
            "unseen_configuration_records": sum(
                count == 0 for _, count, _ in crossfit_rarity_by_id.values()
            ),
            "caveat": "Outlier prevalence is controlled by the per-fold contamination assumption; this is not anomaly ground truth or precision/recall.",
        },
        "seed": SEED,
        "features": list(CATEGORICAL_FEATURES + NUMERIC_FEATURES),
            "rarity_key": ["tls_version", "cipher_suite", "key_exchange"],
        "rarity_method": "Leave-one-country-out add-one-smoothed frequency; a tuple absent from the other countries' no-current-rule-flag reference is marked UNSEEN_CONFIGURATION.",
        "rarity_reference_counts": [
            {"configuration": key, "count": count, "frequency": count / reference_count}
            for key, count in sorted(config_counts.items())
        ],
        "limitations": [
            "Anomaly means unusual relative to this 469-observation SMTP scan cohort, not vulnerable, malicious, or evidence of attack.",
            "The reference cohort is selected by absence of the current deterministic flags; it is not verified benign ground truth.",
            "The 5% contamination value is an explicit operating assumption, not a measured real-world false-positive rate.",
            "No labeled real anomalies are available, so precision/recall are not reported.",
            "Grouped cross-fit scores exclude the scored record's country from the clean reference, but remain cohort-relative and unlabeled.",
            "TLS 1.3 HTTPS PCAPs and MTA-STS certificate records are separate datasets and were not mixed into this SMTP model.",
        ],
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "artifact_sha256": artifact_sha256,
        "model_path": str(MODEL_PATH.relative_to(ROOT)),
        "scores_path": str(SCORES_PATH.relative_to(ROOT)),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Reference: {reference_count}; scored TLS: {len(eligible)}; non-TLS: {len(observations) - len(eligible)}")
    print(f"Outliers among reference training rows: {model_flagged_reference} (contamination assumption {CONTAMINATION:.0%})")
    print(f"Model: {MODEL_PATH.relative_to(ROOT)}")
    print(f"Scores: {SCORES_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    try:
        train()
    except (ImportError, RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"Anomaly training unavailable: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
