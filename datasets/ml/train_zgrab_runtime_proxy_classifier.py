"""Train a rule-flag proxy classifier on features observable by PCAP runtime."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from train_zgrab_risk_classifier import DATA, MODEL_DIR, POSITIVE, _read_joined_rows

ROOT = Path(__file__).resolve().parents[2]
MODEL_ID = "zgrab_runtime_rule_flag_proxy_v2"
MODEL_PATH = MODEL_DIR / f"{MODEL_ID}.joblib"
METADATA_PATH = MODEL_DIR / f"{MODEL_ID}.json"
OOF_PATH = MODEL_DIR / f"{MODEL_ID}_oof.csv"
SEED = 20260929

CATEGORICAL = (
    "tls_negotiated_version", "cipher_suite", "key_exchange",
    "cert_key_algorithm", "cert_ecdsa_curve", "cert_signature_algorithm",
    "cert_self_signed", "cert_is_ca", "cert_server_auth", "cert_client_auth",
    "cert_digital_signature", "cert_key_encipherment", "cert_key_agreement",
    "cert_has_wildcard_san", "cert_has_certificate_policy", "cert_has_sct",
    "cert_has_crl_distribution", "cert_has_authority_key_id", "cert_has_subject_key_id",
)
NUMERIC = (
    "cert_rsa_key_size", "cert_rsa_exponent", "cert_ecdsa_key_size",
    "cert_san_count", "cert_max_san_length", "cert_unique_san_count",
    "cert_key_usage_count", "cert_extension_count", "cert_validity_days",
    "cert_chain_length", "cert_ocsp_url_count", "cert_issuer_url_count",
    "cert_policy_count", "cert_crl_url_count",
)


def _features(row: dict[str, str]) -> dict[str, Any]:
    source = dict(row)
    source["tls_negotiated_version"] = row.get("tls_selected_version") or row.get("tls_version") or ""
    result: dict[str, Any] = {}
    for name in CATEGORICAL:
        value = source.get(name, "")
        result[name] = value if value else "__MISSING__"
    for name in NUMERIC:
        value = source.get(name, "")
        try:
            result[name] = float(value) if value else 0.0
            result[f"{name}__missing"] = 0.0 if value else 1.0
        except (TypeError, ValueError):
            result[name] = 0.0
            result[f"{name}__missing"] = 1.0
    return result


def _coverage(features: dict[str, Any]) -> float:
    observed = sum(features[name] != "__MISSING__" for name in CATEGORICAL)
    observed += sum(features[f"{name}__missing"] == 0.0 for name in NUMERIC)
    return observed / (len(CATEGORICAL) + len(NUMERIC))


def train() -> dict[str, Any]:
    try:
        import joblib
        import sklearn
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support
        from sklearn.model_selection import LeaveOneGroupOut
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise RuntimeError("Install datasets/ml/requirements.txt before training.") from exc

    rows = _read_joined_rows()
    x = [_features(row) for row in rows]
    y = [row["label"] for row in rows]
    groups = [row["country"] for row in rows]
    if len(set(y)) != 2:
        raise ValueError("Both rule-flag proxy classes are required.")
    pipeline = make_pipeline(
        DictVectorizer(sparse=True),
        StandardScaler(with_mean=False),
        LogisticRegression(class_weight="balanced", max_iter=3000, random_state=SEED),
    )

    predictions = [""] * len(rows)
    scores = [""] * len(rows)
    majority_predictions = [""] * len(rows)
    folds = []
    for train_index, test_index in LeaveOneGroupOut().split(x, y, groups):
        fit_y = [y[index] for index in train_index]
        majority = Counter(fit_y).most_common(1)[0][0]
        pipeline.fit([x[index] for index in train_index], fit_y)
        pred = pipeline.predict([x[index] for index in test_index])
        prob = pipeline.predict_proba([x[index] for index in test_index])
        positive_column = list(pipeline.classes_).index(POSITIVE)
        for offset, index in enumerate(test_index):
            predictions[index] = str(pred[offset])
            scores[index] = float(prob[offset][positive_column])
            majority_predictions[index] = majority
        folds.append({
            "held_out_country": groups[test_index[0]],
            "train_rows": len(train_index),
            "test_rows": len(test_index),
            "test_label_counts": dict(Counter(y[index] for index in test_index)),
        })

    ordered_labels = ["NO_CURRENT_RULE_FLAG", POSITIVE]
    confusion = confusion_matrix(y, predictions, labels=ordered_labels)
    precision, recall, per_class_f1, support = precision_recall_fscore_support(
        y, predictions, labels=ordered_labels, zero_division=0,
    )
    per_class = {
        label: {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(per_class_f1[index]),
            "support": int(support[index]),
        }
        for index, label in enumerate(ordered_labels)
    }
    coverage = sorted(_coverage(row) for row in x)
    evaluation = {
        "model_id": MODEL_ID,
        "model_version": "2.0",
        "feature_schema_version": "zgrab_smtp_runtime_proxy_v2",
        "dataset_id": "zgrab_smtp_v1",
        "target": "rule_flag_proxy_v1",
        "target_semantics": "Agreement with the union of seven deterministic ZGrab rule flags; not independent risk ground truth.",
        "model": "DictVectorizer + StandardScaler + class-weighted LogisticRegression",
        "evaluation": "Leave-one-country-out cross-validation; country is grouping metadata, never a feature.",
        "sample_count": len(rows),
        "class_counts": dict(Counter(y)),
        "macro_f1": float(f1_score(y, predictions, labels=ordered_labels, average="macro", zero_division=0)),
        "accuracy": float(accuracy_score(y, predictions)),
        "majority_baseline_macro_f1": float(f1_score(y, majority_predictions, labels=ordered_labels, average="macro", zero_division=0)),
        "classes": per_class,
        "confusion_matrix_labels": ordered_labels,
        "confusion_matrix_rows_actual": confusion.tolist(),
        "folds": folds,
        "runtime_feature_observability": {
            "candidate_feature_count": len(CATEGORICAL) + len(NUMERIC),
            "minimum_training_fraction": coverage[0],
            "p05_training_fraction": coverage[int((len(coverage) - 1) * 0.05)],
            "median_training_fraction": coverage[len(coverage) // 2],
            "maximum_training_fraction": coverage[-1],
            "use": "A runtime input below p05 may abstain; this is an evidence-coverage floor, not a confidence threshold.",
        },
        "limitations": [
            "Metrics measure only agreement with deterministic rule-flag proxy labels.",
            "No evidence supports breach likelihood, independent vulnerability classification, or four-tier risk classification.",
            "Leave-country-out does not eliminate provider or certificate-family dependence.",
            "Runtime use is limited to SMTP handshakes with observable negotiated TLS and leaf certificate evidence.",
        ],
        "feature_fields": list(CATEGORICAL + NUMERIC),
        "categorical_features": list(CATEGORICAL),
        "numeric_features": list(NUMERIC),
        "input_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    pipeline.fit(x, y)
    joblib.dump(pipeline, MODEL_PATH)
    evaluation["artifact_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with OOF_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("record_id", "held_out_country", "actual", "predicted", "uncalibrated_class_score"))
        writer.writeheader()
        for index, row in enumerate(rows):
            writer.writerow({
                "record_id": row["record_id"],
                "held_out_country": row["country"],
                "actual": y[index],
                "predicted": predictions[index],
                "uncalibrated_class_score": scores[index],
            })
    METADATA_PATH.write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evaluation


if __name__ == "__main__":
    try:
        result = train()
    except (ImportError, RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"Training unavailable: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps({
        "model_id": result["model_id"],
        "sample_count": result["sample_count"],
        "class_counts": result["class_counts"],
        "accuracy": result["accuracy"],
        "macro_f1": result["macro_f1"],
        "majority_baseline_macro_f1": result["majority_baseline_macro_f1"],
        "runtime_feature_observability": result["runtime_feature_observability"],
        "model": str(MODEL_PATH.relative_to(ROOT)),
        "metadata": str(METADATA_PATH.relative_to(ROOT)),
    }, indent=2))
