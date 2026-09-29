"""Train/evaluate a grouped, rule-flag proxy classifier on ZGrab SMTP TLS."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from label_zgrab_risk_proxy import OUTPUT as LABELS, build_labels


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "ml" / "processed" / "zgrab_smtp_v1.csv"
MODEL_DIR = ROOT / "datasets" / "ml" / "models"
MODEL_PATH = MODEL_DIR / "zgrab_rule_flag_proxy_v1.joblib"
EVALUATION_PATH = MODEL_DIR / "zgrab_rule_flag_proxy_v1_evaluation.json"
PREDICTIONS_PATH = MODEL_DIR / "zgrab_rule_flag_proxy_v1_oof.csv"
SEED = 20260929
POSITIVE = "HAS_RULE_FLAGGED_ISSUE"

CATEGORICAL_FEATURES = (
    "tls_version",
    "tls_selected_version",
    "cipher_suite",
    "key_exchange",
    "tls_ext_43",
    "tls_ext_51",
    "tls_ext_65281",
    "tls_ext_11",
    "tls_ext_5",
    "tls_ocsp_stapling",
    "tls_ticket",
    "tls_secure_renegotiation",
    "tls_heartbeat",
    "tls_extended_master_secret",
    "tls_session_id_present",
    "cert_key_algorithm",
    "cert_ecdsa_curve",
    "cert_signature_algorithm",
    "cert_validation_level",
    "cert_self_signed",
    "cert_is_ca",
    "cert_server_auth",
    "cert_client_auth",
    "cert_digital_signature",
    "cert_key_encipherment",
    "cert_key_agreement",
    "cert_expired",
    "cert_not_yet_valid",
    "cert_has_wildcard_san",
    "cert_has_ocsp",
    "cert_has_certificate_policy",
    "cert_has_sct",
    "cert_has_crl_distribution",
    "cert_has_authority_key_id",
    "cert_has_subject_key_id",
)
NUMERIC_FEATURES = (
    "tls_extension_count",
    "cert_rsa_key_size",
    "cert_rsa_exponent",
    "cert_ecdsa_key_size",
    "cert_san_count",
    "cert_max_san_length",
    "cert_unique_san_count",
    "cert_key_usage_count",
    "cert_extension_count",
    "cert_validity_days",
    "cert_days_remaining",
    "cert_chain_length",
    "cert_ocsp_url_count",
    "cert_issuer_url_count",
    "cert_policy_count",
    "cert_sct_count",
    "cert_crl_url_count",
)
FORBIDDEN_FEATURES = {
    "ip", "scan_timestamp", "ja3s", "country", "record_id", "source_file",
    "source_row", "data_source", "label", "flag_count", "contributing_flags",
    "rule_flag_legacy_tls", "rule_flag_weak_cipher", "rule_flag_rsa_key_exchange",
    "rule_flag_cbc_cipher", "rule_flag_sha1_certificate",
    "rule_flag_weak_rsa_certificate", "rule_flag_certificate_identity",
}


def _feature_dict(row: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in CATEGORICAL_FEATURES:
        value = row.get(name, "")
        result[name] = value if value else "__MISSING__"
    for name in NUMERIC_FEATURES:
        value = row.get(name, "")
        try:
            result[name] = float(value) if value else 0.0
            result[f"{name}__missing"] = 0.0 if value else 1.0
        except ValueError:
            result[name] = 0.0
            result[f"{name}__missing"] = 1.0
    if set(result) & FORBIDDEN_FEATURES:
        raise ValueError("Forbidden identifier, label, or rule output in feature vector")
    return result


def _read_joined_rows() -> list[dict[str, str]]:
    if not LABELS.exists():
        build_labels()
    with DATA.open(newline="", encoding="utf-8") as f:
        observations = {r["record_id"]: r for r in csv.DictReader(f)}
    with LABELS.open(newline="", encoding="utf-8") as f:
        labels = list(csv.DictReader(f))

    rows = []
    for label in labels:
        if label["label_status"] != "LABELED_PROXY":
            continue
        row = observations[label["record_id"]].copy()
        row["label"] = label["label"]
        rows.append(row)
    return rows


def train() -> None:
    try:
        import joblib
        import sklearn
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support
        from sklearn.model_selection import LeaveOneGroupOut
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise RuntimeError(
            "ML dependency missing. Install with: "
            "python -m pip install -r datasets/ml/requirements.txt"
        ) from exc

    rows = _read_joined_rows()
    if not rows:
        raise ValueError("No labeled TLS handshakes")
    X = [_feature_dict(row) for row in rows]
    y = [row["label"] for row in rows]
    groups = [row["country"] for row in rows]
    if len(set(y)) < 2:
        raise ValueError("Both proxy-label classes are required for training")

    pipeline = make_pipeline(
        DictVectorizer(sparse=True),
        StandardScaler(with_mean=False),
        LogisticRegression(class_weight="balanced", max_iter=3000, random_state=SEED),
    )

    splitter = LeaveOneGroupOut()
    oof_predictions = [""] * len(rows)
    oof_scores = [""] * len(rows)
    baseline_predictions = [""] * len(rows)
    folds = []

    for train_idx, test_idx in splitter.split(X, y, groups):
        train_labels = [y[i] for i in train_idx]
        majority = Counter(train_labels).most_common(1)[0][0]
        pipeline.fit([X[i] for i in train_idx], train_labels)
        probabilities = pipeline.predict_proba([X[i] for i in test_idx])
        classes = list(pipeline.classes_)
        positive_col = classes.index(POSITIVE)
        predictions = pipeline.predict([X[i] for i in test_idx])
        for offset, index in enumerate(test_idx):
            oof_predictions[index] = str(predictions[offset])
            oof_scores[index] = float(probabilities[offset][positive_col])
            baseline_predictions[index] = majority
        folds.append({
            "held_out_country": groups[test_idx[0]],
            "train_rows": len(train_idx),
            "test_rows": len(test_idx),
            "test_label_counts": dict(Counter(y[i] for i in test_idx)),
        })

    labels_order = ["NO_CURRENT_RULE_FLAG", POSITIVE]
    precision, recall, f1, support = precision_recall_fscore_support(
        y, oof_predictions, labels=labels_order, zero_division=0
    )
    baseline_f1 = f1_score(y, baseline_predictions, labels=labels_order, average="macro", zero_division=0)
    class_report = {
        label: {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
        for i, label in enumerate(labels_order)
    }
    evaluation = {
        "dataset_id": "zgrab_smtp_v1",
        "model_id": "zgrab_rule_flag_proxy_v1",
        "model_version": "1.0",
        "feature_schema_version": "zgrab_smtp_v1",
        "target": "rule_flag_proxy_v1",
        "target_semantics": "Agreement with the union of seven deterministic rule flags; not independent risk ground truth.",
        "evaluation": "Leave-one-country-out cross-validation; the country is grouping metadata and is not a feature.",
        "sample_count": len(rows),
        "class_counts": dict(Counter(y)),
        "model": "DictVectorizer + StandardScaler + class-weighted LogisticRegression",
        "model_score_calibration": "Uncalibrated class scores; do not present as probabilities.",
        "macro_f1": float(f1_score(y, oof_predictions, labels=labels_order, average="macro", zero_division=0)),
        "accuracy": float(accuracy_score(y, oof_predictions)),
        "majority_baseline_macro_f1": float(baseline_f1),
        "classes": class_report,
        "folds": folds,
        "limitations": [
            "Target is derived from deterministic rule flags; this measures proxy agreement, not independent detection accuracy.",
            "Only 61 of 530 handshakes have at least one current rule flag; individual findings are rarer.",
            "Real-world representativeness is limited to the collected SMTP submission scan cohort.",
            "No TLS-less observation was labeled as low or safe.",
            "Metrics use one scan per endpoint; broader provider/certificate-family leakage may remain.",
        ],
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "feature_fields": list(CATEGORICAL_FEATURES + NUMERIC_FEATURES),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with PREDICTIONS_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=("record_id", "held_out_country", "actual", "predicted", "uncalibrated_class_score"))
        writer.writeheader()
        for index, row in enumerate(rows):
            writer.writerow({
                "record_id": row["record_id"],
                "held_out_country": row["country"],
                "actual": y[index],
                "predicted": oof_predictions[index],
                "uncalibrated_class_score": oof_scores[index],
            })

    pipeline.fit(X, y)
    joblib.dump(pipeline, MODEL_PATH)
    evaluation["artifact_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    EVALUATION_PATH.write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    print(f"Trained on {len(rows)} handshakes. Macro-F1: {evaluation['macro_f1']:.3f}; majority baseline: {baseline_f1:.3f}")
    print(f"Model: {MODEL_PATH.relative_to(ROOT)}")
    print(f"Evaluation: {EVALUATION_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    try:
        train()
    except (ImportError, RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"Training unavailable: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
