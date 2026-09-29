"""Train a runtime-compatible tier proxy with country-grouped train/val/test."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from label_zgrab_risk_tier import OUTPUT as LABELS, build_labels
from train_zgrab_runtime_proxy_classifier import CATEGORICAL, NUMERIC, _features

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "ml" / "processed" / "zgrab_smtp_v1.csv"
MODEL_ID = "zgrab_runtime_risk_tier_v1"
SCHEMA = "zgrab_smtp_runtime_risk_tier_v1"
MODEL_PATH = ROOT / "datasets" / "ml" / "models" / f"{MODEL_ID}.joblib"
METADATA_PATH = ROOT / "datasets" / "ml" / "models" / f"{MODEL_ID}.json"
SPLIT_PATH = ROOT / "datasets" / "ml" / "splits" / "zgrab_risk_tier_split_v1.csv"
OOF_PATH = ROOT / "datasets" / "ml" / "models" / f"{MODEL_ID}_test_predictions.csv"
SEED = 20260929
LABELS_ORDER = ("LOW", "MEDIUM", "HIGH")
VALIDATION_COUNTRIES = ("Australia", "India", "Russia")
TEST_COUNTRIES = ("Canada", "South_Korea", "Spain", "Italy")


def _read_rows() -> list[dict[str, str]]:
    if not LABELS.is_file():
        build_labels()
    with DATA.open(newline="", encoding="utf-8") as stream:
        observations = {row["record_id"]: row for row in csv.DictReader(stream)}
    with LABELS.open(newline="", encoding="utf-8") as stream:
        labels = list(csv.DictReader(stream))
    rows = []
    for label in labels:
        if label["label_status"] != "LABELED_RULE_RUBRIC_PROXY":
            continue
        row = observations[label["record_id"]].copy()
        row["risk_tier_proxy"] = label["risk_tier_proxy"]
        rows.append(row)
    return rows


def _metrics(actual: list[str], predicted: list[str]) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support

    precision, recall, f1, support = precision_recall_fscore_support(
        actual, predicted, labels=LABELS_ORDER, zero_division=0
    )
    return {
        "sample_count": len(actual),
        "accuracy": float(accuracy_score(actual, predicted)),
        "macro_f1": float(f1_score(actual, predicted, labels=LABELS_ORDER, average="macro", zero_division=0)),
        "confusion_matrix_labels": list(LABELS_ORDER),
        "confusion_matrix_rows_actual": confusion_matrix(actual, predicted, labels=LABELS_ORDER).tolist(),
        "per_class": {
            label: {
                "precision": float(precision[i]), "recall": float(recall[i]),
                "f1": float(f1[i]), "support": int(support[i]),
            }
            for i, label in enumerate(LABELS_ORDER)
        },
    }


def train() -> dict[str, Any]:
    try:
        import joblib
        import sklearn
        from sklearn.dummy import DummyClassifier
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:
        raise RuntimeError("Install datasets/ml/requirements.txt before training") from exc

    rows = _read_rows()
    countries = {row["country"] for row in rows}
    if not set(VALIDATION_COUNTRIES + TEST_COUNTRIES) <= countries:
        raise ValueError("The frozen country split references countries absent from the prepared dataset")
    split: dict[str, str] = {}
    for row in rows:
        country = row["country"]
        split[row["record_id"]] = (
            "test" if country in TEST_COUNTRIES else
            "validation" if country in VALIDATION_COUNTRIES else "train"
        )
    train_rows = [row for row in rows if split[row["record_id"]] == "train"]
    val_rows = [row for row in rows if split[row["record_id"]] == "validation"]
    test_rows = [row for row in rows if split[row["record_id"]] == "test"]
    if any(set(row["risk_tier_proxy"] for row in part) != set(LABELS_ORDER) for part in (train_rows, val_rows, test_rows)):
        raise ValueError("Every frozen split must contain all three proxy classes")

    train_x = [_features(row) for row in train_rows]
    val_x = [_features(row) for row in val_rows]
    test_x = [_features(row) for row in test_rows]
    train_y = [row["risk_tier_proxy"] for row in train_rows]
    val_y = [row["risk_tier_proxy"] for row in val_rows]
    test_y = [row["risk_tier_proxy"] for row in test_rows]
    forbidden = {
        "record_id", "country", "data_source", "source_file", "source_row", "ip",
        "scan_timestamp", "risk_tier_proxy", "active_finding_count", "contributing_findings",
        *(f"rule_flag_{suffix}" for suffix in (
            "legacy_tls", "weak_cipher", "rsa_key_exchange", "cbc_cipher",
            "sha1_certificate", "weak_rsa_certificate", "certificate_identity",
        )),
    }
    if any(set(features) & forbidden for features in train_x + val_x + test_x):
        raise ValueError("A provenance, label, or deterministic-rule field leaked into model features")
    candidates = {
        "logistic_regression": make_pipeline(
            DictVectorizer(sparse=True), StandardScaler(with_mean=False),
            LogisticRegression(class_weight="balanced", max_iter=3000, random_state=SEED),
        ),
        "random_forest": make_pipeline(
            DictVectorizer(sparse=True),
            RandomForestClassifier(
                n_estimators=300, max_depth=8, min_samples_leaf=3,
                class_weight="balanced_subsample", random_state=SEED, n_jobs=1,
            ),
        ),
    }
    validation_metrics = {}
    for name, model in candidates.items():
        model.fit(train_x, train_y)
        validation_metrics[name] = _metrics(val_y, list(model.predict(val_x)))
    selected_name = max(candidates, key=lambda name: validation_metrics[name]["macro_f1"])
    selected = candidates[selected_name]
    selected.fit(train_x + val_x, train_y + val_y)
    test_predictions = list(selected.predict(test_x))
    test_probabilities = selected.predict_proba(test_x)
    test_metrics = _metrics(test_y, test_predictions)
    majority = DummyClassifier(strategy="most_frequent").fit(train_x + val_x, train_y + val_y)
    baseline_predictions = list(majority.predict(test_x))
    test_metrics["majority_baseline_macro_f1"] = _metrics(test_y, baseline_predictions)["macro_f1"]
    coverage_values = sorted(
        (sum(feature[name] != "__MISSING__" for name in CATEGORICAL)
         + sum(feature[f"{name}__missing"] == 0.0 for name in NUMERIC))
        / (len(CATEGORICAL) + len(NUMERIC))
        for feature in train_x + val_x
    )

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    SPLIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SPLIT_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("record_id", "country_group", "data_source", "split", "risk_tier_proxy"))
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "record_id": row["record_id"], "country_group": row["country"],
                "data_source": row["data_source"], "split": split[row["record_id"]],
                "risk_tier_proxy": row["risk_tier_proxy"],
            })
    classes = list(selected.classes_)
    with OOF_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("record_id", "country_group", "actual", "predicted", "max_uncalibrated_score"))
        writer.writeheader()
        for row, predicted, probabilities in zip(test_rows, test_predictions, test_probabilities):
            writer.writerow({
                "record_id": row["record_id"], "country_group": row["country"],
                "actual": row["risk_tier_proxy"], "predicted": predicted,
                "max_uncalibrated_score": float(max(probabilities)),
            })
    metadata: dict[str, Any] = {
        "model_id": MODEL_ID, "model_version": "1.0", "feature_schema_version": SCHEMA,
        "algorithm": selected_name, "selection_metric": "validation_macro_f1",
        "selected_validation_macro_f1": validation_metrics[selected_name]["macro_f1"],
        "validation_candidate_metrics": validation_metrics,
        "target": "zgrab_rule_rubric_tier_v1",
        "target_semantics": "Project-defined deterministic severity proxy from seven existing rule flags; not independent human or breach-risk ground truth.",
        "tier_definition": {
            "LOW": "TLS handshake observed; none of the seven rule flags set.",
            "MEDIUM": "Exactly one non-legacy rule flag set.",
            "HIGH": "TLS 1.0/1.1 flag set or at least two distinct rule flags set.",
            "CRITICAL": "Not modeled separately: only two TLS 1.0 observations; insufficient support for a stable class.",
        },
        "label_inputs_excluded_from_features": ["rule_flag_*", "active_finding_count", "contributing_findings", "country_group", "country", "ip", "scan_timestamp", "record_id", "source_file", "source_row", "data_source"],
        "feature_schema_fields": list(CATEGORICAL + NUMERIC),
        "feature_count": len(CATEGORICAL) + len(NUMERIC),
        "categorical_features": list(CATEGORICAL), "numeric_features": list(NUMERIC),
        "missingness": "Categorical missing values use an explicit token; numeric missingness has a separate indicator and zero is only the imputed numeric placeholder.",
        "split_method": "Frozen country-grouped train/validation/test; no country appears in more than one partition.",
        "split_countries": {
            "train": sorted(countries - set(VALIDATION_COUNTRIES) - set(TEST_COUNTRIES)),
            "validation": list(VALIDATION_COUNTRIES), "test": list(TEST_COUNTRIES),
        },
        "split_sizes": {name: len(part) for name, part in (("train", train_rows), ("validation", val_rows), ("test", test_rows))},
        "runtime_feature_observability": {
            "candidate_feature_count": len(CATEGORICAL) + len(NUMERIC),
            "p05_training_fraction": coverage_values[int((len(coverage_values) - 1) * 0.05)],
            "use": "Runtime may abstain below the training cohort p05; this is evidence coverage, not confidence.",
        },
        "class_counts": {name: dict(Counter(row["risk_tier_proxy"] for row in part)) for name, part in (("train", train_rows), ("validation", val_rows), ("test", test_rows))},
        "test_metrics": test_metrics,
        "test_predictions_path": str(OOF_PATH.relative_to(ROOT)),
        "split_manifest_path": str(SPLIT_PATH.relative_to(ROOT)),
        "sample_count": len(rows), "data_source": "zgrab_real",
        "limitations": [
            "Tiers are a deterministic rule-severity proxy, not independently labeled risk or compromise.",
            "Country grouping reduces geographic leakage but does not ensure server-vendor, certificate-family, or organization independence.",
            "The class counts are small and imbalanced, especially HIGH; test metrics have substantial uncertainty.",
            "The active-scan ZGrab cohort differs from passive PCAP sessions; transfer remains unvalidated.",
            "Class scores are uncalibrated and are not probabilities.",
            "The deterministic rule engine remains authoritative; this estimate cannot override its findings.",
        ],
        "seed": SEED, "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "label_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
    }
    joblib.dump({"model": selected, "classes": classes}, MODEL_PATH)
    metadata["artifact_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    METADATA_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


if __name__ == "__main__":
    try:
        result = train()
    except (ImportError, RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"Training failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps({
        "model_id": result["model_id"], "algorithm": result["algorithm"],
        "split_sizes": result["split_sizes"], "class_counts": result["class_counts"],
        "test_metrics": result["test_metrics"], "artifact": str(MODEL_PATH.relative_to(ROOT)),
    }, indent=2))
