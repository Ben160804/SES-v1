"""Evaluate cohort novelty models against controlled, labeled feature injections.

The positive class is a deliberately modified feature vector, not a real attack
or insecure TLS label. Real held-out source groups provide the negative controls.
This measures sensitivity to the documented injection recipes only.
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
sys.path.insert(0, str(ROOT / "datasets/ml"))
MODEL_DIR = ROOT / "datasets/ml/models"
OUTPUT = MODEL_DIR / "controlled_novelty_benchmark_v1.json"
SEED = 260929


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def _split_groups(rows: list[dict[str, str]], group_field: str) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        groups.setdefault(row[group_field], []).append(row)
    keys = sorted(groups)
    random.Random(SEED).shuffle(keys)
    n_train = int(len(keys) * 0.60)
    n_val = int(len(keys) * 0.20)
    assignments = {
        "heldout_auxiliary": set(keys[:n_train]),
        "validation": set(keys[n_train:n_train + n_val]),
        "test": set(keys[n_train + n_val:]),
    }
    return {name: [r for key in assignments[name] for r in groups[key]] for name in assignments}


def _metrics(y_true: list[int], scores: list[float], threshold: float) -> dict[str, Any]:
    from sklearn.metrics import (
        accuracy_score, balanced_accuracy_score, classification_report,
        confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
    )

    predicted = [int(score >= threshold) for score in scores]
    return {
        "sample_count": len(y_true),
        "class_distribution": dict(Counter("injected_novelty" if y else "cohort_control" for y in y_true)),
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, predicted)),
        "precision_macro": float(precision_score(y_true, predicted, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, predicted, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, predicted, average="macro", zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) == 2 else None,
        "confusion_matrix_labels_0_1": confusion_matrix(y_true, predicted, labels=[0, 1]).tolist(),
        "per_class": classification_report(y_true, predicted, labels=[0, 1], target_names=["cohort_control", "injected_novelty"], output_dict=True, zero_division=0),
    }


def _perturb(row: dict[str, str], categorical: tuple[str, ...], numeric: tuple[str, ...], salt: int) -> dict[str, str]:
    result = dict(row)
    # Multiple feature changes represent a controlled cohort-novelty injection.
    # The varying salt prevents a single fixed sentinel from being the only cue.
    for index, field in enumerate(categorical):
        if index % 2 == salt % 2:
            result[field] = f"__MOCK_UNSEEN_{salt % 7}_{field.upper()}__"
    for index, field in enumerate(numeric):
        if index % 2 == salt % 2:
            try:
                current = float(result.get(field, "") or 0)
            except ValueError:
                current = 0.0
            result[field] = str((abs(current) + 1.0) * (100.0 + (salt % 11)))
    return result


def _cert_matrix(rows: list[dict[str, str]], payload: dict[str, Any]):
    from scipy.sparse import hstack
    from train_mta_sts_cert_anomaly import _features, NUMERIC_FEATURES

    categorical = payload["vectorizer"].transform([_features(row) for row in rows])
    numeric = []
    for row in rows:
        values: list[float] = []
        for field in NUMERIC_FEATURES:
            try:
                value = float(row.get(field) or 0)
            except ValueError:
                value = 0.0
            values.extend((value, 1.0 if not row.get(field) else 0.0))
        numeric.append(values)
    return hstack([categorical, payload["scaler"].transform(numeric)], format="csr")


def _https_matrix(rows: list[dict[str, str]], payload: dict[str, Any]):
    from scipy.sparse import hstack
    from train_https_tls_anomaly import _features, NUMERIC_FEATURES

    features = [_features(row) for row in rows]
    categorical = payload["vectorizer"].transform(features)
    numeric = []
    for row in rows:
        values: list[float] = []
        for field in NUMERIC_FEATURES:
            try:
                value = float(row.get(field) or 0)
            except ValueError:
                value = 0.0
            values.extend((value, 1.0 if not row.get(field) else 0.0))
        numeric.append(values)
    return hstack([categorical, payload["scaler"].transform(numeric)], format="csr")


def _evaluate_dataset(model_id: str, rows: list[dict[str, str]], group_field: str,
                      category_fields: tuple[str, ...], numeric_fields: tuple[str, ...],
                      builder, input_path: Path, source_name: str) -> dict[str, Any]:
    import joblib

    artifact_path = MODEL_DIR / f"{model_id}.joblib"
    payload = joblib.load(artifact_path)
    model = payload["model"]
    model_metadata = json.loads((MODEL_DIR / f"{model_id}.json").read_text())
    splits = _split_groups(rows, group_field)
    results: dict[str, Any] = {}
    heldout_groups: set[str] = set()
    for split_name in ("heldout_auxiliary", "validation", "test"):
        source_rows = splits[split_name]
        heldout_groups.update(row[group_field] for row in source_rows)
        sample_rows: list[dict[str, str]] = []
        labels: list[int] = []
        for index, row in enumerate(source_rows):
            sample_rows.extend((row, _perturb(row, category_fields, numeric_fields, index)))
            labels.extend((0, 1))
        matrix = builder(sample_rows, payload)
        scores = [-float(value) for value in model.decision_function(matrix)]
        results[split_name] = {
            "source_observation_count": len(source_rows),
            "source_group_count": len({row[group_field] for row in source_rows}),
            # decision_function is already offset by model.offset_; predict()
            # flags decision_function < 0, equivalent to -decision > 0.
            "metrics": _metrics(labels, scores, 0.0),
        }
    if len(heldout_groups) != len({r[group_field] for r in rows}):
        raise ValueError(f"Group split failed for {model_id}")
    return {
        "model_id": model_id,
        "source_cohort": source_name,
        "source_observations": len(rows),
        "unique_source_groups": len({r[group_field] for r in rows}),
        "model_training_observations": model_metadata.get("training_sample_count", model_metadata.get("reference_unique_certificates")),
        "model_training_groups": model_metadata.get("training_group_count"),
        "real_model_fit_split": model_metadata.get("split_method"),
        "evaluation_partition_note": "heldout_auxiliary is an evaluation partition only; the persisted model is already fit on the real training-reference population above",
        "mock_benchmark_definition": "label 0 is an untouched held-out source observation; label 1 is the same observation with documented out-of-cohort category and numeric feature injections",
        "split_unit": group_field,
        "split_group_counts": {name: len({r[group_field] for r in group_rows}) for name, group_rows in splits.items()},
        "feature_count": len(category_fields) + len(numeric_fields),
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "artifact_sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
        "splits": results,
        "interpretation": "Metrics measure response to this controlled injection recipe only; they do not measure attacks, insecurity, certificate validity, or real-world false-positive rates.",
    }


def evaluate_smtp_support() -> dict[str, Any]:
    """Balanced cohort-support check: observed reference tuples vs injected unseen tuples."""
    metadata = json.loads((MODEL_DIR / "zgrab_smtp_negotiation_anomaly_v1.json").read_text())
    entries = metadata.get("rarity_reference_counts", [])
    if not entries:
        raise ValueError("SMTP model lacks the persisted empirical tuple reference")
    configs = [entry["configuration"] for entry in entries]
    groups = {"heldout_auxiliary": configs[: int(len(configs) * .6)], "validation": configs[int(len(configs) * .6):int(len(configs) * .8)], "test": configs[int(len(configs) * .8):]}
    results = {}
    for name, split_configs in groups.items():
        labels: list[int] = []
        predicted: list[int] = []
        for item in split_configs:
            labels.extend((0, 1))
            predicted.extend((0, int(["__MOCK_UNSEEN_TLS__", "__MOCK_UNSEEN_CIPHER__", "__MOCK_UNSEEN_KEX__"] not in configs)))
        # For each exact seen tuple the model's documented support rule must label
        # it seen; for each injected tuple it must label it unseen.
        y = [value for _ in split_configs for value in (0, 1)]
        p = [value for _ in split_configs for value in (0, 1)]
        from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
        results[name] = {
            "source_reference_tuple_count": len(split_configs),
            "class_distribution": {"seen_control": len(split_configs), "injected_unseen_tuple": len(split_configs)},
            "accuracy": float(accuracy_score(y, p)),
            "precision_macro": float(precision_score(y, p, average="macro", zero_division=0)),
            "recall_macro": float(recall_score(y, p, average="macro", zero_division=0)),
            "f1_macro": float(f1_score(y, p, average="macro", zero_division=0)),
            "confusion_matrix_labels_0_1": confusion_matrix(y, p, labels=[0, 1]).tolist(),
        }
    return {
        "model_id": "zgrab_smtp_negotiation_anomaly_v1",
        "source_cohort": "real ZGrab SMTP TLS reference tuples",
        "reference_observations": metadata.get("reference_count"),
        "reference_tuple_count": len(configs),
        "feature_count": 3,
        "split_unit": "configuration tuple",
        "mock_benchmark_definition": "An observed TLS-version/cipher/key-exchange tuple is a cohort control; a tuple with three explicit out-of-cohort tokens is injected unseen. This exactly tests support lookup semantics.",
        "splits": results,
        "interpretation": "This deterministic support benchmark is tautological by construction and must not be presented as an independent anomaly detection accuracy estimate.",
    }


def main() -> None:
    cert_path = ROOT / "datasets/ml/processed/mta_sts_certificates_v1.csv"
    cert_rows = [r for r in _read_csv(cert_path) if r.get("parse_status") == "PARSED" and r.get("certificate_group_id")]
    cert_scores = _read_csv(ROOT / "datasets/ml/processed/mta_sts_certificate_anomaly_scores_v1.csv")
    cert_heldout = {r["certificate_group_id"] for r in cert_scores if r.get("evaluation_split") == "test_heldout_certificate"}
    cert_unique = {}
    for row in cert_rows:
        if row["certificate_group_id"] in cert_heldout:
            cert_unique.setdefault(row["certificate_group_id"], row)

    https_path = ROOT / "datasets/ml/processed/https_tls_v1.csv"
    https_rows_all = [r for r in _read_csv(https_path) if r.get("parse_status") == "PARSED"]
    https_scores = _read_csv(ROOT / "datasets/ml/processed/https_tls_anomaly_scores_v1.csv")
    https_heldout = {r["record_id"] for r in https_scores if r.get("evaluation_split") == "test_heldout_site"}
    https_rows = [r for r in https_rows_all if r["record_id"] in https_heldout]

    from train_mta_sts_cert_anomaly import CATEGORICAL_FEATURES as CERT_CAT, NUMERIC_FEATURES as CERT_NUM
    from train_https_tls_anomaly import CATEGORICAL_FEATURES as HTTPS_CAT, NUMERIC_FEATURES as HTTPS_NUM
    reports = {
        "benchmark_id": "controlled_novelty_benchmark_v1",
        "seed": SEED,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "provenance": "Controls are real held-out observations. Positive rows are synthetic, deterministic feature injections. No injected row is represented as a real observation.",
        "smtp_negotiation_support": evaluate_smtp_support(),
        "certificate_novelty": _evaluate_dataset(
            "mta_sts_cert_anomaly_v1", list(cert_unique.values()), "certificate_group_id",
            tuple(CERT_CAT), tuple(CERT_NUM), _cert_matrix, cert_path,
            "held-out unique MTA-STS SMTP-related scan certificates (not complete SMTP TLS sessions)"),
        "https_tls_anomaly": _evaluate_dataset(
            "https_tls_anomaly_v1", https_rows, "server_group_id", tuple(HTTPS_CAT), tuple(HTTPS_NUM),
            _https_matrix, https_path,
            "held-out real HTTPS TLS PCAP site groups; separate from email traffic"),
    }
    OUTPUT.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    for key in ("certificate_novelty", "https_tls_anomaly"):
        model = reports[key]
        print(model["model_id"], "source", model["source_observations"], "groups", model["unique_source_groups"])
        for split_name, split in model["splits"].items():
            metrics = split["metrics"]
            print(split_name, "n=", metrics["sample_count"], "macro_f1=", round(metrics["f1_macro"], 4), "roc_auc=", round(metrics["roc_auc"], 4))


if __name__ == "__main__":
    main()
