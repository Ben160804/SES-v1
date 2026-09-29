"""Train/evaluate the grouped 10k simulated email posture classifier."""

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

from analysis.ml_runtime import EMAIL_RISK_CATEGORICAL, EMAIL_RISK_NUMERIC  # noqa: E402

DATA = ROOT / "datasets/ml/synthetic/synthetic_email_research_cohort_v1.csv"
DATA_META = ROOT / "datasets/ml/synthetic/synthetic_email_research_cohort_v1.json"
MODEL_ID = "synthetic_email_posture_classifier_v2"
MODEL_DIR = ROOT / "datasets/ml/models"
MODEL_PATH = MODEL_DIR / f"{MODEL_ID}.joblib"
META_PATH = MODEL_DIR / f"{MODEL_ID}.json"
SPLIT_PATH = ROOT / "datasets/ml/splits" / f"{MODEL_ID}_split.csv"
PRED_PATH = MODEL_DIR / f"{MODEL_ID}_test_predictions.csv"
LABELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEED = 20261001


def _metrics(actual: list[str], predicted: list[str]) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support

    precision, recall, f1, support = precision_recall_fscore_support(actual, predicted, labels=LABELS, zero_division=0)
    return {
        "sample_count": len(actual),
        "accuracy": float(accuracy_score(actual, predicted)),
        "macro_f1": float(f1_score(actual, predicted, labels=LABELS, average="macro", zero_division=0)),
        "confusion_matrix_labels": list(LABELS),
        "confusion_matrix_rows_actual": confusion_matrix(actual, predicted, labels=LABELS).tolist(),
        "per_class": {label: {"precision": float(precision[i]), "recall": float(recall[i]), "f1": float(f1[i]), "support": int(support[i])} for i, label in enumerate(LABELS)},
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

    with DATA.open(newline="", encoding="utf-8") as source:
        rows = [{**row, "features": json.loads(row["features_json"])} for row in csv.DictReader(source)]
    data_meta = json.loads(DATA_META.read_text(encoding="utf-8"))
    if len(rows) != 10_000 or any(row.get("data_source") != "synthetic_simulation" for row in rows):
        raise ValueError("Expected the provenance-verified 10,000-row synthetic simulation cohort")
    if {r["target"] for r in rows} != set(LABELS):
        raise ValueError("All four simulated target classes must be present")

    partitions = {name: [r for r in rows if r["split"] == name] for name in ("train", "validation", "test")}
    if any(not part for part in partitions.values()):
        raise ValueError("Train/validation/test must all be non-empty")
    if any({r["target"] for r in part} != set(LABELS) for part in partitions.values()):
        raise ValueError("Every split must contain all four generated classes")
    group_sets = {name: {r["configuration_group_id"] for r in part} for name, part in partitions.items()}
    if any(group_sets[a] & group_sets[b] for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))):
        raise ValueError("Endpoint configuration groups cross partitions")

    candidates = {}
    candidate_params = {}
    for c_value in (0.1, 0.3, 1.0, 3.0, 10.0):
        for weight in ("balanced", None):
            key = f"LogisticRegression_C{c_value:g}_weight_{weight or 'none'}"
            candidates[key] = make_pipeline(
                DictVectorizer(sparse=True), StandardScaler(with_mean=False),
                LogisticRegression(C=c_value, class_weight=weight, max_iter=3000, random_state=SEED),
            )
            candidate_params[key] = {"C": c_value, "class_weight": weight}
    for trees in (300, 500):
        for depth in (None, 16):
            for leaf in (1, 3, 6):
                key = f"RandomForest_n{trees}_d{depth or 'full'}_leaf{leaf}"
                candidates[key] = make_pipeline(
                    DictVectorizer(sparse=True),
                    RandomForestClassifier(
                        n_estimators=trees, max_depth=depth, min_samples_leaf=leaf,
                        class_weight="balanced_subsample", random_state=SEED, n_jobs=1,
                    ),
                )
                candidate_params[key] = {
                    "n_estimators": trees, "max_depth": depth,
                    "min_samples_leaf": leaf, "class_weight": "balanced_subsample",
                }
    train_rows, val_rows, test_rows = (partitions[key] for key in ("train", "validation", "test"))
    val_x, val_y = [r["features"] for r in val_rows], [r["target"] for r in val_rows]
    tuned_metrics = {}
    for name, model in candidates.items():
        model.fit([r["features"] for r in train_rows], [r["target"] for r in train_rows])
        tuned_metrics[name] = _metrics(val_y, [str(x) for x in model.predict(val_x)])
    selected_name = max(
        candidates,
        key=lambda n: (
            tuned_metrics[n]["macro_f1"],
            n.startswith("LogisticRegression"),
            -candidate_params[n].get("C", 0),
            -candidate_params[n].get("min_samples_leaf", 0),
        ),
    )
    selected = candidates[selected_name]
    selected_family = "LogisticRegression" if selected_name.startswith("LogisticRegression") else "RandomForest"
    validation_candidates = {
        family: max(
            (name for name in candidates if name.startswith(family)),
            key=lambda name: tuned_metrics[name]["macro_f1"],
        )
        for family in ("LogisticRegression", "RandomForest")
    }
    fit_rows = train_rows + val_rows
    selected.fit([r["features"] for r in fit_rows], [r["target"] for r in fit_rows])
    test_x, test_y = [r["features"] for r in test_rows], [r["target"] for r in test_rows]
    test_predictions = [str(x) for x in selected.predict(test_x)]
    test_metrics = _metrics(test_y, test_predictions)
    baseline = DummyClassifier(strategy="most_frequent").fit([r["features"] for r in train_rows], [r["target"] for r in train_rows])
    test_metrics["majority_baseline_macro_f1"] = _metrics(test_y, [str(x) for x in baseline.predict(test_x)])["macro_f1"]
    test_metrics["training_size_after_refit"] = len(fit_rows)

    SPLIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SPLIT_PATH.open("w", newline="", encoding="utf-8") as target:
        fields = ("sample_id", "configuration_group_id", "profile_family", "protocol", "data_source", "split", "target")
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row[key] for key in fields} for row in rows)
    PRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PRED_PATH.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=("sample_id", "configuration_group_id", "profile_family", "protocol", "actual", "predicted"))
        writer.writeheader()
        writer.writerows({"sample_id": r["sample_id"], "configuration_group_id": r["configuration_group_id"], "profile_family": r["profile_family"], "protocol": r["protocol"], "actual": r["target"], "predicted": p} for r, p in zip(test_rows, test_predictions))

    coverage_values = sorted(
        (sum(f[k] != "__MISSING__" for k in EMAIL_RISK_CATEGORICAL)
         + sum(f[f"{k}__missing"] == 0.0 for k in EMAIL_RISK_NUMERIC))
        / (len(EMAIL_RISK_CATEGORICAL) + len(EMAIL_RISK_NUMERIC))
        for f in (r["features"] for r in train_rows)
    )
    metadata = {
        "model_id": MODEL_ID,
        "model_version": "2.1",
        "feature_schema_version": "synthetic_email_session_risk_v2",
        "algorithm": selected_family,
        "selected_hyperparameters": candidate_params[selected_name],
        "hyperparameter_search": {
            "method": "Exhaustive fixed grid on training data; selection by grouped validation macro-F1; heldout test not used for selection.",
            "candidates": {
                name: {"params": candidate_params[name], "validation_macro_f1": tuned_metrics[name]["macro_f1"]}
                for name in sorted(candidates)
            },
        },
        "task": "Supervised synthetic email endpoint-posture classification from one simulated negotiation",
        "target": "synthetic_full_endpoint_posture_rubric_v1",
        "target_semantics": "LOW/MEDIUM/HIGH/CRITICAL describe a generated endpoint's full supported TLS configuration; input features describe only one simulated client negotiation. Labels do not use Rule Engine outputs.",
        "target_rubric": data_meta["label_rubric"],
        "data_source": "synthetic_simulation",
        "sample_count": len(rows),
        "real_observation_count": 0,
        "synthetic_observation_count": len(rows),
        "protocol_counts": data_meta["protocol_counts"],
        "class_counts": data_meta["class_counts"],
        "split_method": "Grouped stratified 60/20/20 split by full generated endpoint configuration fingerprint; all five negotiations from each endpoint configuration stay together.",
        "split_sizes": {name: len(part) for name, part in partitions.items()},
        "split_class_counts": {name: dict(Counter(r["target"] for r in part)) for name, part in partitions.items()},
        "split_group_counts": {name: len(group_sets[name]) for name in partitions},
        "categorical_features": list(EMAIL_RISK_CATEGORICAL),
        "numeric_features": list(EMAIL_RISK_NUMERIC),
        "feature_count": len(EMAIL_RISK_CATEGORICAL) + len(EMAIL_RISK_NUMERIC),
        "runtime_feature_observability": {"p05_training_fraction": coverage_values[max(0, int((len(coverage_values) - 1) * 0.05))]},
        "validation_candidates": {
            family: tuned_metrics[name]
            for family, name in validation_candidates.items()
        },
        "selection_metric": "validation macro-F1",
        "test_metrics": test_metrics,
        "dataset_sha256": data_meta["dataset_sha256"],
        "limitations": data_meta["limitations"] + [
            "Metrics measure generalization within this programmatically designed simulator only, not real network accuracy.",
            "The per-session feature schema does not expose the endpoint's full supported cipher/version configuration; label inference is deliberately partial.",
        ],
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": selected}, MODEL_PATH)
    metadata["artifact_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    META_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


if __name__ == "__main__":
    result = train()
    print(json.dumps({key: result[key] for key in ("model_id", "sample_count", "protocol_counts", "class_counts", "split_sizes", "split_class_counts", "validation_candidates", "test_metrics")}, indent=2))
