"""Train an independent, synthetic-cohort email-session risk classifier.

Targets come from the testbed's expected scenario contract. The trainer never
loads or calls Rule Engine findings. Scenario-family grouped splits keep related
captures together. This is a controlled synthetic evaluation, not real-world
risk ground truth.
"""

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

from analysis.ml_runtime import EMAIL_RISK_CATEGORICAL, EMAIL_RISK_NUMERIC, _email_risk_features  # noqa: E402
from testbed.runner.comparator import select_evaluated_session  # noqa: E402

CAPTURES = ROOT / "testbed" / "captures"
FAMILY_MANIFEST = ROOT / "datasets/ml/splits/synthetic_family_manifest_v1.csv"
MODEL_ID = "synthetic_email_risk_classifier_v1"
MODEL_PATH = ROOT / "datasets/ml/models" / f"{MODEL_ID}.joblib"
METADATA_PATH = ROOT / "datasets/ml/models" / f"{MODEL_ID}.json"
SPLIT_PATH = ROOT / "datasets/ml/splits" / f"{MODEL_ID}_split.csv"
PREDICTIONS_PATH = ROOT / "datasets/ml/models" / f"{MODEL_ID}_test_predictions.csv"
SEED = 20260929
LABELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _risk_label(expected: dict[str, Any]) -> str:
    """Project rubric over expected scenario facts, independent of rule output."""
    presence = str(expected.get("tls_presence") or "").lower()
    integrity = str(expected.get("starttls_integrity") or "").lower()
    version = str(expected.get("tls_version") or "").strip()
    strength = str(expected.get("cipher_strength") or "").upper()
    trust = str(expected.get("expected_trust_status") or "").upper()
    validity = str(expected.get("cert_validity") or "").lower()
    chain = str(expected.get("cert_chain_shape") or "").lower()
    hostname = str(expected.get("hostname_match") or "").lower()
    fs = expected.get("forward_secrecy")

    if presence == "none" or "stripped" in integrity or integrity in {"downgrade", "broken"} or strength == "BROKEN":
        return "CRITICAL"

    high_conditions = (
        version in {"1.0", "1.1"}
        or strength == "WEAK"
        or validity in {"expired", "not-yet-valid"}
        or hostname in {"mismatched", "mismatch", "false"}
        or trust in {"UNTRUSTED", "UNTRUSTED_CHAIN", "EXPIRED", "HOSTNAME_MISMATCH", "INVALID"}
        or chain in {"self-signed-untrusted", "intermediate-not-ca", "chain-tampered-intermediate-sig"}
        or fs is False
    )
    if high_conditions:
        return "HIGH"
    if strength == "MEDIUM" or trust in {"UNKNOWN", "INCONCLUSIVE"} or chain in {"leaf-only", "complete-chain-untrusted-root"}:
        return "MEDIUM"
    return "LOW"


def _rows() -> list[dict[str, Any]]:
    with FAMILY_MANIFEST.open(newline="", encoding="utf-8") as source:
        groups = {row["scenario_id"]: row for row in csv.DictReader(source)}
    rows: list[dict[str, Any]] = []
    for expected_path in sorted(CAPTURES.glob("*.expected.json")):
        scenario_id = expected_path.name.removesuffix(".expected.json")
        observed_path = CAPTURES / f"{scenario_id}.observed.json"
        if not observed_path.is_file() or scenario_id not in groups:
            continue
        expected_doc = json.loads(expected_path.read_text(encoding="utf-8"))
        observed_doc = json.loads(observed_path.read_text(encoding="utf-8"))
        expected = expected_doc.get("expected", {})
        protocol = str(expected.get("protocol") or "").upper()
        if protocol not in {"SMTP", "IMAP", "POP3"}:
            continue
        _, session, error = select_evaluated_session(protocol, observed_doc.get("sessions", {}))
        if error or session is None:
            continue
        rows.append({
            "scenario_id": scenario_id,
            "family_id": groups[scenario_id]["scenario_family_id"],
            "source_family_id": groups[scenario_id]["scenario_family_id"],
            "certificate_group_id": groups[scenario_id]["certificate_identity_group_id"],
            "protocol": protocol,
            "risk_tier": _risk_label(expected),
            "features": _email_risk_features(session),
            "data_source": "synthetic_testbed",
            "expected": expected,
        })
    # Transitive group components prevent either related scenario families or
    # repeated certificate identities from crossing a split boundary.
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        if parent[node] != node:
            parent[node] = find(parent[node])
        return parent[node]

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for row in rows:
        family_node = f"family:{row['family_id']}"
        find(family_node)
        cert_group = row["certificate_group_id"]
        if cert_group and cert_group != "UNOBSERVED":
            union(family_node, f"certificate:{cert_group}")
    for row in rows:
        row["family_id"] = find(f"family:{row['family_id']}")
    return rows


def _metrics(actual: list[str], predicted: list[str]) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support

    precision, recall, f1, support = precision_recall_fscore_support(
        actual, predicted, labels=LABELS, zero_division=0,
    )
    return {
        "sample_count": len(actual),
        "accuracy": float(accuracy_score(actual, predicted)),
        "macro_f1": float(f1_score(actual, predicted, labels=LABELS, average="macro", zero_division=0)),
        "confusion_matrix_labels": list(LABELS),
        "confusion_matrix_rows_actual": confusion_matrix(actual, predicted, labels=LABELS).tolist(),
        "per_class": {
            label: {"precision": float(precision[i]), "recall": float(recall[i]), "f1": float(f1[i]), "support": int(support[i])}
            for i, label in enumerate(LABELS)
        },
    }


def _split(rows: list[dict[str, Any]]) -> tuple[list[int], list[int], list[int]]:
    from sklearn.model_selection import StratifiedGroupKFold

    y = [row["risk_tier"] for row in rows]
    groups = [row["family_id"] for row in rows]
    for seed in range(SEED, SEED + 500):
        outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        try:
            train_val, test = next(outer.split(rows, y, groups))
            inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=seed + 1)
            train_local, val_local = next(inner.split(
                [rows[i] for i in train_val], [y[i] for i in train_val], [groups[i] for i in train_val]
            ))
        except ValueError:
            continue
        train = [train_val[i] for i in train_local]
        validation = [train_val[i] for i in val_local]
        partitions = (train, validation, list(test))
        if all(set(y[i] for i in part) == set(y) for part in partitions):
            group_sets = [{groups[i] for i in part} for part in partitions]
            if not (group_sets[0] & group_sets[1] or group_sets[0] & group_sets[2] or group_sets[1] & group_sets[2]):
                return partitions
    raise ValueError("Unable to create three family-disjoint splits containing every target class")


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

    rows = _rows()
    if not rows or {row["risk_tier"] for row in rows} != set(LABELS):
        raise ValueError("Synthetic corpus must contain all four risk rubric classes")
    train_idx, val_idx, test_idx = _split(rows)
    x = [row["features"] for row in rows]
    y = [row["risk_tier"] for row in rows]
    train_x, val_x, test_x = ([x[i] for i in part] for part in (train_idx, val_idx, test_idx))
    train_y, val_y, test_y = ([y[i] for i in part] for part in (train_idx, val_idx, test_idx))

    candidates = {
        "LogisticRegression": make_pipeline(
            DictVectorizer(sparse=True), StandardScaler(with_mean=False),
            LogisticRegression(class_weight="balanced", max_iter=3000, random_state=SEED),
        ),
        "RandomForest": make_pipeline(
            DictVectorizer(sparse=True),
            RandomForestClassifier(n_estimators=500, min_samples_leaf=2, class_weight="balanced_subsample", random_state=SEED, n_jobs=1),
        ),
    }
    val_metrics: dict[str, Any] = {}
    for name, model in candidates.items():
        model.fit(train_x, train_y)
        val_metrics[name] = _metrics(val_y, [str(item) for item in model.predict(val_x)])
    selected_name = max(candidates, key=lambda name: (val_metrics[name]["macro_f1"], name == "LogisticRegression"))
    selected = candidates[selected_name]
    # Refit only on train+validation after model selection; the test set remains untouched.
    selected.fit([x[i] for i in train_idx + val_idx], [y[i] for i in train_idx + val_idx])
    test_predictions = [str(value) for value in selected.predict(test_x)]
    dummy = DummyClassifier(strategy="most_frequent").fit(train_x, train_y)
    test_metrics = _metrics(test_y, test_predictions)
    test_metrics["majority_baseline_macro_f1"] = _metrics(test_y, [str(v) for v in dummy.predict(test_x)])["macro_f1"]
    test_metrics["training_size_after_refit"] = len(train_idx) + len(val_idx)

    coverage = sorted(
        sum(features[name] != "__MISSING__" for name in EMAIL_RISK_CATEGORICAL)
        + sum(features[f"{name}__missing"] == 0.0 for name in EMAIL_RISK_NUMERIC)
        for features in [x[i] for i in train_idx]
    )
    coverage_floor = coverage[max(0, int((len(coverage) - 1) * 0.05))] / (len(EMAIL_RISK_CATEGORICAL) + len(EMAIL_RISK_NUMERIC))
    groups = [row["family_id"] for row in rows]
    split_name = {i: name for name, part in zip(("train", "validation", "test"), (train_idx, val_idx, test_idx)) for i in part}
    SPLIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SPLIT_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("scenario_id", "scenario_family_id", "certificate_identity_group_id", "split_group_id", "data_source", "protocol", "split", "risk_tier"))
        writer.writeheader()
        writer.writerows({"scenario_id": row["scenario_id"], "scenario_family_id": row["source_family_id"], "certificate_identity_group_id": row["certificate_group_id"], "split_group_id": row["family_id"], "data_source": row["data_source"], "protocol": row["protocol"], "split": split_name[i], "risk_tier": row["risk_tier"]} for i, row in enumerate(rows))
    PREDICTIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PREDICTIONS_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("scenario_id", "scenario_family_id", "protocol", "actual", "predicted"))
        writer.writeheader()
        writer.writerows({"scenario_id": rows[i]["scenario_id"], "scenario_family_id": groups[i], "protocol": rows[i]["protocol"], "actual": y[i], "predicted": prediction} for i, prediction in zip(test_idx, test_predictions))

    metadata = {
        "model_id": MODEL_ID,
        "model_version": "1.0",
        "feature_schema_version": "synthetic_email_session_risk_v1",
        "algorithm": selected_name,
        "task": "Supervised synthetic email-session cryptographic risk classification",
        "target": "independent_scenario_security_rubric_v1",
        "target_semantics": "LOW/MEDIUM/HIGH/CRITICAL derived from expected scenario fields (TLS presence/integrity, version, cipher strength, certificate validity/trust/identity, and forward secrecy); Rule Engine outputs are never read.",
        "target_rubric": {
            "CRITICAL": "No TLS, STARTTLS stripping/downgrade, or BROKEN cipher.",
            "HIGH": "TLS 1.0/1.1, WEAK cipher, invalid/expired certificate, identity/trust failure, malformed chain, or absent forward secrecy.",
            "MEDIUM": "MEDIUM cipher or explicitly incomplete/unknown certificate trust state.",
            "LOW": "No higher-severity rubric condition observed in the expected scenario contract.",
        },
        "data_source": "synthetic_testbed",
        "sample_count": len(rows),
        "real_observation_count": 0,
        "synthetic_observation_count": len(rows),
        "protocol_counts": dict(Counter(row["protocol"] for row in rows)),
        "class_counts": dict(Counter(y)),
        "split_method": "StratifiedGroupKFold over transitive components linking scenario families and observed certificate identity groups; selected only when each split contains every class.",
        "split_group_policy": "No scenario_family_id or certificate_identity_group_id may occur in more than one split.",
        "split_sizes": {name: len(part) for name, part in zip(("train", "validation", "test"), (train_idx, val_idx, test_idx))},
        "split_class_counts": {name: dict(Counter(y[i] for i in part)) for name, part in zip(("train", "validation", "test"), (train_idx, val_idx, test_idx))},
        "split_group_component_counts": {name: len({groups[i] for i in part}) for name, part in zip(("train", "validation", "test"), (train_idx, val_idx, test_idx))},
        "categorical_features": list(EMAIL_RISK_CATEGORICAL),
        "numeric_features": list(EMAIL_RISK_NUMERIC),
        "feature_count": len(EMAIL_RISK_CATEGORICAL) + len(EMAIL_RISK_NUMERIC),
        "runtime_feature_observability": {"p05_training_fraction": coverage_floor},
        "validation_candidates": val_metrics,
        "selection_metric": "validation macro-F1",
        "test_metrics": test_metrics,
        "data_hashes": {
            "family_manifest_sha256": hashlib.sha256(FAMILY_MANIFEST.read_bytes()).hexdigest(),
            "expected_scenarios_sha256": hashlib.sha256(b"".join(p.read_bytes() for p in sorted(CAPTURES.glob("*.expected.json")))).hexdigest(),
            "observed_scenarios_sha256": hashlib.sha256(b"".join(p.read_bytes() for p in sorted(CAPTURES.glob("*.observed.json")))).hexdigest(),
        },
        "limitations": [
            "All training/evaluation samples are controlled synthetic testbed scenarios; no real SMTP/IMAP/POP3 observations were used for this classifier.",
            "The labels are an explicit project rubric applied to scenario expected facts, not independent human-reviewed real-world security ground truth.",
            "Family-disjoint holdout measures generalization across known synthetic scenario families only; transfer to real networks is NOT_VALIDATED.",
            "This estimates the scenario rubric from partial PCAP-visible facts. A high score is not a calibrated probability of compromise.",
            "Rule Engine findings and rule outputs are not inputs or labels; Rule Engine remains authoritative.",
        ],
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump({"model": selected}, MODEL_PATH)
    metadata["artifact_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    METADATA_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


if __name__ == "__main__":
    result = train()
    print(json.dumps({key: result[key] for key in ("model_id", "sample_count", "class_counts", "split_sizes", "validation_candidates", "test_metrics")}, indent=2))
