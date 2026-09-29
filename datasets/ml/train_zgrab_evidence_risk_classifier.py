"""Train a real-ZGrab classifier from a separate feature-derived risk rubric.

Unlike the legacy proxy models, this trainer does not read any `rule_flag_*`
field or existing classifier label. The target is still a project-defined
rubric over observed evidence, not independently reviewed security truth.
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

DATA = ROOT / "datasets/ml/processed/zgrab_smtp_v1.csv"
MODEL_ID = "zgrab_evidence_risk_classifier_v1"
MODEL_DIR = ROOT / "datasets/ml/models"
MODEL_PATH = MODEL_DIR / f"{MODEL_ID}.joblib"
METADATA_PATH = MODEL_DIR / f"{MODEL_ID}.json"
SPLIT_PATH = ROOT / "datasets/ml/splits" / f"{MODEL_ID}_split.csv"
PREDICTIONS_PATH = MODEL_DIR / f"{MODEL_ID}_test_predictions.csv"
SEED = 20260929
VALIDATION_COUNTRIES = {"Australia", "India", "Russia"}
TEST_COUNTRIES = {"Canada", "South_Korea", "Spain", "Italy"}
LABELS = ("LOW_OR_MEDIUM", "HIGH", "CRITICAL")


def _risk_label(row: dict[str, str]) -> str | None:
    """Apply an explicit security rubric to observed features, never rule flags."""
    if row.get("smtp_observation_state") != "SMTP_RESPONSE_OBSERVED":
        return None
    if row.get("tls_observation_state") != "HANDSHAKE_SUCCEEDED":
        if row.get("starttls_present") != "1" and row.get("tls_observed") != "1":
            return "CRITICAL"
        return None

    cipher = (row.get("cipher_suite") or "").upper()
    if any(token in cipher for token in ("_NULL_", "RC4", "EXPORT")):
        return "CRITICAL"
    if row.get("is_tls10") == "1" or row.get("is_tls11") == "1":
        return "HIGH"
    high_conditions = (
        row.get("cipher_uses_rsa_kex") == "1"
        or row.get("cert_sha1_signature") == "1"
        or (row.get("cert_key_algorithm") == "RSA" and _float(row.get("cert_rsa_key_size")) < 2048)
        or row.get("cert_expired") == "1"
        or row.get("cert_not_yet_valid") == "1"
        or row.get("cert_self_signed") == "True"
        or row.get("browser_trusted") == "False"
        or (row.get("cert_san_count") not in (None, "") and _float(row.get("cert_san_count")) == 0)
    )
    if high_conditions:
        return "HIGH"
    if row.get("cipher_uses_cbc") == "1" or row.get("uses_forward_secrecy") == "0":
        return "LOW_OR_MEDIUM"
    return "LOW_OR_MEDIUM"


def _float(value: str | None) -> float:
    try:
        return float(value) if value not in (None, "") else 0.0
    except (TypeError, ValueError):
        return 0.0


def _features(row: dict[str, str]) -> dict[str, Any]:
    tls_ok = row.get("tls_observation_state") == "HANDSHAKE_SUCCEEDED"
    if tls_ok:
        starttls_status = "UPGRADED" if row.get("starttls_present") == "1" else "IMPLICIT_TLS"
    elif row.get("starttls_present") == "1":
        starttls_status = "STARTTLS_NO_TLS_OBSERVED"
    else:
        starttls_status = "CLEARTEXT_NO_ENCRYPTION"

    cipher = (row.get("cipher_suite") or "").upper()
    strength = (
        "CRITICAL" if any(token in cipher for token in ("_NULL_", "RC4", "EXPORT")) else
        "MEDIUM" if row.get("cipher_uses_cbc") == "1" else
        "WEAK" if row.get("cipher_uses_rsa_kex") == "1" else
        "HIGH" if tls_ok else "__MISSING__"
    )
    browser_trusted = row.get("browser_trusted")
    self_signed = str(row.get("cert_self_signed") or "").lower() == "true"
    trust = (
        "TRUSTED" if browser_trusted == "True" and not self_signed else
        "SELF_SIGNED" if self_signed else
        "UNTRUSTED" if browser_trusted == "False" else "__MISSING__"
    )
    validity = (
        "EXPIRED" if row.get("cert_expired") == "1" else
        "NOT_YET_VALID" if row.get("cert_not_yet_valid") == "1" else
        "VALID" if row.get("certificate_observation_state") == "CERTIFICATE_OBSERVED" else
        "__MISSING__"
    )
    san_count = row.get("cert_san_count") or ""
    session = {
        "protocol": "SMTP",
        "starttls": {"status": starttls_status},
        "tls": {
            "tls_version": row.get("tls_version") or "",
            "raw_version": "",
            "cipher_name": row.get("cipher_suite") or "",
            "cipher_strength": strength,
            "key_exchange": row.get("key_exchange") or ("RSA" if row.get("cipher_uses_rsa_kex") == "1" else ""),
            "tls_extension_count": row.get("tls_extension_count") or "",
        } if tls_ok else None,
        "handshake": {"server_negotiation": {"selected_tls_version": row.get("tls_selected_version") or ""}},
        "certificate": {
            "trust_status": trust,
            "hostname_match": "HAS_SAN" if san_count and _float(san_count) > 0 else "NO_SAN" if san_count else "",
            "chain_length": row.get("cert_chain_length") or "",
            "leaf_cert": {
                "public_key_algorithm": row.get("cert_key_algorithm") or "",
                "public_key_size": row.get("cert_rsa_key_size") or row.get("cert_ecdsa_key_size") or "",
                "signature_algorithm_name": row.get("cert_signature_algorithm") or "",
                "san_dns": ["present"] * int(_float(san_count)),
                "is_expired": row.get("cert_expired") == "1" if row.get("cert_expired") != "" else None,
                "not_yet_valid": row.get("cert_not_yet_valid") == "1" if row.get("cert_not_yet_valid") != "" else None,
            } if row.get("certificate_observation_state") == "CERTIFICATE_OBSERVED" else {},
        } if row.get("certificate_observation_state") == "CERTIFICATE_OBSERVED" else None,
    }
    return _email_risk_features(session)


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

    with DATA.open(newline="", encoding="utf-8") as stream:
        source_rows = list(csv.DictReader(stream))
    rows = []
    for row in source_rows:
        label = _risk_label(row)
        if label is not None:
            rows.append({"record_id": row["record_id"], "country": row.get("country", "UNKNOWN"), "label": label, "features": _features(row)})
    if not rows or {row["label"] for row in rows} != set(LABELS):
        raise ValueError("Risk rubric data must contain all four classes")
    train_rows = [r for r in rows if r["country"] not in VALIDATION_COUNTRIES | TEST_COUNTRIES]
    validation_rows = [r for r in rows if r["country"] in VALIDATION_COUNTRIES]
    test_rows = [r for r in rows if r["country"] in TEST_COUNTRIES]
    if any({r["label"] for r in part} != set(LABELS) for part in (train_rows, validation_rows, test_rows)):
        raise ValueError("Every frozen country split must contain all four rubric classes")
    if ({r["country"] for r in train_rows} & {r["country"] for r in validation_rows}) or ({r["country"] for r in train_rows} & {r["country"] for r in test_rows}) or ({r["country"] for r in validation_rows} & {r["country"] for r in test_rows}):
        raise ValueError("Country leakage across split")

    candidates = {}
    candidate_params = {}
    for c_value in (0.03, 0.1, 0.3, 1.0, 3.0, 10.0):
        for weight in ("balanced", None):
            key = f"LogisticRegression_C{c_value:g}_weight_{weight or 'none'}"
            candidates[key] = make_pipeline(
                DictVectorizer(sparse=True), StandardScaler(with_mean=False),
                LogisticRegression(C=c_value, class_weight=weight, max_iter=3000, random_state=SEED),
            )
            candidate_params[key] = {"C": c_value, "class_weight": weight}
    for trees in (300, 500):
        for leaf in (1, 2, 5):
            key = f"RandomForest_n{trees}_leaf{leaf}"
            candidates[key] = make_pipeline(
                DictVectorizer(sparse=True),
                RandomForestClassifier(
                    n_estimators=trees, min_samples_leaf=leaf,
                    class_weight="balanced_subsample", random_state=SEED, n_jobs=1,
                ),
            )
            candidate_params[key] = {
                "n_estimators": trees, "min_samples_leaf": leaf,
                "class_weight": "balanced_subsample",
            }
    val_x = [r["features"] for r in validation_rows]
    val_y = [r["label"] for r in validation_rows]
    tuned_metrics = {}
    for name, model in candidates.items():
        model.fit([r["features"] for r in train_rows], [r["label"] for r in train_rows])
        tuned_metrics[name] = _metrics(val_y, [str(v) for v in model.predict(val_x)])
    selected_name = max(
        candidates,
        key=lambda name: (
            tuned_metrics[name]["macro_f1"],
            name.startswith("LogisticRegression"),
            -candidate_params[name].get("C", 0),
            -candidate_params[name].get("min_samples_leaf", 0),
        ),
    )
    selected = candidates[selected_name]
    selected_family = "LogisticRegression" if selected_name.startswith("LogisticRegression") else "RandomForest"
    family_best = {
        family: max(
            (name for name in candidates if name.startswith(family)),
            key=lambda name: tuned_metrics[name]["macro_f1"],
        )
        for family in ("LogisticRegression", "RandomForest")
    }
    fit_rows = train_rows + validation_rows
    selected.fit([r["features"] for r in fit_rows], [r["label"] for r in fit_rows])
    test_x = [r["features"] for r in test_rows]
    test_y = [r["label"] for r in test_rows]
    test_predictions = [str(v) for v in selected.predict(test_x)]
    dummy = DummyClassifier(strategy="most_frequent").fit([r["features"] for r in train_rows], [r["label"] for r in train_rows])
    test_metrics = _metrics(test_y, test_predictions)
    test_metrics["majority_baseline_macro_f1"] = _metrics(test_y, [str(v) for v in dummy.predict(test_x)])["macro_f1"]
    test_metrics["training_size_after_refit"] = len(fit_rows)

    split_by_id = {r["record_id"]: name for name, part in (("train", train_rows), ("validation", validation_rows), ("test", test_rows)) for r in part}
    SPLIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SPLIT_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("record_id", "country_group", "data_source", "split", "risk_tier_rubric"))
        writer.writeheader()
        writer.writerows({"record_id": r["record_id"], "country_group": r["country"], "data_source": "zgrab_real", "split": split_by_id[r["record_id"]], "risk_tier_rubric": r["label"]} for r in rows)
    with PREDICTIONS_PATH.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("record_id", "country_group", "actual", "predicted"))
        writer.writeheader()
        writer.writerows({"record_id": r["record_id"], "country_group": r["country"], "actual": r["label"], "predicted": predicted} for r, predicted in zip(test_rows, test_predictions))

    train_features = [r["features"] for r in train_rows]
    coverage = sorted(
        (sum(f[name] != "__MISSING__" for name in EMAIL_RISK_CATEGORICAL) + sum(f[f"{name}__missing"] == 0 for name in EMAIL_RISK_NUMERIC))
        / (len(EMAIL_RISK_CATEGORICAL) + len(EMAIL_RISK_NUMERIC)) for f in train_features
    )
    metadata = {
        "model_id": MODEL_ID,
        "model_version": "1.1",
        "feature_schema_version": "zgrab_email_session_risk_v1",
        "algorithm": selected_family,
        "selected_hyperparameters": candidate_params[selected_name],
        "hyperparameter_search": {
            "method": "Exhaustive fixed grid on train countries; country-held-out validation selection by macro-F1; heldout test was not used for selection.",
            "candidates": {
                name: {"params": candidate_params[name], "validation_macro_f1": tuned_metrics[name]["macro_f1"]}
                for name in sorted(candidates)
            },
        },
        "task": "Supervised real-ZGrab SMTP evidence-rubric classification",
        "target": "zgrab_observed_security_rubric_v1",
        "target_semantics": "LOW/MEDIUM/HIGH/CRITICAL labels are derived from raw observed SMTP/TLS/certificate facts by a documented project rubric; Rule Engine findings, rule flags, and legacy proxy labels are never read.",
        "target_rubric": {
            "CRITICAL": "SMTP response observed but neither STARTTLS nor TLS observed, or a NULL/RC4/EXPORT cipher was negotiated.",
            "HIGH": "TLS 1.0/1.1, static RSA key exchange, SHA-1 certificate signature, RSA key below 2048, invalid validity, self-signed/untrusted certificate, or no SAN.",
            "LOW_OR_MEDIUM": "A completed TLS handshake with no high/critical rubric condition; due only one medium-only observation, CBC/no-forward-secrecy cases are merged into this coarsened class.",
            "NOT_EVALUABLE": "SMTP response failure or attempted STARTTLS/TLS without completed handshake.",
        },
        "data_source": "zgrab_real",
        "sample_count": len(rows),
        "source_observation_count": len(source_rows),
        "not_evaluable_observation_count": len(source_rows) - len(rows),
        "class_counts": dict(Counter(r["label"] for r in rows)),
        "split_method": "Frozen country-grouped train/validation/test; no country appears in multiple splits.",
        "split_countries": {"train": sorted({r["country"] for r in train_rows}), "validation": sorted(VALIDATION_COUNTRIES), "test": sorted(TEST_COUNTRIES)},
        "split_sizes": {"train": len(train_rows), "validation": len(validation_rows), "test": len(test_rows)},
        "split_class_counts": {name: dict(Counter(r["label"] for r in part)) for name, part in (("train", train_rows), ("validation", validation_rows), ("test", test_rows))},
        "categorical_features": list(EMAIL_RISK_CATEGORICAL),
        "numeric_features": list(EMAIL_RISK_NUMERIC),
        "feature_count": len(EMAIL_RISK_CATEGORICAL) + len(EMAIL_RISK_NUMERIC),
        "runtime_feature_observability": {"p05_training_fraction": coverage[max(0, int((len(coverage) - 1) * 0.05))]},
        "validation_candidates": {
            family: tuned_metrics[name]
            for family, name in family_best.items()
        },
        "selection_metric": "validation macro-F1",
        "test_metrics": test_metrics,
        "data_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "limitations": [
            "Labels are an explicit project rubric derived from observations, not independent human-reviewed real-world risk truth.",
            "Evaluation measures prediction of this rubric on held-out countries; server/vendor/certificate-family independence is not guaranteed.",
            "ZGrab is active SMTP scan data, not passive PCAP; runtime transfer to passive sessions is NOT_VALIDATED.",
            "Uncalibrated classifier scores are not probabilities of compromise.",
            "Rule Engine outcomes remain independent and authoritative.",
        ],
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": selected}, MODEL_PATH)
    metadata["artifact_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    METADATA_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


if __name__ == "__main__":
    result = train()
    print(json.dumps({key: result[key] for key in ("model_id", "sample_count", "class_counts", "split_sizes", "validation_candidates", "test_metrics")}, indent=2))
