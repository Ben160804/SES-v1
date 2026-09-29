"""Fit a separate cohort-relative anomaly model for the HTTPS TLS PCAP corpus."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "ml" / "processed" / "https_tls_v1.csv"
MODEL_DIR = ROOT / "datasets" / "ml" / "models"
MODEL_PATH = MODEL_DIR / "https_tls_anomaly_v1.joblib"
METADATA_PATH = MODEL_DIR / "https_tls_anomaly_v1.json"
SCORES_PATH = ROOT / "datasets" / "ml" / "processed" / "https_tls_anomaly_scores_v1.csv"
SEED = 20260929
CONTAMINATION = 0.01

CATEGORICAL_FEATURES = (
    "client_hello_legacy_version", "client_offered_versions", "selected_tls_version",
    "selected_cipher_suite", "selected_cipher_strength", "selected_key_exchange",
    "selected_key_share_group", "record_legacy_version_set",
)
NUMERIC_FEATURES = (
    "client_offered_version_count", "client_offered_cipher_count", "client_extension_count",
    "client_sni_extension", "client_supported_groups_count", "client_key_share_extension",
    "client_signature_algorithms_extension", "server_extension_count",
    "server_supported_versions_extension", "tls_record_count", "tls_record_bytes",
    "tls_record_type_22_count", "tls_record_type_23_count", "tls_payload_bytes_client",
    "tls_payload_bytes_server", "packet_count", "tcp_payload_packet_count",
    "tcp_flow_count", "capture_bytes", "capture_duration_seconds",
    "tcp_sequence_gap_observed", "handshake_observed",
)
RARITY_FIELDS = ("selected_tls_version", "selected_cipher_suite", "selected_key_share_group")
FORBIDDEN_FEATURES = {"record_id", "server_group_id", "data_source", "source_ref", "source_entry_index"}


def _features(row: dict[str, str]) -> dict[str, Any]:
    result = {field: row.get(field) or "__MISSING__" for field in CATEGORICAL_FEATURES}
    for field in NUMERIC_FEATURES:
        raw = row.get(field, "")
        try:
            result[field] = float(raw) if raw else 0.0
            result[f"{field}__missing"] = 0.0 if raw else 1.0
        except ValueError:
            result[field] = 0.0
            result[f"{field}__missing"] = 1.0
    if set(result) & FORBIDDEN_FEATURES:
        raise ValueError("Identity/provenance field leaked into the feature vector")
    return result


def _rarity_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row.get(field, "") for field in RARITY_FIELDS)


def train() -> None:
    try:
        import joblib
        import sklearn
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.model_selection import GroupShuffleSplit
        from sklearn.preprocessing import StandardScaler
        from scipy.sparse import hstack
    except ImportError as exc:
        raise RuntimeError("Install datasets/ml/requirements.txt before training") from exc

    with DATA.open(newline="", encoding="utf-8") as source:
        observations = [row for row in csv.DictReader(source) if row.get("parse_status") == "PARSED"]
    if len(observations) < 100:
        raise ValueError(f"Insufficient HTTPS handshakes: {len(observations)}")

    train_index, test_index = next(GroupShuffleSplit(
        n_splits=1, test_size=0.20, random_state=SEED
    ).split(observations, groups=[row["server_group_id"] for row in observations]))
    train_rows = [observations[index] for index in train_index]
    test_rows = [observations[index] for index in test_index]
    train_features = [_features(row) for row in train_rows]
    all_features = [_features(row) for row in observations]
    vectorizer = DictVectorizer(sparse=True)
    train_categorical = vectorizer.fit_transform(train_features)
    categorical = vectorizer.transform(all_features)

    def numeric_matrix(rows: list[dict[str, str]]) -> list[list[float]]:
        values = []
        for row in rows:
            one = []
            for field in NUMERIC_FEATURES:
                try:
                    value = float(row.get(field) or 0)
                except ValueError:
                    value = 0.0
                one.extend((value, 1.0 if not row.get(field) else 0.0))
            values.append(one)
        return values

    scaler = StandardScaler()
    train_numeric = scaler.fit_transform(numeric_matrix(train_rows))
    numeric = scaler.transform(numeric_matrix(observations))
    train_matrix = hstack([train_categorical, train_numeric], format="csr")
    matrix = hstack([categorical, numeric], format="csr")
    model = IsolationForest(
        n_estimators=300,
        max_samples=min(1024, len(train_rows)),
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=1,
    )
    model.fit(train_matrix)
    decisions = model.decision_function(matrix)
    predictions = model.predict(matrix)

    config_counts = Counter(_rarity_key(row) for row in train_rows)
    config_n = len(train_rows)
    config_k = len(config_counts)
    score_rows = []
    test_flags = 0
    test_ids = {row["record_id"] for row in test_rows}
    unseen_test_tuples = {_rarity_key(row) for row in test_rows if config_counts[_rarity_key(row)] == 0}
    for row, decision, predicted in zip(observations, decisions, predictions):
        key = _rarity_key(row)
        count = config_counts[key]
        rarity_bits = -math.log2((count + 1) / (config_n + config_k))
        is_test = row["record_id"] in test_ids
        test_flags += is_test and int(predicted) == -1
        score_rows.append({
            "record_id": row["record_id"],
            "server_group_id": row["server_group_id"],
            "data_source": row["data_source"],
            "evaluation_split": "test_heldout_site" if is_test else "train_reference",
            "novelty_score": f"{-float(decision):.8f}",
            "novelty_status": "UNUSUAL_RELATIVE_TO_HTTPS_REFERENCE" if int(predicted) == -1 else "WITHIN_HTTPS_REFERENCE",
            "rarity_score_bits": f"{rarity_bits:.6f}",
            "configuration_count": count,
            "reference_count": config_n,
        })

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    SCORES_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "scaler": scaler, "model": model}, MODEL_PATH)
    artifact_sha256 = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with SCORES_PATH.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(score_rows[0]))
        writer.writeheader()
        writer.writerows(score_rows)

    data_meta = json.loads((ROOT / "datasets/ml/metadata/https_tls_v1.json").read_text())
    metadata = {
        "model_id": "https_tls_anomaly_v1",
        "model_version": "1.1",
        "feature_schema_version": "https_tls_v1",
        "task": "Cohort-relative TLS behavior novelty; HTTPS-only, not email and not attack detection.",
        "algorithm": "IsolationForest",
        "reference_population": "TLS PCAP observations in mix.zip; 41 site groups, all sessions TLS 1.3, with three balanced selected cipher suites.",
        "sample_count": len(observations),
        "training_sample_count": len(train_rows),
        "heldout_sample_count": len(test_rows),
        "group_count": len({row["server_group_id"] for row in observations}),
        "training_group_count": len({row["server_group_id"] for row in train_rows}),
        "heldout_group_count": len({row["server_group_id"] for row in test_rows}),
        "contamination_assumption": CONTAMINATION,
        "flagged_count_in_sample": sum(int(predictions[index]) == -1 for index in train_index),
        "heldout_flagged_count": test_flags,
        "heldout_flag_rate": test_flags / len(test_rows),
        "rarity_configuration_count": config_k,
        "heldout_distinct_unseen_rarity_tuples": len(unseen_test_tuples),
        "features": list(CATEGORICAL_FEATURES + NUMERIC_FEATURES),
        "rarity_fields": list(RARITY_FIELDS),
        "split_method": "20% held out by server/site group with GroupShuffleSplit before preprocessing/model fit.",
        "evaluation": "Unlabeled heldout-site novelty and support audit only; no precision/recall or attack-detection claim is possible.",
        "dataset_sha256": data_meta["source_sha256"],
        "limitations": [
            "All observed ServerHellos are TLS 1.3; this corpus cannot train or evaluate legacy TLS detection.",
            "The three selected ciphers are exactly balanced in this collection; observed frequencies do not estimate Internet prevalence.",
            "TLS 1.3 certificate messages are encrypted in these passive captures, so certificate features are unavailable without secrets.",
            "Only 41 hashed site groups exist; one grouped holdout has low independent-group support and broad transfer remains uncertain.",
            "The configured 1% contamination is a review-tail assumption, not a measured false-positive rate.",
            "No IP, hostname, raw archive path, or group identifier is used as a model feature.",
        ],
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "artifact_sha256": artifact_sha256,
        "model_path": str(MODEL_PATH.relative_to(ROOT)),
        "scores_path": str(SCORES_PATH.relative_to(ROOT)),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"HTTPS observations: {len(observations)}; train/test: {len(train_rows)}/{len(test_rows)}; heldout groups: {metadata['heldout_group_count']}; heldout flags: {test_flags}")
    print(f"Model: {MODEL_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    train()
