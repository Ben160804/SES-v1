"""Train a certificate-only novelty model on unique MTA-STS scan certificates."""

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
DATA = ROOT / "datasets" / "ml" / "processed" / "mta_sts_certificates_v1.csv"
MODEL_DIR = ROOT / "datasets" / "ml" / "models"
MODEL_PATH = MODEL_DIR / "mta_sts_cert_anomaly_v1.joblib"
METADATA_PATH = MODEL_DIR / "mta_sts_cert_anomaly_v1.json"
SCORES_PATH = ROOT / "datasets" / "ml" / "processed" / "mta_sts_certificate_anomaly_scores_v1.csv"
SEED = 20260929
CONTAMINATION = 0.05

CATEGORICAL_FEATURES = (
    "key_algorithm", "ecdsa_curve", "signature_hash", "signature_algorithm_oid",
    "self_signed", "is_ca", "server_auth_eku", "client_auth_eku",
    "key_usage_digital_signature", "key_usage_key_encipherment",
    "key_usage_key_agreement", "has_ocsp_or_issuer_info", "has_certificate_policies",
    "has_crl_distribution_points", "has_authority_key_id", "has_subject_key_id",
)
NUMERIC_FEATURES = (
    "key_size_bits", "certificate_validity_days", "san_count", "wildcard_san_count",
    "extension_count", "chain_length_observed",
)
RARITY_FEATURES = ("key_algorithm", "key_size_bits", "signature_hash", "chain_length_observed")


def _features(row: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        field: row.get(field) or "__MISSING__" for field in CATEGORICAL_FEATURES
    }
    for field in NUMERIC_FEATURES:
        raw = row.get(field, "")
        try:
            result[field] = float(raw) if raw else 0.0
            result[f"{field}__missing"] = 0.0 if raw else 1.0
        except ValueError:
            result[field] = 0.0
            result[f"{field}__missing"] = 1.0
    return result


def _rarity_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row.get(field, "") for field in RARITY_FEATURES)


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

    with DATA.open(newline="", encoding="utf-8") as stream:
        observations = [
            row for row in csv.DictReader(stream)
            if row.get("parse_status") == "PARSED" and row.get("certificate_group_id")
        ]
    if not observations:
        raise ValueError("No parsed MTA-STS certificates; run the feature extractor first")

    # A certificate seen hundreds of times should not dominate the learned
    # reference. Keep one representative row per exact certificate fingerprint.
    unique: dict[str, dict[str, str]] = {}
    for row in observations:
        unique.setdefault(row["certificate_group_id"], row)
    unique_certificates = list(unique.values())
    train_index, test_index = next(GroupShuffleSplit(
        n_splits=1, test_size=0.20, random_state=SEED
    ).split(unique_certificates, groups=[row["certificate_group_id"] for row in unique_certificates]))
    reference = [unique_certificates[index] for index in train_index]
    heldout = [unique_certificates[index] for index in test_index]
    train_ids = {row["certificate_group_id"] for row in reference}
    heldout_ids = {row["certificate_group_id"] for row in heldout}
    if train_ids & heldout_ids:
        raise ValueError("Certificate fingerprint leaked across train/test groups")
    vectorizer = DictVectorizer(sparse=True)
    train_categorical = vectorizer.fit_transform([_features(row) for row in reference])
    all_categorical = vectorizer.transform([_features(row) for row in unique_certificates])

    def numeric_rows(rows: list[dict[str, str]]) -> list[list[float]]:
        result = []
        for row in rows:
            values = []
            for field in NUMERIC_FEATURES:
                try:
                    value = float(row.get(field) or 0)
                except ValueError:
                    value = 0.0
                values.extend((value, 1.0 if not row.get(field) else 0.0))
            result.append(values)
        return result

    scaler = StandardScaler()
    train_numeric = scaler.fit_transform(numeric_rows(reference))
    all_numeric = scaler.transform(numeric_rows(unique_certificates))
    train_matrix = hstack([train_categorical, train_numeric], format="csr")
    all_matrix = hstack([all_categorical, all_numeric], format="csr")

    model = IsolationForest(
        n_estimators=300,
        max_samples=min(1024, len(reference)),
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=1,
    )
    model.fit(train_matrix)

    rarity_counts = Counter(_rarity_key(row) for row in reference)
    rarity_n = len(reference)
    rarity_k = len(rarity_counts)
    scored_rows = []
    score_by_fingerprint: dict[str, tuple[float, bool, int, float, str]] = {}
    decisions = model.decision_function(all_matrix)
    flags = model.predict(all_matrix)
    for row, decision, flag in zip(unique_certificates, decisions, flags):
        fingerprint = row["certificate_group_id"]
        count = rarity_counts[_rarity_key(row)]
        probability = (count + 1) / (rarity_n + rarity_k)
        score_by_fingerprint[fingerprint] = (
            float(-decision), int(flag) == -1, count, -math.log2(probability),
            "train_reference" if fingerprint in train_ids else "test_heldout_certificate",
        )
    heldout_flags = sum(score_by_fingerprint[row["certificate_group_id"]][1] for row in heldout)
    heldout_distinct_unseen_rarity_tuples = len({
        _rarity_key(row) for row in heldout if rarity_counts[_rarity_key(row)] == 0
    })

    for row in observations:
        score, flagged, config_count, rarity_bits, evaluation_split = score_by_fingerprint[row["certificate_group_id"]]
        scored_rows.append({
            "record_id": row["record_id"],
            "certificate_group_id": row["certificate_group_id"],
            "data_source": row["data_source"],
            "evaluation_split": evaluation_split,
            "novelty_score": f"{score:.8f}",
            "novelty_status": "UNUSUAL_RELATIVE_TO_MTA_STS_CERT_COHORT" if flagged else "WITHIN_MTA_STS_CERT_REFERENCE",
            "configuration_rarity_bits": f"{rarity_bits:.6f}",
            "unique_certificate_configuration_count": config_count,
            "unique_certificate_reference_count": rarity_n,
        })

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    SCORES_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "scaler": scaler, "model": model}, MODEL_PATH)
    artifact_sha256 = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with SCORES_PATH.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(scored_rows[0]))
        writer.writeheader()
        writer.writerows(scored_rows)

    source_meta = json.loads((ROOT / "datasets/ml/metadata/mta_sts_certificates_v1.json").read_text())
    metadata = {
        "model_id": "mta_sts_cert_anomaly_v1",
        "model_version": "1.1",
        "feature_schema_version": "mta_sts_certificates_v1",
        "task": "Certificate feature novelty relative to a deduplicated SMTP-related certificate cohort; not vulnerability detection.",
        "source_dataset": "mta_sts_certificates_v1",
        "source_sha256": source_meta["source_sha256"],
        "algorithm": "IsolationForest",
        "reference_observations": len(observations),
        "reference_unique_certificates": len(reference),
        "total_unique_certificates": len(unique_certificates),
        "heldout_unique_certificates": len(heldout),
        "scored_observations": len(scored_rows),
        "distinct_rarity_configurations": rarity_k,
        "contamination_assumption": CONTAMINATION,
        "flagged_training_unique_certificates": sum(score_by_fingerprint[row["certificate_group_id"]][1] for row in reference),
        "heldout_flagged_unique_certificates": heldout_flags,
        "heldout_flag_rate": heldout_flags / len(heldout),
        "heldout_distinct_unseen_rarity_tuples": heldout_distinct_unseen_rarity_tuples,
        "split_method": "20% held out by unique certificate fingerprint before preprocessing/model fit.",
        "features": list(CATEGORICAL_FEATURES + NUMERIC_FEATURES),
        "rarity_baseline": {
            "fields": list(RARITY_FEATURES),
            "method": "Add-one-smoothed frequency over unique certificates.",
            "configuration_counts": [
                {"configuration": list(key), "count": count, "frequency": count / rarity_n}
                for key, count in sorted(rarity_counts.items())
            ],
        },
        "evaluation": "Unlabeled heldout-certificate novelty/support audit only; no precision/recall or certificate-vulnerability claim is possible.",
        "limitations": [
            "Source rows contain SMTP-related certificate scans, not complete SMTP sessions.",
            "Exact duplicate certificates were deduplicated for fitting and retain a fingerprint group ID for split control.",
            "The 5% contamination setting is an analyst-facing threshold assumption, not an empirical false-positive rate.",
            "Deterministic certificate validation and crypto rules remain authoritative; novelty does not imply insecurity.",
            "Model is connected to optional PCAP certificate novelty; deterministic certificate validation remains authoritative.",
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
    print(f"Unique certs train/test: {len(reference)}/{len(heldout)}; scored observations: {len(scored_rows)}")
    print(f"Held-out novelty flags under {CONTAMINATION:.0%} assumption: {heldout_flags}/{len(heldout)}")
    print(f"Model: {MODEL_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    train()
