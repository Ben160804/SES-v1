"""Allowlisted local model loading with integrity checks before deserialization."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIRECTORY = ROOT / "datasets" / "ml" / "models"
MODEL_REGISTRY = {
    "zgrab_rule_flag_proxy_v1": (
        "zgrab_rule_flag_proxy_v1.joblib",
        "zgrab_rule_flag_proxy_v1_evaluation.json",
        "zgrab_smtp_v1",
    ),
        "zgrab_runtime_rule_flag_proxy_v2": (
        "zgrab_runtime_rule_flag_proxy_v2.joblib",
        "zgrab_runtime_rule_flag_proxy_v2.json",
        "zgrab_smtp_runtime_proxy_v2",
        ),
    "zgrab_runtime_risk_tier_v1": (
        "zgrab_runtime_risk_tier_v1.joblib",
        "zgrab_runtime_risk_tier_v1.json",
        "zgrab_smtp_runtime_risk_tier_v1",
    ),
    "zgrab_smtp_anomaly_v1": (
        "zgrab_smtp_anomaly_v1.joblib",
        "zgrab_smtp_anomaly_v1.json",
        "zgrab_smtp_v1",
    ),
    "zgrab_smtp_negotiation_anomaly_v1": (
        "zgrab_smtp_negotiation_anomaly_v1.joblib",
        "zgrab_smtp_negotiation_anomaly_v1.json",
        "zgrab_smtp_negotiation_v2",
    ),
    "synthetic_email_risk_classifier_v1": (
        "synthetic_email_risk_classifier_v1.joblib",
        "synthetic_email_risk_classifier_v1.json",
        "synthetic_email_session_risk_v1",
    ),
    "synthetic_email_posture_classifier_v2": (
        "synthetic_email_posture_classifier_v2.joblib",
        "synthetic_email_posture_classifier_v2.json",
        "synthetic_email_session_risk_v2",
    ),
    "zgrab_evidence_risk_classifier_v1": (
        "zgrab_evidence_risk_classifier_v1.joblib",
        "zgrab_evidence_risk_classifier_v1.json",
        "zgrab_email_session_risk_v1",
    ),
    "mta_sts_cert_anomaly_v1": (
        "mta_sts_cert_anomaly_v1.joblib",
        "mta_sts_cert_anomaly_v1.json",
        "mta_sts_certificates_v1",
    ),
    "https_tls_anomaly_v1": (
        "https_tls_anomaly_v1.joblib",
        "https_tls_anomaly_v1.json",
        "https_tls_v1",
    ),
}


class ModelArtifactError(RuntimeError):
    """An artifact is missing, changed, or incompatible with the registry."""


@dataclass(frozen=True)
class LoadedModel:
    model_id: str
    payload: Any
    metadata: dict[str, Any]
    artifact_path: Path


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_model(model_id: str, *, directory: Path | None = None) -> LoadedModel:
    """Load only a known artifact after metadata and digest verification."""
    try:
        artifact_name, metadata_name, expected_schema = MODEL_REGISTRY[model_id]
    except KeyError as exc:
        raise ModelArtifactError(f"Unregistered model id: {model_id!r}") from exc

    root = (directory or MODEL_DIRECTORY).resolve()
    artifact_path = (root / artifact_name).resolve()
    metadata_path = (root / metadata_name).resolve()
    if artifact_path.parent != root or metadata_path.parent != root:
        raise ModelArtifactError("Model path resolves outside the configured artifact directory")
    if not artifact_path.is_file() or not metadata_path.is_file():
        raise ModelArtifactError(f"Model or metadata is missing for {model_id}")

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelArtifactError(f"Invalid model metadata for {model_id}: {exc}") from exc
    if metadata.get("model_id") != model_id:
        raise ModelArtifactError("Metadata model id does not match the requested model")
    if metadata.get("feature_schema_version") != expected_schema:
        raise ModelArtifactError(
            f"Unsupported feature schema: {metadata.get('feature_schema_version')!r}"
        )

    expected_digest = metadata.get("artifact_sha256")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise ModelArtifactError("Metadata does not contain a valid artifact SHA-256")
    actual_digest = _digest(artifact_path)
    if not hmac.compare_digest(actual_digest, expected_digest.lower()):
        raise ModelArtifactError("Artifact digest mismatch; refusing to deserialize model")

    try:
        import joblib
    except ImportError as exc:
        raise ModelArtifactError("joblib is unavailable; install datasets/ml/requirements.txt") from exc
    try:
        payload = joblib.load(artifact_path)
    except Exception as exc:
        raise ModelArtifactError(f"Artifact deserialization failed: {type(exc).__name__}") from exc
    return LoadedModel(model_id, payload, metadata, artifact_path)


def model_catalog(*, directory: Path | None = None) -> dict[str, Any]:
    """Describe registered models and verify artifact hashes without deserializing."""
    root = (directory or MODEL_DIRECTORY).resolve()
    models: list[dict[str, Any]] = []
    for model_id, (artifact_name, metadata_name, expected_schema) in MODEL_REGISTRY.items():
        artifact_path = (root / artifact_name).resolve()
        metadata_path = (root / metadata_name).resolve()
        row: dict[str, Any] = {
            "model_id": model_id,
            "artifact_status": "UNAVAILABLE",
            "feature_schema_version": expected_schema,
        }
        if artifact_path.parent != root or metadata_path.parent != root:
            row.update(artifact_status="REJECTED", reason="Model path escapes artifact directory")
        elif not artifact_path.is_file() or not metadata_path.is_file():
            row["reason"] = "Model artifact or metadata is missing"
        else:
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                actual = _digest(artifact_path)
                expected = metadata.get("artifact_sha256")
                valid = (
                    metadata.get("model_id") == model_id
                    and metadata.get("feature_schema_version") == expected_schema
                    and isinstance(expected, str)
                    and hmac.compare_digest(actual, expected.lower())
                )
                row.update(
                    artifact_status="READY" if valid else "REJECTED",
                    metadata={key: metadata[key] for key in (
                        "model_version", "algorithm", "model", "task", "target",
                        "target_semantics", "reference_cohort", "dataset_id", "sample_count",
                        "data_source", "feature_count", "feature_schema_fields", "split_method",
                        "split_sizes", "split_countries", "class_counts", "tier_definition",
                        "target_rubric", "protocol_counts", "split_class_counts", "split_family_counts",
                        "source_observation_count", "not_evaluable_observation_count", "split_group_component_counts",
                        "synthetic_observation_count", "split_group_counts", "real_observation_count",
                        "test_metrics", "selection_metric", "selected_validation_macro_f1",
                        "validation_candidate_metrics", "validation_candidates",
                        "selected_hyperparameters", "hyperparameter_search",
                        "reference_count", "reference_unique_certificates", "scored_handshakes",
                        "macro_f1", "accuracy", "majority_baseline_macro_f1", "evaluation",
                        "limitations", "contamination_assumption", "feature_schema_version",
                    ) if key in metadata},
                    artifact_sha256=actual,
                )
                if not valid:
                    row["reason"] = "Model id, schema, or artifact digest failed validation"
            except (OSError, json.JSONDecodeError) as exc:
                row.update(artifact_status="REJECTED", reason=f"Invalid model metadata: {type(exc).__name__}")
        models.append(row)
    return {
        "registry_version": 1,
        "model_count": len(models),
        "ready_count": sum(model["artifact_status"] == "READY" for model in models),
        "models": models,
        "independent_outputs": [
            "deterministic_policy_findings",
            "deterministic_posture_assessment",
            "classifier_risk_tier",
            "synthetic_email_risk_classifier",
            "zgrab_evidence_risk_classifier",
            "classifier_rule_flag_proxy_legacy",
            "smtp_configuration_anomaly",
            "smtp_configuration_rarity",
            "certificate_novelty",
        ],
        "authority_note": "ML outputs are advisory and do not alter deterministic policy findings or posture.",
    }
