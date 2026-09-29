"""Focused tests for the allowlisted model artifact loader."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from analysis.ml_artifacts import ModelArtifactError, load_model


class TestMLArtifactRegistry(unittest.TestCase):
    def test_synthetic_email_classifier_model_loads_with_expected_schema(self):
        loaded = load_model("synthetic_email_risk_classifier_v1")
        self.assertEqual(loaded.metadata["feature_schema_version"], "synthetic_email_session_risk_v1")
        self.assertEqual(loaded.metadata["data_source"], "synthetic_testbed")
        self.assertEqual(loaded.metadata["sample_count"], 110)

    def test_synthetic_research_classifier_loads_with_10k_provenance(self):
        loaded = load_model("synthetic_email_posture_classifier_v2")
        self.assertEqual(loaded.metadata["feature_schema_version"], "synthetic_email_session_risk_v2")
        self.assertEqual(loaded.metadata["synthetic_observation_count"], 10_000)
        self.assertEqual(loaded.metadata["real_observation_count"], 0)
        self.assertEqual(loaded.metadata["data_source"], "synthetic_simulation")
        self.assertEqual(loaded.metadata["sample_count"], 10_000)

    def test_real_zgrab_evidence_classifier_loads_with_provenance(self):
        loaded = load_model("zgrab_evidence_risk_classifier_v1")
        self.assertEqual(loaded.metadata["feature_schema_version"], "zgrab_email_session_risk_v1")
        self.assertEqual(loaded.metadata["data_source"], "zgrab_real")
        self.assertEqual(loaded.metadata["source_observation_count"], 1600)
        self.assertNotIn("rule_flag_legacy_tls", loaded.metadata["categorical_features"])

    def test_unknown_model_id_is_rejected(self):
        with self.assertRaisesRegex(ModelArtifactError, "Unregistered"):
            load_model("../../arbitrary")

    def test_tampered_artifact_is_rejected_before_deserialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "https_tls_anomaly_v1.joblib"
            metadata = root / "https_tls_anomaly_v1.json"
            artifact.write_bytes(b"modified artifact")
            metadata.write_text(json.dumps({
                "model_id": "https_tls_anomaly_v1",
                "feature_schema_version": "https_tls_v1",
                "artifact_sha256": hashlib.sha256(b"expected artifact").hexdigest(),
            }), encoding="utf-8")
            with self.assertRaisesRegex(ModelArtifactError, "digest mismatch"):
                load_model("https_tls_anomaly_v1", directory=root)

    def test_metadata_schema_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "https_tls_anomaly_v1.joblib").write_bytes(b"model")
            (root / "https_tls_anomaly_v1.json").write_text(json.dumps({
                "model_id": "https_tls_anomaly_v1",
                "feature_schema_version": "wrong-schema",
                "artifact_sha256": hashlib.sha256(b"model").hexdigest(),
            }), encoding="utf-8")
            with self.assertRaisesRegex(ModelArtifactError, "Unsupported feature schema"):
                load_model("https_tls_anomaly_v1", directory=root)
