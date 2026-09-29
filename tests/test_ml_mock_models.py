"""Smoke-test every registered artifact on missing and populated mock features."""

from __future__ import annotations

import math
import json
import unittest
from pathlib import Path

import numpy as np
from scipy.sparse import hstack

from analysis.ml_artifacts import MODEL_REGISTRY, load_model
from analysis.ml_runtime import analyze_ml_session


def _mock_from_vectorizer(vectorizer) -> dict[str, object]:
    """Create a schema-shaped row using known categorical vocabulary values."""
    row: dict[str, object] = {}
    for feature in vectorizer.get_feature_names_out():
        name = str(feature)
        if "=" in name:
            key, value = name.split("=", 1)
            row.setdefault(key, value)
        else:
            row.setdefault(name, 0.0)
    return row


class MockModelInferenceTests(unittest.TestCase):
    def test_all_registered_models_accept_missing_and_populated_mock_features(self) -> None:
        self.assertEqual(len(MODEL_REGISTRY), 10)
        for model_id in MODEL_REGISTRY:
            with self.subTest(model_id=model_id):
                loaded = load_model(model_id)
                payload = loaded.payload
                if isinstance(payload, dict) and "vectorizer" in payload:
                    vectorizer = payload["vectorizer"]
                    model = payload["model"]
                    scaler = payload.get("scaler")
                    ordinary = _mock_from_vectorizer(vectorizer)
                    for mock in ({}, ordinary):
                        matrix = vectorizer.transform([mock])
                        if scaler is not None:
                            numeric = scaler.transform(np.zeros((1, scaler.n_features_in_)))
                            matrix = hstack([matrix, numeric], format="csr")
                        if hasattr(model, "decision_function"):
                            value = float(model.decision_function(matrix)[0])
                            self.assertTrue(math.isfinite(value))
                        else:
                            self.assertEqual(len(model.predict(matrix)), 1)
                else:
                    model = payload.get("model") if isinstance(payload, dict) else payload
                    for mock in ({}, _mock_from_vectorizer(model.named_steps["dictvectorizer"])):
                        self.assertEqual(len(model.predict([mock])), 1)

    def test_mock_sessions_do_not_mix_cohort_routed_classifiers(self) -> None:
        from analysis.ml_runtime import analyze_ml_session

        cases = (
            ("SMTP", "zgrab_evidence_risk_classifier_v1", "synthetic_email_posture_classifier_v2"),
            ("IMAP", "synthetic_email_posture_classifier_v2", "zgrab_evidence_risk_classifier_v1"),
            ("POP3", "synthetic_email_posture_classifier_v2", "zgrab_evidence_risk_classifier_v1"),
        )
        for protocol, applicable_id, other_id in cases:
            with self.subTest(protocol=protocol):
                result = analyze_ml_session({"protocol": protocol})
                all_results = str(result)
                self.assertIn(applicable_id, all_results)
                self.assertIn(other_id, all_results)

    def test_controlled_seen_and_unseen_mock_tls_and_certificate_configurations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        smtp_meta = json.loads((root / "datasets/ml/models/zgrab_smtp_negotiation_anomaly_v1.json").read_text())
        smtp_config = smtp_meta["rarity_reference_counts"][0]["configuration"]
        known_tls = {
            "protocol": "SMTP",
            "tls": {"tls_version": smtp_config[0], "cipher_name": smtp_config[1], "key_exchange": smtp_config[2]},
            "handshake": {"server_negotiation": {"selected_tls_version": smtp_config[0]}},
        }
        unknown_tls = {
            "protocol": "SMTP",
            "tls": {"tls_version": "TLSv9.9", "cipher_name": "TLS_MOCK_UNSEEN_SUITE", "key_exchange": "mock_curve"},
            "handshake": {"server_negotiation": {"selected_tls_version": "TLSv9.9"}},
        }
        known_result = analyze_ml_session(known_tls)["smtp_configuration_rarity"]
        unknown_result = analyze_ml_session(unknown_tls)["smtp_configuration_rarity"]
        self.assertEqual(known_result["configuration_count"], smtp_meta["rarity_reference_counts"][0]["count"])
        self.assertEqual(known_result["support_status"], "SEEN_CONFIGURATION")
        self.assertEqual(unknown_result["configuration_count"], 0)
        self.assertEqual(unknown_result["support_status"], "UNSEEN_CONFIGURATION")

        cert_meta = json.loads((root / "datasets/ml/models/mta_sts_cert_anomaly_v1.json").read_text())
        cert_config = cert_meta["rarity_baseline"]["configuration_counts"][0]

        def cert_session(config: list[str]) -> dict[str, object]:
            algorithm, key_size, signature_hash, chain_length = config
            leaf = {
                "public_key_algorithm": algorithm,
                "public_key_size": int(key_size),
                "signature_hash_algorithm": signature_hash,
                "signature_algorithm_name": "sha256WithRSAEncryption",
                "signature_algorithm_oid": "1.2.840.113549.1.1.11",
                "ecdsa_curve": "secp256r1",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2025-01-01T00:00:00Z",
                "san_dns": ["mx.mock.example"],
                "san_ip": [],
                "basic_constraints": {"ca": False},
                "key_usage": {"digital_signature": True},
                "extended_key_usage": ["serverAuth"],
                "extension_count": 8,
            }
            return {"protocol": "SMTP", "certificate": {"chain_length": int(chain_length), "leaf_cert": leaf}}

        known_cert = analyze_ml_session(cert_session(cert_config["configuration"]))["certificate_novelty"]
        novel_configuration = ["MOCK_UNSEEN_KEY_ALGORITHM", "8192", "mockhash", "99"]
        unknown_cert = analyze_ml_session(cert_session(novel_configuration))["certificate_novelty"]
        self.assertEqual(known_cert["status"], "COMPLETED_EXPLORATORY")
        self.assertEqual(known_cert["rarity_context"]["reference_match_count"], cert_config["count"])
        self.assertEqual(unknown_cert["status"], "COMPLETED_EXPLORATORY")
        self.assertEqual(unknown_cert["rarity_context"]["reference_match_count"], 0)
        self.assertTrue(math.isfinite(unknown_cert["novelty_score"]))


if __name__ == "__main__":
    unittest.main()
