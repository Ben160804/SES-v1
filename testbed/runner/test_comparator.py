"""
testbed/runner/test_comparator.py
================================
Unit tests for deterministic comparison engine (comparator.py).

Covers the 4 Critical Invariants:
  1. 100% Assertion Coverage (uncovered assertions trigger FAIL)
  2. Fatal-alert scenarios never PASS unnegotiated TLS properties
  3. cert_sig_algo comparison evaluates signature metadata ONLY, never public_key_algorithm
  4. Ambiguous multi-session selection rejects silent arbitrary choice
"""

import json
from pathlib import Path
import unittest
import jsonschema

from testbed.runner.comparator import compare, select_evaluated_session, compare_sig_algo

_project_root = Path(__file__).resolve().parent.parent.parent


class TestComparator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema_path = _project_root / "data" / "comparison_schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)

    def _validate(self, result: dict):
        jsonschema.validate(instance=result, schema=self.schema)

    def test_01_observable_exact_match_pass(self):
        """All observable fields match wire facts exactly -> PASS."""
        expected = {
            "scenario_id": "PCAP-901",
            "expected": {
                "protocol": "SMTP",
                "tls_presence": "STARTTLS-upgraded",
                "tls_version": "1.2",
                "cipher_strength": "strong",
            },
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "starttls_status": {"expected": "UPGRADED", "required": True, "observability": "always"},
                "tls_presence": {"expected": "STARTTLS-upgraded", "required": True, "observability": "always"},
                "tls.version": {"expected": "TLS 1.2", "required": True, "observability": "always"},
                "tls.cipher_strength": {"expected": "strong", "required": True, "observability": "always"},
                "certificate.observable": {"expected": "VISIBLE", "required": True, "observability": "always"},
                "certificate.signature_algorithm": {"expected": "RSA-PKCS1v15", "required": True, "observability": "always"},
                "certificate.validity": {"expected": "valid", "required": True, "observability": "always"},
                "certificate.hostname_match": {"expected": "matched", "required": True, "observability": "always"},
                "certificate.trust_status": {"expected": "TRUSTED_CA", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-901",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "starttls": {"status": "UPGRADED"},
                    "tls": {
                        "tls_version": "TLS 1.2",
                        "cipher_strength": "strong",
                        "cipher_name": "ECDHE-RSA-AES256-GCM-SHA384"
                    },
                    "certificate": {
                        "hostname_match": "matched",
                        "trust_status": "TRUSTED_CA",
                        "leaf_cert": {
                            "signature_algorithm_parameters": "PKCS1v15",
                            "signature_algorithm_name": "sha256WithRSAEncryption",
                            "is_expired": False,
                            "not_yet_valid": False,
                        }
                    }
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(len(res["mismatches"]), 0)
        self.assertEqual(len(res["unknowns"]), 0)
        self.assertEqual(res["evaluated_stream"], 0)

    def test_02_observable_mismatch_fail(self):
        """Observed TLS version differs from expected -> FAIL."""
        expected = {
            "scenario_id": "PCAP-902",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "tls.version": {"expected": "TLS 1.3", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-902",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "tls": {"tls_version": "TLS 1.2"}
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any(m["field"] == "tls.version" for m in res["mismatches"]))

    def test_03_tls13_unobservable_cert_inconclusive(self):
        """TLS 1.3 handshake encrypts certificate, other observable fields match -> INCONCLUSIVE."""
        expected = {
            "scenario_id": "PCAP-005",
            "expected": {
                "protocol": "SMTP",
                "tls_presence": "STARTTLS-upgraded",
                "tls_version": "1.3",
            },
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "starttls_status": {"expected": "UPGRADED", "required": True, "observability": "always"},
                "tls_presence": {"expected": "STARTTLS-upgraded", "required": True, "observability": "always"},
                "tls.version": {"expected": "TLS 1.3", "required": True, "observability": "always"},
                "certificate.observable": {"expected": "ENCRYPTED", "required": True, "observability": "always"},
                "certificate.signature_algorithm": {"expected": "ECDSA", "required": True, "observability": "conditional"},
                "certificate.validity": {"expected": "valid", "required": True, "observability": "conditional"},
                "certificate.hostname_match": {"expected": "matched", "required": True, "observability": "conditional"},
                "certificate.trust_status": {"expected": "TRUSTED_CA", "required": True, "observability": "conditional"},
            }
        }
        observed = {
            "scenario_id": "PCAP-005",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "starttls": {"status": "UPGRADED"},
                    "tls": {"tls_version": "TLS 1.3", "cipher_strength": "strong"},
                    "certificate": None
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "INCONCLUSIVE")
        self.assertEqual(len(res["mismatches"]), 0)
        self.assertIn("certificate.signature_algorithm", res["unknowns"])
        self.assertEqual(res["fields"]["certificate.signature_algorithm"]["status"], "UNOBSERVABLE")

    def test_04_unobservable_plus_mismatch_fail(self):
        """Unobservable certificate + an observable mismatch -> FAIL (mismatch dominates)."""
        expected = {
            "scenario_id": "PCAP-904",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "tls.version": {"expected": "TLS 1.3", "required": True, "observability": "always"},
                "tls.cipher_strength": {"expected": "strong", "required": True, "observability": "always"},
                "certificate.signature_algorithm": {"expected": "ECDSA", "required": True, "observability": "conditional"},
            }
        }
        observed = {
            "scenario_id": "PCAP-904",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "tls": {"tls_version": "TLS 1.3", "cipher_strength": "weak"},
                    "certificate": None
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any(m["field"] == "tls.cipher_strength" for m in res["mismatches"]))
        self.assertIn("certificate.signature_algorithm", res["unknowns"])

    def test_05_cipher_strength_mismatch(self):
        """Cipher strength differs from expected -> FAIL."""
        expected = {
            "scenario_id": "PCAP-905",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "tls.cipher_strength": {"expected": "strong", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-905",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "tls": {"cipher_strength": "export"}
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")

    def test_06_visible_certificate_match(self):
        """Visible certificate matches expected -> PASS."""
        expected = {
            "scenario_id": "PCAP-906",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "certificate.observable": {"expected": "VISIBLE", "required": True, "observability": "always"},
                "certificate.hostname_match": {"expected": "matched", "required": True, "observability": "always"},
                "certificate.validity": {"expected": "valid", "required": True, "observability": "always"},
                "certificate.trust_status": {"expected": "TRUSTED_CA", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-906",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "certificate": {
                        "hostname_match": "matched",
                        "trust_status": "TRUSTED_CA",
                        "leaf_cert": {"is_expired": False, "not_yet_valid": False}
                    }
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "PASS")

    def test_07_visible_certificate_hostname_mismatch(self):
        """Visible certificate has mismatched hostname -> FAIL."""
        expected = {
            "scenario_id": "PCAP-907",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "certificate.observable": {"expected": "VISIBLE", "required": True, "observability": "always"},
                "certificate.hostname_match": {"expected": "matched", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-907",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "certificate": {
                        "hostname_match": "mismatched",
                        "leaf_cert": {}
                    }
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any(m["field"] == "certificate.hostname_match" for m in res["mismatches"]))

    def test_08_rfc5280_sig_algo_uses_only_signature_metadata(self):
        """RFC 5280: cert_sig_algo MUST use signature metadata, never public_key_algorithm."""
        # 1. Matching signature algorithm name
        self.assertTrue(compare_sig_algo("ECDSA", {"signature_algorithm_name": "ecdsa-with-SHA256"}))
        self.assertTrue(compare_sig_algo("RSA-PSS", {"signature_algorithm_parameters": "PSS"}))
        self.assertTrue(compare_sig_algo("RSA-PKCS1V15", {"signature_algorithm_name": "sha256WithRSAEncryption"}))
        self.assertTrue(compare_sig_algo("ED25519", {"signature_algorithm_name": "Ed25519"}))

        # 2. Strict rejection of public_key_algorithm leakage:
        # A cert with public_key_algorithm="rsaEncryption" but NO signature metadata MUST NOT match
        self.assertFalse(compare_sig_algo("RSA-PKCS1V15", {"public_key_algorithm": "rsaEncryption"}))
        self.assertFalse(compare_sig_algo("ECDSA", {"public_key_algorithm": "ecPublicKey"}))

    def test_09_fatal_alert_never_passes_unnegotiated_properties(self):
        """In fatal alert scenario, tls.fatal_alert PASSes, unnegotiated TLS parameters are NOT_APPLICABLE (never PASS)."""
        expected = {
            "scenario_id": "PCAP-121",
            "expected": {
                "protocol": "SMTP",
                "tls_presence": "implicit-TLS",
                "generator_requirement": "server_sends_fatal_alert"
            },
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "tls_presence": {"expected": "implicit-TLS", "required": True, "observability": "always"},
                "tls.fatal_alert": {"expected": True, "required": True, "observability": "always"},
                "tls.version": {"expected": None, "required": False, "observability": "not_applicable"},
                "tls.cipher_strength": {"expected": None, "required": False, "observability": "not_applicable"},
                "certificate.observable": {"expected": "NOT_PRESENT", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-121",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "starttls": {"status": "IMPLICIT_TLS"},
                    "handshake": {
                        "flight": {
                            "alerts": [{"level": "FATAL", "description": "handshake_failure"}]
                        },
                        "forensic_analysis": {"handshake_status": "ABORTED"}
                    },
                    "tls": {},
                    "certificate": None
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "PASS")

        # Prove unnegotiated properties are NOT_APPLICABLE and NOT marked PASS
        self.assertEqual(res["fields"]["tls.fatal_alert"]["status"], "PASS")
        self.assertEqual(res["fields"]["tls.version"]["status"], "NOT_APPLICABLE")
        self.assertEqual(res["fields"]["tls.cipher_strength"]["status"], "NOT_APPLICABLE")
        self.assertEqual(res["fields"]["certificate.observable"]["status"], "PASS")
        self.assertEqual(res["fields"]["certificate.observable"]["observed"], "NOT_PRESENT")

    def test_10_cleartext_no_encryption_pass(self):
        """Cleartext scenario with no TLS expected and none observed -> PASS."""
        expected = {
            "scenario_id": "PCAP-910",
            "expected": {
                "protocol": "SMTP",
                "tls_presence": "none",
            },
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "starttls_status": {"expected": "CLEARTEXT_NO_ENCRYPTION", "required": True, "observability": "always"},
                "tls_presence": {"expected": "none", "required": True, "observability": "always"},
                "tls.version": {"expected": None, "required": False, "observability": "not_applicable"},
                "certificate.observable": {"expected": "NOT_PRESENT", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-910",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "starttls": {"status": "CLEARTEXT_NO_ENCRYPTION"},
                    "tls": {},
                    "certificate": None
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "PASS")

    def test_11_cleartext_unexpected_tls_fail(self):
        """Cleartext scenario where unexpected TLS was observed -> FAIL."""
        expected = {
            "scenario_id": "PCAP-911",
            "expected": {
                "protocol": "SMTP",
                "tls_presence": "none",
            },
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "tls_presence": {"expected": "none", "required": True, "observability": "always"},
                "tls.version": {"expected": None, "required": False, "observability": "not_applicable"},
            }
        }
        observed = {
            "scenario_id": "PCAP-911",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "starttls": {"status": "UPGRADED"},
                    "tls": {"tls_version": "TLS 1.3"},
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")

    def test_12_stream_selection_mail_priority(self):
        """Selects stream 1 (the mail stream) over stream 0 (syn scan / unknown traffic)."""
        sessions = {
            "0": {"protocol": "UNKNOWN"},
            "1": {
                "protocol": "SMTP",
                "starttls": {"status": "UPGRADED"},
                "tls": {"tls_version": "TLS 1.3"}
            }
        }
        best_id, best_session, err = select_evaluated_session("SMTP", sessions)
        self.assertIsNone(err)
        self.assertEqual(best_id, 1)
        self.assertEqual(best_session["protocol"], "SMTP")

    def test_13_ambiguous_multi_session_selection_inconclusive(self):
        """Ambiguous competing sessions tied for top score must resolve to INCONCLUSIVE (not FAIL, not PASS)."""
        sessions = {
            "5": {"protocol": "SMTP", "tls": {"tls_version": "TLS 1.2"}},
            "2": {"protocol": "SMTP", "tls": {"tls_version": "TLS 1.2"}}
        }
        best_id, best_session, err = select_evaluated_session("SMTP", sessions)
        self.assertIsNone(best_id)
        self.assertIsNone(best_session)
        self.assertIn("AMBIGUOUS_STREAM_SELECTION", err)

        # Full compare integration: must be INCONCLUSIVE and report ambiguity
        expected = {
            "scenario_id": "PCAP-913",
            "expected": {"protocol": "SMTP"},
            "assertions": {"protocol": {"expected": "SMTP", "required": True}}
        }
        observed = {"scenario_id": "PCAP-913", "sessions": sessions}
        comp = compare(expected, observed)
        self._validate(comp)
        self.assertEqual(comp["status"], "INCONCLUSIVE")
        self.assertEqual(len(comp["mismatches"]), 0)
        self.assertIn("evaluated_stream", comp["unknowns"])
        self.assertIsNone(comp["evaluated_stream"])
        self.assertIn("AMBIGUOUS_STREAM_SELECTION", comp["fields"]["protocol"]["reason"])

    def test_14_missing_session_fail(self):
        """Empty sessions dictionary -> FAIL."""
        expected = {
            "scenario_id": "PCAP-914",
            "expected": {"protocol": "SMTP"},
            "assertions": {"protocol": {"expected": "SMTP", "required": True}}
        }
        observed = {"scenario_id": "PCAP-914", "sessions": {}}
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")
        self.assertIsNone(res["evaluated_stream"])

    def test_15_100_percent_assertion_coverage_enforcement(self):
        """Any unhandled assertion key in expected['assertions'] triggers FAIL."""
        expected = {
            "scenario_id": "PCAP-915",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True, "observability": "always"},
                "custom_unimplemented_assertion": {"expected": "something", "required": True, "observability": "always"},
            }
        }
        observed = {
            "scenario_id": "PCAP-915",
            "sessions": {
                "0": {"protocol": "SMTP"}
            }
        }
        res = compare(expected, observed)
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any(m["field"] == "custom_unimplemented_assertion" for m in res["mismatches"]))

    def test_16_regression_ambiguous_session_exact_status(self):
        """Regression test verifying ambiguous multi-session verification status is strictly INCONCLUSIVE."""
        expected = {
            "scenario_id": "PCAP-916",
            "expected": {"protocol": "IMAP"},
            "assertions": {"protocol": {"expected": "IMAP", "required": True}}
        }
        # Two competing IMAP sessions with identical telemetry
        observed = {
            "scenario_id": "PCAP-916",
            "sessions": {
                "0": {"protocol": "IMAP", "tls": {"tls_version": "TLS 1.3"}},
                "1": {"protocol": "IMAP", "tls": {"tls_version": "TLS 1.3"}},
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "INCONCLUSIVE", "Ambiguous session verification must be INCONCLUSIVE")
        self.assertEqual(res["mismatches"], [])
        self.assertEqual(res["unknowns"], ["evaluated_stream"])
        self.assertEqual(res["fields"]["protocol"]["status"], "UNOBSERVABLE")

    def test_17_exact_cipher_match_pass(self):
        """Matching exact negotiated cipher passes verification."""
        expected = {
            "scenario_id": "PCAP-917",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True},
                "tls.version": {"expected": "TLS 1.3", "required": True},
                "certificate.observable": {"expected": "ENCRYPTED", "required": True},
                "tls.cipher_name": {"expected": "TLS_AES_256_GCM_SHA384", "required": True},
            }
        }
        observed = {
            "scenario_id": "PCAP-917",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "tls": {
                        "tls_version": "TLS 1.3",
                        "cipher_name": "TLS_AES_256_GCM_SHA384",
                        "cipher_strength": "HIGH",
                    }
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["fields"]["tls.cipher_name"]["status"], "PASS")

    def test_18_exact_cipher_mismatch_fails_even_if_same_strength(self):
        """Exact cipher mismatch yields FAIL even if within same security strength class."""
        expected = {
            "scenario_id": "PCAP-918",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True},
                "tls.version": {"expected": "TLS 1.3", "required": True},
                "certificate.observable": {"expected": "ENCRYPTED", "required": True},
                "tls.cipher_strength": {"expected": "HIGH", "required": True},
                "tls.cipher_name": {"expected": "TLS_AES_256_GCM_SHA384", "required": True},
            }
        }
        # Both are HIGH ciphers, but cipher_name does not match
        observed = {
            "scenario_id": "PCAP-918",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "tls": {
                        "tls_version": "TLS 1.3",
                        "cipher_name": "TLS_CHACHA20_POLY1305_SHA256",
                        "cipher_strength": "HIGH",
                    }
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["fields"]["tls.cipher_strength"]["status"], "PASS")
        self.assertEqual(res["fields"]["tls.cipher_name"]["status"], "FAIL")
        self.assertTrue(any(m["field"] == "tls.cipher_name" for m in res["mismatches"]))

    def test_19_exact_cipher_fatal_alert_not_applicable(self):
        """Fatal alert scenario marks unnegotiated cipher_name as NOT_APPLICABLE."""
        expected = {
            "scenario_id": "PCAP-919",
            "expected": {"protocol": "SMTP"},
            "assertions": {
                "protocol": {"expected": "SMTP", "required": True},
                "tls.fatal_alert": {"expected": True, "required": True},
                "tls.cipher_name": {"expected": "TLS_AES_256_GCM_SHA384", "required": False},
            }
        }
        observed = {
            "scenario_id": "PCAP-919",
            "sessions": {
                "0": {
                    "protocol": "SMTP",
                    "handshake": {
                        "flight": {
                            "alerts": [{"level": "FATAL", "description": "handshake_failure"}]
                        }
                    },
                    "tls": {
                        "cipher_name": None,
                        "cipher_strength": None,
                    }
                }
            }
        }
        res = compare(expected, observed)
        self._validate(res)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["fields"]["tls.fatal_alert"]["status"], "PASS")
        self.assertEqual(res["fields"]["tls.cipher_name"]["status"], "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
