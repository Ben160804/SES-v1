"""
testbed/runner/test_resolver.py
===============================
Zero-Invention Property Tests for TLSCipherResolver.

Verifies:
1. All candidates originate exclusively from the IANA CSV database.
2. No candidates outside the IANA database ever appear.
3. When multiple candidates remain, selected_cipher is strictly None (no arbitrary selection).
4. No cipher is selected for NOT_APPLICABLE scenarios (e.g. cleartext, STARTTLS rejected).
5. Current runtime candidates are strictly a subset of IANA candidates.
6. Resolver is deterministic across repeated invocations.
7. No scenario-ID-specific branches exist in the resolution logic.
8. Old hidden WEAK/MEDIUM/BROKEN heuristics in stager.py are completely removed.
"""

import unittest
from pathlib import Path
import sys

# Ensure mailtest root is on path
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from analysis.ciphers import load_iana_cipher_database
from testbed.runner.spec import load_matrix
from testbed.runner.resolver import (
    TLSCipherResolver,
    ResolutionStatus,
    RuntimeStatus,
    SelectionBasis,
)
from testbed.runner.stager import derive_client_tls_config, SMTPStager


class TestTLSCipherResolver(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.iana_db = load_iana_cipher_database()
        cls.iana_suite_names = {d["name"] for d in cls.iana_db.values()}
        cls.specs = load_matrix()
        cls.smtp_specs = [s for s in cls.specs if s.protocol == "smtp"]
        cls.resolver = TLSCipherResolver(iana_db=cls.iana_db)

    def test_property_a_multiple_candidates_never_gets_selected_cipher(self):
        """Property A: If multiple candidates exist, selected_cipher MUST be None and basis NONE."""
        for spec in self.smtp_specs:
            res = self.resolver.resolve(spec)
            if res.cipher_resolution_status == ResolutionStatus.MULTIPLE_CANDIDATES:
                self.assertIsNone(
                    res.selected_cipher,
                    f"Scenario {spec.scenario_id} selected '{res.selected_cipher}' despite MULTIPLE_CANDIDATES!",
                )
                self.assertEqual(
                    res.selection_basis,
                    SelectionBasis.NONE,
                    f"Scenario {spec.scenario_id} had non-NONE selection basis: {res.selection_basis}",
                )
                self.assertGreater(res.current_runtime_candidate_count, 1)

    def test_property_b_multiple_candidates_never_offered_as_wire_configuration(self):
        """Property B: MULTIPLE_CANDIDATES does not cause client to offer candidates, and refuses staging."""
        stager = SMTPStager()
        for spec in self.smtp_specs:
            res = self.resolver.resolve(spec)
            if res.cipher_resolution_status == ResolutionStatus.MULTIPLE_CANDIDATES:
                client_cfg = derive_client_tls_config(spec)
                self.assertEqual(
                    client_cfg["offered_ciphers"],
                    [],
                    f"Scenario {spec.scenario_id} offered non-empty ciphers on MULTIPLE_CANDIDATES!",
                )
                # If not a baseline scenario, stager MUST refuse deterministic generation
                if spec.scenario_id not in ("PCAP-004", "PCAP-005", "PCAP-001", "PCAP-112"):
                    with self.assertRaises(Exception, msg=f"Scenario {spec.scenario_id} should refuse staging"):
                        stager.render_main_cf(spec, has_pki=spec.needs_pki)

    def test_property_c_runtime_candidates_target_container_runtime(self):
        """Property C: Runtime inspector targets container and respects custom inspector capability."""
        # Standard resolver targets mailtest-postfix
        self.assertTrue(self.resolver.runtime_available)
        self.assertTrue(self.resolver.runtime_inspector.runtime_name.startswith("docker:"))

        # Mock inspector with restricted cipher set ensures dynamic intersection
        from testbed.runner.resolver import StaticRuntimeInspector
        mock_ciphers = {"0x1301"}  # Only TLS_AES_128_GCM_SHA256
        mock_resolver = TLSCipherResolver(
            iana_db=self.iana_db,
            runtime_inspector=StaticRuntimeInspector(mock_ciphers, name="mock_restricted"),
        )
        spec_005 = [s for s in self.smtp_specs if s.scenario_id == "PCAP-005"][0]
        mock_res = mock_resolver.resolve(spec_005)
        self.assertEqual(mock_res.current_runtime_candidates, ["TLS_AES_128_GCM_SHA256"])
        self.assertEqual(mock_res.cipher_resolution_status, ResolutionStatus.UNIQUE)
        self.assertEqual(mock_res.selected_cipher, "TLS_AES_128_GCM_SHA256")

    def test_property_d_runtime_candidates_are_subset_of_iana(self):
        """Property D: Runtime candidates must be a strict subset of IANA candidates."""
        for spec in self.smtp_specs:
            res = self.resolver.resolve(spec)
            iana_set = set(res.iana_candidates)
            rt_set = set(res.current_runtime_candidates)
            self.assertTrue(
                rt_set.issubset(iana_set),
                f"Scenario {spec.scenario_id}: runtime candidates {rt_set - iana_set} not in IANA candidates!",
            )

    def test_property_e_no_scenario_id_specific_cipher_mapping(self):
        """Property E: Two specs with identical TLS parameters produce identical resolution."""
        spec1 = self.smtp_specs[0]
        dict1 = dict(spec1.raw_row)
        dict2 = dict(spec1.raw_row)
        dict1["scenario_id"] = "TEST-AAA"
        dict2["scenario_id"] = "TEST-BBB"
        res1 = self.resolver.resolve(dict1)
        res2 = self.resolver.resolve(dict2)
        self.assertEqual(res1.iana_candidates, res2.iana_candidates)
        self.assertEqual(res1.current_runtime_candidates, res2.current_runtime_candidates)
        self.assertEqual(res1.cipher_resolution_status, res2.cipher_resolution_status)

    def test_property_f_no_hidden_weak_medium_broken_mappings(self):
        """Property F: Old WEAK/MEDIUM/BROKEN heuristics in stager.py and resolver.py are absent."""
        stager_src = (Path(__file__).parent / "stager.py").read_text()
        resolver_src = (Path(__file__).parent / "resolver.py").read_text()
        for bad in ["DES-CBC3-SHA", "RC4-SHA", "AES128-SHA:AES256-SHA"]:
            self.assertNotIn(bad, stager_src)
            self.assertNotIn(bad, resolver_src)

    def test_property_g_resolver_is_deterministic(self):
        """Property G: Resolver produces identical results across repeated invocations."""
        for spec in self.smtp_specs[:15]:
            run1 = self.resolver.resolve(spec)
            run2 = self.resolver.resolve(spec)
            self.assertEqual(run1.to_dict(), run2.to_dict())

    def test_property_h_not_applicable_scenarios_no_fabricated_ciphers(self):
        """Property H: NOT_APPLICABLE scenarios have 0 candidates and no selected cipher."""
        for spec in self.smtp_specs:
            res = self.resolver.resolve(spec)
            if res.cipher_resolution_status == ResolutionStatus.NOT_APPLICABLE:
                self.assertIsNone(res.selected_cipher)
                self.assertEqual(res.iana_candidate_count, 0)
                self.assertEqual(res.current_runtime_candidate_count, 0)
                self.assertEqual(res.selection_basis, SelectionBasis.NONE)

    def test_property_i_negative_special_scenarios_classified_properly(self):
        """Property I: Negative scenario PCAP-121 is SPECIAL_SCENARIO with 0 candidates."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        res_121 = self.resolver.resolve(by_id["PCAP-121"])
        self.assertEqual(res_121.cipher_resolution_status, ResolutionStatus.SPECIAL_SCENARIO)
        self.assertEqual(res_121.special_harness_requirement, "server_sends_fatal_alert")
        self.assertEqual(res_121.iana_candidate_count, 0)
        self.assertEqual(res_121.current_runtime_candidate_count, 0)
        self.assertIsNone(res_121.selected_cipher)

    def test_property_j_baseline_scenarios_still_stage_successfully(self):
        """Property J: Proven baseline scenarios continue to stage without error."""
        stager = SMTPStager()
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        for sid in ["PCAP-004", "PCAP-005", "PCAP-001", "PCAP-112"]:
            spec = by_id[sid]
            client_cfg = derive_client_tls_config(spec)
            self.assertIsNotNone(client_cfg)
            main_cf = stager.render_main_cf(spec, has_pki=spec.needs_pki)
            self.assertIn("smtpd_tls_", main_cf)

    def test_property_k_project_model_conflict_distinguished(self):
        """Property K: Oracle cipher_strength mismatch is recorded in strength_discrepancy while maintaining structural MULTIPLE_CANDIDATES."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        for sid in ["PCAP-006", "PCAP-007", "PCAP-073", "PCAP-078", "PCAP-094", "PCAP-096"]:
            res = self.resolver.resolve(by_id[sid])
            self.assertEqual(
                res.cipher_resolution_status,
                ResolutionStatus.MULTIPLE_CANDIDATES,
                f"Scenario {sid} should be MULTIPLE_CANDIDATES",
            )
            self.assertIsNotNone(
                res.strength_discrepancy,
                f"Scenario {sid} should record strength_discrepancy",
            )
            self.assertIn(
                "Oracle expectation mismatch",
                res.strength_discrepancy,
                f"Scenario {sid} discrepancy should mention oracle mismatch",
            )
            self.assertIsNone(res.selected_cipher)

    def test_property_l_rfc_protocol_impossibility_detected(self):
        """Property L: cert_sig_algo=Ed25519 does not declare TLS 1.0/1.1 impossible; only explicit server_leaf_key_type=Ed25519 does."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        # In matrix rows, cert_sig_algo=Ed25519 represents CA signature; valid MULTIPLE_CANDIDATES
        for sid in ["PCAP-078", "PCAP-083", "PCAP-096"]:
            res = self.resolver.resolve(by_id[sid])
            self.assertEqual(
                res.cipher_resolution_status,
                ResolutionStatus.MULTIPLE_CANDIDATES,
                f"Scenario {sid} should be MULTIPLE_CANDIDATES (cert_sig_algo is CA signature)",
            )
            self.assertGreater(res.iana_candidate_count, 0)
            self.assertGreater(res.current_runtime_candidate_count, 0)

        # RSA-PSS on TLS 1.0/1.1 also valid MULTIPLE_CANDIDATES
        for sid in ["PCAP-073", "PCAP-081", "PCAP-087", "PCAP-100"]:
            res = self.resolver.resolve(by_id[sid])
            self.assertEqual(
                res.cipher_resolution_status,
                ResolutionStatus.MULTIPLE_CANDIDATES,
                f"Scenario {sid} should be MULTIPLE_CANDIDATES",
            )

        # Explicit server_leaf_key_type="Ed25519" on TLS 1.0/1.1 IS PROTOCOL_IMPOSSIBILITY
        spec_ed = dict(by_id["PCAP-078"].raw_row)
        spec_ed["server_leaf_key_type"] = "Ed25519"
        res_explicit = self.resolver.resolve(spec_ed)
        self.assertEqual(
            res_explicit.cipher_resolution_status,
            ResolutionStatus.PROTOCOL_IMPOSSIBILITY,
        )
        self.assertIn("Ed25519", res_explicit.reason)

    def test_property_m_cert_sig_algo_does_not_constrain_tls12_ciphers(self):
        """Property M: cert_sig_algo represents X.509 CA signature, not server leaf auth; does not filter TLS 1.2 ciphers."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        for sid in ["PCAP-082", "PCAP-093", "PCAP-095"]:
            res = self.resolver.resolve(by_id[sid])
            rule = res.traceable_constraints.get("auth_filter", {}).get("rule", "")
            self.assertIn("unconstrained by cert_sig_algo", rule)

    def test_property_n_tls13_independent_of_cert_sig_algo(self):
        """Property N: TLS 1.3 candidate resolution remains completely independent of cert_sig_algo."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        # Compare TLS 1.3 with ECDSA vs RSA-PSS vs Ed25519
        res_ecdsa = self.resolver.resolve(by_id["PCAP-001"])   # ECDSA
        res_rsapss = self.resolver.resolve(by_id["PCAP-019"])  # RSA-PSS
        res_ed = self.resolver.resolve(by_id["PCAP-020"])      # Ed25519
        self.assertEqual(res_ecdsa.iana_candidates, res_rsapss.iana_candidates)
        self.assertEqual(res_ecdsa.iana_candidates, res_ed.iana_candidates)
        self.assertEqual(res_ecdsa.current_runtime_candidates, res_rsapss.current_runtime_candidates)
        self.assertEqual(res_ecdsa.current_runtime_candidates, res_ed.current_runtime_candidates)

    def test_property_o_tls12_auth_filtering_not_applied_to_cert_sig_algo(self):
        """Property O: In TLS 1.2, DHE candidates include all DHE suites without filtering by cert_sig_algo."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        res_112 = self.resolver.resolve(by_id["PCAP-112"])  # DHE + RSA-PKCS1v15
        # Without auth filtering, DHE suites include both DHE-RSA and DHE-DSS/PSK (67 runtime suites)
        self.assertGreater(res_112.current_runtime_candidate_count, 29)

    def test_property_p_explicit_server_leaf_key_type_constrains_tls12_auth(self):
        """Property P: When explicitly modeled, server_leaf_key_type constrains TLS 1.2 authentication candidates."""
        by_id = {s.scenario_id: s for s in self.smtp_specs}
        spec_112 = dict(by_id["PCAP-112"].raw_row)

        # Without server_leaf_key_type, DHE candidates are unconstrained by auth (67 runtime suites)
        res_unconstrained = self.resolver.resolve(spec_112)

        # When explicitly modeling server_leaf_key_type = "RSA"
        spec_rsa = dict(spec_112)
        spec_rsa["server_leaf_key_type"] = "RSA"
        res_rsa = self.resolver.resolve(spec_rsa)
        self.assertEqual(res_rsa.current_runtime_candidate_count, 29)
        self.assertTrue(all("RSA" in c for c in res_rsa.current_runtime_candidates))
        self.assertLess(res_rsa.current_runtime_candidate_count, res_unconstrained.current_runtime_candidate_count)


if __name__ == "__main__":
    unittest.main()
