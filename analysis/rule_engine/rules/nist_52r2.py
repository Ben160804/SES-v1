"""
NIST SP 800-52 Rev. 2 Policy Pack (NIST-52R2).

Implements 24 normative rule evaluation functions grounded strictly in
NIST SP 800-52 Rev. 2 specifications and normative cipher lists.
"""

from typing import Optional
from ..schema import RuleInput, PolicyResult, EvidenceItem
from ..policy.nist_loader import (
    NIST_SEC_3311_TLS12_CIPHERS,
    NIST_SEC_3312_TLS13_CIPHERS,
    NIST_APP_C_PSK_CIPHERS,
    NIST_APP_D_RSA_CIPHERS,
    NIST_APPROVED_CURVES,
)
from ..input_builder import check_lifespan_3_calendar_years


class NIST52r2Evaluator:
    """Evaluates RuleInput against NIST SP 800-52 Rev. 2."""

    def __init__(self, mode: str = "gov_only"):
        """
        mode: 'gov_only' (Federal agencies) or 'citizen_facing' (Public/citizen endpoints).
        """
        self.mode = mode

    def evaluate_all(self, r_in: RuleInput) -> list[PolicyResult]:
        """Runs all 24 NIST SP 800-52r2 rules against the input."""
        results: list[PolicyResult] = [
            self.eval_n52_tls_01(r_in),
            self.eval_n52_tls_02(r_in),
            self.eval_n52_tls_03(r_in),
            self.eval_n52_cipher_01(r_in),
            self.eval_n52_cipher_02(r_in),
            self.eval_n52_cipher_03(r_in),
            self.eval_n52_cipher_04(r_in),
            self.eval_n52_cipher_05(r_in),
            self.eval_n52_cipher_06(r_in),
            self.eval_n52_cipher_07(r_in),
            self.eval_n52_kex_01(r_in),
            self.eval_n52_psk_01(r_in),
            self.eval_n52_psk_02(r_in),
            self.eval_n52_psk_03(r_in),
            self.eval_n52_cert_01(r_in),
            self.eval_n52_cert_02(r_in),
            self.eval_n52_cert_03(r_in),
            self.eval_n52_cert_04(r_in),
            self.eval_n52_cert_05(r_in),
            self.eval_n52_cert_06(r_in),
            self.eval_n52_cert_08(r_in),
            self.eval_n52_cert_09(r_in),
            self.eval_n52_cert_10(r_in),
            self.eval_n52_client_hostname_01(r_in),
            self.eval_n52_proto_01(r_in),
        ]
        return results

    def eval_n52_tls_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        tls_ver = r_in.get("tls_version")
        ev = [EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version")]

        if tls_ver is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-TLS-01",
                name="TLS 1.0 Disallowance",
                source_id="SP800-52R2-S07",
                source_section="3.1",
                source_text="Servers shall not be configured to use TLS 1.0 (Gov-Only); Servers may be configured to use TLS 1.0 (Citizen-Facing).",
                normative_term="SHALL NOT" if self.mode == "gov_only" else "MAY",
                applicability_scope="NIST-GOV-ONLY" if self.mode == "gov_only" else "NIST-CITIZEN-FACING",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No TLS session negotiated on stream.",
            )

        if tls_ver == "TLS 1.0":
            if self.mode == "gov_only":
                return PolicyResult(
                    policy="NIST-52R2",
                    rule_id="N52-TLS-01",
                    name="TLS 1.0 Disallowance",
                    source_id="SP800-52R2-S07",
                    source_section="3.1",
                    source_text="Servers shall not be configured to use TLS 1.0 for government-only applications.",
                    normative_term="SHALL NOT",
                    applicability_scope="NIST-GOV-ONLY",
                    verdict="FAIL",
                    evidence=ev,
                    finding="TLS 1.0 was negotiated in violation of NIST SP 800-52 §3.1 government-only mandate.",
                )
            else:
                return PolicyResult(
                    policy="NIST-52R2",
                    rule_id="N52-TLS-01",
                    name="TLS 1.0 Disallowance",
                    source_id="SP800-52R2-S08",
                    source_section="3.1",
                    source_text="Servers may be configured to use TLS 1.0 for citizen-facing applications.",
                    normative_term="MAY",
                    applicability_scope="NIST-CITIZEN-FACING",
                    verdict="OBSERVATION",
                    evidence=ev,
                    finding="TLS 1.0 was negotiated (permissible under citizen-facing exception).",
                )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-TLS-01",
            name="TLS 1.0 Disallowance",
            source_id="SP800-52R2-S07",
            source_section="3.1",
            source_text="Servers shall not be configured to use TLS 1.0.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY" if self.mode == "gov_only" else "NIST-CITIZEN-FACING",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_tls_02(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        tls_ver = r_in.get("tls_version")
        ev = [EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version")]

        if tls_ver is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-TLS-02",
                name="TLS 1.1 Deprecation",
                source_id="SP800-52R2-S07",
                source_section="3.1",
                source_text="Servers should not be configured to use TLS 1.1.",
                normative_term="SHOULD NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if tls_ver == "TLS 1.1":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-TLS-02",
                name="TLS 1.1 Deprecation",
                source_id="SP800-52R2-S07",
                source_section="3.1",
                source_text="Servers should not be configured to use TLS 1.1.",
                normative_term="SHOULD NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="OBSERVATION",
                evidence=ev,
                finding="TLS 1.1 was negotiated; NIST SP 800-52 §3.1 recommends against TLS 1.1.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-TLS-02",
            name="TLS 1.1 Deprecation",
            source_id="SP800-52R2-S07",
            source_section="3.1",
            source_text="Servers should not be configured to use TLS 1.1.",
            normative_term="SHOULD NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_tls_03(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        tls_ver = r_in.get("tls_version")
        client_vers = r_in.get("client_offered_versions") or []
        ev = [
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
            EvidenceItem(sid, "client_offered_versions", client_vers, "ClientHello -> Supported Versions"),
        ]

        if tls_ver is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-TLS-03",
                name="TLS 1.3 Server Support",
                source_id="SP800-52R2-S10",
                source_section="3.1",
                source_text="Servers shall be configured to support TLS 1.3.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if "TLS 1.3" in client_vers and tls_ver in {"TLS 1.0", "TLS 1.1", "TLS 1.2"}:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-TLS-03",
                name="TLS 1.3 Server Support",
                source_id="SP800-52R2-S10",
                source_section="3.1",
                source_text="Servers shall be configured to support TLS 1.3.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="OBSERVATION",
                evidence=ev,
                finding="Client offered TLS 1.3, but server negotiated lower protocol version. Single session does not prove lack of capability.",
            )

        if tls_ver == "TLS 1.3":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-TLS-03",
                name="TLS 1.3 Server Support",
                source_id="SP800-52R2-S10",
                source_section="3.1",
                source_text="Servers shall be configured to support TLS 1.3.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="PASS",
                evidence=ev,
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-TLS-03",
            name="TLS 1.3 Server Support",
            source_id="SP800-52R2-S10",
            source_section="3.1",
            source_text="Servers shall be configured to support TLS 1.3.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="NOT_APPLICABLE",
            evidence=ev,
            finding="Client did not offer TLS 1.3; server capability unobservable.",
        )

    def eval_n52_cipher_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-01",
                name="Null Cipher Disallowance",
                source_id="SP800-52R2-S34",
                source_section="3.3.1",
                source_text="The server shall not be configured to use NULL cipher suites.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if "NULL" in c_name.upper():
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-01",
                name="Null Cipher Disallowance",
                source_id="SP800-52R2-S34",
                source_section="3.3.1",
                source_text="The server shall not be configured to use NULL cipher suites.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"NULL cipher suite negotiated: {c_name}.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-01",
            name="Null Cipher Disallowance",
            source_id="SP800-52R2-S34",
            source_section="3.3.1",
            source_text="The server shall not be configured to use NULL cipher suites.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cipher_02(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-02",
                name="3DES Cipher Disallowance",
                source_id="SP800-52R2-S36",
                source_section="3.3.1.1",
                source_text="Cipher suites using 3DES are no longer allowed.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        c_upper = c_name.upper()
        if "3DES" in c_upper or "DES_EDE" in c_upper:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-02",
                name="3DES Cipher Disallowance",
                source_id="SP800-52R2-S36",
                source_section="3.3.1.1",
                source_text="Cipher suites using 3DES are no longer allowed.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"Disallowed 3DES cipher suite negotiated: {c_name}.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-02",
            name="3DES Cipher Disallowance",
            source_id="SP800-52R2-S36",
            source_section="3.3.1.1",
            source_text="Cipher suites using 3DES are no longer allowed.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cipher_03(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-03",
                name="Export Cipher Disallowance",
                source_id="SP800-52R2-S34",
                source_section="3.3.1",
                source_text="The server shall not be configured to use EXPORT cipher suites.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if "EXPORT" in c_name.upper():
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-03",
                name="Export Cipher Disallowance",
                source_id="SP800-52R2-S34",
                source_section="3.3.1",
                source_text="The server shall not be configured to use EXPORT cipher suites.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"Disallowed EXPORT cipher suite negotiated: {c_name}.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-03",
            name="Export Cipher Disallowance",
            source_id="SP800-52R2-S34",
            source_section="3.3.1",
            source_text="The server shall not be configured to use EXPORT cipher suites.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cipher_04(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-04",
                name="Anonymous Cipher Disallowance",
                source_id="SP800-52R2-S34",
                source_section="3.3.1",
                source_text="The server shall not be configured to use anonymous cipher suites.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        c_upper = c_name.upper()
        if "ANON" in c_upper or "A_NULL" in c_upper or "_ANON_" in c_upper:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-04",
                name="Anonymous Cipher Disallowance",
                source_id="SP800-52R2-S34",
                source_section="3.3.1",
                source_text="The server shall not be configured to use anonymous cipher suites.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"Disallowed anonymous cipher suite negotiated: {c_name}.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-04",
            name="Anonymous Cipher Disallowance",
            source_id="SP800-52R2-S34",
            source_section="3.3.1",
            source_text="The server shall not be configured to use anonymous cipher suites.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cipher_05(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        tls_ver = r_in.get("tls_version")
        c_name = r_in.get("cipher_name")
        ev = [
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
            EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher"),
        ]

        if tls_ver != "TLS 1.3":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-05",
                name="NIST Approved TLS 1.3 Cipher Suites",
                source_id="SP800-52R2-S38",
                source_section="3.3.1.2",
                source_text="Servers configured to use TLS 1.3 shall support the four cipher suites in Section 3.3.1.2.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="Session is not TLS 1.3.",
            )

        if not c_name or c_name not in NIST_SEC_3312_TLS13_CIPHERS:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-05",
                name="NIST Approved TLS 1.3 Cipher Suites",
                source_id="SP800-52R2-S38",
                source_section="3.3.1.2",
                source_text="Servers configured to use TLS 1.3 shall support the four cipher suites in Section 3.3.1.2.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"TLS 1.3 cipher suite '{c_name}' is not one of the four approved suites in Section 3.3.1.2.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-05",
            name="NIST Approved TLS 1.3 Cipher Suites",
            source_id="SP800-52R2-S38",
            source_section="3.3.1.2",
            source_text="Servers configured to use TLS 1.3 shall support the four cipher suites in Section 3.3.1.2.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cipher_06(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name or not c_name.startswith("TLS_RSA_"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-06",
                name="Static RSA Key Transport Restrictions",
                source_id="SP800-52R2-S114",
                source_section="Appendix D",
                source_text="Transitional static RSA cipher suites may be used under restricted conditions.",
                normative_term="MAY",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="Static RSA key transport cipher not negotiated.",
            )

        if c_name in NIST_APP_D_RSA_CIPHERS:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-06",
                name="Static RSA Key Transport Restrictions",
                source_id="SP800-52R2-S114",
                source_section="Appendix D",
                source_text="Transitional static RSA cipher suites may be used under restricted conditions.",
                normative_term="MAY",
                applicability_scope="NIST-GOV-ONLY",
                verdict="OBSERVATION",
                evidence=ev,
                finding=f"Transitional static RSA cipher '{c_name}' in Appendix D used (disallowed post-2023 under NIST 131A).",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-06",
            name="Static RSA Key Transport Restrictions",
            source_id="SP800-52R2-S114",
            source_section="Appendix D",
            source_text="Transitional static RSA cipher suites may be used under restricted conditions.",
            normative_term="MAY",
            applicability_scope="NIST-GOV-ONLY",
            verdict="FAIL",
            evidence=ev,
            finding=f"Static RSA cipher '{c_name}' is not in Appendix D approved transitional list.",
        )

    def eval_n52_cipher_07(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        kex_type = r_in.get("tls12_kex_type")
        dh_bits = r_in.get("tls12_dh_prime_bits")
        ev = [
            EvidenceItem(sid, "tls12_kex_type", kex_type, "ServerKeyExchange -> Key Exchange Type"),
            EvidenceItem(sid, "tls12_dh_prime_bits", dh_bits, "ServerKeyExchange -> DH Prime Bits"),
        ]

        if kex_type != "DHE":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-07",
                name="DHE Parameter Size",
                source_id="SP800-52R2-S35",
                source_section="3.3.1",
                source_text="When DHE cipher suites are configured, the server shall use DH parameters of at least 2048 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="DHE key exchange not negotiated.",
            )

        if dh_bits is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-07",
                name="DHE Parameter Size",
                source_id="SP800-52R2-S35",
                source_section="3.3.1",
                source_text="When DHE cipher suites are configured, the server shall use DH parameters of at least 2048 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=ev,
                finding="DHE parameters unobservable on wire.",
            )

        if dh_bits < 2048:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CIPHER-07",
                name="DHE Parameter Size",
                source_id="SP800-52R2-S35",
                source_section="3.3.1",
                source_text="When DHE cipher suites are configured, the server shall use DH parameters of at least 2048 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"DHE prime modulus length ({dh_bits} bits) is less than the required 2048 bits.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CIPHER-07",
            name="DHE Parameter Size",
            source_id="SP800-52R2-S35",
            source_section="3.3.1",
            source_text="When DHE cipher suites are configured, the server shall use DH parameters of at least 2048 bits.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_kex_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c12 = r_in.get("tls12_named_curve")
        g13 = r_in.get("tls13_key_exchange_group")
        curve = (g13 or c12 or "").lower()
        ev = [EvidenceItem(sid, "negotiated_curve", curve or None, "Key Exchange -> Negotiated Curve/Group")]

        if not curve:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-KEX-01",
                name="Elliptic Curve Support",
                source_id="SP800-52R2-S54",
                source_section="3.4.2.2",
                source_text="Servers shall be configured to support curves P-256, P-384, or P-521.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No EC group negotiated.",
            )

        if curve not in NIST_APPROVED_CURVES:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-KEX-01",
                name="Elliptic Curve Support",
                source_id="SP800-52R2-S54",
                source_section="3.4.2.2",
                source_text="Servers shall be configured to support curves P-256, P-384, or P-521.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="OBSERVATION",
                evidence=ev,
                finding=f"Curve '{curve}' was negotiated (e.g. x25519). Server capability to support NIST curves is unobservable from single negotiation.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-KEX-01",
            name="Elliptic Curve Support",
            source_id="SP800-52R2-S54",
            source_section="3.4.2.2",
            source_text="Servers shall be configured to support curves P-256, P-384, or P-521.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_psk_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name") or ""
        tls_ver = r_in.get("tls_version")
        ev = [
            EvidenceItem(sid, "cipher_name", c_name or None, "TLS Session -> Negotiated Cipher"),
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
        ]

        if "PSK" not in c_name.upper():
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-PSK-01",
                name="Pre-Shared Key TLS Version Restriction",
                source_id="SP800-52R2-S113",
                source_section="Appendix C",
                source_text="PSK shall not be used with TLS 1.0 or TLS 1.1.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if tls_ver in {"TLS 1.0", "TLS 1.1"}:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-PSK-01",
                name="Pre-Shared Key TLS Version Restriction",
                source_id="SP800-52R2-S113",
                source_section="Appendix C",
                source_text="PSK shall not be used with TLS 1.0 or TLS 1.1.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"PSK cipher '{c_name}' negotiated with disallowed {tls_ver}.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-PSK-01",
            name="Pre-Shared Key TLS Version Restriction",
            source_id="SP800-52R2-S113",
            source_section="Appendix C",
            source_text="PSK shall not be used with TLS 1.0 or TLS 1.1.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_psk_02(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name") or ""
        tls_ver = r_in.get("tls_version")
        ev = [
            EvidenceItem(sid, "cipher_name", c_name or None, "TLS Session -> Negotiated Cipher"),
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
        ]

        if "PSK" not in c_name.upper() or tls_ver != "TLS 1.2":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-PSK-02",
                name="PSK Organizational Boundary Restriction",
                source_id="SP800-52R2-S113",
                source_section="Appendix C",
                source_text="PSK cipher suites in Appendix C are restricted to specific organizational boundaries.",
                normative_term="RESTRICTED",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if c_name in NIST_APP_C_PSK_CIPHERS:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-PSK-02",
                name="PSK Organizational Boundary Restriction",
                source_id="SP800-52R2-S113",
                source_section="Appendix C",
                source_text="PSK cipher suites in Appendix C are restricted to specific organizational boundaries.",
                normative_term="RESTRICTED",
                applicability_scope="NIST-GOV-ONLY",
                verdict="OBSERVATION",
                evidence=ev,
                finding=f"PSK cipher '{c_name}' in Appendix C used; organizational boundary is unobservable on wire.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-PSK-02",
            name="PSK Organizational Boundary Restriction",
            source_id="SP800-52R2-S113",
            source_section="Appendix C",
            source_text="PSK cipher suites in Appendix C are restricted to specific organizational boundaries.",
            normative_term="RESTRICTED",
            applicability_scope="NIST-GOV-ONLY",
            verdict="FAIL",
            evidence=ev,
            finding=f"PSK cipher '{c_name}' is not in Appendix C approved list.",
        )

    def eval_n52_psk_03(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name") or ""
        ev = [EvidenceItem(sid, "cipher_name", c_name or None, "TLS Session -> Negotiated Cipher")]

        if "PSK" not in c_name.upper():
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-PSK-03",
                name="PSK Secret Entropy",
                source_id="SP800-52R2-S113",
                source_section="Appendix C",
                source_text="The PSK shall have an entropy of at least 112 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-PSK-03",
            name="PSK Secret Entropy",
            source_id="SP800-52R2-S113",
            source_section="Appendix C",
            source_text="The PSK shall have an entropy of at least 112 bits.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="NOT_OBSERVABLE",
            evidence=ev,
            finding="Pre-shared key secret entropy cannot be observed in passive network traffic.",
        )

    def eval_n52_cert_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-01",
                name="Certificate RSA Public Key Length",
                source_id="SP800-52R2-S17",
                source_section="3.2.1",
                source_text="RSA public key lengths shall be at least 2048 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        min_rsa = facts.get("min_rsa_key_size")
        ev = [EvidenceItem(sid, "non_anchor_cert_facts.min_rsa_key_size", min_rsa, "X.509 Non-Anchor Cert Set")]

        if min_rsa is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-01",
                name="Certificate RSA Public Key Length",
                source_id="SP800-52R2-S17",
                source_section="3.2.1",
                source_text="RSA public key lengths shall be at least 2048 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No RSA certificates present in non-anchor certificate set.",
            )

        if min_rsa < 2048:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-01",
                name="Certificate RSA Public Key Length",
                source_id="SP800-52R2-S17",
                source_section="3.2.1",
                source_text="RSA public key lengths shall be at least 2048 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"Minimum RSA public key length ({min_rsa} bits) in non-anchor cert set is less than 2048 bits.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-01",
            name="Certificate RSA Public Key Length",
            source_id="SP800-52R2-S17",
            source_section="3.2.1",
            source_text="RSA public key lengths shall be at least 2048 bits.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_02(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-02",
                name="Certificate ECDSA Public Key Length",
                source_id="SP800-52R2-S17",
                source_section="3.2.1",
                source_text="ECDSA public key lengths shall be at least 224 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        min_ec = facts.get("min_ec_key_size")
        ev = [EvidenceItem(sid, "non_anchor_cert_facts.min_ec_key_size", min_ec, "X.509 Non-Anchor Cert Set")]

        if min_ec is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-02",
                name="Certificate ECDSA Public Key Length",
                source_id="SP800-52R2-S17",
                source_section="3.2.1",
                source_text="ECDSA public key lengths shall be at least 224 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No EC certificates present in non-anchor certificate set.",
            )

        if min_ec < 224:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-02",
                name="Certificate ECDSA Public Key Length",
                source_id="SP800-52R2-S17",
                source_section="3.2.1",
                source_text="ECDSA public key lengths shall be at least 224 bits.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"Minimum EC public key length ({min_ec} bits) in non-anchor cert set is less than 224 bits.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-02",
            name="Certificate ECDSA Public Key Length",
            source_id="SP800-52R2-S17",
            source_section="3.2.1",
            source_text="ECDSA public key lengths shall be at least 224 bits.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_03(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-03",
                name="Certificate Weak Signature Hashes",
                source_id="SP800-52R2-S43",
                source_section="3.3.3",
                source_text="Certificates shall be signed using SHA-224 or higher; MD5 and SHA-1 shall not be used.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        weak = facts.get("weak_signature_hashes") or []
        ev = [EvidenceItem(sid, "non_anchor_cert_facts.weak_signature_hashes", weak, "X.509 Non-Anchor Cert Set")]

        if weak:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-03",
                name="Certificate Weak Signature Hashes",
                source_id="SP800-52R2-S43",
                source_section="3.3.3",
                source_text="Certificates shall be signed using SHA-224 or higher; MD5 and SHA-1 shall not be used.",
                normative_term="SHALL NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding=f"Weak signature hash(es) detected in non-anchor certificate set: {', '.join(weak)}.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-03",
            name="Certificate Weak Signature Hashes",
            source_id="SP800-52R2-S43",
            source_section="3.3.3",
            source_text="Certificates shall be signed using SHA-224 or higher; MD5 and SHA-1 shall not be used.",
            normative_term="SHALL NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_04(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-04",
                name="Default Profile Certificate Lifespan",
                source_id="SP800-52R2-S22",
                source_section="Table 3-1",
                source_text="The certificate validity period should not exceed three years in default profile.",
                normative_term="SHOULD NOT",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        nb = leaf.get("not_before")
        na = leaf.get("not_after")
        exceeds = check_lifespan_3_calendar_years(nb, na) if (nb and na) else False
        ev = [
            EvidenceItem(sid, "leaf_cert.not_before", nb, "Leaf Certificate -> Validity Not Before"),
            EvidenceItem(sid, "leaf_cert.not_after", na, "Leaf Certificate -> Validity Not After"),
        ]

        if exceeds:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-04",
                name="Default Profile Certificate Lifespan",
                source_id="SP800-52R2-S22",
                source_section="Table 3-1",
                source_text="The certificate validity period should not exceed three years in default profile.",
                normative_term="SHOULD NOT",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="OBSERVATION",
                evidence=ev,
                finding="Leaf certificate validity period exceeds 3 calendar years (NIST Table 3-1 default profile recommendation).",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-04",
            name="Default Profile Certificate Lifespan",
            source_id="SP800-52R2-S22",
            source_section="Table 3-1",
            source_text="The certificate validity period should not exceed three years in default profile.",
            normative_term="SHOULD NOT",
            applicability_scope="NIST-DEFAULT-PROFILE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_05(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        capture_time = r_in.get("capture_time")
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-05",
                name="Certificate Expiration at Capture Time",
                source_id="SP800-52R2-S17",
                source_section="3.2",
                source_text="Certificates shall be valid at the time of the transaction; expired certificates are invalid.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        if capture_time is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-05",
                name="Certificate Expiration at Capture Time",
                source_id="SP800-52R2-S17",
                source_section="3.2",
                source_text="Certificates shall be valid at the time of the transaction; expired certificates are invalid.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "capture_time", None, "TLS Handshake ServerHello Time Epoch")],
                finding="Capture timestamp unavailable; cannot evaluate capture-time validity without live time substitution.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        expired = facts.get("any_cert_expired_at_capture")
        ev = [
            EvidenceItem(sid, "capture_time", capture_time, "TLS Handshake ServerHello Epoch"),
            EvidenceItem(sid, "non_anchor_cert_facts.any_cert_expired_at_capture", expired, "X.509 Non-Anchor Cert Set"),
        ]

        if expired is True:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-05",
                name="Certificate Expiration at Capture Time",
                source_id="SP800-52R2-S17",
                source_section="3.2",
                source_text="Certificates shall be valid at the time of the transaction; expired certificates are invalid.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding="One or more non-anchor certificates were expired at the time of capture.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-05",
            name="Certificate Expiration at Capture Time",
            source_id="SP800-52R2-S17",
            source_section="3.2",
            source_text="Certificates shall be valid at the time of the transaction; expired certificates are invalid.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_06(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        capture_time = r_in.get("capture_time")
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-06",
                name="Certificate Future Validity at Capture Time",
                source_id="SP800-52R2-S17",
                source_section="3.2",
                source_text="Certificates shall be valid at the time of the transaction; not-yet-valid certificates are invalid.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        if capture_time is None:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-06",
                name="Certificate Future Validity at Capture Time",
                source_id="SP800-52R2-S17",
                source_section="3.2",
                source_text="Certificates shall be valid at the time of the transaction; not-yet-valid certificates are invalid.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "capture_time", None, "TLS Handshake ServerHello Time Epoch")],
                finding="Capture timestamp unavailable; cannot evaluate capture-time validity without live time substitution.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        not_yet = facts.get("any_cert_not_yet_valid_at_capture")
        ev = [
            EvidenceItem(sid, "capture_time", capture_time, "TLS Handshake ServerHello Epoch"),
            EvidenceItem(sid, "non_anchor_cert_facts.any_cert_not_yet_valid_at_capture", not_yet, "X.509 Non-Anchor Cert Set"),
        ]

        if not_yet is True:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-06",
                name="Certificate Future Validity at Capture Time",
                source_id="SP800-52R2-S17",
                source_section="3.2",
                source_text="Certificates shall be valid at the time of the transaction; not-yet-valid certificates are invalid.",
                normative_term="SHALL",
                applicability_scope="NIST-GOV-ONLY",
                verdict="FAIL",
                evidence=ev,
                finding="One or more non-anchor certificates were not yet valid at the time of capture.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-06",
            name="Certificate Future Validity at Capture Time",
            source_id="SP800-52R2-S17",
            source_section="3.2",
            source_text="Certificates shall be valid at the time of the transaction; not-yet-valid certificates are invalid.",
            normative_term="SHALL",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_08(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-08",
                name="Default Profile SAN Requirement",
                source_id="SP800-52R2-S27",
                source_section="Table 3-1",
                source_text="The subject alternative name extension shall be present in the default certificate profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        has_san = leaf.get("has_san", False)
        ev = [EvidenceItem(sid, "leaf_cert.has_san", has_san, "Leaf Certificate -> Subject Alternative Name")]

        if not has_san:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-08",
                name="Default Profile SAN Requirement",
                source_id="SP800-52R2-S27",
                source_section="Table 3-1",
                source_text="The subject alternative name extension shall be present in the default certificate profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="FAIL",
                evidence=ev,
                finding="Subject Alternative Name (SAN) extension is absent from leaf certificate under NIST default profile.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-08",
            name="Default Profile SAN Requirement",
            source_id="SP800-52R2-S27",
            source_section="Table 3-1",
            source_text="The subject alternative name extension shall be present in the default certificate profile.",
            normative_term="PROFILE_REQ",
            applicability_scope="NIST-DEFAULT-PROFILE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_09(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-09",
                name="Default Profile Extended Key Usage",
                source_id="SP800-52R2-S26",
                source_section="Table 3-1",
                source_text="The extended key usage extension shall include id-kp-serverAuth and shall not assert anyExtendedKeyUsage in default profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        has_server_auth = leaf.get("has_server_auth_eku", False)
        has_any = leaf.get("has_any_eku", False)
        ev = [
            EvidenceItem(sid, "leaf_cert.has_server_auth_eku", has_server_auth, "Leaf Certificate -> Extended Key Usage"),
            EvidenceItem(sid, "leaf_cert.has_any_eku", has_any, "Leaf Certificate -> Extended Key Usage"),
        ]

        if not has_server_auth:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-09",
                name="Default Profile Extended Key Usage",
                source_id="SP800-52R2-S26",
                source_section="Table 3-1",
                source_text="The extended key usage extension shall include id-kp-serverAuth and shall not assert anyExtendedKeyUsage in default profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="FAIL",
                evidence=ev,
                finding="Leaf certificate does not assert serverAuth in Extended Key Usage under NIST default profile.",
            )

        if has_any:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-09",
                name="Default Profile Extended Key Usage",
                source_id="SP800-52R2-S26",
                source_section="Table 3-1",
                source_text="The extended key usage extension shall include id-kp-serverAuth and shall not assert anyExtendedKeyUsage in default profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="NIST-DEFAULT-PROFILE",
                verdict="FAIL",
                evidence=ev,
                finding="Leaf certificate asserts prohibited anyExtendedKeyUsage under NIST default profile.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-09",
            name="Default Profile Extended Key Usage",
            source_id="SP800-52R2-S26",
            source_section="Table 3-1",
            source_text="The extended key usage extension shall include id-kp-serverAuth and shall not assert anyExtendedKeyUsage in default profile.",
            normative_term="PROFILE_REQ",
            applicability_scope="NIST-DEFAULT-PROFILE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n52_cert_10(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        ev = [EvidenceItem(sid, "revocation_status", r_in.get("revocation_status"), "Certificate Validation Pipeline")]

        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CERT-10",
                name="Certificate Revocation Checking",
                source_id="SP800-52R2-S104",
                source_section="4.5.1",
                source_text="Clients shall perform revocation checking via CRL or OCSP.",
                normative_term="SHALL",
                applicability_scope="NIST-CLIENT",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="Certificate material unobservable on wire.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CERT-10",
            name="Certificate Revocation Checking",
            source_id="SP800-52R2-S104",
            source_section="4.5.1",
            source_text="Clients shall perform revocation checking via CRL or OCSP.",
            normative_term="SHALL",
            applicability_scope="NIST-CLIENT",
            verdict="NOT_OBSERVABLE",
            evidence=ev,
            finding="Passive network capture cannot observe client-side CRL/OCSP lookup decisions.",
        )

    def eval_n52_client_hostname_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        match_status = r_in.get("hostname_match", "SKIPPED_NO_SNI")
        app_data = r_in.get("application_data_observed")
        client_aborted = r_in.get("client_aborted_with_alert", False)

        ev = [
            EvidenceItem(sid, "hostname_match", match_status, "Certificate Pipeline -> Hostname Matching"),
            EvidenceItem(sid, "application_data_observed", app_data, "TLS Flight -> Record Layer Content Type 23"),
            EvidenceItem(sid, "client_aborted_with_alert", client_aborted, "TLS Flight -> Directional Alerts"),
        ]

        # Case A: No SNI presented by client
        if match_status == "SKIPPED_NO_SNI":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CLIENT-HOSTNAME-01",
                name="Client Hostname Verification Enforcement",
                source_id="SP800-52R2-S105",
                source_section="4.5.1",
                source_text="The client shall terminate the TLS connection if the name check fails.",
                normative_term="SHALL",
                applicability_scope="NIST-CLIENT",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No client SNI was offered to evaluate name verification.",
            )

        # Case B: Mismatch + Client Application Data observed
        if match_status == "MISMATCH" and app_data is True:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CLIENT-HOSTNAME-01",
                name="Client Hostname Verification Enforcement",
                source_id="SP800-52R2-S105",
                source_section="4.5.1",
                source_text="The client shall terminate the TLS connection if the name check fails.",
                normative_term="SHALL",
                applicability_scope="NIST-CLIENT",
                verdict="FAIL",
                evidence=ev,
                finding="Client proceeded to transmit Application Data after a certificate hostname mismatch.",
            )

        # Case C: Mismatch + Client Fatal Alert
        if match_status == "MISMATCH" and client_aborted:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CLIENT-HOSTNAME-01",
                name="Client Hostname Verification Enforcement",
                source_id="SP800-52R2-S105",
                source_section="4.5.1",
                source_text="The client shall terminate the TLS connection if the name check fails.",
                normative_term="SHALL",
                applicability_scope="NIST-CLIENT",
                verdict="NOT_OBSERVABLE",
                evidence=ev,
                finding="Client aborted session with fatal alert after mismatch, but specific causal check is unobservable in passive PCAP.",
            )

        # Case D: Mismatch + Other Termination / Unresolvable AppData
        if match_status == "MISMATCH":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CLIENT-HOSTNAME-01",
                name="Client Hostname Verification Enforcement",
                source_id="SP800-52R2-S105",
                source_section="4.5.1",
                source_text="The client shall terminate the TLS connection if the name check fails.",
                normative_term="SHALL",
                applicability_scope="NIST-CLIENT",
                verdict="NOT_OBSERVABLE",
                evidence=ev,
                finding="Certificate hostname mismatched; client termination causality is unobservable on wire.",
            )

        # Case E: Hostname Matched
        if match_status == "MATCHED":
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-CLIENT-HOSTNAME-01",
                name="Client Hostname Verification Enforcement",
                source_id="SP800-52R2-S105",
                source_section="4.5.1",
                source_text="The client shall terminate the TLS connection if the name check fails.",
                normative_term="SHALL",
                applicability_scope="NIST-CLIENT",
                verdict="NOT_OBSERVABLE",
                evidence=ev,
                finding="Passive capture cannot verify if client verified hostname or simply ignored validation; both produce identical traffic.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-CLIENT-HOSTNAME-01",
            name="Client Hostname Verification Enforcement",
            source_id="SP800-52R2-S105",
            source_section="4.5.1",
            source_text="The client shall terminate the TLS connection if the name check fails.",
            normative_term="SHALL",
            applicability_scope="NIST-CLIENT",
            verdict="NOT_APPLICABLE",
            evidence=ev,
        )

    def eval_n52_proto_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        early_offered = r_in.get("early_data_offered", False)
        early_observed = r_in.get("early_data_observed", False)
        ev = [
            EvidenceItem(sid, "early_data_offered", early_offered, "ClientHello -> Extension 42"),
            EvidenceItem(sid, "early_data_observed", early_observed, "TLS Flight -> Record Layer Content Type 23 pre-ServerHello"),
        ]

        if early_offered or early_observed:
            return PolicyResult(
                policy="NIST-52R2",
                rule_id="N52-PROTO-01",
                name="TLS 1.3 0-RTT Early Data Deprecation",
                source_id="SP800-52R2-S77",
                source_section="3.6",
                source_text="0-RTT early data should not be enabled due to lack of forward secrecy and replay vulnerability.",
                normative_term="SHOULD NOT",
                applicability_scope="NIST-GOV-ONLY",
                verdict="OBSERVATION",
                evidence=ev,
                finding="TLS 1.3 0-RTT early data was offered or observed on stream.",
            )

        return PolicyResult(
            policy="NIST-52R2",
            rule_id="N52-PROTO-01",
            name="TLS 1.3 0-RTT Early Data Deprecation",
            source_id="SP800-52R2-S77",
            source_section="3.6",
            source_text="0-RTT early data should not be enabled due to lack of forward secrecy and replay vulnerability.",
            normative_term="SHOULD NOT",
            applicability_scope="NIST-GOV-ONLY",
            verdict="PASS",
            evidence=ev,
        )
