"""
Mozilla TLS Guidelines 6.0 Modern Profile Policy Pack (MOZ-MODERN).

Implements 6 normative rules grounded directly in data/tls_ref_6.0.json (modern configuration).
"""

from ..schema import RuleInput, PolicyResult, EvidenceItem
from ..policy.mozilla_loader import get_mozilla_modern_profile


class MozillaModernEvaluator:
    """Evaluates RuleInput against Mozilla TLS Guidelines 6.0 Modern profile."""

    def __init__(self):
        self.profile = get_mozilla_modern_profile()

    def evaluate_all(self, r_in: RuleInput) -> list[PolicyResult]:
        return [
            self.eval_mm_tls_01(r_in),
            self.eval_mm_cipher_01(r_in),
            self.eval_mm_kex_01(r_in),
            self.eval_mm_cert_01(r_in),
            self.eval_mm_cert_02(r_in),
            self.eval_mm_cert_03(r_in),
        ]

    def eval_mm_tls_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        tls_ver = r_in.get("tls_version")
        ev = [EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version")]

        if tls_ver is None:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-TLS-01",
                name="Modern TLS Protocol Version",
                source_id="MOZ-6.0-MOD-TLS",
                source_section="Modern Profile",
                source_text="Only TLSv1.3 is permitted in the Mozilla Modern profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No TLS session negotiated on stream.",
            )

        if tls_ver != "TLS 1.3":
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-TLS-01",
                name="Modern TLS Protocol Version",
                source_id="MOZ-6.0-MOD-TLS",
                source_section="Modern Profile",
                source_text="Only TLSv1.3 is permitted in the Mozilla Modern profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="FAIL",
                evidence=ev,
                finding=f"Negotiated version '{tls_ver}' does not satisfy Mozilla Modern profile requirement (TLS 1.3 only).",
            )

        return PolicyResult(
            policy="MOZ-MODERN",
            rule_id="MM-TLS-01",
            name="Modern TLS Protocol Version",
            source_id="MOZ-6.0-MOD-TLS",
            source_section="Modern Profile",
            source_text="Only TLSv1.3 is permitted in the Mozilla Modern profile.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-MODERN",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mm_cipher_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CIPHER-01",
                name="Modern Cipher Suite",
                source_id="MOZ-6.0-MOD-CIPHER",
                source_section="Modern Profile",
                source_text="Cipher suite must be one of the approved Mozilla Modern ciphersuites.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if c_name not in self.profile.ciphersuites:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CIPHER-01",
                name="Modern Cipher Suite",
                source_id="MOZ-6.0-MOD-CIPHER",
                source_section="Modern Profile",
                source_text="Cipher suite must be one of the approved Mozilla Modern ciphersuites.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="FAIL",
                evidence=ev,
                finding=f"Cipher suite '{c_name}' is not in Mozilla Modern approved ciphersuites list.",
            )

        return PolicyResult(
            policy="MOZ-MODERN",
            rule_id="MM-CIPHER-01",
            name="Modern Cipher Suite",
            source_id="MOZ-6.0-MOD-CIPHER",
            source_section="Modern Profile",
            source_text="Cipher suite must be one of the approved Mozilla Modern ciphersuites.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-MODERN",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mm_kex_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        grp = r_in.get("tls13_key_exchange_group") or r_in.get("tls12_named_curve")
        grp_clean = (grp or "").lower()
        ev = [EvidenceItem(sid, "key_exchange_group", grp, "TLS Key Exchange -> Negotiated Group")]

        if not grp:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-KEX-01",
                name="Modern Key Exchange Curve / Group",
                source_id="MOZ-6.0-MOD-KEX",
                source_section="Modern Profile",
                source_text="Key exchange group must be in Mozilla Modern approved tls_curves list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No key exchange group negotiated.",
            )

        if grp_clean not in self.profile.tls_curves:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-KEX-01",
                name="Modern Key Exchange Curve / Group",
                source_id="MOZ-6.0-MOD-KEX",
                source_section="Modern Profile",
                source_text="Key exchange group must be in Mozilla Modern approved tls_curves list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="FAIL",
                evidence=ev,
                finding=f"Key exchange group '{grp}' is not in Mozilla Modern approved curves list.",
            )

        return PolicyResult(
            policy="MOZ-MODERN",
            rule_id="MM-KEX-01",
            name="Modern Key Exchange Curve / Group",
            source_id="MOZ-6.0-MOD-KEX",
            source_section="Modern Profile",
            source_text="Key exchange group must be in Mozilla Modern approved tls_curves list.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-MODERN",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mm_cert_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CERT-01",
                name="Modern Maximum Certificate Lifespan",
                source_id="MOZ-6.0-MOD-LIFESPAN",
                source_section="Modern Profile",
                source_text="Certificate validity period must not exceed 90 days.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        days = leaf.get("lifespan_days", 0)
        ev = [EvidenceItem(sid, "leaf_cert.lifespan_days", days, "Leaf Certificate -> Lifespan Days")]

        if days > self.profile.maximum_certificate_lifespan:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CERT-01",
                name="Modern Maximum Certificate Lifespan",
                source_id="MOZ-6.0-MOD-LIFESPAN",
                source_section="Modern Profile",
                source_text="Certificate validity period must not exceed 90 days.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="FAIL",
                evidence=ev,
                finding=f"Leaf certificate validity period ({days} days) exceeds Mozilla Modern maximum of {self.profile.maximum_certificate_lifespan} days.",
            )

        return PolicyResult(
            policy="MOZ-MODERN",
            rule_id="MM-CERT-01",
            name="Modern Maximum Certificate Lifespan",
            source_id="MOZ-6.0-MOD-LIFESPAN",
            source_section="Modern Profile",
            source_text="Certificate validity period must not exceed 90 days.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-MODERN",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mm_cert_02(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CERT-02",
                name="Modern Certificate Key Type",
                source_id="MOZ-6.0-MOD-KEYTYPE",
                source_section="Modern Profile",
                source_text="Certificate public key must be ECDSA.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        pk_alg = (leaf.get("public_key_algorithm") or "").lower()
        ev = [EvidenceItem(sid, "leaf_cert.public_key_algorithm", leaf.get("public_key_algorithm"), "Leaf Certificate -> Public Key Algorithm")]

        if pk_alg not in ("ec", "ecdsa"):
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CERT-02",
                name="Modern Certificate Key Type",
                source_id="MOZ-6.0-MOD-KEYTYPE",
                source_section="Modern Profile",
                source_text="Certificate public key must be ECDSA.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="FAIL",
                evidence=ev,
                finding=f"Certificate key algorithm '{leaf.get('public_key_algorithm')}' is not ECDSA as required by Mozilla Modern profile.",
            )

        return PolicyResult(
            policy="MOZ-MODERN",
            rule_id="MM-CERT-02",
            name="Modern Certificate Key Type",
            source_id="MOZ-6.0-MOD-KEYTYPE",
            source_section="Modern Profile",
            source_text="Certificate public key must be ECDSA.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-MODERN",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mm_cert_03(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CERT-03",
                name="Modern Certificate Signature Algorithm",
                source_id="MOZ-6.0-MOD-SIG",
                source_section="Modern Profile",
                source_text="Certificate signature algorithm must be in Mozilla Modern approved certificate_signatures list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        sig_name = leaf.get("signature_algorithm_name") or ""
        ev = [EvidenceItem(sid, "leaf_cert.signature_algorithm_name", sig_name, "Leaf Certificate -> Signature Algorithm Name")]

        # Match exact string or case-insensitive match against approved list
        matched = any(sig_name.lower() == s.lower() for s in self.profile.certificate_signatures)
        if not matched:
            return PolicyResult(
                policy="MOZ-MODERN",
                rule_id="MM-CERT-03",
                name="Modern Certificate Signature Algorithm",
                source_id="MOZ-6.0-MOD-SIG",
                source_section="Modern Profile",
                source_text="Certificate signature algorithm must be in Mozilla Modern approved certificate_signatures list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-MODERN",
                verdict="FAIL",
                evidence=ev,
                finding=f"Certificate signature algorithm '{sig_name}' is not in Mozilla Modern approved list {sorted(list(self.profile.certificate_signatures))}.",
            )

        return PolicyResult(
            policy="MOZ-MODERN",
            rule_id="MM-CERT-03",
            name="Modern Certificate Signature Algorithm",
            source_id="MOZ-6.0-MOD-SIG",
            source_section="Modern Profile",
            source_text="Certificate signature algorithm must be in Mozilla Modern approved certificate_signatures list.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-MODERN",
            verdict="PASS",
            evidence=ev,
        )
