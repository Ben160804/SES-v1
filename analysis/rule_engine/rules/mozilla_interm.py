"""
Mozilla TLS Guidelines 6.0 Intermediate Profile Policy Pack (MOZ-INTERM).

Implements 5 normative rules grounded directly in data/tls_ref_6.0.json (intermediate configuration).
"""

from ..schema import RuleInput, PolicyResult, EvidenceItem
from ..policy.mozilla_loader import get_mozilla_intermediate_profile


class MozillaIntermediateEvaluator:
    """Evaluates RuleInput against Mozilla TLS Guidelines 6.0 Intermediate profile."""

    def __init__(self):
        self.profile = get_mozilla_intermediate_profile()

    def evaluate_all(self, r_in: RuleInput) -> list[PolicyResult]:
        return [
            self.eval_mi_tls_01(r_in),
            self.eval_mi_cipher_01(r_in),
            self.eval_mi_kex_01(r_in),
            self.eval_mi_cert_01(r_in),
            self.eval_mi_cert_02(r_in),
        ]

    def eval_mi_tls_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        tls_ver = r_in.get("tls_version")
        ev = [EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version")]

        if tls_ver is None:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-TLS-01",
                name="Intermediate TLS Protocol Version",
                source_id="MOZ-6.0-INT-TLS",
                source_section="Intermediate Profile",
                source_text="Only TLSv1.2 and TLSv1.3 are permitted in the Mozilla Intermediate profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No TLS session negotiated on stream.",
            )

        if tls_ver not in {"TLS 1.2", "TLS 1.3"}:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-TLS-01",
                name="Intermediate TLS Protocol Version",
                source_id="MOZ-6.0-INT-TLS",
                source_section="Intermediate Profile",
                source_text="Only TLSv1.2 and TLSv1.3 are permitted in the Mozilla Intermediate profile.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="FAIL",
                evidence=ev,
                finding=f"Negotiated version '{tls_ver}' is not TLS 1.2 or TLS 1.3 as required by Mozilla Intermediate profile.",
            )

        return PolicyResult(
            policy="MOZ-INTERM",
            rule_id="MI-TLS-01",
            name="Intermediate TLS Protocol Version",
            source_id="MOZ-6.0-INT-TLS",
            source_section="Intermediate Profile",
            source_text="Only TLSv1.2 and TLSv1.3 are permitted in the Mozilla Intermediate profile.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-INTERMEDIATE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mi_cipher_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-CIPHER-01",
                name="Intermediate Cipher Suite",
                source_id="MOZ-6.0-INT-CIPHER",
                source_section="Intermediate Profile",
                source_text="Cipher suite must be one of the approved Mozilla Intermediate ciphersuites.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if c_name not in self.profile.approved_ciphers:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-CIPHER-01",
                name="Intermediate Cipher Suite",
                source_id="MOZ-6.0-INT-CIPHER",
                source_section="Intermediate Profile",
                source_text="Cipher suite must be one of the approved Mozilla Intermediate ciphersuites.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="FAIL",
                evidence=ev,
                finding=f"Cipher suite '{c_name}' is not in Mozilla Intermediate approved ciphersuites list.",
            )

        return PolicyResult(
            policy="MOZ-INTERM",
            rule_id="MI-CIPHER-01",
            name="Intermediate Cipher Suite",
            source_id="MOZ-6.0-INT-CIPHER",
            source_section="Intermediate Profile",
            source_text="Cipher suite must be one of the approved Mozilla Intermediate ciphersuites.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-INTERMEDIATE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mi_kex_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        grp = r_in.get("tls13_key_exchange_group") or r_in.get("tls12_named_curve")
        grp_clean = (grp or "").lower()
        ev = [EvidenceItem(sid, "key_exchange_group", grp, "TLS Key Exchange -> Negotiated Group")]

        if not grp:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-KEX-01",
                name="Intermediate Key Exchange Curve / Group",
                source_id="MOZ-6.0-INT-KEX",
                source_section="Intermediate Profile",
                source_text="Key exchange curve/group must be in Mozilla Intermediate approved tls_curves list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No EC key exchange curve/group negotiated.",
            )

        if grp_clean not in self.profile.tls_curves:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-KEX-01",
                name="Intermediate Key Exchange Curve / Group",
                source_id="MOZ-6.0-INT-KEX",
                source_section="Intermediate Profile",
                source_text="Key exchange curve/group must be in Mozilla Intermediate approved tls_curves list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="FAIL",
                evidence=ev,
                finding=f"Key exchange curve/group '{grp}' is not in Mozilla Intermediate approved curves list.",
            )

        return PolicyResult(
            policy="MOZ-INTERM",
            rule_id="MI-KEX-01",
            name="Intermediate Key Exchange Curve / Group",
            source_id="MOZ-6.0-INT-KEX",
            source_section="Intermediate Profile",
            source_text="Key exchange curve/group must be in Mozilla Intermediate approved tls_curves list.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-INTERMEDIATE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mi_cert_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-CERT-01",
                name="Intermediate Maximum Certificate Lifespan",
                source_id="MOZ-6.0-INT-LIFESPAN",
                source_section="Intermediate Profile",
                source_text="Certificate validity period must not exceed 366 days.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        days = leaf.get("lifespan_days", 0)
        ev = [EvidenceItem(sid, "leaf_cert.lifespan_days", days, "Leaf Certificate -> Lifespan Days")]

        if days > self.profile.maximum_certificate_lifespan:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-CERT-01",
                name="Intermediate Maximum Certificate Lifespan",
                source_id="MOZ-6.0-INT-LIFESPAN",
                source_section="Intermediate Profile",
                source_text="Certificate validity period must not exceed 366 days.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="FAIL",
                evidence=ev,
                finding=f"Leaf certificate validity period ({days} days) exceeds Mozilla Intermediate maximum of {self.profile.maximum_certificate_lifespan} days.",
            )

        return PolicyResult(
            policy="MOZ-INTERM",
            rule_id="MI-CERT-01",
            name="Intermediate Maximum Certificate Lifespan",
            source_id="MOZ-6.0-INT-LIFESPAN",
            source_section="Intermediate Profile",
            source_text="Certificate validity period must not exceed 366 days.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-INTERMEDIATE",
            verdict="PASS",
            evidence=ev,
        )

    def eval_mi_cert_02(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        leaf = r_in.get("leaf_cert")
        if not r_in.get("cert_observable") or not leaf:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-CERT-02",
                name="Intermediate Certificate Signature Algorithm",
                source_id="MOZ-6.0-INT-SIG",
                source_section="Intermediate Profile",
                source_text="Certificate signature algorithm must be in Mozilla Intermediate approved certificate_signatures list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        sig_name = leaf.get("signature_algorithm_name") or ""
        ev = [EvidenceItem(sid, "leaf_cert.signature_algorithm_name", sig_name, "Leaf Certificate -> Signature Algorithm Name")]

        matched = any(sig_name.lower() == s.lower() for s in self.profile.certificate_signatures)
        if not matched:
            return PolicyResult(
                policy="MOZ-INTERM",
                rule_id="MI-CERT-02",
                name="Intermediate Certificate Signature Algorithm",
                source_id="MOZ-6.0-INT-SIG",
                source_section="Intermediate Profile",
                source_text="Certificate signature algorithm must be in Mozilla Intermediate approved certificate_signatures list.",
                normative_term="PROFILE_REQ",
                applicability_scope="MOZ-INTERMEDIATE",
                verdict="FAIL",
                evidence=ev,
                finding=f"Certificate signature algorithm '{sig_name}' is not in Mozilla Intermediate approved list.",
            )

        return PolicyResult(
            policy="MOZ-INTERM",
            rule_id="MI-CERT-02",
            name="Intermediate Certificate Signature Algorithm",
            source_id="MOZ-6.0-INT-SIG",
            source_section="Intermediate Profile",
            source_text="Certificate signature algorithm must be in Mozilla Intermediate approved certificate_signatures list.",
            normative_term="PROFILE_REQ",
            applicability_scope="MOZ-INTERMEDIATE",
            verdict="PASS",
            evidence=ev,
        )
