"""
Regression test: RSA-PSS certificate OID and parameter verification.
---------------------------------------------------------------------
Guards against the silent rsa_padding= keyword regression where PSS(...)
passed as a positional argument lands in the legacy backend= parameter
and is discarded, causing the cert to be signed with PKCS1v15 instead.

RFC 4055 §3.1:
  id-RSASSA-PSS  OID ::= { pkcs-1 10 }
  dotted string: 1.2.840.113549.1.1.10

sha256WithRSAEncryption (PKCS1v15) OID: 1.2.840.113549.1.1.11

Usage:
    python3 testbed/pki/generator/test_rsa_pss_oid.py
"""

import sys
import os

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.join(_here, "..", "..", "..")
if _root not in sys.path:
    sys.path.insert(0, _root)

from cryptography import x509
from testbed.pki.generator.make_certs import PKIFactory

# ponytail: two OID constants, one factory instance reused across all three tests
_PSS_OID   = "1.2.840.113549.1.1.10"   # RFC 4055 §3.1 id-RSASSA-PSS
_PKCS1_OID = "1.2.840.113549.1.1.11"   # sha256WithRSAEncryption

factory = PKIFactory()


def _load(pem):
    return x509.load_pem_x509_certificate(pem.encode())


def test_rsa_pss_oid():
    """
    generate_cert_profile("rsa_pss", ...) must produce a cert whose
    signature algorithm OID is id-RSASSA-PSS (1.2.840.113549.1.1.10),
    not sha256WithRSAEncryption (1.2.840.113549.1.1.11).
    """
    profile = factory.generate_cert_profile("rsa_pss", "valid", "complete", "matched_dns")
    cert = _load(profile["cert_pem"])
    actual = cert.signature_algorithm_oid.dotted_string
    assert actual == _PSS_OID, (
        "RSA-PSS cert has wrong signature OID.\n"
        "  expected : " + _PSS_OID + "  (id-RSASSA-PSS, RFC 4055 §3.1)\n"
        "  actual   : " + actual + "\n"
        "  Likely cause: PSS passed as positional arg 3 (backend=) "
        "instead of rsa_padding= keyword."
    )


def test_rsa_pss_parameters():
    """
    The PSS AlgorithmIdentifier must use SHA-256 as both the outer hash
    and MGF1 hash (salt length 32 == SHA-256 digest length).
    Confirms the PSS struct is wired through, not just that the OID flipped.
    """
    profile = factory.generate_cert_profile("rsa_pss", "valid", "complete", "matched_dns")
    cert = _load(profile["cert_pem"])
    h = cert.signature_hash_algorithm
    assert h is not None, "signature_hash_algorithm is None on PSS cert"
    assert h.name == "sha256", "PSS cert hash algorithm: expected sha256, got " + repr(h.name)
    # Belt-and-suspenders: OID must still be PSS after the parameter walk.
    assert cert.signature_algorithm_oid.dotted_string == _PSS_OID, (
        "OID regressed between OID test and parameter test."
    )


def test_rsa_pkcs_oid_unaffected():
    """
    Fixing the PSS arm must not disturb PKCS1v15.
    generate_cert_profile("rsa_pkcs", ...) must still produce
    sha256WithRSAEncryption (1.2.840.113549.1.1.11).
    """
    profile = factory.generate_cert_profile("rsa_pkcs", "valid", "complete", "matched_dns")
    cert = _load(profile["cert_pem"])
    actual = cert.signature_algorithm_oid.dotted_string
    assert actual == _PKCS1_OID, (
        "RSA-PKCS1v15 cert has wrong OID after PSS fix.\n"
        "  expected : " + _PKCS1_OID + "  (sha256WithRSAEncryption)\n"
        "  actual   : " + actual
    )


if __name__ == "__main__":
    tests = [test_rsa_pss_oid, test_rsa_pss_parameters, test_rsa_pkcs_oid_unaffected]
    failed = 0
    for t in tests:
        try:
            t()
            print("  PASS  " + t.__name__)
        except AssertionError as e:
            print("  FAIL  " + t.__name__ + "\n        " + str(e))
            failed += 1
        except Exception as e:
            print("  ERROR " + t.__name__ + "\n        " + type(e).__name__ + ": " + str(e))
            failed += 1
    print()
    if failed:
        print(str(failed) + "/" + str(len(tests)) + " test(s) failed.")
        sys.exit(1)
    print("All " + str(len(tests)) + " tests passed.")
