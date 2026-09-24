"""
testbed/pki/generator/make_certs.py
====================================
Certificate factory for the SecureMailScope testbed.

Implements the agreed PKI architecture:

  Permanent (written to disk once, reused across runs):
      root_ca.key / root_ca.crt
      rogue_ca.key / rogue_ca.crt

  Cached in memory per run (generated once, keyed by type):
      issuer keys: ECDSA, RSA, Ed25519          (intermediate signs the leaf)
      leaf keys:   ECDSA, RSA-2048, RSA-1024, Ed25519

  Per-scenario (called by the batch runner for each matrix row):
      generate_cert_profile(sig_algo, validity, chain_shape, san_type)
          -> { cert_pem, key_pem, chain_pem, trust_store_pem }

  Mutations handled here:
      CA=FALSE on intermediate     (bad_constraint)
      byte-flip on intermediate    (tampered_sig)
      expired / not-yet-valid      (validity param)
      SAN variants                 (san_type param)
      self-signed leaf             (chain_shape=self_signed_*)
      rogue-root chain             (chain_shape=unknown_root)
      leaf-only chain.pem          (chain_shape=leaf_only)

  Not handled here (caller's responsibility):
      TLS version, cipher selection, STARTTLS stripping -> server config
      cleartext scenarios (tls_presence=none)           -> no PKI needed

Usage:
    from testbed.pki.generator.make_certs import PKIFactory

    factory = PKIFactory(pki_dir="testbed/pki")
    profile = factory.generate_cert_profile(
        sig_algo="ecdsa",
        validity="expired",
        chain_shape="complete",
        san_type="matched_dns",
    )
    # profile["cert_pem"], profile["key_pem"], profile["chain_pem"],
    # profile["trust_store_pem"]
"""

import base64
import datetime
import ipaddress
import pathlib
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The hostname the testbed Postfix/Dovecot servers listen on.
# Matched SANs use this; mismatched SANs deliberately use a different name.
SERVER_HOSTNAME = "mail.test.local"
SERVER_IP       = "172.28.0.10"

# How long a "valid" cert lives (2 years is realistic for a testbed).
VALID_DAYS = 730

# ponytail: one UTC reference point for all temporal math in this module.
_NOW = datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Low-level key generation helpers
# ---------------------------------------------------------------------------

def _make_rsa_key(key_size: int = 2048):
    """Generate an RSA private key of the given size."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _make_ecdsa_key():
    """Generate an ECDSA P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def _make_ed25519_key():
    """Generate an Ed25519 private key."""
    return ed25519.Ed25519PrivateKey.generate()


# ---------------------------------------------------------------------------
# Key cache
# ---------------------------------------------------------------------------

class _KeyCache:
    """
    Holds one key per type so we pay RSA keygen cost at most once per run.

    Issuer keys (used by the intermediate to sign the leaf):
        "ecdsa", "rsa", "ed25519"

    Leaf keys (the leaf certificate's own public key):
        "ecdsa", "rsa2048", "rsa1024", "ed25519"

    ponytail: a plain dict is sufficient; no class hierarchy needed.
    """

    def __init__(self):
        # Build all keys up-front. RSA-2048 is the slowest (~200ms), but we
        # pay it once here rather than once per scenario.
        self.issuer = {
            "ecdsa":   _make_ecdsa_key(),
            "rsa":     _make_rsa_key(2048),
            "ed25519": _make_ed25519_key(),
        }
        self.leaf = {
            "ecdsa":   _make_ecdsa_key(),
            "rsa2048": _make_rsa_key(2048),
            "rsa1024": _make_rsa_key(1024),  # PCAP-126: deliberately weak
            "ed25519": _make_ed25519_key(),
        }


# ---------------------------------------------------------------------------
# X.509 builder helpers
# ---------------------------------------------------------------------------

def _subject_name(cn: str) -> x509.Name:
    """Minimal distinguished name — only CN, nothing more."""
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _basic_constraints(is_ca: bool, path_len=None) -> x509.BasicConstraints:
    return x509.BasicConstraints(ca=is_ca, path_length=path_len)


def _sign(builder, signing_key, sig_algo: str) -> x509.Certificate:
    """
    Sign a certificate builder with the right algorithm for the given sig_algo.
    Validates cryptographic compatibility between signing_key and sig_algo.

    sig_algo values correspond directly to the sidecar schema's cert_sig_algo
    field:
        "ecdsa"    -> ECDSA + SHA-256
        "rsa_pkcs" -> RSA PKCS#1 v1.5 + SHA-256
        "rsa_pss"  -> RSA-PSS + SHA-256
        "ed25519"  -> PureEdDSA (no separate hash)
    """
    if sig_algo == "ecdsa":
        if not isinstance(signing_key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"Incompatible signing key {type(signing_key).__name__} for sig_algo 'ecdsa'")
        return builder.sign(signing_key, hashes.SHA256())
    elif sig_algo == "rsa_pkcs":
        if not isinstance(signing_key, rsa.RSAPrivateKey):
            raise ValueError(f"Incompatible signing key {type(signing_key).__name__} for sig_algo 'rsa_pkcs'")
        return builder.sign(signing_key, hashes.SHA256())
    elif sig_algo == "rsa_pss":
        if not isinstance(signing_key, rsa.RSAPrivateKey):
            raise ValueError(f"Incompatible signing key {type(signing_key).__name__} for sig_algo 'rsa_pss'")
        return builder.sign(
            signing_key,
            hashes.SHA256(),
            rsa_padding=asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.DIGEST_LENGTH,
            ),
        )
    elif sig_algo == "ed25519":
        if not isinstance(signing_key, ed25519.Ed25519PrivateKey):
            raise ValueError(f"Incompatible signing key {type(signing_key).__name__} for sig_algo 'ed25519'")
        return builder.sign(signing_key, None)
    else:
        raise ValueError(f"Unknown sig_algo: {sig_algo!r}")


def _pem(cert_or_key) -> str:
    """Serialize a certificate or private key to PEM string."""
    if isinstance(cert_or_key, x509.Certificate):
        return cert_or_key.public_bytes(serialization.Encoding.PEM).decode()
    # Ed25519 (and Ed448) keys do not support TraditionalOpenSSL format.
    # Use PKCS8, which works for all key types.
    return cert_or_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


# ---------------------------------------------------------------------------
# CA certificate builders
# ---------------------------------------------------------------------------

def _build_ca_cert(
    subject_cn: str,
    subject_key,
    issuer_name: x509.Name,
    issuer_key,
    sig_algo: str = "ecdsa",
    is_ca: bool = True,
    path_len=None,
    issuer_public_key=None,
) -> x509.Certificate:
    """
    Build and sign a CA certificate (root or intermediate).

    is_ca=False produces the bad_constraint scenario: the cert is in the
    chain as if it were a CA but basicConstraints says it is not.
    The trusted root still signs it, so the chain path is found, but the
    validator rejects it with CA_CONSTRAINT_VIOLATION.
    """
    now = _NOW
    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject_name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        # path_length is only valid when is_ca=True. The cryptography library
        # raises if path_length is set on a non-CA cert (bad_constraint scenario).
        .add_extension(_basic_constraints(is_ca, path_len if is_ca else None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        # RFC 5280 §4.2.1.3: If basicConstraints asserts CA:TRUE or pathlen,
        # the keyCertSign bit in KeyUsage MUST be set.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=not is_ca,
                key_agreement=False,
                data_encipherment=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    # RFC 5280 §4.2.1.1: Authority Key Identifier linking to the issuing CA
    if issuer_public_key is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
            critical=False,
        )

    return _sign(builder, issuer_key, sig_algo)


def _build_root_ca(cn: str, key) -> x509.Certificate:
    """
    Self-signed root CA. Always ECDSA for speed.

    The root's sig algo is not tested directly — the matrix varies
    cert_sig_algo on the leaf, not on the root. Using ECDSA here keeps
    root CA generation fast regardless of which leaf sig_algo is requested.
    """
    return _build_ca_cert(
        subject_cn        = cn,
        subject_key       = key,
        issuer_name       = _subject_name(cn),   # self-signed: issuer == subject
        issuer_key        = key,
        sig_algo          = "ecdsa",
        is_ca             = True,
        path_len          = 1,                   # root can sign one level of CAs
        issuer_public_key = key.public_key(),
    )


# ---------------------------------------------------------------------------
# Leaf certificate builder
# ---------------------------------------------------------------------------

def _san_extension(san_type: str):
    """
    Build the SAN extension for the leaf cert based on the scenario's san_type.

    san_type values (from the agreed design):
        "matched_dns"    -> DNS: mail.test.local   (matches SERVER_HOSTNAME)
        "mismatched_dns" -> DNS: rogue.test.local  (does NOT match)
        "wildcard"       -> DNS: *.test.local      (matches mail.test.local)
        "ip_san"         -> IP:  172.28.0.10
        "no_san"         -> no SAN extension at all

    Returns None for "no_san" so the caller skips adding the extension.
    """
    mapping = {
        "matched_dns":    [x509.DNSName(SERVER_HOSTNAME)],
        "mismatched_dns": [x509.DNSName("rogue.test.local")],
        "wildcard":       [x509.DNSName("*.example.com")],
        "ip_san":         [x509.IPAddress(ipaddress.IPv4Address(SERVER_IP))],
    }
    if san_type == "no_san":
        return None
    if san_type not in mapping:
        raise ValueError(f"Unknown san_type: {san_type!r}")
    return x509.SubjectAlternativeName(mapping[san_type])


def _validity_window(validity: str):
    """
    Return (not_valid_before, not_valid_after) for the given validity state.

        "valid"         -> now-1d  .. now+2y  (normal in-window cert)
        "expired"       -> now-2y  .. now-1d  (already expired)
        "not_yet_valid" -> now+1d  .. now+2y  (future cert, not yet usable)
    """
    if validity == "valid":
        return _NOW - datetime.timedelta(days=1), _NOW + datetime.timedelta(days=VALID_DAYS)
    elif validity == "expired":
        return _NOW - datetime.timedelta(days=VALID_DAYS), _NOW - datetime.timedelta(days=1)
    elif validity == "not_yet_valid":
        return _NOW + datetime.timedelta(days=1), _NOW + datetime.timedelta(days=VALID_DAYS)
    else:
        raise ValueError(f"Unknown validity: {validity!r}")


def _build_leaf_cert(
    leaf_key,
    issuer_cert: x509.Certificate,
    issuer_key,
    sig_algo: str,
    validity: str,
    san_type: str,
) -> x509.Certificate:
    """Build and sign a leaf (end-entity) certificate."""
    not_before, not_after = _validity_window(validity)
    san_ext = _san_extension(san_type)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject_name(SERVER_HOSTNAME))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_basic_constraints(False), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True,  key_agreement=False,
                data_encipherment=False, key_cert_sign=False,
                crl_sign=False,         encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
    )

    # SAN is omitted entirely for the "no_san" scenario (tests CN-only fallback).
    if san_ext is not None:
        builder = builder.add_extension(san_ext, critical=False)

    return _sign(builder, issuer_key, sig_algo)


# ---------------------------------------------------------------------------
# Post-generation mutation: tampered signature
# ---------------------------------------------------------------------------

def _tamper_signature(cert: x509.Certificate) -> bytes:
    """
    Flip one byte in the DER signature field of the certificate.

    This produces a cert that is structurally valid (parses cleanly) but
    whose signature does not verify. When used as an intermediate, the
    validator will fail with INVALID_SIGNATURE_IN_CHAIN.

    ponytail: no ASN.1 parser — the signature bytes are always at the tail
    of the DER blob for the cert types we generate. XOR one byte near the
    end. Ceiling: would misfire if certs have trailing attributes after the
    signature; none of our generated certs do.
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    flip_pos = len(der) - 10           # well inside the signature value
    patched = bytearray(der)
    patched[flip_pos] ^= 0xFF
    return bytes(patched)


def _der_to_pem(der: bytes) -> str:
    """Wrap raw DER bytes in a PEM envelope."""
    b64 = base64.encodebytes(der).decode()
    return f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"


# ---------------------------------------------------------------------------
# Issuer key -> sig_algo mapper
# ---------------------------------------------------------------------------

def _issuer_key_for(sig_algo: str, cache: _KeyCache):
    """
    Return the correct cached issuer key for the requested sig_algo.

    sig_algo    issuer key type     note
    ----------  ----------------    ----------------------------------------
    ecdsa       ECDSA               ECDSA + SHA-256
    rsa_pkcs    RSA                 PKCS1v15 + SHA-256
    rsa_pss     RSA (same key!)     PSS + SHA-256  <- same key, diff padding
    ed25519     Ed25519             PureEdDSA
    """
    mapping = {
        "ecdsa":    "ecdsa",
        "rsa_pkcs": "rsa",
        "rsa_pss":  "rsa",    # ponytail: same RSA key, different padding in _sign()
        "ed25519":  "ed25519",
    }
    if sig_algo not in mapping:
        raise ValueError(f"Unknown sig_algo: {sig_algo!r}")
    return cache.issuer[mapping[sig_algo]]


def _leaf_key_for(
    leaf_key_algo: Optional[str] = None,
    leaf_key_size: Optional[int] = None,
    cache: Optional[_KeyCache] = None,
    weak: bool = False,
    sig_algo_fallback: Optional[str] = None,
):
    """
    Return the correct cached leaf key.

    Strict Invariant (RFC 5280): Leaf public key algorithm is decoupled from
    the CA's certificate signature algorithm.
    """
    if cache is None:
        raise ValueError("cache must be provided")

    # 1. Primary: explicitly specified leaf key algorithm and size
    if leaf_key_algo is not None:
        algo = str(leaf_key_algo).lower().strip()
        if algo == "rsa":
            if weak or leaf_key_size == 1024:
                return cache.leaf["rsa1024"]
            return cache.leaf["rsa2048"]
        elif algo == "ecdsa":
            return cache.leaf["ecdsa"]
        elif algo == "ed25519":
            return cache.leaf["ed25519"]
        else:
            raise ValueError(f"Unknown leaf_key_algo: {leaf_key_algo!r}")

    # 2. Secondary fallback for backward compatibility
    if weak or leaf_key_size == 1024:
        return cache.leaf["rsa1024"]

    if sig_algo_fallback:
        mapping = {
            "ecdsa":    "ecdsa",
            "rsa_pkcs": "rsa2048",
            "rsa_pss":  "rsa2048",
            "ed25519":  "ed25519",
        }
        if sig_algo_fallback in mapping:
            return cache.leaf[mapping[sig_algo_fallback]]

    # 3. Default fallback: standard RSA-2048
    return cache.leaf["rsa2048"]


# ---------------------------------------------------------------------------
# Public API: PKIFactory
# ---------------------------------------------------------------------------

class PKIFactory:
    """
    Main entry point for the testbed's PKI system.

    Lifecycle:
        1. __init__    -> load or generate permanent CA material on disk
        2. first call  -> _KeyCache is built (RSA keygen happens here, once)
        3. per scenario -> generate_cert_profile(...)

    pki_dir is the root of the testbed PKI directory (e.g. "testbed/pki").
    Permanent CA certs are stored under pki_dir/ca/.
    """

    def __init__(self, pki_dir: str = "testbed/pki"):
        self._pki_dir = pathlib.Path(pki_dir)
        ca_dir = self._pki_dir / "ca"
        ca_dir.mkdir(parents=True, exist_ok=True)

        # Load or generate permanent CA material.
        self.root_ca_key,  self.root_ca_cert  = self._load_or_create_ca(
            ca_dir, "root_ca",  "SecureMailScope Test Root CA"
        )
        self.rogue_ca_key, self.rogue_ca_cert = self._load_or_create_ca(
            ca_dir, "rogue_ca", "Rogue CA (not trusted)"
        )

        # ponytail: defer key cache until first generate_cert_profile call
        # so __init__ is fast when the CAs already exist on disk.
        self._cache: _KeyCache | None = None

    def _load_or_create_ca(self, ca_dir: pathlib.Path, name: str, cn: str):
        """
        If <name>.key and <name>.crt already exist on disk, load them.
        Otherwise generate a new ECDSA root CA and write them.

        Persisting to disk means re-running the batch runner does not
        invalidate previously captured PCAPs — the same root CA is reused
        so existing trust stores remain valid.
        """
        key_path = ca_dir / f"{name}.key"
        crt_path = ca_dir / f"{name}.crt"

        if key_path.exists() and crt_path.exists():
            key  = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
            return key, cert

        key  = _make_ecdsa_key()
        cert = _build_root_ca(cn, key)
        key_path.write_text(_pem(key))
        crt_path.write_text(_pem(cert))
        return key, cert

    @property
    def _keys(self) -> _KeyCache:
        """Lazy-initialize the key cache on first use."""
        if self._cache is None:
            self._cache = _KeyCache()
        return self._cache

    # ------------------------------------------------------------------
    # Per-scenario entry point
    # ------------------------------------------------------------------

    def materialize(self, pki_spec, output_dir: str | pathlib.Path) -> dict:
        """
        Materialize PKI artifacts for a given PKISpec into output_dir.
        Writes chain.pem and key.pem directly into output_dir.

        Parameters
        ----------
        pki_spec : PKISpec
            Normalized PKI specification containing sig_algo, validity,
            chain_shape, san_type, and weak_key.
        output_dir : str or Path
            Destination directory to stage chain.pem and key.pem.

        Returns
        -------
        dict:
            chain_file       Path to staged chain.pem
            key_file         Path to staged key.pem
            trust_store_pem  Trust store PEM string
            profile          Full generated profile dict
        """
        out_path = pathlib.Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        # ponytail: read PKISpec fields without coupling stager to generator internals
        profile = self.generate_cert_profile(
            sig_algo=pki_spec.sig_algo,
            validity=pki_spec.validity,
            chain_shape=pki_spec.chain_shape,
            san_type=pki_spec.san_type,
            weak_key=getattr(pki_spec, "weak_key", False),
            leaf_key_algo=getattr(pki_spec, "leaf_key_algo", None),
            leaf_key_size=getattr(pki_spec, "leaf_key_size", None),
        )
        chain_file = out_path / "chain.pem"
        key_file = out_path / "key.pem"
        trust_store_file = out_path / "trust_store.pem"
        chain_file.write_text(profile["chain_pem"])
        key_file.write_text(profile["key_pem"])
        trust_store_file.write_text(profile["trust_store_pem"])
        return {
            "chain_file": chain_file,
            "key_file": key_file,
            "trust_store_file": trust_store_file,
            "trust_store_pem": profile["trust_store_pem"],
            "profile": profile,
        }

    def generate_cert_profile(
        self,
        sig_algo: str,
        validity: str,
        chain_shape: str,
        san_type: str,
        weak_key: bool = False,
        leaf_key_algo: Optional[str] = None,
        leaf_key_size: Optional[int] = None,
    ) -> dict:
        """
        Generate the full PKI artifact set for one testbed scenario.

        Parameters
        ----------
        sig_algo : str
            Algorithm used by the intermediate to sign the leaf.
            One of: "ecdsa", "rsa_pkcs", "rsa_pss", "ed25519"

        validity : str
            Leaf certificate temporal state.
            One of: "valid", "expired", "not_yet_valid"

        chain_shape : str
            Chain topology / trust mutation to apply.

        san_type : str
            Subject Alternative Name content in the leaf.

        weak_key : bool
            True for 1024-bit RSA key.

        leaf_key_algo : str, optional
            Server's leaf public key algorithm ("rsa", "ecdsa", "ed25519").
            Decoupled from sig_algo per RFC 5280.

        leaf_key_size : int, optional
            Server's leaf key size (e.g. 2048, 1024).

        Returns
        -------
        dict:
            cert_pem         leaf certificate PEM
            key_pem          leaf private key PEM
            chain_pem        what the server sends (leaf [+ intermediate])
            trust_store_pem  PEM the validator uses as its trust anchor(s)
            intermediate_pem intermediate cert PEM (None if not applicable)
        """
        # --- Self-signed: no intermediate at all -------------------------
        if chain_shape in ("self_signed_trusted", "self_signed_untrusted"):
            return self._self_signed_profile(
                sig_algo, validity, san_type, chain_shape,
                weak_key=weak_key, leaf_key_algo=leaf_key_algo, leaf_key_size=leaf_key_size
            )

        # --- All other shapes: build intermediate + leaf -----------------
        issuer_key = _issuer_key_for(sig_algo, self._keys)

        # unknown_root: rogue CA signs the intermediate so the trusted root
        # won't anchor it -> UNKNOWN_ROOT_CA.
        # All other shapes: trusted root signs the intermediate.
        if chain_shape == "unknown_root":
            signing_ca_cert = self.rogue_ca_cert
            signing_ca_key  = self.rogue_ca_key
        else:
            signing_ca_cert = self.root_ca_cert
            signing_ca_key  = self.root_ca_key

        # Build the intermediate with any structural mutation.
        intermediate_cert = self._build_intermediate(
            chain_shape, issuer_key, signing_ca_cert, signing_ca_key
        )

        # tampered_sig: byte-flip the intermediate's signature AFTER generation.
        # The leaf is still signed by the unpatched intermediate key, so the
        # leaf cert itself is valid — only the intermediate's own cert is broken.
        if chain_shape == "tampered_sig":
            intermediate_pem_str = _der_to_pem(_tamper_signature(intermediate_cert))
        else:
            intermediate_pem_str = _pem(intermediate_cert)

        # Build the leaf cert. The leaf is always signed by the un-tampered
        # issuer_key (the cryptographic operation is valid). The tampered bytes
        # are only in the intermediate's cert DER, not in the leaf.
        # RFC 5280 Invariant: leaf_key is derived independently from leaf_key_algo/size,
        # with fallback to sig_algo if unspecified.
        leaf_key = _leaf_key_for(
            leaf_key_algo=leaf_key_algo,
            leaf_key_size=leaf_key_size,
            cache=self._keys,
            weak=weak_key,
            sig_algo_fallback=sig_algo,
        )
        leaf_cert = _build_leaf_cert(
            leaf_key, intermediate_cert, issuer_key, sig_algo, validity, san_type
        )

        # Assemble chain.pem.
        # leaf_only: intermediate exists (signed the leaf) but is not sent.
        # validator receives only the leaf, cannot walk to root ->
        # INCOMPLETE_CHAIN_MISSING_INTERMEDIATE.
        #
        # unknown_root: chain is Leaf + Intermediate only — no rogue root.
        # Real servers never send the root CA in the Certificate message.
        # The parser distinguishes UNKNOWN_ROOT_CA from INCOMPLETE_CHAIN by
        # checking WHERE the traversal stops: if the intermediate IS present
        # but its issuer (root) is not in the trust store → UNKNOWN_ROOT_CA.
        # If the intermediate itself is absent → INCOMPLETE_CHAIN.
        # The rogue root cert does not need to appear in the PCAP.
        if chain_shape == "leaf_only":
            chain_pem = _pem(leaf_cert)
        else:
            chain_pem = _pem(leaf_cert) + intermediate_pem_str

        # Trust store selection (see design table).
        # All non-self-signed scenarios use trusted_root.pem so the validator
        # can attempt full chain traversal and hit the specific failure point.
        # (If we used empty.pem for bad_constraint/tampered_sig/leaf_only,
        #  the validator would stop at UNKNOWN_ROOT_CA before reaching the
        #  intended failure.)
        trust_store_pem = _pem(self.root_ca_cert)

        return {
            "cert_pem":         _pem(leaf_cert),
            "key_pem":          _pem(leaf_key),
            "chain_pem":        chain_pem,
            "trust_store_pem":  trust_store_pem,
            "intermediate_pem": intermediate_pem_str,
        }

    # ------------------------------------------------------------------
    # Internal: intermediate builder
    # ------------------------------------------------------------------

    def _build_intermediate(
        self,
        chain_shape: str,
        issuer_key,
        signing_ca_cert: x509.Certificate,
        signing_ca_key,
    ) -> x509.Certificate:
        """
        Build the intermediate CA cert with the right chain_shape mutation.

        chain_shape         intermediate behaviour
        ─────────────────   ──────────────────────────────────────────────────
        complete            CA=TRUE, normal path_len=0
        unknown_root        CA=TRUE, signed by rogue CA instead of trusted root
        leaf_only           CA=TRUE (leaf was signed by it; we just don't
                            include this cert in chain.pem later)
        bad_constraint      CA=FALSE -> CA_CONSTRAINT_VIOLATION
        tampered_sig        CA=TRUE, but _tamper_signature() will corrupt it

        The intermediate is always signed by the signing CA's ECDSA key
        (root or rogue). The sig_algo param controls how the intermediate
        signs the leaf, which is resolved in _sign() at leaf-build time.
        """
        is_ca = (chain_shape != "bad_constraint")

        return _build_ca_cert(
            subject_cn        = "SecureMailScope Test Intermediate CA",
            subject_key       = issuer_key,
            issuer_name       = signing_ca_cert.subject,
            issuer_key        = signing_ca_key,
            sig_algo          = "ecdsa",   # root always signs intermediates with ECDSA
            is_ca             = is_ca,
            path_len          = 0,         # intermediate can only sign leaf certs
            issuer_public_key = signing_ca_cert.public_key(),
        )

    # ------------------------------------------------------------------
    # Internal: self-signed profile
    # ------------------------------------------------------------------

    def _self_signed_profile(
        self,
        sig_algo: str,
        validity: str,
        san_type: str,
        chain_shape: str,
        weak_key: bool = False,
        leaf_key_algo: Optional[str] = None,
        leaf_key_size: Optional[int] = None,
    ) -> dict:
        """
        Generate a self-signed leaf certificate profile.

        The leaf signs itself (issuer == subject, signed with its own key).
        No intermediate is generated or needed.

        Trust store:
            self_signed_trusted   -> trust store contains the leaf cert itself
                                     (the leaf IS the trust anchor)
            self_signed_untrusted -> empty trust store (no anchor -> UNTRUSTED)
        """
        # RFC 5280 Strict Invariant for Self-Signed Certificates:
        # Subject public key == signing key == certificate self-signature algorithm's key family.
        if sig_algo == "ecdsa":
            required_family = "ecdsa"
        elif sig_algo in ("rsa_pkcs", "rsa_pss"):
            required_family = "rsa"
        elif sig_algo == "ed25519":
            required_family = "ed25519"
        else:
            raise ValueError(f"Unknown sig_algo for self-signed profile: {sig_algo!r}")

        if leaf_key_algo is not None and leaf_key_algo.lower() != required_family:
            raise ValueError(
                f"Self-signed certificate signature/key incompatibility: requested "
                f"sig_algo '{sig_algo}' (family '{required_family}') but leaf_key_algo is '{leaf_key_algo}'."
            )

        leaf_key = _leaf_key_for(
            leaf_key_algo=required_family,
            leaf_key_size=leaf_key_size,
            cache=self._keys,
            weak=weak_key,
            sig_algo_fallback=sig_algo,
        )

        not_before, not_after = _validity_window(validity)
        san_ext = _san_extension(san_type)

        builder = (
            x509.CertificateBuilder()
            .subject_name(_subject_name(SERVER_HOSTNAME))
            .issuer_name(_subject_name(SERVER_HOSTNAME))   # self-signed
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(_basic_constraints(False), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(leaf_key.public_key()),
                critical=False,
            )
        )
        if san_ext is not None:
            builder = builder.add_extension(san_ext, critical=False)

        leaf_cert = _sign(builder, leaf_key, sig_algo)

        # self_signed_trusted: put the leaf cert directly in the trust store.
        # The validator finds: leaf is self-signed, root == leaf, leaf is in
        # trust store -> TRUSTED_SELF_SIGNED.
        #
        # self_signed_untrusted: empty trust store string.
        # The validator finds: leaf is self-signed, root not in store
        # -> UNTRUSTED_SELF_SIGNED.
        if chain_shape == "self_signed_trusted":
            trust_store_pem = _pem(leaf_cert)
        else:
            trust_store_pem = ""

        return {
            "cert_pem":         _pem(leaf_cert),
            "key_pem":          _pem(leaf_key),
            "chain_pem":        _pem(leaf_cert),   # no intermediate; send leaf only
            "trust_store_pem":  trust_store_pem,
            "intermediate_pem": None,
        }


# ---------------------------------------------------------------------------
# CLI: smoke-test the factory
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Run directly to:
      1. Generate (or reload) root_ca and rogue_ca under testbed/pki/ca/.
      2. Smoke-test a representative cross-section with real openssl verify.

    python testbed/pki/generator/make_certs.py
    """
    import subprocess
    import sys
    import tempfile

    # Resolve pki_dir relative to this file: two directories up = testbed/pki
    here    = pathlib.Path(__file__).resolve().parent
    pki_dir = here.parent

    print(f"PKI dir : {pki_dir}")
    factory = PKIFactory(pki_dir=str(pki_dir))
    print(f"Root CA : {factory.root_ca_cert.subject.rfc4514_string()}")
    print(f"Rogue CA: {factory.rogue_ca_cert.subject.rfc4514_string()}")
    print()

    def openssl_verify(chain_pem: str, trust_store_pem: str) -> tuple[bool, str]:
        """
        Run `openssl verify` on the leaf cert, using intermediates from chain_pem
        as untrusted chain material and trust_store_pem as the trust anchor.

        openssl verify -CAfile store.pem [-untrusted intermediates.pem] leaf.pem

        Passing intermediates via -untrusted tells openssl to USE them during
        path building without trusting them directly. Passing all certs as a
        single file instead verifies each cert independently — which is wrong.

        ponytail: subprocess + temp files. No pyOpenSSL dependency needed.
        """
        import re
        # Split chain.pem into individual PEM blocks (first = leaf, rest = intermediates).
        certs = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            chain_pem, re.DOTALL
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            leaf_f  = tmp / "leaf.pem"
            store_f = tmp / "store.pem"
            leaf_f.write_text(certs[0])
            store_f.write_text(trust_store_pem)

            cmd = ["openssl", "verify", "-CAfile", str(store_f)]

            # If there are intermediate/chain certs beyond the leaf, pass them
            # via -untrusted so openssl uses them during path building.
            if len(certs) > 1:
                untrusted_f = tmp / "untrusted.pem"
                untrusted_f.write_text("\n".join(certs[1:]))
                cmd += ["-untrusted", str(untrusted_f)]

            cmd.append(str(leaf_f))

            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0, (result.stdout + result.stderr).strip()

    # Each entry: (sig_algo, validity, chain_shape, san_type, expect_pass, label)
    # expect_pass=True  → openssl verify must exit 0 (chain is valid and trusted)
    # expect_pass=False → openssl verify must exit non-zero (deliberate failure)
    smoke_tests = [
        # --- Scenarios that must PASS openssl verify ---
        ("ecdsa",    "valid",         "complete",             "matched_dns",    True,  "PCAP-001 baseline (ECDSA, valid, complete chain)"),
        ("rsa_pkcs", "valid",         "complete",             "matched_dns",    True,  "PCAP-018 RSA-PKCS1v15"),
        ("rsa_pss",  "valid",         "complete",             "matched_dns",    True,  "PCAP-019 RSA-PSS"),
        ("ed25519",  "valid",         "complete",             "matched_dns",    True,  "PCAP-020 Ed25519"),
        ("ecdsa",    "valid",         "complete",             "mismatched_dns", True,  "PCAP-021 hostname mismatch (chain still valid; SNI check is separate)"),
        ("ecdsa",    "valid",         "complete",             "wildcard",       True,  "PCAP-117 wildcard SAN"),
        ("ecdsa",    "valid",         "complete",             "ip_san",         True,  "PCAP-116 IP SAN"),
        ("ecdsa",    "valid",         "complete",             "no_san",         True,  "PCAP-115 no SAN"),
        ("ecdsa",    "valid",         "self_signed_trusted",  "matched_dns",    True,  "PCAP-012 self-signed trusted (leaf IS trust anchor)"),

        # --- Scenarios that must FAIL openssl verify ---
        ("ecdsa",    "expired",       "complete",             "matched_dns",    False, "PCAP-010 expired cert"),
        ("ecdsa",    "not_yet_valid", "complete",             "matched_dns",    False, "PCAP-011 not-yet-valid cert"),
        ("ecdsa",    "valid",         "self_signed_untrusted","matched_dns",    False, "PCAP-013 self-signed untrusted (empty trust store)"),
        ("ecdsa",    "valid",         "unknown_root",         "matched_dns",    False, "PCAP-014 unknown root (rogue root not in trust store)"),
        ("ecdsa",    "valid",         "bad_constraint",       "matched_dns",    False, "PCAP-015 CA=FALSE intermediate"),
        ("ecdsa",    "valid",         "tampered_sig",         "matched_dns",    False, "PCAP-016 tampered intermediate signature"),
        ("ecdsa",    "valid",         "leaf_only",            "matched_dns",    False, "PCAP-017 leaf-only chain (intermediate missing)"),
    ]

    ok = fail = 0
    for sig_algo, validity, chain_shape, san_type, expect_pass, label in smoke_tests:
        try:
            p = factory.generate_cert_profile(sig_algo, validity, chain_shape, san_type)

            # For self_signed_untrusted the trust store is empty — openssl needs
            # at least a valid (possibly empty) file, so write "" and let it fail.
            trust = p["trust_store_pem"] or ""
            passed, output = openssl_verify(p["chain_pem"], trust)

            if passed == expect_pass:
                status = "OK  "
                ok += 1
            else:
                direction = "expected PASS got FAIL" if expect_pass else "expected FAIL got PASS"
                status = f"FAIL ({direction})"
                fail += 1

            print(f"  {status}  {label}")
            # Print openssl output only on unexpected results to keep noise low.
            if passed != expect_pass:
                for line in output.splitlines():
                    print(f"           {line}")

        except Exception as exc:
            print(f"  FAIL  {label}: {exc}")
            fail += 1

    print(f"\n{ok} passed, {fail} failed.")
    sys.exit(0 if fail == 0 else 1)

