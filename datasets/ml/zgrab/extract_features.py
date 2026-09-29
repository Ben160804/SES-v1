import csv
import json
from datetime import datetime, timezone
from pathlib import Path


INPUT_FILES = sorted(
    str(p) for p in Path("datasets/ml/zgrab").glob("zgrab_*.json")
)

OUTPUT = Path("datasets/ml/zgrab/zgrab_features.csv")


def get(d, *keys, default=None):
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
    return d


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def extract(row):
    smtp = get(row, "data", "smtp", default={}) or {}
    result = smtp.get("result") or {}

    tls = result.get("tls") or {}
    handshake = tls.get("handshake_log") or {}
    server_hello = handshake.get("server_hello") or {}

    certs = handshake.get("server_certificates") or {}
    cert = get(certs, "certificate", "parsed", default={}) or {}

    # TLS
    cipher = server_hello.get("cipher_suite") or {}
    key_share = server_hello.get("key_share") or {}

    version_obj = server_hello.get("version")
    tls_version = (
        version_obj.get("name")
        if isinstance(version_obj, dict)
        else version_obj
    )

    supported_versions = server_hello.get("supported_versions") or {}
    selected_version = (
        supported_versions.get("selected_version") or {}
    )

    extension_ids = server_hello.get("extension_identifiers") or []

    # Certificate
    ski = cert.get("subject_key_info") or {}
    rsa_key = ski.get("rsa_public_key") or {}
    ecdsa_key = ski.get("ecdsa_public_key") or {}

    extensions = cert.get("extensions") or {}
    san = extensions.get("subject_alt_name") or {}
    basic = extensions.get("basic_constraints") or {}
    eku = extensions.get("extended_key_usage") or {}
    key_usage = extensions.get("key_usage") or {}

    validity = cert.get("validity") or {}

    aia = extensions.get("authority_info_access") or {}
    policies = extensions.get("certificate_policies") or []
    scts = extensions.get("signed_certificate_timestamps") or []
    crl = extensions.get("crl_distribution_points") or []

    chain = certs.get("chain") or []

    # -------------------------
    # State
    # -------------------------

    tls_observed = bool(tls)
    certificate_observed = bool(cert)

    tls_success = bool(
        tls.get("handshake_completed_successfully")
    )

    # -------------------------
    # TLS
    # -------------------------

    cipher_name = cipher.get("name")
    cipher_upper = (cipher_name or "").upper()

    key_exchange = key_share.get("name")
    key_exchange_upper = (key_exchange or "").upper()

    tls_version_upper = (tls_version or "").upper()

    is_tls10 = tls_version_upper in {"TLSV1.0", "TLS1.0"}
    is_tls11 = tls_version_upper in {"TLSV1.1", "TLS1.1"}
    is_tls12 = tls_version_upper in {"TLSV1.2", "TLS1.2"}
    is_tls13 = tls_version_upper in {"TLSV1.3", "TLS1.3"}

    uses_ecdhe = "ECDHE" in cipher_upper
    uses_rsa_kex = (
        cipher_upper.startswith("TLS_RSA_")
        and "ECDHE" not in cipher_upper
    )
    uses_cbc = "CBC" in cipher_upper
    uses_aead = any(
        x in cipher_upper
        for x in ("GCM", "CHACHA20", "POLY1305")
    )

    # PFS only for ephemeral ECDHE/key-share style exchange.
    uses_forward_secrecy = uses_ecdhe or key_exchange_upper in {
        "X25519",
        "SECP256R1",
        "SECP384R1",
        "SECP521R1",
    }

    # Actual numeric ServerHello extension IDs observed in our data.
    ext_43 = 43 in extension_ids
    ext_51 = 51 in extension_ids
    ext_65281 = 65281 in extension_ids
    ext_11 = 11 in extension_ids
    ext_5 = 5 in extension_ids

    # -------------------------
    # Certificate
    # -------------------------

    cert_key_algorithm = (
        ski.get("key_algorithm", {}).get("name")
        if isinstance(ski.get("key_algorithm"), dict)
        else ski.get("key_algorithm")
    )

    rsa_key_size = rsa_key.get("length")
    rsa_exponent = rsa_key.get("exponent")

    ecdsa_key_size = ecdsa_key.get("length")
    ecdsa_curve = ecdsa_key.get("curve")

    signature_algorithm = (
        cert.get("signature_algorithm", {}).get("name")
        if isinstance(cert.get("signature_algorithm"), dict)
        else cert.get("signature_algorithm")
    )

    signature_upper = (signature_algorithm or "").upper()

    cert_sha1 = "SHA1" in signature_upper
    cert_sha256 = "SHA256" in signature_upper
    cert_sha384 = "SHA384" in signature_upper
    cert_sha512 = "SHA512" in signature_upper

    san_names = san.get("dns_names") or []
    san_count = len(san_names)

    has_wildcard_san = any(
        isinstance(x, str) and x.startswith("*.")
        for x in san_names
    )

    max_san_length = max(
        (len(x) for x in san_names if isinstance(x, str)),
        default=0,
    )

    unique_san_count = len(set(san_names))

    cert_self_signed = get(
        cert, "signature", "self_signed"
    )

    cert_is_ca = basic.get("is_ca")
    cert_server_auth = eku.get("server_auth")
    cert_client_auth = eku.get("client_auth")

    key_usage_count = sum(
        1
        for key, value in key_usage.items()
        if key != "value" and value is True
    ) if isinstance(key_usage, dict) else None

    digital_signature = (
        key_usage.get("digital_signature")
        if isinstance(key_usage, dict)
        else None
    )

    key_encipherment = (
        key_usage.get("key_encipherment")
        if isinstance(key_usage, dict)
        else None
    )

    key_agreement = (
        key_usage.get("key_agreement")
        if isinstance(key_usage, dict)
        else None
    )

    # -------------------------
    # Certificate validity
    # -------------------------

    scan_time = parse_time(
        smtp.get("timestamp") or row.get("timestamp")
    )

    validity_start = parse_time(validity.get("start"))
    validity_end = parse_time(validity.get("end"))

    validity_days = None
    days_remaining = None
    expired = None
    not_yet_valid = None

    if validity_start and validity_end:
        validity_days = (
            validity_end - validity_start
        ).total_seconds() / 86400

        reference = scan_time or datetime.now(timezone.utc)

        days_remaining = (
            validity_end - reference
        ).total_seconds() / 86400

        expired = days_remaining < 0
        not_yet_valid = reference < validity_start

    # -------------------------
    # Certificate infrastructure
    # -------------------------

    ocsp_urls = aia.get("ocsp_urls") or []
    issuer_urls = aia.get("issuer_urls") or []

    # -------------------------
    # Derived security flags
    # -------------------------

    legacy_tls = is_tls10 or is_tls11

    weak_rsa_key = (
        rsa_key_size is not None
        and rsa_key_size < 2048
    )

    weak_cipher = uses_cbc or uses_rsa_kex

    sha1_risk = cert_sha1

    certificate_identity_risk = any(
        x is True
        for x in (
            cert_self_signed,
            expired,
            not_yet_valid,
        )
    )

    # -------------------------
    # Feature vector
    # -------------------------

    return {
        # Metadata
        "ip": row.get("ip"),
        "port": smtp.get("port"),
        "scan_timestamp": smtp.get("timestamp"),

        # SMTP
        "smtp_status": smtp.get("status"),
        "smtp_protocol": smtp.get("protocol"),
        "banner_present": int(bool(result.get("banner"))),
        "ehlo_present": int(bool(result.get("ehlo"))),
        "starttls_present": int("starttls" in result),

        # TLS state
        "tls_observed": int(tls_observed),
        "tls_handshake_success": int(tls_success),

        # TLS raw
        "tls_version": tls_version if tls_observed else None,
        "tls_selected_version": (
            selected_version.get("name")
            if tls_observed
            else None
        ),
        "cipher_suite": cipher_name if tls_observed else None,
        "key_exchange": key_exchange if tls_observed else None,
        "ja3s": tls.get("ja3s") if tls_observed else None,

        # TLS handshake properties
        "tls_extension_count": (
            len(extension_ids) if tls_observed else None
        ),
        "tls_ext_43": int(ext_43) if tls_observed else None,
        "tls_ext_51": int(ext_51) if tls_observed else None,
        "tls_ext_65281": int(ext_65281) if tls_observed else None,
        "tls_ext_11": int(ext_11) if tls_observed else None,
        "tls_ext_5": int(ext_5) if tls_observed else None,

        "tls_ocsp_stapling": (
            int(bool(server_hello.get("ocsp_stapling")))
            if tls_observed else None
        ),
        "tls_ticket": (
            int(bool(server_hello.get("ticket")))
            if tls_observed else None
        ),
        "tls_secure_renegotiation": (
            int(bool(server_hello.get("secure_renegotiation")))
            if tls_observed else None
        ),
        "tls_heartbeat": (
            int(bool(server_hello.get("heartbeat")))
            if tls_observed else None
        ),
        "tls_extended_master_secret": (
            int(bool(server_hello.get("extended_master_secret")))
            if tls_observed else None
        ),
        "tls_session_id_present": (
            int(bool(server_hello.get("session_id")))
            if tls_observed else None
        ),

        # TLS derived
        "cipher_uses_aead": (
            int(uses_aead) if tls_observed else None
        ),
        "cipher_uses_cbc": (
            int(uses_cbc) if tls_observed else None
        ),
        "cipher_uses_rsa_kex": (
            int(uses_rsa_kex) if tls_observed else None
        ),
        "cipher_uses_ecdhe": (
            int(uses_ecdhe) if tls_observed else None
        ),
        "uses_forward_secrecy": (
            int(uses_forward_secrecy) if tls_observed else None
        ),

        "is_tls10": int(is_tls10) if tls_observed else None,
        "is_tls11": int(is_tls11) if tls_observed else None,
        "is_tls12": int(is_tls12) if tls_observed else None,
        "is_tls13": int(is_tls13) if tls_observed else None,
        "is_legacy_tls": (
            int(legacy_tls) if tls_observed else None
        ),

        # Certificate state
        "certificate_observed": int(certificate_observed),
        "browser_trusted": (
            get(certs, "validation", "browser_trusted")
            if certificate_observed else None
        ),

        # Certificate crypto
        "cert_key_algorithm": (
            cert_key_algorithm if certificate_observed else None
        ),
        "cert_rsa_key_size": (
            rsa_key_size if certificate_observed else None
        ),
        "cert_rsa_exponent": (
            rsa_exponent if certificate_observed else None
        ),
        "cert_ecdsa_key_size": (
            ecdsa_key_size if certificate_observed else None
        ),
        "cert_ecdsa_curve": (
            ecdsa_curve if certificate_observed else None
        ),
        "cert_signature_algorithm": (
            signature_algorithm if certificate_observed else None
        ),
        "cert_sha1_signature": (
            int(cert_sha1) if certificate_observed else None
        ),
        "cert_sha256_signature": (
            int(cert_sha256) if certificate_observed else None
        ),
        "cert_sha384_signature": (
            int(cert_sha384) if certificate_observed else None
        ),
        "cert_sha512_signature": (
            int(cert_sha512) if certificate_observed else None
        ),

        # Certificate validation
        "cert_validation_level": (
            cert.get("validation_level")
            if certificate_observed else None
        ),
        "cert_self_signed": (
            cert_self_signed if certificate_observed else None
        ),

        # SAN
        "cert_san_count": (
            san_count if certificate_observed else None
        ),
        "cert_has_wildcard_san": (
            int(has_wildcard_san) if certificate_observed else None
        ),
        "cert_max_san_length": (
            max_san_length if certificate_observed else None
        ),
        "cert_unique_san_count": (
            unique_san_count if certificate_observed else None
        ),

        # Certificate constraints / usage
        "cert_is_ca": (
            cert_is_ca if certificate_observed else None
        ),
        "cert_server_auth": (
            cert_server_auth if certificate_observed else None
        ),
        "cert_client_auth": (
            cert_client_auth if certificate_observed else None
        ),
        "cert_digital_signature": (
            digital_signature if certificate_observed else None
        ),
        "cert_key_encipherment": (
            key_encipherment if certificate_observed else None
        ),
        "cert_key_agreement": (
            key_agreement if certificate_observed else None
        ),
        "cert_key_usage_count": (
            key_usage_count if certificate_observed else None
        ),
        "cert_extension_count": (
            len(extensions) if certificate_observed else None
        ),

        # Certificate validity
        "cert_validity_days": (
            validity_days if certificate_observed else None
        ),
        "cert_days_remaining": (
            days_remaining if certificate_observed else None
        ),
        "cert_expired": (
            int(expired) if expired is not None else None
        ),
        "cert_not_yet_valid": (
            int(not_yet_valid) if not_yet_valid is not None else None
        ),

        # Certificate chain
        "cert_chain_length": (
            len(chain) if certificate_observed else None
        ),

        # Certificate infrastructure
        "cert_ocsp_url_count": (
            len(ocsp_urls) if certificate_observed else None
        ),
        "cert_issuer_url_count": (
            len(issuer_urls) if certificate_observed else None
        ),
        "cert_has_ocsp": (
            int(bool(ocsp_urls)) if certificate_observed else None
        ),
        "cert_policy_count": (
            len(policies) if certificate_observed else None
        ),
        "cert_has_certificate_policy": (
            int(bool(policies)) if certificate_observed else None
        ),
        "cert_sct_count": (
            len(scts) if certificate_observed else None
        ),
        "cert_has_sct": (
            int(bool(scts)) if certificate_observed else None
        ),
        "cert_crl_url_count": (
            len(crl) if certificate_observed else None
        ),
        "cert_has_crl_distribution": (
            int(bool(crl)) if certificate_observed else None
        ),
        "cert_has_authority_key_id": (
            int(bool(extensions.get("authority_key_id")))
            if certificate_observed else None
        ),
        "cert_has_subject_key_id": (
            int(bool(extensions.get("subject_key_id")))
            if certificate_observed else None
        ),

        # Security findings / derived flags
        "risk_legacy_tls": (
            int(legacy_tls) if tls_observed else None
        ),
        "risk_weak_cipher": (
            int(weak_cipher) if tls_observed else None
        ),
        "risk_rsa_key_exchange": (
            int(uses_rsa_kex) if tls_observed else None
        ),
        "risk_cbc_cipher": (
            int(uses_cbc) if tls_observed else None
        ),
        "risk_sha1_certificate": (
            int(sha1_risk) if certificate_observed else None
        ),
        "risk_weak_rsa_certificate": (
            int(weak_rsa_key) if certificate_observed else None
        ),
        "risk_certificate_identity": (
            int(certificate_identity_risk)
            if certificate_observed else None
        ),

        # Protocol outcome
        "smtp_plaintext_only": int(
            bool(result)
            and not tls_observed
            and "starttls" not in result
        ),
        "smtp_starttls_to_tls_success": int(
            "starttls" in result and tls_success
        ),
    }


def main():
    rows = []

    for filename in INPUT_FILES:
        path = Path(filename)

        if not path.exists():
            print(f"WARNING: missing {path}")
            continue

        with path.open() as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    row = json.loads(line)
                    rows.append(extract(row))
                except Exception as e:
                    print(
                        f"ERROR parsing row in {path} "
                        f"line {line_number}: {e}"
                    )

    if not rows:
        raise SystemExit("No observations extracted.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(rows[0].keys())

    with OUTPUT.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Extracted observations : {len(rows)}")
    print(f"Features               : {len(fieldnames)}")
    print(f"Output                 : {OUTPUT}")


if __name__ == "__main__":
    main()
