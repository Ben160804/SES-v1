"""Extract a provenance-preserving, certificate-only MTA-STS feature table."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "datasets" / "posture" / "mta-sts" / "stls_scans.zip"
OUTPUT = ROOT / "datasets" / "ml" / "processed" / "mta_sts_certificates_v1.csv"
METADATA = ROOT / "datasets" / "ml" / "metadata" / "mta_sts_certificates_v1.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _scan_time(value: str) -> datetime | None:
    normalized = value.strip().removesuffix(" UTC")
    normalized = re.sub(r"(\.\d{6})\d+", r"\1", normalized)
    try:
        parsed = datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S.%f %z")
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> Any | None:
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _features(cert: x509.Certificate, scanned_at: datetime | None, chain_length: int) -> dict[str, Any]:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        rsa_exponent = public_key.public_numbers().e
        ecdsa_curve = ""
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_algorithm = "ECDSA"
        rsa_exponent = ""
        ecdsa_curve = public_key.curve.name
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_algorithm, rsa_exponent, ecdsa_curve = "Ed25519", "", ""
    elif isinstance(public_key, ed448.Ed448PublicKey):
        key_algorithm, rsa_exponent, ecdsa_curve = "Ed448", "", ""
    else:
        key_algorithm, rsa_exponent, ecdsa_curve = type(public_key).__name__, "", ""

    san = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    dns_names = san.get_values_for_type(x509.DNSName) if san else []
    basic = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    eku = _extension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    key_usage = _extension(cert, ExtensionOID.KEY_USAGE)
    try:
        signature_hash = cert.signature_hash_algorithm.name
    except (AttributeError, UnsupportedAlgorithm):
        signature_hash = "unknown"

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    validity_days = (not_after - not_before).days
    remaining = (not_after - scanned_at).total_seconds() / 86400 if scanned_at else None
    expired = scanned_at > not_after if scanned_at else None
    not_yet_valid = scanned_at < not_before if scanned_at else None

    return {
        "key_algorithm": key_algorithm,
        "key_size_bits": getattr(public_key, "key_size", None),
        "rsa_exponent": rsa_exponent,
        "ecdsa_curve": ecdsa_curve,
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash": signature_hash,
        "certificate_validity_days": validity_days,
        "days_remaining_at_scan": round(remaining, 3) if remaining is not None else "",
        "expired_at_scan": expired if expired is not None else "",
        "not_yet_valid_at_scan": not_yet_valid if not_yet_valid is not None else "",
        "self_signed": cert.subject == cert.issuer,
        "san_count": len(san) if san else 0,
        "wildcard_san_count": sum(name.startswith("*.") for name in dns_names),
        "is_ca": basic.ca if basic else False,
        "path_length_constraint": basic.path_length if basic else "",
        "server_auth_eku": bool(eku and x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku),
        "client_auth_eku": bool(eku and x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku),
        "key_usage_digital_signature": key_usage.digital_signature if key_usage else "",
        "key_usage_key_encipherment": key_usage.key_encipherment if key_usage else "",
        "key_usage_key_agreement": key_usage.key_agreement if key_usage else "",
        "extension_count": len(cert.extensions),
        "has_ocsp_or_issuer_info": _extension(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS) is not None,
        "has_certificate_policies": _extension(cert, ExtensionOID.CERTIFICATE_POLICIES) is not None,
        "has_crl_distribution_points": _extension(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS) is not None,
        "has_authority_key_id": _extension(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER) is not None,
        "has_subject_key_id": _extension(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER) is not None,
        "chain_length_observed": chain_length,
    }


def extract() -> None:
    if not SOURCE.exists():
        raise FileNotFoundError(SOURCE)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    METADATA.parent.mkdir(parents=True, exist_ok=True)
    counts = {"source_records": 0, "rows_written": 0, "scan_success": 0, "certificate_parsed": 0, "certificate_parse_failed": 0, "malformed_rows_skipped": 0, "missing_certificate": 0, "non_success_scan_rows": 0, "bad_timestamp": 0}
    parse_errors: Counter[str] = Counter()
    fields = [
        "record_id", "certificate_group_id", "data_source", "source_file", "source_row",
        "scan_timestamp_utc", "scan_status", "scan_port", "chain_length_reported",
        "certificate_observed", "parse_status", "key_algorithm", "key_size_bits",
        "rsa_exponent", "ecdsa_curve", "signature_algorithm_oid", "signature_hash",
        "certificate_validity_days", "days_remaining_at_scan", "expired_at_scan",
        "not_yet_valid_at_scan", "self_signed", "san_count", "wildcard_san_count",
        "is_ca", "path_length_constraint", "server_auth_eku", "client_auth_eku",
        "key_usage_digital_signature", "key_usage_key_encipherment", "key_usage_key_agreement",
        "extension_count", "has_ocsp_or_issuer_info", "has_certificate_policies",
        "has_crl_distribution_points", "has_authority_key_id", "has_subject_key_id",
        "chain_length_observed",
    ]

    with zipfile.ZipFile(SOURCE) as archive, archive.open("stls_scans.txt") as raw, OUTPUT.open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        reader = csv.reader(io.TextIOWrapper(raw, encoding="utf-8", newline=""))
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for source_row, row in enumerate(reader, start=1):
            counts["source_records"] += 1
            row = [value.strip() for value in row]
            if len(row) < 7:
                counts["malformed_rows_skipped"] += 1
                continue
            timestamp = _scan_time(row[0])
            if timestamp is None:
                counts["bad_timestamp"] += 1
            try:
                port = int(row[3])
                chain_length = int(row[5])
            except ValueError:
                port, chain_length = "", 0
            status = row[4]
            if status.lower() == "success":
                counts["scan_success"] += 1
            encoded = row[6] if len(row) >= 7 and status.lower() == "success" else ""
            base = {
                "record_id": hashlib.sha256(f"{source_row}:{encoded}".encode()).hexdigest()[:24],
                "certificate_group_id": "",
                "data_source": "mta_sts_smtp_scan_certificate",
                "source_file": "stls_scans.zip:stls_scans.txt",
                "source_row": source_row,
                "scan_timestamp_utc": timestamp.isoformat() if timestamp else "",
                "scan_status": status,
                "scan_port": port,
                "chain_length_reported": chain_length,
                "certificate_observed": bool(encoded),
                "parse_status": "NO_CERTIFICATE" if not encoded else "PARSE_ERROR",
            }
            if not encoded:
                if status.lower() == "success":
                    counts["missing_certificate"] += 1
                else:
                    counts["non_success_scan_rows"] += 1
                    base["parse_status"] = "NOT_A_SUCCESS_CERTIFICATE_ROW"
            else:
                try:
                    cert_pem = base64.b64decode(encoded, validate=True)
                    cert = x509.load_pem_x509_certificate(cert_pem)
                    facts = _features(cert, timestamp, chain_length)
                    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                    base.update(facts)
                    base["certificate_group_id"] = fingerprint
                    base["parse_status"] = "PARSED"
                    counts["certificate_parsed"] += 1
                except Exception as exc:
                    base["parse_status"] = f"PARSE_ERROR:{type(exc).__name__}"
                    counts["certificate_parse_failed"] += 1
                    parse_errors[type(exc).__name__] += 1
            writer.writerow(base)
            counts["rows_written"] += 1

    metadata = {
        "dataset_id": "mta_sts_certificates_v1",
        "description": "Certificate-only features from SMTP/MTA-STS related scans; not full SMTP TLS handshake records.",
        "source_path": str(SOURCE.relative_to(ROOT)),
        "source_member": "stls_scans.txt",
        "source_sha256": _sha256(SOURCE),
        "counts": counts,
        "certificate_parse_error_types": dict(parse_errors),
        "model_feature_exclusions": [
            "record_id", "certificate_group_id", "data_source", "source_file", "source_row",
            "scan_timestamp_utc", "scan_status", "scan_port", "chain_length_reported",
            "certificate_observed", "parse_status",
        ],
        "limitations": [
            "The source contains SMTP-related scan certificates, not complete negotiated SMTP TLS sessions.",
            "Certificate parsing is not chain/path validation and does not establish endpoint identity correctness.",
            "Scan records and certificates may be repeated; group by certificate_group_id before train/test splitting.",
            "Expired status is evaluated at the recorded scan time, not the present date.",
            "Anomaly scores over this cohort indicate rarity only, not vulnerability or maliciousness.",
        ],
        "output_path": str(OUTPUT.relative_to(ROOT)),
        "schema_version": "1.0",
    }
    METADATA.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Source rows: {counts['source_records']}; output rows: {counts['rows_written']}; certificates parsed: {counts['certificate_parsed']}; malformed rows skipped: {counts['malformed_rows_skipped']}; certificate parse failures: {counts['certificate_parse_failed']}")
    print(f"Feature table: {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    extract()
