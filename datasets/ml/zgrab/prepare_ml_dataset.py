"""Prepare immutable ZGrab observations for downstream ML experiments."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from extract_features import extract


ROOT = Path(__file__).resolve().parents[3]
RAW_DIR = ROOT / "datasets" / "ml" / "zgrab"
OUTPUT_DIR = ROOT / "datasets" / "ml" / "processed"
METADATA_DIR = ROOT / "datasets" / "ml" / "metadata"
OUTPUT_CSV = OUTPUT_DIR / "zgrab_smtp_v1.csv"
OUTPUT_METADATA = METADATA_DIR / "zgrab_smtp_v1.json"

IDENTIFIER_FIELDS = {"ip", "scan_timestamp", "ja3s"}
RULE_FLAG_PREFIX = "risk_"
STATE_FIELDS = (
    "record_id",
    "data_source",
    "source_file",
    "source_row",
    "country",
    "smtp_observation_state",
    "starttls_observation_state",
    "tls_observation_state",
    "certificate_observation_state",
)


def _country_from_filename(filename: str) -> str:
    parts = Path(filename).stem.split("_")
    country_parts = [part for part in parts if part not in {"zgrab", "587"}]
    return "_".join(country_parts)


def _observation_states(features: dict[str, Any]) -> tuple[str, str, str, str]:
    smtp_status = str(features.get("smtp_status") or "").lower()
    starttls = features.get("starttls_present") == 1
    tls_observed = features.get("tls_observed") == 1
    handshake_success = features.get("tls_handshake_success") == 1
    certificate_observed = features.get("certificate_observed") == 1

    if smtp_status != "success":
        smtp_state = "SMTP_PROBE_FAILED"
    else:
        smtp_state = "SMTP_RESPONSE_OBSERVED"

    if handshake_success:
        starttls_state = "TLS_HANDSHAKE_SUCCEEDED"
    elif starttls:
        starttls_state = "STARTTLS_OBSERVED_NO_COMPLETED_TLS"
    else:
        starttls_state = "STARTTLS_NOT_OBSERVED"

    if handshake_success:
        tls_state = "HANDSHAKE_SUCCEEDED"
    elif tls_observed:
        tls_state = "TLS_OBSERVED_HANDSHAKE_INCOMPLETE"
    else:
        tls_state = "TLS_NOT_OBSERVED"

    if certificate_observed:
        cert_state = "CERTIFICATE_OBSERVED"
    elif not tls_observed:
        cert_state = "CERTIFICATE_NOT_OBSERVED_NO_TLS"
    elif not handshake_success:
        cert_state = "CERTIFICATE_NOT_OBSERVED_INCOMPLETE_HANDSHAKE"
    else:
        cert_state = "CERTIFICATE_NOT_OBSERVED"

    return smtp_state, starttls_state, tls_state, cert_state


def _iter_records(paths: list[Path]):
    for path in paths:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON at {path.name}:{line_number}") from exc
                if not isinstance(raw, dict):
                    raise ValueError(f"Expected a JSON object at {path.name}:{line_number}")
                yield path, line_number, raw


def prepare() -> tuple[int, dict[str, Any]]:
    paths = sorted(RAW_DIR.glob("zgrab_*.json"))
    if not paths:
        raise FileNotFoundError(f"No raw ZGrab JSONL files in {RAW_DIR}")

    records: list[dict[str, Any]] = []
    ips: set[str] = set()
    sources: dict[str, dict[str, Any]] = {}
    smtp_states: Counter[str] = Counter()
    starttls_states: Counter[str] = Counter()
    tls_states: Counter[str] = Counter()
    certificate_states: Counter[str] = Counter()
    feature_fields: list[str] | None = None

    for path, line_number, raw in _iter_records(paths):
        features = extract(raw)
        if feature_fields is None:
            feature_fields = [
                name for name in features
                if name not in IDENTIFIER_FIELDS
            ]

        smtp_state, starttls_state, tls_state, cert_state = _observation_states(features)
        smtp_states[smtp_state] += 1
        starttls_states[starttls_state] += 1
        tls_states[tls_state] += 1
        certificate_states[cert_state] += 1

        ip = raw.get("ip")
        if ip:
            ips.add(str(ip))

        source_name = path.name
        source = sources.setdefault(
            source_name,
            {"country": _country_from_filename(source_name), "records": 0},
        )
        source["records"] += 1

        record = {
            "record_id": f"{source_name}:{line_number}",
            "data_source": "zgrab_real",
            "source_file": source_name,
            "source_row": line_number,
            "country": source["country"],
            "smtp_observation_state": smtp_state,
            "starttls_observation_state": starttls_state,
            "tls_observation_state": tls_state,
            "certificate_observation_state": cert_state,
        }

        for name in feature_fields:
            value = features.get(name)
            # Rename derived rule outcomes so they cannot be mistaken for raw
            # observations or included accidentally in classifier features.
            if name.startswith(RULE_FLAG_PREFIX):
                name = "rule_flag_" + name[len(RULE_FLAG_PREFIX):]
            elif name == "smtp_plaintext_only":
                name = "smtp_no_starttls_or_tls_observed"
            elif name == "smtp_starttls_to_tls_success":
                name = "smtp_starttls_tls_observed"
            record[name] = value

        records.append(record)

    if feature_fields is None or not records:
        raise ValueError("No valid ZGrab observations were extracted")
    fields = list(records[0])
    if len({row["record_id"] for row in records}) != len(records):
        raise ValueError("Generated record_id values are not unique")
    if any(field in fields for field in IDENTIFIER_FIELDS):
        raise ValueError("An identifier field leaked into the prepared table")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    metadata = {
        "dataset_id": "zgrab_smtp_v1",
        "schema_version": 1,
        "data_source": "real-world active ZGrab2 SMTP observations",
        "record_count": len(records),
        "unique_ip_count_for_audit_only": len(ips),
        "feature_count_including_states_and_metadata": len(fields),
        "input_files": {
            name: {
                **details,
                "sha256": hashlib.sha256((RAW_DIR / name).read_bytes()).hexdigest(),
            }
            for name, details in sorted(sources.items())
        },
        "observation_state_counts": {
            "smtp": dict(sorted(smtp_states.items())),
            "starttls": dict(sorted(starttls_states.items())),
            "tls": dict(sorted(tls_states.items())),
            "certificate": dict(sorted(certificate_states.items())),
        },
        "handling": {
            "raw_files_modified": False,
            "removed_from_prepared_table": sorted(IDENTIFIER_FIELDS),
            "ip_values_retained": False,
            "scan_timestamp_retained": False,
            "ja3s_retained": False,
            "missing_values": "Preserved as empty CSV cells; interpret with explicit observation-state columns.",
            "rule_flags": "Renamed rule_flag_* and excluded from ML feature inputs by default.",
            "grouping_and_provenance_fields": [
                "record_id", "data_source", "source_file", "source_row", "country"
            ],
            "model_feature_policy": "Choose a task-specific feature allowlist. Exclude provenance/grouping fields and all rule_flag_* fields unless a deliberate ablation is being run.",
            "risk_label": None,
            "warning": "This dataset has no independent ground-truth risk labels. Do not treat rule flags as independent labels or model features.",
        },
        "feature_fields": fields,
        "output_csv": str(OUTPUT_CSV.relative_to(ROOT)),
    }
    OUTPUT_METADATA.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return len(records), metadata


if __name__ == "__main__":
    try:
        row_count, summary = prepare()
    except (AssertionError, FileNotFoundError, ValueError) as exc:
        print(f"Dataset preparation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Prepared {row_count} records: {summary['output_csv']}")
    print(f"Metadata: {OUTPUT_METADATA.relative_to(ROOT)}")
