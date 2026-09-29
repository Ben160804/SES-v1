"""Create an explicitly rule-derived binary target for the ZGrab prototype."""

from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "datasets" / "ml" / "processed" / "zgrab_smtp_v1.csv"
OUTPUT = ROOT / "datasets" / "ml" / "labels" / "zgrab_risk_proxy_v1.csv"
FLAG_FIELDS = (
    "rule_flag_legacy_tls",
    "rule_flag_weak_cipher",
    "rule_flag_rsa_key_exchange",
    "rule_flag_cbc_cipher",
    "rule_flag_sha1_certificate",
    "rule_flag_weak_rsa_certificate",
    "rule_flag_certificate_identity",
)


def build_labels() -> tuple[int, int, int]:
    if not SOURCE.is_file():
        raise FileNotFoundError(f"Prepared dataset not found: {SOURCE}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    eligible = 0
    flagged = 0
    with SOURCE.open(newline="", encoding="utf-8") as source, OUTPUT.open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        reader = csv.DictReader(source)
        missing_fields = set(FLAG_FIELDS) - set(reader.fieldnames or ())
        if missing_fields:
            raise ValueError(f"Missing rule flags: {sorted(missing_fields)}")

        fields = (
            "record_id",
            "data_source",
            "label_schema",
            "label_status",
            "label",
            "flag_count",
            "contributing_flags",
        )
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()

        for row in reader:
            total += 1
            if row["tls_observation_state"] != "HANDSHAKE_SUCCEEDED":
                writer.writerow({
                    "record_id": row["record_id"],
                    "data_source": row["data_source"],
                    "label_schema": "rule_flag_proxy_v1",
                    "label_status": "NOT_EVALUABLE",
                    "label": "",
                    "flag_count": "",
                    "contributing_flags": "",
                })
                continue

            active = [name for name in FLAG_FIELDS if row[name] == "1"]
            label = "HAS_RULE_FLAGGED_ISSUE" if active else "NO_CURRENT_RULE_FLAG"
            eligible += 1
            flagged += bool(active)
            writer.writerow({
                "record_id": row["record_id"],
                "data_source": row["data_source"],
                "label_schema": "rule_flag_proxy_v1",
                "label_status": "LABELED_PROXY",
                "label": label,
                "flag_count": len(active),
                "contributing_flags": ";".join(active),
            })

    return total, eligible, flagged


if __name__ == "__main__":
    total, eligible, flagged = build_labels()
    print(f"Rows: {total}; TLS-labeled: {eligible}; has-rule-flag: {flagged}")
    print(f"Labels: {OUTPUT.relative_to(ROOT)}")
