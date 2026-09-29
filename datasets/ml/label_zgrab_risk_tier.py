"""Build a transparent three-tier proxy target from deterministic ZGrab findings."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "datasets" / "ml" / "processed" / "zgrab_smtp_v1.csv"
OUTPUT = ROOT / "datasets" / "ml" / "labels" / "zgrab_risk_tier_v1.csv"
FINDINGS = (
    "rule_flag_legacy_tls", "rule_flag_weak_cipher", "rule_flag_rsa_key_exchange",
    "rule_flag_cbc_cipher", "rule_flag_sha1_certificate",
    "rule_flag_weak_rsa_certificate", "rule_flag_certificate_identity",
)


def assign_tier(active: list[str]) -> tuple[str, str]:
    """Conservative severity proxy; CRITICAL is not split with only two examples."""
    if not active:
        return "LOW", "no_current_rule_flag"
    if "rule_flag_legacy_tls" in active or len(active) >= 2:
        return "HIGH", "legacy_tls_or_multiple_distinct_rule_flags"
    return "MEDIUM", "single_nonlegacy_rule_flag"


def build_labels() -> dict[str, int]:
    counts: Counter[str] = Counter()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with SOURCE.open(newline="", encoding="utf-8") as source, OUTPUT.open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        reader = csv.DictReader(source)
        missing = set(FINDINGS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"Missing deterministic finding fields: {sorted(missing)}")
        fields = (
            "record_id", "data_source", "country_group", "label_schema", "label_status",
            "risk_tier_proxy", "active_finding_count", "contributing_findings", "tier_reason",
        )
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for row in reader:
            state = row.get("tls_observation_state")
            base = {
                "record_id": row["record_id"],
                "data_source": row.get("data_source", "zgrab_real"),
                "country_group": row.get("country", "UNKNOWN"),
                "label_schema": "zgrab_rule_rubric_tier_v1",
            }
            if state != "HANDSHAKE_SUCCEEDED":
                writer.writerow({**base, "label_status": "NOT_EVALUABLE", "risk_tier_proxy": "", "active_finding_count": "", "contributing_findings": "", "tier_reason": "TLS handshake not observed"})
                continue
            active = [name for name in FINDINGS if row.get(name) == "1"]
            tier, reason = assign_tier(active)
            counts[tier] += 1
            writer.writerow({
                **base,
                "label_status": "LABELED_RULE_RUBRIC_PROXY",
                "risk_tier_proxy": tier,
                "active_finding_count": len(active),
                "contributing_findings": ";".join(active),
                "tier_reason": reason,
            })
    return dict(counts)


if __name__ == "__main__":
    print(build_labels())
