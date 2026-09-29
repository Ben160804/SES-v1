"""Evidence-gated KEV/EPSS enrichment for explicitly identified CVEs."""

from __future__ import annotations

import csv
import gzip
import re
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
KEV_PATH = ROOT / "datasets" / "threat-intelligence" / "kev" / "known_exploited_vulnerabilities.csv"
EPSS_PATH = ROOT / "datasets" / "threat-intelligence" / "epss" / "epss_scores-2026-09-26.csv.gz"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}\Z", re.IGNORECASE)


@lru_cache(maxsize=4)
def _load_kev(path_text: str, mtime_ns: int) -> dict[str, dict[str, str]]:
    del mtime_ns
    with Path(path_text).open(newline="", encoding="utf-8-sig") as source:
        return {row["cveID"].upper(): row for row in csv.DictReader(source) if row.get("cveID")}


@lru_cache(maxsize=4)
def _load_epss(path_text: str, mtime_ns: int) -> dict[str, dict[str, str]]:
    del mtime_ns
    with gzip.open(path_text, "rt", newline="", encoding="utf-8") as source:
        first = source.readline()
        while first.startswith("#"):
            first = source.readline()
        return {
            row["cve"].upper(): row
            for row in csv.DictReader(chain([first], source))
            if row.get("cve")
        }


def prioritize_cves(cve_ids: Iterable[str]) -> dict:
    """Rank only supplied CVE identifiers; never infer CVEs from crypto facts."""
    normalized = set()
    for value in cve_ids:
        cve = str(value).strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise ValueError(f"Invalid CVE identifier: {value}")
        normalized.add(cve)
    if not normalized:
        return {
            "status": "NO_CVE_MAPPING",
            "items": [],
            "note": "No CVE was explicitly linked to the observed finding; no vulnerability match was inferred.",
        }

    kev = _load_kev(str(KEV_PATH), KEV_PATH.stat().st_mtime_ns) if KEV_PATH.exists() else {}
    epss = _load_epss(str(EPSS_PATH), EPSS_PATH.stat().st_mtime_ns) if EPSS_PATH.exists() else {}
    results = []
    for cve in sorted(normalized):
        kev_row = kev.get(cve)
        epss_row = epss.get(cve)
        probability = float(epss_row["epss"]) if epss_row and epss_row.get("epss") else None
        if kev_row:
            priority = "KNOWN_EXPLOITED"
        elif probability is None:
            priority = "UNRANKED"
        elif probability >= 0.5:
            priority = "VERY_HIGH"
        elif probability >= 0.1:
            priority = "HIGH"
        elif probability >= 0.01:
            priority = "MODERATE"
        else:
            priority = "LOW"
        results.append({
            "cve_id": cve,
            "priority": priority,
            "kev": None if not kev_row else {
                "listed": True,
                "date_added": kev_row.get("dateAdded"),
                "due_date": kev_row.get("dueDate"),
                "required_action": kev_row.get("requiredAction"),
                "known_ransomware_campaign_use": kev_row.get("knownRansomwareCampaignUse"),
            },
            "epss": None if probability is None else {
                "probability": probability,
                "percentile": float(epss_row["percentile"]) if epss_row.get("percentile") else None,
                "snapshot": EPSS_PATH.name,
            },
            "priority_method": "KEV membership takes precedence; otherwise EPSS probability bands (>=0.50 very high, >=0.10 high, >=0.01 moderate).",
        })
    results.sort(key=lambda item: (
        {"KNOWN_EXPLOITED": 0, "VERY_HIGH": 1, "HIGH": 2, "MODERATE": 3, "LOW": 4, "UNRANKED": 5}[item["priority"]],
        -(item["epss"]["probability"] if item["epss"] else -1),
        item["cve_id"],
    ))
    return {
        "status": "ENRICHED",
        "source_policy": "CVE identifiers must be explicitly associated with a finding by another evidence-backed component.",
        "items": results,
    }
