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


FINDING_TITLES = {
    "cleartext_auth": "Credentials attempted before TLS",
    "cleartext_session": "Mail session continued without encryption",
    "starttls": "STARTTLS negotiation weakness",
    "protocol": "Deprecated TLS protocol",
    "cipher": "Weak or deprecated cipher configuration",
    "key_exchange": "Weak key exchange configuration",
    "certificate": "Certificate security or validation issue",
    "policy_other": "Cryptographic policy failure",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
PRIORITY_BY_SEVERITY = {
    "CRITICAL": ("P1", "Immediate"),
    "HIGH": ("P2", "High"),
    "MEDIUM": ("P3", "Moderate"),
    "LOW": ("P4", "Low"),
}


def _rule_family(rule_id: str) -> str:
    rule = rule_id.upper()
    if "CIPHER" in rule or "-SYM-" in rule:
        return "cipher"
    if "KEX" in rule or "-DH-" in rule or "PSK" in rule:
        return "key_exchange"
    if "CERT" in rule or "HASH" in rule or "SIG" in rule or "RSA" in rule:
        return "certificate"
    if "TLS" in rule or "PROTO" in rule:
        return "protocol"
    return "policy_other"


def _explicit_cves(value: object) -> set[str]:
    """Read only structured CVE links; never infer CVEs from free text or crypto facts."""
    if not isinstance(value, dict):
        return set()
    raw = value.get("cve_ids")
    if not isinstance(raw, (list, tuple, set)):
        return set()
    return {
        str(candidate).strip().upper()
        for candidate in raw
        if CVE_PATTERN.fullmatch(str(candidate).strip().upper())
    }


def prioritize_report(report: dict, source_name: str = "") -> dict:
    """Prioritize one saved PCAP from deterministic posture evidence and scope."""
    stream_reports = report.get("stream_reports", {})
    if not isinstance(stream_reports, dict):
        stream_reports = {}

    grouped: dict[str, dict] = {}
    analyzed_streams = 0
    streams_with_findings: set[int] = set()
    cve_links: dict[str, set[str]] = {}

    def add_finding(stream_id: int, family: str, severity: str, recommendation: str, evidence: object, cves: set[str]) -> None:
        family = family if family in FINDING_TITLES else "policy_other"
        severity = severity.upper()
        if severity not in PRIORITY_BY_SEVERITY:
            severity = "MEDIUM"
        item = grouped.setdefault(family, {
            "family": family,
            "title": FINDING_TITLES[family],
            "severity": severity,
            "recommendation": recommendation or "Review the cited deterministic finding and remediate the observed configuration.",
            "streams": set(),
            "evidence": [],
            "cve_ids": set(),
        })
        item["streams"].add(stream_id)
        item["cve_ids"].update(cves)
        item["evidence"].append({"stream_id": stream_id, "details": evidence})
        streams_with_findings.add(stream_id)
        for cve in cves:
            cve_links.setdefault(cve, set()).add(family)

    for stream_key, stream in stream_reports.items():
        if not isinstance(stream, dict):
            continue
        try:
            stream_id = int(stream.get("stream_id", stream_key))
        except (TypeError, ValueError):
            continue
        analyzed_streams += 1
        posture = stream.get("posture_assessment")
        posture = posture if isinstance(posture, dict) else {}
        posture_findings = posture.get("findings")
        posture_findings = posture_findings if isinstance(posture_findings, list) else []
        represented: set[str] = set()
        for finding in posture_findings:
            if not isinstance(finding, dict):
                continue
            family = str(finding.get("family") or "policy_other")
            represented.add(family)
            cves = _explicit_cves(finding)
            evidence = finding.get("evidence", [])
            if isinstance(evidence, list):
                for evidence_item in evidence:
                    cves.update(_explicit_cves(evidence_item))
            add_finding(
                stream_id,
                family,
                str(finding.get("severity") or "MEDIUM"),
                str(finding.get("recommendation") or ""),
                evidence,
                cves,
            )

        # Older stored reports may not have a posture summary. Retain their
        # deterministic FAIL results and the rule evidence without ML inference.
        if not posture_findings:
            policy_results = stream.get("policy_results")
            if isinstance(policy_results, dict):
                for policy, results in policy_results.items():
                    if not isinstance(results, list):
                        continue
                    for result in results:
                        if not isinstance(result, dict) or str(result.get("verdict", "")).upper() != "FAIL":
                            continue
                        family = _rule_family(str(result.get("rule_id") or ""))
                        if family in represented:
                            continue
                        represented.add(family)
                        evidence = result.get("evidence", [])
                        cves = _explicit_cves(result)
                        if isinstance(evidence, list):
                            for evidence_item in evidence:
                                cves.update(_explicit_cves(evidence_item))
                        add_finding(
                            stream_id,
                            family,
                            "HIGH",
                            "",
                            {
                                "policy": policy,
                                "rule_id": result.get("rule_id"),
                                "name": result.get("name"),
                                "finding": result.get("finding"),
                                "evidence": evidence,
                            },
                            cves,
                        )

    cve_enrichment = prioritize_cves(sorted(cve_links))
    enriched_by_cve = {
        item["cve_id"]: item
        for item in cve_enrichment.get("items", [])
        if isinstance(item, dict) and item.get("cve_id")
    }
    items = []
    for finding in grouped.values():
        severity = finding["severity"]
        priority_code, priority_label = PRIORITY_BY_SEVERITY[severity]
        affected = sorted(finding["streams"])
        cves = sorted(finding["cve_ids"])
        items.append({
            "priority": priority_code,
            "priority_label": priority_label,
            "severity": severity,
            "family": finding["family"],
            "title": finding["title"],
            "affected_streams": affected,
            "affected_stream_count": len(affected),
            "evidence_count": sum(
                len(item["details"]) if isinstance(item.get("details"), list) else 1
                for item in finding["evidence"]
            ),
            "evidence": finding["evidence"],
            "recommendation": finding["recommendation"],
            "cve_ids": cves,
            "cve_enrichment": [enriched_by_cve[cve] for cve in cves if cve in enriched_by_cve],
            "priority_basis": "Deterministic severity first; number of affected streams breaks ties. This is a triage ordering, not a probability of exploitation.",
        })
    items.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]],
        -item["affected_stream_count"],
        item["title"],
    ))
    for rank, item in enumerate(items, start=1):
        item["rank"] = rank

    return {
        "status": "PRIORITIZED" if items else "NO_PRIORITIZED_FINDINGS",
        "source_name": source_name,
        "total_streams": analyzed_streams,
        "streams_with_findings": len(streams_with_findings),
        "items": items,
        "cve_enrichment": cve_enrichment,
        "cve_link_policy": "KEV/EPSS is applied only to structured CVE identifiers explicitly linked to finding evidence. No CVE is inferred from TLS versions, cipher suites, or certificate properties.",
        "note": None if items else "No deterministic priority findings were recorded. Missing or unobservable evidence must not be interpreted as proof of safety.",
    }
