"""Explainable deterministic posture rubric; intentionally separate from ML."""

from __future__ import annotations

from typing import Any


RUBRIC_VERSION = "deterministic_posture_v1"
TIER_THRESHOLDS = ((90, "LOW"), (75, "MODERATE"), (50, "HIGH"), (0, "CRITICAL"))

REMEDIATION = {
    "protocol": (25, "HIGH", "Disable TLS 1.0/1.1; require TLS 1.2 or newer and prefer TLS 1.3."),
    "cipher": (20, "HIGH", "Restrict negotiation to currently approved AEAD cipher suites and remove obsolete suites."),
    "key_exchange": (15, "MEDIUM", "Prefer ephemeral ECDHE key exchange with supported modern groups; disable static RSA key exchange."),
    "certificate": (20, "HIGH", "Renew or reissue the certificate as indicated by the finding; verify validity, identity, chain, key strength, and signature algorithm."),
    "cleartext_session": (35, "HIGH", "Require encrypted transport for mail access and submission; do not permit cleartext fallback."),
    "cleartext_auth": (60, "CRITICAL", "Immediately disable authentication before TLS; require a successful encrypted session before accepting credentials."),
    "starttls": (20, "HIGH", "Require successful STARTTLS where policy expects it; investigate rejection, stripping, or client fallback."),
    "policy_other": (10, "MEDIUM", "Review the cited policy failure and configure the service to meet the selected cryptographic profile."),
}


def _value(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def _policy_family(rule_id: str) -> str:
    rule = rule_id.upper()
    if "CIPHER" in rule or "-SYM-" in rule:
        return "cipher"
    if "KEX" in rule or "-DH-" in rule:
        return "key_exchange"
    if "CERT" in rule or "HASH" in rule or "SIG" in rule or "RSA" in rule:
        return "certificate"
    if "TLS" in rule or "PROTO" in rule:
        return "protocol"
    if "PSK" in rule:
        return "key_exchange"
    return "policy_other"


def assess_posture(
    policy_results: dict[str, list[Any]],
    observations: list[Any],
) -> dict[str, Any]:
    """Summarize deterministic failures into a non-calibrated 0-100 heuristic."""
    grouped: dict[str, dict[str, Any]] = {}

    def record(family: str, evidence: dict[str, Any]) -> None:
        penalty, severity, recommendation = REMEDIATION[family]
        entry = grouped.setdefault(family, {
            "family": family,
            "severity": severity,
            "penalty": penalty,
            "recommendation": recommendation,
            "evidence": [],
        })
        entry["evidence"].append(evidence)

    evaluable = False
    for policy, results in policy_results.items():
        for result in results:
            verdict = str(_value(result, "verdict", ""))
            if verdict in ("PASS", "FAIL"):
                evaluable = True
            if verdict != "FAIL":
                continue
            rule_id = str(_value(result, "rule_id", ""))
            family = _policy_family(rule_id)
            record(family, {
                "source": "policy",
                "policy": policy,
                "rule_id": rule_id,
                "name": _value(result, "name", ""),
                "finding": _value(result, "finding", ""),
                "evidence": [
                    _value(evidence, "to_dict", lambda: evidence)()
                    if callable(_value(evidence, "to_dict")) else evidence
                    for evidence in (_value(result, "evidence", []) or [])
                ],
            })

    observation_families = {
        "OBS-SEC-PLAINTEXT-AUTH": "cleartext_auth",
        "OBS-STARTTLS-01": "cleartext_session",
        "OBS-STARTTLS-ADVERTISED-NOT-USED": "starttls",
        "OBS-STARTTLS-03": "starttls",
        "OBS-CERT-HOSTNAME-MISMATCH": "certificate",
    }
    for observation in observations:
        if not _value(observation, "detected", False):
            continue
        evaluable = True
        obs_id = str(_value(observation, "obs_id", ""))
        family = observation_families.get(obs_id)
        if family:
            record(family, {
                "source": "observation",
                "obs_id": obs_id,
                "name": _value(observation, "name", ""),
                "description": _value(observation, "description", ""),
                "evidence": [
                    evidence.to_dict() if hasattr(evidence, "to_dict") else evidence
                    for evidence in (_value(observation, "evidence", []) or [])
                ],
            })

    if not evaluable:
        return {
            "rubric_version": RUBRIC_VERSION,
            "status": "NOT_EVALUABLE",
            "score": None,
            "tier": "NOT_EVALUABLE",
            "score_type": "DETERMINISTIC_HEURISTIC_NOT_CALIBRATED",
            "findings": [],
            "limitations": ["No policy verdict or security observation was evaluable."],
        }

    penalties = sum(item["penalty"] for item in grouped.values())
    score = max(0, 100 - penalties)
    tier = next(name for minimum, name in TIER_THRESHOLDS if score >= minimum)
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings = sorted(grouped.values(), key=lambda item: (priority_order[item["severity"]], item["family"]))
    return {
        "rubric_version": RUBRIC_VERSION,
        "status": "ASSESSED",
        "score": score,
        "tier": tier,
        "score_type": "DETERMINISTIC_HEURISTIC_NOT_CALIBRATED",
        "scoring_method": "100 minus the maximum fixed penalty once per distinct finding family; floor at zero.",
        "tier_thresholds": {name: minimum for minimum, name in TIER_THRESHOLDS},
        "findings": findings,
        "limitations": [
            "This score is a transparent heuristic, not a probability, ML prediction, compliance certification, or breach likelihood.",
            "Policy-pack failures can represent profile non-conformance; use cited policy and evidence to interpret each finding.",
            "Multiple findings in one family are listed but incur only one family penalty to avoid policy-pack duplication.",
        ],
    }
