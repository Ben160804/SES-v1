"""Optional cohort-aware ML observations for normalized PCAP sessions.

ML output is advisory, keeps its source cohort visible, and never changes a
rule-engine result. Classifier, anomaly, rarity, and certificate outputs remain
independent so consumers can inspect their different semantics.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from .ml_artifacts import LoadedModel, ModelArtifactError, load_model


SMTP_CATEGORICAL = (
    "tls_version", "cipher_suite", "key_exchange", "cert_key_algorithm",
    "cert_ecdsa_curve", "cert_signature_algorithm",
)
SMTP_NUMERIC = (
    "tls_extension_count", "cert_rsa_key_size", "cert_ecdsa_key_size", "cert_chain_length",
)
CERT_CATEGORICAL = (
    "key_algorithm", "ecdsa_curve", "signature_hash", "signature_algorithm_oid",
    "self_signed", "is_ca", "server_auth_eku", "client_auth_eku",
    "key_usage_digital_signature", "key_usage_key_encipherment",
    "key_usage_key_agreement", "has_ocsp_or_issuer_info", "has_certificate_policies",
    "has_crl_distribution_points", "has_authority_key_id", "has_subject_key_id",
)
CERT_NUMERIC = (
    "key_size_bits", "certificate_validity_days", "san_count", "wildcard_san_count",
    "extension_count", "chain_length_observed",
)
EMAIL_RISK_CATEGORICAL = (
    "protocol", "starttls_status", "tls_negotiated_version", "cipher_suite",
    "key_exchange", "cipher_strength", "cert_key_algorithm",
    "cert_signature_algorithm", "cert_trust_status", "cert_hostname_match",
    "cert_validity_state",
)
EMAIL_RISK_NUMERIC = (
    "tls_extension_count", "cert_key_size", "cert_san_count", "cert_chain_length",
)

RISK_PROXY_CATEGORICAL = (
    "tls_negotiated_version", "tls_version", "tls_selected_version", "cipher_suite", "key_exchange",
    "tls_ext_43", "tls_ext_51", "tls_ext_65281", "tls_ext_11", "tls_ext_5",
    "tls_ocsp_stapling", "tls_ticket", "tls_secure_renegotiation",
    "tls_heartbeat", "tls_extended_master_secret", "tls_session_id_present",
    "cert_key_algorithm", "cert_ecdsa_curve", "cert_signature_algorithm",
    "cert_validation_level", "cert_self_signed", "cert_is_ca",
    "cert_server_auth", "cert_client_auth", "cert_digital_signature",
    "cert_key_encipherment", "cert_key_agreement", "cert_expired",
    "cert_not_yet_valid", "cert_has_wildcard_san", "cert_has_ocsp",
    "cert_has_certificate_policy", "cert_has_sct", "cert_has_crl_distribution",
    "cert_has_authority_key_id", "cert_has_subject_key_id",
)
RISK_PROXY_NUMERIC = (
    "tls_extension_count", "cert_rsa_key_size", "cert_rsa_exponent",
    "cert_ecdsa_key_size", "cert_san_count", "cert_max_san_length",
    "cert_unique_san_count", "cert_key_usage_count", "cert_extension_count",
    "cert_validity_days", "cert_days_remaining", "cert_chain_length",
    "cert_ocsp_url_count", "cert_issuer_url_count", "cert_policy_count",
    "cert_sct_count", "cert_crl_url_count",
)


@lru_cache(maxsize=4)
def _model(model_id: str) -> LoadedModel:
    return load_model(model_id)


def _tls_version(value: Any) -> str:
    if value is None:
        return ""
    value = str(value).strip()
    match = re.search(r"TLS\s*v?(1\.[0-3])", value, flags=re.IGNORECASE)
    if match:
        return f"TLSv{match.group(1)}"
    return value


def _raw_version(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    mapping = {"0x0301": "TLSv1.0", "0x0302": "TLSv1.1", "0x0303": "TLSv1.2", "0x0304": "TLSv1.3"}
    return mapping.get(text, _tls_version(value))


def _signature_name(value: Any) -> str:
    text = str(value or "").upper().replace("_", "-")
    compact = re.sub(r"[^A-Z0-9]", "", text)
    for digest in ("SHA1", "SHA256", "SHA384", "SHA512"):
        if digest in compact and "RSA" in compact:
            return f"{digest}-RSA"
        if digest in compact and ("ECDSA" in compact or "EC" in compact):
            return f"ECDSA-{digest}"
    if "ED25519" in compact:
        return "ED25519"
    if "ED448" in compact:
        return "ED448"
    return text


def _session_facts(session: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    tls = session.get("tls") or {}
    handshake = session.get("handshake") or {}
    negotiation = handshake.get("server_negotiation") or {}
    ske = negotiation.get("tls12_server_key_exchange") or {}
    certificate = session.get("certificate") or {}
    leaf = certificate.get("leaf_cert") or {}
    pk_alg = str(leaf.get("public_key_algorithm") or "")
    if pk_alg.upper() in ("EC", "ECDSA", "ELLIPTICCURVEPUBLICKEY"):
        pk_alg = "ECDSA"
    elif pk_alg:
        pk_alg = pk_alg.upper()
    group = (
        tls.get("tls13_key_exchange_group")
        or ske.get("named_curve")
        or ske.get("kex_type")
        or tls.get("key_exchange")
        or ""
    )
    raw_version = tls.get("raw_version") or negotiation.get("raw_version")
    selected_version = negotiation.get("selected_tls_version") or tls.get("tls_version")
    selected_version = _tls_version(selected_version)
    negotiated_version = selected_version or _raw_version(raw_version)
    observation = {
        "tls_version": _raw_version(raw_version) if raw_version else negotiated_version,
        "tls_negotiated_version": negotiated_version,
        "tls_selected_version": selected_version,
        "cipher_suite": tls.get("cipher_name") or "",
        "key_exchange": str(group),
        "cert_key_algorithm": pk_alg,
        "cert_ecdsa_curve": str(leaf.get("ecdsa_curve") or ""),
        "cert_signature_algorithm": _signature_name(leaf.get("signature_algorithm_name")),
        "tls_extension_count": "",
        "cert_rsa_key_size": "",
        "cert_ecdsa_key_size": "",
        "cert_chain_length": str(certificate.get("chain_length") or ""),
    }
    try:
        key_size = int(leaf.get("public_key_size"))
    except (ValueError, TypeError):
        key_size = None
    if pk_alg == "RSA":
        observation["cert_rsa_key_size"] = str(key_size) if key_size else ""
    elif pk_alg == "ECDSA":
        observation["cert_ecdsa_key_size"] = str(key_size) if key_size else ""
    return observation, {"tls": tls, "certificate": certificate, "leaf": leaf, "ske": ske}


def _smtp_feature_dict(row: dict[str, str]) -> dict[str, Any]:
    features: dict[str, Any] = {
        key: row.get(key) or "__MISSING__" for key in SMTP_CATEGORICAL
    }
    features["tls_negotiated_version"] = (
        row.get("tls_negotiated_version")
        or row.get("tls_selected_version")
        or row.get("tls_version")
        or "__MISSING__"
    )
    for key in SMTP_NUMERIC:
        value = row.get(key, "")
        try:
            features[key] = float(value) if value else 0.0
            features[f"{key}__missing"] = 0.0 if value else 1.0
        except ValueError:
            features[key] = 0.0
            features[f"{key}__missing"] = 1.0
    return features


def _certificate_features(row: dict[str, Any]) -> tuple[dict[str, Any], list[float]]:
    features: dict[str, Any] = {
        key: (str(row.get(key)) if row.get(key) is not None and row.get(key) != "" else "__MISSING__")
        for key in CERT_CATEGORICAL
    }
    numeric_values: list[float] = []
    for key in CERT_NUMERIC:
        value = row.get(key, "")
        try:
            numeric = float(value) if value != "" else 0.0
            missing = value == ""
            numeric_values.extend((numeric, 1.0 if missing else 0.0))
            features[key] = numeric
            features[f"{key}__missing"] = 1.0 if missing else 0.0
        except (TypeError, ValueError):
            numeric_values.extend((0.0, 1.0))
            features[key] = 0.0
            features[f"{key}__missing"] = 1.0
    return features, numeric_values


def _certificate_row(facts: dict[str, Any]) -> dict[str, Any] | None:
    certificate = facts["certificate"]
    leaf = facts["leaf"]
    if not leaf:
        return None
    algorithm = str(leaf.get("public_key_algorithm") or "")
    algorithm = "ECDSA" if algorithm.upper() in ("EC", "ECDSA") else algorithm.upper()
    san_dns = leaf.get("san_dns") or []
    san_ip = leaf.get("san_ip") or []
    basic = leaf.get("basic_constraints") or {}
    key_usage = leaf.get("key_usage") or {}
    eku = leaf.get("extended_key_usage") or []
    def parse_dt(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    before = parse_dt(leaf.get("not_before"))
    after = parse_dt(leaf.get("not_after"))
    validity = (after - before).total_seconds() / 86400 if after and before else ""
    oid = str(leaf.get("signature_algorithm_oid") or "")
    ext_access = leaf.get("authority_information_access")
    try:
        key_size = int(leaf.get("public_key_size"))
    except (TypeError, ValueError):
        key_size = ""
    return {
        "key_algorithm": algorithm,
        "key_size_bits": key_size,
        "rsa_exponent": leaf.get("public_key_exponent", ""),
        "ecdsa_curve": leaf.get("ecdsa_curve", ""),
        "signature_algorithm_oid": oid,
        "signature_hash": str(leaf.get("signature_hash_algorithm") or "unknown").lower(),
        "certificate_validity_days": validity,
        "days_remaining_at_scan": "",
        "expired_at_scan": "",
        "not_yet_valid_at_scan": "",
        "self_signed": leaf.get("is_self_signed", certificate.get("is_self_signed", "")),
        "san_count": len(san_dns) + len(san_ip),
        "wildcard_san_count": sum(str(name).startswith("*.") for name in san_dns),
        "is_ca": basic.get("ca", ""),
        "path_length_constraint": basic.get("path_length", ""),
        "server_auth_eku": (
            "serverAuth" in eku or "1.3.6.1.5.5.7.3.1" in eku
            if leaf.get("extended_key_usage_present") is not False else ""
        ),
        "client_auth_eku": (
            "clientAuth" in eku or "1.3.6.1.5.5.7.3.2" in eku
            if leaf.get("extended_key_usage_present") is not False else ""
        ),
        "key_usage_digital_signature": key_usage.get("digital_signature", ""),
        "key_usage_key_encipherment": key_usage.get("key_encipherment", ""),
        "key_usage_key_agreement": key_usage.get("key_agreement", ""),
        "extension_count": leaf.get("extension_count", ""),
        "has_ocsp_or_issuer_info": (
            int(leaf.get("ocsp_url_count", 0) or 0) + int(leaf.get("issuer_url_count", 0) or 0) > 0
            if "ocsp_url_count" in leaf or "issuer_url_count" in leaf
            else bool(ext_access) if ext_access is not None else ""
        ),
        "has_certificate_policies": leaf.get("has_certificate_policy", ""),
        "has_crl_distribution_points": leaf.get("has_crl_distribution", ""),
        "has_authority_key_id": leaf.get("has_authority_key_id", ""),
        "has_subject_key_id": leaf.get("has_subject_key_id", ""),
        "ocsp_url_count": leaf.get("ocsp_url_count", ""),
        "issuer_url_count": leaf.get("issuer_url_count", ""),
        "policy_count": leaf.get("policy_count", ""),
        "sct_count": leaf.get("sct_count", ""),
        "crl_url_count": leaf.get("crl_url_count", ""),
        "san_dns": san_dns,
        "san_ip": san_ip,
        "key_usage": key_usage,
        "chain_length_observed": certificate.get("chain_length", ""),
    }


def _email_risk_features(session: dict[str, Any]) -> dict[str, Any]:
    """Canonical evidence-only feature vector shared by training and runtime."""
    facts, context = _session_facts(session)
    certificate = context["certificate"]
    leaf = context["leaf"]
    tls = context["tls"]
    starttls = session.get("starttls") or {}
    values: dict[str, Any] = {
        "protocol": str(session.get("protocol") or "__MISSING__").upper(),
        "starttls_status": str(starttls.get("status") or "__MISSING__"),
        "tls_negotiated_version": facts.get("tls_negotiated_version") or "__MISSING__",
        "cipher_suite": facts.get("cipher_suite") or "__MISSING__",
        "key_exchange": facts.get("key_exchange") or "__MISSING__",
        "cipher_strength": str(tls.get("cipher_strength") or "__MISSING__"),
        "cert_key_algorithm": str(leaf.get("public_key_algorithm") or "__MISSING__").upper(),
        "cert_signature_algorithm": _signature_name(leaf.get("signature_algorithm_name")) or "__MISSING__",
        "cert_trust_status": str(certificate.get("trust_status") or "__MISSING__"),
        "cert_hostname_match": str(certificate.get("hostname_match") or "__MISSING__"),
        "cert_validity_state": (
            "EXPIRED" if leaf.get("is_expired") is True else
            "NOT_YET_VALID" if leaf.get("not_yet_valid") is True else
            "VALID" if leaf and leaf.get("is_expired") is False and leaf.get("not_yet_valid") is False else
            "__MISSING__"
        ),
    }
    try:
        values["cert_key_size"] = float(leaf.get("public_key_size"))
        values["cert_key_size__missing"] = 0.0
    except (TypeError, ValueError):
        values["cert_key_size"] = 0.0
        values["cert_key_size__missing"] = 1.0
    san = (leaf.get("san_dns") or []) + (leaf.get("san_ip") or [])
    values["cert_san_count"] = float(len(san)) if leaf else 0.0
    values["cert_san_count__missing"] = 0.0 if leaf else 1.0
    for name, raw in (
        ("tls_extension_count", tls.get("tls_extension_count")),
        ("cert_chain_length", certificate.get("chain_length")),
    ):
        try:
            values[name] = float(raw)
            values[f"{name}__missing"] = 0.0
        except (TypeError, ValueError):
            values[name] = 0.0
            values[f"{name}__missing"] = 1.0
    return values


def _classify_synthetic_email_risk(session: dict[str, Any]) -> dict[str, Any]:
    model_id = "synthetic_email_posture_classifier_v2"
    try:
        loaded = _model(model_id)
        features = _email_risk_features(session)
        categorical = loaded.metadata["categorical_features"]
        numeric = loaded.metadata["numeric_features"]
        observed = sum(features[name] != "__MISSING__" for name in categorical)
        observed += sum(features[f"{name}__missing"] == 0.0 for name in numeric)
        total = len(categorical) + len(numeric)
        coverage = observed / total if total else 0.0
        coverage_floor = float(loaded.metadata.get("runtime_feature_observability", {}).get("p05_training_fraction", 0.0))
        if coverage < coverage_floor:
            return {
                "model_id": loaded.model_id,
                "model_version": loaded.metadata.get("model_version"),
                "status": "NOT_EVALUABLE_LOW_FEATURE_COVERAGE",
                "reason": "Observed fields are below the fifth-percentile coverage of the synthetic training cohort.",
                "feature_coverage": coverage,
                "training_p05_floor": coverage_floor,
                "data_source": loaded.metadata.get("data_source", "synthetic_simulation"),
                "cross_cohort_transfer_status": "NOT_VALIDATED",
            }
        model = loaded.payload["model"]
        scores = model.predict_proba([features])[0]
        classes = [str(label) for label in model.classes_]
        class_scores = {label: float(scores[i]) for i, label in enumerate(classes)}
        prediction = str(model.predict([features])[0])
        return {
            "model_id": loaded.model_id,
            "model_name": loaded.metadata.get("algorithm"),
            "model_version": loaded.metadata.get("model_version"),
            "feature_schema_version": loaded.metadata.get("feature_schema_version"),
            "status": "COMPLETED_EXPERIMENTAL_NOT_VALIDATED",
            "prediction": prediction,
            "predicted_risk_tier": prediction,
            "class_scores_uncalibrated": class_scores,
            "confidence_score_uncalibrated": max(class_scores.values()),
            "score_semantics": "Uncalibrated class scores; not probabilities of compromise.",
            "feature_coverage": coverage,
            "feature_observability": {"observed_fields": observed, "candidate_fields": total, "fraction": coverage},
            "data_source": loaded.metadata.get("data_source", "synthetic_simulation"),
            "training_sample_count": loaded.metadata.get("sample_count"),
            "evaluation_status": "CONTROLLED_SYNTHETIC_HELDOUT_ONLY",
            "heldout_test_metrics": loaded.metadata.get("test_metrics"),
            "cohort": "10,000 programmatically simulated SMTP/IMAP/POP3 feature sessions",
            "cross_cohort_transfer_status": "NOT_VALIDATED",
            "target_semantics": loaded.metadata.get("target_semantics"),
            "limitations": loaded.metadata.get("limitations", []),
            "authority_note": "Synthetic endpoint-posture estimate only; it cannot change or override deterministic Rule Engine findings.",
        }
    except ModelArtifactError as exc:
        return {"model_id": model_id, "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
    except Exception as exc:
        return {"model_id": model_id, "status": "MODEL_ERROR", "reason": type(exc).__name__}


def _classify_zgrab_evidence_risk(session: dict[str, Any]) -> dict[str, Any]:
    model_id = "zgrab_evidence_risk_classifier_v1"
    try:
        loaded = _model(model_id)
        features = _email_risk_features(session)
        categorical = loaded.metadata["categorical_features"]
        numeric = loaded.metadata["numeric_features"]
        observed = sum(features[name] != "__MISSING__" for name in categorical)
        observed += sum(features[f"{name}__missing"] == 0.0 for name in numeric)
        total = len(categorical) + len(numeric)
        coverage = observed / total if total else 0.0
        floor = float(loaded.metadata.get("runtime_feature_observability", {}).get("p05_training_fraction", 0.0))
        observability = {"observed_fields": observed, "candidate_fields": total, "fraction": coverage, "training_p05_floor": floor}
        if coverage < floor:
            return {
                "model_id": loaded.model_id,
                "model_version": loaded.metadata.get("model_version"),
                "status": "NOT_EVALUABLE_LOW_FEATURE_COVERAGE",
                "feature_coverage": coverage,
                "feature_observability": observability,
                "reason": "Observed evidence is below the fifth-percentile floor in the ZGrab training cohort.",
                "data_source": "zgrab_real",
                "cross_cohort_transfer_status": "NOT_VALIDATED",
            }
        model = loaded.payload["model"]
        raw_scores = model.predict_proba([features])[0]
        classes = [str(label) for label in model.classes_]
        class_scores = {label: float(raw_scores[i]) for i, label in enumerate(classes)}
        prediction = str(model.predict([features])[0])
        return {
            "model_id": loaded.model_id,
            "model_name": loaded.metadata.get("algorithm"),
            "model_version": loaded.metadata.get("model_version"),
            "feature_schema_version": loaded.metadata.get("feature_schema_version"),
            "status": "COMPLETED_ADVISORY_RUBRIC_ESTIMATE",
            "prediction": prediction,
            "predicted_risk_tier": prediction,
            "class_scores_uncalibrated": class_scores,
            "confidence_score_uncalibrated": max(class_scores.values()),
            "score_semantics": "Uncalibrated agreement score for the documented observed-evidence rubric; not a probability of compromise or independent vulnerability truth.",
            "feature_coverage": coverage,
            "feature_observability": observability,
            "data_source": "zgrab_real",
            "reference_cohort": "real active ZGrab SMTP observations",
            "training_sample_count": loaded.metadata.get("sample_count"),
            "evaluation": loaded.metadata.get("test_metrics"),
            "target_semantics": loaded.metadata.get("target_semantics"),
            "cross_cohort_transfer_status": "NOT_VALIDATED",
            "limitations": loaded.metadata.get("limitations", []),
            "authority_note": "Advisory classifier for a project-defined evidence rubric. Rule Engine findings and posture are separate and authoritative.",
        }
    except ModelArtifactError as exc:
        return {"model_id": model_id, "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
    except Exception as exc:
        return {"model_id": model_id, "status": "MODEL_ERROR", "reason": type(exc).__name__}


def _risk_proxy_features(observation: dict[str, Any], cert: dict[str, Any]) -> dict[str, Any]:
    """Build the training-time ZGrab proxy-classifier schema from PCAP evidence."""
    source = dict(observation)
    source.update(cert)
    source["tls_negotiated_version"] = observation.get("tls_negotiated_version") or observation.get("tls_selected_version") or observation.get("tls_version", "")
    # Certificate names differ slightly between parser telemetry and the ZGrab
    # feature table; map only observed facts and leave unsupported fields missing.
    source["cert_has_ocsp"] = int(cert.get("ocsp_url_count", 0) or 0) > 0 if "ocsp_url_count" in cert else ""
    source["cert_has_certificate_policy"] = cert.get("has_certificate_policies", "")
    source["cert_has_crl_distribution"] = cert.get("has_crl_distribution_points", "")
    source["cert_has_authority_key_id"] = cert.get("has_authority_key_id", "")
    source["cert_has_subject_key_id"] = cert.get("has_subject_key_id", "")
    source["cert_has_sct"] = bool(cert.get("sct_count", 0)) if cert.get("sct_count") != "" else ""
    source["cert_has_wildcard_san"] = bool(cert.get("wildcard_san_count", 0)) if cert.get("wildcard_san_count") != "" else ""
    source["cert_server_auth"] = cert.get("server_auth_eku", "")
    source["cert_client_auth"] = cert.get("client_auth_eku", "")
    source["cert_is_ca"] = cert.get("is_ca", "")
    source["cert_self_signed"] = cert.get("self_signed", "")
    source["cert_digital_signature"] = cert.get("key_usage_digital_signature", "")
    source["cert_key_encipherment"] = cert.get("key_usage_key_encipherment", "")
    source["cert_key_agreement"] = cert.get("key_usage_key_agreement", "")
    source["cert_rsa_key_size"] = cert.get("key_size_bits", "") if cert.get("key_algorithm") == "RSA" else ""
    source["cert_ecdsa_key_size"] = cert.get("key_size_bits", "") if cert.get("key_algorithm") == "ECDSA" else ""
    source["cert_validity_days"] = cert.get("certificate_validity_days", "")
    source["cert_chain_length"] = cert.get("chain_length_observed", "")
    source["cert_rsa_exponent"] = cert.get("rsa_exponent", "")
    san_names = (cert.get("san_dns") or []) + (cert.get("san_ip") or [])
    source["cert_san_count"] = cert.get("san_count", "")
    source["cert_max_san_length"] = max((len(str(name)) for name in san_names), default=0) if san_names else ""
    source["cert_unique_san_count"] = len({str(name).lower() for name in san_names}) if san_names else ""
    usage = cert.get("key_usage") or {}
    source["cert_key_usage_count"] = sum(value is True for value in usage.values()) if usage else ""
    source["cert_extension_count"] = cert.get("extension_count", "")
    source["cert_ocsp_url_count"] = cert.get("ocsp_url_count", "")
    source["cert_issuer_url_count"] = cert.get("issuer_url_count", "")
    source["cert_policy_count"] = cert.get("policy_count", "")
    source["cert_sct_count"] = cert.get("sct_count", "")
    source["cert_crl_url_count"] = cert.get("crl_url_count", "")
    result: dict[str, Any] = {}
    for name in RISK_PROXY_CATEGORICAL:
        value = source.get(name)
        result[name] = str(value) if value is not None and value != "" else "__MISSING__"
    for name in RISK_PROXY_NUMERIC:
        value = source.get(name)
        try:
            result[name] = float(value) if value is not None and value != "" else 0.0
            result[f"{name}__missing"] = 0.0 if value is not None and value != "" else 1.0
        except (TypeError, ValueError):
            result[name] = 0.0
            result[f"{name}__missing"] = 1.0
    return result


def _classify_rule_flag_proxy(observation: dict[str, Any], cert: dict[str, Any] | None) -> dict[str, Any]:
    model_id = "zgrab_runtime_rule_flag_proxy_v2"
    if not observation.get("tls_negotiated_version") or not observation.get("cipher_suite"):
        return _not_evaluable(model_id, "A negotiated TLS version and cipher are required.")
    if cert is None:
        return _not_evaluable(model_id, "The training cohort contains TLS handshakes with certificate observations; no leaf certificate is available.")
    try:
        loaded = _model(model_id)
        model = loaded.payload
        features = _risk_proxy_features(observation, cert)
        categorical = loaded.metadata["categorical_features"]
        numeric = loaded.metadata["numeric_features"]
        observed_feature_count = sum(features[name] != "__MISSING__" for name in categorical)
        observed_feature_count += sum(features[f"{name}__missing"] == 0.0 for name in numeric)
        total_feature_count = len(categorical) + len(numeric)
        coverage = observed_feature_count / total_feature_count if total_feature_count else 0.0
        coverage_floor = float(loaded.metadata["runtime_feature_observability"]["p05_training_fraction"])
        observability = {
            "observed_fields": observed_feature_count,
            "candidate_fields": total_feature_count,
            "fraction": coverage,
            "training_p05_floor": coverage_floor,
        }
        if coverage < coverage_floor:
            return {
                "model_id": loaded.model_id,
                "status": "NOT_EVALUABLE_LOW_FEATURE_COVERAGE",
                "reason": "Observed feature coverage is below the fifth-percentile coverage in the training cohort.",
                "feature_observability": observability,
                "feature_coverage": coverage,
                "model_version": loaded.metadata.get("model_version"),
                "data_source": loaded.metadata.get("data_source", "zgrab_real"),
                "target_semantics": loaded.metadata.get("target_semantics"),
                "cross_cohort_transfer_status": "NOT_VALIDATED",
            }
        predicted = str(model.predict([features])[0])
        probabilities = model.predict_proba([features])[0]
        classes = list(model.classes_)
        positive = "HAS_RULE_FLAGGED_ISSUE"
        score = float(probabilities[classes.index(positive)])
        return {
            "model_id": loaded.model_id,
            "model_name": loaded.metadata.get("algorithm", loaded.metadata.get("model")),
            "model_version": loaded.metadata.get("model_version"),
            "feature_schema_version": loaded.metadata.get("feature_schema_version"),
            "status": "COMPLETED_EXPLORATORY_PROXY_ESTIMATE",
            "predicted_class": predicted,
            "prediction": predicted,
            "proxy_issue_score": score,
            "confidence_score_uncalibrated": float(max(probabilities)),
            "score_semantics": "Uncalibrated model score; not probability of compromise or independent vulnerability evidence.",
            "feature_observability": {
                **observability,
            },
            "feature_coverage": coverage,
            "target_semantics": loaded.metadata.get("target_semantics"),
            "data_source": "zgrab_real",
            "reference_sample_count": loaded.metadata.get("sample_count"),
            "evaluation": {
                "method": loaded.metadata.get("evaluation"),
                "macro_f1": loaded.metadata.get("macro_f1"),
                "sample_count": loaded.metadata.get("sample_count"),
            },
            "reference_cohort": "real active ZGrab SMTP TLS handshakes",
            "cross_cohort_transfer_status": "NOT_VALIDATED",
            "limitations": loaded.metadata.get("limitations", []),
            "authority_note": "Supplementary exploratory output only. The label proxies current rule flags, and transfer from active ZGrab observations to passive PCAP telemetry is not validated. Deterministic findings and posture remain authoritative and are returned independently.",
        }
    except (ModelArtifactError, KeyError, ValueError) as exc:
        return {"model_id": model_id, "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
    except Exception as exc:
        return {"model_id": model_id, "status": "MODEL_ERROR", "reason": type(exc).__name__}


def _classify_risk_tier(observation: dict[str, Any], cert: dict[str, Any] | None) -> dict[str, Any]:
    model_id = "zgrab_runtime_risk_tier_v1"
    if not observation.get("tls_negotiated_version") or not observation.get("cipher_suite"):
        return _not_evaluable(model_id, "Negotiated TLS version and cipher are required.")
    if cert is None:
        return _not_evaluable(model_id, "A leaf certificate is required by the training feature cohort.")
    try:
        loaded = _model(model_id)
        features = _risk_proxy_features(observation, cert)
        categorical = loaded.metadata["categorical_features"]
        numeric = loaded.metadata["numeric_features"]
        observed = sum(features[name] != "__MISSING__" for name in categorical)
        observed += sum(features[f"{name}__missing"] == 0.0 for name in numeric)
        candidate_count = len(categorical) + len(numeric)
        coverage = observed / candidate_count if candidate_count else 0.0
        floor = float(loaded.metadata["runtime_feature_observability"]["p05_training_fraction"])
        observability = {
            "observed_fields": observed,
            "candidate_fields": candidate_count,
            "fraction": coverage,
            "training_p05_floor": floor,
        }
        if coverage < floor:
            return {
                "model_id": loaded.model_id,
                "model_version": loaded.metadata.get("model_version"),
                "status": "NOT_EVALUABLE_LOW_FEATURE_COVERAGE",
                "reason": "Observed feature coverage is below the training cohort's fifth-percentile floor.",
                "feature_observability": observability,
                "target_semantics": loaded.metadata.get("target_semantics"),
            }
        model = loaded.payload["model"]
        probabilities = model.predict_proba([features])[0]
        classes = [str(label) for label in model.classes_]
        class_scores = {label: float(probabilities[i]) for i, label in enumerate(classes)}
        predicted = str(model.predict([features])[0])
        return {
            "model_id": loaded.model_id,
            "model_name": loaded.metadata.get("algorithm", loaded.metadata.get("model")),
            "model_version": loaded.metadata.get("model_version"),
            "feature_schema_version": loaded.metadata.get("feature_schema_version"),
            "status": "COMPLETED_EXPLORATORY_TIER_PROXY",
            "predicted_tier_proxy": predicted,
            "prediction": predicted,
            "class_scores_uncalibrated": class_scores,
            "confidence_score_uncalibrated": float(max(class_scores.values())),
            "score_semantics": "Uncalibrated class scores; not calibrated risk probabilities.",
            "feature_observability": observability,
            "feature_coverage": coverage,
            "data_source": "zgrab_real",
            "reference_sample_count": loaded.metadata.get("sample_count"),
            "target_semantics": loaded.metadata.get("target_semantics"),
            "cross_cohort_transfer_status": "NOT_VALIDATED",
            "limitations": loaded.metadata.get("limitations", []),
            "authority_note": "Proxy tier is advisory; deterministic findings and posture remain separate and authoritative.",
        }
    except (ModelArtifactError, KeyError, ValueError) as exc:
        return {"model_id": model_id, "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
    except Exception as exc:
        return {"model_id": model_id, "status": "MODEL_ERROR", "reason": type(exc).__name__}


def _not_evaluable(model_id: str, reason: str) -> dict[str, Any]:
    return {"model_id": model_id, "status": "NOT_EVALUABLE", "reason": reason}


def analyze_ml_session(
    session: dict[str, Any],
    *,
    smtp_model_id: str = "zgrab_smtp_negotiation_anomaly_v1",
) -> dict[str, Any]:
    """Return optional ML context for one `PCAPAnalyzer.analyze()` session.

    Outputs carry cohort-transfer limitations and do not affect deterministic
    policy results. SMTP classifier, anomaly, rarity, and certificate novelty
    are independent outputs.
    """
    protocol = str(session.get("protocol") or "Unknown").upper()
    smtp_result: dict[str, Any]
    rarity_result: dict[str, Any]
    certificate_result: dict[str, Any]

    proxy_classifier: dict[str, Any]
    risk_tier_classifier: dict[str, Any]
    synthetic_email_classifier: dict[str, Any]
    zgrab_evidence_classifier: dict[str, Any]
    if protocol in {"IMAP", "POP3"}:
        synthetic_email_classifier = _classify_synthetic_email_risk(session)
    elif protocol == "SMTP":
        synthetic_email_classifier = {
            "model_id": "synthetic_email_posture_classifier_v2",
            "status": "NOT_APPLICABLE",
            "reason": "SMTP sessions are routed to the real-ZGrab SMTP classifier; the synthetic classifier is reserved for IMAP/POP3 until real cohorts are available.",
            "data_source": "synthetic_simulation",
        }
    else:
        synthetic_email_classifier = {
            "model_id": "synthetic_email_posture_classifier_v2",
            "status": "NOT_APPLICABLE",
            "reason": "The training cohort contains SMTP, IMAP, and POP3 scenarios only.",
        }
    if protocol == "SMTP":
        zgrab_evidence_classifier = _classify_zgrab_evidence_risk(session)
    else:
        zgrab_evidence_classifier = {
            "model_id": "zgrab_evidence_risk_classifier_v1",
            "status": "NOT_APPLICABLE",
            "reason": "The real labeled cohort contains SMTP observations only.",
        }
    if protocol != "SMTP":
        smtp_result = {"model_id": smtp_model_id, "status": "NOT_APPLICABLE", "reason": "The model reference cohort contains SMTP observations only."}
        rarity_result = {"baseline_id": "zgrab_smtp_configuration_rarity_v1", "status": "NOT_APPLICABLE", "reason": "The reference cohort contains SMTP observations only."}
        proxy_classifier = {"model_id": "zgrab_runtime_rule_flag_proxy_v2", "status": "NOT_APPLICABLE", "reason": "The classifier was trained on SMTP TLS observations only."}
        risk_tier_classifier = {"model_id": "zgrab_runtime_risk_tier_v1", "status": "NOT_APPLICABLE", "reason": "The classifier was trained on SMTP TLS observations only."}
    else:
        facts, session_context = _session_facts(session)
        cert_row = _certificate_row(session_context)
        proxy_classifier = _classify_rule_flag_proxy(facts, cert_row)
        risk_tier_classifier = _classify_risk_tier(facts, cert_row)
        if not facts["tls_version"] or not facts["cipher_suite"]:
            smtp_result = _not_evaluable(smtp_model_id, "Negotiated TLS version and cipher are not both observable.")
            rarity_result = {"baseline_id": "zgrab_smtp_configuration_rarity_v1", "status": "NOT_EVALUABLE", "reason": "Negotiated TLS version and cipher are not both observable."}
        else:
            try:
                loaded = _model(smtp_model_id)
                vector = loaded.payload["vectorizer"].transform([_smtp_feature_dict(facts)])
                model = loaded.payload["model"]
                decision = float(model.decision_function(vector)[0])
                isolation_flagged = int(model.predict(vector)[0]) == -1
                key = json.dumps([facts["tls_negotiated_version"], facts["cipher_suite"], facts["key_exchange"]], separators=(",", ":"))
                rarity_counts = {
                    json.dumps(item["configuration"], separators=(",", ":")): item["count"]
                    for item in loaded.metadata.get("rarity_reference_counts", [])
                }
                count = int(rarity_counts.get(key, 0))
                ref_n = int(loaded.metadata.get("reference_count", 0))
                config_n = int(loaded.metadata.get("reference_configuration_count", 0))
                rarity_bits = -math.log2((count + 1) / (ref_n + config_n)) if ref_n else None
                # Categorical TLS configurations are sparse. The held-out
                # transfer audit showed the Isolation Forest misses most
                # controlled rare/broken tuples, while exact cohort support
                # reliably distinguishes seen from unseen configurations.
                # Use support as the primary novelty decision and retain IF
                # as a separately visible secondary score. Novelty is not risk.
                novelty_flag = count == 0
                rarity_result = {
                    "baseline_id": "zgrab_smtp_configuration_rarity_v1",
                    "model_version": loaded.metadata.get("model_version"),
                    "status": "COMPLETED_EXPLORATORY",
                    "data_source": "zgrab_real",
                    "reference_cohort": "real active ZGrab SMTP TLS observations",
                    "reference_count": ref_n,
                    "configuration_count": count,
                    "empirical_frequency": count / ref_n if ref_n else None,
                    "rarity_bits": rarity_bits,
                    "novelty_flag": novelty_flag,
                    "prediction": "UNSEEN_CONFIGURATION" if novelty_flag else "SEEN_CONFIGURATION",
                    "support_status": "SEEN_CONFIGURATION" if count else "UNSEEN_CONFIGURATION",
                    "semantics": "Cohort support/rarity only; an unseen tuple is not evidence of vulnerability, attack, or risk.",
                    "cross_cohort_transfer_status": "NOT_VALIDATED",
                }
                smtp_result = {
                    "model_id": loaded.model_id,
                    "model_name": "Empirical configuration rarity (primary) + Isolation Forest (secondary)",
                    "model_version": loaded.metadata.get("model_version"),
                    "status": "COMPLETED_EXPLORATORY",
                    "cohort": "zgrab_real_smtp_tls",
                    "feature_schema_version": loaded.metadata.get("feature_schema_version"),
                    "features_used": loaded.metadata.get("features", []),
                    "feature_count": len(loaded.metadata.get("features", [])),
                    "feature_observability": {
                        "observed_fields": sum(bool(facts.get(name)) for name in ("tls_negotiated_version", "cipher_suite", "key_exchange")),
                        "candidate_fields": 3,
                        "fraction": sum(bool(facts.get(name)) for name in ("tls_negotiated_version", "cipher_suite", "key_exchange")) / 3,
                    },
                    "feature_coverage": sum(bool(facts.get(name)) for name in ("tls_negotiated_version", "cipher_suite", "key_exchange")) / 3,
                    "data_source": "zgrab_real",
                    "data_provenance": {
                        "source": "zgrab_real",
                        "reference_cohort": "real active ZGrab SMTP TLS negotiation features without current rule flags",
                        "reference_sample_count": loaded.metadata.get("reference_count"),
                    },
                    "reference_sample_count": loaded.metadata.get("reference_count"),
                    "reference_cohort": "real active ZGrab SMTP TLS negotiation features without current rule flags",
                    "cross_cohort_transfer_status": "NOT_VALIDATED",
                    "anomaly_method": "Exact tuple support in the real ZGrab SMTP reference cohort",
                    "anomaly_score": rarity_bits,
                    "anomaly_flag": novelty_flag,
                    "unusual_relative_to_reference": novelty_flag,
                    "prediction": "NOVEL_CONFIGURATION" if novelty_flag else "WITHIN_REFERENCE",
                    "isolation_forest_score": -decision,
                    "isolation_forest_flag": isolation_flagged,
                    "isolation_forest_role": "Secondary score; not the primary anomaly decision for sparse categorical SMTP features.",
                    "configuration_rarity_bits": rarity_bits,
                    "configuration_seen_in_reference": count > 0,
                    "reference_configuration_count": count,
                    "reference_support_status": (
                        "SEEN_CONFIGURATION" if count > 0 else "UNSEEN_CONFIGURATION"
                    ),
                    "interpretation_note": (
                        "Unseen configurations indicate cohort novelty; do not interpret as an attack or vulnerability."
                        if count == 0 else
                        "The exact version/cipher/key-exchange tuple occurs in the reference cohort; novelty remains cohort-relative."
                    ),
                    "limitations": loaded.metadata.get("limitations", []),
                }
            except (ModelArtifactError, KeyError, ValueError) as exc:
                smtp_result = {"model_id": smtp_model_id, "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
                rarity_result = {"baseline_id": "zgrab_smtp_configuration_rarity_v1", "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
            except Exception as exc:
                smtp_result = {"model_id": smtp_model_id, "status": "MODEL_ERROR", "reason": type(exc).__name__}
                rarity_result = {"baseline_id": "zgrab_smtp_configuration_rarity_v1", "status": "MODEL_ERROR", "reason": type(exc).__name__}

    _, certificate_facts = _session_facts(session)
    cert_row = _certificate_row(certificate_facts)
    if cert_row is None:
        certificate_result = _not_evaluable(
            "mta_sts_cert_anomaly_v1",
            "No leaf certificate is observable; TLS 1.3 passive captures may encrypt certificate messages.",
        )
    else:
        try:
            loaded = _model("mta_sts_cert_anomaly_v1")
            vectorizer = loaded.payload["vectorizer"]
            scaler = loaded.payload["scaler"]
            model = loaded.payload["model"]
            feature_dict, numeric_values = _certificate_features(cert_row)
            from scipy.sparse import hstack

            matrix = hstack([
                vectorizer.transform([feature_dict]),
                scaler.transform([numeric_values]),
            ], format="csr")
            decision = float(model.decision_function(matrix)[0])
            flagged = int(model.predict(matrix)[0]) == -1
            observed_cert_fields = sum(feature_dict[name] != "__MISSING__" for name in CERT_CATEGORICAL)
            observed_cert_fields += sum(feature_dict[f"{name}__missing"] == 0.0 for name in CERT_NUMERIC)
            rarity_metadata = loaded.metadata.get("rarity_baseline", {})
            rarity_fields = rarity_metadata.get("fields", [])
            rarity_configuration = [str(cert_row.get(field, "")) for field in rarity_fields]
            rarity_counts = {
                tuple(str(value) for value in entry.get("configuration", [])): int(entry.get("count", 0))
                for entry in rarity_metadata.get("configuration_counts", [])
            }
            rarity_count = rarity_counts.get(tuple(rarity_configuration), 0)
            rarity_ref_count = int(loaded.metadata.get("reference_unique_certificates", 0))
            rarity_config_count = len(rarity_counts)
            rarity_bits = -math.log2((rarity_count + 1) / (rarity_ref_count + rarity_config_count)) if rarity_ref_count else None
            certificate_result = {
                    "model_id": loaded.model_id,
                    "model_name": loaded.metadata.get("algorithm", loaded.metadata.get("model")),
                    "model_version": loaded.metadata.get("model_version"),
                    "status": "COMPLETED_EXPLORATORY",
                    "cohort": "mta_sts_smtp_related_scan_certificates",
                "cohort": "mta_sts_smtp_related_scan_certificates",
                "data_source": "mta_sts_certificate_corpus",
                "data_provenance": {
                    "source": "mta_sts_certificate_corpus",
                    "reference_cohort": "deduplicated MTA-STS SMTP scan certificates",
                    "reference_unique_certificates": loaded.metadata.get("reference_unique_certificates"),
                },
                "reference_cohort": "deduplicated MTA-STS SMTP scan certificates",
                "reference_sample_count": loaded.metadata.get("reference_unique_certificates"),
                "novelty_score": -decision,
                "certificate_novelty_score": -decision,
                "unusual_relative_to_reference": flagged,
                "novelty_flag": flagged,
                "prediction": "NOVEL_RELATIVE_TO_COHORT" if flagged else "WITHIN_REFERENCE",
                "feature_count": len(CERT_CATEGORICAL) + len(CERT_NUMERIC),
                "feature_observability": {
                    "observed_fields": observed_cert_fields,
                    "candidate_fields": len(CERT_CATEGORICAL) + len(CERT_NUMERIC),
                    "fraction": observed_cert_fields / (len(CERT_CATEGORICAL) + len(CERT_NUMERIC)),
                },
                "feature_coverage": observed_cert_fields / (len(CERT_CATEGORICAL) + len(CERT_NUMERIC)),
                "novelty_cues": [
                    f"Unseen reference configuration for {', '.join(rarity_fields)}"
                    if rarity_count == 0 else
                    "No unseen exact rarity configuration among the configured certificate features."
                ],
                "rarity_context": {
                    "features": rarity_fields,
                    "reference_match_count": rarity_count,
                    "reference_frequency": rarity_count / rarity_ref_count if rarity_ref_count else None,
                    "rarity_bits": rarity_bits,
                    "interpretation": "Cohort frequency context, not a vulnerability explanation.",
                },
                "limitations": loaded.metadata.get("limitations", []),
                "feature_observability_note": "Some certificate extensions are not exported by the current PCAP telemetry and remain explicitly missing.",
            }
        except (ModelArtifactError, KeyError, ValueError) as exc:
            certificate_result = {"model_id": "mta_sts_cert_anomaly_v1", "status": "MODEL_UNAVAILABLE", "reason": str(exc)}
        except Exception as exc:
            certificate_result = {"model_id": "mta_sts_cert_anomaly_v1", "status": "MODEL_ERROR", "reason": type(exc).__name__}

    tier_status = risk_tier_classifier.get("status")
    tier_available = tier_status == "COMPLETED_EXPLORATORY_TIER_PROXY"
    synthetic_risk_available = synthetic_email_classifier.get("status") == "COMPLETED_EXPERIMENTAL_NOT_VALIDATED"
    zgrab_evidence_available = zgrab_evidence_classifier.get("status") == "COMPLETED_ADVISORY_RUBRIC_ESTIMATE"
    outputs = {
        "synthetic_email_risk_classifier": synthetic_email_classifier,
        "zgrab_evidence_risk_classifier": zgrab_evidence_classifier,
        "classifier": proxy_classifier,
        "classifier_risk_tier": risk_tier_classifier,
        "smtp_configuration_anomaly": smtp_result,
        "smtp_configuration_rarity": rarity_result,
        "certificate_novelty": certificate_result,
    }
    return {
        **outputs,
        "ml_assessment": {
            "schema_version": "ml_assessment_v1",
            "status": (
                "ADVISORY_REAL_ZGRAB_RUBRIC_AVAILABLE" if zgrab_evidence_available else
                "EXPERIMENTAL_SYNTHETIC_RISK_AVAILABLE" if synthetic_risk_available else
                "ADVISORY_PROXY_TIER_AVAILABLE" if tier_available else
                "PARTIAL_OR_NOT_EVALUABLE"
            ),
            "synthetic_risk_prediction": synthetic_email_classifier.get("predicted_risk_tier"),
            "synthetic_risk_model_id": synthetic_email_classifier.get("model_id"),
            "synthetic_risk_model_version": synthetic_email_classifier.get("model_version"),
            "synthetic_risk_confidence_uncalibrated": synthetic_email_classifier.get("confidence_score_uncalibrated"),
            "zgrab_evidence_risk_prediction": zgrab_evidence_classifier.get("predicted_risk_tier"),
            "zgrab_evidence_risk_model_id": zgrab_evidence_classifier.get("model_id"),
            "zgrab_evidence_risk_model_version": zgrab_evidence_classifier.get("model_version"),
            "zgrab_evidence_risk_confidence_uncalibrated": zgrab_evidence_classifier.get("confidence_score_uncalibrated"),
            "predicted_tier_proxy": risk_tier_classifier.get("predicted_tier_proxy") if tier_available else None,
            "tier_model_id": risk_tier_classifier.get("model_id"),
            "tier_model_version": risk_tier_classifier.get("model_version"),
            "tier_confidence_score_uncalibrated": risk_tier_classifier.get("confidence_score_uncalibrated"),
            "tier_feature_coverage": risk_tier_classifier.get("feature_coverage"),
            "component_statuses": {
                key: value.get("status", "UNKNOWN") for key, value in outputs.items()
            },
            "combined_risk_score": None,
            "semantics": "The legacy real-ZGrab tier remains a deterministic-rule proxy. The new real-ZGrab classifier predicts a separate raw-evidence project rubric; the synthetic classifier predicts its separate expected-scenario rubric. Anomaly and certificate novelty remain cohort-relative context and are not combined into risk.",
            "authority_note": "Advisory ML only; deterministic rule findings and posture remain authoritative.",
        },
    }
