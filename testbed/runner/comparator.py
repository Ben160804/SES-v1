"""
testbed/runner/comparator.py
============================
Deterministic Differential Comparison Engine (SecureMailScope Testbed).

Role:
-----
Consumes:
  1. expected.json  (ScenarioSpec / matrix intent)
  2. observed.json  (Pure passive PCAPAnalyzer output across all streams)

Produces:
  comparison.json   (Deterministic audit with PASS / FAIL / INCONCLUSIVE verdict)

Semantics & Invariants:
----------------------
1. 100% Assertion Coverage:
   The comparator strictly audits every assertion emitted by to_expected_dict().
   If any assertion key in expected["assertions"] lacks an evaluation result,
   it is immediately flagged as FAIL.

2. Strict Wire Honesty:
   Unnegotiated TLS parameters (such as cipher suite or version in fatal-alert aborts)
   are NEVER marked PASS. Aborted sessions record unnegotiated parameters as NOT_APPLICABLE.

3. RFC 5280 PKI Signature Verification:
   Certificate signature algorithm comparison evaluates ONLY signature metadata
   (signature_algorithm_name, signature_algorithm_parameters, signature_algorithm_oid).
   It NEVER inspects leaf_cert["public_key_algorithm"].

4. Ambiguity Detection:
   Multi-session selection detects ties among competing candidate streams.
   It NEVER silently guesses or breaks ties arbitrarily. Ambiguity triggers INCONCLUSIVE.
"""

from typing import Any, Dict, List, Optional, Tuple


def select_evaluated_session(
    expected_protocol: str,
    sessions: Dict[str, Any],
) -> Tuple[Optional[int], Optional[Dict[str, Any]], Optional[str]]:
    """
    Deterministically identify the relevant mail session from all analyzed streams.

    Does NOT blindly assume stream 0. Ranks candidate streams based on:
      1. Matching protocol (SMTP, IMAP, POP3)
      2. Active TLS negotiation / STARTTLS upgrade
      3. Completed or initiated email command exchange

    Detects ambiguous multi-session scenarios: if multiple streams tie for the top
    positive score, returns (None, None, error_message) rather than silently guessing.
    """
    if not sessions:
        return None, None, None

    candidates: List[Tuple[int, int, Dict[str, Any]]] = []
    norm_proto = expected_protocol.upper()

    for str_id, session in sessions.items():
        try:
            stream_id = int(str_id)
        except (ValueError, TypeError):
            continue

        proto = str(session.get("protocol") or "").upper()
        stls = session.get("starttls") or {}
        tls = session.get("tls") or {}
        handshake = session.get("handshake") or {}

        # Heuristic scoring for mail session relevance
        score = 0
        if proto == norm_proto:
            score += 100
        elif proto in ("SMTP", "IMAP", "POP3"):
            score += 20

        # Active TLS or STARTTLS presence
        if tls and tls.get("tls_version"):
            score += 50
        if stls.get("status") in ("UPGRADED", "IMPLICIT_TLS"):
            score += 40
        elif stls.get("status") in ("CLEARTEXT_NO_ENCRYPTION", "STRIPPED_STARTTLS"):
            score += 30

        # Handshake flights or alerts observed
        if handshake.get("flight", {}).get("messages"):
            score += 15
        if handshake.get("flight", {}).get("alerts"):
            score += 15

        candidates.append((score, stream_id, session))

    if not candidates:
        return None, None, None

    # Sort descending by score
    candidates.sort(key=lambda c: -c[0])
    top_score = candidates[0][0]
    top_candidates = [c for c in candidates if c[0] == top_score]

    # Ambiguity check: multiple streams tied for the highest relevance score
    if len(top_candidates) > 1 and top_score > 0:
        tied_ids = [c[1] for c in top_candidates]
        err = f"AMBIGUOUS_STREAM_SELECTION: multiple streams {tied_ids} tied with relevance score {top_score}"
        return None, None, err

    best_score, best_stream_id, best_session = candidates[0]
    return best_stream_id, best_session, None


def compare_sig_algo(expected: str, leaf_cert: Dict[str, Any]) -> bool:
    """
    Compare expected cert_sig_algo with certificate signature metadata ONLY (RFC 5280 §4.1.1.2).

    STRICT INVARIANT: NEVER inspect leaf_cert['public_key_algorithm'] (RFC 5280 §4.1.2.7),
    as that represents SubjectPublicKeyInfo, not the CA's signature mechanism.
    """
    sig_name = str(leaf_cert.get("signature_algorithm_name") or "").lower()
    sig_params = str(leaf_cert.get("signature_algorithm_parameters") or "").lower()
    sig_oid = str(leaf_cert.get("signature_algorithm_oid") or "").lower()

    exp = expected.upper().replace("_", "-").replace(" ", "-")

    if exp == "ECDSA":
        # ECDSA signatures: ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512, etc. (OIDs 1.2.840.10045.4.*)
        return "ecdsa" in sig_name or "1.2.840.10045.4." in sig_oid
    elif exp in ("RSA-PKCS1V15", "RSA-PKCS1-V1-5"):
        # RSA PKCS#1 v1.5 signatures: sha256WithRSAEncryption, sha384WithRSAEncryption, etc.
        is_pkcs1_param = "pkcs1" in sig_params
        is_rsa_sig = "rsa" in sig_name and "pss" not in sig_name and "pss" not in sig_params
        return is_pkcs1_param or is_rsa_sig
    elif exp == "RSA-PSS":
        # RSA-PSS signatures: rsassa-pss, id-rsassa-pss, or parameters == "PSS"
        return "pss" in sig_name or "pss" in sig_params or "1.2.840.113549.1.1.10" in sig_oid
    elif exp == "ED25519":
        # Ed25519 signatures: PureEd25519 (OID 1.3.101.112)
        return "ed25519" in sig_name or "1.3.101.112" in sig_oid
    return False


def compare(
    expected_artifact: Dict[str, Any],
    observed_artifact: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare scenario intent against passive wire observation without cross-layer leakage.

    Enforces:
      - 100% assertion coverage
      - Zero false PASS on unnegotiated properties in fatal alert scenarios
      - RFC 5280 signature algorithm inspection
      - Ambiguity detection in multi-session selection
    """
    scenario_id = expected_artifact.get("scenario_id", "UNKNOWN")
    expected_data = expected_artifact.get("expected", {})
    assertions = expected_artifact.get("assertions", {})
    sessions = observed_artifact.get("sessions", {})

    expected_proto = expected_data.get("protocol", "SMTP")
    stream_id, session, ambiguity_err = select_evaluated_session(expected_proto, sessions)

    fields: Dict[str, Any] = {}
    mismatches: List[Dict[str, Any]] = []
    unknowns: List[str] = []

    if ambiguity_err:
        # Ambiguous multi-session selection detected: passive observer cannot determine
        # primary stream without external context -> INCONCLUSIVE
        return {
            "schema_version": "1.0",
            "scenario_id": scenario_id,
            "status": "INCONCLUSIVE",
            "fields": {
                "protocol": {
                    "status": "UNOBSERVABLE",
                    "expected": expected_proto,
                    "observed": None,
                    "reason": ambiguity_err,
                }
            },
            "mismatches": [],
            "unknowns": ["evaluated_stream"],
            "evaluated_stream": None,
        }

    if session is None:
        # No session detected at all in capture
        mismatches.append({
            "field": "protocol",
            "expected": expected_proto,
            "observed": None,
            "reason": "No analyzed sessions found in capture"
        })
        return {
            "schema_version": "1.0",
            "scenario_id": scenario_id,
            "status": "FAIL",
            "fields": {
                "protocol": {
                    "status": "FAIL",
                    "expected": expected_proto,
                    "observed": None,
                    "reason": "No analyzed sessions found in capture"
                }
            },
            "mismatches": mismatches,
            "unknowns": unknowns,
            "evaluated_stream": None,
        }

    stls = session.get("starttls") or {}
    tls_info = session.get("tls") or {}
    handshake = session.get("handshake") or {}
    cert_info = session.get("certificate")

    # Wire alert detection
    has_fatal_alert = any(
        str(a.get("level")).upper() == "FATAL"
        for a in handshake.get("flight", {}).get("alerts", [])
    ) or handshake.get("forensic_analysis", {}).get("handshake_status") == "ABORTED"

    # 1. Protocol
    observed_proto = session.get("protocol")
    if observed_proto == expected_proto:
        fields["protocol"] = {"status": "PASS", "expected": expected_proto, "observed": observed_proto}
    else:
        fields["protocol"] = {"status": "FAIL", "expected": expected_proto, "observed": observed_proto}
        mismatches.append({"field": "protocol", "expected": expected_proto, "observed": observed_proto})

    # 2. STARTTLS Status / Transport Mode
    stls_assertion = assertions.get("starttls_status", {})
    expected_stls = stls_assertion.get("expected")
    observed_stls = stls.get("status")
    stls_required = stls_assertion.get("required", False)

    if not stls_required:
        fields["starttls_status"] = {
            "status": "NOT_APPLICABLE",
            "expected": expected_stls,
            "observed": observed_stls,
            "reason": "STARTTLS status not required for this scenario"
        }
    elif observed_stls == expected_stls:
        fields["starttls_status"] = {"status": "PASS", "expected": expected_stls, "observed": observed_stls}
    elif expected_stls is not None:
        fields["starttls_status"] = {"status": "FAIL", "expected": expected_stls, "observed": observed_stls}
        mismatches.append({"field": "starttls_status", "expected": expected_stls, "observed": observed_stls})
    else:
        fields["starttls_status"] = {"status": "NOT_APPLICABLE", "expected": None, "observed": observed_stls}

    # 3. TLS Presence
    expected_presence = assertions.get("tls_presence", {}).get("expected")
    if observed_stls == "UPGRADED":
        observed_presence = "STARTTLS-upgraded"
    elif observed_stls == "IMPLICIT_TLS" or (handshake.get("client_hello") and not stls.get("starttls_offered")):
        observed_presence = "implicit-TLS"
    elif observed_stls in ("CLEARTEXT_NO_ENCRYPTION", "STRIPPED_STARTTLS") or not tls_info:
        observed_presence = "none"
    else:
        observed_presence = "none"

    if observed_presence == expected_presence:
        fields["tls_presence"] = {"status": "PASS", "expected": expected_presence, "observed": observed_presence}
    elif expected_presence is not None:
        fields["tls_presence"] = {"status": "FAIL", "expected": expected_presence, "observed": observed_presence}
        mismatches.append({"field": "tls_presence", "expected": expected_presence, "observed": observed_presence})
    else:
        fields["tls_presence"] = {"status": "NOT_APPLICABLE", "expected": None, "observed": observed_presence}

    # 4. TLS Fatal Alert (Negative Handshake Assertions)
    if "tls.fatal_alert" in assertions:
        fatal_assertion = assertions["tls.fatal_alert"]
        exp_fatal = fatal_assertion.get("expected", False)
        req_fatal = fatal_assertion.get("required", False)
        if req_fatal or exp_fatal:
            if has_fatal_alert:
                fields["tls.fatal_alert"] = {"status": "PASS", "expected": True, "observed": True}
            else:
                fields["tls.fatal_alert"] = {
                    "status": "FAIL",
                    "expected": True,
                    "observed": False,
                    "reason": "Expected fatal TLS alert not observed on wire"
                }
                mismatches.append({"field": "tls.fatal_alert", "expected": True, "observed": False})
        else:
            fields["tls.fatal_alert"] = {"status": "NOT_APPLICABLE", "expected": False, "observed": has_fatal_alert}

    # 5. TLS Version
    ver_assertion = assertions.get("tls.version", {})
    expected_ver = ver_assertion.get("expected")
    observed_ver = tls_info.get("tls_version")
    is_tls_required = ver_assertion.get("required", False)

    if not is_tls_required:
        if observed_ver is None:
            ver_entry = {
                "status": "NOT_APPLICABLE" if has_fatal_alert else "PASS",
                "expected": None,
                "observed": None,
            }
            if has_fatal_alert:
                ver_entry["reason"] = "Handshake aborted before version negotiation"
            fields["tls.version"] = ver_entry
        else:
            fields["tls.version"] = {"status": "FAIL", "expected": None, "observed": observed_ver, "reason": "Unexpected TLS on session"}
            mismatches.append({"field": "tls.version", "expected": None, "observed": observed_ver})
    else:
        if observed_ver == expected_ver:
            fields["tls.version"] = {"status": "PASS", "expected": expected_ver, "observed": observed_ver}
        elif observed_ver is None:
            fields["tls.version"] = {"status": "FAIL", "expected": expected_ver, "observed": None, "reason": "TLS handshake was not negotiated"}
            mismatches.append({"field": "tls.version", "expected": expected_ver, "observed": None})
        else:
            fields["tls.version"] = {"status": "FAIL", "expected": expected_ver, "observed": observed_ver}
            mismatches.append({"field": "tls.version", "expected": expected_ver, "observed": observed_ver})

    # 6. Cipher Strength
    cipher_assertion = assertions.get("tls.cipher_strength", {})
    expected_strength = cipher_assertion.get("expected")
    observed_strength = tls_info.get("cipher_strength")
    is_strength_required = cipher_assertion.get("required", False)

    def _norm_strength(s: Any) -> Optional[str]:
        if s is None:
            return None
        st = str(s).upper().strip()
        if st in ("STRONG", "HIGH"):
            return "HIGH"
        if st in ("WEAK", "LOW"):
            return "WEAK"
        if st in ("MEDIUM", "MODERATE"):
            return "MEDIUM"
        return st

    if not is_strength_required:
        cipher_entry = {
            "status": "NOT_APPLICABLE",
            "expected": None,
            "observed": observed_strength,
        }
        if has_fatal_alert:
            cipher_entry["reason"] = "Cipher negotiation was aborted before agreement by fatal alert"
        fields["tls.cipher_strength"] = cipher_entry
    else:
        if _norm_strength(observed_strength) == _norm_strength(expected_strength):
            fields["tls.cipher_strength"] = {"status": "PASS", "expected": expected_strength, "observed": observed_strength}
        else:
            fields["tls.cipher_strength"] = {"status": "FAIL", "expected": expected_strength, "observed": observed_strength}
            mismatches.append({"field": "tls.cipher_strength", "expected": expected_strength, "observed": observed_strength})

    # 6b. Exact Negotiated Cipher Suite (Fix #2A Requirement)
    cipher_name_assertion = assertions.get("tls.cipher_name", {})
    expected_cipher_name = cipher_name_assertion.get("expected")
    is_cipher_name_required = cipher_name_assertion.get("required", False)
    observed_cipher_name = tls_info.get("cipher_name")

    if not is_cipher_name_required:
        cipher_name_entry = {
            "status": "NOT_APPLICABLE",
            "expected": expected_cipher_name,
            "observed": observed_cipher_name,
        }
        if has_fatal_alert:
            cipher_name_entry["reason"] = "Cipher negotiation was aborted before agreement by fatal alert"
        fields["tls.cipher_name"] = cipher_name_entry
    else:
        if observed_cipher_name == expected_cipher_name:
            fields["tls.cipher_name"] = {"status": "PASS", "expected": expected_cipher_name, "observed": observed_cipher_name}
        elif observed_cipher_name is None:
            fields["tls.cipher_name"] = {
                "status": "FAIL",
                "expected": expected_cipher_name,
                "observed": None,
                "reason": "TLS cipher negotiation not observed on wire"
            }
            mismatches.append({"field": "tls.cipher_name", "expected": expected_cipher_name, "observed": None, "reason": "TLS cipher negotiation not observed on wire"})
        else:
            fields["tls.cipher_name"] = {
                "status": "FAIL",
                "expected": expected_cipher_name,
                "observed": observed_cipher_name,
                "reason": f"Negotiated cipher '{observed_cipher_name}' does not match expected exact cipher '{expected_cipher_name}'"
            }
            mismatches.append({
                "field": "tls.cipher_name",
                "expected": expected_cipher_name,
                "observed": observed_cipher_name,
                "reason": f"Negotiated cipher '{observed_cipher_name}' does not match expected exact cipher '{expected_cipher_name}'"
            })

    # 7. Forward Secrecy
    pfs_assertion = assertions.get("tls.forward_secrecy", {})
    expected_pfs = pfs_assertion.get("expected")
    observed_pfs = tls_info.get("forward_secrecy")
    is_pfs_required = pfs_assertion.get("required", False)

    if not is_pfs_required:
        pfs_entry = {
            "status": "NOT_APPLICABLE",
            "expected": expected_pfs,
            "observed": observed_pfs,
        }
        if has_fatal_alert:
            pfs_entry["reason"] = "Handshake aborted before key exchange by fatal alert"
        fields["tls.forward_secrecy"] = pfs_entry
    else:
        if observed_pfs == expected_pfs:
            fields["tls.forward_secrecy"] = {"status": "PASS", "expected": expected_pfs, "observed": observed_pfs}
        else:
            fields["tls.forward_secrecy"] = {"status": "FAIL", "expected": expected_pfs, "observed": observed_pfs}
            mismatches.append({"field": "tls.forward_secrecy", "expected": expected_pfs, "observed": observed_pfs})

    # 8. Certificate Observability & Attributes
    cert_obs_assertion = assertions.get("certificate.observable", {})
    expected_cert_obs = cert_obs_assertion.get("expected", "NOT_PRESENT")

    has_leaf = cert_info is not None and cert_info.get("leaf_cert") is not None
    is_tls13 = tls_info.get("tls_version") == "TLS 1.3"
    is_psk_resumed = bool(tls_info.get("tls13_psk_selected"))
    gen_req = expected_data.get("generator_requirement", "")

    if has_leaf:
        actual_wire_obs = "VISIBLE"
    elif is_tls13 and not is_psk_resumed and not has_fatal_alert:
        actual_wire_obs = "ENCRYPTED"
    else:
        actual_wire_obs = "NOT_PRESENT"

    if expected_cert_obs == "ENCRYPTED":
        if actual_wire_obs == "ENCRYPTED":
            fields["certificate.observable"] = {"status": "PASS", "expected": "ENCRYPTED", "observed": "UNOBSERVABLE"}
        elif actual_wire_obs == "VISIBLE":
            fields["certificate.observable"] = {"status": "FAIL", "expected": "ENCRYPTED", "observed": "VISIBLE", "reason": "Certificate unexpectedly sent in plaintext"}
            mismatches.append({"field": "certificate.observable", "expected": "ENCRYPTED", "observed": "VISIBLE"})
        else:
            fields["certificate.observable"] = {"status": "FAIL", "expected": "ENCRYPTED", "observed": actual_wire_obs}
            mismatches.append({"field": "certificate.observable", "expected": "ENCRYPTED", "observed": actual_wire_obs})
    elif expected_cert_obs == "VISIBLE":
        if actual_wire_obs == "VISIBLE":
            fields["certificate.observable"] = {"status": "PASS", "expected": "VISIBLE", "observed": "VISIBLE"}
        else:
            fields["certificate.observable"] = {"status": "FAIL", "expected": "VISIBLE", "observed": actual_wire_obs}
            mismatches.append({"field": "certificate.observable", "expected": "VISIBLE", "observed": actual_wire_obs})
    else:  # NOT_PRESENT
        if actual_wire_obs == "NOT_PRESENT":
            fields["certificate.observable"] = {"status": "PASS", "expected": "NOT_PRESENT", "observed": "NOT_PRESENT"}
        elif actual_wire_obs == "ENCRYPTED" and gen_req == "psk_dhe_resumption_without_cert":
            fields["certificate.observable"] = {"status": "PASS", "expected": "NOT_PRESENT", "observed": "NOT_PRESENT"}
        else:
            fields["certificate.observable"] = {"status": "PASS" if actual_wire_obs == "NOT_PRESENT" else "FAIL", "expected": "NOT_PRESENT", "observed": actual_wire_obs}
            if actual_wire_obs != "NOT_PRESENT":
                mismatches.append({"field": "certificate.observable", "expected": "NOT_PRESENT", "observed": actual_wire_obs})

    # Internal Certificate Attributes
    cert_fields = [
        ("certificate.signature_algorithm", "cert_sig_algo"),
        ("certificate.validity", "cert_validity"),
        ("certificate.hostname_match", "hostname_match"),
        ("certificate.trust_status", "expected_trust_status"),
    ]

    for field_key, spec_key in cert_fields:
        assertion = assertions.get(field_key, {})
        exp_val = assertion.get("expected")
        req = assertion.get("required", False)
        obs_mode = assertion.get("observability", "always")

        if not req or exp_val is None or obs_mode == "not_applicable":
            fields[field_key] = {"status": "NOT_APPLICABLE", "expected": exp_val, "observed": None}
            continue

        if obs_mode == "conditional" and not has_leaf:
            # Wire certificate is unobservable due to TLS 1.3 encryption
            fields[field_key] = {"status": "UNOBSERVABLE", "expected": exp_val, "observed": None}
            unknowns.append(field_key)
        elif has_leaf:
            leaf = cert_info["leaf_cert"]
            if field_key == "certificate.signature_algorithm":
                match = compare_sig_algo(str(exp_val), leaf)
                obs_val = leaf.get("signature_algorithm_parameters") or leaf.get("signature_algorithm_name")
            elif field_key == "certificate.validity":
                if leaf.get("is_expired"):
                    obs_val = "expired"
                elif leaf.get("not_yet_valid"):
                    obs_val = "not-yet-valid"
                else:
                    obs_val = "valid"
                match = (obs_val == exp_val)
            elif field_key == "certificate.hostname_match":
                obs_val = str(cert_info.get("hostname_match", "")).lower()
                match = (obs_val == str(exp_val).lower())
            elif field_key == "certificate.trust_status":
                obs_val = cert_info.get("trust_status")
                match = (obs_val == exp_val)
            else:
                obs_val = None
                match = False

            if match:
                fields[field_key] = {"status": "PASS", "expected": exp_val, "observed": obs_val}
            else:
                fields[field_key] = {"status": "FAIL", "expected": exp_val, "observed": obs_val}
                mismatches.append({"field": field_key, "expected": exp_val, "observed": obs_val})
        else:
            # Expected visible certificate was not observed
            fields[field_key] = {"status": "FAIL", "expected": exp_val, "observed": None, "reason": "Expected visible certificate missing"}
            mismatches.append({"field": field_key, "expected": exp_val, "observed": None})

    # 9. Exhaustive Bidirectional Assertion Audit (Fix #1 Requirement: 100% Coverage)
    missing_assertions = set(assertions.keys()) - set(fields.keys())
    for missing_key in sorted(missing_assertions):
        missing_rule = assertions[missing_key]
        fields[missing_key] = {
            "status": "FAIL",
            "expected": missing_rule.get("expected"),
            "observed": None,
            "reason": f"Comparator missing evaluation handler for assertion '{missing_key}'",
        }
        mismatches.append({
            "field": missing_key,
            "expected": missing_rule.get("expected"),
            "observed": None,
            "reason": f"Uncovered assertion '{missing_key}'",
        })

    # Overall Status Resolution
    if mismatches:
        overall_status = "FAIL"
    elif unknowns:
        overall_status = "INCONCLUSIVE"
    else:
        overall_status = "PASS"

    return {
        "schema_version": "1.0",
        "scenario_id": scenario_id,
        "status": overall_status,
        "fields": fields,
        "mismatches": mismatches,
        "unknowns": unknowns,
        "evaluated_stream": stream_id,
    }
