"""
SecureMailScope Cryptographic Policy & Forensic Rule Engine — Input Builder.

Transforms raw/normalized PCAP session telemetry from PCAPAnalyzer.analyze()
into the canonical RuleInput representation.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Union
from .schema import RuleInput, LeafCertFacts, NonAnchorCertFacts, AnalyzerTrustStoreInfo, HeuristicsInfo


def _parse_utc_datetime(val: Any) -> Optional[datetime]:
    """
    Parses a string or datetime into a timezone-aware UTC datetime.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            s = val.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def add_calendar_years(dt: datetime, years: int) -> datetime:
    """
    Adds calendar years to a datetime, handling leap years gracefully (Feb 29 -> Feb 28).
    """
    try:
        return dt.replace(year=dt.year + years)
    except ValueError:
        return dt.replace(year=dt.year + years, day=28)


def check_lifespan_3_calendar_years(not_before: datetime, not_after: datetime) -> bool:
    """
    Returns True if not_after exceeds not_before + 3 calendar years.
    """
    return not_after > add_calendar_years(not_before, 3)


class InputBuilder:
    """
    Builds canonical RuleInput from PCAPAnalyzer session dictionary.
    """

    @classmethod
    def build(cls, session: dict[str, Any], trust_store_manager: Optional[Any] = None) -> RuleInput:
        stream_id = session.get("stream_id", 0)
        protocol = session.get("protocol", "Unknown")

        # ── Capture Time (Temporal Provenance) ─────────────────────────────────
        handshake = session.get("handshake") or {}
        time_epoch = handshake.get("handshake_time_epoch")
        if time_epoch is None:
            server_neg = handshake.get("server_negotiation") or {}
            time_epoch = server_neg.get("handshake_time_epoch")

        capture_time: Optional[datetime] = None
        if time_epoch is not None:
            try:
                capture_time = datetime.fromtimestamp(float(time_epoch), tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                capture_time = None

        # ── Application Data Observability ─────────────────────────────────────
        flight = handshake.get("flight") or {}
        raw_app_data = flight.get("application_data_observed")
        tls_info = session.get("tls") or {}
        tls_ver = tls_info.get("tls_version")

        application_data_observed: Union[bool, str]
        if raw_app_data in (True, False, "NOT_DETERMINABLE"):
            application_data_observed = raw_app_data
        elif tls_ver == "TLS 1.3" and flight.get("outer_record_23_observed"):
            application_data_observed = "NOT_DETERMINABLE"
        else:
            application_data_observed = bool(raw_app_data)

        # ── Analyzer Trust Store Telemetry ─────────────────────────────────────
        cert_block = session.get("certificate")
        ca_file_path: Optional[str] = None
        if trust_store_manager is not None and hasattr(trust_store_manager, "get_ca_file_path"):
            try:
                ca_file_path = trust_store_manager.get_ca_file_path()
            except Exception:
                ca_file_path = None

        if cert_block:
            analyzer_trust_store: AnalyzerTrustStoreInfo = {
                "active_store": cert_block.get("active_trust_store", "unknown"),
                "description": cert_block.get("active_trust_store_description", ""),
                "ca_file_path": ca_file_path,
                "anchored": bool(cert_block.get("anchored_in_active_store", False)),
                "verification_error": cert_block.get("path_verification_error"),
            }
        else:
            analyzer_trust_store = {
                "active_store": "unknown",
                "description": "",
                "ca_file_path": ca_file_path,
                "anchored": False,
                "verification_error": None,
            }

        # ── TLS Parameters & Negotiation ───────────────────────────────────────
        raw_version = tls_info.get("raw_version")
        tls_version = tls_info.get("tls_version")
        raw_cipher_suite = tls_info.get("raw_cipher_suite")
        cipher_name = tls_info.get("cipher_name")
        tls13_psk_selected = tls_info.get("tls13_psk_selected")
        tls13_key_exchange_group = tls_info.get("tls13_key_exchange_group")
        tls13_key_exchange_mode = tls_info.get("tls13_key_exchange_mode")
        hello_retry_request = bool(tls_info.get("hello_retry_request", False))

        server_neg = handshake.get("server_negotiation") or {}
        ske = server_neg.get("tls12_server_key_exchange") or {}
        tls12_kex_type = ske.get("kex_type")
        tls12_named_curve = ske.get("named_curve")
        tls12_dh_prime_bits = ske.get("dh_prime_length_bits")
        tls12_wire_sig_alg = ske.get("wire_signature_algorithm")

        ds = server_neg.get("downgrade_sentinel") or {}
        downgrade_sentinel = {
            "detected": bool(ds.get("sentinel_detected", False)),
            "type": ds.get("sentinel_type"),
        }

        # ── Client Hello Parameters ───────────────────────────────────────────
        client_hello = handshake.get("client_hello") or {}
        early_data_offered = bool(client_hello.get("early_data_offered", False))
        early_data_observed = bool(flight.get("early_data_observed", False))
        handshake_status = handshake.get("forensic_analysis", {}).get("handshake_status")

        raw_alerts = flight.get("alerts") or []
        flight_alerts = [
            {
                "frame": a.get("frame"),
                "level": a.get("level"),
                "description": a.get("description"),
                "sender": a.get("sender", "unknown"),
            }
            for a in raw_alerts
        ]
        client_aborted_with_alert = any(
            a.get("sender") == "client" and a.get("level") == "FATAL"
            for a in flight_alerts
        )
        server_aborted_with_alert = any(
            a.get("sender") == "server" and a.get("level") == "FATAL"
            for a in flight_alerts
        )

        client_offered_versions = client_hello.get("offered_versions") or []
        raw_offered_ciphers = client_hello.get("offered_ciphers") or []
        client_offered_ciphers = [
            c["name"] if (isinstance(c, dict) and "name" in c) else str(c)
            for c in raw_offered_ciphers
        ]
        client_supported_groups = client_hello.get("supported_groups") or []
        client_signature_algorithms = client_hello.get("signature_algorithms") or []
        client_sni = client_hello.get("sni")
        client_alpn = client_hello.get("alpn") or []

        # ── STARTTLS ──────────────────────────────────────────────────────────
        st = session.get("starttls") or {}
        starttls_offered = bool(st.get("starttls_offered", False))
        starttls_requested = bool(st.get("starttls_requested", False))
        starttls_accepted = bool(st.get("starttls_accepted", False))
        starttls_rejected = bool(st.get("starttls_rejected", False))
        plaintext_auth_attempted = bool(st.get("plaintext_auth_attempted", False))
        starttls_status = st.get("status", "CLEARTEXT_NO_ENCRYPTION")

        # ── Certificate Material & Facts ──────────────────────────────────────
        cert_observable = (
            cert_block is not None
            and cert_block.get("leaf_cert") is not None
        )
        cert_unobservable_reason: Optional[str] = None
        if not cert_observable:
            if tls_version == "TLS 1.3" and cert_block is None:
                cert_unobservable_reason = "TLS13_ENCRYPTED"
            elif tls_version is None:
                cert_unobservable_reason = "NO_TLS"
            elif cert_block and cert_block.get("trust_status") == "CERT_PARSE_ERROR":
                cert_unobservable_reason = "PARSE_ERROR"
            else:
                cert_unobservable_reason = "UNAVAILABLE"

        chain_length = cert_block.get("chain_length", 0) if cert_block else 0
        hostname_match = cert_block.get("hostname_match", "SKIPPED_NO_SNI") if cert_block else "SKIPPED_NO_SNI"
        revocation_status = cert_block.get("revocation_status", "NOT_CHECKED (PASSIVE_OFFLINE_ANALYSIS)") if cert_block else "NOT_CHECKED (PASSIVE_OFFLINE_ANALYSIS)"

        leaf_cert: Optional[LeafCertFacts] = None
        non_anchor_cert_facts: Optional[NonAnchorCertFacts] = None

        if cert_observable and cert_block:
            raw_leaf = cert_block["leaf_cert"]
            nb = _parse_utc_datetime(raw_leaf.get("not_before"))
            na = _parse_utc_datetime(raw_leaf.get("not_after"))
            san_dns = raw_leaf.get("san_dns") or []
            san_ip = raw_leaf.get("san_ip") or []
            eku_list = raw_leaf.get("extended_key_usage") or []
            has_eku = bool(raw_leaf.get("extended_key_usage_present", False) or raw_leaf.get("has_extended_key_usage", False))

            is_exp_capture = (capture_time > na) if (capture_time is not None and na is not None) else None
            not_yet_capture = (capture_time < nb) if (capture_time is not None and nb is not None) else None

            # Safe public key size parsing
            pk_size_raw = raw_leaf.get("public_key_size", 0)
            try:
                pk_size = int(pk_size_raw)
            except (ValueError, TypeError):
                pk_size = 0

            leaf_cert = {
                "subject_dn": raw_leaf.get("subject_dn", ""),
                "issuer_dn": raw_leaf.get("issuer_dn", ""),
                "is_self_signed": bool(raw_leaf.get("is_self_signed", False) or (raw_leaf.get("subject_dn") == raw_leaf.get("issuer_dn"))),
                "san_dns": san_dns,
                "san_ip": san_ip,
                "has_san": bool(san_dns or san_ip),
                "public_key_algorithm": raw_leaf.get("public_key_algorithm", "Unknown"),
                "public_key_size": pk_size,
                "signature_algorithm_name": raw_leaf.get("signature_algorithm_name", ""),
                "signature_hash_algorithm": raw_leaf.get("signature_hash_algorithm"),
                "signature_params": raw_leaf.get("signature_algorithm_parameters"),
                "basic_constraints": raw_leaf.get("basic_constraints"),
                "key_usage": raw_leaf.get("key_usage"),
                "extended_key_usage": eku_list,
                "has_eku_extension": has_eku,
                "has_server_auth_eku": ("serverAuth" in eku_list or "1.3.6.1.5.5.7.3.1" in eku_list),
                "has_any_eku": ("anyExtendedKeyUsage" in eku_list or "2.5.29.37.0" in eku_list),
                "not_before": nb or datetime.min.replace(tzinfo=timezone.utc),
                "not_after": na or datetime.max.replace(tzinfo=timezone.utc),
                "lifespan_days": (na - nb).days if (na and nb) else 0,
                "is_expired_at_capture": is_exp_capture,
                "not_yet_valid_at_capture": not_yet_capture,
            }

            # ── Non-Anchor Path Aggregation (RFC 5280 §6.1.1 / §6.1.3) ─────────
            resolved_path = cert_block.get("resolved_path") or []
            full_chain = cert_block.get("full_chain") or []
            anchored = bool(cert_block.get("anchored_in_active_store", False))

            non_anchor_certs: list[dict[str, Any]] = []
            path_basis: str

            if anchored and resolved_path:
                path_basis = "VALIDATED_PATH"
                # Exclude root anchor (terminating self-signed anchor or where subject == issuer)
                # Keep index of detailed certs from full_chain for quick metadata lookup
                fc_by_serial = {c.get("serial_number"): c for c in full_chain if c.get("serial_number")}
                fc_by_subject = {c.get("subject_dn"): c for c in full_chain if c.get("subject_dn")}

                for i, p_item in enumerate(resolved_path):
                    # Check if terminating root anchor
                    is_terminating_root = (i == len(resolved_path) - 1 and p_item.get("subject") == p_item.get("issuer"))
                    if is_terminating_root:
                        continue
                    # Match detail dict from full_chain or raw_leaf
                    serial = p_item.get("serial_number") or p_item.get("serial")
                    subject = p_item.get("subject")
                    detail = fc_by_serial.get(serial) or fc_by_subject.get(subject)
                    if detail is not None:
                        non_anchor_certs.append(detail)
                    elif i == 0:
                        non_anchor_certs.append(raw_leaf)
            elif full_chain:
                path_basis = "RECEIVED_CHAIN_FALLBACK"
                # Always include leaf
                non_anchor_certs.append(full_chain[0])
                # Intermediates excluding self-signed root anchors
                for c in full_chain[1:]:
                    if not (c.get("is_self_signed", False) or c.get("subject_dn") == c.get("issuer_dn")):
                        non_anchor_certs.append(c)
            else:
                path_basis = "UNAVAILABLE"

            # Compute aggregates across non-anchor cert set
            rsa_sizes = []
            ec_sizes = []
            weak_hashes = set()
            expired_capture_list = []
            not_yet_capture_list = []
            ca_violated = False

            for idx, c in enumerate(non_anchor_certs):
                pk_alg = c.get("public_key_algorithm", "")
                try:
                    pk_sz = int(c.get("public_key_size", 0))
                except (ValueError, TypeError):
                    pk_sz = 0

                if pk_alg == "RSA" and pk_sz > 0:
                    rsa_sizes.append(pk_sz)
                elif pk_alg in ("EC", "ECDSA", "Ed25519", "Ed448") and pk_sz > 0:
                    ec_sizes.append(pk_sz)

                # Signature hash check
                h_algo = (c.get("signature_hash_algorithm") or "").lower()
                s_name = (c.get("signature_algorithm_name") or "").lower()
                if h_algo in ("md5", "sha1"):
                    weak_hashes.add(h_algo)
                elif "md5" in s_name:
                    weak_hashes.add("md5")
                elif "sha1" in s_name or "sha-1" in s_name:
                    weak_hashes.add("sha1")

                # Capture-time validity
                c_nb = _parse_utc_datetime(c.get("not_before"))
                c_na = _parse_utc_datetime(c.get("not_after"))
                if capture_time is not None:
                    if c_na is not None:
                        expired_capture_list.append(capture_time > c_na)
                    if c_nb is not None:
                        not_yet_capture_list.append(capture_time < c_nb)

                # Intermediate CA constraint check (idx > 0 indicates intermediate)
                if idx > 0:
                    bc = c.get("basic_constraints")
                    if bc is None or not bc.get("ca", False):
                        ca_violated = True

            min_rsa = min(rsa_sizes) if rsa_sizes else None
            min_ec = min(ec_sizes) if ec_sizes else None
            any_exp = any(expired_capture_list) if (capture_time is not None and expired_capture_list) else None
            any_nyv = any(not_yet_capture_list) if (capture_time is not None and not_yet_capture_list) else None

            non_anchor_cert_facts = {
                "path_basis": path_basis,
                "certs": non_anchor_certs,
                "min_rsa_key_size": min_rsa,
                "min_ec_key_size": min_ec,
                "weak_signature_hashes": sorted(list(weak_hashes)),
                "any_cert_expired_at_capture": any_exp,
                "any_cert_not_yet_valid_at_capture": any_nyv,
                "ca_constraint_violated": ca_violated,
            }

        # ── Heuristics Reference ──────────────────────────────────────────────
        heuristics: HeuristicsInfo = {
            "h_cipher_strength": tls_info.get("cipher_strength", "UNKNOWN"),
            "h_forward_secrecy": bool(tls_info.get("forward_secrecy", False)),
            "h_kex_type": tls_info.get("key_exchange", "UNKNOWN"),
        }

        return {
            "stream_id": stream_id,
            "protocol": protocol,
            "capture_time": capture_time,
            "application_data_observed": application_data_observed,
            "analyzer_trust_store": analyzer_trust_store,
            "raw_version": raw_version,
            "tls_version": tls_version,
            "raw_cipher_suite": raw_cipher_suite,
            "cipher_name": cipher_name,
            "tls13_psk_selected": tls13_psk_selected,
            "tls13_key_exchange_group": tls13_key_exchange_group,
            "tls13_key_exchange_mode": tls13_key_exchange_mode,
            "hello_retry_request": hello_retry_request,
            "tls12_kex_type": tls12_kex_type,
            "tls12_named_curve": tls12_named_curve,
            "tls12_dh_prime_bits": tls12_dh_prime_bits,
            "tls12_wire_sig_alg": tls12_wire_sig_alg,
            "downgrade_sentinel": downgrade_sentinel,
            "early_data_offered": early_data_offered,
            "early_data_observed": early_data_observed,
            "handshake_status": handshake_status,
            "flight_alerts": flight_alerts,
            "client_aborted_with_alert": client_aborted_with_alert,
            "server_aborted_with_alert": server_aborted_with_alert,
            "client_offered_versions": client_offered_versions,
            "client_offered_ciphers": client_offered_ciphers,
            "client_supported_groups": client_supported_groups,
            "client_signature_algorithms": client_signature_algorithms,
            "client_sni": client_sni,
            "client_alpn": client_alpn,
            "starttls_offered": starttls_offered,
            "starttls_requested": starttls_requested,
            "starttls_accepted": starttls_accepted,
            "starttls_rejected": starttls_rejected,
            "plaintext_auth_attempted": plaintext_auth_attempted,
            "starttls_status": starttls_status,
            "cert_observable": cert_observable,
            "cert_unobservable_reason": cert_unobservable_reason,
            "chain_length": chain_length,
            "hostname_match": hostname_match,
            "revocation_status": revocation_status,
            "leaf_cert": leaf_cert,
            "non_anchor_cert_facts": non_anchor_cert_facts,
            "heuristics": heuristics,
        }


def build_rule_input(session: dict[str, Any], trust_store_manager: Optional[Any] = None) -> RuleInput:
    """Convenience functional wrapper around InputBuilder.build."""
    return InputBuilder.build(session, trust_store_manager=trust_store_manager)
