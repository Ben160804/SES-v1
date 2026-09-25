"""
Policy-Neutral Forensic Observations Layer (OBS-*).

Implements 12 factual, policy-neutral forensic observation functions evaluating
framing, identity, handshake, trust provenance, and observability.
"""

from ..schema import RuleInput, ObservationResult, EvidenceItem


class ObservationsEvaluator:
    """Evaluates RuleInput against 12 policy-neutral forensic observations."""

    def evaluate_all(self, r_in: RuleInput) -> list[ObservationResult]:
        return [
            self.eval_obs_starttls_01(r_in),
            self.eval_obs_starttls_advertised_not_used(r_in),
            self.eval_obs_starttls_03(r_in),
            self.eval_obs_starttls_unadvertised_request(r_in),
            self.eval_obs_sec_plaintext_auth(r_in),
            self.eval_obs_cert_hostname_mismatch(r_in),
            self.eval_obs_analyzer_trust_status(r_in),
            self.eval_obs_analyzer_chain_status(r_in),
            self.eval_obs_proto_01(r_in),
            self.eval_obs_proto_02(r_in),
            self.eval_obs_proto_03(r_in),
            self.eval_obs_cert_01(r_in),
        ]

    def eval_obs_starttls_01(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        status = r_in.get("starttls_status", "")
        detected = (status == "CLEARTEXT_NO_ENCRYPTION")
        ev = [EvidenceItem(sid, "starttls_status", status, "STARTTLS State Machine -> Status")]
        return ObservationResult(
            obs_id="OBS-STARTTLS-01",
            name="Cleartext Unencrypted Session",
            category="Framing",
            detected=detected,
            evidence=ev,
            description="Session conducted completely in plaintext with no TLS encapsulation." if detected else "Session did not operate as pure cleartext.",
        )

    def eval_obs_starttls_advertised_not_used(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        offered = r_in.get("starttls_offered", False)
        tls_ver = r_in.get("tls_version")
        detected = bool(offered and tls_ver is None)
        ev = [
            EvidenceItem(sid, "starttls_offered", offered, "STARTTLS State Machine -> Offered"),
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
        ]
        return ObservationResult(
            obs_id="OBS-STARTTLS-ADVERTISED-NOT-USED",
            name="STARTTLS Advertised But Not Utilized",
            category="Framing",
            detected=detected,
            evidence=ev,
            description=(
                "Server advertised STARTTLS capability, but session proceeded in cleartext. "
                "Indicates opportunistic cleartext fallback, unconfigured client, or potential upstream stripping if captured at server."
                if detected else "STARTTLS was either not offered or TLS was established."
            ),
        )

    def eval_obs_starttls_03(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        status = r_in.get("starttls_status", "")
        rejected = r_in.get("starttls_rejected", False)
        detected = bool(status == "STARTTLS_REJECTED" or rejected)
        ev = [
            EvidenceItem(sid, "starttls_status", status, "STARTTLS State Machine -> Status"),
            EvidenceItem(sid, "starttls_rejected", rejected, "STARTTLS State Machine -> Rejected"),
        ]
        return ObservationResult(
            obs_id="OBS-STARTTLS-03",
            name="STARTTLS Upgrade Rejection",
            category="Framing",
            detected=detected,
            evidence=ev,
            description="Server issued an explicit negative response (4xx, 5xx, -ERR, NO/BAD) to client upgrade request." if detected else "No STARTTLS upgrade rejection observed.",
        )

    def eval_obs_starttls_unadvertised_request(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        requested = r_in.get("starttls_requested", False)
        offered = r_in.get("starttls_offered", False)
        detected = bool(requested and not offered)
        ev = [
            EvidenceItem(sid, "starttls_requested", requested, "STARTTLS State Machine -> Requested"),
            EvidenceItem(sid, "starttls_offered", offered, "STARTTLS State Machine -> Offered"),
        ]
        return ObservationResult(
            obs_id="OBS-STARTTLS-UNADVERTISED-REQUEST",
            name="Unadvertised STARTTLS Request",
            category="Framing",
            detected=detected,
            evidence=ev,
            description="Client requested STARTTLS without observing capability advertisement (RFC 3207 §4 protocol anomaly)." if detected else "STARTTLS was not requested blindly.",
        )

    def eval_obs_sec_plaintext_auth(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        auth = r_in.get("plaintext_auth_attempted", False)
        tls_ver = r_in.get("tls_version")
        detected = bool(auth and tls_ver is None)
        ev = [
            EvidenceItem(sid, "plaintext_auth_attempted", auth, "STARTTLS State Machine -> Plaintext Auth"),
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
        ]
        return ObservationResult(
            obs_id="OBS-SEC-PLAINTEXT-AUTH",
            name="Cleartext Authentication Transmission",
            category="Security",
            detected=detected,
            evidence=ev,
            description="Cleartext authentication tokens (AUTH, USER, PASS, LOGIN) transmitted without TLS encryption." if detected else "No cleartext authentication observed outside TLS.",
        )

    def eval_obs_cert_hostname_mismatch(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        match_status = r_in.get("hostname_match", "SKIPPED_NO_SNI")
        detected = (match_status == "MISMATCH")
        ev = [EvidenceItem(sid, "hostname_match", match_status, "Certificate Pipeline -> Hostname Matching")]
        return ObservationResult(
            obs_id="OBS-CERT-HOSTNAME-MISMATCH",
            name="Certificate Hostname Mismatch",
            category="Identity",
            detected=detected,
            evidence=ev,
            description="Server certificate SAN/CN identifiers do not match ClientHello SNI under RFC 9525 rules." if detected else f"Hostname status: {match_status}.",
        )

    def eval_obs_analyzer_trust_status(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        ts_info = r_in.get("analyzer_trust_store") or {}
        store_type = ts_info.get("active_store", "unknown")
        anchored = ts_info.get("anchored", False)
        err = ts_info.get("verification_error")
        desc = ts_info.get("description", "")
        ev = [
            EvidenceItem(sid, "analyzer_trust_store.active_store", store_type, "Analyzer Trust Store Configuration"),
            EvidenceItem(sid, "analyzer_trust_store.anchored", anchored, "Analyzer Trust Store Validation"),
            EvidenceItem(sid, "analyzer_trust_store.verification_error", err, "Analyzer Trust Store Verification Error"),
        ]
        desc_text = (
            f"Analyzer trust store '{store_type}' ({desc}): "
            f"anchored={anchored}, verification_error={err}. "
            f"Statement about analyzer local environment, NOT client PKIX compliance."
        )
        return ObservationResult(
            obs_id="OBS-ANALYZER-TRUST-STATUS",
            name="Analyzer Trust Store Status",
            category="Trust",
            detected=True,
            evidence=ev,
            description=desc_text,
        )

    def eval_obs_analyzer_chain_status(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        chain_len = r_in.get("chain_length", 0)
        facts = r_in.get("non_anchor_cert_facts") or {}
        basis = facts.get("path_basis", "UNAVAILABLE")
        non_anchor_count = len(facts.get("certs", []))
        detected = (chain_len > 0)
        ev = [
            EvidenceItem(sid, "chain_length", chain_len, "Wire Certificate Message Count"),
            EvidenceItem(sid, "non_anchor_cert_facts.path_basis", basis, "Certificate Path Aggregation Basis"),
            EvidenceItem(sid, "non_anchor_cert_facts.count", non_anchor_count, "Non-Anchor Cert Set Count"),
        ]
        desc_text = (
            f"Wire certificate chain length: {chain_len}; path basis: {basis}; "
            f"non-anchor certificates evaluated: {non_anchor_count}."
            if detected else "No certificates observed on wire."
        )
        return ObservationResult(
            obs_id="OBS-ANALYZER-CHAIN-STATUS",
            name="Analyzer Certificate Chain Status",
            category="Trust",
            detected=detected,
            evidence=ev,
            description=desc_text,
        )

    def eval_obs_proto_01(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        hrr = r_in.get("hello_retry_request", False)
        ev = [EvidenceItem(sid, "hello_retry_request", hrr, "ServerHello -> HelloRetryRequest Random Sentinel")]
        return ObservationResult(
            obs_id="OBS-PROTO-01",
            name="HelloRetryRequest Negotiation",
            category="Handshake",
            detected=bool(hrr),
            evidence=ev,
            description="RFC 8446 HelloRetryRequest exchange triggered by key share mismatch." if hrr else "No HelloRetryRequest observed.",
        )

    def eval_obs_proto_02(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        mode = r_in.get("tls13_key_exchange_mode")
        detected = (mode == "PSK_ONLY")
        ev = [EvidenceItem(sid, "tls13_key_exchange_mode", mode, "TLS 1.3 Key Exchange Mode")]
        return ObservationResult(
            obs_id="OBS-PROTO-02",
            name="TLS 1.3 PSK-Only Resumption",
            category="Handshake",
            detected=detected,
            evidence=ev,
            description="TLS 1.3 session resumption without newly negotiated ephemeral key share." if detected else f"Key exchange mode: {mode or 'NONE'}.",
        )

    def eval_obs_proto_03(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        ds = r_in.get("downgrade_sentinel") or {}
        det = ds.get("detected", False)
        stype = ds.get("type")
        ev = [
            EvidenceItem(sid, "downgrade_sentinel.detected", det, "ServerHello.random -> Sentinel Bytes"),
            EvidenceItem(sid, "downgrade_sentinel.type", stype, "ServerHello.random -> Sentinel Type"),
        ]
        return ObservationResult(
            obs_id="OBS-PROTO-03",
            name="RFC 8446 Downgrade Sentinel Detected",
            category="Handshake",
            detected=bool(det),
            evidence=ev,
            description=f"RFC 8446 downgrade protection sentinel ({stype}) detected in ServerHello.random." if det else "No downgrade sentinel detected.",
        )

    def eval_obs_cert_01(self, r_in: RuleInput) -> ObservationResult:
        sid = r_in.get("stream_id", 0)
        observable = r_in.get("cert_observable", False)
        tls_ver = r_in.get("tls_version")
        detected = bool(not observable and tls_ver == "TLS 1.3")
        ev = [
            EvidenceItem(sid, "cert_observable", observable, "Certificate Pipeline"),
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
        ]
        return ObservationResult(
            obs_id="OBS-CERT-01",
            name="TLS 1.3 Encrypted Certificate Handshake",
            category="Observability",
            detected=detected,
            evidence=ev,
            description="Certificate messages encrypted under TLS 1.3; passive X.509 extraction impossible without private keys." if detected else "Certificate was observable or session was not TLS 1.3.",
        )
