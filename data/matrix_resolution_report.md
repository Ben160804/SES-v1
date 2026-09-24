# Deterministic Scenario Contract & Resolution Report (Fix #2)

## Executive Summary

This document provides the authoritative resolution audit for all 126 scenarios in the `mailtest` forensic testbed matrix following the implementation of **Fix #2: Executable Scenario Contracts & Deterministic Resolution**.

### Key Architectural Achievements
1. **Deterministic Execution Contract Layer**: Created `data/scenario_contracts.json` containing formal contracts for exactly 126 scenarios, decoupling matrix intent from execution mechanics.
2. **Zero Heuristics & Anti-Hardcoding**: Completely eliminated all hardcoded scenario-ID bypasses (`PROVEN_BASELINES`, `PROVEN_IMAP_BASELINES`, `PROVEN_POP3_BASELINES`) from `testbed/runner/stager.py` and resolver.
3. **Deterministic Selection Policy**: Formulated and enforced the deterministic class-ranking policy: `1. IANA Rec=Y, 2. Rec=N, 3. Rec=D, 4. Name ASC`. Ambiguity is eliminated on the wire without guessing.
4. **Scientific Decoupling of PKI & TLS**: Disentangled X.509 CA signature algorithm (`cert_sig_algo`) from server leaf public key (`server_leaf_key_type`). In TLS 1.2, leaf key compatibility is derived directly from the selected cipher authentication construction. In TLS 1.3, standard RSA-2048 leaf keys are used without fabricating an ECDSA default.
5. **Dynamic Runtime Capability Probing**: Refactored `ContainerRuntimeInspector` to query all TLS 1.3 ciphers dynamically from the authoritative IANA database, eliminating static cipher suite arguments.
6. **Explicit Discrepancy Telemetry**: Maintained all 11 `MATRIX_ORACLE_INCONSISTENT` rows as explicitly `UNRESOLVABLE` with traceable telemetry, preventing false assertions.

---

## Matrix Resolution Statistics

| Category | Count | Percentage | Description |
| :--- | :---: | :---: | :--- |
| **STANDARD (RESOLVED)** | **90** | 71.4% | Concrete wire cipher deterministically selected and staged |
| **DEDICATED_HARNESS** | **19** | 15.1% | Dedicated protocol/MITM/TLS testbed harness required |
| **UNRESOLVABLE** | **11** | 8.7% | Matrix specification contradictory (oracle mismatch) |
| **NOT_APPLICABLE** | **6** | 4.8% | Cleartext email protocol interaction (no TLS on wire) |
| **MULTIPLE_CANDIDATES** | **0** | 0.0% | Zero scenarios remain ambiguously unselected |
| **TOTAL** | **126** | 100.0% | Authoritative matrix coverage |

---

## Proof of Determinism & Byte-Identity

Across two completely independent, repeated full-matrix resolution sweeps:
- **Run 1 SHA-256 Digest**: `94e56ffc042054be36e61f1c7ac0c6edbd4d94fefa0fa96d431fc2a33723db6f`
- **Run 2 SHA-256 Digest**: `94e56ffc042054be36e61f1c7ac0c6edbd4d94fefa0fa96d431fc2a33723db6f`
- **Match**: `100% BYTE-IDENTICAL`

---

## Formally UNRESOLVABLE Scenarios (11 Total)

These scenarios represent genuine matrix contradictions where the matrix row demands a cipher strength that cannot mathematically be satisfied by the specified protocol version and key exchange.

| Scenario ID | Protocol | TLS Ver | KEX | Strength | Reason | Missing Information |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| `PCAP-006` | SMTP | 1.0 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.0, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-007` | SMTP | 1.1 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.1, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-025` | IMAP | 1.0 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.0, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-026` | IMAP | 1.1 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.1, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-044` | POP3 | 1.0 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.0, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-045` | POP3 | 1.1 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.1, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-073` | SMTP | 1.0 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.0, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-078` | SMTP | 1.1 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.1, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-094` | SMTP | 1.1 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.1, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-096` | SMTP | 1.0 | `(none)` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" for TLS 1.0, but structural candidates only achieve ["BROKEN", "MEDIUM", "WEAK"] in analysis/ciphers.py |
| `PCAP-112` | SMTP | 1.2 | `DHE` | HIGH | MATRIX_ORACLE_INCONSISTENT | Oracle expectation mismatch: matrix specifies cipher_strength="HIGH" with DHE, but all DHE suites in analysis/ciphers.py are classified as "WEAK" due to IANA deprecation (Recommended="D") |

---

## Dedicated Harness Scenarios (19 Total)

| Scenario ID | Protocol | Dedicated Harness | Status | Harness Parameters |
| :--- | :---: | :--- | :---: | :--- |
| `PCAP-064` | SMTP | `mitm_starttls_strip` | `IMPLEMENTED` | `{"protocol": "smtp", "port": 25, "action": "strip_starttls"}` |
| `PCAP-065` | SMTP | `mitm_starttls_strip` | `IMPLEMENTED` | `{"protocol": "smtp", "port": 25, "action": "strip_starttls"}` |
| `PCAP-066` | IMAP | `mitm_starttls_strip` | `NOT_IMPLEMENTED` | `{"protocol": "imap", "port": 143, "action": "strip_starttls"}` |
| `PCAP-067` | IMAP | `mitm_starttls_strip` | `NOT_IMPLEMENTED` | `{"protocol": "imap", "port": 143, "action": "strip_starttls"}` |
| `PCAP-068` | POP3 | `mitm_starttls_strip` | `IMPLEMENTED` | `{"protocol": "pop3", "port": 110, "action": "strip_starttls"}` |
| `PCAP-069` | POP3 | `mitm_starttls_strip` | `IMPLEMENTED` | `{"protocol": "pop3", "port": 110, "action": "strip_starttls"}` |
| `PCAP-106` | SMTP | `psk_resumption` | `NOT_IMPLEMENTED` | `{"psk_mode": "PSK_ONLY", "tls_version": "1.3"}` |
| `PCAP-107` | SMTP | `psk_dhe_resumption` | `IMPLEMENTED` | `{"psk_mode": "PSK_DHE", "tls_version": "1.3"}` |
| `PCAP-108` | SMTP | `hello_retry_request` | `NOT_IMPLEMENTED` | `{"client_initial_key_share": "secp256r1", "server_required_group": "x25519"}` |
| `PCAP-109` | SMTP | `downgrade_sentinel` | `NOT_IMPLEMENTED` | `{"client_offered_max": "1.3", "server_negotiated": "1.2", "sentinel": "DOWNGRD\\x01"}` |
| `PCAP-110` | SMTP | `legacy_client_sentinel` | `IMPLEMENTED` | `{"client_offered_max": "1.2", "server_negotiated": "1.2"}` |
| `PCAP-113` | SMTP | `server_rejects_starttls` | `IMPLEMENTED` | `{"smtp_code": 454}` |
| `PCAP-114` | SMTP | `custom_extension_50` | `NOT_IMPLEMENTED` | `{"ext13": "standard_sig_algs", "ext50": "distinct_cert_sig_algs"}` |
| `PCAP-119` | SMTP | `dag_pki` | `NOT_IMPLEMENTED` | `{"topology": "multi_issuer_dag", "backtracking_required": true}` |
| `PCAP-120` | SMTP | `unadvertised_starttls` | `IMPLEMENTED` | `{"server_advertises_starttls": false, "client_sends_starttls": true}` |
| `PCAP-121` | SMTP | `server_sends_fatal_alert` | `IMPLEMENTED` | `{"alert_level": "fatal", "alert_description": 40}` |
| `PCAP-122` | SMTP | `early_data_0rtt` | `NOT_IMPLEMENTED` | `{"early_data": true}` |
| `PCAP-125` | SMTP | `sentinel_suppression` | `NOT_IMPLEMENTED` | `{"client_offered_max": "1.3", "server_negotiated": "1.2", "sentinel": false}` |
| `PCAP-126` | SMTP | `cert_rsa1024` | `IMPLEMENTED` | `{"leaf_key_algorithm": "rsa", "leaf_key_size": 1024, "seclevel": 0}` |

---

## Cleartext Not Applicable Scenarios (6 Total)

| Scenario ID | Protocol | Mode | Reason |
| :--- | :---: | :--- | :--- |
| `PCAP-004` | SMTP | `none` | Cleartext protocol interaction; no TLS negotiation occurs on wire |
| `PCAP-023` | IMAP | `none` | Cleartext protocol interaction; no TLS negotiation occurs on wire |
| `PCAP-042` | POP3 | `none` | Cleartext protocol interaction; no TLS negotiation occurs on wire |
| `PCAP-061` | SMTP | `none` | Cleartext protocol interaction; no TLS negotiation occurs on wire |
| `PCAP-062` | IMAP | `none` | Cleartext protocol interaction; no TLS negotiation occurs on wire |
| `PCAP-063` | POP3 | `none` | Cleartext protocol interaction; no TLS negotiation occurs on wire |

---

## Standard Resolved Scenarios (90 Total)

| Scenario ID | Proto | Ver | Class | Selected IANA Cipher Suite | OpenSSL Name | Candidates | Leaf Key |
| :--- | :---: | :---: | :---: | :--- | :--- | :---: | :---: |
| `PCAP-001` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-002` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-003` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-005` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-008` | SMTP | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-009` | SMTP | 1.3 | WEAK | `TLS_AES_128_CCM_8_SHA256` | `TLS_AES_128_CCM_8_SHA256` | 1 | `rsa-2048` |
| `PCAP-010` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-011` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-012` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-013` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-014` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-015` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-016` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-017` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-018` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-019` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-020` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-021` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-022` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-024` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-027` | IMAP | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-028` | IMAP | 1.3 | WEAK | `TLS_AES_128_CCM_8_SHA256` | `TLS_AES_128_CCM_8_SHA256` | 1 | `rsa-2048` |
| `PCAP-029` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-030` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-031` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-032` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-033` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-034` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-035` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-036` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-037` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-038` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-039` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-040` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-041` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-043` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-046` | POP3 | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-047` | POP3 | 1.3 | WEAK | `TLS_AES_128_CCM_8_SHA256` | `TLS_AES_128_CCM_8_SHA256` | 1 | `rsa-2048` |
| `PCAP-048` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-049` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-050` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-051` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-052` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-053` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-054` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-055` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-056` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-057` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-058` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-059` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-060` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-070` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-071` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-072` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-074` | SMTP | 1.1 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 2 | `ecdsa-256` |
| `PCAP-075` | SMTP | 1.2 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-076` | SMTP | 1.1 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-077` | SMTP | 1.3 | WEAK | `TLS_AES_128_CCM_8_SHA256` | `TLS_AES_128_CCM_8_SHA256` | 1 | `rsa-2048` |
| `PCAP-079` | SMTP | 1.2 | WEAK | `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` | `ECDHE-ECDSA-AES128-CCM8` | 2 | `ecdsa-256` |
| `PCAP-080` | SMTP | 1.2 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 6 | `ecdsa-256` |
| `PCAP-081` | SMTP | 1.0 | WEAK | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `DHE-RSA-AES128-SHA` | 8 | `rsa-2048` |
| `PCAP-082` | SMTP | 1.2 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-083` | SMTP | 1.0 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 2 | `ecdsa-256` |
| `PCAP-084` | SMTP | 1.0 | WEAK | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `DHE-RSA-AES128-SHA` | 8 | `rsa-2048` |
| `PCAP-085` | SMTP | 1.0 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-086` | SMTP | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-087` | SMTP | 1.1 | WEAK | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `DHE-RSA-AES128-SHA` | 8 | `rsa-2048` |
| `PCAP-088` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-089` | SMTP | 1.1 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 2 | `ecdsa-256` |
| `PCAP-090` | SMTP | 1.3 | WEAK | `TLS_AES_128_CCM_8_SHA256` | `TLS_AES_128_CCM_8_SHA256` | 1 | `rsa-2048` |
| `PCAP-091` | SMTP | 1.0 | WEAK | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `DHE-RSA-AES128-SHA` | 8 | `rsa-2048` |
| `PCAP-092` | SMTP | 1.1 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 2 | `ecdsa-256` |
| `PCAP-093` | SMTP | 1.2 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 6 | `ecdsa-256` |
| `PCAP-095` | SMTP | 1.2 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-097` | SMTP | 1.1 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-098` | SMTP | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-099` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-100` | SMTP | 1.1 | WEAK | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `DHE-RSA-AES128-SHA` | 8 | `rsa-2048` |
| `PCAP-101` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-102` | SMTP | 1.2 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-103` | SMTP | 1.2 | BROKEN | `TLS_ECDHE_ECDSA_WITH_NULL_SHA` | `ECDHE-ECDSA-NULL-SHA` | 1 | `ecdsa-256` |
| `PCAP-104` | SMTP | 1.2 | MEDIUM | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `ECDHE-ECDSA-AES128-SHA` | 6 | `ecdsa-256` |
| `PCAP-105` | SMTP | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-111` | SMTP | 1.2 | HIGH | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `ECDHE-ECDSA-AES128-GCM-SHA256` | 7 | `ecdsa-256` |
| `PCAP-115` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-116` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-117` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-118` | SMTP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-123` | IMAP | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |
| `PCAP-124` | POP3 | 1.3 | HIGH | `TLS_AES_128_CCM_SHA256` | `TLS_AES_128_CCM_SHA256` | 4 | `rsa-2048` |

---

## Representative Resolution Examples

### 1. Ordinary CLASS Scenario (PCAP-005: SMTP STARTTLS 1.3 HIGH)
```json
{
  "scenario_id": "PCAP-005",
  "intent": "smtp STARTTLS-upgraded (inventory)",
  "tls_version": "1.3",
  "matrix_kex": "(none)",
  "cert_auth_intent": "ECDSA",
  "matrix_cipher_strength": "HIGH",
  "generation_mode": "STANDARD",
  "cipher_mode": "CLASS",
  "iana_candidates": [
    "TLS_AES_128_GCM_ASCONHASH256",
    "TLS_AES_128_CCM_ASCONHASH256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256"
  ],
  "iana_candidate_count": 6,
  "current_runtime_candidates": [
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
  ],
  "current_runtime_candidate_count": 4,
  "candidate_count_before_selection": 4,
  "candidate_names_after_all_filters": [
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
  ],
  "selected_cipher": "TLS_AES_128_CCM_SHA256",
  "selection_basis": "EXPLICIT_REPOSITORY_POLICY",
  "selection_rank": 1,
  "cipher_resolution_status": "RESOLVED",
  "runtime_status": "SUPPORTED",
  "leaf_key_algorithm": "rsa",
  "leaf_key_size": 2048,
  "special_harness": null,
  "special_harness_requirement": null,
  "special_harness_parameters": {},
  "cipher_telemetry": {
    "selected_cipher": "TLS_AES_128_CCM_SHA256",
    "openssl_name": "TLS_AES_128_CCM_SHA256",
    "selection_rank": 1,
    "total_runtime_candidates": 4,
    "leaf_key_algorithm": "rsa",
    "leaf_key_size": 2048,
    "policy": "1. IANA Rec=Y, 2. Rec=N, 3. Rec=D, 4. Name ASC"
  },
  "reason": "Deterministically resolved via repository policy (4 runtime candidates)",
  "missing_information": null,
  "traceable_constraints": {
    "initial_iana_universe": 354,
    "version_filter": {
      "rule": "RFC 8446 TLS 1.3 symmetric-only suites (kex=TLS13_EPHEMERAL)",
      "count": 7
    },
    "kex_filter": {
      "rule": "RFC 8446 KEX decoupled from cipher suites",
      "count": 7
    },
    "strength_filter": {
      "rule": "Target cipher strength: HIGH",
      "count": 6
    },
    "auth_filter": {
      "rule": "TLS 1.3 or non-cert decoupled authentication",
      "count": 6
    },
    "iana_candidate_count": 6,
    "runtime_supported_count": 4
  },
  "strength_discrepancy": null
}
```

### 2. Dedicated Phenomenon Scenario (PCAP-108: SMTP STARTTLS 1.3 HelloRetryRequest)
```json
{
  "scenario_id": "PCAP-108",
  "intent": "TLS 1.3 HelloRetryRequest",
  "tls_version": "1.3",
  "matrix_kex": "ECDHE",
  "cert_auth_intent": "ECDSA",
  "matrix_cipher_strength": "HIGH",
  "generation_mode": "DEDICATED_HARNESS",
  "cipher_mode": "CLASS",
  "iana_candidates": [],
  "iana_candidate_count": 0,
  "current_runtime_candidates": [],
  "current_runtime_candidate_count": 0,
  "candidate_count_before_selection": 0,
  "candidate_names_after_all_filters": [],
  "selected_cipher": null,
  "selection_basis": "NONE",
  "selection_rank": null,
  "cipher_resolution_status": "SPECIAL_HARNESS",
  "runtime_status": "NOT_APPLICABLE",
  "leaf_key_algorithm": "rsa",
  "leaf_key_size": 2048,
  "special_harness": "hello_retry_request",
  "special_harness_requirement": "hello_retry_request",
  "special_harness_parameters": {
    "client_initial_key_share": "secp256r1",
    "server_required_group": "x25519"
  },
  "cipher_telemetry": {},
  "reason": "Dedicated test harness required: hello_retry_request (status: NOT_IMPLEMENTED)",
  "missing_information": "Dedicated harness not yet implemented: hello_retry_request",
  "traceable_constraints": {
    "dedicated_harness": "hello_retry_request"
  },
  "strength_discrepancy": null
}
```

### 3. Formally Unresolvable Scenario (PCAP-006: Matrix Oracle Contradiction)
```json
{
  "scenario_id": "PCAP-006",
  "intent": "smtp implicit-TLS (inventory)",
  "tls_version": "1.0",
  "matrix_kex": "(none)",
  "cert_auth_intent": "ECDSA",
  "matrix_cipher_strength": "HIGH",
  "generation_mode": "UNRESOLVABLE",
  "cipher_mode": "CLASS",
  "iana_candidates": [],
  "iana_candidate_count": 0,
  "current_runtime_candidates": [],
  "current_runtime_candidate_count": 0,
  "candidate_count_before_selection": 0,
  "candidate_names_after_all_filters": [],
  "selected_cipher": null,
  "selection_basis": "NONE",
  "selection_rank": null,
  "cipher_resolution_status": "UNRESOLVABLE",
  "runtime_status": "NO_RUNTIME_CANDIDATE",
  "leaf_key_algorithm": null,
  "leaf_key_size": null,
  "special_harness": null,
  "special_harness_requirement": null,
  "special_harness_parameters": {},
  "cipher_telemetry": {},
  "reason": "MATRIX_ORACLE_INCONSISTENT",
  "missing_information": "Oracle expectation mismatch: matrix specifies cipher_strength=\"HIGH\" for TLS 1.0, but structural candidates only achieve [\"BROKEN\", \"MEDIUM\", \"WEAK\"] in analysis/ciphers.py",
  "traceable_constraints": {
    "status": "MATRIX_ORACLE_INCONSISTENT"
  },
  "strength_discrepancy": "MATRIX_ORACLE_INCONSISTENT"
}
```
