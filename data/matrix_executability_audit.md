# Forensic Matrix Executability & Determinism Audit (Fix #2 — Pass 1)

> **Audit Status**: Formal Pre-Implementation Forensic Audit (Pass 1 Complete — Audit Only)
> **Scope**: 126 Scenario Matrix Rows (`data/pcap_generation_matrix.csv`)
> **Rule Enforcement**: ZERO code modifications during Pass 1; no CSV edits; no heuristic bypasses; no silent repairs.

---

## Executive Summary

```text
Total Scenarios Audited:              126
  - EXECUTABLE_NOW:                   6
  - DEDICATED_HARNESS_REQUIRED (Sole): 5
  - MULTIPLE Blockers (Compound):     115

Underlying Blocker Occurrence Across All 126 Scenarios:
  - Missing Scenario Parameters:      113 scenarios
  - Resolver Blockers (MULTIPLE):     111 scenarios
  - Stager Blockers:                  106 scenarios
  - Client Blockers:                  6 scenarios
  - PKI Architecture Blockers:        109 scenarios
  - Dedicated Harnesses Required:     18 scenarios
  - Matrix Oracle Inconsistencies:    11 scenarios
```

---

## PASS 1A — Source-of-Truth Boundaries

To prevent cross-layer leakage and eliminate synthetic heuristics, the authoritative scope of every project component is rigorously defined below:

### 1. IANA TLS Parameters Registry (`data/tls_ciphers.csv`)
**Authoritative ONLY for:**
- 16-bit Cipher Suite numerical identifier (e.g. `0x00,0x9F` -> `0x009f`).
- Official IANA Cipher Suite Description name (e.g. `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`).
- DTLS applicability flag (`DTLS-OK`: `Y`/`N`).
- IANA Recommendation status (`Recommended`: `Y` = Recommended, `N` = Not Recommended, `D` = Deprecated per RFC 10015).
- Formal RFC citation references (e.g. `[RFC5288][RFC10015]`).

**Explicitly NOT Authoritative for (Must NOT be inferred from IANA):**
- Project security classification tiers (`HIGH`, `MEDIUM`, `WEAK`, `BROKEN`).
- TLS version boundaries (IANA registry does NOT have a TLS version column; suites valid in TLS 1.0 vs 1.2 vs 1.3 are external RFC specifications).
- Certificate topology, leaf key types, or key sizes.
- Certificate validity, SAN behavior, or PKIX trust store states.
- Mail protocol commands (STARTTLS, STLS, EHLO) or MITM proxy behavior.
- TLS 1.3 key shares, HelloRetryRequest conditions, or PSK resumption.

### 2. Forensic Cipher Suite Classifier (`analysis/ciphers.py`)
**Authoritative ONLY for:**
- The repository's canonical 4-tier cryptographic strength taxonomy (`HIGH`, `MEDIUM`, `WEAK`, `BROKEN`).
- Mathematical Forward Secrecy (`has_pfs`) determination.
- Key exchange mechanism parsing (`ANONYMOUS`, `TLS13_EPHEMERAL`, `ECDHE`, `DHE`, `PSK`, `ECDHE_PSK`, `DHE_PSK`, `KERBEROS`, `RSA_STATIC`).
- Bidirectional translation between IANA names and OpenSSL runtime strings (`iana_to_openssl`, `openssl_to_iana`).

### 3. Scenario Matrix (`data/pcap_generation_matrix.csv`)
**Authoritative ONLY for:**
- Scenario metadata (`scenario_id`, `layer`, `description`).
- High-level scenario intent (`protocol`, `tls_presence`, `starttls_integrity`, `tls_version`, `cipher_strength`, `cert_validity`, `cert_chain_shape`, `cert_sig_algo`, `hostname_match`, `auth_outcome`).
- Oracle comparison expectations (`expected_starttls_status`, `expected_trust_status`, `expected_protocol`).
- Dedicated phenomenon tags (`generator_requirement`, `tls13_kex_mode`, `tls12_kex_type`, `downgrade_sentinel`).

### 4. Scenario Specification Normalizer (`testbed/runner/spec.py`)
**Authoritative for:**
- Normalizing CSV strings into typed, frozen dataclasses (`ScenarioSpec`, `ServerSpec`, `ClientSpec`, `NetworkSpec`, `OracleSpec`, `PKISpec`).
- Standard and non-standard email port mappings (RFC 8314 / RFC 5321 / RFC 3501 / RFC 1939).
- Generating deterministic `expected.json` artifacts with assertion maps.

### 5. Traceable TLS Cipher Resolver (`testbed/runner/resolver.py`)
**Authoritative for:**
- Intersecting scenario constraints with IANA parameters and live target container OpenSSL capabilities (`ContainerRuntimeInspector`).
- Categorizing constraint outcomes (`UNIQUE`, `MULTIPLE_CANDIDATES`, `NO_CANDIDATE`, `NOT_APPLICABLE`, `PROTOCOL_IMPOSSIBILITY`, `SPECIAL_SCENARIO`).
- Auditing oracle strength discrepancies without synthetic fallback.

### 6. Daemon Stagers (`testbed/runner/stager.py`)
**Authoritative for:**
- Rendering daemon configurations (`main.cf` for Postfix, `dovecot.conf` for Dovecot) and staging certificates.
- *Current Defect*: Contains hardcoded bypass sets (`PROVEN_BASELINES`, `PROVEN_IMAP_BASELINES`, `PROVEN_POP3_BASELINES`) to allow 10 specific baseline scenarios to stage despite resolver `MULTIPLE_CANDIDATES`.

### 7. Protocol Client Drivers (`testbed/runner/client.py`)
**Authoritative for:**
- Scripting client-side SMTP, IMAP, and POP3 state machines, TLS negotiation, authentication, and error trapping.

### 8. PKI Factory (`testbed/pki/generator/make_certs.py`)
**Authoritative for:**
- Generating root CAs, intermediates, and scenario-specific leaf certificates and key pairs.
- *Current Defect*: Conflates CA signature algorithm (`cert_sig_algo`) with leaf public key type in `_leaf_key_for()`.

### 9. Adversarial MITM Proxy Harness (`testbed/mitm/*`)
**Authoritative for:**
- Wire-level STARTTLS tampering (suppressing `250-STARTTLS` or `STLS` banner announcements).
- *Current Defect*: Only supports SMTP (port 25) and POP3 (port 110); IMAP proxy is absent.

---

## PASS 1B — Cipher-Strength Authority (`analysis/ciphers.py`)

The repository's 4-tier classification model is strictly implemented in `analysis/ciphers.py` using a load-bearing evaluation order:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 1: BROKEN                                                         │
│ Criteria: Anonymous KEX (no authentication) OR NULL cipher OR EXPORT  │
│           grade OR RC4 OR 3DES OR DES OR MD5 hashing                   │
│ Count in IANA Registry: 98 suites                                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 2: WEAK                                                           │
│ Criteria: IANA Deprecated (Recommended == 'D')                         │
│           OR Non-PFS Key Exchange (Static RSA, plain PSK, Kerberos)    │
│           OR Truncated 64-bit authentication tags (CCM_8 / CCM-8)      │
│ Note: Traps ALL DHE suites (due to Rec='D') and Static RSA GCM suites. │
│ Count in IANA Registry: 206 suites                                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 3: HIGH                                                           │
│ Criteria: Forward Secrecy (has_pfs == True)                            │
│           AND Modern AEAD encryption (GCM, POLY1305, full CCM)         │
│           AND NOT Deprecated (Rec != 'D')                              │
│ Count in IANA Registry: 26 suites                                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 4: MEDIUM (Catch-all for remaining PFS suites)                    │
│ Criteria: Forward Secrecy (has_pfs == True)                            │
│           AND Legacy CBC mode OR Camellia/ARIA/SEED                    │
│ Count in IANA Registry: 24 suites                                      │
└────────────────────────────────────────────────────────────────────────┘
```

### Machine-Readable Breakdown of Repository Cipher Universe

| Tier | IANA Count | Ephemeral PFS | Required Ciphers / Hash Modes | Examples |
|---|---|---|---|---|
| **HIGH** | 26 | Guaranteed (`True`) | AEAD (AES-GCM, ChaCha20-Poly1305, AES-CCM) + Recommended | `TLS_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |
| **MEDIUM** | 24 | Guaranteed (`True`) | Legacy CBC mode + Ephemeral (ECDHE/DHE) | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`, `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` |
| **WEAK** | 206 | None (`False`) or Deprecated | Static RSA, Plain PSK, Truncated CCM_8, or IANA Deprecated (`Rec=D`) | `TLS_RSA_WITH_AES_256_GCM_SHA384`, `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` |
| **BROKEN** | 98 | Any | Anonymous, NULL, EXPORT, RC4, 3DES, DES, MD5 | `TLS_DH_anon_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_3DES_EDE_CBC_SHA` |
| **UNCLASSIFIED** | 0 | N/A | None (100% of 354 registry ciphers are deterministically mapped) | None |

---

## PASS 1D — Identification of Exact Missing Dimensions

Across the 120 non-executable scenarios, the audit reveals **7 distinct missing technical dimensions** that prevent deterministic generation:

1. **Deterministic Cipher Selection Contract** (111 scenarios):
   - The matrix rows specify only `cipher_strength: HIGH/WEAK/MEDIUM/BROKEN` and `tls_version`.
   - Multiple candidate suites satisfy these constraints (e.g. 5 candidates for TLS 1.3 HIGH; 30+ candidates for TLS 1.2 ECDHE HIGH).
   - Missing: An explicit specification dimension indicating either:
     - `exact_cipher_suite`: a single concrete IANA suite name (e.g. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`).
     - `class_constraint` + `selection_policy`: acceptable security class with a deterministic resolution policy (e.g. lexicographical first).

2. **Server Leaf Public-Key Cryptography Contract** (114 scenarios with PKI):
   - The matrix provides `cert_sig_algo` (how CA signed cert), but lacks `server_leaf_key_algorithm` (RSA vs ECDSA vs Ed25519) and `server_leaf_key_size` (1024 vs 2048 vs 4096).
   - In TLS 1.2, cipher suites constrain the *leaf authentication key* (e.g. `ECDHE_RSA` requires an RSA leaf key; `ECDHE_ECDSA` requires an ECDSA leaf key).

3. **TLS 1.3 Ephemeral Key Share Group Specification** (`PCAP-108`):
   - `PCAP-108` tests HelloRetryRequest. It requires client to offer a key share in group A (e.g. `secp256r1`) while server requires group B (`x25519`).
   - Missing: `client_key_share_groups` and `server_preferred_groups`.

4. **TLS 1.3 Pre-Shared Key Resumption Contract** (`PCAP-106`, `PCAP-107`, `PCAP-122`):
   - Testing PSK resumption requires establishing an initial session ticket, then initiating a secondary resumed handshake with `pre_shared_key` extension.
   - Missing: Automated multi-stage session orchestration contract (`psk_ticket_establishment` -> `psk_resumption`).

5. **Downgrade Sentinel Wire Control Contract** (`PCAP-109`, `PCAP-110`, `PCAP-125`):
   - Testing RFC 8446 downgrade protection requires controlling whether the client offers TLS 1.3, whether the server negotiates TLS 1.2, and whether `ServerHello.random` embeds `DOWNGRD\x01`.
   - Missing: Explicit client offered versions list (`supported_versions: [1.3, 1.2]`) and server sentinel suppression control.

6. **Client Extension 50 Contract** (`PCAP-114`):
   - Requires injecting RFC 8446 Extension 50 (`signature_algorithms_cert`) with values distinct from Extension 13.
   - Missing: Dedicated packet crafting harness specification.

7. **Multi-Issuer Directed Acyclic Graph (DAG) PKI Contract** (`PCAP-119`):
   - Requires generating cross-certified intermediate CAs to test RFC 4158 path backtracking.
   - Missing: Multi-issuer PKI graph definition in `make_certs.py`.

---

## PASS 1E — Identification of Matrix Inconsistencies (`MATRIX_ORACLE_INCONSISTENT`)

The audit identified **11 concrete contradictions** between the matrix oracle expectations and authoritative project classifications. These MUST NOT be silently repaired during Pass 1:

### Contradiction 1: PCAP-112 DHE Suite Classified as WEAK by Project Policy
- **Matrix Row**: `PCAP-112,canonical,SMTP STARTTLS + TLS 1.2 DHE,SMTP,STARTTLS-upgraded,normal,1.2,HIGH,...`
- **Matrix Expectation**: `cipher_strength: HIGH`
- **Wire Execution**: Postfix stages `DHE-RSA-AES256-GCM-SHA384` (`0x009f`).
- **Forensic Analyzer Fact**: `analysis/ciphers.py` line 135 classifies all suites with IANA `Recommended == 'D'` as `WEAK`. In `data/tls_ciphers.csv`, line 119 records `"0x00,0x9F",TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,Y,D,[RFC5288][RFC10015]`.
- **Comparator Result**: Comparison fails with `expected: HIGH, observed: WEAK`.
- **Finding**: Under the project's cryptographic strength model, ZERO DHE cipher suites can achieve `HIGH` because all DHE suites in IANA are deprecated (`Rec='D'`). The matrix expectation `HIGH` is contradictory.

### Contradiction 2: Ten TLS 1.0 & TLS 1.1 Rows Specifying HIGH Cipher Strength
In TLS 1.0 (RFC 2246) and TLS 1.1 (RFC 4346), modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305, AES-CCM) do not exist. All supported cipher suites use legacy CBC mode, 3DES, or RC4.
Under `analysis/ciphers.py`:
- AEAD with PFS is required for `HIGH`.
- Ephemeral ciphers with CBC mode are classified as `MEDIUM`.
- Static RSA ciphers are classified as `WEAK`.
Therefore, the achievable strength pool for TLS 1.0 and TLS 1.1 is strictly `['BROKEN', 'MEDIUM', 'WEAK']`. `HIGH` is mathematically impossible.

The following 10 matrix rows have irreconcilable oracle contradictions:
| Scenario ID | Protocol | TLS Version | Matrix `cipher_strength` | Achievable Strengths in `analysis/ciphers.py` | Status |
|---|---|---|---|---|---|
| `PCAP-006` | SMTP | 1.0 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-007` | SMTP | 1.1 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-025` | IMAP | 1.0 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-026` | IMAP | 1.1 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-044` | POP3 | 1.0 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-045` | POP3 | 1.1 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-073` | SMTP | 1.0 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-078` | SMTP | 1.1 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-094` | SMTP | 1.1 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |
| `PCAP-096` | SMTP | 1.0 | **HIGH** | `['BROKEN', 'MEDIUM', 'WEAK']` | MATRIX_ORACLE_INCONSISTENT |

---

## PASS 1F — Certificate Semantics & Conflation Audit

RFC 5280 and RFC 8446 establish that three certificate attributes are mathematically and operationally distinct:
1. **Certificate Signature Algorithm** (`cert_sig_algo`): The cryptographic scheme used by the issuing CA to sign the certificate (RFC 5280 §4.1.1.2).
2. **Leaf Public-Key Algorithm** (`server_leaf_key_algorithm`): The algorithm of the key pair owned by the server (RFC 5280 §4.1.2.7 SubjectPublicKeyInfo).
3. **Leaf Key Size** (`server_leaf_key_size`): Modulus length or curve size (e.g. RSA-2048, RSA-1024, P-256).

### Conflation Points in Current Repository
1. **`testbed/pki/generator/make_certs.py` (Lines 433-449)**:
   ```python
   def _leaf_key_for(sig_algo: str, cache: _KeyCache, weak: bool = False):
       if weak:
           return cache.leaf["rsa1024"]
       mapping = {
           "ecdsa":    "ecdsa",
           "rsa_pkcs": "rsa2048",
           "rsa_pss":  "rsa2048",
           "ed25519":  "ed25519",
       }
       return cache.leaf[mapping[sig_algo]]
   ```
   *Flaw*: `make_certs.py` unconditionally forces the server's leaf public key to match the CA's signature algorithm! An ECDSA CA cannot issue an RSA certificate, and an RSA CA cannot issue an ECDSA certificate under this implementation.

2. **`testbed/runner/spec.py` (`PKISpec`)**:
   *Flaw*: `PKISpec` contains `sig_algo: str` but has no field for `leaf_key_algorithm`. Normalization completely ignores server leaf key type.

3. **`testbed/runner/resolver.py` (Lines 530-565)**:
   *Consequence*: Because `server_leaf_key_type` is omitted from matrix rows, the resolver correctly refuses to filter TLS 1.2 cipher suites by `cert_sig_algo`, resulting in massive candidate pools (30+ suites) and `MULTIPLE_CANDIDATES`.

---

## PASS 1G — Special Protocol Scenarios Audit

The 11 dedicated phenomenon scenarios were inspected to evaluate whether standard Python `ssl` and Postfix/Dovecot can generate them, or if a raw TLS/custom harness is required:

| Scenario ID | Generator Requirement | Intended Wire Phenomenon | Required Controls | Can Python `ssl` Generate? | Can Postfix/Dovecot Generate? | Harness Required? |
|---|---|---|---|---|---|---|
| `PCAP-106` | `psk_resumption_without_cert` | TLS 1.3 PSK-only resumption (`psk_ke`, no DHE, no cert) | PSK ticket establishment + resumption with `psk_ke` mode | **NO** (cannot force `psk_ke` mode) | **NO** (no raw PSK mode) | **Raw TLS Harness Required** |
| `PCAP-107` | `psk_dhe_resumption_without_cert` | TLS 1.3 PSK resumption with DHE (`psk_dhe_ke`, no cert) | Session ticket caching + sequential resumption | **YES** (Python 3.12+ `SSLSession`) | **YES** (ticket keys enabled) | Standard Runner Multi-Stage Script |
| `PCAP-108` | `client_group_mismatch_then_retry` | TLS 1.3 HelloRetryRequest (HRR) | Client offers key share in group A; server requires group B | **NO** (cannot omit preferred key share) | **NO** | **Raw TLS Client Required** |
| `PCAP-109` | `server_downgrade_with_sentinel` | TLS 1.3 offered, TLS 1.2 negotiated with `DOWNGRD\x01` sentinel | Client offers TLS 1.3; Server max TLS 1.2; sentinel embedded | **NO** (client aborts with alert on downgrade) | **YES** (OpenSSL 1.1.1+ auto-embeds) | **Tolerant Downgrade Client Required** |
| `PCAP-110` | `legacy_client_server_with_sentinel` | TLS 1.2-only client + server with sentinel | Client max TLS 1.2, server max TLS 1.2 | **YES** (`max_version = TLSv1_2`) | **YES** | Standard Postfix + Python `ssl` |
| `PCAP-114` | `client_cert_sig_alg_ext50` | ClientHello extension 50 present and distinct from ext 13 | Inject RFC 8446 extension 50 with distinct algorithm set | **NO** (OpenSSL high-level API does not expose ext 50) | **NO** | **Raw TLS Client Packet Injector Required** |
| `PCAP-119` | `custom_multi_issuer_pki` | PKI multiple issuers RFC 4158 path backtracking | DAG PKI certificate graph with cross-certification | **YES** (standard TLS) | **YES** | **DAG PKI Generator Required** |
| `PCAP-121` | `server_sends_fatal_alert` | Fatal Alert 40 (handshake_failure) | Empty cipher intersection between client and server | **YES** (trapped via `SSLError`) | **YES** (disjoint `tls_high_cipherlist`) | **EXECUTABLE NOW** (Proven on wire) |
| `PCAP-122` | `psk_resumption_with_early_data` | TLS 1.3 0-RTT early data | Client sends early data flight with ticket | **NO** | **NO** (Postfix disables 0-RTT) | **Dedicated 0-RTT Harness Required** |
| `PCAP-125` | `server_downgrade_without_sentinel` | TLS 1.3 client downgraded to TLS 1.2 without sentinel | Server suppresses RFC 8446 downgrade sentinel in ServerHello.random | **NO** | **NO** (OpenSSL enforces sentinel) | **Adversarial MITM Sentinel Suppressor Required** |
| `PCAP-126` | `cert_rsa1024` | TLS 1.2 with weak RSA-1024 server leaf key | RSA-1024 leaf cert + OpenSSL security level 0 (@SECLEVEL=0) | **YES** (`@SECLEVEL=0`) | **YES** (with `@SECLEVEL=0` in `main.cf`) | Standard Postfix + Stager `@SECLEVEL=0` |

---

## PASS 1C — Complete 126-Scenario Audit Classification Table

| Scenario ID | Layer | Protocol | Pres | Ver | Strength | Executability Status | Primary Blockers / Determinism Issues |
|---|---|---|---|---|---|---|---|
| `PCAP-001` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation |
| `PCAP-002` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation |
| `PCAP-003` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation |
| `PCAP-004` | inventory | SMTP | none | N/A | N/A | **EXECUTABLE_NOW** | None (Executable) |
| `PCAP-005` | inventory | SMTP | STARTTLS-upgraded | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation |
| `PCAP-006` | inventory | SMTP | implicit-TLS | 1.0 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-007` | inventory | SMTP | implicit-TLS | 1.1 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-008` | inventory | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-009` | inventory | SMTP | implicit-TLS | 1.3 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-010` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-011` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-012` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-013` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-014` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-015` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-016` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-017` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-018` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-019` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-020` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-021` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-022` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-023` | inventory | IMAP | none | N/A | N/A | **EXECUTABLE_NOW** | None (Executable) |
| `PCAP-024` | inventory | IMAP | STARTTLS-upgraded | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation |
| `PCAP-025` | inventory | IMAP | implicit-TLS | 1.0 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-026` | inventory | IMAP | implicit-TLS | 1.1 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-027` | inventory | IMAP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-028` | inventory | IMAP | implicit-TLS | 1.3 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-029` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-030` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-031` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-032` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-033` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-034` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-035` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-036` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-037` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-038` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-039` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-040` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-041` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-042` | inventory | POP3 | none | N/A | N/A | **EXECUTABLE_NOW** | None (Executable) |
| `PCAP-043` | inventory | POP3 | STARTTLS-upgraded | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation |
| `PCAP-044` | inventory | POP3 | implicit-TLS | 1.0 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-045` | inventory | POP3 | implicit-TLS | 1.1 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-046` | inventory | POP3 | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-047` | inventory | POP3 | implicit-TLS | 1.3 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-048` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-049` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-050` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-051` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-052` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-053` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-054` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-055` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-056` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-057` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-058` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-059` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-060` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-061` | inventory | SMTP | none | N/A | N/A | **EXECUTABLE_NOW** | None (Executable) |
| `PCAP-062` | inventory | IMAP | none | N/A | N/A | **EXECUTABLE_NOW** | None (Executable) |
| `PCAP-063` | inventory | POP3 | none | N/A | N/A | **EXECUTABLE_NOW** | None (Executable) |
| `PCAP-064` | inventory | SMTP | STARTTLS-upgraded | N/A | N/A | **DEDICATED_HARNESS_REQUIRED** | Harness: mitm_starttls_strip |
| `PCAP-065` | inventory | SMTP | STARTTLS-upgraded | N/A | N/A | **DEDICATED_HARNESS_REQUIRED** | Harness: mitm_starttls_strip |
| `PCAP-066` | inventory | IMAP | STARTTLS-upgraded | N/A | N/A | **MULTIPLE** | Stager Unresolvable; Harness: mitm_starttls_strip |
| `PCAP-067` | inventory | IMAP | STARTTLS-upgraded | N/A | N/A | **MULTIPLE** | Stager Unresolvable; Harness: mitm_starttls_strip |
| `PCAP-068` | inventory | POP3 | STARTTLS-upgraded | N/A | N/A | **DEDICATED_HARNESS_REQUIRED** | Harness: mitm_starttls_strip |
| `PCAP-069` | inventory | POP3 | STARTTLS-upgraded | N/A | N/A | **DEDICATED_HARNESS_REQUIRED** | Harness: mitm_starttls_strip |
| `PCAP-070` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-071` | inventory | IMAP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-072` | inventory | POP3 | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-073` | inventory | SMTP | implicit-TLS | 1.0 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-074` | inventory | SMTP | implicit-TLS | 1.1 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-075` | inventory | SMTP | implicit-TLS | 1.2 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-076` | inventory | SMTP | implicit-TLS | 1.1 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-077` | inventory | SMTP | implicit-TLS | 1.3 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-078` | inventory | SMTP | implicit-TLS | 1.1 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-079` | inventory | SMTP | implicit-TLS | 1.2 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-080` | inventory | SMTP | implicit-TLS | 1.2 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-081` | inventory | SMTP | implicit-TLS | 1.0 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-082` | inventory | SMTP | implicit-TLS | 1.2 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-083` | inventory | SMTP | implicit-TLS | 1.0 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-084` | inventory | SMTP | implicit-TLS | 1.0 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-085` | inventory | SMTP | implicit-TLS | 1.0 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-086` | inventory | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-087` | inventory | SMTP | implicit-TLS | 1.1 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-088` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-089` | inventory | SMTP | implicit-TLS | 1.1 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-090` | inventory | SMTP | implicit-TLS | 1.3 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-091` | inventory | SMTP | implicit-TLS | 1.0 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-092` | inventory | SMTP | implicit-TLS | 1.1 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-093` | inventory | SMTP | implicit-TLS | 1.2 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-094` | inventory | SMTP | implicit-TLS | 1.1 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-095` | inventory | SMTP | implicit-TLS | 1.2 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-096` | inventory | SMTP | implicit-TLS | 1.0 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Oracle Inconsistent |
| `PCAP-097` | inventory | SMTP | implicit-TLS | 1.1 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-098` | inventory | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-099` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-100` | inventory | SMTP | implicit-TLS | 1.1 | WEAK | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-101` | inventory | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-102` | inventory | SMTP | implicit-TLS | 1.2 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-103` | inventory | SMTP | implicit-TLS | 1.2 | BROKEN | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-104` | inventory | SMTP | implicit-TLS | 1.2 | MEDIUM | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-105` | inventory | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-106` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; Client Lacks Feature; Harness: psk_resumption_without_cert |
| `PCAP-107` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; Client Lacks Feature; Harness: psk_dhe_resumption_without_cert |
| `PCAP-108` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Client Lacks Feature; Harness: hello_retry_request |
| `PCAP-109` | canonical | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Client Lacks Feature; Harness: server_downgrade_with_sentinel |
| `PCAP-110` | canonical | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Harness: legacy_client_server_with_sentinel |
| `PCAP-111` | canonical | SMTP | STARTTLS-upgraded | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-112` | canonical | SMTP | STARTTLS-upgraded | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; PKI Conflation; Oracle Inconsistent |
| `PCAP-113` | canonical | SMTP | STARTTLS-upgraded | N/A | N/A | **DEDICATED_HARNESS_REQUIRED** | Harness: server_rejects_starttls |
| `PCAP-114` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Client Lacks Feature; Harness: client_cert_sig_alg_ext50 |
| `PCAP-115` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-116` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-117` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-118` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-119` | canonical | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-120` | canonical | SMTP | STARTTLS-upgraded | N/A | N/A | **MULTIPLE** | Missing Parameters (Cipher/Class); Harness: unadvertised_starttls |
| `PCAP-121` | canonical | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Harness: server_sends_fatal_alert |
| `PCAP-122` | canonical | SMTP | implicit-TLS | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Client Lacks Feature; Harness: psk_resumption_with_early_data |
| `PCAP-123` | canonical | IMAP | STARTTLS-upgraded | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-124` | canonical | POP3 | STARTTLS-upgraded | 1.3 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation |
| `PCAP-125` | canonical | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Harness: server_downgrade_without_sentinel |
| `PCAP-126` | canonical | SMTP | implicit-TLS | 1.2 | HIGH | **MULTIPLE** | Missing Parameters (Cipher/Class); Resolver MULTIPLE; Stager Unresolvable; PKI Conflation; Harness: cert_rsa1024 |

---

## PASS 1H — Confirmation of Strict Zero-Modification Policy

During Pass 1:
- `data/pcap_generation_matrix.csv` was **NOT** modified.
- `testbed/runner/resolver.py` logic was **NOT** altered.
- `stager.py` baseline bypasses (`PROVEN_*`) were **NOT** removed.
- No schemas were altered.
- No PCAPs were regenerated.
- No arbitrary ciphers were selected.

All 126 rows have been traceably audited against ground truth repository facts.