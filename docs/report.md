# SecureMailScope (SES-v1) — Full Technical Report

**Project:** SecureMailScope  
**Hackathon:** Smart India Hackathon (SIH) | Problem Statement ID: 26159  
**Sponsor:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Report Date:** 2026-09-27  

---

## Table of Contents

1. [Project Overview & Problem Statement](#1-project-overview--problem-statement)
2. [Repository Structure](#2-repository-structure)
3. [System Architecture — Three Coupled Systems](#3-system-architecture)
4. [System 1 — Testbed & Dataset Factory](#4-system-1--testbed--dataset-factory)
5. [System 2 — Forensic Telemetry Engine](#5-system-2--forensic-telemetry-engine)
6. [System 3 — Rule Engine & Policy Layer](#6-system-3--rule-engine--policy-layer)
7. [Testbed Runner & Batch Automation](#7-testbed-runner--batch-automation)
8. [Data Layer](#8-data-layer)
9. [Test Suite](#9-test-suite)
10. [Current Batch Run State](#10-current-batch-run-state)
11. [End-to-End Data Flow Walk-Through](#11-end-to-end-data-flow-walk-through)
12. [Remaining Roadmap](#12-remaining-roadmap)
13. [Engineering Decisions & Obstacles](#13-engineering-decisions--obstacles)

---

## 1. Project Overview & Problem Statement

### What It Is

SecureMailScope is a **passive, wire-level network forensic engine** for email infrastructure. It reads raw `.pcap` / `.pcapng` packet captures containing SMTP, IMAP, or POP3 traffic and produces a structured cryptographic security audit — without requiring private keys, session keylogs, or any modification to the monitored servers.

### The Problem in Numbers

- **73%+ of enterprise mail servers** still accept deprecated TLS 1.0/1.1 or legacy CBC-mode ciphers, leaving them vulnerable to BEAST, POODLE, and SWEET32 attacks.
- **Silent STARTTLS Stripping:** SMTP/IMAP/POP3 begin in cleartext before upgrading. A MitM attacker can suppress the `STARTTLS` advertisement — unlike browser HTTPS, no client alert is raised and the connection silently stays cleartext.
- **45–60 minutes** of manual Wireshark work per suspicious capture for a senior analyst. SecureMailScope reduces this to seconds.
- **Decryption barrier:** Most tools need private keys. SOC analysts in passive forensics mode never have them. SecureMailScope requires none.

### What It Produces

For every TCP stream in a capture, SecureMailScope emits:

- Protocol identification (SMTP / IMAP / POP3)
- STARTTLS 5-step state audit (advertised → requested → accepted → handshake → cleartext check)
- TLS handshake reconstruction (version, cipher, KEX group, PSK mode, HRR, downgrade sentinel, 0-RTT)
- X.509 certificate chain telemetry (subject, issuer, validity, SAN, key size, signature algorithm)
- PKIX trust path validation result
- RFC 6125 hostname match result
- Normative policy verdicts from 4 policy packs (NIST SP 800-52r2 with 25 rules, NIST SP 800-131A, Mozilla Modern, Mozilla Intermediate)
- 12 policy-neutral forensic observations

---

## 2. Repository Structure

```
SES-v1/
├── analysis/                        # Core forensic engine
│   ├── constants.py                 # All RFC wire codes: TLS versions, handshake types,
│   │                                #   named groups, alert codes, signature schemes,
│   │                                #   HRR magic constant, downgrade sentinels
│   ├── ciphers.py                   # IANA cipher registry loader + 4-tier classifier
│   │                                #   + IANA↔OpenSSL bidirectional translator
│   ├── trust_store.py               # Swappable root CA trust store manager
│   ├── cert_validator.py            # X.509 ASN.1 parsing, signature verification,
│   │                                #   PKIX path validation, RFC 6125 hostname matching
│   ├── starttls.py                  # TCP stream reassembly, protocol DPI,
│   │                                #   STARTTLS 5-step state machine
│   ├── tls_session.py               # Stateful TLS 1.2/1.3 handshake reconstructor
│   ├── parser.py                    # PCAPAnalyzer — unified orchestration facade
│   └── rule_engine/
│       ├── engine.py                # RuleEngine orchestrator
│       ├── input_builder.py         # Session dict → RuleInput normalizer
│       ├── schema.py                # All TypedDict / dataclass contracts
│       ├── policy/
│       │   └── nist_loader.py       # Loads approved NIST cipher lists from JSON
│       └── rules/
│           ├── nist_52r2.py         # 25 NIST SP 800-52r2 rules
│           ├── nist_131a.py         # NIST SP 800-131A transition rules
│           ├── mozilla_modern.py    # Mozilla Modern profile rules
│           ├── mozilla_interm.py    # Mozilla Intermediate profile rules
│           └── observations.py     # 12 policy-neutral forensic observations
│
├── testbed/
│   ├── docker-compose.yml           # 5-container mail fleet
│   ├── postfix/                     # Postfix SMTP Docker image + Jinja2 config templates
│   ├── dovecot/                     # Dovecot IMAP/POP3 Docker image + config templates
│   ├── mitm/                        # MitM proxy harness (6 attack servers)
│   ├── legacy/                      # C-based legacy TLS binaries + Ed25519 Python variant
│   ├── pki/
│   │   ├── ca/                      # root_ca.key/crt + rogue_ca.key/crt
│   │   └── generator/make_certs.py  # PKIFactory: generates all 15+ cert variants
│   ├── runner/
│   │   ├── spec.py                  # ScenarioSpec — frozen dataclass from CSV row
│   │   ├── resolver.py              # Deterministic TLS cipher selector
│   │   ├── stager.py                # ScenarioSpec → staged artifact directory
│   │   ├── client.py                # SMTP / IMAP / POP3 deterministic clients
│   │   ├── runner.py                # Single scenario end-to-end executor
│   │   ├── batch.py                 # BatchOrchestrator: all 126 scenarios
│   │   ├── comparator.py            # expected.json vs observed.json → comparison.json
│   │   ├── observed.py              # Builds observed.json from PCAPAnalyzer output
│   │   └── scenario_contract.py     # Validates against data/scenario_contracts.json
│   ├── staged/                      # Per-scenario staged PKI + config snapshots
│   ├── active/                      # Live Docker volume mount (hot-swap between runs)
│   └── captures/                    # 126 PCAPs + 6 artifact files each
│
├── data/
│   ├── pcap_generation_matrix.csv   # 126 scenario definitions
│   ├── scenario_contracts.json      # Pre-computed resolution contracts per scenario
│   ├── sidecar_schema.json          # 28-field ground-truth label schema
│   ├── expected_schema.json         # JSON Schema for expected.json
│   ├── observed_schema.json         # JSON Schema for observed.json
│   ├── comparison_schema.json       # JSON Schema for comparison.json
│   ├── tls_ciphers.csv              # Full IANA TLS cipher registry (~500 suites)
│   ├── nist_sp800_52_r2_rules.json  # Machine-readable NIST 800-52r2 rule definitions
│   ├── nist_sp800_52_r2_ciphers.json # NIST-approved cipher lists
│   ├── matrix_resolution_report.md  # Audit of all 126 scenario resolvability
│   ├── matrix_executability_audit.md
│   ├── NIST.SP.800-52r2.pdf
│   └── NIST.SP.800-131Ar2.pdf
│
├── scratch/                         # Live milestone integration tests
├── SIH_SECUREMAILSCOPE_MASTER_DOSSIER.md
├── mailcap.pcap                     # Baseline SMTP+STARTTLS→TLS 1.3 capture
├── tls12_only.pcap                  # Baseline forced TLS 1.2 capture
├── smtp_cleartext_insecure.pcap     # Cleartext SMTP capture
└── create_insecure_pcap.py
```

---

## 3. System Architecture

The project is three tightly integrated systems:

```
┌──────────────────────────────────────────────────────────────────────┐
│               SYSTEM 1 — TESTBED & DATASET FACTORY                  │
│                                                                      │
│  pcap_generation_matrix.csv (126 rows)                               │
│          ↓                                                           │
│  BatchOrchestrator (batch.py)                                        │
│     ├── ScenarioSpec (spec.py) — normalize CSV row                   │
│     ├── TLSCipherResolver (resolver.py) — pick cipher deterministically│
│     ├── PKIFactory (make_certs.py) — generate cert variant           │
│     ├── SMTPStager / IMAPStager / POP3Stager — render config files   │
│     ├── Docker deploy + tshark capture                               │
│     └── SMTPClient / IMAPClient / POP3Client — drive protocol        │
│          ↓                                                           │
│  testbed/captures/PCAP-NNN.pcap  (126 captures)                     │
└──────────────────────────────────────┬───────────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────────┐
│          SYSTEM 2 — FORENSIC TELEMETRY ENGINE (analysis/)            │
│                                                                      │
│  PCAPAnalyzer.analyze(pcap_path)                                     │
│     │                                                                │
│     ├── Layer 1: TCP stream reassembly (starttls.py)                 │
│     │     StreamFlow{client_data, server_data, chunks}               │
│     │                                                                │
│     ├── Layer 2: Protocol DPI + STARTTLS state machine (starttls.py) │
│     │     detect_protocol() → SMTP / IMAP / POP3                    │
│     │     detect_starttls() → 5-step status + cleartext check        │
│     │                                                                │
│     ├── Layer 3: TLS handshake reconstruction (tls_session.py)       │
│     │     extract_tls_info() → version, cipher, KEX group,           │
│     │     PSK mode, HRR, downgrade sentinel, alerts, certs DER       │
│     │                                                                │
│     ├── Layer 4: X.509 engine (cert_validator.py)                   │
│     │     extract_certificates() → parse DER → LeafCert + chain      │
│     │     verify_certificate_signature() → RSA/ECDSA/Ed25519 math    │
│     │     verify_pkix_path() → RFC 5280 chain + Basic Constraints    │
│     │     check_hostname_match() → RFC 6125 SAN / CN matching        │
│     │                                                                │
│     └── Layer 5: Cipher classification (ciphers.py)                 │
│           get_cipher_info(hex_id) → HIGH / MEDIUM / WEAK / BROKEN   │
│                                                                      │
│  Returns: dict[stream_id → session_dict]                            │
└──────────────────────────────────────┬───────────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────────┐
│        SYSTEM 3 — RULE ENGINE & POLICY LAYER (rule_engine/)          │
│                                                                      │
│  RuleEngine.evaluate_stream(session_dict)                            │
│     │                                                                │
│     ├── InputBuilder.build() → RuleInput (TypedDict)                 │
│     │                                                                │
│     ├── NIST52r2Evaluator.evaluate_all()  → 25 PolicyResult objects  │
│     ├── NIST131aEvaluator.evaluate_all()  → PolicyResult objects     │
│     ├── MozillaModernEvaluator            → PolicyResult objects     │
│     ├── MozillaIntermEvaluator            → PolicyResult objects     │
│     └── ObservationsEvaluator             → 12 ObservationResult obj │
│                                                                      │
│  Returns: StreamRuleReport → written to PCAP-NNN.evidence.json       │
│                                                                      │
│  Comparator: expected.json vs observed.json → PCAP-NNN.comparison.json│
│                                                                      │
│  [PLANNED] Feature Extractor → XGBoost Risk Scorer (0–100)           │
│  [PLANNED] Isolation Forest Anomaly Detector                         │
│  [PLANNED] Remediation Engine + HTML/PDF Report + SOC Dashboard      │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Zero-decryption:** All analysis is strictly on cleartext TLS handshake metadata. No HKDF, no key derivation, no payload inspection.
- **RFC-grounded:** Every decision links to a specific RFC section. Comments in code cite the normative clause justifying each implementation choice.
- **Deterministic:** Given the same PCAP and trust store, the engine always produces identical output. No randomness, no timestamps in verdicts.
- **Pluggable trust:** Swap between lab root CA and Mozilla production bundle at construction time.
- **Fault-isolated:** A single stream failure never aborts the PCAP analysis. A single scenario failure never aborts the batch.

---

## 4. System 1 — Testbed & Dataset Factory

### 4.1 Docker Mail Fleet

Five containers on an isolated bridge (`172.28.0.0/16`, no external routing):

| Container | IP | Role |
|---|---|---|
| `mailtest-postfix` | `172.28.0.10` | SMTP (Postfix on port 2525) |
| `mailtest-dovecot` | `172.28.0.11` | IMAP port 1143 / POP3 port 1110 |
| `mailtest-client` | `172.28.0.20` | Protocol test client (Python) |
| `mailtest-mitm` | `172.28.0.30` | MitM proxy harness |
| `mailtest-legacy` | dynamic | C-based legacy TLS binaries |

The `testbed/active/` directory is bind-mounted into server containers. The runner hot-swaps `chain.pem`, `key.pem`, `main.cf`, `dovecot.conf` between scenarios without rebuilding images, then issues `postfix reload` / `dovecot reload`.

**Engineering obstacles overcome in Postfix:**
- **Chroot jail:** Debian defaults to `smtp inet n - y` (chrooted). Inside minimal Docker, `/var/spool/postfix` lacks required libs → silent crash. Fix: `smtp inet n - n`.
- **Reverse DNS hang:** Workers hung on reverse lookup before sending `220` banner. Fix: `disable_dns_lookups = yes`.
- **Open relay:** Postfix 3.7+ refuses to start without explicit policy. Fix: `smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination`.

### 4.2 PKI Certificate Factory (`testbed/pki/generator/make_certs.py`)

`PKIFactory` generates all certificate variants. Permanent CAs on disk: `root_ca.crt/key` (Ed25519, legitimate) and `rogue_ca.crt/key` (for untrusted chains).

**Main entry point:**
```python
profile = factory.generate_cert_profile(
    sig_algo="ecdsa",        # ecdsa | rsa_pkcs | rsa_pss | ed25519
    validity="expired",      # valid | expired | not_yet_valid
    chain_shape="complete",  # complete | self_signed_trusted | self_signed_untrusted
                             # unknown_root | bad_constraint | tampered_sig | leaf_only
    san_type="matched_dns",  # matched_dns | mismatched | ip_san | wildcard | cn_only
)
# Returns: {cert_pem, key_pem, chain_pem, trust_store_pem}
```

**Chain shape mutations:**

| Shape | What changes |
|---|---|
| `complete` | Standard leaf ← intermediate ← root (3-tier) |
| `self_signed_trusted` | Self-signed leaf whose root IS in trust store |
| `self_signed_untrusted` | Self-signed from rogue CA, trust store empty |
| `unknown_root` | Valid chain but root not in trust store |
| `bad_constraint` | Intermediate has `cA=False` Basic Constraints |
| `tampered_sig` | Intermediate signature byte-flipped (crypto invalid) |
| `leaf_only` | `chain.pem` has only the leaf, no intermediates |

**Validity mutations:** `expired` = backdated `notAfter`, `not_yet_valid` = `notBefore` 1 year in future, `valid` = standard 730-day window.

**SAN variants:** `matched_dns` (`DNS:mail.test.local`), `mismatched`, `ip_san` (`IP:172.28.0.10`), `wildcard` (`DNS:*.test.local`), `cn_only` (no SAN extension — triggers RFC 6125 CN fallback).

### 4.3 The 126-Scenario Matrix

**105 combinatorial scenarios** cross-multiply: Protocol × TLS version × Cipher strength × Cert validity × Chain shape × Sig algo × Hostname match × STARTTLS integrity × Auth state.

**21 canonical RFC edge-case scenarios (PCAP-106 to PCAP-126):**

| ID | What It Exercises |
|---|---|
| PCAP-106 | TLS 1.3 PSK-only (`psk_ke`) — no forward secrecy, no cert |
| PCAP-107 | TLS 1.3 PSK+DHE (`psk_dhe_ke`) — FS maintained |
| PCAP-108 | TLS 1.3 HelloRetryRequest — client offered wrong group |
| PCAP-109 | RFC 8446 downgrade sentinel `DOWNGRD\x01` in ServerHello random |
| PCAP-110 | TLS 1.2-only client with benign sentinel |
| PCAP-111/112 | STARTTLS + TLS 1.2 ECDHE vs DHE |
| PCAP-113 | SMTP STARTTLS rejected (`454 TLS not available`) |
| PCAP-114 | RFC 8446 ext 50 (Sig Algs Cert) distinct from ext 13 |
| PCAP-115 | No SAN — legacy CN fallback |
| PCAP-116 | IP address SAN (`IP:172.28.0.10`) |
| PCAP-117/118 | Wildcard SAN: matches single label, not multi-label |
| PCAP-119 | Multi-issuer PKI requiring RFC 4158 backtracking |
| PCAP-120 | Client sends unadvertised STARTTLS |
| PCAP-121 | Fatal `handshake_failure` alert (Level 2, Desc 40) |
| PCAP-122 | TLS 1.3 0-RTT early data |
| PCAP-126 | TLS 1.2 + weak RSA-1024 public key |

### 4.4 MitM Harness (`testbed/mitm/`)

Six Python servers launched by `main.py`:
- `smtp_proxy.py` — strips STARTTLS from server's EHLO response
- `imap_proxy.py` — suppresses CAPABILITY STARTTLS
- `pop3_proxy.py` — strips STLS from CAPA
- `downgrade_server.py` — forces older TLS version than client offered
- `psk_server.py` — TLS 1.3 PSK-only (no certificate)
- `zero_rtt_server.py` — accepts TLS 1.3 0-RTT early data

### 4.5 Legacy TLS Harness (`testbed/legacy/`)

- `legacy_ecdh_server.c` / `legacy_ecdh_client.c` — C programs using OpenSSL directly for deprecated TLS features unreachable from Python's `ssl` module. Pre-compiled as 3.2 MB static binaries.
- `legacy_ed25519_server.py` / `legacy_ed25519_client.py` — Python variant for precise Ed25519 handshake control.

---

## 5. System 2 — Forensic Telemetry Engine

### 5.1 `analysis/constants.py` — RFC Wire Code Registry

Pure data — all RFC lookup tables with inline comments explaining why each value is what it is.

**Key tables:**
```python
TLS_VERSION_MAP = {"0x0301": "TLS 1.0", "0x0302": "TLS 1.1",
                   "0x0303": "TLS 1.2", "0x0304": "TLS 1.3"}

# Keys are decimal strings — tshark emits key_share_group as BASE_DEC
TLS13_GROUP_MAP = {
    "23": "secp256r1", "24": "secp384r1", "25": "secp521r1",
    "29": "x25519", "30": "x448",
    "256": "ffdhe2048", ..., "260": "ffdhe8192",
    "4588": "x25519_kyber768_draft00",
    "25497": "x25519_mlkem768",
}

TLS13_PSK_MODE_MAP = {
    "0": "psk_ke (PSK-only, no forward secrecy)",
    "1": "psk_dhe_ke (PSK + (EC)DHE, forward secrecy maintained)",
}

# RFC 8446 §4.1.4 — SHA-256("HelloRetryRequest")
RFC8446_HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
# RFC 8446 §4.1.3 — "DOWNGRD\x01" in last 8 bytes of TLS 1.2 ServerHello.random
RFC8446_DOWNGRADE_SENTINEL_TLS12 = "444f574e47524401"
```

Alert map covers all 30+ RFC codes: `handshake_failure`=40, `bad_certificate`=42, `unknown_ca`=48, `inappropriate_fallback`=86, etc.

Signature scheme map covers RSASSA-PKCS1-v1_5, ECDSA, DSA, RSASSA-PSS, EdDSA, and draft ML-DSA with their 2-byte wire codes (e.g. `"0x0804"` = `rsa_pss_rsae_sha256`).

### 5.2 `analysis/ciphers.py` — Cipher Database & 4-Tier Classifier

Parses `data/tls_ciphers.csv` (~500 IANA cipher suites) into a dict keyed by 4-char lowercase hex ID.

**Eight edge cases handled (all documented in module header):**
1. Unassigned/reserved rows → skipped
2. SCSV pseudo-suites (`_SCSV` suffix) → filtered (not real ciphers)
3. Anonymous suites (`ANON`) → `BROKEN` (math PFS, zero authentication)
4. PSK/Kerberos without DHE → no PFS → `WEAK`
5. TLS 1.3 suites (`TLS_AES_*`, `TLS_CHACHA20_*`) → `kex="TLS13_EPHEMERAL"`, always PFS
6. `_CCM_8` truncated 64-bit tag → `WEAK` (must be checked BEFORE `CCM` HIGH check)
7. IANA `Recommended="D"` (deprecated) → `WEAK`
8. Static RSA KEX (e.g. `TLS_RSA_WITH_AES_256_GCM_SHA384`) → `WEAK` despite AEAD, because no PFS

**Classification order is load-bearing:**
```python
if kex == "ANONYMOUS" or NULL or EXPORT or RC4/3DES/DES/MD5:
    strength = "BROKEN"
elif rec == "D" or not has_pfs or "_CCM_8":   # WEAK before HIGH!
    strength = "WEAK"
elif has_pfs and (GCM or POLY1305 or CCM):
    strength = "HIGH"
else:
    strength = "MEDIUM"
```

**`iana_to_openssl()` / `openssl_to_iana()`:** Bidirectional translation using Python's `ssl.SSLContext` to enumerate live OpenSSL cipher IDs, then correlating via shared 16-bit hex keys. Falls back to hardcoded `CANONICAL_IANA_TO_OPENSSL` for legacy ciphers modern OpenSSL won't enumerate.

### 5.3 `analysis/trust_store.py` — Trust Store Manager

```python
TrustStoreManager(trust_store="testbed")    # lab root CA (default)
TrustStoreManager(trust_store="production") # Mozilla CA bundle via certifi
TrustStoreManager(ca_path="/path/to/ca.pem") # explicit path
```

Lazy-loads the CA bundle on first call to `get_store()`. Keeps two parallel data structures:
- `_loaded_store` — opaque `cryptography.x509.verification.Store` for path validation
- `_store_certs` — plain `list[Certificate]` for `any(leaf == root for root in ...)` membership checks (Store is not iterable after construction)

Handles empty trust store (0-byte PEM) gracefully for `self_signed_untrusted` scenarios.

### 5.4 `analysis/cert_validator.py` — X.509 Cryptographic Engine (~90 KB)

#### Signature Verification

Verifies the signature over `child_cert.tbs_certificate_bytes` (ASN.1 TBSCertificate — NOT full cert DER):

```python
# RSA: dispatch on parameter type to distinguish PKCS#1 v1.5 vs PSS
sig_params = getattr(child_cert, "signature_algorithm_parameters", None)
if isinstance(sig_params, padding.PSS):
    key.verify(sig, tbs_bytes, sig_params, hash_alg)  # PSS — params encode MGF + salt
else:
    key.verify(sig, tbs_bytes, padding.PKCS1v15(), hash_alg)  # PKCS#1 v1.5

# ECDSA
key.verify(sig, tbs_bytes, ec.ECDSA(hash_alg))

# Ed25519/Ed448 — PureEdDSA, NO hash argument (RFC 8032)
key.verify(sig, tbs_bytes)
```

Why branch on `isinstance()` not OID string: `cryptography`'s `verify()` is type-dispatched — each key type has a different method signature.

#### RFC 6125 Hostname Matching

1. If SAN extension present: ONLY use SAN entries (never fall back to CN)
2. `dNSName`: exact match or single-label wildcard (`*.example.com` → `mail.example.com` ✓, `a.mail.example.com` ✗)
3. `iPAddress`: parsed via `ipaddress.ip_address()` comparison
4. CN fallback ONLY when no SAN extension exists (PCAP-115)

#### PKIX Path Validation (RFC 5280)

Chain: leaf → intermediate(s) → root. Validates:
- `Basic Constraints cA=True` + `pathLenConstraint` on all CA certs
- `Key Usage: keyCertSign` on CA certs
- Validity timestamps at `handshake_time_epoch`
- Cryptographic signature at each hop via `verify_certificate_signature()`

#### RFC 4158 PKIX Backtracking (PCAP-119)

When multiple CAs share the same Subject DN, implements DFS with backtracking to find a valid trust path — identical to production TLS stack behavior.

### 5.5 `analysis/starttls.py` — Protocol DPI & STARTTLS State Machine

#### TCP Stream Reassembly

Uses tshark `follow,tcp,raw` output. `_identify_server_node()` uses a 5-tier hierarchy:
1. Server greeting banner (`220`, `+OK`, `* OK`, `* PREAUTH`)
2. Client initiation (`\x16\x03` TLS ClientHello, `EHLO`, `CAPA`, `USER`, `STARTTLS`)
3. Known service ports: `{25, 465, 587, 2525, 143, 993, 1143, 110, 995, 1110}`
4. Privileged port heuristic (< 1024 = server)
5. Fallback: Node 1 is server

#### Protocol DPI

```python
# SMTP: RFC 5321 banner
b"220" in server_data or b"ESMTP" in data → "SMTP"
# IMAP: RFC 3501 §6.1.1
b"* OK" or b"* PREAUTH" → "IMAP"
# POP3: RFC 1939 §3
b"+OK" → "POP3"
# Implicit TLS by port
465 → "SMTP", 993 → "IMAP", 995 → "POP3"
```

#### STARTTLS 5-Step State Machine

Walks `chunks` chronologically:
- Step 1: Server advertised `STARTTLS`/`STLS` in capability list?
- Step 2: Client sent `STARTTLS`/`STLS` command?
- Step 3: Server responded `220 Ready` (SMTP) or `+OK` (POP3)?
- Step 4: TLS `ClientHello` (`\x16\x03`) immediately follows?
- Step 5: Any `AUTH LOGIN`, `AUTH PLAIN`, `USER`, `PASS` in cleartext frames?

Status values: `COMPLETED_SUCCESSFULLY`, `CLEARTEXT_NO_ENCRYPTION`, `STRIPPED_SERVER`, `STRIPPED_CLIENT`, `STARTTLS_REJECTED`, `STARTTLS_WITHOUT_ADVERTISEMENT`, `CLEARTEXT_AUTH_DETECTED`.

### 5.6 `analysis/tls_session.py` — TLS Handshake Reconstructor

Uses tshark field extraction (`-T fields -e tls.*`) to pull handshake metadata without decryption.

**RFC 8446 encryption boundary:** TLS 1.3 encrypts all records after `ServerHello` under outer record type 23 (`application_data`). Without modeling this, encrypted `Finished` / `NewSessionTicket` messages get misclassified as app data. The module explicitly marks TLS 1.3 post-ServerHello type-23 records as `"NOT_DETERMINABLE"`.

**What is extracted:**
- `tls_version` — from `supported_versions` extension in ServerHello (TLS 1.3), or from `legacy_record_version` (TLS 1.2)
- `raw_cipher_suite` — negotiated cipher hex (e.g. `0xc02b`)
- `tls13_key_exchange_group` — named group from ServerHello `key_share` ext
- `tls13_psk_selected` — `pre_shared_key` ext in both ClientHello and ServerHello
- `tls13_key_exchange_mode` — from `psk_key_exchange_modes` ext (type 45)
- `hello_retry_request` — ServerHello.random == `RFC8446_HRR_RANDOM`
- `downgrade_sentinel` — last 8 bytes of TLS 1.2 ServerHello.random == `"444f574e47524401"`
- `early_data_offered` — `early_data` ext (type 42) in ClientHello
- `flight_alerts` — all TLS alert records with level + description
- `certificates_der` — raw DER bytes of all certs from `Certificate` message
- `client_offered_versions`, `client_offered_ciphers`, `client_supported_groups`, `client_signature_algorithms`, `client_sni`

**`parse_named_group(val)`** normalizes tshark's decimal vs hex inconsistency: `"29"` or `"0x001d"` both → `"x25519"`.

### 5.7 `analysis/parser.py` — PCAPAnalyzer Orchestrator

```python
analyzer = PCAPAnalyzer(pcap_path, trust_store="testbed")
sessions = analyzer.analyze()  # → dict[stream_id → session_dict]
```

Per-stream pipeline: reassemble → DPI → STARTTLS state machine → TLS reconstruction → cert extraction → signature verification → PKIX path → hostname match → cipher classification → emit session dict.

**Output session dict** (abbreviated):
```python
{
    "stream_id": 0, "protocol": "SMTP",
    "starttls_status": "COMPLETED_SUCCESSFULLY",
    "cleartext_auth_attempted": False,
    "handshake": {
        "tls_version": "TLS 1.2",
        "cipher_name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "cipher_strength": "MEDIUM",
        "forward_secrecy": True,
        "named_group": "secp256r1",
        "hello_retry_request": False,
        "downgrade_sentinel": {"detected": False},
        "handshake_status": "COMPLETED",
        "handshake_time_epoch": 1727300123.456,
    },
    "certificates": [{
        "subject": "CN=mail.test.local",
        "san_dns": ["mail.test.local"],
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00",
        "signature_algorithm_name": "ecdsa-with-SHA256",
        "public_key_algorithm": "EC", "public_key_size": 256,
        "signature_valid": True,
    }],
    "trust": {
        "trust_status": "TRUSTED",
        "hostname_match": "MATCH",
        "chain_length": 3, "pkix_path_valid": True,
    }
}
```

---

## 6. System 3 — Rule Engine & Policy Layer

The rule engine in `analysis/rule_engine/` transforms raw session telemetry from `PCAPAnalyzer` into deterministic normative policy verdicts. It is **not a scorer** — it produces discrete verdicts (`PASS`, `FAIL`, `NOT_APPLICABLE`, `OBSERVATION`, `NOT_OBSERVABLE`) tied to specific RFC clauses.

### 6.1 Schema (`analysis/rule_engine/schema.py`)

All inter-module contracts are frozen dataclasses or TypedDicts.

**`EvidenceItem`** — atomic provenance unit:
```python
@dataclass(frozen=True)
class EvidenceItem:
    stream_id: int
    field: str        # e.g. "tls_version"
    value: Any        # e.g. "TLS 1.0"
    source: str       # e.g. "TLS Session -> Negotiated Version"
    frame: Optional[int] = None
    context: Optional[str] = None
```

**`PolicyResult`** — single rule evaluation:
```python
@dataclass(frozen=True)
class PolicyResult:
    policy: str           # "NIST-52R2" | "NIST-131A" | "MOZ-MODERN" | "MOZ-INTERM"
    rule_id: str          # e.g. "N52-TLS-01"
    name: str             # "TLS 1.0 Disallowance"
    source_id: str        # "SP800-52R2-S07"
    source_section: str   # "3.1"
    source_text: str      # verbatim normative clause from the standard
    normative_term: str   # "SHALL NOT" | "SHALL" | "SHOULD" | "MAY" | ...
    applicability_scope: str  # "NIST-GOV-ONLY" | "NIST-CITIZEN-FACING" | ...
    verdict: str          # "PASS" | "FAIL" | "OBSERVATION" | "NOT_OBSERVABLE" | "NOT_APPLICABLE"
    evidence: list[EvidenceItem]
    finding: Optional[str]  # human-readable explanation
```

**`ObservationResult`** — policy-neutral forensic fact:
```python
@dataclass(frozen=True)
class ObservationResult:
    obs_id: str       # "OBS-STARTTLS-01"
    name: str
    category: str     # "Framing" | "Identity" | "Handshake" | "Trust" | "Security"
    detected: bool
    evidence: list[EvidenceItem]
    description: str
```

**`StreamRuleReport`** — all verdicts for one TCP stream:
```python
@dataclass(frozen=True)
class StreamRuleReport:
    stream_id: int
    protocol: str
    policy_results: dict[str, list[PolicyResult]]  # pack_name → results
    observations: list[ObservationResult]
    input_snapshot: dict[str, Any]
```

**`RuleInput`** — the normalized TypedDict fed to all evaluators. Key fields:
```python
class RuleInput(TypedDict, total=False):
    stream_id: int
    protocol: str
    capture_time: Optional[datetime]
    tls_version: Optional[str]            # "TLS 1.2" | "TLS 1.3" | None
    raw_cipher_suite: Optional[str]       # "0xc02b"
    cipher_name: Optional[str]
    tls13_psk_selected: Optional[bool]
    tls13_key_exchange_group: Optional[str]
    tls13_key_exchange_mode: Optional[str]
    hello_retry_request: bool
    downgrade_sentinel: DowngradeSentinelInfo
    early_data_offered: bool
    handshake_status: Optional[str]
    flight_alerts: list[dict]
    starttls_offered: bool
    starttls_requested: bool
    starttls_accepted: bool
    starttls_rejected: bool
    plaintext_auth_attempted: bool
    starttls_status: str
    cert_observable: bool
    chain_length: int
    hostname_match: str
    leaf_cert: Optional[LeafCertFacts]
    non_anchor_cert_facts: Optional[NonAnchorCertFacts]
    heuristics: HeuristicsInfo  # h_cipher_strength, h_forward_secrecy, h_kex_type
    client_offered_versions: list[str]
    client_offered_ciphers: list[str]
    client_supported_groups: list[str]
    client_signature_algorithms: list[str]
    client_sni: Optional[str]
```

### 6.2 Input Builder (`analysis/rule_engine/input_builder.py`)

`InputBuilder.build(session_dict, trust_store_manager)` normalizes the raw PCAPAnalyzer output into a `RuleInput`.

Key responsibilities:
- Parses all datetime strings into timezone-aware UTC `datetime` objects via `_parse_utc_datetime()`
- Flattens nested cert facts into `LeafCertFacts` and `NonAnchorCertFacts` TypedDicts
- Computes `HeuristicsInfo`: `h_cipher_strength`, `h_forward_secrecy`, `h_kex_type`
- Computes `lifespan_exceeds_3_years` via `check_lifespan_3_calendar_years(not_before, not_after)` — uses `add_calendar_years()` which handles Feb 29 leap year edge case by substituting Feb 28
- Sets `cert_observable` / `cert_unobservable_reason` (PSK-only = no cert on wire)
- Sets `capture_time` from `handshake_time_epoch` for timestamp-based cert validity rules

### 6.3 NIST SP 800-52r2 Evaluator — 25 Rules (`rules/nist_52r2.py`)

`NIST52r2Evaluator(mode="gov_only")` runs 25 rules. `mode` controls whether TLS 1.0 is `SHALL NOT` (gov_only) or `MAY` (citizen_facing).

**TLS version rules:**
- `N52-TLS-01` — TLS 1.0 disallowance. Gov-only: `FAIL`. Citizen-facing: `OBSERVATION`.
- `N52-TLS-02` — TLS 1.1 disallowance (both modes: `SHALL NOT`).
- `N52-TLS-03` — TLS 1.2/1.3 is acceptable (`PASS`).

**Cipher suite rules (sourced from `data/nist_sp800_52_r2_ciphers.json`):**
- `N52-CIPHER-01` — TLS 1.2 cipher must be on NIST approved list (§3.3.1.1)
- `N52-CIPHER-02` — TLS 1.3 cipher must be on NIST approved list (§3.3.1.2)
- `N52-CIPHER-03` — No NULL encryption ciphers
- `N52-CIPHER-04` — No EXPORT-grade ciphers
- `N52-CIPHER-05` — No RC4 ciphers
- `N52-CIPHER-06` — No 3DES/DES ciphers
- `N52-CIPHER-07` — No anonymous key exchange

**KEX rule:**
- `N52-KEX-01` — Ephemeral DH group must be NIST-approved (P-256/P-384/P-521, ffdhe2048+). X25519 is also accepted.

**PSK rules:**
- `N52-PSK-01` — PSK-only (`psk_ke`) provides no FS beyond PSK lifetime: `OBSERVATION`
- `N52-PSK-02` — PSK+DHE (`psk_dhe_ke`) maintains FS: `PASS`
- `N52-PSK-03` — PSK cipher must be from NIST App C approved PSK list

**Certificate rules:**
- `N52-CERT-01` — Signature algorithm: ECDSA, RSA-PSS, or RSA PKCS#1v15 with SHA-256+
- `N52-CERT-02` — RSA public key ≥ 2048 bits; EC key ≥ 224 bits
- `N52-CERT-03` — Certificate not expired at capture time
- `N52-CERT-04` — Certificate not before capture time (not-yet-valid)
- `N52-CERT-05` — Certificate lifespan ≤ 3 calendar years (NIST §3.2.4)
- `N52-CERT-06` — Subject Alternative Name (SAN) extension must be present
- `N52-CERT-08` — No SHA-1 or MD5 signature hash
- `N52-CERT-09` — Certificate chain must be trusted (PKIX path valid)
- `N52-CERT-10` — Hostname must match (RFC 6125 SAN/CN check)

**Protocol / client rules:**
- `N52-CLIENT-HOSTNAME-01` — Client SNI must match the cert hostname
- `N52-PROTO-01` — No plaintext auth before TLS upgrade

**Example FAIL verdict (TLS 1.0, gov_only mode):**
```python
PolicyResult(
    policy="NIST-52R2",
    rule_id="N52-TLS-01",
    name="TLS 1.0 Disallowance",
    source_section="3.1",
    source_text="Servers shall not be configured to use TLS 1.0 for government-only applications.",
    normative_term="SHALL NOT",
    applicability_scope="NIST-GOV-ONLY",
    verdict="FAIL",
    evidence=[EvidenceItem(0, "tls_version", "TLS 1.0", "TLS Session -> Negotiated Version")],
    finding="TLS 1.0 was negotiated in violation of NIST SP 800-52 §3.1 government-only mandate.",
)
```

### 6.4 NIST SP 800-131A Evaluator (`rules/nist_131a.py`)

Implements NIST SP 800-131A Rev. 2 transition requirements:
- Minimum RSA key size: 2048 bits (disallowed below 1024)
- Minimum EC key size: 224 bits
- Approved hash functions for signatures: SHA-2 family (SHA-256, SHA-384, SHA-512)
- SHA-1 disallowed for digital signatures
- MD5 disallowed entirely

### 6.5 Mozilla Modern & Intermediate Evaluators

**Mozilla Modern** (`rules/mozilla_modern.py`) — strictest profile:
- TLS 1.3 only (TLS 1.2 = FAIL)
- Only AEAD ciphers: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`
- ECDHE with approved curves only

**Mozilla Intermediate** (`rules/mozilla_interm.py`) — balanced profile:
- TLS 1.2 + TLS 1.3 both acceptable
- Broader cipher list including ECDHE-ECDSA/RSA with AES-GCM
- No CBC ciphers, no static RSA

### 6.6 Forensic Observations Evaluator — 12 Observations (`rules/observations.py`)

Policy-neutral — these run regardless of which security standard applies:

| ID | Category | What It Detects |
|---|---|---|
| `OBS-STARTTLS-01` | Framing | Session completely in cleartext, no TLS at all |
| `OBS-STARTTLS-ADVERTISED-NOT-USED` | Framing | Server advertised STARTTLS but session stayed cleartext |
| `OBS-STARTTLS-03` | Framing | STARTTLS upgrade rejected by server (454) |
| `OBS-STARTTLS-UNADVERTISED-REQUEST` | Framing | Client sent STARTTLS without server advertising it |
| `OBS-SEC-PLAINTEXT-AUTH` | Security | Credentials sent in cleartext (AUTH LOGIN/PLAIN, USER/PASS) |
| `OBS-CERT-HOSTNAME-MISMATCH` | Identity | Certificate hostname doesn't match SNI |
| `OBS-ANALYZER-TRUST-STATUS` | Trust | Trust path validation result (TRUSTED / UNTRUSTED / etc.) |
| `OBS-ANALYZER-CHAIN-STATUS` | Trust | Chain completeness (complete / leaf_only / tampered / etc.) |
| `OBS-PROTO-01` | Handshake | HelloRetryRequest triggered |
| `OBS-PROTO-02` | Handshake | TLS 1.3 0-RTT early data used (replay surface) |
| `OBS-PROTO-03` | Handshake | RFC 8446 downgrade sentinel detected |
| `OBS-CERT-01` | Observability | Certificate not observable (PSK-only, no cert on wire) |

### 6.7 Engine Orchestrator (`analysis/rule_engine/engine.py`)

```python
engine = RuleEngine(mode="gov_only", trust_store_manager=tsm)

# Single stream
stream_report = engine.evaluate_stream(session_dict)

# All streams in a PCAP
session_report = engine.evaluate_sessions(sessions_dict)
```

`evaluate_stream()` flow:
1. `InputBuilder.build(session, trust_store_manager)` → `RuleInput`
2. `NIST52r2Evaluator.evaluate_all(r_in)` → 25 `PolicyResult` objects
3. `NIST131aEvaluator.evaluate_all(r_in)` → N `PolicyResult` objects
4. `MozillaModernEvaluator.evaluate_all(r_in)` → N `PolicyResult` objects
5. `MozillaIntermEvaluator.evaluate_all(r_in)` → N `PolicyResult` objects
6. `ObservationsEvaluator.evaluate_all(r_in)` → 12 `ObservationResult` objects
7. Assemble into `StreamRuleReport`

`evaluate_sessions()` iterates all stream IDs and assembles a `SessionReport(stream_reports={...}, total_streams=N)`.

**`mode` parameter:**
- `"gov_only"` — Federal government context. TLS 1.0/1.1 = `FAIL`.
- `"citizen_facing"` — Public-facing servers. TLS 1.0 = `OBSERVATION` (permissible under NIST exception).

---

## 7. Testbed Runner & Batch Automation

### 7.1 ScenarioSpec (`testbed/runner/spec.py`)

Frozen dataclass parsed from a `pcap_generation_matrix.csv` row. Normalizes string values via lookup tables:

```python
@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str        # "PCAP-001"
    protocol: str           # "smtp" | "imap" | "pop3"
    tls_version: str        # "tls10" | "tls11" | "tls12" | "tls13" | "none"
    cipher_strength: str    # "HIGH" | "MEDIUM" | "WEAK" | "BROKEN"
    cert_validity: str      # "valid" | "expired" | "not_yet_valid"
    cert_chain_shape: str   # "complete" | "self_signed_trusted" | ...
    cert_sig_algo: str      # "ecdsa" | "rsa_pkcs" | "rsa_pss" | "ed25519"
    hostname_match: str     # "matched" | "mismatched"
    starttls_integrity: str # "normal" | "stripped" | "rejected" | ...
    auth_state: str         # "none" | "plaintext" | "post_tls"
    generator_requirement: str  # canonical identifier for special harness needs
```

`load_matrix(path)` reads the CSV → list of `ScenarioSpec`.

### 7.2 TLS Cipher Resolver (`testbed/runner/resolver.py`)

Deterministic, traceable cipher selection from `pcap_generation_matrix.csv` intent + IANA database + runtime OpenSSL capabilities.

**Resolution status enum:**
```python
class ResolutionStatus(str, Enum):
    CONFIGURABLE_CANDIDATE_SELECTED = "CONFIGURABLE_CANDIDATE_SELECTED"
    DAEMON_CANNOT_ENFORCE = "DAEMON_CANNOT_ENFORCE"  # e.g. needs Dovecot but only Postfix running
    UNRESOLVABLE = "UNRESOLVABLE"    # contradictory spec (cleartext + HIGH cipher)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # cleartext scenario, no cipher needed
    SPECIAL_HARNESS = "SPECIAL_HARNESS"  # needs MitM or legacy binary
```

**Deterministic selection algorithm:**
1. Filter IANA cipher registry to matching `tls_version` + `cipher_strength` tier
2. Prefer IANA `Recommended="Y"` first
3. Then `Recommended="N"`, then `Recommended="D"`
4. Alphabetical tie-breaking as final determinism guarantee
5. Validate selected cipher is actually supported by running OpenSSL/Postfix instance

**`ResolutionResult`** records the full rationale including `selection_basis` (`UNIQUE`, `EXPLICIT_REPOSITORY_POLICY`, `EXACT_CONTRACT`), `selected_cipher` (IANA name), `openssl_cipher` (for server config), and `runtime_status`.

Loads pre-computed contracts from `data/scenario_contracts.json` as fast-path fallback to avoid re-deriving from scratch on every batch run.

### 7.3 Stager (`testbed/runner/stager.py`)

Transforms `ScenarioSpec` → self-contained staged directory:
```
testbed/staged/PCAP-001/
├── chain.pem      # X.509 certificate chain from PKIFactory
├── key.pem        # Private key
├── main.cf        # Rendered Postfix config (SMTP scenarios)
├── dovecot.conf   # Rendered Dovecot config (IMAP/POP3 scenarios)
└── manifest.json  # All parameters for reproducibility
```

Three stager classes handle protocol-specific config rendering:
- `SMTPStager` — renders `postfix/templates/main.cf` with cipher string, TLS version, cert paths
- `IMAPStager` — renders `dovecot/templates/dovecot.conf` with IMAP settings
- `POP3Stager` — renders `dovecot.conf` with POP3-specific settings

Config templates use Jinja2-style variable substitution. The stager calls `iana_to_openssl()` to translate the selected IANA cipher name into an OpenSSL cipher string before injecting it into the server config.

### 7.4 Clients (`testbed/runner/client.py`)

Three deterministic client classes implement the full scripted protocol loop.

**`ClientResult` dataclass:**
```python
@dataclass
class ClientResult:
    scenario_id: str
    success: bool
    tls_negotiated: bool
    expected_condition: str   # "NORMAL" | "STARTTLS_REJECTED" | "MANDATORY_ABORT" | ...
    tls_version: Optional[str]
    cipher: Optional[Tuple[str, str, int]]
    peer_certificate_der: Optional[bytes]
    transcript: List[Dict[str, Any]]  # full protocol transcript
    error: Optional[str]
```

**`SMTPClient`** drives:
1. Connect to `172.28.0.10:2525` (or `172.28.0.10:465` for implicit TLS)
2. Receive `220` banner
3. Send `EHLO`; parse capabilities via `parse_ehlo_capabilities()`
4. If scenario requires STARTTLS: send `STARTTLS`, receive `220 Ready`
5. Wrap socket: `ssl.SSLContext` with forced TLS version + cipher list
6. Send post-TLS `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`

**`IMAPClient`** drives: `CAPABILITY` → optional `STARTTLS` → `LOGIN`.
**`POP3Client`** drives: `CAPA` → optional `STLS` → `USER`/`PASS`.

`derive_client_tls_config(spec)` translates `ScenarioSpec` into `ssl.SSLContext` parameters (forced version, cipher list, SNI) using the same `TLSCipherResolver` used by the stager — ensuring client and server are configured symmetrically.

### 7.5 Comparator (`testbed/runner/comparator.py`)

**Inputs:** `expected.json` (assertions from `ScenarioSpec`) + `observed.json` (PCAPAnalyzer output).
**Output:** `comparison.json` with per-assertion PASS/FAIL/INCONCLUSIVE verdict.

**Four design invariants:**

1. **100% assertion coverage** — every assertion key in `expected["assertions"]` must have an evaluation result. Missing = FAIL.

2. **Wire honesty** — if TLS aborted with a fatal alert, cipher/version were never negotiated. These are `NOT_APPLICABLE`, not PASS.

3. **RFC 5280 signature scope** — `compare_sig_algo()` inspects ONLY `signature_algorithm_name`, `signature_algorithm_oid`, and `signature_algorithm_parameters`. It NEVER looks at `public_key_algorithm` (SubjectPublicKeyInfo, which is the subject's key — not the issuer's signing mechanism).

4. **Ambiguity detection** — `select_evaluated_session()` ranks candidate streams by: protocol match + TLS presence + STARTTLS status + handshake message count. If multiple streams tie for the top score → `INCONCLUSIVE`, never a silent guess.

**Stream selection scoring:**
```python
score = 0
if session protocol matches expected protocol: score += 50
if session has TLS: score += 30
if starttls_status in ("UPGRADED", "IMPLICIT_TLS"): score += 40
if handshake flight messages present: score += 15
if handshake alerts present: score += 15
```

**Verdict states:** `PASS`, `FAIL`, `NOT_APPLICABLE` (parameter not negotiated), `INCONCLUSIVE` (ambiguous multi-stream or encrypted evidence).

### 7.6 ScenarioRunner (`testbed/runner/runner.py`)

Executes one scenario end-to-end:

```
ScenarioSpec
    ↓ resolve_scenario()
ResolutionResult (cipher, status)
    ↓ PKIFactory.generate_cert_profile()
Cert chain + key
    ↓ SMTPStager/IMAPStager/POP3Stager.stage()
testbed/staged/PCAP-NNN/ artifacts
    ↓ deploy to testbed/active/ + postfix/dovecot reload
    ↓ discover_docker_bridge() → tshark -i <bridge> -w PCAP-NNN.pcap &
    ↓ SMTPClient/IMAPClient/POP3Client.run()
ClientResult
    ↓ tshark terminates
PCAP-NNN.pcap
    ↓ PCAPAnalyzer.analyze()
sessions dict
    ↓ build_observed_artifact()
PCAP-NNN.observed.json
    ↓ RuleEngine.evaluate_sessions()
PCAP-NNN.evidence.json
    ↓ compare(expected, observed)
PCAP-NNN.comparison.json
```

`discover_docker_bridge()` uses `docker network inspect testbed_mailtest_net` to dynamically find the bridge interface name (e.g. `br-87a3125207be`) — avoids hardcoding.

`cleanup_scenario_artifacts()` removes stale `.pcap`, `.expected`, `.observed`, `.comparison`, `.evidence`, `.batch` files before re-running a scenario, preventing cross-contamination.

### 7.7 BatchOrchestrator (`testbed/runner/batch.py`)

Pipelines all 126 scenarios:

```
1. check_preflight() — verify which daemons are running
2. For each scenario:
   a. Resume check — skip if SHA-256 hashes match prior verified run
   b. Stale artifact cleanup
   c. classify_scenario() → EXECUTABLE_STANDARD | BLOCKED | UNRESOLVABLE | SPECIAL_HARNESS
   d. If EXECUTABLE_STANDARD: execute via ScenarioRunner
3. Fault-isolated: one failure never aborts the batch
4. Write batch_run_<run_id>.json + batch_report.json + batch_report.md
```

**`BatchExecutionCategory` enum:**
- `EXECUTABLE_STANDARD` — has concrete cipher, correct daemons running
- `BLOCKED` — needs daemon that isn't running (e.g. Dovecot down)
- `UNRESOLVABLE` — contradictory spec (e.g. cleartext + HIGH cipher)
- `SPECIAL_HARNESS` — needs MitM proxy or legacy binary

**Per-scenario artifact set** written to `testbed/captures/`:
```
PCAP-NNN.pcap          — raw capture
PCAP-NNN.expected.json — ground-truth assertions
PCAP-NNN.observed.json — PCAPAnalyzer output
PCAP-NNN.comparison.json — comparator verdicts
PCAP-NNN.evidence.json  — rule engine PolicyResult objects
PCAP-NNN.batch.json     — run metadata (run_id, timing, hashes)
```

**Artifact integrity hashing:**
```python
def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"
```

Each artifact's hash is recorded in the batch manifest. Resume logic compares these hashes to skip already-verified scenarios.

---

## 8. Data Layer

| File | Size | Purpose |
|---|---|---|
| `pcap_generation_matrix.csv` | 22 KB | 126 scenario definitions — the master test matrix |
| `scenario_contracts.json` | 70 KB | Pre-computed resolution contracts per scenario ID |
| `sidecar_schema.json` | 5 KB | 28-field JSON Schema for ground-truth PCAP labels |
| `expected_schema.json` | 4 KB | JSON Schema enforced on every `expected.json` artifact |
| `observed_schema.json` | 1.4 KB | JSON Schema for `observed.json` |
| `comparison_schema.json` | 1.9 KB | JSON Schema for `comparison.json` |
| `tls_ciphers.csv` | 28 KB | Full IANA TLS cipher registry (~500 suites) |
| `nist_sp800_52_r2_rules.json` | 109 KB | Machine-readable NIST 800-52r2 rule definitions |
| `nist_sp800_52_r2_rules.md` | 80 KB | Human-readable NIST rules reference |
| `nist_sp800_52_r2_ciphers.json` | 4 KB | NIST-approved cipher lists (Sections 3.3.1.1/1.2, App C, App D) |
| `tls_ref_6.0.json` / `guidelines/6.0.json` | 4 KB | TLS 1.3 reference cipher data |
| `matrix_resolution_report.md` | 24 KB | Audit of all 126 scenario resolvability decisions |
| `matrix_executability_audit.md` | 42 KB | Full per-scenario executability analysis |
| `NIST.SP.800-52r2.pdf` | 815 KB | Authoritative standard (referenced by rule engine) |
| `NIST.SP.800-131Ar2.pdf` | 686 KB | Authoritative standard (referenced by 131A evaluator) |

**`sidecar_schema.json` 28 fields** include: `scenario_id`, `protocol`, `tls_presence`, `starttls_integrity`, `tls_version`, `cipher_strength`, `cert_validity`, `cert_chain_shape`, `cert_sig_algo`, `hostname_match`, `auth_outcome`, `expected_starttls_status`, `expected_trust_status`, `downgrade_sentinel`, `forward_secrecy`, `hello_retry_request`, `tls13_kex_mode`, and more.

**Schema validation** is enforced at runtime via `jsonschema.validate()` inside `comparator.py` and `runner.py`. Any artifact that fails validation produces an immediate `FAIL`.

---

## 9. Test Suite

| File | What It Tests |
|---|---|
| `analysis/test_rule_engine.py` (19.8 KB) | All 25 NIST 800-52r2 rules, 131A, Mozilla, observations — per-rule PASS/FAIL/NOT_APPLICABLE |
| `analysis/test_tls_session_hrr.py` (8.4 KB) | HRR detection, PSK mode extraction, downgrade sentinel, 0-RTT |
| `analysis/test_stream_reassembly.py` (18.3 KB) | TCP reassembly: out-of-order, retransmissions, segmented TLS records |
| `analysis/test_pkix_backtracking.py` (27.4 KB) | PKIX path: multi-issuer chains, backtracking, bad_constraint, tampered_sig |
| `analysis/test_cert_validator_san_ip.py` (7.2 KB) | Hostname matching: IP SAN, wildcard, CN fallback, multi-label rejection |
| `testbed/runner/test_resolver.py` (18.2 KB) | Cipher resolver: deterministic selection, executability classification |
| `testbed/runner/test_data_integrity.py` (9.4 KB) | Schema validation, hash verification, manifest consistency |
| `testbed/runner/test_comparator.py` (26 KB) | Comparator: PASS/FAIL/INCONCLUSIVE verdicts, ambiguity, wire honesty |
| `testbed/runner/test_batch.py` (27.7 KB) | Batch orchestrator: resume logic, fault isolation, artifact lifecycle |
| `testbed/test_baseline_end_to_end.py` (4.7 KB) | End-to-end: one full pipeline run → comparison PASS |
| `testbed/pki/generator/test_rsa_pss_oid.py` | RSA-PSS OID encoding correctness in DER |
| `scratch/test_live_milestone1_pcap083.py` (7 KB) | Live integration test against Docker for PCAP-083 |
| `scratch/test_live_milestone2_pcap084.py` (7 KB) | Live integration test for PCAP-084 (RSA-1024 weak key) |

---

## 10. Current Batch Run State

As of 2026-09-26, `testbed/captures/` holds **126 captured scenarios** (PCAP-001 through PCAP-126) each with a full artifact set.

**Batch runs logged:**
- `batch_run_batch_20260923_222851_8eb6175a.json` — 137 KB (large multi-scenario run)
- `batch_run_batch_20260924_085243_bf8c2d9d.json` — 137 KB
- `batch_run_batch_20260924_055333_24ca9958.json` — 139 KB
- `batch_run_batch_20260925_202031_fc1d0337.json` — 24.9 KB
- 20+ additional runs from incremental development

**Latest small batch run** (`batch_20260925_225656_45d30f5a`):
```
Scenarios selected: 2 (PCAP-004, PCAP-005)
Generated: 1 (PCAP-005: PASS, 1.23s, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
Failed: 1 (PCAP-004: staging failed)
Bridge: br-87a3125207be
```

**`batch_report.md` format:**
```markdown
# Batch Generation Report: `batch_test_failure_isolation`
- Started: 2026-09-25 22:58:29 UTC  |  Total Duration: 2.50s
## Summary Metrics
| Metric | Count |
| Total Selected | 2 |
| Successfully Generated | 1 |
|   ├─ Comparison PASS | 1 |
| Failed Executions | 1 |
## Detailed Scenario Execution Matrix
| Scenario | Protocol | Category | State | Comparison | Cipher | Duration |
| PCAP-004 | SMTP | EXECUTABLE_STANDARD | FAILED | - | - | - |
| PCAP-005 | SMTP | EXECUTABLE_STANDARD | GENERATED | PASS | - | 1.23s |
```

---

## 11. End-to-End Data Flow Walk-Through

Full trace for PCAP-083 (SMTP + STARTTLS + TLS 1.2 + ECDHE-ECDSA-AES128-CBC-SHA):

```
1. BatchOrchestrator reads pcap_generation_matrix.csv row 83
   → ScenarioSpec(scenario_id="PCAP-083", protocol="smtp",
                  tls_version="tls12", cipher_strength="MEDIUM",
                  cert_sig_algo="ecdsa", starttls_integrity="normal",
                  cert_chain_shape="complete", cert_validity="valid")

2. TLSCipherResolver.resolve_scenario(spec)
   → Filter IANA DB: TLS 1.2 + MEDIUM tier
   → Selection algorithm: IANA Recommended="N" alphabetical tie-break
   → selected_cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
   → openssl_cipher = "ECDHE-ECDSA-AES128-SHA"
   → status = CONFIGURABLE_CANDIDATE_SELECTED

3. PKIFactory.generate_cert_profile(sig_algo="ecdsa", validity="valid",
                                     chain_shape="complete", san_type="matched_dns")
   → root_ca signs intermediate (P-256 ECDSA), intermediate signs leaf
   → leaf: CN=mail.test.local, SAN=DNS:mail.test.local, valid 2 years
   → chain.pem (leaf + intermediate), key.pem (leaf private key)

4. SMTPStager.stage(spec, resolver_result, cert_profile)
   → Renders main.cf:
       smtpd_tls_protocols = TLSv1.2
       smtpd_tls_mandatory_ciphers = medium
       smtpd_tls_cert_file = /etc/mailtest/active/chain.pem
       smtpd_tls_key_file = /etc/mailtest/active/key.pem
   → Writes testbed/staged/PCAP-083/{chain.pem, key.pem, main.cf, manifest.json}

5. ScenarioRunner deploys:
   → cp staged/PCAP-083/* testbed/active/
   → docker exec mailtest-postfix postfix reload
   → discover_docker_bridge() → "br-87a3125207be"
   → tshark -i br-87a3125207be -w captures/PCAP-083.pcap &

6. SMTPClient.run(spec):
   → Connect TCP to 172.28.0.10:2525
   → ← "220 mailtest.example.com ESMTP Postfix"
   → → "EHLO client.example.com"
   → ← "250-STARTTLS\r\n250 OK"
   → → "STARTTLS"
   → ← "220 2.0.0 Ready to start TLS"
   → SSLContext(TLS1.2).wrap_socket(sni="mail.test.local")
   → ClientHello → ServerHello → Certificate → ServerHelloDone
     → ClientKeyExchange → ChangeCipherSpec → Finished (both)
   → → "EHLO" (post-TLS), MAIL FROM, RCPT TO, DATA, QUIT
   → ClientResult(success=True, tls_negotiated=True)

7. tshark terminates → PCAP-083.pcap (4,524 bytes written)

8. PCAPAnalyzer.analyze("captures/PCAP-083.pcap"):
   → tshark follow,tcp,raw → 1 stream
   → _identify_server_node(): b"220" found → Node 0 = server
   → detect_protocol(): b"220" + b"ESMTP" → "SMTP"
   → detect_starttls():
       Step 1: b"STARTTLS" in server EHLO response → advertised=True
       Step 2: b"STARTTLS\r\n" in client data → requested=True
       Step 3: b"220 2.0.0 Ready" in server data → accepted=True
       Step 4: b"\x16\x03" immediately after → handshake=True
       Step 5: no AUTH LOGIN/PLAIN/USER/PASS in cleartext → clean
       → starttls_status = "COMPLETED_SUCCESSFULLY"
   → extract_tls_info():
       ServerHello: version=0x0303 (TLS 1.2), cipher=0xC009
       cipher_name = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", strength="MEDIUM"
       named_group = "secp256r1" (from ServerKeyExchange)
       forward_secrecy = True
       hello_retry_request = False
       downgrade_sentinel = {detected: False}
       handshake_status = "COMPLETED"
   → extract_certificates(): 2 DER blobs from Certificate message
   → For leaf cert:
       subject="CN=mail.test.local", san_dns=["mail.test.local"]
       sig_algo="ecdsa-with-SHA256", public_key="EC P-256"
       not_before=2025-01-01, not_after=2027-01-01
   → verify_certificate_signature(leaf, intermediate): ECDSA P-256 → True
   → verify_pkix_path(): leaf←intermediate←root, all constraints OK → TRUSTED
   → check_hostname_match(leaf, "mail.test.local"): SAN DNS:mail.test.local = MATCH

9. build_observed_artifact() → PCAP-083.observed.json

10. RuleEngine.evaluate_stream(session):
    → InputBuilder.build(): RuleInput with all fields populated
    → NIST52r2Evaluator: 25 rules
        N52-TLS-01: TLS 1.2 ≠ TLS 1.0/1.1 → PASS
        N52-CIPHER-01: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA in NIST approved list → PASS
        N52-KEX-01: secp256r1 is NIST-approved curve → PASS
        N52-CERT-01: ecdsa-with-SHA256 approved sig algo → PASS
        N52-CERT-02: EC P-256 key size 256 ≥ 224 → PASS
        N52-CERT-03: not expired at capture time → PASS
        N52-CERT-05: lifespan 730 days ≤ 3 years → PASS
        N52-CERT-06: SAN extension present → PASS
        N52-CERT-09: TRUSTED → PASS
        N52-CERT-10: MATCH → PASS
        N52-PROTO-01: no plaintext auth → PASS
        [all 25 rules → PASS]
    → ObservationsEvaluator: 12 observations
        OBS-STARTTLS-01: detected=False (TLS was used)
        OBS-SEC-PLAINTEXT-AUTH: detected=False
        OBS-CERT-HOSTNAME-MISMATCH: detected=False
        OBS-ANALYZER-TRUST-STATUS: detected=True, description="TRUSTED"
        [all clean]
    → StreamRuleReport → PCAP-083.evidence.json

11. compare(expected, observed) → PCAP-083.comparison.json
    → expected tls_version="tls12" vs observed "TLS 1.2" → PASS
    → expected cipher_strength="MEDIUM" vs observed "MEDIUM" → PASS
    → expected starttls_integrity="normal" vs observed "COMPLETED_SUCCESSFULLY" → PASS
    → expected hostname_match="matched" vs observed "MATCH" → PASS
    → expected trust="TRUSTED" vs observed "TRUSTED" → PASS
    → Overall verdict: PASS

12. BatchOrchestrator records:
    → duration=3.731s
    → artifact hashes (SHA-256 for each of 5 files)
    → execution_state="GENERATED", comparison_status="PASS"
    → PCAP-083.batch.json written
    → Entry added to batch_run_<run_id>.json
```

---

## 12. Remaining Roadmap

The forensic telemetry foundation and rule engine are complete. These are the planned next components:

### A. Feature Extraction Pipeline

Transform `SessionReport` JSON into 28-dimensional feature vectors:

| Feature | Type |
|---|---|
| `protocol` | Categorical (one-hot) |
| `tls_version` | Ordinal: 0=none, 1=TLS1.0, 2=TLS1.1, 3=TLS1.2, 4=TLS1.3 |
| `cipher_tier` | Ordinal: 0=BROKEN, 1=WEAK, 2=MEDIUM, 3=HIGH |
| `kex_type` | Categorical: RSA, DHE, ECDHE, PSK, PSK_DHE |
| `starttls_status` | Ordinal: stripped=0, rejected=1, none=2, completed=3 |
| `forward_secrecy` | Boolean |
| `downgrade_sentinel` | Boolean |
| `cleartext_auth` | Boolean |
| `hrr_triggered` | Boolean |
| `zero_rtt_used` | Boolean |
| `cert_days_to_expiry` | Numerical (negative = expired) |
| `public_key_bits` | Numerical |
| `san_count` | Numerical |
| `alert_count` | Numerical |
| `hostname_match` | Boolean |
| `nist_52r2_fail_count` | Numerical |
| `nist_52r2_pass_rate` | Float |

### B. AI Posture Risk Scorer (Supervised ML)

XGBoost or Random Forest classifier trained on 126 labeled scenarios. Outputs a **Cryptographic Posture Score** 0–100:

| Score | Tier | Example Conditions |
|---|---|---|
| 0–20 | CRITICAL | STARTTLS stripped + credentials leaked, NULL cipher |
| 20–40 | HIGH | TLS 1.0/1.1, broken cipher, expired/untrusted cert |
| 40–60 | MEDIUM | TLS 1.2 CBC-mode, missing SAN, weak RSA-1024 key |
| 60–80 | LOW | TLS 1.2 AEAD, minor cert issues |
| 80–100 | SECURE | TLS 1.3, AEAD, ECDHE, valid chain, hostname match |

### C. TLS Behavioral Anomaly Detection (Unsupervised ML)

Isolation Forest or Autoencoder trained on normal RFC-compliant traffic. Flags sessions that don't violate static rules but exhibit abnormal behavioral footprints (unusual extension ordering, non-standard port pairings, unexpected downgrade retries).

### D. Prescriptive Remediation Engine

Auto-generate copy-pasteable server config fixes per finding:
```
Weak cipher / TLS 1.0:
  smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

Plaintext auth:
  smtpd_tls_auth_only = yes

STARTTLS stripping protection:
  DNS _mta-sts TXT record + TLSA/DANE records
```

### E. Multi-Format Report Generator

- **JSON** — machine-readable for SIEM ingestion (Splunk, Elastic, QRadar, Sentinel)
- **HTML** — standalone interactive single-page report with collapsible stream trees
- **PDF** — executive audit report with compliance scorecards and cert chain diagrams

### F. SOC Security Dashboard (React)

- Drag-and-drop PCAP upload
- Global cryptographic posture grade (A+ to F)
- Interactive stream timeline (packet-level protocol transitions)
- X.509 certificate chain tree viewer highlighting trust break points
- One-click remediation script download

---

## 13. Engineering Decisions & Obstacles

### Zero-Decryption Architecture
All analysis operates on cleartext TLS handshake metadata. No HKDF, no key derivation. Every claim is defensible purely from observable wire evidence — critical for passive SOC forensics where private keys are unavailable.

### Postfix Chroot in Docker
Debian Postfix defaults to chrooted workers. In a minimal Docker image, libraries aren't in `/var/spool/postfix` → silent crash. Fix: `smtp inet n - n` in `master.cf`.

### Docker Bridge Interface Discovery
Bridge name (e.g. `br-87a3125207be`) is dynamically assigned. `discover_docker_bridge()` calls `docker network inspect testbed_mailtest_net` at runtime — works on any machine.

### RFC 8446 Encryption Boundary
TLS 1.3 wraps all post-ServerHello records in outer type 23. Without modeling this, encrypted `Finished` messages get misclassified as application data. Solved by tracking the handshake/encryption boundary state explicitly.

### RSA-PSS OID Encoding
Two OID forms exist: generic `rsaEncryption` with PSS parameters in `signatureAlgorithm`, and `id-RSASSA-PSS` with explicit embedded params. The validator handles both. The `getattr(cert, "signature_algorithm_parameters", None)` guard protects against older `cryptography` versions.

### HelloRetryRequest vs ServerHello
RFC 8446 reuses the ServerHello message type for HRR. The only way to distinguish them is matching the full 32-byte random field against `SHA-256("HelloRetryRequest")`. Implemented in `tls_session.py`.

### Downgrade Sentinel
RFC 8446 mandates the `DOWNGRD\x01` sentinel in bytes 24-32 of TLS 1.2 ServerHello.random when a TLS 1.3-capable server negotiates down. Clients must reject connections where this sentinel is present without a legitimate TLS 1.3 negotiation. PCAP-109 tests this.

### Comparator Wire Honesty
A naive comparator might PASS `cipher_suite` for a scenario where the handshake aborted — because the expected value matches what *would have* been negotiated. The comparator enforces `NOT_APPLICABLE` for any parameter that couldn't be observed due to handshake abortion.

### PKIX Backtracking
RFC 4158 PKIX path building requires DFS with backtracking when multiple CAs share the same Subject DN. PCAP-119 exercises this. Implemented as iterative DFS in `cert_validator.py`, identical to production TLS stack behavior.

### Deterministic Batch Resume
Batch runs can take hours. The resume system SHA-256-hashes all artifacts per scenario. On re-run, scenarios with matching hashes are skipped, ensuring coherent results — not a mix of old and new artifacts from different configurations.

### Anonymous Cipher Classification
Anonymous suites (`DH_anon`, `ECDH_anon`) provide mathematical PFS but zero authentication, making them trivially vulnerable to MitM. They are classified `BROKEN` even though `has_pfs=True` — the BROKEN check runs before the HIGH/MEDIUM checks to prevent them from ever appearing secure.

### Static RSA + AEAD = WEAK, Not HIGH
`TLS_RSA_WITH_AES_256_GCM_SHA384` uses modern AES-256-GCM (AEAD) but static RSA key exchange (no PFS). If the RSA private key is later compromised, all past sessions can be decrypted. The WEAK check (`not has_pfs`) runs before the HIGH check (`AEAD`) precisely to catch this case.

---

*End of Report*

**Repository:** `/home/rick/SES-v1`  
**Last Batch Run:** 2026-09-25  
**Total Captures:** 126 scenarios (PCAP-001 through PCAP-126)  
**Python Version:** 3.14 (CPython)  
**Key Libraries:** `scapy`, `cryptography`, `jsonschema`, `certifi`, `tshark` (subprocess)  
**Primary Languages:** Python 3.14, C (legacy harness)  
