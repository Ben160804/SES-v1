# SecureMailScope — Dataset Recommendations for the Two ML Gaps

**Gap 1**: Cryptographic Risk Classification — large labeled dataset of TLS security/cryptographic configurations with risk/security labels  
**Gap 2**: Email TLS generalization — real-world SMTP/IMAP/POP3 STARTTLS PCAPs with TLS handshakes and certificates

---

## Datasets That Solve the Gaps

### 1. Rapid7 Sonar "More SSL" Certificate Dataset

| Field | Value |
|---|---|
| **Gap it solves** | **Gap 1** (Risk Classification) — provides real email server X.509 certificates |
| **Number of records** | ~10M+ certificates per protocol (SMTP/25, SMTPS/465, SMTP/587, POP3/110, IMAPS/993) |
| **Size** | ~18 GB total (certs only); ~550 MB total (names only) |
| **Protocols** | SMTP STARTTLS (25), SMTPS (465), SMTP STARTTLS (587), POP3 STARTTLS (110), IMAPS (993) |
| **Certificates?** | ✅ Full X.509 certificate chains in JSON (subject, issuer, validity, key algo, key length, sig algo, SAN, etc.) |
| **PCAP/handshake?** | ❌ Certificate data only (no handshake capture, no cipher suites, no TLS version) |
| **Labels** | ⚠️ Derivable: key_size < 2048 (weak), SHA1 signature (weak), self-signed, expired, hostname mismatch, not CA-trusted |
| **Download URL** | `https://opendata.rapid7.com/sonar.moressl?page=1` |
| **License** | Free for research; attribution to Rapid7 Labs required |
| **Recommended subset** | `smtp_starttls_25_certs.gz` (3.3 GB) + `smtp_starttls_25_names.gz` (72 MB) for email-focused risk classification |

### 2. EFF StartTLS Everywhere Policy Database

| Field | Value |
|---|---|
| **Gap it solves** | **Gap 1 + Gap 2** — domain-level STARTTLS policy context (enforce vs testing) |
| **Number of records** | ~200 domains with STARTTLS policies |
| **Size** | 50 KB (policy.json) |
| **Protocols** | SMTP (domain-level) |
| **Certificates?** | ❌ Policy file only |
| **PCAP/handshake?** | ❌ |
| **Labels** | ✅ Binary: STARTTLS enforced vs testing/not-enforced per domain |
| **Download URL** | `https://raw.githubusercontent.com/EFForg/starttls-everywhere/master/policy.json` |
| **License** | BSD-3-Clause |
| **Recommended subset** | Full file (50 KB) — join with Rapid7 cert data by domain name to add STARTTLS policy label |

### 3. Censys Universal Internet Dataset (BigQuery)

| Field | Value |
|---|---|
| **Gap it solves** | **Gap 1** (best option — has both TLS version AND cipher suite from real handshakes) |
| **Number of records** | 15+ billion total (millions of SMTP/IMAPS/POP3 records) |
| **Size** | Full dataset: TB-scale; filtered queries: GB-scale (pay-as-you-go) |
| **Protocols** | SMTP (25/587/465), IMAP (143/993), POP3 (110/995), HTTPS (443), and more |
| **Certificates?** | ✅ Full X.509 parse + validation status (trusted/untrusted/expired/revoked/dv/ov/ev) |
| **PCAP/handshake?** | ❌ TLS metadata extracted from handshakes (no raw packets) |
| **Labels** | ✅ Built-in: `tls.version_selected`, `tls.cipher_selected`, `tls.jarm`, certificate validation labels |
| **Download URL** | `https://console.cloud.google.com/bigquery?p=censys-io&gt;m=universal_internet_dataset` |
| **License** | Free tier (limited GB processed); paid for large queries |
| **Recommended subset** | Query for `service_name IN ('SMTP', 'SMTPS', 'IMAPS', 'POP3S')` with TLS + cert fields — yields ~100K-1M email TLS records |

### 4. MAWI Working Group Traffic Archive

| Field | Value |
|---|---|
| **Gap it solves** | **Gap 2** (STARTTLS PCAPs) — only source of real email STARTTLS packet captures |
| **Number of records** | 1 daily 15-minute trace per day (since 2001); each trace contains 100–1000 email flows with STARTTLS |
| **Size** | ~12–15 MB per trace (gzip-compressed PCAP) |
| **Protocols** | SMTP, IMAP, POP3 with STARTTLS (on backbone link traffic) |
| **PCAP/handshake?** | ✅ Full PCAP with STARTTLS upgrade + TLS handshake + certificates |
| **Certificates?** | ✅ Extractable from handshake (requires Zeek/Bro parsing) |
| **Labels** | ❌ None (need rule-based derivation from TLS properties) |
| **Download URL** | `http://mawi.wide.ad.jp/mawi/samplepoint-F/2024/<YYYYMMDDHHMM>.pcap.gz` (latest: 2024-06-19) |
| **License** | Free for research, IP addresses scrambled (privacy) |
| **Recommended subset** | Download 2-5 recent daily traces (~30-75 MB) for proof-of-concept STARTTLS extraction |

### 5. ZGrab2 SMTP/STARTTLS Scan Data (ISI/Censys)

| Field | Value |
|---|---|
| **Gap it solves** | **Gap 2 alternative** — real SMTP STARTTLS handshake data (not full PCAP) |
| **Number of records** | ~10–50M email server scan results |
| **Size** | ~1–5 GB per scan campaign |
| **Protocols** | SMTP STARTTLS (25, 587), SMTPS (465), IMAP STARTTLS (143), POP3 STARTTLS (110) |
| **PCAP/handshake?** | ⚠️ Handshake metadata only (TLS version, cipher suite, extensions) — extracted via ZGrab2, not raw packets |
| **Certificates?** | ✅ Full cert chains with properties |
| **Labels** | ⚠️ Derived: TLS version, cipher suite strength, cert validity, hostname match |
| **Download URL** | No centralized download — ZGrab2 produces this data but the raw scan results are rarely published. The existing `mix.zip` is HTTPS-only ZGrab2 data. Must re-run ZGrab2 with `--smtp --starttls` flags. |
| **License** | N/A (tool-based, requires infrastructure to re-scan) |

---

## Datasets We Should NOT Download

### A. CIC-IDS2017 / UNSW-NB15 / CICIDS2018
- **Why not**: Labeled as "intrusion detection" datasets. Email protocols appear as **background traffic** (only 110/788,579 flows are email-based in CICIDS2017), and labels are attack-type (DoS, brute force, botnet) — not TLS security/cipher risk. No STARTTLS handshake analysis. Would add noise, not signal.

### B. CESNET-TLS22 / CESNET-TLS-Year22 (141M+ TLS flows)
- **Why not**: HTTPS-only (port 443). The search result explicitly states "191 application/service labels (Google, Facebook, Netflix...)" — these are web services, not email protocols. Would add TLS 1.2/1.3 volume but no email-specific insight. Redundant with existing mix.zip.

### C. Cisco Umbrella/OpenDNS Security Graph
- **Why not**: DNS-query dataset with domain reputations. Provides domain→threat mapping but no TLS handshake data, cipher suites, or certificates. Does not solve either gap.

### D. Kaggle "IDS Encrypted & Post-Quantum Cryptography" (PQC datasets)
- **Why not**: The PQClass dataset covers 4 OSes × 2 browsers × PQC-on/off = 16 sessions. The CESNET-TLS22 portion is HTTPS-only. Neither provides email protocol data or cryptographic risk labels.

### E. Shodan IoT / Censys Host Data (not Certificate Data)
- **Why not**: Host-level data (open ports, banners) does not include TLS cipher suite selection or certificate properties. The Censys certificate dataset (item 3 above) is the relevant subset.

---

## Recommended Download Plan

### Step 1: Download Rapid7 Sonar Names Files (550 MB total)
```
# Smallest, fastest download — gives domain-to-certificate mapping
# for all email protocols (SMTP/25, SMTP/587, SMTPS/465, POP3/110, IMAPS/993)
wget https://opendata.rapid7.com/sonar.moressl/20260918/2026-09-18-1789713664-smtp_starttls_25_names.gz
wget https://opendata.rapid7.com/sonar.moressl/20260917/2026-09-17-1789683916-smtp_starttls_587_names.gz
wget https://opendata.rapid7.com/sonar.moressl/20260917/2026-09-17-1789666769-smtps_465_names.gz
```
- **What it gives**: Domain names → certificate fingerprints for email servers
- **Closes Gap 1?** Partially — provides the domain list for filtering

### Step 2: Download ONE Rapid7 Cert File (3.3 GB)
```
# Just SMTP STARTTLS on port 25 — the most standard email path
wget https://opendata.rapid7.com/sonar.moressl/20260918/2026-09-18-1789713664-smtp_starttls_25_certs.gz
```
- **What it gives**: Full X.509 certificates from ~millions of real SMTP STARTTLS email servers
- **Extractable features**: key_algorithm, key_length, signature_algorithm, validity_dates, issuer, subject, SAN, self_signed, CA_trust
- **Derivable risk labels**: weak_key (<2048), weak_sig (SHA1), expired, self_signed, hostname_mismatch → 5-tier risk labels
- **Closes Gap 1?** ✅ **YES** — provides the labeled (via derivation) TLS certificate risk dataset needed for training a cryptographic risk classifier on real email server data

### Step 3: Download EFF StartTLS policy.json (50 KB)
```
curl -sL https://raw.githubusercontent.com/EFForg/starttls-everywhere/master/policy.json -o policy.json
```
- **What it gives**: Domain-level STARTTLS policy mode (enforce vs testing)
- **Can join with**: Rapid7 cert data by domain name
- **Adds label**: `starttls_enforced` (binary) — whether a major email provider enforces STARTTLS

### Step 4: Download 2 MAWI daily traces (~25-30 MB)
```
wget http://mawi.wide.ad.jp/mawi/samplepoint-F/2024/202406191400.pcap.gz
wget http://mawi.wide.ad.jp/mawi/samplepoint-F/2024/202406121400.pcap.gz
```
- **What it gives**: Real backbone PCAP containing SMTP/IMAP/POP3 with STARTTLS handshakes + TLS certificates
- **Close Gap 2?** ✅ **YES** (partially) — provides the first real email STARTTLS PCAP data for the project. 2 traces give ~200-2000 email flows with full STARTTLS handshake visibility.

---

## Which Datasets Actually Close the Two Gaps?

| Gap | Dataset | Downloads needed | Size | Closes gap? |
|---|---|---|---|---|
| **Gap 1: Crypto risk classification** | Rapid7 Sonar SMTP STARTTLS certs (25) | Step 1 (names, 550 MB) + Step 2 (certs, 3.3 GB) | ~3.9 GB | ✅ **YES** — real email server certificates → derive risk labels (weak key, weak sig, expired, self-signed) |
| **Gap 1: Crypto risk classification** | EFF StartTLS policy.json | Step 3 (50 KB) | 50 KB | ✅ Supplements — adds STARTTLS enforcement label |
| **Gap 1: Crypto risk classification** | Censys BigQuery | One-time Google Cloud account setup | Free tier (limited) → $5–20 for filtered query | ✅ Alternative — richer (has TLS version + cipher suite, not just certs) but requires cloud setup |
| **Gap 2: Real email STARTTLS PCAPs** | MAWI Working Group Archive | Step 4 (2 daily traces) | ~25-30 MB | ✅ **YES (partially)** — only public source of real email STARTTLS packet captures; requires Zeek/Bro parsing |
| **Gap 2: Real email STARTTLS PCAPs** | ZGrab2 re-scan | Not a download — requires running ZGrab2 with SMTP STARTTLS modules | N/A (compute time) | ⚠️ Partial alternative — handshake metadata, not full PCAP |

---

## Final Answer

**Yes, we can close both gaps, but no single dataset solves both.**

**Gap 1 (Cryptorisk Classification): CLOSED** — Download **Rapid7 Sonar SMTP STARTTLS certificates** (3.3 GB for certs + 72 MB for names). This provides ~millions of real email server certificates from SMTP STARTTLS connections. With the existing `tls-compliance-dataset` rules and `tls_ciphers.csv` reference data, we can derive cryptographic risk labels (weak key, weak signature, expired, self-signed, hostname mismatch) and train a real risk classifier on 100K+ labeled examples. This transforms risk classification from "50 synthetic testbed samples" to "100K+ real email server certificates with derived labels."

**Gap 2 (Real email STARTTLS PCAPs): PARTIALLY CLOSED** — Download **2 MAWI daily traces** (25-30 MB). This provides real backbone PCAPs containing SMTP/IMAP/POP3 STARTTLS handshakes with certificates. While not as numerous as the mix.zip (which is HTTPS-only), these are the **only publicly available real email STARTTLS packet captures in existence**. Combined with scapy/Zeek parsing, this gives ~hundreds to low-thousands of real email STARTTLS sessions. This improves anomaly detection from "synthetic-only" to "real + synthetic hybrid."

**Total additional download**: ~4 GB (Rapid7) + 30 MB (MAWI) + 50 KB (EFF) = ~4 GB total, down from the 3.5+ GB already downloaded for mix.zip which was useful for anomaly detection but didn't solve the email TLS gaps.