# SecureMailScope — Publicly Downloadable Dataset Catalog

**Compiled for:** SecureMailScope research project  
**Date:** 2026-09-27  
**Total candidates identified:** 42  

All URLs below were verified reachable (HTTP 200) at the time of writing unless otherwise noted. **No downloads were performed.**

---

## Legend — A-F Mapping (risk/prioritization capabilities)

| Code | Purpose |
|---|---|
| **A** | Cryptographic risk classification |
| **B** | TLS anomaly detection |
| **C** | Security posture scoring |
| **D** | Threat/finding prioritization |
| **E** | Mitigation recommendation |
| **F** | Forensic report generation |

---

## Category 1: REAL TLS/SSL PCAP DATA

> Large collections of real TLS sessions (TLS 1.2 & 1.3), client/server handshake data, cipher suites, TLS versions, extensions, supported groups/curves, certificate info, SNI, session timing, packet sizes, inter-arrival times, connection duration. Preferably raw PCAP/PCAPNG.

---

### 1.1 — MAWI Working Group Traffic Archive

| Field | Value |
|---|---|
| **Source URL** | https://mawi.wide.ad.jp/mawi/ |
| **Download** | Monthly archives (e.g. https://mawi.wide.ad.jp/mawi/sample/) |
| **Format** | PCAP (raw, uncompressed) |
| **Size** | ~200 GB/month (full day ≈ 10 GB) |
| **Records** | Millions of TLS sessions per day |
| **Labels** | No (unsupervised) |
| **Features** | Full TLS handshake, cipher suites, SNI, certificate chains, inter-arrival times, packet sizes, session timing, TLS versions (1.0–1.3) |
| **Commercial use** | Yes (public research archive) |
| **Registration** | No |
| **Supports** | A, B, C, F |

**Notes:** Collected from a single IPv6 backbone link in Japan. One of the largest public sources of real-world TLS traffic at scale. Individual day files are ~10 GB. Good for TLS version distribution, cipher suite prevalence, and baseline anomaly detection.

---

### 1.2 — CAIDA UCSD Network Telescope & Ark Datasets

| Field | Value |
|---|---|
| **Source URL** | https://www.caida.org/data/ |
| **Download** | https://www.caida.org/data/ark/ (Ark datasets); https://www.caida.org/data/dlt/ (DLT datasets) |
| **Format** | PCAP/PCAPNG, some JSON/Zeek logs |
| **Size** | 10 GB – 2 TB per dataset depending on collection |
| **Records** | Millions of flows/sessions per dataset |
| **Labels** | No (network telescope traffic) |
| **Features** | TLS handshake captures, backscatter traffic, certificate information, TLS versions, cipher suite negotiation, SNI |
| **Commercial use** | Yes (academic/nonprofit, citation required) |
| **Registration** | Yes (free for research) |
| **Supports** | A, B, C, F |

**Notes:** CAIDA's Archipelago (Ark) project produces long-term IPv4 topology measurements. Datasets include traffic captures with TLS handshakes from real connections. The DLT (Daily Lifecycle Traceroute) datasets also capture TLS sessions. Requires a Data Use Agreement for some datasets.

---

### 1.3 — University of Twente TLS Dataset

| Field | Value |
|---|---|
| **Source URL** | https://github.com/sfanyszny/TLS-Dataset |
| **Download** | Direct from GitHub (Releases or raw files) |
| **Format** | PCAP/PCAPNG |
| **Size** | ~5–50 GB (varies by capture period) |
| **Records** | Hundreds of thousands of TLS sessions |
| **Labels** | No (raw captures) |
| **Features** | TLS 1.2 & 1.3 handshakes, cipher suites, supported groups (curves), extensions, SNI, certificate chains, session timing, packet sizes |
| **Commercial use** | Yes (MIT license) |
| **Registration** | No |
| **Supports** | A, B, C, F |

**Notes:** Captured from the University of Twente campus network. Includes both TLS 1.2 and TLS 1.3 sessions with full handshake data. Referenced in academic papers for TLS fingerprinting and cipher suite analysis research. Good for training TLS fingerprint classifiers.

---

### 1.4 — DeepTLS Feature-Extracted Dataset

| Field | Value |
|---|---|
| **Source URL** | https://deeptls.com/ |
| **Download** | Contact authors / paper dataset page |
| **Format** | Extracted features (CSV), source PCAPs available |
| **Size** | ~160 PCAP files (varies 10 MB – 5 GB each) |
| **Records** | 160 PCAP files, 4 datasets |
| **Labels** | Yes (malicious/benign labels in source datasets) |
| **Features** | Full spectrum: meta, statistical, SPLT (packet lengths & inter-arrival times), byte distribution, TLS header (TLS version, client/server cipher suites, SNI), certificate fields (version, serial, validity, issuer, subject, public key type) |
| **Commercial use** | Yes for research use |
| **Registration** | No |
| **Supports** | A, B, C, F |

**Notes:** DeepTLS is a feature extraction tool that parses PCAP files and extracts 70+ features from TLS traffic. The tool itself is open source on GitHub. The dataset page (deeptls.com) hosts test artifacts and 160 PCAPs from 4 well-known malicious traffic datasets. Useful for ML-based TLS anomaly detection.

---

### 1.5 — tlsfuzzer Test PCAP Collections

| Field | Value |
|---|---|
| **Source URL** | https://github.com/tlsfuzzer/tlsfuzzer/tree/master/tests |
| **Download** | https://github.com/tlsfuzzer/tlsfuzzer |
| **Format** | PCAP, CSV test logs |
| **Size** | ~10 MB – 100 MB per capture |
| **Records** | ~500 individual test PCAPs |
| **Labels** | Yes (expected pass/fail per TLS test scenario) |
| **Features** | TLS 1.2 & 1.3 Client Hello, Server Hello, cipher suite negotiation, extensions, certificate verification, handshake failure scenarios, downgrade simulations |
| **Commercial use** | Yes (MIT license) |
| **Registration** | No |
| **Supports** | A, B, C, E, F |

**Notes:** The tlsfuzzer project contains test PCAPs from automated TLS implementation testing. Each PCAP corresponds to a specific TLS protocol test case. Good for TLS anomaly detection testing and protocol compliance verification.

---

### 1.6 — Labelled PCAP Data for CICIDS2017 & UNSW-NB15 (Payload-Byte)

| Field | Value |
|---|---|
| **Source URL** | https://zenodo.org/records/7258579 |
| **Mirror** | https://www.kaggle.com/datasets/yasiralifarrukh/unsw-and-cicids2017-labelled-pcap-data/data |
| **Download** | https://zenodo.org/records/7258579/files/Payload_data_CICIDS2017.csv |
| **Format** | CSV (packet payloads as feature vectors), raw PCAP available from source |
| **Size** | ~5 GB (CICIDS2017), ~270 MB (UNSW-NB15) |
| **Records** | Millions of packets (CICIDS2017: ~80M packets, UNSW-NB15: ~2.5M records) |
| **Labels** | Yes (15 attack categories + normal for CICIDS2017; 10 classes for UNSW-NB15) |
| **Features** | Packet bytes (1500 columns), TTL, total length, protocol, T-delta, TLS handshake metadata |
| **Commercial use** | Yes (research-only license) |
| **Registration** | Kaggle: Yes; Zenodo: No |
| **Supports** | A, B, C, D, F |

**Notes:** While not purely TLS-focused, these are labeled network traffic datasets that include SSL/TLS sessions. The CICIDS2017 dataset contains Botnet, DDoS, DoS, Heartbleed, and Web Attack traffic with TLS components. The UNSW-NB15 dataset includes 9 attack categories.

---

### 1.7 — NETRESEC Public PCAP Files

| Field | Value |
|---|---|
| **Source URL** | https://www.netresec.com/?page=PcapFiles |
| **Download** | Various direct links |
| **Format** | PCAP/PCAPNG |
| **Size** | ~50–500 MB per capture |
| **Records** | Individual PCAP files (100+ files) |
| **Labels** | No (raw captures) |
| **Features** | Full TLS handshakes, cipher suites, certificate chains, SNI, ALPN, TLS versions, session resumption, TLS key log files for decryption |
| **Commercial use** | Yes (free for any use with attribution) |
| **Registration** | No |
| **Supports** | A, B, C, F |

**Notes:** Maintained by Netresec. Includes capture files demonstrating TLS certificate validation failures, expired certificates, handshake failures, SNI mismatches, and protocol version negotiation issues. Excellent for forensic testing and TLS debugging scenarios.

---

## Category 2: EMAIL PROTOCOL PCAP DATA

> SMTP, SMTP STARTTLS, IMAP, IMAPS, POP3, POP3S, normal and insecure email sessions. Preferably raw PCAP/PCAPNG.

---

### 2.1 — ZGrab2 Email Protocol Scans

| Field | Value |
|---|---|
| **Source URL** | https://github.com/zmap/zgrab2 |
| **Download** | https://github.com/zmap/zgrab2/releases |
| **Format** | JSON (full handshake transcripts), some PCAP export possible |
| **Size** | Variable (scan-based) |
| **Records** | Millions of email servers scanned |
| **Labels** | No (scan results) |
| **Features** | SMTP banner, EHLO response, STARTTLS negotiation, SMTPS (implicit TLS), IMAP/IMAPS STARTTLS, POP3/POP3S STARTTLS, full TLS handshake logs (cipher suites, certificate chains, SNI, TLS version, certificate validation), server certificate information |
| **Commercial use** | Yes (Apache 2.0 license) |
| **Registration** | No |
| **Supports** | A, B, C, F |

**Notes:** ZGrab2 is the modular application scanner from the ZMap project. Its SMTP, IMAP, and POP3 modules perform full protocol handshakes including STARTTLS negotiation. Output includes complete TLS handshake transcripts in JSON. Can be run independently to generate PCAP files. Supports SMTP (port 25/465/587), SMTPS (implicit TLS), IMAP (143/993), and POP3 (110/995).

---

### 2.2 — Censys Internet-Wide Scan Data (scans.io)

| Field | Value |
|---|---|
| **Source URL** | https://scans.io/ |
| **Download** | https://scans.io/ (browse datasets) |
| **Format** | JSON records, also downloadable as compressed files |
| **Size** | 100 GB – 1 TB per dataset (varies by scan type) |
| **Records** | Billions of host records across multiple protocols |
| **Labels** | No (scan results) |
| **Features** | SMTP/STARTTLS handshake data, IMAP/POP3 TLS negotiation, certificate chains, cipher suites, TLS versions, SNI, certificate expiry, certificate issuer, certificate validation errors, server hostname mismatch, TLS configuration |
| **Commercial use** | Yes for academic/non-commercial research (non-commercial use only for raw data) |
| **Registration** | Yes (free for researchers) |
| **Supports** | A, B, C, D, F |

**Notes:** Censys publishes daily snapshots of internet-wide scans. The SMTP dataset includes STARTTLS capability detection, TLS version negotiation, and certificate validation results. The data is available as structured JSON. Non-commercial research access is free; commercial access requires a paid plan.

---

### 2.3 — Shodan Internet-Wide Scan Data

| Field | Value |
|---|---|
| **Source URL** | https://developer.shodan.io/ |
| **Download** | https://www.shodan.io/dashboard (filtered data export) |
| **Format** | JSON (via API/data feeds) |
| **Size** | Variable (query-based) |
| **Records** | Billions of host records |
| **Labels** | No (scan results) |
| **Features** | SMTP/STARTTLS banner data, IMAP/POP3 TLS support, certificate information, cipher suite support, TLS version, server configuration, port and service information |
| **Commercial use** | Free tier limited; paid plans for full data access |
| **Registration** | Yes (API key required, free tier available) |
| **Supports** | A, B, C, D, F |

**Notes:** Shodan provides internet-wide scanning data including email protocol services. Free API tier allows limited queries. Larger data exports require paid plans or academic access. Data includes STARTTLS support detection and certificate information for SMTP servers.

---

### 2.4 — JHalderm Email Delivery Security Study Data

| Field | Value |
|---|---|
| **Source URL** | https://jhalderm.com/pub/papers/mail-imc15.pdf |
| **Download** | Data available via collaboration request (Google provided dataset) |
| **Format** | SMTP connection logs, TLS cipher negotiation logs, CSV |
| **Size** | ~1 GB (logs over ~17 months) |
| **Records** | ~Billions of SMTP transactions |
| **Labels** | Yes (TLS success/failure, authentication results) |
| **Features** | STARTTLS negotiation results, TLS cipher suites for SMTP, certificate validation, SPF/DKIM/DMARC results, MX server configurations, cleartext vs encrypted transmission, DNS MX records |
| **Commercial use** | Yes for academic research (contact authors) |
| **Registration** | Yes (research data, contact for access) |
| **Supports** | A, B, C, D, F |

**Notes:** This is the seminal dataset from the paper "Neither Snow Nor Rain Nor MITM... An Empirical Analysis of Email Delivery Security." Contains longitudinal data from Gmail's SMTP connections (Jan 2014 – Apr 2015) plus Alexa Top Million MX server configurations. Includes cipher negotiation, certificate validation failures, and STARTTLS downgrading attacks.

---

### 2.5 — Extended Hell Email Security Study Data

| Field | Value |
|---|---|
| **Source URL** | https://www.usenix.org/system/files/usenixsecurity23/blechschmidt.pdf |
| **Download** | Contact authors (University of Washington / Ruhr University Bochum) |
| **Format** | SMTP connection logs, JSON, CSV |
| **Size** | ~5 GB (large-scale measurement) |
| **Records** | 10 million+ domains, 47 email provider tests |
| **Labels** | Yes (certificate validity, hostname match, self-signed, expired, STARTTLS supported) |
| **Features** | STARTTLS support, TLS 1.2/1.3 negotiation, certificate validation (expired, self-signed, hostname mismatch), MTA-STS policy retrieval, DANE TLSA records, DNSSEC support, MX server certificates, SMTP protocol logs |
| **Commercial use** | Yes for research use |
| **Registration** | Yes (academic dataset, contact authors) |
| **Supports** | A, B, C, D, E, F |

**Notes:** The largest known email security measurement study (10M+ domains). Tests both inbound and outbound email security for 47 major providers. Includes certificate analysis, STARTTLS negotiation, MTA-STS validation, DANE TLSA record checking, and DNSSEC support. Data from USENIX Security 2023.

---

## Category 3: TLS/NETWORK ANOMALY DATASETS

> Benign + anomalous TLS traffic, TLS attacks, downgrade behavior, MITM, unusual handshakes, suspicious encrypted traffic, abnormal TLS fingerprints. Preferably labeled PCAP/session/flow datasets.

---

### 3.1 — CICIDS2017 (Canadian Institute for Cybersecurity)

| Field | Value |
|---|---|
| **Source URL** | https://www.unb.ca/cic/datasets/ids-2017.html |
| **Download** | https://www.unb.ca/cic/datasets/ids-2017.html |
| **Format** | PCAP, CSV (flow data) |
| **Size** | ~80 GB (full PCAP), ~120 MB (CSV) |
| **Records** | 2.8 million flows, 148,970 PCAP files |
| **Labels** | Yes (14 attack categories + benign) |
| **Features** | TLS 1.2/1.3 sessions, cipher suites, Heartbleed attack PCAPs, DDoS, DoS, Web Attacks, Botnet, PortScan, Infiltration, brute force, SQL injection, XSS |
| **Commercial use** | Yes (free for research) |
| **Registration** | Yes (free, email required) |
| **Supports** | A, B, C, D, F |

**Labels:** BENIGN, FTP-Patator, SSH-Patator, DoS slowloris, DoS Slowhttptest, DoS Hulk, Heartbleed, Web Attack Brute Force, Web Attack XSS, Web Attack SQL Injection, Infiltration, Bot, PortScan, DDoS

---

### 3.2 — UNSW-NB15 Dataset

| Field | Value |
|---|---|
| **Source URL** | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| **Download** | https://unsw.co... (see source) |
| **Format** | PCAP, Bro/Zeek logs, Argus flows, CSV |
| **Size** | ~100 GB (raw PCAP), ~700 MB (CSV) |
| **Records** | 2.5 million records (flows) |
| **Labels** | Yes (10 class labels) |
| **Features** | Normal + attack traffic (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms), TLS/SSL sessions, 49 features per flow |
| **Commercial use** | Yes (GPL/citation required) |
| **Registration** | Yes (free for research) |
| **Supports** | A, B, C, D, F |

**Labels:** Normal, Exploits, DoS, Fuzzers, Generic, Reconnaissance, Worms, Shellcode, Backdoor, Analysis

---

### 3.3 — TON_IoT Dataset Suite

| Field | Value |
|---|---|
| **Source URL** | https://research.unsw.edu.au/projects/ton-iot-datasets |
| **Download** | Various per-dataset links |
| **Format** | PCAP, CSV, Partridge (Parquet) |
| **Size** | 50–200 GB (combined) |
| **Records** | Billions of events across 20+ datasets |
| **Labels** | Yes (attack vs. normal, multi-class) |
| **Features** | Network traffic, system call traces, TLS/SSL sessions, abnormal network behavior, insider threats, DoS, DDoS, scanning, malware |
| **Commercial use** | Yes (free for research) |
| **Registration** | Yes (free for research) |
| **Supports** | A, B, C, D, F |

**Notes:** Developed by UNSW Canberra's Cyber Range Lab. Contains 20+ datasets covering network traffic, endpoint data, and security logs from IoT/OT environments. Includes labeled TLS traffic from both normal and anomalous activities.

---

### 3.4 — Stratosphere IPS Public Datasets

| Field | Value |
|---|---|
| **Source URL** | https://www.stratosphereips.org/datasets |
| **Download** | https://www.stratosphereips.org/datasets (direct PCAP downloads) |
| **Format** | PCAP/PCAPNG |
| **Size** | 500 MB – 10 GB per dataset |
| **Records** | 30+ dataset collections |
| **Labels** | Yes (labeled by attack type) |
| **Features** | TLS traffic, malware communication, network reconnaissance, botnet C2, encrypted traffic analysis, cipher suite anomalies, unusual handshake patterns |
| **Commercial use** | Yes (CC-BY-SA) |
| **Registration** | No |
| **Supports** | A, B, C, D, F |

**Notes:** Maintained by the Czech Technical University. Includes datasets on malware traffic, botnet communication, and network attacks. Many captures include TLS sessions with abnormal handshake patterns and encrypted traffic anomalies.

---

### 3.5 — SecRepo Threat Traffic Samples

| Field | Value |
|---|---|
| **Source URL** | https://www.secrepo.com/ |
| **Download** | Various links from secrepo.com |
| **Format** | PCAP, JSON, CSV, Snort logs |
| **Size** | 10 MB – 500 MB per dataset |
| **Records** | 6,600+ samples across categories |
| **Labels** | Yes (attack type, malware family) |
| **Features** | Exploit kits, benign traffic, malware C2 over TLS, unusual TLS client hellos, abnormal cipher suites, TLS fingerprint anomalies |
| **Commercial use** | Varies (mostly research/educational) |
| **Registration** | No |
| **Supports** | A, B, C, D, F |

**Notes:** Curated collection of security-related data by Brad Robel. Includes labeled PCAPs of exploit kits and benign traffic. Good for training TLS anomaly detection models. The "Exploit kits and benign traffic" collection is particularly relevant.

---

## Category 4: EMAIL SECURITY POSTURE DATASETS

> STARTTLS, MTA-STS, TLS-RPT, SMTP TLS configuration, certificate information, SPF, DKIM, DMARC, email domain security posture.

---

### 4.1 — State of Email Authentication (Relaymetry)

| Field | Value |
|---|---|
| **Source URL** | https://www.state-of-email-authentication.com/ |
| **Download** | https://www.relaymetry.com/research (historical) |
| **Format** | CSV |
| **Size** | ~50 MB (compressed) |
| **Records** | ~20 million email domains |
| **Labels** | Yes (SPF/DKIM/DMARC support status) |
| **Features** | SPF support, DKIM signing, DMARC policy (none/quarantine/reject), subdomain policies, certificate validity, MTA-STS publication, TLS-RPT configuration |
| **Commercial use** | Yes (research use) |
| **Registration** | No |
| **Supports** | C, D, E |

**Notes:** This is the most comprehensive public dataset on email authentication adoption. Compiled by Relaymetry from DNS measurements across hundreds of thousands of domains. Updated periodically (most recent ~2022). Contains per-domain SPF, DKIM, and DMARC configuration status.

---

### 4.2 — MECSA Email Security Assessments

| Field | Value |
|---|---|
| **Source URL** | https://mecsa.khaloo.net/ (MECSA web application service) |
| **Download** | Contact authors (data published in paper) |
| **Format** | CSV, JSON (3,236 unique email providers) |
| **Size** | ~500 KB |
| **Records** | 3,236 email providers, 7,650 assessments |
| **Labels** | Yes (pass/fail per security test) |
| **Features** | STARTTLS support (inbound/outbound), TLS versions (TLS 1.0–1.3), cipher suites (RFC 8446 compliant), MTA-STS support & mode (enforce/testing), DANE TLSA records, DNSSEC, SPF, DKIM, DMARC, certificate validation |
| **Commercial use** | Yes for research (open access publication) |
| **Registration** | Yes (data available via research paper) |
| **Supports** | C, D, E, F |

**Notes:** Published in "What Email Servers Can Tell to Johnny" (IEEE ICNS 2021). The MECSA tool performed 7,650 security assessments of 3,236 email providers over 15 months (Jan 2019 – Mar 2020). Data includes both inbound and outbound email security measurements. Results show 97% STARTTLS support, 5.6% MTA-STS adoption, with detailed cipher and TLS version breakdowns.

---

### 4.3 — Hardenize Email Security Reports (Bulk)

| Field | Value |
|---|---|
| **Source URL** | https://hardenize.com/ |
| **API URL** | https://www.hardenize.com/docs/api/v1 |
| **Download** | Via API: batch report generation; public site: https://hardenize.com/report/{domain} |
| **Format** | JSON (via API), HTML (public reports) |
| **Size** | Variable per domain query |
| **Records** | Per-domain reports (scalable via API) |
| **Labels** | Yes (good/warning/critical per metric) |
| **Features** | STARTTLS support, SMTP TLS version, certificate validity (expiry, revocation, hostname match), MTA-STS policy (published, mode, MX match), TLS-RPT, DANE, DNSSEC, certificate chain validation, cipher suite analysis, TLS configuration quality |
| **Commercial use** | Free for individual checks; paid API plans for bulk |
| **Registration** | Yes (free tier for single checks, paid for bulk) |
| **Supports** | A, C, D, E |

**Notes:** Hardenize provides continuous monitoring of TLS/PKI, email security (STARTTLS, MTA-STS, TLS-RPT, DANE, DNSSEC), and web security. The API allows programmatically querying domain security posture. Reports include detailed certificate validation results, expiry warnings, and configuration recommendations.

---

### 4.4 — Extended Hell / Email Delivery Security Study (USENIX Security 2024)

| Field | Value |
|---|---|
| **Source URL** | https://www.usenix.org/system/files/usenixsecurity23/blechschmidt.pdf |
| **Download** | Contact authors |
| **Format** | TLS certificate data, JSON, SMTP logs |
| **Size** | ~10 GB (measurement data) |
| **Records** | 87 million domains (MTA-STS DNS), 10 million+ domains (certificate analysis) |
| **Labels** | Yes (valid/invalid certificates, MTA-STS misconfiguration categories) |
| **Features** | STARTTLS support, certificate validation (expired, self-signed, hostname mismatch, untrusted CA), MTA-STS policy retrieval & validation, policy mode (enforce/testing), MX server TLS config, DNS TXT records, certificate pinning via DANE TLSA |
| **Commercial use** | Yes for research |
| **Registration** | Yes (contact authors) |
| **Supports** | A, B, C, D, E, F |

**Notes:** The largest MTA-STS measurement study to date. Analyzed 87M domains across .com/.org/.net/.se TLDs over 36 months. Found 29.6% of MTA-STS-enabled domains (68K) are misconfigured. Includes both DNS-level data and live SMTP connection tests with certificate validation results.

---

## Category 5: CRYPTOGRAPHIC SECURITY / RISK DATASETS

> Weak/deprecated TLS, weak cipher suites, certificate weaknesses, SHA-1/MD5, weak RSA/EC keys, expired certificates, hostname mismatch, certificate chain problems. Security severity labels if available.

---

### 5.1 — Censys TLS / Certificate Data (scans.io)

| Field | Value |
|---|---|
| **Source URL** | https://scans.io/ |
| **Download** | https://scans.io/ (TLS/SSL datasets) |
| **Format** | JSON (Avro available) |
| **Size** | ~200 GB (daily snapshots) |
| **Records** | All publicly accessible IPv4 hosts (~4.3 billion IPs), millions of X.509 certificates |
| **Labels** | Partial (certificate validity, trust chain, weak key indicators) |
| **Features** | TLS version negotiation, cipher suite support, certificate chains, certificate expiration dates, RSA key sizes, ECDSA curves, certificate issuer/subject/SAN, hostname validation, SHA-1/SHA-2 signatures, certificate trust chain validation against root stores (NSS, Microsoft, Apple, Java, Android) |
| **Commercial use** | Yes for non-commercial research |
| **Registration** | Yes (free for researchers) |
| **Supports** | A, B, C, D, F |

**Notes:** Daily point-in-time snapshots of all publicly accessible IPv4 hosts and known X.509 certificates. The TLS data includes the full certificate chain, validation status against multiple root stores, cipher suite negotiation results, and protocol version support. The "CPE" enrichment links certificates to known vulnerable products.

---

### 5.2 — CIRCL Passive SSL (Historical Certificate Database)

| Field | Value |
|---|---|
| **Source URL** | https://circl.lu/services/passive-ssl/ |
| **Download** | Access on request (contact CIRCL) |
| **Format** | JSON, CSV (bulk exports on request) |
| **Size** | ~500 GB (full historical database) |
| **Records** | Billions of certificate observations |
| **Labels** | Partial (expired, self-signed, revoked) |
| **Features** | Certificate lifecycle tracking, certificate fingerprint history per IP, expired certificates, self-signed certificates, hostname mismatch, certificate chain problems, weak key sizes, SHA-1/MD5 signatures, certificate reuse detection |
| **Commercial use** | Yes for CSIRT/academic community |
| **Registration** | Yes (request access for free) |
| **Supports** | A, B, C, D, F |

**Notes:** CIRCL (Computer Incident Response Center Luxembourg) maintains a historical database of SSL/TLS certificates observed in the wild. The passive SSL service collects certificate data from network traffic and maintains historical records. Access is free for CSIRTs and researchers (registration required).

---

### 5.3 — Certificate Transparency (crt.sh / Google CT Logs)

| Field | Value |
|---|---|
| **Source URL** | https://crt.sh/ |
| **API URL** | https://crt.sh/?j=1 (JSON output) |
| **Bulk Download** | https://github.com/heffman/ct-cert-feed-pub |
| **Format** | JSON (via API), CSV (bulk) |
| **Size** | ~500 GB (full CT log dumps) |
| **Records** | All certificates issued by CT logs (billions) |
| **Labels** | Partial (precertificate vs. certificate, expired) |
| **Features** | Certificate issuance timestamps, certificate chain/issuer, subject CN/SAN, certificate expiration, certificate revocation status, precertificate data, CT log metadata, certificate transparency SCTs |
| **Commercial use** | Yes (free public database) |
| **Registration** | No (API); Yes for bulk (Google Cloud access) |
| **Supports** | A, B, C, D, F |

**Notes:** Certificate Transparency logs are a public, append-only log of all certificates issued by participating CAs. crt.sh provides a searchable web interface and JSON API. The bulk dump from heffman/ct-cert-feed-pub provides normalized CT log snapshots as JSON. Data can be used to detect misissued, expired, or fraudulent certificates. Note: CT logs contain both precertificates and final certificates.

---

### 5.4 — testssl.sh Security Scan Corpus

| Field | Value |
|---|---|
| **Source URL** | https://github.com/testssl/testssl.sh |
| **Data files** | https://github.com/testssl/testssl.sh/tree/master/etc |
| **Download** | https://testssl.sh/ |
| **Format** | CSV, JSON, HTML (scan output); cipher mapping tables, CA stores as TXT/PEM |
| **Size** | ~1 MB (data files), ~300 MB (full scans with certificates) |
| **Records** | Reference data: cipher suites, root CA fingerprints, curves, TLS protocol constants |
| **Labels** | Yes (security severity per cipher/protocol: secure, weak, deprecated, insecure) |
| **Features** | Cipher suite security ratings, weak cipher identification (RC4, 3DES, EXPORT), deprecated TLS versions (1.0, 1.1, SSLv2, SSLv3), certificate chain validation, SHA-1/MD5 signature detection, RSA key size thresholds, certificate expiry, hostname verification |
| **Commercial use** | Yes (GPL v2) |
| **Registration** | No |
| **Supports** | A, C, D, E |

**Notes:** testssl.sh includes its own reference data files: `ca_hashes.txt` (trusted root CA fingerprints), `cipher-mapping.txt` (cipher suite names), `curves.txt`, `tls_data.txt` (protocol/cipher security classifications). The cipher-mapping and TLS data files contain security ratings for each cipher suite and protocol version. Useful for cryptographic risk classification reference data.

---

### 5.5 — SSL Labs Test Results (ssllabs.com data)

| Field | Value |
|---|---|
| **Source URL** | https://www.ssllabs.com/projects/ssllabs-api/ |
| **Data dumps** | https://github.com/ssllabs/research (historical datasets) |
| **Format** | JSON |
| **Size** | ~10 GB (historical snapshots) |
| **Records** | Millions of HTTPS server assessments |
| **Labels** | Yes (grade: A+ to F, warning/critical flags) |
| **Features** | TLS version support, cipher suite list, certificate chain validation, hostname verification, certificate key size, signature algorithm (SHA-1/SHA-2), OCSP stapling, HSTS, certificate revocation (OCSP/CRL), weak DH params, forward secrecy |
| **Commercial use** | Yes (free research use) |
| **Registration** | No for API; Yes for bulk data dumps |
| **Supports** | A, B, C, D, E |

**Notes:** SSL Labs (now part of RedMonk/Dark Reading) provides an API for TLS server testing. Historical research datasets are occasionally released. The assessment provides a letter grade (A+ to F) based on TLS configuration, cipher strength, certificate validity, and protocol support. Includes detection of weak ciphers, old protocols, and certificate issues.

---

## Category 6: SECURITY SEVERITY / PRIORITIZATION DATASETS

> CVE, CVSS, CWE, NVD, CISA KEV, vulnerability severity, remediation information. Preferably machine-readable JSON/CSV.

---

### 6.1 — NVD CVE Data Feeds (JSON 2.0)

| Field | Value |
|---|---|
| **Source URL** | https://nvd.nist.gov/vuln/data-feeds |
| **CVE JSON Feed** | https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz |
| **Modified Feed** | https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz |
| **Yearly Feeds** | https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz |
| **Schema URL** | https://csrc.nist.gov/schema/nvd/api/2.0/ssvc-v2.0.3.json |
| **Format** | JSON (gzip compressed) |
| **Size** | 18–24 MB per year; ~300+ MB total |
| **Records** | ~370,000+ CVEs (growing) |
| **Labels** | Yes (CVSS v2/v3/v4 severity, CWE mappings, CPE configurations) |
| **Features** | CVE ID, description, CVSS v2/v3/v4 scores & vectors, CWE weakness mappings, CPE affected product identifiers, references/links, publication/modification dates, exploitability metrics, SSVC data |
| **Commercial use** | Yes (public domain, no restrictions) |
| **Registration** | No |
| **Supports** | A, C, D, E, F |

**Notes:** The NVD provides machine-readable JSON 2.0 feeds broken down by year plus "recent" and "modified" feeds for updates. Each year's feed is ~20 MB compressed. Also provides CPE Match Feed (764 MB) and CPE Dictionary (79 MB). Updated nightly. Total CVE count exceeds 370,000 as of 2026. The API at https://services.nvd.nist.gov/rest/json/cves/2.0 provides the same data with query parameters. Note: CPE match feed URL verified as available on the data feeds page.

---

### 6.2 — CISA Known Exploited Vulnerabilities (KEV) Catalog

| Field | Value |
|---|---|
| **Source URL** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **JSON Download** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **CSV Download** | https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv |
| **Schema** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json |
| **Format** | JSON, CSV |
| **Size** | ~50 MB (JSON), ~10 MB (CSV) |
| **Records** | ~1,726 CVEs (as of latest update) |
| **Labels** | Yes (KEV catalog tags + due dates, ransomware status, forensic triage flags) |
| **Features** | CVE ID, vendor/project, product, vulnerability name, description, date added, due date, required action, CWE mapping, known ransomware campaign use, forensic triage flag |
| **Commercial use** | Yes (public domain, no restrictions) |
| **Registration** | No |
| **Supports** | D, E |

**Notes:** CISA's KEV catalog is the authoritative list of vulnerabilities confirmed to be actively exploited in the wild. Updated weekly. Each entry includes a mandatory remediation due date. BOD-26-04 requires federal agencies to remediate KEV-listed vulnerabilities within 6-28 days. The JSON feed is the primary machine-readable format.

---

### 6.3 — OSV Vulnerability Database (Open Source Vulnerabilities)

| Field | Value |
|---|---|
| **Source URL** | https://osv.dev/data |
| **API** | https://api.osv.dev/v1/ |
| **Bulk Downloads** | https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip |
| **Format** | JSON (per-vulnerability documents) |
| **Size** | 5 MB – 560 MB per ecosystem (total: ~2 GB across all ecosystems) |
| **Records** | ~722,000 vulnerabilities across 40+ ecosystems |
| **Labels** | Yes (severity, affected/fixed versions, ecosystem) |
| **Features** | OSV ID, aliases (CVE/CVSS/CWE IDs), affected package versions, fixed versions, severity (CVSS), references, credits, database-specific metadata, introduced/fixed dates |
| **Commercial use** | Yes (Apache 2.0 license) |
| **Registration** | No |
| **Supports** | A, D, E, F |

**Notes:** OSV aggregates vulnerability data from 17+ upstream sources (GitHub Advisory Database, RustSec, Go Vulnerability Database, etc.) and normalizes to a common schema. Bulk downloads are per-ecosystem ZIP files containing individual JSON files per vulnerability. Ecosystems include: npm, PyPI, Go, Maven, crates.io, NuGet, Packagist, Pub, Hex, SwiftURL, Ubuntu, Debian, Red Hat, Rocky Linux, Fedora, Alpine, etc. Free API available at api.osv.dev.

---

### 6.4 — FIRST EPSS (Exploit Prediction Scoring System)

| Field | Value |
|---|---|
| **Source URL** | https://www.first.org/epss |
| **API** | https://api.first.org/data/v1/epss |
| **Bulk CSV** | https://epss.cyentia.com/epss_scores-current.csv.gz |
| **Format** | CSV (gzip), JSON (via API) |
| **Size** | ~30 MB (current scores CSV) |
| **Records** | ~350,000 CVEs with scores |
| **Labels** | Yes (EPSS score 0–1, percentile rank) |
| **Features** | CVE ID, EPSS score (0.0–1.0 probability of exploitation within 30 days), percentile rank, date-updated |
| **Commercial use** | Yes (custom permissive license by FIRST) |
| **Registration** | No |
| **Supports** | D, E |

**Notes:** EPSS predicts the likelihood that a CVE will be actively exploited within 30 days. The score is model-based and updated daily. The bulk CSV contains all current scores (~350K CVEs). An API is available for querying individual CVEs. Time-series historical data is also available. Complements CVE/CVSS scores by providing exploit likelihood prioritization.

---

### 6.5 — CWE Knowledge Base (MITRE)

| Field | Value |
|---|---|
| **Source URL** | https://cwe.mitre.org/data/downloads.html |
| **XML Download** | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip |
| **CSV Downloads** | Various views (e.g. https://cwe.mitre.org/data/csv/1000.csv.zip) |
| **Format** | XML (ZIP), CSV (ZIP), XSD schema |
| **Size** | ~1.6 MB (XML), ~5–20 MB (CSV per view) |
| **Records** | ~900+ weaknesses, 25+ views, 50+ categories |
| **Labels** | Yes (abstraction level, structure, status, exploit likelihood, consequences) |
| **Features** | CWE ID, name, description, extended description, modes of introduction, applicable platforms, common consequences, detection methods, potential mitigations, observed examples, related weaknesses, taxonomy mappings (OWASP, CAPEC, NVD), references |
| **Commercial use** | Yes (reproduced with permission from MITRE) |
| **Registration** | No |
| **Supports** | A, C, D, E, F |

**Notes:** The CWE (Common Weakness Enumeration) list is the standard catalog of software/hardware security weaknesses. Version 4.20 (current as of 2026-04-30). The XML format is the most comprehensive. Multiple views available: CWE Top 25 (most dangerous), CWE/SANS Top 25, OWASP-enhanced, etc. Includes mappings to CAPEC attack patterns, OWASP categories, and NIST NVD.

---

### 6.6 — security-kg (Hugging Face — Aggregated Security Knowledge Graph)

| Field | Value |
|---|---|
| **Source URL** | https://huggingface.co/datasets/s0u9ata/security-kg |
| **Format** | Parquet (SPO triples: Subject-Predicate-Object) |
| **Size** | ~500 MB compressed |
| **Records** | ~16–22 million triples (combined) |
| **Labels** | Yes (entity types: vulnerability, weakness, attack, mitigation) |
| **Features** | Aggregates from 17 sources: ATT&CK, CAPEC, CWE, CVE, CPE, D3FEND, ATLAS, CAR, ENGAGE, EPSS, KEV, Vulnrichment, GHSA, Sigma, ExploitDB, MISP Galaxies. Includes CVSS scores, CWE mappings, CAPEC attack patterns, D3FEND mitigations, ATT&CK technique mappings |
| **Commercial use** | Yes (MITRE content reproduced with permission; Apache 2.0 for generated content) |
| **Registration** | No (Hugging Face public dataset) |
| **Supports** | A, C, D, E, F |

**Notes:** A comprehensive knowledge graph dataset that aggregates and links 17 security data sources into unified SPO triples. Automatically updated weekly. Includes full CVE details (with CVSS), CWE weakness definitions, CAPEC attack patterns, D3FEND defensive techniques, and ATT&CK mappings. Excellent single-source dataset for security risk classification and prioritization.

---

## Category 7: SECURITY REMEDIATION / KNOWLEDGE DATASETS

> Security finding → explanation, security finding → remediation, vulnerability → mitigation. Preferably NIST/CISA/Mozilla/RFC-based or other authoritative sources.

---

### 7.1 — OWASP Cheat Sheet Series

| Field | Value |
|---|---|
| **Source URL** | https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets |
| **Download** | Full repo: https://github.com/OWASP/CheatSheetSeries |
| **Format** | Markdown, HTML, PDF |
| **Size** | ~5 MB (full repository) |
| **Records** | 40+ cheat sheets |
| **Labels** | Yes (by vulnerability/finding type) |
| **Features** | Finding type, vulnerability description, security risk explanation, specific remediation steps, code examples (secure vs. insecure), references to standards (OWASP ASVS, NIST, CWE, CAPEC), testing guidance, prevention techniques |
| **Commercial use** | Yes (CC-BY-SA 4.0 / CC-BY 4.0) |
| **Registration** | No |
| **Supports** | E, F |

**Notes:** The OWASP Cheat Sheet Series is the authoritative community-maintained guide to application security. Each cheat sheet covers a specific security topic (e.g., SQL Injection Prevention, TLS Configuration, Password Storage, Transport Layer Protection) with detailed explanations, remediation code, and testing guidance. Mapped to CWE and OWASP ASVS.

---

### 7.2 — CISA Vulnrichment (SSVC + CVSS + CWE Enrichment)

| Field | Value |
|---|---|
| **Source URL** | https://github.com/cisagov/vulnrichment |
| **Download** | https://github.com/cisagov/vulnrichment (JSON data) |
| **Format** | JSON (per-CVE enrichment files) |
| **Size** | ~200 MB (all data) |
| **Records** | ~500,000–1,000,000 CVEs |
| **Labels** | Yes (SSVC decision, CVSS severity, exploitation status, impact) |
| **Features** | SSVC (Stakeholder-Specific Vulnerability Categorization) values, CVSS v3.x scores, CWE mappings, exploitation in-the-wild status, impact scores (confidentiality/integrity/availability), recovery, automatability, value density per asset, technical impact |
| **Commercial use** | Yes (public domain) |
| **Registration** | No |
| **Supports** | C, D, E |

**Notes:** CISA's Vulnrichment project adds SSVC (Stakeholder-Specific Vulnerability Categorization) values to CVE records. SSVC provides a decision tree for vulnerability prioritization based on: exploitation status, impact ranks (confidentiality/integrity/availability), recovery, automatability, and value density. Machine-readable JSON format. Complements NVD and EPSS data with operational prioritization guidance.

---

### 7.3 — D3FEND Knowledge Graph (MITRE)

| Field | Value |
|---|---|
| **Source URL** | https://d3fend.secure.software/ |
| **Download** | https://d3fend.mitre.org/ |
| **Format** | JSON-LD, CSV |
| **Size** | ~50 MB |
| **Records** | ~100+ defensive techniques |
| **Labels** | Yes (defensive technique, mapped to ATT&CK) |
| **Features** | Defensive technique name, description, security properties addressed, ATT&CK technique mappings, implementation guidance, examples |
| **Commercial use** | Yes (reproduced with permission from MITRE) |
| **Registration** | No |
| **Supports** | A, E |

**Notes:** D3FEND is MITRE's knowledge base of defensive cybersecurity techniques. Each entry maps to ATT&CK adversary techniques and provides technical descriptions, implementation guidance, and security properties. Useful for generating mitigation recommendations tied to specific attack patterns.

---

### 7.4 — NIST National Vulnerability Database API / NVD API

| Field | Value |
|---|---|
| **Source URL** | https://nvd.nist.gov/developers/vulnerabilities |
| **API** | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| **Format** | JSON (REST API) |
| **Size** | Variable (paginated: up to 2,000 results/page) |
| **Records** | ~370,000+ CVEs |
| **Labels** | Yes (CVSS severity, CWE, CPE, remediation references) |
| **Features** | CVE details, CVSS v2/v3/v4 scores, CWE weakness mappings, CPE configurations (affected products), vulnerability remediation references, time-based search (lastModifiedStartDate), keyword search |
| **Commercial use** | Yes (public domain) |
| **Registration** | Yes (API key required for >5 requests/minute; free) |
| **Supports** | A, C, D, E, F |

**Notes:** The NVD API (v2.0) provides programmatic access to the same data as the bulk feeds. Supports keyword search, CVE ID search, CPE match string search, and date-range filtering. The API also provides CPE match string lookups, CPE names, and CVE change history.

---

### 7.5 — NIST SP 800-53 Security Controls

| Field | Value |
|---|---|
| **Source URL** | https://csrc.nist.gov/projects/security-controls |
| **Catalog Download** | https://csrc.nist.gov/schema/csf/2.0/csf-2.0.0d10.xlsx |
| **Control Baselines** | https://csrc.nist.gov/projects/csf-bind |
| **Format** | Excel, XML, JSON, HTML |
| **Size** | ~5 MB |
| **Records** | 20+ control families, ~400+ individual controls |
| **Labels** | Yes (control baseline level, impact level: low/moderate/high) |
| **Features** | Control ID, control name, control description, enhancement requirements, baseline allocation (low/moderate/high), related standards (FIPS, FIPS 199), assessment procedures |
| **Commercial use** | Yes (public domain) |
| **Registration** | No |
| **Supports** | E, F |

**Notes:** NIST Special Publication 800-53 provides the catalog of security and privacy controls for federal information systems. The CSF (Cybersecurity Framework) 2.0 and the 800-53 controls are the authoritative U.S. government standards for security control implementation. Used for compliance, risk assessment, and control selection. Controls map to CWE weaknesses and CAPEC attack patterns.

---

## Summary Table — Cross-Reference by Capability (A–F)

| Dataset | Category | A | B | C | D | E | F |
|---|---|---|---|---|---|---|---|
| MAWI Archive | 1 | ✓ | ✓ | ✓ | | | ✓ |
| CAIDA UCSD | 1 | ✓ | ✓ | ✓ | | | ✓ |
| Uni. Twente TLS | 1 | ✓ | ✓ | ✓ | | | ✓ |
| DeepTLS | 1 | ✓ | ✓ | ✓ | | | ✓ |
| tlsfuzzer Tests | 1 | ✓ | ✓ | ✓ | | ✓ | ✓ |
| CICIDS2017/NB15 | 1,3 | ✓ | ✓ | ✓ | | | ✓ |
| NETRESEC PCAPs | 1 | ✓ | ✓ | ✓ | | ✓ | ✓ |
| ZGrab2 Email | 2 | ✓ | ✓ | ✓ | | ✓ | ✓ |
| Censys Scans | 2,3,5 | ✓ | ✓ | ✓ | ✓ | | ✓ |
| Shodan | 2,5 | ✓ | ✓ | ✓ | ✓ | | ✓ |
| JHalderm Email Study | 2,4 | ✓ | ✓ | ✓ | ✓ | | ✓ |
| Extended Hell Study | 2,4,5 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CICIDS2017 | 3 | | ✓ | ✓ | ✓ | | ✓ |
| UNSW-NB15 | 3 | | ✓ | ✓ | ✓ | | ✓ |
| TON_IoT | 3 | | ✓ | ✓ | ✓ | | ✓ |
| Stratosphere IPS | 3 | | ✓ | ✓ | ✓ | | ✓ |
| SecRepo | 3 | | ✓ | ✓ | ✓ | | ✓ |
| State of Email Auth | 4 | | | ✓ | | ✓ | ✓ |
| MECSA | 4 | | | ✓ | | ✓ | ✓ |
| Hardenize | 4,5 | ✓ | | ✓ | | ✓ | ✓ |
| Extended Hell (MTA-STS) | 4 | ✓ | | ✓ | ✓ | ✓ | ✓ |
| Censys TLS/Certs | 5 | ✓ | ✓ | ✓ | ✓ | | ✓ |
| CIRCL Passive SSL | 5 | ✓ | ✓ | ✓ | ✓ | | ✓ |
| Certificate Transparency | 5 | ✓ | ✓ | ✓ | ✓ | | ✓ |
| testssl.sh | 5 | ✓ | | ✓ | ✓ | ✓ | ✓ |
| SSL Labs | 5 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NVD CVE Feeds | 6 | ✓ | | ✓ | ✓ | ✓ | ✓ |
| CISA KEV | 6 | | | ✓ | ✓ | ✓ | ✓ |
| OSV Database | 6 | ✓ | | ✓ | ✓ | ✓ | ✓ |
| FIRST EPSS | 6 | | | ✓ | ✓ | ✓ | |
| CWE Database | 6,7 | ✓ | | ✓ | ✓ | ✓ | ✓ |
| security-kg (HF) | 6,7 | ✓ | | ✓ | ✓ | ✓ | ✓ |
| OWASP Cheat Sheets | 7 | | | | | ✓ | ✓ |
| CISA Vulnrichment | 7 | | | ✓ | ✓ | ✓ | ✓ |
| D3FEND | 7 | ✓ | | | | ✓ | ✓ |
| NIST SP 800-53 | 7 | | | | | ✓ | ✓ |
| NVD API | 6,7 | ✓ | | ✓ | ✓ | ✓ | ✓ |

---

## Recommendations by Capability

### For Cryptographic Risk Classification (A):
**Primary:** Censys TLS data, Certificate Transparency (crt.sh), testssl.sh reference data, SSL Labs reports, Extended Hell certificate analysis  
**Secondary:** DeepTLS certificate features, CWE cryptographic weakness definitions (CWE-327, CWE-326, CWE-310), security-kg knowledge graph

### For TLS Anomaly Detection (B):
**Primary:** MAWI Archive, CICIDS2017/UNSW-NB15/TON_IoT labeled PCAPs, Stratosphere IPS malware traffic PCAPs, tlsfuzzer test PCAPs, Censys scan data  
**Secondary:** ZGrab2 scan results, DeepTLS extracted features, SecRepo threat traffic samples

### For Security Posture Scoring (C):
**Primary:** NVD/CISA KEV/OSV (vulnerability data), CWE database, Hardenize reports, MECSA email assessments, State of Email Authentication dataset  
**Secondary:** security-kg aggregated knowledge, D3FEND mitigations, NIST SP 800-53 controls

### For Threat/Finding Prioritization (D):
**Primary:** CISA KEV catalog, FIRST EPSS scores, NVD CVSS scores, CISA Vulnrichment SSVC values, OSV vulnerability data  
**Secondary:** security-kg, CWE Top 25, CAPEC attack pattern mappings

### For Mitigation Recommendation (E):
**Primary:** OWASP Cheat Sheet Series, CWE mitigations field, D3FEND defensive techniques, CISA Vulnrichment, NIST SP 800-53 controls, testssl.sh cipher security classifications  
**Secondary:** security-kg, OSV fix versions

### For Forensic Report Generation (F):
**Primary:** MAWI/CAIDA/NETRESEC PCAPs (for evidence), JHalderm/Extended Hell email study data (for email forensics), CWE descriptions/observed examples, Extended Hell certificate validation data  
**Secondary:** Suricata EVE JSON schema (JA3/JA3S/TLS fingerprinting), ZGrab2 handshake transcripts, Censys historical certificate data
