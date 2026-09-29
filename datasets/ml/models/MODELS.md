# ML Models — SecureMailScope

All models are loaded by `analysis/ml_runtime.py` via the integrity-checked registry in
`analysis/ml_artifacts.py`. Each `.joblib` artifact has a corresponding `.json` metadata
file that stores the `artifact_sha256` digest and schema tag; loading fails if the digest
does not match.

---

## Demo-ready models (active in ml_runtime.py)

### zgrab_evidence_risk_classifier_v1
**Role:** Primary SMTP risk classifier for ZGrab-sourced sessions.  
**Input:** Canonical protocol, TLS version, cipher, certificate, and STARTTLS features
extracted from ZGrab evidence objects.  
**Output:** `predicted_risk_tier` (LOW / MEDIUM / HIGH) + uncalibrated confidence score.  
**Notes:** Trained against the ZGrab SMTP rubric (F1 0.944 on held-out rubric labels).
Labels are rubric-derived, not independent security ground truth.  
**Files:** `zgrab_evidence_risk_classifier_v1.joblib`, `zgrab_evidence_risk_classifier_v1.json`

---

### synthetic_email_posture_classifier_v2
**Role:** Risk classifier for IMAP/POP3 sessions (synthetic-data pathway).  
**Input:** Protocol, TLS posture, and certificate features from simulated IMAP/POP3 sessions.  
**Output:** `predicted_risk_tier` + confidence score.  
**Notes:** F1 0.511 on grouped simulated data — runs and routes correctly but real-network
effectiveness is unvalidated. Supersedes `synthetic_email_risk_classifier_v1`.  
**Files:** `synthetic_email_posture_classifier_v2.joblib`, `synthetic_email_posture_classifier_v2.json`

---

### zgrab_runtime_rule_flag_proxy_v2
**Role:** Secondary proxy that re-scores rule-engine flag patterns using ML features.  
**Input:** Structured observation dict and optional certificate row from a ZGrab SMTP session.  
**Output:** Proxy risk flags alongside rule-engine output (advisory only).  
**Notes:** Supersedes `zgrab_rule_flag_proxy_v1`. Used in the main `run_ml_analysis` call path.  
**Files:** `zgrab_runtime_rule_flag_proxy_v2.joblib`, `zgrab_runtime_rule_flag_proxy_v2.json`

---

### zgrab_runtime_risk_tier_v1
**Role:** Assigns a risk tier directly from raw SMTP TLS observation features.  
**Input:** Structured SMTP TLS observation dict and optional certificate row.  
**Output:** `predicted_risk_tier`.  
**Notes:** NOT_APPLICABLE when session is not SMTP TLS; used alongside the proxy classifier.  
**Files:** `zgrab_runtime_risk_tier_v1.joblib`, `zgrab_runtime_risk_tier_v1.json`

---

### zgrab_smtp_negotiation_anomaly_v1
**Role:** Detects novelty / anomaly in SMTP TLS negotiation configuration.  
**Input:** SMTP negotiation feature vector (cipher selection, version, extension patterns).  
**Output:** Novelty score + anomaly flag. Runs when required features are observable.  
**Notes:** Controlled mock tests produce metrics against injected feature changes, not real
attacks. Latest audit: `zgrab_smtp_negotiation_anomaly_v1_synthetic_audit_v4.json`.  
**Files:** `zgrab_smtp_negotiation_anomaly_v1.joblib`, `zgrab_smtp_negotiation_anomaly_v1.json`

---

### mta_sts_cert_anomaly_v1
**Role:** Detects certificate anomalies in the MTA-STS certificate corpus.  
**Input:** Certificate features extracted by `datasets/ml/extract_mta_sts_certificate_features.py`.  
**Output:** Novelty/anomaly score relative to the MTA-STS baseline distribution.  
**Notes:** Runs when MTA-STS certificate data is available for the session.  
**Files:** `mta_sts_cert_anomaly_v1.joblib`, `mta_sts_cert_anomaly_v1.json`

---

## Supporting artifacts (not ML models)

| File | Purpose |
|------|---------|
| `controlled_novelty_benchmark_v1.json` | Benchmark results from `evaluate_controlled_novelty.py` — verifies anomaly model responses to injected feature perturbations. |
| `synthetic_email_ml_audit_v1.json` | Audit of the v2 posture classifier over the synthetic email research cohort. |
| `synthetic_pcap_runtime_coverage_v5.json` | Coverage report: which PCAP scenarios exercise each ML model path. Latest version only. |
| `synthetic_email_posture_classifier_v2_test_predictions.csv` | Hold-out test predictions for the v2 posture classifier. |
| `zgrab_evidence_risk_classifier_v1_test_predictions.csv` | Hold-out test predictions for the ZGrab evidence classifier. |
| `zgrab_runtime_risk_tier_v1_test_predictions.csv` | Hold-out test predictions for the runtime risk tier classifier. |
| `zgrab_runtime_rule_flag_proxy_v2_oof.csv` | Out-of-fold predictions from cross-validation for the v2 proxy classifier. |

---

## Archived / superseded models

Moved to `archive/`. Not loaded by the current runtime.

| Model | Reason archived |
|-------|----------------|
| `zgrab_rule_flag_proxy_v1` | Superseded by `zgrab_runtime_rule_flag_proxy_v2`. |
| `zgrab_smtp_anomaly_v1` | Superseded by `zgrab_smtp_negotiation_anomaly_v1`; not called by ml_runtime.py. |
| `https_tls_anomaly_v1` | HTTPS TLS anomaly detector — explicitly not used as an email security classifier. |
| `synthetic_email_risk_classifier_v1` | Superseded by `synthetic_email_posture_classifier_v2` (better feature contract, higher F1). |

Audit JSONs for `zgrab_smtp_anomaly_v1` are also in `archive/`.

---

## Key limitations (demo honesty)

- **SMTP classifier F1 0.944** is measured against a ZGrab rubric, not independent real-world ground truth.
- **IMAP/POP3 classifier F1 0.511** — runs and routes correctly; performance is weak and unvalidated on real traffic.
- **Anomaly models** measure response to injected perturbations, not real attack traffic or operational false-positive rates.
- All ML outputs are **advisory**. They do not override the Rule Engine findings.
