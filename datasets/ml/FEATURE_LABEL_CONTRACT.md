# SecureMailScope ML Feature and Label Contract

Version: `1.2`  
Status: implemented ML contract and limitations. The sections below that describe earlier prototypes are historical where they conflict with the current implementation summary at the end of this document.

## Design Rules

- The parser produces observed session facts. The rule engine evaluates policy. ML consumes observed facts in parallel and never changes a rule verdict.
- Every row keeps `data_source`, schema version, and provenance outside the model feature vector.
- Empty means unknown or unobserved, not zero or secure. Keep the prepared SMTP, STARTTLS, TLS, and certificate state columns.
- Do not combine SMTP, synthetic email, and HTTPS populations into one baseline or one headline metric.
- No model output is a CVE finding. CVE/KEV/EPSS enrichment is a separate evidence-backed operation.

## Tasks and Targets

### 1. Risk-Tier Classifier (Prototype)

**Question answered:** from observed TLS and certificate fields, can a model estimate whether the current deterministic checks would raise at least one crypto finding?

**First prototype target:** `rule_flag_proxy_v1`, one of `HAS_RULE_FLAGGED_ISSUE` or `NO_CURRENT_RULE_FLAG`. This binary target is deliberately narrower than the product's eventual risk tiers.

The original `zgrab_rule_flag_proxy_v1` uses a broad 52-field schema and is retained for reproducibility only. Runtime selects `zgrab_runtime_rule_flag_proxy_v2`, trained on 33 fields explicitly mapped to parser-observable evidence. It keeps the same proxy target, reports country-held-out proxy agreement, and abstains when input coverage is below the training cohort's 5th-percentile coverage (currently 84.8%). The resulting score is uncalibrated and is not independent risk evidence. The narrower runtime schema's lower cross-validated score is preferred over scoring with a feature schema substantially unavailable to passive PCAP analysis.

The target is not breach likelihood, attack probability, compliance, or independent human ground truth. For the ZGrab prototype, `HAS_RULE_FLAGGED_ISSUE` means at least one of the seven existing `rule_flag_*` outputs is true on a successfully negotiated TLS session. `NO_CURRENT_RULE_FLAG` means none was raised; it does **not** mean proven secure. Non-TLS rows are `NOT_EVALUABLE` for this classifier and remain available for state analysis.

Current labeled cohort: **61 HAS_RULE_FLAGGED_ISSUE / 469 NO_CURRENT_RULE_FLAG**, from 530 completed handshakes. There are only 2 TLS 1.0 examples and no weak-RSA-key examples. This dataset cannot support a defensible four-tier supervised classifier. A multi-tier risk rubric remains a later task requiring a reviewed severity mapping and enough examples per class.

`comparison.json` statuses are parser-vs-fixture checks, not risk labels. ZGrab `rule_flag_*` columns are derived findings, not independent ground truth. The prototype label builder uses them only to construct the explicitly named proxy target; training code excludes them from model inputs.

**Data:** the 530 real ZGrab TLS handshakes are the real SMTP cohort; the other 1,070 records are useful for protocol-state analysis, not TLS cryptographic-tier training. The 110 synthetic testbed cases and any generated variants can cover rare configurations, but must keep `data_source=synthetic` or `synthetic_derived` and retain a `parent_record_id` for grouping. Use synthetic cases to test the classifier under known conditions; do not use them to claim real-world performance.

The initial classifier is a proof-of-concept rule-flag surrogate. Its metrics measure agreement with existing flags, not independent security accuracy or discovery beyond the rules. Report per-class counts and limitations. Do not describe it as breach prediction or a validated security-risk model. The current model and scoring files use the ZGrab schema only; no adapter from `analysis.parser` / `RuleInput` has been implemented yet.

### 2. TLS Anomaly Detection

**Question answered:** how unusual is this observed negotiation relative to a named reference cohort?

**Target/output:** `anomaly_score` plus `anomaly_status` (`UNUSUAL`, `WITHIN_REFERENCE`, or `NOT_EVALUABLE`). This is relative rarity, not a vulnerability or attack verdict.

**Data and cohorts:**

- SMTP reference: successful ZGrab SMTP TLS handshakes (currently 530). Keep it as its own cohort and identify the scan population/version.
- Synthetic email testbed: controlled regression cases and injected edge cases; report its results separately.
- `mix.zip`: separate TLS 1.3 HTTPS cohort for general TLS experiments only. It is not an email baseline.
- MTA-STS certificate observations: separate certificate-only cohort; not full SMTP handshakes.

The HTTPS cohort is now extracted to `processed/https_tls_v1.csv`: 41,205 PCAPs parsed, 41,205 ClientHellos, 41,204 ServerHellos, all observed negotiations TLS 1.3, three selected cipher suites balanced at 13,735 / 13,735 / 13,734, and 41 hashed server/site groups. Its separate Isolation Forest flags 413 in-sample observations at the configured 1% contamination setting. This is a review-tail assumption, not measured detector performance. The corpus cannot support legacy TLS detection and must not be represented as email traffic. Filename-derived source refs and group IDs are provenance only, never model features.

The current MTA-STS certificate extractor keeps 21,490 successfully parsed scan-certificate observations from 122,917 source rows, representing 9,459 distinct leaf-certificate fingerprints. The 1,978 malformed/short source rows are skipped; 99,449 non-success scan rows are retained as non-certificate observations. Its Isolation Forest is fitted once per distinct certificate and scores the 21,490 source observations. It marks 473 distinct certificates under a chosen 5% contamination setting. This is in-sample, cohort-relative novelty with no anomaly ground truth; it is not measured detector performance or certificate vulnerability assessment. Group by certificate fingerprint for any future split, and keep this certificate-only cohort distinct from SMTP session records.

The original certificate-aware implementation uses an Isolation Forest over version, cipher, KEX, and certificate categories. `zgrab_smtp_negotiation_anomaly_v1` uses negotiated TLS version, cipher, and key exchange, excluding certificate fields unavailable on some passive TLS 1.3 captures. Its 469-row reference is selected by no current deterministic findings and is not independently verified benign. Model version 2.0 uses exact tuple support as the primary cohort-novelty decision and retains Isolation Forest as a secondary score. The latter's leave-one-country-out 24/530 flags under a 5% contamination assumption are cohort-stability output, not a measured false-positive rate. In the latest controlled synthetic transfer audit, the primary method marked 8/8 BROKEN, 6/6 WEAK, 7/7 MEDIUM, and 12/38 HIGH-strength tuples unseen; the secondary Isolation Forest flagged 0/8 BROKEN and 0/6 WEAK. Cipher-strength categories are descriptive strata, not independent anomaly labels. Do not present either method as a security-risk or attack detector. The output is strictly cohort-relative: an unseen tuple may be secure, and a seen tuple may be insecure.

### 3. Scores and Finding Priority

- `deterministic_posture_score`: derived only from the documented rule/severity rubric; evidence-linked and explainable.
- `ml_policy_tier` / `ml_confidence`: classifier output kept separate from deterministic findings and scores.
- `anomaly_score`: relative to the selected reference population; never added to posture score by default.
- `finding_priority`: rule severity plus evidence confidence and applicable context. Use KEV/EPSS only when a finding has a defensible CVE mapping.

Do not create a combined score until its formula, scale, handling of `NOT_EVALUABLE`, and evaluation are documented. TLS configuration problems generally do not identify a CVE by themselves; do not attach unrelated CVEs based only on a cipher or certificate property.

## Feature Allowlist and Leakage Exclusions

### ZGrab Risk-Tier Prototype

Candidate observed inputs from `zgrab_smtp_v1.csv`:

- State: `starttls_observation_state`, `tls_observation_state`, `certificate_observation_state`.
- Negotiation: `tls_version`, `tls_selected_version`, `cipher_suite`, `key_exchange`, `tls_extension_count`, and observed extension indicators.
- Certificate facts: `cert_key_algorithm`, RSA/ECDSA key size and curve, `cert_signature_algorithm`, `browser_trusted`, `cert_self_signed`, `cert_validity_days`, `cert_days_remaining`, `cert_expired`, `cert_not_yet_valid`, chain length, EKU, key-usage and certificate-extension observations.
- SMTP context: `smtp_protocol`, `banner_present`, `ehlo_present`, `starttls_present` only when evaluating a task whose target requires those facts.

Use categorical encoding for protocol/version/cipher/algorithm/group names. Keep missing values plus observation-state columns; do not fill absent certificate facts with zero. For the partial-evidence experiment, mask only explicit observed facts and record the masking scheme.

Exclude from model inputs:

- `record_id`, `data_source`, `source_file`, `source_row`, `country`, IP, domain, hostname, SNI value, certificate subject/issuer, timestamps, and capture identifiers. Some are absent from the prepared table; others must remain provenance/grouping metadata only.
- All `rule_flag_*` columns, rule verdicts, severity, policy outcomes, comparison statuses, label source, target, and generation/scenario IDs.
- `ja3s` and other opaque fingerprints as numeric values.
- Duplicate derived rule indicators (`is_legacy_tls`, `risk_*`, `smtp_no_starttls_or_tls_observed`) when the target rubric is built from the same underlying condition. Prefer original observed values and a task-specific allowlist.

The excluded IP/domain/certificate identity may be used to group related records before splitting, never as a predictive feature.

### Anomaly Model

Use observed TLS version, negotiated cipher, KEX/group, key algorithm/size, signature algorithm, and selected handshake-extension presence. Include protocol/cohort as a baseline selector, not as a shortcut for anomaly. Exclude identity fields, timestamps, source-country labels, record IDs, `rule_flag_*`, rule severity, and generated anomaly labels from inputs.

## Splits and Evaluation

- Split by entity group before fitting preprocessing or models. Group by endpoint and, where available, certificate fingerprint/domain/service identity. Keep every generated variant with its parent in the same split.
- For testbed PCAPs, hold out entire scenario/configuration families, not random captures. Keep all synthetic metrics separate from real ZGrab metrics.
- Use train/validation/test where class counts permit. With rare classes, show counts and per-class metrics; do not use a random split to imply generalization. If a class cannot appear in each split, report that limitation instead of fabricating balance.
- Freeze categorical vocabularies and imputers on training data only. Keep a `NOT_EVALUABLE`/abstain path for insufficient evidence.
- Compare classifier to a majority-class baseline and the deterministic rubric. Evaluate anomaly models against a stated rarity baseline and separately against controlled synthetic cases.
- Do not use test results to tune thresholds. Save split manifest, seed, source hashes, schema version, and model version.

## Dataset Roles (Current Inventory)

| Source | Use | Not suitable for |
|---|---|---|
| 1,600 ZGrab SMTP observations; 530 observed TLS handshakes | Real SMTP feature analysis; SMTP anomaly reference; evidence-rubric classifier; deterministic-finding proxy classifiers | Independent human-reviewed risk labels; passive-PCAP parser validation |
| 10,000 generated feature-level email sessions (2,000 simulated endpoint profiles; 0 real rows) | Grouped synthetic endpoint-posture classifier; controlled feature experiments for SMTP/IMAP/POP3 | PCAP/parser validation, real-world prevalence or real-world generalization claims |
| 110 synthetic email PCAPs from 126 contracts | Feature/parser validation; runtime integration and rare-condition coverage | Classifier ground truth or real-world prevalence/generalization claims |
| `mix.zip` TLS 1.3 HTTPS | Separate general-TLS anomaly experiment | SMTP/IMAP/POP3 baseline or certificate-risk labels |
| MTA-STS policies and scan certificates | Policy posture and certificate-only features, preserving collection context | Full SMTP TLS handshake dataset |
| NVD / KEV / EPSS | Enrichment and prioritization for defensibly mapped vulnerabilities | Per-session TLS risk labels |
| NIST / CWE / OWASP | Rule sources, recommendations, explanation retrieval | ML observations or labels |
| MAWI captures | Potential real passive email traffic after protocol/handshake audit | Training until session counts, truncation, and labels are verified |

## Runtime Contract

For each PCAP session, persist parser observations, deterministic policy results, classifier output, anomaly result, score components, provenance, and recommendations as separate structured objects. ML may add context but cannot convert a deterministic `FAIL` into `PASS`. Insufficient evidence produces an explicit status, not a guessed secure result. LLM reports and natural-language queries are deferred until the user selects a provider/model; the LLM may only summarize evidence retrieved from storage.

`analysis/ml_runtime.py` is invoked by `RuleEngine` after independent policy evaluation and serialized under `ml_results`. Primary classifier routing is SMTP→the real-ZGrab evidence-rubric classifier and IMAP/POP3→the synthetic v2 posture classifier. There is no fallback across cohorts when a model abstains. The ZGrab target comes from raw observed facts rather than Rule Engine outputs, but is not independent human-reviewed truth and passive-PCAP transfer is not validated. The synthetic target describes generated endpoint-profile posture and is not real-world ground truth. SMTP sessions also use the negotiation-only anomaly model, exposing exact tuple support as the primary anomaly signal plus a separate Isolation Forest score/flag and `cross_cohort_transfer_status=NOT_VALIDATED`. An observable leaf certificate is scored independently against the MTA-STS certificate cohort. The legacy real-ZGrab tier labels still proxy deterministic findings. Certificate-derived public facts are mapped where parser evidence exists; capture-time expiry and unsupported TLS features remain missing rather than imputed. No ML result changes Rule Engine results.

## Implemented Model Snapshot (2026-09-29)

This current snapshot supersedes the earlier “prototype/next stages” wording above. Rule findings, supervised estimates, anomaly scores, and certificate novelty are independent result objects; the ML aggregator does not combine them into a posture score and cannot override a rule result.

### Programmatic Synthetic Email Endpoint-Posture Classifier v2

- Generator: `datasets/ml/generate_synthetic_email_research_cohort.py`; model trainer: `datasets/ml/train_synthetic_email_posture_classifier.py`.
- Dataset: `datasets/ml/synthetic/synthetic_email_research_cohort_v1.csv`, 10,000 feature-level simulated sessions, 2,000 generated endpoint-profile instances, five client negotiations/profile. Protocol rows: SMTP 3,332, IMAP 3,336, POP3 3,332. Global labels: LOW/MEDIUM/HIGH/CRITICAL = 2,500 each. Provenance is `synthetic_simulation`; 0 real observations. It is not an LLM-generated dataset or a PCAP corpus. Eight designed profile families yield 508 distinct feature-configuration fingerprints; fingerprints are group metadata, not inputs.
- Label: full generated endpoint configuration, not Rule Engine result. CRITICAL means TLS disabled or NULL/RC4 permitted; HIGH means TLS below 1.2, static RSA KEX, weak RSA key, untrusted/mismatched certificate, or SHA-1; MEDIUM means no higher condition but CBC is permitted or certificate lifetime exceeds 825 days; LOW means no higher condition with modern TLS, AEAD/ECDHE-capable suites, and strong trusted matching cert. Input describes only one negotiation, so this is partial observation of the profile target.
- Features: 15 canonical fields from `_email_risk_features` (11 categorical and 4 numeric); identifiers, raw profile family, group IDs, target flags and deterministic finding outputs are excluded. Training and runtime call the same feature extractor.
- Split: configuration-fingerprint-grouped, disjoint train 6,390 rows / 303 groups, validation 1,735 / 102, test 1,875 / 103. Total 508 groups. Group-preserving allocation makes row ratios approximately 64/17/19, not exact 60/20/20. Test supports LOW 570, MEDIUM 475, HIGH 520, CRITICAL 310.
- Hyperparameter grid: Logistic Regression C={0.1,0.3,1,3,10} with balanced/unweighted classes; Random Forest 300/500 trees, depth full/16, leaf size 1/3/6. Selected by grouped validation macro-F1, never by heldout test. Best validation: Logistic Regression .490 (C=.1, balanced), Random Forest .473; selected Logistic Regression. Test accuracy .513, macro-F1 .511 vs majority macro-F1 .071. Per-class P/R/F1: LOW .806/.351/.489; MEDIUM .500/.507/.504; HIGH .676/.629/.651; CRITICAL .293/.626/.400. Confusion matrix (actual rows / predicted columns, LOW/MEDIUM/HIGH/CRITICAL): `[[200,61,7,302],[48,241,74,112],[0,140,327,53],[0,40,76,194]]`.
- Interpretation: these are grouped held-out results within the designed simulator, not real-world efficacy. Test performance shows substantial confusion, including weak LOW recall and CRITICAL precision. Sidecar behavior predicted HIGH or CRITICAL on 21/22 IMAP samples and CRITICAL on 21/22 POP3 samples; this is a target/distribution mismatch warning, not a test accuracy result. Model is advisory. The 110 existing synthetic PCAPs remain for parser/runtime validation and are not counted as training observations.
- Main runtime routing: SMTP uses the real-ZGrab evidence-rubric classifier; IMAP and POP3 use this synthetic v2 classifier. If the primary classifier abstains, it remains abstained; no cross-cohort fallback occurs. Real-world transfer for either classifier is not validated.

### Supervised SMTP Risk-Tier Proxy

- Artifact: `zgrab_runtime_risk_tier_v1`; Logistic Regression; 33 runtime-observable negotiation/certificate fields.
- Source: 530 real ZGrab SMTP TLS handshakes; only those with a completed handshake are label-evaluable. LOW=469, MEDIUM=41, HIGH=20. The other 1,070 of 1,600 SMTP observations are `NOT_EVALUABLE` for the TLS tier target, not negative/secure examples.
- Rubric: LOW = no current rule flags; MEDIUM = exactly one non-legacy flag; HIGH = legacy TLS or at least two distinct rule flags. The current seven rule flags generate target labels only and are excluded from inputs. CRITICAL is not a modeled class: there are only two TLS 1.0 observations and no adequate independent support for a separate class.
- Frozen split by country group: train 298 (LOW 266, MEDIUM 25, HIGH 7), validation 138 (125,11,2), test 94 (78,5,11); country groups do not overlap. No IP, country, timestamp, row ID, or rule flag is a predictive input.
- Held-out test: accuracy 0.936; macro-F1 0.808 vs majority macro-F1 0.302. Class F1: LOW 0.968 (n=78), MEDIUM 0.600 (n=5), HIGH 0.857 (n=11). Confusion matrix in LOW/MEDIUM/HIGH order: `[[76,2,0],[1,3,1],[2,0,9]]`.
- Interpretation: these measure prediction of a documented deterministic severity proxy across held-out countries. They are not independent human security labels, compromise likelihood, or validated generalization to passive PCAP; class scores are uncalibrated. Runtime reports evidence coverage and abstains below its training coverage threshold.
- The older binary `zgrab_runtime_rule_flag_proxy_v2` remains available for compatibility and is also a rule-flag proxy, not a separate truth source.

### Synthetic Email Risk Classifier (Experimental)

- Artifact: `synthetic_email_risk_classifier_v1`; Random Forest selected against Logistic Regression on validation macro-F1; 15 runtime-observable categorical/numeric fields with explicit missing-value indicators.
- Source: 110 captured synthetic PCAP scenarios (SMTP 66, IMAP 22, POP3 22). Labels come from a separate project rubric applied to expected scenario facts. Neither Rule Engine findings nor `rule_flag_*` columns are read by the training code.
- Rubric: CRITICAL = no TLS, STARTTLS downgrade/stripping, or BROKEN cipher; HIGH = TLS 1.0/1.1, WEAK cipher, certificate validity/identity/trust/chain issue, or absent forward secrecy; MEDIUM = MEDIUM cipher or explicitly incomplete trust state; LOW = no higher-severity rubric condition in the expected scenario.
- Grouped split: train 71 (LOW 27/MEDIUM 4/HIGH 25/CRITICAL 15), validation 19 (8/2/6/3), test 20 (9/2/5/4); 32/14/10 transitive groups. A group connects scenarios sharing either a scenario family or an observed certificate identity, preventing either from crossing partitions.
- Validation macro-F1: Logistic Regression 0.277; Random Forest 0.315 (selected). Heldout test macro-F1 0.375, accuracy 0.450; majority baseline macro-F1 0.155. LOW/MEDIUM/HIGH/CRITICAL F1: 0.000/0.000/0.500/1.000, with supports 9/2/5/4. Confusion matrix: `[[0,0,9,0],[1,0,1,0],[0,0,5,0],[0,0,0,4]]`.
- Interpretation: this is trained from expected testbed facts independently of Rule Engine outputs, but held-out performance is poor. The artifact is integrated for experimental advisory inference across the three email protocols; it does not establish effective risk classification or real-world transfer. Scores are uncalibrated and no output overrides deterministic findings.

### Real ZGrab Evidence-Rubric Classifier (Advisory)

- Artifact: `zgrab_evidence_risk_classifier_v1`; selected Logistic Regression; 15 canonical session fields with categorical encoding and explicit numeric missingness.
- Source: 1,600 real active-ZGrab SMTP observations. The deterministic rubric labels 1,524; 76 failed/incomplete observations remain `NOT_EVALUABLE`.
- No Rule Engine findings, `risk_*`/`rule_flag_*` fields, or legacy classifier target are read by the trainer. The target is still a project-defined label derived from raw observations, not independently reviewed risk truth.
- Labels: CRITICAL = SMTP response without STARTTLS/TLS or NULL/RC4/EXPORT cipher; HIGH = TLS 1.0/1.1, static RSA KEX, SHA-1 signature, RSA key below 2048, invalid dates, self-signed/untrusted cert, or no SAN; LOW_OR_MEDIUM = completed handshake without higher-tier conditions. CBC/no-forward-secrecy are merged into LOW_OR_MEDIUM because only one medium-only row exists. Counts are 994/62/468 in CRITICAL/HIGH/LOW_OR_MEDIUM order.
- Frozen country split: train 849 (551/33/265), validation 292 (154/13/125), test 383 (289/16/78), in CRITICAL/HIGH/LOW_OR_MEDIUM order. No country crosses a split; IP/country/identity/time are not features.
- Validation candidate macro-F1: Logistic Regression 1.000, Random Forest 1.000; Logistic Regression wins the fixed tie break. Test accuracy 0.990, macro-F1 0.944 vs majority 0.287. Per-class F1: LOW_OR_MEDIUM .975 (n=78), HIGH .857 (n=16), CRITICAL 1.000 (n=289); confusion matrix `[[78,0,0],[4,12,0],[0,0,289]]` in LOW_OR_MEDIUM/HIGH/CRITICAL order.
- These metrics assess reproduction of the rubric across held-out countries. They do not prove independent risk accuracy, detection beyond the rubric, or transfer from active scans to passive PCAP. Runtime use is SMTP-only, advisory, uncalibrated, and explicitly marked `NOT_VALIDATED` for cross-cohort transfer. It cannot be called a proven safety net for Rule Engine misses.

### Anomaly and Certificate Novelty

- SMTP negotiation novelty uses its dedicated ZGrab SMTP cohort and remains explicitly exploratory. It does not imply insecurity or attack. The certificate-aware legacy anomaly model remains separately registered.
- HTTPS TLS novelty: 41,205 real HTTPS/TLS 1.3 PCAP observations, 30 named source features, Isolation Forest; fit on 32,160 observations from 32 site groups and evaluated descriptively on 9,045 observations from 9 held-out site groups. With the 1% contamination assumption, 52/9,045 held-out observations were flagged. There are no anomaly ground-truth labels, so this is not precision/recall or an email detector. The model is intentionally not applied to SMTP/IMAP/POP3 runtime sessions.
- Certificate novelty: 21,490 parsed scan-certificate observations, 9,459 distinct leaf fingerprints. Fingerprint-group split: 7,567 reference certificates and 1,892 held out. Isolation Forest uses 22 certificate fields and a 5% analyst review-tail assumption; 77/1,892 held-out unique certificates were flagged. This is novelty only, not vulnerability detection. The cohort consists of SMTP-related scan/HTTP-context certificates, not 23K complete SMTP handshakes. Runtime may independently compare an observed PCAP leaf certificate against this reference cohort.
- Runtime inference is protocol-aware: SMTP uses the real-ZGrab evidence-rubric classifier; IMAP/POP3 use synthetic v2; SMTP anomaly and other SMTP-cohort outputs remain SMTP-only. Fresh full synthetic PCAP reparse processed 110 captures/116 streams without analysis failures: the real-ZGrab classifier returned advisory estimates on 68 SMTP sessions; synthetic v2 completed experimentally on all 24 IMAP and 24 POP3 sessions and was `NOT_APPLICABLE` on SMTP. SMTP-only outputs were `NOT_APPLICABLE` on all 48 IMAP/POP3 streams, and certificate novelty ran only where a leaf was observable. Missing feature evidence yields explicit `NOT_EVALUABLE`, not an assumed secure result. Full status detail is saved to `models/synthetic_pcap_runtime_coverage_v5.json`; this validates execution/applicability, not accuracy. The mock-artifact smoke test exercises all 10 registered artifacts with missing and populated schema-shaped features; this validates inference plumbing, not predictive quality.

### Validation Boundaries

- The synthetic corpus is kept separate from ZGrab, HTTPS, and certificate cohorts. Its expected facts provide the experimental classifier's rubric labels; these are independent of Rule Engine outputs but are not human-reviewed security truth. Sidecar audits remain behavior/coverage checks and do not replace the family-heldout classifier metrics above.
- Synthetic anomaly flags and unseen configuration tuples are transfer/coverage observations only. The expected cipher-strength labels do not validate the learned ZGrab proxy tier.
- Model artifacts and JSON metadata record schema/model version, feature names, data source, split strategy, hashes, metrics where labels exist, and limitations. Re-run the named training scripts to regenerate artifacts; preserve their grouped split manifests.
- NVD, KEV, and EPSS remain enrichment inputs only. No CVE is attached to a TLS/certificate property without an evidence-backed product/version mapping. No learned risk score is presented as deterministic posture score.
