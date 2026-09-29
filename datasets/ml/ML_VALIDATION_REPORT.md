# SecureMailScope ML Validation Report

Date: 2026-09-29 (10k synthetic cohort and v3 parser/runtime audit)  
Scope: ML/data preparation, training, evaluation and parser-runtime validation only. Frontend, dashboard and LLM/query features are outside this report.

## Implemented Models

| Model | Role / source | Features | Evaluation |
|---|---|---:|---|
| `zgrab_rule_flag_proxy_v1` | Legacy broad rule-flag proxy; 530 real ZGrab SMTP TLS observations | 52 | Leave-country-out proxy agreement; retained for reproducibility and not used by the runtime. |
| `zgrab_runtime_rule_flag_proxy_v2` | Binary proxy for deterministic-rule flag presence; 530 real ZGrab SMTP TLS observations | 33 | Country-held-out proxy agreement; retained for compatibility. Not independent security ground truth. |
| `zgrab_runtime_risk_tier_v1` | LOW/MEDIUM/HIGH deterministic-severity proxy classifier; 530 real ZGrab SMTP TLS observations | 33 | Country-held-out train/validation/test: 298/138/94. Test accuracy 0.936, macro-F1 0.808; majority macro-F1 0.302. |
| `synthetic_email_risk_classifier_v1` | Scenario-contract risk rubric classifier for SMTP/IMAP/POP3; 110 synthetic PCAP observations | 15 | Scenario-family and certificate-identity grouped train/validation/test: 71/19/20. Random Forest selected at validation macro-F1 0.315; held-out test macro-F1 0.375, accuracy 0.450; NOT validated for real-world use. |
| `zgrab_evidence_risk_classifier_v1` | SMTP evidence-rubric classifier trained from real ZGrab observations; does not read Rule Engine outputs | 15 | Country-held-out train/validation/test: 849/292/383. Test macro-F1 0.944, accuracy 0.990 against its documented rubric; not independent security truth or validated passive-PCAP transfer. |
| `synthetic_email_posture_classifier_v2` | Programmatic feature-level simulation of SMTP/IMAP/POP3 endpoint posture; 10,000 rows, 2,000 profile instances | 15 | Grouped configuration split 6,390/1,735/1,875. Held-out simulator macro-F1 0.511, accuracy 0.513. Synthetic-only; real-network effectiveness is not established. |
| `zgrab_smtp_negotiation_anomaly_v1` | SMTP TLS configuration novelty against the 469-session ZGrab reference subset | 3 | Unsupervised, no anomaly labels; outputs cohort-relative score and rarity support. |
| `zgrab_smtp_anomaly_v1` | SMTP TLS/certificate configuration novelty against ZGrab | 6 | Exploratory cohort-relative novelty; not vulnerability or attack detection. |
| `https_tls_anomaly_v1` | General TLS behavior novelty, using 41,205 real HTTPS/TLS 1.3 PCAPs | 30 | 32,160 train-reference observations; 9,045 held out across 9 of 41 site groups; 52 flagged under 1% contamination. No anomaly ground truth. Not an email model. |
| `mta_sts_cert_anomaly_v1` | Certificate novelty using 21,490 parsed scan-certificate observations (9,459 unique certs) | 22 | 7,567 unique certs in reference; 1,892 held out by fingerprint; 77 flagged under 5% contamination. No vulnerability labels. |

The saved binary proxy, SMTP cohort models, HTTPS model, certificate model, and synthetic email model remain separate result types. No weighted “AI security score” combines their scores; deterministic posture/rule outputs remain separate and authoritative.

All 10 allowlisted model artifacts pass metadata/schema/SHA-256 checks. The binary compatibility classifier reports grouped out-of-fold macro-F1 0.953 (majority baseline 0.469), with confusion matrix `[[465,4],[6,55]]` in `NO_CURRENT_RULE_FLAG`, `HAS_RULE_FLAGGED_ISSUE` order. This measures agreement with the deterministic-rule proxy only.

| Binary proxy class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| NO_CURRENT_RULE_FLAG | 0.987 | 0.991 | 0.989 | 469 |
| HAS_RULE_FLAGGED_ISSUE | 0.932 | 0.902 | 0.917 | 61 |

## Supervised Label and Metrics

### Independent-of-Rule-Engine Synthetic Email Classifier

The new `synthetic_email_risk_classifier_v1` is trained from the 110 controlled testbed capture observations (SMTP 66, IMAP 22, POP3 22). Labels come from a documented rubric applied to each scenario's expected TLS, STARTTLS, cipher, certificate, and forward-secrecy facts. Its trainer does not load Rule Engine findings or `rule_flag_*` fields. Features are extracted from the observed session using the same `_email_risk_features` function used at runtime (15 fields; categorical encoding plus explicit numeric missingness). Transitive scenario-family and certificate-identity components are disjoint across train/validation/test: 71/19/20 samples and 32/14/10 components. Class distribution is LOW 44, MEDIUM 8, HIGH 36, CRITICAL 22. Training split distribution: LOW 27/MEDIUM 4/HIGH 25/CRITICAL 15; validation: 8/2/6/3; test: 9/2/5/4.

Logistic Regression validation macro-F1 was 0.277; Random Forest was selected at 0.315. On the held-out test (20 samples), accuracy was 0.450, macro-F1 0.375 versus majority-baseline macro-F1 0.155. Per-class F1: LOW 0.000 (n=9), MEDIUM 0.000 (n=2), HIGH 0.500 (n=5), CRITICAL 1.000 (n=4). Confusion matrix in LOW/MEDIUM/HIGH/CRITICAL order: `[[0,0,9,0],[1,0,1,0],[0,0,5,0],[0,0,0,4]]`. These weak held-out results mean the model is implemented, persisted, loaded, and integrated, but **its effectiveness is not demonstrated**. Its outputs are experimental advisory estimates only. Scores are not calibrated probabilities. Synthetic labels are rubric labels, not independent human-reviewed risk truth, and no real SMTP/IMAP/POP3 records trained this model.

### Real ZGrab Classifier Proxy

The tier target is `zgrab_rule_rubric_tier_v1`, generated deterministically from seven existing rule flags on completed TLS handshakes. LOW means no rule flag; MEDIUM exactly one non-legacy flag; HIGH means legacy TLS or at least two distinct flags. CRITICAL is not modeled because only two TLS 1.0 observations exist. The labels measure the defined rule rubric, not independently reviewed risk, attack likelihood, or breach probability.

| Split | Total | LOW | MEDIUM | HIGH |
|---|---:|---:|---:|---:|
| Train | 298 | 266 | 25 | 7 |
| Validation | 138 | 125 | 11 | 2 |
| Test | 94 | 78 | 5 | 11 |

Country-grouped split is frozen and disjoint: 9 countries train, 3 validation, 4 test. No IP/country/time/rule labels enter the 33-feature model. Of the 1,600 total real SMTP observations, 530 had TLS handshakes and are tier-evaluable; remaining 1,070 are not negative examples.

Held-out test (class order LOW, MEDIUM, HIGH):

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| LOW | 0.962 | 0.974 | 0.968 | 78 |
| MEDIUM | 0.600 | 0.600 | 0.600 | 5 |
| HIGH | 0.900 | 0.818 | 0.857 | 11 |

Confusion matrix, actual rows / predicted columns: `[[76, 2, 0], [1, 3, 1], [2, 0, 9]]`. Metrics are a held-out-country test of proxy-label prediction. Small class supports, country-only grouping, likely service/certificate relatedness, active-ZGrab-to-passive-PCAP shift, and uncalibrated scores mean this is a research prototype, not production accuracy evidence.

### Real ZGrab Evidence-Rubric Classifier (separate from Rule Engine outputs)

`zgrab_evidence_risk_classifier_v1` is trained on 1,524 evaluable rows from the 1,600 real active-ZGrab SMTP observations. Its trainer reads raw SMTP/TLS/certificate facts and never reads `risk_*`, `rule_flag_*`, Rule Engine verdicts, or legacy proxy labels. The 76 SMTP-failure or incomplete-handshake observations are `NOT_EVALUABLE`, not safe negatives. Its 15 inputs are observed session facts with categorical encoding and explicit numeric missingness; IDs, IPs, country and timestamps are excluded from model inputs.

The labels are a stated project rubric: CRITICAL means an SMTP response with neither STARTTLS nor TLS, or a NULL/RC4/EXPORT cipher; HIGH means TLS 1.0/1.1, static RSA key exchange, SHA-1 certificate signature, undersized RSA, invalid validity, self-signed/untrusted certificate, or no SAN; `LOW_OR_MEDIUM` means a completed handshake without one of those higher-tier conditions. CBC/no-forward-secrecy are coarsened into `LOW_OR_MEDIUM` because only one medium-only example exists. Counts are CRITICAL 994, HIGH 62 and LOW_OR_MEDIUM 468.

The frozen country-grouped split has no country overlap: train 849 (551/33/265), validation 292 (154/13/125), and test 383 (289/16/78), with counts ordered CRITICAL/HIGH/LOW_OR_MEDIUM. A fixed grid searched Logistic Regression C={0.03,0.1,0.3,1,3,10} with balanced/unweighted classes and Random Forest tree/leaf settings. Both model families still scored validation macro-F1 1.000; Logistic Regression (C=0.03, balanced weights) won the fixed simplicity tie-break. Held-out test accuracy is 0.990 and macro-F1 0.944 versus majority-baseline macro-F1 0.287. Per-class precision/recall/F1: LOW_OR_MEDIUM 0.951/1.000/0.975 (n=78), HIGH 1.000/0.750/0.857 (n=16), CRITICAL 1.000/1.000/1.000 (n=289). Confusion matrix in LOW_OR_MEDIUM/HIGH/CRITICAL order: `[[78,0,0],[4,12,0],[0,0,289]]`.

These scores show prediction of this rubric across held-out countries; they do **not** establish independent security ground truth, discovery of findings the rubric does not encode, production risk accuracy, or transfer from active scans to passive PCAP sessions. The rubric overlaps security conditions that deterministic checks also inspect, although the training code does not consume their outputs. Runtime returns an advisory rubric estimate with uncalibrated scores, coverage, model version and `cross_cohort_transfer_status=NOT_VALIDATED`. Do not describe it as a validated safety net for Rule Engine misses.

## Unsupervised Models

The HTTPS model is fit only on the 32,160 training-reference PCAPs; preprocessing is also fit on that split. Evaluation holds out entire site groups. Its 52/9,045 flagged heldout observations are an unlabeled review-tail rate, not measured false positives. All data observed in the corpus is TLS 1.3, and TLS 1.3 certificates are encrypted in these PCAPs. Do not use this result to claim SMTP behavior, legacy TLS detection, or attack detection.

Certificate novelty fits on distinct fingerprint groups so duplicate certificate observations do not cross the fit/evaluation partition. Seventy-seven of 1,892 heldout unique certificates were flagged. This models distributional novelty only; unusual is not insecure. The corpus contains scan/HTTP-context SMTP-related certificates, not 23,475 complete SMTP sessions.

SMTP anomaly inference uses the real ZGrab SMTP TLS cohort and remains separate from HTTPS. There is no labeled real SMTP anomaly truth. Runtime model version 2.0 makes exact negotiated `(version, cipher, key exchange)` support the primary novelty signal; an unseen tuple is reported as novel relative to this active-scan cohort. Isolation Forest remains a secondary score because its transfer check missed the controlled weak/broken tuples. On the 59 evaluable synthetic SMTP scenarios, exact support marked 8/8 BROKEN, 6/6 WEAK, 7/7 MEDIUM, and 12/38 HIGH-strength tuples unseen; Isolation Forest flagged 0/8 BROKEN, 0/6 WEAK, 1/7 MEDIUM, and 0/38 HIGH. Those expected strength labels are descriptive strata only, not independent anomaly truth, so these are not precision/recall or real-world detection claims. A common insecure tuple can remain within-reference, and a secure rare tuple can be novel. Deterministic findings remain separate.

### Controlled Mock Metrics for Novelty Models

To make anomaly-model behavior testable despite the absence of independently labeled anomalies, `evaluate_controlled_novelty.py` evaluates the saved artifacts against explicit injected feature changes. Untouched observations from held-out real source groups are class 0; copies with out-of-cohort categorical values and extreme numeric values are synthetic class 1. Parent certificates or HTTPS site groups are kept within one evaluation partition. The resulting CSV-free JSON report is `models/controlled_novelty_benchmark_v1.json`; it records source/model hashes, feature counts, class distributions, confusion matrices, precision, recall, F1 and ROC-AUC. These metrics only measure the specified injection recipe.

| Model | Real fit set | Held-out real controls | Mock test partition | Test macro-F1 / ROC-AUC | Test confusion matrix (control, injected) |
|---|---:|---:|---:|---:|---|
| SMTP exact tuple support | 469 SMTP observations; 7 distinct reference tuples | Same named reference cohort | 2 seen tuples + 2 constructed unseen tuples | 1.000 / not meaningful | `[[2,0],[0,2]]` |
| Certificate Isolation Forest | 7,567 unique certificate fingerprints | 1,892 unique fingerprints, split by fingerprint | 379 controls + 379 injected variants | 0.979 / 0.995 | `[[363,16],[0,379]]` |
| HTTPS Isolation Forest | 32,160 TLS PCAP observations | 9,045 observations from 9 held-out site groups | 3,015 controls + 3,015 injected variants, 3 held-out sites | 0.921 / 1.000 | `[[3015,0],[476,2539]]` |

For certificate novelty, the mock test has 100% injected-case recall and 4.2% control false-positive rate under this injection recipe. For HTTPS, the mock test has 84.2% injection recall and zero control flags in these three held-out site groups; the validation partition contains just one site group. The strong ROC-AUC is expected for large artificial feature perturbations and is not evidence of attack detection or population-wide false-positive performance. SMTP support's perfect score is tautological: membership in the exact tuple table defines the answer, and the test has only two tuples per class. These mock metrics must be shown separately from classifier metrics and never presented as real anomaly accuracy. No threshold was tuned on the mock test set and no model artifact was changed from these results.

## Runtime and Tests

`analysis/ml_runtime.py` exposes the two primary cohort-routed classifiers, legacy diagnostic proxies, SMTP anomaly/rarity, and certificate novelty with model IDs, schema/provenance/coverage and explicit abstention/not-applicable states. SMTP uses the real-ZGrab evidence-rubric classifier; IMAP and POP3 use the synthetic v2 classifier. There is no silent fallback: if the applicable SMTP classifier abstains, the synthetic classifier is not substituted. Synthetic v2 is available on all three protocols for controlled testing, but only routed on IMAP/POP3 in production-path inference. Both learned classifiers are advisory and cross-cohort transfer is unvalidated. SMTP anomaly's primary flag is unseen exact tuple support; Isolation Forest remains separately visible. SMTP-only models do not run for IMAP/POP3. ML never changes a deterministic Rule Engine verdict.

### Synthetic Email Endpoint-Posture Classifier v2

`synthetic_email_posture_classifier_v2` is trained only on `datasets/ml/synthetic/synthetic_email_research_cohort_v1.csv`, generated by `datasets/ml/generate_synthetic_email_research_cohort.py`. This is a programmatic feature-level simulation, not LLM output, captured traffic, or 10,000 PCAPs. The generator creates 2,000 simulated endpoint-profile instances, five client-negotiation rows per profile, across SMTP (3,332), IMAP (3,336), and POP3 (3,332). It uses eight designed profile families and produces 508 distinct configuration fingerprints; repeated configurations are grouped in the split. Every row is marked `synthetic_simulation`; real observations used: 0. The existing 110 synthetic PCAPs remain the packet/parser/runtime integration corpus.

The target is a project-defined rubric on each endpoint's **full supported configuration**, while model features describe one negotiation. CRITICAL: TLS unavailable or NULL/RC4 permitted. HIGH: TLS below 1.2, static RSA KEX, weak RSA key, untrusted/mismatched certificate, or SHA-1. MEDIUM: no higher-tier condition but CBC is permitted or certificate lifetime exceeds 825 days. LOW: modern TLS with AEAD/ECDHE-capable suites and a strong, trusted, matching certificate, with no higher-tier condition. The label uses generated endpoint configuration facts, not Rule Engine outputs. The mismatch between full profile label and partial negotiated-session inputs is deliberate and makes the task nontrivial, but leaves residual risk that simulator feature patterns encode the rubric. This is not independent human-reviewed security truth.

The selected model is Logistic Regression (15 canonical runtime features: 11 categorical and 4 numeric). The fixed split groups by generated endpoint-configuration fingerprint: train 6,390 rows / 303 groups; validation 1,735 / 102; test 1,875 / 103. There are 508 distinct groups total; all five rows from a group stay together. Grouping repeated configuration fingerprints means these are not 60/20/20 exact row proportions. Classes are balanced globally at 2,500 each; test supports are LOW 570, MEDIUM 475, HIGH 520, CRITICAL 310.

Hyperparameters were searched on training rows and selected by the frozen grouped validation split; the held-out test was not used for selection. The grid compared Logistic Regression C values 0.1–10 with balanced/unweighted classes and Random Forest tree count/depth/leaf-size settings. Best validation macro-F1 was 0.490 for Logistic Regression (C=0.1, balanced weights) and 0.473 for Random Forest; Logistic Regression remained selected. On held-out test: accuracy 0.513, macro-F1 0.511, versus majority-class macro-F1 0.071. Per-class precision/recall/F1: LOW 0.806/0.351/0.489, MEDIUM 0.500/0.507/0.504, HIGH 0.676/0.629/0.651, CRITICAL 0.293/0.626/0.400. Confusion matrix, actual rows and predicted columns in LOW/MEDIUM/HIGH/CRITICAL order: `[[200,61,7,302],[48,241,74,112],[0,140,327,53],[0,40,76,194]]`. These metrics describe held-out groups inside this designed simulator only; they do not establish real-world performance or prevalence. In particular, LOW recall and CRITICAL precision show substantial confusion.

On the existing 110 synthetic PCAP sidecars, the v2 model was applicable to IMAP/POP3 (22 each), and correctly returned NOT_APPLICABLE for SMTP under the route. Predictions were skewed HIGH/CRITICAL on IMAP (15/22 HIGH, 6/22 CRITICAL) and CRITICAL on POP3 (21/22), demonstrating distribution/target mismatch rather than validated PCAP accuracy. The sidecar audit checks runtime behavior only; these captures are not an independent held-out evaluation cohort for v2.

Successful runtime classifier/anomaly results expose a prediction/flag, model ID/name/version, feature coverage, data source/cohort, and explicitly uncalibrated class scores where available. The synthetic v2 classifier includes its heldout simulator metrics and the real-ZGrab evidence-rubric result names its rubric target and unvalidated cohort transfer. Certificate novelty exposes its score, flag, coverage, provenance and a coarse unseen-configuration cue. Anomaly and novelty values remain cohort-relative and are not probabilities. The fresh parser run processed 110 synthetic PCAPs into 116 streams (SMTP 68, IMAP 24, POP3 24), including TLS-less sessions, with zero analysis failures. The primary real-ZGrab evidence-rubric classifier returned an advisory result for all 68 SMTP sessions; synthetic v2 returned NOT_APPLICABLE for SMTP and completed experimentally for all 24 IMAP and 24 POP3 sessions. SMTP-only outputs were NOT_APPLICABLE on all 48 IMAP/POP3 streams. Certificate novelty ran where a leaf was observable (31 SMTP, 1 IMAP, 1 POP3) and returned NOT_EVALUABLE otherwise. Legacy proxy classifiers completed on 24 SMTP, abstained for low feature coverage on 7, and were not evaluable on 37. SMTP anomaly/rarity completed on 59 SMTP sessions and were not evaluable on 9. These counts verify runtime execution/applicability, not predictive accuracy. Full output: `models/synthetic_pcap_runtime_coverage_v5.json`.

Validation tests: 42 ML/runtime/artifact/posture/store/threat/cohort/mock-model tests passed using `unittest`; all 7 API tests passed separately. The controlled novelty benchmark's provenance/metric regression assertions passed. Dedicated mock tests load all 10 registered artifacts on missing and populated feature rows, check a known-seen versus injected-unseen SMTP TLS tuple, and check known versus injected-unseen certificate configurations. The synthetic sidecar audit covers all 110 scenarios, and the fresh parser-to-PCAP audit covers all 110 captures/116 streams, all protocols, TLS-less sessions and the updated classifier routing. These checks establish execution/applicability and response to controlled cases, not real-world predictive effectiveness.

The validation grid was run only for the two routed supervised classifiers, using their frozen validation partitions. Legacy proxy models were not tuned because their target is deterministic-rule agreement, not independent security risk. Isolation Forest contamination settings were not tuned against synthetic injections: there are no independent anomaly labels, and optimizing to our own mock cases would make the reported hit rate circular. All ten registered artifacts were nevertheless exercised with mock feature rows for missing-data and inference smoke coverage.

## Provenance and Limitations

- Real ZGrab observations: 1,600 SMTP targets; 530 completed TLS handshakes/certificates. They are active scan observations, not passive captured enterprise traffic.
- Real ZGrab evidence-rubric classifier: 1,600 source rows, of which 1,524 received rubric labels and 76 were not evaluable; no synthetic rows or Rule Engine outputs were used for its training target.
- Real HTTPS PCAP corpus: 41,205 TLS 1.3 observations; used only for general-TLS novelty.
- MTA-STS-derived certificate set: 21,490 parsed observations, 9,459 unique leaf certificates; not complete handshakes.
- Synthetic email testbed: 110 current captures used for testing only; never counted as real observations.
- New synthetic research cohort: 10,000 generated feature-level sessions, 2,000 profile instances, 0 real observations; SMTP 3,332, IMAP 3,336, POP3 3,332. It is not 10,000 captures and does not add real-world evidence.
- NVD / CISA KEV / EPSS are enrichment data, not classifier labels. Do not attach CVEs without a supported product/version mapping.
- No independent human-reviewed SMTP risk labels or anomaly labels exist. Report proxy target semantics and cohort beside every model result. The 530 ZGrab certificates contribute certificate features to the supervised SMTP cohort; the certificate novelty reference is the distinct scan/HTTP-context corpus, and observable PCAP leaf certificates are scored against that named cohort at runtime.
- Novelty is not insecurity; classifier score is not a probability; Rule Engine findings remain authoritative.

See `FEATURE_LABEL_CONTRACT.md` for feature schemas, exclusions, split details, and training commands. Per-model hashes and exact metadata are in `models/*.json`.
