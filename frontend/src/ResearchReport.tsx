import type { ComponentType, ReactNode } from 'react'

type Props = { Brand: ComponentType<{ compact?: boolean }> }

function PipelineDiagram() {
  return <div className="diagram-frame">
    <svg className="pipeline-svg" viewBox="0 0 1040 365" role="img" aria-labelledby="pipeline-title pipeline-desc">
      <title id="pipeline-title">Forensic analysis architecture</title>
      <desc id="pipeline-desc">A packet capture is reconstructed into TCP and email protocol sessions, TLS and certificate evidence, then assessed separately by deterministic rules and advisory machine learning before producing a report.</desc>
      <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8" fill="none" stroke="#e82e3e" strokeWidth="1.3" /></marker></defs>
      <g className="diagram-label"><text x="28" y="33">INPUT</text><text x="271" y="33">RECONSTRUCTION</text><text x="531" y="33">ANALYSIS</text><text x="842" y="33">OUTPUT</text></g>
      <g className="diagram-node"><rect x="24" y="100" width="170" height="124" rx="4" /><text x="45" y="140" className="node-step">01 / CAPTURE</text><text x="45" y="174" className="node-title">PCAP / PCAPNG</text><text x="45" y="199" className="node-sub">Packet bytes + timestamps</text></g>
      <g className="diagram-node"><rect x="253" y="65" width="210" height="194" rx="4" /><text x="275" y="103" className="node-step">02 / SESSION MODEL</text><text x="275" y="139" className="node-title">TCP streams</text><text x="275" y="164" className="node-sub">Ordering · gaps · provenance</text><line x1="275" y1="184" x2="441" y2="184" className="node-line"/><text x="275" y="211" className="node-title">SMTP · IMAP · POP3</text><text x="275" y="236" className="node-sub">STARTTLS · implicit TLS</text></g>
      <g className="diagram-node"><rect x="520" y="65" width="230" height="194" rx="4" /><text x="542" y="103" className="node-step">03 / EVIDENCE</text><text x="542" y="139" className="node-title">TLS handshake</text><text x="542" y="164" className="node-sub">Version · cipher · key exchange</text><line x1="542" y1="184" x2="728" y2="184" className="node-line"/><text x="542" y="211" className="node-title">X.509 certificate</text><text x="542" y="236" className="node-sub">Path · time · identity · key</text></g>
      <g className="diagram-node"><rect x="820" y="65" width="194" height="194" rx="4" /><text x="842" y="103" className="node-step">04 / ASSESS</text><text x="842" y="139" className="node-title">Rule engine</text><text x="842" y="164" className="node-sub">Deterministic policy findings</text><line x1="842" y1="184" x2="992" y2="184" className="node-line"/><text x="842" y="211" className="node-title">ML layer</text><text x="842" y="236" className="node-sub">Advisory classification / novelty</text></g>
      <path d="M194 162 H246" className="diagram-arrow" markerEnd="url(#arrow)"/><path d="M463 162 H513" className="diagram-arrow" markerEnd="url(#arrow)"/><path d="M750 162 H813" className="diagram-arrow" markerEnd="url(#arrow)"/>
      <path d="M916 259 V313 H520" className="diagram-arrow" markerEnd="url(#arrow)"/><g className="diagram-output"><rect x="337" y="294" width="365" height="49" rx="3"/><text x="365" y="324">EVIDENCE-LINKED REPORT · JSON / HTML / PRINT</text></g>
      <text x="27" y="336" className="diagram-note">PASSIVE INPUT · NO SCANNING · UNKNOWN IS PRESERVED AS UNKNOWN</text>
    </svg>
  </div>
}

function Section({ id, index, title, children }: { id: string; index: string; title: string; children: ReactNode }) {
  return <section id={id} className="paper-section"><div className="paper-section-label"><span>{index}</span><i /></div><div><h2>{title}</h2>{children}</div></section>
}

export function ResearchReport({ Brand }: Props) {
  return <div className="paper-site">
    <header className="paper-header"><Brand compact /><div className="paper-actions"><a href="/workspace" className="paper-link">Analysis workspace <span>↗</span></a><button className="icon-button print-button" onClick={() => window.print()} aria-label="Print or save the technical report as PDF">PRINT / SAVE PDF</button></div></header>
    <div className="paper-layout">
      <aside className="paper-index"><span className="index-heading">ON THIS PAGE</span><a href="#abstract">Abstract</a><a href="#architecture">System architecture</a><a href="#method">Methodology</a><a href="#data">Data & provenance</a><a href="#evaluation">Evaluation</a><a href="#limitations">Limitations</a><a href="#references">References</a></aside>
      <article className="paper">
        <div className="paper-kicker"><span>SIH26159</span><span>TECHNICAL REPORT · 2026</span><span>VERSION 1.0</span></div>
        <h1>Email transport forensics</h1>
        <p className="paper-deck">Passive cryptographic forensics for SMTP, IMAP, and POP3 communications.</p>
        <div className="paper-rule" />
        <Section id="abstract" index="00" title="Abstract">
          <p className="paper-lead">Email transports negotiate encryption in the packets that incident responders already collect. This framework reconstructs those sessions, evaluates cryptographic evidence against deterministic policy rules, and adds advisory machine-learning outputs for risk classification and cohort-relative novelty.</p>
          <p>The framework accepts PCAP and PCAPNG input; reconstructs TCP streams and mail-protocol upgrade transitions; extracts observable TLS and certificate properties; and stores per-stream evidence, policy findings, posture assessments, and ML results. The design keeps unknown or unavailable observations explicit. It does not actively connect to endpoints.</p>
          <div className="keyword-line"><b>KEYWORDS</b> Passive forensics · STARTTLS · TLS · X.509 · email security · anomaly detection</div>
        </Section>
        <Section id="architecture" index="01" title="System architecture">
          <p>The analysis path separates byte reconstruction, deterministic evaluation, and learned intelligence. The Rule Engine remains authoritative for standards-based findings; ML results are presented alongside it and never replace or suppress a rule verdict.</p>
          <PipelineDiagram />
          <div className="paper-callout"><b>Design boundary</b><span>Rule findings answer whether observed evidence violates a stated policy. ML outputs estimate a rubric category or describe novelty relative to a named cohort. They are different signals and remain separately visible.</span></div>
        </Section>
        <Section id="method" index="02" title="Analysis methodology">
          <div className="method-grid">
            <div><span className="method-number">2.1</span><h3>Capture and session reconstruction</h3><p>Packets are grouped by TCP flow and reassembled with sequence and direction context. Protocol identification uses stream evidence, with port numbers treated as hints. SMTP, IMAP, and POP3 state machines identify STARTTLS or STLS advertisements, requests, and outcomes.</p></div>
            <div><span className="method-number">2.2</span><h3>TLS and certificate analysis</h3><p>When handshake bytes are available, the parser records negotiated version, cipher suite, and key-exchange evidence. Observable X.509 certificates are parsed for identity, validity, key algorithm and size, signature, chain, and extensions. Encrypted or absent certificate data is marked unavailable.</p></div>
            <div><span className="method-number">2.3</span><h3>Deterministic security assessment</h3><p>The Rule Engine evaluates protocol, cipher, key-exchange, forward-secrecy, STARTTLS, certificate, and policy-profile conditions. Findings retain identifiers, evidence, applicability, and verdicts. A separate posture rubric summarizes evaluated finding families and is explicitly a heuristic, not a probability.</p></div>
            <div><span className="method-number">2.4</span><h3>Advisory ML analysis</h3><p>The SMTP classifier is trained on a documented rubric applied to real ZGrab observations; the IMAP/POP3 classifier is trained on a separately generated simulation cohort. SMTP configuration rarity and certificate novelty are cohort-relative. The HTTPS model is kept separate from email traffic.</p></div>
          </div>
        </Section>
        <Section id="data" index="03" title="Datasets and provenance">
          <p>Each corpus is used only for the task it supports. Real, simulated, and non-email TLS observations are not merged under a single provenance label.</p>
          <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Corpus</th><th>Observations</th><th>Use</th><th>Provenance / boundary</th></tr></thead><tbody>
            <tr><td>ZGrab SMTP</td><td>1,600 scans; 530 TLS handshakes</td><td>SMTP classifier; SMTP novelty reference</td><td>Real active scans; not passive enterprise PCAPs</td></tr>
            <tr><td>Generated email feature cohort</td><td>10,000 simulated rows; 2,000 profiles</td><td>IMAP/POP3 classifier training</td><td>Synthetic feature simulation; 0 real observations</td></tr>
            <tr><td>Controlled email captures</td><td>110 PCAP scenarios</td><td>Parser, runtime, and regression coverage</td><td>Synthetic; not counted as real traffic</td></tr>
            <tr><td>HTTPS TLS PCAP cohort</td><td>41,205 TLS observations</td><td>Separate HTTPS novelty model</td><td>Real HTTPS; not email traffic</td></tr>
            <tr><td>SMTP-related certificate corpus</td><td>21,490 observations; 9,459 unique certificates</td><td>Certificate novelty reference</td><td>Scan/HTTP context; not complete SMTP handshakes</td></tr>
            <tr><td>NVD / CISA KEV / EPSS</td><td>Threat-intelligence records</td><td>Explicit CVE enrichment</td><td>Not classifier training labels; no CVE inferred from a cipher alone</td></tr>
          </tbody></table></div>
        </Section>
        <Section id="evaluation" index="04" title="Model evaluation">
          <p>Supervised splits keep related groups together. ZGrab evaluation groups by country; simulated email rows group by endpoint-configuration fingerprint. Hyperparameter selection uses validation data, and test data is held out.</p>
          <div className="metric-grid">
            <div className="metric-card"><span>SMTP · ZGRAB RUBRIC</span><strong>0.944</strong><small>Test macro-F1 · 383 test rows</small><p>Test accuracy 0.990. Target labels are rubric-derived, not independent security truth.</p></div>
            <div className="metric-card"><span>IMAP / POP3 · SIMULATION</span><strong>0.511</strong><small>Test macro-F1 · 1,875 test rows</small><p>Zero real training observations. Results describe generalization within the designed simulator.</p></div>
            <div className="metric-card metric-card-wide"><span>COHORT NOVELTY · CONTROLLED FEATURE INJECTIONS</span><strong>Not real-world accuracy</strong><small>Separate held-out controls and deliberately altered mock variants</small><p>Certificate and HTTPS injection tests verify response to synthetic out-of-cohort changes. They do not measure attack detection, security, or operational false-positive rates. SMTP exact-tuple support is a lookup self-check, not an independent benchmark.</p></div>
          </div>
          <p className="metric-footnote">Classifier scores are not calibrated compromise probabilities. The SMTP risk target is a documented evidence rubric. The synthetic classifier remains experimental; active-scan to passive-PCAP transfer has not been validated.</p>
        </Section>
        <Section id="limitations" index="05" title="Limitations and responsible interpretation">
          <ul className="paper-list"><li><b>Visibility is capture-dependent.</b> Packet loss, truncation, missing directions, and encrypted TLS 1.3 certificate messages can limit what can be concluded.</li><li><b>Rule results and ML results are distinct.</b> A classifier estimate cannot overturn a deterministic policy finding.</li><li><b>Novelty is not insecurity.</b> Rare secure settings can be unusual; common insecure settings can be familiar to a cohort.</li><li><b>Training labels are bounded.</b> The ZGrab classifier predicts its stated rubric. The IMAP/POP3 model is simulation-trained. Neither is established as production-grade risk prediction.</li><li><b>Threat context needs an evidenced mapping.</b> KEV and EPSS prioritize supplied CVEs; the system does not invent CVE links from cryptographic properties.</li><li><b>Recommendations are evidence-linked policy guidance.</b> No LLM-generated finding or recommendation is presented as an observed fact.</li></ul>
        </Section>
        <Section id="references" index="06" title="Standards and project records">
          <ol className="references"><li><a href="https://www.rfc-editor.org/rfc/rfc3207" target="_blank" rel="noreferrer">RFC 3207 — SMTP Service Extension for Secure SMTP over TLS</a></li><li><a href="https://www.rfc-editor.org/rfc/rfc8446" target="_blank" rel="noreferrer">RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3</a></li><li><a href="https://csrc.nist.gov/pubs/sp/800/52/r2/final" target="_blank" rel="noreferrer">NIST SP 800-52 Rev. 2 — Guidelines for the Selection, Configuration, and Use of TLS</a></li><li><a href="https://csrc.nist.gov/pubs/sp/800/131/a/r2/final" target="_blank" rel="noreferrer">NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths</a></li><li><a href="https://wiki.mozilla.org/Security/Server_Side_TLS" target="_blank" rel="noreferrer">Mozilla Server Side TLS Guidelines</a></li><li>Project validation records: <code>datasets/ml/ML_VALIDATION_REPORT.md</code>, <code>datasets/ml/FEATURE_LABEL_CONTRACT.md</code>, and the dataset metadata under <code>datasets/ml/metadata/</code>.</li></ol>
          <p className="paper-endnote">This report distinguishes implemented functionality from validation strength. Dataset counts and model metrics reflect the local project artifacts; consult the linked validation record before making performance claims.</p>
        </Section>
        <footer className="paper-footer"><Brand compact /><span>TECHNICAL REPORT · SIH26159</span></footer>
      </article>
    </div>
  </div>
}
