import { ResearchReport } from './ResearchReport'
import { Workspace } from './Workspace'

function Brand({ compact = false }: { compact?: boolean }) {
  return <a className={`brand-home ${compact ? 'brand-home-compact' : ''}`} href="/" aria-label="Return to the project home">HOME <span aria-hidden="true">↗</span></a>
}

function AnalysisDrawing() {
  return <div className="landing-visual" aria-label="Flow from packet capture to evidence-backed security assessment">
    <div className="visual-head"><span>ANALYSIS PATH</span><span>PASSIVE PCAP FORENSICS</span></div>
    <svg viewBox="0 0 720 250" role="img" aria-labelledby="flow-title flow-desc">
      <title id="flow-title">Passive email analysis path</title>
      <desc id="flow-desc">A passive capture is reconstructed into sessions, assessed in parallel by the deterministic rule engine and advisory ML, then joined in an evidence report.</desc>
      <path className="flow-track" d="M101 126H232M292 126H355M355 126 424 75M355 126 424 177M480 75H548V126M480 177H548V126M548 126H619"/>
      <circle className="flow-junction" cx="355" cy="126" r="3.5"/><circle className="flow-junction" cx="548" cy="126" r="3.5"/>
      <circle className="flow-pulse" r="4" opacity="0"><animateMotion path="M101 126H355L424 75H548V126H619" dur="4.6s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.03;.995;1" dur="4.6s" repeatCount="indefinite"/></circle>
      <circle className="flow-pulse" r="4" opacity="0"><animateMotion path="M101 126H355L424 177H548V126H619" dur="4.6s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;1;0" keyTimes="0;.03;.995;1" dur="4.6s" repeatCount="indefinite"/></circle>
      <g className="flow-node" transform="translate(70 126)"><circle r="30"/><path d="M-10 -9h20v18h-20zM-6 -14v5m12-5v5m-12 18v5m12-5v5"/><text y="63">CAPTURE</text><text y="81">PCAP / PCAPNG</text></g>
      <g className="flow-node" transform="translate(262 126)"><circle r="30"/><path d="M-12 -7h24v17h-24zM-7 -13h14M-7 16h14"/><text y="63">RECONSTRUCT</text><text y="81">TCP · MAIL · TLS</text></g>
      <g className="flow-node" transform="translate(455 75)"><text className="flow-label-top" y="-39">RULE ENGINE</text><circle r="25"/><path d="M-10 -8h20M-10 0h13M-10 8h17"/><text y="49">Deterministic findings</text></g>
      <g className="flow-node flow-node-ml" transform="translate(455 177)"><circle r="25"/><path d="M-10 8l7-9 6 5 9-13"/><text y="49">ML LAYER</text><text y="67">Risk · anomaly · novelty</text></g>
      <g className="flow-node flow-node-output" transform="translate(650 126)"><circle r="30"/><path d="M-10 -12h15l6 6v18h-21zM5-12v7h6M-5 1h12M-5 7h9"/><text y="63">EVIDENCE</text><text y="81">Findings + context</text></g>
    </svg>
    <div className="visual-foot"><span>RULE FINDINGS REMAIN AUTHORITATIVE</span><span>ML IS ADVISORY</span></div>
  </div>
}

function Landing() {
  return <main className="landing-page">
    <header className="landing-header"><Brand/><nav aria-label="Main"><a href="#method">How it works</a><a href="/technical-report">Technical report</a></nav><div className="landing-header-actions"><a href="/workspace" className="landing-open">Open workspace <span>↗</span></a><a href="https://github.com/Ben160804/SES-v1/tree/master/testbed/captures" className="landing-open" target="_blank" rel="noreferrer">Test data <span>↗</span></a></div></header>
    <section className="landing-hero">
      <div className="hero-copy">
        <div className="hero-index"><span/> PASSIVE PCAP ANALYSIS · EMAIL TRANSPORT SECURITY</div>
        <h1>Email transport<br/>security <em>analysis.</em></h1>
        <p>Analyze SMTP, IMAP, and POP3 captures. Reconstruct sessions, inspect STARTTLS and TLS negotiation, parse visible certificate data, and evaluate each stream against deterministic policy checks.</p>
        <div className="hero-actions"><a className="button button-primary" href="/workspace">Analyze a capture <span>↗</span></a><a className="hero-text-link" href="/technical-report">Read the research report <span>→</span></a></div>
        <div className="hero-note"><span>01</span> No active probing <i/> <span>02</span> Findings stay evidence-linked <i/> <span>03</span> ML stays advisory</div>
      </div>
      <AnalysisDrawing/>
    </section>
    <section className="landing-method" id="method">
      <div className="method-lead"><span className="section-index">ANALYSIS PIPELINE</span><h2>From packet capture<br/><span>to evidence-based results.</span></h2><p>Protocol observations, deterministic policy checks, posture summaries, and advisory ML outputs are calculated separately and linked to the analyzed stream.</p></div>
      <div className="method-rows">
        <article><span>01</span><div><h3>Reconstruct protocol sessions</h3><p>Reassemble TCP streams, identify SMTP, IMAP, and POP3, and track STARTTLS or implicit TLS state and handshake evidence.</p></div></article>
        <article><span>02</span><div><h3>Evaluate cryptographic configuration</h3><p>Extract negotiated TLS version, cipher suite, key exchange, forward-secrecy indicators, and available X.509 certificate fields. Apply deterministic policy checks.</p></div></article>
        <article><span>03</span><div><h3>Report assessment results</h3><p>Present stream evidence, policy outcomes, deterministic posture, and separate advisory ML estimates with feature coverage, data provenance, and limitations.</p></div></article>
      </div>
    </section>
    <section className="landing-proof"><div><span className="section-index">CASE EVIDENCE</span><h2>Inspect each stream<br/>and its assessment.</h2></div><div className="proof-detail"><p>Review reconstructed protocol state, negotiated TLS parameters, visible certificate data, policy findings, posture summaries, and advisory ML outputs. Export case results as JSON, HTML, or PDF.</p><a href="/technical-report">Read the architecture, datasets, and evaluation <span>↗</span></a></div></section>
    <footer className="landing-footer"><Brand compact/><span>PASSIVE PCAP FORENSICS · SIH26159</span><a href="/workspace">Open analysis workspace ↗</a></footer>
  </main>
}

export default function App() {
  const path = window.location.pathname.replace(/\/$/, '') || '/'
  if (path === '/technical-report') return <ResearchReport Brand={Brand} />
  if (path === '/workspace') return <Workspace Brand={Brand} />
  return <Landing />
}
