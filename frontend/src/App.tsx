import { ResearchReport } from './ResearchReport'
import { Workspace } from './Workspace'

function Brand({ compact = false }: { compact?: boolean }) {
  return <a className={`brand ${compact ? 'brand-compact' : ''}`} href="/" aria-label="SecureMailScope home">
    <span><strong>SecureMailScope</strong></span>
  </a>
}

function Landing() {
  return <main className="landing">
    <header className="landing-header"><Brand /></header>
    <section className="landing-hero">
      <div className="hero-copy">
        <h1>See what the<br /><em>mail session</em><br />actually negotiated.</h1>
        <p className="hero-description">A forensic workspace for examining the cryptographic posture of SMTP, IMAP, and POP3 traffic—from packet evidence to policy findings.</p>
        <div className="hero-actions">
          <a className="button button-primary" href="/workspace">Open analysis workspace <span aria-hidden="true">↗</span></a>
          <a className="button button-secondary" href="/technical-report">Read the technical report <span aria-hidden="true">→</span></a>
        </div>
        <p className="hero-footnote">PCAP / PCAPNG <span>·</span> No active scanning <span>·</span> Rule findings kept separate from ML</p>
      </div>
      <div className="hero-figure" aria-label="Analysis pipeline: packet capture, session reconstruction, security assessment, evidence report">
        <div className="figure-topline"><span>ANALYSIS PATH</span><span>01 — 04</span></div>
        <div className="flow-step"><span className="flow-index">01</span><div><b>Packet evidence</b><small>PCAP · PCAPNG</small></div><span className="flow-glyph">⌁</span></div>
        <div className="flow-connector" />
        <div className="flow-step"><span className="flow-index">02</span><div><b>Session reconstruction</b><small>TCP · SMTP · IMAP · POP3</small></div><span className="flow-glyph">⇄</span></div>
        <div className="flow-connector split" />
        <div className="flow-branches"><div className="flow-branch"><span className="branch-rule">RULE ENGINE</span><small>Deterministic policy checks</small></div><div className="flow-branch"><span className="branch-ml">ML LAYER</span><small>Advisory risk & novelty</small></div></div>
        <div className="flow-connector merge" />
        <div className="flow-step report-step"><span className="flow-index">04</span><div><b>Evidence-backed report</b><small>Findings · coverage · limitations</small></div><span className="flow-glyph">↗</span></div>
        <div className="figure-bottom"><span>● SYSTEM READY</span></div>
      </div>
    </section>
    <footer className="landing-footer"><span>SMART INDIA HACKATHON · SECUREMAILSCOPE</span><span>PCAP IN <i /> EVIDENCE OUT</span></footer>
  </main>
}

export default function App() {
  const path = window.location.pathname.replace(/\/$/, '') || '/'
  if (path === '/technical-report') return <ResearchReport Brand={Brand} />
  if (path === '/workspace') return <Workspace Brand={Brand} />
  return <Landing />
}
