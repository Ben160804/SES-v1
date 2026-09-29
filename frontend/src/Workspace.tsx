import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type DragEvent, type ReactNode, type RefObject } from 'react'
import { api, uploadAnalysis, type AnalysisDetail, type AnalysisReport, type AnalysisSummary, type DashboardSummary, type PolicyResult, type StreamReport, type ThreatPrioritization } from './lib/api'

type Props = { Brand: ComponentType<{ compact?: boolean }> }
type Tab = 'overview' | 'captures' | 'investigation' | 'intelligence' | 'reports'
type InvestigationView = 'findings' | 'sessions' | 'timeline'
type QueueStatus = 'queued' | 'uploading' | 'analyzing' | 'stored' | 'failed' | 'cancelled'
type QueueItem = { key: string; file: File; status: QueueStatus; sent: number; total: number; error?: string; runId?: string }

const MAX_UPLOAD = 512 * 1024 * 1024
const NAV: Array<{ id: Tab; label: string; glyph: string }> = [
  { id: 'overview', label: 'Overview', glyph: '◫' },
  { id: 'captures', label: 'Capture intake', glyph: '⇧' },
  { id: 'investigation', label: 'Investigation', glyph: '⌕' },
  { id: 'intelligence', label: 'Threat context', glyph: '⌁' },
  { id: 'reports', label: 'Reports', glyph: '↗' },
]

const isObject = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value))
const text = (value: unknown, fallback = 'Not observable') => value === null || value === undefined || value === '' ? fallback : typeof value === 'string' ? value : String(value)
const runTime = (value: string) => new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const bytes = (n: number) => n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} KB` : `${(n / (1024 * 1024)).toFixed(1)} MB`
const pretty = (value: unknown) => JSON.stringify(value, null, 2)

function flattenStreams(report: AnalysisReport | null): StreamReport[] {
  if (!report?.stream_reports) return []
  return Object.entries(report.stream_reports).map(([key, value]) => ({ ...value, stream_id: Number(key) }))
}
function reportWithoutModelCodenames(report: AnalysisReport): AnalysisReport {
  const cleanValue = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(cleanValue)
    if (!isObject(value)) return value
    return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "model_id").map(([key, nested]) => [key, cleanValue(nested)]))
  }
  const streamReports = Object.fromEntries(Object.entries(report.stream_reports).map(([id, stream]) => {
    const results = stream.ml_results ?? {}
    const friendlyResults = Object.fromEntries(Object.entries(results).map(([key, value]) => [ML_DISPLAY_NAMES[key] ?? "Additional ML signal", cleanValue(value)]))
    return [id, { ...stream, ml_results: friendlyResults }]
  }))
  return { ...report, stream_reports: streamReports }
}
function failedRules(stream: StreamReport): PolicyResult[] {
  return Object.values(stream.policy_results ?? {}).flat().filter((item) => item.verdict === 'FAIL')
}
function findingsCount(stream: StreamReport) {
  return failedRules(stream).length + (stream.observations ?? []).filter((item) => item.detected).length
}
function allFindings(report: AnalysisReport | null) {
  return flattenStreams(report).flatMap((stream) => [
    ...failedRules(stream).map((rule) => ({ stream, kind: 'POLICY' as const, title: rule.name ?? rule.rule_id ?? 'Policy finding', severity: rule.verdict ?? 'FAIL', note: rule.finding ?? '', id: rule.rule_id ?? 'RULE' })),
    ...(stream.observations ?? []).filter((item) => item.detected).map((item) => ({ stream, kind: 'OBSERVATION' as const, title: item.name ?? item.obs_id ?? 'Observation', severity: 'OBSERVED', note: item.description ?? '', id: item.obs_id ?? 'OBS' })),
  ])
}

function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) { return <span className={`badge ${tone}`}>{children}</span> }
function semanticTone(value: unknown) {
  const textValue = String(value ?? '').toUpperCase()
  if (/CRITICAL|HIGH|FAIL|ERROR|EXPIRED|REJECTED/.test(textValue)) return 'badge-red'
  if (/MEDIUM|NOVEL|UNSEEN|WARNING|PARTIAL|NOT_EVALUABLE/.test(textValue)) return 'badge-amber'
  if (/LOW|PASS|NORMAL|WITHIN_REFERENCE|COMPLETED|READY|DETECTED/.test(textValue)) return 'badge-green'
  if (/OBSERVED|INFO|APPLICABLE|ADVISORY/.test(textValue)) return 'badge-blue'
  return 'badge-muted'
}
function mlStatusLabel(value: unknown) {
  const status = String(value ?? '').toUpperCase()
  if (status.startsWith('COMPLETED_ADVISORY')) return 'Available · advisory estimate'
  if (status.startsWith('COMPLETED_EXPLORATORY_PROXY')) return 'Available · exploratory proxy'
  if (status.startsWith('COMPLETED_EXPLORATORY')) return 'Available · exploratory'
  if (status.startsWith('COMPLETED_EXPERIMENTAL')) return 'Available · experimental, not validated'
  if (status === 'ADVISORY_REAL_ZGRAB_RUBRIC_AVAILABLE') return 'Advisory results available'
  if (status === 'EXPERIMENTAL_SYNTHETIC_RISK_AVAILABLE') return 'Simulated-data estimate available · experimental'
  if (status === 'NOT_EVALUABLE' || status.startsWith('NOT_EVALUABLE_')) return 'Not enough observable data'
  if (status === 'NOT_APPLICABLE') return 'Not applicable to this protocol'
  if (status === 'MODEL_UNAVAILABLE') return 'Model unavailable'
  if (status === 'MODEL_ERROR') return 'Could not produce a result'
  if (status === 'DISABLED') return 'Not run'
  if (!status) return 'No result'
  return status.replaceAll('_', ' ').toLowerCase().replace(/^./, (letter) => letter.toUpperCase())
}
function mlStatusTone(value: unknown) {
  const status = String(value ?? '').toUpperCase()
  if (status === 'MODEL_ERROR' || status === 'MODEL_UNAVAILABLE') return 'badge-red'
  if (status.startsWith('COMPLETED') || status.includes('AVAILABLE')) return 'badge-blue'
  if (status.startsWith('NOT_EVALUABLE')) return 'badge-amber'
  return 'badge-muted'
}
function mlPredictionLabel(value: unknown) {
  if (typeof value === 'boolean') return value ? 'Unusual configuration' : 'Seen configuration'
  const prediction = String(value ?? '').toUpperCase()
  const labels: Record<string, string> = {
    WITHIN_REFERENCE: 'Typical in reference data',
    SEEN_CONFIGURATION: 'Seen in reference data',
    UNSEEN_CONFIGURATION: 'Not seen in reference data',
    NOVEL_RELATIVE_TO_COHORT: 'Unusual versus reference data',
    NOVEL_CONFIGURATION: 'Unseen SMTP configuration',
    HAS_RULE_FLAGGED_ISSUE: 'Resembles rule-flagged examples',
    NO_RULE_FLAGGED_ISSUE: 'No rule-flag pattern estimated',
    KNOWN: 'Seen configuration',
    NOVEL: 'Unusual configuration',
    LOW_OR_MEDIUM: 'Low or medium estimate',
  }
  return labels[prediction] ?? (prediction ? prediction.replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase()) : 'Result unavailable')
}
function SectionTitle({ eyebrow, title, detail, action }: { eyebrow?: string; title: string; detail?: string; action?: ReactNode }) {
  return <div className="section-title"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{detail && <p className="muted">{detail}</p>}</div>{action}</div>
}
function EmptyState({ title, copy, action }: { title: string; copy: string; action?: ReactNode }) { return <div className="empty-state"><span className="empty-glyph">∅</span><h3>{title}</h3><p>{copy}</p>{action}</div> }
function Metric({ label, value, sub }: { label: string; value: string | number; sub?: string }) { return <article className="metric"><span>{label}</span><strong>{value}</strong>{sub && <small>{sub}</small>}</article> }

function ExportActions({ summary, detail }: { summary: AnalysisSummary; detail: AnalysisDetail }) {
  const json = () => {
    const envelope = { report_metadata: { run_id: summary.run_id, source_name: summary.source_name, created_at: summary.created_at, total_streams: summary.total_streams }, report: reportWithoutModelCodenames(detail.report) }
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' })
    downloadBlob(blob, `${safeName(summary.source_name)}-${summary.run_id.slice(0, 8)}.json`)
  }
  const html = () => {
    const report = buildHtmlReport(summary, detail.report)
    const blob = new Blob([report], { type: 'text/html;charset=utf-8' })
    downloadBlob(blob, `${safeName(summary.source_name)}-${summary.run_id.slice(0, 8)}.html`)
  }
  const pdf = () => {
    const printWindow = window.open('', '_blank')
    if (!printWindow) return window.alert('Allow pop-ups for this local application to create a PDF report.')
    printWindow.opener = null
    printWindow.document.write(buildHtmlReport(summary, detail.report, true))
    printWindow.document.close()
    printWindow.focus()
    window.setTimeout(() => printWindow.print(), 300)
  }
  return <div className="button-row"><button className="button button-small" onClick={json}>Export JSON</button><button className="button button-small" onClick={html}>Export HTML</button><button className="button button-small" onClick={pdf}>Save PDF</button></div>
}

function safeName(name: string) { return name.replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '') || 'analysis' }
function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url; link.download = filename; link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
function esc(value: unknown) { return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!) }
function htmlBarChart(title: string, values: Record<string, number>) {
  const rows = Object.entries(values).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...rows.map(([, count]) => count))
  const total = rows.reduce((sum, [, count]) => sum + count, 0)
  if (!rows.length) return `<section class="chart"><h3>${esc(title)}</h3><p>No observations recorded.</p></section>`
  const bars = rows.map(([label, count]) => `<div class="bar-row"><span>${esc(label)}</span><div class="track" aria-hidden="true"><i style="width:${count / max * 100}%"></i></div><b>${count}</b></div>`).join('')
  const table = `<table class="chart-data"><caption>${esc(title)} · ${total} observations</caption><thead><tr><th scope="col">Category</th><th scope="col">Count</th></tr></thead><tbody>${rows.map(([label, count]) => `<tr><th scope="row">${esc(label)}</th><td>${count}</td></tr>`).join('')}</tbody></table>`
  return `<figure class="chart" aria-label="${esc(title)}. ${rows.map(([label, count]) => `${esc(label)}: ${count}`).join(', ')}"><figcaption>${esc(title)}</figcaption><div class="bars">${bars}</div>${table}</figure>`
}
function buildHtmlReport(summary: AnalysisSummary, report: AnalysisReport, print = false) {
  const streams = flattenStreams(report)
  const policyCounts: Record<string, number> = {}
  const protocolCounts: Record<string, number> = {}
  const tlsCounts: Record<string, number> = {}
  const mlCounts: Record<string, number> = {}
  let certificateCount = 0
  let failureCount = 0
  let detectedCount = 0
  for (const stream of streams) {
    protocolCounts[stream.protocol] = (protocolCounts[stream.protocol] ?? 0) + 1
    const snapshot = stream.input_snapshot ?? {}
    const tls = isObject(snapshot.tls) ? snapshot.tls : snapshot
    const version = tls.tls_version ?? tls.tls_selected_version ?? tls.version
    const tlsLabel = version === undefined || version === null || version === '' ? 'TLS not observed' : String(version)
    tlsCounts[tlsLabel] = (tlsCounts[tlsLabel] ?? 0) + 1
    const certificate = isObject(snapshot.certificate) ? snapshot.certificate : snapshot
    if (certificate.observable === true || certificate.certificate_observed === true || isObject(certificate.leaf_cert)) certificateCount++
    for (const items of Object.values(stream.policy_results ?? {})) for (const item of items) {
      const verdict = String(item.verdict ?? 'UNKNOWN')
      policyCounts[verdict] = (policyCounts[verdict] ?? 0) + 1
      if (verdict === 'FAIL') failureCount++
    }
    detectedCount += (stream.observations ?? []).filter((observation) => observation.detected).length
    for (const [key, result] of Object.entries(stream.ml_results ?? {})) {
      if (!isObject(result) || key === 'ml_assessment') continue
      const status = mlStatusLabel(result.status)
      mlCounts[status] = (mlCounts[status] ?? 0) + 1
    }
  }
  const observationCount = streams.reduce((sum, stream) => sum + (stream.observations ?? []).length, 0)
  const sessionRows = streams.map((stream) => {
    const snapshot = stream.input_snapshot ?? {}
    const tls = isObject(snapshot.tls) ? snapshot.tls : snapshot
    const certificate = isObject(snapshot.certificate) ? snapshot.certificate : snapshot
    const leaf = isObject(certificate.leaf_cert) ? certificate.leaf_cert : certificate
    const posture = stream.posture_assessment ?? {}
    const policies = Object.entries(stream.policy_results ?? {}).flatMap(([pack, items]) => items.map((item) => ({ pack, item })))
    const policyRows = policies.map(({ pack, item }) => `<tr><td>${esc(item.name ?? item.rule_id ?? 'Policy check')}</td><td>${esc(policyPackLabel(pack))}</td><td>${esc(item.verdict ?? 'UNKNOWN')}</td><td>${esc(item.finding ?? '—')}</td></tr>`).join('')
    const observations = (stream.observations ?? []).map((item) => `<tr><td>${item.detected ? 'Detected' : 'Not detected'}</td><td>${esc(item.name ?? 'Observation')}</td><td>${esc(item.description ?? '—')}</td></tr>`).join('')
    const mlRows = Object.entries(stream.ml_results ?? {}).filter(([key, value]) => key !== 'ml_assessment' && isObject(value)).map(([key, rawResult]) => {
      const result = rawResult as Record<string, unknown>
      const output = result.prediction ?? result.predicted_risk_tier ?? result.predicted_tier_proxy ?? result.predicted_class ?? result.risk_tier ?? result.classification ?? result.label ?? result.novelty_flag
      const score = result.anomaly_score ?? result.novelty_score ?? result.certificate_novelty_score ?? result.confidence_score_uncalibrated
      const coverage = typeof result.feature_coverage === 'number' ? `${Math.round(result.feature_coverage * 100)}%` : '—'
      const confidence = typeof result.confidence_score_uncalibrated === 'number' ? `${Math.round(result.confidence_score_uncalibrated * 100)}% (uncalibrated)` : '—'
      const notes = [result.reason, result.interpretation_note, result.score_semantics, Array.isArray(result.limitations) ? result.limitations[0] : null].filter((part) => typeof part === 'string').join(' ')
      return `<tr><th scope="row">${esc(ML_DISPLAY_NAMES[key] ?? 'Additional ML signal')}</th><td>${esc(String(result.status ?? 'UNKNOWN').startsWith('COMPLETED') && output !== undefined ? mlPredictionLabel(output) : '—')}</td><td>${esc(mlStatusLabel(result.status))}</td><td>${coverage}</td><td>${score === undefined ? '—' : esc(String(Number(score).toPrecision(4)))}${confidence !== '—' ? `<small>${esc(confidence)}</small>` : ''}</td><td>${esc(notes || '—')}</td></tr>`
    }).join('')
    const recs = Array.isArray(posture.findings) ? posture.findings.filter(isObject).filter((item) => typeof item.recommendation === 'string') : []
    const recommendations = recs.length ? `<ul>${recs.map((item) => `<li><b>${esc(item.family)}</b> · ${esc(item.recommendation)}</li>`).join('')}</ul>` : '<p>No evidence-linked mitigation guidance was produced for this session.</p>'
    const tlsFacts: Array<[string, unknown]> = [['Version', tls.tls_version ?? tls.tls_selected_version ?? tls.version], ['Cipher', tls.cipher_name ?? tls.cipher_suite], ['Key exchange', tls.key_exchange ?? tls.tls13_key_exchange_group ?? tls.kex], ['Forward secrecy', tls.forward_secrecy ?? tls.uses_forward_secrecy], ['Encryption transition', tls.starttls_status ?? tls.starttls_outcome ?? tls.status]]
    const certFacts: Array<[string, unknown]> = [['Observed', certificate.observable ?? certificate.certificate_observed], ['Hostname match', certificate.hostname_match], ['Public-key algorithm', leaf.public_key_algorithm ?? leaf.key_algorithm], ['Key size', leaf.public_key_size ?? leaf.key_size_bits], ['Signature algorithm', leaf.signature_algorithm], ['Valid until', leaf.not_after], ['Chain length', certificate.chain_length], ['Revocation', certificate.revocation_status]]
    const factRows = (facts: Array<[string, unknown]>) => facts.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value === undefined || value === null || value === '' ? '—' : sessionValue(label, value))}</dd></div>`).join('')
    return `<section class="session-report"><header><span class="stream-tag">SESSION ${String(stream.stream_id).padStart(3, '0')}</span><h3>${esc(stream.protocol)} communication</h3><p>${policies.filter(({ item }) => item.verdict === 'FAIL').length} policy failures · ${(stream.observations ?? []).filter((item) => item.detected).length} detected observations</p></header><h4>Negotiated transport</h4><dl class="fact-list">${factRows(tlsFacts)}</dl><h4>Certificate and trust evidence</h4><dl class="fact-list">${factRows(certFacts)}</dl><h4>Deterministic posture</h4><p><b>${esc(posture.score ?? '—')} / 100 · ${esc(posture.tier ?? 'Not evaluated')}</b> <span>Rule-based heuristic, not an ML probability.</span></p><h4>Policy checks (${policies.length})</h4><div class="table-wrap"><table><thead><tr><th>Check</th><th>Standard</th><th>Result</th><th>Finding</th></tr></thead><tbody>${policyRows || '<tr><td colspan="4">No policy checks recorded.</td></tr>'}</tbody></table></div><h4>Forensic observations (${(stream.observations ?? []).length})</h4><div class="table-wrap"><table><thead><tr><th>Status</th><th>Observation</th><th>Evidence summary</th></tr></thead><tbody>${observations || '<tr><td colspan="3">No observations recorded.</td></tr>'}</tbody></table></div><h4>Machine-learning signals · advisory</h4><div class="table-wrap"><table><thead><tr><th>Signal</th><th>Estimate</th><th>Availability</th><th>Feature coverage</th><th>Scores</th><th>Interpretation and limitations</th></tr></thead><tbody>${mlRows || '<tr><td colspan="6">No ML outputs were recorded for this session.</td></tr>'}</tbody></table></div><h4>Mitigation guidance</h4>${recommendations}</section>`
  }).join('')
  const findings = streams.flatMap((stream) => failedRules(stream).map((item) => `<article class="finding"><span>STREAM ${String(stream.stream_id).padStart(3, '0')} · ${esc(item.source_id ?? item.policy ?? 'DETERMINISTIC POLICY')}</span><h3>${esc(item.name ?? item.rule_id ?? 'Policy finding')}</h3><p>${esc(item.finding ?? 'A deterministic policy check failed.')}</p>${item.evidence?.length ? `<pre>${esc(pretty(item.evidence))}</pre>` : ''}</article>`)).join('')
  const charts = [htmlBarChart('Reconstructed protocols', protocolCounts), htmlBarChart('Observed TLS versions', tlsCounts), htmlBarChart('Deterministic policy outcomes', policyCounts), htmlBarChart('ML runtime availability', mlCounts)].join('')
  const metrics = `<div class="kpis"><div><small>SESSIONS</small><b>${streams.length}</b></div><div><small>POLICY FAILURES</small><b>${failureCount}</b></div><div><small>DETECTED OBSERVATIONS</small><b>${detectedCount} / ${observationCount}</b></div><div><small>CERTIFICATES OBSERVED</small><b>${certificateCount}</b></div></div>`
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Forensic assessment — ${esc(summary.source_name)}</title><style>
    :root{color-scheme:light;--ink:#202327;--muted:#616873;--line:#d8dce1;--paper:#fff;--accent:#b52131;--soft:#f3f5f7}*{box-sizing:border-box}body{margin:0;background:#eef0f2;color:var(--ink);font:13px/1.55 Inter,Arial,sans-serif}.report{max-width:1080px;margin:28px auto;background:var(--paper);padding:52px 62px 64px;box-shadow:0 4px 30px #17202a12}.masthead{display:flex;justify-content:space-between;align-items:center;padding-bottom:12px;border-bottom:2px solid var(--ink);font-size:9px;letter-spacing:.13em;text-transform:uppercase}.masthead b{color:var(--accent)}.cover{padding:48px 0 28px;border-bottom:1px solid var(--line)}.cover .kicker,.eyebrow{color:var(--accent);font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}.cover h1{max-width:760px;margin:12px 0;font:500 42px/1.08 Georgia,serif;letter-spacing:-.035em}.cover .subhead{max-width:760px;color:var(--muted);font-size:15px}.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 24px;margin-top:28px}.meta-grid div{border-top:1px solid var(--line);padding-top:8px}.meta-grid dt{color:var(--muted);font-size:8px;letter-spacing:.1em;text-transform:uppercase}.meta-grid dd{margin:3px 0 0;font-size:11px;overflow-wrap:anywhere}.notice{margin:18px 0;padding:13px 15px;border-left:3px solid var(--accent);background:var(--soft);color:#38404a;font-size:10px}.section{padding:23px 0;border-bottom:1px solid var(--line)}.section h2{margin:0 0 6px;font:500 24px Georgia,serif;letter-spacing:-.02em}.section .lead{max-width:820px;color:var(--muted);font-size:10px}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin:16px 0}.kpis>div{padding:9px 15px;border-left:1px solid var(--line)}.kpis>div:first-child{border-left:0;padding-left:0}.kpis small{display:block;color:var(--muted);font-size:8px;letter-spacing:.08em}.kpis b{display:block;margin-top:3px;font:500 26px Georgia,serif}.chart-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.chart{min-width:0;margin:0;padding:13px 14px;border:1px solid var(--line);background:#fff;break-inside:avoid}.chart figcaption,.chart h3{margin:0 0 10px;font-size:11px;font-weight:700}.bars{display:grid;gap:7px}.bar-row{display:grid;grid-template-columns:minmax(90px,1fr) minmax(80px,1.6fr) 25px;align-items:center;gap:8px;font-size:9px}.bar-row>span{overflow-wrap:anywhere}.bar-row>b{text-align:right;font-variant-numeric:tabular-nums}.track{height:7px;background:#e9ecef}.track i{display:block;height:100%;min-width:2px;background:#66717c}.bar-row:first-child .track i{background:var(--accent)}.chart-data{margin-top:10px;font-size:8px}.chart-data caption{text-align:left;color:var(--muted);padding-bottom:4px}.chart-data th,.chart-data td{padding:3px 5px;border:0;border-top:1px solid #eef0f2;background:none}.chart-data td{text-align:right;font-variant-numeric:tabular-nums}.table-wrap{width:100%;overflow:visible}table{width:100%;border-collapse:collapse;font-size:9px}thead{display:table-header-group}th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--line)}th{background:#f3f5f7;font-size:8px;letter-spacing:.045em}td small{display:block;color:var(--muted);margin-top:3px}tr{break-inside:avoid}.finding{margin:10px 0;padding:12px 14px;border-left:2px solid var(--accent);background:#faf7f7;break-inside:avoid}.finding>span,.stream-tag{color:var(--accent);font-size:8px;font-weight:700;letter-spacing:.09em}.finding h3{margin:4px 0;font-size:13px}.finding p{margin:0;color:#434a53;font-size:10px}.finding pre{white-space:pre-wrap;font-size:8px;background:#f1f2f4;padding:8px}.session-report{padding:20px 0;border-bottom:1px solid var(--line);break-inside:auto}.session-report>header{padding:0 0 10px;border-bottom:1px solid var(--line)}.session-report>header h3{margin:3px 0;font:500 18px Georgia,serif}.session-report>header p{margin:0;color:var(--muted);font-size:9px}.session-report h4{margin:15px 0 6px;font-size:9px;letter-spacing:.06em;text-transform:uppercase}.fact-list{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:0}.fact-list>div{padding:6px 8px;background:var(--soft)}.fact-list dt{color:var(--muted);font-size:7px;text-transform:uppercase}.fact-list dd{margin:2px 0 0;font-size:9px;overflow-wrap:anywhere}.session-report p{font-size:9px}.session-report ul{font-size:9px}.foot{padding-top:16px;color:var(--muted);font-size:8px}.print-button{display:${print ? 'none' : 'inline-block'};margin-top:20px;padding:9px 14px;border:0;background:var(--ink);color:#fff;font-size:10px;cursor:pointer}@page{size:A4;margin:15mm}@media print{body{background:#fff}.report{max-width:none;margin:0;padding:0;box-shadow:none}.cover{padding-top:30px}.section{break-inside:avoid}.session-report{break-before:page}.print-button{display:none}.chart-grid{gap:7px}.chart{padding:9px}.foot{position:static}}@media(max-width:700px){.report{margin:0;padding:25px 18px}.cover h1{font-size:34px}.meta-grid,.chart-grid,.fact-list{grid-template-columns:repeat(2,1fr)}.kpis{grid-template-columns:repeat(2,1fr)}.kpis>div:nth-child(3){border-left:0}.table-wrap{overflow-x:auto}.table-wrap table{min-width:700px}}
    </style></head><body><main class="report"><div class="masthead"><b>SecureMailScope</b><span>Passive email cryptographic forensics</span><span>Forensic assessment</span></div><header class="cover"><p class="kicker">Case report · ${esc(summary.run_id.slice(0, 12))}</p><h1>Cryptographic posture assessment</h1><p class="subhead">Evidence-led review of reconstructed email sessions, negotiated TLS, certificate visibility, deterministic policy checks, and advisory machine-learning signals.</p><dl class="meta-grid"><div><dt>Capture</dt><dd>${esc(summary.source_name)}</dd></div><div><dt>Analysis time</dt><dd>${esc(runTime(summary.created_at))}</dd></div><div><dt>Case identifier</dt><dd>${esc(summary.run_id)}</dd></div><div><dt>Analysis mode</dt><dd>Passive PCAP inspection</dd></div><div><dt>Reconstructed streams</dt><dd>${streams.length}</dd></div><div><dt>Report scope</dt><dd>Observed packet evidence only</dd></div></dl></header><div class="notice"><b>Interpretation:</b> Rule-engine results are deterministic checks against the configured standards. The posture score is a heuristic, not an ML probability. ML classification and cohort novelty are advisory; an unusual configuration is not, by itself, proof of insecurity. Unobserved certificate or handshake fields remain unknown.</div><section class="section"><p class="eyebrow">01 · Executive summary</p><h2>At a glance</h2>${metrics}<p class="lead">This report describes ${streams.length} reconstructed stream${streams.length === 1 ? '' : 's'} from <b>${esc(summary.source_name)}</b>. It recorded ${failureCount} deterministic policy failure${failureCount === 1 ? '' : 's'}, ${detectedCount} detected forensic observation${detectedCount === 1 ? '' : 's'}, and ${certificateCount} stream${certificateCount === 1 ? '' : 's'} with a certificate visible to passive inspection.</p></section><section class="section"><p class="eyebrow">02 · Observed data</p><h2>Traffic and policy profile</h2><p class="lead">Counts below summarize only the reconstructed streams and checks contained in this report. Each chart also includes a text table for exact values.</p><div class="chart-grid">${charts}</div></section><section class="section"><p class="eyebrow">03 · Findings</p><h2>Deterministic policy findings</h2>${findings || '<p>No deterministic policy failures were recorded. Missing evidence is not interpreted as a pass.</p>'}</section><section class="section"><p class="eyebrow">04 · Session evidence</p><h2>Stream-by-stream record</h2><p class="lead">Transport facts, certificate visibility, every policy result, observations, ML outputs, and available mitigation guidance are separated by reconstructed stream.</p>${sessionRows || '<p>No TCP streams were reconstructed from this capture.</p>'}</section><section class="section"><p class="eyebrow">05 · Method and limitations</p><h2>How to interpret this report</h2><ul><li>Parser and session fields describe evidence available in the supplied capture. Passive capture can omit packets or lack the secrets required to decrypt TLS 1.3 handshake messages.</li><li>Certificate fields are reported only when a certificate was visible and extracted. “Not observed” does not establish that the server has no certificate.</li><li>Policy outcomes are deterministic checks; applicability and observability are reported separately from pass or fail.</li><li>Classifier tiers follow their documented training labels. Uncalibrated confidence is not a probability of compromise or vulnerability.</li><li>Anomaly and certificate novelty compare observed features with a reference cohort. Novelty is not equivalent to maliciousness or insecurity.</li><li>Threat-intelligence enrichment is limited to CVE identifiers explicitly linked to evidence. No vulnerability is inferred from a TLS version, cipher, or certificate property alone.</li></ul><p>Machine-readable structured results are available through the separate JSON export.</p></section><footer class="foot">Generated locally by SecureMailScope · ${esc(summary.run_id)} · Values reflect the saved analysis report and its stated evidence limits.</footer><button class="print-button" onclick="window.print()">Print or save as PDF</button></main></body></html>`
}

export function Workspace({ Brand }: Props) {
  const [tab, setTab] = useState<Tab>(() => {
    const candidate = window.location.hash.split('/').at(-1) as Tab | undefined
    return NAV.some((item) => item.id === candidate) ? candidate! : 'overview'
  })
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([])
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null)
  const [details, setDetails] = useState<Record<string, AnalysisDetail>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [apiState, setApiState] = useState<'checking' | 'online' | 'offline'>('checking')
  const [pageError, setPageError] = useState('')
  const [loading, setLoading] = useState(true)
  const [queue, setQueue] = useState<QueueItem[]>([])
  const [trustStore, setTrustStore] = useState('testbed')
  const [filter, setFilter] = useState('')
  const [selectedStream, setSelectedStream] = useState<number | null>(null)
  const [investigationView, setInvestigationView] = useState<InvestigationView>('findings')
  const [captureSearch, setCaptureSearch] = useState('')
  const [captureSearchOpen, setCaptureSearchOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<AnalysisSummary | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const dragDepth = useRef(0)
  const [dragging, setDragging] = useState(false)
  const aborters = useRef(new Map<string, () => void>())

  const refresh = useCallback(async () => {
    setPageError('')
    try {
      const [health, list] = await Promise.all([api.health(), api.listAnalyses(500)])
      setApiState(health.status === 'ok' ? 'online' : 'offline')
      setAnalyses(list.items)
      try { setDashboard(await api.getOverview()) } catch { setDashboard(null) }
      if (list.items.length) {
        setSelected((current) => current && list.items.some((item) => item.run_id === current) ? current : list.items[0].run_id)
      } else setSelected(null)
      setDetails((current) => {
        const keep = new Set(list.items.map((item) => item.run_id))
        return Object.fromEntries(Object.entries(current).filter(([id]) => keep.has(id)))
      })
    } catch (error) {
      setApiState('offline')
      setPageError(error instanceof Error ? error.message : 'Could not connect to the local analysis service.')
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => {
    const restoreTab = () => {
      const candidate = window.location.hash.split('/').at(-1) as Tab | undefined
      if (NAV.some((item) => item.id === candidate)) setTab(candidate!)
    }
    window.addEventListener('popstate', restoreTab)
    return () => window.removeEventListener('popstate', restoreTab)
  }, [])
  useEffect(() => {
    document.title = `${NAV.find((item) => item.id === tab)?.label ?? 'Workspace'} — Email transport forensics`
  }, [tab])
  useEffect(() => {
    if (!selected || details[selected] || apiState !== 'online') return
    let active = true
    api.getAnalysis(selected).then((detail) => { if (active) setDetails((current) => ({ ...current, [selected]: detail })) })
      .catch((error: unknown) => { if (active) setPageError(error instanceof Error ? error.message : 'Could not load report details.') })
    return () => { active = false }
  }, [selected, details, apiState])

  const activeSummary = analyses.find((item) => item.run_id === selected) ?? null
  const captureMatches = analyses.filter((item) => `${item.source_name} ${item.run_id}`.toLowerCase().includes(captureSearch.trim().toLowerCase())).slice(0, 30)
  const activeDetail = selected ? details[selected] ?? null : null
  useEffect(() => { if (!captureSearchOpen) setCaptureSearch(activeSummary?.source_name ?? '') }, [activeSummary?.source_name, captureSearchOpen])
  const streams = useMemo(() => flattenStreams(activeDetail?.report ?? null), [activeDetail])
  const findingRows = useMemo(() => allFindings(activeDetail?.report ?? null), [activeDetail])
  useEffect(() => {
    if (streams.length && (selectedStream === null || !streams.some((stream) => stream.stream_id === selectedStream))) {
      setSelectedStream(streams[0].stream_id)
    }
  }, [streams, selectedStream])
  const visibleAnalyses = analyses.filter((item) => `${item.source_name} ${item.run_id}`.toLowerCase().includes(filter.toLowerCase()))
  const postureScores = streams.map((stream) => stream.posture_assessment?.score).filter((score): score is number => typeof score === 'number')
  const postureAverage = postureScores.length ? Math.round(postureScores.reduce((sum, score) => sum + score, 0) / postureScores.length) : null

  const addFiles = useCallback((fileList: FileList | File[]) => {
    const incoming = Array.from(fileList)
    const staged: QueueItem[] = incoming.map((file) => {
      const key = `${file.name}:${file.size}:${file.lastModified}:${crypto.randomUUID()}`
      let error: string | undefined
      if (!/\.(pcap|pcapng)$/i.test(file.name)) error = 'Choose a .pcap or .pcapng capture.'
      else if (file.size === 0) error = 'The selected file is empty.'
      else if (file.size > MAX_UPLOAD) error = 'File exceeds the API limit of 512 MiB.'
      return { key, file, status: error ? 'failed' : 'queued', sent: 0, total: file.size, error }
    })
    setQueue((current) => [...current, ...staged])
  }, [])
  const retryItem = useCallback((key: string) => setQueue((current) => current.map((item) => item.key === key ? { ...item, status: 'queued', error: undefined, sent: 0 } : item)), [])
  const removeItem = useCallback((key: string) => setQueue((current) => current.filter((item) => item.key !== key)), [])
  const clearCompleted = useCallback(() => setQueue((current) => current.filter((item) => item.status === 'queued' || item.status === 'uploading' || item.status === 'analyzing')), [])
  const deleteAnalysis = useCallback(async (item: AnalysisSummary) => {
    try {
      await api.deleteAnalysis(item.run_id)
      setDetails((current) => { const next = { ...current }; delete next[item.run_id]; return next })
      setDeleteTarget(null)
      await refresh()
    } catch (error) {
      setPageError(error instanceof Error ? error.message : 'Could not delete the saved analysis.')
    }
  }, [refresh])

  const processQueue = useCallback(async () => {
    for (const item of queue) {
      if (item.status !== 'queued') continue
      setQueue((current) => current.map((row) => row.key === item.key ? { ...row, status: 'uploading' } : row))
      try {
        const result = await uploadAnalysis(item.file, { trustStore }, (sent, total) => {
          setQueue((current) => current.map((row) => row.key === item.key ? { ...row, status: sent >= total ? 'analyzing' : 'uploading', sent, total } : row))
        }, (abort) => aborters.current.set(item.key, abort))
        setQueue((current) => current.map((row) => row.key === item.key ? { ...row, status: 'stored', sent: row.total, runId: result.run_id } : row))
        const detail = await api.getAnalysis(result.run_id)
        setDetails((current) => ({ ...current, [result.run_id]: detail }))
        await refresh()
        setSelected(result.run_id)
      } catch (error) {
        setQueue((current) => current.map((row) => row.key === item.key ? { ...row, status: (error instanceof Error && error.message === 'Upload cancelled.') ? 'cancelled' : 'failed', error: error instanceof Error ? error.message : 'Capture analysis failed.' } : row))
      } finally { aborters.current.delete(item.key) }
    }
  }, [queue, refresh, trustStore])

  const queueBusy = queue.some((item) => item.status === 'uploading' || item.status === 'analyzing')
  const hasQueued = queue.some((item) => item.status === 'queued')
  const acceptDrop = (event: DragEvent) => { event.preventDefault(); dragDepth.current = 0; setDragging(false); if (event.dataTransfer.files.length) addFiles(event.dataTransfer.files) }

  const navTo = (next: Tab) => { setTab(next); if (next === 'investigation') setInvestigationView('findings'); setPageError(''); window.history.pushState({}, '', `/workspace#/${next}`) }
  return <div className="workspace-shell">
    <aside className="workspace-rail">
      <Brand compact />
      <div className="rail-divider" />
      <span className="rail-label">FORENSIC WORKSPACE</span>
      <nav aria-label="Workspace">
        {NAV.map((item) => <button key={item.id} className={`rail-link ${tab === item.id ? 'active' : ''}`} onClick={() => navTo(item.id)}><span aria-hidden="true">{item.glyph}</span>{item.label}</button>)}
      </nav>
      <div className="rail-bottom"><a href="/technical-report">Technical report <span>↗</span></a><div className="api-health"><i className={apiState === 'online' ? 'online' : apiState === 'offline' ? 'offline' : ''} /> API {apiState === 'checking' ? 'CHECKING' : apiState.toUpperCase()}</div><small>LOCAL ANALYSIS INSTANCE</small></div>
    </aside>
    <main className="workspace-main" onDragEnter={(event) => { event.preventDefault(); dragDepth.current += 1; setDragging(true) }} onDragLeave={(event) => { event.preventDefault(); dragDepth.current -= 1; if (dragDepth.current <= 0) setDragging(false) }} onDragOver={(event) => event.preventDefault()} onDrop={acceptDrop}>
      <header className="workspace-top"><div className="breadcrumbs"><a href="/">WORKSPACE</a><span>/</span><span>{NAV.find((item) => item.id === tab)?.label.toUpperCase()}</span></div><div className="workspace-tools"><div className="capture-picker"><label className="capture-switcher"><span>CURRENT CAPTURE</span><input aria-label="Search captures" aria-expanded={captureSearchOpen} aria-controls="capture-search-results" placeholder={activeSummary?.source_name ?? (analyses.length ? 'Search PCAPs…' : 'No captures analyzed')} value={captureSearch} onFocus={() => { setCaptureSearch(''); setCaptureSearchOpen(true) }} onChange={(event) => { setCaptureSearch(event.target.value); setCaptureSearchOpen(true) }} onBlur={() => window.setTimeout(() => { setCaptureSearchOpen(false); setCaptureSearch(activeSummary?.source_name ?? '') }, 120)} onKeyDown={(event) => { if (event.key === 'Escape') setCaptureSearchOpen(false); if (event.key === 'Enter' && captureMatches.length === 1) { setSelected(captureMatches[0].run_id); setCaptureSearch(captureMatches[0].source_name); setCaptureSearchOpen(false) } }} disabled={!analyses.length}/></label>{captureSearchOpen && analyses.length > 0 && <div className="capture-search-results" id="capture-search-results" role="listbox" aria-label="Matching captures">{captureMatches.length ? captureMatches.map((item) => <button key={item.run_id} type="button" role="option" aria-selected={item.run_id === selected} onMouseDown={(event) => event.preventDefault()} onClick={() => { setSelected(item.run_id); setCaptureSearch(item.source_name); setCaptureSearchOpen(false) }}><b>{item.source_name}</b><small>{item.total_streams} streams · {runTime(item.created_at)} · {item.run_id.slice(0, 8)}</small></button>) : <p>No matching PCAPs</p>}</div>}</div></div></header>
      {pageError && <div role="alert" className="alert alert-error"><span>{pageError}</span><button onClick={() => void refresh()}>Retry</button></div>}
      {apiState === 'offline' && <div className="offline-panel"><span className="offline-mark">!</span><div><b>Analysis service is not reachable.</b><p>Start the local API at <code>127.0.0.1:8000</code>, then retry. The workspace will not show fabricated reports or metrics.</p></div><button className="button button-small" onClick={() => void refresh()}>Retry connection</button></div>}
      <div className="workspace-page-frame" key={tab}>
        {tab === 'overview' && <OverviewPage analyses={analyses} activeSummary={activeSummary} streams={streams} findings={findingRows} postureAverage={postureAverage} dashboard={dashboard} loading={loading} onGo={navTo} onSelect={setSelected} />}
        {tab === 'captures' && <CapturesPage analyses={visibleAnalyses} allCount={dashboard?.capture_count ?? analyses.length} filter={filter} setFilter={setFilter} inputRef={inputRef} queue={queue} addFiles={addFiles} processQueue={processQueue} queueBusy={queueBusy} hasQueued={hasQueued} trustStore={trustStore} setTrustStore={setTrustStore} aborters={aborters.current} retryItem={retryItem} removeItem={removeItem} clearCompleted={clearCompleted} onSelect={setSelected} onDelete={setDeleteTarget} onTab={navTo} />}
        {tab === 'investigation' && <InvestigationPage view={investigationView} setView={setInvestigationView} findings={findingRows} streams={streams} summary={activeSummary} selectedStream={selectedStream} setSelectedStream={setSelectedStream} onGo={() => navTo('captures')} />}
        {tab === 'intelligence' && <ThreatPage summary={activeSummary} />}
        {tab === 'reports' && <ReportsPage activeSummary={activeSummary} activeDetail={activeDetail} />}
      </div>
      {deleteTarget && <div className="confirm-scrim" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setDeleteTarget(null) }}><section className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="delete-title" aria-describedby="delete-description"><span className="eyebrow">LOCAL ARCHIVE</span><h2 id="delete-title">Delete this analysis?</h2><p id="delete-description"><b>{deleteTarget.source_name}</b> and its saved report and stream evidence will be removed from the local database. Uploaded PCAP files are not retained after analysis.</p><div className="confirm-actions"><button className="button" onClick={() => setDeleteTarget(null)}>Cancel</button><button className="button button-danger" onClick={() => void deleteAnalysis(deleteTarget)}>Delete analysis</button></div></section></div>}
      {dragging && <div className="drop-overlay" role="presentation"><div><span>↓</span><b>Drop captures to add them to the analysis queue</b><small>PCAP and PCAPNG · up to 512 MiB per file</small></div></div>}
    </main>
  </div>
}

function OverviewPage({ analyses, activeSummary, streams, findings, postureAverage, dashboard, loading, onGo, onSelect }: { analyses: AnalysisSummary[]; activeSummary: AnalysisSummary | null; streams: StreamReport[]; findings: ReturnType<typeof allFindings>; postureAverage: number | null; dashboard: DashboardSummary | null; loading: boolean; onGo: (tab: Tab) => void; onSelect: (id: string) => void }) {
  const counts = streams.reduce<Record<string, number>>((result, stream) => { result[stream.protocol] = (result[stream.protocol] ?? 0) + 1; return result }, {})
  const topAnalyses = analyses.slice(0, 6)
  return <div className="page-content">
    <SectionTitle eyebrow="MAIL SECURITY FORENSICS" title="Investigation overview" detail="Capture activity, protocol reconstruction, deterministic posture, and model output for the selected case." action={<button className="button button-primary" onClick={() => onGo('captures')}>Add capture <span>↗</span></button>} />
    {!analyses.length && !loading ? <EmptyState title="No analyses in the archive" copy="Upload a PCAP or PCAPNG capture to begin. Analysis runs are saved by the local backend." action={<button className="button button-primary" onClick={() => onGo('captures')}>Open PCAP analysis</button>} /> : <>
      <ArchiveAnalytics data={dashboard}/>
      <div className="content-grid overview-grid">
        <section className="panel case-overview"><div className="panel-head"><div><span className="eyebrow">ACTIVE CASE</span><h2>{activeSummary?.source_name ?? 'Choose a report'}</h2></div>{activeSummary && <Badge>{activeSummary.run_id.slice(0, 10)}</Badge>}</div>
          {!activeSummary ? <p className="muted">Select a report from the archive to view its analysis.</p> : <><div className="report-meta"><span>{runTime(activeSummary.created_at)}</span><span>{streams.length} streams analyzed</span><span className="mono">{activeSummary.run_id.slice(0, 12)}</span></div><div className="protocol-strip">{['SMTP', 'IMAP', 'POP3'].map((name) => <div key={name}><small>{name}</small><b>{counts[name] ?? 0}</b><span>streams</span></div>)}</div><div className="bar-list">{Object.entries(counts).map(([name, count]) => <div key={name} className="bar-row"><span>{name}</span><div className="bar-track"><i style={{ width: `${streams.length ? count / streams.length * 100 : 0}%` }} /></div><b>{count}</b></div>)}</div></>}
        </section>
        <section className="panel"><div className="panel-head"><div><span className="eyebrow">LOCAL ARCHIVE</span><h2>Recent analyses</h2></div><button className="text-button" onClick={() => onGo('captures')}>Upload more →</button></div>
          {topAnalyses.length ? <div className="archive-list">{topAnalyses.map((item) => <button key={item.run_id} className={`archive-row ${item.run_id === activeSummary?.run_id ? 'selected' : ''}`} onClick={() => onSelect(item.run_id)}><span className="file-mark">PC</span><span className="archive-name"><b>{item.source_name}</b><small>{runTime(item.created_at)}</small></span><span className="archive-streams">{item.total_streams} streams</span><span className="arrow">↗</span></button>)}</div> : <p className="muted">{loading ? 'Loading analyses…' : 'No saved analyses yet.'}</p>}
        </section>
      </div>
      <div className="metric-grid overview-metrics"><Metric label="CAPTURES IN ARCHIVE" value={dashboard?.capture_count ?? analyses.length} sub="Local analysis records"/><Metric label="RECONSTRUCTED FLOWS" value={activeSummary ? streams.length : '—'} sub={activeSummary ? activeSummary.source_name : 'Select a case above'}/><Metric label="RULE FINDINGS" value={activeSummary ? findings.filter((item) => item.kind === 'POLICY').length : '—'} sub="Deterministic policy failures"/><Metric label="POSTURE SCORE" value={postureAverage === null ? '—' : `${postureAverage}`} sub="Heuristic · out of 100 · not ML"/></div>
      <CaptureCharts streams={streams}/>
      <section className="panel intelligence-overview"><div className="panel-heading"><div><span className="eyebrow">LEARNED SIGNALS</span><h2>ML outputs across this capture</h2><p>See which signals ran, what they estimated, and how much input was available. These are advisory signals, not policy verdicts.</p></div><button className="text-button" onClick={() => onGo('investigation')}>Open session evidence <span>→</span></button></div><OverviewML streams={streams}/></section>
      <section className="panel recent-findings"><div className="panel-head"><div><span className="eyebrow">SELECTED REPORT</span><h2>Findings at a glance</h2></div><button className="text-button" onClick={() => onGo('investigation')}>Inspect findings →</button></div>{findings.length ? <div className="finding-preview">{findings.slice(0, 5).map((finding, index) => <div key={`${finding.id}-${finding.stream.stream_id}-${index}`} className="finding-preview-row"><Badge tone={finding.kind === 'POLICY' ? 'badge-red' : 'badge-blue'}>{finding.kind}</Badge><span><b>{finding.title}</b><small>Stream {finding.stream.stream_id} · {finding.id}</small></span><span className="finding-kind">{finding.severity}</span></div>)}</div> : <p className="muted">{activeSummary ? 'No failed policy checks or detected observations were recorded.' : 'Select an analysis to inspect findings.'}</p>}</section>
    </>}
  </div>
}

function ArchiveAnalytics({ data }: { data: DashboardSummary | null }) {
  if (!data || !data.capture_count) return <section className="archive-analytics archive-empty"><div><span className="eyebrow">ARCHIVE TELEMETRY</span><h2>Capture data visualized together</h2><p>Analyze captures to build aggregate protocol, TLS, certificate, policy, and model views here.</p></div><span className="archive-empty-mark">↗</span></section>
  const failCount = data.rule_verdicts.FAIL ?? 0
  const completedCount = Object.entries(data.ml_statuses).filter(([status]) => status.startsWith('COMPLETED')).reduce((sum, [, count]) => sum + count, 0)
  const observedCerts = data.certificate_counts.Observed ?? 0
  const timeline = Object.entries(data.captures_by_day).slice(-14)
  const panels: Array<{ title: string; label: string; values: Record<string, number>; kind: 'protocol' | 'tls' | 'rules' | 'severity' | 'ml' | 'posture' }> = [
    { title: 'Mail protocol mix', label: 'RECONSTRUCTED STREAMS', values: data.protocol_counts, kind: 'protocol' },
    { title: 'Negotiated TLS versions', label: 'TLS EVIDENCE', values: data.tls_version_counts, kind: 'tls' },
    { title: 'Deterministic rule results', label: 'RULE ENGINE', values: data.rule_verdicts, kind: 'rules' },
    { title: 'Failed rule severity', label: 'OBSERVED POLICY FAILURES', values: data.rule_severities, kind: 'severity' },
    { title: 'ML runtime states', label: 'ADVISORY MODELS', values: data.ml_statuses, kind: 'ml' },
    { title: 'Posture tiers', label: 'DETERMINISTIC HEURISTIC', values: data.posture_tiers, kind: 'posture' },
  ]
  return <section className="archive-analytics">
    <header className="archive-analytics-head"><div><span className="eyebrow">ARCHIVE TELEMETRY</span><h2>One view across your captures</h2><p>Aggregated from all {data.capture_count} saved analyses. Counts reflect observed evidence, not inferred exposure.</p></div><div className="analytics-period">{data.capture_count} CAPTURES <i>·</i> {data.stream_count} FLOWS</div></header>
    <div className="analytics-kpis"><div><small>RULE FAILURES</small><b className={failCount ? 'tone-critical' : ''}>{failCount}</b></div><div><small>CERTIFICATES OBSERVED</small><b>{observedCerts}</b></div><div><small>COMPLETED MODEL RUNS</small><b>{completedCount}</b></div><div><small>ACTIVE DAYS · 14 MAX</small><b>{timeline.length}</b></div></div>
    <div className="archive-chart-grid">{panels.map((panel) => <ArchiveBarChart key={panel.kind} {...panel}/>)}</div>
    <p className="analytics-key"><span><i className="bar-risk"/>Rule failure / deprecated TLS</span><span><i className="bar-watch"/>Medium / runtime warning</span><span><i className="bar-positive"/>Pass / LOW posture</span><span><i className="bar-neutral"/>Observed counts</span></p>
    <div className="archive-timeline"><div className="timeline-chart-head"><span><small>INGESTION HISTORY</small><b>Captures analyzed by day</b></span><span>{timeline.length ? `${timeline.length} active days` : 'No daily activity'}</span></div><div className="timeline-chart-bars">{timeline.map(([day, count]) => <div className="timeline-chart-day" key={day}><span>{day.slice(5)}</span><i><b style={{ height: `${count / Math.max(...timeline.map(([, n]) => n)) * 100}%` }}/></i><em>{count}</em></div>)}</div></div>
  </section>
}

function ArchiveBarChart({ title, label, values, kind }: { title: string; label: string; values: Record<string, number>; kind: 'protocol' | 'tls' | 'rules' | 'severity' | 'ml' | 'posture' }) {
  const rows = Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, 7)
  const maximum = Math.max(1, ...rows.map(([, value]) => value))
  const tone = (name: string) => {
    const value = name.toUpperCase()
    if (kind === 'tls' && /TLS\s*V?\s*1\.[01]|SSLV/.test(value)) return 'bar-risk'
    if (kind === 'rules' && value === 'FAIL') return 'bar-risk'
    if (kind === 'severity' && /CRITICAL|HIGH/.test(value)) return 'bar-risk'
    if (kind === 'ml' && /ERROR|UNAVAILABLE/.test(value)) return 'bar-watch'
    if (kind === 'posture' && /CRITICAL|HIGH/.test(value)) return 'bar-risk'
    if ((kind === 'rules' && value === 'PASS') || (kind === 'posture' && value === 'LOW')) return 'bar-positive'
    if ((kind === 'severity' && value === 'MEDIUM') || (kind === 'posture' && value === 'MEDIUM')) return 'bar-watch'
    return 'bar-neutral'
  }
  return <article className={`archive-chart chart-${kind}`}><div className="archive-chart-heading"><span className="eyebrow">{label}</span><h3>{title}</h3></div>{rows.length ? <div className="archive-chart-rows">{rows.map(([name, count]) => <div className="archive-chart-row" key={name}><span title={name}>{kind === 'ml' ? mlStatusLabel(name) : name.replaceAll('_', ' ').toLowerCase()}</span><div><i className={tone(name)} style={{ width: `${count / maximum * 100}%` }}/></div><b>{count}</b></div>)}</div> : <p className="chart-unavailable">No observations recorded</p>}</article>
}

function CaptureCharts({ streams }: { streams: StreamReport[] }) {
  if (!streams.length) return null
  const tally = (values: string[]) => values.reduce<Record<string, number>>((result, value) => { result[value] = (result[value] ?? 0) + 1; return result }, {})
  const protocols = tally(streams.map((stream) => stream.protocol || 'Unknown'))
  const tlsVersions = tally(streams.map((stream) => {
    const snapshot = isObject(stream.input_snapshot) ? stream.input_snapshot : {}
    const tls = isObject(snapshot.tls) ? snapshot.tls : snapshot
    const version = tls.tls_version ?? tls.version
    return version === null || version === undefined || version === '' ? 'TLS not observed' : String(version)
  }))
  const certificateCount = streams.filter((stream) => {
    const snapshot = isObject(stream.input_snapshot) ? stream.input_snapshot : {}
    const certificate = isObject(snapshot.certificate) ? snapshot.certificate : snapshot
    return certificate.observable === true || certificate.certificate_observed === true || isObject(certificate.leaf_cert)
  }).length
  return <section className="telemetry-grid" aria-label="Observed capture data charts">
    <TelemetryBars title="Protocol mix" eyebrow="RECONSTRUCTED FLOWS" values={protocols} total={streams.length} kind="protocol"/>
    <TelemetryBars title="TLS version coverage" eyebrow="OBSERVED NEGOTIATIONS" values={tlsVersions} total={streams.length} kind="tls"/>
    <section className="panel telemetry-panel certificate-coverage"><div className="panel-head"><div><span className="eyebrow">CERTIFICATE EVIDENCE</span><h2>Certificate coverage</h2></div><span className="chart-count">{certificateCount}<i> / {streams.length}</i></span></div><div className="coverage-track" role="img" aria-label={`${certificateCount} of ${streams.length} streams have observed certificate evidence`}><i className="bar-neutral" style={{ width: `${certificateCount / streams.length * 100}%` }}/></div><p>{certificateCount} streams with certificate evidence · {streams.length - certificateCount} without observed certificates</p><small>Absence of a certificate in a capture does not prove the server has none.</small></section>
  </section>
}

function TelemetryBars({ title, eyebrow, values, total, kind }: { title: string; eyebrow: string; values: Record<string, number>; total: number; kind: 'protocol' | 'tls' }) {
  const rows = Object.entries(values).sort((a, b) => b[1] - a[1])
  return <section className="panel telemetry-panel"><div className="panel-head"><div><span className="eyebrow">{eyebrow}</span><h2>{title}</h2></div><span className="chart-count">{total}<i> total</i></span></div><div className="telemetry-bars">{rows.map(([name, value]) => { const legacy = kind === 'tls' && /TLS\s*V?\s*1\.[01]|SSLV/i.test(name); return <div className="telemetry-row" key={name}><span>{name}</span><div className="telemetry-track"><i className={legacy ? 'bar-risk' : 'bar-neutral'} style={{ width: `${value / total * 100}%` }}/></div><b>{value}</b></div> })}</div><small>Counts come from this selected capture. Red marks deprecated TLS only.</small></section>
}

const MODEL_ROWS = [
  ['zgrab_evidence_risk_classifier', 'SMTP risk estimate', 'Based on real SMTP scan observations; advisory labels'],
  ['synthetic_email_risk_classifier', 'IMAP / POP3 risk estimate', 'Based on simulated email scenarios; experimental'],
  ['classifier_risk_tier', 'SMTP risk tier estimate', 'Labels derived from existing policy checks'],
  ['classifier', 'SMTP policy-pattern estimate', 'Learns patterns in existing policy-check labels'],
  ['smtp_configuration_anomaly', 'SMTP configuration unusualness', 'Compared with observed real SMTP TLS configurations'],
  ['smtp_configuration_rarity', 'SMTP configuration frequency', 'Compared with observed real SMTP TLS configurations'],
  ['certificate_novelty', 'Certificate unusualness', 'Compared with SMTP-related certificate observations'],
] as const

const ML_DISPLAY_NAMES: Record<string, string> = {
  ml_assessment: "Overall ML summary",
  synthetic_email_risk_classifier: "Simulated mail risk estimate",
  zgrab_evidence_risk_classifier: "SMTP risk estimate",
  classifier_risk_tier: "SMTP risk tier estimate",
  classifier: "SMTP policy-pattern estimate",
  smtp_configuration_anomaly: "SMTP configuration unusualness",
  smtp_configuration_rarity: "SMTP configuration frequency",
  certificate_novelty: "Certificate unusualness",
}

function OverviewML({ streams }: { streams: StreamReport[] }) {
  if (!streams.length) return <div className="ml-overview-empty"><span>ML</span><p>Model outputs will appear here after analyzing a capture. Applicability and feature coverage are shown per session.</p></div>
  return <div className="model-table"><div className="model-table-head"><span>MODEL / REFERENCE COHORT</span><span>SESSION COVERAGE</span><span>OBSERVED OUTPUTS</span><span>AVERAGE FEATURE COVERAGE</span></div>{MODEL_ROWS.map(([key, label, cohort]) => {
    const rows = streams.map((stream) => ({ stream, value: stream.ml_results?.[key] })).filter(({ value }) => isObject(value)) as Array<{ stream: StreamReport; value: Record<string, unknown> }>
    const evaluable = rows.filter(({ value }) => String(value.status ?? '').startsWith('COMPLETED'))
    const counts = evaluable.reduce<Record<string, number>>((acc, { value }) => {
      const prediction = value.prediction ?? value.predicted_risk_tier ?? value.predicted_tier_proxy
      const display = typeof prediction === 'boolean' ? (prediction ? 'NOVEL' : 'KNOWN') : typeof prediction === 'string' ? prediction : null
      if (display) acc[display] = (acc[display] ?? 0) + 1
      return acc
    }, {})
    const coverage = evaluable.map(({ value }) => value.feature_coverage).filter((value): value is number => typeof value === 'number')
    const average = coverage.length ? `${Math.round(coverage.reduce((a, b) => a + b, 0) / coverage.length * 100)}%` : '—'
    const state = rows.length ? evaluable.length ? `${evaluable.length} / ${streams.length} evaluable` : `${rows.length} / ${streams.length} assessed` : 'No runtime output'
    const output = Object.entries(counts).map(([name, count]) => `${mlPredictionLabel(name)} · ${count}`).join('   /   ')
    return <div className="model-table-row" key={key}><div className="model-name"><b>{label}</b><small>{cohort}</small></div><span className="model-coverage">{state}</span><span className="model-output">{output || statusSummary(rows.map(({ value }) => String(value.status ?? 'UNKNOWN')))}</span><span className="model-feature-coverage">{average}</span></div>
  })}</div>
}

function statusSummary(statuses: string[]) {
  if (!statuses.length) return '—'
  const tally = statuses.reduce<Record<string, number>>((acc, status) => { acc[status] = (acc[status] ?? 0) + 1; return acc }, {})
  return Object.entries(tally).map(([status, count]) => `${mlStatusLabel(status)} · ${count}`).join(' / ')
}

function CapturesPage(props: {
  analyses: AnalysisSummary[]; allCount: number; filter: string; setFilter: (value: string) => void; inputRef: RefObject<HTMLInputElement>; queue: QueueItem[]; addFiles: (files: FileList | File[]) => void; processQueue: () => Promise<void>; queueBusy: boolean; hasQueued: boolean; trustStore: string; setTrustStore: (value: string) => void; aborters: Map<string, () => void>; retryItem: (key: string) => void; removeItem: (key: string) => void; clearCompleted: () => void; onSelect: (id: string) => void; onDelete: (item: AnalysisSummary) => void; onTab: (tab: Tab) => void
}) {
  return <div className="page-content">
    <SectionTitle eyebrow="CAPTURE INGESTION" title="PCAP analysis" detail="Submit one or several captures. Each file is analyzed by the local backend and its report is persisted in SQLite." />
    <div className="upload-settings"><label>Certificate trust store<select value={props.trustStore} onChange={(event) => props.setTrustStore(event.target.value)}><option value="testbed">Testbed roots</option><option value="system">Operating-system roots</option><option value="production">Configured production roots</option></select></label><div className="analysis-guarantee"><span className="status-dot"/><span><b>Full analysis enabled</b><small>Parser · Rule Engine · applicable ML models</small></span></div></div>
    <input id="capture-files" ref={props.inputRef} aria-label="Select PCAP and PCAPNG files" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/vnd.tcpdump.pcapng" multiple hidden onChange={(event) => { if (event.target.files) props.addFiles(event.target.files); event.target.value = '' }} />
    <button className="upload-zone" onClick={() => props.inputRef.current?.click()}><span className="upload-symbol">↑</span><b>Choose packet captures</b><span>or drag files anywhere into this workspace</span><small>PCAP / PCAPNG · max 512 MiB per capture</small></button>
    {props.queue.length > 0 && <section className="panel queue-panel"><div className="panel-head"><div><span className="eyebrow">UPLOAD QUEUE</span><h2>{props.queue.length} capture{props.queue.length === 1 ? '' : 's'}</h2></div><div className="button-row"><button className="button button-small" onClick={() => props.inputRef.current?.click()}>Add captures</button><button className="button button-small" onClick={props.clearCompleted} disabled={props.queueBusy || !props.queue.some((item) => item.status === 'stored' || item.status === 'failed' || item.status === 'cancelled')}>Clear completed</button><button className="button button-primary button-small" onClick={() => void props.processQueue()} disabled={!props.hasQueued || props.queueBusy}>{props.queueBusy ? 'Processing queue…' : `Analyze ${props.queue.filter((item) => item.status === 'queued').length} queued`}</button></div></div>
      <div className="queue-list">{props.queue.map((item) => <div key={item.key} className="queue-row"><span className="file-mark">PC</span><div className="queue-file"><b>{item.file.name}</b><small>{bytes(item.file.size)} {item.runId ? `· report ${item.runId.slice(0, 10)}` : ''}</small>{item.status === 'uploading' && <div className="progress-track"><i style={{ width: `${item.total ? item.sent / item.total * 100 : 0}%` }} /></div>}</div><Badge tone={item.status === 'failed' ? 'badge-red' : item.status === 'stored' ? 'badge-green' : ''}>{item.status}</Badge>{item.error && <span className="queue-error">{item.error}</span>}{(item.status === 'uploading' || item.status === 'analyzing') ? <button className="text-button" onClick={() => props.aborters.get(item.key)?.()}>Cancel</button> : item.status === 'failed' ? <button className="text-button" onClick={() => props.retryItem(item.key)}>Retry</button> : <button className="text-button" onClick={() => props.removeItem(item.key)}>Remove</button>}</div>)}</div>
      <p className="muted small-copy">Processing is sequential to limit local resource use. Byte progress reflects actual browser upload progress; analysis duration is reported as a working state, not a fabricated percentage. Stopping an in-progress transfer cannot cancel work the server has already started.</p></section>}
    <section className="panel archive-panel"><div className="panel-head"><div><span className="eyebrow">PERSISTED IN THE LOCAL DATABASE</span><h2>Analysis archive <span className="count-pill">{props.allCount}</span></h2></div><input className="search-input" value={props.filter} onChange={(event) => props.setFilter(event.target.value)} placeholder="Filter file or run ID" aria-label="Filter analysis archive" /></div>
      {props.analyses.length ? <div className="archive-table-wrap"><table className="archive-table"><thead><tr><th>Capture</th><th>Analysed</th><th>Streams</th><th>Report ID</th><th /></tr></thead><tbody>{props.analyses.map((item) => <tr key={item.run_id}><td><b>{item.source_name}</b></td><td>{runTime(item.created_at)}</td><td>{item.total_streams}</td><td className="mono">{item.run_id.slice(0, 12)}</td><td className="archive-actions"><button className="text-button" onClick={() => { props.onSelect(item.run_id); props.onTab('reports') }}>Open report →</button><button className="text-button delete-action" aria-label={`Delete analysis ${item.source_name}`} onClick={() => props.onDelete(item)}>Delete</button></td></tr>)}</tbody></table></div> : <EmptyState title="No matching reports" copy="Try another filter or analyze a capture to populate the archive." />}
    </section>
  </div>
}

function InvestigationPage({ view, setView, findings, streams, summary, selectedStream, setSelectedStream, onGo }: { view: InvestigationView; setView: (view: InvestigationView) => void; findings: ReturnType<typeof allFindings>; streams: StreamReport[]; summary: AnalysisSummary | null; selectedStream: number | null; setSelectedStream: (value: number | null) => void; onGo: () => void }) {
  const failures = findings.filter((finding) => finding.kind === 'POLICY').length
  const observations = findings.filter((finding) => finding.kind === 'OBSERVATION').length
  return <div className="page-content">
    <SectionTitle eyebrow="CASE INVESTIGATION" title={summary?.source_name ?? 'Investigation'} detail={summary ? `${runTime(summary.created_at)} · ${streams.length} reconstructed sessions` : 'Choose a capture to review its findings, sessions, and packet evidence.'} action={summary && <Badge tone={failures ? 'badge-red' : 'badge-green'}>{failures ? `${failures} policy failures` : 'No policy failures'}</Badge>} />
    <div className="case-toolbar"><div className="segmented-tabs" role="tablist" aria-label="Investigation views">{([['findings', 'Findings', findings.length], ['sessions', 'Sessions', streams.length], ['timeline', 'Evidence timeline', null]] as const).map(([id, label, count]) => <button role="tab" aria-selected={view === id} className={view === id ? 'active' : ''} key={id} onClick={() => setView(id)}>{label}{count !== null && <span>{count}</span>}</button>)}</div><div className="case-legend"><span className="legend-rule">Rule engine</span><span className="legend-ml">ML advisory</span><span className="legend-posture">Posture</span></div></div>
    {!summary ? <EmptyState title="No capture selected" copy="Analyze a PCAP, then return here to inspect the evidence produced by the parser, policy rules, and applicable ML models." action={<button className="button button-primary" onClick={onGo}>Analyze a capture</button>} /> : <>
      <div className="case-summary-strip"><div><small>POLICY FAILURES</small><b className={failures ? 'tone-critical' : 'tone-good'}>{failures}</b></div><div><small>OBSERVATIONS</small><b className={observations ? 'tone-watch' : ''}>{observations}</b></div><div><small>SESSIONS</small><b>{streams.length}</b></div><div><small>ML EXECUTION</small><b>{mlSummary(streams)}</b></div></div>
      {view === 'findings' && <FindingsPage findings={findings} summary={summary} onGo={onGo} />}
      {view === 'sessions' && <SessionsPage streams={streams} selectedStream={selectedStream} setSelectedStream={setSelectedStream} summary={summary} />}
      {view === 'timeline' && <TimelinePage streams={streams} summary={summary} />}
    </>}
  </div>
}

function mlSummary(streams: StreamReport[]) {
  if (!streams.length) return '—'
  const isError = (status: unknown) => ['MODEL_ERROR', 'MODEL_UNAVAILABLE'].includes(String(status))
  const withOutput = streams.filter((stream) => Object.keys(stream.ml_results ?? {}).length > 0 && !isError(stream.ml_results?.status)).length
  const hasErrors = streams.some((stream) => isError(stream.ml_results?.status) || Object.values(stream.ml_results ?? {}).filter(isObject).some((result) => isError(result.status)))
  return `${withOutput}/${streams.length} streams${hasErrors ? ' · errors' : ' with outputs'}`
}

function FindingsPage({ findings, summary, onGo }: { findings: ReturnType<typeof allFindings>; summary: AnalysisSummary | null; onGo: () => void }) {
  return <div className="page-content investigation-content"><SectionTitle eyebrow="DETERMINISTIC POLICY RESULTS" title="Findings" detail={summary ? `Evidence from ${summary.source_name}. Machine-learning estimates are shown separately.` : 'Select an analysis from the report archive to review its findings.'} action={summary ? <Badge>{findings.length} items</Badge> : undefined} />{!summary ? <EmptyState title="No report selected" copy="Analyze a PCAP or select a saved report first." action={<button className="button button-primary" onClick={onGo}>Open capture archive</button>} /> : findings.length ? <div className="finding-list">{findings.map((item, index) => <article className="panel finding-card" key={`${item.stream.stream_id}-${item.id}-${index}`}><div className="finding-card-head"><Badge tone={item.kind === 'POLICY' ? 'badge-red' : 'badge-blue'}>{item.kind === 'POLICY' ? 'RULE ENGINE' : 'OBSERVATION'}</Badge><span className="mono">{item.id}</span><Badge tone={semanticTone(item.severity)}>{item.severity}</Badge></div><h2>{item.title}</h2><p>{text(item.note, 'No additional description was included in the report.')}</p><div className="finding-footer"><span>Stream {item.stream.stream_id} · {item.stream.protocol}</span>{item.kind === 'POLICY' && <span>Deterministic policy result</span>}</div></article>)}</div> : <EmptyState title="No findings in this report" copy="No policy failures or detected forensic observations were recorded. This does not imply that unavailable evidence is safe." />}</div>
}

function SessionsPage({ streams, selectedStream, setSelectedStream, summary }: { streams: StreamReport[]; selectedStream: number | null; setSelectedStream: (value: number | null) => void; summary: AnalysisSummary | null }) {
  const active = streams.find((stream) => stream.stream_id === selectedStream) ?? null
  if (!summary) return <div className="page-content investigation-content"><SectionTitle eyebrow="STREAM RECONSTRUCTION" title="Sessions & evidence" detail="Select an analysis from the archive."/><EmptyState title="No report selected" copy="Choose a saved analysis to inspect reconstructed streams." /></div>
  return <div className="page-content investigation-content">{streams.length ? <><section className="panel flow-ribbon"><div className="flow-ribbon-heading"><div><span className="eyebrow">RECONSTRUCTED FLOWS</span><h2>Sessions</h2></div><span className="count-pill">{streams.length} flows</span></div><div className="flow-ribbon-list" role="tablist" aria-label="Reconstructed sessions">{streams.map((stream) => <button key={stream.stream_id} role="tab" aria-selected={selectedStream === stream.stream_id} className={`flow-ribbon-item ${selectedStream === stream.stream_id ? 'selected' : ''}`} onClick={() => setSelectedStream(stream.stream_id)}><span className="flow-ribbon-id">{String(stream.stream_id).padStart(3, '0')}</span><span className="flow-ribbon-protocol">{stream.protocol}</span><span className="flow-ribbon-findings">{findingsCount(stream)} finding{findingsCount(stream) === 1 ? '' : 's'}</span></button>)}</div></section>{active ? <StreamEvidence stream={active} /> : <EmptyState title="Select a stream" copy="Choose a session above to review transport, certificate, policy, and ML evidence."/>}</> : <EmptyState title="No streams reconstructed" copy="The capture may contain no analyzable TCP streams. Review report limitations and capture integrity."/>}</div>
}

function StreamEvidence({ stream }: { stream: StreamReport }) {
  const snapshot = isObject(stream.input_snapshot) ? stream.input_snapshot : {}
  const tls = isObject(snapshot.tls) ? snapshot.tls : snapshot
  const heuristics = isObject(snapshot.heuristics) ? snapshot.heuristics : {}
  const certificate = isObject(snapshot.certificate) ? snapshot.certificate : {
    observable: snapshot.cert_observable,
    unobservable_reason: snapshot.cert_unobservable_reason,
    chain_length: snapshot.chain_length,
    hostname_match: snapshot.hostname_match,
    revocation_status: snapshot.revocation_status,
    leaf_cert: snapshot.leaf_cert,
    non_anchor_cert_facts: snapshot.non_anchor_cert_facts,
  }
  const starttls = isObject(snapshot.starttls) ? snapshot.starttls : snapshot
  const rules = Object.entries(stream.policy_results ?? {}).flatMap(([pack, items]) => items.map((item) => ({ pack, item })))
  const failed = rules.filter(({ item }) => item.verdict === 'FAIL')
  const facts: Array<[string, unknown]> = [['TLS version', tls.tls_version ?? tls.version], ['Cipher suite', tls.cipher_name ?? tls.cipher_suite], ['Key exchange', tls.key_exchange ?? tls.tls13_key_exchange_group ?? tls.kex], ['Forward secrecy', tls.forward_secrecy ?? tls.uses_forward_secrecy ?? heuristics.h_forward_secrecy], ['Encryption start', starttls.status ?? starttls.outcome ?? (starttls.starttls_status || (starttls.starttls_accepted ? 'UPGRADE_ACCEPTED' : null))], ['Handshake', tls.handshake_status ?? tls.status]]
  const policyGroups = Object.entries(rules.reduce<Record<string, Array<{ pack: string; item: PolicyResult }>>>((groups, entry) => { (groups[entry.pack] ??= []).push(entry); return groups }, {}))
  const observations = stream.observations ?? []
  return <div className="stream-evidence"><div className="stream-detail-head"><div><span className="eyebrow">ACTIVE SESSION · {String(stream.stream_id).padStart(3, '0')}</span><h2>{stream.protocol}</h2></div><Badge>{findingsCount(stream)} findings / observations</Badge></div>
    <div className="session-evidence-grid">
      <section className="session-card session-transport"><SessionCardHeading eyebrow="OBSERVED CONNECTION" title="Negotiated transport" detail="Values come from this reconstructed session."/><div className="fact-grid">{facts.map(([label, value]) => <div className="fact" key={label}><small>{label}</small><b>{sessionValue(label, value)}</b></div>)}</div></section>
      <section className="session-card"><SessionCardHeading eyebrow="DETERMINISTIC · NOT ML" title="Security posture"/><PostureSummary posture={stream.posture_assessment ?? {}} /></section>
      <section className="session-card"><SessionCardHeading eyebrow="CERTIFICATE EVIDENCE" title="Certificate & trust"/><CertificateSummary certificate={certificate} /></section>
      <section className="session-card session-ml-card"><SessionCardHeading eyebrow="ADVISORY SIGNALS" title="Machine-learning results" detail="Each signal shows its result or why it could not produce one. These estimates do not replace policy checks."/><MLResults value={stream.ml_results ?? {}} protocol={stream.protocol}/></section>
      <section className="session-card session-policy-card"><SessionCardHeading eyebrow="DETERMINISTIC CHECKS" title="Policy coverage" detail={`${failed.length} failed · ${rules.length} checks evaluated`}/><PolicyOutcomeChart rules={rules}/>{policyGroups.length ? <div className="policy-pack-grid">{policyGroups.map(([pack, entries]) => <div className="policy-pack" key={pack}><header><b>{policyPackLabel(pack)}</b><span>{entries.filter(({ item }) => item.verdict === 'FAIL').length} failed · {entries.length} checks</span></header><div className="policy-compact-list">{entries.map(({ item }, index) => <PolicyCheck key={`${pack}-${item.rule_id}-${index}`} item={item} />)}</div></div>)}</div> : <p className="muted">No deterministic policy checks were recorded.</p>}{failed.length === 0 && rules.length > 0 && <p className="policy-clear-note">No policy failures were found in the checks that ran. This does not resolve unavailable evidence.</p>}</section>
      <section className="session-card"><SessionCardHeading eyebrow="PACKET ANALYSIS" title="Forensic observations"/>{observations.length ? <div className="observation-list">{observations.map((item, index) => <div className="observation-row" key={`${item.obs_id}-${index}`}><Badge tone={item.detected ? 'badge-red' : 'badge-muted'}>{item.detected ? 'Detected' : 'Not detected'}</Badge><div><b>{item.name ?? 'Observation'}</b><p>{item.description ?? 'No additional description.'}</p></div></div>)}</div> : <p className="muted">No observation records.</p>}</section>
      <section className="session-card"><SessionCardHeading eyebrow="EVIDENCE-LINKED" title="Mitigation guidance"/>{<Recommendations posture={stream.posture_assessment ?? {}} />}</section>
    </div>
  </div>
}

function SessionCardHeading({ eyebrow, title, detail }: { eyebrow: string; title: string; detail?: string }) {
  return <header className="session-card-heading"><div><span className="eyebrow">{eyebrow}</span><h3>{title}</h3>{detail && <p>{detail}</p>}</div></header>
}

function sessionValue(label: string, value: unknown) {
  if (value === undefined || value === null || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  const display: Record<string, string> = {
    IMPLICIT_TLS: 'TLS active from connection start',
    UPGRADE_ACCEPTED: 'STARTTLS accepted',
    HANDSHAKE_STATUS_UNRESOLVED: 'Could not determine from captured handshake',
    SKIPPED_NO_SNI: 'Not checked · server name unavailable',
    NOT_CHECKED: 'Not checked',
    NOT_CHECKED_PASSIVE_OFFLINE_ANALYSIS: 'Not checked · offline capture',
  }
  const raw = String(value)
  if (display[raw]) return display[raw]
  if (label === 'Revocation' && raw.includes('PASSIVE_OFFLINE_ANALYSIS')) return 'Not checked · offline capture'
  return raw.replaceAll('_', ' ')
}

function policyPackLabel(pack: string) {
  const normalized = pack.toUpperCase()
  if (normalized.includes('MOZ') && normalized.includes('INTERM')) return 'Mozilla · Intermediate'
  if (normalized.includes('MOZ') && normalized.includes('MODERN')) return 'Mozilla · Modern'
  if (normalized.includes('NIST') || normalized.includes('131A')) return 'NIST cryptographic guidance'
  return pack.replaceAll('_', ' ').replaceAll('-', ' ')
}

function PolicyOutcomeChart({ rules }: { rules: Array<{ pack: string; item: PolicyResult }> }) {
  const groups = [
    { label: 'Passed', count: rules.filter(({ item }) => item.verdict === 'PASS').length, tone: 'policy-bar-pass' },
    { label: 'Failed', count: rules.filter(({ item }) => item.verdict === 'FAIL').length, tone: 'policy-bar-fail' },
    { label: 'Not applicable', count: rules.filter(({ item }) => item.verdict === 'NOT_APPLICABLE').length, tone: 'policy-bar-na' },
    { label: 'Not observable', count: rules.filter(({ item }) => item.verdict === 'NOT_OBSERVABLE').length, tone: 'policy-bar-unknown' },
  ].filter((group) => group.count > 0)
  const otherCount = rules.length - groups.reduce((sum, group) => sum + group.count, 0)
  if (otherCount > 0) groups.push({ label: 'Other outcome', count: otherCount, tone: 'policy-bar-unknown' })
  const total = groups.reduce((sum, group) => sum + group.count, 0)
  if (!total) return null
  return <div className="policy-outcome-chart" aria-label={`${groups.map((group) => `${group.label}: ${group.count}`).join(', ')} policy checks`}><div className="policy-outcome-bar">{groups.map((group) => <i key={group.label} className={group.tone} style={{ width: `${group.count / total * 100}%` }} title={`${group.label}: ${group.count}`} />)}</div><div className="policy-outcome-legend">{groups.map((group) => <span key={group.label}><i className={group.tone}/>{group.label} <b>{group.count}</b></span>)}</div></div>
}

function PolicyCheck({ item }: { item: PolicyResult }) {
  const verdict = String(item.verdict ?? 'UNKNOWN').toUpperCase()
  const verdictLabels: Record<string, string> = { FAIL: 'Failed', PASS: 'Passed', NOT_APPLICABLE: 'Not applicable', NOT_OBSERVABLE: 'Not observable', NOT_EVALUABLE: 'Not evaluated' }
  const evidenceText = item.evidence?.slice(0, 2).map((evidence) => [evidence.field, evidence.value].filter((part) => part !== undefined && part !== null).map(String).join(': ')).filter(Boolean).join(' · ')
  const verdictLabel = verdictLabels[verdict] ?? verdict.replaceAll('_', ' ').toLowerCase().replace(/^./, (letter) => letter.toUpperCase())
  return <div className={`policy-check-row ${verdict === 'FAIL' ? 'policy-check-fail' : ''}`}><span className="policy-check-name">{item.name ?? 'Policy check'}{verdict === 'FAIL' && item.finding && <small>{item.finding}</small>}{verdict === 'FAIL' && evidenceText && <small>Evidence: {evidenceText}</small>}</span><Badge tone={verdict === 'FAIL' ? 'badge-red' : verdict === 'PASS' ? 'badge-green' : 'badge-muted'}>{verdictLabel}</Badge></div>
}

function CertificateSummary({ certificate }: { certificate: Record<string, unknown> }) {
  const leaf = isObject(certificate.leaf_cert) ? certificate.leaf_cert : certificate
  const candidates: Array<[string, unknown]> = [
    ['Observation', certificate.observable === false || certificate.certificate_observed === false ? 'Not observed in capture' : certificate.observable ?? certificate.certificate_observed],
    ['Trust status', certificate.trust_status ?? leaf.trust_status],
    ['Hostname match', certificate.hostname_match ?? leaf.hostname_match],
    ['Key algorithm', leaf.public_key_algorithm ?? leaf.key_algorithm],
    ['Key size', leaf.public_key_size ?? leaf.key_size_bits],
    ['Signature', leaf.signature_algorithm],
    ['Valid from', leaf.not_before],
    ['Valid until', leaf.not_after],
    ['Expired', leaf.is_expired === undefined && leaf.expired === undefined ? undefined : (leaf.is_expired ?? leaf.expired) ? 'Yes' : 'No'],
    ['Self-signed', leaf.is_self_signed === undefined && leaf.self_signed === undefined ? undefined : (leaf.is_self_signed ?? leaf.self_signed) ? 'Yes' : 'No'],
    ['SAN entries', leaf.san_count],
    ['Chain length', certificate.chain_length],
    ['Revocation', sessionValue('Revocation', certificate.revocation_status)],
  ]
  const fields = candidates.filter(([, value]) => value !== undefined && value !== null && value !== '')
  if (!fields.length) return <p className="muted">— No certificate details were observable in this session.</p>
  const notObserved = certificate.observable === false || certificate.certificate_observed === false
  return <><div className="fact-grid certificate-grid">{fields.map(([label, value]) => <div className="fact" key={label}><small>{label}</small><b>{sessionValue(label, value)}</b></div>)}</div>{notObserved && <p className="muted small-copy">No certificate was captured for this session. It may still exist on the server; passive traffic did not expose it here.</p>}</>
}

function PostureSummary({ posture }: { posture: Record<string, unknown> }) {
  if (!Object.keys(posture).length) return <p className="muted">No deterministic posture summary is present in this report.</p>
  const score = typeof posture.score === 'number' ? posture.score : null
  const tier = text(posture.tier, text(posture.status, 'NOT EVALUABLE'))
  const findings = Array.isArray(posture.findings) ? posture.findings.filter(isObject) : []
  return <><div className="posture-card"><div className="posture-score"><span>{score === null ? '—' : score}</span><small>{score === null ? 'SCORE' : '/ 100'}</small></div><div><Badge tone={semanticTone(tier)}>{tier}</Badge><p>Deterministic estimate, not an ML probability.</p></div></div>{findings.length > 0 && <div className="posture-findings">{findings.map((finding, index) => <div key={`${String(finding.family)}-${index}`}><Badge tone={semanticTone(finding.severity)}>{text(finding.severity)}</Badge><span><b>{text(finding.family)}</b><small>{Array.isArray(finding.evidence) ? finding.evidence.length : 0} linked evidence items</small></span></div>)}</div>}</>
}

function Recommendations({ posture }: { posture: Record<string, unknown> }) {
  const findings = Array.isArray(posture.findings) ? posture.findings.filter(isObject) : []
  const items = findings.filter((finding) => typeof finding.recommendation === 'string')
  return items.length ? <div className="recommendation-list">{items.map((finding, index) => <article key={`${String(finding.family)}-${index}`}><Badge tone={finding.severity === 'HIGH' || finding.severity === 'CRITICAL' ? 'badge-red' : ''}>{text(finding.severity, 'GUIDANCE')}</Badge><div><b>{text(finding.family, 'Security posture')}</b><p>{String(finding.recommendation)}</p></div></article>)}</div> : <p className="muted">No evidence-linked mitigation guidance was produced for this stream.</p>
}

function TimelinePage({ streams, summary }: { streams: StreamReport[]; summary: AnalysisSummary | null }) {
  const events = streams.flatMap((stream) => {
    const entries: Array<{ streamId: number; protocol: string; frame: number | null; field: string; value: unknown; source: string; status: string }> = []
    for (const [pack, items] of Object.entries(stream.policy_results ?? {})) for (const item of items) for (const evidence of item.evidence ?? []) {
      const frame = typeof evidence.frame === 'number' ? evidence.frame : null
      entries.push({ streamId: stream.stream_id, protocol: stream.protocol, frame, field: String(evidence.field ?? item.rule_id ?? pack), value: evidence.value, source: String(evidence.source ?? pack), status: frame === null ? 'PACKET REFERENCE UNAVAILABLE' : 'PACKET REFERENCED' })
    }
    for (const observation of stream.observations ?? []) for (const evidence of observation.evidence ?? []) {
      const frame = typeof evidence.frame === 'number' ? evidence.frame : null
      entries.push({ streamId: stream.stream_id, protocol: stream.protocol, frame, field: String(evidence.field ?? observation.obs_id ?? 'observation'), value: evidence.value, source: String(evidence.source ?? observation.name ?? 'forensic observation'), status: frame === null ? 'PACKET REFERENCE UNAVAILABLE' : 'PACKET REFERENCED' })
    }
    return entries
  }).sort((a, b) => (a.frame ?? Number.MAX_SAFE_INTEGER) - (b.frame ?? Number.MAX_SAFE_INTEGER) || a.streamId - b.streamId)
  return <div className="page-content investigation-content">{!summary ? <EmptyState title="No report selected" copy="Choose a saved analysis first."/> : events.length ? <section className="panel timeline-panel"><div className="panel-head"><div><span className="eyebrow">PACKET-PROVENANCE VIEW</span><h2>Evidence timeline · {events.length} references</h2><p className="muted">Only packet references present in the analysis report are shown.</p></div><Badge tone="badge-blue">Ordered by frame when available</Badge></div><div className="timeline-list">{events.map((event,index)=><article key={`${event.streamId}-${event.frame}-${event.field}-${index}`} className="timeline-event"><span className="timeline-pin"/><div className="timeline-time">{event.frame === null ? 'FRAME —' : `FRAME ${event.frame}`}<small>STREAM {event.streamId} · {event.protocol}</small></div><div className="timeline-copy"><b>{event.field}</b><code>{text(event.value)}</code><small>{event.source}</small></div><Badge tone={event.frame === null ? 'badge-muted' : 'badge-green'}>{event.status}</Badge></article>)}</div><p className="muted small-copy">A frame number is shown only when the parser linked evidence to one. Entries without a frame are not assigned a synthetic timestamp or packet order.</p></section> : <EmptyState title="No packet-linked evidence entries" copy="This report contains no evidence atoms with timeline details."/>}</div>
}

function MLResults({ value, protocol }: { value: Record<string, unknown>; protocol: string }) {
  const modelKeys = Object.keys(ML_DISPLAY_NAMES).filter((key) => key !== 'ml_assessment')
  const extraKeys = Object.keys(value).filter((key) => key !== 'status' && key !== 'ml_assessment' && !modelKeys.includes(key))
  const keys = [...modelKeys, ...extraKeys]
  const assessment = isObject(value.ml_assessment) ? value.ml_assessment : {}
  const cohortLabels: Record<string, string> = { zgrab_real_smtp_tls: 'real SMTP TLS observations', mta_sts_smtp_related_scan_certificates: 'SMTP-related certificate observations', synthetic_email_scenarios: 'simulated email scenarios' }
  if (!keys.length && !Object.keys(assessment).length) return <p className="muted">No machine-learning outputs were recorded for this session.</p>
  return <div className="ml-results-area">
    <div className="ml-advisory-note"><b>Advisory only</b><span>Machine-learning estimates add context. Deterministic policy checks remain authoritative. No combined ML risk score is produced.</span></div>
    <div className="ml-table-scroll"><table className="ml-evidence-table"><thead><tr><th>Signal</th><th>Estimated result</th><th>Availability</th><th>Input coverage</th><th>Score & context</th></tr></thead><tbody>{keys.map((name) => {
      const row = isObject(value[name]) ? value[name] as Record<string, unknown> : {}
      const applicable = name === 'synthetic_email_risk_classifier' ? /IMAP|POP3/i.test(protocol) : name !== 'certificate_novelty' || row.status !== 'NOT_APPLICABLE'
      const status = String(row.status ?? (value[name] == null ? 'NO_OUTPUT' : 'UNKNOWN'))
      const prediction = row.prediction ?? row.predicted_risk_tier ?? row.predicted_tier_proxy ?? row.predicted_class ?? row.risk_tier ?? row.classification ?? row.label ?? row.novelty_flag ?? row.anomaly_flag
      const predictionLabel = prediction === undefined ? '—' : mlPredictionLabel(prediction)
      const completed = status.startsWith('COMPLETED')
      const coverage = typeof row.feature_coverage === 'number' ? Math.max(0, Math.min(1, row.feature_coverage)) : null
      const confidenceValue = row.confidence ?? row.confidence_score_uncalibrated
      const scoreValue = row.anomaly_score ?? row.novelty_score ?? row.certificate_novelty_score ?? row.proxy_issue_score ?? row.empirical_frequency
        ?? row.configuration_rarity_bits ?? row.isolation_forest_score
      const scoreLabel = row.anomaly_score !== undefined || row.isolation_forest_score !== undefined ? 'Anomaly score' : row.novelty_score !== undefined || row.certificate_novelty_score !== undefined ? 'Novelty score' : row.proxy_issue_score !== undefined ? 'Pattern score' : row.empirical_frequency !== undefined ? 'Observed frequency' : 'Configuration rarity score'
      const reason = row.reason ?? row.interpretation_note ?? row.feature_observability_note
      const cues = Array.isArray(row.novelty_cues) ? row.novelty_cues.filter((cue): cue is string => typeof cue === 'string') : []
      const limitations = Array.isArray(row.limitations) ? row.limitations.filter((item): item is string => typeof item === 'string') : []
      const classScores = isObject(row.class_scores_uncalibrated) ? Object.entries(row.class_scores_uncalibrated) : []
      const featureInfo = isObject(row.feature_observability) ? row.feature_observability : {}
      const observedFields = typeof featureInfo.observed_fields === 'number' && typeof featureInfo.candidate_fields === 'number' ? `${featureInfo.observed_fields} of ${featureInfo.candidate_fields} inputs observed` : ''
      const referenceCount = row.reference_sample_count ?? row.reference_count
      const trainingCount = row.training_sample_count
      const sourceName = String(row.data_source ?? '')
      const sourceLabel = sourceName.includes('synthetic') ? 'Simulated email scenarios' : sourceName.includes('certificate') ? 'SMTP-related certificate scans' : sourceName.includes('zgrab') ? 'Real SMTP scan observations' : ''
      const notApplicable = status === 'NOT_APPLICABLE' || (!applicable && value[name] === undefined)
      const displayStatus = notApplicable ? 'NOT_APPLICABLE' : status
      const emptyReason = row.reason ? String(row.reason) : status.startsWith('NOT_EVALUABLE') ? 'Required session features were missing or too incomplete.' : notApplicable ? `This signal does not apply to ${protocol} sessions.` : status === 'NO_OUTPUT' ? 'No result was recorded for this signal.' : ''
      const context = [
        scoreValue !== undefined ? `${scoreLabel}: ${typeof scoreValue === 'number' ? Number(scoreValue.toPrecision(4)).toString() : String(scoreValue)}` : '',
        confidenceValue !== undefined && confidenceValue !== null ? `Confidence: ${typeof confidenceValue === 'number' ? `${Math.round(confidenceValue * 100)}% · uncalibrated` : String(confidenceValue)}` : '',
        referenceCount !== undefined ? `Reference cohort: ${referenceCount}` : '',
        trainingCount !== undefined ? `Training observations: ${trainingCount}` : '',
        row.configuration_count !== undefined ? `${row.configuration_count} matching configurations` : '',
        row.cohort !== undefined ? `Compared with ${cohortLabels[String(row.cohort)] ?? mlPredictionLabel(row.cohort)}` : '',
        sourceLabel ? `Source: ${sourceLabel}` : '',
      ].filter(Boolean).join(' · ')
      const explanation = [reason, cues.length ? `Signals considered: ${cues.join('; ')}` : '', classScores.length ? `Uncalibrated class scores: ${classScores.map(([label, score]) => `${mlPredictionLabel(label)} ${typeof score === 'number' ? `${Math.round(score * 100)}%` : score}`).join(' · ')}` : '', row.score_semantics ?? limitations[0]].filter((part) => typeof part === 'string' && part.length > 0).join(' ')
      return <tr key={name}><th scope="row"><b>{ML_DISPLAY_NAMES[name] ?? 'Additional ML signal'}</b>{sourceLabel && <small>{sourceLabel}</small>}</th><td><span className={completed ? 'ml-table-result' : 'ml-table-no-result'}>{completed ? predictionLabel : '—'}</span></td><td><Badge tone={mlStatusTone(displayStatus)}>{mlStatusLabel(displayStatus)}</Badge>{!completed && <small className="ml-table-explanation">{emptyReason || 'No output available for this session.'}</small>}</td><td>{coverage === null ? '—' : <div className="ml-table-coverage"><span>{Math.round(coverage * 100)}%</span><i><b style={{ width: `${coverage * 100}%` }}/></i>{observedFields && <small>{observedFields}</small>}</div>}</td><td>{context && <span className="ml-table-context">{context}</span>}{explanation && <small className="ml-table-explanation">{explanation}</small>}</td></tr>
    })}</tbody></table></div>
    {Object.keys(assessment).length > 0 && <div className="ml-assessment-summary"><div><small>COMBINED ML RISK</small><b>{assessment.combined_risk_score === null || assessment.combined_risk_score === undefined ? '—' : String(assessment.combined_risk_score)}</b><span>{assessment.predicted_tier_proxy ? mlPredictionLabel(assessment.predicted_tier_proxy) : 'No combined risk tier is produced'}</span></div><p>{text(assessment.authority_note, 'These advisory outputs are separate from the deterministic Rule Engine.')}</p></div>}
  </div>
}

function ThreatPage({ summary }: { summary: AnalysisSummary | null }) {
  const [report, setReport] = useState<ThreatPrioritization | null>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)
  const runId = summary?.run_id ?? null
  useEffect(() => {
    if (!runId) { setReport(null); setError(""); setBusy(false); return }
    let active = true
    setBusy(true); setError(""); setReport(null)
    api.getThreatPrioritization(runId)
      .then((value) => { if (active) setReport(value) })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : "Could not prioritize this analysis.") })
      .finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [runId, reload])

  const priorityTone = (priority: string) => priority === "P1" || priority === "P2" ? "badge-red" : priority === "P3" ? "badge-amber" : "badge-muted"
  const items = report?.items ?? []
  const kevCount = items.reduce((count, item) => count + item.cve_enrichment.filter((entry) => isObject(entry.kev) && entry.kev.listed === true).length, 0)
  const cveCount = items.reduce((count, item) => count + item.cve_enrichment.length, 0)
  return <div className="page-content">
    <SectionTitle eyebrow="THREAT CONTEXT · AUTOMATIC · EVIDENCE-LINKED" title="Threat prioritization" detail="Priorities are generated from deterministic findings in the selected PCAP. KEV and EPSS are added only when the evidence contains an explicit CVE link." />
    {!summary ? <section className="panel threat-empty"><span className="eyebrow">NO ACTIVE CAPTURE</span><h2>Select a PCAP to prioritize</h2><p>Use the current capture selector in the top bar. Findings and recommendations load automatically.</p></section> : <>
      <section className="panel threat-scope"><div><span className="eyebrow">SELECTED ANALYSIS</span><h2>{summary.source_name}</h2><p>{summary.total_streams} reconstructed streams · priorities update automatically when you switch captures</p></div></section>
      {error && <div role="alert" className="alert alert-error"><span>{error}</span><button onClick={() => setReload((value) => value + 1)}>Retry</button></div>}
      {busy && !report ? <section className="panel threat-empty"><span className="eyebrow">ANALYSIS</span><h2>Prioritizing observed findings…</h2></section> : report && <>
        <div className="threat-kpis">
          <div><small>PRIORITIZED FINDING TYPES</small><b>{items.length}</b></div>
          <div><small>STREAMS WITH FINDINGS</small><b>{report.streams_with_findings}<i> / {report.total_streams}</i></b></div>
          <div><small>KEV-LINKED</small><b>{kevCount}</b></div>
          <div><small>CVE ENRICHMENTS</small><b>{cveCount}</b></div>
        </div>
        {items.length ? <section className="threat-priority-list" aria-label="Prioritized security findings">
          {items.map((item) => <article className="panel threat-priority-card" key={item.family}>
            <header><span className="threat-rank">{String(item.rank).padStart(2, "0")}</span><div className="threat-priority-title"><span className="eyebrow">{item.priority} · {item.priority_label} PRIORITY</span><h2>{item.title}</h2></div><Badge tone={priorityTone(item.priority)}>{item.severity}</Badge></header>
            <div className="threat-impact"><span>{item.affected_stream_count} affected {item.affected_stream_count === 1 ? "stream" : "streams"} · {item.evidence_count} evidence record{item.evidence_count === 1 ? "" : "s"}</span><span>Streams {item.affected_streams.join(", ")}</span></div>
            <div className="threat-recommendation"><small>RECOMMENDED ACTION</small><p>{item.recommendation}</p></div>
            <p className="threat-priority-basis">{item.priority_basis}</p>
            <details className="threat-evidence"><summary>View supporting evidence</summary><pre className="data-block">{pretty(item.evidence)}</pre></details>
            {item.cve_enrichment.length > 0 && <div className="threat-linked-cves"><small>LINKED VULNERABILITY CONTEXT</small>{item.cve_enrichment.map((entry) => {
              const kev = isObject(entry.kev) ? entry.kev : {}
              const epss = isObject(entry.epss) ? entry.epss : {}
              const probability = typeof epss.probability === "number" ? (epss.probability * 100).toFixed(2) + "%" : "Unavailable"
              return <p key={String(entry.cve_id)}><b>{String(entry.cve_id)}</b><Badge tone={priorityTone(String(entry.priority))}>{String(entry.priority)}</Badge><span>{kev.listed ? "CISA KEV" : "Not in KEV"} · EPSS {probability}</span></p>
            })}</div>}
          </article>)}
        </section> : <section className="panel threat-empty"><span className="eyebrow">NO PRIORITIZED FINDINGS</span><h2>No deterministic priority findings recorded</h2><p>{text(report.note, "This does not establish that unobservable traffic or unavailable evidence is safe.")}</p></section>}
        <section className="panel threat-cve-note"><div><span className="eyebrow">CVE ENRICHMENT · KEV + EPSS</span><h2>{cveCount ? "Evidence-linked CVEs enriched" : "No evidence-linked CVEs in this capture"}</h2><p>{report.cve_link_policy}</p></div>{cveCount === 0 && <Badge tone="badge-muted">NOT MAPPED</Badge>}</section>
      </>}
    </>}
  </div>
}
function ReportsPage({ activeSummary, activeDetail }: { activeSummary: AnalysisSummary | null; activeDetail: AnalysisDetail | null }) {
  return <div className="page-content"><SectionTitle eyebrow="CASE OUTPUTS" title="Forensic reports" detail="Review and export the selected capture as a structured forensic artifact." />
    <section className="panel report-preview report-preview-full">{activeSummary && activeDetail ? <><div className="report-preview-top"><div><span className="eyebrow">EVIDENCE REPORT</span><h2>{activeSummary.source_name}</h2><p className="muted">{runTime(activeSummary.created_at)} · {activeDetail.report.total_streams} TCP streams · case {activeSummary.run_id.slice(0, 12)}</p></div><ExportActions summary={activeSummary} detail={activeDetail} /></div><ReportPreview report={activeDetail.report} /></> : activeSummary ? <EmptyState title="Loading saved report" copy="The selected capture is being loaded."/> : <EmptyState title="Select a capture" copy="Use the searchable Current Capture control above to choose a PCAP, then review or export its forensic report."/>}</section>
  </div>
}

function ReportPreview({ report }: { report: AnalysisReport }) {
  const streams = flattenStreams(report)
  const failures = streams.flatMap((stream) => failedRules(stream))
  const observed = streams.flatMap((stream) => stream.observations ?? []).filter((item) => item.detected)
  const protocols: Record<string, number> = {}
  const tlsVersions: Record<string, number> = {}
  const ruleOutcomes: Record<string, number> = {}
  const mlAvailability: Record<string, number> = {}
  const postureTiers: Record<string, number> = {}
  let observedCertificates = 0
  for (const stream of streams) {
    protocols[stream.protocol] = (protocols[stream.protocol] ?? 0) + 1
    const snapshot = stream.input_snapshot ?? {}
    const tls = isObject(snapshot.tls) ? snapshot.tls : snapshot
    const version = tls.tls_version ?? tls.tls_selected_version ?? tls.version
    const tlsLabel = version === undefined || version === null || version === '' ? 'TLS not observed' : String(version)
    tlsVersions[tlsLabel] = (tlsVersions[tlsLabel] ?? 0) + 1
    const certificate = isObject(snapshot.certificate) ? snapshot.certificate : snapshot
    if (certificate.observable === true || certificate.certificate_observed === true || isObject(certificate.leaf_cert)) observedCertificates++
    for (const items of Object.values(stream.policy_results ?? {})) for (const item of items) {
      const verdict = String(item.verdict ?? 'UNKNOWN').replaceAll('_', ' ')
      ruleOutcomes[verdict] = (ruleOutcomes[verdict] ?? 0) + 1
    }
    for (const result of Object.values(stream.ml_results ?? {})) if (isObject(result) && result.status !== 'ADVISORY_REAL_ZGRAB_RUBRIC_AVAILABLE') {
      const state = result.status === 'NOT_APPLICABLE' ? 'Not applicable' : String(result.status ?? 'UNKNOWN').startsWith('COMPLETED') ? 'Result available' : mlStatusLabel(result.status)
      mlAvailability[state] = (mlAvailability[state] ?? 0) + 1
    }
    const tier = String(stream.posture_assessment?.tier ?? 'Not evaluated')
    postureTiers[tier] = (postureTiers[tier] ?? 0) + 1
  }
  return <div className="forensic-report-preview">
    <header className="report-cover-preview"><span className="eyebrow">PASSIVE EMAIL FORENSICS · CASE REPORT</span><h2>Cryptographic posture assessment</h2><p>Evidence-led summary of reconstructed streams, negotiated TLS, certificate visibility, deterministic policy outcomes, and advisory ML results.</p></header>
    <div className="preview-metrics"><Metric label="RECONSTRUCTED STREAMS" value={streams.length}/><Metric label="POLICY FAILURES" value={failures.length}/><Metric label="DETECTED OBSERVATIONS" value={observed.length}/><Metric label="CERTIFICATES OBSERVED" value={observedCertificates}/></div>
    <section className="report-preview-section"><div className="report-section-title"><span className="eyebrow">01 · OBSERVED PROFILE</span><h3>Traffic and policy overview</h3><p>Charts use counts from this saved report. Missing evidence is shown separately from policy passes.</p></div><div className="report-preview-charts"><ReportBarChart title="Mail protocols" values={protocols}/><ReportBarChart title="Observed TLS versions" values={tlsVersions}/><ReportBarChart title="Policy outcomes" values={ruleOutcomes}/><ReportBarChart title="ML output availability" values={mlAvailability}/><ReportBarChart title="Deterministic posture tiers" values={postureTiers}/></div></section>
    <section className="report-preview-section"><div className="report-section-title"><span className="eyebrow">02 · DETERMINISTIC FINDINGS</span><h3>{failures.length ? `${failures.length} policy failures` : 'No policy failures recorded'}</h3><p>The Rule Engine provides deterministic standards checks. These remain authoritative when interpreting advisory ML output.</p></div>{failures.length ? <div className="report-finding-list">{streams.flatMap((stream) => failedRules(stream).map((item, index) => <article key={`${stream.stream_id}-${item.rule_id}-${index}`}><span>SESSION {String(stream.stream_id).padStart(3, '0')} · {item.source_id ?? item.policy ?? 'POLICY CHECK'}</span><h4>{item.name ?? item.rule_id ?? 'Policy failure'}</h4><p>{item.finding ?? 'A deterministic policy check failed.'}</p>{item.evidence?.length ? <small>{item.evidence.slice(0, 2).map((evidence) => `${text(evidence.field, 'Evidence')}: ${text(evidence.value)}`).join(' · ')}</small> : null}</article>))}</div> : <p className="report-no-failures">No deterministic failures were recorded. This does not mean missing or unobservable evidence is safe.</p>}</section>
    <section className="report-preview-section"><div className="report-section-title"><span className="eyebrow">03 · SESSION RECORDS</span><h3>Stream-by-stream evidence</h3><p>Includes available transport, posture, certificate, policy, observation, recommendation, and ML information.</p></div><div className="report-session-list">{streams.map((stream) => <article key={stream.stream_id} className="report-session-preview"><StreamEvidence stream={stream}/></article>)}</div></section>
    <section className="report-preview-limit"><b>Interpretation and limits</b><p>Posture scores are deterministic heuristics, not ML probabilities. ML confidence values are uncalibrated. Novelty means unusual relative to a reference cohort; it does not mean insecure or malicious. Certificate or TLS fields absent from a passive capture are reported as unobserved, not as safe.</p></section>
  </div>
}

function ReportBarChart({ title, values }: { title: string; values: Record<string, number> }) {
  const entries = Object.entries(values).sort((a, b) => b[1] - a[1])
  const maximum = Math.max(1, ...entries.map(([, count]) => count))
  return <figure className="report-bar-chart" aria-label={`${title}: ${entries.map(([label, count]) => `${label} ${count}`).join(', ') || 'no observations'}`}><figcaption>{title}</figcaption>{entries.length ? <div>{entries.map(([label, count]) => <div className="report-bar-row" key={label}><span>{label}</span><i><b style={{ width: `${count / maximum * 100}%` }}/></i><strong>{count}</strong></div>)}</div> : <p>No observations.</p>}</figure>
}
