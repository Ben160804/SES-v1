import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type DragEvent, type ReactNode, type RefObject } from 'react'
import { api, uploadAnalysis, type AnalysisDetail, type AnalysisReport, type AnalysisSummary, type ModelCatalog, type PolicyResult, type StreamReport, type ThreatResponse } from './lib/api'

type Props = { Brand: ComponentType<{ compact?: boolean }> }
type Tab = 'overview' | 'captures' | 'findings' | 'sessions' | 'timeline' | 'intelligence' | 'ml' | 'reports'
type QueueStatus = 'queued' | 'uploading' | 'analyzing' | 'stored' | 'failed' | 'cancelled'
type QueueItem = { key: string; file: File; status: QueueStatus; sent: number; total: number; error?: string; runId?: string }

const MAX_UPLOAD = 512 * 1024 * 1024
const NAV: Array<{ id: Tab; label: string; glyph: string }> = [
  { id: 'overview', label: 'Overview', glyph: '◫' },
  { id: 'captures', label: 'PCAP analysis', glyph: '⇧' },
  { id: 'findings', label: 'Findings', glyph: '!' },
  { id: 'sessions', label: 'Sessions & evidence', glyph: '≋' },
  { id: 'timeline', label: 'Evidence timeline', glyph: '◷' },
  { id: 'intelligence', label: 'Threat context', glyph: '⌁' },
  { id: 'ml', label: 'ML models', glyph: '∿' },
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
function SectionTitle({ eyebrow, title, detail, action }: { eyebrow?: string; title: string; detail?: string; action?: ReactNode }) {
  return <div className="section-title"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{detail && <p className="muted">{detail}</p>}</div>{action}</div>
}
function EmptyState({ title, copy, action }: { title: string; copy: string; action?: ReactNode }) { return <div className="empty-state"><span className="empty-glyph">∅</span><h3>{title}</h3><p>{copy}</p>{action}</div> }
function Metric({ label, value, sub }: { label: string; value: string | number; sub?: string }) { return <article className="metric"><span>{label}</span><strong>{value}</strong>{sub && <small>{sub}</small>}</article> }

function ExportActions({ summary, detail }: { summary: AnalysisSummary; detail: AnalysisDetail }) {
  const json = () => {
    const envelope = { report_metadata: { run_id: summary.run_id, source_name: summary.source_name, created_at: summary.created_at, total_streams: summary.total_streams }, report: detail.report }
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
function buildHtmlReport(summary: AnalysisSummary, report: AnalysisReport, print = false) {
  const streams = flattenStreams(report)
  const rows = streams.map((stream) => {
    const snapshot = stream.input_snapshot ?? {}
    const tls = isObject(snapshot.tls) ? snapshot.tls : snapshot
    const rules = failedRules(stream)
    return `<tr><td>${stream.stream_id}</td><td>${esc(stream.protocol)}</td><td>${esc((tls as Record<string, unknown>).tls_version ?? (tls as Record<string, unknown>).version)}</td><td>${esc((tls as Record<string, unknown>).cipher_name ?? (tls as Record<string, unknown>).cipher_suite)}</td><td>${rules.length}</td><td>${esc(stream.posture_assessment?.score ?? '—')}</td></tr>`
  }).join('')
  const findings = streams.flatMap((stream) => failedRules(stream).map((item) => `<li><b>${esc(item.name ?? item.rule_id)}</b> · stream ${stream.stream_id}<br>${esc(item.finding ?? '')}</li>`)).join('')
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>SecureMailScope report — ${esc(summary.source_name)}</title><style>body{font:15px/1.6 system-ui,sans-serif;color:#19191b;max-width:1000px;margin:50px auto;padding:0 24px}h1{font-size:34px}h2{margin-top:40px;border-bottom:1px solid #ddd;padding-bottom:8px}.meta{color:#555}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:9px;border-bottom:1px solid #ddd}th{background:#f5eeee}li{margin:12px 0}.note{padding:14px;background:#f6f1f1;border-left:3px solid #ae5559}.print{${print ? 'display:none' : ''}}@media print{body{margin:0 auto}.print{display:none}}</style><body><p class="meta">SECUREMAILSCOPE · PASSIVE EMAIL FORENSICS</p><h1>Analysis report</h1><p class="meta">Capture: ${esc(summary.source_name)} · Analysed: ${esc(runTime(summary.created_at))} · Streams: ${streams.length}</p><div class="note">Rule-engine findings are deterministic policy results. Machine-learning outputs and posture summaries are separate advisory results. Unknown or unavailable evidence is not interpreted as safe.</div><h2>Stream summary</h2><table><thead><tr><th>Stream</th><th>Protocol</th><th>TLS version</th><th>Cipher</th><th>Rule findings</th><th>Posture heuristic</th></tr></thead><tbody>${rows || '<tr><td colspan="6">No reconstructed streams</td></tr>'}</tbody></table><h2>Deterministic findings</h2><ul>${findings || '<li>No policy failures were recorded in this analysis.</li>'}</ul><h2>Machine-readable record</h2><pre>${esc(JSON.stringify(report, null, 2))}</pre><button class="print" onclick="window.print()">Print / Save as PDF</button><p class="meta">Generated locally by SecureMailScope. This report reflects observable capture evidence and stated analysis limitations.</p></body></html>`
}

export function Workspace({ Brand }: Props) {
  const [tab, setTab] = useState<Tab>(() => {
    const candidate = window.location.hash.split('/').at(-1) as Tab | undefined
    return NAV.some((item) => item.id === candidate) ? candidate! : 'overview'
  })
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([])
  const [details, setDetails] = useState<Record<string, AnalysisDetail>>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [catalog, setCatalog] = useState<ModelCatalog | null>(null)
  const [apiState, setApiState] = useState<'checking' | 'online' | 'offline'>('checking')
  const [pageError, setPageError] = useState('')
  const [loading, setLoading] = useState(true)
  const [queue, setQueue] = useState<QueueItem[]>([])
  const [trustStore, setTrustStore] = useState('testbed')
  const [enableMl, setEnableMl] = useState(true)
  const [filter, setFilter] = useState('')
  const [selectedStream, setSelectedStream] = useState<number | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const dragDepth = useRef(0)
  const [dragging, setDragging] = useState(false)
  const aborters = useRef(new Map<string, () => void>())

  const refresh = useCallback(async () => {
    setPageError('')
    try {
      const [health, list, models] = await Promise.all([api.health(), api.listAnalyses(100), api.getModels()])
      setApiState(health.status === 'ok' ? 'online' : 'offline')
      setAnalyses(list.items)
      setCatalog(models)
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
    document.title = `${NAV.find((item) => item.id === tab)?.label ?? 'Workspace'} — SecureMailScope`
  }, [tab])
  useEffect(() => {
    if (!selected || details[selected] || apiState !== 'online') return
    let active = true
    api.getAnalysis(selected).then((detail) => { if (active) setDetails((current) => ({ ...current, [selected]: detail })) })
      .catch((error: unknown) => { if (active) setPageError(error instanceof Error ? error.message : 'Could not load report details.') })
    return () => { active = false }
  }, [selected, details, apiState])

  const activeSummary = analyses.find((item) => item.run_id === selected) ?? null
  const activeDetail = selected ? details[selected] ?? null : null
  const streams = useMemo(() => flattenStreams(activeDetail?.report ?? null), [activeDetail])
  const findingRows = useMemo(() => allFindings(activeDetail?.report ?? null), [activeDetail])
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

  const processQueue = useCallback(async () => {
    for (const item of queue) {
      if (item.status !== 'queued') continue
      setQueue((current) => current.map((row) => row.key === item.key ? { ...row, status: 'uploading' } : row))
      try {
        const result = await uploadAnalysis(item.file, { trustStore, enableMl }, (sent, total) => {
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
  }, [queue, refresh, trustStore, enableMl])

  const queueBusy = queue.some((item) => item.status === 'uploading' || item.status === 'analyzing')
  const hasQueued = queue.some((item) => item.status === 'queued')
  const acceptDrop = (event: DragEvent) => { event.preventDefault(); dragDepth.current = 0; setDragging(false); if (event.dataTransfer.files.length) addFiles(event.dataTransfer.files) }

  const navTo = (next: Tab) => { setTab(next); setPageError(''); window.history.pushState({}, '', `/workspace#/${next}`) }
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
      <header className="workspace-top"><div className="breadcrumbs"><a href="/">SECUREMAILSCOPE</a><span>/</span><span>{NAV.find((item) => item.id === tab)?.label.toUpperCase()}</span></div><div className="top-actions"><span className={`connection ${apiState}`}>{apiState === 'online' ? 'Connected to local API' : apiState === 'checking' ? 'Connecting…' : 'API unavailable'}</span><button className="button button-small" onClick={() => void refresh()} disabled={loading}>Refresh</button></div></header>
      {pageError && <div role="alert" className="alert alert-error"><span>{pageError}</span><button onClick={() => void refresh()}>Retry</button></div>}
      {apiState === 'offline' && <div className="offline-panel"><span className="offline-mark">!</span><div><b>Analysis service is not reachable.</b><p>Start the local API at <code>127.0.0.1:8000</code>, then retry. The workspace will not show fabricated reports or metrics.</p></div><button className="button button-small" onClick={() => void refresh()}>Retry connection</button></div>}
      {tab === 'overview' && <OverviewPage analyses={analyses} activeSummary={activeSummary} streams={streams} findings={findingRows} postureAverage={postureAverage} loading={loading} onGo={navTo} onSelect={setSelected} />}
      {tab === 'captures' && <CapturesPage analyses={visibleAnalyses} allCount={analyses.length} filter={filter} setFilter={setFilter} inputRef={inputRef} queue={queue} addFiles={addFiles} processQueue={processQueue} queueBusy={queueBusy} hasQueued={hasQueued} trustStore={trustStore} setTrustStore={setTrustStore} enableMl={enableMl} setEnableMl={setEnableMl} aborters={aborters.current} retryItem={retryItem} removeItem={removeItem} clearCompleted={clearCompleted} onSelect={setSelected} onTab={navTo} />}
      {tab === 'findings' && <FindingsPage findings={findingRows} summary={activeSummary} onGo={() => navTo('captures')} />}
      {tab === 'sessions' && <SessionsPage streams={streams} selectedStream={selectedStream} setSelectedStream={setSelectedStream} summary={activeSummary} />}
      {tab === 'timeline' && <TimelinePage streams={streams} summary={activeSummary} />}
      {tab === 'intelligence' && <ThreatPage />}
      {tab === 'ml' && <MLPage catalog={catalog} streams={streams} />}
      {tab === 'reports' && <ReportsPage analyses={visibleAnalyses} filter={filter} setFilter={setFilter} activeSummary={activeSummary} activeDetail={activeDetail} selected={selected} onSelect={setSelected} loading={loading} />}
      {dragging && <div className="drop-overlay" role="presentation"><div><span>↓</span><b>Drop captures to add them to the analysis queue</b><small>PCAP and PCAPNG · up to 512 MiB per file</small></div></div>}
    </main>
  </div>
}

function OverviewPage({ analyses, activeSummary, streams, findings, postureAverage, loading, onGo, onSelect }: { analyses: AnalysisSummary[]; activeSummary: AnalysisSummary | null; streams: StreamReport[]; findings: ReturnType<typeof allFindings>; postureAverage: number | null; loading: boolean; onGo: (tab: Tab) => void; onSelect: (id: string) => void }) {
  const counts = streams.reduce<Record<string, number>>((result, stream) => { result[stream.protocol] = (result[stream.protocol] ?? 0) + 1; return result }, {})
  const topAnalyses = analyses.slice(0, 6)
  return <div className="page-content">
    <SectionTitle eyebrow="FORENSIC CONSOLE / OVERVIEW" title="Analysis overview" detail="A live view of persisted PCAP analyses. Counts reflect the selected report and local archive." action={<button className="button button-primary" onClick={() => onGo('captures')}>＋ Analyze PCAPs</button>} />
    {!analyses.length && !loading ? <EmptyState title="No analyses in the archive" copy="Upload a PCAP or PCAPNG capture to begin. Analysis runs are saved by the local backend." action={<button className="button button-primary" onClick={() => onGo('captures')}>Open PCAP analysis</button>} /> : <>
      <div className="metric-grid overview-metrics"><Metric label="ARCHIVED ANALYSES" value={analyses.length} sub="Stored analysis reports"/><Metric label="TCP STREAMS" value={activeSummary ? streams.length : '—'} sub={activeSummary ? activeSummary.source_name : 'Choose a report to inspect'}/><Metric label="DETERMINISTIC FINDINGS" value={activeSummary ? findings.filter((item) => item.kind === 'POLICY').length : '—'} sub="Policy failures in selected report"/><Metric label="POSTURE HEURISTIC" value={postureAverage === null ? '—' : `${postureAverage}/100`} sub="Mean of evaluable stream scores; not an ML probability"/></div>
      <div className="content-grid overview-grid">
        <section className="panel"><div className="panel-head"><div><span className="eyebrow">SELECTED REPORT</span><h2>{activeSummary?.source_name ?? 'Choose a report'}</h2></div><button className="text-button" onClick={() => onGo('reports')}>All reports →</button></div>
          {!activeSummary ? <p className="muted">Select a report from the archive to view its analysis.</p> : <><div className="report-meta"><span>{runTime(activeSummary.created_at)}</span><span>{streams.length} streams analyzed</span><span className="mono">{activeSummary.run_id.slice(0, 12)}</span></div><div className="protocol-strip">{['SMTP', 'IMAP', 'POP3'].map((name) => <div key={name}><small>{name}</small><b>{counts[name] ?? 0}</b><span>streams</span></div>)}</div><div className="bar-list">{Object.entries(counts).map(([name, count]) => <div key={name} className="bar-row"><span>{name}</span><div className="bar-track"><i style={{ width: `${streams.length ? count / streams.length * 100 : 0}%` }} /></div><b>{count}</b></div>)}</div></>}
        </section>
        <section className="panel"><div className="panel-head"><div><span className="eyebrow">LOCAL ARCHIVE</span><h2>Recent analyses</h2></div><button className="text-button" onClick={() => onGo('captures')}>Upload more →</button></div>
          {topAnalyses.length ? <div className="archive-list">{topAnalyses.map((item) => <button key={item.run_id} className={`archive-row ${item.run_id === activeSummary?.run_id ? 'selected' : ''}`} onClick={() => onSelect(item.run_id)}><span className="file-mark">PC</span><span className="archive-name"><b>{item.source_name}</b><small>{runTime(item.created_at)}</small></span><span className="archive-streams">{item.total_streams} streams</span><span className="arrow">↗</span></button>)}</div> : <p className="muted">{loading ? 'Loading analyses…' : 'No saved analyses yet.'}</p>}
        </section>
      </div>
      <section className="panel recent-findings"><div className="panel-head"><div><span className="eyebrow">SELECTED REPORT</span><h2>Findings at a glance</h2></div><button className="text-button" onClick={() => onGo('findings')}>Inspect findings →</button></div>{findings.length ? <div className="finding-preview">{findings.slice(0, 5).map((finding, index) => <div key={`${finding.id}-${finding.stream.stream_id}-${index}`} className="finding-preview-row"><Badge tone={finding.kind === 'POLICY' ? 'badge-red' : 'badge-muted'}>{finding.kind}</Badge><span><b>{finding.title}</b><small>Stream {finding.stream.stream_id} · {finding.id}</small></span><span className="finding-kind">{finding.severity}</span></div>)}</div> : <p className="muted">{activeSummary ? 'No failed policy checks or detected observations were recorded.' : 'Select an analysis to inspect findings.'}</p>}</section>
    </>}
  </div>
}

function CapturesPage(props: {
  analyses: AnalysisSummary[]; allCount: number; filter: string; setFilter: (value: string) => void; inputRef: RefObject<HTMLInputElement>; queue: QueueItem[]; addFiles: (files: FileList | File[]) => void; processQueue: () => Promise<void>; queueBusy: boolean; hasQueued: boolean; trustStore: string; setTrustStore: (value: string) => void; enableMl: boolean; setEnableMl: (value: boolean) => void; aborters: Map<string, () => void>; retryItem: (key: string) => void; removeItem: (key: string) => void; clearCompleted: () => void; onSelect: (id: string) => void; onTab: (tab: Tab) => void
}) {
  return <div className="page-content">
    <SectionTitle eyebrow="CAPTURE INGESTION" title="PCAP analysis" detail="Submit one or several captures. Each file is analyzed by the local backend and its report is persisted in SQLite." />
    <div className="upload-settings"><label>Certificate trust store<select value={props.trustStore} onChange={(event) => props.setTrustStore(event.target.value)}><option value="testbed">Testbed roots</option><option value="system">Operating-system roots</option><option value="production">Configured production roots</option></select></label><label className="toggle-label"><input type="checkbox" checked={props.enableMl} onChange={(event) => props.setEnableMl(event.target.checked)} /><span>Run advisory ML inference</span></label><span className="muted setting-note">ML results remain separate from deterministic findings.</span></div>
    <input id="capture-files" ref={props.inputRef} aria-label="Select PCAP and PCAPNG files" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/vnd.tcpdump.pcapng" multiple hidden onChange={(event) => { if (event.target.files) props.addFiles(event.target.files); event.target.value = '' }} />
    <button className="upload-zone" onClick={() => props.inputRef.current?.click()}><span className="upload-symbol">↑</span><b>Choose packet captures</b><span>or drag files anywhere into this workspace</span><small>PCAP / PCAPNG · max 512 MiB per capture</small></button>
    {props.queue.length > 0 && <section className="panel queue-panel"><div className="panel-head"><div><span className="eyebrow">UPLOAD QUEUE</span><h2>{props.queue.length} capture{props.queue.length === 1 ? '' : 's'}</h2></div><div className="button-row"><button className="button button-small" onClick={() => props.inputRef.current?.click()}>Add captures</button><button className="button button-small" onClick={props.clearCompleted} disabled={props.queueBusy || !props.queue.some((item) => item.status === 'stored' || item.status === 'failed' || item.status === 'cancelled')}>Clear completed</button><button className="button button-primary button-small" onClick={() => void props.processQueue()} disabled={!props.hasQueued || props.queueBusy}>{props.queueBusy ? 'Processing queue…' : `Analyze ${props.queue.filter((item) => item.status === 'queued').length} queued`}</button></div></div>
      <div className="queue-list">{props.queue.map((item) => <div key={item.key} className="queue-row"><span className="file-mark">PC</span><div className="queue-file"><b>{item.file.name}</b><small>{bytes(item.file.size)} {item.runId ? `· report ${item.runId.slice(0, 10)}` : ''}</small>{item.status === 'uploading' && <div className="progress-track"><i style={{ width: `${item.total ? item.sent / item.total * 100 : 0}%` }} /></div>}</div><Badge tone={item.status === 'failed' ? 'badge-red' : item.status === 'stored' ? 'badge-green' : ''}>{item.status}</Badge>{item.error && <span className="queue-error">{item.error}</span>}{(item.status === 'uploading' || item.status === 'analyzing') ? <button className="text-button" onClick={() => props.aborters.get(item.key)?.()}>Cancel</button> : item.status === 'failed' ? <button className="text-button" onClick={() => props.retryItem(item.key)}>Retry</button> : <button className="text-button" onClick={() => props.removeItem(item.key)}>Remove</button>}</div>)}</div>
      <p className="muted small-copy">Processing is sequential to limit local resource use. Byte progress reflects actual browser upload progress; analysis duration is reported as a working state, not a fabricated percentage. Stopping an in-progress transfer cannot cancel work the server has already started.</p></section>}
    <section className="panel archive-panel"><div className="panel-head"><div><span className="eyebrow">PERSISTED IN THE LOCAL DATABASE</span><h2>Analysis archive <span className="count-pill">{props.allCount}</span></h2></div><input className="search-input" value={props.filter} onChange={(event) => props.setFilter(event.target.value)} placeholder="Filter file or run ID" aria-label="Filter analysis archive" /></div>
      {props.analyses.length ? <div className="archive-table-wrap"><table className="archive-table"><thead><tr><th>Capture</th><th>Analysed</th><th>Streams</th><th>Report ID</th><th /></tr></thead><tbody>{props.analyses.map((item) => <tr key={item.run_id}><td><b>{item.source_name}</b></td><td>{runTime(item.created_at)}</td><td>{item.total_streams}</td><td className="mono">{item.run_id.slice(0, 12)}</td><td><button className="text-button" onClick={() => { props.onSelect(item.run_id); props.onTab('reports') }}>Open report →</button></td></tr>)}</tbody></table></div> : <EmptyState title="No matching reports" copy="Try another filter or analyze a capture to populate the archive." />}
    </section>
  </div>
}

function FindingsPage({ findings, summary, onGo }: { findings: ReturnType<typeof allFindings>; summary: AnalysisSummary | null; onGo: () => void }) {
  return <div className="page-content"><SectionTitle eyebrow="DETERMINISTIC POLICY RESULTS" title="Findings" detail={summary ? `Evidence from ${summary.source_name}. Machine-learning estimates are shown separately.` : 'Select an analysis from the report archive to review its findings.'} action={summary ? <Badge>{findings.length} items</Badge> : undefined} />{!summary ? <EmptyState title="No report selected" copy="Analyze a PCAP or select a saved report first." action={<button className="button button-primary" onClick={onGo}>Open capture archive</button>} /> : findings.length ? <div className="finding-list">{findings.map((item, index) => <article className="panel finding-card" key={`${item.stream.stream_id}-${item.id}-${index}`}><div className="finding-card-head"><Badge tone={item.kind === 'POLICY' ? 'badge-red' : 'badge-muted'}>{item.kind}</Badge><span className="mono">{item.id}</span><Badge tone={item.kind === 'POLICY' ? 'badge-red' : ''}>{item.severity}</Badge></div><h2>{item.title}</h2><p>{text(item.note, 'No additional description was included in the report.')}</p><div className="finding-footer"><span>Stream {item.stream.stream_id} · {item.stream.protocol}</span>{item.kind === 'POLICY' && <span>Rule-engine result</span>}</div></article>)}</div> : <EmptyState title="No findings in this report" copy="No policy failures or detected forensic observations were recorded. This does not imply that unavailable evidence is safe." />}</div>
}

function SessionsPage({ streams, selectedStream, setSelectedStream, summary }: { streams: StreamReport[]; selectedStream: number | null; setSelectedStream: (value: number | null) => void; summary: AnalysisSummary | null }) {
  const active = streams.find((stream) => stream.stream_id === selectedStream) ?? null
  if (!summary) return <div className="page-content"><SectionTitle eyebrow="STREAM RECONSTRUCTION" title="Sessions & evidence" detail="Select an analysis from the archive."/><EmptyState title="No report selected" copy="Choose a saved analysis to inspect reconstructed streams." /></div>
  return <div className="page-content"><SectionTitle eyebrow="STREAM RECONSTRUCTION" title="Sessions & evidence" detail={`${summary.source_name} · ${streams.length} reconstructed stream${streams.length === 1 ? '' : 's'}`} />{streams.length ? <div className="sessions-layout"><section className="panel stream-list-panel"><div className="panel-head"><h2>Streams</h2><span className="count-pill">{streams.length}</span></div>{streams.map((stream) => <button key={stream.stream_id} className={`stream-row ${selectedStream === stream.stream_id ? 'selected' : ''}`} onClick={() => setSelectedStream(stream.stream_id)}><span className="stream-id">{String(stream.stream_id).padStart(3, '0')}</span><span className="stream-main"><b>{stream.protocol}</b><small>{findingsCount(stream)} recorded finding{findingsCount(stream) === 1 ? '' : 's'}</small></span><span className="arrow">→</span></button>)}</section><section className="panel stream-detail-panel">{active ? <StreamEvidence stream={active} /> : <EmptyState title="Select a stream" copy="Choose a stream to review TLS, certificate, rule-engine, posture, and ML evidence."/>}</section></div> : <EmptyState title="No streams reconstructed" copy="The capture may contain no analyzable TCP streams. Review report limitations and capture integrity."/>}</div>
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
  const facts: Array<[string, unknown]> = [['TLS version', tls.tls_version ?? tls.version], ['Cipher suite', tls.cipher_name ?? tls.cipher_suite], ['Key exchange', tls.key_exchange ?? tls.tls13_key_exchange_group ?? tls.kex], ['Forward secrecy', tls.forward_secrecy ?? tls.uses_forward_secrecy ?? heuristics.h_forward_secrecy], ['STARTTLS state', starttls.status ?? starttls.outcome ?? (starttls.starttls_status || (starttls.starttls_accepted ? 'UPGRADE_ACCEPTED' : null))], ['Handshake', tls.handshake_status ?? tls.status]]
  return <div className="stream-evidence"><div className="stream-detail-head"><div><span className="eyebrow">STREAM {String(stream.stream_id).padStart(3, '0')}</span><h2>{stream.protocol}</h2></div><Badge>{findingsCount(stream)} findings / observations</Badge></div>
    <h3>Negotiated transport</h3><div className="fact-grid">{facts.map(([label, value]) => <div className="fact" key={label}><small>{label}</small><b>{text(value)}</b></div>)}</div>
    <h3>Certificate evidence</h3>{Object.keys(certificate).length ? <pre className="data-block">{pretty(certificate)}</pre> : <p className="muted">Certificate fields were not present in this stream report.</p>}
    <h3>Deterministic policy checks</h3><div className="rule-list">{rules.map(({ pack, item }, index) => <details className="rule-row rule-detail" key={`${pack}-${item.rule_id}-${index}`}><span className={`verdict-dot verdict-${(item.verdict ?? '').toLowerCase()}`} /><summary><b>{item.name ?? item.rule_id}</b><small>{pack} · {item.rule_id} · {item.applicability_scope ?? 'scope unavailable'}</small></summary><Badge tone={item.verdict === 'FAIL' ? 'badge-red' : ''}>{item.verdict ?? 'UNKNOWN'}</Badge>{item.finding && <p>{item.finding}</p>}<div className="rule-evidence"><p><b>Standard:</b> {item.source_id ?? 'Unavailable'} § {item.source_section ?? '—'} · {item.normative_term ?? 'term unavailable'}</p>{item.source_text && <p>{item.source_text}</p>}{item.evidence?.length ? <pre className="data-block">{pretty(item.evidence)}</pre> : <p>No evidence atoms were recorded for this result.</p>}</div></details>)}</div>
    <h3>Forensic observations</h3><div className="observation-list">{(stream.observations ?? []).length ? stream.observations?.map((item, index) => <div className="observation-row" key={`${item.obs_id}-${index}`}><Badge tone={item.detected ? 'badge-red' : 'badge-muted'}>{item.detected ? 'DETECTED' : 'NOT DETECTED'}</Badge><div><b>{item.name ?? item.obs_id}</b><p>{item.description ?? 'No additional description.'}</p></div></div>) : <p className="muted">No observation records.</p>}</div>
    <h3>Posture assessment <span className="subtle-tag">DETERMINISTIC · NOT ML</span></h3><pre className="data-block">{pretty(stream.posture_assessment ?? {})}</pre>
    <h3>Mitigation guidance <span className="subtle-tag">EVIDENCE-LINKED</span></h3><Recommendations posture={stream.posture_assessment ?? {}} />
    <h3>ML outputs <span className="subtle-tag">ADVISORY</span></h3><MLResults value={stream.ml_results ?? {}} />
  </div>
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
  return <div className="page-content"><SectionTitle eyebrow="PACKET-PROVENANCE VIEW" title="Evidence timeline" detail={summary ? `${summary.source_name} · timeline includes only packet references present in the analysis report.` : 'Select an analysis to inspect packet-linked evidence.'}/>{!summary ? <EmptyState title="No report selected" copy="Choose a saved analysis first."/> : events.length ? <section className="panel timeline-panel"><div className="panel-head"><div><span className="eyebrow">OBSERVED EVIDENCE ATOMS</span><h2>{events.length} evidence references</h2></div><Badge>Ordering by frame where available</Badge></div><div className="timeline-list">{events.map((event,index)=><article key={`${event.streamId}-${event.frame}-${event.field}-${index}`} className="timeline-event"><span className="timeline-pin"/><div className="timeline-time">{event.frame === null ? 'FRAME —' : `FRAME ${event.frame}`}<small>STREAM {event.streamId} · {event.protocol}</small></div><div className="timeline-copy"><b>{event.field}</b><code>{text(event.value)}</code><small>{event.source}</small></div><Badge tone={event.frame === null ? 'badge-muted' : 'badge-green'}>{event.status}</Badge></article>)}</div><p className="muted small-copy">A frame number is shown only when the parser linked evidence to one. Entries without a frame are not assigned a synthetic timestamp or packet order.</p></section> : <EmptyState title="No packet-linked evidence entries" copy="This report contains no evidence atoms with timeline details."/>}</div>
}

function MLResults({ value }: { value: Record<string, unknown> }) {
  const entries = Object.entries(value)
  if (!entries.length) return <p className="muted">ML inference was disabled or produced no model outputs for this stream.</p>
  return <div className="ml-result-list">{entries.map(([name, result]) => { const row = isObject(result) ? result : { value: result }; const version = row.model_version; const status = row.status; const prediction = row.prediction ?? row.risk_tier ?? row.classification ?? row.label; return <details className="ml-result" key={name}><summary><span><b>{name.replaceAll('_', ' ')}</b><small>{text(row.model_id, 'Reference / baseline')} {version ? `· v${version}` : ''}</small></span><span>{prediction ? <Badge tone="badge-red">{String(prediction)}</Badge> : <Badge>{text(status, 'AVAILABLE')}</Badge>}</span></summary><pre className="data-block">{pretty(row)}</pre></details> })}</div>
}

function ThreatPage() {
  const [ids, setIds] = useState('')
  const [result, setResult] = useState<ThreatResponse | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const prioritize = async () => {
    const values = [...new Set(ids.split(/[\s,;]+/).map((id) => id.trim()).filter(Boolean))]
    setError(''); setResult(null)
    if (!values.length) { setError('Enter one or more CVE identifiers that are explicitly supported by your evidence.'); return }
    setBusy(true)
    try { setResult(await api.prioritize(values)) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Enrichment failed.') } finally { setBusy(false) }
  }
  const items = Array.isArray(result?.items) ? result.items as Array<Record<string, unknown>> : []
  return <div className="page-content"><SectionTitle eyebrow="THREAT CONTEXT · EVIDENCE-GATED" title="Threat prioritization" detail="Enrich only CVEs that have already been defensibly linked to an observed product or finding. The system does not infer CVEs from a cipher suite or TLS version." />
    <section className="panel threat-form"><label htmlFor="cve-ids">Evidence-supported CVE identifiers</label><textarea id="cve-ids" rows={3} value={ids} onChange={(event) => setIds(event.target.value)} placeholder="CVE-2024-12345, CVE-2023-00000"/><div className="threat-form-foot"><p className="muted">Priority is based on CISA KEV membership and the available EPSS snapshot. This is deterministic enrichment, not an ML prediction.</p><button className="button button-primary" onClick={() => void prioritize()} disabled={busy}>{busy ? 'Checking sources…' : 'Enrich CVEs'}</button></div>{error && <div role="alert" className="alert alert-error">{error}</div>}</section>
    {result && <section className="panel threat-results"><div className="panel-head"><div><span className="eyebrow">ENRICHMENT RESULT</span><h2>{text(result.status)}</h2></div></div>{items.length ? <div className="archive-table-wrap"><table className="archive-table"><thead><tr><th>CVE</th><th>Priority</th><th>KEV</th><th>EPSS</th><th>Source</th></tr></thead><tbody>{items.map((item) => { const kev = isObject(item.kev) ? item.kev : {}; const epss = isObject(item.epss) ? item.epss : {}; return <tr key={String(item.cve_id)}><td className="mono">{String(item.cve_id)}</td><td><Badge tone="badge-red">{String(item.priority)}</Badge></td><td>{kev.listed ? 'CISA KEV' : 'Not listed'}</td><td>{typeof epss.probability === 'number' ? `${(epss.probability * 100).toFixed(2)}%` : 'Unavailable'}</td><td>{String(epss.snapshot ?? 'KEV dataset')}</td></tr> })}</tbody></table></div> : <p className="muted">{text(result.note, 'No enrichment records returned.')}</p>}</section>}
  </div>
}

function MLPage({ catalog, streams }: { catalog: ModelCatalog | null; streams: StreamReport[] }) {
  const statuses = streams.flatMap((stream) => Object.values(stream.ml_results ?? {}).filter(isObject).map((entry) => String(entry.status ?? 'UNKNOWN')))
  return <div className="page-content"><SectionTitle eyebrow="ADVISORY ANALYTICS" title="ML models" detail="Models run only when their cohort and observable features apply. These outputs supplement the deterministic Rule Engine and cannot override its findings." action={catalog && <Badge tone={catalog.ready_count === catalog.model_count ? 'badge-green' : 'badge-red'}>{catalog.ready_count}/{catalog.model_count} artifacts ready</Badge>} />
    <div className="notice-panel"><span>i</span><div><b>Read model scores with their provenance.</b><p>SMTP classification uses the real-ZGrab evidence rubric; IMAP/POP3 classification is simulation-trained. Novelty means unusual relative to a named reference cohort—not insecure or malicious. Confidence scores are not calibrated breach probabilities.</p></div></div>
    {streams.length > 0 && <section className="panel model-runtime"><div className="panel-head"><div><span className="eyebrow">SELECTED REPORT</span><h2>Runtime coverage by stream</h2></div><span>{streams.length} streams</span></div><div className="runtime-bars">{streams.map((stream) => <div key={stream.stream_id}><span>{stream.protocol} / {stream.stream_id}</span><div className="bar-track"><i style={{ width: `${Math.min(100, Object.keys(stream.ml_results ?? {}).length * 24)}%` }} /></div><small>{Object.keys(stream.ml_results ?? {}).length} output groups</small></div>)}</div><p className="muted small-copy">These are executed output counts, not model quality scores. Status mix: {statuses.length ? [...new Set(statuses)].join(', ') : 'No ML outputs in selected analysis.'}</p></section>}
    <div className="model-grid">{(catalog?.models ?? []).map((model) => { const meta = model.metadata ?? {}; return <article className="panel model-card" key={model.model_id}><div className="model-card-head"><Badge tone={model.artifact_status === 'READY' ? 'badge-green' : 'badge-red'}>{model.artifact_status}</Badge><span className="mono">{String(meta.model_version ?? 'registered')}</span></div><h2>{model.model_id.replaceAll('_', ' ')}</h2><p>{text(meta.task, text(meta.target, 'Model task recorded in artifact metadata.'))}</p><div className="model-meta"><span>ALGORITHM</span><b>{text(meta.algorithm ?? meta.model)}</b><span>DATA SOURCE</span><b>{text(meta.data_source ?? meta.dataset_id ?? meta.source_cohort)}</b><span>FEATURES</span><b>{text(meta.feature_count)}</b><span>VERSIONED SCHEMA</span><b>{model.feature_schema_version}</b></div>{Array.isArray(meta.limitations) && <details><summary>Limitations</summary><ul>{(meta.limitations as string[]).map((item) => <li key={item}>{item}</li>)}</ul></details>}</article> })}</div>
    <p className="footnote">{catalog?.authority_note ?? 'Artifact availability is not evidence of model effectiveness.'} Model catalog reports integrity/load readiness, not real-world accuracy.</p>
  </div>
}

function ReportsPage({ analyses, filter, setFilter, activeSummary, activeDetail, selected, onSelect, loading }: { analyses: AnalysisSummary[]; filter: string; setFilter: (value: string) => void; activeSummary: AnalysisSummary | null; activeDetail: AnalysisDetail | null; selected: string | null; onSelect: (id: string) => void; loading: boolean }) {
  return <div className="page-content"><SectionTitle eyebrow="FORENSIC EXPORTS" title="Reports" detail="Export the exact persisted report data as JSON or a standalone HTML document. Save a print-ready PDF through the browser print dialog." />
    <div className="reports-layout"><section className="panel report-picker"><div className="panel-head"><h2>Saved analyses</h2><input className="search-input" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter" aria-label="Filter saved analyses" /></div>{analyses.map((item) => <button key={item.run_id} className={`report-select ${selected === item.run_id ? 'selected' : ''}`} onClick={() => onSelect(item.run_id)}><span className="file-mark">PC</span><span><b>{item.source_name}</b><small>{runTime(item.created_at)} · {item.total_streams} streams</small></span></button>)}{!analyses.length && <p className="muted">{loading ? 'Loading archive…' : 'No reports saved yet.'}</p>}</section>
      <section className="panel report-preview">{activeSummary && activeDetail ? <><div className="report-preview-top"><div><span className="eyebrow">ANALYSIS REPORT</span><h2>{activeSummary.source_name}</h2><p className="muted">{runTime(activeSummary.created_at)} · {activeDetail.report.total_streams} TCP streams · report {activeSummary.run_id.slice(0, 12)}</p></div><ExportActions summary={activeSummary} detail={activeDetail} /></div><ReportPreview report={activeDetail.report} /></> : <EmptyState title="Select a saved analysis" copy="Choose a capture from the list to preview its findings and generate an export."/>}</section></div>
  </div>
}

function ReportPreview({ report }: { report: AnalysisReport }) {
  const streams = flattenStreams(report)
  const failures = streams.flatMap((stream) => failedRules(stream))
  const observed = streams.flatMap((stream) => stream.observations ?? []).filter((item) => item.detected)
  return <><div className="preview-metrics"><Metric label="TOTAL STREAMS" value={streams.length}/><Metric label="POLICY FAILURES" value={failures.length}/><Metric label="DETECTED OBSERVATIONS" value={observed.length}/></div><div className="report-stream-table"><table className="archive-table"><thead><tr><th>Stream</th><th>Protocol</th><th>Policy fail</th><th>Posture score</th></tr></thead><tbody>{streams.map((stream) => <tr key={stream.stream_id}><td>{String(stream.stream_id).padStart(3, '0')}</td><td>{stream.protocol}</td><td>{failedRules(stream).length}</td><td>{text(stream.posture_assessment?.score, 'Not evaluable')}</td></tr>)}</tbody></table></div><p className="footnote">ML output, when present, remains a separate advisory field in the JSON and HTML export. The posture score is a deterministic heuristic, not an ML probability.</p></>
}
