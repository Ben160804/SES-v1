import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type DragEvent, type ReactNode, type RefObject } from 'react'
import { api, uploadAnalysis, type AnalysisDetail, type AnalysisReport, type AnalysisSummary, type DashboardSummary, type PolicyResult, type StreamReport, type ThreatResponse } from './lib/api'

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
  { id: 'reports', label: 'Reports & assistant', glyph: '↗' },
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
function semanticTone(value: unknown) {
  const textValue = String(value ?? '').toUpperCase()
  if (/CRITICAL|HIGH|FAIL|ERROR|EXPIRED|REJECTED/.test(textValue)) return 'badge-red'
  if (/MEDIUM|NOVEL|UNSEEN|WARNING|PARTIAL|NOT_EVALUABLE/.test(textValue)) return 'badge-amber'
  if (/LOW|PASS|NORMAL|WITHIN_REFERENCE|COMPLETED|READY|DETECTED/.test(textValue)) return 'badge-green'
  if (/OBSERVED|INFO|APPLICABLE|ADVISORY/.test(textValue)) return 'badge-blue'
  return 'badge-muted'
}
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
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Forensic report — ${esc(summary.source_name)}</title><style>body{font:15px/1.6 system-ui,sans-serif;color:#19191b;max-width:1000px;margin:50px auto;padding:0 24px}h1{font-size:34px}h2{margin-top:40px;border-bottom:1px solid #ddd;padding-bottom:8px}.meta{color:#555}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:9px;border-bottom:1px solid #ddd}th{background:#f5eeee}li{margin:12px 0}.note{padding:14px;background:#f6f1f1;border-left:3px solid #ae5559}.print{${print ? 'display:none' : ''}}@media print{body{margin:0 auto}.print{display:none}}</style><body><p class="meta">PASSIVE EMAIL FORENSICS</p><h1>Analysis report</h1><p class="meta">Capture: ${esc(summary.source_name)} · Analysed: ${esc(runTime(summary.created_at))} · Streams: ${streams.length}</p><div class="note">Rule-engine findings are deterministic policy results. Machine-learning outputs and posture summaries are separate advisory results. Unknown or unavailable evidence is not interpreted as safe.</div><h2>Stream summary</h2><table><thead><tr><th>Stream</th><th>Protocol</th><th>TLS version</th><th>Cipher</th><th>Rule findings</th><th>Posture heuristic</th></tr></thead><tbody>${rows || '<tr><td colspan="6">No reconstructed streams</td></tr>'}</tbody></table><h2>Deterministic findings</h2><ul>${findings || '<li>No policy failures were recorded in this analysis.</li>'}</ul><h2>Machine-readable record</h2><pre>${esc(JSON.stringify(report, null, 2))}</pre><button class="print" onclick="window.print()">Print / Save as PDF</button><p class="meta">Generated locally. This report reflects observable capture evidence and stated analysis limitations.</p></body></html>`
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
  const [reportView, setReportView] = useState<'exports' | 'assistant'>('exports')
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
  const activeDetail = selected ? details[selected] ?? null : null
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
      <header className="workspace-top"><div className="breadcrumbs"><a href="/">WORKSPACE</a><span>/</span><span>{NAV.find((item) => item.id === tab)?.label.toUpperCase()}</span></div><div className="workspace-tools"><label className="capture-switcher"><span>CURRENT CAPTURE</span><select aria-label="Switch current capture" value={selected ?? ''} onChange={(event) => setSelected(event.target.value || null)} disabled={!analyses.length}><option value="">{analyses.length ? 'Choose a capture' : 'No captures analyzed'}</option>{analyses.map((item) => <option value={item.run_id} key={item.run_id}>{item.source_name} · {item.total_streams} flows</option>)}</select></label><span className={`connection ${apiState}`} title={apiState === 'online' ? 'Forensic API is available' : 'Forensic API state'}>{apiState === 'online' ? 'ONLINE' : apiState === 'checking' ? 'CHECKING' : 'OFFLINE'}</span><button className="icon-refresh" aria-label="Refresh analyses" onClick={() => void refresh()} disabled={loading}>↻</button></div></header>
      {pageError && <div role="alert" className="alert alert-error"><span>{pageError}</span><button onClick={() => void refresh()}>Retry</button></div>}
      {apiState === 'offline' && <div className="offline-panel"><span className="offline-mark">!</span><div><b>Analysis service is not reachable.</b><p>Start the local API at <code>127.0.0.1:8000</code>, then retry. The workspace will not show fabricated reports or metrics.</p></div><button className="button button-small" onClick={() => void refresh()}>Retry connection</button></div>}
      {tab === 'overview' && <OverviewPage analyses={analyses} activeSummary={activeSummary} streams={streams} findings={findingRows} postureAverage={postureAverage} dashboard={dashboard} loading={loading} onGo={navTo} onSelect={setSelected} />}
      {tab === 'captures' && <CapturesPage analyses={visibleAnalyses} allCount={dashboard?.capture_count ?? analyses.length} filter={filter} setFilter={setFilter} inputRef={inputRef} queue={queue} addFiles={addFiles} processQueue={processQueue} queueBusy={queueBusy} hasQueued={hasQueued} trustStore={trustStore} setTrustStore={setTrustStore} aborters={aborters.current} retryItem={retryItem} removeItem={removeItem} clearCompleted={clearCompleted} onSelect={setSelected} onDelete={setDeleteTarget} onTab={navTo} />}
      {tab === 'investigation' && <InvestigationPage view={investigationView} setView={setInvestigationView} findings={findingRows} streams={streams} summary={activeSummary} selectedStream={selectedStream} setSelectedStream={setSelectedStream} onGo={() => navTo('captures')} />}
      {tab === 'intelligence' && <ThreatPage />}
      {tab === 'reports' && <ReportsPage analyses={visibleAnalyses} filter={filter} setFilter={setFilter} activeSummary={activeSummary} activeDetail={activeDetail} selected={selected} onSelect={setSelected} loading={loading} view={reportView} setView={setReportView} />}
      {deleteTarget && <div className="confirm-scrim" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setDeleteTarget(null) }}><section className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="delete-title" aria-describedby="delete-description"><span className="eyebrow">LOCAL ARCHIVE</span><h2 id="delete-title">Delete this analysis?</h2><p id="delete-description"><b>{deleteTarget.source_name}</b> and its saved report and stream evidence will be removed from the local database. Uploaded PCAP files are not retained after analysis.</p><div className="confirm-actions"><button className="button" onClick={() => setDeleteTarget(null)}>Cancel</button><button className="button button-danger" onClick={() => void deleteAnalysis(deleteTarget)}>Delete analysis</button></div></section></div>}
      {dragging && <div className="drop-overlay" role="presentation"><div><span>↓</span><b>Drop captures to add them to the analysis queue</b><small>PCAP and PCAPNG · up to 512 MiB per file</small></div></div>}
    </main>
  </div>
}

function OverviewPage({ analyses, activeSummary, streams, findings, postureAverage, dashboard, loading, onGo, onSelect }: { analyses: AnalysisSummary[]; activeSummary: AnalysisSummary | null; streams: StreamReport[]; findings: ReturnType<typeof allFindings>; postureAverage: number | null; dashboard: DashboardSummary | null; loading: boolean; onGo: (tab: Tab) => void; onSelect: (id: string) => void }) {
  const counts = streams.reduce<Record<string, number>>((result, stream) => { result[stream.protocol] = (result[stream.protocol] ?? 0) + 1; return result }, {})
  const topAnalyses = analyses.slice(0, 6)
  return <div className="page-content page-enter">
    <SectionTitle eyebrow="MAIL SECURITY FORENSICS" title="Investigation overview" detail="Capture activity, protocol reconstruction, deterministic posture, and model output for the selected case." action={<button className="button button-primary" onClick={() => onGo('captures')}>Add capture <span>↗</span></button>} />
    {!analyses.length && !loading ? <EmptyState title="No analyses in the archive" copy="Upload a PCAP or PCAPNG capture to begin. Analysis runs are saved by the local backend." action={<button className="button button-primary" onClick={() => onGo('captures')}>Open PCAP analysis</button>} /> : <>
      <div className="metric-grid overview-metrics"><Metric label="CAPTURES IN ARCHIVE" value={dashboard?.capture_count ?? analyses.length} sub="Local analysis records"/><Metric label="RECONSTRUCTED FLOWS" value={activeSummary ? streams.length : '—'} sub={activeSummary ? activeSummary.source_name : 'Select a case above'}/><Metric label="RULE FINDINGS" value={activeSummary ? findings.filter((item) => item.kind === 'POLICY').length : '—'} sub="Deterministic policy failures"/><Metric label="POSTURE SCORE" value={postureAverage === null ? '—' : `${postureAverage}`} sub="Heuristic · out of 100 · not ML"/></div>
      <ArchiveAnalytics data={dashboard}/>
      <div className="content-grid overview-grid">
        <section className="panel case-overview"><div className="panel-head"><div><span className="eyebrow">ACTIVE CASE</span><h2>{activeSummary?.source_name ?? 'Choose a report'}</h2></div>{activeSummary && <Badge>{activeSummary.run_id.slice(0, 10)}</Badge>}</div>
          {!activeSummary ? <p className="muted">Select a report from the archive to view its analysis.</p> : <><div className="report-meta"><span>{runTime(activeSummary.created_at)}</span><span>{streams.length} streams analyzed</span><span className="mono">{activeSummary.run_id.slice(0, 12)}</span></div><div className="protocol-strip">{['SMTP', 'IMAP', 'POP3'].map((name) => <div key={name}><small>{name}</small><b>{counts[name] ?? 0}</b><span>streams</span></div>)}</div><div className="bar-list">{Object.entries(counts).map(([name, count]) => <div key={name} className="bar-row"><span>{name}</span><div className="bar-track"><i style={{ width: `${streams.length ? count / streams.length * 100 : 0}%` }} /></div><b>{count}</b></div>)}</div></>}
        </section>
        <section className="panel"><div className="panel-head"><div><span className="eyebrow">LOCAL ARCHIVE</span><h2>Recent analyses</h2></div><button className="text-button" onClick={() => onGo('captures')}>Upload more →</button></div>
          {topAnalyses.length ? <div className="archive-list">{topAnalyses.map((item) => <button key={item.run_id} className={`archive-row ${item.run_id === activeSummary?.run_id ? 'selected' : ''}`} onClick={() => onSelect(item.run_id)}><span className="file-mark">PC</span><span className="archive-name"><b>{item.source_name}</b><small>{runTime(item.created_at)}</small></span><span className="archive-streams">{item.total_streams} streams</span><span className="arrow">↗</span></button>)}</div> : <p className="muted">{loading ? 'Loading analyses…' : 'No saved analyses yet.'}</p>}
        </section>
      </div>
      <CaptureCharts streams={streams}/>
      <section className="panel intelligence-overview"><div className="panel-heading"><div><span className="eyebrow">LEARNED SIGNALS</span><h2>ML outputs across this capture</h2><p>Per-session model results, separated by purpose. Cohort novelty is not a security verdict.</p></div><button className="text-button" onClick={() => onGo('investigation')}>Open session evidence <span>→</span></button></div><OverviewML streams={streams}/></section>
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
  return <article className={`archive-chart chart-${kind}`}><div className="archive-chart-heading"><span className="eyebrow">{label}</span><h3>{title}</h3></div>{rows.length ? <div className="archive-chart-rows">{rows.map(([name, count]) => <div className="archive-chart-row" key={name}><span title={name}>{name.replaceAll('_', ' ').toLowerCase()}</span><div><i className={tone(name)} style={{ width: `${count / maximum * 100}%` }}/></div><b>{count}</b></div>)}</div> : <p className="chart-unavailable">No observations recorded</p>}</article>
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
  ['zgrab_evidence_risk_classifier', 'SMTP risk classification', 'Real ZGrab SMTP · rubric-derived'],
  ['synthetic_email_risk_classifier', 'IMAP / POP3 risk classification', 'Programmatic email simulation'],
  ['classifier_risk_tier', 'SMTP tier proxy', 'Real ZGrab SMTP · rule-derived target'],
  ['classifier', 'SMTP rule-flag proxy', 'Real ZGrab SMTP · rule-label proxy'],
  ['smtp_configuration_anomaly', 'SMTP configuration novelty', 'Real ZGrab SMTP TLS cohort'],
  ['smtp_configuration_rarity', 'SMTP tuple rarity', 'Real ZGrab SMTP TLS cohort'],
  ['certificate_novelty', 'Certificate novelty', 'SMTP-related scan certificate corpus'],
] as const

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
    const output = Object.entries(counts).map(([name, count]) => `${name.replaceAll('_', ' ')} · ${count}`).join('   /   ')
    return <div className="model-table-row" key={key}><div className="model-name"><b>{label}</b><small>{cohort}</small></div><span className="model-coverage">{state}</span><span className="model-output">{output || statusSummary(rows.map(({ value }) => String(value.status ?? 'UNKNOWN')))}</span><span className="model-feature-coverage">{average}</span></div>
  })}</div>
}

function statusSummary(statuses: string[]) {
  if (!statuses.length) return '—'
  const tally = statuses.reduce<Record<string, number>>((acc, status) => { acc[status] = (acc[status] ?? 0) + 1; return acc }, {})
  return Object.entries(tally).map(([status, count]) => `${status.replaceAll('_', ' ').toLowerCase()} · ${count}`).join(' / ')
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
  return <div className="page-content investigation-content">{streams.length ? <div className="sessions-layout"><section className="panel stream-list-panel"><div className="panel-head"><div><span className="eyebrow">RECONSTRUCTED FLOWS</span><h2>Sessions</h2></div><span className="count-pill">{streams.length}</span></div>{streams.map((stream) => <button key={stream.stream_id} className={`stream-row ${selectedStream === stream.stream_id ? 'selected' : ''}`} onClick={() => setSelectedStream(stream.stream_id)}><span className="stream-id">{String(stream.stream_id).padStart(3, '0')}</span><span className="stream-main"><b>{stream.protocol}</b><small>{findingsCount(stream)} recorded finding{findingsCount(stream) === 1 ? '' : 's'}</small></span><span className="arrow">→</span></button>)}</section><section className="panel stream-detail-panel">{active ? <StreamEvidence stream={active} /> : <EmptyState title="Select a stream" copy="Choose a stream to review TLS, certificate, rule-engine, posture, and ML evidence."/>}</section></div> : <EmptyState title="No streams reconstructed" copy="The capture may contain no analyzable TCP streams. Review report limitations and capture integrity."/>}</div>
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
    <h3>Security posture <span className="subtle-tag">DETERMINISTIC · NOT ML</span></h3><PostureSummary posture={stream.posture_assessment ?? {}} />
    <h3>ML outputs <span className="subtle-tag">ADVISORY</span></h3><MLResults value={stream.ml_results ?? {}} />
    <h3>Certificate & trust</h3><CertificateSummary certificate={certificate} />
    <h3>Deterministic policy checks</h3><div className="rule-list">{rules.map(({ pack, item }, index) => <details className="rule-row rule-detail" key={`${pack}-${item.rule_id}-${index}`}><span className={`verdict-dot verdict-${(item.verdict ?? '').toLowerCase()}`} /><summary><b>{item.name ?? item.rule_id}</b><small>{pack} · {item.rule_id} · {item.applicability_scope ?? 'scope unavailable'}</small></summary><Badge tone={item.verdict === 'FAIL' ? 'badge-red' : ''}>{item.verdict ?? 'UNKNOWN'}</Badge>{item.finding && <p>{item.finding}</p>}<div className="rule-evidence"><p><b>Standard:</b> {item.source_id ?? 'Unavailable'} § {item.source_section ?? '—'} · {item.normative_term ?? 'term unavailable'}</p>{item.source_text && <p>{item.source_text}</p>}{item.evidence?.length ? <pre className="data-block">{pretty(item.evidence)}</pre> : <p>No evidence atoms were recorded for this result.</p>}</div></details>)}</div>
    <h3>Forensic observations</h3><div className="observation-list">{(stream.observations ?? []).length ? stream.observations?.map((item, index) => <div className="observation-row" key={`${item.obs_id}-${index}`}><Badge tone={item.detected ? 'badge-red' : 'badge-muted'}>{item.detected ? 'DETECTED' : 'NOT DETECTED'}</Badge><div><b>{item.name ?? item.obs_id}</b><p>{item.description ?? 'No additional description.'}</p></div></div>) : <p className="muted">No observation records.</p>}</div>
    <h3>Mitigation guidance <span className="subtle-tag">EVIDENCE-LINKED</span></h3><Recommendations posture={stream.posture_assessment ?? {}} />
  </div>
}

function CertificateSummary({ certificate }: { certificate: Record<string, unknown> }) {
  const leaf = isObject(certificate.leaf_cert) ? certificate.leaf_cert : certificate
  const candidates: Array<[string, unknown]> = [
    ['Observation', certificate.observable ?? certificate.certificate_observed],
    ['Trust status', certificate.trust_status ?? leaf.trust_status],
    ['Hostname match', certificate.hostname_match ?? leaf.hostname_match],
    ['Key algorithm', leaf.public_key_algorithm ?? leaf.key_algorithm],
    ['Key size', leaf.public_key_size ?? leaf.key_size_bits],
    ['Signature', leaf.signature_algorithm],
    ['Valid from', leaf.not_before],
    ['Valid until', leaf.not_after],
    ['Expired', leaf.is_expired ?? leaf.expired],
    ['Self-signed', leaf.is_self_signed ?? leaf.self_signed],
    ['SAN entries', leaf.san_count],
    ['Chain length', certificate.chain_length],
    ['Revocation', certificate.revocation_status],
  ]
  const fields = candidates.filter(([, value]) => value !== undefined && value !== null && value !== '')
  if (!Object.keys(certificate).length) return <p className="muted">Certificate fields were not present in this stream report.</p>
  const notObserved = certificate.observable === false || certificate.certificate_observed === false
  return <><div className="fact-grid certificate-grid">{fields.map(([label, value]) => <div className="fact" key={label}><small>{label}</small><b>{text(value)}</b></div>)}</div>{notObserved && <p className="muted small-copy">The certificate was not observable in this capture. This does not mean that the endpoint has no certificate.</p>}<details className="evidence-raw"><summary>Full parsed certificate evidence</summary><pre className="data-block">{pretty(certificate)}</pre></details></>
}

function PostureSummary({ posture }: { posture: Record<string, unknown> }) {
  if (!Object.keys(posture).length) return <p className="muted">No deterministic posture summary is present in this report.</p>
  const score = typeof posture.score === 'number' ? posture.score : null
  const tier = text(posture.tier, text(posture.status, 'NOT EVALUABLE'))
  const findings = Array.isArray(posture.findings) ? posture.findings.filter(isObject) : []
  return <><div className="posture-card"><div className="posture-score"><span>{score === null ? '—' : score}</span><small>{score === null ? 'SCORE' : '/ 100'}</small></div><div><Badge tone={semanticTone(tier)}>{tier}</Badge><p>{text(posture.score_type, 'Deterministic heuristic, not an ML probability')}</p></div></div>{findings.length > 0 && <div className="posture-findings">{findings.map((finding, index) => <div key={`${String(finding.family)}-${index}`}><Badge tone={semanticTone(finding.severity)}>{text(finding.severity)}</Badge><span><b>{text(finding.family)}</b><small>{Array.isArray(finding.evidence) ? finding.evidence.length : 0} linked evidence items</small></span></div>)}</div>}<details className="evidence-raw"><summary>Scoring method & limitations</summary><pre className="data-block">{pretty({ scoring_method: posture.scoring_method, limitations: posture.limitations, rubric_version: posture.rubric_version })}</pre></details></>
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

function MLResults({ value }: { value: Record<string, unknown> }) {
  if (typeof value.status === 'string' && ['MODEL_ERROR', 'MODEL_UNAVAILABLE'].includes(value.status)) return <div className="ml-error-state"><Badge tone="badge-red">{value.status}</Badge><p>{text(value.reason, 'The ML runtime could not complete for this session.')}</p></div>
  const entries = Object.entries(value)
  if (!entries.length) return <p className="muted">The ML pipeline returned no outputs for this session. See case status for execution errors.</p>
  return <div className="ml-result-list">{entries.map(([name, result]) => {
    const row = isObject(result) ? result : { value: result }
    const version = row.model_version
    const status = row.status
    const prediction = row.prediction ?? row.risk_tier ?? row.classification ?? row.label ?? row.novelty_flag
    const predictionLabel = prediction === true ? 'NOVEL' : prediction === false ? 'KNOWN' : prediction
    const coverage = typeof row.feature_coverage === 'number' ? `${Math.round(row.feature_coverage * 100)}% feature coverage` : ''
    const score = row.anomaly_score ?? row.novelty_score ?? row.score
    return <details className="ml-result" key={name}>
      <summary><span className="ml-result-title"><b>{name.replaceAll('_', ' ')}</b><small>{text(row.model_id, 'Model')} {version ? `· v${version}` : ''}</small></span><span className="ml-result-status">{prediction !== undefined ? <Badge tone={semanticTone(predictionLabel)}>{String(predictionLabel)}</Badge> : null}<Badge tone={semanticTone(status)}>{text(status, 'RESULT')}</Badge></span></summary>
      <div className="ml-result-body">{coverage ? <span>{coverage}</span> : null}{score !== undefined ? <span>Score <b>{text(score)}</b></span> : null}{row.confidence !== undefined ? <span>Confidence <b>{text(row.confidence)}</b></span> : null}{row.cohort !== undefined ? <span>Cohort <b>{text(row.cohort)}</b></span> : null}{row.reason !== undefined ? <p>{text(row.reason)}</p> : null}</div>
      <details className="ml-raw"><summary>Model provenance & evidence</summary><pre className="data-block">{pretty(row)}</pre></details>
    </details>
  })}</div>
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

function ReportsPage({ analyses, filter, setFilter, activeSummary, activeDetail, selected, onSelect, loading, view, setView }: { analyses: AnalysisSummary[]; filter: string; setFilter: (value: string) => void; activeSummary: AnalysisSummary | null; activeDetail: AnalysisDetail | null; selected: string | null; onSelect: (id: string) => void; loading: boolean; view: 'exports' | 'assistant'; setView: (view: 'exports' | 'assistant') => void }) {
  return <div className="page-content"><SectionTitle eyebrow="CASE OUTPUTS" title="Reports & assistant" detail="Export evidence as a forensic artifact, or prepare an analyst question for the optional language-model layer." />
    <div className="segmented-tabs report-tabs" role="tablist" aria-label="Report tools"><button role="tab" aria-selected={view === 'exports'} className={view === 'exports' ? 'active' : ''} onClick={() => setView('exports')}>Forensic exports</button><button role="tab" aria-selected={view === 'assistant'} className={view === 'assistant' ? 'active' : ''} onClick={() => setView('assistant')}>AI assistant <span className="pending-pill">Integration pending</span></button></div>
    {view === 'exports' ? <div className="reports-layout"><section className="panel report-picker"><div className="panel-head"><div><span className="eyebrow">LOCAL CASE ARCHIVE</span><h2>Saved analyses</h2></div><input className="search-input" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter captures" aria-label="Filter saved analyses" /></div>{analyses.map((item) => <button key={item.run_id} className={`report-select ${selected === item.run_id ? 'selected' : ''}`} onClick={() => onSelect(item.run_id)}><span className="file-mark">PC</span><span><b>{item.source_name}</b><small>{runTime(item.created_at)} · {item.total_streams} streams</small></span></button>)}{!analyses.length && <p className="muted">{loading ? 'Loading archive…' : 'No reports saved yet.'}</p>}</section>
      <section className="panel report-preview">{activeSummary && activeDetail ? <><div className="report-preview-top"><div><span className="eyebrow">EVIDENCE REPORT</span><h2>{activeSummary.source_name}</h2><p className="muted">{runTime(activeSummary.created_at)} · {activeDetail.report.total_streams} TCP streams · case {activeSummary.run_id.slice(0, 12)}</p></div><ExportActions summary={activeSummary} detail={activeDetail} /></div><ReportPreview report={activeDetail.report} /></> : <EmptyState title="Select a saved analysis" copy="Choose a capture to review findings and export JSON, HTML, or a print-ready PDF."/>}</section></div> : <AssistantWorkspace summary={activeSummary} />}
  </div>
}

function AssistantWorkspace({ summary }: { summary: AnalysisSummary | null }) {
  return <div className="assistant-layout">
    <section className="assistant-intro"><div className="assistant-kicker"><span className="assistant-spark">✳</span><span>ANALYST ASSISTANCE · OUTSIDE DETECTION PATH</span></div><h2>Ask the evidence.<br/><em>Keep the source visible.</em></h2><p>Language-model features will explain stored analysis and search the local case archive. They will not change parser output, policy findings, or ML inference.</p><div className="assistant-status"><span className="status-dot"/><span><b>Connection point prepared</b><small>LLM provider is not configured in this build.</small></span></div></section>
    <div className="assistant-tools">
      <article className="panel assistant-card"><div className="assistant-card-head"><span className="tool-number">01</span><Badge>REPORT EXPLANATION</Badge></div><h3>Explain this capture</h3><p>Generate a readable incident brief from the selected capture's observed sessions, rule evidence, posture, and advisory ML outputs.</p><label>Selected case</label><div className="assistant-case">{summary ? <><b>{summary.source_name}</b><small>{summary.total_streams} streams · {summary.run_id.slice(0, 10)}</small></> : <span>Select a saved analysis first</span>}</div><textarea disabled rows={3} placeholder="Optional focus: summarize STARTTLS downgrade evidence…"/><button className="button" disabled>Generate analyst brief <span>↗</span></button><small className="footnote">Unavailable until an LLM service is configured. Exports remain available above.</small></article>
      <article className="panel assistant-card"><div className="assistant-card-head"><span className="tool-number">02</span><Badge>ARCHIVE QUERY</Badge></div><h3>Search the analysis archive</h3><p>Ask questions across saved sessions and findings, then inspect the structured filter and matching evidence.</p><label htmlFor="archive-question">Question</label><textarea id="archive-question" disabled rows={3} placeholder="Show sessions that negotiated TLS 1.0 or used CBC suites"/><button className="button" disabled>Query local archive <span>⌕</span></button><small className="footnote">A future query is constrained to read-only structured database operations.</small></article>
    </div>
    <div className="assistant-integrity"><span>ⓘ</span><p><b>Analysis remains authoritative.</b> Assistant responses will be generated from persisted evidence and must cite the relevant capture, stream, rule, or ML result. No answer will be presented as a new detection.</p></div>
  </div>
}

function ReportPreview({ report }: { report: AnalysisReport }) {
  const streams = flattenStreams(report)
  const failures = streams.flatMap((stream) => failedRules(stream))
  const observed = streams.flatMap((stream) => stream.observations ?? []).filter((item) => item.detected)
  return <><div className="preview-metrics"><Metric label="TOTAL STREAMS" value={streams.length}/><Metric label="POLICY FAILURES" value={failures.length}/><Metric label="DETECTED OBSERVATIONS" value={observed.length}/></div><div className="report-stream-table"><table className="archive-table"><thead><tr><th>Stream</th><th>Protocol</th><th>Policy fail</th><th>Posture score</th></tr></thead><tbody>{streams.map((stream) => <tr key={stream.stream_id}><td>{String(stream.stream_id).padStart(3, '0')}</td><td>{stream.protocol}</td><td>{failedRules(stream).length}</td><td>{text(stream.posture_assessment?.score, 'Not evaluable')}</td></tr>)}</tbody></table></div><p className="footnote">ML output, when present, remains a separate advisory field in the JSON and HTML export. The posture score is a deterministic heuristic, not an ML probability.</p></>
}
