export const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'

export interface AnalysisSummary {
  run_id: string
  created_at: string
  source_name: string
  total_streams: number
}

export interface StreamReport {
  stream_id: number
  protocol: string
  policy_results?: Record<string, PolicyResult[]>
  observations?: Observation[]
  input_snapshot?: Record<string, unknown>
  ml_results?: Record<string, unknown>
  posture_assessment?: Record<string, unknown>
}

export interface PolicyResult {
  policy?: string
  rule_id?: string
  name?: string
  source_id?: string
  source_section?: string
  source_text?: string
  normative_term?: string
  verdict?: string
  finding?: string | null
  applicability_scope?: string
  evidence?: Array<Record<string, unknown>>
}

export interface Observation {
  obs_id?: string
  name?: string
  category?: string
  detected?: boolean
  description?: string
  evidence?: Array<Record<string, unknown>>
}

export interface AnalysisReport {
  total_streams: number
  stream_reports: Record<string, StreamReport>
}

export interface AnalysisDetail {
  run_id: string
  report: AnalysisReport
}

export interface ModelCatalog {
  model_count: number
  ready_count: number
  models: Array<{
    model_id: string
    artifact_status: string
    feature_schema_version?: string
    metadata?: Record<string, unknown>
  }>
  authority_note?: string
}

export interface ThreatResponse {
  status: string
  items: Array<Record<string, unknown>>
  source_policy?: string
  note?: string
}

export interface ThreatPriorityItem {
  rank: number
  priority: string
  priority_label: string
  severity: string
  family: string
  title: string
  affected_streams: number[]
  affected_stream_count: number
  evidence_count: number
  evidence: Array<Record<string, unknown>>
  recommendation: string
  cve_ids: string[]
  cve_enrichment: Array<Record<string, unknown>>
  priority_basis: string
}

export interface ThreatPrioritization {
  status: string
  source_name: string
  total_streams: number
  streams_with_findings: number
  items: ThreatPriorityItem[]
  cve_enrichment: ThreatResponse
  cve_link_policy: string
  note?: string | null
}

export interface DashboardSummary {
  capture_count: number
  stream_count: number
  captures_by_day: Record<string, number>
  protocol_counts: Record<string, number>
  tls_version_counts: Record<string, number>
  certificate_counts: Record<string, number>
  rule_verdicts: Record<string, number>
  rule_severities: Record<string, number>
  ml_statuses: Record<string, number>
  posture_tiers: Record<string, number>
  ml_model_summary?: Record<string, {
    observed_outputs: number
    completed_outputs: number
    status_counts: Record<string, number>
    prediction_counts: Record<string, number>
    mean_feature_coverage: number | null
    coverage_sample_count: number
  }>
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init)
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json() as { detail?: string }
      if (body.detail) detail = body.detail
    } catch { /* the HTTP status is sufficient */ }
    throw new Error(detail)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  health: () => request<{ status: string; api_version: string }>(`${API_BASE}/health`),
  listAnalyses: (limit = 100) => request<{ items: AnalysisSummary[]; count: number }>(`${API_BASE}/analyses?limit=${limit}`),
  getOverview: () => request<DashboardSummary>(`${API_BASE}/overview`),
  getAnalysis: (runId: string) => request<AnalysisDetail>(`${API_BASE}/analyses/${encodeURIComponent(runId)}`),
  deleteAnalysis: (runId: string) => request<void>(`${API_BASE}/analyses/${encodeURIComponent(runId)}`, { method: 'DELETE' }),
  getModels: () => request<ModelCatalog>(`${API_BASE}/ml/models`),
  prioritize: (cveIds: string[]) => request<ThreatResponse>(`${API_BASE}/threat-prioritization`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cve_ids: cveIds }),
  }),
  getThreatPrioritization: (runId: string) => request<ThreatPrioritization>(`${API_BASE}/analyses/${encodeURIComponent(runId)}/threat-prioritization`),
}

export function uploadAnalysis(
  file: File,
  options: { trustStore: string },
  onProgress: (loaded: number, total: number) => void,
  onAbort?: (abort: () => void) => void,
): Promise<{ run_id: string; total_streams: number }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const query = new URLSearchParams({ trust_store: options.trustStore })
    xhr.open('POST', `${API_BASE}/analyses?${query}`)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name))
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded, event.total)
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText) as { run_id: string; total_streams: number }) }
        catch { reject(new Error('The API returned an invalid analysis response.')) }
      } else {
        let detail = `Analysis failed (${xhr.status}).`
        try { detail = JSON.parse(xhr.responseText).detail ?? detail } catch { /* keep status */ }
        reject(new Error(detail))
      }
    }
    xhr.onerror = () => reject(new Error('Could not reach the local analysis API.'))
    xhr.onabort = () => reject(new Error('Upload cancelled.'))
    onAbort?.(() => xhr.abort())
    xhr.send(file)
  })
}
