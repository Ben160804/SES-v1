import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const apiMock = vi.hoisted(() => ({
  health: vi.fn(),
  listAnalyses: vi.fn(),
  getOverview: vi.fn(),
  getAnalysis: vi.fn(),
  prioritize: vi.fn(),
  uploadAnalysis: vi.fn(),
}))

vi.mock('./lib/api', () => ({
  api: apiMock,
  uploadAnalysis: apiMock.uploadAnalysis,
}))

describe('forensic web application', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiMock.health.mockResolvedValue({ status: 'ok', api_version: '1.0.0' })
    apiMock.listAnalyses.mockResolvedValue({ items: [], count: 0 })
    apiMock.getOverview.mockResolvedValue({ capture_count: 0, stream_count: 0, captures_by_day: {}, protocol_counts: {}, tls_version_counts: {}, certificate_counts: {}, rule_verdicts: {}, rule_severities: {}, ml_statuses: {}, posture_tiers: {} })
    apiMock.getAnalysis.mockReset()
    apiMock.uploadAnalysis.mockReset()
  })

  it('presents the two intended landing actions', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: /know what the wire reveals/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /analyze a capture/i })).toHaveAttribute('href', '/workspace')
    expect(screen.getByRole('link', { name: /read the research report/i })).toHaveAttribute('href', '/technical-report')
  })

  it('renders the research report with the project architecture and ML caveats', () => {
    window.history.replaceState({}, '', '/technical-report')
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Email transport forensics' })).toBeInTheDocument()
    expect(screen.getByText(/SMTP, IMAP, and POP3 communications/i)).toBeInTheDocument()
    expect(screen.getByText(/They do not measure attack detection/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /print or save the technical report as pdf/i })).toBeInTheDocument()
  })

  it('uses the real API state and an honest empty archive state', async () => {
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'Investigation overview' })).toBeInTheDocument()
    expect(await screen.findByText('No analyses in the archive')).toBeInTheDocument()
    expect(screen.getByText('ONLINE')).toBeInTheDocument()
    expect(apiMock.listAnalyses).toHaveBeenCalledWith(500)
  })

  it('shows the API failure instead of substituting sample data', async () => {
    apiMock.health.mockRejectedValue(new Error('Connection refused'))
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    expect(await screen.findByText(/analysis service is not reachable/i)).toBeInTheDocument()
    expect(screen.queryByText(/92% secure/i)).not.toBeInTheDocument()
  })

  it('uses case-centered navigation and keeps the reports page focused on forensic exports', async () => {
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'Investigation overview' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /ml models/i })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /investigation/i }))
    expect(await screen.findByRole('tab', { name: /findings/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /sessions/i })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^reports$/i }))
    expect(await screen.findByRole('heading', { name: 'Forensic reports' })).toBeInTheDocument()
    expect(screen.getByText(/use the searchable current capture control/i)).toBeInTheDocument()
    expect(screen.queryByText(/assistant/i)).not.toBeInTheDocument()
  })

  it('switches cases from the persistent header and surfaces per-model outputs on overview', async () => {
    const cases = [
      { run_id: 'case-a', created_at: '2026-09-29T08:00:00Z', source_name: 'alpha.pcap', total_streams: 1 },
      { run_id: 'case-b', created_at: '2026-09-29T09:00:00Z', source_name: 'beta.pcap', total_streams: 1 },
    ]
    apiMock.listAnalyses.mockResolvedValue({ items: cases, count: 2 })
    apiMock.getAnalysis.mockImplementation(async (runId: string) => ({ run_id: runId, report: { total_streams: 1, stream_reports: { '1': {
      stream_id: 1,
      protocol: 'SMTP',
      ml_results: {
        zgrab_evidence_risk_classifier: { model_id: 'zgrab_evidence_risk_classifier_v1', model_version: '1.0', status: 'COMPLETED_ADVISORY_RUBRIC_ESTIMATE', prediction: 'HIGH', feature_coverage: .8 },
        certificate_novelty: { model_id: 'mta_sts_cert_anomaly_v1', status: 'COMPLETED_EXPLORATORY', prediction: 'WITHIN_REFERENCE', feature_coverage: .9 },
      },
    } } } }))
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    const switcher = await screen.findByRole('textbox', { name: /search captures/i })
    expect(screen.getByText('SMTP risk estimate')).toBeInTheDocument()
    expect(screen.getByText(/HIGH · 1/i)).toBeInTheDocument()
    fireEvent.focus(switcher)
    fireEvent.change(switcher, { target: { value: 'beta' } })
    fireEvent.click(await screen.findByRole('option', { name: /beta\.pcap/i }))
    expect(await screen.findByRole('heading', { name: 'beta.pcap' })).toBeInTheDocument()
    expect(switcher).toHaveValue('beta.pcap')
  })

  it('opens the upload workspace from the overview action', async () => {
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    const button = await screen.findByRole('button', { name: /add capture/i })
    fireEvent.click(button)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'PCAP analysis' })).toBeInTheDocument())
    expect(screen.getByText(/certificate trust store/i)).toBeInTheDocument()
    expect(screen.getByText(/parser · rule engine · applicable ml models/i)).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /ml/i })).not.toBeInTheDocument()
  })

  it('queues a real selected file, sends it through the API, and archives its report', async () => {
    window.history.replaceState({}, '', '/workspace#/captures')
    const file = new File(['pcap bytes'], 'mail-trace.pcap', { type: 'application/vnd.tcpdump.pcap' })
    const summary = { run_id: 'run-42', created_at: '2026-09-29T08:00:00Z', source_name: file.name, total_streams: 1 }
    apiMock.listAnalyses.mockResolvedValueOnce({ items: [], count: 0 }).mockResolvedValue({ items: [summary], count: 1 })
    apiMock.uploadAnalysis.mockImplementation(async (_file, _options, onProgress) => {
      onProgress(file.size, file.size)
      return { run_id: summary.run_id, total_streams: 1 }
    })
    apiMock.getAnalysis.mockResolvedValue({ run_id: summary.run_id, report: { total_streams: 1, stream_reports: {} } })
    render(<App />)
    const input = await screen.findByLabelText(/select pcap and pcapng files/i)
    fireEvent.change(input, { target: { files: [file] } })
    fireEvent.click(await screen.findByRole('button', { name: /analyze 1 queued/i }))
    expect(await screen.findByText('mail-trace.pcap')).toBeInTheDocument()
    await waitFor(() => expect(apiMock.uploadAnalysis).toHaveBeenCalledTimes(1))
    expect(apiMock.uploadAnalysis).toHaveBeenCalledWith(file, { trustStore: 'testbed' }, expect.any(Function), expect.any(Function))
    expect(await screen.findByText(/report run-42/i)).toBeInTheDocument()
  })
})
