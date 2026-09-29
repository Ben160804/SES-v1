import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const apiMock = vi.hoisted(() => ({
  health: vi.fn(),
  listAnalyses: vi.fn(),
  getAnalysis: vi.fn(),
  getModels: vi.fn(),
  prioritize: vi.fn(),
  uploadAnalysis: vi.fn(),
}))

vi.mock('./lib/api', () => ({
  api: apiMock,
  uploadAnalysis: apiMock.uploadAnalysis,
}))

const catalog = {
  model_count: 10,
  ready_count: 10,
  authority_note: 'ML outputs are advisory.',
  models: [],
}

describe('SecureMailScope application', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiMock.health.mockResolvedValue({ status: 'ok', api_version: '1.0.0' })
    apiMock.listAnalyses.mockResolvedValue({ items: [], count: 0 })
    apiMock.getModels.mockResolvedValue(catalog)
    apiMock.uploadAnalysis.mockReset()
  })

  it('presents the two intended landing actions', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: /see what the mail session actually negotiated/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /open analysis workspace/i })).toHaveAttribute('href', '/workspace')
    expect(screen.getByRole('link', { name: /read the technical report/i })).toHaveAttribute('href', '/technical-report')
  })

  it('renders the research report with the project architecture and ML caveats', () => {
    window.history.replaceState({}, '', '/technical-report')
    render(<App />)
    expect(screen.getByRole('heading', { name: 'SecureMailScope' })).toBeInTheDocument()
    expect(screen.getByText(/SMTP, IMAP, and POP3 communications/i)).toBeInTheDocument()
    expect(screen.getByText(/They do not measure attack detection/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /print or save the technical report as pdf/i })).toBeInTheDocument()
  })

  it('uses the real API state and an honest empty archive state', async () => {
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'Analysis overview' })).toBeInTheDocument()
    expect(await screen.findByText('No analyses in the archive')).toBeInTheDocument()
    expect(screen.getByText('Connected to local API')).toBeInTheDocument()
    expect(apiMock.listAnalyses).toHaveBeenCalledWith(100)
  })

  it('shows the API failure instead of substituting sample data', async () => {
    apiMock.health.mockRejectedValue(new Error('Connection refused'))
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    expect(await screen.findByText(/analysis service is not reachable/i)).toBeInTheDocument()
    expect(screen.queryByText(/92% secure/i)).not.toBeInTheDocument()
  })

  it('opens the upload workspace from the overview action', async () => {
    window.history.replaceState({}, '', '/workspace')
    render(<App />)
    const button = await screen.findByRole('button', { name: /analyze pcaps/i })
    fireEvent.click(button)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'PCAP analysis' })).toBeInTheDocument())
    expect(screen.getByText(/certificate trust store/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/run advisory ml inference/i)).toBeInTheDocument()
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
    expect(apiMock.uploadAnalysis).toHaveBeenCalledWith(file, { trustStore: 'testbed', enableMl: true }, expect.any(Function), expect.any(Function))
    expect(await screen.findByText(/report run-42/i)).toBeInTheDocument()
  })
})
