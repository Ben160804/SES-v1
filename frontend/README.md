# SecureMailScope React frontend

The React application is a local operator interface for the existing forensic
API. It has a minimal landing page, a technical report, and an analysis
workspace. It renders values returned by the backend and shows an explicit
empty/offline state instead of example statistics.

## Run locally

Install the API, parser, certificate, and ML dependencies from the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-app.txt
uvicorn analysis.api:app --host 127.0.0.1 --port 8000
```

Then start Vite in another terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. Vite proxies `/api` to the local FastAPI
service. The app can also be built and served from the same-origin FastAPI
application:

```bash
npm run build
cd ..
uvicorn analysis.api:app --host 127.0.0.1 --port 8000
```

Keep the service bound to loopback for this single-operator setup. The API has
no user authentication or multi-tenant access control, so it must not be
exposed directly to a network.

## Operator workflow

- Add one or more PCAP/PCAPNG files; the frontend validates extension and size,
  while the backend analyzes each capture and persists the report in SQLite.
- Use the overview for the case archive and selected-capture summary. The
  Investigation area groups deterministic findings, reconstructed sessions,
  certificate/TLS evidence, ML advisory results, posture, and packet references.
- Every API analysis run enables the ML layer. Models return not-applicable or
  not-evaluable states where the protocol cohort or observed evidence does not
  support inference; the interface does not offer an ML-off switch.
- Export the persisted analysis as JSON or standalone HTML. “Save PDF” opens a
  print-ready report and invokes the browser print dialog.
- Enrich explicitly supplied CVE IDs with the local KEV/EPSS data. The UI does
  not infer CVEs from TLS settings.
- The Assistant area has entry points for report explanations and natural-
  language archive queries. They remain disabled until an LLM backend is
  connected; neither feature is represented as active analysis today.

Raw PCAP retention follows the backend's configured lifecycle; report exports
contain the analysis record, not the original packet payloads. ML output is
advisory and remains separate from deterministic policy findings.

## Frontend checks

```bash
npm run typecheck
npm test
npm run build
```
