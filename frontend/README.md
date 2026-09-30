# Frontend

The frontend is a React and TypeScript application for the SecureMailScope API. It contains the project landing page, technical report, PCAP analysis workspace, and case report views. Analysis and security findings are provided by the backend; the frontend does not implement packet parsing or policy evaluation.

## Development

Install dependencies and start the Vite development server:

```bash
npm ci
npm run dev
```

Run the API separately from the repository root:

```bash
python run.py
```

Vite proxies `/api` requests to `http://127.0.0.1:8000` by default. Set `SECUREMAILSCOPE_API_URL` to configure another API address.

## Production build

```bash
npm run build
```

The generated files are written to `frontend/dist/`. When that build exists, the FastAPI application serves the frontend and its assets from the same origin.

## Frontend checks

```bash
npm run typecheck
npm test
```

See the repository [README](../README.md) for backend setup, data provenance, ML scope, and project limitations.
