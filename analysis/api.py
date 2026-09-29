"""Local HTTP API for PCAP analysis and persisted SecureMailScope reports."""

from __future__ import annotations

import os
import tempfile
from urllib.parse import unquote
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .rule_engine.engine import RuleEngine
from .report_store import ReportStore
from .threat_intel import prioritize_cves
from .ml_artifacts import model_catalog

ROOT = Path(__file__).resolve().parents[1]
MAX_PCAP_BYTES = 512 * 1024 * 1024


class CVEPrioritizationRequest(BaseModel):
    cve_ids: list[str] = Field(min_length=1, max_length=100)


def create_app(store: ReportStore | None = None) -> FastAPI:
    report_store = store or ReportStore(
        os.environ.get("SECUREMAILSCOPE_DB", str(ROOT / "data" / "securemailscope.sqlite"))
    )
    app = FastAPI(
        title="SecureMailScope Forensic API",
        version="1.0.0",
        description="Local PCAP analysis and persisted independent rule/ML results.",
    )
    app.state.report_store = report_store

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "api_version": "1.0.0"}

    @app.get("/api/v1/ml/models")
    def list_ml_models() -> dict[str, Any]:
        return model_catalog()

    @app.get("/api/v1/analyses")
    def list_analyses(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
        runs = report_store.list_runs(limit)
        return {"items": runs, "count": len(runs)}

    @app.get("/api/v1/overview")
    def overview() -> dict[str, Any]:
        return report_store.dashboard_summary()

    @app.post(
        "/api/v1/analyses",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/octet-stream": {
                        "schema": {"type": "string", "format": "binary"}
                    }
                },
            }
        },
    )
    async def analyze_capture(
        request: Request,
        filename: str = Header(default="capture.pcap", alias="X-Filename"),
        trust_store: str = Query(default="testbed", pattern="^(testbed|production|system)$"),
    ) -> dict[str, Any]:
        accepted_types = {
            "application/octet-stream",
            "application/vnd.tcpdump.pcap",
            "application/vnd.tcpdump.pcapng",
        }
        if request.headers.get("content-type", "").split(";", 1)[0].lower() not in accepted_types:
            raise HTTPException(status_code=415, detail="Upload the capture as a PCAP binary body")
        with tempfile.TemporaryDirectory(prefix="securemailscope-") as temp_dir:
            decoded_filename = unquote(filename)
            safe_filename = Path(decoded_filename).name or "capture.pcap"
            capture_path = Path(temp_dir) / safe_filename
            size = 0
            with capture_path.open("wb") as destination:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > MAX_PCAP_BYTES:
                        raise HTTPException(status_code=413, detail="PCAP exceeds the 512 MiB upload limit")
                    destination.write(chunk)
            if size == 0:
                raise HTTPException(status_code=400, detail="PCAP body is empty")
            try:
                # ML is part of every analysis run. Individual model outputs
                # remain protocol/cohort/feature gated inside ml_runtime.
                engine = RuleEngine(enable_ml=True)
                report = engine.evaluate_pcap(str(capture_path), trust_store=trust_store)
                run_id = report_store.save_report(report, safe_filename)
            except HTTPException:
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=422,
                    detail=f"Capture analysis failed ({type(exc).__name__}); verify the PCAP and analyzer dependencies.",
                ) from exc
        return {"run_id": run_id, "total_streams": report.total_streams}

    @app.get("/api/v1/analyses/{run_id}")
    def get_analysis(run_id: str) -> dict[str, Any]:
        report = report_store.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return {"run_id": run_id, "report": report}

    @app.delete("/api/v1/analyses/{run_id}", status_code=204)
    def delete_analysis(run_id: str) -> None:
        if not report_store.delete_run(run_id):
            raise HTTPException(status_code=404, detail="Analysis not found")

    @app.get("/api/v1/analyses/{run_id}/streams/{stream_id}")
    def get_stream(run_id: str, stream_id: int) -> dict[str, Any]:
        stream = report_store.get_stream(run_id, stream_id)
        if stream is None:
            raise HTTPException(status_code=404, detail="Stream not found")
        return {"run_id": run_id, "stream": stream}

    @app.post("/api/v1/threat-prioritization")
    def prioritize(request: CVEPrioritizationRequest) -> dict[str, Any]:
        try:
            return prioritize_cves(request.cve_ids)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    # A built React app is served from the same local origin as the API. During
    # development Vite proxies /api to this application, so CORS is unnecessary.
    frontend_dist = ROOT / "frontend" / "dist"
    frontend_index = frontend_dist / "index.html"
    assets_dir = frontend_dist / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

    if frontend_index.is_file():
        @app.get("/", include_in_schema=False)
        def frontend_root() -> FileResponse:
            return FileResponse(frontend_index)

        @app.get("/{frontend_path:path}", include_in_schema=False)
        def frontend_routes(frontend_path: str) -> FileResponse:
            if frontend_path == "api" or frontend_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="API route not found")
            return FileResponse(frontend_index)

    return app


app = create_app()
