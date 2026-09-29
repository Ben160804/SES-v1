"""Contract tests for the read-only forensic report API."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from analysis.api import create_app
from analysis.api import CVEPrioritizationRequest
from analysis.report_store import ReportStore


class TestReportAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = ReportStore(Path(self.temp_dir.name) / "api.sqlite")
        self.run_id = self.store.save_report({
            "total_streams": 1,
            "stream_reports": {
                "4": {
                    "stream_id": 4,
                    "protocol": "SMTP",
                    "policy_results": {"NIST-52R2": [{"verdict": "FAIL"}]},
                    "observations": [],
                    "ml_results": {"smtp_configuration_anomaly": {"status": "COMPLETED_EXPLORATORY"}},
                    "posture_assessment": {"status": "ASSESSED", "score": 80},
                    "input_snapshot": {"tls": {"tls_version": "TLS 1.2"}},
                }
            },
        }, "capture.pcap")
        self.app = create_app(self.store)
        self.routes = {
            (method, route.path): route.endpoint
            for route in self.app.routes if hasattr(route, "endpoint")
            for method in (route.methods or set())
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_lists_and_returns_report_with_separate_outputs(self):
        listing = self.routes[("GET", "/api/v1/analyses")](limit=50)
        self.assertEqual(listing["items"][0]["run_id"], self.run_id)
        report = self.routes[("GET", "/api/v1/analyses/{run_id}")](run_id=self.run_id)["report"]
        stream = report["stream_reports"]["4"]
        self.assertIn("policy_results", stream)
        self.assertIn("ml_results", stream)
        self.assertIn("posture_assessment", stream)

    def test_ml_model_catalog_is_available_for_frontend_consumers(self):
        catalog = self.routes[("GET", "/api/v1/ml/models")]()
        self.assertEqual(catalog["model_count"], 10)
        self.assertIn("classifier_risk_tier", catalog["independent_outputs"])
        self.assertIn("synthetic_email_risk_classifier", catalog["independent_outputs"])
        self.assertIn("zgrab_evidence_risk_classifier", catalog["independent_outputs"])
        self.assertIn("smtp_configuration_rarity", catalog["independent_outputs"])
        self.assertIn("advisory", catalog["authority_note"])

    def test_built_react_frontend_is_served_from_same_local_origin(self):
        frontend_routes = {
            route.path: route.endpoint for route in self.app.routes
            if getattr(route, "path", None) in {"/", "/{frontend_path:path}"}
        }
        if not (Path(__file__).resolve().parents[1] / "frontend/dist/index.html").is_file():
            self.skipTest("Build the React frontend before checking same-origin serving")
        self.assertIn("/", frontend_routes)
        self.assertIn("/{frontend_path:path}", frontend_routes)
        response = frontend_routes["/"]()
        self.assertEqual(Path(response.path), Path(__file__).resolve().parents[1] / "frontend/dist/index.html")
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as api_fallback:
            frontend_routes["/{frontend_path:path}"](frontend_path="api/not-a-route")
        self.assertEqual(api_fallback.exception.status_code, 404)

    def test_stream_endpoint_and_missing_ids(self):
        response = self.routes[("GET", "/api/v1/analyses/{run_id}/streams/{stream_id}")](
            run_id=self.run_id, stream_id=4
        )
        self.assertEqual(response["stream"]["protocol"], "SMTP")
        self.assertIn("posture_assessment", response["stream"])
        with self.assertRaises(HTTPException) as missing_run:
            self.routes[("GET", "/api/v1/analyses/{run_id}")](run_id="missing")
        self.assertEqual(missing_run.exception.status_code, 404)
        with self.assertRaises(HTTPException) as missing_stream:
            self.routes[("GET", "/api/v1/analyses/{run_id}/streams/{stream_id}")](
                run_id=self.run_id, stream_id=99
            )
        self.assertEqual(missing_stream.exception.status_code, 404)

    def test_list_limit_is_bounded_by_store(self):
        with self.assertRaises(ValueError):
            self.routes[("GET", "/api/v1/analyses")](limit=501)

    def test_threat_prioritization_endpoint_requires_explicit_cve_ids(self):
        endpoint = self.routes[("POST", "/api/v1/threat-prioritization")]
        response = endpoint(CVEPrioritizationRequest(cve_ids=["CVE-2024-12345"]))
        self.assertEqual(response["status"], "ENRICHED")
        with self.assertRaises(HTTPException) as invalid:
            endpoint(CVEPrioritizationRequest(cve_ids=["not-a-cve"]))
        self.assertEqual(invalid.exception.status_code, 422)

    def test_pcap_ingest_analyzes_and_persists_full_result(self):
        messages = [{"type": "http.request", "body": b"pcap-data", "more_body": False}]

        async def receive():
            return messages.pop(0) if messages else {"type": "http.disconnect"}

        request = Request({
            "type": "http", "method": "POST", "path": "/api/v1/analyses",
            "headers": [(b"content-type", b"application/octet-stream")],
            "query_string": b"", "server": ("test", 80), "client": ("test", 1),
            "scheme": "http", "http_version": "1.1",
        }, receive)

        class FakeReport:
            total_streams = 1

            def to_dict(self):
                return {"total_streams": 1, "stream_reports": {}}

        with patch("analysis.api.RuleEngine") as engine:
            engine.return_value.evaluate_pcap.return_value = FakeReport()
            result = asyncio.run(self.routes[("POST", "/api/v1/analyses")](
                request, filename="input.pcap", trust_store="testbed", enable_ml=True
            ))
        self.assertEqual(result["total_streams"], 1)
        self.assertIsNotNone(self.store.get_run(result["run_id"]))

    def test_pcap_ingest_rejects_unknown_content_type(self):
        request = Request({
            "type": "http", "method": "POST", "path": "/api/v1/analyses",
            "headers": [(b"content-type", b"text/plain")], "query_string": b"",
            "server": ("test", 80), "client": ("test", 1), "scheme": "http", "http_version": "1.1",
        }, lambda: None)
        with self.assertRaises(HTTPException) as rejected:
            asyncio.run(self.routes[("POST", "/api/v1/analyses")](
                request, filename="input.pcap", trust_store="testbed", enable_ml=True
            ))
        self.assertEqual(rejected.exception.status_code, 415)


if __name__ == "__main__":
    unittest.main()
