"""Exercise the built React frontend against a real local PCAP API workflow."""

import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from analysis.api import create_app
from analysis.report_store import ReportStore


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "testbed/captures/PCAP-001.pcap"


class TestFrontendBackendIntegration(unittest.TestCase):
    def test_spa_serves_and_real_capture_report_round_trips_through_sqlite(self):
        if not (ROOT / "frontend/dist/index.html").is_file():
            self.skipTest("Build the React frontend before running this integration check")
        with tempfile.TemporaryDirectory() as directory:
            store = ReportStore(Path(directory) / "analysis.sqlite")
            client = TestClient(create_app(store))
            home = client.get("/")
            self.assertEqual(home.status_code, 200)
            self.assertIn(b"SecureMailScope", home.content)
            spa_route = client.get("/workspace")
            self.assertEqual(spa_route.status_code, 200)
            asset_paths = re.findall(rb'(?:src|href)="([^\"]+/assets/[^\"]+)"', home.content)
            self.assertTrue(asset_paths)
            self.assertEqual(client.get(asset_paths[0].decode()).status_code, 200)

            response = client.post(
                "/api/v1/analyses?trust_store=testbed&enable_ml=true",
                content=CAPTURE.read_bytes(),
                headers={
                    "content-type": "application/octet-stream",
                    "X-Filename": quote("../mail trace.pcap"),
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            run_id = response.json()["run_id"]
            self.assertGreater(response.json()["total_streams"], 0)

            listing = client.get("/api/v1/analyses").json()
            self.assertEqual(listing["count"], 1)
            self.assertEqual(listing["items"][0]["source_name"], "mail trace.pcap")
            payload = client.get(f"/api/v1/analyses/{run_id}").json()["report"]
            self.assertGreater(payload["total_streams"], 0)
            stream = next(iter(payload["stream_reports"].values()))
            self.assertIn("policy_results", stream)
            self.assertIn("ml_results", stream)
            self.assertIn("posture_assessment", stream)
            catalog = client.get("/api/v1/ml/models").json()
            self.assertEqual(catalog["model_count"], 10)


if __name__ == "__main__":
    unittest.main()
