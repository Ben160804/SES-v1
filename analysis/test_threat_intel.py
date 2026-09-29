"""Tests for explicit-evidence-only KEV/EPSS enrichment."""

import csv
import gzip
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis import threat_intel


class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.kev_path = root / "kev.csv"
        with self.kev_path.open("w", newline="", encoding="utf-8") as target:
            writer = csv.DictWriter(target, fieldnames=["cveID", "dateAdded", "dueDate", "requiredAction", "knownRansomwareCampaignUse"])
            writer.writeheader()
            writer.writerow({"cveID": "CVE-2024-12345", "dateAdded": "2024-01-01", "dueDate": "2024-02-01", "requiredAction": "Patch", "knownRansomwareCampaignUse": "Unknown"})
        self.epss_path = root / "epss.csv.gz"
        with gzip.open(self.epss_path, "wt", newline="", encoding="utf-8") as target:
            target.write("#snapshot:test\ncve,epss,percentile\n")
            target.write("CVE-2024-12345,0.02,0.91\n")
            target.write("CVE-2025-54321,0.62,0.99\n")
        self.patcher = patch.object(threat_intel, "KEV_PATH", self.kev_path)
        self.patcher.start()
        self.epss_patcher = patch.object(threat_intel, "EPSS_PATH", self.epss_path)
        self.epss_patcher.start()

    def tearDown(self):
        threat_intel._load_kev.cache_clear()
        threat_intel._load_epss.cache_clear()
        self.patcher.stop()
        self.epss_patcher.stop()
        self.temp_dir.cleanup()

    def test_kev_takes_precedence_and_epss_ranks_other_cves(self):
        result = threat_intel.prioritize_cves(["cve-2025-54321", "CVE-2024-12345"])
        self.assertEqual(result["items"][0]["priority"], "KNOWN_EXPLOITED")
        self.assertTrue(result["items"][0]["kev"]["listed"])
        self.assertEqual(result["items"][1]["priority"], "VERY_HIGH")

    def test_no_explicit_cve_returns_no_mapping(self):
        self.assertEqual(threat_intel.prioritize_cves([])["status"], "NO_CVE_MAPPING")

    def test_invalid_cve_identifier_is_rejected(self):
        with self.assertRaises(ValueError):
            threat_intel.prioritize_cves(["TLS_RSA_WITH_AES_128_CBC_SHA"])


if __name__ == "__main__":
    unittest.main()
