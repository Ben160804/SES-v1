"""Guard the controlled novelty evaluation and its provenance semantics."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "datasets/ml/models/controlled_novelty_benchmark_v1.json"


def test_controlled_novelty_benchmarks_have_disjoint_grouped_test_partitions():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert "synthetic" in report["provenance"]
    assert "real held-out" in report["provenance"]
    for model_id in ("certificate_novelty", "https_tls_anomaly"):
        model = report[model_id]
        assert model["source_observations"] > 0
        assert model["feature_count"] > 0
        assert model["artifact_sha256"]
        assert model["input_sha256"]
        assert model["splits"]["test"]["metrics"]["sample_count"] > 0
        assert model["splits"]["validation"]["metrics"]["sample_count"] > 0
        assert model["splits"]["test"]["metrics"]["confusion_matrix_labels_0_1"]
        assert "not measure attacks" in model["interpretation"]
    assert report["smtp_negotiation_support"]["splits"]["test"]["accuracy"] == 1.0
    assert "tautological" in report["smtp_negotiation_support"]["interpretation"]

