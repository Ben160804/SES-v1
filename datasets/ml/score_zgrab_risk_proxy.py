"""Apply the ZGrab-only rule-flag proxy model; never score non-TLS records."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from train_zgrab_risk_classifier import (
    DATA,
    MODEL_PATH,
    _feature_dict,
)


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "datasets" / "ml" / "processed" / "zgrab_risk_proxy_scores_v1.csv"


def score() -> tuple[int, int]:
    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError(
            "ML dependency missing. Install with: "
            "python -m pip install -r datasets/ml/requirements.txt"
        ) from exc

    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Trained model not found: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    scored = 0
    not_evaluable = 0

    with DATA.open(newline="", encoding="utf-8") as source, OUTPUT.open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        reader = csv.DictReader(source)
        fields = (
            "record_id",
            "data_source",
            "status",
            "model_id",
            "target_semantics",
            "predicted_class",
            "uncalibrated_class_score",
        )
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for row in reader:
            result = {
                "record_id": row["record_id"],
                "data_source": row["data_source"],
                "status": "NOT_EVALUABLE",
                "model_id": "zgrab_rule_flag_proxy_v1",
                "target_semantics": "Proxy for the presence of one or more current deterministic flags; not ground-truth risk.",
                "predicted_class": "",
                "uncalibrated_class_score": "",
            }
            if row["tls_observation_state"] == "HANDSHAKE_SUCCEEDED":
                features = _feature_dict(row)
                prediction = model.predict([features])[0]
                classes = list(model.classes_)
                probability = model.predict_proba([features])[0]
                positive_score = probability[classes.index("HAS_RULE_FLAGGED_ISSUE")]
                result.update({
                    "status": "COMPLETED",
                    "predicted_class": prediction,
                    "uncalibrated_class_score": f"{positive_score:.6f}",
                })
                scored += 1
            else:
                not_evaluable += 1
            writer.writerow(result)

    return scored, not_evaluable


if __name__ == "__main__":
    try:
        scored_count, not_evaluable_count = score()
    except (ImportError, RuntimeError, FileNotFoundError) as exc:
        print(f"Scoring unavailable: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Scored {scored_count}; not evaluable {not_evaluable_count}")
    print(f"Scores: {OUTPUT.relative_to(ROOT)}")
