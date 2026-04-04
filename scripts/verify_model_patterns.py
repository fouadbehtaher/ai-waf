import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Dict, List

import joblib

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from core.attack_taxonomy import ATTACK_FAMILIES, attack_family_metadata
from core.ml_models import WeightedRiskModel


META_COLUMNS = {
    "request_id",
    "timestamp",
    "method",
    "path",
    "remote_addr",
    "label",
    "attack_family",
    "source_dataset",
    "expected_action",
    "attack_types_json",
    "rule_block",
    "hybrid_block",
}


def parse_label(raw_value: str) -> int:
    label = (raw_value or "").strip().lower()
    return 1 if label in {"1", "true", "attack", "malicious", "blocked"} else 0


def load_rows(csv_path: Path) -> List[Dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def safe_rate(matches: int, total: int) -> float:
    if not total:
        return 0.0
    return round(matches / float(total), 6)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify that the active AI artifact recognizes supported WAF attack patterns.")
    parser.add_argument("--dataset", default=str(settings.attack_pattern_dataset_path), help="Attack-pattern verification dataset.")
    parser.add_argument("--artifact", default=str(settings.model_artifact_path), help="Trained model artifact path.")
    parser.add_argument(
        "--output",
        default=str(settings.model_verification_report_path),
        help="Destination JSON report path for pattern verification.",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    artifact_path = Path(args.artifact)
    if not dataset_path.exists():
        raise SystemExit("Verification dataset not found: {0}".format(dataset_path))
    if not artifact_path.exists():
        raise SystemExit("Model artifact not found: {0}".format(artifact_path))

    rows = load_rows(dataset_path)
    artifact = joblib.load(artifact_path)
    feature_names = artifact["feature_names"]
    threshold = float(artifact["threshold"])
    artifact_kind = str(artifact.get("artifact_kind", "isolation_forest"))
    heuristic_model = WeightedRiskModel(weights=dict(settings.model_weights), bias=settings.model_bias)

    family_buckets: Dict[str, List[Dict[str, float]]] = defaultdict(list)
    benign_rows = []
    all_labels: List[int] = []
    all_ml_predictions: List[int] = []
    all_hybrid_predictions: List[int] = []

    for row in rows:
        feature_map = {name: float(row.get(name, 0.0) or 0.0) for name in feature_names}
        if artifact_kind == "random_forest_classifier":
            ml_normalized = float(artifact["estimator"].predict_proba([[feature_map.get(name, 0.0) for name in feature_names]])[0][1])
        else:
            ml_score = -float(artifact["estimator"].score_samples([[feature_map.get(name, 0.0) for name in feature_names]])[0])
            min_score = float(artifact.get("min_score", threshold))
            max_score = float(artifact.get("max_score", max(threshold, 1.0)))
            ml_normalized = 0.0 if max_score <= min_score else max(0.0, min(1.0, (ml_score - min_score) / (max_score - min_score)))
        heuristic_score = heuristic_model.predict_with_breakdown(feature_map).score
        hybrid_score = round(
            max(0.0, min(1.0, heuristic_score * settings.heuristic_weight + ml_normalized * settings.ml_weight)),
            6,
        )
        label = parse_label(row.get("label", ""))
        family = (row.get("attack_family") or "benign").strip().lower() or "benign"
        expected_action = (row.get("expected_action") or ("block" if label else "allow")).strip().lower()
        result = {
            "ml_score": round(ml_normalized, 6),
            "hybrid_score": hybrid_score,
            "label": label,
            "expected_action": expected_action,
            "ml_positive": int(ml_normalized >= threshold),
            "hybrid_monitor": int(hybrid_score >= settings.monitor_threshold),
            "hybrid_block": int(hybrid_score >= settings.block_threshold),
        }
        family_buckets[family].append(result)
        if family == "benign":
            benign_rows.append(result)
        all_labels.append(label)
        all_ml_predictions.append(result["ml_positive"])
        all_hybrid_predictions.append(result["hybrid_monitor"])

    family_results = []
    verified_count = 0
    supported_families = [family.attack_type for family in ATTACK_FAMILIES]
    for family in supported_families:
        bucket = family_buckets.get(family, [])
        metadata = attack_family_metadata(family)
        ml_detected = sum(item["ml_positive"] for item in bucket if item["label"] == 1)
        hybrid_detected = sum(item["hybrid_monitor"] for item in bucket if item["label"] == 1)
        hybrid_blocked = sum(item["hybrid_block"] for item in bucket if item["label"] == 1)
        positives = sum(1 for item in bucket if item["label"] == 1)
        average_ml = round(sum(item["ml_score"] for item in bucket) / float(max(len(bucket), 1)), 6)
        average_hybrid = round(sum(item["hybrid_score"] for item in bucket) / float(max(len(bucket), 1)), 6)
        verification_pass = positives > 0 and safe_rate(ml_detected, positives) >= 0.7 and safe_rate(hybrid_detected, positives) >= 0.9
        if verification_pass:
            verified_count += 1
        family_results.append(
            {
                "attack_type": family,
                "label": metadata["label"],
                "description": metadata["description"],
                "samples": len(bucket),
                "malicious_samples": positives,
                "ml_detect_rate": safe_rate(ml_detected, positives),
                "hybrid_detect_rate": safe_rate(hybrid_detected, positives),
                "hybrid_block_rate": safe_rate(hybrid_blocked, positives),
                "average_ml_score": average_ml,
                "average_hybrid_score": average_hybrid,
                "verified": verification_pass,
            }
        )

    benign_clear_ml = sum(1 for item in benign_rows if item["ml_positive"] == 0)
    benign_allow_hybrid = sum(1 for item in benign_rows if item["hybrid_monitor"] == 0)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_path": str(dataset_path),
        "artifact_path": str(artifact_path),
        "model_version": artifact.get("model_version", "unknown"),
        "threshold": round(threshold, 6),
        "monitor_threshold": round(float(settings.monitor_threshold), 6),
        "block_threshold": round(float(settings.block_threshold), 6),
        "supported_families": len(supported_families),
        "verified_families": verified_count,
        "family_pass_rate": safe_rate(verified_count, len(supported_families)),
        "benign_samples": len(benign_rows),
        "benign_ml_clear_rate": safe_rate(benign_clear_ml, len(benign_rows)),
        "benign_hybrid_allow_rate": safe_rate(benign_allow_hybrid, len(benign_rows)),
        "family_results": family_results,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
