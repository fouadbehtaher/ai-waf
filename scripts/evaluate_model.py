import argparse
import csv
import json
from pathlib import Path
import sys
from typing import Dict, List

import joblib
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


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
    if label in {"1", "true", "attack", "malicious", "blocked"}:
        return 1
    return 0


def evaluate_predictions(labels: List[int], predictions: List[int], scores: List[float]) -> Dict[str, float]:
    return {
        "precision": round(precision_score(labels, predictions, zero_division=0), 6),
        "recall": round(recall_score(labels, predictions, zero_division=0), 6),
        "f1": round(f1_score(labels, predictions, zero_division=0), 6),
        "roc_auc": round(roc_auc_score(labels, scores) if len(set(labels)) > 1 else 0.0, 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a trained WAF ML model.")
    parser.add_argument("--dataset", required=True, help="Labeled CSV dataset path.")
    parser.add_argument("--artifact", required=True, help="Model artifact path created by train_model.py.")
    parser.add_argument(
        "--rules-column",
        default="rule_block",
        help="Optional column containing rule-only baseline predictions.",
    )
    parser.add_argument(
        "--hybrid-column",
        default="hybrid_block",
        help="Optional column containing hybrid baseline predictions.",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    artifact = joblib.load(args.artifact)

    with dataset_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    feature_names = artifact["feature_names"]
    labels = [parse_label(row.get("label", "")) for row in rows]
    matrix = [[float(row.get(name, 0.0) or 0.0) for name in feature_names] for row in rows]
    artifact_kind = str(artifact.get("artifact_kind", "isolation_forest"))
    if artifact_kind == "random_forest_classifier":
        scores = [float(value[1]) for value in artifact["estimator"].predict_proba(matrix)]
    else:
        scores = [-float(score) for score in artifact["estimator"].score_samples(matrix)]
    threshold = float(artifact["threshold"])
    predictions = [1 if score >= threshold else 0 for score in scores]

    output = {
        "ml_only": evaluate_predictions(labels, predictions, scores),
        "threshold": threshold,
        "model_version": artifact.get("model_version", "unknown"),
    }

    if args.rules_column in rows[0]:
        baseline = [parse_label(row.get(args.rules_column, "")) for row in rows]
        output["rule_only"] = evaluate_predictions(labels, baseline, baseline)

    if args.hybrid_column in rows[0]:
        hybrid = [parse_label(row.get(args.hybrid_column, "")) for row in rows]
        output["hybrid"] = evaluate_predictions(labels, hybrid, hybrid)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
