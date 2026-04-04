import argparse
import csv
import json
from pathlib import Path
import sys
from typing import Dict, List, Tuple

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_recall_curve, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from core.storage import Storage


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


def load_dataset(csv_path: Path) -> Tuple[List[Dict[str, float]], List[int], List[str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if not rows:
        raise SystemExit("Dataset is empty: {0}".format(csv_path))

    feature_names = [name for name in rows[0].keys() if name not in META_COLUMNS]
    features: List[Dict[str, float]] = []
    labels: List[int] = []

    for row in rows:
        labels.append(parse_label(row.get("label", "")))
        features.append({name: float(row.get(name, 0.0) or 0.0) for name in feature_names})

    return features, labels, feature_names


def vectorize(features: List[Dict[str, float]], feature_names: List[str]) -> List[List[float]]:
    return [[feature_map.get(name, 0.0) for name in feature_names] for feature_map in features]


def choose_threshold(scores: List[float], labels: List[int], beta: float = 2.0) -> float:
    precision, recall, thresholds = precision_recall_curve(labels, scores)
    if len(thresholds) == 0:
        return 0.5

    best_threshold = thresholds[0]
    best_score = -1.0
    beta_squared = beta * beta
    for index, threshold in enumerate(thresholds):
        denominator = beta_squared * precision[index] + recall[index]
        current_score = 0.0 if denominator == 0 else (1 + beta_squared) * precision[index] * recall[index] / denominator
        if current_score > best_score:
            best_score = current_score
            best_threshold = threshold
    return float(best_threshold)


def evaluate(scores: List[float], labels: List[int], threshold: float) -> Dict[str, float]:
    predictions = [1 if score >= threshold else 0 for score in scores]
    metrics = {
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "roc_auc": roc_auc_score(labels, scores) if len(set(labels)) > 1 else 0.0,
        "threshold": threshold,
        "positive_rate": sum(predictions) / float(max(len(predictions), 1)),
    }
    return {key: round(float(value), 6) for key, value in metrics.items()}


def main() -> None:
    default_db_target = settings.database_url or str(settings.db_path)
    parser = argparse.ArgumentParser(description="Train a WAF ML model for the runtime pipeline.")
    parser.add_argument("--dataset", default=str(settings.labeled_dataset_path), help="Labeled CSV dataset path.")
    parser.add_argument(
        "--artifact",
        default=str(settings.model_artifact_path),
        help="Destination model artifact path.",
    )
    parser.add_argument("--db", default=default_db_target, help="Database path or PostgreSQL URL for model registration.")
    parser.add_argument("--version", default="iforest-v1", help="Model version to register.")
    parser.add_argument(
        "--algorithm",
        choices=("random_forest", "isolation_forest"),
        default="random_forest",
        help="ML algorithm used for the artifact.",
    )
    parser.add_argument("--random-state", type=int, default=42, help="Random state for reproducibility.")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    artifact_path = Path(args.artifact)
    feature_rows, labels, feature_names = load_dataset(dataset_path)

    if len(set(labels)) < 2:
        raise SystemExit("The dataset must contain both benign and malicious labels.")

    train_rows, test_rows, train_labels, test_labels = train_test_split(
        feature_rows,
        labels,
        test_size=0.3,
        stratify=labels,
        random_state=args.random_state,
    )
    train_rows, validation_rows, train_labels, validation_labels = train_test_split(
        train_rows,
        train_labels,
        test_size=0.25,
        stratify=train_labels,
        random_state=args.random_state,
    )

    train_matrix = vectorize(train_rows, feature_names)
    validation_matrix = vectorize(validation_rows, feature_names)
    test_matrix = vectorize(test_rows, feature_names)

    if args.algorithm == "isolation_forest":
        benign_train_rows = [row for row, label in zip(train_rows, train_labels) if label == 0]
        if not benign_train_rows:
            raise SystemExit("Isolation Forest requires benign training examples.")
        train_matrix = vectorize(benign_train_rows, feature_names)
        contamination = max(0.01, min(sum(labels) / float(len(labels)), 0.49))
        estimator = IsolationForest(
            n_estimators=300,
            contamination=contamination,
            random_state=args.random_state,
        )
        estimator.fit(train_matrix)
        validation_scores = [-float(score) for score in estimator.score_samples(validation_matrix)]
        test_scores = [-float(score) for score in estimator.score_samples(test_matrix)]
        artifact_kind = "isolation_forest"
        model_name = "isolation_forest"
        model_type = "isolation_forest"
        min_score = min(validation_scores + test_scores)
        max_score = max(validation_scores + test_scores)
    else:
        estimator = RandomForestClassifier(
            n_estimators=400,
            max_depth=None,
            min_samples_leaf=1,
            class_weight="balanced_subsample",
            random_state=args.random_state,
        )
        estimator.fit(train_matrix, train_labels)
        validation_scores = [float(value[1]) for value in estimator.predict_proba(validation_matrix)]
        test_scores = [float(value[1]) for value in estimator.predict_proba(test_matrix)]
        artifact_kind = "random_forest_classifier"
        model_name = "random_forest"
        model_type = "random_forest_classifier"
        min_score = min(validation_scores + test_scores)
        max_score = max(validation_scores + test_scores)

    threshold = choose_threshold(validation_scores, validation_labels)
    metrics = evaluate(test_scores, test_labels, threshold)
    metrics.update(
        {
            "dataset_rows": len(feature_rows),
            "feature_count": len(feature_names),
            "benign_rows": sum(1 for value in labels if value == 0),
            "malicious_rows": sum(1 for value in labels if value == 1),
            "train_rows": len(train_rows),
            "validation_rows": len(validation_rows),
            "test_rows": len(test_rows),
        }
    )

    artifact = {
        "estimator": estimator,
        "artifact_kind": artifact_kind,
        "feature_names": feature_names,
        "threshold": threshold,
        "min_score": min_score,
        "max_score": max_score,
        "model_name": model_name,
        "model_version": args.version,
        "metrics": metrics,
    }

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path)

    storage = Storage(args.db, database_url=settings.database_url)
    storage.initialize()
    storage.register_model_version(
        model_version=args.version,
        model_type=model_type,
        artifact_path=str(artifact_path),
        metrics=metrics,
        is_active=True,
    )

    print(json.dumps({"artifact": str(artifact_path), "metrics": metrics}, indent=2))


if __name__ == "__main__":
    main()
