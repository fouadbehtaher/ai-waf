from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score, precision_recall_curve, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from utils import clamp, to_iso, utc_now


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def _parse_label(raw_value: str) -> int:
    return 1 if str(raw_value or "").strip().lower() == "malicious" else 0


def _vectorize(features: List[Dict[str, float]], feature_names: List[str]) -> List[List[float]]:
    return [[float(feature_map.get(name, 0.0) or 0.0) for name in feature_names] for feature_map in features]


def _choose_threshold(scores: List[float], labels: List[int], beta: float = 2.0) -> float:
    precision, recall, thresholds = precision_recall_curve(labels, scores)
    if len(thresholds) == 0:
        return 0.5

    best_threshold = float(thresholds[0])
    best_score = -1.0
    beta_squared = beta * beta
    for index, threshold in enumerate(thresholds):
        denominator = beta_squared * precision[index] + recall[index]
        current_score = 0.0 if denominator == 0 else (1 + beta_squared) * precision[index] * recall[index] / denominator
        if current_score > best_score:
            best_score = current_score
            best_threshold = float(threshold)
    return best_threshold


def _evaluate(scores: List[float], labels: List[int], threshold: float) -> Dict[str, float]:
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


def analyze_ml_log_training(runtime_settings, telemetry: Dict[str, object], active_model: Dict[str, object] | None = None, latest_apply_event: Dict[str, object] | None = None) -> Dict[str, object]:
    labeled_rows = int(telemetry.get("labeled_rows") or 0)
    benign_rows = int(telemetry.get("benign_rows") or 0)
    malicious_rows = int(telemetry.get("malicious_rows") or 0)
    total_live_requests = int(telemetry.get("total_live_requests") or 0)
    distinct_labeled_paths = int(telemetry.get("distinct_labeled_paths") or 0)

    min_labeled_rows = max(int(getattr(runtime_settings, "ml_log_training_min_labeled_rows", 40) or 40), 4)
    min_benign_rows = max(int(getattr(runtime_settings, "ml_log_training_min_benign_rows", 15) or 15), 2)
    min_malicious_rows = max(int(getattr(runtime_settings, "ml_log_training_min_malicious_rows", 15) or 15), 2)
    cooldown_seconds = max(int(getattr(runtime_settings, "ml_log_training_cooldown_seconds", 86400) or 86400), 60)
    algorithm = str(getattr(runtime_settings, "ml_log_training_algorithm", "random_forest") or "random_forest").strip().lower()

    mode = "ready"
    confidence = "medium"
    reasons: list[str] = []

    if labeled_rows < min_labeled_rows or benign_rows < min_benign_rows or malicious_rows < min_malicious_rows:
        mode = "insufficient_data"
        confidence = "low"
        reasons.append(
            "Daily ML retraining needs at least {0} labeled rows with {1} benign and {2} malicious examples.".format(
                min_labeled_rows,
                min_benign_rows,
                min_malicious_rows,
            )
        )
    else:
        confidence = "high" if labeled_rows >= (min_labeled_rows * 2) else "medium"
        reasons.append(
            "The logged training corpus is ready for {0} retraining with {1} labeled requests.".format(
                algorithm.replace("_", " "),
                labeled_rows,
            )
        )

    last_apply = latest_apply_event or {}
    cooldown_remaining_seconds = 0
    if last_apply.get("created_at_epoch"):
        elapsed = max(0.0, utc_now().timestamp() - float(last_apply.get("created_at_epoch") or 0.0))
        cooldown_remaining_seconds = max(0, int(cooldown_seconds - elapsed))

    can_apply = mode == "ready"
    can_auto_apply = bool(getattr(runtime_settings, "ml_log_training_enabled", False)) and can_apply and cooldown_remaining_seconds <= 0
    active_model = active_model or {}
    summary = reasons[0] if reasons else "No ML log-training recommendation is available."

    return {
        "generated_at": to_iso(),
        "enabled": bool(getattr(runtime_settings, "ml_log_training_enabled", False)),
        "mode": mode,
        "confidence": confidence,
        "can_apply": can_apply,
        "can_auto_apply": can_auto_apply,
        "cooldown_remaining_seconds": cooldown_remaining_seconds,
        "current_model": active_model,
        "targets": {
            "window_seconds": int(getattr(runtime_settings, "ml_log_training_window_seconds", 604800) or 604800),
            "min_labeled_rows": min_labeled_rows,
            "min_benign_rows": min_benign_rows,
            "min_malicious_rows": min_malicious_rows,
            "cooldown_seconds": cooldown_seconds,
            "algorithm": algorithm,
        },
        "telemetry": {
            "total_live_requests": total_live_requests,
            "labeled_rows": labeled_rows,
            "benign_rows": benign_rows,
            "malicious_rows": malicious_rows,
            "label_coverage_rate": _round_float(float(telemetry.get("label_coverage_rate") or 0.0), 4),
            "distinct_labeled_paths": distinct_labeled_paths,
            "latest_label_epoch": float(telemetry.get("latest_label_epoch") or 0.0),
        },
        "recommendation": {
            "summary": summary,
            "reasons": reasons,
            "candidate_version": "logs-{0}-{1}".format(algorithm.replace("_", "-"), utc_now().strftime("%Y%m%d-%H%M%S")),
        },
        "last_log_training": {
            "created_at": str(last_apply.get("created_at") or ""),
            "actor_username": str(last_apply.get("actor_username") or ""),
            "details": last_apply.get("details") or {},
        },
    }


def train_model_from_logged_rows(rows: List[Dict[str, object]], runtime_settings, storage, actor_username: str, trigger: str) -> Dict[str, object]:
    if not rows:
        raise ValueError("No labeled request rows are available for ML log training.")

    algorithm = str(getattr(runtime_settings, "ml_log_training_algorithm", "random_forest") or "random_forest").strip().lower()
    version = "logs-{0}-{1}".format(algorithm.replace("_", "-"), utc_now().strftime("%Y%m%d-%H%M%S"))
    artifact_dir = Path(runtime_settings.model_artifact_path).parent
    artifact_path = artifact_dir / "{0}.joblib".format(version)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    feature_names = sorted({feature_name for row in rows for feature_name in (row.get("features") or {}).keys()})
    if not feature_names:
        raise ValueError("Labeled request rows do not include any feature vectors.")

    features = [dict(row.get("features") or {}) for row in rows]
    labels = [_parse_label(str(row.get("label") or "")) for row in rows]
    class_counts = Counter(labels)
    if len(class_counts) < 2:
        raise ValueError("ML log training needs both benign and malicious labeled rows.")

    matrix = _vectorize(features, feature_names)
    evaluation_mode = "holdout"

    min_class_count = min(class_counts.values())
    if len(rows) >= 12 and min_class_count >= 4:
        train_x, test_x, train_y, test_y = train_test_split(
            matrix,
            labels,
            test_size=0.25,
            stratify=labels,
            random_state=42,
        )
    else:
        train_x = matrix
        train_y = labels
        test_x = matrix
        test_y = labels
        evaluation_mode = "in_sample_fallback"

    if algorithm == "isolation_forest":
        benign_train = [row for row, label in zip(train_x, train_y) if label == 0]
        if not benign_train:
            raise ValueError("Isolation Forest training needs benign examples.")
        contamination = max(0.01, min(sum(labels) / float(len(labels)), 0.49))
        estimator = IsolationForest(
            n_estimators=250,
            contamination=contamination,
            random_state=42,
        )
        estimator.fit(benign_train)
        test_scores = [-float(score) for score in estimator.score_samples(test_x)]
        threshold = _choose_threshold(test_scores, test_y)
        metrics = _evaluate(test_scores, test_y, threshold)
        artifact_kind = "isolation_forest"
        model_name = "isolation_forest"
        model_type = "isolation_forest"
        min_score = min(test_scores)
        max_score = max(test_scores)
    else:
        estimator = RandomForestClassifier(
            n_estimators=250,
            max_depth=None,
            min_samples_leaf=1,
            class_weight="balanced_subsample",
            random_state=42,
        )
        estimator.fit(train_x, train_y)
        test_scores = [float(value[1]) for value in estimator.predict_proba(test_x)]
        threshold = _choose_threshold(test_scores, test_y)
        metrics = _evaluate(test_scores, test_y, threshold)
        artifact_kind = "random_forest_classifier"
        model_name = "random_forest"
        model_type = "random_forest_classifier"
        min_score = min(test_scores)
        max_score = max(test_scores)

    metrics.update(
        {
            "dataset_rows": len(rows),
            "feature_count": len(feature_names),
            "benign_rows": int(class_counts.get(0, 0)),
            "malicious_rows": int(class_counts.get(1, 0)),
            "evaluation_mode": evaluation_mode,
            "algorithm": algorithm,
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
        "model_version": version,
        "metrics": metrics,
    }
    joblib.dump(artifact, artifact_path)

    storage.register_model_version(
        model_version=version,
        model_type=model_type,
        artifact_path=str(artifact_path),
        metrics=metrics,
        is_active=True,
    )

    return {
        "model_version": version,
        "model_type": model_type,
        "artifact_path": str(artifact_path),
        "metrics": metrics,
        "training_rows": len(rows),
        "trigger": trigger,
        "actor_username": actor_username,
    }
