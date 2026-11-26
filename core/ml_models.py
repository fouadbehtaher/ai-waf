import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

from utils import clamp

try:
    import joblib
except Exception:
    joblib = None


@dataclass
class ScoreResult:
    score: float
    bias: float
    contributions: Dict[str, float]
    model_name: str
    model_version: str
    raw_score: float

    def as_dict(self) -> Dict[str, object]:
        sorted_contributions = dict(
            sorted(
                self.contributions.items(),
                key=lambda item: abs(item[1]),
                reverse=True,
            )
        )
        return {
            "score": self.score,
            "bias": self.bias,
            "contributions": sorted_contributions,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "raw_score": self.raw_score,
        }


class WeightedRiskModel:
    def __init__(self, weights: Dict[str, float], bias: float = 0.0, version: str = "heuristic-v1"):
        self.weights = dict(weights)
        self.bias = float(bias)
        self.model_name = "heuristic"
        self.model_version = version

    def predict_with_breakdown(self, features: Mapping[str, float]) -> ScoreResult:
        contributions: Dict[str, float] = {}
        raw_score = self.bias

        for feature_name, weight in self.weights.items():
            feature_value = float(features.get(feature_name, 0.0))
            contribution = round(feature_value * weight, 4)
            if contribution:
                contributions[feature_name] = contribution
            raw_score += contribution

        score = round(clamp(raw_score), 4)
        return ScoreResult(
            score=score,
            bias=self.bias,
            contributions=contributions,
            model_name=self.model_name,
            model_version=self.model_version,
            raw_score=round(raw_score, 4),
        )


class IsolationForestRiskModel:
    def __init__(self, artifact: Dict[str, object]):
        self.estimator = artifact["estimator"]
        self.feature_names = list(artifact["feature_names"])
        self.threshold = float(artifact.get("threshold", 0.5))
        self.min_score = float(artifact.get("min_score", self.threshold))
        self.max_score = float(artifact.get("max_score", max(self.threshold, 1.0)))
        self.model_name = str(artifact.get("model_name", "isolation_forest"))
        self.model_version = str(artifact.get("model_version", "iforest-v1"))

    def predict_with_breakdown(self, features: Mapping[str, float]) -> ScoreResult:
        vector = [[float(features.get(feature_name, 0.0)) for feature_name in self.feature_names]]
        raw_anomaly_score = float(-self.estimator.score_samples(vector)[0])
        normalized = 0.0
        if self.max_score > self.min_score:
            normalized = (raw_anomaly_score - self.min_score) / (self.max_score - self.min_score)
        score = round(clamp(normalized), 4)
        return ScoreResult(
            score=score,
            bias=0.0,
            contributions={"anomaly_score": round(score, 4)},
            model_name=self.model_name,
            model_version=self.model_version,
            raw_score=round(raw_anomaly_score, 4),
        )


class ProbabilityClassifierRiskModel:
    def __init__(self, artifact: Dict[str, object]):
        self.estimator = artifact["estimator"]
        self.feature_names = list(artifact["feature_names"])
        self.threshold = float(artifact.get("threshold", 0.5))
        self.model_name = str(artifact.get("model_name", "classifier"))
        self.model_version = str(artifact.get("model_version", "classifier-v1"))

    def predict_with_breakdown(self, features: Mapping[str, float]) -> ScoreResult:
        vector = [[float(features.get(feature_name, 0.0)) for feature_name in self.feature_names]]
        probability = float(self.estimator.predict_proba(vector)[0][1])
        score = round(clamp(probability), 4)
        return ScoreResult(
            score=score,
            bias=0.0,
            contributions={"classifier_probability": round(score, 4)},
            model_name=self.model_name,
            model_version=self.model_version,
            raw_score=round(probability, 4),
        )


class EnsembleRiskModel:
    def __init__(
        self,
        heuristic_model: WeightedRiskModel,
        anomaly_model: Optional[object],
        heuristic_weight: float,
        ml_weight: float,
    ):
        self.heuristic_model = heuristic_model
        self.anomaly_model = anomaly_model
        self.heuristic_weight = float(heuristic_weight)
        self.ml_weight = float(ml_weight)
        self.model_name = "hybrid" if anomaly_model else heuristic_model.model_name
        self.model_version = (
            "{0}+{1}".format(heuristic_model.model_version, anomaly_model.model_version)
            if anomaly_model
            else heuristic_model.model_version
        )

    def predict_with_breakdown(self, features: Mapping[str, float]) -> ScoreResult:
        heuristic_result = self.heuristic_model.predict_with_breakdown(features)
        if self.anomaly_model is None:
            return heuristic_result

        anomaly_result = self.anomaly_model.predict_with_breakdown(features)
        blended_score = clamp(
            heuristic_result.score * self.heuristic_weight + anomaly_result.score * self.ml_weight
        )
        contributions = {
            "heuristic_component": round(heuristic_result.score * self.heuristic_weight, 4),
            "ml_component": round(anomaly_result.score * self.ml_weight, 4),
        }
        for feature_name, contribution in heuristic_result.contributions.items():
            contributions["heuristic:{0}".format(feature_name)] = contribution
        for feature_name, contribution in anomaly_result.contributions.items():
            contributions["ml:{0}".format(feature_name)] = contribution

        return ScoreResult(
            score=round(blended_score, 4),
            bias=0.0,
            contributions=contributions,
            model_name=self.model_name,
            model_version=self.model_version,
            raw_score=round(blended_score, 4),
        )


def _load_fallback_weights(settings) -> WeightedRiskModel:
    candidate = Path(settings.fallback_model_path)
    if candidate.exists():
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        return WeightedRiskModel(
            weights=payload.get("weights", dict(settings.model_weights)),
            bias=float(payload.get("bias", settings.model_bias)),
            version=str(payload.get("model_version", "heuristic-v1")),
        )

    return WeightedRiskModel(weights=dict(settings.model_weights), bias=settings.model_bias)


def _load_anomaly_model(settings, active_metadata: Optional[Dict[str, object]] = None) -> Optional[object]:
    active_path = ""
    if active_metadata:
        active_path = str(active_metadata.get("artifact_path") or "").strip()
    candidate = Path(active_path) if active_path else Path(settings.model_artifact_path)
    if not candidate.exists() or joblib is None:
        return None

    artifact = joblib.load(candidate)
    artifact_kind = str(artifact.get("artifact_kind", "isolation_forest"))
    if artifact_kind == "random_forest_classifier":
        return ProbabilityClassifierRiskModel(artifact)
    return IsolationForestRiskModel(artifact)


def load_runtime_model(settings, active_metadata: Optional[Dict[str, object]] = None) -> EnsembleRiskModel:
    heuristic_model = _load_fallback_weights(settings)
    anomaly_model = _load_anomaly_model(settings, active_metadata=active_metadata)
    return EnsembleRiskModel(
        heuristic_model=heuristic_model,
        anomaly_model=anomaly_model,
        heuristic_weight=settings.heuristic_weight,
        ml_weight=settings.ml_weight,
    )


def load_model(model_path: Optional[str] = None) -> WeightedRiskModel:
    if model_path:
        candidate = Path(model_path)
        if candidate.exists():
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            return WeightedRiskModel(
                weights=payload.get("weights", {}),
                bias=float(payload.get("bias", 0.0)),
                version=str(payload.get("model_version", "heuristic-v1")),
            )
    return WeightedRiskModel(weights={}, bias=0.0)


def load_lstm_model(model_path: Optional[str] = None) -> WeightedRiskModel:
    return load_model(model_path)


def predict_score(model, features: Mapping[str, float]) -> float:
    return model.predict_with_breakdown(features).score


def predict_score_with_breakdown(model, features: Mapping[str, float]) -> ScoreResult:
    return model.predict_with_breakdown(features)


def predict_lstm(model, features: Mapping[str, float]) -> float:
    return predict_score(model, features)
