from __future__ import annotations

from typing import Dict, Iterable, Tuple

from utils import to_iso


THRESHOLD_FIELDS = {"block_threshold", "monitor_threshold"}
RATE_LIMIT_FIELDS = {
    "rate_limit_max_requests",
    "token_bucket_capacity",
    "token_bucket_refill_rate",
}
CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}
CONFIDENCE_LABELS = {value: key for key, value in CONFIDENCE_ORDER.items()}
SOURCE_PRIORITY = {"feedback_loop": 2, "auto_tuning": 1}
SOURCE_LABELS = {
    "feedback_loop": "Feedback Loop",
    "auto_tuning": "Auto-Tuning",
}


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def _direction_for_field(field: str, current_value, proposed_value: float) -> str:
    current = float(current_value or 0.0)
    proposed = float(proposed_value or 0.0)
    if abs(proposed - current) < 0.001:
        return "steady"
    if field in THRESHOLD_FIELDS or field in RATE_LIMIT_FIELDS:
        return "relax" if proposed > current else "harden"
    return "change"


def _normalize_change_entry(field: str, current_settings: Dict[str, object], value, source: str) -> Dict[str, object]:
    current_value = current_settings.get(field)
    direction = _direction_for_field(field, current_value, value)
    delta = abs(float(value or 0.0) - float(current_value or 0.0))
    if isinstance(current_value, int) and not isinstance(current_value, bool):
        normalized_value = int(value)
    else:
        normalized_value = _round_float(value, 3)
    return {
        "field": field,
        "value": normalized_value,
        "current": current_value,
        "source": source,
        "direction": direction,
        "delta": _round_float(delta, 4),
    }


def _merge_change_sets(
    current_settings: Dict[str, object],
    change_sets: Iterable[Tuple[str, Dict[str, object]]],
) -> Dict[str, object]:
    merged: Dict[str, Dict[str, object]] = {}
    conflicts: list[Dict[str, object]] = []

    for source, changes in change_sets:
        for field, value in (changes or {}).items():
            candidate = _normalize_change_entry(field, current_settings, value, source)
            existing = merged.get(field)
            if existing is None:
                merged[field] = candidate
                continue

            if existing["direction"] == candidate["direction"]:
                if candidate["delta"] > existing["delta"]:
                    merged[field] = candidate
                continue

            winner = existing
            loser = candidate
            if SOURCE_PRIORITY.get(candidate["source"], 0) > SOURCE_PRIORITY.get(existing["source"], 0):
                winner = candidate
                loser = existing
                merged[field] = candidate

            conflicts.append(
                {
                    "field": field,
                    "current": existing["current"],
                    "winner_source": winner["source"],
                    "winner_label": SOURCE_LABELS.get(winner["source"], winner["source"]),
                    "winner_direction": winner["direction"],
                    "winner_value": winner["value"],
                    "loser_source": loser["source"],
                    "loser_label": SOURCE_LABELS.get(loser["source"], loser["source"]),
                    "loser_direction": loser["direction"],
                    "loser_value": loser["value"],
                }
            )

    directions = {
        field: entry["direction"]
        for field, entry in merged.items()
        if entry["direction"] in {"relax", "harden"}
    }
    return {
        "changes": {
            field: entry["value"]
            for field, entry in merged.items()
            if entry["direction"] != "steady"
        },
        "change_sources": {
            field: entry["source"]
            for field, entry in merged.items()
            if entry["direction"] != "steady"
        },
        "change_directions": directions,
        "conflicts": conflicts,
    }


def _highest_confidence(*values: str) -> str:
    best = max((CONFIDENCE_ORDER.get(value or "", 0) for value in values), default=0)
    return CONFIDENCE_LABELS.get(best, "low")


def _strategy_summary(key: str, report: Dict[str, object], manual_ready: bool, auto_ready: bool) -> Dict[str, object]:
    recommendation = report.get("recommendation", {})
    return {
        "key": key,
        "label": SOURCE_LABELS.get(key, key.replace("_", " ").title()),
        "enabled": bool(report.get("enabled")),
        "mode": str(report.get("mode") or "steady"),
        "confidence": str(report.get("confidence") or "low"),
        "manual_ready": manual_ready,
        "automatic_ready": auto_ready,
        "cooldown_remaining_seconds": int(report.get("cooldown_remaining_seconds") or 0),
        "changes": dict(recommendation.get("changes") or {}),
        "summary": str(recommendation.get("summary") or report.get("summary") or ""),
    }


def _derive_posture(merged_directions: Dict[str, str], dynamic_report: Dict[str, object]) -> str:
    unique_directions = {direction for direction in merged_directions.values() if direction in {"relax", "harden"}}
    if len(unique_directions) > 1:
        return "mixed"
    if len(unique_directions) == 1:
        return next(iter(unique_directions))
    if dynamic_report.get("active"):
        return "dynamic"
    return "steady"


def _build_summary(posture: str, dynamic_report: Dict[str, object], manual_changes: Dict[str, object], conflicts: list[Dict[str, object]]) -> str:
    if conflicts:
        return (
            "Analyst feedback and traffic heuristics disagree on at least one field. "
            "The merged adaptivity plan follows Feedback Loop for conflicting changes and keeps non-conflicting traffic tuning."
        )
    if posture == "harden":
        return "Adaptivity recommends hardening the live WAF posture based on recent attack pressure and reviewed outcomes."
    if posture == "relax":
        return "Adaptivity recommends relaxing sensitivity because reviewed traffic indicates false-positive pressure."
    if posture == "dynamic":
        return (
            "Dynamic thresholds are active and currently shaping the effective block and monitor thresholds from live traffic."
        )
    if manual_changes:
        return "Adaptivity has pending runtime changes ready for review."
    return "Adaptivity is steady right now. Dynamic thresholds, auto-tuning, and feedback loop do not require a policy change."


def analyze_adaptivity(
    runtime_settings,
    auto_tuning_report: Dict[str, object],
    feedback_loop_report: Dict[str, object],
    dynamic_threshold_report: Dict[str, object],
    latest_apply_event: Dict[str, object] | None = None,
) -> Dict[str, object]:
    current_settings = {
        "block_threshold": _round_float(getattr(runtime_settings, "block_threshold", 0.72), 3),
        "monitor_threshold": _round_float(getattr(runtime_settings, "monitor_threshold", 0.48), 3),
        "rate_limit_max_requests": int(getattr(runtime_settings, "rate_limit_max_requests", 30) or 30),
        "token_bucket_capacity": int(getattr(runtime_settings, "token_bucket_capacity", 45) or 45),
        "token_bucket_refill_rate": _round_float(getattr(runtime_settings, "token_bucket_refill_rate", 0.75), 3),
    }

    manual_merge = _merge_change_sets(
        current_settings,
        [
            ("auto_tuning", dict((auto_tuning_report or {}).get("recommendation", {}).get("changes") or {}))
            if auto_tuning_report.get("can_apply")
            else ("auto_tuning", {}),
            ("feedback_loop", dict((feedback_loop_report or {}).get("recommendation", {}).get("changes") or {}))
            if feedback_loop_report.get("can_apply")
            else ("feedback_loop", {}),
        ],
    )
    automatic_merge = _merge_change_sets(
        current_settings,
        [
            ("auto_tuning", dict((auto_tuning_report or {}).get("recommendation", {}).get("changes") or {}))
            if auto_tuning_report.get("enabled") and auto_tuning_report.get("can_auto_apply")
            else ("auto_tuning", {}),
            ("feedback_loop", dict((feedback_loop_report or {}).get("recommendation", {}).get("changes") or {}))
            if feedback_loop_report.get("enabled") and feedback_loop_report.get("can_auto_apply")
            else ("feedback_loop", {}),
        ],
    )

    dynamic_effective = dict((dynamic_threshold_report or {}).get("effective") or {})
    effective_block = dynamic_effective.get("block_threshold", current_settings["block_threshold"])
    effective_monitor = dynamic_effective.get("monitor_threshold", current_settings["monitor_threshold"])
    posture = _derive_posture(manual_merge["change_directions"], dynamic_threshold_report)
    confidence = _highest_confidence(
        auto_tuning_report.get("confidence", "low"),
        feedback_loop_report.get("confidence", "low"),
    )
    if manual_merge["conflicts"] and confidence == "high":
        confidence = "medium"

    strategy_status = {
        "auto_tuning": _strategy_summary(
            "auto_tuning",
            auto_tuning_report,
            manual_ready=bool(auto_tuning_report.get("can_apply")),
            auto_ready=bool(auto_tuning_report.get("enabled") and auto_tuning_report.get("can_auto_apply")),
        ),
        "feedback_loop": _strategy_summary(
            "feedback_loop",
            feedback_loop_report,
            manual_ready=bool(feedback_loop_report.get("can_apply")),
            auto_ready=bool(feedback_loop_report.get("enabled") and feedback_loop_report.get("can_auto_apply")),
        ),
        "dynamic_thresholds": {
            "key": "dynamic_thresholds",
            "label": "Dynamic Thresholds",
            "enabled": bool(dynamic_threshold_report.get("enabled")),
            "active": bool(dynamic_threshold_report.get("active")),
            "mode": str(dynamic_threshold_report.get("mode") or "static"),
            "summary": str(dynamic_threshold_report.get("summary") or ""),
            "effective": {
                "block_threshold": _round_float(effective_block, 4),
                "monitor_threshold": _round_float(effective_monitor, 4),
                "source": dynamic_effective.get("source", "static"),
            },
        },
    }

    manual_sources = sorted(set(manual_merge["change_sources"].values()))
    automatic_sources = sorted(set(automatic_merge["change_sources"].values()))
    last_apply = latest_apply_event or {}
    summary = _build_summary(posture, dynamic_threshold_report, manual_merge["changes"], manual_merge["conflicts"])

    return {
        "generated_at": to_iso(),
        "posture": posture,
        "confidence": confidence,
        "summary": summary,
        "can_apply": bool(manual_merge["changes"]),
        "can_auto_apply": bool(automatic_merge["changes"]),
        "current": current_settings,
        "effective": {
            "block_threshold": _round_float(effective_block, 4),
            "monitor_threshold": _round_float(effective_monitor, 4),
            "source": dynamic_effective.get("source", "static"),
        },
        "dynamic_thresholds": strategy_status["dynamic_thresholds"],
        "strategies": strategy_status,
        "recommendation": {
            "summary": summary,
            "changes": manual_merge["changes"],
            "automatic_changes": automatic_merge["changes"],
            "change_sources": manual_merge["change_sources"],
            "automatic_change_sources": automatic_merge["change_sources"],
            "change_directions": manual_merge["change_directions"],
            "automatic_change_directions": automatic_merge["change_directions"],
            "conflicts": manual_merge["conflicts"],
            "manual_ready_strategies": manual_sources,
            "automatic_ready_strategies": automatic_sources,
        },
        "last_adaptivity_cycle": {
            "created_at": str(last_apply.get("created_at") or ""),
            "actor_username": str(last_apply.get("actor_username") or ""),
            "details": last_apply.get("details") or {},
        },
        "reports": {
            "auto_tuning": auto_tuning_report,
            "feedback_loop": feedback_loop_report,
            "dynamic_thresholds": dynamic_threshold_report,
        },
    }
