from __future__ import annotations

from typing import Dict, Tuple

from utils import clamp, to_iso, utc_now


THRESHOLD_MIN = 0.20
THRESHOLD_MAX = 0.95
THRESHOLD_GAP = 0.08


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def _bounded_threshold_pair(monitor_threshold: float, block_threshold: float) -> Tuple[float, float]:
    bounded_block = clamp(float(block_threshold), THRESHOLD_MIN + THRESHOLD_GAP, THRESHOLD_MAX)
    bounded_monitor = clamp(float(monitor_threshold), THRESHOLD_MIN, bounded_block - THRESHOLD_GAP)
    return (_round_float(bounded_monitor), _round_float(bounded_block))


def analyze_feedback_loop(runtime_settings, telemetry: Dict[str, object], latest_apply_event: Dict[str, object] | None = None) -> Dict[str, object]:
    total_feedback = int(telemetry.get("total_feedback") or 0)
    benign_feedback = int(telemetry.get("benign_feedback") or 0)
    malicious_feedback = int(telemetry.get("malicious_feedback") or 0)
    benign_blocked = int(telemetry.get("benign_blocked") or 0)
    benign_monitored = int(telemetry.get("benign_monitored") or 0)
    malicious_allowed = int(telemetry.get("malicious_allowed") or 0)
    malicious_monitored = int(telemetry.get("malicious_monitored") or 0)

    false_positive_feedback = benign_blocked + (0.5 * benign_monitored)
    missed_attack_feedback = malicious_allowed + (0.35 * malicious_monitored)
    benign_false_positive_rate = false_positive_feedback / float(max(benign_feedback, 1)) if benign_feedback else 0.0
    malicious_escape_rate = missed_attack_feedback / float(max(malicious_feedback, 1)) if malicious_feedback else 0.0

    min_feedback = max(int(getattr(runtime_settings, "feedback_loop_min_feedback", 3) or 3), 1)
    cooldown_seconds = max(int(getattr(runtime_settings, "feedback_loop_cooldown_seconds", 900) or 900), 60)
    relax_step = clamp(float(getattr(runtime_settings, "feedback_loop_relax_step", 0.04) or 0.04), 0.01, 0.12)
    harden_step = clamp(float(getattr(runtime_settings, "feedback_loop_harden_step", 0.05) or 0.05), 0.01, 0.12)

    current_values = {
        "block_threshold": float(getattr(runtime_settings, "block_threshold", 0.72) or 0.72),
        "monitor_threshold": float(getattr(runtime_settings, "monitor_threshold", 0.48) or 0.48),
    }
    recommended_values = dict(current_values)
    reasons: list[str] = []
    mode = "steady"
    confidence = "low"

    if total_feedback < min_feedback:
        mode = "insufficient_feedback"
        reasons.append(
            "Feedback loop waits for at least {0} labeled outcomes, but only {1} were observed in the current window.".format(
                min_feedback,
                total_feedback,
            )
        )
    else:
        confidence = "medium" if total_feedback < (min_feedback * 3) else "high"
        feedback_delta = false_positive_feedback - missed_attack_feedback

        if feedback_delta > 0.1:
            mode = "relax"
            weighted_step = min(relax_step + min(feedback_delta * 0.02, 0.03), 0.12)
            next_monitor, next_block = _bounded_threshold_pair(
                current_values["monitor_threshold"] + (weighted_step * 0.85),
                current_values["block_threshold"] + weighted_step,
            )
            recommended_values["block_threshold"] = next_block
            recommended_values["monitor_threshold"] = next_monitor
            reasons.append(
                "Requests labeled benign were blocked or monitored more often than attacks were missed, so the WAF should reduce sensitivity."
            )
            reasons.append(
                "Benign feedback produced a false-positive pressure of {0:.1%}, so thresholds are raised by about {1:.3f}.".format(
                    benign_false_positive_rate,
                    weighted_step,
                )
            )
        elif feedback_delta < -0.1:
            mode = "harden"
            weighted_step = min(harden_step + min(abs(feedback_delta) * 0.02, 0.03), 0.12)
            next_monitor, next_block = _bounded_threshold_pair(
                current_values["monitor_threshold"] - max(weighted_step * 0.85, 0.015),
                current_values["block_threshold"] - weighted_step,
            )
            recommended_values["block_threshold"] = next_block
            recommended_values["monitor_threshold"] = next_monitor
            reasons.append(
                "Some requests labeled malicious were still allowed, so the WAF should increase sensitivity."
            )
            reasons.append(
                "Malicious feedback produced an escape pressure of {0:.1%}, so thresholds are tightened by about {1:.3f}.".format(
                    malicious_escape_rate,
                    weighted_step,
                )
            )
        else:
            reasons.append(
                "Feedback is balanced right now, so no change is recommended."
            )

    changed_fields = {}
    for key, current_value in current_values.items():
        suggested_value = recommended_values[key]
        if abs(float(suggested_value) - float(current_value)) >= 0.001:
            changed_fields[key] = _round_float(suggested_value, 3)

    last_apply = latest_apply_event or {}
    last_apply_timestamp = str(last_apply.get("created_at") or "")
    cooldown_remaining_seconds = 0
    if last_apply.get("created_at_epoch"):
        elapsed = max(0.0, utc_now().timestamp() - float(last_apply.get("created_at_epoch") or 0.0))
        cooldown_remaining_seconds = max(0, int(cooldown_seconds - elapsed))

    can_apply = bool(changed_fields) and total_feedback >= min_feedback
    can_auto_apply = bool(getattr(runtime_settings, "feedback_loop_enabled", False)) and can_apply and cooldown_remaining_seconds <= 0
    summary_message = reasons[0] if reasons else "No feedback-loop recommendation is available."

    return {
        "generated_at": to_iso(),
        "enabled": bool(getattr(runtime_settings, "feedback_loop_enabled", False)),
        "mode": mode,
        "confidence": confidence,
        "can_apply": can_apply,
        "can_auto_apply": can_auto_apply,
        "cooldown_remaining_seconds": cooldown_remaining_seconds,
        "current": {
            "block_threshold": _round_float(current_values["block_threshold"], 3),
            "monitor_threshold": _round_float(current_values["monitor_threshold"], 3),
        },
        "targets": {
            "window_seconds": int(getattr(runtime_settings, "feedback_loop_window_seconds", 86400) or 86400),
            "min_feedback": min_feedback,
            "cooldown_seconds": cooldown_seconds,
            "relax_step": _round_float(relax_step, 3),
            "harden_step": _round_float(harden_step, 3),
        },
        "telemetry": {
            "total_feedback": total_feedback,
            "benign_feedback": benign_feedback,
            "malicious_feedback": malicious_feedback,
            "benign_blocked": benign_blocked,
            "benign_monitored": benign_monitored,
            "malicious_allowed": malicious_allowed,
            "malicious_monitored": malicious_monitored,
            "false_positive_feedback": _round_float(false_positive_feedback, 3),
            "missed_attack_feedback": _round_float(missed_attack_feedback, 3),
            "benign_false_positive_rate": _round_float(benign_false_positive_rate, 4),
            "malicious_escape_rate": _round_float(malicious_escape_rate, 4),
        },
        "recommendation": {
            "summary": summary_message,
            "reasons": reasons,
            "changes": changed_fields,
            "recommended_settings": {
                key: changed_fields.get(key, _round_float(value, 3))
                for key, value in recommended_values.items()
            },
        },
        "last_feedback_apply": {
            "created_at": last_apply_timestamp,
            "actor_username": str(last_apply.get("actor_username") or ""),
            "details": last_apply.get("details") or {},
        },
    }
