from __future__ import annotations

from typing import Dict, Tuple

from utils import clamp, to_iso, utc_now


THRESHOLD_MIN = 0.20
THRESHOLD_MAX = 0.95
THRESHOLD_GAP = 0.08

RATE_LIMIT_MIN = 8
RATE_LIMIT_MAX = 300
BUCKET_CAPACITY_MIN = 10
BUCKET_CAPACITY_MAX = 400
REFILL_MIN = 0.2
REFILL_MAX = 10.0


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def _bounded_threshold_pair(monitor_threshold: float, block_threshold: float) -> Tuple[float, float]:
    bounded_block = clamp(float(block_threshold), THRESHOLD_MIN + THRESHOLD_GAP, THRESHOLD_MAX)
    bounded_monitor = clamp(float(monitor_threshold), THRESHOLD_MIN, bounded_block - THRESHOLD_GAP)
    return (_round_float(bounded_monitor), _round_float(bounded_block))


def analyze_auto_tuning(runtime_settings, telemetry: Dict[str, object], latest_apply_event: Dict[str, object] | None = None) -> Dict[str, object]:
    total_requests = int(telemetry.get("total_requests") or 0)
    blocked = int(telemetry.get("blocked_requests") or 0)
    monitored = int(telemetry.get("monitored_requests") or 0)
    allowed = int(telemetry.get("allowed_requests") or 0)
    labeled_requests = int(telemetry.get("labeled_requests") or 0)
    benign_labeled = int(telemetry.get("benign_labeled") or 0)
    malicious_labeled = int(telemetry.get("malicious_labeled") or 0)
    benign_false_positive_count = int(telemetry.get("benign_false_positive_count") or 0)
    malicious_allowed = int(telemetry.get("malicious_allowed") or 0)
    attack_marked = int(telemetry.get("attack_marked_requests") or 0)
    flagged_requests = int(telemetry.get("flagged_requests") or 0)
    avg_risk_score = _round_float(float(telemetry.get("avg_risk_score") or 0.0), 4)

    false_positive_rate = 0.0
    if benign_labeled:
        false_positive_rate = benign_false_positive_count / float(max(benign_labeled, 1))

    attack_rate = attack_marked / float(max(total_requests, 1))
    block_rate = blocked / float(max(total_requests, 1))
    monitor_rate = monitored / float(max(total_requests, 1))
    malicious_miss_rate = malicious_allowed / float(max(malicious_labeled, 1)) if malicious_labeled else 0.0

    min_samples = max(int(getattr(runtime_settings, "auto_tuning_min_samples", 12) or 12), 5)
    cooldown_seconds = max(int(getattr(runtime_settings, "auto_tuning_cooldown_seconds", 900) or 900), 60)
    target_false_positive_rate = clamp(float(getattr(runtime_settings, "auto_tuning_target_false_positive_rate", 0.12) or 0.12), 0.0, 0.6)
    target_attack_rate = clamp(float(getattr(runtime_settings, "auto_tuning_target_attack_rate", 0.18) or 0.18), 0.01, 0.95)

    current_values = {
        "block_threshold": float(getattr(runtime_settings, "block_threshold", 0.72)),
        "monitor_threshold": float(getattr(runtime_settings, "monitor_threshold", 0.48)),
        "rate_limit_max_requests": int(getattr(runtime_settings, "rate_limit_max_requests", 30)),
        "token_bucket_capacity": int(getattr(runtime_settings, "token_bucket_capacity", 45)),
        "token_bucket_refill_rate": float(getattr(runtime_settings, "token_bucket_refill_rate", 0.75)),
    }
    recommended_values = dict(current_values)
    reasons: list[str] = []
    mode = "steady"
    confidence = "low"

    if total_requests < min_samples:
        mode = "insufficient_data"
        reasons.append(
            "Collected {0} live requests in the analysis window, but auto-tuning waits for at least {1} samples.".format(
                total_requests,
                min_samples,
            )
        )
    else:
        confidence = "medium" if total_requests < (min_samples * 3) else "high"
        false_positive_pressure = false_positive_rate - target_false_positive_rate
        attack_pressure = attack_rate - target_attack_rate

        if benign_labeled >= max(3, min_samples // 4) and false_positive_pressure > 0.03:
            mode = "relax"
            threshold_step = min(max(false_positive_pressure * 0.55, 0.02), 0.08)
            next_block = recommended_values["block_threshold"] + threshold_step
            next_monitor = recommended_values["monitor_threshold"] + (threshold_step * 0.8)
            next_monitor, next_block = _bounded_threshold_pair(next_monitor, next_block)
            recommended_values["block_threshold"] = next_block
            recommended_values["monitor_threshold"] = next_monitor
            recommended_values["rate_limit_max_requests"] = min(
                RATE_LIMIT_MAX,
                max(recommended_values["rate_limit_max_requests"] + 4, int(round(recommended_values["rate_limit_max_requests"] * 1.12))),
            )
            recommended_values["token_bucket_capacity"] = min(
                BUCKET_CAPACITY_MAX,
                max(recommended_values["token_bucket_capacity"] + 4, int(round(recommended_values["token_bucket_capacity"] * 1.1))),
            )
            recommended_values["token_bucket_refill_rate"] = _round_float(
                min(REFILL_MAX, recommended_values["token_bucket_refill_rate"] + 0.08),
                3,
            )
            reasons.append(
                "False positive rate reached {0:.1%}, above the target {1:.1%}, so thresholds and rate limits are relaxed.".format(
                    false_positive_rate,
                    target_false_positive_rate,
                )
            )
        elif attack_pressure > 0.03 or (block_rate + monitor_rate) > max(target_attack_rate, 0.2) or malicious_miss_rate > 0.1:
            mode = "harden"
            pressure = max(attack_pressure, (block_rate + monitor_rate) - max(target_attack_rate, 0.2), malicious_miss_rate)
            threshold_step = min(max(pressure * 0.35, 0.015), 0.07)
            next_block = recommended_values["block_threshold"] - threshold_step
            next_monitor = recommended_values["monitor_threshold"] - max(threshold_step * 0.85, 0.015)
            next_monitor, next_block = _bounded_threshold_pair(next_monitor, next_block)
            recommended_values["block_threshold"] = next_block
            recommended_values["monitor_threshold"] = next_monitor
            recommended_values["rate_limit_max_requests"] = max(
                RATE_LIMIT_MIN,
                min(recommended_values["rate_limit_max_requests"] - 3, int(round(recommended_values["rate_limit_max_requests"] * 0.9))),
            )
            recommended_values["token_bucket_capacity"] = max(
                BUCKET_CAPACITY_MIN,
                min(recommended_values["token_bucket_capacity"] - 4, int(round(recommended_values["token_bucket_capacity"] * 0.9))),
            )
            recommended_values["token_bucket_refill_rate"] = _round_float(
                max(REFILL_MIN, recommended_values["token_bucket_refill_rate"] - 0.08),
                3,
            )
            reasons.append(
                "Attack rate reached {0:.1%} with block rate {1:.1%}, so the gateway hardens thresholds and rate limits.".format(
                    attack_rate,
                    block_rate,
                )
            )
            if malicious_miss_rate > 0.0:
                reasons.append(
                    "Some requests labeled malicious were still allowed ({0:.1%} miss rate), so stricter blocking is recommended.".format(
                        malicious_miss_rate,
                    )
                )
        else:
            reasons.append(
                "False positives ({0:.1%}) and attack pressure ({1:.1%}) are within the current targets, so no tuning change is needed.".format(
                    false_positive_rate,
                    attack_rate,
                )
            )

    changed_fields = {}
    for key, current_value in current_values.items():
        suggested_value = recommended_values[key]
        if isinstance(current_value, float):
            if abs(float(suggested_value) - float(current_value)) >= 0.001:
                changed_fields[key] = _round_float(suggested_value, 3)
        else:
            if int(suggested_value) != int(current_value):
                changed_fields[key] = int(suggested_value)

    last_apply = latest_apply_event or {}
    last_apply_timestamp = str(last_apply.get("created_at") or "")
    cooldown_remaining_seconds = 0
    if last_apply.get("created_at_epoch"):
        elapsed = max(0.0, utc_now().timestamp() - float(last_apply.get("created_at_epoch") or 0.0))
        cooldown_remaining_seconds = max(0, int(cooldown_seconds - elapsed))

    can_apply = bool(changed_fields) and total_requests >= min_samples
    can_auto_apply = bool(getattr(runtime_settings, "auto_tuning_enabled", False)) and can_apply and cooldown_remaining_seconds <= 0

    summary_message = reasons[0] if reasons else "No auto-tuning recommendation is available."
    return {
        "generated_at": to_iso(),
        "enabled": bool(getattr(runtime_settings, "auto_tuning_enabled", False)),
        "mode": mode,
        "confidence": confidence,
        "can_apply": can_apply,
        "can_auto_apply": can_auto_apply,
        "cooldown_remaining_seconds": cooldown_remaining_seconds,
        "current": {
            **{key: _round_float(value, 3) if isinstance(value, float) else value for key, value in current_values.items()},
            "auto_tuning_enabled": bool(getattr(runtime_settings, "auto_tuning_enabled", False)),
        },
        "targets": {
            "window_seconds": int(getattr(runtime_settings, "auto_tuning_window_seconds", 3600) or 3600),
            "min_samples": min_samples,
            "cooldown_seconds": cooldown_seconds,
            "false_positive_rate": _round_float(target_false_positive_rate, 4),
            "attack_rate": _round_float(target_attack_rate, 4),
        },
        "telemetry": {
            "total_requests": total_requests,
            "blocked_requests": blocked,
            "monitored_requests": monitored,
            "allowed_requests": allowed,
            "labeled_requests": labeled_requests,
            "benign_labeled": benign_labeled,
            "malicious_labeled": malicious_labeled,
            "benign_false_positive_count": benign_false_positive_count,
            "malicious_allowed": malicious_allowed,
            "attack_marked_requests": attack_marked,
            "flagged_requests": flagged_requests,
            "false_positive_rate": _round_float(false_positive_rate, 4),
            "attack_rate": _round_float(attack_rate, 4),
            "block_rate": _round_float(block_rate, 4),
            "monitor_rate": _round_float(monitor_rate, 4),
            "malicious_miss_rate": _round_float(malicious_miss_rate, 4),
            "avg_risk_score": avg_risk_score,
        },
        "recommendation": {
            "summary": summary_message,
            "reasons": reasons,
            "changes": changed_fields,
            "recommended_settings": {
                key: changed_fields.get(key, (_round_float(value, 3) if isinstance(value, float) else value))
                for key, value in recommended_values.items()
            },
        },
        "last_auto_tune": {
            "created_at": last_apply_timestamp,
            "actor_username": str(last_apply.get("actor_username") or ""),
            "details": last_apply.get("details") or {},
        },
    }
