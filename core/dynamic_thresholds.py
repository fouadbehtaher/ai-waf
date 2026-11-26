from __future__ import annotations

from typing import Dict, Mapping

from utils import clamp, to_iso


THRESHOLD_MIN = 0.20
THRESHOLD_MAX = 0.95
THRESHOLD_GAP = 0.08


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def analyze_dynamic_thresholds(runtime_settings, telemetry: Dict[str, object], endpoint_policy: Mapping[str, object] | None = None) -> Dict[str, object]:
    total_requests = int(telemetry.get("total_requests") or 0)
    avg_risk_score = float(telemetry.get("avg_risk_score") or 0.0)
    stddev_risk_score = float(telemetry.get("stddev_risk_score") or 0.0)
    blocked_requests = int(telemetry.get("blocked_requests") or 0)
    monitored_requests = int(telemetry.get("monitored_requests") or 0)
    allowed_requests = int(telemetry.get("allowed_requests") or 0)
    min_risk_score = float(telemetry.get("min_risk_score") or 0.0)
    max_risk_score = float(telemetry.get("max_risk_score") or 0.0)
    benign_labeled = int(telemetry.get("benign_labeled") or 0)
    benign_false_positive_count = int(telemetry.get("benign_false_positive_count") or 0)
    false_positive_rate = float(telemetry.get("false_positive_rate") or 0.0)
    flagged_ratio = float(telemetry.get("flagged_ratio") or 0.0)
    requests_per_minute = float(telemetry.get("requests_per_minute") or 0.0)
    request_rate_per_second = float(telemetry.get("request_rate_per_second") or 0.0)
    endpoint_policy = dict(endpoint_policy or {})

    static_block_threshold = float(endpoint_policy.get("block_threshold", getattr(runtime_settings, "block_threshold", 0.72)) or getattr(runtime_settings, "block_threshold", 0.72))
    static_monitor_threshold = float(endpoint_policy.get("monitor_threshold", getattr(runtime_settings, "monitor_threshold", 0.48)) or getattr(runtime_settings, "monitor_threshold", 0.48))
    enabled = bool(getattr(runtime_settings, "dynamic_thresholds_enabled", False))
    window_seconds = max(int(getattr(runtime_settings, "dynamic_thresholds_window_seconds", 1800) or 1800), 60)
    min_samples = max(int(getattr(runtime_settings, "dynamic_thresholds_min_samples", 20) or 20), 5)
    std_multiplier = clamp(float(getattr(runtime_settings, "dynamic_thresholds_std_multiplier", 1.0) or 1.0), 0.1, 4.0)
    target_false_positive_rate = clamp(float(getattr(runtime_settings, "auto_tuning_target_false_positive_rate", 0.12) or 0.12), 0.0, 0.6)
    configured_floor = clamp(
        float(getattr(runtime_settings, "dynamic_thresholds_min_block_threshold", 0.32) or 0.32),
        THRESHOLD_MIN + THRESHOLD_GAP,
        THRESHOLD_MAX,
    )
    configured_ceiling = clamp(
        float(getattr(runtime_settings, "dynamic_thresholds_max_block_threshold", 0.92) or 0.92),
        configured_floor,
        THRESHOLD_MAX,
    )

    sensitivity = str(endpoint_policy.get("sensitivity") or telemetry.get("endpoint_sensitivity") or "standard").strip().lower()
    endpoint_scope = str(telemetry.get("scope") or ("endpoint" if endpoint_policy else "global"))
    target_requests_per_min = int(telemetry.get("target_requests_per_min") or endpoint_policy.get("requests_per_min") or getattr(runtime_settings, "rate_limit_max_requests", 30) or 30)
    load_ratio = requests_per_minute / float(max(target_requests_per_min, 1)) if target_requests_per_min else 0.0
    sensitivity_adjustment = 0.0
    if sensitivity == "critical":
        sensitivity_adjustment = -0.05
    elif sensitivity == "protected":
        sensitivity_adjustment = -0.025

    load_adjustment = 0.0
    if load_ratio > 0.0:
        load_adjustment -= min(max(load_ratio - 0.85, 0.0) * 0.06, 0.08)
    if flagged_ratio > 0.22:
        load_adjustment -= min((flagged_ratio - 0.22) * 0.12, 0.06)

    false_positive_relief = 0.0
    if benign_labeled and false_positive_rate > target_false_positive_rate:
        false_positive_relief = min((false_positive_rate - target_false_positive_rate) * 0.35, 0.08)

    raw_block_threshold = avg_risk_score + (stddev_risk_score * std_multiplier)
    adjusted_block_threshold = raw_block_threshold + sensitivity_adjustment + load_adjustment + false_positive_relief
    clamped_block_threshold = clamp(adjusted_block_threshold, configured_floor, configured_ceiling)
    effective_block_threshold = static_block_threshold
    effective_monitor_threshold = static_monitor_threshold
    monitor_was_clamped = False
    mode = "static"
    summary = "Dynamic thresholds are disabled, so the WAF continues using the configured static thresholds."
    reasons: list[str] = []

    if total_requests < min_samples:
        mode = "insufficient_data"
        summary = (
            "Dynamic thresholds need at least {0} live requests in the analysis window, but only {1} are available.".format(
                min_samples,
                total_requests,
            )
        )
        reasons.append(summary)
    elif enabled:
        mode = "dynamic"
        effective_block_threshold = float(clamped_block_threshold)
        effective_monitor_threshold = min(static_monitor_threshold, max(THRESHOLD_MIN, effective_block_threshold - THRESHOLD_GAP))
        monitor_was_clamped = effective_monitor_threshold < static_monitor_threshold
        summary = (
            "Blocking adapts to the {0} traffic window using avg_score + ({1:.2f} x std_dev), which currently yields {2:.3f}.".format(
                "matched endpoint" if endpoint_scope == "endpoint" else "global",
                std_multiplier,
                effective_block_threshold,
            )
        )
        reasons.append(
            "The active blocking threshold follows the recent live-score distribution for this {0} instead of the fixed value {1:.3f}.".format(
                "endpoint" if endpoint_scope == "endpoint" else "gateway",
                static_block_threshold,
            )
        )
        if sensitivity_adjustment < 0.0:
            reasons.append(
                "Endpoint sensitivity is {0}, so the dynamic threshold is tightened by {1:.3f}.".format(
                    sensitivity,
                    abs(sensitivity_adjustment),
                )
            )
        if load_adjustment < 0.0:
            reasons.append(
                "Current request pressure is {0:.1f} req/min with flagged ratio {1:.1%}, so the threshold hardens under live load.".format(
                    requests_per_minute,
                    flagged_ratio,
                )
            )
        if false_positive_relief > 0.0:
            reasons.append(
                "Reviewed benign traffic shows a false-positive rate of {0:.1%}, so the threshold is relaxed by {1:.3f} to reduce false positives.".format(
                    false_positive_rate,
                    false_positive_relief,
                )
            )
        if monitor_was_clamped:
            reasons.append(
                "The monitoring threshold was temporarily clamped to {0:.3f} so it stays below the dynamic blocking threshold.".format(
                    effective_monitor_threshold,
                )
            )
        if adjusted_block_threshold != clamped_block_threshold:
            reasons.append(
                "The adjusted dynamic threshold {0:.3f} was bounded to the safety range [{1:.3f}, {2:.3f}].".format(
                    adjusted_block_threshold,
                    configured_floor,
                    configured_ceiling,
                )
            )
    else:
        reasons.append(
            "Live traffic statistics are ready. Turn on Dynamic Thresholds in Runtime settings if you want the gateway to follow recent traffic automatically."
        )

    return {
        "generated_at": to_iso(),
        "enabled": enabled,
        "active": bool(enabled and total_requests >= min_samples),
        "mode": mode,
        "summary": summary,
        "live_only": True,
        "formula": {
            "label": "avg_score + std_dev",
            "expression": "avg_score + ({0:.2f} x std_dev)".format(std_multiplier),
            "std_multiplier": _round_float(std_multiplier, 3),
            "base_raw_block_threshold": _round_float(raw_block_threshold, 4),
            "sensitivity_adjustment": _round_float(sensitivity_adjustment, 4),
            "load_adjustment": _round_float(load_adjustment, 4),
            "false_positive_relief": _round_float(false_positive_relief, 4),
        },
        "targets": {
            "window_seconds": window_seconds,
            "min_samples": min_samples,
            "min_block_threshold": _round_float(configured_floor, 3),
            "max_block_threshold": _round_float(configured_ceiling, 3),
            "target_false_positive_rate": _round_float(target_false_positive_rate, 4),
            "target_requests_per_min": target_requests_per_min,
        },
        "telemetry": {
            "scope": endpoint_scope,
            "matched_path": str(telemetry.get("matched_path") or endpoint_policy.get("matched_path") or ""),
            "endpoint_policy_id": str(telemetry.get("endpoint_policy_id") or endpoint_policy.get("policy_id") or ""),
            "endpoint_policy_name": str(telemetry.get("endpoint_policy_name") or endpoint_policy.get("name") or ""),
            "endpoint_sensitivity": sensitivity,
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "monitored_requests": monitored_requests,
            "allowed_requests": allowed_requests,
            "benign_labeled": benign_labeled,
            "benign_false_positive_count": benign_false_positive_count,
            "false_positive_rate": _round_float(false_positive_rate, 4),
            "flagged_ratio": _round_float(flagged_ratio, 4),
            "request_rate_per_second": _round_float(request_rate_per_second, 4),
            "requests_per_minute": _round_float(requests_per_minute, 2),
            "load_ratio": _round_float(load_ratio, 4),
            "avg_risk_score": _round_float(avg_risk_score, 4),
            "stddev_risk_score": _round_float(stddev_risk_score, 4),
            "min_risk_score": _round_float(min_risk_score, 4),
            "max_risk_score": _round_float(max_risk_score, 4),
        },
        "current": {
            "block_threshold": _round_float(static_block_threshold, 3),
            "monitor_threshold": _round_float(static_monitor_threshold, 3),
        },
        "computed": {
            "raw_block_threshold": _round_float(raw_block_threshold, 4),
            "adjusted_block_threshold": _round_float(adjusted_block_threshold, 4),
            "clamped_block_threshold": _round_float(clamped_block_threshold, 4),
        },
        "effective": {
            "block_threshold": _round_float(effective_block_threshold, 4),
            "monitor_threshold": _round_float(effective_monitor_threshold, 4),
            "monitor_threshold_clamped": monitor_was_clamped,
            "source": (
                "dynamic_endpoint" if enabled and total_requests >= min_samples and endpoint_scope == "endpoint"
                else "dynamic_global" if enabled and total_requests >= min_samples
                else "static"
            ),
        },
        "reasons": reasons,
    }
