from __future__ import annotations

from typing import Dict, Mapping

from core.bot_detection import analyze_bot_signals
from utils import clamp, to_iso


PROFILE_ORDER = ("normal", "elevated", "suspicious", "restricted")
PROFILE_RANK = {name: index + 1 for index, name in enumerate(PROFILE_ORDER)}


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def _path_risk_tokens(request_record) -> Dict[str, bool]:
    path_text = str(getattr(request_record, "path", "") or "").lower()
    return {
        "login_path": any(token in path_text for token in ("login", "signin", "auth")),
        "admin_path": any(token in path_text for token in ("admin", "config", "wp-admin")),
    }


def _profile_thresholds(settings) -> Dict[str, float]:
    suspicious_threshold = max(float(getattr(settings, "adaptive_rate_limit_min_suspicion_score", 2) or 2), 1.0)
    elevated_threshold = max(0.75, suspicious_threshold - 0.75)
    restricted_threshold = max(suspicious_threshold + 2.0, 3.5)
    return {
        "elevated": _round_float(elevated_threshold, 3),
        "suspicious": _round_float(suspicious_threshold, 3),
        "restricted": _round_float(restricted_threshold, 3),
    }


def _profile_budget(requests_per_min: int) -> Dict[str, object]:
    safe_requests = max(int(requests_per_min or 1), 1)
    return {
        "requests_per_min": safe_requests,
        "capacity": safe_requests,
        "refill_rate": _round_float(safe_requests / 60.0, 4),
    }


def _policy_map(settings) -> Dict[str, Dict[str, object]]:
    return {
        "normal": {
            "profile": "normal",
            **_profile_budget(getattr(settings, "adaptive_rate_limit_normal_requests_per_min", 60)),
        },
        "elevated": {
            "profile": "elevated",
            **_profile_budget(getattr(settings, "adaptive_rate_limit_elevated_requests_per_min", 30)),
        },
        "suspicious": {
            "profile": "suspicious",
            **_profile_budget(getattr(settings, "adaptive_rate_limit_suspicious_requests_per_min", 10)),
        },
        "restricted": {
            "profile": "restricted",
            **_profile_budget(getattr(settings, "adaptive_rate_limit_restricted_requests_per_min", 3)),
        },
    }


def _profile_for_score(risk_score: float, thresholds: Mapping[str, float]) -> str:
    if risk_score >= float(thresholds.get("restricted", 3.5) or 3.5):
        return "restricted"
    if risk_score >= float(thresholds.get("suspicious", 2.0) or 2.0):
        return "suspicious"
    if risk_score >= float(thresholds.get("elevated", 1.25) or 1.25):
        return "elevated"
    return "normal"


def _risk_band_for_score(risk_score: float, thresholds: Mapping[str, float]) -> str:
    if risk_score >= float(thresholds.get("restricted", 3.5) or 3.5):
        return "critical"
    if risk_score >= float(thresholds.get("suspicious", 2.0) or 2.0):
        return "high"
    if risk_score >= float(thresholds.get("elevated", 1.25) or 1.25):
        return "medium"
    return "low"


def _score_risk_signals(metrics: Mapping[str, object], settings) -> Dict[str, object]:
    suspicious_request_threshold = max(
        int(getattr(settings, "adaptive_rate_limit_suspicious_request_threshold", 8) or 8),
        1,
    )
    unique_paths_threshold = max(int(getattr(settings, "adaptive_rate_limit_unique_paths_threshold", 4) or 4), 1)
    block_ratio_threshold = clamp(
        float(getattr(settings, "adaptive_rate_limit_block_ratio_threshold", 0.25) or 0.25),
        0.05,
        1.0,
    )
    flagged_ratio_threshold = clamp(
        float(getattr(settings, "adaptive_rate_limit_flagged_ratio_threshold", 0.35) or 0.35),
        0.05,
        1.0,
    )
    avg_risk_threshold = clamp(
        float(getattr(settings, "adaptive_rate_limit_avg_risk_threshold", 0.55) or 0.55),
        0.05,
        1.0,
    )
    block_threshold = clamp(float(getattr(settings, "block_threshold", 0.72) or 0.72), 0.05, 1.0)

    total_requests = int(metrics.get("ip_request_count_window", metrics.get("total_requests", 0)) or 0)
    session_requests = int(metrics.get("session_request_count_window", metrics.get("session_requests", 0)) or 0)
    unique_paths = int(metrics.get("unique_paths_window", metrics.get("unique_paths", 0)) or 0)
    block_ratio = float(metrics.get("ip_block_ratio", metrics.get("block_ratio", 0.0)) or 0.0)
    flagged_ratio = float(metrics.get("ip_flagged_ratio", metrics.get("flagged_ratio", 0.0)) or 0.0)
    avg_risk_score = float(metrics.get("ip_avg_risk_score_window", metrics.get("avg_risk_score", 0.0)) or 0.0)
    max_risk_score = float(metrics.get("ip_max_risk_score_window", metrics.get("max_risk_score", 0.0)) or 0.0)
    fingerprint_reuse_count = int(metrics.get("fingerprint_reuse_count", 0) or 0)
    path_hits_window = int(metrics.get("path_hits_window", 0) or 0)
    automation_signal = bool(metrics.get("automation_signal", False))
    automation_fingerprint_signal = bool(metrics.get("automation_fingerprint_signal", False))
    headless_browser_signal = bool(metrics.get("headless_browser_signal", False))
    browser_integrity_signal = bool(metrics.get("browser_integrity_signal", False))
    scraping_surface_signal = bool(metrics.get("scraping_surface_signal", False))
    scraping_pattern_signal = bool(metrics.get("scraping_pattern_signal", False))
    human_browser_signal = bool(metrics.get("human_browser_signal", False))
    login_path = bool(metrics.get("login_path", False))
    admin_path = bool(metrics.get("admin_path", False))

    risk_score = 0.0
    reasons: list[str] = []

    if automation_signal:
        risk_score += 0.75
        reasons.append("Automation or scanner user-agent detected.")
    if automation_fingerprint_signal and not automation_signal:
        risk_score += 0.85
        reasons.append("Automation fingerprints suggest scripted tooling or browser automation.")
    if headless_browser_signal:
        risk_score += 0.9
        reasons.append("Headless browser fingerprints indicate likely bot-driven interaction.")
    if browser_integrity_signal:
        risk_score += 0.65
        reasons.append("Browser integrity checks failed, so the client does not look like a normal interactive browser.")
    if login_path:
        risk_score += 0.75
        reasons.append("Authentication endpoints are receiving traffic and need tighter throttling.")
    if admin_path:
        risk_score += 0.85
        reasons.append("Administrative paths are being accessed and attract reconnaissance or abuse.")
    if scraping_surface_signal:
        risk_score += 0.3
        reasons.append("The request targets a scraping-prone surface such as search, export, or public API content.")
    if scraping_pattern_signal:
        risk_score += 1.1
        reasons.append("Live behavior resembles scraping or automated collection rather than normal browsing.")
    if total_requests >= suspicious_request_threshold:
        risk_score += 1.5
        reasons.append(
            "Recent request volume from this IP reached {0}, which exceeds the adaptive request threshold.".format(
                total_requests,
            )
        )
    if session_requests >= max(3, suspicious_request_threshold // 2):
        risk_score += 0.75
        reasons.append("The same session is generating repeated requests inside the analytics window.")
    if unique_paths >= unique_paths_threshold:
        risk_score += 1.25
        reasons.append(
            "This IP touched {0} distinct paths, which resembles probing or scanning.".format(unique_paths)
        )
    if total_requests >= 3 and block_ratio >= block_ratio_threshold:
        risk_score += 2.25
        reasons.append(
            "The recent block ratio for this IP is {0:.1%}, which is above the configured offense threshold.".format(
                block_ratio,
            )
        )
    if total_requests >= 3 and flagged_ratio >= flagged_ratio_threshold:
        risk_score += 1.5
        reasons.append(
            "The combined block and monitor ratio reached {0:.1%}, so this source already looks risky.".format(
                flagged_ratio,
            )
        )
    if total_requests >= 2 and avg_risk_score >= avg_risk_threshold:
        risk_score += 1.25
        reasons.append(
            "The rolling average hybrid risk score for this IP is {0:.3f}, above the adaptive risk threshold.".format(
                avg_risk_score,
            )
        )
    if max_risk_score >= block_threshold:
        risk_score += 1.5
        reasons.append(
            "At least one recent request from this IP already crossed the blocking risk threshold ({0:.3f}).".format(
                block_threshold,
            )
        )
    if fingerprint_reuse_count >= 3:
        risk_score += 0.5
        reasons.append("The same request fingerprint is being replayed repeatedly.")
    if login_path and path_hits_window >= 3:
        risk_score += 0.75
        reasons.append("Repeated authentication attempts on the same path increase brute-force pressure.")
    if admin_path and unique_paths >= max(2, unique_paths_threshold // 2):
        risk_score += 0.5
        reasons.append("Administrative probing is spreading across multiple paths.")
    if human_browser_signal and not headless_browser_signal and not scraping_pattern_signal and risk_score > 0.0:
        risk_score = max(risk_score - 0.35, 0.0)
        reasons.append("Browser integrity looks consistent with an interactive user, so bot pressure is reduced slightly.")

    return {
        "risk_score": _round_float(risk_score, 3),
        "reasons": reasons,
        "signal_thresholds": {
            "request_threshold": suspicious_request_threshold,
            "unique_paths_threshold": unique_paths_threshold,
            "block_ratio_threshold": _round_float(block_ratio_threshold, 3),
            "flagged_ratio_threshold": _round_float(flagged_ratio_threshold, 3),
            "avg_risk_threshold": _round_float(avg_risk_threshold, 3),
        },
    }


def _telemetry_metrics(row: Mapping[str, object]) -> Dict[str, object]:
    total_requests = int(row.get("total_requests", 0) or 0)
    blocked_requests = int(row.get("blocked_requests", 0) or 0)
    monitored_requests = int(row.get("monitored_requests", 0) or 0)
    flagged_requests = int(row.get("flagged_requests", blocked_requests + monitored_requests) or 0)
    block_ratio = float(row.get("block_ratio", 0.0) or 0.0)
    flagged_ratio = float(row.get("flagged_ratio", 0.0) or 0.0)
    if total_requests > 0:
        if not block_ratio:
            block_ratio = blocked_requests / float(total_requests)
        if not flagged_ratio:
            flagged_ratio = flagged_requests / float(total_requests)
    return {
        "total_requests": total_requests,
        "unique_paths": int(row.get("unique_paths", 0) or 0),
        "blocked_requests": blocked_requests,
        "monitored_requests": monitored_requests,
        "flagged_requests": flagged_requests,
        "block_ratio": _round_float(block_ratio, 4),
        "flagged_ratio": _round_float(flagged_ratio, 4),
        "avg_risk_score": float(row.get("avg_risk_score", 0.0) or 0.0),
        "max_risk_score": float(row.get("max_risk_score", 0.0) or 0.0),
    }


def resolve_rate_limit_profile(request_record, history_snapshot, settings) -> Dict[str, object]:
    enabled = bool(getattr(settings, "adaptive_rate_limiting_enabled", False))
    thresholds = _profile_thresholds(settings)
    policies = _policy_map(settings)

    if not enabled:
        requests_per_min = max(int(round(float(getattr(settings, "token_bucket_refill_rate", 0.75) or 0.75) * 60.0)), 1)
        return {
            "enabled": False,
            "profile": "static",
            "profile_rank": 0,
            "requests_per_min": requests_per_min,
            "capacity": float(getattr(settings, "token_bucket_capacity", requests_per_min) or requests_per_min),
            "refill_rate": float(getattr(settings, "token_bucket_refill_rate", requests_per_min / 60.0) or (requests_per_min / 60.0)),
            "suspicion_score": 0,
            "risk_score": 0.0,
            "risk_band": "low",
            "reasons": ["Adaptive rate limiting is disabled, so the default token bucket remains active."],
            "thresholds": thresholds,
        }

    path_signals = _path_risk_tokens(request_record)
    user_agent = str(getattr(request_record, "user_agent", "") or "").lower()
    automation_signal = any(agent in user_agent for agent in getattr(settings, "automation_user_agents", ()))
    bot_signals = analyze_bot_signals(request_record, history_snapshot, settings=settings)

    score_payload = _score_risk_signals(
        {
            "ip_request_count_window": getattr(history_snapshot, "ip_request_count_window", 0),
            "session_request_count_window": getattr(history_snapshot, "session_request_count_window", 0),
            "unique_paths_window": getattr(history_snapshot, "unique_paths_window", 0),
            "ip_block_ratio": getattr(history_snapshot, "ip_block_ratio", 0.0),
            "ip_flagged_ratio": getattr(history_snapshot, "ip_flagged_ratio", 0.0),
            "ip_avg_risk_score_window": getattr(history_snapshot, "ip_avg_risk_score_window", 0.0),
            "ip_max_risk_score_window": getattr(history_snapshot, "ip_max_risk_score_window", 0.0),
            "fingerprint_reuse_count": getattr(history_snapshot, "fingerprint_reuse_count", 0),
            "path_hits_window": getattr(history_snapshot, "path_hits_window", 0),
            "automation_signal": automation_signal,
            "automation_fingerprint_signal": bool(bot_signals.get("automation_fingerprint_signal", 0.0)),
            "headless_browser_signal": bool(bot_signals.get("headless_browser_signal", 0.0)),
            "browser_integrity_signal": bool(bot_signals.get("browser_integrity_signal", 0.0)),
            "scraping_surface_signal": bool(bot_signals.get("scraping_surface_signal", 0.0)),
            "scraping_pattern_signal": bool(bot_signals.get("scraping_pattern_signal", 0.0)),
            "human_browser_signal": bool(bot_signals.get("human_browser_signal", 0.0)),
            "login_path": path_signals["login_path"],
            "admin_path": path_signals["admin_path"],
        },
        settings,
    )

    risk_score = float(score_payload["risk_score"] or 0.0)
    profile = _profile_for_score(risk_score, thresholds)
    risk_band = _risk_band_for_score(risk_score, thresholds)
    selected_policy = policies[profile]
    reasons = list(score_payload["reasons"])
    if not reasons:
        reasons.append("Recent traffic from this IP looks normal, so the gateway keeps the standard request budget.")

    return {
        "enabled": True,
        "profile": profile,
        "profile_rank": PROFILE_RANK[profile],
        "requests_per_min": int(selected_policy["requests_per_min"]),
        "capacity": float(selected_policy["capacity"]),
        "refill_rate": float(selected_policy["refill_rate"]),
        "suspicion_score": int(round(risk_score)),
        "risk_score": _round_float(risk_score, 3),
        "risk_band": risk_band,
        "reasons": reasons,
        "thresholds": thresholds,
        "signal_thresholds": score_payload["signal_thresholds"],
        "profiles": policies,
    }


def analyze_adaptive_rate_limit(runtime_settings, telemetry: Dict[str, object]) -> Dict[str, object]:
    enabled = bool(getattr(runtime_settings, "adaptive_rate_limiting_enabled", False))
    window_seconds = max(int(getattr(runtime_settings, "adaptive_rate_limit_window_seconds", 900) or 900), 60)
    thresholds = _profile_thresholds(runtime_settings)
    policies = _policy_map(runtime_settings)
    ip_rows = list(telemetry.get("ip_rows") or [])

    profile_counts = {profile: 0 for profile in PROFILE_ORDER}
    risk_band_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    restricted_candidate_ips = 0
    scored_rows = []
    for row in ip_rows:
        metrics = _telemetry_metrics(row)
        score_payload = _score_risk_signals(metrics, runtime_settings)
        risk_score = float(score_payload["risk_score"] or 0.0)
        profile = _profile_for_score(risk_score, thresholds)
        risk_band = _risk_band_for_score(risk_score, thresholds)
        profile_counts[profile] += 1
        risk_band_counts[risk_band] += 1
        if profile == "restricted":
            restricted_candidate_ips += 1
        scored_rows.append(
            {
                "remote_addr": row.get("remote_addr", ""),
                "profile": profile,
                "risk_band": risk_band,
                "risk_score": _round_float(risk_score, 3),
                "total_requests": metrics["total_requests"],
                "block_ratio": _round_float(metrics["block_ratio"], 4),
                "flagged_ratio": _round_float(metrics["flagged_ratio"], 4),
                "avg_risk_score": _round_float(metrics["avg_risk_score"], 4),
                "max_risk_score": _round_float(metrics["max_risk_score"], 4),
                "reasons": score_payload["reasons"][:3],
            }
        )

    summary = (
        "Risk-based adaptive throttling is active: normal IPs keep {0} req/min, elevated IPs get {1}, suspicious IPs get {2}, and restricted offenders drop to {3}.".format(
            policies["normal"]["requests_per_min"],
            policies["elevated"]["requests_per_min"],
            policies["suspicious"]["requests_per_min"],
            policies["restricted"]["requests_per_min"],
        )
        if enabled
        else "Adaptive rate limiting is disabled, so the gateway is using the shared default token bucket for every IP."
    )

    reasons = [
        "Risk-based throttling blends request volume, unique-path probing, recent block ratio, recent flagged ratio, and recent hybrid risk scores.",
        "Profile escalation follows four bands: normal, elevated, suspicious, then restricted.",
    ]
    if enabled:
        reasons.append(
            "IPs crossing {0:.2f} move into elevated throttling, {1:.2f} into suspicious throttling, and {2:.2f} into restricted throttling.".format(
                thresholds["elevated"],
                thresholds["suspicious"],
                thresholds["restricted"],
            )
        )

    return {
        "generated_at": to_iso(),
        "enabled": enabled,
        "live_only": True,
        "summary": summary,
        "policy": policies,
        "classifier": {
            "min_suspicion_score": max(int(getattr(runtime_settings, "adaptive_rate_limit_min_suspicion_score", 2) or 2), 1),
            "suspicious_request_threshold": max(int(getattr(runtime_settings, "adaptive_rate_limit_suspicious_request_threshold", 8) or 8), 1),
            "unique_paths_threshold": max(int(getattr(runtime_settings, "adaptive_rate_limit_unique_paths_threshold", 4) or 4), 1),
            "block_ratio_threshold": _round_float(float(getattr(runtime_settings, "adaptive_rate_limit_block_ratio_threshold", 0.25) or 0.25), 3),
            "flagged_ratio_threshold": _round_float(float(getattr(runtime_settings, "adaptive_rate_limit_flagged_ratio_threshold", 0.35) or 0.35), 3),
            "avg_risk_threshold": _round_float(float(getattr(runtime_settings, "adaptive_rate_limit_avg_risk_threshold", 0.55) or 0.55), 3),
            "window_seconds": window_seconds,
            "risk_thresholds": thresholds,
        },
        "telemetry": {
            "distinct_ips": int(telemetry.get("distinct_ips") or 0),
            "total_requests": int(telemetry.get("total_requests") or 0),
            "avg_requests_per_ip": _round_float(float(telemetry.get("avg_requests_per_ip") or 0.0), 3),
            "max_requests_per_ip": int(telemetry.get("max_requests_per_ip") or 0),
            "high_volume_ips": int(telemetry.get("high_volume_ips") or 0),
            "recon_like_ips": int(telemetry.get("recon_like_ips") or 0),
            "offender_ips": int(telemetry.get("offender_ips") or 0),
            "flagged_ips": int(telemetry.get("flagged_ips") or 0),
            "high_risk_ips": int(telemetry.get("high_risk_ips") or 0),
            "suspicious_candidate_ips": int(telemetry.get("suspicious_candidate_ips") or 0),
            "restricted_candidate_ips": int(restricted_candidate_ips),
            "profile_counts": profile_counts,
            "risk_band_counts": risk_band_counts,
            "top_risky_ips": scored_rows[:5],
        },
        "reasons": reasons,
    }
