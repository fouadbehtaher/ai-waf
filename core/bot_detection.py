from __future__ import annotations

from typing import Dict, Mapping

from utils import clamp


SCRAPING_QUERY_TOKENS = ("q=", "query=", "search=", "page=", "offset=", "limit=", "cursor=", "sort=")
SEC_FETCH_HEADERS = ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")
CLIENT_HINT_HEADERS = ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")


def _lower_headers(headers: Mapping[str, object] | None) -> Dict[str, str]:
    lowered: Dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        lowered[str(key).strip().lower()] = str(value or "").strip()
    return lowered


def analyze_bot_signals(request_record, history_snapshot, endpoint_policy=None, settings=None) -> Dict[str, float]:
    endpoint_policy = dict(endpoint_policy or {})
    headers = _lower_headers(getattr(request_record, "headers", {}) or {})
    user_agent = str(getattr(request_record, "user_agent", "") or "").lower()
    path = str(getattr(request_record, "path", "") or "").lower()
    query = str(getattr(request_record, "query_string", "") or "").lower()
    referer = str(getattr(request_record, "referer", "") or "").strip()
    cookies_count = int(getattr(request_record, "cookies_count", 0) or 0)
    settings = settings

    if settings is not None and not bool(getattr(settings, "bot_detection_enabled", True)):
        return {
            "browser_claim_signal": 0.0,
            "automation_fingerprint_signal": 0.0,
            "headless_browser_signal": 0.0,
            "browser_integrity_signal": 0.0,
            "browser_integrity_gap_score": 0.0,
            "human_browser_signal": 0.0,
            "scraping_surface_signal": 0.0,
            "scraping_pattern_signal": 0.0,
            "bot_likelihood_score": 0.0,
        }

    browser_markers = tuple(getattr(settings, "browser_user_agent_markers", ()) or ())
    automation_markers = tuple(getattr(settings, "automation_fingerprint_tokens", ()) or ())
    headless_markers = tuple(getattr(settings, "headless_browser_tokens", ()) or ())
    scraping_tokens = tuple(getattr(settings, "scraping_path_tokens", ()) or ())
    integrity_gap_threshold = max(int(getattr(settings, "bot_browser_integrity_gap_threshold", 2) or 2), 1)
    scraping_request_threshold = max(int(getattr(settings, "bot_scraping_request_threshold", 6) or 6), 2)
    endpoint_policy_id = str(endpoint_policy.get("policy_id") or "").lower()

    header_text = " ".join(f"{key}:{value}".lower() for key, value in headers.items())
    browser_claimed = bool(user_agent) and any(token in user_agent for token in browser_markers)
    automation_user_agent = bool(user_agent) and any(token in user_agent for token in tuple(getattr(settings, "automation_user_agents", ()) or ()))
    automation_fingerprint = any(token in user_agent or token in header_text for token in automation_markers)
    headless_browser = any(token in user_agent or token in header_text for token in headless_markers)
    accept = headers.get("accept", "").lower()
    accept_language = headers.get("accept-language", "").lower()
    sec_fetch_present = any(name in headers for name in SEC_FETCH_HEADERS)
    client_hints_present = any(name in headers for name in CLIENT_HINT_HEADERS)
    browser_integrity_gaps = 0

    if browser_claimed:
        if not accept:
            browser_integrity_gaps += 1
        elif accept.strip() == "*/*":
            browser_integrity_gaps += 1
        if not accept_language:
            browser_integrity_gaps += 1
        if not sec_fetch_present:
            browser_integrity_gaps += 1
        if any(token in user_agent for token in ("chrome/", "edg/", "chromium")) and not client_hints_present:
            browser_integrity_gaps += 1
        if any(token in path for token in ("login", "admin")) and not (headers.get("origin") or referer):
            browser_integrity_gaps += 1

    browser_integrity_signal = float(browser_claimed and (headless_browser or browser_integrity_gaps >= integrity_gap_threshold))
    human_browser_signal = float(
        browser_claimed
        and not automation_user_agent
        and not automation_fingerprint
        and browser_integrity_gaps <= 1
        and bool(accept)
        and (bool(accept_language) or sec_fetch_present or client_hints_present or bool(referer) or cookies_count > 0)
    )

    scraping_surface_signal = float(
        any(token in path for token in scraping_tokens)
        or any(token in query for token in SCRAPING_QUERY_TOKENS)
        or endpoint_policy_id.startswith("builtin-search")
        or endpoint_policy_id.startswith("builtin-public-api")
    )

    ip_request_count = int(getattr(history_snapshot, "ip_request_count_window", 0) or 0)
    unique_paths = int(getattr(history_snapshot, "unique_paths_window", 0) or 0)
    fingerprint_reuse = int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0)
    path_hits = int(getattr(history_snapshot, "path_hits_window", 0) or 0)
    scraping_pattern_signal = float(
        scraping_surface_signal
        and (
            automation_user_agent
            or automation_fingerprint
            or headless_browser
            or browser_integrity_signal
            or ip_request_count >= scraping_request_threshold
            or unique_paths >= 4
            or fingerprint_reuse >= 2
            or path_hits >= 3
        )
    )

    raw_bot_score = 0.0
    if automation_user_agent:
        raw_bot_score += 0.25
    if automation_fingerprint:
        raw_bot_score += 0.70
    if headless_browser:
        raw_bot_score += 0.60
    if browser_integrity_signal:
        raw_bot_score += 0.45
    if scraping_surface_signal:
        raw_bot_score += 0.20
    if scraping_pattern_signal:
        raw_bot_score += 0.55
    if fingerprint_reuse >= 2:
        raw_bot_score += 0.25
    if unique_paths >= 4:
        raw_bot_score += 0.20
    if human_browser_signal and raw_bot_score < 1.0:
        raw_bot_score -= 0.35

    return {
        "browser_claim_signal": float(browser_claimed),
        "automation_fingerprint_signal": float(automation_fingerprint),
        "headless_browser_signal": float(headless_browser),
        "browser_integrity_signal": browser_integrity_signal,
        "browser_integrity_gap_score": round(clamp(browser_integrity_gaps / 4.0, 0.0, 1.5), 4),
        "human_browser_signal": human_browser_signal,
        "scraping_surface_signal": scraping_surface_signal,
        "scraping_pattern_signal": scraping_pattern_signal,
        "bot_likelihood_score": round(clamp(raw_bot_score, 0.0, 1.5), 4),
    }
