import re
from typing import Dict

from core.bot_detection import analyze_bot_signals


SQLI_PATTERN = re.compile(
    r"(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bor\s+1=1\b|\bsleep\s*\(|\bwaitfor\b)",
    re.IGNORECASE,
)
XSS_PATTERN = re.compile(r"(<script|javascript:|onerror=|onload=|alert\s*\()", re.IGNORECASE)
TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|/etc/passwd)", re.IGNORECASE)
COMMAND_INJECTION_PATTERN = re.compile(r"(\|\||&&|;cat\s|;ls\s|;bash\s|cmd=|/bin/sh|powershell)", re.IGNORECASE)
ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


def extract_features(request_record, history_snapshot, rate_limit_result, settings, endpoint_policy=None, connection_snapshot=None, transport_snapshot=None) -> Dict[str, float]:
    path_text = request_record.path or ""
    query_text = request_record.query_string or ""
    body_text = request_record.body_text or ""
    payload_text = " ".join(
        [
            path_text,
            query_text,
            body_text,
        ]
    ).lower()
    encoded_surface = (path_text + query_text).lower()
    encoded_matches = len(ENCODED_PATTERN.findall(encoded_surface))
    suspicious_hits = sum(1 for keyword in settings.suspicious_keywords if keyword in payload_text)
    body_length = request_record.body_length
    query_length = len(query_text)
    user_agent = (request_record.user_agent or "").lower()
    sql_injection_signal = float(bool(SQLI_PATTERN.search(payload_text)))
    xss_signal = float(bool(XSS_PATTERN.search(payload_text)))
    traversal_signal = float(bool(TRAVERSAL_PATTERN.search(payload_text)))
    command_injection_signal = float(bool(COMMAND_INJECTION_PATTERN.search(payload_text)))
    is_mutating = request_record.method in {"POST", "PUT", "PATCH", "DELETE"}
    has_json_body = "application/json" in (request_record.content_type or "").lower()
    has_form_body = "application/x-www-form-urlencoded" in (request_record.content_type or "").lower()
    automation_user_agent_signal = float(any(agent in user_agent for agent in settings.automation_user_agents))
    missing_user_agent_signal = float(not user_agent or user_agent == "unknown")
    login_path_signal = float(any(token in request_record.path.lower() for token in ("login", "signin", "auth")))
    admin_path_signal = float(any(token in request_record.path.lower() for token in ("admin", "config", "wp-admin")))
    bot_signals = analyze_bot_signals(
        request_record,
        history_snapshot,
        endpoint_policy=endpoint_policy,
        settings=settings,
    )
    browser_claim_signal = float(bot_signals.get("browser_claim_signal", 0.0) or 0.0)
    automation_fingerprint_signal = float(bot_signals.get("automation_fingerprint_signal", 0.0) or 0.0)
    headless_browser_signal = float(bot_signals.get("headless_browser_signal", 0.0) or 0.0)
    browser_integrity_signal = float(bot_signals.get("browser_integrity_signal", 0.0) or 0.0)
    browser_integrity_gap_score = float(bot_signals.get("browser_integrity_gap_score", 0.0) or 0.0)
    human_browser_signal = float(bot_signals.get("human_browser_signal", 0.0) or 0.0)
    scraping_surface_signal = float(bot_signals.get("scraping_surface_signal", 0.0) or 0.0)
    scraping_pattern_signal = float(bot_signals.get("scraping_pattern_signal", 0.0) or 0.0)
    bot_likelihood_score = float(bot_signals.get("bot_likelihood_score", 0.0) or 0.0)
    ip_request_rate_score = min(history_snapshot.ip_request_count_window / float(max(settings.rate_limit_max_requests, 1)), 2.0)
    session_request_rate_score = min(
        history_snapshot.session_request_count_window / float(max(settings.rate_limit_max_requests // 2, 1)),
        2.0,
    )
    encoded_character_ratio = round(encoded_matches / float(max(len(path_text) + len(query_text), 1)), 4)
    double_encoding_signal = float("%25" in encoded_surface or encoded_surface.count("%") >= 6)
    payload_evasion_signal = float(
        double_encoding_signal
        or encoded_character_ratio >= 0.18
        or (encoded_character_ratio >= 0.09 and suspicious_hits >= 1)
    )
    query_attack_signal = float(
        query_length >= 18
        and any(
            (
                sql_injection_signal,
                xss_signal,
                traversal_signal,
                command_injection_signal,
                payload_evasion_signal,
            )
        )
    )
    special_character_count = sum(payload_text.count(char) for char in ("'", "\"", "<", ">", ";", "%", "/", "\\", "(", ")", "|", "&"))
    special_character_score = round(min(special_character_count / 12.0, 1.5), 4)
    ddos_signal = float(
        (not rate_limit_result.allowed)
        or (
            history_snapshot.ip_request_count_window >= max(int(settings.rate_limit_max_requests * 0.8), 8)
            and rate_limit_result.pressure >= 0.85
        )
    )
    endpoint_policy_map = dict(endpoint_policy or {})
    endpoint_sensitivity = str(endpoint_policy_map.get("sensitivity", "standard") or "standard").strip().lower()
    protected_endpoint_signal = float(endpoint_sensitivity in {"protected", "critical"})
    critical_endpoint_signal = float(endpoint_sensitivity == "critical")
    endpoint_burst_score = min(
        (history_snapshot.path_hits_window + 1) / float(max(int(endpoint_policy_map.get("ddos_monitor_hits", 8) or 8), 1)),
        2.0,
    )
    connection_map = connection_snapshot.as_dict() if hasattr(connection_snapshot, "as_dict") else dict(connection_snapshot or {})
    active_connection_pressure = float(connection_map.get("active_pressure", 0.0) or 0.0)
    connection_per_ip_pressure = float(connection_map.get("connection_per_ip_pressure", 0.0) or 0.0)
    connection_burst_pressure = float(connection_map.get("burst_pressure", 0.0) or 0.0)
    new_connections_per_second_pressure = float(connection_map.get("new_connections_per_second_pressure", 0.0) or 0.0)
    stale_connection_pressure = float(connection_map.get("stale_pressure", 0.0) or 0.0)
    concurrent_sessions_pressure = float(connection_map.get("concurrent_sessions_pressure", 0.0) or 0.0)
    half_open_signal = float(bool(connection_map.get("stale_connections_ip", 0) or connection_map.get("stale_connections_endpoint", 0)))
    # Only count a hard Layer 4 signal in the hybrid score when the tracker reached
    # an actual block threshold. Monitor-only states already contribute via the
    # pressure features and should not double-push the score into a false block.
    layer4_connection_signal = float(bool(connection_map.get("block_triggered")))
    per_connection_throttle_signal = float(
        bool(
            connection_map.get("active_connections_ip", 0)
            and (
                connection_per_ip_pressure >= 1.0
                or new_connections_per_second_pressure >= 1.0
                or concurrent_sessions_pressure >= 1.0
            )
        )
    )
    transport_map = transport_snapshot.as_dict() if hasattr(transport_snapshot, "as_dict") else dict(transport_snapshot or {})
    transport_enabled = bool(transport_map.get("enabled", False))
    transport_enriched_signal = float(transport_enabled and bool(transport_map.get("proxy_enriched")))
    syn_like_flood_signal = float(transport_enabled and bool(transport_map.get("syn_like_flood_signal")))
    connection_reset_signal = float(transport_enabled and bool(transport_map.get("connection_reset_signal")))
    abnormal_session_establishment_signal = float(
        transport_enabled and bool(transport_map.get("abnormal_session_establishment_signal"))
    )
    udp_flood_signal = float(transport_enabled and bool(transport_map.get("udp_flood_signal")))
    connection_churn_signal = float(transport_enabled and bool(transport_map.get("connection_churn_signal")))
    short_lived_abusive_signal = float(transport_enabled and bool(transport_map.get("short_lived_abusive_signal")))
    retry_timeout_signal = float(transport_enabled and bool(transport_map.get("retry_timeout_signal")))
    malformed_transport_signal = float(transport_enabled and bool(transport_map.get("malformed_transport_signal")))
    brute_force_signal = float(
        bool(login_path_signal)
        and (
            history_snapshot.ip_request_count_window >= 5
            or history_snapshot.session_request_count_window >= 3
            or rate_limit_result.pressure >= 0.65
        )
    )
    automation_abuse_signal = float(
        (
            bool(automation_user_agent_signal)
            and (
                history_snapshot.ip_request_count_window >= 8
                or history_snapshot.unique_paths_window >= 4
                or bool(admin_path_signal)
            )
        )
        or bool(automation_fingerprint_signal)
        or bool(headless_browser_signal)
        or bool(scraping_pattern_signal)
        or (
            bool(browser_integrity_signal)
            and bool(
                admin_path_signal
                or headless_browser_signal
                or scraping_pattern_signal
                or (protected_endpoint_signal and automation_fingerprint_signal)
            )
        )
    )

    features = {
        "url_length": float(len(request_record.url or "")),
        "query_length": float(query_length),
        "query_length_score": min(query_length / 120.0, 1.5),
        "body_length": float(body_length),
        "body_length_score": min(body_length / float(max(settings.max_body_length, 1)), 1.5),
        "path_depth": float(len([segment for segment in (request_record.path or "/").split("/") if segment])),
        "header_count": float(len(request_record.headers)),
        "cookies_count": float(request_record.cookies_count),
        "method_is_mutating": float(is_mutating),
        "has_json_body": float(has_json_body),
        "has_form_body": float(has_form_body),
        "suspicious_keyword_hits": float(suspicious_hits),
        "sql_injection_signal": sql_injection_signal,
        "xss_signal": xss_signal,
        "traversal_signal": traversal_signal,
        "command_injection_signal": command_injection_signal,
        "ddos_signal": ddos_signal,
        "brute_force_signal": brute_force_signal,
        "automation_abuse_signal": automation_abuse_signal,
        "query_attack_signal": query_attack_signal,
        "payload_evasion_signal": payload_evasion_signal,
        "special_character_score": special_character_score,
        "encoded_character_ratio": encoded_character_ratio,
        "automation_user_agent_signal": automation_user_agent_signal,
        "browser_claim_signal": browser_claim_signal,
        "automation_fingerprint_signal": automation_fingerprint_signal,
        "headless_browser_signal": headless_browser_signal,
        "browser_integrity_signal": browser_integrity_signal,
        "browser_integrity_gap_score": browser_integrity_gap_score,
        "human_browser_signal": human_browser_signal,
        "scraping_surface_signal": scraping_surface_signal,
        "scraping_pattern_signal": scraping_pattern_signal,
        "bot_likelihood_score": bot_likelihood_score,
        "missing_user_agent_signal": missing_user_agent_signal,
        "login_path_signal": login_path_signal,
        "admin_path_signal": admin_path_signal,
        "protected_endpoint_signal": protected_endpoint_signal,
        "critical_endpoint_signal": critical_endpoint_signal,
        "endpoint_burst_score": endpoint_burst_score,
        "active_connection_pressure": active_connection_pressure,
        "connection_per_ip_pressure": connection_per_ip_pressure,
        "connection_burst_pressure": connection_burst_pressure,
        "new_connections_per_second_pressure": new_connections_per_second_pressure,
        "stale_connection_pressure": stale_connection_pressure,
        "concurrent_sessions_pressure": concurrent_sessions_pressure,
        "half_open_signal": half_open_signal,
        "layer4_connection_signal": layer4_connection_signal,
        "per_connection_throttle_signal": per_connection_throttle_signal,
        "transport_enriched_signal": transport_enriched_signal,
        "syn_like_flood_signal": syn_like_flood_signal,
        "connection_reset_signal": connection_reset_signal,
        "abnormal_session_establishment_signal": abnormal_session_establishment_signal,
        "udp_flood_signal": udp_flood_signal,
        "connection_churn_signal": connection_churn_signal,
        "short_lived_abusive_signal": short_lived_abusive_signal,
        "retry_timeout_signal": retry_timeout_signal,
        "malformed_transport_signal": malformed_transport_signal,
        "login_failure_signal": 0.0,
        "failed_login_attempts_window": 0.0,
        "ip_request_rate_score": ip_request_rate_score,
        "session_request_rate_score": session_request_rate_score,
        "ip_block_ratio": history_snapshot.ip_block_ratio,
        "fingerprint_reuse_score": min(history_snapshot.fingerprint_reuse_count / 5.0, 1.0),
        "path_novelty_score": float(history_snapshot.path_hits_window == 0),
        "unique_path_pressure": min(history_snapshot.unique_paths_window / 20.0, 1.0),
        "token_bucket_pressure": rate_limit_result.pressure,
    }
    return features


def create_features_dataframe(request_record, history_snapshot, rate_limit_result, settings, endpoint_policy=None, connection_snapshot=None, transport_snapshot=None) -> Dict[str, float]:
    return extract_features(
        request_record,
        history_snapshot,
        rate_limit_result,
        settings,
        endpoint_policy=endpoint_policy,
        connection_snapshot=connection_snapshot,
        transport_snapshot=transport_snapshot,
    )
