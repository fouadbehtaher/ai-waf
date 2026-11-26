from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from utils import clamp


TRANSPORT_PROTOCOL_HEADERS = (
    "X-WAF-Transport-Protocol",
    "X-Transport-Protocol",
)
FORWARDED_PROTOCOL_HEADERS = ("X-Forwarded-Proto",)
TCP_FLAG_HEADERS = (
    "X-WAF-TCP-Flags",
    "X-TCP-Flags",
)
RESET_HEADERS = (
    "X-WAF-Connection-Reset",
    "X-Connection-Reset",
    "X-Upstream-Reset",
)
SESSION_ESTABLISHED_HEADERS = (
    "X-WAF-Session-Established",
    "X-Session-Established",
)
CONNECTION_DURATION_HEADERS = (
    "X-WAF-Connection-Duration-Ms",
    "X-Connection-Duration-Ms",
    "X-Upstream-Connection-Duration-Ms",
)
RETRY_COUNT_HEADERS = (
    "X-WAF-Retry-Count",
    "X-Retry-Count",
    "X-Upstream-Retry-Count",
)
TIMEOUT_HEADERS = (
    "X-WAF-Upstream-Timeout",
    "X-Upstream-Timeout",
    "X-WAF-Request-Timeout",
    "X-Request-Timeout",
)
TRANSPORT_VALID_HEADERS = (
    "X-WAF-Transport-Valid",
    "X-Transport-Valid",
)
MALFORMED_TRANSPORT_HEADERS = (
    "X-WAF-Malformed-Transport",
    "X-Malformed-Transport",
)


def _header(headers: Dict[str, str], names: tuple[str, ...]) -> str:
    lowered_headers = {str(key).strip().lower(): str(value) for key, value in (headers or {}).items()}
    for name in names:
        value = str(lowered_headers.get(str(name).strip().lower(), "") or "").strip()
        if value:
            return value
    return ""


def _presence_bool_header(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return False
    if normalized in {"0", "false", "no", "off", "n"}:
        return False
    return True


def _tri_bool_header(value: str) -> tuple[Optional[bool], bool]:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None, False
    if normalized in {"1", "true", "yes", "on", "y"}:
        return True, False
    if normalized in {"0", "false", "no", "off", "n"}:
        return False, False
    return None, True


def _parse_int_header(raw_value: str, minimum: int = 0) -> tuple[Optional[int], bool]:
    normalized = str(raw_value or "").strip()
    if not normalized:
        return None, False
    try:
        parsed = int(float(normalized))
    except (TypeError, ValueError):
        return None, True
    if parsed < int(minimum):
        return None, True
    return parsed, False


def _parse_timeout_header(raw_value: str) -> tuple[bool, bool]:
    normalized = str(raw_value or "").strip().lower()
    if not normalized:
        return False, False
    if normalized in {"1", "true", "yes", "on", "y", "timeout", "timedout", "timed_out", "deadline"}:
        return True, False
    if normalized in {"0", "false", "no", "off", "n"}:
        return False, False
    parsed_number, malformed = _parse_int_header(normalized, minimum=0)
    if not malformed and parsed_number is not None:
        return parsed_number > 0, False
    if "timeout" in normalized or "deadline" in normalized:
        return True, False
    return False, True


def _parse_tcp_flags(raw_value: str) -> list[str]:
    separators = str(raw_value or "").replace(",", " ").replace("|", " ").split()
    flags = []
    for item in separators:
        normalized = item.strip().upper()
        if normalized and normalized not in flags:
            flags.append(normalized)
    return flags


def _normalize_transport_protocol(raw_value: str) -> str:
    normalized = str(raw_value or "").strip().lower()
    if not normalized:
        return "tcp"
    if any(token in normalized for token in ("udp", "quic", "http3", "http/3")):
        return "udp"
    if any(token in normalized for token in ("tcp", "http", "https", "ws", "wss")):
        return "tcp"
    return normalized


@dataclass
class TransportAwarenessSnapshot:
    enabled: bool
    transport_scope: str
    transport_protocol: str
    proxy_enriched: bool
    tcp_flags: list[str]
    tcp_flag_mode: str
    syn_observed: bool
    ack_observed: bool
    rst_observed: bool
    fin_observed: bool
    suspicious_flag_combo: bool
    session_established_hint: bool | None
    reset_hint: bool
    connection_duration_ms: int | None
    retry_count: int
    timeout_hint: bool
    connection_churn_signal: bool
    short_lived_abusive_signal: bool
    retry_timeout_signal: bool
    malformed_transport_signal: bool
    syn_like_flood_signal: bool
    connection_reset_signal: bool
    abnormal_session_establishment_signal: bool
    udp_flood_signal: bool
    abnormal_session_score: int
    connection_churn_ratio: float
    short_lived_score: int
    retry_timeout_score: int
    malformed_transport_score: int
    risk_score: float
    reasons: list[str]
    monitor_triggered: bool
    block_triggered: bool
    thresholds: Dict[str, int | float]

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "transport_scope": self.transport_scope,
            "transport_protocol": self.transport_protocol,
            "proxy_enriched": self.proxy_enriched,
            "tcp_flags": list(self.tcp_flags),
            "tcp_flag_mode": self.tcp_flag_mode,
            "syn_observed": self.syn_observed,
            "ack_observed": self.ack_observed,
            "rst_observed": self.rst_observed,
            "fin_observed": self.fin_observed,
            "suspicious_flag_combo": self.suspicious_flag_combo,
            "session_established_hint": self.session_established_hint,
            "reset_hint": self.reset_hint,
            "connection_duration_ms": self.connection_duration_ms,
            "retry_count": self.retry_count,
            "timeout_hint": self.timeout_hint,
            "connection_churn_signal": self.connection_churn_signal,
            "short_lived_abusive_signal": self.short_lived_abusive_signal,
            "retry_timeout_signal": self.retry_timeout_signal,
            "malformed_transport_signal": self.malformed_transport_signal,
            "syn_like_flood_signal": self.syn_like_flood_signal,
            "connection_reset_signal": self.connection_reset_signal,
            "abnormal_session_establishment_signal": self.abnormal_session_establishment_signal,
            "udp_flood_signal": self.udp_flood_signal,
            "abnormal_session_score": self.abnormal_session_score,
            "connection_churn_ratio": self.connection_churn_ratio,
            "short_lived_score": self.short_lived_score,
            "retry_timeout_score": self.retry_timeout_score,
            "malformed_transport_score": self.malformed_transport_score,
            "risk_score": self.risk_score,
            "reasons": list(self.reasons),
            "monitor_triggered": self.monitor_triggered,
            "block_triggered": self.block_triggered,
            "thresholds": dict(self.thresholds),
            "supported_proxy_headers": {
                "transport_protocol": list(TRANSPORT_PROTOCOL_HEADERS + FORWARDED_PROTOCOL_HEADERS),
                "tcp_flags": list(TCP_FLAG_HEADERS),
                "connection_reset": list(RESET_HEADERS),
                "session_established": list(SESSION_ESTABLISHED_HEADERS),
                "connection_duration_ms": list(CONNECTION_DURATION_HEADERS),
                "retry_count": list(RETRY_COUNT_HEADERS),
                "timeout_hint": list(TIMEOUT_HEADERS),
                "transport_valid": list(TRANSPORT_VALID_HEADERS),
                "malformed_transport": list(MALFORMED_TRANSPORT_HEADERS),
            },
        }


def analyze_transport_awareness(
    request_record,
    history_snapshot,
    rate_limit_result,
    connection_snapshot,
    endpoint_policy,
    settings,
) -> TransportAwarenessSnapshot:
    headers = dict(getattr(request_record, "headers", {}) or {})
    transport_header = _header(headers, TRANSPORT_PROTOCOL_HEADERS)
    forwarded_proto_header = _header(headers, FORWARDED_PROTOCOL_HEADERS)
    tcp_flags = _parse_tcp_flags(_header(headers, TCP_FLAG_HEADERS))
    reset_header = _header(headers, RESET_HEADERS)
    session_established_header = _header(headers, SESSION_ESTABLISHED_HEADERS)
    connection_duration_header = _header(headers, CONNECTION_DURATION_HEADERS)
    retry_count_header = _header(headers, RETRY_COUNT_HEADERS)
    timeout_header = _header(headers, TIMEOUT_HEADERS)
    transport_valid_header = _header(headers, TRANSPORT_VALID_HEADERS)
    malformed_transport_header = _header(headers, MALFORMED_TRANSPORT_HEADERS)

    proxy_enriched = bool(
        transport_header
        or tcp_flags
        or reset_header
        or session_established_header
        or connection_duration_header
        or retry_count_header
        or timeout_header
        or transport_valid_header
        or malformed_transport_header
    )
    transport_scope = "reverse_proxy_enriched" if proxy_enriched else "application_inference"
    tcp_flag_mode = "proxy_header" if tcp_flags else "inferred"
    transport_protocol = _normalize_transport_protocol(
        transport_header or forwarded_proto_header or getattr(request_record, "scheme", "http")
    )
    connection_map = connection_snapshot.as_dict() if hasattr(connection_snapshot, "as_dict") else dict(connection_snapshot or {})
    endpoint_map = dict(endpoint_policy or {})

    syn_observed = "SYN" in tcp_flags
    ack_observed = "ACK" in tcp_flags
    rst_observed = "RST" in tcp_flags
    fin_observed = "FIN" in tcp_flags
    suspicious_flag_combo = (syn_observed and fin_observed) or (syn_observed and rst_observed)
    reset_hint = _presence_bool_header(reset_header)
    session_established_hint, session_established_malformed = _tri_bool_header(session_established_header)
    connection_duration_ms, duration_malformed = _parse_int_header(connection_duration_header, minimum=0)
    retry_count_value, retry_malformed = _parse_int_header(retry_count_header, minimum=0)
    retry_count = int(retry_count_value or 0)
    timeout_hint, timeout_malformed = _parse_timeout_header(timeout_header)
    transport_valid_hint, transport_valid_malformed = _tri_bool_header(transport_valid_header)
    malformed_hint, malformed_hint_malformed = _tri_bool_header(malformed_transport_header)
    explicit_malformed_transport = malformed_hint is True

    unknown_transport_protocol = bool(transport_header and transport_protocol not in {"tcp", "udp"})
    tcp_flags_on_udp = transport_protocol == "udp" and bool(tcp_flags)
    contradictory_session_reset = bool(reset_hint and session_established_hint is True)

    connection_burst = max(
        int(connection_map.get("connection_burst_ip", 0) or 0),
        int(connection_map.get("connection_burst_endpoint", 0) or 0),
    )
    stale_connections = max(
        int(connection_map.get("stale_connections_ip", 0) or 0),
        int(connection_map.get("stale_connections_endpoint", 0) or 0),
    )
    active_connections = max(
        int(connection_map.get("active_connections_ip", 0) or 0),
        int(connection_map.get("active_connections_endpoint", 0) or 0),
    )
    new_connections_per_second = int(connection_map.get("new_connections_per_second_ip", 0) or 0)
    connection_burst_pressure = float(connection_map.get("burst_pressure", 0.0) or 0.0)
    stale_pressure = float(connection_map.get("stale_pressure", 0.0) or 0.0)

    thresholds = {
        "syn_monitor_burst": max(int(getattr(settings, "transport_syn_monitor_burst_threshold", 6) or 6), 1),
        "syn_block_burst": max(int(getattr(settings, "transport_syn_block_burst_threshold", 10) or 10), 2),
        "reset_monitor_stale": max(int(getattr(settings, "transport_reset_monitor_stale_threshold", 1) or 1), 1),
        "reset_block_stale": max(int(getattr(settings, "transport_reset_block_stale_threshold", 2) or 2), 1),
        "abnormal_monitor_score": max(int(getattr(settings, "transport_abnormal_session_monitor_score", 4) or 4), 1),
        "abnormal_block_score": max(int(getattr(settings, "transport_abnormal_session_block_score", 6) or 6), 2),
        "udp_monitor_burst": max(int(getattr(settings, "transport_udp_monitor_burst_threshold", 5) or 5), 1),
        "udp_block_burst": max(int(getattr(settings, "transport_udp_block_burst_threshold", 9) or 9), 2),
        "churn_monitor_ratio": max(float(getattr(settings, "transport_churn_monitor_ratio", 2.5) or 2.5), 1.0),
        "churn_block_ratio": max(
            float(getattr(settings, "transport_churn_block_ratio", 4.0) or 4.0),
            float(getattr(settings, "transport_churn_monitor_ratio", 2.5) or 2.5),
        ),
        "short_lived_duration_ms_threshold": max(int(getattr(settings, "transport_short_lived_duration_ms_threshold", 250) or 250), 1),
        "short_lived_monitor_score": max(int(getattr(settings, "transport_short_lived_monitor_score", 3) or 3), 1),
        "short_lived_block_score": max(int(getattr(settings, "transport_short_lived_block_score", 5) or 5), 2),
        "retry_monitor_score": max(int(getattr(settings, "transport_retry_monitor_score", 3) or 3), 1),
        "retry_block_score": max(int(getattr(settings, "transport_retry_block_score", 5) or 5), 2),
        "malformed_monitor_score": max(int(getattr(settings, "transport_malformed_monitor_score", 2) or 2), 1),
        "malformed_block_score": max(int(getattr(settings, "transport_malformed_block_score", 4) or 4), 2),
    }

    syn_like_flood_signal = (
        (syn_observed and not ack_observed and connection_burst >= thresholds["syn_monitor_burst"])
        or (
            not proxy_enriched
            and transport_protocol == "tcp"
            and connection_burst >= thresholds["syn_monitor_burst"]
            and stale_connections >= 1
            and str(getattr(request_record, "session_id", "anonymous") or "anonymous") == "anonymous"
            and int(getattr(request_record, "cookies_count", 0) or 0) == 0
        )
    )
    connection_reset_signal = bool(rst_observed or reset_hint)

    abnormal_session_score = 0
    sensitivity = str(endpoint_map.get("sensitivity", "standard") or "standard").strip().lower()
    path_text = str(getattr(request_record, "path", "/") or "/").lower()
    login_or_admin = any(token in path_text for token in ("login", "signin", "auth", "admin", "config"))
    if sensitivity in {"protected", "critical"}:
        abnormal_session_score += 1
    if login_or_admin:
        abnormal_session_score += 1
    if str(getattr(request_record, "session_id", "anonymous") or "anonymous") == "anonymous":
        abnormal_session_score += 1
    if int(getattr(request_record, "cookies_count", 0) or 0) == 0:
        abnormal_session_score += 1
    if not str(getattr(request_record, "referer", "") or "").strip():
        abnormal_session_score += 1
    user_agent = str(getattr(request_record, "user_agent", "") or "").strip().lower()
    if not user_agent or user_agent == "unknown":
        abnormal_session_score += 1
    if _header(headers, ("Connection",)).strip().lower() == "close":
        abnormal_session_score += 1
    if float(getattr(rate_limit_result, "pressure", 0.0) or 0.0) >= 0.55:
        abnormal_session_score += 1
    if int(getattr(history_snapshot, "unique_paths_window", 0) or 0) >= 3:
        abnormal_session_score += 1
    if session_established_hint is False:
        abnormal_session_score += 2
    if suspicious_flag_combo:
        abnormal_session_score += 1

    abnormal_session_establishment_signal = abnormal_session_score >= thresholds["abnormal_monitor_score"]
    udp_flood_signal = transport_protocol == "udp" and connection_burst >= thresholds["udp_monitor_burst"]

    connection_close = _header(headers, ("Connection",)).strip().lower() == "close"
    no_session_or_cookie = (
        str(getattr(request_record, "session_id", "anonymous") or "anonymous") == "anonymous"
        and int(getattr(request_record, "cookies_count", 0) or 0) == 0
    )
    aggressive_client_evidence = 0
    if any(agent in user_agent for agent in ("curl", "wget", "python-requests", "aiohttp", "sqlmap", "nikto", "nmap")):
        aggressive_client_evidence += 1
    if no_session_or_cookie:
        aggressive_client_evidence += 1
    if float(getattr(rate_limit_result, "pressure", 0.0) or 0.0) >= 0.45:
        aggressive_client_evidence += 1
    if int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0) >= 2:
        aggressive_client_evidence += 1
    if float(getattr(history_snapshot, "ip_block_ratio", 0.0) or 0.0) >= 0.2:
        aggressive_client_evidence += 1
    if int(getattr(history_snapshot, "unique_paths_window", 0) or 0) >= 3:
        aggressive_client_evidence += 1

    connection_churn_ratio = round(
        new_connections_per_second / float(max(active_connections, 1)),
        4,
    )
    churn_prerequisite = (
        proxy_enriched
        or connection_close
        or connection_duration_ms is not None
        or session_established_hint is False
        or (new_connections_per_second >= thresholds["syn_monitor_burst"] and aggressive_client_evidence >= 3)
    )
    connection_churn_signal = bool(
        churn_prerequisite
        and new_connections_per_second >= 2
        and connection_churn_ratio >= float(thresholds["churn_monitor_ratio"])
    )

    short_lived_score = 0
    if connection_duration_ms is not None and connection_duration_ms <= int(thresholds["short_lived_duration_ms_threshold"]):
        short_lived_score += 2
    if connection_close:
        short_lived_score += 1
    if no_session_or_cookie:
        short_lived_score += 1
    if aggressive_client_evidence >= 2:
        short_lived_score += 1
    if session_established_hint is False:
        short_lived_score += 2
    if connection_reset_signal:
        short_lived_score += 1
    short_lived_abusive_signal = short_lived_score >= int(thresholds["short_lived_monitor_score"])

    inferred_retry_pattern = (
        int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0) >= 2
        and int(getattr(history_snapshot, "path_hits_window", 0) or 0) >= 2
        and no_session_or_cookie
    )
    retry_timeout_score = 0
    retry_timeout_score += min(retry_count, 3)
    if timeout_hint:
        retry_timeout_score += 2
    if inferred_retry_pattern:
        retry_timeout_score += 1
    if connection_reset_signal:
        retry_timeout_score += 1
    if connection_close:
        retry_timeout_score += 1
    retry_timeout_signal = retry_timeout_score >= int(thresholds["retry_monitor_score"])

    malformed_transport_score = 0
    malformed_details: list[str] = []
    if explicit_malformed_transport:
        malformed_transport_score += 2
        malformed_details.append("proxy flagged transport as malformed")
    if transport_valid_hint is False:
        malformed_transport_score += 1
        malformed_details.append("proxy reported invalid transport")
    if transport_valid_malformed:
        malformed_transport_score += 1
        malformed_details.append("transport validity header could not be parsed")
    if malformed_hint_malformed:
        malformed_transport_score += 1
        malformed_details.append("malformed transport header could not be parsed")
    if unknown_transport_protocol:
        malformed_transport_score += 1
        malformed_details.append("unknown transport protocol")
    if tcp_flags_on_udp:
        malformed_transport_score += 1
        malformed_details.append("TCP flags were attached to UDP metadata")
    if suspicious_flag_combo:
        malformed_transport_score += 1
        malformed_details.append("suspicious TCP flag combination")
    if duration_malformed:
        malformed_transport_score += 1
        malformed_details.append("connection duration header was malformed")
    if retry_malformed:
        malformed_transport_score += 1
        malformed_details.append("retry-count header was malformed")
    if timeout_malformed:
        malformed_transport_score += 1
        malformed_details.append("timeout header was malformed")
    if session_established_malformed:
        malformed_transport_score += 1
        malformed_details.append("session establishment header was malformed")
    if contradictory_session_reset:
        malformed_transport_score += 1
        malformed_details.append("reset and established hints contradicted each other")
    malformed_transport_signal = malformed_transport_score >= int(thresholds["malformed_monitor_score"])

    reasons: list[str] = []
    if syn_like_flood_signal:
        reasons.append(
            "SYN-like transport pattern detected with {0} connection starts inside the Layer 4 window.".format(connection_burst)
        )
    if connection_reset_signal:
        reasons.append(
            "RST or connection reset behavior was observed{}.".format(
                " via reverse-proxy transport headers" if proxy_enriched else ""
            )
        )
    if abnormal_session_establishment_signal:
        reasons.append(
            "Session establishment looks abnormal for this endpoint with evidence score {0}.".format(abnormal_session_score)
        )
    if udp_flood_signal:
        reasons.append(
            "UDP-like transport burst reached {0} starts inside the Layer 4 window.".format(connection_burst)
        )
    if connection_churn_signal:
        reasons.append(
            "Connection churn is elevated with {0} new connections/sec across {1} active connections (ratio {2:.2f}).".format(
                new_connections_per_second,
                max(active_connections, 1),
                connection_churn_ratio,
            )
        )
    if short_lived_abusive_signal:
        duration_label = "{0} ms".format(connection_duration_ms) if connection_duration_ms is not None else "unknown duration"
        reasons.append(
            "Short-lived abusive connections are suspected with {0} and evidence score {1}.".format(
                duration_label,
                short_lived_score,
            )
        )
    if retry_timeout_signal:
        reasons.append(
            "Unusual retries/timeouts were observed with retry score {0} and retry count {1}.".format(
                retry_timeout_score,
                retry_count,
            )
        )
    if malformed_transport_signal:
        reason = "Malformed or contradictory transport metadata was observed with validation score {0}.".format(
            malformed_transport_score
        )
        if malformed_details:
            reason = "{0} Details: {1}.".format(reason.rstrip("."), ", ".join(malformed_details[:4]))
        reasons.append(reason)
    if not reasons:
        reasons.append("No TCP/UDP transport anomaly was observed for this request.")

    enabled = bool(getattr(settings, "transport_awareness_enabled", True))
    block_triggered = enabled and (
        (syn_like_flood_signal and connection_burst >= thresholds["syn_block_burst"])
        or (udp_flood_signal and connection_burst >= thresholds["udp_block_burst"])
        or (connection_reset_signal and stale_connections >= thresholds["reset_block_stale"])
        or (abnormal_session_score >= thresholds["abnormal_block_score"])
        or (connection_churn_signal and connection_churn_ratio >= float(thresholds["churn_block_ratio"]))
        or (short_lived_score >= int(thresholds["short_lived_block_score"]))
        or (retry_timeout_score >= int(thresholds["retry_block_score"]))
        or (malformed_transport_score >= int(thresholds["malformed_block_score"]))
        or (suspicious_flag_combo and connection_burst_pressure >= 0.8)
    )
    monitor_triggered = enabled and not block_triggered and (
        syn_like_flood_signal
        or connection_reset_signal
        or abnormal_session_establishment_signal
        or udp_flood_signal
        or connection_churn_signal
        or short_lived_abusive_signal
        or retry_timeout_signal
        or malformed_transport_signal
        or suspicious_flag_combo
    )

    risk_score = 0.0
    risk_score += 0.02 if proxy_enriched else 0.0
    risk_score += 0.40 if syn_like_flood_signal else 0.0
    risk_score += 0.18 if connection_reset_signal else 0.0
    risk_score += 0.22 if abnormal_session_establishment_signal else 0.0
    risk_score += 0.35 if udp_flood_signal else 0.0
    risk_score += 0.16 if connection_churn_signal else 0.0
    risk_score += 0.16 if short_lived_abusive_signal else 0.0
    risk_score += 0.14 if retry_timeout_signal else 0.0
    risk_score += 0.18 if malformed_transport_signal else 0.0
    risk_score += 0.12 if suspicious_flag_combo else 0.0
    risk_score += min(connection_burst_pressure, 1.0) * 0.16
    risk_score += min(stale_pressure, 1.0) * 0.10
    risk_score += min(connection_churn_ratio / float(max(float(thresholds["churn_block_ratio"]), 1.0)), 1.0) * 0.08
    risk_score += min(short_lived_score / float(max(int(thresholds["short_lived_block_score"]), 1)), 1.0) * 0.06
    risk_score += min(retry_timeout_score / float(max(int(thresholds["retry_block_score"]), 1)), 1.0) * 0.06
    risk_score += min(malformed_transport_score / float(max(int(thresholds["malformed_block_score"]), 1)), 1.0) * 0.08
    risk_score += min(active_connections / float(max(int(thresholds["syn_block_burst"]), 1)), 1.0) * 0.08
    risk_score = round(clamp(risk_score, 0.0, 1.5), 4)

    return TransportAwarenessSnapshot(
        enabled=enabled,
        transport_scope=transport_scope,
        transport_protocol=transport_protocol,
        proxy_enriched=proxy_enriched,
        tcp_flags=tcp_flags,
        tcp_flag_mode=tcp_flag_mode,
        syn_observed=syn_observed,
        ack_observed=ack_observed,
        rst_observed=rst_observed,
        fin_observed=fin_observed,
        suspicious_flag_combo=suspicious_flag_combo,
        session_established_hint=session_established_hint,
        reset_hint=reset_hint,
        connection_duration_ms=connection_duration_ms,
        retry_count=retry_count,
        timeout_hint=timeout_hint,
        connection_churn_signal=connection_churn_signal,
        short_lived_abusive_signal=short_lived_abusive_signal,
        retry_timeout_signal=retry_timeout_signal,
        malformed_transport_signal=malformed_transport_signal,
        syn_like_flood_signal=syn_like_flood_signal,
        connection_reset_signal=connection_reset_signal,
        abnormal_session_establishment_signal=abnormal_session_establishment_signal,
        udp_flood_signal=udp_flood_signal,
        abnormal_session_score=abnormal_session_score,
        connection_churn_ratio=connection_churn_ratio,
        short_lived_score=short_lived_score,
        retry_timeout_score=retry_timeout_score,
        malformed_transport_score=malformed_transport_score,
        risk_score=risk_score,
        reasons=reasons,
        monitor_triggered=monitor_triggered,
        block_triggered=block_triggered,
        thresholds=thresholds,
    )
