from dataclasses import dataclass, field
from typing import List, Mapping, Optional


@dataclass
class RuleMatch:
    name: str
    attack_type: str
    severity: float
    action: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class RuleResult:
    matched_rules: List[RuleMatch] = field(default_factory=list)
    should_block: bool = False
    should_monitor: bool = False
    severity: float = 0.0

    @property
    def reasons(self) -> List[str]:
        return [rule.reason for rule in self.matched_rules]

    @property
    def attack_types(self) -> List[str]:
        attack_types = []
        for rule in self.matched_rules:
            if rule.attack_type not in attack_types:
                attack_types.append(rule.attack_type)
        return attack_types

    def add(self, match: RuleMatch) -> None:
        self.matched_rules.append(match)
        self.severity = max(self.severity, match.severity)
        if match.action == "block":
            self.should_block = True
            self.should_monitor = True
        elif match.action == "monitor":
            self.should_monitor = True

    def as_dict(self) -> dict:
        return {
            "should_block": self.should_block,
            "should_monitor": self.should_monitor,
            "severity": self.severity,
            "reasons": self.reasons,
            "attack_types": self.attack_types,
            "matched_rules": [rule.as_dict() for rule in self.matched_rules],
        }


def check_rules(
    request_record,
    features: Mapping[str, float],
    history_snapshot,
    rate_limit_result,
    blacklist_record: Optional[object],
    manual_block_rule: Optional[Mapping[str, object]],
    endpoint_policy: Optional[Mapping[str, object]] = None,
    connection_snapshot=None,
    transport_snapshot=None,
    settings=None,
) -> RuleResult:
    result = RuleResult()
    payload_text = " ".join(
        [
            request_record.path or "",
            request_record.query_string or "",
            request_record.body_text or "",
        ]
    ).lower()

    if blacklist_record is not None:
        result.add(
            RuleMatch(
                name="ip_blacklist",
                attack_type="blacklist",
                severity=1.0,
                action="block",
                reason="Client IP is blacklisted: {0}".format(blacklist_record.reason),
            )
        )

    if manual_block_rule is not None:
        scope_type = str(manual_block_rule.get("scope_type", "signature"))
        result.add(
            RuleMatch(
                name="manual_targeted_block",
                attack_type="manual_policy",
                severity=1.0,
                action="block",
                reason="Manual block rule matched this request ({0})".format(scope_type),
            )
        )

    endpoint_policy = dict(endpoint_policy or {})
    ddos_protection_enabled = bool(getattr(settings, "ddos_protection_enabled", True))
    endpoint_name = str(endpoint_policy.get("name") or "current endpoint")
    endpoint_sensitivity = str(endpoint_policy.get("sensitivity", "standard") or "standard")
    recent_endpoint_hits = int(getattr(history_snapshot, "path_hits_window", 0) or 0) + 1
    monitor_hits = int(endpoint_policy.get("ddos_monitor_hits", getattr(settings, "ddos_monitor_request_threshold", 14)) or getattr(settings, "ddos_monitor_request_threshold", 14))
    block_hits = int(endpoint_policy.get("ddos_block_hits", getattr(settings, "ddos_block_request_threshold", 24)) or getattr(settings, "ddos_block_request_threshold", 24))
    monitor_pressure = float(endpoint_policy.get("ddos_monitor_pressure", getattr(settings, "ddos_monitor_pressure_threshold", 0.85)) or getattr(settings, "ddos_monitor_pressure_threshold", 0.85))
    block_pressure = float(endpoint_policy.get("ddos_block_pressure", getattr(settings, "ddos_block_pressure_threshold", 0.97)) or getattr(settings, "ddos_block_pressure_threshold", 0.97))

    if not rate_limit_result.allowed:
        profile_label = str(getattr(rate_limit_result, "profile", "default") or "default")
        requests_per_min = int(getattr(rate_limit_result, "requests_per_min", 0) or 0)
        result.add(
            RuleMatch(
                name="token_bucket_limit",
                attack_type="ddos",
                severity=0.98,
                action="block",
                reason=(
                    "Client exhausted the {0} token bucket rate limit".format(profile_label)
                    + (" ({0} req/min)".format(requests_per_min) if requests_per_min else "")
                ),
            )
        )

    if ddos_protection_enabled and rate_limit_result.allowed and (
        recent_endpoint_hits >= block_hits
        or (recent_endpoint_hits >= 2 and rate_limit_result.pressure >= block_pressure)
    ):
        action = "block" if endpoint_sensitivity == "critical" else "monitor"
        severity = 0.97 if action == "block" else 0.84
        result.add(
            RuleMatch(
                name="endpoint_flood_guard",
                attack_type="ddos",
                severity=severity,
                action=action,
                reason=(
                    "{0} exceeded the endpoint-specific flood threshold with {1} recent hits and {2:.1%} bucket pressure".format(
                        endpoint_name,
                        recent_endpoint_hits,
                        rate_limit_result.pressure,
                    )
                ),
            )
        )

    connection_map = connection_snapshot.as_dict() if hasattr(connection_snapshot, "as_dict") else dict(connection_snapshot or {})
    if ddos_protection_enabled and bool(connection_map.get("block_triggered")):
        endpoint_label = str(connection_map.get("endpoint_label") or endpoint_name)
        active_connections = max(
            int(connection_map.get("active_connections_endpoint", 0) or 0),
            int(connection_map.get("active_connections_ip", 0) or 0),
        )
        burst_count = max(
            int(connection_map.get("connection_burst_endpoint", 0) or 0),
            int(connection_map.get("connection_burst_ip", 0) or 0),
        )
        new_connections_per_second = int(connection_map.get("new_connections_per_second_ip", 0) or 0)
        concurrent_sessions = int(connection_map.get("concurrent_sessions_source", 0) or 0)
        stale_count = max(
            int(connection_map.get("stale_connections_endpoint", 0) or 0),
            int(connection_map.get("stale_connections_ip", 0) or 0),
        )
        result.add(
            RuleMatch(
                name="connection_guard_block",
                attack_type="ddos",
                severity=0.99,
                action="block",
                reason=(
                    "Connection guard blocked {0} after active connections={1}, burst starts={2}, new connections/sec={3}, concurrent sessions={4}, stale in-flight requests={5}.".format(
                        endpoint_label,
                        active_connections,
                        burst_count,
                        new_connections_per_second,
                        concurrent_sessions,
                        stale_count,
                    )
                ),
            )
        )
    elif ddos_protection_enabled and bool(connection_map.get("monitor_triggered")):
        endpoint_label = str(connection_map.get("endpoint_label") or endpoint_name)
        result.add(
            RuleMatch(
                name="connection_guard_watch",
                attack_type="ddos",
                severity=0.81,
                action="monitor",
                reason=(
                    "Connection-level pressure on {0} is elevated, so the gateway is monitoring connections per IP, new connections/sec, concurrent sessions, and stale in-flight activity.".format(
                        endpoint_label,
                    )
                ),
            )
        )

    transport_map = transport_snapshot.as_dict() if hasattr(transport_snapshot, "as_dict") else dict(transport_snapshot or {})
    if bool(getattr(settings, "transport_awareness_enabled", True)) and bool(transport_map.get("block_triggered")):
        protocol = str(transport_map.get("transport_protocol") or "tcp").upper()
        thresholds = dict(transport_map.get("thresholds") or {})
        malformed_hard_block = bool(transport_map.get("malformed_transport_signal")) and (
            int(transport_map.get("malformed_transport_score", 0) or 0) >= int(thresholds.get("malformed_block_score", 4) or 4)
        )
        retry_hard_block = bool(transport_map.get("retry_timeout_signal")) and (
            int(transport_map.get("retry_timeout_score", 0) or 0) >= int(thresholds.get("retry_block_score", 5) or 5)
        )
        short_lived_hard_block = bool(transport_map.get("short_lived_abusive_signal")) and (
            int(transport_map.get("short_lived_score", 0) or 0) >= int(thresholds.get("short_lived_block_score", 5) or 5)
        )
        churn_hard_block = bool(transport_map.get("connection_churn_signal")) and (
            float(transport_map.get("connection_churn_ratio", 0.0) or 0.0) >= float(thresholds.get("churn_block_ratio", 4.0) or 4.0)
        )
        reason = "Transport-level anomaly triggered a Layer 4 block."
        if malformed_hard_block:
            reason = "Malformed or contradictory transport behavior crossed the Layer 4 hardening threshold."
        elif retry_hard_block:
            reason = "Unusual retries/timeouts crossed the configured Layer 4 hardening threshold."
        elif short_lived_hard_block:
            reason = "Short-lived abusive connections crossed the Layer 4 hardening threshold."
        elif churn_hard_block:
            reason = "Connection churn became excessive for this source and crossed the Layer 4 hardening threshold."
        elif transport_map.get("syn_like_flood_signal"):
            reason = "{0} SYN-like flood behavior exceeded the configured Layer 4 burst ceiling.".format(protocol)
        elif transport_map.get("udp_flood_signal"):
            reason = "UDP-like transport burst exceeded the configured Layer 4 flood ceiling."
        elif transport_map.get("connection_reset_signal"):
            reason = "Repeated RST or connection reset behavior combined with stale in-flight activity triggered a Layer 4 block."
        elif transport_map.get("abnormal_session_establishment_signal"):
            reason = "Abnormal session establishment crossed the Layer 4 hardening threshold."
        result.add(
            RuleMatch(
                name="transport_awareness_block",
                attack_type="ddos"
                if transport_map.get("syn_like_flood_signal")
                or transport_map.get("udp_flood_signal")
                or transport_map.get("connection_churn_signal")
                else "anomaly",
                severity=0.97,
                action="block",
                reason=reason,
            )
        )
    elif bool(getattr(settings, "transport_awareness_enabled", True)) and bool(transport_map.get("monitor_triggered")):
        protocol = str(transport_map.get("transport_protocol") or "tcp").upper()
        reason = "{0} transport behavior is suspicious and is being monitored at Layer 4.".format(protocol)
        if transport_map.get("malformed_transport_signal"):
            reason = "Malformed or contradictory transport behavior is being monitored at Layer 4."
        elif transport_map.get("retry_timeout_signal"):
            reason = "Unusual retries/timeouts are being monitored at Layer 4."
        elif transport_map.get("short_lived_abusive_signal"):
            reason = "Short-lived abusive connections are being monitored at Layer 4."
        elif transport_map.get("connection_churn_signal"):
            reason = "Connection churn is elevated and is being monitored at Layer 4."
        elif transport_map.get("syn_like_flood_signal"):
            reason = "{0} SYN-like establishment pattern is elevated and is being monitored.".format(protocol)
        elif transport_map.get("connection_reset_signal"):
            reason = "RST or connection reset behavior was observed and is being monitored."
        elif transport_map.get("abnormal_session_establishment_signal"):
            reason = "Session establishment looks abnormal for this protected endpoint and is being monitored."
        elif transport_map.get("udp_flood_signal"):
            reason = "UDP-like transport burst is elevated and is being monitored."
        result.add(
            RuleMatch(
                name="transport_awareness_watch",
                attack_type="ddos"
                if transport_map.get("syn_like_flood_signal")
                or transport_map.get("udp_flood_signal")
                or transport_map.get("connection_churn_signal")
                else "anomaly",
                severity=0.79,
                action="monitor",
                reason=reason,
            )
        )

    if ddos_protection_enabled and features.get("ddos_signal") and rate_limit_result.allowed:
        profile_label = str(getattr(rate_limit_result, "profile", "default") or "default")
        result.add(
            RuleMatch(
                name="flood_pattern",
                attack_type="ddos",
                severity=0.83,
                action="monitor",
                reason="High-rate request burst under the {0} profile resembles request flooding or DDoS-style behavior".format(profile_label),
            )
        )

    if ddos_protection_enabled and rate_limit_result.allowed and (
        recent_endpoint_hits >= monitor_hits
        or (recent_endpoint_hits >= 2 and rate_limit_result.pressure >= monitor_pressure)
    ):
        result.add(
            RuleMatch(
                name="ddos_watch",
                attack_type="ddos",
                severity=0.76,
                action="monitor",
                reason=(
                    "{0} is approaching its endpoint-specific rate ceiling and is being monitored for DDoS-style pressure".format(
                        endpoint_name,
                    )
                ),
            )
        )

    if features.get("sql_injection_signal"):
        result.add(
            RuleMatch(
                name="sql_injection_signature",
                attack_type="sql_injection",
                severity=1.0,
                action="block",
                reason="SQL injection pattern detected",
            )
        )

    if "bad_keyword" in payload_text:
        result.add(
            RuleMatch(
                name="demo_bad_keyword",
                attack_type="suspicious_payload",
                severity=0.95,
                action="block",
                reason="Explicit bad_keyword marker detected",
            )
        )

    if features.get("xss_signal"):
        result.add(
            RuleMatch(
                name="xss_signature",
                attack_type="xss",
                severity=1.0,
                action="block",
                reason="Cross-site scripting pattern detected",
            )
        )

    if features.get("traversal_signal"):
        result.add(
            RuleMatch(
                name="path_traversal_signature",
                attack_type="path_traversal",
                severity=0.95,
                action="block",
                reason="Path traversal pattern detected",
            )
        )

    if features.get("command_injection_signal"):
        result.add(
            RuleMatch(
                name="command_injection_signature",
                attack_type="command_injection",
                severity=0.95,
                action="block",
                reason="Command injection pattern detected",
            )
        )

    if features.get("payload_evasion_signal"):
        result.add(
            RuleMatch(
                name="payload_evasion_pattern",
                attack_type="payload_evasion",
                severity=0.86,
                action="monitor" if not features.get("suspicious_keyword_hits", 0.0) else "block",
                reason="Encoded or evasive payload structure suggests an attack attempting signature bypass",
            )
        )

    if features.get("login_failure_signal"):
        failed_attempts_window = float(features.get("failed_login_attempts_window", 0.0) or 0.0)
        if failed_attempts_window >= 3.0 or rate_limit_result.pressure >= 0.35:
            action = "block" if failed_attempts_window >= 7.0 or not rate_limit_result.allowed else "monitor"
            result.add(
                RuleMatch(
                    name="failed_login_streak",
                    attack_type="brute_force",
                    severity=0.94 if action == "block" else 0.79,
                    action=action,
                    reason="Repeated failed authentication attempts suggest login abuse or credential stuffing",
                )
            )

    if features.get("brute_force_signal"):
        action = "block" if features.get("automation_abuse_signal") or not rate_limit_result.allowed else "monitor"
        result.add(
            RuleMatch(
                name="login_abuse_pattern",
                attack_type="brute_force",
                severity=0.88 if action == "block" else 0.76,
                action=action,
                reason="Repeated authentication-style activity suggests brute-force or credential-stuffing behavior",
            )
        )

    if features.get("automation_fingerprint_signal"):
        action = (
            "block"
            if features.get("headless_browser_signal")
            and (features.get("login_path_signal") or features.get("admin_path_signal") or features.get("protected_endpoint_signal"))
            else "monitor"
        )
        result.add(
            RuleMatch(
                name="automation_fingerprint",
                attack_type="malicious_automation",
                severity=0.91 if action == "block" else 0.78,
                action=action,
                reason="Automation fingerprints matched scripted tooling, browser automation, or headless control markers.",
            )
        )

    if features.get("browser_integrity_signal") and features.get("browser_claim_signal"):
        action = (
            "block"
            if features.get("headless_browser_signal")
            and (features.get("login_path_signal") or features.get("admin_path_signal"))
            else "monitor"
        )
        result.add(
            RuleMatch(
                name="browser_integrity_mismatch",
                attack_type="malicious_automation",
                severity=0.88 if action == "block" else 0.72,
                action=action,
                reason="Browser integrity checks failed, so the claimed browser headers do not look like a normal human-operated client.",
            )
        )

    if features.get("scraping_pattern_signal"):
        action = (
            "block"
            if (
                not rate_limit_result.allowed
                or features.get("headless_browser_signal")
                or float(features.get("bot_likelihood_score", 0.0) or 0.0) >= 1.0
                or int(getattr(history_snapshot, "fingerprint_reuse_count", 0) or 0) >= 3
            )
            else "monitor"
        )
        result.add(
            RuleMatch(
                name="scraping_bot_control",
                attack_type="malicious_automation",
                severity=0.93 if action == "block" else 0.77,
                action=action,
                reason="Scraping bot control detected automated collection on search, export, or public data surfaces.",
            )
        )

    if features.get("automation_abuse_signal"):
        result.add(
            RuleMatch(
                name="automation_abuse_pattern",
                attack_type="malicious_automation",
                severity=0.74,
                action="monitor",
                reason="Automated client behavior indicates bot-driven probing or abuse",
            )
        )

    if features.get("suspicious_keyword_hits", 0.0) >= 2.0:
        result.add(
            RuleMatch(
                name="keyword_correlation",
                attack_type="suspicious_payload",
                severity=0.75,
                action="monitor",
                reason="Multiple suspicious keywords were detected",
            )
        )

    if features.get("body_length", 0.0) > 8192.0:
        result.add(
            RuleMatch(
                name="oversized_payload",
                attack_type="oversized_body",
                severity=0.82,
                action="block",
                reason="Request body exceeded the configured maximum",
            )
        )

    if history_snapshot.ip_request_count_window >= 60 and history_snapshot.unique_paths_window >= 10:
        result.add(
            RuleMatch(
                name="burst_reconnaissance",
                attack_type="reconnaissance",
                severity=0.70,
                action="monitor",
                reason="IP generated a burst of requests across many paths",
            )
        )

    if features.get("automation_user_agent_signal") and features.get("admin_path_signal"):
        result.add(
            RuleMatch(
                name="automated_admin_probe",
                attack_type="reconnaissance",
                severity=0.74,
                action="monitor",
                reason="Automated client appears to be probing an administrative path",
            )
        )

    if history_snapshot.ip_block_ratio >= 0.5 and history_snapshot.ip_request_count_window >= 4:
        result.add(
            RuleMatch(
                name="repeat_offender",
                attack_type="repeat_offender",
                severity=0.80,
                action="monitor",
                reason="This IP has a high recent block ratio",
            )
        )

    return result
