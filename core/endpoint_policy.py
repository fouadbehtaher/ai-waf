from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
from typing import Dict, Iterable, List, Mapping

from utils import clamp, to_iso


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


def _safe_methods(raw_methods) -> list[str]:
    if raw_methods is None:
        return ["*"]
    if isinstance(raw_methods, str):
        values = [item.strip().upper() for item in raw_methods.split(",") if item.strip()]
    else:
        values = [str(item).strip().upper() for item in raw_methods if str(item).strip()]
    return values or ["*"]


def _method_matches(policy_methods: Iterable[str], method: str) -> bool:
    methods = [str(item).strip().upper() for item in policy_methods if str(item).strip()]
    if not methods or "*" in methods:
        return True
    return str(method or "GET").strip().upper() in methods


def _path_matches(pattern: str, path: str) -> bool:
    normalized_pattern = str(pattern or "/*").strip() or "/*"
    normalized_path = str(path or "/").strip() or "/"
    if normalized_pattern in {"*", "/*"}:
        return True
    if "*" not in normalized_pattern:
        return normalized_path == normalized_pattern
    if normalized_pattern.endswith("*") and normalized_pattern.count("*") == 1:
        return normalized_path.startswith(normalized_pattern[:-1])
    return fnmatch(normalized_path, normalized_pattern)


def _match_score(policy: Mapping[str, object], path: str) -> tuple[int, int]:
    pattern = str(policy.get("path_pattern") or "/*")
    priority = int(policy.get("priority", 0) or 0)
    if "*" not in pattern:
        specificity = 1000 + len(pattern)
    elif pattern.endswith("*") and pattern.count("*") == 1:
        specificity = 600 + len(pattern.rstrip("*"))
    else:
        specificity = 300 + len(pattern.replace("*", ""))
    if not _path_matches(pattern, path):
        specificity = 0
    return (priority, specificity)


def _build_policy(
    policy_id: str,
    name: str,
    description: str,
    path_pattern: str,
    methods,
    priority: int,
    sensitivity: str,
    settings_map: Mapping[str, object],
    source: str,
    is_enabled: bool = True,
) -> Dict[str, object]:
    policy = {
        "policy_id": policy_id,
        "name": name,
        "description": description,
        "path_pattern": path_pattern,
        "methods": _safe_methods(methods),
        "priority": int(priority or 0),
        "sensitivity": str(sensitivity or "standard").strip().lower(),
        "settings": dict(settings_map or {}),
        "source": source,
        "is_enabled": bool(is_enabled),
    }
    return policy


def default_endpoint_policies(settings) -> List[Dict[str, object]]:
    base_monitor_hits = max(int(getattr(settings, "ddos_monitor_request_threshold", 14) or 14), 2)
    base_block_hits = max(int(getattr(settings, "ddos_block_request_threshold", 24) or 24), base_monitor_hits + 1)
    base_monitor_pressure = clamp(float(getattr(settings, "ddos_monitor_pressure_threshold", 0.85) or 0.85), 0.1, 1.0)
    base_block_pressure = clamp(float(getattr(settings, "ddos_block_pressure_threshold", 0.97) or 0.97), base_monitor_pressure, 1.0)
    block_threshold = float(getattr(settings, "block_threshold", 0.72) or 0.72)
    monitor_threshold = float(getattr(settings, "monitor_threshold", 0.48) or 0.48)

    return [
        _build_policy(
            policy_id="builtin-auth-login",
            name="Authentication Login",
            description="Critical authentication endpoint with strict throttling and lower thresholds against brute-force and login floods.",
            path_pattern="/api/auth/login",
            methods=["POST"],
            priority=120,
            sensitivity="critical",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 6,
                "block_threshold": _round_float(block_threshold, 3),
                "monitor_threshold": _round_float(monitor_threshold, 3),
                "ddos_monitor_hits": 4,
                "ddos_block_hits": 8,
                "ddos_monitor_pressure": 0.45,
                "ddos_block_pressure": 0.78,
                "connection_monitor_active": 3,
                "connection_block_active": 6,
                "connection_monitor_per_ip": 3,
                "connection_block_per_ip": 6,
                "connection_burst_monitor": 4,
                "connection_burst_block": 8,
                "connection_new_per_second_monitor": 2,
                "connection_new_per_second_block": 4,
                "connection_stale_monitor": 2,
                "connection_stale_block": 4,
                "connection_sessions_monitor": 2,
                "connection_sessions_block": 4,
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-auth-surface",
            name="Authentication Surface",
            description="Protects broader authentication paths with endpoint-scoped buckets and early flood monitoring.",
            path_pattern="/api/auth/*",
            methods=["*"],
            priority=105,
            sensitivity="protected",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 16,
                "block_threshold": _round_float(min(block_threshold, 0.66), 3),
                "monitor_threshold": _round_float(min(monitor_threshold, 0.44), 3),
                "ddos_monitor_hits": 5,
                "ddos_block_hits": 10,
                "ddos_monitor_pressure": 0.60,
                "ddos_block_pressure": 0.86,
                "connection_monitor_active": 4,
                "connection_block_active": 8,
                "connection_monitor_per_ip": 4,
                "connection_block_per_ip": 8,
                "connection_burst_monitor": 6,
                "connection_burst_block": 10,
                "connection_new_per_second_monitor": 3,
                "connection_new_per_second_block": 6,
                "connection_stale_monitor": 2,
                "connection_stale_block": 4,
                "connection_sessions_monitor": 2,
                "connection_sessions_block": 4,
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-login-surface",
            name="Login Surface",
            description="Generic login endpoints keep a stricter profile than standard traffic so credential abuse is throttled before it spreads.",
            path_pattern="*/login*",
            methods=["*"],
            priority=112,
            sensitivity="critical",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 10,
                "block_threshold": _round_float(min(block_threshold, 0.65), 3),
                "monitor_threshold": _round_float(min(monitor_threshold, 0.43), 3),
                "ddos_monitor_hits": 5,
                "ddos_block_hits": 9,
                "ddos_monitor_pressure": 0.55,
                "ddos_block_pressure": 0.82,
                "connection_monitor_active": 3,
                "connection_block_active": 6,
                "connection_monitor_per_ip": 3,
                "connection_block_per_ip": 6,
                "connection_burst_monitor": 5,
                "connection_burst_block": 9,
                "connection_new_per_second_monitor": 2,
                "connection_new_per_second_block": 4,
                "connection_stale_monitor": 2,
                "connection_stale_block": 4,
                "connection_sessions_monitor": 2,
                "connection_sessions_block": 4,
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-admin-surface",
            name="Administrative Surface",
            description="Administrative and configuration endpoints get tighter rate budgets and faster DDoS escalation.",
            path_pattern="*/admin*",
            methods=["*"],
            priority=100,
            sensitivity="critical",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 10,
                "block_threshold": _round_float(min(block_threshold, 0.62), 3),
                "monitor_threshold": _round_float(min(monitor_threshold, 0.42), 3),
                "ddos_monitor_hits": 4,
                "ddos_block_hits": 8,
                "ddos_monitor_pressure": 0.52,
                "ddos_block_pressure": 0.82,
                "connection_monitor_active": 3,
                "connection_block_active": 6,
                "connection_monitor_per_ip": 3,
                "connection_block_per_ip": 6,
                "connection_burst_monitor": 4,
                "connection_burst_block": 8,
                "connection_new_per_second_monitor": 2,
                "connection_new_per_second_block": 4,
                "connection_stale_monitor": 2,
                "connection_stale_block": 4,
                "connection_sessions_monitor": 2,
                "connection_sessions_block": 4,
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-search-surface",
            name="Search Surface",
            description="Search endpoints get a distinct scrape-aware profile with endpoint-scoped throttling so bursts can be isolated without affecting the rest of the API.",
            path_pattern="*/search*",
            methods=["GET"],
            priority=90,
            sensitivity="protected",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 24,
                "block_threshold": _round_float(min(block_threshold, 0.69), 3),
                "monitor_threshold": _round_float(min(monitor_threshold, 0.46), 3),
                "ddos_monitor_hits": 8,
                "ddos_block_hits": 16,
                "ddos_monitor_pressure": 0.72,
                "ddos_block_pressure": 0.9,
                "connection_monitor_active": 5,
                "connection_block_active": 10,
                "connection_monitor_per_ip": 5,
                "connection_block_per_ip": 10,
                "connection_burst_monitor": 7,
                "connection_burst_block": 12,
                "connection_new_per_second_monitor": 3,
                "connection_new_per_second_block": 6,
                "connection_stale_monitor": 2,
                "connection_stale_block": 4,
                "connection_sessions_monitor": 3,
                "connection_sessions_block": 5,
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-config-surface",
            name="Configuration Surface",
            description="Configuration routes remain under protected throttling because they are common reconnaissance and abuse targets.",
            path_pattern="/config*",
            methods=["*"],
            priority=95,
            sensitivity="critical",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 12,
                "block_threshold": _round_float(min(block_threshold, 0.64), 3),
                "monitor_threshold": _round_float(min(monitor_threshold, 0.44), 3),
                "ddos_monitor_hits": 4,
                "ddos_block_hits": 8,
                "ddos_monitor_pressure": 0.55,
                "ddos_block_pressure": 0.84,
                "connection_monitor_active": 3,
                "connection_block_active": 6,
                "connection_monitor_per_ip": 3,
                "connection_block_per_ip": 6,
                "connection_burst_monitor": 4,
                "connection_burst_block": 8,
                "connection_new_per_second_monitor": 2,
                "connection_new_per_second_block": 4,
                "connection_stale_monitor": 2,
                "connection_stale_block": 4,
                "connection_sessions_monitor": 2,
                "connection_sessions_block": 4,
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-public-api-surface",
            name="Public API Surface",
            description="Public API endpoints keep a separate high-volume profile so open traffic stays isolated from login and admin surfaces.",
            path_pattern="/api/public*",
            methods=["*"],
            priority=70,
            sensitivity="standard",
            settings_map={
                "bucket_scope": "ip_endpoint",
                "requests_per_min": 60,
                "block_threshold": _round_float(max(block_threshold, 0.78), 3),
                "monitor_threshold": _round_float(max(monitor_threshold, 0.52), 3),
                "ddos_monitor_hits": max(base_monitor_hits + 6, 20),
                "ddos_block_hits": max(base_block_hits + 12, 36),
                "ddos_monitor_pressure": _round_float(min(base_monitor_pressure + 0.05, 0.92), 3),
                "ddos_block_pressure": _round_float(min(base_block_pressure + 0.01, 0.99), 3),
                "connection_monitor_active": max(int(getattr(settings, "connection_monitor_active_threshold", 6) or 6), 6),
                "connection_block_active": max(int(getattr(settings, "connection_block_active_threshold", 12) or 12), 12),
                "connection_monitor_per_ip": max(int(getattr(settings, "connection_monitor_per_ip_threshold", 6) or 6), 6),
                "connection_block_per_ip": max(int(getattr(settings, "connection_block_per_ip_threshold", 12) or 12), 12),
                "connection_burst_monitor": max(int(getattr(settings, "connection_monitor_burst_threshold", 10) or 10), 12),
                "connection_burst_block": max(int(getattr(settings, "connection_block_burst_threshold", 18) or 18), 20),
                "connection_new_per_second_monitor": max(int(getattr(settings, "connection_monitor_new_connections_per_second", 4) or 4), 5),
                "connection_new_per_second_block": max(int(getattr(settings, "connection_block_new_connections_per_second", 8) or 8), 10),
                "connection_stale_monitor": max(int(getattr(settings, "connection_monitor_stale_threshold", 2) or 2), 2),
                "connection_stale_block": max(int(getattr(settings, "connection_block_stale_threshold", 5) or 5), 5),
                "connection_sessions_monitor": max(int(getattr(settings, "connection_monitor_sessions_per_source", 3) or 3), 4),
                "connection_sessions_block": max(int(getattr(settings, "connection_block_sessions_per_source", 6) or 6), 8),
            },
            source="builtin",
        ),
        _build_policy(
            policy_id="builtin-default",
            name="Default Gateway Scope",
            description="Baseline policy for general traffic when no narrower endpoint-specific policy matches.",
            path_pattern="/*",
            methods=["*"],
            priority=1,
            sensitivity="standard",
            settings_map={
                "bucket_scope": "ip",
                "requests_per_min": int(getattr(settings, "rate_limit_max_requests", 30) or 30),
                "block_threshold": _round_float(block_threshold, 3),
                "monitor_threshold": _round_float(monitor_threshold, 3),
                "ddos_monitor_hits": base_monitor_hits,
                "ddos_block_hits": base_block_hits,
                "ddos_monitor_pressure": _round_float(base_monitor_pressure, 3),
                "ddos_block_pressure": _round_float(base_block_pressure, 3),
                "connection_monitor_active": max(int(getattr(settings, "connection_monitor_active_threshold", 6) or 6), 1),
                "connection_block_active": max(int(getattr(settings, "connection_block_active_threshold", 12) or 12), 2),
                "connection_monitor_per_ip": max(int(getattr(settings, "connection_monitor_per_ip_threshold", 6) or 6), 1),
                "connection_block_per_ip": max(int(getattr(settings, "connection_block_per_ip_threshold", 12) or 12), 2),
                "connection_burst_monitor": max(int(getattr(settings, "connection_monitor_burst_threshold", 10) or 10), 1),
                "connection_burst_block": max(int(getattr(settings, "connection_block_burst_threshold", 18) or 18), 2),
                "connection_new_per_second_monitor": max(int(getattr(settings, "connection_monitor_new_connections_per_second", 4) or 4), 1),
                "connection_new_per_second_block": max(int(getattr(settings, "connection_block_new_connections_per_second", 8) or 8), 2),
                "connection_stale_monitor": max(int(getattr(settings, "connection_monitor_stale_threshold", 2) or 2), 1),
                "connection_stale_block": max(int(getattr(settings, "connection_block_stale_threshold", 5) or 5), 2),
                "connection_sessions_monitor": max(int(getattr(settings, "connection_monitor_sessions_per_source", 3) or 3), 1),
                "connection_sessions_block": max(int(getattr(settings, "connection_block_sessions_per_source", 6) or 6), 2),
            },
            source="builtin",
        ),
    ]


def resolve_endpoint_policy(request_record, settings, custom_policies: Iterable[Mapping[str, object]] | None = None) -> Dict[str, object]:
    candidates = []
    for policy in default_endpoint_policies(settings):
        candidates.append(deepcopy(policy))
    for custom_policy in custom_policies or []:
        if not bool(custom_policy.get("is_enabled", True)):
            continue
        candidates.append(
            _build_policy(
                policy_id=str(custom_policy.get("policy_id") or ""),
                name=str(custom_policy.get("name") or "Custom policy"),
                description=str(custom_policy.get("description") or ""),
                path_pattern=str(custom_policy.get("path_pattern") or "/*"),
                methods=custom_policy.get("methods") or ["*"],
                priority=int(custom_policy.get("priority", 50) or 50),
                sensitivity=str(custom_policy.get("sensitivity") or "protected"),
                settings_map=custom_policy.get("settings") or {},
                source=str(custom_policy.get("source") or "custom"),
                is_enabled=bool(custom_policy.get("is_enabled", True)),
            )
        )

    candidate_paths = [str(getattr(request_record, "path", "/") or "/")]
    gateway_path = str(getattr(request_record, "gateway_path", "") or "")
    if gateway_path and gateway_path not in candidate_paths:
        candidate_paths.append(gateway_path)

    matched = []
    for policy in candidates:
        if not _method_matches(policy.get("methods", ["*"]), getattr(request_record, "method", "GET")):
            continue
        matched_paths = [path for path in candidate_paths if _path_matches(str(policy.get("path_pattern") or "/*"), path)]
        if not matched_paths:
            continue
        policy_copy = dict(policy)
        best_path = max(matched_paths, key=lambda path: _match_score(policy_copy, path)[1])
        policy_copy["_matched_path"] = best_path
        matched.append(policy_copy)

    if not matched:
        matched = [default_endpoint_policies(settings)[-1]]

    best = max(matched, key=lambda item: _match_score(item, str(item.get("_matched_path") or getattr(request_record, "path", "/"))))
    settings_map = dict(best.get("settings") or {})
    requests_per_min = int(settings_map.get("requests_per_min", getattr(settings, "rate_limit_max_requests", 30)) or getattr(settings, "rate_limit_max_requests", 30))
    requests_per_min = max(requests_per_min, 1)
    capacity = int(settings_map.get("capacity", requests_per_min) or requests_per_min)
    capacity = max(capacity, 1)
    refill_rate = float(settings_map.get("refill_rate", requests_per_min / 60.0) or (requests_per_min / 60.0))
    block_threshold = float(settings_map.get("block_threshold", getattr(settings, "block_threshold", 0.72)) or getattr(settings, "block_threshold", 0.72))
    monitor_threshold = float(settings_map.get("monitor_threshold", getattr(settings, "monitor_threshold", 0.48)) or getattr(settings, "monitor_threshold", 0.48))
    policy = {
        **best,
        "matched": True,
        "matched_path": str(best.get("_matched_path") or getattr(request_record, "path", "/")),
        "bucket_scope": str(settings_map.get("bucket_scope", "ip") or "ip"),
        "requests_per_min": requests_per_min,
        "capacity": capacity,
        "refill_rate": _round_float(refill_rate, 4),
        "block_threshold": _round_float(block_threshold, 3),
        "monitor_threshold": _round_float(monitor_threshold, 3),
        "ddos_monitor_hits": int(settings_map.get("ddos_monitor_hits", getattr(settings, "ddos_monitor_request_threshold", 14)) or getattr(settings, "ddos_monitor_request_threshold", 14)),
        "ddos_block_hits": int(settings_map.get("ddos_block_hits", getattr(settings, "ddos_block_request_threshold", 24)) or getattr(settings, "ddos_block_request_threshold", 24)),
        "ddos_monitor_pressure": _round_float(settings_map.get("ddos_monitor_pressure", getattr(settings, "ddos_monitor_pressure_threshold", 0.85)), 3),
        "ddos_block_pressure": _round_float(settings_map.get("ddos_block_pressure", getattr(settings, "ddos_block_pressure_threshold", 0.97)), 3),
        "connection_monitor_per_ip": int(settings_map.get("connection_monitor_per_ip", getattr(settings, "connection_monitor_per_ip_threshold", 6)) or getattr(settings, "connection_monitor_per_ip_threshold", 6)),
        "connection_block_per_ip": int(settings_map.get("connection_block_per_ip", getattr(settings, "connection_block_per_ip_threshold", 12)) or getattr(settings, "connection_block_per_ip_threshold", 12)),
        "connection_new_per_second_monitor": int(settings_map.get("connection_new_per_second_monitor", getattr(settings, "connection_monitor_new_connections_per_second", 4)) or getattr(settings, "connection_monitor_new_connections_per_second", 4)),
        "connection_new_per_second_block": int(settings_map.get("connection_new_per_second_block", getattr(settings, "connection_block_new_connections_per_second", 8)) or getattr(settings, "connection_block_new_connections_per_second", 8)),
        "connection_sessions_monitor": int(settings_map.get("connection_sessions_monitor", getattr(settings, "connection_monitor_sessions_per_source", 3)) or getattr(settings, "connection_monitor_sessions_per_source", 3)),
        "connection_sessions_block": int(settings_map.get("connection_sessions_block", getattr(settings, "connection_block_sessions_per_source", 6)) or getattr(settings, "connection_block_sessions_per_source", 6)),
        "resolved_at": to_iso(),
    }
    return policy


def merge_rate_limit_policy(
    base_policy: Mapping[str, object],
    endpoint_policy: Mapping[str, object],
    request_record,
    settings,
) -> Dict[str, object]:
    merged = dict(base_policy or {})
    endpoint_requests = int(endpoint_policy.get("requests_per_min", getattr(settings, "rate_limit_max_requests", 30)) or getattr(settings, "rate_limit_max_requests", 30))
    endpoint_capacity = int(endpoint_policy.get("capacity", endpoint_requests) or endpoint_requests)
    endpoint_refill_rate = float(endpoint_policy.get("refill_rate", endpoint_requests / 60.0) or (endpoint_requests / 60.0))

    if merged:
        merged["requests_per_min"] = min(int(merged.get("requests_per_min", endpoint_requests) or endpoint_requests), endpoint_requests)
        merged["capacity"] = min(int(merged.get("capacity", endpoint_capacity) or endpoint_capacity), endpoint_capacity)
        merged["refill_rate"] = min(float(merged.get("refill_rate", endpoint_refill_rate) or endpoint_refill_rate), endpoint_refill_rate)
    else:
        merged.update(
            {
                "requests_per_min": endpoint_requests,
                "capacity": endpoint_capacity,
                "refill_rate": endpoint_refill_rate,
            }
        )

    bucket_scope = str(endpoint_policy.get("bucket_scope", merged.get("bucket_scope", "ip")) or "ip")
    scope_key = str(getattr(request_record, "remote_addr", "") or "unknown")
    if bucket_scope == "ip_endpoint":
        scope_key = "{0}|ep:{1}".format(scope_key, endpoint_policy.get("policy_id", "default"))

    reasons = list(merged.get("reasons") or [])
    endpoint_reason = "Endpoint policy {0} applies {1} sensitivity on {2}.".format(
        endpoint_policy.get("name", "scope"),
        endpoint_policy.get("sensitivity", "standard"),
        endpoint_policy.get("path_pattern", "/*"),
    )
    if endpoint_reason not in reasons:
        reasons.append(endpoint_reason)

    merged.update(
        {
            "scope": bucket_scope,
            "rate_limit_key": scope_key,
            "bucket_scope": bucket_scope,
            "endpoint_policy_id": endpoint_policy.get("policy_id", ""),
            "endpoint_policy_name": endpoint_policy.get("name", ""),
            "endpoint_policy_sensitivity": endpoint_policy.get("sensitivity", "standard"),
            "endpoint_policy_source": endpoint_policy.get("source", "builtin"),
            "reasons": reasons,
        }
    )
    return merged


def analyze_security_scope(
    settings,
    custom_policies: Iterable[Mapping[str, object]],
    telemetry: Mapping[str, object],
    layer4_telemetry: Mapping[str, object] | None = None,
    proxy_transport_telemetry: Mapping[str, object] | None = None,
    pre_app_filter_telemetry: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    builtins = default_endpoint_policies(settings)
    custom_items = []
    for item in custom_policies:
        custom_items.append(
            {
                "policy_id": item.get("policy_id", ""),
                "name": item.get("name", "Custom policy"),
                "description": item.get("description", ""),
                "path_pattern": item.get("path_pattern", "/*"),
                "methods": _safe_methods(item.get("methods") or ["*"]),
                "priority": int(item.get("priority", 50) or 50),
                "sensitivity": str(item.get("sensitivity") or "protected"),
                "settings": dict(item.get("settings") or {}),
                "source": item.get("source", "custom"),
                "is_enabled": bool(item.get("is_enabled", True)),
                "created_at": item.get("created_at", ""),
                "updated_at": item.get("updated_at", ""),
            }
        )

    top_paths = list(telemetry.get("top_paths") or [])
    return {
        "generated_at": to_iso(),
        "ddos_protection": {
            "enabled": bool(getattr(settings, "ddos_protection_enabled", True)),
            "monitor_request_threshold": int(getattr(settings, "ddos_monitor_request_threshold", 14) or 14),
            "block_request_threshold": int(getattr(settings, "ddos_block_request_threshold", 24) or 24),
            "monitor_pressure_threshold": _round_float(float(getattr(settings, "ddos_monitor_pressure_threshold", 0.85) or 0.85), 3),
            "block_pressure_threshold": _round_float(float(getattr(settings, "ddos_block_pressure_threshold", 0.97) or 0.97), 3),
            "rate_limit_backend": str(getattr(settings, "rate_limit_backend", "auto") or "auto"),
            "adaptive_rate_limiting_enabled": bool(getattr(settings, "adaptive_rate_limiting_enabled", False)),
        },
        "layer4_protection": {
            "enabled": bool(getattr(settings, "connection_tracking_enabled", True)),
            "transport_scope": "application_gateway",
            "half_open_mode": str((layer4_telemetry or {}).get("half_open_mode") or "application_approximation"),
            "window_seconds": int(getattr(settings, "connection_window_seconds", 30) or 30),
            "stale_seconds": int(getattr(settings, "connection_stale_seconds", 20) or 20),
            "monitor_active_threshold": int(getattr(settings, "connection_monitor_active_threshold", 6) or 6),
            "block_active_threshold": int(getattr(settings, "connection_block_active_threshold", 12) or 12),
            "monitor_burst_threshold": int(getattr(settings, "connection_monitor_burst_threshold", 10) or 10),
            "block_burst_threshold": int(getattr(settings, "connection_block_burst_threshold", 18) or 18),
            "monitor_stale_threshold": int(getattr(settings, "connection_monitor_stale_threshold", 2) or 2),
            "block_stale_threshold": int(getattr(settings, "connection_block_stale_threshold", 5) or 5),
            "per_connection_throttling": {
                "connections_per_ip": {
                    "monitor": int(getattr(settings, "connection_monitor_per_ip_threshold", 6) or 6),
                    "block": int(getattr(settings, "connection_block_per_ip_threshold", 12) or 12),
                },
                "new_connections_per_second": {
                    "monitor": int(getattr(settings, "connection_monitor_new_connections_per_second", 4) or 4),
                    "block": int(getattr(settings, "connection_block_new_connections_per_second", 8) or 8),
                },
                "concurrent_sessions_per_source": {
                    "monitor": int(getattr(settings, "connection_monitor_sessions_per_source", 3) or 3),
                    "block": int(getattr(settings, "connection_block_sessions_per_source", 6) or 6),
                },
                "telemetry": {
                    "top_new_connection_ips": list((layer4_telemetry or {}).get("top_new_connection_ips") or []),
                    "top_session_sources": list((layer4_telemetry or {}).get("top_session_sources") or []),
                    "max_new_connections_per_second": int((layer4_telemetry or {}).get("max_new_connections_per_second") or 0),
                    "max_concurrent_sessions_per_source": int((layer4_telemetry or {}).get("max_concurrent_sessions_per_source") or 0),
                },
            },
            "active_connections_total": int((layer4_telemetry or {}).get("active_connections_total") or 0),
            "tracked_ips": int((layer4_telemetry or {}).get("tracked_ips") or 0),
            "top_active_ips": list((layer4_telemetry or {}).get("top_active_ips") or []),
            "transport_awareness": {
                "enabled": bool(getattr(settings, "transport_awareness_enabled", True)),
                "scope_modes": ["application_inference", "reverse_proxy_enriched"],
                "supported_proxy_headers": {
                    "transport_protocol": [
                        "X-WAF-Transport-Protocol",
                        "X-Transport-Protocol",
                        "X-Forwarded-Proto",
                    ],
                    "tcp_flags": ["X-WAF-TCP-Flags", "X-TCP-Flags"],
                    "connection_reset": ["X-WAF-Connection-Reset", "X-Connection-Reset", "X-Upstream-Reset"],
                    "session_established": ["X-WAF-Session-Established", "X-Session-Established"],
                    "connection_duration_ms": [
                        "X-WAF-Connection-Duration-Ms",
                        "X-Connection-Duration-Ms",
                        "X-Upstream-Connection-Duration-Ms",
                    ],
                    "retry_count": ["X-WAF-Retry-Count", "X-Retry-Count", "X-Upstream-Retry-Count"],
                    "timeout_hint": [
                        "X-WAF-Upstream-Timeout",
                        "X-Upstream-Timeout",
                        "X-WAF-Request-Timeout",
                        "X-Request-Timeout",
                    ],
                    "transport_valid": ["X-WAF-Transport-Valid", "X-Transport-Valid"],
                    "malformed_transport": ["X-WAF-Malformed-Transport", "X-Malformed-Transport"],
                },
                "syn_monitor_burst_threshold": int(getattr(settings, "transport_syn_monitor_burst_threshold", 6) or 6),
                "syn_block_burst_threshold": int(getattr(settings, "transport_syn_block_burst_threshold", 10) or 10),
                "reset_monitor_stale_threshold": int(getattr(settings, "transport_reset_monitor_stale_threshold", 1) or 1),
                "reset_block_stale_threshold": int(getattr(settings, "transport_reset_block_stale_threshold", 2) or 2),
                "abnormal_session_monitor_score": int(getattr(settings, "transport_abnormal_session_monitor_score", 4) or 4),
                "abnormal_session_block_score": int(getattr(settings, "transport_abnormal_session_block_score", 6) or 6),
                "udp_monitor_burst_threshold": int(getattr(settings, "transport_udp_monitor_burst_threshold", 5) or 5),
                "udp_block_burst_threshold": int(getattr(settings, "transport_udp_block_burst_threshold", 9) or 9),
                "churn_monitor_ratio": _round_float(float(getattr(settings, "transport_churn_monitor_ratio", 2.5) or 2.5), 3),
                "churn_block_ratio": _round_float(float(getattr(settings, "transport_churn_block_ratio", 4.0) or 4.0), 3),
                "short_lived_duration_ms_threshold": int(getattr(settings, "transport_short_lived_duration_ms_threshold", 250) or 250),
                "short_lived_monitor_score": int(getattr(settings, "transport_short_lived_monitor_score", 3) or 3),
                "short_lived_block_score": int(getattr(settings, "transport_short_lived_block_score", 5) or 5),
                "retry_monitor_score": int(getattr(settings, "transport_retry_monitor_score", 3) or 3),
                "retry_block_score": int(getattr(settings, "transport_retry_block_score", 5) or 5),
                "malformed_monitor_score": int(getattr(settings, "transport_malformed_monitor_score", 2) or 2),
                "malformed_block_score": int(getattr(settings, "transport_malformed_block_score", 4) or 4),
                "telemetry": {
                    "syn_like_events": int(telemetry.get("syn_like_events") or 0),
                    "connection_reset_events": int(telemetry.get("connection_reset_events") or 0),
                    "abnormal_session_events": int(telemetry.get("abnormal_session_events") or 0),
                    "udp_transport_events": int(telemetry.get("udp_transport_events") or 0),
                    "connection_churn_events": int(telemetry.get("connection_churn_events") or 0),
                    "short_lived_abusive_events": int(telemetry.get("short_lived_abusive_events") or 0),
                    "retry_timeout_events": int(telemetry.get("retry_timeout_events") or 0),
                    "malformed_transport_events": int(telemetry.get("malformed_transport_events") or 0),
                    "transport_enriched_requests": int(telemetry.get("transport_enriched_requests") or 0),
                },
            },
            "socket_proxy_controls": {
                "enabled": bool((proxy_transport_telemetry or {}).get("enabled", getattr(settings, "proxy_transport_controls_enabled", True))),
                "connect_timeout_seconds": _round_float(float((proxy_transport_telemetry or {}).get("connect_timeout_seconds", getattr(settings, "proxy_connect_timeout_seconds", 3.0)) or getattr(settings, "proxy_connect_timeout_seconds", 3.0)), 3),
                "read_timeout_seconds": _round_float(float((proxy_transport_telemetry or {}).get("read_timeout_seconds", getattr(settings, "proxy_read_timeout_seconds", 10.0)) or getattr(settings, "proxy_read_timeout_seconds", 10.0)), 3),
                "idle_pool_recycle_seconds": int((proxy_transport_telemetry or {}).get("idle_pool_recycle_seconds", getattr(settings, "proxy_idle_pool_recycle_seconds", 30)) or getattr(settings, "proxy_idle_pool_recycle_seconds", 30)),
                "upstream_pool_connections": int((proxy_transport_telemetry or {}).get("upstream_pool_connections", getattr(settings, "proxy_upstream_pool_connections", 16)) or getattr(settings, "proxy_upstream_pool_connections", 16)),
                "upstream_pool_maxsize": int((proxy_transport_telemetry or {}).get("upstream_pool_maxsize", getattr(settings, "proxy_upstream_pool_maxsize", 32)) or getattr(settings, "proxy_upstream_pool_maxsize", 32)),
                "upstream_concurrency_limit": int((proxy_transport_telemetry or {}).get("upstream_concurrency_limit", getattr(settings, "proxy_upstream_concurrency_limit", 24)) or getattr(settings, "proxy_upstream_concurrency_limit", 24)),
                "upstream_pool_block": bool((proxy_transport_telemetry or {}).get("upstream_pool_block", getattr(settings, "proxy_upstream_pool_block", True))),
                "keepalive_abuse_protection_enabled": bool((proxy_transport_telemetry or {}).get("keepalive_abuse_protection_enabled", getattr(settings, "proxy_keepalive_abuse_protection_enabled", True))),
                "keepalive_monitor_score": int((proxy_transport_telemetry or {}).get("keepalive_monitor_score", getattr(settings, "proxy_keepalive_monitor_score", 3)) or getattr(settings, "proxy_keepalive_monitor_score", 3)),
                "keepalive_block_score": int((proxy_transport_telemetry or {}).get("keepalive_block_score", getattr(settings, "proxy_keepalive_block_score", 5)) or getattr(settings, "proxy_keepalive_block_score", 5)),
                "telemetry": {
                    "active_upstream_requests": int((proxy_transport_telemetry or {}).get("active_upstream_requests") or 0),
                    "max_active_upstream_requests": int((proxy_transport_telemetry or {}).get("max_active_upstream_requests") or 0),
                    "idle_recycles": int((proxy_transport_telemetry or {}).get("idle_recycles") or 0),
                    "pool_protection_blocks": int((proxy_transport_telemetry or {}).get("pool_protection_blocks") or 0),
                    "keepalive_close_events": int((proxy_transport_telemetry or {}).get("keepalive_close_events") or 0),
                    "keepalive_abuse_events": int((proxy_transport_telemetry or {}).get("keepalive_abuse_events") or 0),
                    "keepalive_block_events": int((proxy_transport_telemetry or {}).get("keepalive_block_events") or 0),
                    "total_proxied_requests": int((proxy_transport_telemetry or {}).get("total_proxied_requests") or 0),
                    "session_generation": int((proxy_transport_telemetry or {}).get("session_generation") or 0),
                    "last_session_refresh_at": str((proxy_transport_telemetry or {}).get("last_session_refresh_at") or ""),
                },
            },
            "volumetric_pre_app_filtering": {
                "enabled": bool((pre_app_filter_telemetry or {}).get("enabled", getattr(settings, "pre_app_filter_enabled", True))),
                "mode": str((pre_app_filter_telemetry or {}).get("mode") or "wsgi_pre_app"),
                "summary": str((pre_app_filter_telemetry or {}).get("summary") or ""),
                "window_seconds": int((pre_app_filter_telemetry or {}).get("window_seconds", getattr(settings, "pre_app_filter_window_seconds", 10)) or getattr(settings, "pre_app_filter_window_seconds", 10)),
                "burst_window_seconds": _round_float(float((pre_app_filter_telemetry or {}).get("burst_window_seconds", 1.0) or 1.0), 3),
                "ip_request_threshold": int((pre_app_filter_telemetry or {}).get("ip_request_threshold", getattr(settings, "pre_app_filter_ip_request_threshold", 120)) or getattr(settings, "pre_app_filter_ip_request_threshold", 120)),
                "ip_burst_threshold": int((pre_app_filter_telemetry or {}).get("ip_burst_threshold", getattr(settings, "pre_app_filter_ip_burst_threshold", 40)) or getattr(settings, "pre_app_filter_ip_burst_threshold", 40)),
                "global_request_threshold": int((pre_app_filter_telemetry or {}).get("global_request_threshold", getattr(settings, "pre_app_filter_global_request_threshold", 600)) or getattr(settings, "pre_app_filter_global_request_threshold", 600)),
                "ip_bytes_threshold": int((pre_app_filter_telemetry or {}).get("ip_bytes_threshold", getattr(settings, "pre_app_filter_ip_bytes_threshold", 1048576)) or getattr(settings, "pre_app_filter_ip_bytes_threshold", 1048576)),
                "block_ttl_seconds": int((pre_app_filter_telemetry or {}).get("block_ttl_seconds", getattr(settings, "pre_app_filter_block_ttl_seconds", 15)) or getattr(settings, "pre_app_filter_block_ttl_seconds", 15)),
                "management_exempt_prefixes": list((pre_app_filter_telemetry or {}).get("management_exempt_prefixes") or []),
                "telemetry": dict((pre_app_filter_telemetry or {}).get("telemetry") or {}),
            },
        },
        "summary": "DDoS protection combines volumetric pre-app filtering, token buckets, endpoint-sensitive throttling, per-connection throttling, application-level connection guard telemetry, transport-layer anomaly detection for churn, short-lived abuse, retries/timeouts, malformed metadata, and socket/proxy transport controls for upstream timeouts, idle recycle, keep-alive abuse handling, and pool protection.",
        "built_in_policies": builtins,
        "custom_policies": custom_items,
        "telemetry": {
            "window_seconds": int(telemetry.get("window_seconds") or getattr(settings, "security_scope_window_seconds", 3600) or 3600),
            "top_paths": top_paths,
            "ddos_events": int(telemetry.get("ddos_events") or 0),
            "blocked_ddos_events": int(telemetry.get("blocked_ddos_events") or 0),
            "sensitive_path_hits": int(telemetry.get("sensitive_path_hits") or 0),
        },
    }
