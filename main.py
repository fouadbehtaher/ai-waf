import json
import logging
import mimetypes
import time
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import requests
from flask import Flask, Response, jsonify, redirect, render_template_string, request

from config import LOG_FILE, REPORTS_DIR, Settings, settings
from core.auth import (
    audit_details_from_request,
    get_current_auth_session,
    hash_password,
    issue_auth_token,
    require_auth,
    require_roles,
    verify_password,
)
from core import data_ingestion as di
from core import feature_engineering as fe
from core import mitigation as mi
from core import ml_models as ml
from core import rate_limiter as rl
from core import rule_engine as re
from core import endpoint_policy as ep
from core.connection_guard import ConnectionTracker
from core import transport_awareness as ta
from core.proxy_transport import ProxyTransportController, ProxyTransportControlError
from core.pre_app_filter import PreAppVolumetricFilter, VolumetricPreAppMiddleware
from core import adaptivity as ad
from core import auto_tuning as at
from core import dynamic_thresholds as dt
from core import adaptive_rate_limit as arl
from core import feedback_loop as fl
from core import ml_log_training as mlt
from core.simulation_suite import load_attack_simulation_report, run_attack_simulation_suite
from core.storage import Storage
from utils import discover_local_ipv4_addresses, shorten


logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
FRONTEND_SESSION_COOKIE = "waf_session"
MANAGEABLE_SETTING_FIELDS = {
    "backend_base_url",
    "request_timeout_seconds",
    "pre_app_filter_enabled",
    "pre_app_filter_window_seconds",
    "pre_app_filter_ip_request_threshold",
    "pre_app_filter_ip_burst_threshold",
    "pre_app_filter_global_request_threshold",
    "pre_app_filter_ip_bytes_threshold",
    "pre_app_filter_block_ttl_seconds",
    "proxy_transport_controls_enabled",
    "proxy_connect_timeout_seconds",
    "proxy_read_timeout_seconds",
    "proxy_idle_pool_recycle_seconds",
    "proxy_upstream_pool_connections",
    "proxy_upstream_pool_maxsize",
    "proxy_upstream_concurrency_limit",
    "proxy_upstream_pool_block",
    "proxy_keepalive_abuse_protection_enabled",
    "proxy_keepalive_monitor_score",
    "proxy_keepalive_block_score",
    "transparent_proxy",
    "redis_url",
    "rate_limit_backend",
    "redis_key_prefix",
    "block_threshold",
    "monitor_threshold",
    "analytics_window_seconds",
    "dashboard_window_seconds",
    "recent_event_limit",
    "security_scope_window_seconds",
    "connection_tracking_enabled",
    "connection_window_seconds",
    "connection_stale_seconds",
    "connection_monitor_active_threshold",
    "connection_block_active_threshold",
    "connection_monitor_burst_threshold",
    "connection_block_burst_threshold",
    "connection_monitor_stale_threshold",
    "connection_block_stale_threshold",
    "connection_monitor_per_ip_threshold",
    "connection_block_per_ip_threshold",
    "connection_monitor_new_connections_per_second",
    "connection_block_new_connections_per_second",
    "connection_monitor_sessions_per_source",
    "connection_block_sessions_per_source",
    "transport_awareness_enabled",
    "transport_syn_monitor_burst_threshold",
    "transport_syn_block_burst_threshold",
    "transport_reset_monitor_stale_threshold",
    "transport_reset_block_stale_threshold",
    "transport_abnormal_session_monitor_score",
    "transport_abnormal_session_block_score",
    "transport_udp_monitor_burst_threshold",
    "transport_udp_block_burst_threshold",
    "transport_churn_monitor_ratio",
    "transport_churn_block_ratio",
    "transport_short_lived_duration_ms_threshold",
    "transport_short_lived_monitor_score",
    "transport_short_lived_block_score",
    "transport_retry_monitor_score",
    "transport_retry_block_score",
    "transport_malformed_monitor_score",
    "transport_malformed_block_score",
    "rate_limit_window_seconds",
    "rate_limit_max_requests",
    "token_bucket_capacity",
    "token_bucket_refill_rate",
    "ddos_protection_enabled",
    "ddos_monitor_request_threshold",
    "ddos_block_request_threshold",
    "ddos_monitor_pressure_threshold",
    "ddos_block_pressure_threshold",
    "temporary_blacklist_seconds",
    "targeted_block_ttl_seconds",
    "blacklist_repeat_offense_threshold",
    "max_body_length",
    "max_payload_preview_chars",
    "heuristic_weight",
    "ml_weight",
    "auth_token_ttl_seconds",
    "auto_tuning_enabled",
    "auto_tuning_window_seconds",
    "auto_tuning_min_samples",
    "auto_tuning_cooldown_seconds",
    "auto_tuning_target_false_positive_rate",
    "auto_tuning_target_attack_rate",
    "dynamic_thresholds_enabled",
    "dynamic_thresholds_window_seconds",
    "dynamic_thresholds_min_samples",
    "dynamic_thresholds_std_multiplier",
    "dynamic_thresholds_min_block_threshold",
    "dynamic_thresholds_max_block_threshold",
    "adaptive_rate_limiting_enabled",
    "adaptive_rate_limit_window_seconds",
    "adaptive_rate_limit_normal_requests_per_min",
    "adaptive_rate_limit_elevated_requests_per_min",
    "adaptive_rate_limit_suspicious_requests_per_min",
    "adaptive_rate_limit_restricted_requests_per_min",
    "adaptive_rate_limit_min_suspicion_score",
    "adaptive_rate_limit_suspicious_request_threshold",
    "adaptive_rate_limit_unique_paths_threshold",
    "adaptive_rate_limit_block_ratio_threshold",
    "adaptive_rate_limit_flagged_ratio_threshold",
    "adaptive_rate_limit_avg_risk_threshold",
    "feedback_loop_enabled",
    "feedback_loop_window_seconds",
    "feedback_loop_min_feedback",
    "feedback_loop_cooldown_seconds",
    "feedback_loop_relax_step",
    "feedback_loop_harden_step",
    "ml_log_training_enabled",
    "ml_log_training_window_seconds",
    "ml_log_training_min_labeled_rows",
    "ml_log_training_min_benign_rows",
    "ml_log_training_min_malicious_rows",
    "ml_log_training_cooldown_seconds",
    "ml_log_training_algorithm",
}

HOME_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ settings.app_name }}</title>
    <style>
        :root {
            --bg: #f4f0e6;
            --panel: #fffaf3;
            --ink: #13293d;
            --muted: #607080;
            --accent: #ab4e1a;
            --border: #eadfce;
            --good: #1f7a47;
            --bad: #a11d33;
        }
        body {
            margin: 0;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background:
                radial-gradient(circle at top right, rgba(171, 78, 26, 0.10), transparent 28%),
                linear-gradient(180deg, #fbf7f0 0%, #f4f0e6 100%);
            color: var(--ink);
        }
        main {
            max-width: 1040px;
            margin: 0 auto;
            padding: 40px 18px 60px;
        }
        .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 20px;
            box-shadow: 0 18px 40px rgba(19, 41, 61, 0.08);
            padding: 28px;
            margin-bottom: 18px;
        }
        h1 {
            margin: 0 0 10px;
            font-size: 2.4rem;
        }
        p, li {
            color: var(--muted);
            line-height: 1.65;
        }
        code, pre {
            background: #f6efe3;
            border-radius: 14px;
            display: block;
            padding: 14px;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin: 22px 0;
        }
        .button {
            padding: 12px 18px;
            border-radius: 999px;
            text-decoration: none;
            color: white;
            background: var(--ink);
        }
        .button.alt {
            background: white;
            color: var(--ink);
            border: 1px solid var(--border);
        }
        .callout {
            border-left: 4px solid var(--accent);
            padding-left: 14px;
        }
    </style>
</head>
<body>
    <main>
        <section class="panel">
            <h1>{{ settings.app_name }}</h1>
            <p>
                This version behaves like a real gateway: it captures requests, extracts behavioral features,
                applies hybrid scoring plus rules, persists telemetry in SQLite, manages blacklists, exports reports,
                and can proxy traffic to a backend service.
            </p>
            <div class="actions">
                <a class="button" href="/dashboard">Open dashboard</a>
                <a class="button alt" href="/reports/summary">Open summary report</a>
                <a class="button alt" href="/health">Health check</a>
            </div>
            <p class="callout">
                Backend target: <strong>{{ settings.backend_base_url }}</strong>
            </p>
        </section>

        <section class="panel">
            <h2>Run the sample backend</h2>
            <pre>python sample_backend.py</pre>
            <h2>Run the WAF</h2>
            <pre>python main.py
python serve.py</pre>
            <h2>Try requests through the WAF</h2>
            <pre>curl "http://127.0.0.1:5000/proxy/api/hello?name=world"

curl "http://127.0.0.1:5000/protected?message=hello"

curl "http://127.0.0.1:5000/protected?message=bad_keyword"

curl -X POST "http://127.0.0.1:5000/proxy/login" -H "Content-Type: application/json" -d "{\"query\":\"SELECT * FROM users\"}"</pre>
        </section>
    </main>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ settings.app_name }} Dashboard</title>
    <style>
        :root {
            --bg: #eef5ef;
            --panel: #fcfffb;
            --ink: #143229;
            --muted: #60736d;
            --accent: #0f766e;
            --border: #dce7de;
            --good: #1f7a47;
            --warn: #b7791f;
            --bad: #b42318;
        }
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(15, 118, 110, 0.10), transparent 30%),
                linear-gradient(180deg, #f8fbf8 0%, #eef5ef 100%);
            color: var(--ink);
        }
        main {
            max-width: 1240px;
            margin: 0 auto;
            padding: 28px 18px 44px;
        }
        .hero {
            display: flex;
            justify-content: space-between;
            align-items: end;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 18px;
        }
        .toolbar {
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
        }
        .toolbar a {
            text-decoration: none;
            color: var(--accent);
        }
        .grid {
            display: grid;
            gap: 16px;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            margin-bottom: 18px;
        }
        .card, .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 18px;
            box-shadow: 0 14px 34px rgba(20, 50, 41, 0.06);
        }
        .card {
            padding: 18px;
        }
        .card span {
            display: block;
            font-size: 0.92rem;
            color: var(--muted);
            margin-bottom: 8px;
        }
        .card strong {
            font-size: 1.9rem;
        }
        .panel {
            padding: 16px;
            margin-bottom: 18px;
        }
        .columns {
            display: grid;
            gap: 16px;
            grid-template-columns: 1fr 1fr;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 10px;
            border-top: 1px solid var(--border);
            vertical-align: top;
            text-align: left;
        }
        th {
            color: var(--muted);
            font-size: 0.88rem;
        }
        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .allow { background: rgba(31, 122, 71, 0.12); color: var(--good); }
        .monitor { background: rgba(183, 121, 31, 0.14); color: var(--warn); }
        .block { background: rgba(180, 35, 24, 0.12); color: var(--bad); }
        .muted {
            color: var(--muted);
        }
        @media (max-width: 900px) {
            .columns {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <main>
        <section class="hero">
            <div>
                <h1>{{ settings.app_name }} Dashboard</h1>
                <p class="muted">
                    Window: last {{ snapshot.window_seconds }} seconds | Average latency {{ snapshot.avg_latency_ms }} ms
                </p>
            </div>
            <div class="toolbar">
                <a href="/">Home</a>
                <a href="/reports/summary">Summary report</a>
                <a href="/reports/events.csv">CSV export</a>
                <a href="/api/model">Active model</a>
            </div>
        </section>

        <section class="grid">
            <article class="card"><span>Total requests</span><strong>{{ snapshot.total_requests }}</strong></article>
            <article class="card"><span>Allowed</span><strong style="color: var(--good)">{{ snapshot.allowed }}</strong></article>
            <article class="card"><span>Monitored</span><strong style="color: var(--warn)">{{ snapshot.monitored }}</strong></article>
            <article class="card"><span>Blocked</span><strong style="color: var(--bad)">{{ snapshot.blocked }}</strong></article>
            <article class="card"><span>Unique IPs</span><strong>{{ snapshot.unique_ips }}</strong></article>
            <article class="card"><span>Blacklist size</span><strong>{{ snapshot.blacklist_size }}</strong></article>
        </section>

        <section class="columns">
            <article class="panel">
                <h2>Top Attack Types</h2>
                <table>
                    <thead><tr><th>Attack type</th><th>Count</th></tr></thead>
                    <tbody>
                    {% if snapshot.top_attack_types %}
                        {% for item in snapshot.top_attack_types %}
                        <tr><td>{{ item.label or item.attack_type }}</td><td>{{ item.count }}</td></tr>
                        {% endfor %}
                    {% else %}
                        <tr><td colspan="2">No attack categories detected yet.</td></tr>
                    {% endif %}
                    </tbody>
                </table>
            </article>
            <article class="panel">
                <h2>Top Offending Sources</h2>
                <table>
                    <thead><tr><th>IP</th><th>Total</th><th>Blocked</th></tr></thead>
                    <tbody>
                    {% if snapshot.top_offenders %}
                        {% for item in snapshot.top_offenders %}
                        <tr><td>{{ item.remote_addr }}</td><td>{{ item.total_requests }}</td><td>{{ item.blocked_requests }}</td></tr>
                        {% endfor %}
                    {% else %}
                        <tr><td colspan="3">No traffic captured yet.</td></tr>
                    {% endif %}
                    </tbody>
                </table>
            </article>
        </section>

        <section class="panel">
            <h2>Recent Requests</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Request</th>
                        <th>Source</th>
                        <th>Action</th>
                        <th>Risk</th>
                        <th>Latency</th>
                        <th>Attack types</th>
                        <th>Payload preview</th>
                    </tr>
                </thead>
                <tbody>
                {% if snapshot.events %}
                    {% for event in snapshot.events %}
                    <tr>
                        <td>{{ event.timestamp }}</td>
                        <td>{{ event.method }} {{ event.path }}</td>
                        <td>{{ event.remote_addr }}</td>
                        <td><span class="pill {{ event.action }}">{{ event.action }}</span></td>
                        <td>{{ "%.2f"|format(event.risk_score) }}</td>
                        <td>{{ "%.2f"|format(event.latency_ms) }} ms</td>
                        <td>{{ event.attack_types|join(", ") if event.attack_types else "-" }}</td>
                        <td>{{ event.payload_preview or "-" }}</td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr><td colspan="8">No traffic recorded yet.</td></tr>
                {% endif %}
                </tbody>
            </table>
        </section>
    </main>
</body>
</html>
"""

SUMMARY_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>{{ settings.app_name }} Summary Report</title>
    <style>
        body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; margin: 32px; color: #13293d; }
        h1, h2 { margin-bottom: 10px; }
        pre { background: #f6efe3; border-radius: 14px; padding: 16px; white-space: pre-wrap; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #e4d8c7; padding: 10px; text-align: left; }
        th { background: #faf1e5; }
    </style>
</head>
<body>
    <h1>{{ settings.app_name }} Summary Report</h1>
    <p>Generated at {{ summary.generated_at }} for the last {{ summary.window_seconds }} seconds.</p>

    <h2>Executive Summary</h2>
    <pre>{{ summary_text }}</pre>

    <h2>Top Attack Types</h2>
    <table>
        <tr><th>Attack type</th><th>Count</th></tr>
        {% for item in summary.top_attack_types %}
        <tr><td>{{ item.label or item.attack_type }}</td><td>{{ item.count }}</td></tr>
        {% endfor %}
    </table>

    <h2>Blacklist</h2>
    <table>
        <tr><th>IP</th><th>Reason</th><th>Source</th><th>Expires at</th></tr>
        {% if summary.blacklist %}
            {% for item in summary.blacklist %}
            <tr><td>{{ item.ip_address }}</td><td>{{ item.reason }}</td><td>{{ item.source }}</td><td>{{ item.expires_at or "manual" }}</td></tr>
            {% endfor %}
        {% else %}
            <tr><td colspan="4">No blacklisted IPs.</td></tr>
        {% endif %}
    </table>
</body>
</html>
"""


def _normalize_forwarded_path(subpath: str) -> str:
    if not subpath:
        return "/"
    return "/" + subpath.lstrip("/")


def _build_summary_text(summary: dict) -> str:
    top_attack_types = ", ".join(
        "{0} ({1})".format(item.get("label", item["attack_type"]), item["count"]) for item in summary["top_attack_types"]
    ) or "None"
    top_sources = ", ".join(
        "{0} ({1} blocked)".format(item["remote_addr"], item["blocked_requests"]) for item in summary["top_offenders"]
    ) or "None"
    active_model = summary.get("active_model") or {}

    return "\n".join(
        [
            "Total requests: {0}".format(summary["total_requests"]),
            "Allowed: {0}".format(summary["allowed"]),
            "Monitored: {0}".format(summary["monitored"]),
            "Blocked: {0}".format(summary["blocked"]),
            "Average latency: {0} ms".format(summary["avg_latency_ms"]),
            "Average risk score: {0}".format(summary["avg_risk_score"]),
            "Top attack types: {0}".format(top_attack_types),
            "Top sources: {0}".format(top_sources),
            "Blacklist size: {0}".format(summary["blacklist_size"]),
            "Active model: {0}".format(active_model.get("model_version", "heuristic fallback")),
        ]
    )


def _parse_int_arg(name: str, default: int, minimum: int = 1, maximum: Optional[int] = None) -> int:
    raw_value = request.args.get(name, default)
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        parsed = default
    parsed = max(parsed, minimum)
    if maximum is not None:
        parsed = min(parsed, maximum)
    return parsed


def _settings_field_map() -> dict:
    return {field.name: field for field in fields(Settings)}


def _coerce_setting_value(base_settings: Settings, key: str, raw_value):
    if key not in MANAGEABLE_SETTING_FIELDS:
        raise ValueError("Setting '{0}' is not editable from the dashboard".format(key))

    current_value = getattr(base_settings, key)
    if isinstance(current_value, bool):
        if isinstance(raw_value, bool):
            return raw_value
        return str(raw_value).strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(current_value, int) and not isinstance(current_value, bool):
        return int(raw_value)
    if isinstance(current_value, float):
        return float(raw_value)
    if isinstance(current_value, Path):
        return Path(str(raw_value))
    return str(raw_value)


def _serialize_runtime_settings(current_settings: Settings) -> dict:
    payload = {}
    for key in sorted(MANAGEABLE_SETTING_FIELDS):
        value = getattr(current_settings, key)
        payload[key] = str(value) if isinstance(value, Path) else value
    return payload


def _coerce_endpoint_policy_payload(payload: dict, current_settings: Settings) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Endpoint policy payload must be an object.")

    name = str(payload.get("name") or "").strip()
    path_pattern = str(payload.get("path_pattern") or "").strip()
    if not name:
        raise ValueError("Endpoint policy name is required.")
    if not path_pattern:
        raise ValueError("Endpoint policy path_pattern is required.")

    raw_methods = payload.get("methods")
    if isinstance(raw_methods, str):
        methods = [item.strip().upper() for item in raw_methods.split(",") if item.strip()]
    elif isinstance(raw_methods, list):
        methods = [str(item).strip().upper() for item in raw_methods if str(item).strip()]
    else:
        methods = ["*"]
    methods = methods or ["*"]

    sensitivity = str(payload.get("sensitivity") or "protected").strip().lower()
    if sensitivity not in {"standard", "protected", "critical"}:
        raise ValueError("Endpoint policy sensitivity must be standard, protected, or critical.")

    bucket_scope = str(payload.get("bucket_scope") or "ip_endpoint").strip().lower()
    if bucket_scope not in {"ip", "ip_endpoint"}:
        raise ValueError("Endpoint policy bucket_scope must be ip or ip_endpoint.")

    priority = int(payload.get("priority", 50) or 50)
    settings_map = {
        "bucket_scope": bucket_scope,
        "requests_per_min": max(int(payload.get("requests_per_min", current_settings.rate_limit_max_requests) or current_settings.rate_limit_max_requests), 1),
        "ddos_monitor_hits": max(int(payload.get("ddos_monitor_hits", current_settings.ddos_monitor_request_threshold) or current_settings.ddos_monitor_request_threshold), 1),
        "ddos_block_hits": max(int(payload.get("ddos_block_hits", current_settings.ddos_block_request_threshold) or current_settings.ddos_block_request_threshold), 2),
        "ddos_monitor_pressure": round(float(payload.get("ddos_monitor_pressure", current_settings.ddos_monitor_pressure_threshold) or current_settings.ddos_monitor_pressure_threshold), 3),
        "ddos_block_pressure": round(float(payload.get("ddos_block_pressure", current_settings.ddos_block_pressure_threshold) or current_settings.ddos_block_pressure_threshold), 3),
        "connection_monitor_active": max(int(payload.get("connection_monitor_active", current_settings.connection_monitor_active_threshold) or current_settings.connection_monitor_active_threshold), 1),
        "connection_block_active": max(int(payload.get("connection_block_active", current_settings.connection_block_active_threshold) or current_settings.connection_block_active_threshold), 2),
        "connection_monitor_per_ip": max(int(payload.get("connection_monitor_per_ip", current_settings.connection_monitor_per_ip_threshold) or current_settings.connection_monitor_per_ip_threshold), 1),
        "connection_block_per_ip": max(int(payload.get("connection_block_per_ip", current_settings.connection_block_per_ip_threshold) or current_settings.connection_block_per_ip_threshold), 2),
        "connection_burst_monitor": max(int(payload.get("connection_burst_monitor", current_settings.connection_monitor_burst_threshold) or current_settings.connection_monitor_burst_threshold), 1),
        "connection_burst_block": max(int(payload.get("connection_burst_block", current_settings.connection_block_burst_threshold) or current_settings.connection_block_burst_threshold), 2),
        "connection_new_per_second_monitor": max(int(payload.get("connection_new_per_second_monitor", current_settings.connection_monitor_new_connections_per_second) or current_settings.connection_monitor_new_connections_per_second), 1),
        "connection_new_per_second_block": max(int(payload.get("connection_new_per_second_block", current_settings.connection_block_new_connections_per_second) or current_settings.connection_block_new_connections_per_second), 2),
        "connection_stale_monitor": max(int(payload.get("connection_stale_monitor", current_settings.connection_monitor_stale_threshold) or current_settings.connection_monitor_stale_threshold), 1),
        "connection_stale_block": max(int(payload.get("connection_stale_block", current_settings.connection_block_stale_threshold) or current_settings.connection_block_stale_threshold), 2),
        "connection_sessions_monitor": max(int(payload.get("connection_sessions_monitor", current_settings.connection_monitor_sessions_per_source) or current_settings.connection_monitor_sessions_per_source), 1),
        "connection_sessions_block": max(int(payload.get("connection_sessions_block", current_settings.connection_block_sessions_per_source) or current_settings.connection_block_sessions_per_source), 2),
    }

    raw_block_threshold = payload.get("block_threshold")
    raw_monitor_threshold = payload.get("monitor_threshold")
    if raw_block_threshold not in {None, ""}:
        settings_map["block_threshold"] = round(float(raw_block_threshold), 3)
    if raw_monitor_threshold not in {None, ""}:
        settings_map["monitor_threshold"] = round(float(raw_monitor_threshold), 3)

    if settings_map["ddos_block_hits"] <= settings_map["ddos_monitor_hits"]:
        settings_map["ddos_block_hits"] = settings_map["ddos_monitor_hits"] + 1
    if settings_map["ddos_block_pressure"] < settings_map["ddos_monitor_pressure"]:
        settings_map["ddos_block_pressure"] = settings_map["ddos_monitor_pressure"]
    if settings_map["connection_block_active"] <= settings_map["connection_monitor_active"]:
        settings_map["connection_block_active"] = settings_map["connection_monitor_active"] + 1
    if settings_map["connection_block_per_ip"] <= settings_map["connection_monitor_per_ip"]:
        settings_map["connection_block_per_ip"] = settings_map["connection_monitor_per_ip"] + 1
    if settings_map["connection_burst_block"] <= settings_map["connection_burst_monitor"]:
        settings_map["connection_burst_block"] = settings_map["connection_burst_monitor"] + 1
    if settings_map["connection_new_per_second_block"] <= settings_map["connection_new_per_second_monitor"]:
        settings_map["connection_new_per_second_block"] = settings_map["connection_new_per_second_monitor"] + 1
    if settings_map["connection_stale_block"] <= settings_map["connection_stale_monitor"]:
        settings_map["connection_stale_block"] = settings_map["connection_stale_monitor"] + 1
    if settings_map["connection_sessions_block"] <= settings_map["connection_sessions_monitor"]:
        settings_map["connection_sessions_block"] = settings_map["connection_sessions_monitor"] + 1

    description = str(payload.get("description") or "").strip()
    is_enabled = bool(payload.get("is_enabled", True))

    return {
        "policy_id": str(payload.get("policy_id") or "").strip() or None,
        "name": name,
        "description": description,
        "path_pattern": path_pattern,
        "methods": methods,
        "priority": priority,
        "sensitivity": sensitivity,
        "settings_map": settings_map,
        "is_enabled": is_enabled,
    }


def create_app(app_settings: Optional[Settings] = None, serve_frontend: bool = True) -> Flask:
    current_settings = app_settings or settings
    storage = Storage(current_settings.db_path, database_url=current_settings.database_url)
    storage.initialize(current_settings)
    model = ml.load_runtime_model(current_settings, active_metadata=storage.get_active_model_metadata())
    rate_limiter = rl.build_rate_limiter(current_settings)

    app = Flask(__name__)
    app.secret_key = current_settings.secret_key
    app.config["APP_SETTINGS"] = current_settings
    app.config["STORAGE"] = storage
    app.config["RISK_MODEL"] = model
    app.config["RATE_LIMITER"] = rate_limiter
    app.config["CONNECTION_TRACKER"] = ConnectionTracker()
    app.config["PROXY_TRANSPORT"] = ProxyTransportController()
    app.config["AUTO_TUNING_STATE"] = {"next_due_epoch": 0.0}
    app.config["FEEDBACK_LOOP_STATE"] = {"next_due_epoch": 0.0}
    app.config["ML_LOG_TRAINING_STATE"] = {"next_due_epoch": 0.0}

    def get_effective_settings() -> Settings:
        overrides = storage.get_runtime_setting_overrides()
        if not overrides:
            return current_settings

        safe_overrides = {}
        for key, value in overrides.items():
            try:
                safe_overrides[key] = _coerce_setting_value(current_settings, key, value)
            except (TypeError, ValueError):
                continue
        if not safe_overrides:
            return current_settings
        return current_settings.with_overrides(**safe_overrides)

    pre_app_filter = PreAppVolumetricFilter(settings_provider=get_effective_settings)
    app.config["PRE_APP_FILTER"] = pre_app_filter
    app.wsgi_app = VolumetricPreAppMiddleware(app.wsgi_app, pre_app_filter)

    def get_actor_context() -> dict:
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        return {
            "user_id": user.get("user_id"),
            "username": user.get("username", ""),
            "display_name": user.get("display_name", ""),
            "role": user.get("role", ""),
        }

    def record_audit(action: str, target_type: str, target_id: str = "", details: Optional[dict] = None) -> dict:
        actor = get_actor_context()
        merged_details = audit_details_from_request()
        if details:
            merged_details.update(details)
        return storage.log_audit_event(
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=merged_details,
            actor_user_id=actor.get("user_id"),
            actor_username=actor.get("username", ""),
        )

    def runtime_setting_refresh_required(changes: dict) -> bool:
        watched_fields = {
            "redis_url",
            "rate_limit_backend",
            "redis_key_prefix",
            "rate_limit_window_seconds",
            "rate_limit_max_requests",
            "token_bucket_capacity",
            "token_bucket_refill_rate",
            "proxy_transport_controls_enabled",
            "proxy_connect_timeout_seconds",
            "proxy_read_timeout_seconds",
            "proxy_idle_pool_recycle_seconds",
            "proxy_upstream_pool_connections",
            "proxy_upstream_pool_maxsize",
            "proxy_upstream_concurrency_limit",
            "proxy_upstream_pool_block",
            "proxy_keepalive_abuse_protection_enabled",
            "proxy_keepalive_monitor_score",
            "proxy_keepalive_block_score",
        }
        return any(key in watched_fields for key in (changes or {}))

    def get_latest_strategy_apply_event(action: str, strategy_source: str) -> Optional[dict]:
        direct_event = storage.get_latest_audit_event(action)
        adaptivity_event = storage.get_latest_audit_event("settings.adaptivity")
        if adaptivity_event:
            change_sources = dict((adaptivity_event.get("details") or {}).get("change_sources") or {})
            if strategy_source in change_sources.values():
                direct_epoch = float((direct_event or {}).get("created_at_epoch") or 0.0)
                adaptivity_epoch = float(adaptivity_event.get("created_at_epoch") or 0.0)
                if adaptivity_epoch >= direct_epoch:
                    return adaptivity_event
        return direct_event

    def get_auto_tuning_report(runtime_settings: Optional[Settings] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        telemetry = storage.get_auto_tuning_telemetry(active_settings.auto_tuning_window_seconds)
        latest_apply_event = get_latest_strategy_apply_event("settings.auto_tune", "auto_tuning")
        return at.analyze_auto_tuning(active_settings, telemetry, latest_apply_event=latest_apply_event)

    def get_dynamic_threshold_report(runtime_settings: Optional[Settings] = None, endpoint_policy: Optional[dict] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        telemetry = storage.get_dynamic_threshold_telemetry(
            active_settings.dynamic_thresholds_window_seconds,
            endpoint_policy=endpoint_policy,
        )
        return dt.analyze_dynamic_thresholds(active_settings, telemetry, endpoint_policy=endpoint_policy)

    def get_adaptive_rate_limit_report(runtime_settings: Optional[Settings] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        telemetry = storage.get_adaptive_rate_limit_telemetry(
            active_settings.adaptive_rate_limit_window_seconds,
            active_settings.adaptive_rate_limit_suspicious_request_threshold,
            active_settings.adaptive_rate_limit_unique_paths_threshold,
            active_settings.adaptive_rate_limit_block_ratio_threshold,
            active_settings.adaptive_rate_limit_flagged_ratio_threshold,
            active_settings.adaptive_rate_limit_avg_risk_threshold,
        )
        return arl.analyze_adaptive_rate_limit(active_settings, telemetry)

    def get_security_scope_report(runtime_settings: Optional[Settings] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        telemetry = storage.get_security_scope_telemetry(active_settings.security_scope_window_seconds)
        custom_policies = storage.list_endpoint_policies(enabled_only=False)
        layer4_telemetry = app.config["CONNECTION_TRACKER"].summary(active_settings)
        proxy_transport_telemetry = app.config["PROXY_TRANSPORT"].summary(active_settings)
        pre_app_filter_telemetry = app.config["PRE_APP_FILTER"].summary(active_settings)
        return ep.analyze_security_scope(
            active_settings,
            custom_policies,
            telemetry,
            layer4_telemetry=layer4_telemetry,
            proxy_transport_telemetry=proxy_transport_telemetry,
            pre_app_filter_telemetry=pre_app_filter_telemetry,
        )

    def get_feedback_loop_report(runtime_settings: Optional[Settings] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        telemetry = storage.get_feedback_loop_telemetry(active_settings.feedback_loop_window_seconds)
        latest_apply_event = get_latest_strategy_apply_event("settings.feedback_loop", "feedback_loop")
        return fl.analyze_feedback_loop(active_settings, telemetry, latest_apply_event=latest_apply_event)

    def get_adaptivity_report(runtime_settings: Optional[Settings] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        auto_tuning_report = get_auto_tuning_report(active_settings)
        feedback_loop_report = get_feedback_loop_report(active_settings)
        dynamic_threshold_report = get_dynamic_threshold_report(active_settings)
        latest_apply_event = storage.get_latest_audit_event("settings.adaptivity")
        return ad.analyze_adaptivity(
            active_settings,
            auto_tuning_report=auto_tuning_report,
            feedback_loop_report=feedback_loop_report,
            dynamic_threshold_report=dynamic_threshold_report,
            latest_apply_event=latest_apply_event,
        )

    def get_ml_log_training_report(runtime_settings: Optional[Settings] = None) -> dict:
        active_settings = runtime_settings or get_effective_settings()
        telemetry = storage.get_ml_log_training_telemetry(active_settings.ml_log_training_window_seconds)
        latest_apply_event = storage.get_latest_audit_event("model.logs_retrain")
        active_model = storage.get_active_model_metadata() or {}
        return mlt.analyze_ml_log_training(active_settings, telemetry, active_model=active_model, latest_apply_event=latest_apply_event)

    def apply_auto_tuning_changes(report: dict, runtime_settings: Settings, trigger: str, actor_username: str = "auto-tuner") -> dict:
        changes = dict((report or {}).get("recommendation", {}).get("changes") or {})
        if not changes:
            return {
                "applied": False,
                "message": "No auto-tuning changes were recommended.",
                "settings": _serialize_runtime_settings(runtime_settings),
                "report": report,
            }

        overrides = storage.set_runtime_setting_overrides(changes, updated_by=actor_username)
        updated_settings = get_effective_settings()
        if runtime_setting_refresh_required(changes):
            app.config["RATE_LIMITER"] = rl.build_rate_limiter(updated_settings)

        audit_payload = {
            "trigger": trigger,
            "mode": report.get("mode", "steady"),
            "changes": changes,
            "summary": report.get("recommendation", {}).get("summary", ""),
            "telemetry": report.get("telemetry", {}),
            "targets": report.get("targets", {}),
            "auto_tuning_enabled": bool(getattr(updated_settings, "auto_tuning_enabled", False)),
            "overrides": overrides,
        }
        record_audit("settings.auto_tune", "runtime_settings", "runtime", audit_payload)
        app.config["AUTO_TUNING_STATE"]["next_due_epoch"] = time.time() + max(int(updated_settings.auto_tuning_cooldown_seconds or 900), 60)

        return {
            "applied": True,
            "message": "Auto-tuning applied updated thresholds and rate limits.",
            "changes": changes,
            "settings": _serialize_runtime_settings(updated_settings),
            "report": get_auto_tuning_report(updated_settings),
        }

    def apply_feedback_loop_changes(report: dict, runtime_settings: Settings, trigger: str, actor_username: str = "feedback-loop") -> dict:
        changes = dict((report or {}).get("recommendation", {}).get("changes") or {})
        if not changes:
            return {
                "applied": False,
                "message": "No feedback-loop changes were recommended.",
                "settings": _serialize_runtime_settings(runtime_settings),
                "report": report,
            }

        overrides = storage.set_runtime_setting_overrides(changes, updated_by=actor_username)
        updated_settings = get_effective_settings()
        audit_payload = {
            "trigger": trigger,
            "mode": report.get("mode", "steady"),
            "changes": changes,
            "summary": report.get("recommendation", {}).get("summary", ""),
            "telemetry": report.get("telemetry", {}),
            "targets": report.get("targets", {}),
            "feedback_loop_enabled": bool(getattr(updated_settings, "feedback_loop_enabled", False)),
            "overrides": overrides,
        }
        record_audit("settings.feedback_loop", "runtime_settings", "runtime", audit_payload)
        app.config["FEEDBACK_LOOP_STATE"]["next_due_epoch"] = time.time() + max(int(updated_settings.feedback_loop_cooldown_seconds or 900), 60)

        return {
            "applied": True,
            "message": "Feedback loop applied updated thresholds from labeled request outcomes.",
            "changes": changes,
            "settings": _serialize_runtime_settings(updated_settings),
            "report": get_feedback_loop_report(updated_settings),
        }

    def apply_adaptivity_changes(
        report: dict,
        runtime_settings: Settings,
        trigger: str,
        actor_username: str = "adaptivity",
        automatic_only: bool = False,
    ) -> dict:
        recommendation = (report or {}).get("recommendation", {})
        changes_key = "automatic_changes" if automatic_only else "changes"
        source_key = "automatic_change_sources" if automatic_only else "change_sources"
        changes = dict(recommendation.get(changes_key) or {})
        change_sources = dict(recommendation.get(source_key) or {})

        if not changes:
            return {
                "applied": False,
                "message": "No adaptivity changes were recommended.",
                "settings": _serialize_runtime_settings(runtime_settings),
                "report": report,
            }

        overrides = storage.set_runtime_setting_overrides(changes, updated_by=actor_username)
        updated_settings = get_effective_settings()
        if runtime_setting_refresh_required(changes):
            app.config["RATE_LIMITER"] = rl.build_rate_limiter(updated_settings)

        feedback_used = any(source == "feedback_loop" for source in change_sources.values())
        auto_used = any(source == "auto_tuning" for source in change_sources.values())
        now_epoch = time.time()
        if feedback_used:
            app.config["FEEDBACK_LOOP_STATE"]["next_due_epoch"] = now_epoch + max(
                int(updated_settings.feedback_loop_cooldown_seconds or 900),
                60,
            )
        if auto_used:
            app.config["AUTO_TUNING_STATE"]["next_due_epoch"] = now_epoch + max(
                int(updated_settings.auto_tuning_cooldown_seconds or 900),
                60,
            )

        audit_payload = {
            "trigger": trigger,
            "posture": report.get("posture", "steady"),
            "changes": changes,
            "change_sources": change_sources,
            "conflicts": recommendation.get("conflicts", []),
            "summary": recommendation.get("summary", report.get("summary", "")),
            "confidence": report.get("confidence", "low"),
            "effective": report.get("effective", {}),
            "automatic_only": automatic_only,
            "strategies": {
                "auto_tuning": report.get("strategies", {}).get("auto_tuning", {}),
                "feedback_loop": report.get("strategies", {}).get("feedback_loop", {}),
                "dynamic_thresholds": report.get("strategies", {}).get("dynamic_thresholds", {}),
            },
            "overrides": overrides,
        }
        record_audit("settings.adaptivity", "runtime_settings", "runtime", audit_payload)

        return {
            "applied": True,
            "message": "Adaptivity applied the merged runtime policy changes.",
            "changes": changes,
            "change_sources": change_sources,
            "settings": _serialize_runtime_settings(updated_settings),
            "report": get_adaptivity_report(updated_settings),
        }

    def apply_ml_log_training(runtime_settings: Settings, trigger: str, actor_username: str = "log-trainer") -> dict:
        rows = storage.list_labeled_training_rows(runtime_settings.ml_log_training_window_seconds)
        training_result = mlt.train_model_from_logged_rows(rows, runtime_settings, storage, actor_username=actor_username, trigger=trigger)
        app.config["RISK_MODEL"] = ml.load_runtime_model(runtime_settings, active_metadata=storage.get_active_model_metadata())
        app.config["ML_LOG_TRAINING_STATE"]["next_due_epoch"] = time.time() + max(int(runtime_settings.ml_log_training_cooldown_seconds or 86400), 60)
        record_audit(
            "model.logs_retrain",
            "model",
            training_result.get("model_version", ""),
            training_result,
        )
        return {
            "applied": True,
            "message": "ML log training produced and activated a new model from reviewed request logs.",
            "training": training_result,
            "report": get_ml_log_training_report(runtime_settings),
            "active_model": storage.get_active_model_metadata(),
        }

    def maybe_run_auto_tuning(trigger: str = "request") -> Optional[dict]:
        runtime_settings = get_effective_settings()
        if not bool(getattr(runtime_settings, "auto_tuning_enabled", False)):
            return None

        state = app.config.get("AUTO_TUNING_STATE", {})
        now_epoch = time.time()
        next_due_epoch = float(state.get("next_due_epoch") or 0.0)
        if next_due_epoch and now_epoch < next_due_epoch:
            return None

        report = get_auto_tuning_report(runtime_settings)
        cooldown_remaining = int(report.get("cooldown_remaining_seconds") or 0)
        if cooldown_remaining > 0:
            state["next_due_epoch"] = now_epoch + cooldown_remaining
            return report

        if report.get("mode") == "insufficient_data":
            state["next_due_epoch"] = 0.0
            return report

        if not report.get("can_auto_apply"):
            state["next_due_epoch"] = now_epoch + max(int(runtime_settings.auto_tuning_cooldown_seconds or 900), 60)
            return report

        return apply_auto_tuning_changes(report, runtime_settings, trigger=trigger, actor_username="auto-tuner")

    def maybe_run_feedback_loop(trigger: str = "label_feedback") -> Optional[dict]:
        runtime_settings = get_effective_settings()
        if not bool(getattr(runtime_settings, "feedback_loop_enabled", False)):
            return None

        state = app.config.get("FEEDBACK_LOOP_STATE", {})
        now_epoch = time.time()
        next_due_epoch = float(state.get("next_due_epoch") or 0.0)
        if next_due_epoch and now_epoch < next_due_epoch:
            return None

        report = get_feedback_loop_report(runtime_settings)
        cooldown_remaining = int(report.get("cooldown_remaining_seconds") or 0)
        if cooldown_remaining > 0:
            state["next_due_epoch"] = now_epoch + cooldown_remaining
            return report

        if report.get("mode") == "insufficient_feedback":
            state["next_due_epoch"] = 0.0
            return report

        if not report.get("can_auto_apply"):
            state["next_due_epoch"] = now_epoch + max(int(runtime_settings.feedback_loop_cooldown_seconds or 900), 60)
            return report

        return apply_feedback_loop_changes(report, runtime_settings, trigger=trigger, actor_username="feedback-loop")

    def maybe_run_adaptivity(trigger: str = "request_label") -> Optional[dict]:
        runtime_settings = get_effective_settings()
        report = get_adaptivity_report(runtime_settings)
        now_epoch = time.time()

        auto_status = report.get("strategies", {}).get("auto_tuning", {})
        feedback_status = report.get("strategies", {}).get("feedback_loop", {})
        auto_state = app.config.get("AUTO_TUNING_STATE", {})
        feedback_state = app.config.get("FEEDBACK_LOOP_STATE", {})

        if auto_status.get("enabled"):
            auto_cooldown = int(auto_status.get("cooldown_remaining_seconds") or 0)
            if auto_cooldown > 0:
                auto_state["next_due_epoch"] = now_epoch + auto_cooldown
            elif auto_status.get("mode") == "insufficient_data":
                auto_state["next_due_epoch"] = 0.0
            elif not auto_status.get("automatic_ready"):
                auto_state["next_due_epoch"] = now_epoch + max(int(runtime_settings.auto_tuning_cooldown_seconds or 900), 60)

        if feedback_status.get("enabled"):
            feedback_cooldown = int(feedback_status.get("cooldown_remaining_seconds") or 0)
            if feedback_cooldown > 0:
                feedback_state["next_due_epoch"] = now_epoch + feedback_cooldown
            elif feedback_status.get("mode") == "insufficient_feedback":
                feedback_state["next_due_epoch"] = 0.0
            elif not feedback_status.get("automatic_ready"):
                feedback_state["next_due_epoch"] = now_epoch + max(int(runtime_settings.feedback_loop_cooldown_seconds or 900), 60)

        if not report.get("can_auto_apply"):
            return report

        return apply_adaptivity_changes(
            report,
            runtime_settings,
            trigger=trigger,
            actor_username="adaptivity",
            automatic_only=True,
        )

    def maybe_run_ml_log_training(trigger: str = "request") -> Optional[dict]:
        runtime_settings = get_effective_settings()
        if not bool(getattr(runtime_settings, "ml_log_training_enabled", False)):
            return None

        state = app.config.get("ML_LOG_TRAINING_STATE", {})
        now_epoch = time.time()
        next_due_epoch = float(state.get("next_due_epoch") or 0.0)
        if next_due_epoch and now_epoch < next_due_epoch:
            return None

        report = get_ml_log_training_report(runtime_settings)
        cooldown_remaining = int(report.get("cooldown_remaining_seconds") or 0)
        if cooldown_remaining > 0:
            state["next_due_epoch"] = now_epoch + cooldown_remaining
            return report

        if report.get("mode") == "insufficient_data":
            state["next_due_epoch"] = 0.0
            return report

        if not report.get("can_auto_apply"):
            state["next_due_epoch"] = now_epoch + max(int(runtime_settings.ml_log_training_cooldown_seconds or 86400), 60)
            return report

        return apply_ml_log_training(runtime_settings, trigger=trigger, actor_username="log-trainer")

    @app.before_request
    def handle_preflight():
        if request.method != "OPTIONS":
            return None
        if request.path.startswith("/api/") or request.path.startswith("/reports/") or request.path == "/health":
            return Response(status=204)
        return None

    @app.after_request
    def apply_cors_headers(response):
        origin = request.headers.get("Origin", "")
        if not origin:
            return response

        runtime_settings = get_effective_settings()
        allowed_origins = set(runtime_settings.cors_allowed_origins or ())
        if origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        return response

    def handle_security_pipeline(forwarded_path: str, forward_to_backend: bool):
        runtime_settings = get_effective_settings()
        started_at = time.perf_counter()
        record = di.capture_request(request, runtime_settings, forwarded_path=forwarded_path)
        endpoint_policy = ep.resolve_endpoint_policy(record, runtime_settings, storage.list_endpoint_policies(enabled_only=True))
        connection_snapshot = app.config["CONNECTION_TRACKER"].register(record, endpoint_policy, runtime_settings)
        try:
            history_snapshot = storage.get_history_snapshot(record, runtime_settings.analytics_window_seconds)
            blacklist_record = storage.is_blacklisted(record.remote_addr)
            manual_block_rule = storage.match_manual_block_rule_for_request(record)
            adaptive_rate_limit_policy = arl.resolve_rate_limit_profile(record, history_snapshot, runtime_settings)
            effective_rate_limit_policy = ep.merge_rate_limit_policy(adaptive_rate_limit_policy, endpoint_policy, record, runtime_settings)
            rate_limit_result = rl.enforce_rate_limit(
                storage,
                record,
                history_snapshot,
                runtime_settings,
                limiter=app.config["RATE_LIMITER"],
                policy=effective_rate_limit_policy,
            )
            evaluation_settings = runtime_settings.with_overrides(
                rate_limit_max_requests=max(int(getattr(rate_limit_result, "requests_per_min", runtime_settings.rate_limit_max_requests) or runtime_settings.rate_limit_max_requests), 1),
                token_bucket_capacity=int(round(float(getattr(rate_limit_result, "capacity", runtime_settings.token_bucket_capacity) or runtime_settings.token_bucket_capacity))),
                token_bucket_refill_rate=float(getattr(rate_limit_result, "refill_rate", runtime_settings.token_bucket_refill_rate) or runtime_settings.token_bucket_refill_rate),
                block_threshold=float(endpoint_policy.get("block_threshold", runtime_settings.block_threshold) or runtime_settings.block_threshold),
                monitor_threshold=float(endpoint_policy.get("monitor_threshold", runtime_settings.monitor_threshold) or runtime_settings.monitor_threshold),
            )
            transport_snapshot = ta.analyze_transport_awareness(
                request_record=record,
                history_snapshot=history_snapshot,
                rate_limit_result=rate_limit_result,
                connection_snapshot=connection_snapshot,
                endpoint_policy=endpoint_policy,
                settings=evaluation_settings,
            )
            features = fe.extract_features(
                record,
                history_snapshot,
                rate_limit_result,
                evaluation_settings,
                endpoint_policy=endpoint_policy,
                connection_snapshot=connection_snapshot,
                transport_snapshot=transport_snapshot,
            )
            score_result = ml.predict_score_with_breakdown(app.config["RISK_MODEL"], features)
            rule_result = re.check_rules(
                request_record=record,
                features=features,
                history_snapshot=history_snapshot,
                rate_limit_result=rate_limit_result,
                blacklist_record=blacklist_record,
                manual_block_rule=manual_block_rule,
                endpoint_policy=endpoint_policy,
                connection_snapshot=connection_snapshot,
                transport_snapshot=transport_snapshot,
                settings=evaluation_settings,
            )
            dynamic_threshold_report = (
                get_dynamic_threshold_report(runtime_settings, endpoint_policy=endpoint_policy)
                if runtime_settings.dynamic_thresholds_enabled
                else None
            )
            decision = mi.decide_action(
                rule_result,
                score_result,
                history_snapshot,
                evaluation_settings,
                dynamic_threshold_report=dynamic_threshold_report,
            )
            decision_engine = mi.build_decision_explanation(
                rule_result,
                score_result,
                history_snapshot,
                decision,
                evaluation_settings,
            )

            proxied = False
            backend_status = None

            if decision.action == "block":
                latency_ms = (time.perf_counter() - started_at) * 1000.0
                storage.record_request(
                    request_record=record,
                    features=features,
                    score_result=score_result,
                    rule_result=rule_result,
                    decision=decision,
                    history_snapshot=history_snapshot,
                    latency_ms=latency_ms,
                    attack_types=decision.attack_types,
                    backend_status=backend_status,
                    was_proxied=False,
                    endpoint_policy=endpoint_policy,
                )
                if mi.should_blacklist_ip(decision, history_snapshot, runtime_settings, record.remote_addr):
                    storage.add_blacklist(
                        ip_address=record.remote_addr,
                        reason="Adaptive blacklist after repeated blocked requests",
                        source="adaptive",
                        ttl_seconds=runtime_settings.temporary_blacklist_seconds,
                    )
                if record.traffic_origin == "live":
                    maybe_run_auto_tuning(trigger="blocked_request")
                    maybe_run_ml_log_training(trigger="blocked_request")
                return jsonify(mi.block_request(record, decision)), decision.status_code

            if forward_to_backend:
                try:
                    proxy_response, proxy_transport_decision = app.config["PROXY_TRANSPORT"].proxy_request(
                        record=record,
                        backend_url=runtime_settings.backend_base_url,
                        settings=runtime_settings,
                        history_snapshot=history_snapshot,
                        rate_limit_result=rate_limit_result,
                        transport_snapshot=transport_snapshot,
                    )
                    proxied = True
                    backend_status = proxy_response.status_code
                    latency_ms = (time.perf_counter() - started_at) * 1000.0
                    storage.record_request(
                        request_record=record,
                        features=features,
                        score_result=score_result,
                        rule_result=rule_result,
                        decision=decision,
                        history_snapshot=history_snapshot,
                        latency_ms=latency_ms,
                        attack_types=decision.attack_types,
                        backend_status=backend_status,
                        was_proxied=proxied,
                        endpoint_policy=endpoint_policy,
                    )
                    if record.traffic_origin == "live":
                        maybe_run_auto_tuning(trigger="proxied_request")
                        maybe_run_ml_log_training(trigger="proxied_request")
                    response = di.to_flask_response(proxy_response)
                    response.headers["X-WAF-Proxy-Transport-Mode"] = (
                        "close" if proxy_transport_decision.force_connection_close else "keepalive"
                    )
                    response.headers["X-WAF-Upstream-Pool-Generation"] = str(proxy_transport_decision.session_generation)
                    return response
                except ProxyTransportControlError as exc:
                    latency_ms = (time.perf_counter() - started_at) * 1000.0
                    proxy_block_decision = mi.MitigationDecision(
                        action="block",
                        status_code=exc.status_code,
                        reasons=list(exc.decision.reasons),
                        risk_score=score_result.score,
                        attack_types=list(exc.attack_types),
                        model_name=score_result.model_name,
                        model_version=score_result.model_version,
                        block_threshold_used=decision.block_threshold_used,
                        monitor_threshold_used=decision.monitor_threshold_used,
                        threshold_mode=decision.threshold_mode,
                        decision_path="proxy_transport_block",
                        decision_confidence="high",
                        confidence_reason="Upstream transport protection blocked the request before it reached the backend application.",
                    )
                    storage.record_request(
                        request_record=record,
                        features=features,
                        score_result=score_result,
                        rule_result=rule_result,
                        decision=proxy_block_decision,
                        history_snapshot=history_snapshot,
                        latency_ms=latency_ms,
                        attack_types=proxy_block_decision.attack_types,
                        backend_status=exc.status_code,
                        was_proxied=False,
                        endpoint_policy=endpoint_policy,
                    )
                    return (
                        jsonify(
                            {
                                "message": exc.message,
                                "request_id": record.request_id,
                                "attack_types": proxy_block_decision.attack_types,
                                "reasons": proxy_block_decision.reasons,
                                "proxy_transport": exc.decision.as_dict(),
                            }
                        ),
                        exc.status_code,
                    )
                except requests.RequestException as exc:
                    latency_ms = (time.perf_counter() - started_at) * 1000.0
                    storage.record_request(
                        request_record=record,
                        features=features,
                        score_result=score_result,
                        rule_result=rule_result,
                        decision=decision,
                        history_snapshot=history_snapshot,
                        latency_ms=latency_ms,
                        attack_types=decision.attack_types,
                        backend_status=502,
                        was_proxied=False,
                        endpoint_policy=endpoint_policy,
                    )
                    if record.traffic_origin == "live":
                        maybe_run_auto_tuning(trigger="proxy_failure")
                        maybe_run_ml_log_training(trigger="proxy_failure")
                    logger.exception("Backend proxy failed for request %s", record.request_id)
                    return (
                        jsonify(
                            {
                                "message": "Backend request failed",
                                "request_id": record.request_id,
                                "error": str(exc),
                            }
                        ),
                        502,
                    )

            latency_ms = (time.perf_counter() - started_at) * 1000.0
            storage.record_request(
                request_record=record,
                features=features,
                score_result=score_result,
                rule_result=rule_result,
                decision=decision,
                history_snapshot=history_snapshot,
                latency_ms=latency_ms,
                attack_types=decision.attack_types,
                backend_status=None,
                was_proxied=False,
                endpoint_policy=endpoint_policy,
            )
            if record.traffic_origin == "live":
                maybe_run_auto_tuning(trigger="inspected_request")
                maybe_run_ml_log_training(trigger="inspected_request")
            return jsonify(
                {
                    "message": "Request passed through the inspection pipeline",
                    "request_id": record.request_id,
                    "action": decision.action,
                    "risk_score": decision.risk_score,
                    "attack_types": decision.attack_types,
                    "features": features,
                    "score_breakdown": score_result.as_dict(),
                    "decision_engine": decision_engine,
                    "rule_hits": rule_result.reasons,
                    "history": history_snapshot.as_dict(),
                    "rate_limit": rate_limit_result.as_dict(),
                    "endpoint_policy": endpoint_policy,
                    "connection_guard": connection_snapshot.as_dict(),
                    "transport_awareness": transport_snapshot.as_dict(),
                    "echo": {
                        "method": record.method,
                        "path": record.path,
                        "query_string": record.query_string,
                        "body_preview": shorten(record.body_text, 160),
                    },
                }
            )
        finally:
            app.config["CONNECTION_TRACKER"].release(record.request_id)

    def inspect_failed_login_attempt(username: str) -> dict:
        runtime_settings = get_effective_settings()
        started_at = time.perf_counter()
        record = di.capture_request(request, runtime_settings, forwarded_path=request.path)
        endpoint_policy = ep.resolve_endpoint_policy(record, runtime_settings, storage.list_endpoint_policies(enabled_only=True))
        connection_snapshot = app.config["CONNECTION_TRACKER"].register(record, endpoint_policy, runtime_settings)
        try:
            history_snapshot = storage.get_history_snapshot(record, runtime_settings.analytics_window_seconds)
            blacklist_record = storage.is_blacklisted(record.remote_addr)
            manual_block_rule = storage.match_manual_block_rule_for_request(record)
            adaptive_rate_limit_policy = arl.resolve_rate_limit_profile(record, history_snapshot, runtime_settings)
            effective_rate_limit_policy = ep.merge_rate_limit_policy(adaptive_rate_limit_policy, endpoint_policy, record, runtime_settings)
            rate_limit_result = rl.enforce_rate_limit(
                storage,
                record,
                history_snapshot,
                runtime_settings,
                limiter=app.config["RATE_LIMITER"],
                policy=effective_rate_limit_policy,
            )
            evaluation_settings = runtime_settings.with_overrides(
                rate_limit_max_requests=max(int(getattr(rate_limit_result, "requests_per_min", runtime_settings.rate_limit_max_requests) or runtime_settings.rate_limit_max_requests), 1),
                token_bucket_capacity=int(round(float(getattr(rate_limit_result, "capacity", runtime_settings.token_bucket_capacity) or runtime_settings.token_bucket_capacity))),
                token_bucket_refill_rate=float(getattr(rate_limit_result, "refill_rate", runtime_settings.token_bucket_refill_rate) or runtime_settings.token_bucket_refill_rate),
                block_threshold=float(endpoint_policy.get("block_threshold", runtime_settings.block_threshold) or runtime_settings.block_threshold),
                monitor_threshold=float(endpoint_policy.get("monitor_threshold", runtime_settings.monitor_threshold) or runtime_settings.monitor_threshold),
            )
            transport_snapshot = ta.analyze_transport_awareness(
                request_record=record,
                history_snapshot=history_snapshot,
                rate_limit_result=rate_limit_result,
                connection_snapshot=connection_snapshot,
                endpoint_policy=endpoint_policy,
                settings=evaluation_settings,
            )
            features = fe.extract_features(
                record,
                history_snapshot,
                rate_limit_result,
                evaluation_settings,
                endpoint_policy=endpoint_policy,
                connection_snapshot=connection_snapshot,
                transport_snapshot=transport_snapshot,
            )
            prior_login_attempts = int(history_snapshot.path_hits_window or 0)
            features["login_failure_signal"] = 1.0
            features["failed_login_attempts_window"] = float(prior_login_attempts + 1)
            if prior_login_attempts >= 2 or history_snapshot.session_request_count_window >= 2 or rate_limit_result.pressure >= 0.35:
                features["brute_force_signal"] = 1.0
            if prior_login_attempts >= 5 or rate_limit_result.pressure >= 0.8:
                features["automation_abuse_signal"] = max(float(features.get("automation_abuse_signal", 0.0)), 1.0)

            score_result = ml.predict_score_with_breakdown(app.config["RISK_MODEL"], features)
            rule_result = re.check_rules(
                request_record=record,
                features=features,
                history_snapshot=history_snapshot,
                rate_limit_result=rate_limit_result,
                blacklist_record=blacklist_record,
                manual_block_rule=manual_block_rule,
                endpoint_policy=endpoint_policy,
                connection_snapshot=connection_snapshot,
                transport_snapshot=transport_snapshot,
                settings=evaluation_settings,
            )
            dynamic_threshold_report = (
                get_dynamic_threshold_report(runtime_settings, endpoint_policy=endpoint_policy)
                if runtime_settings.dynamic_thresholds_enabled
                else None
            )
            decision = mi.decide_action(
                rule_result,
                score_result,
                history_snapshot,
                evaluation_settings,
                dynamic_threshold_report=dynamic_threshold_report,
            )
            latency_ms = (time.perf_counter() - started_at) * 1000.0
            storage.record_request(
                request_record=record,
                features=features,
                score_result=score_result,
                rule_result=rule_result,
                decision=decision,
                history_snapshot=history_snapshot,
                latency_ms=latency_ms,
                attack_types=decision.attack_types,
                backend_status=401 if decision.action != "block" else 429,
                was_proxied=False,
                endpoint_policy=endpoint_policy,
            )
            if record.traffic_origin == "live":
                maybe_run_auto_tuning(trigger="failed_login")
                maybe_run_ml_log_training(trigger="failed_login")
            return {
                "record": record,
                "history_snapshot": history_snapshot,
                "rate_limit_result": rate_limit_result,
                "features": features,
                "score_result": score_result,
                "rule_result": rule_result,
                "decision": decision,
                "endpoint_policy": endpoint_policy,
                "connection_guard": connection_snapshot,
                "transport_awareness": transport_snapshot,
                "username": username,
            }
        finally:
            app.config["CONNECTION_TRACKER"].release(record.request_id)

    def serve_dashboard_ui(asset_path: str = ""):
        runtime_settings = get_effective_settings()
        if runtime_settings.frontend_use_dev_server:
            return redirect(runtime_settings.frontend_dev_server_url, code=302)

        if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
            if asset_path:
                candidate = FRONTEND_DIST / asset_path
                if candidate.exists() and candidate.is_file():
                    mimetype = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
                    response = Response(candidate.read_bytes(), mimetype=mimetype)
                    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
                    return response
            index_path = FRONTEND_DIST / "index.html"
            response = Response(index_path.read_text(encoding="utf-8"), mimetype="text/html")
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response

        snapshot = storage.dashboard_snapshot(
            limit=runtime_settings.recent_event_limit,
            window_seconds=runtime_settings.dashboard_window_seconds,
        )
        return render_template_string(DASHBOARD_TEMPLATE, settings=runtime_settings, snapshot=snapshot)

    def current_model_metadata():
        active_runtime_model = app.config.get("RISK_MODEL")
        metadata = storage.get_active_model_metadata() or {
            "model_version": getattr(active_runtime_model, "model_version", "heuristic-fallback"),
            "model_type": getattr(active_runtime_model, "model_name", "heuristic"),
        }
        verification_path = Path(current_settings.model_verification_report_path)
        if verification_path.exists():
            try:
                verification_report = json.loads(verification_path.read_text(encoding="utf-8"))
                if verification_report.get("model_version") == metadata.get("model_version"):
                    metadata["verification"] = verification_report
            except (OSError, json.JSONDecodeError):
                pass
        return metadata

    def current_attack_simulation_report(runtime_settings: Settings) -> Optional[dict]:
        return load_attack_simulation_report(Path(runtime_settings.attack_simulation_report_path))

    def _notification_priority(kind: str) -> int:
        priority_map = {"alert": 4, "warning": 3, "success": 2, "info": 1}
        return priority_map.get(str(kind or "info"), 1)

    def _notification_timestamp_epoch(value: Optional[str]) -> float:
        if not value:
            return 0.0
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError:
            return 0.0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    def _notification_counts(items: list[dict]) -> dict:
        by_kind = {}
        by_category = {}
        for item in items:
            kind = str(item.get("kind") or "info")
            category = str(item.get("category") or "system")
            by_kind[kind] = by_kind.get(kind, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1
        return {"total": len(items), "by_kind": by_kind, "by_category": by_category}

    def _normalize_notification(item: dict) -> dict:
        normalized = dict(item)
        normalized.setdefault("category", "system")
        normalized.setdefault("source", "runtime")
        normalized.setdefault("kind", "info")
        normalized.setdefault("request_id", "")
        normalized.setdefault("action", "")
        normalized.setdefault("priority", _notification_priority(normalized.get("kind", "info")))
        return normalized

    def _command_notification_from_audit(event: dict, session_data: Optional[dict]) -> Optional[dict]:
        action = str(event.get("action") or "")
        details = event.get("details") or {}
        actor_username = str(event.get("actor_username") or "")
        session_user = (session_data or {}).get("user") or {}
        current_role = str(session_user.get("role") or "")
        current_username = str(session_user.get("username") or "")
        request_id = str(details.get("request_id") or "")

        if action == "auth.login":
            if current_username and actor_username != current_username:
                return None
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success",
                "category": "session",
                "source": "audit",
                "title": "Authenticated session established",
                "message": "Signed in as {0}. Session tracking and privileged commands are active.".format(
                    actor_username or current_username or "current user"
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "request.label":
            label = str(details.get("label") or "needs_review")
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "warning" if label == "malicious" else "info",
                "category": "command",
                "source": "audit",
                "title": "Request label updated",
                "message": "{0} marked request {1} as {2}.".format(
                    actor_username or "An analyst",
                    request_id or "the selected request",
                    label.replace("_", " "),
                ),
                "timestamp": event.get("created_at"),
                "request_id": request_id,
                "action": action,
            }

        if action == "manual_block.add":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "alert",
                "category": "command",
                "source": "audit",
                "title": "Targeted block rule created",
                "message": "{0} created a {1} block for request {2}.".format(
                    actor_username or "An analyst",
                    details.get("scope", "signature"),
                    request_id or "the selected request",
                ),
                "timestamp": event.get("created_at"),
                "request_id": request_id,
                "action": action,
            }

        if action == "manual_block.delete":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success",
                "category": "command",
                "source": "audit",
                "title": "Targeted block removed",
                "message": "{0} removed a targeted block rule from the gateway.".format(actor_username or "An analyst"),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "blacklist.add":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "warning",
                "category": "command",
                "source": "audit",
                "title": "IP blacklist updated",
                "message": "{0} blacklisted {1}.".format(actor_username or "An analyst", details.get("ip_address") or event.get("target_id") or "a source"),
                "timestamp": event.get("created_at"),
                "request_id": request_id,
                "action": action,
            }

        if action == "blacklist.delete":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success",
                "category": "command",
                "source": "audit",
                "title": "IP blacklist entry removed",
                "message": "{0} removed {1} from the blacklist.".format(
                    actor_username or "An analyst",
                    details.get("ip_address") or event.get("target_id") or "the selected source",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "request.delete":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "warning",
                "category": "command",
                "source": "audit",
                "title": "Request record deleted",
                "message": "{0} removed request {1} from the stored audit history.".format(
                    actor_username or "An administrator",
                    request_id or event.get("target_id") or "the selected request",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "simulation.attack_suite.run":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success",
                "category": "command",
                "source": "audit",
                "title": "Attack simulation executed",
                "message": "{0} ran a {1} simulation and exercised {2} requests.".format(
                    actor_username or "An analyst",
                    details.get("profile", "full"),
                    details.get("total_requests", 0),
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "settings.update":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "info",
                "category": "system",
                "source": "audit",
                "title": "Runtime policy updated",
                "message": "{0} changed live WAF settings.".format(actor_username or "An administrator"),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "security_scope.policy_upsert":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "warning",
                "category": "command",
                "source": "audit",
                "title": "Endpoint policy saved",
                "message": "{0} saved endpoint policy {1} for {2}.".format(
                    actor_username or "An administrator",
                    details.get("name") or event.get("target_id") or "the selected scope",
                    details.get("path_pattern") or "the configured path",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "security_scope.policy_delete":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success",
                "category": "command",
                "source": "audit",
                "title": "Endpoint policy removed",
                "message": "{0} removed endpoint policy {1}.".format(
                    actor_username or "An administrator",
                    details.get("name") or event.get("target_id") or "the selected scope",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "settings.auto_tune":
            change_count = len(details.get("changes") or {})
            trigger = details.get("trigger", "auto")
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success" if change_count else "info",
                "category": "system",
                "source": "audit",
                "title": "Auto-tuning adjusted runtime policy" if change_count else "Auto-tuning reviewed runtime policy",
                "message": "{0} reviewed the recent false positives and attack rate via {1}, with {2} setting change{3}.".format(
                    actor_username or "The auto-tuner",
                    trigger,
                    change_count,
                    "" if change_count == 1 else "s",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "settings.feedback_loop":
            change_count = len(details.get("changes") or {})
            trigger = details.get("trigger", "feedback")
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success" if change_count else "info",
                "category": "system",
                "source": "audit",
                "title": "Feedback loop adjusted runtime policy" if change_count else "Feedback loop reviewed labeled outcomes",
                "message": "{0} reviewed labeled request outcomes via {1}, with {2} setting change{3}.".format(
                    actor_username or "The feedback loop",
                    trigger,
                    change_count,
                    "" if change_count == 1 else "s",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "settings.adaptivity":
            change_count = len(details.get("changes") or {})
            trigger = details.get("trigger", "adaptivity")
            posture = details.get("posture", "steady")
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success" if change_count else "info",
                "category": "system",
                "source": "audit",
                "title": "Adaptivity merged runtime policy" if change_count else "Adaptivity reviewed runtime policy",
                "message": "{0} reconciled feedback and traffic heuristics via {1} in {2} posture, with {3} setting change{4}.".format(
                    actor_username or "The adaptivity controller",
                    trigger,
                    posture,
                    change_count,
                    "" if change_count == 1 else "s",
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action == "model.logs_retrain":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "success",
                "category": "model",
                "source": "audit",
                "title": "Model retrained from request logs",
                "message": "{0} activated model {1} using reviewed traffic logs via {2}.".format(
                    actor_username or "The log trainer",
                    details.get("model_version", "the latest model"),
                    details.get("trigger", "runtime"),
                ),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        if action in {"user.create_or_update", "user.update"} and current_role == "admin":
            return {
                "id": "audit-{0}".format(event.get("event_id", "")),
                "kind": "info",
                "category": "system",
                "source": "audit",
                "title": "User directory changed",
                "message": "{0} updated dashboard access control records.".format(actor_username or "An administrator"),
                "timestamp": event.get("created_at"),
                "action": action,
            }

        return None

    def auth_payload(session_data: Optional[dict]) -> dict:
        current_session = session_data or {}
        user = current_session.get("user") or {}
        return {
            "user": user,
            "created_at": current_session.get("created_at"),
            "last_seen_at": current_session.get("last_seen_at"),
            "expires_at": current_session.get("expires_at"),
            "ip_address": current_session.get("ip_address", ""),
            "user_agent": current_session.get("user_agent", ""),
            "capabilities": {
                "can_review": user.get("role") in {"analyst", "admin"},
                "can_admin": user.get("role") == "admin",
            },
        }

    def sanitize_request_detail_for_role(item: dict, role: str) -> dict:
        safe_item = dict(item or {})
        current_role = str(role or "").strip().lower()
        can_view_internals = current_role in {"analyst", "admin"}
        safe_item["can_view_internals"] = can_view_internals
        if can_view_internals:
            return safe_item

        safe_item["score_breakdown"] = None
        safe_item["rule_result"] = None
        safe_item["features"] = None
        safe_item["internal_detail_redacted"] = True
        return safe_item

    def enrich_request_detail_with_decision_engine(item: dict, runtime_settings: Settings) -> dict:
        if not item:
            return item

        enriched = dict(item)
        decision_payload = dict(enriched.get("decision_engine") or {})
        score_payload = dict(enriched.get("score_breakdown") or {})
        rule_payload = dict(enriched.get("rule_result") or {})
        history_payload = dict(enriched.get("history_snapshot") or {})

        decision = mi.MitigationDecision(
            action=str(decision_payload.get("action") or enriched.get("decision_action") or "allow"),
            status_code=int(decision_payload.get("status_code") or enriched.get("decision_status_code") or 200),
            reasons=list(decision_payload.get("reasons") or []),
            risk_score=float(decision_payload.get("risk_score") or enriched.get("risk_score") or 0.0),
            attack_types=list(decision_payload.get("attack_types") or enriched.get("attack_types") or []),
            model_name=str(decision_payload.get("model_name") or score_payload.get("model_name") or ""),
            model_version=str(decision_payload.get("model_version") or score_payload.get("model_version") or ""),
            block_threshold_used=float(decision_payload.get("block_threshold_used") or runtime_settings.block_threshold or 0.0),
            monitor_threshold_used=float(decision_payload.get("monitor_threshold_used") or runtime_settings.monitor_threshold or 0.0),
            threshold_mode=str(decision_payload.get("threshold_mode") or "static"),
            decision_path=str(decision_payload.get("decision_path") or "allow_below_thresholds"),
            decision_confidence=str(decision_payload.get("decision_confidence") or "low"),
            confidence_reason=str(decision_payload.get("confidence_reason") or ""),
        )
        score_result = SimpleNamespace(
            score=float(score_payload.get("score") or enriched.get("risk_score") or 0.0),
            raw_score=float(score_payload.get("raw_score") or enriched.get("risk_score") or 0.0),
            model_name=str(score_payload.get("model_name") or decision.model_name or ""),
            model_version=str(score_payload.get("model_version") or decision.model_version or ""),
        )
        rule_result = SimpleNamespace(
            should_block=bool(rule_payload.get("should_block", False)),
            should_monitor=bool(rule_payload.get("should_monitor", False)),
            severity=float(rule_payload.get("severity", 0.0) or 0.0),
            attack_types=list(rule_payload.get("attack_types") or decision.attack_types or []),
            matched_rules=list(rule_payload.get("matched_rules") or []),
        )
        history_snapshot = SimpleNamespace(
            ip_request_count_window=int(history_payload.get("ip_request_count_window", 0) or 0),
            ip_block_count_window=int(history_payload.get("ip_block_count_window", 0) or 0),
            ip_monitor_count_window=int(history_payload.get("ip_monitor_count_window", 0) or 0),
            session_request_count_window=int(history_payload.get("session_request_count_window", 0) or 0),
            fingerprint_reuse_count=int(history_payload.get("fingerprint_reuse_count", 0) or 0),
            path_hits_window=int(history_payload.get("path_hits_window", 0) or 0),
            unique_paths_window=int(history_payload.get("unique_paths_window", 0) or 0),
            ip_block_ratio=float(history_payload.get("ip_block_ratio", 0.0) or 0.0),
            ip_flagged_ratio=float(history_payload.get("ip_flagged_ratio", 0.0) or 0.0),
            ip_avg_risk_score_window=float(history_payload.get("ip_avg_risk_score_window", 0.0) or 0.0),
            ip_max_risk_score_window=float(history_payload.get("ip_max_risk_score_window", 0.0) or 0.0),
        )
        enriched["decision_engine"] = mi.build_decision_explanation(
            rule_result,
            score_result,
            history_snapshot,
            decision,
            runtime_settings,
        )
        return enriched

    def system_context(runtime_settings: Settings) -> dict:
        current_origin = request.host_url.rstrip("/")
        current_host = request.host.split(":")[0]
        lan_urls = []
        for address in discover_local_ipv4_addresses():
            lan_urls.append(
                {
                    "origin": "http://{0}:{1}".format(address, runtime_settings.port),
                    "dashboard_url": "http://{0}:{1}/dashboard/".format(address, runtime_settings.port),
                }
            )

        return {
            "app_name": runtime_settings.app_name,
            "listen_host": runtime_settings.host,
            "port": runtime_settings.port,
            "request_host": current_host,
            "current_origin": current_origin,
            "dashboard_url": "{0}/dashboard/".format(current_origin),
            "gateway_url": "{0}/".format(current_origin),
            "frontend_embedded": serve_frontend,
            "transparent_proxy": runtime_settings.transparent_proxy,
            "backend_base_url": runtime_settings.backend_base_url,
            "database_backend": storage.database_backend,
            "rate_limit_backend": getattr(app.config["RATE_LIMITER"], "backend_name", "storage"),
            "dashboard_ui_ready": (FRONTEND_DIST / "index.html").exists(),
            "active_model": current_model_metadata(),
            "lan_urls": lan_urls,
        }

    def dashboard_notifications(snapshot: dict, session_data: Optional[dict], runtime_settings: Settings, limit: int = 10) -> list[dict]:
        notifications = []
        auth_info = auth_payload(session_data)
        model_info = current_model_metadata()
        simulation_report = snapshot.get("simulation") or current_attack_simulation_report(runtime_settings)
        blocked_count = int(snapshot.get("blocked") or 0)
        blacklist_size = int(snapshot.get("blacklist_size") or 0)
        top_attack_types = snapshot.get("top_attack_types") or []
        recent_events = snapshot.get("events") or []
        now_epoch = time.time()

        if auth_info.get("expires_at"):
            try:
                expires_at = datetime.fromisoformat(str(auth_info["expires_at"]))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                remaining_seconds = max(int(expires_at.timestamp() - now_epoch), 0)
            except ValueError:
                remaining_seconds = 0
            if 0 < remaining_seconds <= 900:
                notifications.append(
                    {
                        "id": "session-expiring",
                        "kind": "warning",
                        "category": "session",
                        "source": "runtime",
                        "title": "Session expires soon",
                        "message": "Your authenticated session will expire in about {0} minutes unless activity continues.".format(
                            max(remaining_seconds // 60, 1)
                        ),
                        "timestamp": auth_info.get("expires_at"),
                    }
                )

        if blocked_count > 0:
            notifications.append(
                {
                    "id": "blocked-window",
                    "kind": "alert",
                    "category": "threat",
                    "source": "runtime",
                    "title": "Blocked traffic detected",
                    "message": "{0} request(s) were blocked during the selected observation window.".format(blocked_count),
                    "timestamp": snapshot.get("generated_at"),
                }
            )

        if blacklist_size > 0:
            notifications.append(
                {
                    "id": "blacklist-active",
                    "kind": "warning",
                    "category": "command",
                    "source": "runtime",
                    "title": "Blacklist entries are active",
                    "message": "{0} source IPs are currently blacklisted by the gateway.".format(blacklist_size),
                    "timestamp": snapshot.get("generated_at"),
                }
            )

        if top_attack_types:
            top_attack = next((item for item in top_attack_types if int(item.get("count", 0)) > 0), None)
        else:
            top_attack = None
        if top_attack is not None:
            notifications.append(
                {
                    "id": "top-attack-type",
                    "kind": "info",
                    "category": "threat",
                    "source": "runtime",
                    "title": "Dominant attack family",
                    "message": "{0} is currently the most frequent attack type with {1} event(s).".format(
                        top_attack.get("label", top_attack.get("attack_type", "unknown")),
                        top_attack.get("count", 0),
                    ),
                    "timestamp": snapshot.get("generated_at"),
                }
            )

        if recent_events:
            latest_event = recent_events[0]
            notifications.append(
                {
                    "id": "latest-event",
                    "kind": "info" if latest_event.get("action") != "block" else "alert",
                    "category": "threat",
                    "source": "runtime",
                    "title": "Latest decisive event",
                    "message": "{0} {1} from {2} ended with {3}.".format(
                        latest_event.get("method", "GET"),
                        latest_event.get("path", "/"),
                        latest_event.get("remote_addr", "unknown"),
                        latest_event.get("action", "allow"),
                    ),
                    "timestamp": latest_event.get("timestamp"),
                    "request_id": latest_event.get("request_id"),
                }
            )

        if model_info.get("model_type") == "heuristic" or "fallback" in str(model_info.get("model_version", "")).lower():
            notifications.append(
                {
                    "id": "heuristic-model",
                    "kind": "warning",
                    "category": "model",
                    "source": "runtime",
                    "title": "Fallback scoring is active",
                    "message": "The gateway is using heuristic scoring instead of a strongly validated trained artifact.",
                    "timestamp": snapshot.get("generated_at"),
                }
            )

        verification = model_info.get("verification") or {}
        if verification:
            family_pass_rate = float(verification.get("family_pass_rate", 0.0) or 0.0)
            notifications.append(
                {
                    "id": "model-verification",
                    "kind": "success" if family_pass_rate >= 0.8 else "warning",
                    "category": "model",
                    "source": "runtime",
                    "title": "Model pattern verification",
                    "message": "The active AI artifact verified {0}/{1} supported attack families.".format(
                        verification.get("verified_families", 0),
                        verification.get("supported_families", 0),
                    ),
                    "timestamp": verification.get("generated_at", snapshot.get("generated_at")),
                }
            )
        else:
            notifications.append(
                {
                    "id": "model-unverified",
                    "kind": "warning",
                    "category": "model",
                    "source": "runtime",
                    "title": "Model verification is missing",
                    "message": "No recent attack-pattern verification report is attached to the active AI artifact.",
                    "timestamp": snapshot.get("generated_at"),
                }
            )

        if simulation_report:
            notifications.append(
                {
                    "id": "attack-simulation",
                    "kind": "success" if int(simulation_report.get("total_requests") or 0) > 0 else "info",
                    "category": "system",
                    "source": "runtime",
                    "title": "Attack simulation suite available",
                    "message": "Last {0} simulation exercised {1} families and blocked {2}/{3} requests without affecting live threat totals.".format(
                        simulation_report.get("profile", "full"),
                        simulation_report.get("summary", {}).get("families_exercised", 0),
                        simulation_report.get("summary", {}).get("blocked", 0),
                        simulation_report.get("total_requests", 0),
                    ),
                    "timestamp": simulation_report.get("generated_at", snapshot.get("generated_at")),
                }
            )

        if runtime_settings.transparent_proxy:
            notifications.append(
                {
                    "id": "network-ready",
                    "kind": "success",
                    "category": "system",
                    "source": "runtime",
                    "title": "Transparent gateway mode is active",
                    "message": "Requests hitting the root path are inspected and forwarded through the WAF pipeline.",
                    "timestamp": snapshot.get("generated_at"),
                }
            )

        audit_candidates = storage.list_audit_events(limit=max(limit * 4, 24))
        for event in audit_candidates:
            notification = _command_notification_from_audit(event, session_data)
            if notification:
                notifications.append(notification)

        deduplicated = []
        seen_ids = set()
        for item in sorted(
            (_normalize_notification(item) for item in notifications),
            key=lambda current: (-_notification_timestamp_epoch(current.get("timestamp")), -int(current.get("priority", 0))),
        ):
            notification_id = str(item.get("id") or "")
            if notification_id and notification_id in seen_ids:
                continue
            if notification_id:
                seen_ids.add(notification_id)
            deduplicated.append(item)
        return deduplicated[: max(1, int(limit or 10))]

    def apply_request_label(request_id: str):
        payload = request.get_json(silent=True) or {}
        label = (payload.get("label") or "").strip().lower()
        notes = (payload.get("notes") or "").strip()
        if not label:
            return jsonify({"message": "label is required"}), 400
        updated = storage.update_request_label(request_id=request_id, label=label, notes=notes)
        if not updated:
            return jsonify({"message": "Request not found", "request_id": request_id}), 404
        return jsonify({"message": "Request label updated", "request_id": request_id, "label": label, "notes": notes})

    @app.route("/", methods=ALL_METHODS)
    def home():
        runtime_settings = get_effective_settings()
        if not serve_frontend:
            return jsonify(
                {
                    "app": runtime_settings.app_name,
                    "mode": "api-only",
                    "api_base": "/api",
                    "frontend_public_url": runtime_settings.frontend_public_url,
                    "dashboard_embedded": False,
                }
            )
        if runtime_settings.transparent_proxy and runtime_settings.backend_base_url:
            return handle_security_pipeline("/", forward_to_backend=True)
        return render_template_string(HOME_TEMPLATE, settings=runtime_settings)

    @app.route("/health", methods=["GET"])
    def health():
        runtime_settings = get_effective_settings()
        return jsonify(
            {
                "status": "ok",
                "app": runtime_settings.app_name,
                "backend_base_url": runtime_settings.backend_base_url,
                "database": runtime_settings.database_url or str(current_settings.db_path),
                "database_backend": storage.database_backend,
                "rate_limit_backend": getattr(app.config["RATE_LIMITER"], "backend_name", "storage"),
                "pre_app_filter_enabled": runtime_settings.pre_app_filter_enabled,
                "proxy_transport_controls_enabled": runtime_settings.proxy_transport_controls_enabled,
                "dashboard_ui_ready": (FRONTEND_DIST / "index.html").exists(),
                "auth_enabled": True,
                "frontend_dev_server": runtime_settings.frontend_use_dev_server,
                "frontend_embedded": serve_frontend,
            }
        )

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        payload = request.get_json(silent=True) or {}
        username = (payload.get("username") or "").strip().lower()
        password = payload.get("password") or ""
        if not username or not password:
            return jsonify({"message": "username and password are required"}), 400

        user = storage.get_user_by_username(username, include_password_hash=True)
        if user is None or not bool(user.get("is_active")) or not verify_password(password, user.get("password_hash", "")):
            failed_attempt = inspect_failed_login_attempt(username=username)
            failed_decision = failed_attempt["decision"]
            failed_record = failed_attempt["record"]
            failed_attempts_window = int(failed_attempt["features"].get("failed_login_attempts_window", 0.0) or 0)
            storage.log_audit_event(
                action="auth.login_failed",
                target_type="user",
                target_id=username,
                details={
                    **audit_details_from_request(),
                    "username": username,
                    "request_id": failed_record.request_id,
                    "attack_types": failed_decision.attack_types,
                    "risk_score": failed_decision.risk_score,
                    "failed_attempts_window": failed_attempts_window,
                },
            )
            if failed_decision.action == "block":
                return (
                    jsonify(
                        {
                            "message": "Authentication temporarily blocked by the AI-based WAF",
                            "request_id": failed_record.request_id,
                            "attack_types": failed_decision.attack_types,
                            "risk_score": failed_decision.risk_score,
                            "failed_attempts_window": failed_attempts_window,
                            "reasons": failed_decision.reasons,
                            "transport_awareness": failed_attempt["transport_awareness"].as_dict(),
                        }
                    ),
                    429,
                )
            return (
                jsonify(
                    {
                        "message": "Invalid credentials",
                        "request_id": failed_record.request_id,
                        "attack_types": failed_decision.attack_types,
                        "risk_score": failed_decision.risk_score,
                        "failed_attempts_window": failed_attempts_window,
                        "action": failed_decision.action,
                        "transport_awareness": failed_attempt["transport_awareness"].as_dict(),
                    }
                ),
                401,
            )

        runtime_settings = get_effective_settings()
        token = issue_auth_token()
        session_payload = storage.create_auth_session(
            token=token,
            user_id=user["user_id"],
            ttl_seconds=runtime_settings.auth_token_ttl_seconds,
            ip_address=request.headers.get("X-Forwarded-For") or request.remote_addr or "",
            user_agent=request.headers.get("User-Agent", ""),
        )
        audit_entry = storage.log_audit_event(
            action="auth.login",
            target_type="session",
            target_id=token,
            details=audit_details_from_request(),
            actor_user_id=user["user_id"],
            actor_username=user["username"],
        )
        response = jsonify(
            {
                "message": "Login successful",
                "token": token,
                **auth_payload(session_payload),
                "audit_event_id": audit_entry["event_id"],
            }
        )
        response.set_cookie(
            FRONTEND_SESSION_COOKIE,
            token,
            max_age=runtime_settings.auth_token_ttl_seconds,
            httponly=True,
            samesite="Lax",
        )
        return response

    @app.route("/api/auth/me", methods=["GET"])
    @require_auth
    def auth_me():
        session = get_current_auth_session(touch=False) or {}
        return jsonify(auth_payload(session))

    @app.route("/api/auth/logout", methods=["POST"])
    @require_auth
    def logout():
        session = get_current_auth_session(touch=False) or {}
        token = session.get("token", "")
        user = session.get("user") or {}
        if token:
            storage.delete_auth_session(token)
        storage.log_audit_event(
            action="auth.logout",
            target_type="session",
            target_id=token,
            details=audit_details_from_request(),
            actor_user_id=user.get("user_id"),
            actor_username=user.get("username", ""),
        )
        response = jsonify({"message": "Logged out"})
        response.delete_cookie(FRONTEND_SESSION_COOKIE)
        return response

    @app.route("/dashboard", defaults={"asset_path": ""}, methods=["GET"])
    @app.route("/dashboard/", defaults={"asset_path": ""}, methods=["GET"])
    @app.route("/dashboard/<path:asset_path>", methods=["GET"])
    def dashboard(asset_path: str):
        if not serve_frontend:
            return redirect(get_effective_settings().frontend_public_url, code=302)
        if asset_path == "" and request.path == "/dashboard":
            return redirect("/dashboard/", code=302)
        return serve_dashboard_ui(asset_path)

    @app.route("/legacy-dashboard", methods=["GET"])
    @require_roles("viewer")
    def legacy_dashboard():
        if not serve_frontend:
            return jsonify({"message": "Legacy dashboard is disabled in api-only mode"}), 404
        runtime_settings = get_effective_settings()
        snapshot = storage.dashboard_snapshot(
            limit=runtime_settings.recent_event_limit,
            window_seconds=runtime_settings.dashboard_window_seconds,
        )
        return render_template_string(DASHBOARD_TEMPLATE, settings=runtime_settings, snapshot=snapshot)

    @app.route("/reports/summary", methods=["GET"])
    @require_roles("viewer")
    def summary_report():
        runtime_settings = get_effective_settings()
        summary = storage.summary_report(window_seconds=runtime_settings.dashboard_window_seconds)
        summary["simulation"] = current_attack_simulation_report(runtime_settings)
        return render_template_string(
            SUMMARY_TEMPLATE,
            settings=runtime_settings,
            summary=summary,
            summary_text=_build_summary_text(summary),
        )

    @app.route("/reports/summary.json", methods=["GET"])
    @require_roles("viewer")
    def summary_report_json():
        runtime_settings = get_effective_settings()
        payload = storage.summary_report(window_seconds=runtime_settings.dashboard_window_seconds)
        payload["simulation"] = current_attack_simulation_report(runtime_settings)
        return jsonify(payload)

    @app.route("/api/dashboard/summary", methods=["GET"])
    @require_roles("viewer")
    def dashboard_summary_api():
        runtime_settings = get_effective_settings()
        window_seconds = _parse_int_arg(
            "window_seconds",
            runtime_settings.dashboard_window_seconds,
            minimum=60,
            maximum=60 * 60 * 24 * 30,
        )
        limit = _parse_int_arg("limit", runtime_settings.recent_event_limit, minimum=1, maximum=100)
        notification_limit = _parse_int_arg("notification_limit", 10, minimum=1, maximum=30)
        snapshot = storage.dashboard_snapshot(limit=limit, window_seconds=window_seconds)
        snapshot["active_model"] = current_model_metadata()
        session = get_current_auth_session(touch=False) or {}
        snapshot["auth"] = auth_payload(session)
        snapshot["system"] = system_context(runtime_settings)
        snapshot["simulation"] = current_attack_simulation_report(runtime_settings)
        snapshot["notifications"] = dashboard_notifications(snapshot, session, runtime_settings, limit=notification_limit)
        snapshot["notification_counts"] = _notification_counts(snapshot["notifications"])
        return jsonify(snapshot)

    @app.route("/api/dashboard/timeline", methods=["GET"])
    @require_roles("viewer")
    def dashboard_timeline_api():
        runtime_settings = get_effective_settings()
        window_seconds = _parse_int_arg(
            "window_seconds",
            runtime_settings.dashboard_window_seconds,
            minimum=60,
            maximum=60 * 60 * 24 * 30,
        )
        bucket_seconds = _parse_int_arg("bucket_seconds", 3600, minimum=60, maximum=60 * 60 * 24)
        return jsonify(storage.request_timeline(window_seconds=window_seconds, bucket_seconds=bucket_seconds))

    @app.route("/api/dashboard/overview", methods=["GET"])
    @require_roles("viewer")
    def dashboard_overview_api():
        runtime_settings = get_effective_settings()
        window_seconds = _parse_int_arg(
            "window_seconds",
            runtime_settings.dashboard_window_seconds,
            minimum=60,
            maximum=60 * 60 * 24 * 30,
        )
        limit = _parse_int_arg("limit", runtime_settings.recent_event_limit, minimum=1, maximum=100)
        page_size = _parse_int_arg("page_size", 20, minimum=1, maximum=100)
        return jsonify(
            {
                "summary": storage.summary_report(window_seconds=window_seconds),
                "timeline": storage.request_timeline(window_seconds=window_seconds, bucket_seconds=3600),
                "requests": storage.list_requests(page=1, page_size=page_size),
                "active_model": current_model_metadata(),
                "simulation": current_attack_simulation_report(runtime_settings),
                "blacklist": {"items": storage.list_blacklist()},
                "auth": auth_payload(get_current_auth_session(touch=False) or {}),
                "system": system_context(runtime_settings),
                "limits": {"recent_limit": limit, "page_size": page_size},
            }
        )

    @app.route("/api/dashboard/notifications", methods=["GET"])
    @require_roles("viewer")
    def dashboard_notifications_api():
        runtime_settings = get_effective_settings()
        window_seconds = _parse_int_arg(
            "window_seconds",
            runtime_settings.dashboard_window_seconds,
            minimum=60,
            maximum=60 * 60 * 24 * 30,
        )
        notification_limit = _parse_int_arg("limit", 12, minimum=1, maximum=40)
        snapshot = storage.dashboard_snapshot(limit=8, window_seconds=window_seconds)
        session = get_current_auth_session(touch=False) or {}
        snapshot["simulation"] = current_attack_simulation_report(runtime_settings)
        notifications = dashboard_notifications(snapshot, session, runtime_settings, limit=notification_limit)
        return jsonify(
            {
                "generated_at": snapshot.get("generated_at"),
                "auth": auth_payload(session),
                "system": system_context(runtime_settings),
                "simulation": snapshot.get("simulation"),
                "notifications": notifications,
                "counts": _notification_counts(notifications),
            }
        )

    @app.route("/reports/events.csv", methods=["GET"])
    @require_roles("viewer")
    def export_events_csv():
        export_path = REPORTS_DIR / "requests_export.csv"
        file_path = storage.export_requests_csv(export_path)
        return Response(
            file_path.read_text(encoding="utf-8"),
            mimetype="text/csv",
            headers={"Content-Disposition": 'attachment; filename="{0}"'.format(file_path.name)},
        )

    @app.route("/api/model", methods=["GET"])
    @require_roles("viewer")
    def active_model():
        return jsonify(current_model_metadata())

    @app.route("/api/model/verification", methods=["GET"])
    @require_roles("viewer")
    def active_model_verification():
        payload = current_model_metadata()
        verification = payload.get("verification")
        if verification:
            return jsonify(verification)
        return jsonify({"message": "No model verification report is currently available."}), 404

    @app.route("/api/simulations/attack-suite", methods=["GET", "POST"])
    @require_auth
    def attack_simulation_suite_api():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if request.method == "GET":
            report = current_attack_simulation_report(runtime_settings)
            if report:
                return jsonify(report)
            return jsonify({"message": "No attack simulation report is currently available."}), 404

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Attack simulations require analyst role or higher"}), 403

        payload = request.get_json(silent=True) or {}
        profile = str(payload.get("profile") or "full").strip().lower()
        if profile not in {"quick", "full"}:
            return jsonify({"message": "profile must be quick or full"}), 400

        report = run_attack_simulation_suite(app, storage, runtime_settings, profile=profile)
        record_audit(
            "simulation.attack_suite.run",
            "attack_simulation",
            report.get("run_id", ""),
            {
                "run_id": report.get("run_id", ""),
                "profile": report.get("profile", profile),
                "total_requests": report.get("total_requests", 0),
                "blocked": report.get("summary", {}).get("blocked", 0),
                "monitored": report.get("summary", {}).get("monitored", 0),
                "allowed": report.get("summary", {}).get("allowed", 0),
            },
        )
        return jsonify(report), 201

    @app.route("/api/requests", methods=["GET"])
    @require_roles("viewer")
    def request_collection():
        page = _parse_int_arg("page", 1, minimum=1, maximum=100000)
        page_size = _parse_int_arg("page_size", 20, minimum=1, maximum=100)
        search = (request.args.get("search") or "").strip()
        action = (request.args.get("action") or "").strip() or None
        label = request.args.get("label")
        if label is not None:
            label = label.strip()
        label = label or None
        attack_type = (request.args.get("attack_type") or "").strip() or None
        remote_addr = (request.args.get("remote_addr") or "").strip() or None
        return jsonify(
            storage.list_requests(
                page=page,
                page_size=page_size,
                search=search,
                action=action,
                label=label,
                attack_type=attack_type,
                remote_addr=remote_addr,
            )
        )

    @app.route("/api/requests/<request_id>", methods=["GET", "DELETE"])
    @require_auth
    def request_item(request_id: str):
        if request.method == "DELETE":
            session = get_current_auth_session(touch=False) or {}
            user = session.get("user") or {}
            if user.get("role") != "admin":
                return jsonify({"message": "Deleting request records requires admin role"}), 403
            deleted = storage.delete_request(request_id)
            if not deleted:
                return jsonify({"message": "Request not found", "request_id": request_id}), 404
            record_audit("request.delete", "request", request_id, {"request_id": request_id})
            return jsonify({"message": "Request deleted", "request_id": request_id})

        item = storage.get_request_detail(request_id)
        if item is None:
            return jsonify({"message": "Request not found", "request_id": request_id}), 404
        item = enrich_request_detail_with_decision_engine(item, get_effective_settings())
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        return jsonify(sanitize_request_detail_for_role(item, user.get("role", "")))

    @app.route("/api/requests/<request_id>/label", methods=["POST", "PATCH"])
    @require_roles("analyst")
    def request_label(request_id: str):
        result = apply_request_label(request_id)
        if isinstance(result, tuple):
            response, status = result
            if status >= 400:
                return result
        payload = request.get_json(silent=True) or {}
        record_audit(
            "request.label",
            "request",
            request_id,
            {"request_id": request_id, "label": payload.get("label"), "notes": payload.get("notes", "")},
        )
        if str(payload.get("label") or "").strip().lower() in {"benign", "malicious"}:
            maybe_run_adaptivity(trigger="request_label")
            maybe_run_ml_log_training(trigger="request_label")
        return result

    @app.route("/api/requests/<request_id>/blacklist", methods=["POST"])
    @require_roles("analyst")
    def request_blacklist(request_id: str):
        request_item_data = storage.get_request_detail(request_id)
        if request_item_data is None:
            return jsonify({"message": "Request not found", "request_id": request_id}), 404

        runtime_settings = get_effective_settings()
        payload = request.get_json(silent=True) or {}
        scope = (payload.get("scope") or "signature").strip().lower()
        ttl_seconds = payload.get("ttl_seconds", runtime_settings.targeted_block_ttl_seconds)
        reason = (payload.get("reason") or "Blocked from dashboard request review").strip()

        if scope == "ip":
            ip_address = request_item_data["remote_addr"]
            storage.add_blacklist(ip_address=ip_address, reason=reason, source="manual", ttl_seconds=ttl_seconds)
            record_audit(
                "blacklist.add",
                "ip_address",
                ip_address,
                {"request_id": request_id, "scope": scope, "reason": reason, "ttl_seconds": ttl_seconds},
            )
            return jsonify(
                {
                    "message": "Source IP added to blacklist",
                    "request_id": request_id,
                    "ip_address": ip_address,
                    "reason": reason,
                    "scope": scope,
                }
            ), 201

        try:
            rule = storage.create_manual_block_rule_from_request(
                request_detail=request_item_data,
                scope_type=scope,
                reason=reason,
                source="manual",
                ttl_seconds=ttl_seconds,
            )
        except ValueError as exc:
            return jsonify({"message": str(exc), "request_id": request_id, "scope": scope}), 400
        record_audit(
            "manual_block.add",
            "manual_rule",
            rule.get("rule_id", ""),
            {"request_id": request_id, "scope": scope, "reason": reason, "ttl_seconds": ttl_seconds},
        )

        return jsonify(
            {
                "message": "Targeted block rule created",
                "request_id": request_id,
                "scope": scope,
                "rule": rule,
            }
        ), 201

    @app.route("/api/manual-blocks", methods=["GET"])
    @require_roles("viewer")
    def manual_block_collection():
        items = storage.list_manual_block_rules()
        return jsonify({"items": items, "count": len(items)})

    @app.route("/api/manual-blocks/<rule_id>", methods=["DELETE"])
    @require_roles("analyst")
    def manual_block_detail(rule_id: str):
        removed = storage.remove_manual_block_rule(rule_id)
        if not removed:
            return jsonify({"message": "Manual block rule not found", "rule_id": rule_id}), 404
        record_audit("manual_block.delete", "manual_rule", rule_id, {"rule_id": rule_id})
        return jsonify({"message": "Manual block rule removed", "rule_id": rule_id})

    @app.route("/api/blacklist", methods=["GET", "POST"])
    @require_auth
    def blacklist_collection():
        if request.method == "GET":
            session = get_current_auth_session(touch=False) or {}
            user = session.get("user") or {}
            if not user.get("role"):
                return jsonify({"message": "Authentication required"}), 401
            items = storage.list_blacklist()
            return jsonify({"items": items, "count": len(items)})

        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Blacklist updates require analyst role or higher"}), 403
        payload = request.get_json(silent=True) or {}
        ip_address = (payload.get("ip_address") or "").strip()
        reason = (payload.get("reason") or "Manually added").strip()
        ttl_seconds = payload.get("ttl_seconds")
        if not ip_address:
            return jsonify({"message": "ip_address is required"}), 400
        storage.add_blacklist(ip_address=ip_address, reason=reason, source="manual", ttl_seconds=ttl_seconds)
        record_audit(
            "blacklist.add",
            "ip_address",
            ip_address,
            {"ip_address": ip_address, "reason": reason, "ttl_seconds": ttl_seconds},
        )
        return jsonify({"message": "IP added to blacklist", "ip_address": ip_address, "reason": reason}), 201

    @app.route("/api/blacklist/<path:ip_address>", methods=["DELETE"])
    @require_roles("analyst")
    def blacklist_detail(ip_address: str):
        storage.remove_blacklist(ip_address)
        record_audit("blacklist.delete", "ip_address", ip_address, {"ip_address": ip_address})
        return jsonify({"message": "IP removed from blacklist", "ip_address": ip_address})

    @app.route("/api/labels/<request_id>", methods=["POST"])
    @require_roles("analyst")
    def label_request(request_id: str):
        result = apply_request_label(request_id)
        if isinstance(result, tuple):
            response, status = result
            if status >= 400:
                return result
        payload = request.get_json(silent=True) or {}
        record_audit(
            "request.label",
            "request",
            request_id,
            {"request_id": request_id, "label": payload.get("label"), "notes": payload.get("notes", "")},
        )
        if str(payload.get("label") or "").strip().lower() in {"benign", "malicious"}:
            maybe_run_adaptivity(trigger="request_label")
            maybe_run_ml_log_training(trigger="request_label")
        return result

    @app.route("/api/admin/settings", methods=["GET", "PATCH"])
    @require_auth
    def admin_settings():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if request.method == "GET":
            if user.get("role") not in {"analyst", "admin"}:
                return jsonify({"message": "Settings view requires analyst role or higher"}), 403
            return jsonify(
                {
                    "settings": _serialize_runtime_settings(runtime_settings),
                    "editable_fields": sorted(MANAGEABLE_SETTING_FIELDS),
                }
            )

        if user.get("role") != "admin":
            return jsonify({"message": "Settings updates require admin role"}), 403

        payload = request.get_json(silent=True) or {}
        changes = payload.get("settings") or {}
        if not isinstance(changes, dict) or not changes:
            return jsonify({"message": "settings payload is required"}), 400

        sanitized = {}
        for key, raw_value in changes.items():
            try:
                sanitized[key] = _coerce_setting_value(current_settings, key, raw_value)
            except (TypeError, ValueError) as exc:
                return jsonify({"message": str(exc), "setting": key}), 400

        overrides = storage.set_runtime_setting_overrides(sanitized, updated_by=user.get("username", ""))
        record_audit(
            "settings.update",
            "runtime_settings",
            "runtime",
            {"changes": sanitized, "overrides": overrides},
        )
        updated_settings = get_effective_settings()
        if any(key in sanitized for key in {"redis_url", "rate_limit_backend", "redis_key_prefix"}):
            app.config["RATE_LIMITER"] = rl.build_rate_limiter(updated_settings)
        return jsonify(
            {
                "message": "Runtime settings updated",
                "settings": _serialize_runtime_settings(updated_settings),
                "editable_fields": sorted(MANAGEABLE_SETTING_FIELDS),
            }
        )

    @app.route("/api/admin/settings/auto-tune", methods=["GET", "POST"])
    @require_auth
    def admin_settings_auto_tune():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Auto-tuning view requires analyst role or higher"}), 403

        if request.method == "GET":
            return jsonify(get_auto_tuning_report(runtime_settings))

        if user.get("role") != "admin":
            return jsonify({"message": "Auto-tuning apply requires admin role"}), 403

        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action") or "apply").strip().lower()
        report = get_auto_tuning_report(runtime_settings)

        if action == "preview":
            return jsonify(report)

        result = apply_auto_tuning_changes(
            report,
            runtime_settings,
            trigger=str(payload.get("trigger") or "manual"),
            actor_username=user.get("username", "") or "admin",
        )
        return jsonify(result)

    @app.route("/api/admin/settings/dynamic-thresholds", methods=["GET"])
    @require_auth
    def admin_settings_dynamic_thresholds():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Dynamic threshold view requires analyst role or higher"}), 403

        return jsonify(get_dynamic_threshold_report(runtime_settings))

    @app.route("/api/admin/settings/adaptive-rate-limit", methods=["GET"])
    @require_auth
    def admin_settings_adaptive_rate_limit():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Adaptive rate-limit view requires analyst role or higher"}), 403

        return jsonify(get_adaptive_rate_limit_report(runtime_settings))

    @app.route("/api/admin/security-scope", methods=["GET"])
    @require_auth
    def admin_security_scope():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Security scope view requires analyst role or higher"}), 403

        return jsonify(get_security_scope_report(runtime_settings))

    @app.route("/api/admin/security-scope/policies", methods=["POST"])
    @require_roles("admin")
    def admin_security_scope_policies():
        runtime_settings = get_effective_settings()
        payload = request.get_json(silent=True) or {}
        try:
            sanitized = _coerce_endpoint_policy_payload(payload, runtime_settings)
        except (TypeError, ValueError) as exc:
            return jsonify({"message": str(exc)}), 400

        policy = storage.save_endpoint_policy(
            policy_id=sanitized["policy_id"],
            name=sanitized["name"],
            description=sanitized["description"],
            path_pattern=sanitized["path_pattern"],
            methods=sanitized["methods"],
            priority=sanitized["priority"],
            sensitivity=sanitized["sensitivity"],
            settings_map=sanitized["settings_map"],
            source="custom",
            is_enabled=sanitized["is_enabled"],
        )
        record_audit(
            "security_scope.policy_upsert",
            "endpoint_policy",
            policy["policy_id"],
            {
                "name": policy["name"],
                "path_pattern": policy["path_pattern"],
                "methods": policy["methods"],
                "sensitivity": policy["sensitivity"],
                "priority": policy["priority"],
            },
        )
        return jsonify({"message": "Endpoint policy saved", "policy": policy, "report": get_security_scope_report(runtime_settings)}), 201

    @app.route("/api/admin/security-scope/policies/<policy_id>", methods=["PATCH", "DELETE"])
    @require_roles("admin")
    def admin_security_scope_policy_detail(policy_id: str):
        runtime_settings = get_effective_settings()
        existing = next((item for item in storage.list_endpoint_policies(enabled_only=False) if item["policy_id"] == policy_id), None)
        if existing is None:
            return jsonify({"message": "Endpoint policy not found", "policy_id": policy_id}), 404

        if request.method == "DELETE":
            removed = storage.delete_endpoint_policy(policy_id)
            if not removed:
                return jsonify({"message": "Endpoint policy not found", "policy_id": policy_id}), 404
            record_audit(
                "security_scope.policy_delete",
                "endpoint_policy",
                policy_id,
                {"policy_id": policy_id, "name": existing["name"], "path_pattern": existing["path_pattern"]},
            )
            return jsonify({"message": "Endpoint policy deleted", "policy_id": policy_id})

        payload = request.get_json(silent=True) or {}
        merged_payload = {
            "policy_id": policy_id,
            "name": payload.get("name", existing["name"]),
            "description": payload.get("description", existing.get("description", "")),
            "path_pattern": payload.get("path_pattern", existing["path_pattern"]),
            "methods": payload.get("methods", existing["methods"]),
            "priority": payload.get("priority", existing["priority"]),
            "sensitivity": payload.get("sensitivity", existing["sensitivity"]),
            "is_enabled": payload.get("is_enabled", existing["is_enabled"]),
            "requests_per_min": payload.get("requests_per_min", existing["settings"].get("requests_per_min")),
            "bucket_scope": payload.get("bucket_scope", existing["settings"].get("bucket_scope", "ip_endpoint")),
            "block_threshold": payload.get("block_threshold", existing["settings"].get("block_threshold")),
            "monitor_threshold": payload.get("monitor_threshold", existing["settings"].get("monitor_threshold")),
            "ddos_monitor_hits": payload.get("ddos_monitor_hits", existing["settings"].get("ddos_monitor_hits")),
            "ddos_block_hits": payload.get("ddos_block_hits", existing["settings"].get("ddos_block_hits")),
            "ddos_monitor_pressure": payload.get("ddos_monitor_pressure", existing["settings"].get("ddos_monitor_pressure")),
            "ddos_block_pressure": payload.get("ddos_block_pressure", existing["settings"].get("ddos_block_pressure")),
            "connection_monitor_active": payload.get("connection_monitor_active", existing["settings"].get("connection_monitor_active")),
            "connection_block_active": payload.get("connection_block_active", existing["settings"].get("connection_block_active")),
            "connection_monitor_per_ip": payload.get("connection_monitor_per_ip", existing["settings"].get("connection_monitor_per_ip")),
            "connection_block_per_ip": payload.get("connection_block_per_ip", existing["settings"].get("connection_block_per_ip")),
            "connection_burst_monitor": payload.get("connection_burst_monitor", existing["settings"].get("connection_burst_monitor")),
            "connection_burst_block": payload.get("connection_burst_block", existing["settings"].get("connection_burst_block")),
            "connection_new_per_second_monitor": payload.get("connection_new_per_second_monitor", existing["settings"].get("connection_new_per_second_monitor")),
            "connection_new_per_second_block": payload.get("connection_new_per_second_block", existing["settings"].get("connection_new_per_second_block")),
            "connection_stale_monitor": payload.get("connection_stale_monitor", existing["settings"].get("connection_stale_monitor")),
            "connection_stale_block": payload.get("connection_stale_block", existing["settings"].get("connection_stale_block")),
            "connection_sessions_monitor": payload.get("connection_sessions_monitor", existing["settings"].get("connection_sessions_monitor")),
            "connection_sessions_block": payload.get("connection_sessions_block", existing["settings"].get("connection_sessions_block")),
        }
        try:
            sanitized = _coerce_endpoint_policy_payload(merged_payload, runtime_settings)
        except (TypeError, ValueError) as exc:
            return jsonify({"message": str(exc)}), 400

        policy = storage.save_endpoint_policy(
            policy_id=policy_id,
            name=sanitized["name"],
            description=sanitized["description"],
            path_pattern=sanitized["path_pattern"],
            methods=sanitized["methods"],
            priority=sanitized["priority"],
            sensitivity=sanitized["sensitivity"],
            settings_map=sanitized["settings_map"],
            source="custom",
            is_enabled=sanitized["is_enabled"],
        )
        record_audit(
            "security_scope.policy_upsert",
            "endpoint_policy",
            policy["policy_id"],
            {
                "name": policy["name"],
                "path_pattern": policy["path_pattern"],
                "methods": policy["methods"],
                "sensitivity": policy["sensitivity"],
                "priority": policy["priority"],
            },
        )
        return jsonify({"message": "Endpoint policy updated", "policy": policy, "report": get_security_scope_report(runtime_settings)})

    @app.route("/api/admin/settings/feedback-loop", methods=["GET", "POST"])
    @require_auth
    def admin_settings_feedback_loop():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Feedback loop view requires analyst role or higher"}), 403

        if request.method == "GET":
            return jsonify(get_feedback_loop_report(runtime_settings))

        if user.get("role") != "admin":
            return jsonify({"message": "Feedback loop apply requires admin role"}), 403

        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action") or "apply").strip().lower()
        report = get_feedback_loop_report(runtime_settings)

        if action == "preview":
            return jsonify(report)

        result = apply_feedback_loop_changes(
            report,
            runtime_settings,
            trigger=str(payload.get("trigger") or "manual"),
            actor_username=user.get("username", "") or "admin",
        )
        return jsonify(result)

    @app.route("/api/admin/settings/adaptivity", methods=["GET", "POST"])
    @require_auth
    def admin_settings_adaptivity():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "Adaptivity view requires analyst role or higher"}), 403

        if request.method == "GET":
            return jsonify(get_adaptivity_report(runtime_settings))

        if user.get("role") != "admin":
            return jsonify({"message": "Adaptivity apply requires admin role"}), 403

        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action") or "apply").strip().lower()
        report = get_adaptivity_report(runtime_settings)

        if action == "preview":
            return jsonify(report)

        result = apply_adaptivity_changes(
            report,
            runtime_settings,
            trigger=str(payload.get("trigger") or "manual"),
            actor_username=user.get("username", "") or "admin",
        )
        return jsonify(result)

    @app.route("/api/admin/settings/ml-log-training", methods=["GET", "POST"])
    @require_auth
    def admin_settings_ml_log_training():
        session = get_current_auth_session(touch=False) or {}
        user = session.get("user") or {}
        runtime_settings = get_effective_settings()

        if user.get("role") not in {"analyst", "admin"}:
            return jsonify({"message": "ML log-training view requires analyst role or higher"}), 403

        if request.method == "GET":
            return jsonify(get_ml_log_training_report(runtime_settings))

        if user.get("role") != "admin":
            return jsonify({"message": "ML log-training apply requires admin role"}), 403

        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action") or "apply").strip().lower()
        report = get_ml_log_training_report(runtime_settings)

        if action == "preview":
            return jsonify(report)

        if not report.get("can_apply"):
            return jsonify({"message": "Not enough reviewed logs are available for retraining yet.", "report": report}), 400

        result = apply_ml_log_training(
            runtime_settings,
            trigger=str(payload.get("trigger") or "manual"),
            actor_username=user.get("username", "") or "admin",
        )
        return jsonify(result)

    @app.route("/api/admin/users", methods=["GET", "POST"])
    @require_roles("admin")
    def admin_users():
        if request.method == "GET":
            items = storage.list_users()
            return jsonify({"items": items, "count": len(items)})

        payload = request.get_json(silent=True) or {}
        username = (payload.get("username") or "").strip().lower()
        password = payload.get("password") or ""
        display_name = (payload.get("display_name") or username).strip() or username
        role = (payload.get("role") or "viewer").strip().lower()
        is_active = bool(payload.get("is_active", True))
        if not username or not password:
            return jsonify({"message": "username and password are required"}), 400
        if role not in {"viewer", "analyst", "admin"}:
            return jsonify({"message": "role must be viewer, analyst, or admin"}), 400

        user_record = storage.upsert_user(
            username=username,
            password_hash=hash_password(password),
            display_name=display_name,
            role=role,
            is_active=is_active,
        )
        record_audit(
            "user.create_or_update",
            "user",
            user_record.get("user_id", ""),
            {"username": username, "role": role, "is_active": is_active},
        )
        return jsonify({"message": "User saved", "user": user_record}), 201

    @app.route("/api/admin/users/<user_id>", methods=["PATCH"])
    @require_roles("admin")
    def admin_user_detail(user_id: str):
        payload = request.get_json(silent=True) or {}
        updates = {}
        if "display_name" in payload:
            updates["display_name"] = (payload.get("display_name") or "").strip() or "Unnamed User"
        if "role" in payload:
            role = (payload.get("role") or "").strip().lower()
            if role not in {"viewer", "analyst", "admin"}:
                return jsonify({"message": "role must be viewer, analyst, or admin"}), 400
            updates["role"] = role
        if "is_active" in payload:
            updates["is_active"] = bool(payload.get("is_active"))
        if payload.get("password"):
            updates["password_hash"] = hash_password(payload.get("password"))

        user_record = storage.update_user(user_id=user_id, **updates)
        if user_record is None:
            return jsonify({"message": "User not found", "user_id": user_id}), 404
        if "is_active" in updates and not updates["is_active"]:
            storage.delete_auth_sessions_for_user(user_id)
        record_audit(
            "user.update",
            "user",
            user_id,
            {"updates": {key: value for key, value in updates.items() if key != "password_hash"}},
        )
        return jsonify({"message": "User updated", "user": user_record})

    @app.route("/api/admin/audit", methods=["GET"])
    @require_roles("admin")
    def admin_audit():
        limit = _parse_int_arg("limit", 100, minimum=1, maximum=500)
        items = storage.list_audit_events(limit=limit)
        return jsonify({"items": items, "count": len(items)})

    @app.route("/inspect", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route("/inspect/<path:subpath>", methods=ALL_METHODS)
    def inspect(subpath: str):
        return handle_security_pipeline(_normalize_forwarded_path(subpath), forward_to_backend=False)

    @app.route("/protected", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route("/protected/<path:subpath>", methods=ALL_METHODS)
    def protected(subpath: str):
        return handle_security_pipeline(_normalize_forwarded_path(subpath), forward_to_backend=False)

    @app.route("/proxy", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route("/proxy/<path:subpath>", methods=ALL_METHODS)
    def proxy(subpath: str):
        return handle_security_pipeline(_normalize_forwarded_path(subpath), forward_to_backend=True)

    @app.route("/<path:subpath>", methods=ALL_METHODS)
    def transparent_proxy(subpath: str):
        if not current_settings.transparent_proxy:
            return jsonify({"message": "Route not found"}), 404
        return handle_security_pipeline(_normalize_forwarded_path(subpath), forward_to_backend=True)

    return app


def create_api_app(app_settings: Optional[Settings] = None) -> Flask:
    return create_app(app_settings=app_settings, serve_frontend=False)


app = create_app()


if __name__ == "__main__":
    logger.info("Starting %s on %s:%s", settings.app_name, settings.host, settings.port)
    app.run(host=settings.host, port=settings.port, debug=settings.debug)
