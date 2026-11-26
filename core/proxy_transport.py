from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from time import time
from typing import Dict, Mapping
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

from core.data_ingestion import HOP_BY_HOP_HEADERS, ProxyResponseRecord
from utils import clamp, to_iso


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


@dataclass
class ProxyTransportDecision:
    allowed: bool
    status_code: int
    reasons: list[str] = field(default_factory=list)
    keepalive_requested: bool = False
    keepalive_abuse_score: int = 0
    keepalive_abuse_signal: bool = False
    force_connection_close: bool = False
    pool_protection_blocked: bool = False
    connect_timeout_seconds: float = 0.0
    read_timeout_seconds: float = 0.0
    active_upstream_requests: int = 0
    session_generation: int = 0
    concurrency_limit: int = 0
    attack_types: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "status_code": self.status_code,
            "reasons": list(self.reasons),
            "keepalive_requested": self.keepalive_requested,
            "keepalive_abuse_score": self.keepalive_abuse_score,
            "keepalive_abuse_signal": self.keepalive_abuse_signal,
            "force_connection_close": self.force_connection_close,
            "pool_protection_blocked": self.pool_protection_blocked,
            "connect_timeout_seconds": _round_float(self.connect_timeout_seconds, 3),
            "read_timeout_seconds": _round_float(self.read_timeout_seconds, 3),
            "active_upstream_requests": self.active_upstream_requests,
            "session_generation": self.session_generation,
            "concurrency_limit": self.concurrency_limit,
            "attack_types": list(self.attack_types),
        }


class ProxyTransportControlError(RuntimeError):
    def __init__(self, message: str, status_code: int, attack_types: list[str], decision: ProxyTransportDecision):
        super().__init__(message)
        self.message = message
        self.status_code = int(status_code)
        self.attack_types = list(attack_types)
        self.decision = decision


class ProxyTransportController:
    def __init__(self) -> None:
        self._lock = RLock()
        self._session: requests.Session | None = None
        self._settings_signature: tuple | None = None
        self._session_generation = 0
        self._last_used_epoch = 0.0
        self._last_session_refresh_at = ""
        self._active_upstream_requests = 0
        self._max_active_upstream_requests = 0
        self._idle_recycles = 0
        self._pool_protection_blocks = 0
        self._keepalive_close_events = 0
        self._keepalive_abuse_events = 0
        self._keepalive_block_events = 0
        self._total_proxied_requests = 0

    def _settings_signature_for(self, settings) -> tuple:
        return (
            bool(getattr(settings, "proxy_transport_controls_enabled", True)),
            float(getattr(settings, "proxy_connect_timeout_seconds", 3.0) or 3.0),
            float(getattr(settings, "proxy_read_timeout_seconds", 10.0) or 10.0),
            int(getattr(settings, "proxy_idle_pool_recycle_seconds", 30) or 30),
            int(getattr(settings, "proxy_upstream_pool_connections", 16) or 16),
            int(getattr(settings, "proxy_upstream_pool_maxsize", 32) or 32),
            int(getattr(settings, "proxy_upstream_concurrency_limit", 24) or 24),
            bool(getattr(settings, "proxy_upstream_pool_block", True)),
            bool(getattr(settings, "proxy_keepalive_abuse_protection_enabled", True)),
            int(getattr(settings, "proxy_keepalive_monitor_score", 3) or 3),
            int(getattr(settings, "proxy_keepalive_block_score", 5) or 5),
        )

    def _close_session_unlocked(self) -> None:
        session = self._session
        self._session = None
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    def _build_session_unlocked(self, settings) -> None:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=max(int(getattr(settings, "proxy_upstream_pool_connections", 16) or 16), 1),
            pool_maxsize=max(int(getattr(settings, "proxy_upstream_pool_maxsize", 32) or 32), 1),
            max_retries=0,
            pool_block=bool(getattr(settings, "proxy_upstream_pool_block", True)),
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._close_session_unlocked()
        self._session = session
        self._settings_signature = self._settings_signature_for(settings)
        self._session_generation += 1
        self._last_session_refresh_at = to_iso()
        self._last_used_epoch = time()

    def _ensure_session_unlocked(self, settings) -> None:
        signature = self._settings_signature_for(settings)
        now_epoch = time()
        idle_recycle_seconds = max(int(getattr(settings, "proxy_idle_pool_recycle_seconds", 30) or 30), 1)
        session_missing = self._session is None
        settings_changed = signature != self._settings_signature
        idle_expired = bool(self._session is not None and self._last_used_epoch and (now_epoch - self._last_used_epoch) >= idle_recycle_seconds)

        if session_missing or settings_changed or idle_expired:
            if idle_expired and not session_missing and not settings_changed:
                self._idle_recycles += 1
            self._build_session_unlocked(settings)

    def _filtered_headers(self, record, force_connection_close: bool, session_generation: int) -> Dict[str, str]:
        forwarded_headers = {
            key: value
            for key, value in dict(getattr(record, "headers", {}) or {}).items()
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() not in {"host", "content-length"}
        }
        prior_forwarded = str(record.headers.get("X-Forwarded-For", "") or "").strip()
        if prior_forwarded:
            forwarded_headers["X-Forwarded-For"] = "{0}, {1}".format(prior_forwarded, record.remote_addr)
        else:
            forwarded_headers["X-Forwarded-For"] = record.remote_addr
        forwarded_headers["X-WAF-Request-ID"] = record.request_id
        forwarded_headers["X-WAF-Proxy-Connection-Mode"] = "close" if force_connection_close else "keepalive"
        forwarded_headers["X-WAF-Upstream-Pool-Generation"] = str(session_generation)
        forwarded_headers["Connection"] = "close" if force_connection_close else "keep-alive"
        return forwarded_headers

    def analyze_request(self, record, history_snapshot, rate_limit_result, transport_snapshot, settings) -> ProxyTransportDecision:
        headers = dict(getattr(record, "headers", {}) or {})
        connection_header = str(headers.get("Connection", "") or "").strip().lower()
        keep_alive_header = str(headers.get("Keep-Alive", "") or "").strip()
        keepalive_requested = "keep-alive" in connection_header or bool(keep_alive_header)
        user_agent = str(getattr(record, "user_agent", "") or "").strip().lower()
        automation_signal = any(
            token in user_agent for token in tuple(getattr(settings, "automation_user_agents", ()) or ())
        )
        no_session_state = (
            str(getattr(record, "session_id", "anonymous") or "anonymous") == "anonymous"
            and int(getattr(record, "cookies_count", 0) or 0) == 0
        )
        transport_map = transport_snapshot.as_dict() if hasattr(transport_snapshot, "as_dict") else dict(transport_snapshot or {})

        score = 0
        reasons: list[str] = []
        if keepalive_requested:
            score += 1
            reasons.append("Client requested keep-alive reuse.")
        if keep_alive_header:
            score += 1
            reasons.append("Client supplied an explicit Keep-Alive header.")
        if bool(transport_map.get("connection_churn_signal")):
            score += 1
            reasons.append("Connection churn is already elevated for this source.")
        if bool(transport_map.get("short_lived_abusive_signal")):
            score += 1
            reasons.append("Short-lived abusive connection behavior was detected.")
        if bool(transport_map.get("retry_timeout_signal")):
            score += 1
            reasons.append("Retries/timeouts suggest unstable or abusive keep-alive reuse.")
        if float(getattr(rate_limit_result, "pressure", 0.0) or 0.0) >= 0.55:
            score += 1
            reasons.append("Token bucket pressure is elevated.")
        if int(getattr(history_snapshot, "ip_request_count_window", 0) or 0) >= max(int(getattr(settings, "rate_limit_max_requests", 30) or 30) // 3, 5):
            score += 1
            reasons.append("Recent request volume from this IP is high.")
        if automation_signal:
            score += 1
            reasons.append("Automation-style client identity is present.")
        if no_session_state:
            score += 1
            reasons.append("No durable session or cookie state is present.")

        enabled = bool(getattr(settings, "proxy_transport_controls_enabled", True))
        keepalive_protection = bool(getattr(settings, "proxy_keepalive_abuse_protection_enabled", True))
        monitor_score = max(int(getattr(settings, "proxy_keepalive_monitor_score", 3) or 3), 1)
        block_score = max(int(getattr(settings, "proxy_keepalive_block_score", 5) or 5), monitor_score)
        keepalive_abuse_signal = enabled and keepalive_protection and score >= monitor_score
        force_connection_close = keepalive_abuse_signal
        attack_types: list[str] = []
        if keepalive_abuse_signal:
            with self._lock:
                self._keepalive_abuse_events += 1
            attack_types.append("anomaly")
        with self._lock:
            active_requests = self._active_upstream_requests
            session_generation = self._session_generation

        concurrency_limit = max(int(getattr(settings, "proxy_upstream_concurrency_limit", 24) or 24), 1)
        pool_protection_blocked = enabled and active_requests >= concurrency_limit
        if pool_protection_blocked:
            attack_types = ["ddos"]
            reasons.append(
                "Upstream connection pool protection rejected this request because {0} active upstream requests already reached the concurrency ceiling.".format(
                    active_requests
                )
            )
        elif keepalive_abuse_signal and keepalive_requested:
            reasons.append(
                "Proxy transport controls will close the upstream connection instead of keeping it alive for this request."
            )
        elif enabled:
            reasons.append("Proxy transport controls are within the configured operating window.")

        allowed = not pool_protection_blocked and not (keepalive_requested and keepalive_abuse_signal and score >= block_score)
        status_code = 200
        if pool_protection_blocked:
            status_code = 503
        elif not allowed:
            status_code = 429
            attack_types = ["anomaly"]
            reasons.append("Keep-alive abuse crossed the proxy transport hardening threshold.")

        return ProxyTransportDecision(
            allowed=allowed,
            status_code=status_code,
            reasons=reasons,
            keepalive_requested=keepalive_requested,
            keepalive_abuse_score=score,
            keepalive_abuse_signal=keepalive_abuse_signal,
            force_connection_close=force_connection_close,
            pool_protection_blocked=pool_protection_blocked,
            connect_timeout_seconds=float(getattr(settings, "proxy_connect_timeout_seconds", 3.0) or 3.0),
            read_timeout_seconds=float(getattr(settings, "proxy_read_timeout_seconds", 10.0) or 10.0),
            active_upstream_requests=active_requests,
            session_generation=session_generation,
            concurrency_limit=concurrency_limit,
            attack_types=attack_types,
        )

    def proxy_request(self, record, backend_url: str, settings, history_snapshot, rate_limit_result, transport_snapshot) -> tuple[ProxyResponseRecord, ProxyTransportDecision]:
        decision = self.analyze_request(record, history_snapshot, rate_limit_result, transport_snapshot, settings)
        if not decision.allowed:
            if decision.pool_protection_blocked:
                self._pool_protection_blocks += 1
                raise ProxyTransportControlError(
                    "Upstream connection pool protection rejected the request.",
                    503,
                    decision.attack_types or ["ddos"],
                    decision,
                )
            self._keepalive_block_events += 1
            raise ProxyTransportControlError(
                "Keep-alive abuse crossed the proxy transport hardening threshold.",
                429,
                decision.attack_types or ["anomaly"],
                decision,
            )

        with self._lock:
            self._ensure_session_unlocked(settings)
            self._active_upstream_requests += 1
            self._max_active_upstream_requests = max(self._max_active_upstream_requests, self._active_upstream_requests)
            active_session = self._session
            session_generation = self._session_generation
            self._last_used_epoch = time()
            if decision.force_connection_close:
                self._keepalive_close_events += 1
            decision.session_generation = session_generation
            decision.active_upstream_requests = self._active_upstream_requests

        normalized_base = backend_url.rstrip("/") + "/"
        target_url = urljoin(normalized_base, record.path.lstrip("/"))
        if record.query_string:
            target_url = "{0}?{1}".format(target_url, record.query_string)

        try:
            response = active_session.request(
                method=record.method,
                url=target_url,
                headers=self._filtered_headers(record, decision.force_connection_close, session_generation),
                data=record.body_bytes,
                timeout=(
                    float(getattr(settings, "proxy_connect_timeout_seconds", 3.0) or 3.0),
                    float(getattr(settings, "proxy_read_timeout_seconds", 10.0) or 10.0),
                ),
                allow_redirects=False,
            )
            with self._lock:
                self._total_proxied_requests += 1
            return (
                ProxyResponseRecord(
                    status_code=response.status_code,
                    headers={
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() not in HOP_BY_HOP_HEADERS
                    },
                    body=response.content,
                    elapsed_ms=response.elapsed.total_seconds() * 1000.0,
                    final_url=target_url,
                ),
                decision,
            )
        finally:
            with self._lock:
                self._active_upstream_requests = max(self._active_upstream_requests - 1, 0)
                self._last_used_epoch = time()

    def acquire_slot(self, settings) -> bool:
        with self._lock:
            self._ensure_session_unlocked(settings)
            concurrency_limit = max(int(getattr(settings, "proxy_upstream_concurrency_limit", 24) or 24), 1)
            if self._active_upstream_requests >= concurrency_limit:
                self._pool_protection_blocks += 1
                return False
            self._active_upstream_requests += 1
            self._max_active_upstream_requests = max(self._max_active_upstream_requests, self._active_upstream_requests)
            return True

    def release_slot(self) -> None:
        with self._lock:
            self._active_upstream_requests = max(self._active_upstream_requests - 1, 0)
            self._last_used_epoch = time()

    def summary(self, settings) -> dict:
        with self._lock:
            self._ensure_session_unlocked(settings)
            return {
                "enabled": bool(getattr(settings, "proxy_transport_controls_enabled", True)),
                "connect_timeout_seconds": _round_float(float(getattr(settings, "proxy_connect_timeout_seconds", 3.0) or 3.0), 3),
                "read_timeout_seconds": _round_float(float(getattr(settings, "proxy_read_timeout_seconds", 10.0) or 10.0), 3),
                "idle_pool_recycle_seconds": max(int(getattr(settings, "proxy_idle_pool_recycle_seconds", 30) or 30), 1),
                "upstream_pool_connections": max(int(getattr(settings, "proxy_upstream_pool_connections", 16) or 16), 1),
                "upstream_pool_maxsize": max(int(getattr(settings, "proxy_upstream_pool_maxsize", 32) or 32), 1),
                "upstream_concurrency_limit": max(int(getattr(settings, "proxy_upstream_concurrency_limit", 24) or 24), 1),
                "upstream_pool_block": bool(getattr(settings, "proxy_upstream_pool_block", True)),
                "keepalive_abuse_protection_enabled": bool(getattr(settings, "proxy_keepalive_abuse_protection_enabled", True)),
                "keepalive_monitor_score": max(int(getattr(settings, "proxy_keepalive_monitor_score", 3) or 3), 1),
                "keepalive_block_score": max(int(getattr(settings, "proxy_keepalive_block_score", 5) or 5), 1),
                "active_upstream_requests": self._active_upstream_requests,
                "max_active_upstream_requests": self._max_active_upstream_requests,
                "idle_recycles": self._idle_recycles,
                "pool_protection_blocks": self._pool_protection_blocks,
                "keepalive_close_events": self._keepalive_close_events,
                "keepalive_abuse_events": self._keepalive_abuse_events,
                "keepalive_block_events": self._keepalive_block_events,
                "total_proxied_requests": self._total_proxied_requests,
                "session_generation": self._session_generation,
                "last_session_refresh_at": self._last_session_refresh_at,
            }
