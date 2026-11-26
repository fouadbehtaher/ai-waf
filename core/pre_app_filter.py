from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Callable, Deque, Dict, Iterable, Mapping, MutableMapping, Optional

from utils import get_client_ip, to_iso


logger = logging.getLogger(__name__)

BURST_WINDOW_SECONDS = 1.0
MANAGEMENT_EXEMPT_PREFIXES = (
    "/dashboard",
    "/legacy-dashboard",
    "/reports",
    "/health",
    "/api",
    "/assets",
)


def _epoch_to_iso(epoch_value: float) -> str:
    if epoch_value <= 0:
        return ""
    return datetime.fromtimestamp(epoch_value, tz=timezone.utc).isoformat(timespec="seconds")


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _headers_from_environ(environ: Mapping[str, object]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for key, value in environ.items():
        if not key.startswith("HTTP_"):
            continue
        header_name = key[5:].replace("_", "-").title()
        headers[header_name] = str(value or "")
    if environ.get("CONTENT_TYPE"):
        headers["Content-Type"] = str(environ.get("CONTENT_TYPE") or "")
    if environ.get("CONTENT_LENGTH"):
        headers["Content-Length"] = str(environ.get("CONTENT_LENGTH") or "")
    return headers


@dataclass(frozen=True)
class PreAppVolumetricDecision:
    allowed: bool
    reason: str = ""
    scope: str = ""
    status_code: int = 200
    retry_after_seconds: int = 0
    ip_address: str = ""
    path: str = ""
    threshold: int = 0
    observed: int = 0


@dataclass
class PreAppVolumetricFilter:
    settings_provider: Callable[[], object]
    management_exempt_prefixes: Iterable[str] = MANAGEMENT_EXEMPT_PREFIXES
    lock: threading.Lock = field(default_factory=threading.Lock)
    ip_window_hits: MutableMapping[str, Deque[float]] = field(default_factory=lambda: defaultdict(deque))
    ip_burst_hits: MutableMapping[str, Deque[float]] = field(default_factory=lambda: defaultdict(deque))
    ip_bytes_window: MutableMapping[str, Deque[tuple[float, int]]] = field(default_factory=lambda: defaultdict(deque))
    ip_bytes_totals: MutableMapping[str, int] = field(default_factory=lambda: defaultdict(int))
    global_window_hits: Deque[float] = field(default_factory=deque)
    temporary_ip_blocks: Dict[str, float] = field(default_factory=dict)
    blocked_ip_counts: MutableMapping[str, int] = field(default_factory=lambda: defaultdict(int))
    blocked_reason_counts: MutableMapping[str, int] = field(default_factory=lambda: defaultdict(int))
    total_seen: int = 0
    total_allowed: int = 0
    total_blocked: int = 0
    total_global_blocks: int = 0
    max_ip_window_hits: int = 0
    max_ip_burst_hits: int = 0
    max_global_window_hits: int = 0
    max_ip_bytes_window: int = 0
    last_blocked_at: str = ""
    last_blocked_reason: str = ""
    last_blocked_ip: str = ""

    def _prune(self, now_epoch: float, settings) -> None:
        window_seconds = max(int(getattr(settings, "pre_app_filter_window_seconds", 10) or 10), 1)
        while self.global_window_hits and now_epoch - self.global_window_hits[0] > float(window_seconds):
            self.global_window_hits.popleft()

        expired_blocks = [ip_address for ip_address, until_epoch in self.temporary_ip_blocks.items() if until_epoch <= now_epoch]
        for ip_address in expired_blocks:
            self.temporary_ip_blocks.pop(ip_address, None)

        ip_window_cutoff = now_epoch - float(window_seconds)
        burst_cutoff = now_epoch - BURST_WINDOW_SECONDS
        for ip_address in list(self.ip_window_hits.keys()):
            window_queue = self.ip_window_hits[ip_address]
            while window_queue and window_queue[0] < ip_window_cutoff:
                window_queue.popleft()
            if not window_queue:
                self.ip_window_hits.pop(ip_address, None)

        for ip_address in list(self.ip_burst_hits.keys()):
            burst_queue = self.ip_burst_hits[ip_address]
            while burst_queue and burst_queue[0] < burst_cutoff:
                burst_queue.popleft()
            if not burst_queue:
                self.ip_burst_hits.pop(ip_address, None)

        for ip_address in list(self.ip_bytes_window.keys()):
            bytes_queue = self.ip_bytes_window[ip_address]
            while bytes_queue and bytes_queue[0][0] < ip_window_cutoff:
                _, size = bytes_queue.popleft()
                self.ip_bytes_totals[ip_address] = max(int(self.ip_bytes_totals.get(ip_address, 0) or 0) - int(size or 0), 0)
            if not bytes_queue:
                self.ip_bytes_window.pop(ip_address, None)
                self.ip_bytes_totals.pop(ip_address, None)

    def _is_management_exempt(self, path: str) -> bool:
        normalized_path = str(path or "/").strip() or "/"
        return any(normalized_path.startswith(prefix) for prefix in self.management_exempt_prefixes)

    def evaluate(self, environ: Mapping[str, object]) -> PreAppVolumetricDecision:
        settings = self.settings_provider()
        if not bool(getattr(settings, "pre_app_filter_enabled", True)):
            return PreAppVolumetricDecision(allowed=True)

        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        if method == "OPTIONS":
            return PreAppVolumetricDecision(allowed=True)

        path = str(environ.get("PATH_INFO") or "/")
        if self._is_management_exempt(path):
            return PreAppVolumetricDecision(allowed=True)

        headers = _headers_from_environ(environ)
        ip_address = get_client_ip(headers, str(environ.get("REMOTE_ADDR") or ""))
        content_length = max(_safe_int(environ.get("CONTENT_LENGTH"), 0), 0)
        now_epoch = time.time()

        with self.lock:
            self._prune(now_epoch, settings)
            self.total_seen += 1

            window_hits = self.ip_window_hits[ip_address]
            burst_hits = self.ip_burst_hits[ip_address]
            bytes_hits = self.ip_bytes_window[ip_address]
            current_ip_bytes = int(self.ip_bytes_totals.get(ip_address, 0) or 0)

            projected_ip_window = len(window_hits) + 1
            projected_ip_burst = len(burst_hits) + 1
            projected_global_window = len(self.global_window_hits) + 1
            projected_ip_bytes = current_ip_bytes + content_length

            self.max_ip_window_hits = max(self.max_ip_window_hits, projected_ip_window)
            self.max_ip_burst_hits = max(self.max_ip_burst_hits, projected_ip_burst)
            self.max_global_window_hits = max(self.max_global_window_hits, projected_global_window)
            self.max_ip_bytes_window = max(self.max_ip_bytes_window, projected_ip_bytes)

            active_block_until = float(self.temporary_ip_blocks.get(ip_address) or 0.0)
            if active_block_until > now_epoch:
                retry_after = max(int(round(active_block_until - now_epoch)), 1)
                return self._register_block(
                    ip_address=ip_address,
                    path=path,
                    reason="IP is under a temporary volumetric pre-app block.",
                    scope="temporary_ip_block",
                    status_code=429,
                    retry_after_seconds=retry_after,
                    threshold=int(getattr(settings, "pre_app_filter_block_ttl_seconds", 15) or 15),
                    observed=projected_ip_window,
                )

            global_request_threshold = max(int(getattr(settings, "pre_app_filter_global_request_threshold", 600) or 600), 1)
            if projected_global_window > global_request_threshold:
                return self._register_block(
                    ip_address=ip_address,
                    path=path,
                    reason="Global volumetric pressure exceeded the pre-app gateway threshold.",
                    scope="global_window",
                    status_code=503,
                    retry_after_seconds=1,
                    threshold=global_request_threshold,
                    observed=projected_global_window,
                    apply_temporary_block=False,
                )

            ip_request_threshold = max(int(getattr(settings, "pre_app_filter_ip_request_threshold", 120) or 120), 1)
            if projected_ip_window > ip_request_threshold:
                return self._register_block(
                    ip_address=ip_address,
                    path=path,
                    reason="Per-IP request volume exceeded the pre-app gateway threshold.",
                    scope="ip_window",
                    status_code=429,
                    retry_after_seconds=max(int(getattr(settings, "pre_app_filter_block_ttl_seconds", 15) or 15), 1),
                    threshold=ip_request_threshold,
                    observed=projected_ip_window,
                )

            ip_burst_threshold = max(int(getattr(settings, "pre_app_filter_ip_burst_threshold", 40) or 40), 1)
            if projected_ip_burst > ip_burst_threshold:
                return self._register_block(
                    ip_address=ip_address,
                    path=path,
                    reason="Per-IP burst volume exceeded the pre-app gateway threshold.",
                    scope="ip_burst",
                    status_code=429,
                    retry_after_seconds=max(int(getattr(settings, "pre_app_filter_block_ttl_seconds", 15) or 15), 1),
                    threshold=ip_burst_threshold,
                    observed=projected_ip_burst,
                )

            ip_bytes_threshold = max(int(getattr(settings, "pre_app_filter_ip_bytes_threshold", 1048576) or 1048576), 1)
            if projected_ip_bytes > ip_bytes_threshold:
                return self._register_block(
                    ip_address=ip_address,
                    path=path,
                    reason="Per-IP byte volume exceeded the pre-app gateway threshold.",
                    scope="ip_bytes",
                    status_code=429,
                    retry_after_seconds=max(int(getattr(settings, "pre_app_filter_block_ttl_seconds", 15) or 15), 1),
                    threshold=ip_bytes_threshold,
                    observed=projected_ip_bytes,
                )

            self.global_window_hits.append(now_epoch)
            window_hits.append(now_epoch)
            burst_hits.append(now_epoch)
            bytes_hits.append((now_epoch, content_length))
            self.ip_bytes_totals[ip_address] = projected_ip_bytes
            self.total_allowed += 1

        return PreAppVolumetricDecision(allowed=True, ip_address=ip_address, path=path)

    def _register_block(
        self,
        ip_address: str,
        path: str,
        reason: str,
        scope: str,
        status_code: int,
        retry_after_seconds: int,
        threshold: int,
        observed: int,
        apply_temporary_block: bool = True,
    ) -> PreAppVolumetricDecision:
        if apply_temporary_block:
            self.temporary_ip_blocks[ip_address] = time.time() + float(max(retry_after_seconds, 1))
        else:
            self.total_global_blocks += 1

        self.total_blocked += 1
        self.blocked_ip_counts[ip_address] += 1
        self.blocked_reason_counts[scope] += 1
        self.last_blocked_at = to_iso()
        self.last_blocked_reason = reason
        self.last_blocked_ip = ip_address

        logger.warning(
            "Pre-app volumetric block: ip=%s path=%s scope=%s observed=%s threshold=%s status=%s reason=%s",
            ip_address,
            path,
            scope,
            observed,
            threshold,
            status_code,
            reason,
        )

        return PreAppVolumetricDecision(
            allowed=False,
            reason=reason,
            scope=scope,
            status_code=status_code,
            retry_after_seconds=max(retry_after_seconds, 1),
            ip_address=ip_address,
            path=path,
            threshold=threshold,
            observed=observed,
        )

    def summary(self, settings) -> Dict[str, object]:
        now_epoch = time.time()
        with self.lock:
            self._prune(now_epoch, settings)
            active_blocks = [
                {
                    "ip_address": ip_address,
                    "blocked_until_epoch": round(until_epoch, 3),
                    "blocked_until": _epoch_to_iso(float(until_epoch or 0.0)),
                }
                for ip_address, until_epoch in self.temporary_ip_blocks.items()
            ]
            top_blocked_ips = sorted(
                (
                    {
                        "ip_address": ip_address,
                        "blocked_events": int(count or 0),
                        "blocked_until_epoch": round(float(self.temporary_ip_blocks.get(ip_address) or 0.0), 3),
                        "blocked_until": _epoch_to_iso(float(self.temporary_ip_blocks.get(ip_address) or 0.0)),
                    }
                    for ip_address, count in self.blocked_ip_counts.items()
                ),
                key=lambda item: (-item["blocked_events"], item["ip_address"]),
            )[:5]
            blocked_reason_counts = dict(
                sorted(self.blocked_reason_counts.items(), key=lambda item: (-int(item[1] or 0), str(item[0])))
            )

        return {
            "enabled": bool(getattr(settings, "pre_app_filter_enabled", True)),
            "mode": "wsgi_pre_app",
            "summary": "Volumetric attacks are dropped at the WSGI gateway before Flask request parsing and the full inspection pipeline.",
            "window_seconds": max(int(getattr(settings, "pre_app_filter_window_seconds", 10) or 10), 1),
            "burst_window_seconds": BURST_WINDOW_SECONDS,
            "ip_request_threshold": max(int(getattr(settings, "pre_app_filter_ip_request_threshold", 120) or 120), 1),
            "ip_burst_threshold": max(int(getattr(settings, "pre_app_filter_ip_burst_threshold", 40) or 40), 1),
            "global_request_threshold": max(int(getattr(settings, "pre_app_filter_global_request_threshold", 600) or 600), 1),
            "ip_bytes_threshold": max(int(getattr(settings, "pre_app_filter_ip_bytes_threshold", 1048576) or 1048576), 1),
            "block_ttl_seconds": max(int(getattr(settings, "pre_app_filter_block_ttl_seconds", 15) or 15), 1),
            "management_exempt_prefixes": list(self.management_exempt_prefixes),
            "telemetry": {
                "total_seen": int(self.total_seen or 0),
                "allowed": int(self.total_allowed or 0),
                "blocked": int(self.total_blocked or 0),
                "global_blocks": int(self.total_global_blocks or 0),
                "active_ip_blocks": len(active_blocks),
                "active_blocks": active_blocks,
                "top_blocked_ips": top_blocked_ips,
                "blocked_reason_counts": blocked_reason_counts,
                "max_ip_window_hits": int(self.max_ip_window_hits or 0),
                "max_ip_burst_hits": int(self.max_ip_burst_hits or 0),
                "max_global_window_hits": int(self.max_global_window_hits or 0),
                "max_ip_bytes_window": int(self.max_ip_bytes_window or 0),
                "last_blocked_at": self.last_blocked_at,
                "last_blocked_reason": self.last_blocked_reason,
                "last_blocked_ip": self.last_blocked_ip,
            },
        }


class VolumetricPreAppMiddleware:
    def __init__(self, app, controller: PreAppVolumetricFilter):
        self.app = app
        self.controller = controller

    def __call__(self, environ, start_response):
        decision = self.controller.evaluate(environ)
        if decision.allowed:
            return self.app(environ, start_response)

        status = HTTPStatus(decision.status_code)
        payload = {
            "message": "Request blocked by the AI-based WAF before entering the application pipeline",
            "layer": "pre_app_volumetric_filter",
            "blocked_before_pipeline": True,
            "attack_types": ["ddos"],
            "reasons": [decision.reason],
            "scope": decision.scope,
            "ip_address": decision.ip_address,
            "path": decision.path,
            "threshold": decision.threshold,
            "observed": decision.observed,
            "retry_after_seconds": decision.retry_after_seconds,
        }
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("Retry-After", str(max(decision.retry_after_seconds, 1))),
            ("X-WAF-Pre-App-Filter", "volumetric"),
        ]
        start_response("{0} {1}".format(status.value, status.phrase), headers)
        return [body]
