from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import RLock
from time import time
from typing import Dict, Tuple

from utils import clamp, to_iso


def _round_float(value: float, places: int = 3) -> float:
    return round(float(value or 0.0), places)


@dataclass
class ConnectionSnapshot:
    enabled: bool
    request_id: str
    remote_addr: str
    endpoint_key: str
    endpoint_label: str
    scope: str
    active_connections_ip: int
    active_connections_endpoint: int
    concurrent_sessions_source: int
    connection_burst_ip: int
    connection_burst_endpoint: int
    new_connections_per_second_ip: int
    stale_connections_ip: int
    stale_connections_endpoint: int
    active_pressure: float
    connection_per_ip_pressure: float
    burst_pressure: float
    new_connections_per_second_pressure: float
    stale_pressure: float
    concurrent_sessions_pressure: float
    risk_score: float
    risk_band: str
    reasons: list[str]
    thresholds: Dict[str, int | float]
    monitor_triggered: bool
    block_triggered: bool
    half_open_mode: str = "application_approximation"

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "request_id": self.request_id,
            "remote_addr": self.remote_addr,
            "endpoint_key": self.endpoint_key,
            "endpoint_label": self.endpoint_label,
            "scope": self.scope,
            "active_connections_ip": self.active_connections_ip,
            "active_connections_endpoint": self.active_connections_endpoint,
            "concurrent_sessions_source": self.concurrent_sessions_source,
            "connection_burst_ip": self.connection_burst_ip,
            "connection_burst_endpoint": self.connection_burst_endpoint,
            "new_connections_per_second_ip": self.new_connections_per_second_ip,
            "stale_connections_ip": self.stale_connections_ip,
            "stale_connections_endpoint": self.stale_connections_endpoint,
            "active_pressure": self.active_pressure,
            "connection_per_ip_pressure": self.connection_per_ip_pressure,
            "burst_pressure": self.burst_pressure,
            "new_connections_per_second_pressure": self.new_connections_per_second_pressure,
            "stale_pressure": self.stale_pressure,
            "concurrent_sessions_pressure": self.concurrent_sessions_pressure,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "reasons": list(self.reasons),
            "thresholds": dict(self.thresholds),
            "monitor_triggered": self.monitor_triggered,
            "block_triggered": self.block_triggered,
            "half_open_mode": self.half_open_mode,
        }


class ConnectionTracker:
    def __init__(self) -> None:
        self._lock = RLock()
        self._active: dict[str, dict[str, object]] = {}
        self._recent_ip: dict[str, deque[float]] = defaultdict(deque)
        self._recent_endpoint: dict[Tuple[str, str], deque[float]] = defaultdict(deque)
        self._stale_ip: dict[str, deque[float]] = defaultdict(deque)
        self._stale_endpoint: dict[Tuple[str, str], deque[float]] = defaultdict(deque)

    def _endpoint_key(self, request_record, endpoint_policy: Dict[str, object]) -> Tuple[str, str]:
        policy_id = str(endpoint_policy.get("policy_id") or "").strip()
        endpoint_key = policy_id or str(endpoint_policy.get("matched_path") or getattr(request_record, "path", "/") or "/")
        endpoint_label = str(endpoint_policy.get("name") or endpoint_key)
        return endpoint_key, endpoint_label

    def _session_key(self, request_record) -> str:
        session_id = str(getattr(request_record, "session_id", "") or "").strip()
        if session_id and session_id.lower() != "anonymous":
            return "session:{0}".format(session_id[:128])
        user_agent = str(getattr(request_record, "user_agent", "") or "unknown").strip().lower()
        return "anonymous:{0}".format(user_agent[:64] or "unknown")

    def _recent_count_since(self, queue: deque[float], cutoff: float) -> int:
        count = 0
        for value in reversed(queue):
            if value < cutoff:
                break
            count += 1
        return count

    def _cleanup(self, now_epoch: float, settings) -> None:
        window_seconds = max(int(getattr(settings, "connection_window_seconds", 30) or 30), 1)
        stale_seconds = max(int(getattr(settings, "connection_stale_seconds", 20) or 20), 1)
        window_cutoff = now_epoch - float(window_seconds)
        stale_cutoff = now_epoch - float(stale_seconds)

        for bucket in (self._recent_ip, self._stale_ip):
            for key in list(bucket.keys()):
                queue = bucket[key]
                while queue and queue[0] < window_cutoff:
                    queue.popleft()
                if not queue:
                    bucket.pop(key, None)

        for bucket in (self._recent_endpoint, self._stale_endpoint):
            for key in list(bucket.keys()):
                queue = bucket[key]
                while queue and queue[0] < window_cutoff:
                    queue.popleft()
                if not queue:
                    bucket.pop(key, None)

        stale_request_ids = [request_id for request_id, item in self._active.items() if float(item["started_at"]) <= stale_cutoff]
        for request_id in stale_request_ids:
            item = self._active.pop(request_id, None)
            if not item:
                continue
            remote_addr = str(item["remote_addr"])
            endpoint_key = str(item["endpoint_key"])
            self._stale_ip[remote_addr].append(now_epoch)
            self._stale_endpoint[(remote_addr, endpoint_key)].append(now_epoch)

    def _thresholds(self, settings, endpoint_policy: Dict[str, object]) -> Dict[str, int | float]:
        settings_map = dict(endpoint_policy.get("settings") or {})
        return {
            "monitor_active": max(int(settings_map.get("connection_monitor_active", getattr(settings, "connection_monitor_active_threshold", 6)) or getattr(settings, "connection_monitor_active_threshold", 6)), 1),
            "block_active": max(int(settings_map.get("connection_block_active", getattr(settings, "connection_block_active_threshold", 12)) or getattr(settings, "connection_block_active_threshold", 12)), 2),
            "monitor_per_ip": max(int(settings_map.get("connection_monitor_per_ip", getattr(settings, "connection_monitor_per_ip_threshold", 6)) or getattr(settings, "connection_monitor_per_ip_threshold", 6)), 1),
            "block_per_ip": max(int(settings_map.get("connection_block_per_ip", getattr(settings, "connection_block_per_ip_threshold", 12)) or getattr(settings, "connection_block_per_ip_threshold", 12)), 2),
            "monitor_burst": max(int(settings_map.get("connection_burst_monitor", getattr(settings, "connection_monitor_burst_threshold", 10)) or getattr(settings, "connection_monitor_burst_threshold", 10)), 1),
            "block_burst": max(int(settings_map.get("connection_burst_block", getattr(settings, "connection_block_burst_threshold", 18)) or getattr(settings, "connection_block_burst_threshold", 18)), 2),
            "monitor_new_per_second": max(int(settings_map.get("connection_new_per_second_monitor", getattr(settings, "connection_monitor_new_connections_per_second", 4)) or getattr(settings, "connection_monitor_new_connections_per_second", 4)), 1),
            "block_new_per_second": max(int(settings_map.get("connection_new_per_second_block", getattr(settings, "connection_block_new_connections_per_second", 8)) or getattr(settings, "connection_block_new_connections_per_second", 8)), 2),
            "monitor_stale": max(int(settings_map.get("connection_stale_monitor", getattr(settings, "connection_monitor_stale_threshold", 2)) or getattr(settings, "connection_monitor_stale_threshold", 2)), 1),
            "block_stale": max(int(settings_map.get("connection_stale_block", getattr(settings, "connection_block_stale_threshold", 5)) or getattr(settings, "connection_block_stale_threshold", 5)), 2),
            "monitor_sessions_per_source": max(int(settings_map.get("connection_sessions_monitor", getattr(settings, "connection_monitor_sessions_per_source", 3)) or getattr(settings, "connection_monitor_sessions_per_source", 3)), 1),
            "block_sessions_per_source": max(int(settings_map.get("connection_sessions_block", getattr(settings, "connection_block_sessions_per_source", 6)) or getattr(settings, "connection_block_sessions_per_source", 6)), 2),
            "window_seconds": max(int(getattr(settings, "connection_window_seconds", 30) or 30), 1),
            "stale_seconds": max(int(getattr(settings, "connection_stale_seconds", 20) or 20), 1),
            "per_second_window": 1,
        }

    def register(self, request_record, endpoint_policy: Dict[str, object], settings) -> ConnectionSnapshot:
        with self._lock:
            now_epoch = time()
            self._cleanup(now_epoch, settings)
            endpoint_key, endpoint_label = self._endpoint_key(request_record, endpoint_policy)
            remote_addr = str(getattr(request_record, "remote_addr", "") or "unknown")
            self._active[str(getattr(request_record, "request_id", ""))] = {
                "remote_addr": remote_addr,
                "endpoint_key": endpoint_key,
                "endpoint_label": endpoint_label,
                "session_key": self._session_key(request_record),
                "started_at": now_epoch,
            }
            self._recent_ip[remote_addr].append(now_epoch)
            self._recent_endpoint[(remote_addr, endpoint_key)].append(now_epoch)
            return self._build_snapshot(request_record, endpoint_policy, settings, now_epoch)

    def release(self, request_id: str) -> None:
        if not request_id:
            return
        with self._lock:
            self._active.pop(str(request_id), None)

    def snapshot(self, request_record, endpoint_policy: Dict[str, object], settings) -> ConnectionSnapshot:
        with self._lock:
            now_epoch = time()
            self._cleanup(now_epoch, settings)
            return self._build_snapshot(request_record, endpoint_policy, settings, now_epoch)

    def _build_snapshot(self, request_record, endpoint_policy: Dict[str, object], settings, now_epoch: float) -> ConnectionSnapshot:
        enabled = bool(getattr(settings, "connection_tracking_enabled", True))
        endpoint_key, endpoint_label = self._endpoint_key(request_record, endpoint_policy)
        remote_addr = str(getattr(request_record, "remote_addr", "") or "unknown")
        endpoint_tuple = (remote_addr, endpoint_key)
        thresholds = self._thresholds(settings, endpoint_policy)
        second_cutoff = now_epoch - float(thresholds["per_second_window"])

        active_connections_ip = sum(1 for item in self._active.values() if item["remote_addr"] == remote_addr)
        active_connections_endpoint = sum(
            1 for item in self._active.values() if item["remote_addr"] == remote_addr and item["endpoint_key"] == endpoint_key
        )
        concurrent_sessions_source = len(
            {
                str(item.get("session_key") or "")
                for item in self._active.values()
                if item["remote_addr"] == remote_addr and str(item.get("session_key") or "")
            }
        )
        connection_burst_ip = len(self._recent_ip.get(remote_addr, ()))
        connection_burst_endpoint = len(self._recent_endpoint.get(endpoint_tuple, ()))
        new_connections_per_second_ip = self._recent_count_since(self._recent_ip.get(remote_addr, deque()), second_cutoff)
        stale_connections_ip = len(self._stale_ip.get(remote_addr, ()))
        stale_connections_endpoint = len(self._stale_endpoint.get(endpoint_tuple, ()))

        active_pressure = max(
            active_connections_ip / float(max(int(thresholds["block_active"]), 1)),
            active_connections_endpoint / float(max(int(thresholds["block_active"]), 1)),
        )
        connection_per_ip_pressure = active_connections_ip / float(max(int(thresholds["block_per_ip"]), 1))
        burst_pressure = max(
            connection_burst_ip / float(max(int(thresholds["block_burst"]), 1)),
            connection_burst_endpoint / float(max(int(thresholds["block_burst"]), 1)),
        )
        new_connections_per_second_pressure = new_connections_per_second_ip / float(max(int(thresholds["block_new_per_second"]), 1))
        stale_pressure = max(
            stale_connections_ip / float(max(int(thresholds["block_stale"]), 1)),
            stale_connections_endpoint / float(max(int(thresholds["block_stale"]), 1)),
        )
        concurrent_sessions_pressure = concurrent_sessions_source / float(max(int(thresholds["block_sessions_per_source"]), 1))
        risk_score = _round_float(
            min(
                max(
                    active_pressure,
                    connection_per_ip_pressure,
                    burst_pressure,
                    new_connections_per_second_pressure,
                    stale_pressure,
                    concurrent_sessions_pressure,
                ),
                2.5,
            ),
            3,
        )

        reasons: list[str] = []
        if active_connections_ip >= int(thresholds["monitor_per_ip"]):
            reasons.append(
                "Connections from {0} reached {1} active in-flight requests.".format(remote_addr, active_connections_ip)
            )
        if active_connections_endpoint >= int(thresholds["monitor_active"]):
            reasons.append(
                "Concurrent in-flight requests on {0} reached {1}.".format(endpoint_label, active_connections_endpoint)
            )
        if connection_burst_endpoint >= int(thresholds["monitor_burst"]):
            reasons.append(
                "Connection burst on {0} reached {1} starts inside the L4 window.".format(endpoint_label, connection_burst_endpoint)
            )
        if new_connections_per_second_ip >= int(thresholds["monitor_new_per_second"]):
            reasons.append(
                "New connections from {0} reached {1} within one second.".format(remote_addr, new_connections_per_second_ip)
            )
        if stale_connections_endpoint >= int(thresholds["monitor_stale"]):
            reasons.append(
                "Approximate half-open or abandoned in-flight requests were observed on {0}.".format(endpoint_label)
            )
        if concurrent_sessions_source >= int(thresholds["monitor_sessions_per_source"]):
            reasons.append(
                "Concurrent sessions from {0} reached {1} tracked session buckets.".format(remote_addr, concurrent_sessions_source)
            )
        if not reasons and enabled:
            reasons.append("Connection-level pressure is currently within the configured Layer 4 window.")

        block_triggered = enabled and (
            active_connections_ip >= int(thresholds["block_per_ip"])
            or active_connections_endpoint >= int(thresholds["block_active"])
            or connection_burst_ip >= int(thresholds["block_burst"])
            or connection_burst_endpoint >= int(thresholds["block_burst"])
            or new_connections_per_second_ip >= int(thresholds["block_new_per_second"])
            or stale_connections_ip >= int(thresholds["block_stale"])
            or stale_connections_endpoint >= int(thresholds["block_stale"])
            or concurrent_sessions_source >= int(thresholds["block_sessions_per_source"])
        )
        monitor_triggered = enabled and not block_triggered and (
            active_connections_ip >= int(thresholds["monitor_per_ip"])
            or active_connections_endpoint >= int(thresholds["monitor_active"])
            or connection_burst_ip >= int(thresholds["monitor_burst"])
            or connection_burst_endpoint >= int(thresholds["monitor_burst"])
            or new_connections_per_second_ip >= int(thresholds["monitor_new_per_second"])
            or stale_connections_ip >= int(thresholds["monitor_stale"])
            or stale_connections_endpoint >= int(thresholds["monitor_stale"])
            or concurrent_sessions_source >= int(thresholds["monitor_sessions_per_source"])
        )

        if block_triggered:
            risk_band = "critical"
        elif monitor_triggered:
            risk_band = "high"
        elif risk_score >= 0.5:
            risk_band = "medium"
        else:
            risk_band = "low"

        return ConnectionSnapshot(
            enabled=enabled,
            request_id=str(getattr(request_record, "request_id", "") or ""),
            remote_addr=remote_addr,
            endpoint_key=endpoint_key,
            endpoint_label=endpoint_label,
            scope=str(endpoint_policy.get("bucket_scope", "ip") or "ip"),
            active_connections_ip=active_connections_ip,
            active_connections_endpoint=active_connections_endpoint,
            concurrent_sessions_source=concurrent_sessions_source,
            connection_burst_ip=connection_burst_ip,
            connection_burst_endpoint=connection_burst_endpoint,
            new_connections_per_second_ip=new_connections_per_second_ip,
            stale_connections_ip=stale_connections_ip,
            stale_connections_endpoint=stale_connections_endpoint,
            active_pressure=_round_float(active_pressure, 4),
            connection_per_ip_pressure=_round_float(connection_per_ip_pressure, 4),
            burst_pressure=_round_float(burst_pressure, 4),
            new_connections_per_second_pressure=_round_float(new_connections_per_second_pressure, 4),
            stale_pressure=_round_float(stale_pressure, 4),
            concurrent_sessions_pressure=_round_float(concurrent_sessions_pressure, 4),
            risk_score=risk_score,
            risk_band=risk_band,
            reasons=reasons,
            thresholds=thresholds,
            monitor_triggered=monitor_triggered,
            block_triggered=block_triggered,
        )

    def summary(self, settings) -> Dict[str, object]:
        with self._lock:
            now_epoch = time()
            self._cleanup(now_epoch, settings)
            active_by_ip: dict[str, int] = defaultdict(int)
            active_by_endpoint: dict[Tuple[str, str], int] = defaultdict(int)
            sessions_by_ip: dict[str, set[str]] = defaultdict(set)
            for item in self._active.values():
                remote_addr = str(item["remote_addr"])
                endpoint_key = str(item["endpoint_key"])
                active_by_ip[remote_addr] += 1
                active_by_endpoint[(remote_addr, endpoint_key)] += 1
                session_key = str(item.get("session_key") or "")
                if session_key:
                    sessions_by_ip[remote_addr].add(session_key)

            top_active_ips = sorted(
                (
                    {
                        "remote_addr": remote_addr,
                        "active_connections": count,
                    }
                    for remote_addr, count in active_by_ip.items()
                ),
                key=lambda item: (-item["active_connections"], item["remote_addr"]),
            )[:5]
            top_new_connection_ips = sorted(
                (
                    {
                        "remote_addr": remote_addr,
                        "new_connections_per_second": self._recent_count_since(queue, now_epoch - 1.0),
                    }
                    for remote_addr, queue in self._recent_ip.items()
                ),
                key=lambda item: (-item["new_connections_per_second"], item["remote_addr"]),
            )[:5]
            top_session_sources = sorted(
                (
                    {
                        "remote_addr": remote_addr,
                        "concurrent_sessions": len(session_keys),
                    }
                    for remote_addr, session_keys in sessions_by_ip.items()
                ),
                key=lambda item: (-item["concurrent_sessions"], item["remote_addr"]),
            )[:5]

            return {
                "enabled": bool(getattr(settings, "connection_tracking_enabled", True)),
                "active_connections_total": len(self._active),
                "tracked_ips": len(active_by_ip),
                "top_active_ips": top_active_ips,
                "top_new_connection_ips": top_new_connection_ips,
                "top_session_sources": top_session_sources,
                "max_new_connections_per_second": max([item["new_connections_per_second"] for item in top_new_connection_ips] or [0]),
                "max_concurrent_sessions_per_source": max([item["concurrent_sessions"] for item in top_session_sources] or [0]),
                "window_seconds": max(int(getattr(settings, "connection_window_seconds", 30) or 30), 1),
                "stale_seconds": max(int(getattr(settings, "connection_stale_seconds", 20) or 20), 1),
                "half_open_mode": "application_approximation",
            }
