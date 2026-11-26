import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from core.data_ingestion import RequestRecord
from core.feature_engineering import extract_features
from core.ml_models import WeightedRiskModel
from core.rate_limiter import RateLimitResult
from core.rule_engine import check_rules
from core.storage import HistorySnapshot
from utils import build_full_url, fingerprint, json_dumps, sha256_hex, shorten


def _make_record(
    index: int,
    *,
    method: str,
    path: str,
    query: str = "",
    body: str = "",
    remote_addr: str = "10.0.0.10",
    user_agent: str = "Mozilla/5.0",
    session_id: str = "anonymous",
    content_type: str = "",
    host: str = "training.local",
) -> RequestRecord:
    timestamp_dt = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index)
    timestamp = timestamp_dt.isoformat(timespec="seconds")
    body_bytes = body.encode("utf-8")
    headers: Dict[str, str] = {
        "Host": host,
        "User-Agent": user_agent,
    }
    if content_type:
        headers["Content-Type"] = content_type
    url = build_full_url("http", host, path, query)
    return RequestRecord(
        request_id="pattern-{0:04d}".format(index),
        timestamp=timestamp,
        timestamp_epoch=timestamp_dt.timestamp(),
        method=method.upper(),
        scheme="http",
        host=host,
        path=path,
        gateway_path=path,
        query_string=query,
        url=url,
        headers=headers,
        body_text=body,
        body_bytes=body_bytes,
        body_length=len(body_bytes),
        remote_addr=remote_addr,
        user_agent=user_agent,
        referer="",
        content_type=content_type,
        session_id=session_id,
        request_fingerprint=fingerprint(method.upper(), path, query, body),
        payload_hash=sha256_hex(body_bytes),
        payload_preview=shorten(body, 160),
        cookies_count=0,
    )


def _scenario(
    family: str,
    label: str,
    index: int,
    *,
    method: str,
    path: str,
    query: str = "",
    body: str = "",
    remote_addr: str = "10.0.0.10",
    user_agent: str = "Mozilla/5.0",
    session_id: str = "anonymous",
    content_type: str = "",
    ip_request_count_window: int = 0,
    ip_block_count_window: int = 0,
    session_request_count_window: int = 0,
    fingerprint_reuse_count: int = 0,
    path_hits_window: int = 0,
    unique_paths_window: int = 0,
    allowed: bool = True,
    remaining_tokens: float = 40.0,
    expected_action: str = "allow",
) -> Dict[str, object]:
    return {
        "family": family,
        "label": label,
        "expected_action": expected_action,
        "record": _make_record(
            index,
            method=method,
            path=path,
            query=query,
            body=body,
            remote_addr=remote_addr,
            user_agent=user_agent,
            session_id=session_id,
            content_type=content_type,
        ),
        "history": HistorySnapshot(
            ip_request_count_window=ip_request_count_window,
            ip_block_count_window=ip_block_count_window,
            session_request_count_window=session_request_count_window,
            fingerprint_reuse_count=fingerprint_reuse_count,
            path_hits_window=path_hits_window,
            unique_paths_window=unique_paths_window,
        ),
        "rate_limit": RateLimitResult(
            allowed=allowed,
            remaining_tokens=remaining_tokens,
            capacity=45.0,
            refill_rate=0.75,
            backend="synthetic",
        ),
    }


def _build_scenarios() -> List[Dict[str, object]]:
    scenarios: List[Dict[str, object]] = []
    index = 1

    benign_templates = [
        ("GET", "/", "message=hello", "", "Mozilla/5.0", "", "user-benign"),
        ("GET", "/products", "page=1&sort=name", "", "Mozilla/5.0", "", "user-benign"),
        ("GET", "/api/hello", "name=beta", "", "Mozilla/5.0", "", "user-benign"),
        ("POST", "/contact", "", "name=Alice&message=Need help", "Mozilla/5.0", "application/x-www-form-urlencoded", "user-form"),
        ("POST", "/api/orders", "", "{\"item\":\"book\",\"qty\":1}", "Mozilla/5.0", "application/json", "user-json"),
        ("GET", "/blog/2026/launch", "", "", "Mozilla/5.0", "", "user-benign"),
    ]
    for repeat in range(4):
        for method, path, query, body, user_agent, content_type, session_id in benign_templates:
            scenarios.append(
                _scenario(
                    "benign",
                    "benign",
                    index,
                    method=method,
                    path=path,
                    query=query,
                    body=body,
                    user_agent=user_agent,
                    content_type=content_type,
                    session_id="{0}-{1}".format(session_id, repeat),
                    remote_addr="10.0.0.{0}".format(10 + repeat),
                    ip_request_count_window=repeat,
                    session_request_count_window=repeat,
                    fingerprint_reuse_count=max(repeat - 1, 0),
                    path_hits_window=repeat,
                    unique_paths_window=repeat + 1,
                    remaining_tokens=44.0 - repeat,
                    expected_action="allow",
                )
            )
            index += 1

    sqli_queries = [
        "id=1 UNION SELECT username,password FROM users",
        "user=admin' OR 1=1 --",
        "search=test;DROP TABLE audit_log",
        "item=1 WAITFOR DELAY '0:0:5'",
    ]
    for query in sqli_queries * 3:
        scenarios.append(
            _scenario(
                "sql_injection",
                "malicious",
                index,
                method="GET",
                path="/products",
                query=query,
                remote_addr="10.0.1.10",
                user_agent="sqlmap/1.8",
                ip_request_count_window=12,
                fingerprint_reuse_count=4,
                path_hits_window=6,
                unique_paths_window=3,
                remaining_tokens=10.0,
                expected_action="block",
            )
        )
        index += 1

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
    ]
    for payload in xss_payloads * 3:
        scenarios.append(
            _scenario(
                "xss",
                "malicious",
                index,
                method="POST",
                path="/comments",
                body=payload,
                content_type="text/plain",
                remote_addr="10.0.2.11",
                user_agent="Mozilla/5.0",
                session_id="xss-user",
                ip_request_count_window=8,
                session_request_count_window=4,
                fingerprint_reuse_count=2,
                path_hits_window=3,
                unique_paths_window=2,
                remaining_tokens=14.0,
                expected_action="block",
            )
        )
        index += 1

    traversal_queries = [
        "file=../../etc/passwd",
        "template=..%2f..%2f..%2fwindows/win.ini",
        "path=..\\..\\boot.ini",
        "download=%2e%2e%2fsecret.txt",
    ]
    for query in traversal_queries * 3:
        scenarios.append(
            _scenario(
                "path_traversal",
                "malicious",
                index,
                method="GET",
                path="/download",
                query=query,
                remote_addr="10.0.3.12",
                user_agent="curl/8.0",
                ip_request_count_window=9,
                fingerprint_reuse_count=3,
                path_hits_window=4,
                unique_paths_window=2,
                remaining_tokens=12.0,
                expected_action="block",
            )
        )
        index += 1

    command_bodies = [
        "cmd=cat /etc/passwd",
        "name=test && whoami",
        "target=127.0.0.1; bash -c id",
        "host=server || powershell Get-ChildItem",
    ]
    for body in command_bodies * 3:
        scenarios.append(
            _scenario(
                "command_injection",
                "malicious",
                index,
                method="POST",
                path="/tools/ping",
                body=body,
                content_type="application/x-www-form-urlencoded",
                remote_addr="10.0.4.13",
                user_agent="python-requests/2.32",
                ip_request_count_window=7,
                fingerprint_reuse_count=3,
                path_hits_window=2,
                unique_paths_window=2,
                remaining_tokens=11.0,
                expected_action="block",
            )
        )
        index += 1

    for iteration in range(12):
        scenarios.append(
            _scenario(
                "ddos",
                "malicious",
                index,
                method="GET",
                path="/api/search",
                query="q=item{0}".format(iteration),
                remote_addr="10.0.5.14",
                user_agent="Go-http-client/1.1",
                ip_request_count_window=40 + iteration,
                fingerprint_reuse_count=6,
                path_hits_window=8,
                unique_paths_window=12 + (iteration % 3),
                allowed=iteration % 3 != 0,
                remaining_tokens=max(0.0, 3.0 - iteration * 0.15),
                expected_action="block",
            )
        )
        index += 1

    for iteration in range(12):
        scenarios.append(
            _scenario(
                "brute_force",
                "malicious",
                index,
                method="POST",
                path="/admin/login",
                body="username=admin&password=guess{0}".format(iteration),
                content_type="application/x-www-form-urlencoded",
                remote_addr="10.0.6.15",
                user_agent="curl/8.0",
                session_id="brute-force",
                ip_request_count_window=10 + iteration,
                session_request_count_window=5 + iteration,
                fingerprint_reuse_count=5,
                path_hits_window=6 + iteration,
                unique_paths_window=2,
                allowed=iteration % 4 != 0,
                remaining_tokens=max(1.0, 8.0 - iteration * 0.35),
                expected_action="block",
            )
        )
        index += 1

    recon_paths = [
        "/admin",
        "/wp-admin",
        "/config",
        "/phpmyadmin",
        "/backup",
    ]
    for repeat in range(2):
        for path in recon_paths:
            scenarios.append(
                _scenario(
                    "reconnaissance",
                    "malicious",
                    index,
                    method="GET",
                    path=path,
                    remote_addr="10.0.7.16",
                    user_agent="nikto/2.5",
                    ip_request_count_window=65 + repeat,
                    fingerprint_reuse_count=3,
                    path_hits_window=0,
                    unique_paths_window=15 + repeat,
                    remaining_tokens=16.0,
                    expected_action="monitor",
                )
            )
            index += 1

    for iteration in range(10):
        scenarios.append(
            _scenario(
                "automation_abuse",
                "malicious",
                index,
                method="GET",
                path="/admin/health" if iteration % 2 else "/api/export",
                query="batch={0}".format(iteration),
                remote_addr="10.0.8.17",
                user_agent="python-requests/2.32",
                ip_request_count_window=15 + iteration,
                fingerprint_reuse_count=4,
                path_hits_window=iteration % 3,
                unique_paths_window=5 + iteration,
                remaining_tokens=9.0,
                expected_action="monitor",
            )
        )
        index += 1

    evasive_queries = [
        "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "file=%252e%252e%252fetc%252fpasswd",
        "name=%2555%254e%2549%254f%254e%2520%2553%2545%254c%2545%2543%2554",
        "path=%2e%2e%2f%2e%2e%2fsecret",
    ]
    for query in evasive_queries * 3:
        scenarios.append(
            _scenario(
                "payload_evasion",
                "malicious",
                index,
                method="GET",
                path="/search",
                query=query,
                remote_addr="10.0.9.18",
                user_agent="Mozilla/5.0",
                ip_request_count_window=11,
                fingerprint_reuse_count=2,
                path_hits_window=1,
                unique_paths_window=4,
                remaining_tokens=10.0,
                expected_action="block",
            )
        )
        index += 1

    anomaly_paths = [
        "/a9f3/zz/{0}".format("x" * 20),
        "/api/edge/%7B%7D/{0}".format("q" * 18),
        "/content/{0}/raw".format("~" * 10),
        "/sync/{0}/delta".format("m" * 16),
    ]
    for iteration in range(12):
        path = anomaly_paths[iteration % len(anomaly_paths)]
        scenarios.append(
            _scenario(
                "anomaly",
                "malicious",
                index,
                method="PUT" if iteration % 2 else "GET",
                path=path,
                query="v={0}&nonce=%25{1:02d}".format(iteration, iteration),
                body="{\"blob\":\"" + ("A" * (200 + iteration * 15)) + "\"}" if iteration % 2 else "",
                content_type="application/json" if iteration % 2 else "",
                remote_addr="10.0.10.19",
                user_agent="aiohttp/3.9",
                session_id="anomaly-session",
                ip_request_count_window=18 + iteration,
                session_request_count_window=10 + iteration,
                fingerprint_reuse_count=1,
                path_hits_window=0,
                unique_paths_window=18 + iteration,
                remaining_tokens=6.0,
                expected_action="monitor",
            )
        )
        index += 1

    return scenarios


def generate_pattern_dataset_rows(settings) -> Tuple[List[str], List[Dict[str, object]]]:
    heuristic_model = WeightedRiskModel(weights=dict(settings.model_weights), bias=settings.model_bias)
    rows: List[Dict[str, object]] = []
    feature_names = set()

    for scenario in _build_scenarios():
        record = scenario["record"]
        history_snapshot = scenario["history"]
        rate_limit_result = scenario["rate_limit"]
        feature_map = extract_features(record, history_snapshot, rate_limit_result, settings)
        rule_result = check_rules(
            request_record=record,
            features=feature_map,
            history_snapshot=history_snapshot,
            rate_limit_result=rate_limit_result,
            blacklist_record=None,
            manual_block_rule=None,
            settings=settings,
        )
        heuristic_score = heuristic_model.predict_with_breakdown(feature_map)
        family = str(scenario["family"])
        attack_types = list(rule_result.attack_types)
        if family != "benign" and family not in attack_types:
            attack_types.append(family)
        feature_names.update(feature_map.keys())
        rows.append(
            {
                "request_id": record.request_id,
                "timestamp": record.timestamp,
                "method": record.method,
                "path": record.path,
                "remote_addr": record.remote_addr,
                "label": scenario["label"],
                "attack_family": family,
                "source_dataset": "synthetic_attack_patterns",
                "expected_action": scenario["expected_action"],
                "attack_types_json": json_dumps(attack_types),
                "rule_block": int(rule_result.should_block),
                "hybrid_block": int(rule_result.should_block or heuristic_score.score >= settings.block_threshold),
                "features": feature_map,
            }
        )

    return sorted(feature_names), rows


def write_pattern_dataset(output_path: Path, settings) -> Path:
    feature_names, rows = generate_pattern_dataset_rows(settings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "request_id",
                "timestamp",
                "method",
                "path",
                "remote_addr",
                "label",
                "attack_family",
                "source_dataset",
                "expected_action",
                "attack_types_json",
                "rule_block",
                "hybrid_block",
            ]
            + feature_names
        )
        for row in rows:
            writer.writerow(
                [
                    row["request_id"],
                    row["timestamp"],
                    row["method"],
                    row["path"],
                    row["remote_addr"],
                    row["label"],
                    row["attack_family"],
                    row["source_dataset"],
                    row["expected_action"],
                    row["attack_types_json"],
                    row["rule_block"],
                    row["hybrid_block"],
                ]
                + [row["features"].get(feature_name, 0.0) for feature_name in feature_names]
            )
    return output_path
