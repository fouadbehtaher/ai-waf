import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from core.attack_taxonomy import ATTACK_FAMILIES, attack_family_metadata, canonical_attack_type


_ATTACK_FAMILY_ORDER = {family.attack_type: index for index, family in enumerate(ATTACK_FAMILIES)}
_BENIGN_CONTROL_METADATA = {
    "attack_type": "benign_control",
    "label": "Benign Control Traffic",
    "description": "Known-safe requests generated during simulation to verify that legitimate traffic still passes through the WAF.",
}


def _base_ip(run_seed: int, family_index: int) -> str:
    third_octet = 50 + (run_seed % 40)
    fourth_octet = 10 + family_index
    return "198.51.{0}.{1}".format(third_octet, fourth_octet)


def build_attack_simulation_suite(profile: str = "full", run_seed: int = 1) -> List[dict]:
    size = str(profile or "full").strip().lower()
    if size not in {"quick", "full"}:
        size = "full"

    suite: List[dict] = []
    family_order = [
        "benign",
        "sql_injection",
        "xss",
        "path_traversal",
        "command_injection",
        "payload_evasion",
        "reconnaissance",
        "automation_abuse",
        "brute_force",
        "ddos",
        "anomaly",
    ]
    family_ips = {family: _base_ip(run_seed, index) for index, family in enumerate(family_order)}

    def add_request(
        family: str,
        *,
        method: str,
        target: str,
        query: str = "",
        body: str = "",
        headers: Dict[str, str] | None = None,
    ) -> None:
        scenario_headers = {"X-Forwarded-For": family_ips[family], "X-WAF-Simulation": "1"}
        if headers:
            scenario_headers.update(headers)
        suite.append(
            {
                "family": family,
                "method": method.upper(),
                "target": target,
                "query": query,
                "body": body,
                "headers": scenario_headers,
            }
        )

    benign_templates = [
        ("GET", "/inspect", "message=hello", "", {"User-Agent": "Mozilla/5.0"}),
        ("GET", "/inspect/products", "page=1&sort=name", "", {"User-Agent": "Mozilla/5.0"}),
        ("POST", "/inspect/contact", "", "name=Alice&message=Need help", {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}),
        ("POST", "/inspect/api/orders", "", "{\"item\":\"book\",\"qty\":1}", {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}),
    ]
    benign_rounds = 2 if size == "quick" else 4
    for _ in range(benign_rounds):
        for method, target, query, body, headers in benign_templates:
            add_request("benign", method=method, target=target, query=query, body=body, headers=headers)

    sqli_payloads = [
        ("GET", "/inspect/products", "id=1 UNION SELECT username,password FROM users", "", {"User-Agent": "sqlmap/1.8"}),
        ("GET", "/inspect/login", "user=admin' OR 1=1 --", "", {"User-Agent": "sqlmap/1.8"}),
        ("POST", "/inspect/report", "", "search=test;DROP TABLE audit_log", {"User-Agent": "sqlmap/1.8", "Content-Type": "text/plain"}),
        ("GET", "/inspect/items", "item=1 WAITFOR DELAY '0:0:5'", "", {"User-Agent": "sqlmap/1.8"}),
    ]
    for method, target, query, body, headers in sqli_payloads[: 2 if size == "quick" else len(sqli_payloads)]:
        add_request("sql_injection", method=method, target=target, query=query, body=body, headers=headers)

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
    ]
    for payload in xss_payloads[: 2 if size == "quick" else len(xss_payloads)]:
        add_request(
            "xss",
            method="POST",
            target="/inspect/comments",
            body=payload,
            headers={"User-Agent": "Mozilla/5.0", "Content-Type": "text/plain"},
        )

    traversal_queries = [
        "file=../../etc/passwd",
        "template=..%2f..%2f..%2fwindows/win.ini",
        "path=..\\..\\boot.ini",
        "download=%2e%2e%2fsecret.txt",
    ]
    for query in traversal_queries[: 2 if size == "quick" else len(traversal_queries)]:
        add_request(
            "path_traversal",
            method="GET",
            target="/inspect/download",
            query=query,
            headers={"User-Agent": "curl/8.0"},
        )

    command_payloads = [
        "cmd=cat /etc/passwd",
        "name=test && whoami",
        "target=127.0.0.1; bash -c id",
        "host=server || powershell Get-ChildItem",
    ]
    for body in command_payloads[: 2 if size == "quick" else len(command_payloads)]:
        add_request(
            "command_injection",
            method="POST",
            target="/inspect/tools/ping",
            body=body,
            headers={"User-Agent": "python-requests/2.32", "Content-Type": "application/x-www-form-urlencoded"},
        )

    evasive_queries = [
        "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "file=%252e%252e%252fetc%252fpasswd",
        "name=%2555%254e%2549%254f%254e%2520%2553%2545%254c%2545%2543%2554",
        "path=%2e%2e%2f%2e%2e%2fsecret",
    ]
    for query in evasive_queries[: 2 if size == "quick" else len(evasive_queries)]:
        add_request(
            "payload_evasion",
            method="GET",
            target="/inspect/search",
            query=query,
            headers={"User-Agent": "Mozilla/5.0"},
        )

    recon_paths = ["/inspect/admin", "/inspect/wp-admin", "/inspect/config", "/inspect/phpmyadmin", "/inspect/backup"]
    for path in recon_paths[: 3 if size == "quick" else len(recon_paths)]:
        add_request(
            "reconnaissance",
            method="GET",
            target=path,
            headers={"User-Agent": "nikto/2.5"},
        )

    automation_targets = ["/inspect/admin/health", "/inspect/api/export", "/inspect/admin/jobs", "/inspect/api/dump"]
    for target in automation_targets[: 2 if size == "quick" else len(automation_targets)]:
        add_request(
            "automation_abuse",
            method="GET",
            target=target,
            query="batch=1",
            headers={"User-Agent": "python-requests/2.32"},
        )

    brute_attempts = 6 if size == "quick" else 12
    for attempt in range(brute_attempts):
        add_request(
            "brute_force",
            method="POST",
            target="/inspect/admin/login",
            body="username=admin&password=guess{0}".format(attempt),
            headers={"User-Agent": "curl/8.0", "Content-Type": "application/x-www-form-urlencoded"},
        )

    ddos_attempts = 18 if size == "quick" else 52
    for attempt in range(ddos_attempts):
        add_request(
            "ddos",
            method="GET",
            target="/inspect/api/search",
            query="q=item{0}".format(attempt),
            headers={"User-Agent": "Go-http-client/1.1"},
        )

    anomaly_attempts = 4 if size == "quick" else 8
    for attempt in range(anomaly_attempts):
        target = "/inspect/sync/{0}/delta".format("m" * (8 + attempt))
        add_request(
            "anomaly",
            method="PUT" if attempt % 2 else "GET",
            target=target,
            query="v={0}&nonce=%25{1:02d}".format(attempt, attempt),
            body="{\"blob\":\"" + ("A" * (180 + attempt * 18)) + "\"}" if attempt % 2 else "",
            headers={
                "User-Agent": "aiohttp/3.9",
                **({"Content-Type": "application/json"} if attempt % 2 else {}),
            },
        )

    return suite


def run_attack_simulation_suite(app, storage, settings, *, profile: str = "full", report_path: Path | None = None) -> dict:
    run_started = datetime.now(timezone.utc)
    run_id = run_started.strftime("sim-%Y%m%d%H%M%S")
    suite = build_attack_simulation_suite(profile=profile, run_seed=int(run_started.timestamp()) % 1000)
    family_stats: Dict[str, Dict[str, object]] = defaultdict(
        lambda: {
            "sent": 0,
            "allowed": 0,
            "monitored": 0,
            "blocked": 0,
            "request_ids": [],
            "observed_attack_types": Counter(),
        }
    )
    observed_attack_counts: Counter[str] = Counter()
    simulation_ips = set()

    with app.test_client() as client:
        for scenario in suite:
            simulation_ips.add(str(scenario["headers"].get("X-Forwarded-For", "")))
            target = scenario["target"]
            if scenario.get("query"):
                target = "{0}?{1}".format(target, scenario["query"])
            response = client.open(
                target,
                method=scenario["method"],
                data=scenario.get("body", ""),
                headers=scenario["headers"],
            )
            payload = response.get_json(silent=True) or {}
            action = str(payload.get("action") or ("block" if response.status_code >= 400 else "allow"))
            request_id = payload.get("request_id", "")
            family = str(scenario["family"])
            family_bucket = family_stats[family]
            family_bucket["sent"] += 1
            if action == "block":
                family_bucket["blocked"] += 1
            elif action == "monitor":
                family_bucket["monitored"] += 1
            else:
                family_bucket["allowed"] += 1
            if request_id:
                family_bucket["request_ids"].append(request_id)

            for raw_attack_type in payload.get("attack_types", []) or []:
                canonical = canonical_attack_type(raw_attack_type)
                if not canonical:
                    continue
                family_bucket["observed_attack_types"][canonical] += 1
                observed_attack_counts[canonical] += 1

    for ip_address in simulation_ips:
        if ip_address:
            storage.remove_blacklist(ip_address)

    family_results = []
    control_traffic = None
    for family, stats in family_stats.items():
        observed_rows = [
            {
                "attack_type": attack_type,
                "label": attack_family_metadata(attack_type)["label"],
                "count": count,
            }
            for attack_type, count in sorted(
                stats["observed_attack_types"].items(),
                key=lambda item: (-item[1], _ATTACK_FAMILY_ORDER.get(item[0], 999), item[0]),
            )[:4]
        ]
        result = {
            "sent": int(stats["sent"]),
            "allowed": int(stats["allowed"]),
            "monitored": int(stats["monitored"]),
            "blocked": int(stats["blocked"]),
            "request_ids": list(stats["request_ids"])[:12],
            "observed_attack_types": observed_rows,
        }
        if family == "benign":
            control_traffic = {
                **_BENIGN_CONTROL_METADATA,
                **result,
            }
            continue

        metadata = attack_family_metadata(family)
        family_results.append(
            {
                "attack_type": metadata["attack_type"],
                "label": metadata["label"],
                "description": metadata["description"],
                **result,
            }
        )

    family_results.sort(key=lambda item: _ATTACK_FAMILY_ORDER.get(item["attack_type"], 999))
    observed_attack_types = [
        {
            "attack_type": attack_type,
            "label": attack_family_metadata(attack_type)["label"],
            "description": attack_family_metadata(attack_type)["description"],
            "count": count,
        }
        for attack_type, count in sorted(
            observed_attack_counts.items(),
            key=lambda item: (-item[1], _ATTACK_FAMILY_ORDER.get(item[0], 999), item[0]),
        )
    ]

    if control_traffic is None:
        control_traffic = {
            **_BENIGN_CONTROL_METADATA,
            "sent": 0,
            "allowed": 0,
            "monitored": 0,
            "blocked": 0,
            "request_ids": [],
            "observed_attack_types": [],
        }

    report = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": str(profile or "full"),
        "total_requests": len(suite),
        "families": family_results,
        "control_traffic": control_traffic,
        "observed_attack_types": observed_attack_types,
        "simulation_ips": sorted(ip for ip in simulation_ips if ip),
        "summary": {
            "blocked": sum(item["blocked"] for item in family_results) + int(control_traffic["blocked"]),
            "monitored": sum(item["monitored"] for item in family_results) + int(control_traffic["monitored"]),
            "allowed": sum(item["allowed"] for item in family_results) + int(control_traffic["allowed"]),
            "families_exercised": len(family_results),
            "attack_families_exercised": len(family_results),
            "supported_attack_families": len(ATTACK_FAMILIES),
            "attack_requests": sum(item["sent"] for item in family_results),
            "control_requests": int(control_traffic["sent"]),
            "control_allowed": int(control_traffic["allowed"]),
            "control_monitored": int(control_traffic["monitored"]),
            "control_blocked": int(control_traffic["blocked"]),
        },
        "started_at": run_started.isoformat(timespec="seconds"),
    }

    target_path = Path(report_path or settings.attack_simulation_report_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def load_attack_simulation_report(report_path: Path) -> dict | None:
    candidate = Path(report_path)
    if not candidate.exists():
        return None
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
