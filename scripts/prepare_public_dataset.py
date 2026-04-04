import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sys
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from core.data_ingestion import RequestRecord
from core.feature_engineering import extract_features
from core.ml_models import WeightedRiskModel
from core.rate_limiter import RateLimitResult
from core.rule_engine import check_rules
from core.storage import HistorySnapshot
from utils import build_full_url, fingerprint, json_dumps, sha256_hex, shorten


DEFAULT_FIELD_CANDIDATES = {
    "timestamp": ("timestamp", "ts", "time", "datetime", "date"),
    "method": ("method", "http_method", "verb"),
    "url": ("url", "uri", "request_uri", "request_url"),
    "path": ("path", "request_path", "endpoint", "resource"),
    "query": ("query", "query_string", "querystring"),
    "body": ("body", "payload", "request_body", "message", "data"),
    "label": ("label", "class", "target", "is_attack", "malicious"),
    "attack_type": ("attack_type", "attack", "category", "type"),
    "ip": ("ip", "src_ip", "source_ip", "remote_addr", "client_ip"),
    "user_agent": ("user_agent", "ua", "agent"),
    "session": ("session_id", "session", "user_id", "flow_id"),
    "content_type": ("content_type", "mime_type"),
    "host": ("host", "hostname", "server_name"),
    "scheme": ("scheme", "protocol"),
}

POSITIVE_LABELS = {
    "1",
    "true",
    "attack",
    "attacker",
    "malicious",
    "anomaly",
    "anomalous",
    "bad",
    "blocked",
    "abnormal",
    "sqli",
    "xss",
    "traversal",
    "command_injection",
}

BENIGN_LABELS = {
    "",
    "0",
    "false",
    "benign",
    "normal",
    "legitimate",
    "allow",
    "allowed",
    "clean",
}

BENIGN_ATTACK_TYPES = {"", "benign", "normal", "none", "legitimate", "clean"}


def detect_input_format(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return "jsonl"
    return "csv"


def iter_rows(path: Path, input_format: str, delimiter: str) -> Iterable[Dict[str, object]]:
    if input_format == "jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if isinstance(payload, dict):
                    yield payload
        return

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        for row in reader:
            yield dict(row)


def as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


def pick_value(row: Dict[str, object], explicit_name: str | None, field_name: str) -> str:
    candidates = []
    if explicit_name:
        candidates.append(explicit_name)
    candidates.extend(DEFAULT_FIELD_CANDIDATES[field_name])
    for name in candidates:
        if name in row and as_text(row.get(name)).strip():
            return as_text(row.get(name)).strip()
    return ""


def parse_timestamp(raw_value: str, row_index: int) -> Tuple[str, float]:
    if not raw_value:
        fallback = datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=row_index)
        return fallback.isoformat(timespec="seconds"), fallback.timestamp()

    raw_value = raw_value.strip()
    try:
        numeric = float(raw_value)
        if numeric > 1_000_000_000_000:
            numeric /= 1000.0
        parsed = datetime.fromtimestamp(numeric, tz=timezone.utc)
        return parsed.isoformat(timespec="seconds"), parsed.timestamp()
    except ValueError:
        pass

    normalized = raw_value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat(timespec="seconds"), parsed.timestamp()
    except ValueError:
        fallback = datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=row_index)
        return fallback.isoformat(timespec="seconds"), fallback.timestamp()


def split_attack_types(raw_value: str) -> List[str]:
    if not raw_value:
        return []
    try:
        decoded = json.loads(raw_value)
        if isinstance(decoded, list):
            return [as_text(part).strip().lower() for part in decoded if as_text(part).strip()]
    except Exception:
        pass

    parts = [
        part.strip().strip("[]{}()'\"").lower()
        for part in re.split(r"[|,;/]+", raw_value)
        if part.strip()
    ]
    return [part for part in parts if part not in BENIGN_ATTACK_TYPES]


def normalize_label(label_text: str, attack_type_text: str) -> str:
    label = (label_text or "").strip().lower()
    if label in POSITIVE_LABELS:
        return "malicious"
    if label in BENIGN_LABELS:
        attack_types = split_attack_types(attack_type_text)
        return "malicious" if attack_types else "benign"
    attack_types = split_attack_types(attack_type_text)
    return "malicious" if attack_types else "benign"


def infer_attack_types(feature_map: Dict[str, float], row_attack_types: List[str], normalized_label: str) -> List[str]:
    if row_attack_types:
        return row_attack_types

    attack_types: List[str] = []
    if feature_map.get("sql_injection_signal"):
        attack_types.append("sql_injection")
    if feature_map.get("xss_signal"):
        attack_types.append("xss")
    if feature_map.get("traversal_signal"):
        attack_types.append("path_traversal")
    if feature_map.get("command_injection_signal"):
        attack_types.append("command_injection")
    if feature_map.get("token_bucket_pressure", 0.0) >= 0.95:
        attack_types.append("rate_limit")
    if feature_map.get("automation_user_agent_signal") and feature_map.get("admin_path_signal"):
        attack_types.append("reconnaissance")
    if normalized_label == "malicious" and not attack_types:
        attack_types.append("unknown_attack")
    return attack_types


def compute_rate_limit_result(
    bucket_state: Dict[str, Tuple[float, float]],
    ip_address: str,
    current_epoch: float,
) -> RateLimitResult:
    capacity = float(settings.token_bucket_capacity)
    refill_rate = float(settings.token_bucket_refill_rate)
    tokens, updated_at = bucket_state.get(ip_address, (capacity, current_epoch))
    elapsed = max(0.0, current_epoch - updated_at)
    tokens = min(capacity, tokens + elapsed * refill_rate)
    allowed = tokens >= 1.0
    if allowed:
        tokens -= 1.0
    bucket_state[ip_address] = (tokens, current_epoch)
    return RateLimitResult(
        allowed=allowed,
        remaining_tokens=tokens,
        capacity=capacity,
        refill_rate=refill_rate,
    )


def build_request_record(
    row: Dict[str, object],
    row_index: int,
    field_map: Dict[str, str | None],
) -> RequestRecord:
    raw_timestamp = pick_value(row, field_map.get("timestamp"), "timestamp")
    timestamp, timestamp_epoch = parse_timestamp(raw_timestamp, row_index)
    method = (pick_value(row, field_map.get("method"), "method") or "GET").upper()
    raw_url = pick_value(row, field_map.get("url"), "url")
    explicit_path = pick_value(row, field_map.get("path"), "path")
    explicit_query = pick_value(row, field_map.get("query"), "query")
    parsed_url = urlparse(raw_url if raw_url else explicit_path or "/")
    path = explicit_path or parsed_url.path or "/"
    if "?" in path and not explicit_query:
        path, explicit_query = path.split("?", 1)
    query_string = explicit_query or parsed_url.query or ""
    scheme = pick_value(row, field_map.get("scheme"), "scheme") or parsed_url.scheme or "http"
    host = pick_value(row, field_map.get("host"), "host") or parsed_url.netloc or "dataset.local"
    body_text = pick_value(row, field_map.get("body"), "body")
    ip_address = pick_value(row, field_map.get("ip"), "ip") or "0.0.0.0"
    user_agent = pick_value(row, field_map.get("user_agent"), "user_agent") or "dataset-agent"
    session_id = pick_value(row, field_map.get("session"), "session") or "anonymous"
    content_type = pick_value(row, field_map.get("content_type"), "content_type") or "text/plain"
    body_bytes = body_text.encode("utf-8", errors="ignore")
    headers = {
        "Host": host,
        "User-Agent": user_agent,
        "Content-Type": content_type,
    }

    return RequestRecord(
        request_id="public-{0:06d}".format(row_index),
        timestamp=timestamp,
        timestamp_epoch=timestamp_epoch,
        method=method,
        scheme=scheme,
        host=host,
        path=path or "/",
        gateway_path=path or "/",
        query_string=query_string,
        url=build_full_url(scheme, host, path or "/", query_string),
        headers=headers,
        body_text=body_text,
        body_bytes=body_bytes,
        body_length=len(body_bytes),
        remote_addr=ip_address,
        user_agent=user_agent,
        referer="",
        content_type=content_type,
        session_id=session_id,
        request_fingerprint=fingerprint(method, path or "/", query_string, body_text),
        payload_hash=sha256_hex(body_bytes),
        payload_preview=shorten(body_text, settings.max_payload_preview_chars),
        cookies_count=0,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize a public dataset into the WAF training schema with engineered features."
    )
    parser.add_argument("--input", required=True, help="Input dataset path (CSV or JSONL).")
    parser.add_argument(
        "--output",
        default=str(settings.prepared_public_dataset_path),
        help="Destination CSV path using the WAF training schema.",
    )
    parser.add_argument(
        "--input-format",
        choices=("auto", "csv", "jsonl"),
        default="auto",
        help="Input file format.",
    )
    parser.add_argument("--delimiter", default=",", help="CSV delimiter when the input format is CSV.")
    parser.add_argument("--timestamp-column", default=None, help="Optional explicit timestamp column name.")
    parser.add_argument("--method-column", default=None, help="Optional explicit HTTP method column name.")
    parser.add_argument("--url-column", default=None, help="Optional explicit URL column name.")
    parser.add_argument("--path-column", default=None, help="Optional explicit path column name.")
    parser.add_argument("--query-column", default=None, help="Optional explicit query-string column name.")
    parser.add_argument("--body-column", default=None, help="Optional explicit body or payload column name.")
    parser.add_argument("--label-column", default=None, help="Optional explicit label column name.")
    parser.add_argument("--attack-type-column", default=None, help="Optional explicit attack-type column name.")
    parser.add_argument("--ip-column", default=None, help="Optional explicit IP column name.")
    parser.add_argument("--user-agent-column", default=None, help="Optional explicit user-agent column name.")
    parser.add_argument("--session-column", default=None, help="Optional explicit session identifier column name.")
    parser.add_argument("--content-type-column", default=None, help="Optional explicit content-type column name.")
    parser.add_argument("--host-column", default=None, help="Optional explicit host column name.")
    parser.add_argument("--scheme-column", default=None, help="Optional explicit scheme column name.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    input_format = detect_input_format(input_path, args.input_format)
    rows = list(iter_rows(input_path, input_format, args.delimiter))
    if not rows:
        raise SystemExit("Input dataset is empty: {0}".format(input_path))

    field_map = {
        "timestamp": args.timestamp_column,
        "method": args.method_column,
        "url": args.url_column,
        "path": args.path_column,
        "query": args.query_column,
        "body": args.body_column,
        "label": args.label_column,
        "attack_type": args.attack_type_column,
        "ip": args.ip_column,
        "user_agent": args.user_agent_column,
        "session": args.session_column,
        "content_type": args.content_type_column,
        "host": args.host_column,
        "scheme": args.scheme_column,
    }

    ip_request_counts: Dict[str, int] = defaultdict(int)
    ip_block_counts: Dict[str, int] = defaultdict(int)
    session_request_counts: Dict[str, int] = defaultdict(int)
    fingerprint_counts: Dict[str, int] = defaultdict(int)
    ip_path_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    ip_unique_paths: Dict[str, set[str]] = defaultdict(set)
    bucket_state: Dict[str, Tuple[float, float]] = {}
    heuristic_model = WeightedRiskModel(weights=dict(settings.model_weights), bias=settings.model_bias)

    prepared_rows: List[Dict[str, object]] = []
    feature_names = set()
    attack_counter: Counter[str] = Counter()

    for row_index, row in enumerate(rows, start=1):
        record = build_request_record(row, row_index, field_map)
        history_snapshot = HistorySnapshot(
            ip_request_count_window=ip_request_counts[record.remote_addr],
            ip_block_count_window=ip_block_counts[record.remote_addr],
            session_request_count_window=session_request_counts[record.session_id],
            fingerprint_reuse_count=fingerprint_counts[record.request_fingerprint],
            path_hits_window=ip_path_counts[record.remote_addr][record.path],
            unique_paths_window=len(ip_unique_paths[record.remote_addr]),
        )
        rate_limit_result = compute_rate_limit_result(bucket_state, record.remote_addr, record.timestamp_epoch)
        feature_map = extract_features(record, history_snapshot, rate_limit_result, settings)
        rule_result = check_rules(
            request_record=record,
            features=feature_map,
            history_snapshot=history_snapshot,
            rate_limit_result=rate_limit_result,
            blacklist_record=None,
            settings=settings,
        )
        heuristic_score = heuristic_model.predict_with_breakdown(feature_map)
        raw_label = pick_value(row, field_map.get("label"), "label")
        raw_attack_type = pick_value(row, field_map.get("attack_type"), "attack_type")
        normalized_label = normalize_label(raw_label, raw_attack_type)
        attack_types = infer_attack_types(feature_map, split_attack_types(raw_attack_type), normalized_label)
        rule_block = int(rule_result.should_block)
        hybrid_block = int(rule_result.should_block or heuristic_score.score >= settings.block_threshold)

        ip_request_counts[record.remote_addr] += 1
        session_request_counts[record.session_id] += 1
        fingerprint_counts[record.request_fingerprint] += 1
        ip_path_counts[record.remote_addr][record.path] += 1
        ip_unique_paths[record.remote_addr].add(record.path)
        if hybrid_block:
            ip_block_counts[record.remote_addr] += 1

        feature_names.update(feature_map.keys())
        attack_counter.update(attack_types)
        prepared_rows.append(
            {
                "request_id": record.request_id,
                "timestamp": record.timestamp,
                "method": record.method,
                "path": record.path,
                "remote_addr": record.remote_addr,
                "label": normalized_label,
                "attack_types_json": json_dumps(attack_types),
                "rule_block": rule_block,
                "hybrid_block": hybrid_block,
                "features": feature_map,
            }
        )

    ordered_features = sorted(feature_names)
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
                "attack_types_json",
                "rule_block",
                "hybrid_block",
            ]
            + ordered_features
        )
        for row in prepared_rows:
            writer.writerow(
                [
                    row["request_id"],
                    row["timestamp"],
                    row["method"],
                    row["path"],
                    row["remote_addr"],
                    row["label"],
                    row["attack_types_json"],
                    row["rule_block"],
                    row["hybrid_block"],
                ]
                + [row["features"].get(feature_name, 0.0) for feature_name in ordered_features]
            )

    summary = {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "rows": len(prepared_rows),
        "malicious_rows": sum(1 for row in prepared_rows if row["label"] == "malicious"),
        "benign_rows": sum(1 for row in prepared_rows if row["label"] == "benign"),
        "top_attack_types": attack_counter.most_common(8),
        "field_map": {key: value for key, value in field_map.items() if value},
        "feature_count": len(ordered_features),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
