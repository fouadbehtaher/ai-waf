import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from utils import percentile


def hit(url: str, timeout: int) -> float:
    started = time.perf_counter()
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return (time.perf_counter() - started) * 1000.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a lightweight latency and throughput benchmark.")
    parser.add_argument("--url", required=True, help="Target URL to benchmark.")
    parser.add_argument("--requests", type=int, default=50, help="Number of requests to send.")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency level.")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout.")
    parser.add_argument(
        "--output",
        default=str(settings.benchmark_output_path),
        help="Optional JSON output path.",
    )
    args = parser.parse_args()

    overall_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(args.concurrency, 1)) as executor:
        latencies = list(executor.map(lambda _: hit(args.url, args.timeout), range(args.requests)))
    total_seconds = max(time.perf_counter() - overall_started, 1e-9)

    report = {
        "url": args.url,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "avg_latency_ms": round(sum(latencies) / float(len(latencies)), 4),
        "p50_latency_ms": round(percentile(latencies, 0.50), 4),
        "p95_latency_ms": round(percentile(latencies, 0.95), 4),
        "throughput_rps": round(args.requests / total_seconds, 4),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
