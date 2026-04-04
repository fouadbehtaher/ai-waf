import argparse
import csv
import json
import re
from pathlib import Path
import sys
from typing import Dict, List, Tuple

import joblib
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings


def parse_label(raw_value: str) -> int:
    value = (raw_value or "").strip().lower()
    return 1 if value in {"1", "true", "attack", "malicious", "blocked"} else 0


def load_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def dataset_summary(path: Path) -> Dict[str, object]:
    rows = load_rows(path)
    labels: Dict[str, int] = {}
    for row in rows:
        label = (row.get("label") or "").strip().lower() or "missing"
        labels[label] = labels.get(label, 0) + 1
    return {
        "dataset": path.name,
        "rows": len(rows),
        "feature_columns": max(len(rows[0].keys()) - 7, 0) if rows else 0,
        "label_distribution": labels,
    }


def safe_roc_auc(labels: List[int], scores: List[float]) -> float:
    if len(set(labels)) < 2:
        return 0.0
    return float(roc_auc_score(labels, scores))


def metric_pack(labels: List[int], predictions: List[int], scores: List[float]) -> Dict[str, float]:
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    benign_total = fp + tn
    return {
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
        "roc_auc": round(safe_roc_auc(labels, scores), 6),
        "false_positive_rate": round(float(fp / benign_total) if benign_total else 0.0, 6),
        "true_positive": int(tp),
        "false_positive": int(fp),
        "true_negative": int(tn),
        "false_negative": int(fn),
    }


def evaluate_dataset(dataset_path: Path, artifact_path: Path) -> Dict[str, object]:
    rows = load_rows(dataset_path)
    labels = [parse_label(row.get("label", "")) for row in rows]
    rule_predictions = [1 if json.loads(row.get("attack_types_json") or "[]") else 0 for row in rows]

    artifact = joblib.load(artifact_path)
    feature_names = artifact["feature_names"]
    threshold = float(artifact["threshold"])
    matrix = [[float(row.get(name, 0.0) or 0.0) for name in feature_names] for row in rows]
    ml_scores = [-float(score) for score in artifact["estimator"].score_samples(matrix)]
    ml_predictions = [1 if score >= threshold else 0 for score in ml_scores]
    hybrid_predictions = [1 if (rule_hit or ml_hit) else 0 for rule_hit, ml_hit in zip(rule_predictions, ml_predictions)]
    hybrid_scores = [max(float(rule_hit), score) for rule_hit, score in zip(rule_predictions, ml_scores)]

    return {
        "dataset": dataset_path.name,
        "model_version": artifact.get("model_version", "unknown"),
        "threshold": round(threshold, 6),
        "rule_only": metric_pack(labels, rule_predictions, [float(item) for item in rule_predictions]),
        "ml_only": metric_pack(labels, ml_predictions, ml_scores),
        "hybrid": metric_pack(labels, hybrid_predictions, hybrid_scores),
    }


def load_json(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def parse_test_results(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {"path": str(path), "status": "missing"}

    text = path.read_text(encoding="utf-8", errors="replace")
    clean_text = text.replace("\x00", "")
    match = re.search(r"Ran\s+(\d+)\s+tests?\s+in\s+([0-9.]+)s", clean_text)
    status = "ok" if "\nOK" in clean_text or clean_text.strip().endswith("OK") else "unknown"
    result = {
        "path": str(path),
        "status": status,
        "raw_tail": clean_text[-1000:],
    }
    if match:
        result["tests_run"] = int(match.group(1))
        result["duration_seconds"] = float(match.group(2))
    return result


def render_markdown(results: Dict[str, object]) -> str:
    lines: List[str] = [
        "# Academic Results Summary",
        "",
        "## Dataset summary",
        "",
        "| Dataset | Rows | Feature columns | Label distribution |",
        "|---|---:|---:|---|",
    ]
    for item in results["datasets"]:
        lines.append(
            "| {0} | {1} | {2} | {3} |".format(
                item["dataset"],
                item["rows"],
                item["feature_columns"],
                json.dumps(item["label_distribution"], ensure_ascii=False),
            )
        )

    for title, section in [
        ("Labeled telemetry evaluation", results["evaluations"]["labeled"]),
        ("Prepared public dataset evaluation", results["evaluations"]["public"]),
    ]:
        lines.extend(
            [
                "",
                "## {0}".format(title),
                "",
                "Model version: `{0}`".format(section["model_version"]),
                "",
                "| Pipeline | Precision | Recall | F1 | ROC-AUC | FPR | TP | FP | TN | FN |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for key in ["rule_only", "ml_only", "hybrid"]:
            metrics = section[key]
            lines.append(
                "| {0} | {1:.4f} | {2:.4f} | {3:.4f} | {4:.4f} | {5:.4f} | {6} | {7} | {8} | {9} |".format(
                    key.replace("_", " "),
                    metrics["precision"],
                    metrics["recall"],
                    metrics["f1"],
                    metrics["roc_auc"],
                    metrics["false_positive_rate"],
                    metrics["true_positive"],
                    metrics["false_positive"],
                    metrics["true_negative"],
                    metrics["false_negative"],
                )
            )

    lines.extend(
        [
            "",
            "## Benchmarks",
            "",
            "| Scenario | Avg latency ms | P50 latency ms | P95 latency ms | Throughput rps | Requests | Concurrency |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, key in [
        ("Local proxy", "proxy_local"),
        ("Docker proxy", "proxy_docker"),
        ("Local inspect", "inspect_local"),
        ("Docker inspect", "inspect_docker"),
    ]:
        report = results["benchmarks"].get(key) or {}
        if not report:
            continue
        lines.append(
            "| {0} | {1:.4f} | {2:.4f} | {3:.4f} | {4:.4f} | {5} | {6} |".format(
                name,
                float(report.get("avg_latency_ms", 0.0)),
                float(report.get("p50_latency_ms", 0.0)),
                float(report.get("p95_latency_ms", 0.0)),
                float(report.get("throughput_rps", 0.0)),
                int(report.get("requests", 0)),
                int(report.get("concurrency", 0)),
            )
        )

    stress = results.get("rate_limit_stress") or {}
    if stress:
        lines.extend(
            [
                "",
                "## Rate-limit stress evidence",
                "",
                "- URL: `{0}`".format(stress.get("url", "")),
                "- Requests: `{0}` at concurrency `{1}`".format(stress.get("requests", 0), stress.get("concurrency", 0)),
                "- Status counts: `{0}`".format(json.dumps(stress.get("status_counts", {}), ensure_ascii=False)),
            ]
        )

    tests = results.get("tests") or {}
    lines.extend(
        [
            "",
            "## Test evidence",
            "",
            "- Status: `{0}`".format(tests.get("status", "unknown")),
            "- Tests run: `{0}`".format(tests.get("tests_run", "n/a")),
            "- Duration seconds: `{0}`".format(tests.get("duration_seconds", "n/a")),
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate academic evaluation artifacts for the WAF project.")
    parser.add_argument("--labeled-dataset", default=str(settings.labeled_dataset_path))
    parser.add_argument("--public-dataset", default=str(settings.prepared_public_dataset_path))
    parser.add_argument("--artifact", default=str(settings.model_artifact_path))
    parser.add_argument("--proxy-local-benchmark", default=str(PROJECT_ROOT / "reports" / "benchmark_summary_local.json"))
    parser.add_argument("--proxy-docker-benchmark", default=str(PROJECT_ROOT / "reports" / "benchmark_summary.json"))
    parser.add_argument("--inspect-local-benchmark", default=str(PROJECT_ROOT / "reports" / "benchmark_inspect_local.json"))
    parser.add_argument("--inspect-docker-benchmark", default=str(PROJECT_ROOT / "reports" / "benchmark_inspect_docker.json"))
    parser.add_argument("--rate-limit-stress", default=str(PROJECT_ROOT / "reports" / "rate_limit_stress.json"))
    parser.add_argument("--tests-file", default=str(PROJECT_ROOT / "reports" / "test_results.txt"))
    parser.add_argument("--output-json", default=str(PROJECT_ROOT / "reports" / "academic_results.json"))
    parser.add_argument("--output-markdown", default=str(PROJECT_ROOT / "reports" / "academic_results.md"))
    args = parser.parse_args()

    labeled_dataset = Path(args.labeled_dataset)
    public_dataset = Path(args.public_dataset)
    artifact = Path(args.artifact)
    output_json = Path(args.output_json)
    output_markdown = Path(args.output_markdown)

    results = {
        "datasets": [
            dataset_summary(labeled_dataset),
            dataset_summary(public_dataset),
        ],
        "evaluations": {
            "labeled": evaluate_dataset(labeled_dataset, artifact),
            "public": evaluate_dataset(public_dataset, artifact),
        },
        "benchmarks": {
            "proxy_local": load_json(Path(args.proxy_local_benchmark)),
            "proxy_docker": load_json(Path(args.proxy_docker_benchmark)),
            "inspect_local": load_json(Path(args.inspect_local_benchmark)),
            "inspect_docker": load_json(Path(args.inspect_docker_benchmark)),
        },
        "rate_limit_stress": load_json(Path(args.rate_limit_stress)),
        "tests": parse_test_results(Path(args.tests_file)),
    }

    output_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    output_markdown.write_text(render_markdown(results), encoding="utf-8")
    print(json.dumps({"json": str(output_json), "markdown": str(output_markdown)}, indent=2))


if __name__ == "__main__":
    main()
