import argparse
import csv
from pathlib import Path
import sys
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings


META_COLUMNS = [
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


def read_rows(csv_path: Path) -> List[Dict[str, str]]:
    if not csv_path.exists():
        return []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge available WAF datasets into a unified training corpus.")
    parser.add_argument(
        "--inputs",
        nargs="*",
        default=[
            str(settings.attack_pattern_dataset_path),
            str(settings.labeled_dataset_path),
            str(settings.prepared_public_dataset_path),
        ],
        help="Ordered dataset inputs to merge.",
    )
    parser.add_argument(
        "--output",
        default=str(settings.training_corpus_path),
        help="Destination CSV path for the merged training corpus.",
    )
    args = parser.parse_args()

    all_rows: List[Dict[str, str]] = []
    feature_names = set()

    for raw_input in args.inputs:
        input_path = Path(raw_input)
        for row in read_rows(input_path):
            all_rows.append(row)
            feature_names.update(name for name in row.keys() if name not in META_COLUMNS)

    if not all_rows:
        raise SystemExit("No datasets were found to merge.")

    ordered_features = sorted(feature_names)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(META_COLUMNS + ordered_features)
        for index, row in enumerate(all_rows, start=1):
            request_id = row.get("request_id") or "merged-{0:05d}".format(index)
            writer.writerow(
                [
                    request_id,
                    row.get("timestamp", ""),
                    row.get("method", ""),
                    row.get("path", ""),
                    row.get("remote_addr", ""),
                    row.get("label", ""),
                    row.get("attack_family", ""),
                    row.get("source_dataset", Path(row.get("source_dataset", "")).name or "merged"),
                    row.get("expected_action", ""),
                    row.get("attack_types_json", "[]"),
                    row.get("rule_block", 0),
                    row.get("hybrid_block", 0),
                ]
                + [row.get(feature_name, 0.0) for feature_name in ordered_features]
            )

    print("Merged {0} rows into {1}".format(len(all_rows), output_path))


if __name__ == "__main__":
    main()
