import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from core.storage import Storage


def main() -> None:
    default_db_target = settings.database_url or str(settings.db_path)
    parser = argparse.ArgumentParser(description="Export labeled WAF requests to a CSV dataset.")
    parser.add_argument("--db", default=default_db_target, help="Database path or PostgreSQL URL.")
    parser.add_argument(
        "--output",
        default=str(settings.labeled_dataset_path),
        help="Destination CSV path for the exported dataset.",
    )
    parser.add_argument(
        "--include-unlabeled",
        action="store_true",
        help="Export all requests, even if they do not have a human-assigned label.",
    )
    args = parser.parse_args()

    storage = Storage(args.db, database_url=settings.database_url)
    storage.initialize()
    output_path = storage.export_labeled_dataset(
        output_path=Path(args.output),
        include_unlabeled=args.include_unlabeled,
    )
    print("Exported dataset to {0}".format(output_path))


if __name__ == "__main__":
    main()
