import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from core.pattern_validation import write_pattern_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic WAF attack-pattern dataset using the live feature schema.")
    parser.add_argument(
        "--output",
        default=str(settings.attack_pattern_dataset_path),
        help="Destination CSV path for the generated attack-pattern dataset.",
    )
    args = parser.parse_args()

    output_path = write_pattern_dataset(Path(args.output), settings)
    print("Generated attack-pattern dataset at {0}".format(output_path))


if __name__ == "__main__":
    main()
