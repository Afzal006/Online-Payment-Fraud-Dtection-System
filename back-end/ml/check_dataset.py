import os
from pathlib import Path
from typing import Optional, Tuple

# Project root and dataset directory
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"

# Common PaySim dataset filenames
STANDARD_FILENAMES = [
    "PS_20174392719_1491204439457_log.csv",
    "fraud_detection.csv",
    "onlinefraud.csv",
    "paysim.csv",
    "dataset.csv",
]

EXPECTED_COLUMNS = [
    "step",
    "type",
    "amount",
    "nameOrig",
    "oldbalanceOrg",
    "newbalanceOrig",
    "nameDest",
    "oldbalanceDest",
    "newbalanceDest",
    "isFraud",
    "isFlaggedFraud",
]


def find_dataset_file(directory: Optional[Path] = None) -> Tuple[bool, Optional[Path], str]:
    """
    Check if a valid dataset CSV file is present in the dataset directory.

    Returns:
        (is_present: bool, path: Optional[Path], message: str)
    """
    target_dir = directory or DATASET_DIR

    if not target_dir.exists():
        return False, None, f"Dataset directory '{target_dir}' does not exist."

    # First check standard filenames
    for filename in STANDARD_FILENAMES:
        candidate = target_dir / filename
        if candidate.exists() and candidate.is_file() and candidate.stat().st_size > 0:
            return True, candidate, f"Found standard dataset file: {candidate.name} ({candidate.stat().st_size / (1024 * 1024):.2f} MB)"

    # Check any other .csv file in dataset/
    csv_files = [f for f in target_dir.glob("*.csv") if f.is_file() and f.stat().st_size > 0]
    if csv_files:
        found_file = csv_files[0]
        return True, found_file, f"Found CSV dataset file: {found_file.name} ({found_file.stat().st_size / (1024 * 1024):.2f} MB)"

    return False, None, f"No CSV dataset found in '{target_dir}'. Please place the PaySim dataset CSV file there."


def main():
    """CLI runner to check dataset status."""
    is_present, path, message = find_dataset_file()
    print("=" * 65)
    print(" PAY_SIM DATASET STATUS CHECK")
    print("=" * 65)
    print(f"Dataset Directory : {DATASET_DIR}")
    print(f"Status            : {'[FOUND]' if is_present else '[NOT FOUND / PENDING]'}")
    print(f"Details           : {message}")
    if not is_present:
        print("\nNext step: Place the PaySim dataset CSV in the dataset/ folder.")
        print("Refer to DATASET_SETUP.md for full details.")
    print("=" * 65)
    return 0 if is_present else 1


if __name__ == "__main__":
    main()
