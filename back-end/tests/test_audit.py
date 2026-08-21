import json
from pathlib import Path
import pandas as pd
import pytest
from ml.check_dataset import find_dataset_file, EXPECTED_COLUMNS

BASE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = BASE_DIR / "docs"


def test_dataset_file_detected():
    """Verify that the PaySim CSV dataset is present, readable, and non-empty."""
    is_present, path, message = find_dataset_file()
    assert is_present is True, f"Dataset not found: {message}"
    assert path is not None
    assert path.exists()
    assert path.stat().st_size > 100 * 1024 * 1024  # > 100 MB


def test_dataset_schema_and_columns():
    """Verify that the first chunk of the dataset has all 11 required columns."""
    is_present, path, _ = find_dataset_file()
    assert is_present is True

    # Read top 1,000 rows for fast verification
    df_sample = pd.read_csv(path, nrows=1000)
    for col in EXPECTED_COLUMNS:
        assert col in df_sample.columns, f"Required column '{col}' missing from dataset"

    assert len(df_sample.columns) == 11
    assert set(df_sample["isFraud"].unique()).issubset({0, 1})
    assert set(df_sample["isFlaggedFraud"].unique()).issubset({0, 1})


def test_feature_specification_validity():
    """Verify that docs/feature_specification.json is valid and contains 11 logical features."""
    spec_path = DOCS_DIR / "feature_specification.json"
    assert spec_path.exists(), "docs/feature_specification.json does not exist"

    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)

    assert spec["target_column"] == "isFraud"
    assert spec["total_records"] == 6362620
    assert len(spec["logical_features"]) == 11
    assert len(spec["excluded_columns"]) == 4
    assert "temporal_evaluation_options" in spec
    assert spec["transformed_matrix_total_columns"] == 15

    feature_names = [f["name"] for f in spec["logical_features"]]
    expected_features = [
        "type",
        "amount",
        "oldbalanceOrg",
        "newbalanceOrig",
        "oldbalanceDest",
        "newbalanceDest",
        "errorBalanceOrig",
        "errorBalanceDest",
        "hourOfDay",
        "isMerchantDest",
        "amountToBalanceRatio",
    ]
    assert feature_names == expected_features


def test_audit_report_exists_and_covers_review_points():
    """Verify that docs/dataset_audit.md exists and contains all required sections and corrections."""
    report_path = DOCS_DIR / "dataset_audit.md"
    assert report_path.exists(), "docs/dataset_audit.md does not exist"

    content = report_path.read_text(encoding="utf-8")
    assert "## 1. Dataset Verification & Schema Integrity" in content
    assert "No exact duplicate rows were detected across the 11 available columns" in content
    assert "## 2. Target Variable Analysis (`isFraud`)" in content
    assert "Dataset-Specific Observation" in content
    assert "## 3. Analysis of Rule-Based Indicator (`isFlaggedFraud`)" in content
    assert "## 4. Numerical Features Summary Statistics" in content
    assert "## 5. Temporal & Step Feature Analysis" in content
    assert "## 6. Real-Time Feature Availability Matrix & Production Limitations" in content
    assert "## 7. Logical Features vs. Transformed Matrix Columns" in content
    assert "## 8. Target Leakage & Feature Decisions" in content
    assert "## 9. Real-Time Inference Availability & Frontend Mapping" in content
    assert "## 10. Recommended Preprocessing & Imbalance Strategy" in content
