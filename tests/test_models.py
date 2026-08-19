import json
from pathlib import Path
import pytest
import joblib

from ml.predict import FraudPredictor, predict

BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"
DOCS_DIR = BASE_DIR / "docs"


def test_baseline_artifacts_exist():
    """Verify that all baseline model pipelines, metadata, and plots were generated."""
    expected_artifacts = [
        ARTIFACTS_DIR / "preprocessor.joblib",
        ARTIFACTS_DIR / "feature_names.json",
        ARTIFACTS_DIR / "baseline_metrics.json",
        ARTIFACTS_DIR / "logistic_regression_baseline.joblib",
        ARTIFACTS_DIR / "decision_tree_baseline.joblib",
        ARTIFACTS_DIR / "random_forest_baseline.joblib",
        ARTIFACTS_DIR / "logistic_regression_confusion_matrix.png",
        ARTIFACTS_DIR / "decision_tree_confusion_matrix.png",
        ARTIFACTS_DIR / "random_forest_confusion_matrix.png",
    ]
    for artifact in expected_artifacts:
        assert artifact.exists(), f"Expected artifact '{artifact.name}' does not exist"


def test_baseline_metrics_content():
    """Verify that baseline_metrics.json contains valid evaluation entries for all 3 models."""
    metrics_path = ARTIFACTS_DIR / "baseline_metrics.json"
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    assert len(metrics) == 3
    model_names = [m["model_name"] for m in metrics]
    assert "Logistic Regression" in model_names
    assert "Decision Tree" in model_names
    assert "Random Forest" in model_names

    for m in metrics:
        assert 0.0 <= m["precision"] <= 1.0
        assert 0.0 <= m["recall"] <= 1.0
        assert 0.0 <= m["f1_score"] <= 1.0
        assert 0.0 <= m["pr_auc"] <= 1.0
        assert 0.0 <= m["roc_auc"] <= 1.0
        assert m["true_positives"] >= 0
        assert m["false_positives"] >= 0


def test_predict_interface_legitimate_transaction():
    """Verify real-time prediction output format and LOW risk score for standard transaction."""
    tx_legit = {
        "type": "PAYMENT",
        "amount": 50.0,
        "oldbalanceOrg": 10000.0,
        "newbalanceOrig": 9950.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "M999888",
        "step": 10,
    }

    result = predict(tx_legit)

    assert isinstance(result, dict)
    assert "fraud_probability" in result
    assert "predicted_class" in result
    assert "risk_score" in result
    assert "risk_level" in result

    assert 0.0 <= result["fraud_probability"] <= 1.0
    assert result["predicted_class"] in [0, 1]
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    assert result["risk_level"] == "LOW"


def test_predict_interface_fraudulent_transaction():
    """Verify real-time prediction correctly flags account draining transfer."""
    tx_fraud = {
        "type": "TRANSFER",
        "amount": 900000.0,
        "oldbalanceOrg": 900000.0,
        "newbalanceOrig": 0.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "C123456",
        "step": 3,
    }

    result = predict(tx_fraud)

    assert result["fraud_probability"] > 0.70
    assert result["predicted_class"] == 1
    assert result["risk_score"] >= 70
    assert result["risk_level"] == "HIGH"


def test_baseline_report_exists_and_complete():
    """Verify that docs/baseline_model_report.md exists and contains required sections."""
    report_path = DOCS_DIR / "baseline_model_report.md"
    assert report_path.exists(), "docs/baseline_model_report.md does not exist"

    content = report_path.read_text(encoding="utf-8")
    assert "## 1. Executive Summary & Model Comparison" in content
    assert "## 2. In-Depth Metric Analysis & Key Findings" in content
    assert "## 4. Strict Data Leakage Checklist" in content
    assert "## 6. Recommendation for Phase 3 (Strong Models & Tuning)" in content
