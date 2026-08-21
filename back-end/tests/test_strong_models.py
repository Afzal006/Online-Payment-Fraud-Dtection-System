import json
from pathlib import Path
import pytest
import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"
DOCS_DIR = BASE_DIR / "docs"


def test_tuned_artifacts_exist():
    """Verify that tuned model artifacts and confusion matrix images exist."""
    required_artifacts = [
        ARTIFACTS_DIR / "random_forest_tuned.joblib",
        ARTIFACTS_DIR / "xgboost_tuned.joblib",
        ARTIFACTS_DIR / "cv_results.json",
        ARTIFACTS_DIR / "strong_model_metrics.json",
        ARTIFACTS_DIR / "random_forest_tuned_confusion_matrix.png",
        ARTIFACTS_DIR / "xgboost_tuned_confusion_matrix.png",
    ]
    for art in required_artifacts:
        assert art.exists(), f"Missing tuned artifact: {art.name}"


def test_cv_results_structure():
    """Verify that cv_results.json has 5-fold CV results for both RF and XGBoost candidates."""
    with open(ARTIFACTS_DIR / "cv_results.json", "r", encoding="utf-8") as f:
        cv_data = json.load(f)

    assert len(cv_data) >= 6  # 3 RF + 3 XGB configs

    for name, res in cv_data.items():
        assert "f1_mean" in res
        assert "f1_std" in res
        assert "pr_auc_mean" in res
        assert "recall_mean" in res
        assert "precision_mean" in res
        assert 0.0 <= res["f1_mean"] <= 1.0
        assert 0.0 <= res["f1_std"] <= 0.1  # Highly stable


def test_strong_model_metrics_test_evaluation():
    """Verify that strong_model_metrics.json contains holdout test evaluations."""
    with open(ARTIFACTS_DIR / "strong_model_metrics.json", "r", encoding="utf-8") as f:
        metrics = json.load(f)

    assert len(metrics) == 2
    model_names = [m["model_name"] for m in metrics]
    assert "Tuned Random Forest" in model_names
    assert "Tuned XGBoost" in model_names

    for m in metrics:
        assert m["test_f1_score"] > 0.95
        assert m["test_recall"] > 0.95
        assert m["test_precision"] > 0.95
        assert m["test_pr_auc"] > 0.95
        assert m["true_positives"] > 300
        assert m["false_positives"] <= 5


def test_tuned_model_inference():
    """Verify that both tuned models can predict on sample data seamlessly."""
    rf_pipeline = joblib.load(ARTIFACTS_DIR / "random_forest_tuned.joblib")
    xgb_pipeline = joblib.load(ARTIFACTS_DIR / "xgboost_tuned.joblib")

    sample_tx = pd.DataFrame([{
        "type": "PAYMENT",
        "amount": 25.0,
        "oldbalanceOrg": 1000.0,
        "newbalanceOrig": 975.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "errorBalanceOrig": 0.0,
        "errorBalanceDest": 25.0,
        "isMerchantDest": 1,
        "amountToBalanceRatio": 25.0 / 1001.0,
        "hourOfDay": 14,
    }])

    p_rf = rf_pipeline.predict_proba(sample_tx)[0, 1]
    p_xgb = xgb_pipeline.predict_proba(sample_tx)[0, 1]

    assert 0.0 <= p_rf <= 0.30
    assert 0.0 <= p_xgb <= 0.30


def test_strong_model_report_exists():
    """Verify that docs/strong_model_tuning_report.md exists and contains required sections."""
    report_path = DOCS_DIR / "strong_model_tuning_report.md"
    assert report_path.exists()

    content = report_path.read_text(encoding="utf-8")
    assert "## 1. Executive Summary & Strong Model Comparison" in content
    assert "## 2. Comparison with Phase 2 Baseline" in content
    assert "## 3. In-Depth Analysis: Why is Performance So High on PaySim?" in content
    assert "## 4. Best Hyperparameter Selections" in content
    assert "## 5. Recommendation for Phase 4 (Model Packaging)" in content
