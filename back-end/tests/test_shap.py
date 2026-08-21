import json
from pathlib import Path
import pytest
import pandas as pd

from ml.explain import FraudExplainer, get_fraud_explainer, explain
from app.services.shap_service import get_shap_service, explain_transaction

BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"


def test_shap_explainer_initialization():
    """Verify that FraudExplainer loads production model and initializes TreeExplainer."""
    explainer = get_fraud_explainer()
    assert explainer is not None
    assert explainer._classifier is not None
    assert explainer._preprocessor is not None
    assert len(explainer._transformed_feature_names) == 15


def test_shap_explanation_legitimate_payment():
    """Verify SHAP explanation on legitimate payment produces LOW risk and positive narrative."""
    tx_legit = {
        "type": "PAYMENT",
        "amount": 35.0,
        "oldbalanceOrg": 5000.0,
        "newbalanceOrig": 4965.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "M999111",
        "step": 12,
    }

    res = explain(tx_legit, top_k=5)

    assert isinstance(res, dict)
    assert res["prediction"] == 0
    assert res["predicted_class_name"] == "Legitimate"
    assert 0.0 <= res["fraud_probability"] <= 0.30
    assert 0.70 <= res["legitimate_probability"] <= 1.0
    assert 0 <= res["risk_score"] <= 30
    assert res["risk_level"] == "LOW"
    assert len(res["top_features"]) == 5
    assert len(res["all_features_shap"]) == 15
    assert "approved" in res["explanation_text"].lower() or "normal" in res["explanation_text"].lower()


def test_shap_explanation_fraudulent_transfer():
    """Verify SHAP explanation on fraudulent transaction identifies top risk drivers."""
    tx_fraud = {
        "type": "TRANSFER",
        "amount": 650000.0,
        "oldbalanceOrg": 650000.0,
        "newbalanceOrig": 0.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "C445566",
        "step": 3,
    }

    res = explain(tx_fraud, top_k=5)

    assert res["prediction"] == 1
    assert res["predicted_class_name"] == "Fraudulent"
    assert res["fraud_probability"] >= 0.70
    assert res["risk_score"] >= 70
    assert res["risk_level"] == "HIGH"
    assert len(res["top_features"]) <= 5
    assert len(res["positive_risk_factors"]) > 0

    # Ensure top features are sorted by absolute SHAP value
    shap_magnitudes = [abs(f["shap_value"]) for f in res["top_features"]]
    assert shap_magnitudes == sorted(shap_magnitudes, reverse=True)

    # Check that explanation text mentions high risk
    assert "high risk" in res["explanation_text"].lower()


def test_shap_feature_names_are_human_readable():
    """Verify display_name values are formatted cleanly for users and admin dashboards."""
    tx = {
        "type": "CASH_OUT",
        "amount": 150000.0,
        "oldbalanceOrg": 150000.0,
        "newbalanceOrig": 0.0,
        "oldbalanceDest": 10000.0,
        "newbalanceDest": 160000.0,
        "nameDest": "C102030",
        "step": 8,
    }

    res = explain(tx)
    for feat in res["top_features"]:
        assert "display_name" in feat
        assert isinstance(feat["display_name"], str)
        assert len(feat["display_name"]) > 0
        assert not feat["display_name"].startswith("num__")
        assert not feat["display_name"].startswith("cat__")


def test_no_leakage_features_in_shap():
    """Verify that excluded columns (isFraud, isFlaggedFraud, nameOrig, nameDest) never appear."""
    tx = {
        "type": "PAYMENT",
        "amount": 100.0,
        "oldbalanceOrg": 1000.0,
        "newbalanceOrig": 900.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "M123456",
        "step": 1,
    }

    res = explain(tx)
    all_feature_names = [f["feature"] for f in res["all_features_shap"]]

    excluded = ["isFraud", "isFlaggedFraud", "nameOrig", "nameDest"]
    for exc in excluded:
        for fname in all_feature_names:
            assert exc not in fname, f"Leakage column '{exc}' found in SHAP feature list"


def test_shap_service_frontend_contract():
    """Verify app.services.shap_service format_frontend_contract conforms to Supplement Section 7.1."""
    service = get_shap_service()
    tx = {
        "type": "TRANSFER",
        "amount": 500000.0,
        "oldbalanceOrg": 500000.0,
        "newbalanceOrig": 0.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "C555555",
        "step": 5,
    }
    raw_exp = service.explain_transaction(tx, prediction_id=1042)
    frontend_contract = service.format_frontend_contract(raw_exp, prediction_id=1042)

    assert frontend_contract["prediction_id"] == 1042
    assert "top_features" in frontend_contract
    assert "explanation_text" in frontend_contract
    assert len(frontend_contract["top_features"]) <= 5
    for item in frontend_contract["top_features"]:
        assert "feature" in item
        assert "value" in item
        assert "shap_value" in item
        assert "direction" in item
        assert item["direction"] in ["increases_risk", "decreases_risk"]


def test_shap_invalid_input_handling():
    """Verify that invalid payloads raise appropriate validation errors without crashing."""
    service = get_shap_service()
    with pytest.raises(ValueError, match="Missing required numeric transaction field"):
        service.explain_transaction({"type": "PAYMENT", "oldbalanceOrg": 100.0})
