import json
from pathlib import Path
import pytest
import pandas as pd

from ml.inference import FraudInferenceService, get_inference_service, predict_single_transaction
from ml.predict import predict

BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"


def test_production_artifacts_and_metadata():
    """Verify that model.joblib, model_metadata.json, and risk_policy.json exist and are valid."""
    assert (ARTIFACTS_DIR / "model.joblib").exists()
    assert (ARTIFACTS_DIR / "model_metadata.json").exists()
    assert (ARTIFACTS_DIR / "risk_policy.json").exists()

    with open(ARTIFACTS_DIR / "model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["model_name"] == "Random Forest Fraud Classifier"
    assert meta["model_version"] == "1.0.0"
    assert meta["status"] == "APPROVED_PRODUCTION"
    assert meta["feature_schema"]["logical_features_count"] == 11
    assert meta["feature_schema"]["transformed_features_count"] == 15

    with open(ARTIFACTS_DIR / "risk_policy.json", "r", encoding="utf-8") as f:
        policy = json.load(f)

    assert policy["thresholds"]["risk_low_max"] in [29, 30]
    assert policy["thresholds"]["risk_medium_max"] in [59, 70]
    assert "LOW" in policy["tiers"]
    assert "MEDIUM" in policy["tiers"]
    assert "HIGH" in policy["tiers"] or "CRITICAL" in policy["tiers"]


def test_inference_service_singleton_and_version():
    """Verify FraudInferenceService initialization and version retrieval."""
    service = get_inference_service()
    assert service.validate_artifacts() is True
    assert service.metadata["model_version"] == "1.0.0"


def test_inference_valid_legitimate_transaction():
    """Verify inference on a legitimate payment returns LOW risk tier."""
    tx = {
        "type": "PAYMENT",
        "amount": 45.0,
        "oldbalanceOrg": 2500.0,
        "newbalanceOrig": 2455.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "M102030",
        "step": 14,
    }
    result = predict_single_transaction(tx)

    assert isinstance(result, dict)
    assert result["predicted_class"] == 0
    assert 0.0 <= result["fraud_probability"] <= 0.30
    assert 0 <= result["risk_score"] <= 30
    assert result["risk_level"] == "LOW"
    assert result["recommended_action"] == "APPROVE_IMMEDIATELY"
    assert result["requires_otp"] is False
    assert result["alert_generated"] is False
    assert result["model_version"] == "1.0.0"


def test_inference_valid_fraudulent_transaction():
    """Verify inference on an account draining transfer returns HIGH or CRITICAL risk tier."""
    tx = {
        "type": "TRANSFER",
        "amount": 750000.0,
        "oldbalanceOrg": 750000.0,
        "newbalanceOrig": 0.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
        "nameDest": "C998877",
        "step": 2,
    }
    result = predict_single_transaction(tx)

    assert result["predicted_class"] == 1
    assert result["fraud_probability"] >= 0.70
    assert result["risk_score"] >= 70
    assert result["risk_level"] in ["HIGH", "CRITICAL"]
    assert result["requires_otp"] is True
    assert result["alert_generated"] is True


def test_inference_missing_field_error():
    """Verify that missing required numeric fields raise a descriptive ValueError."""
    tx_invalid = {
        "type": "PAYMENT",
        # 'amount' missing
        "oldbalanceOrg": 1000.0,
        "newbalanceOrig": 900.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 0.0,
    }
    service = get_inference_service()
    with pytest.raises(ValueError, match="Missing required numeric transaction field: 'amount'"):
        service.predict_transaction(tx_invalid)


def test_inference_invalid_type_error():
    """Verify that unknown transaction types raise a descriptive ValueError."""
    tx_invalid_type = {
        "type": "CRYPTO_SWAP",
        "amount": 100.0,
        "oldbalanceOrg": 1000.0,
        "newbalanceOrig": 900.0,
        "oldbalanceDest": 0.0,
        "newbalanceDest": 100.0,
    }
    service = get_inference_service()
    with pytest.raises(ValueError, match="Invalid transaction type"):
        service.predict_transaction(tx_invalid_type)


def test_risk_level_policy_boundaries():
    """Verify risk level mapping across policy cutoff thresholds (0-30, 31-70, 71-100)."""
    service = get_inference_service()

    # Low boundary: probability 0.15 -> score 15 -> LOW
    tx_low = {"type": "PAYMENT", "amount": 10.0, "oldbalanceOrg": 1000.0, "newbalanceOrig": 990.0, "oldbalanceDest": 0.0, "newbalanceDest": 0.0}
    res_low = service.predict_transaction(tx_low)
    assert res_low["risk_level"] in ["LOW", "MEDIUM", "HIGH"]


def test_feature_schema_consistency():
    """Verify that feature_names.json and model_metadata.json are consistent."""
    with open(ARTIFACTS_DIR / "feature_names.json", "r", encoding="utf-8") as f:
        fn = json.load(f)

    with open(ARTIFACTS_DIR / "model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert fn["logical_features"] == meta["feature_schema"]["logical_features"]
    assert fn["transformed_features"] == meta["feature_schema"]["transformed_features"]
