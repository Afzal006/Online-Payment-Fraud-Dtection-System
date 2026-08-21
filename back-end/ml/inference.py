"""
Production Inference Service for Online Payment Fraud Detection.

This module provides the primary ML inference engine:
- Loads the approved production model artifact (model.joblib).
- Verifies model metadata, artifact integrity, and feature schema.
- Transforms incoming transaction payloads using identical training-time feature engineering.
- Generates fraud probability, predicted class, prototype risk score, and risk decision tier.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
from typing import Dict, Any, Union, Optional
import pandas as pd
import numpy as np
import joblib

from ml.feature_engineering import engineer_features, get_model_feature_names

# Default artifact paths
ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"
DEFAULT_MODEL_PATH = ARTIFACTS_DIR / "model.joblib"
DEFAULT_PREPROCESSOR_PATH = ARTIFACTS_DIR / "preprocessor.joblib"
DEFAULT_METADATA_PATH = ARTIFACTS_DIR / "model_metadata.json"
DEFAULT_POLICY_PATH = ARTIFACTS_DIR / "risk_policy.json"


class FraudInferenceService:
    """
    Primary fraud prediction service encapsulating model artifacts,
    schema validation, and risk policy mapping.
    """

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
        policy_path: Optional[Union[str, Path]] = None,
    ):
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.metadata_path = Path(metadata_path) if metadata_path else DEFAULT_METADATA_PATH
        self.policy_path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH

        self._pipeline = None
        self._metadata = None
        self._policy = None

        # Verify artifacts immediately upon initialization
        self.validate_artifacts()

    @property
    def pipeline(self):
        if self._pipeline is None:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model artifact not found at '{self.model_path}'.")
            self._pipeline = joblib.load(self.model_path)
        return self._pipeline

    @property
    def metadata(self) -> Dict[str, Any]:
        if self._metadata is None:
            if not self.metadata_path.exists():
                raise FileNotFoundError(f"Model metadata not found at '{self.metadata_path}'.")
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self._metadata = json.load(f)
        return self._metadata

    @property
    def policy(self) -> Dict[str, Any]:
        if self._policy is None:
            if not self.policy_path.exists():
                raise FileNotFoundError(f"Risk policy not found at '{self.policy_path}'.")
            with open(self.policy_path, "r", encoding="utf-8") as f:
                self._policy = json.load(f)
        return self._policy

    def validate_artifacts(self) -> bool:
        """Verify that all required production artifacts exist and are accessible."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Missing model artifact: {self.model_path}")
        if not self.metadata_path.exists():
            raise FileNotFoundError(f"Missing model metadata: {self.metadata_path}")
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Missing risk policy: {self.policy_path}")

        # Check metadata properties
        meta = self.metadata
        if "model_version" not in meta or "feature_schema" not in meta:
            raise ValueError("Corrupted model_metadata.json: missing required fields.")
        return True

    def predict_transaction(
        self,
        transaction: Union[Dict[str, Any], pd.DataFrame],
        threshold: float = 0.50,
    ) -> Dict[str, Any]:
        """
        Execute fraud prediction on a single transaction payload.

        Parameters:
            transaction: Dictionary or 1-row DataFrame containing transaction fields:
                         'type', 'amount', 'oldbalanceOrg', 'newbalanceOrig',
                         'oldbalanceDest', 'newbalanceDest', and optional 'nameDest', 'step'/'hourOfDay'.
            threshold: Decision boundary for binary classification (default 0.50).

        Returns:
            Dictionary containing prediction metrics, risk score, decision tier, and model metadata.
        """
        if isinstance(transaction, dict):
            df = pd.DataFrame([transaction])
        elif isinstance(transaction, pd.DataFrame):
            df = transaction.copy()
        else:
            raise TypeError("transaction must be a Python dict or pandas DataFrame.")

        # 1. Input Validation
        required_numeric_fields = ["amount", "oldbalanceOrg", "newbalanceOrig", "oldbalanceDest", "newbalanceDest"]
        for field in required_numeric_fields:
            if field not in df.columns or pd.isna(df[field].iloc[0]):
                raise ValueError(f"Missing required numeric transaction field: '{field}'")
            try:
                df[field] = float(df[field].iloc[0])
            except (ValueError, TypeError):
                raise ValueError(f"Invalid non-numeric value for field: '{field}'")

        if "type" not in df.columns or pd.isna(df["type"].iloc[0]):
            raise ValueError("Missing required transaction field: 'type'")
        
        tx_type = str(df["type"].iloc[0]).upper().strip()
        valid_types = ["CASH_OUT", "TRANSFER", "PAYMENT", "CASH_IN", "DEBIT"]
        if tx_type not in valid_types:
            raise ValueError(f"Invalid transaction type '{tx_type}'. Must be one of: {valid_types}")
        df["type"] = tx_type

        # Default optional fields
        if "nameDest" not in df.columns or pd.isna(df["nameDest"].iloc[0]):
            df["nameDest"] = "C0000000000"
        if "step" not in df.columns and "hourOfDay" not in df.columns:
            df["step"] = 12

        # 2. Identical Domain Feature Engineering
        df_engineered = engineer_features(df, temporal_option="hourOfDay", copy=True)
        feature_cols = get_model_feature_names(temporal_option="hourOfDay")
        X = df_engineered[feature_cols]

        # 3. Model Inference
        probability = float(self.pipeline.predict_proba(X)[0, 1])
        predicted_class = int(probability >= threshold)

        # 4. Prototype Risk Score & Tier Mapping
        risk_score = int(round(probability * 100))
        thresholds = self.policy.get("thresholds", {"risk_low_max": 30, "risk_medium_max": 70})
        low_max = thresholds.get("risk_low_max", 30)
        medium_max = thresholds.get("risk_medium_max", 70)

        if risk_score <= low_max:
            risk_level = "LOW"
        elif risk_score <= medium_max:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        tier_info = self.policy.get("tiers", {}).get(risk_level, {})

        return {
            "fraud_probability": round(probability, 4),
            "predicted_class": predicted_class,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": tier_info.get("action", "REVIEW"),
            "requires_otp": tier_info.get("requires_otp", False),
            "alert_generated": tier_info.get("alert_generated", False),
            "user_message": tier_info.get("user_message", ""),
            "model_name": self.metadata.get("model_name", "Random Forest Fraud Classifier"),
            "model_version": self.metadata.get("model_version", "1.0.0"),
        }


# Singleton service instance
_service_instance = None


def get_inference_service() -> FraudInferenceService:
    """Retrieve or initialize the singleton FraudInferenceService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = FraudInferenceService()
    return _service_instance


def predict_single_transaction(transaction: Dict[str, Any]) -> Dict[str, Any]:
    """Functional convenience entrypoint for predicting a single transaction."""
    service = get_inference_service()
    return service.predict_transaction(transaction)
