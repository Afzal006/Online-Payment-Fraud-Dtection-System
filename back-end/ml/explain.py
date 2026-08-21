"""
Explainable AI (SHAP) Module for Online Payment Fraud Detection.

Provides local and global feature attribution using shap.TreeExplainer
for the packaged production Random Forest model.

Key Features:
- Exact Shapley value calculation for tree-based ensemble classifiers.
- Translates transformed columns into human-readable financial features.
- Generates JSON explanation contracts matching Supplement Section 7.1.
- Synthesizes grounded natural language risk explanations.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
from typing import Dict, Any, List, Union, Optional
import pandas as pd
import numpy as np
import joblib
import shap

from ml.feature_engineering import engineer_features, get_model_feature_names

ARTIFACTS_DIR = BASE_DIR / "ml" / "artifacts"
DEFAULT_MODEL_PATH = ARTIFACTS_DIR / "model.joblib"
DEFAULT_METADATA_PATH = ARTIFACTS_DIR / "model_metadata.json"
DEFAULT_POLICY_PATH = ARTIFACTS_DIR / "risk_policy.json"

# Human-readable feature naming map
FEATURE_NAME_MAP = {
    "cat__type_CASH_OUT": "Transaction Type (CASH_OUT)",
    "cat__type_TRANSFER": "Transaction Type (TRANSFER)",
    "cat__type_PAYMENT": "Transaction Type (PAYMENT)",
    "cat__type_CASH_IN": "Transaction Type (CASH_IN)",
    "cat__type_DEBIT": "Transaction Type (DEBIT)",
    "num__amount": "Transaction Amount",
    "num__oldbalanceOrg": "Sender Balance Before",
    "num__newbalanceOrig": "Sender Balance After",
    "num__oldbalanceDest": "Receiver Balance Before",
    "num__newbalanceDest": "Receiver Balance After",
    "num__errorBalanceOrig": "Sender Balance Discrepancy",
    "num__errorBalanceDest": "Receiver Balance Discrepancy",
    "num__isMerchantDest": "Merchant Destination",
    "num__amountToBalanceRatio": "Amount-to-Balance Ratio",
    "num__hourOfDay": "Transaction Hour",
}


class FraudExplainer:
    """
    Explainable AI Engine wrapping SHAP TreeExplainer for the Random Forest model.
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
        self._preprocessor = None
        self._classifier = None
        self._explainer = None
        self._transformed_feature_names = None
        self._metadata = None
        self._policy = None

        self._initialize_explainer()

    def _initialize_explainer(self):
        """Load pipeline components and initialize SHAP TreeExplainer."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at '{self.model_path}'.")

        self._pipeline = joblib.load(self.model_path)
        self._preprocessor = self._pipeline.named_steps["preprocessor"]
        self._classifier = self._pipeline.named_steps["classifier"]

        # Initialize TreeExplainer
        self._explainer = shap.TreeExplainer(self._classifier)
        self._transformed_feature_names = list(self._preprocessor.get_feature_names_out())

    @property
    def metadata(self) -> Dict[str, Any]:
        if self._metadata is None:
            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self._metadata = json.load(f)
            else:
                self._metadata = {"model_name": "Random Forest Fraud Classifier", "model_version": "1.0.0"}
        return self._metadata

    @property
    def policy(self) -> Dict[str, Any]:
        if self._policy is None:
            if self.policy_path.exists():
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    self._policy = json.load(f)
            else:
                self._policy = {"thresholds": {"risk_low_max": 30, "risk_medium_max": 70}}
        return self._policy

    def explain_transaction(
        self,
        transaction: Union[Dict[str, Any], pd.DataFrame],
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Compute SHAP feature attributions and generate human-readable explanation
        for a single transaction.

        Parameters:
            transaction: Transaction dict or 1-row DataFrame.
            top_k: Number of highest-magnitude contributing features to return (default 5).

        Returns:
            JSON-serializable explanation dictionary matching Supplement Section 7.1.
        """
        if isinstance(transaction, dict):
            df = pd.DataFrame([transaction])
        elif isinstance(transaction, pd.DataFrame):
            df = transaction.copy()
        else:
            raise TypeError("transaction must be a dict or pandas DataFrame.")

        # 1. Validation & Preprocessing
        required_numeric = ["amount", "oldbalanceOrg", "newbalanceOrig", "oldbalanceDest", "newbalanceDest"]
        for field in required_numeric:
            if field not in df.columns or pd.isna(df[field].iloc[0]):
                raise ValueError(f"Missing required numeric transaction field: '{field}'")
            df[field] = float(df[field].iloc[0])

        if "type" not in df.columns or pd.isna(df["type"].iloc[0]):
            raise ValueError("Missing required transaction field: 'type'")
        tx_type = str(df["type"].iloc[0]).upper().strip()
        df["type"] = tx_type

        if "nameDest" not in df.columns or pd.isna(df["nameDest"].iloc[0]):
            df["nameDest"] = "C0000000000"
        if "step" not in df.columns and "hourOfDay" not in df.columns:
            df["step"] = 12

        # Apply feature engineering
        df_engineered = engineer_features(df, temporal_option="hourOfDay", copy=True)
        feature_cols = get_model_feature_names(temporal_option="hourOfDay")
        X = df_engineered[feature_cols]

        # 2. Transform Features & Run Inference
        X_trans = self._preprocessor.transform(X)
        probabilities = self._classifier.predict_proba(X_trans)[0]
        fraud_prob = float(probabilities[1])
        legit_prob = float(probabilities[0])
        predicted_class = int(fraud_prob >= 0.50)

        # Risk score and tier
        risk_score = int(round(fraud_prob * 100))
        thresholds = self.policy.get("thresholds", {"risk_low_max": 30, "risk_medium_max": 70})
        if risk_score <= thresholds.get("risk_low_max", 30):
            risk_level = "LOW"
        elif risk_score <= thresholds.get("risk_medium_max", 70):
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        # 3. Compute SHAP Values
        shap_values_raw = self._explainer.shap_values(X_trans)

        # Handle binary classification output shape (1, n_features, 2) or list of arrays
        if isinstance(shap_values_raw, list):
            shap_fraud = shap_values_raw[1][0]  # Class 1 (Fraud)
        elif isinstance(shap_values_raw, np.ndarray) and len(shap_values_raw.shape) == 3:
            shap_fraud = shap_values_raw[0, :, 1]  # (1, 15, 2) -> Class 1
        elif isinstance(shap_values_raw, np.ndarray) and len(shap_values_raw.shape) == 2:
            shap_fraud = shap_values_raw[0]
        else:
            shap_fraud = np.array(shap_values_raw).ravel()

        # 4. Map SHAP Contributions to Features
        feature_contributions = []
        positive_factors = []
        negative_factors = []
        raw_transformed_values = X_trans[0]

        for i, feat_name in enumerate(self._transformed_feature_names):
            s_val = float(shap_fraud[i])
            raw_val = float(raw_transformed_values[i])
            human_name = FEATURE_NAME_MAP.get(feat_name, feat_name)
            direction = "increases_risk" if s_val > 0 else "decreases_risk"

            item = {
                "feature": feat_name,
                "display_name": human_name,
                "value": round(raw_val, 4),
                "shap_value": round(s_val, 4),
                "direction": direction,
            }
            feature_contributions.append(item)

            if s_val > 0.001:
                positive_factors.append(item)
            elif s_val < -0.001:
                negative_factors.append(item)

        # Sort all features by absolute SHAP magnitude
        sorted_features = sorted(feature_contributions, key=lambda x: abs(x["shap_value"]), reverse=True)
        top_features = sorted_features[:top_k]

        # 5. Generate Natural Language Explanation
        explanation_text = self._generate_explanation_narrative(
            risk_level=risk_level,
            fraud_prob=fraud_prob,
            top_features=top_features,
            tx_data=df_engineered.iloc[0].to_dict(),
        )

        return {
            "prediction": predicted_class,
            "predicted_class_name": "Fraudulent" if predicted_class == 1 else "Legitimate",
            "fraud_probability": round(fraud_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "top_features": top_features,
            "positive_risk_factors": sorted(positive_factors, key=lambda x: x["shap_value"], reverse=True)[:top_k],
            "negative_risk_factors": sorted(negative_factors, key=lambda x: x["shap_value"])[:top_k],
            "all_features_shap": feature_contributions,  # Full vector for audit persistence
            "explanation_text": explanation_text,
            "model_version": self.metadata.get("model_version", "1.0.0"),
            "model_name": self.metadata.get("model_name", "Random Forest Fraud Classifier"),
        }

    def _generate_explanation_narrative(
        self,
        risk_level: str,
        fraud_prob: float,
        top_features: List[Dict[str, Any]],
        tx_data: Dict[str, Any],
    ) -> str:
        """Synthesize clear, grounded natural language summary of the fraud decision."""
        if risk_level == "LOW":
            return (
                "Transaction approved. Balance reconciliation, transaction mechanism, "
                "and amount patterns align normally with legitimate customer payment behavior."
            )

        # For medium or high risk, identify the primary positive drivers
        reasons = []
        err_orig = abs(float(tx_data.get("errorBalanceOrig", 0.0)))
        err_dest = abs(float(tx_data.get("errorBalanceDest", 0.0)))
        ratio = float(tx_data.get("amountToBalanceRatio", 0.0))
        tx_type = str(tx_data.get("type", ""))

        for feat in top_features:
            if feat["direction"] == "increases_risk":
                name = feat["feature"]
                if "errorBalanceOrig" in name and err_orig > 0.01:
                    reasons.append("an inconsistent sender account balance after transfer")
                elif "amountToBalanceRatio" in name and ratio >= 0.5:
                    reasons.append(f"draining a large proportion ({min(100, int(ratio * 100))}%) of the sender's total balance")
                elif "type_TRANSFER" in name or "type_CASH_OUT" in name:
                    reasons.append(f"the high-risk transaction mechanism ({tx_type})")
                elif "errorBalanceDest" in name and err_dest > 0.01:
                    reasons.append("anomalous destination balance changes")
                elif "hourOfDay" in name:
                    reasons.append(f"unusual transaction timing ({int(tx_data.get('hourOfDay', 0))}:00 hrs)")

        if reasons:
            unique_reasons = list(dict.fromkeys(reasons))
            combined_reasons = " and ".join(unique_reasons[:2])
            prefix = "Flagged as HIGH RISK" if risk_level == "HIGH" else "Flagged for ADDITIONAL VERIFICATION"
            return f"{prefix} mainly due to {combined_reasons}."
        else:
            return f"Flagged as {risk_level} risk (risk score: {int(round(fraud_prob * 100))}) based on multi-feature risk indicator attributions."


# Singleton instance
_explainer_instance = None


def get_fraud_explainer() -> FraudExplainer:
    """Retrieve or create singleton FraudExplainer instance."""
    global _explainer_instance
    if _explainer_instance is None:
        _explainer_instance = FraudExplainer()
    return _explainer_instance


def explain(transaction: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
    """Convenience top-level function for SHAP explanation."""
    explainer = get_fraud_explainer()
    return explainer.explain_transaction(transaction, top_k=top_k)
