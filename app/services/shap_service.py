"""
SHAP Explanation Service for Flask Backend & APIs.

Wraps the machine learning SHAP engine (ml.explain) to provide:
- Dual-View Explainable AI:
  1. Customer View: Simple, reassuring, non-technical explanations that prevent adversarial gaming.
  2. Admin/SOC View: In-depth game-theoretic SHAP attributions, base values, and risk signals telemetry.
- JSON output contracts matching Supplement Section 7.1.
"""

from typing import Dict, Any, List, Optional
from ml.explain import get_fraud_explainer, explain as ml_explain


class ShapService:
    """Service layer exposing SHAP explanations and dual-view formatting to Flask controllers."""

    def __init__(self):
        self._explainer = None

    @property
    def explainer(self):
        if self._explainer is None:
            self._explainer = get_fraud_explainer()
        return self._explainer

    def explain_transaction(
        self,
        transaction_data: Dict[str, Any],
        top_k: int = 5,
        prediction_id: Optional[int] = None,
        risk_signals: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate local SHAP explanations and dual-view narratives for a transaction.
        """
        explanation = self.explainer.explain_transaction(transaction_data, top_k=top_k)
        if prediction_id is not None:
            explanation["prediction_id"] = prediction_id

        # Generate Dual-View Explanations
        risk_level = explanation.get("risk_level", "LOW")
        signals = risk_signals or []

        customer_summary = self.generate_customer_explanation(
            risk_level=risk_level,
            transaction_data=transaction_data,
            risk_signals=signals,
        )
        admin_summary = explanation.get("explanation_text", "")

        explanation["customer_explanation"] = customer_summary
        explanation["admin_explanation"] = admin_summary
        explanation["human_readable_summary"] = customer_summary  # Friendly fallback

        return explanation

    @classmethod
    def generate_customer_explanation(
        cls,
        risk_level: str,
        transaction_data: Dict[str, Any],
        risk_signals: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Generate safe, customer-friendly explanation without revealing internal weights or thresholds.
        """
        if risk_level == "LOW":
            return "Payment verified and approved. Details match your normal account activity."

        signals = risk_signals or []
        messages: List[str] = []

        for s in signals:
            code = s.get("code", "")
            if code == "NEW_BENEFICIARY_FIRST_TRANSFER":
                messages.append("This is your first transfer to this recipient.")
            elif code in ["HIGH_AMOUNT_DEVIATION", "MODERATE_AMOUNT_SPIKE"]:
                messages.append("This payment amount is higher than your usual transactions.")
            elif code == "RAPID_REPEATED_TRANSACTIONS":
                messages.append("Multiple transactions were initiated within a short time.")
            elif code == "HIGH_VALUE_TRANSFER":
                messages.append("High-value payment requires additional security authorization.")
            elif code == "CRITICAL_BALANCE_DRAIN":
                messages.append("Transfer requires verification to protect full account balance.")
            elif code == "IMPOSSIBLE_TRAVEL":
                messages.append("Anomalous location jump detected requiring step-up verification.")
            elif code == "UNUSUAL_LOCATION":
                messages.append("Payment initiated from a new or unfamiliar location.")
            elif code == "RAPID_GEO_CHANGE":
                messages.append("Rapid location change detected across distant geographic regions.")
            elif code == "UNKNOWN_DEVICE_LOGIN":
                messages.append("Transaction initiated from an unverified or new device.")

        if not messages:
            if risk_level in ["HIGH", "CRITICAL"]:
                messages.append("This transaction requires step-up identity verification for your security.")
            else:
                messages.append("Routine security check applied.")

        # Combine up to 2 safe customer-facing messages
        unique_msgs = list(dict.fromkeys(messages))[:2]
        return " ".join(unique_msgs)

    def format_frontend_contract(
        self,
        explanation_data: Dict[str, Any],
        prediction_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Format explanation specifically for the frontend UI drawer.
        """
        return {
            "prediction_id": prediction_id or explanation_data.get("prediction_id"),
            "risk_score": explanation_data.get("risk_score"),
            "risk_level": explanation_data.get("risk_level"),
            "top_features": [
                {
                    "feature": item["feature"],
                    "display_name": item["display_name"],
                    "value": item["value"],
                    "shap_value": item["shap_value"],
                    "direction": item["direction"],
                }
                for item in explanation_data.get("top_features", [])
            ],
            "explanation_text": explanation_data.get("admin_explanation") or explanation_data.get("explanation_text", ""),
            "customer_explanation": explanation_data.get("customer_explanation", ""),
        }


# Global singleton instance
_shap_service_instance = None


def get_shap_service() -> ShapService:
    """Retrieve singleton ShapService instance."""
    global _shap_service_instance
    if _shap_service_instance is None:
        _shap_service_instance = ShapService()
    return _shap_service_instance


def explain_transaction(
    transaction: Dict[str, Any],
    top_k: int = 5,
    prediction_id: Optional[int] = None,
    risk_signals: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Top-level convenience helper for transaction explanation."""
    service = get_shap_service()
    return service.explain_transaction(
        transaction,
        top_k=top_k,
        prediction_id=prediction_id,
        risk_signals=risk_signals,
    )
