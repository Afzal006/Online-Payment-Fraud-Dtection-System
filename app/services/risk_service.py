"""
Risk Decision and Adaptive Real-Time Hybrid Policy Service.

Implements a transparent Real-Time Fraud Risk Engine combining:
1. Calibrated Machine Learning Model Score (Random Forest fraud probability P_fraud)
2. Domain & Behavioral Risk Signals (Velocity, Deviation, Beneficiary, Temporal)
3. 4-Tier Adaptive Security Routing:
   - LOW (0 - 29): Instant Auto-Approval (APPROVE_IMMEDIATELY)
   - MEDIUM (30 - 59): Monitored Approval (APPROVE_WITH_MONITORING)
   - HIGH (60 - 79): Step-up 2FA Challenge (TRIGGER_OTP_VERIFICATION)
   - CRITICAL (80 - 100): Step-up OTP + Automated SOC Incident Alert (TRIGGER_SECURITY_REVIEW)
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.services.risk_signal_service import RiskSignalService

POLICY_PATH = Path(__file__).resolve().parent.parent.parent / "ml" / "artifacts" / "risk_policy.json"


class RiskDecisionService:
    """Centralized risk decision engine combining ML probabilities and behavioral risk signals."""

    # 4-Tier Boundaries (Configurable defaults)
    RISK_LOW_MAX = 29
    RISK_MEDIUM_MAX = 59
    RISK_HIGH_MAX = 79
    RISK_CRITICAL_MAX = 100

    # Indian Payment Amount Policy Tiers (INR ₹)
    AMOUNT_NORMAL_MAX = 10000.0        # ₹0 - ₹10,000: Normal everyday payment
    AMOUNT_MODERATE_MAX = 50000.0      # ₹10,001 - ₹50,000: Moderate risk
    AMOUNT_SIGNIFICANT_MAX = 100000.0  # ₹50,001 - ₹1,00,000: Significant risk

    @classmethod
    def load_policy_config(cls) -> Dict[str, Any]:
        """Load external risk policy JSON configuration or fallback to defaults."""
        if POLICY_PATH.exists():
            try:
                with open(POLICY_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    @classmethod
    def calculate_rule_risk(
        cls,
        amount: float,
        tx_type: str,
        has_account_simulation: bool = False,
        is_account_drain: bool = False,
        hour_of_day: int = 12,
        is_merchant_dest: bool = False,
        features: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, List[str], List[Dict[str, Any]]]:
        """
        Calculate rule-based risk score (0-100) and identify contributing risk signals.

        Returns:
            (signals_score, risk_factors_strings, structured_signals_list)
        """
        feat = features or {
            "amount": amount,
            "tx_type": tx_type,
            "is_merchant_dest": 1 if is_merchant_dest else 0,
            "hour_of_day": hour_of_day,
            "is_unusual_night_hours": 1 if 1 <= hour_of_day <= 5 else 0,
        }

        # Evaluate structured signals from RiskSignalService
        signals = RiskSignalService.evaluate_signals(
            features=feat,
            has_account_simulation=has_account_simulation,
            is_account_drain=is_account_drain,
        )

        signals_score = RiskSignalService.calculate_signals_score(signals)
        factors = [s["message"] for s in signals if s.get("weight", 0) > 0]

        return signals_score, factors

    @classmethod
    def evaluate_hybrid_risk(
        cls,
        ml_fraud_prob: float,
        amount: float,
        tx_type: str,
        has_account_simulation: bool = False,
        is_account_drain: bool = False,
        hour_of_day: int = 12,
        is_merchant_dest: bool = False,
        features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Combine ML fraud probability and behavioral risk signals into a 0-100 risk score and 4-tier decision.

        Returns:
            Dictionary with ml_score, rule_score, final_risk_score, risk_level, decision, signals, etc.
        """
        # 1. Base ML Probability & Score (0 - 100)
        ml_prob = max(0.0, min(1.0, float(ml_fraud_prob)))
        ml_score = int(round(ml_prob * 100))

        # 2. Extract Structured Risk Signals & Score
        feat = features or {
            "amount": amount,
            "tx_type": tx_type,
            "is_merchant_dest": 1 if is_merchant_dest else 0,
            "hour_of_day": hour_of_day,
            "is_unusual_night_hours": 1 if 1 <= hour_of_day <= 5 else 0,
        }
        structured_signals = RiskSignalService.evaluate_signals(
            features=feat,
            has_account_simulation=has_account_simulation,
            is_account_drain=is_account_drain,
        )
        signals_score = RiskSignalService.calculate_signals_score(structured_signals)
        risk_factors = [s["message"] for s in structured_signals if s.get("weight", 0) > 0]

        clean_type = tx_type.strip().upper()

        # 3. Transparent Weighted Combination & Policy Rules
        if is_account_drain:
            # Critical account-drain pattern: High priority
            final_score = max(85, int(round(0.60 * ml_score + 0.40 * signals_score)))
        elif has_account_simulation:
            # Simulation provided: Balanced 50% ML / 50% Signals
            weighted = 0.50 * ml_score + 0.50 * signals_score
            final_score = int(round(weighted))
        else:
            # Real-time daily transaction: 25% ML / 75% Signals
            weighted = 0.25 * ml_score + 0.75 * signals_score
            final_score = int(round(weighted))

            # General Policy Rules for Indian daily payment risk bands:
            if amount > cls.AMOUNT_SIGNIFICANT_MAX and clean_type in ["TRANSFER", "CASH_OUT"]:
                final_score = max(75, final_score)
            elif amount > cls.AMOUNT_MODERATE_MAX and clean_type in ["TRANSFER", "CASH_OUT"]:
                final_score = max(65, final_score)
            elif amount > cls.AMOUNT_NORMAL_MAX and clean_type in ["TRANSFER", "CASH_OUT"]:
                final_score = max(35, final_score)

        # Ensure high ML certainty is never masked by negative signal discounts
        final_score = max(final_score, ml_score)
        final_score = max(0, min(100, final_score))

        # 4. 4-Tier Adaptive Security Routing
        if final_score <= cls.RISK_LOW_MAX:
            risk_level = "LOW"
            decision = "APPROVE_IMMEDIATELY"
            initial_status = "APPROVED"
            requires_otp = False
            create_alert = False
            alert_severity = None
            user_msg = "Payment verified and approved automatically."
        elif final_score <= cls.RISK_MEDIUM_MAX:
            risk_level = "MEDIUM"
            decision = "APPROVE_WITH_MONITORING"
            initial_status = "APPROVED"
            requires_otp = False
            create_alert = False
            alert_severity = None
            user_msg = "Payment completed with routine telemetry monitoring."
        elif final_score <= cls.RISK_HIGH_MAX:
            risk_level = "HIGH"
            decision = "TRIGGER_OTP_VERIFICATION"
            initial_status = "OTP_REQUIRED"
            requires_otp = True
            create_alert = True
            alert_severity = "HIGH"
            user_msg = "Additional verification required. One-time verification code sent."
        else:
            risk_level = "CRITICAL"
            decision = "TRIGGER_SECURITY_REVIEW"
            initial_status = "UNDER_REVIEW"
            requires_otp = True
            create_alert = True
            alert_severity = "CRITICAL"
            user_msg = "High-risk transaction detected. Verification required and security review opened."

        return {
            "ml_fraud_probability": round(ml_prob, 4),
            "ml_score": ml_score,
            "rule_score": signals_score,
            "signals_score": signals_score,
            "risk_score": final_score,
            "risk_level": risk_level,
            "decision": decision,
            "initial_status": initial_status,
            "requires_otp": requires_otp,
            "create_alert": create_alert,
            "alert_severity": alert_severity,
            "risk_factors": risk_factors,
            "risk_signals": structured_signals,
            "user_message": user_msg,
        }

    @classmethod
    def evaluate_risk(cls, risk_score: int) -> Dict[str, Any]:
        """Backward-compatible helper evaluating raw integer risk score across 4 tiers."""
        if not isinstance(risk_score, int):
            try:
                risk_score = int(round(float(risk_score)))
            except (ValueError, TypeError):
                risk_score = 0

        bounded_score = max(0, min(100, risk_score))

        if bounded_score <= cls.RISK_LOW_MAX:
            return {
                "risk_score": bounded_score,
                "risk_level": "LOW",
                "decision": "APPROVE_IMMEDIATELY",
                "initial_status": "APPROVED",
                "requires_otp": False,
                "create_alert": False,
                "user_message": "Payment verified and approved automatically.",
            }
        elif bounded_score <= cls.RISK_MEDIUM_MAX:
            return {
                "risk_score": bounded_score,
                "risk_level": "MEDIUM",
                "decision": "APPROVE_WITH_MONITORING",
                "initial_status": "APPROVED",
                "requires_otp": False,
                "create_alert": False,
                "user_message": "Payment completed with routine telemetry monitoring.",
            }
        elif bounded_score <= cls.RISK_HIGH_MAX:
            return {
                "risk_score": bounded_score,
                "risk_level": "HIGH",
                "decision": "TRIGGER_OTP_VERIFICATION",
                "initial_status": "OTP_REQUIRED",
                "requires_otp": True,
                "create_alert": True,
                "alert_severity": "HIGH",
                "user_message": "Additional verification required. One-time verification code sent.",
            }
        else:
            return {
                "risk_score": bounded_score,
                "risk_level": "CRITICAL",
                "decision": "TRIGGER_SECURITY_REVIEW",
                "initial_status": "UNDER_REVIEW",
                "requires_otp": True,
                "create_alert": True,
                "alert_severity": "CRITICAL",
                "user_message": "High-risk transaction detected. Verification required and security review opened.",
            }


def evaluate_transaction_risk(risk_score: int) -> Dict[str, Any]:
    """Convenience functional interface for risk evaluation."""
    return RiskDecisionService.evaluate_risk(risk_score)
