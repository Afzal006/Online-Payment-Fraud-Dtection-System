"""
Modular Risk Signal Detection Engine.

Evaluates behavioral, velocity, beneficiary, and transaction features
to detect discrete, actionable fraud risk signals with standardized codes,
severities, human-readable explanations, and scoring weights.
"""

from typing import Dict, Any, List, Optional


class RiskSignalService:
    """Detects structured risk signals from transaction and behavioral features."""

    # Indian Daily Payment Amount Thresholds (INR ₹)
    AMOUNT_NORMAL_MAX = 10000.0
    AMOUNT_MODERATE_MAX = 50000.0
    AMOUNT_SIGNIFICANT_MAX = 100000.0

    @classmethod
    def evaluate_signals(
        cls,
        features: Dict[str, Any],
        has_account_simulation: bool = False,
        is_account_drain: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate and return all active risk signals.

        Returns:
            List of dictionaries:
            [
                {
                    "code": str,
                    "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
                    "message": str,
                    "weight": int
                }
            ]
        """
        signals: List[Dict[str, Any]] = []

        amount = float(features.get("amount", 0.0))
        tx_type = str(features.get("tx_type", "TRANSFER")).upper().strip()
        is_merchant = bool(features.get("is_merchant_dest", False))

        tx_1m = features.get("tx_count_last_1m", 0)
        tx_10m = features.get("tx_count_last_10m", 0)
        tx_1h = features.get("tx_count_last_1h", 0)

        user_tx_count = features.get("user_tx_count", 0)
        user_avg_amount = features.get("user_avg_amount", 0.0)
        deviation_ratio = features.get("amount_deviation_ratio", 1.0)
        user_fraud_rate = features.get("user_fraud_rate", 0.0)

        is_first_time_ben = features.get("is_first_time_beneficiary", True)
        ben_tx_count = features.get("beneficiary_tx_count", 0)
        ben_prior_success = features.get("beneficiary_prior_success", False)

        is_night = bool(features.get("is_unusual_night_hours", False))
        hour_of_day = features.get("hour_of_day", 12)

        # 1. RAPID_REPEATED_TRANSACTIONS (CRITICAL)
        if tx_1m >= 1:
            signals.append({
                "code": "RAPID_REPEATED_TRANSACTIONS",
                "severity": "CRITICAL",
                "message": "Multiple payment attempts initiated in rapid succession (< 60 seconds).",
                "weight": 35,
            })

        # 2. CRITICAL_BALANCE_DRAIN (CRITICAL)
        if is_account_drain:
            signals.append({
                "code": "CRITICAL_BALANCE_DRAIN",
                "severity": "CRITICAL",
                "message": "Account balance completely depleted to ₹0.00 in a single transaction.",
                "weight": 40,
            })

        # 3. HIGH_TRANSACTION_VELOCITY (HIGH)
        if tx_10m >= 3 or tx_1h >= 5:
            signals.append({
                "code": "HIGH_TRANSACTION_VELOCITY",
                "severity": "HIGH",
                "message": f"Abnormal transaction burst ({tx_10m} payments in last 10m / {tx_1h} in last 1h).",
                "weight": 25,
            })

        # 4. HIGH_AMOUNT_DEVIATION (HIGH)
        if user_tx_count >= 2 and deviation_ratio >= 3.5:
            signals.append({
                "code": "HIGH_AMOUNT_DEVIATION",
                "severity": "HIGH",
                "message": f"Payment amount (₹{amount:,.2f}) is {deviation_ratio:.1f}x higher than customer historical average (₹{user_avg_amount:,.2f}).",
                "weight": 25,
            })
        elif user_tx_count >= 2 and 2.0 <= deviation_ratio < 3.5:
            signals.append({
                "code": "MODERATE_AMOUNT_SPIKE",
                "severity": "MEDIUM",
                "message": f"Payment amount is {deviation_ratio:.1f}x above customer normal spending baseline.",
                "weight": 15,
            })

        # 5. HIGH_VALUE_TRANSFER (HIGH)
        if amount > cls.AMOUNT_SIGNIFICANT_MAX:
            if tx_type in ["TRANSFER", "CASH_OUT"]:
                signals.append({
                    "code": "HIGH_VALUE_TRANSFER",
                    "severity": "HIGH",
                    "message": f"High-value transaction exceeding ₹1,00,000 threshold (₹{amount:,.2f}).",
                    "weight": 30,
                })
        elif amount > cls.AMOUNT_MODERATE_MAX:
            if tx_type in ["TRANSFER", "CASH_OUT"]:
                signals.append({
                    "code": "MODERATE_VALUE_TRANSFER",
                    "severity": "MEDIUM",
                    "message": f"Significant transaction value exceeding ₹50,000 (₹{amount:,.2f}).",
                    "weight": 15,
                })

        # 6. NEW_BENEFICIARY_FIRST_TRANSFER (MEDIUM)
        if is_first_time_ben and tx_type == "TRANSFER" and not is_merchant:
            signals.append({
                "code": "NEW_BENEFICIARY_FIRST_TRANSFER",
                "severity": "MEDIUM",
                "message": "First payment initiated to a newly added beneficiary handle.",
                "weight": 15,
            })

        # 7. UNUSUAL_TRANSACTION_TIME (MEDIUM)
        if is_night:
            signals.append({
                "code": "UNUSUAL_TRANSACTION_TIME",
                "severity": "MEDIUM",
                "message": f"Off-hours payment executed during high-risk night window ({hour_of_day}:00).",
                "weight": 10,
            })

        # 8. CUSTOMER_HISTORICAL_RISK (HIGH)
        if user_tx_count >= 3 and user_fraud_rate >= 0.25:
            signals.append({
                "code": "CUSTOMER_HISTORICAL_RISK",
                "severity": "HIGH",
                "message": f"Customer account has elevated historical incident rate ({user_fraud_rate*100:.1f}% flagged).",
                "weight": 20,
            })

        # 9. UNVERIFIED_BALANCE_CONTEXT (LOW)
        if not has_account_simulation and not is_merchant:
            signals.append({
                "code": "UNVERIFIED_BALANCE_CONTEXT",
                "severity": "LOW",
                "message": "Account balance simulation context unverified.",
                "weight": 5,
            })

        # 10. TRUST DISCOUNTS (Positive signals that reduce false positive friction)
        if is_merchant and amount <= cls.AMOUNT_MODERATE_MAX:
            signals.append({
                "code": "MERCHANT_PAYMENT_TRUST",
                "severity": "LOW",
                "message": "Payment directed to verified merchant commercial recipient.",
                "weight": -15,
            })

        if ben_tx_count >= 3 and ben_prior_success and not is_first_time_ben:
            signals.append({
                "code": "ESTABLISHED_BENEFICIARY_TRUST",
                "severity": "LOW",
                "message": f"Trusted recurrent beneficiary with {ben_tx_count} successful prior payments.",
                "weight": -10,
            })

        return signals

    @classmethod
    def calculate_signals_score(cls, signals: List[Dict[str, Any]]) -> int:
        """Sum weights of active signals bounded to [0, 100]."""
        raw_score = sum(s.get("weight", 0) for s in signals)
        return max(0, min(100, raw_score))
