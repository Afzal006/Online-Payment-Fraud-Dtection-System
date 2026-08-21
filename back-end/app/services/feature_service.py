"""
Centralized Feature Engineering Service for Real-Time Fraud Detection.

Derives contextual, behavioral, velocity, temporal, and beneficiary features
from live transaction payloads and historical database records.

Data Leakage Prevention:
- Historical queries strictly filter for transactions created before the reference timestamp (`created_at < ref_time`).
- The current transaction is never included in its own historical baseline calculations.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy import func

from app.extensions import db
from app.models.transaction import Transaction
from app.models.beneficiary import Beneficiary
from app.models.user import User


class FeatureService:
    """Extracts domain, behavioral, velocity, and temporal features for fraud scoring."""

    @classmethod
    def extract_features(
        cls,
        user_id: int,
        amount: float,
        tx_type: str,
        beneficiary_id: Optional[int] = None,
        destination_upi_id: Optional[str] = None,
        is_merchant_dest: bool = False,
        reference_time: Optional[datetime] = None,
        current_tx_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Extract comprehensive feature set for a candidate transaction.

        Parameters:
            user_id: ID of the originating customer
            amount: Transaction amount in INR (₹)
            tx_type: Transaction type ('TRANSFER', 'PAYMENT', etc.)
            beneficiary_id: Optional ID of saved Beneficiary
            destination_upi_id: Destination UPI handle or identifier
            is_merchant_dest: True if recipient is a merchant
            reference_time: Timestamp of candidate transaction (defaults to now UTC)
            current_tx_id: Optional transaction ID (excluded from history if updating)

        Returns:
            Dictionary of calculated feature variables
        """
        ref_time = reference_time or datetime.now(timezone.utc)
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        amount = float(amount)
        clean_type = str(tx_type).strip().upper()

        # 1. Temporal Features
        hour_of_day = ref_time.hour
        day_of_week = ref_time.weekday()  # 0=Monday, 6=Sunday
        is_weekend = 1 if day_of_week in [5, 6] else 0
        is_unusual_night_hours = 1 if 1 <= hour_of_day <= 5 else 0

        # Base query for strictly prior transactions by this user (Data Leakage Protection)
        base_query = db.session.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at < ref_time,
        )
        if current_tx_id is not None:
            base_query = base_query.filter(Transaction.id != current_tx_id)

        # 2. Customer Behavioral Baselines
        history_stats = base_query.with_entities(
            func.count(Transaction.id).label("tx_count"),
            func.avg(Transaction.amount).label("avg_amount"),
            func.max(Transaction.amount).label("max_amount"),
        ).first()

        user_tx_count = int(history_stats.tx_count or 0) if history_stats else 0
        user_avg_amount = float(history_stats.avg_amount or 0.0) if history_stats else 0.0
        user_max_amount = float(history_stats.max_amount or 0.0) if history_stats else 0.0

        if user_tx_count > 0 and user_avg_amount > 0:
            amount_deviation_ratio = round(amount / (user_avg_amount + 1.0), 2)
        else:
            amount_deviation_ratio = 1.0  # Baseline when no history exists

        # Historical fraud / high-risk rate
        flagged_count = base_query.filter(
            (Transaction.prediction == 1) | (Transaction.status.in_(["FLAGGED", "UNDER_REVIEW", "REJECTED"]))
        ).count()
        user_fraud_rate = round(flagged_count / user_tx_count, 4) if user_tx_count > 0 else 0.0

        # 3. Multi-Window Velocity Aggregations
        t_1m = ref_time - timedelta(minutes=1)
        t_10m = ref_time - timedelta(minutes=10)
        t_1h = ref_time - timedelta(hours=1)
        t_24h = ref_time - timedelta(hours=24)

        tx_count_last_1m = base_query.filter(Transaction.created_at >= t_1m).count()
        tx_count_last_10m = base_query.filter(Transaction.created_at >= t_10m).count()
        tx_count_last_1h = base_query.filter(Transaction.created_at >= t_10h if False else Transaction.created_at >= t_1h).count()
        
        last_24h_stats = base_query.filter(Transaction.created_at >= t_24h).with_entities(
            func.count(Transaction.id).label("count_24h"),
            func.sum(Transaction.amount).label("volume_24h"),
        ).first()

        tx_count_last_24h = int(last_24h_stats.count_24h or 0) if last_24h_stats else 0
        volume_last_24h = float(last_24h_stats.volume_24h or 0.0) if last_24h_stats else 0.0

        # 4. Beneficiary Trust Features
        is_first_time_beneficiary = True
        beneficiary_tx_count = 0
        beneficiary_age_days = 0.0
        beneficiary_prior_success = False

        if beneficiary_id:
            beneficiary = db.session.get(Beneficiary, beneficiary_id)
            if beneficiary:
                if beneficiary.created_at:
                    b_created = beneficiary.created_at
                    if b_created.tzinfo is None:
                        b_created = b_created.replace(tzinfo=timezone.utc)
                    age_delta = ref_time - b_created
                    beneficiary_age_days = max(0.0, round(age_delta.total_seconds() / 86400.0, 2))

                # Check prior approved transactions to this beneficiary
                prior_approved = base_query.filter(
                    Transaction.beneficiary_id == beneficiary_id,
                    Transaction.status == "APPROVED",
                ).count()
                beneficiary_tx_count = prior_approved
                if prior_approved > 0:
                    is_first_time_beneficiary = False
                    beneficiary_prior_success = True
        elif destination_upi_id:
            # Check by destination UPI handle in history
            prior_to_upi = base_query.filter(
                Transaction.destination_upi_id == destination_upi_id,
                Transaction.status == "APPROVED",
            ).count()
            beneficiary_tx_count = prior_to_upi
            if prior_to_upi > 0:
                is_first_time_beneficiary = False
                beneficiary_prior_success = True

        return {
            # Transaction Domain Features
            "amount": amount,
            "tx_type": clean_type,
            "is_merchant_dest": 1 if is_merchant_dest else 0,
            # Temporal Features
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "is_unusual_night_hours": is_unusual_night_hours,
            # Customer Behavioral Baselines
            "user_tx_count": user_tx_count,
            "user_avg_amount": user_avg_amount,
            "user_max_amount": user_max_amount,
            "amount_deviation_ratio": amount_deviation_ratio,
            "user_fraud_rate": user_fraud_rate,
            # Velocity Features
            "tx_count_last_1m": tx_count_last_1m,
            "tx_count_last_10m": tx_count_last_10m,
            "tx_count_last_1h": tx_count_last_1h,
            "tx_count_last_24h": tx_count_last_24h,
            "volume_last_24h": volume_last_24h,
            # Beneficiary Features
            "is_first_time_beneficiary": is_first_time_beneficiary,
            "beneficiary_tx_count": beneficiary_tx_count,
            "beneficiary_age_days": beneficiary_age_days,
            "beneficiary_prior_success": beneficiary_prior_success,
        }
