"""
Transaction Database Model.

Persists incoming payment transactions, ML model fraud assessments,
risk scoring tiers, and adaptive challenge state.
"""

from datetime import datetime, timezone
from app.extensions import db


class Transaction(db.Model):
    """Payment transaction entity with fraud risk scores, constraints, and indexes."""

    __tablename__ = "transactions"
    __table_args__ = (
        db.CheckConstraint("amount > 0", name="check_tx_amount_positive"),
        db.CheckConstraint("fraud_probability >= 0.0 AND fraud_probability <= 1.0", name="check_tx_fraud_prob_range"),
        db.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_tx_risk_score_range"),
        db.CheckConstraint("risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="check_tx_risk_level"),
        db.Index("ix_transactions_user_id_created_at", "user_id", "created_at"),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    step = db.Column(db.Integer, default=1, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'TRANSFER', 'CASH_OUT', 'PAYMENT', 'CASH_IN', 'DEBIT'
    amount = db.Column(db.Float, nullable=False)
    name_orig = db.Column(db.String(50), nullable=True)
    oldbalance_org = db.Column(db.Float, nullable=False)
    newbalance_orig = db.Column(db.Float, nullable=False)
    name_dest = db.Column(db.String(50), nullable=True)
    oldbalance_dest = db.Column(db.Float, nullable=False)
    newbalance_dest = db.Column(db.Float, nullable=False)

    # ML Assessment & Risk Engine Fields
    prediction = db.Column(db.Integer, nullable=False, default=0)
    fraud_probability = db.Column(db.Float, nullable=False, default=0.0)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_level = db.Column(db.String(20), nullable=False, default="LOW")  # 'LOW', 'MEDIUM', 'HIGH'
    decision = db.Column(db.String(50), nullable=False, default="APPROVE_IMMEDIATELY")
    status = db.Column(db.String(30), nullable=False, default="APPROVED")  # 'APPROVED', 'PENDING_OTP', 'VERIFIED', 'REJECTED', 'FLAGGED'

    # Adaptive Challenge (OTP) Fields
    requires_otp = db.Column(db.Boolean, default=False, nullable=False)
    otp_code = db.Column(db.String(10), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0, nullable=False)

    # Customer Payment Identity & Beneficiary Tracking (Phase 1)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey("beneficiaries.id", ondelete="SET NULL"), nullable=True, index=True)
    destination_upi_id = db.Column(db.String(100), nullable=True)
    destination_name = db.Column(db.String(100), nullable=True)
    payment_note = db.Column(db.String(255), nullable=True)
    balance_before = db.Column(db.Float, nullable=True)
    balance_after = db.Column(db.Float, nullable=True)

    # Explanation JSON / audit cache
    explanation_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    user = db.relationship("User", back_populates="transactions")
    alert = db.relationship("Alert", back_populates="transaction", uselist=False, cascade="all, delete-orphan")
    beneficiary = db.relationship("Beneficiary", back_populates="transactions")

    def to_dict(self) -> dict:
        """Convert transaction instance to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "step": self.step,
            "type": self.type,
            "amount": self.amount,
            "name_orig": self.name_orig,
            "oldbalance_org": self.oldbalance_org,
            "newbalance_orig": self.newbalance_orig,
            "name_dest": self.name_dest,
            "oldbalance_dest": self.oldbalance_dest,
            "newbalance_dest": self.newbalance_dest,
            "prediction": self.prediction,
            "fraud_probability": self.fraud_probability,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "decision": self.decision,
            "status": self.status,
            "requires_otp": self.requires_otp,
            "beneficiary_id": self.beneficiary_id,
            "destination_upi_id": self.destination_upi_id,
            "destination_name": self.destination_name,
            "payment_note": self.payment_note,
            "balance_before": float(self.balance_before) if self.balance_before is not None else None,
            "balance_after": float(self.balance_after) if self.balance_after is not None else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Transaction {self.id}: {self.type} {self.amount} ({self.risk_level})>"
