from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from app.extensions import db


class Beneficiary(db.Model):
    """Saved recipient entity with 24h cooling period, progressive trust, and audit state."""

    __tablename__ = "beneficiaries"
    __table_args__ = (
        db.UniqueConstraint("user_id", "beneficiary_upi_id", name="uq_user_beneficiary_upi"),
        db.Index("ix_beneficiaries_user_id_status", "user_id", "status"),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    beneficiary_name = db.Column(db.String(100), nullable=False)
    beneficiary_upi_id = db.Column(db.String(100), nullable=False, index=True)
    beneficiary_account_reference = db.Column(db.String(50), nullable=True)
    beneficiary_phone = db.Column(db.String(20), nullable=True)
    nickname = db.Column(db.String(50), nullable=True)

    is_verified = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(db.String(20), default="ACTIVE", nullable=False)  # 'ACTIVE', 'REVOKED', 'INACTIVE'
    trust_status = db.Column(db.String(32), default="COOLING", nullable=False)  # 'COOLING', 'NEW', 'ESTABLISHED', 'TRUSTED', 'REVOKED'

    # 24-Hour Mandatory Security Cooling Period
    cooling_period_hours = db.Column(db.Integer, default=24, nullable=False)
    cooling_expires_at = db.Column(db.DateTime, nullable=True)

    # Intelligence & Payment Telemetry
    successful_payment_count = db.Column(db.Integer, default=0, nullable=False)
    failed_payment_count = db.Column(db.Integer, default=0, nullable=False)
    total_transferred_amount = db.Column(db.Float, default=0.0, nullable=False)
    first_payment_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = db.relationship("User", back_populates="beneficiaries")
    transactions = db.relationship("Transaction", back_populates="beneficiary")

    def is_cooling_active(self, reference_time: Optional[datetime] = None) -> bool:
        """Evaluate if the 24-hour mandatory security cooling period is currently active."""
        if self.status in ["REVOKED", "INACTIVE"] or self.trust_status == "REVOKED":
            return False

        if not self.cooling_expires_at:
            return False

        ref = reference_time or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)

        exp = self.cooling_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)

        return exp > ref

    def get_cooling_remaining_seconds(self, reference_time: Optional[datetime] = None) -> int:
        """Calculate remaining cooling period seconds."""
        if not self.is_cooling_active(reference_time):
            return 0

        ref = reference_time or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)

        exp = self.cooling_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)

        return max(0, int((exp - ref).total_seconds()))

    def get_effective_trust_status(self, reference_time: Optional[datetime] = None) -> str:
        """Compute point-in-time progressive trust status."""
        if self.status in ["REVOKED", "INACTIVE"] or self.trust_status == "REVOKED":
            return "REVOKED"

        if self.is_cooling_active(reference_time):
            return "COOLING"

        if self.successful_payment_count >= 3 and self.failed_payment_count == 0:
            return "TRUSTED"
        elif self.successful_payment_count >= 1:
            return "ESTABLISHED"

        return "NEW"

    def to_dict(self, include_admin: bool = False, reference_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Convert beneficiary to JSON-serializable dictionary with cooling and trust metadata."""
        effective_trust = self.get_effective_trust_status(reference_time)
        cooling_active = self.is_cooling_active(reference_time)
        cooling_remaining = self.get_cooling_remaining_seconds(reference_time)

        base = {
            "id": self.id,
            "user_id": self.user_id,
            "beneficiary_name": self.beneficiary_name,
            "beneficiary_upi_id": self.beneficiary_upi_id,
            "beneficiary_account_reference": self.beneficiary_account_reference,
            "beneficiary_phone": self.beneficiary_phone,
            "nickname": self.nickname,
            "is_verified": self.is_verified,
            "status": self.status,
            "trust_status": effective_trust,
            "cooling_period_active": cooling_active,
            "cooling_period_remaining_seconds": cooling_remaining,
            "cooling_expires_at": self.cooling_expires_at.isoformat() if self.cooling_expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }

        if include_admin:
            base.update({
                "successful_payment_count": self.successful_payment_count,
                "failed_payment_count": self.failed_payment_count,
                "total_transferred_amount": self.total_transferred_amount,
                "first_payment_at": self.first_payment_at.isoformat() if self.first_payment_at else None,
                "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
                "revocation_reason": self.revocation_reason,
            })

        return base

    def __repr__(self) -> str:
        return f"<Beneficiary {self.id}: {self.beneficiary_name} ({self.beneficiary_upi_id}) Status:{self.status} Trust:{self.trust_status}>"
