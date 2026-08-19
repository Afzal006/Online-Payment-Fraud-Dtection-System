"""
Beneficiary Database Model.

Manages customer saved beneficiaries for fast, validated, and low-friction payment transfers.
"""

from datetime import datetime, timezone
from app.extensions import db


class Beneficiary(db.Model):
    """Saved recipient entity with UPI ID, verification state, and audit timestamps."""

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
    status = db.Column(db.String(20), default="ACTIVE", nullable=False)  # 'ACTIVE', 'INACTIVE'

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="beneficiaries")
    transactions = db.relationship("Transaction", back_populates="beneficiary")

    def to_dict(self) -> dict:
        """Convert beneficiary to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "beneficiary_name": self.beneficiary_name,
            "beneficiary_upi_id": self.beneficiary_upi_id,
            "beneficiary_account_reference": self.beneficiary_account_reference,
            "beneficiary_phone": self.beneficiary_phone,
            "nickname": self.nickname,
            "is_verified": self.is_verified,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }

    def __repr__(self) -> str:
        return f"<Beneficiary {self.id}: {self.beneficiary_name} ({self.beneficiary_upi_id}) User:{self.user_id}>"
