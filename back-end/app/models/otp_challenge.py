"""
OTP Challenge Database Model.

Persists hashed one-time password challenges, expiration timestamps,
and attempt counters for adaptive security flows.
"""

from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


class OTPChallenge(db.Model):
    """Adaptive multi-factor challenge record."""

    __tablename__ = "otp_challenges"
    __table_args__ = (
        db.CheckConstraint("status IN ('ACTIVE', 'VERIFIED', 'EXPIRED', 'EXHAUSTED')", name="check_otp_status"),
        db.Index("ix_otp_challenges_transaction_id", "transaction_id"),
        db.Index("ix_otp_challenges_user_id", "user_id"),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey("transactions.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    otp_hash = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(50), default="TRANSACTION_VERIFICATION", nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)
    max_attempts = db.Column(db.Integer, default=3, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="ACTIVE", nullable=False)  # 'ACTIVE', 'VERIFIED', 'EXPIRED', 'EXHAUSTED'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    transaction = db.relationship("Transaction", backref=db.backref("otp_challenges", lazy="dynamic", cascade="all, delete-orphan"))
    user = db.relationship("User", backref=db.backref("otp_challenges", lazy="dynamic", cascade="all, delete-orphan"))

    def set_otp(self, plaintext_otp: str) -> None:
        """Hash plaintext OTP before storage."""
        self.otp_hash = generate_password_hash(plaintext_otp)

    def check_otp(self, candidate_otp: str) -> bool:
        """Verify candidate OTP against stored hash."""
        return check_password_hash(self.otp_hash, candidate_otp)

    @property
    def is_expired(self) -> bool:
        """Check if challenge has passed expiration time."""
        now = datetime.now(timezone.utc)
        if self.expires_at.tzinfo is None:
            return now.replace(tzinfo=None) > self.expires_at
        return now > self.expires_at

    def to_dict(self) -> dict:
        """Serialize challenge metadata (never exposing otp_hash)."""
        return {
            "id": self.id,
            "transaction_id": self.transaction_id,
            "user_id": self.user_id,
            "purpose": self.purpose,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "attempt_count": self.attempt_count,
            "max_attempts": self.max_attempts,
            "status": self.status,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<OTPChallenge {self.id}: Tx {self.transaction_id} [{self.status}]>"
