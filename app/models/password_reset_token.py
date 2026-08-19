"""
Password Reset Token Database Model.

Represents cryptographically secure, single-use, time-limited password reset tokens.
Security:
- Raw tokens are NEVER stored in the database. Only SHA-256 token hashes are stored.
- Tokens expire after a configurable duration (default 10 minutes).
- Tokens are single-use (`used_at` timestamp).
- Failed verification attempts are tracked to prevent brute-force attacks (`attempt_count`).
"""

from datetime import datetime, timezone
from typing import Optional
from app.extensions import db


class PasswordResetToken(db.Model):
    """Password reset token model with single-use, hash verification, and rate limiting."""

    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        db.Index("idx_pwd_reset_user_expires", "user_id", "expires_at"),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = db.Column(db.String(255), nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)
    requested_ip = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    user = db.relationship("User", back_populates="password_reset_tokens")

    def is_valid(self, max_attempts: int = 5) -> bool:
        """Check if token is active, unexpired, unused, and within attempt limits."""
        if self.used_at is not None:
            return False
        if self.attempt_count >= max_attempts:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now < expires

    def mark_used(self) -> None:
        """Mark token as consumed/used."""
        self.used_at = datetime.now(timezone.utc)

    def record_failed_attempt(self) -> None:
        """Increment failed attempt counter for brute-force protection."""
        self.attempt_count += 1

    def to_dict(self) -> dict:
        """Serialize token metadata (guarantees token_hash is never exposed in public responses)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_used": self.used_at is not None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<PasswordResetToken id={self.id} user_id={self.user_id} used={self.used_at is not None}>"
