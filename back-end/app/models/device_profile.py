"""
DeviceProfile Database Model.

Represents client device identities, telemetry attributes, trust states,
and authentication histories for device intelligence and zero-trust verification.
"""

from datetime import datetime, timezone
from app.extensions import db


class DeviceProfile(db.Model):
    """Device profile record storing privacy-conscious client telemetry and trust status."""

    __tablename__ = "device_profiles"
    __table_args__ = (
        db.CheckConstraint(
            "trust_status IN ('TRUSTED', 'SUSPICIOUS', 'UNKNOWN', 'BLOCKED')",
            name="check_device_trust_status",
        ),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_hash = db.Column(db.String(64), nullable=False, index=True)  # SHA-256 pseudonymized hash
    device_type = db.Column(db.String(50), default="Desktop", nullable=False)
    browser = db.Column(db.String(50), default="Unknown", nullable=False)
    operating_system = db.Column(db.String(50), default="Unknown", nullable=False)
    trust_status = db.Column(db.String(20), default="UNKNOWN", nullable=False)  # 'TRUSTED', 'SUSPICIOUS', 'UNKNOWN', 'BLOCKED'
    last_ip_hash = db.Column(db.String(64), nullable=True)  # Privacy-preserving SHA-256 IP representation
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    successful_login_count = db.Column(db.Integer, default=0, nullable=False)
    first_seen_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user = db.relationship("User", backref=db.backref("devices", lazy="dynamic", cascade="all, delete-orphan"))

    def to_dict(self, include_admin: bool = False) -> dict:
        """
        Convert device profile to a privacy-conscious dictionary.

        Never exposes raw device_hash or internal secrets to customer endpoints.
        """
        data = {
            "id": self.id,
            "device_type": self.device_type,
            "browser": self.browser,
            "operating_system": self.operating_system,
            "trust_status": self.trust_status,
            "is_active": self.is_active,
            "first_seen_at": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
        }

        if include_admin:
            data.update({
                "user_id": self.user_id,
                "failed_login_count": self.failed_login_count,
                "successful_login_count": self.successful_login_count,
                "last_ip_hash": self.last_ip_hash,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            })

        return data

    def __repr__(self) -> str:
        return f"<DeviceProfile {self.id}: User {self.user_id} [{self.browser} on {self.operating_system}] - {self.trust_status}>"
