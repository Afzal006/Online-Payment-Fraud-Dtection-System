"""
AuditLog Database Model.

Represents immutable structured audit trail records for security, compliance,
and forensic investigation (aligning with PCI-DSS v4.0 and RBI Digital Payment guidelines).
"""

from datetime import datetime, timezone
import json
from app.extensions import db


class AuditLog(db.Model):
    """Immutable audit trail record for tracking security and transactional events."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    request_id = db.Column(db.String(36), nullable=False, index=True)  # UUIDv4 correlation ID
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_type = db.Column(db.String(60), nullable=False, index=True)
    actor = db.Column(db.String(120), nullable=False, default="SYSTEM")
    action = db.Column(db.String(120), nullable=False)
    target_resource = db.Column(db.String(120), nullable=True)
    result = db.Column(db.String(30), nullable=False, default="SUCCESS")  # 'SUCCESS', 'DENIED', 'FAILURE', 'FLAGGED'
    severity = db.Column(db.String(20), nullable=False, default="INFO")  # 'INFO', 'WARN', 'CRITICAL'
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details_json = db.Column(db.Text, nullable=True)  # JSON-serialized sanitized metadata
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    # Relationships
    user = db.relationship("User", backref=db.backref("audit_logs", lazy="dynamic"))

    @property
    def details(self) -> dict:
        """Parse details_json to dictionary safely."""
        if not self.details_json:
            return {}
        try:
            return json.loads(self.details_json)
        except Exception:
            return {"raw": self.details_json}

    @details.setter
    def details(self, value: dict):
        """Serialize dictionary to details_json safely."""
        if value is None:
            self.details_json = None
        elif isinstance(value, str):
            self.details_json = value
        else:
            self.details_json = json.dumps(value)

    def to_dict(self) -> dict:
        """Convert audit log instance to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "actor": self.actor,
            "action": self.action,
            "target_resource": self.target_resource,
            "result": self.result,
            "severity": self.severity,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AuditLog {self.id}: [{self.severity}] {self.event_type} by {self.actor} -> {self.result}>"
