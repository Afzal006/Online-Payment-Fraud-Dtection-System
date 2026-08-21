"""
SOC Case Management Database Model.

Represents formal security incident investigations, linking multiple alerts,
evidence graphs, and analyst timelines.
"""

from datetime import datetime, timezone
import json
from typing import Dict, Any, Optional
from app.extensions import db


class SOCCase(db.Model):
    """Security Operations Center (SOC) incident investigation case entity."""

    __tablename__ = "soc_cases"
    __table_args__ = (
        db.CheckConstraint("priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="check_case_priority"),
        db.CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'IN_PROGRESS', 'ESCALATED_LEGAL', 'RESOLVED_CONFIRMED_FRAUD', 'RESOLVED_FALSE_POSITIVE', 'CLOSED')",
            name="check_case_status",
        ),
        db.Index("ix_soc_cases_status_priority", "status", "priority"),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_number = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    customer_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    lead_analyst_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    priority = db.Column(db.String(20), default="HIGH", nullable=False)
    status = db.Column(db.String(32), default="NEW", nullable=False)

    resolution_summary = db.Column(db.Text, nullable=True)
    evidence_snapshot_json = db.Column(db.Text, nullable=True)  # Immutable JSON forensic snapshot

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    resolved_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    alerts = db.relationship("Alert", back_populates="case", lazy="select")
    notes = db.relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.created_at.asc()")
    customer = db.relationship("User", foreign_keys=[customer_id])
    lead_analyst = db.relationship("User", foreign_keys=[lead_analyst_id])

    def get_evidence(self) -> Dict[str, Any]:
        """Deserialize forensic evidence JSON snapshot."""
        if not self.evidence_snapshot_json:
            return {}
        try:
            return json.loads(self.evidence_snapshot_json)
        except Exception:
            return {}

    def to_dict(self, include_evidence: bool = True, include_notes: bool = False) -> Dict[str, Any]:
        """Convert case model to JSON-serializable dictionary."""
        data = {
            "id": self.id,
            "case_number": self.case_number,
            "title": self.title,
            "description": self.description,
            "customer_id": self.customer_id,
            "customer_name": self.customer.name if self.customer else "Unknown",
            "customer_email": self.customer.email if self.customer else "Unknown",
            "lead_analyst_id": self.lead_analyst_id,
            "lead_analyst_email": self.lead_analyst.email if self.lead_analyst else None,
            "priority": self.priority,
            "status": self.status,
            "alert_count": len(self.alerts) if self.alerts else 0,
            "resolution_summary": self.resolution_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }

        if include_evidence:
            data["evidence"] = self.get_evidence()

        if include_notes:
            data["notes"] = [n.to_dict() for n in self.notes]
            data["alerts"] = [a.to_dict() for a in self.alerts]

        return data

    def __repr__(self) -> str:
        return f"<SOCCase {self.id}: {self.case_number} [{self.priority}] - {self.status}>"
