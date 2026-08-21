"""
CaseNote Database Model.

Represents chronological investigator notes, evidence attachments,
and status change audit records in a SOC investigation.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from app.extensions import db


class CaseNote(db.Model):
    """Chronological investigation note or timeline step on a SOC case."""

    __tablename__ = "case_notes"
    __table_args__ = (
        db.CheckConstraint(
            "note_type IN ('ANALYST_NOTE', 'INVESTIGATION_STEP', 'EVIDENCE_ATTACHED', 'STATUS_CHANGE', 'ESCALATION_NOTE')",
            name="check_case_note_type",
        ),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.Integer, db.ForeignKey("soc_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    author_email = db.Column(db.String(120), nullable=True)

    note_type = db.Column(db.String(32), default="ANALYST_NOTE", nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    case = db.relationship("SOCCase", back_populates="notes")
    author = db.relationship("User", foreign_keys=[author_id])

    def to_dict(self) -> Dict[str, Any]:
        """Convert note instance to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "case_id": self.case_id,
            "author_id": self.author_id,
            "author_email": self.author_email or (self.author.email if self.author else "System"),
            "note_type": self.note_type,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<CaseNote {self.id}: Case {self.case_id} [{self.note_type}] - {self.author_email}>"
