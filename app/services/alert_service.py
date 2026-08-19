"""
Security Alert Service.

Manages creation, retrieval, and administrative resolution of high-risk security alerts.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from app.extensions import db
from app.models.alert import Alert
from app.models.transaction import Transaction
from app.models.user import User


class AlertService:
    """Service layer managing security incident alerts and admin workflows."""

    @staticmethod
    def create_security_alert(
        transaction_id: int,
        user_id: int,
        severity: str = "HIGH",
        message: str = "",
        alert_type: str = "FRAUD_ALERT",
    ) -> Alert:
        """Create a new security alert for a high-risk transaction."""
        existing = Alert.query.filter_by(transaction_id=transaction_id).first()
        if existing:
            return existing

        alert = Alert(
            transaction_id=transaction_id,
            user_id=user_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            status="OPEN",
        )
        db.session.add(alert)
        db.session.commit()
        return alert

    @staticmethod
    def get_all_alerts(
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve alerts with linked transaction and user details for admin review."""
        query = Alert.query

        if status:
            query = query.filter_by(status=status.upper())
        if severity:
            query = query.filter_by(severity=severity.upper())

        alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()

        results = []
        for a in alerts:
            tx = a.transaction
            user = a.user
            results.append({
                "id": a.id,
                "transaction_id": a.transaction_id,
                "user_id": a.user_id,
                "user_name": user.name if user else "Unknown",
                "user_email": user.email if user else "Unknown",
                "transaction_type": tx.type if tx else "Unknown",
                "transaction_amount": tx.amount if tx else 0.0,
                "risk_score": tx.risk_score if tx else 0,
                "risk_level": tx.risk_level if tx else "UNKNOWN",
                "alert_type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "status": a.status,
                "notes": a.notes,
                "resolved_by": a.resolved_by,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            })
        return results

    @staticmethod
    def resolve_alert(alert_id: int, admin_id: int, note: Optional[str] = None) -> Optional[Alert]:
        """Mark an alert as resolved by administrator and record notes."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        alert.status = "RESOLVED"
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolved_by = admin_identifier
        if note:
            alert.notes = note
        db.session.commit()
        return alert

    @staticmethod
    def dismiss_alert(alert_id: int, admin_id: int, note: Optional[str] = None) -> Optional[Alert]:
        """Dismiss an alert without escalating."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        alert.status = "DISMISSED"
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolved_by = admin_identifier
        if note:
            alert.notes = note
        db.session.commit()
        return alert
