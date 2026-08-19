"""
Security Alert Service.

Manages creation, retrieval, triage, and administrative lifecycle state machine
of security incident alerts with duplicate correlation.
"""

import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from app.extensions import db
from app.models.alert import Alert
from app.models.transaction import Transaction
from app.models.user import User


class AlertService:
    """Service layer managing security incident alerts and SOC triage workflows."""

    VALID_LIFECYCLE_STATUSES = {
        "OPEN",
        "ACKNOWLEDGED",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE",
        "ESCALATED",
        "DISMISSED",
    }

    @staticmethod
    def compute_alert_dedup_signature(user_id: int, alert_type: str, severity: str) -> str:
        """Generate a deterministic signature for correlating duplicate alert triggers."""
        raw = f"{user_id}:{alert_type}:{severity}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def create_security_alert(
        cls,
        transaction_id: int,
        user_id: int,
        severity: str = "HIGH",
        message: str = "",
        alert_type: str = "FRAUD_ALERT",
    ) -> Alert:
        """Create a new security alert or correlate with recent existing alert."""
        existing = Alert.query.filter_by(transaction_id=transaction_id).first()
        if existing:
            return existing

        signature = cls.compute_alert_dedup_signature(user_id, alert_type, severity)
        now = datetime.now(timezone.utc)

        # Check for active deduplication window (last 15 minutes for same user and alert type)
        recent_open = (
            Alert.query.filter(
                Alert.user_id == user_id,
                Alert.dedup_signature == signature,
                Alert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]),
                Alert.created_at >= now - timedelta(minutes=15),
            )
            .order_by(Alert.created_at.desc())
            .first()
        )

        if recent_open:
            recent_open.correlation_count += 1
            db.session.commit()

        alert = Alert(
            transaction_id=transaction_id,
            user_id=user_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            status="OPEN",
            dedup_signature=signature,
            correlation_count=1,
            created_at=now,
        )
        db.session.add(alert)
        db.session.commit()
        return alert

    @staticmethod
    def get_all_alerts(
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to_id: Optional[int] = None,
        case_id: Optional[int] = None,
        customer_id: Optional[int] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve alerts with linked transaction and user details for admin review."""
        query = Alert.query

        if status:
            query = query.filter_by(status=status.upper())
        if severity:
            query = query.filter_by(severity=severity.upper())
        if assigned_to_id:
            query = query.filter_by(assigned_to_id=assigned_to_id)
        if case_id:
            query = query.filter_by(case_id=case_id)
        if customer_id:
            query = query.filter_by(user_id=customer_id)

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
                "case_id": a.case_id,
                "transaction_type": tx.type if tx else "Unknown",
                "transaction_amount": tx.amount if tx else 0.0,
                "risk_score": tx.risk_score if tx else 0,
                "risk_level": tx.risk_level if tx else "UNKNOWN",
                "alert_type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "status": a.status,
                "assigned_to_id": a.assigned_to_id,
                "assigned_to_email": a.assignee.email if a.assignee else None,
                "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "acknowledged_by": a.acknowledged_by,
                "notes": a.notes,
                "resolved_by": a.resolved_by,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "dedup_signature": a.dedup_signature,
                "correlation_count": a.correlation_count,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })
        return results

    @staticmethod
    def acknowledge_alert(alert_id: int, admin_id: int) -> Optional[Alert]:
        """Analyst acknowledges an open alert for triage."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        alert.status = "ACKNOWLEDGED"
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = admin_identifier
        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="ALERT_ACKNOWLEDGED",
            actor=admin_identifier,
            action=f"POST /api/admin/alerts/{alert_id}/acknowledge",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"Alert:{alert_id}",
            severity="INFO",
            details={"alert_id": alert_id, "transaction_id": alert.transaction_id},
        )

        return alert

    @staticmethod
    def assign_alert(alert_id: int, admin_id: int, assignee_id: int) -> Optional[Alert]:
        """Assign an alert to a specific admin analyst."""
        alert = db.session.get(Alert, alert_id)
        assignee = db.session.get(User, assignee_id)
        if not alert or not assignee:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        alert.assigned_to_id = assignee_id
        alert.assigned_at = datetime.now(timezone.utc)
        if alert.status == "OPEN":
            alert.status = "ACKNOWLEDGED"
            alert.acknowledged_at = datetime.now(timezone.utc)
            alert.acknowledged_by = admin_identifier

        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="ALERT_ASSIGNED",
            actor=admin_identifier,
            action=f"POST /api/admin/alerts/{alert_id}/assign",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"Alert:{alert_id}",
            severity="INFO",
            details={"alert_id": alert_id, "assignee_id": assignee_id, "assignee_email": assignee.email},
        )

        return alert

    @staticmethod
    def investigate_alert(alert_id: int, admin_id: int, note: Optional[str] = None) -> Optional[Alert]:
        """Move alert into active investigation state."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        alert.status = "INVESTIGATING"
        if note:
            existing = alert.notes + "\n" if alert.notes else ""
            alert.notes = f"{existing}[{datetime.now(timezone.utc).isoformat()}] {admin_identifier}: {note}"

        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="ALERT_INVESTIGATED",
            actor=admin_identifier,
            action=f"POST /api/admin/alerts/{alert_id}/investigate",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"Alert:{alert_id}",
            severity="INFO",
            details={"alert_id": alert_id, "note": note},
        )

        return alert

    @staticmethod
    def escalate_alert(alert_id: int, admin_id: int, case_id: Optional[int] = None, note: Optional[str] = None) -> Optional[Alert]:
        """Escalate an alert, optionally linking to a formal SOC case."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        alert.status = "ESCALATED"
        if case_id:
            alert.case_id = case_id
        if note:
            existing = alert.notes + "\n" if alert.notes else ""
            alert.notes = f"{existing}[ESCALATED {datetime.now(timezone.utc).isoformat()}] {admin_identifier}: {note}"

        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="ALERT_ESCALATED",
            actor=admin_identifier,
            action=f"POST /api/admin/alerts/{alert_id}/escalate",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"Alert:{alert_id}",
            severity="WARN",
            details={"alert_id": alert_id, "case_id": case_id, "note": note},
        )

        return alert

    @staticmethod
    def resolve_alert(
        alert_id: int,
        admin_id: int,
        resolution_type: str = "RESOLVED",
        note: Optional[str] = None,
    ) -> Optional[Alert]:
        """Mark an alert as resolved or false positive and record resolution notes."""
        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None

        admin_user = db.session.get(User, admin_id)
        admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

        status_val = "FALSE_POSITIVE" if resolution_type.upper() == "FALSE_POSITIVE" else "RESOLVED"
        alert.status = status_val
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolved_by = admin_identifier
        if note:
            existing = alert.notes + "\n" if alert.notes else ""
            alert.notes = f"{existing}[{status_val} {datetime.now(timezone.utc).isoformat()}] {admin_identifier}: {note}"

        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type=f"ALERT_{status_val}",
            actor=admin_identifier,
            action=f"POST /api/admin/alerts/{alert_id}/resolve",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"Alert:{alert_id}",
            severity="INFO",
            details={"alert_id": alert_id, "resolution_type": status_val, "note": note},
        )

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
            existing = alert.notes + "\n" if alert.notes else ""
            alert.notes = f"{existing}[DISMISSED {datetime.now(timezone.utc).isoformat()}] {admin_identifier}: {note}"

        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="ALERT_DISMISSED",
            actor=admin_identifier,
            action=f"POST /api/admin/alerts/{alert_id}/dismiss",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"Alert:{alert_id}",
            severity="INFO",
            details={"alert_id": alert_id, "transaction_id": alert.transaction_id, "note": note},
        )

        return alert

