"""
Audit Service.

Provides centralized management for recording, sanitizing, and querying
immutable audit trail events across all business and security operations.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Optional, Dict, Any
from flask import has_request_context, request, g
from app.extensions import db
from app.models.audit_log import AuditLog
from app.utils.sanitizer import sanitize_data

logger = logging.getLogger("fraudshield.audit")


class AuditService:
    """Service for creating and querying structured audit log entries."""

    @staticmethod
    def log_event(
        event_type: str,
        actor: str = "SYSTEM",
        action: str = "UNKNOWN_ACTION",
        result: str = "SUCCESS",
        user_id: Optional[int] = None,
        target_resource: Optional[str] = None,
        severity: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Optional[AuditLog]:
        """
        Record a sanitized, immutable audit log entry into the database and JSON logger.

        Never raises exceptions to callers to ensure main application flow is never disrupted.
        """
        try:
            # 1. Resolve request correlation ID
            resolved_request_id = request_id
            if not resolved_request_id and has_request_context():
                resolved_request_id = getattr(g, "request_id", "N/A")
            if not resolved_request_id:
                resolved_request_id = "SYSTEM"

            # 2. Resolve client network context
            resolved_ip = ip_address
            resolved_ua = user_agent
            if has_request_context():
                if not resolved_ip:
                    resolved_ip = getattr(g, "client_ip", request.remote_addr)
                if not resolved_ua:
                    resolved_ua = request.headers.get("User-Agent", "")[:255]

            # 3. Sanitize metadata payload
            sanitized_details = sanitize_data(details) if details is not None else {}

            # 4. Create and persist database audit record
            audit_entry = AuditLog(
                request_id=resolved_request_id,
                user_id=user_id,
                event_type=event_type,
                actor=actor,
                action=action,
                target_resource=target_resource,
                result=result,
                severity=severity,
                ip_address=resolved_ip,
                user_agent=resolved_ua,
                created_at=datetime.now(timezone.utc),
            )
            audit_entry.details = sanitized_details

            db.session.add(audit_entry)
            db.session.commit()

            # 5. Emit structured logger message
            log_level = logging.INFO
            if severity == "WARN":
                log_level = logging.WARNING
            elif severity == "CRITICAL":
                log_level = logging.ERROR

            logger.log(
                log_level,
                f"[{severity}] {event_type} | Actor: {actor} | Action: {action} | Result: {result}",
                extra={
                    "event_type": event_type,
                    "actor": actor,
                    "action": action,
                    "result": result,
                    "details": sanitized_details,
                    "request_id": resolved_request_id,
                },
            )

            return audit_entry

        except Exception as e:
            logger.error(f"Failed to record audit log event '{event_type}': {str(e)}")
            try:
                db.session.rollback()
            except Exception:
                pass
            return None

    @staticmethod
    def query_logs(
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[int] = None,
        request_id: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Dict[str, Any]:
        """Query and paginate audit log events with filtering."""
        query = AuditLog.query

        if event_type:
            query = query.filter(AuditLog.event_type == event_type)
        if severity:
            query = query.filter(AuditLog.severity == severity)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if request_id:
            query = query.filter(AuditLog.request_id == request_id)
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (AuditLog.actor.ilike(search_term))
                | (AuditLog.action.ilike(search_term))
                | (AuditLog.target_resource.ilike(search_term))
            )

        total = query.count()
        logs = (
            query.order_by(AuditLog.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 1,
            "logs": [log.to_dict() for log in logs],
        }
