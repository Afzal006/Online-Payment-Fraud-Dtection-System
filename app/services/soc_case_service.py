"""
SOC Case Management Service.

Coordinates security incident investigations, forensic evidence compilation,
analyst tasking, investigation timelines, and multi-entity correlation.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from app.extensions import db
from app.models.soc_case import SOCCase
from app.models.case_note import CaseNote
from app.models.alert import Alert
from app.models.user import User
from app.models.transaction import Transaction
from app.models.device_profile import DeviceProfile
from app.models.geo_location_record import GeoLocationRecord
from app.models.beneficiary import Beneficiary
from app.services.audit_service import AuditService


class SOCCaseService:
    """Service layer managing SOC cases, evidence snapshots, and analyst timelines."""

    VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    VALID_STATUSES = {
        "NEW",
        "TRIAGED",
        "IN_PROGRESS",
        "ESCALATED_LEGAL",
        "RESOLVED_CONFIRMED_FRAUD",
        "RESOLVED_FALSE_POSITIVE",
        "CLOSED",
    }

    @staticmethod
    def generate_case_number() -> str:
        """Generate a sequential, collision-resistant SOC case reference number."""
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y%m%d")
        count_today = SOCCase.query.filter(SOCCase.case_number.like(f"CASE-{date_str}-%")).count()
        return f"CASE-{date_str}-{count_today + 1:04d}"

    @classmethod
    def compile_forensic_evidence(
        cls,
        customer_id: int,
        transaction_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Compile a comprehensive forensic evidence graph for customer and incident."""
        customer = db.session.get(User, customer_id)
        if not customer:
            return {}

        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Customer Identity & Baseline
        customer_data = {
            "user_id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "role": customer.role,
            "created_at": customer.created_at.isoformat() if customer.created_at else None,
        }

        # 2. Trigger Transaction & SHAP / ML Breakdown
        tx_data = None
        if transaction_id:
            tx = db.session.get(Transaction, transaction_id)
            if tx and tx.user_id == customer_id:
                expl = {}
                if tx.explanation_json:
                    try:
                        expl = json.loads(tx.explanation_json)
                    except Exception:
                        expl = {}

                tx_data = {
                    "transaction_id": tx.id,
                    "amount": tx.amount,
                    "type": tx.type,
                    "name_orig": tx.name_orig,
                    "name_dest": tx.name_dest,
                    "oldbalance_org": tx.oldbalance_org,
                    "newbalance_orig": tx.newbalance_orig,
                    "risk_score": tx.risk_score,
                    "risk_level": tx.risk_level,
                    "ml_fraud_prob": tx.fraud_probability,
                    "rule_triggers": expl.get("rule_triggers", []),
                    "top_shap_factors": expl.get("top_shap_factors", expl.get("shap_positive_factors", [])),
                    "mitigating_shap_factors": expl.get("mitigating_shap_factors", expl.get("shap_negative_factors", [])),
                    "created_at": tx.created_at.isoformat() if tx.created_at else None,
                }

        # 3. Known Device Profiles
        devices = (
            DeviceProfile.query.filter_by(user_id=customer_id)
            .order_by(DeviceProfile.last_seen_at.desc())
            .limit(5)
            .all()
        )
        device_data = [d.to_dict() for d in devices]

        # 4. Recent Geographic Locations & Travel Anomalies
        locations = (
            GeoLocationRecord.query.filter_by(user_id=customer_id)
            .order_by(GeoLocationRecord.created_at.desc())
            .limit(5)
            .all()
        )
        geo_data = [l.to_dict() for l in locations]

        # 5. Beneficiaries & Cooling State
        beneficiaries = (
            Beneficiary.query.filter_by(user_id=customer_id)
            .order_by(Beneficiary.created_at.desc())
            .limit(10)
            .all()
        )
        beneficiary_data = [b.to_dict() for b in beneficiaries]

        return {
            "captured_at": now_iso,
            "customer_identity": customer_data,
            "primary_trigger": tx_data,
            "device_telemetry": device_data,
            "geo_telemetry": geo_data,
            "beneficiary_telemetry": beneficiary_data,
        }

    @classmethod
    def create_case(
        cls,
        customer_id: int,
        title: str,
        priority: str = "HIGH",
        lead_analyst_id: Optional[int] = None,
        description: Optional[str] = None,
        alert_ids: Optional[List[int]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        actor_admin_id: Optional[int] = None,
    ) -> Tuple[Optional[SOCCase], Optional[str]]:
        """Create a new formal SOC investigation case."""
        customer = db.session.get(User, customer_id)
        if not customer:
            return None, "Customer not found"

        priority_norm = priority.upper() if priority else "HIGH"
        if priority_norm not in cls.VALID_PRIORITIES:
            return None, f"Invalid priority. Must be one of {list(cls.VALID_PRIORITIES)}"

        lead_analyst = None
        if lead_analyst_id:
            lead_analyst = db.session.get(User, lead_analyst_id)
            if not lead_analyst:
                return None, "Lead analyst not found"

        # Evidence compilation
        primary_tx_id = None
        if alert_ids:
            first_alert = db.session.get(Alert, alert_ids[0])
            if first_alert:
                primary_tx_id = first_alert.transaction_id

        if not evidence:
            evidence = cls.compile_forensic_evidence(customer_id, primary_tx_id)

        case_num = cls.generate_case_number()
        initial_status = "TRIAGED" if lead_analyst_id else "NEW"

        soc_case = SOCCase(
            case_number=case_num,
            title=title.strip(),
            description=description.strip() if description else "",
            customer_id=customer_id,
            lead_analyst_id=lead_analyst_id,
            priority=priority_norm,
            status=initial_status,
            evidence_snapshot_json=json.dumps(evidence),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.session.add(soc_case)
        db.session.flush()  # Generate case.id

        # Attach alerts
        if alert_ids:
            for aid in alert_ids:
                alert_obj = db.session.get(Alert, aid)
                if alert_obj:
                    alert_obj.case_id = soc_case.id
                    if alert_obj.status in ("OPEN", "ACKNOWLEDGED"):
                        alert_obj.status = "ESCALATED"

        # Add initial timeline note
        actor_user = db.session.get(User, actor_admin_id) if actor_admin_id else lead_analyst
        actor_email = actor_user.email if actor_user else "System"

        init_note = CaseNote(
            case_id=soc_case.id,
            author_id=actor_admin_id or lead_analyst_id,
            author_email=actor_email,
            note_type="STATUS_CHANGE",
            content=f"SOC Case {case_num} opened with priority {priority_norm}. Initial status: {initial_status}.",
            created_at=datetime.now(timezone.utc),
        )
        db.session.add(init_note)
        db.session.commit()

        # Audit logging
        AuditService.log_event(
            event_type="CASE_CREATED",
            actor=actor_email,
            action=f"POST /api/admin/cases",
            result="SUCCESS",
            user_id=actor_admin_id,
            target_resource=f"SOCCase:{soc_case.id}:{case_num}",
            severity="INFO",
            details={
                "case_id": soc_case.id,
                "case_number": case_num,
                "customer_id": customer_id,
                "priority": priority_norm,
                "lead_analyst_id": lead_analyst_id,
                "attached_alerts": alert_ids or [],
            },
        )

        return soc_case, None

    @staticmethod
    def get_case_detail(case_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve full investigation dossier for a SOC case."""
        soc_case = db.session.get(SOCCase, case_id)
        if not soc_case:
            return None
        return soc_case.to_dict(include_evidence=True, include_notes=True)

    @classmethod
    def list_cases(
        cls,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        analyst_id: Optional[int] = None,
        customer_id: Optional[int] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Dict[str, Any]:
        """Query and paginate SOC cases with rich filters."""
        query = SOCCase.query

        if status:
            query = query.filter_by(status=status.upper())
        if priority:
            query = query.filter_by(priority=priority.upper())
        if analyst_id:
            query = query.filter_by(lead_analyst_id=analyst_id)
        if customer_id:
            query = query.filter_by(customer_id=customer_id)

        total = query.count()
        cases = (
            query.order_by(
                db.case(
                    (SOCCase.priority == "CRITICAL", 1),
                    (SOCCase.priority == "HIGH", 2),
                    (SOCCase.priority == "MEDIUM", 3),
                    (SOCCase.priority == "LOW", 4),
                    else_=5,
                ),
                SOCCase.created_at.desc(),
            )
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "cases": [c.to_dict(include_evidence=False, include_notes=False) for c in cases],
        }

    @classmethod
    def update_case_status(
        cls,
        case_id: int,
        new_status: str,
        actor_admin_id: int,
        resolution_summary: Optional[str] = None,
        note: Optional[str] = None,
        block_devices: bool = False,
        revoke_beneficiaries: bool = False,
    ) -> Tuple[Optional[SOCCase], Optional[str]]:
        """Advance case lifecycle with validation, side-effects, and audit trail."""
        soc_case = db.session.get(SOCCase, case_id)
        if not soc_case:
            return None, "Case not found"

        status_norm = new_status.upper()
        if status_norm not in cls.VALID_STATUSES:
            return None, f"Invalid status. Must be one of {list(cls.VALID_STATUSES)}"

        actor_user = db.session.get(User, actor_admin_id)
        actor_email = actor_user.email if actor_user else f"Admin #{actor_admin_id}"
        now = datetime.now(timezone.utc)

        old_status = soc_case.status
        soc_case.status = status_norm
        soc_case.updated_at = now

        if status_norm in ("RESOLVED_CONFIRMED_FRAUD", "RESOLVED_FALSE_POSITIVE"):
            soc_case.resolved_at = now
            if resolution_summary:
                soc_case.resolution_summary = resolution_summary.strip()
            # Also resolve attached alerts
            for alert in soc_case.alerts:
                if alert.status not in ("RESOLVED", "FALSE_POSITIVE", "DISMISSED"):
                    alert.status = "RESOLVED" if status_norm == "RESOLVED_CONFIRMED_FRAUD" else "FALSE_POSITIVE"
                    alert.resolved_at = now
                    alert.resolved_by = actor_email

        if status_norm == "CLOSED":
            soc_case.closed_at = now

        # Security Remediation actions on Confirmed Fraud
        remediation_actions = []
        if status_norm == "RESOLVED_CONFIRMED_FRAUD":
            if block_devices:
                devices = DeviceProfile.query.filter_by(user_id=soc_case.customer_id).all()
                for d in devices:
                    d.trust_status = "BLOCKED"
                remediation_actions.append(f"Blocked {len(devices)} device profile(s)")

            if revoke_beneficiaries:
                from app.services.beneficiary_service import BeneficiaryService
                bens = Beneficiary.query.filter_by(user_id=soc_case.customer_id).all()
                for b in bens:
                    b.trust_status = "REVOKED"
                remediation_actions.append(f"Revoked {len(bens)} beneficiary account(s)")

        # Record Status Change Note
        status_note_content = f"Status changed from {old_status} to {status_norm} by {actor_email}."
        if resolution_summary:
            status_note_content += f"\nResolution Summary: {resolution_summary}"
        if remediation_actions:
            status_note_content += f"\nRemediations applied: {', '.join(remediation_actions)}"

        db.session.add(
            CaseNote(
                case_id=soc_case.id,
                author_id=actor_admin_id,
                author_email=actor_email,
                note_type="STATUS_CHANGE",
                content=status_note_content,
                created_at=now,
            )
        )

        if note:
            db.session.add(
                CaseNote(
                    case_id=soc_case.id,
                    author_id=actor_admin_id,
                    author_email=actor_email,
                    note_type="ANALYST_NOTE",
                    content=note.strip(),
                    created_at=now,
                )
            )

        db.session.commit()

        # Audit logging
        AuditService.log_event(
            event_type="CASE_STATUS_CHANGED",
            actor=actor_email,
            action=f"POST /api/admin/cases/{case_id}/status",
            result="SUCCESS",
            user_id=actor_admin_id,
            target_resource=f"SOCCase:{case_id}:{soc_case.case_number}",
            severity="WARN" if "FRAUD" in status_norm or "ESCALATED" in status_norm else "INFO",
            details={
                "case_id": case_id,
                "old_status": old_status,
                "new_status": status_norm,
                "resolution_summary": resolution_summary,
                "remediations": remediation_actions,
            },
        )

        return soc_case, None

    @classmethod
    def assign_lead_analyst(
        cls,
        case_id: int,
        analyst_id: int,
        actor_admin_id: int,
    ) -> Tuple[Optional[SOCCase], Optional[str]]:
        """Assign or reassign lead analyst on a SOC case."""
        soc_case = db.session.get(SOCCase, case_id)
        if not soc_case:
            return None, "Case not found"

        analyst = db.session.get(User, analyst_id)
        if not analyst or analyst.role.upper() != "ADMIN":
            return None, "Target user is not a valid admin analyst"

        actor_user = db.session.get(User, actor_admin_id)
        actor_email = actor_user.email if actor_user else f"Admin #{actor_admin_id}"
        now = datetime.now(timezone.utc)

        prev_analyst_email = soc_case.lead_analyst.email if soc_case.lead_analyst else "Unassigned"
        soc_case.lead_analyst_id = analyst_id
        soc_case.updated_at = now

        if soc_case.status == "NEW":
            soc_case.status = "TRIAGED"

        db.session.add(
            CaseNote(
                case_id=soc_case.id,
                author_id=actor_admin_id,
                author_email=actor_email,
                note_type="STATUS_CHANGE",
                content=f"Lead analyst reassigned from {prev_analyst_email} to {analyst.email}.",
                created_at=now,
            )
        )
        db.session.commit()

        AuditService.log_event(
            event_type="CASE_ASSIGNED",
            actor=actor_email,
            action=f"POST /api/admin/cases/{case_id}/assign",
            result="SUCCESS",
            user_id=actor_admin_id,
            target_resource=f"SOCCase:{case_id}",
            severity="INFO",
            details={
                "case_id": case_id,
                "assigned_analyst_id": analyst_id,
                "assigned_analyst_email": analyst.email,
            },
        )

        return soc_case, None

    @classmethod
    def add_case_note(
        cls,
        case_id: int,
        author_id: int,
        content: str,
        note_type: str = "ANALYST_NOTE",
    ) -> Tuple[Optional[CaseNote], Optional[str]]:
        """Add a chronological investigation note, step, or evidence note."""
        soc_case = db.session.get(SOCCase, case_id)
        if not soc_case:
            return None, "Case not found"

        if not content or not content.strip():
            return None, "Note content cannot be empty"

        valid_note_types = {
            "ANALYST_NOTE",
            "INVESTIGATION_STEP",
            "EVIDENCE_ATTACHED",
            "STATUS_CHANGE",
            "ESCALATION_NOTE",
        }
        type_norm = note_type.upper() if note_type else "ANALYST_NOTE"
        if type_norm not in valid_note_types:
            return None, f"Invalid note type. Must be one of {list(valid_note_types)}"

        author = db.session.get(User, author_id)
        author_email = author.email if author else f"Admin #{author_id}"
        now = datetime.now(timezone.utc)

        note_obj = CaseNote(
            case_id=case_id,
            author_id=author_id,
            author_email=author_email,
            note_type=type_norm,
            content=content.strip(),
            created_at=now,
        )
        soc_case.updated_at = now
        db.session.add(note_obj)
        db.session.commit()

        AuditService.log_event(
            event_type="CASE_NOTE_ADDED",
            actor=author_email,
            action=f"POST /api/admin/cases/{case_id}/notes",
            result="SUCCESS",
            user_id=author_id,
            target_resource=f"SOCCase:{case_id}:Note",
            severity="INFO",
            details={"case_id": case_id, "note_type": type_norm, "preview": content[:100]},
        )

        return note_obj, None

    @classmethod
    def attach_alert(
        cls,
        case_id: int,
        alert_id: int,
        actor_admin_id: int,
    ) -> Tuple[Optional[Alert], Optional[str]]:
        """Link an existing alert to a SOC investigation case."""
        soc_case = db.session.get(SOCCase, case_id)
        if not soc_case:
            return None, "Case not found"

        alert = db.session.get(Alert, alert_id)
        if not alert:
            return None, "Alert not found"

        actor_user = db.session.get(User, actor_admin_id)
        actor_email = actor_user.email if actor_user else f"Admin #{actor_admin_id}"
        now = datetime.now(timezone.utc)

        alert.case_id = case_id
        if alert.status in ("OPEN", "ACKNOWLEDGED"):
            alert.status = "ESCALATED"
        soc_case.updated_at = now

        db.session.add(
            CaseNote(
                case_id=soc_case.id,
                author_id=actor_admin_id,
                author_email=actor_email,
                note_type="EVIDENCE_ATTACHED",
                content=f"Security Alert #{alert.id} ({alert.alert_type} [{alert.severity}]) attached to case.",
                created_at=now,
            )
        )
        db.session.commit()

        AuditService.log_event(
            event_type="ALERT_ATTACHED_TO_CASE",
            actor=actor_email,
            action=f"POST /api/admin/cases/{case_id}/alerts/attach",
            result="SUCCESS",
            user_id=actor_admin_id,
            target_resource=f"SOCCase:{case_id}:Alert:{alert_id}",
            severity="INFO",
            details={"case_id": case_id, "alert_id": alert_id},
        )

        return alert, None

    @classmethod
    def get_soc_metrics(cls) -> Dict[str, Any]:
        """Aggregate high-level operational metrics for the SOC dashboard."""
        total_cases = SOCCase.query.count()
        new_cases = SOCCase.query.filter_by(status="NEW").count()
        triaged_cases = SOCCase.query.filter_by(status="TRIAGED").count()
        in_progress_cases = SOCCase.query.filter_by(status="IN_PROGRESS").count()
        escalated_cases = SOCCase.query.filter_by(status="ESCALATED_LEGAL").count()
        confirmed_fraud = SOCCase.query.filter_by(status="RESOLVED_CONFIRMED_FRAUD").count()
        false_positive = SOCCase.query.filter_by(status="RESOLVED_FALSE_POSITIVE").count()
        closed_cases = SOCCase.query.filter_by(status="CLOSED").count()

        critical_cases = SOCCase.query.filter_by(priority="CRITICAL").count()
        high_cases = SOCCase.query.filter_by(priority="HIGH").count()
        medium_cases = SOCCase.query.filter_by(priority="MEDIUM").count()
        low_cases = SOCCase.query.filter_by(priority="LOW").count()

        total_alerts = Alert.query.count()
        open_alerts = Alert.query.filter(Alert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"])).count()

        return {
            "cases": {
                "total": total_cases,
                "active": new_cases + triaged_cases + in_progress_cases + escalated_cases,
                "by_status": {
                    "NEW": new_cases,
                    "TRIAGED": triaged_cases,
                    "IN_PROGRESS": in_progress_cases,
                    "ESCALATED_LEGAL": escalated_cases,
                    "RESOLVED_CONFIRMED_FRAUD": confirmed_fraud,
                    "RESOLVED_FALSE_POSITIVE": false_positive,
                    "CLOSED": closed_cases,
                },
                "by_priority": {
                    "CRITICAL": critical_cases,
                    "HIGH": high_cases,
                    "MEDIUM": medium_cases,
                    "LOW": low_cases,
                },
            },
            "alerts": {
                "total": total_alerts,
                "open": open_alerts,
            },
        }
