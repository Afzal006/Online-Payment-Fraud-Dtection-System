"""
Beneficiary Management Service.

Encapsulates CRUD operations, tenant isolation, unique UPI validation,
and audit tracking for customer saved beneficiaries.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional
from app.extensions import db
from app.models.beneficiary import Beneficiary
from app.models.user import User
from app.utils.validators import validate_beneficiary_input, validate_upi_id

logger = logging.getLogger(__name__)


class BeneficiaryService:
    """Service layer managing beneficiary records with strict customer ownership enforcement."""

    @staticmethod
    def get_user_beneficiaries(user_id: int) -> List[Dict[str, Any]]:
        """Retrieve all active saved beneficiaries for the authenticated user."""
        beneficiaries = (
            Beneficiary.query.filter_by(user_id=user_id, status="ACTIVE")
            .order_by(Beneficiary.created_at.desc())
            .all()
        )
        return [b.to_dict() for b in beneficiaries]

    @staticmethod
    def get_beneficiary_by_id(beneficiary_id: int, user_id: int) -> Tuple[Optional[Beneficiary], Optional[str], int]:
        """
        Fetch a single beneficiary, validating ownership.

        Returns:
            (beneficiary, error_message, http_status)
        """
        beneficiary = db.session.get(Beneficiary, beneficiary_id)
        if not beneficiary:
            return None, "Beneficiary not found", 404

        if beneficiary.user_id != user_id:
            logger.warning(
                "Unauthorized beneficiary access attempt: user %d tried to access beneficiary %d (owner: %d)",
                user_id, beneficiary_id, beneficiary.user_id
            )
            return None, "Forbidden: Access denied to this beneficiary", 403

        return beneficiary, None, 200

    @staticmethod
    def create_beneficiary(user_id: int, data: Dict[str, Any]) -> Tuple[Optional[Beneficiary], Optional[str], int]:
        """
        Create and persist a new beneficiary for the user.

        Returns:
            (beneficiary, error_message, http_status)
        """
        is_valid, error_msg = validate_beneficiary_input(data)
        if not is_valid:
            return None, error_msg, 400

        clean_name = data["beneficiary_name"].strip()
        clean_upi = data["beneficiary_upi_id"].strip().lower()
        clean_phone = data.get("beneficiary_phone", "").strip() or None
        clean_nickname = data.get("nickname", "").strip() or None
        clean_ref = data.get("beneficiary_account_reference", "").strip() or None

        # Check for duplicate beneficiary for this user
        existing = Beneficiary.query.filter_by(
            user_id=user_id,
            beneficiary_upi_id=clean_upi,
        ).first()

        if existing:
            if existing.status == "ACTIVE":
                return None, f"Beneficiary with UPI ID '{clean_upi}' already exists in your saved list", 409
            else:
                # Reactivate if previously archived
                existing.status = "ACTIVE"
                existing.beneficiary_name = clean_name
                existing.beneficiary_phone = clean_phone
                existing.nickname = clean_nickname
                db.session.commit()
                return existing, None, 200

        now = datetime.now(timezone.utc)
        beneficiary = Beneficiary(
            user_id=user_id,
            beneficiary_name=clean_name,
            beneficiary_upi_id=clean_upi,
            beneficiary_phone=clean_phone,
            beneficiary_account_reference=clean_ref,
            nickname=clean_nickname,
            is_verified=True,
            status="ACTIVE",
            trust_status="COOLING",
            cooling_period_hours=24,
            cooling_expires_at=now + timedelta(hours=24),
            created_at=now,
        )

        try:
            db.session.add(beneficiary)
            db.session.commit()
            logger.info("Created beneficiary #%d ('%s') for user #%d with 24h cooling", beneficiary.id, clean_upi, user_id)

            from app.services.audit_service import AuditService
            user = db.session.get(User, user_id)
            user_email = user.email if user else f"User:{user_id}"

            AuditService.log_event(
                event_type="BENEFICIARY_ADDED",
                actor=user_email,
                action="POST /api/beneficiaries",
                result="SUCCESS",
                user_id=user_id,
                target_resource=f"Beneficiary:{beneficiary.id}",
                severity="INFO",
                details={
                    "beneficiary_id": beneficiary.id,
                    "beneficiary_upi": clean_upi,
                    "cooling_expires_at": beneficiary.cooling_expires_at.isoformat(),
                },
            )

            return beneficiary, None, 201
        except Exception as e:
            db.session.rollback()
            logger.error("Failed to create beneficiary for user #%d: %s", user_id, str(e))
            return None, "Database error creating beneficiary record", 500

    @staticmethod
    def update_beneficiary(
        beneficiary_id: int,
        user_id: int,
        data: Dict[str, Any],
    ) -> Tuple[Optional[Beneficiary], Optional[str], int]:
        """Update beneficiary details (nickname, name, phone)."""
        beneficiary, error_msg, status_code = BeneficiaryService.get_beneficiary_by_id(beneficiary_id, user_id)
        if error_msg:
            return None, error_msg, status_code

        if "beneficiary_name" in data:
            name = str(data["beneficiary_name"]).strip()
            if len(name) < 2 or len(name) > 100:
                return None, "Beneficiary name must be between 2 and 100 characters", 400
            beneficiary.beneficiary_name = name

        if "nickname" in data:
            nick = str(data["nickname"]).strip() if data["nickname"] else None
            if nick and len(nick) > 50:
                return None, "Nickname must not exceed 50 characters", 400
            beneficiary.nickname = nick

        if "beneficiary_phone" in data:
            phone = str(data["beneficiary_phone"]).strip() if data["beneficiary_phone"] else None
            if phone and len(phone) > 20:
                return None, "Phone number must not exceed 20 characters", 400
            beneficiary.beneficiary_phone = phone

        if "beneficiary_upi_id" in data:
            upi = str(data["beneficiary_upi_id"]).strip().lower()
            is_valid_upi, upi_err = validate_upi_id(upi)
            if not is_valid_upi:
                return None, upi_err, 400

            # Check duplicate
            dup = Beneficiary.query.filter(
                Beneficiary.user_id == user_id,
                Beneficiary.beneficiary_upi_id == upi,
                Beneficiary.id != beneficiary_id,
            ).first()
            if dup:
                return None, f"Another beneficiary with UPI ID '{upi}' already exists", 409
            beneficiary.beneficiary_upi_id = upi

        try:
            db.session.commit()
            return beneficiary, None, 200
        except Exception as e:
            db.session.rollback()
            return None, f"Failed to update beneficiary: {str(e)}", 500

    @staticmethod
    def revoke_beneficiary(
        beneficiary_id: int,
        user_id: int,
        reason: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], int]:
        """Revoke/deactivate a saved beneficiary with tenant boundary enforcement."""
        beneficiary, error_msg, status_code = BeneficiaryService.get_beneficiary_by_id(beneficiary_id, user_id)
        if error_msg:
            return False, error_msg, status_code

        now = datetime.now(timezone.utc)
        beneficiary.status = "REVOKED"
        beneficiary.trust_status = "REVOKED"
        beneficiary.revoked_at = now
        beneficiary.revocation_reason = reason or "Customer self-service revocation"

        try:
            db.session.commit()
            logger.info("Revoked beneficiary #%d for user #%d", beneficiary_id, user_id)

            from app.services.audit_service import AuditService
            user = db.session.get(User, user_id)
            user_email = user.email if user else f"User:{user_id}"

            AuditService.log_event(
                event_type="BENEFICIARY_REVOKED",
                actor=user_email,
                action=f"POST /api/beneficiaries/{beneficiary_id}/revoke",
                result="SUCCESS",
                user_id=user_id,
                target_resource=f"Beneficiary:{beneficiary.id}",
                severity="WARN",
                details={
                    "beneficiary_id": beneficiary.id,
                    "beneficiary_upi": beneficiary.beneficiary_upi_id,
                    "reason": beneficiary.revocation_reason,
                },
            )

            return True, None, 200
        except Exception as e:
            db.session.rollback()
            return False, f"Failed to revoke beneficiary: {str(e)}", 500

    @staticmethod
    def delete_beneficiary(beneficiary_id: int, user_id: int) -> Tuple[bool, Optional[str], int]:
        """Delete / revoke a saved beneficiary with ownership verification."""
        return BeneficiaryService.revoke_beneficiary(beneficiary_id, user_id, reason="Customer deleted beneficiary")

    @staticmethod
    def record_payment_outcome(beneficiary_id: int, amount: float, success: bool):
        """Update beneficiary transaction counters and progressive trust state."""
        beneficiary = db.session.get(Beneficiary, beneficiary_id)
        if not beneficiary:
            return

        now = datetime.now(timezone.utc)
        beneficiary.last_used_at = now

        if success:
            if beneficiary.first_payment_at is None:
                beneficiary.first_payment_at = now
            beneficiary.successful_payment_count += 1
            beneficiary.total_transferred_amount += float(amount)
        else:
            beneficiary.failed_payment_count += 1

        # Update progressive trust status
        beneficiary.trust_status = beneficiary.get_effective_trust_status(reference_time=now)
        db.session.commit()

    @staticmethod
    def get_admin_customer_beneficiaries(customer_id: int) -> Dict[str, Any]:
        """Retrieve complete beneficiary telemetry for an admin/SOC customer investigation."""
        beneficiaries = (
            Beneficiary.query.filter_by(user_id=customer_id)
            .order_by(Beneficiary.created_at.desc())
            .all()
        )
        return {
            "customer_id": customer_id,
            "total": len(beneficiaries),
            "beneficiaries": [b.to_dict(include_admin=True) for b in beneficiaries],
        }
