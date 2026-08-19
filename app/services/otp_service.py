"""
Adaptive One-Time Password (OTP) Challenge Service.

Handles cryptographically secure OTP generation, hashing, simulated delivery,
expiration tracking, and attempt rate-limiting.
"""

import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, Dict, Any
from flask import current_app
from app.extensions import db
from app.models.transaction import Transaction
from app.models.user import User
from app.models.otp_challenge import OTPChallenge

logger = logging.getLogger(__name__)


class OTPService:
    """Service managing multi-factor OTP challenges and verification lifecycle."""

    DEFAULT_EXPIRY_SECONDS = 180  # 3 minutes
    MAX_ATTEMPTS = 3

    @staticmethod
    def generate_otp_code(digits: int = 6) -> str:
        """Generate a cryptographically secure numeric OTP."""
        lower_bound = 10 ** (digits - 1)
        upper_bound = (10 ** digits) - 1
        return str(secrets.randbelow(upper_bound - lower_bound + 1) + lower_bound)

    @classmethod
    def create_challenge(
        cls,
        transaction_id: int,
        user_id: int,
        expiry_seconds: Optional[int] = None,
    ) -> Tuple[Optional[OTPChallenge], Optional[str], Optional[str]]:
        """
        Generate and persist a secure OTP challenge for a transaction.

        Returns:
            (challenge, plaintext_otp_debug, error_message)
        """
        tx = db.session.get(Transaction, transaction_id)
        if not tx:
            return None, None, "Transaction not found"

        if tx.user_id != user_id:
            return None, None, "Forbidden: Transaction does not belong to authenticated user"

        # Check if transaction requires OTP or is already approved
        if tx.status in ["APPROVED", "REJECTED"]:
            return None, None, f"Transaction is already in terminal state '{tx.status}'"

        if not tx.requires_otp and tx.risk_level == "LOW":
            return None, None, "Transaction was auto-approved and does not require OTP verification"

        # Invalidate any previously active unverified challenges for this transaction
        active_challenges = OTPChallenge.query.filter_by(
            transaction_id=transaction_id,
            user_id=user_id,
            status="ACTIVE",
        ).all()
        for c in active_challenges:
            c.status = "EXPIRED"

        # Generate secure OTP
        plaintext_otp = cls.generate_otp_code(6)
        expiry_duration = expiry_seconds or current_app.config.get("OTP_EXPIRY_SECONDS", cls.DEFAULT_EXPIRY_SECONDS)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_duration)

        challenge = OTPChallenge(
            transaction_id=transaction_id,
            user_id=user_id,
            purpose="TRANSACTION_VERIFICATION",
            expires_at=expires_at,
            max_attempts=current_app.config.get("OTP_MAX_ATTEMPTS", cls.MAX_ATTEMPTS),
            status="ACTIVE",
        )
        challenge.set_otp(plaintext_otp)

        db.session.add(challenge)
        db.session.commit()

        # Simulated Delivery Log (Safe for local dev/demo)
        user = db.session.get(User, user_id)
        user_email = user.email if user else "user"
        logger.info(
            "[SIMULATED OTP DELIVERY] Sent OTP code '%s' for Transaction #%d to user '%s' (Expires in %ds)",
            plaintext_otp, transaction_id, user_email, expiry_duration
        )

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="OTP_REQUESTED",
            actor=user_email,
            action="POST /api/otp/request",
            result="SUCCESS",
            user_id=user_id,
            target_resource=f"Transaction:{transaction_id}",
            severity="INFO",
            details={"transaction_id": transaction_id, "expiry_seconds": expiry_duration},
        )

        return challenge, plaintext_otp, None

    @classmethod
    def verify_challenge(
        cls,
        transaction_id: int,
        user_id: int,
        candidate_otp: str,
    ) -> Tuple[bool, str, int, Optional[Dict[str, Any]]]:
        """
        Verify a candidate OTP code against the active challenge.

        Returns:
            (success, message, http_status_code, updated_transaction_data)
        """
        tx = db.session.get(Transaction, transaction_id)
        if not tx:
            return False, "Transaction not found", 404, None

        if tx.user_id != user_id:
            return False, "Forbidden: Access denied to this transaction challenge", 403, None

        challenge = (
            OTPChallenge.query.filter_by(transaction_id=transaction_id, user_id=user_id)
            .order_by(OTPChallenge.created_at.desc())
            .first()
        )

        if not challenge:
            return False, "No OTP challenge found for this transaction", 404, None

        if challenge.status != "ACTIVE":
            return False, f"Challenge is no longer active (Current status: {challenge.status})", 400, None

        # Check expiration
        if challenge.is_expired:
            challenge.status = "EXPIRED"
            db.session.commit()
            return False, "OTP has expired. Please request a new code.", 410, None

        # Increment attempt counter
        challenge.attempt_count += 1

        if challenge.attempt_count > challenge.max_attempts:
            challenge.status = "EXHAUSTED"
            tx.status = "REJECTED"
            db.session.commit()
            return False, "Maximum verification attempts exceeded. Transaction rejected.", 429, None

        # Check hash match
        if not challenge.check_otp(str(candidate_otp).strip()):
            remaining = challenge.max_attempts - challenge.attempt_count
            user = db.session.get(User, user_id)
            user_email = user.email if user else f"User:{user_id}"

            from app.services.audit_service import AuditService
            AuditService.log_event(
                event_type="OTP_FAILED",
                actor=user_email,
                action="POST /api/otp/verify",
                result="FAILURE",
                user_id=user_id,
                target_resource=f"Transaction:{transaction_id}",
                severity="WARN",
                details={"transaction_id": transaction_id, "attempt_count": challenge.attempt_count},
            )

            if remaining <= 0:
                challenge.status = "EXHAUSTED"
                tx.status = "REJECTED"
                db.session.commit()
                return False, "Invalid OTP code. Challenge exhausted and transaction rejected.", 429, None

            db.session.commit()
            return False, f"Invalid OTP code. {remaining} attempt(s) remaining.", 400, None

        # Successful verification
        challenge.status = "VERIFIED"
        challenge.verified_at = datetime.now(timezone.utc)

        user = db.session.get(User, tx.user_id)
        user_email = user.email if user else f"User:{user_id}"

        # Transition transaction state based on original risk tier
        if tx.risk_level == "CRITICAL":
            tx.status = "VERIFIED_PENDING_REVIEW"
            status_message = "OTP verified successfully. Transaction queued for administrative security review."
        else:
            # Re-verify and atomically deduct available balance
            if user and user.role == "USER" and tx.type in ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"]:
                current_bal = float(user.account_balance) if user.account_balance is not None else 0.0
                if current_bal < tx.amount:
                    tx.status = "REJECTED"
                    db.session.commit()
                    return False, f"Transaction rejected: Insufficient funds (Available: ₹{current_bal:,.2f}, required: ₹{tx.amount:,.2f})", 400, tx.to_dict()

                tx.balance_before = current_bal
                user.account_balance = round(user.account_balance - tx.amount, 2)
                tx.balance_after = float(user.account_balance)

            if tx.beneficiary_id:
                from app.models.beneficiary import Beneficiary
                b = db.session.get(Beneficiary, tx.beneficiary_id)
                if b:
                    b.last_used_at = datetime.now(timezone.utc)

            tx.status = "APPROVED"
            status_message = "OTP verified successfully. Transaction approved."

        db.session.commit()

        from app.services.audit_service import AuditService
        AuditService.log_event(
            event_type="OTP_VERIFIED",
            actor=user_email,
            action="POST /api/otp/verify",
            result="SUCCESS",
            user_id=user_id,
            target_resource=f"Transaction:{transaction_id}",
            severity="INFO",
            details={"transaction_id": transaction_id, "status": tx.status},
        )

        return True, status_message, 200, tx.to_dict()
