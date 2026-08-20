import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional
from flask import current_app
from flask_jwt_extended import create_access_token
from app.extensions import db
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.services.audit_service import AuditService


class AuthService:
    """Service layer managing user accounts, authentication lifecycles, and secure password resets."""

    @staticmethod
    def register_user(
        name: str,
        email: str,
        password: str,
        phone_number: Optional[str] = None,
        role: str = "USER",
    ) -> Tuple[Optional[User], Optional[str]]:
        """
        Register a new user in the database with a hashed password and optional phone OTP challenge.

        Returns:
            (User, None) on success
            (None, error_message) on failure
        """
        import re
        clean_email = email.strip().lower()
        clean_name = name.strip()

        # Check for existing email
        existing_user = User.query.filter_by(email=clean_email).first()
        if existing_user:
            return None, "Email is already registered"

        phone_digits = None
        if phone_number and str(phone_number).strip():
            from app.utils.validators import validate_phone_number
            is_valid_phone, phone_digits, phone_err = validate_phone_number(str(phone_number))
            if not is_valid_phone:
                return None, phone_err

            # Check if phone number is already registered
            existing_phone = User.query.filter(
                (User.phone_number == phone_digits) | (User.phone_number == f"+91{phone_digits}")
            ).first()
            if existing_phone:
                return None, "Mobile number is already registered to another account"

        user_role = role.upper() if role in ["USER", "ADMIN"] else "USER"
        user = User(
            name=clean_name,
            email=clean_email,
            phone_number=phone_digits,
            role=user_role,
            account_balance=100000.0 if user_role == "USER" else 0.0,
            is_phone_verified=False if phone_digits else True,
            is_active=True,
        )
        user.set_password(password)

        db.session.add(user)
        db.session.flush()  # Populates user.id

        # Generate unique Customer Account ID and Primary UPI ID if not set
        user.customer_account_id = f"FS-{100000 + user.id}" if user_role == "USER" else f"FS-ADMIN-{user.id:02d}"
        
        # Primary UPI ID
        email_prefix = clean_email.split("@")[0].replace(".", "_").replace("+", "_")
        user.primary_upi_id = f"{email_prefix}@fraudshield"

        # If mobile number was provided, generate secure OTP and dispatch via SmsProvider
        if phone_digits:
            raw_otp = f"{secrets.randbelow(900000) + 100000}"
            user.set_phone_otp(raw_otp, expiry_seconds=300)
            from app.providers.sms_provider import get_sms_provider
            sms_provider = get_sms_provider()
            sms_ok, sms_err = sms_provider.send_otp(
                phone_number=f"+91{phone_digits}",
                otp_code=raw_otp,
                purpose="REGISTRATION"
            )
            if not sms_ok:
                current_app.logger.warning("SMS OTP dispatch returned: %s", sms_err)

        db.session.commit()

        # Audit Log Event
        AuditService.log_event(
            event_type="USER_REGISTERED",
            actor=user.email,
            action="POST /api/auth/register",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={
                "role": user.role,
                "customer_account_id": user.customer_account_id,
                "phone_number": user.phone_number,
                "is_phone_verified": user.is_phone_verified,
            },
        )

        return user, None

    @staticmethod
    def verify_phone_otp(
        phone_or_email: str,
        otp_code: str,
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Verify incoming 6-digit OTP against user's stored hash and activate phone verification.
        """
        import re
        if not phone_or_email or not otp_code:
            return False, None, "Identifier and OTP code are required."

        clean_id = phone_or_email.strip()
        user = None
        digits_only = re.sub(r"\D", "", clean_id)
        if len(digits_only) == 10:
            user = User.query.filter(
                (User.phone_number == digits_only) | (User.phone_number == f"+91{digits_only}")
            ).first()
        elif len(digits_only) == 12 and digits_only.startswith("91"):
            user = User.query.filter(
                (User.phone_number == digits_only[2:]) | (User.phone_number == f"+{digits_only}")
            ).first()

        if not user:
            user = User.query.filter(
                (User.email == clean_id.lower()) | (User.primary_upi_id == clean_id.lower())
            ).first()

        if not user:
            return False, None, "Account not found for the provided identifier."

        if user.is_phone_verified:
            return True, user, "Mobile number is already verified."

        is_valid, err = user.check_phone_otp(otp_code)
        db.session.commit()

        if not is_valid:
            AuditService.log_event(
                event_type="PHONE_VERIFICATION_FAILED",
                actor=user.email,
                action="POST /api/auth/verify-phone-otp",
                result="FAILURE",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                details={"reason": err, "attempts": user.phone_otp_attempts},
            )
            return False, user, err

        AuditService.log_event(
            event_type="PHONE_VERIFIED",
            actor=user.email,
            action="POST /api/auth/verify-phone-otp",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={
                "phone_number": user.phone_number,
                "verified_at": user.phone_verified_at.isoformat() if user.phone_verified_at else None
            },
        )
        return True, user, None

    @staticmethod
    def resend_phone_otp(
        phone_or_email: str,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Rate-limited resend of phone verification OTP code.
        """
        import re
        if not phone_or_email:
            return False, None, "Identifier is required."

        clean_id = phone_or_email.strip()
        user = None
        digits_only = re.sub(r"\D", "", clean_id)
        if len(digits_only) == 10:
            user = User.query.filter(
                (User.phone_number == digits_only) | (User.phone_number == f"+91{digits_only}")
            ).first()
        elif len(digits_only) == 12 and digits_only.startswith("91"):
            user = User.query.filter(
                (User.phone_number == digits_only[2:]) | (User.phone_number == f"+{digits_only}")
            ).first()

        if not user:
            user = User.query.filter(
                (User.email == clean_id.lower()) | (User.primary_upi_id == clean_id.lower())
            ).first()

        if not user:
            # Anti-enumeration: return true silently if account does not exist
            return True, None, None

        if user.is_phone_verified:
            return False, None, "Mobile number is already verified."

        now = datetime.now(timezone.utc)
        if user.phone_otp_last_sent_at:
            last_sent = user.phone_otp_last_sent_at
            if last_sent.tzinfo is None:
                last_sent = last_sent.replace(tzinfo=timezone.utc)
            if (now - last_sent).total_seconds() < 60:
                remaining_sec = int(60 - (now - last_sent).total_seconds())
                return False, None, f"Please wait {remaining_sec} second(s) before requesting another OTP."

        raw_otp = f"{secrets.randbelow(900000) + 100000}"
        user.set_phone_otp(raw_otp, expiry_seconds=300)

        from app.providers.sms_provider import get_sms_provider
        sms_provider = get_sms_provider()
        target_phone = user.phone_number or "phone"
        if not target_phone.startswith("+"):
            target_phone = f"+91{target_phone}"

        sms_ok, sms_err = sms_provider.send_otp(
            phone_number=target_phone,
            otp_code=raw_otp,
            purpose="REGISTRATION"
        )
        db.session.commit()

        if not sms_ok:
            return False, None, sms_err or "Failed to deliver SMS verification code."

        AuditService.log_event(
            event_type="PHONE_OTP_RESENT",
            actor=user.email,
            action="POST /api/auth/resend-phone-otp",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
        )

        dev_otp = raw_otp if current_app.config.get("TESTING") or current_app.config.get("DEBUG") else None
        return True, dev_otp, None

    @staticmethod
    def authenticate_user(
        email: str,
        password: str,
        user_agent: Optional[str] = None,
        client_ip: Optional[str] = None,
        client_telemetry: Optional[Dict[str, Any]] = None,
        client_device_id: Optional[str] = None,
        location_payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[User], Optional[str]]:
        """
        Authenticate user credentials, evaluate device trust, and issue a JWT access token.

        Returns:
            (access_token, user, None) on success
            (None, None, error_message) on failure
        """
        from flask import has_request_context, request, g
        from app.services.device_trust_service import DeviceTrustService

        clean_email = email.strip().lower()
        user = User.query.filter_by(email=clean_email).first()

        # Resolve device context
        resolved_ua = user_agent
        resolved_ip = client_ip
        resolved_dev_id = client_device_id

        if has_request_context():
            if not resolved_ua:
                resolved_ua = request.headers.get("User-Agent", "")
            if not resolved_ip:
                resolved_ip = getattr(g, "client_ip", request.remote_addr)
            if not resolved_dev_id:
                resolved_dev_id = request.headers.get("X-Device-Fingerprint")

        dev_profile = None
        if user:
            dev_profile, dev_trust_status, is_new_dev = DeviceTrustService.evaluate_or_register_device(
                user_id=user.id,
                user_agent=resolved_ua,
                client_ip=resolved_ip,
                client_telemetry=client_telemetry,
                client_device_id=resolved_dev_id,
            )

            # Blocked device enforcement
            if dev_trust_status == "BLOCKED":
                AuditService.log_event(
                    event_type="LOGIN_FAILED",
                    actor=clean_email,
                    action="POST /api/auth/login",
                    result="DENIED",
                    user_id=user.id,
                    target_resource=f"DeviceProfile:{dev_profile.id}",
                    severity="CRITICAL",
                    details={"reason": "Access denied: Device profile is blocked"},
                )
                return None, None, "Access from this device has been blocked for security reasons"

        if not user or not user.check_password(password):
            if dev_profile:
                DeviceTrustService.record_login_attempt(dev_profile.id, success=False)

            AuditService.log_event(
                event_type="LOGIN_FAILED",
                actor=clean_email,
                action="POST /api/auth/login",
                result="FAILURE",
                severity="WARN",
                details={"reason": "Invalid email or password"},
            )
            return None, None, "Invalid email or password"

        # Check phone verification state
        if not user.is_phone_verified and user.phone_number:
            AuditService.log_event(
                event_type="LOGIN_FAILED",
                actor=clean_email,
                action="POST /api/auth/login",
                result="DENIED",
                user_id=user.id,
                severity="WARN",
                details={"reason": "Mobile number is pending verification"},
            )
            return None, None, "Account mobile number is pending verification. Please verify your phone OTP."

        # Record successful login on device
        if dev_profile:
            DeviceTrustService.record_login_attempt(dev_profile.id, success=True)

        # Record login geographic location
        from app.services.geo_intelligence_service import GeoIntelligenceService
        resolved_loc = location_payload
        if not resolved_loc and has_request_context():
            resolved_loc = {
                "city": request.headers.get("X-Client-City"),
                "country": request.headers.get("X-Client-Country"),
            }

        geo_eval = GeoIntelligenceService.evaluate_event_location(
            user_id=user.id,
            client_ip=resolved_ip,
            location_payload=resolved_loc,
            event_type="LOGIN",
            persist=True,
        )

        # Generate JWT with user role in additional claims
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                "role": user.role,
                "email": user.email,
                "name": user.name,
            },
        )

        AuditService.log_event(
            event_type="LOGIN_SUCCESS",
            actor=user.email,
            action="POST /api/auth/login",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={"role": user.role, "device_id": dev_profile.id if dev_profile else None},
        )

        return access_token, user, None

    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[User]:
        """Fetch user by database ID."""
        return db.session.get(User, user_id)

    @staticmethod
    def request_password_reset(
        email: str,
        remote_ip: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Initiate a password reset flow for the given email.

        Security & Anti-Enumeration:
        - If the email does not exist, returns (True, None) without creating a token.
        - The caller always receives an identical generic success message.
        - Enforces rate limiting per account (max requests per window).
        - Invalidates all previous active reset tokens for this user.
        - Stores only SHA-256 token hash in database.
        - Dispatches reset link via EmailProvider abstraction.
        - NEVER exposes raw reset token in API responses or public logs.

        Returns:
            (success: bool, error_message_or_none: Optional[str])
        """
        clean_email = email.strip().lower()
        user = User.query.filter_by(email=clean_email).first()

        # Anti-enumeration: If user does not exist, log requested and silently return success
        if not user:
            AuditService.log_event(
                event_type="PASSWORD_RESET_REQUESTED",
                actor=clean_email,
                action="POST /api/auth/forgot-password",
                result="NOT_FOUND",
                severity="INFO",
                ip_address=remote_ip,
                details={"reason": "Email not registered"},
            )
            return True, None

        # Configuration parameters
        expiry_minutes = current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRY_MINUTES", 15)
        max_requests = current_app.config.get("PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW", 3)
        window_minutes = current_app.config.get("PASSWORD_RESET_REQUEST_WINDOW_MINUTES", 15)

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=window_minutes)

        # Rate limiting: count requests by this user in the active window
        recent_requests_count = PasswordResetToken.query.filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_at >= window_start,
        ).count()

        if recent_requests_count >= max_requests:
            AuditService.log_event(
                event_type="PASSWORD_RESET_RATE_LIMITED",
                actor=user.email,
                action="POST /api/auth/forgot-password",
                result="RATE_LIMITED",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                ip_address=remote_ip,
                details={"attempts_in_window": recent_requests_count},
            )
            return False, "Too many password reset requests. Please try again later."

        # Invalidate any existing active/unused reset tokens for this user
        active_tokens = PasswordResetToken.query.filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).all()
        for tok in active_tokens:
            tok.used_at = now

        # Generate cryptographically secure token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = now + timedelta(minutes=expiry_minutes)

        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            used_at=None,
            attempt_count=0,
            requested_ip=remote_ip,
            created_at=now,
        )
        db.session.add(reset_record)
        db.session.commit()

        AuditService.log_event(
            event_type="PASSWORD_RESET_REQUESTED",
            actor=user.email,
            action="POST /api/auth/forgot-password",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            ip_address=remote_ip,
        )

        # Dispatch reset email via EmailProvider
        from app.providers.email_provider import get_email_provider
        email_provider = get_email_provider()
        reset_url = f"/reset-password?token={raw_token}"
        email_ok, email_err = email_provider.send_password_reset_email(
            recipient_email=user.email,
            reset_url=reset_url,
            expires_at=expires_at,
        )

        if email_ok:
            AuditService.log_event(
                event_type="PASSWORD_RESET_EMAIL_SENT",
                actor=user.email,
                action="POST /api/auth/forgot-password",
                result="SUCCESS",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="INFO",
            )
        else:
            AuditService.log_event(
                event_type="PASSWORD_RESET_FAILED",
                actor=user.email,
                action="POST /api/auth/forgot-password",
                result="FAILURE",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                details={"reason": email_err or "Email dispatch failed"},
            )

        return True, None

    @staticmethod
    def reset_password_with_token(
        token: str,
        new_password: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify reset token, update user password, mark token as used, and invalidate other tokens.

        Security:
        - Compares SHA-256 hash of incoming raw token against stored token_hash.
        - Enforces attempt count limits (locks token after max failed attempts).
        - Enforces single-use and expiration.
        - Updates password hash using Werkzeug scrypt/pbkdf2.
        - Atomically commits all changes.

        Returns:
            (success: bool, error_message_or_none: Optional[str])
        """
        if not token or not isinstance(token, str) or not token.strip():
            AuditService.log_event(
                event_type="PASSWORD_RESET_FAILED",
                actor="ANONYMOUS",
                action="POST /api/auth/reset-password",
                result="FAILURE",
                severity="WARN",
                details={"reason": "Missing token"},
            )
            return False, "Reset token is required"

        clean_token = token.strip()
        computed_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()

        # Look up token record
        reset_record = PasswordResetToken.query.filter_by(token_hash=computed_hash).first()
        if not reset_record:
            AuditService.log_event(
                event_type="PASSWORD_RESET_FAILED",
                actor="ANONYMOUS",
                action="POST /api/auth/reset-password",
                result="FAILURE",
                severity="WARN",
                details={"reason": "Invalid or unknown token hash"},
            )
            return False, "Invalid or expired reset token"

        max_attempts = current_app.config.get("PASSWORD_RESET_MAX_ATTEMPTS", 5)

        # Check attempt limits
        if reset_record.attempt_count >= max_attempts:
            AuditService.log_event(
                event_type="PASSWORD_RESET_FAILED",
                actor=f"User:{reset_record.user_id}",
                action="POST /api/auth/reset-password",
                result="DENIED",
                user_id=reset_record.user_id,
                severity="CRITICAL",
                details={"reason": "Maximum token attempts exceeded - locked"},
            )
            return False, "Too many failed attempts. This reset token has been locked."

        # Check if already used
        if reset_record.used_at is not None:
            reset_record.record_failed_attempt()
            db.session.commit()
            AuditService.log_event(
                event_type="PASSWORD_RESET_TOKEN_REUSED",
                actor=f"User:{reset_record.user_id}",
                action="POST /api/auth/reset-password",
                result="DENIED",
                user_id=reset_record.user_id,
                severity="WARN",
                details={"reason": "Token already consumed"},
            )
            return False, "This reset token has already been used"

        # Check expiration
        now = datetime.now(timezone.utc)
        expires = reset_record.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        if now >= expires:
            reset_record.record_failed_attempt()
            db.session.commit()
            AuditService.log_event(
                event_type="PASSWORD_RESET_TOKEN_EXPIRED",
                actor=f"User:{reset_record.user_id}",
                action="POST /api/auth/reset-password",
                result="FAILURE",
                user_id=reset_record.user_id,
                severity="WARN",
                details={"reason": "Token expired"},
            )
            return False, "This reset token has expired"

        # Fetch user
        user = db.session.get(User, reset_record.user_id)
        if not user:
            return False, "User account associated with this token no longer exists"

        # Password policy check (min 8 characters)
        if not new_password or len(new_password) < 8:
            reset_record.record_failed_attempt()
            db.session.commit()
            AuditService.log_event(
                event_type="PASSWORD_RESET_FAILED",
                actor=user.email,
                action="POST /api/auth/reset-password",
                result="FAILURE",
                user_id=user.id,
                severity="WARN",
                details={"reason": "Password policy violated (length < 8)"},
            )
            return False, "Password must be at least 8 characters long"

        # Update password and timestamps
        user.set_password(new_password)
        user.password_changed_at = now

        # Mark this token as used
        reset_record.mark_used()

        # Invalidate all other active reset tokens for this user
        other_tokens = PasswordResetToken.query.filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != reset_record.id,
            PasswordResetToken.used_at.is_(None),
        ).all()
        for tok in other_tokens:
            tok.used_at = now

        db.session.commit()

        AuditService.log_event(
            event_type="PASSWORD_RESET_COMPLETED",
            actor=user.email,
            action="POST /api/auth/reset-password",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
        )

        return True, None

