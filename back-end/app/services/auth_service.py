import os
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
        Register a new user account with Email Verification and optional Phone OTP challenge.
        Account begins in PENDING_VERIFICATION state until both factors are verified.

        Returns:
            (User, None) on success
            (None, error_message) on failure
        """
        from app.utils.validators import validate_email_syntax_and_domain, validate_phone_number
        from app.providers.email_provider import get_email_provider
        from app.providers.sms_provider import get_sms_provider

        clean_name = name.strip()
        is_valid_email, clean_email, email_err = validate_email_syntax_and_domain(email)
        if not is_valid_email:
            return None, email_err

        # Check for duplicate email
        existing_user = User.query.filter_by(email=clean_email).first()
        if existing_user:
            if existing_user.account_status == "PENDING_VERIFICATION" and not existing_user.is_email_verified:
                return None, "Email is already registered and pending verification. Please verify your account or sign in."
            return None, "Email is already registered. An account with this email address already exists. Please login or reset your password."

        # Check and normalize mobile number
        phone_digits = None
        if phone_number and str(phone_number).strip():
            is_valid_phone, phone_digits, phone_err = validate_phone_number(str(phone_number))
            if not is_valid_phone:
                return None, phone_err

        user_role = role.upper() if role in ["USER", "ADMIN"] else "USER"
        user = User(
            name=clean_name,
            email=clean_email,
            phone_number=phone_digits,
            role=user_role,
            account_balance=100000.0 if user_role == "USER" else 0.0,
            is_email_verified=False,
            is_phone_verified=False,
            is_active=False,
            account_status="PENDING_VERIFICATION",
        )
        user.set_password(password)

        db.session.add(user)
        db.session.flush()  # Populates user.id

        # Generate unique Customer Account ID and Primary UPI ID
        user.customer_account_id = f"FS-{100000 + user.id}" if user_role == "USER" else f"FS-ADMIN-{user.id:02d}"
        email_prefix = clean_email.split("@")[0].replace(".", "_").replace("+", "_")
        user.primary_upi_id = f"{email_prefix}@fraudshield"

        # 1. Generate & Dispatch Email Verification OTP and Direct Token
        raw_email_otp = f"{secrets.randbelow(900000) + 100000}"
        user.set_email_otp(raw_email_otp, expiry_seconds=300)
        raw_email_token = secrets.token_urlsafe(32)
        user.set_email_verification_token(raw_email_token, expiry_seconds=86400)

        base_url = (
            (current_app.config.get("APP_PUBLIC_URL") if current_app else None)
            or os.environ.get("APP_PUBLIC_URL")
            or "http://127.0.0.1:5000"
        ).rstrip("/")
        verification_url = f"{base_url}/api/auth/verify-email?token={raw_email_token}"

        email_provider = get_email_provider()
        email_ok, email_err = email_provider.send_email_verification_otp(
            recipient_email=user.email,
            otp_code=raw_email_otp,
            recipient_name=user.name,
            verification_url=verification_url,
            expires_in_minutes=5,
        )
        if not email_ok:
            current_app.logger.warning("Email verification OTP dispatch returned: %s", email_err)

        # 2. If mobile number was provided, generate secure OTP and dispatch via SmsProvider
        if phone_digits:
            raw_phone_otp = f"{secrets.randbelow(900000) + 100000}"
            user.set_phone_otp(raw_phone_otp, expiry_seconds=300)
            sms_provider = get_sms_provider()
            sms_ok, sms_err = sms_provider.send_otp(
                phone_number=f"+91{phone_digits}",
                otp_code=raw_phone_otp,
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
                "is_email_verified": user.is_email_verified,
                "is_phone_verified": user.is_phone_verified,
                "account_status": user.account_status,
            },
        )
        AuditService.log_event(
            event_type="EMAIL_VERIFICATION_SENT",
            actor=user.email,
            action="POST /api/auth/register",
            result="SUCCESS" if email_ok else "DISPATCH_FAILED",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO" if email_ok else "WARN",
        )

        return user, None

    @staticmethod
    def verify_email_otp(
        email: str,
        otp_code: str,
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Verify incoming 6-digit OTP against user's stored email verification hash.
        """
        if not email or not otp_code:
            return False, None, "Email address and verification code are required."

        clean_email = email.strip().lower()
        user = User.query.filter_by(email=clean_email).first()
        if not user:
            return False, None, "No account found for this email address."

        if user.is_email_verified:
            return True, user, "Email address is already verified."

        is_valid, err = user.check_email_otp(otp_code)
        db.session.commit()

        if not is_valid:
            AuditService.log_event(
                event_type="EMAIL_VERIFICATION_FAILED",
                actor=clean_email,
                action="POST /api/auth/verify-email-otp",
                result="FAILURE",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                details={"reason": err},
            )
            return False, user, err or "Invalid or expired verification code."

        AuditService.log_event(
            event_type="EMAIL_VERIFICATION_COMPLETED",
            actor=clean_email,
            action="POST /api/auth/verify-email-otp",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={
                "is_email_verified": True,
                "is_fully_verified": user.is_fully_verified,
                "account_status": user.account_status,
            },
        )
        return True, user, None

    @staticmethod
    def resend_email_verification(
        email: str,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Rate-limited resend of email verification code with 60-second cooldown.
        """
        if not email:
            return False, None, "Email address is required."

        clean_email = email.strip().lower()
        user = User.query.filter_by(email=clean_email).first()
        if not user:
            # Anti-enumeration
            return True, None, None

        if user.is_email_verified:
            return False, None, "Email address is already verified."

        now = datetime.now(timezone.utc)
        if user.email_verification_last_sent_at:
            last_sent = user.email_verification_last_sent_at
            if last_sent.tzinfo is None:
                last_sent = last_sent.replace(tzinfo=timezone.utc)
            elapsed = (now - last_sent).total_seconds()
            if elapsed < 60:
                remaining_sec = int(60 - elapsed)
                return False, None, f"Please wait {remaining_sec} second(s) before requesting another verification email."

        raw_otp = f"{secrets.randbelow(900000) + 100000}"
        user.set_email_otp(raw_otp, expiry_seconds=300)
        raw_token = secrets.token_urlsafe(32)
        user.set_email_verification_token(raw_token, expiry_seconds=86400)

        from app.providers.email_provider import get_email_provider
        email_provider = get_email_provider()

        base_url = (
            (current_app.config.get("APP_PUBLIC_URL") if current_app else None)
            or os.environ.get("APP_PUBLIC_URL")
            or "http://127.0.0.1:5000"
        ).rstrip("/")
        verification_url = f"{base_url}/api/auth/verify-email?token={raw_token}"

        email_ok, email_err = email_provider.send_email_verification_otp(
            recipient_email=user.email,
            otp_code=raw_otp,
            recipient_name=user.name,
            verification_url=verification_url,
            expires_in_minutes=5,
        )
        db.session.commit()

        if not email_ok:
            AuditService.log_event(
                event_type="EMAIL_DELIVERY_FAILED",
                actor=user.email,
                action="POST /api/auth/resend-email-verification",
                result="FAILURE",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                details={"reason": email_err},
            )
            return False, None, email_err or "Failed to deliver email verification code."

        AuditService.log_event(
            event_type="EMAIL_VERIFICATION_RESEND",
            actor=user.email,
            action="POST /api/auth/resend-email-verification",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
        )

        return True, None, None

    @staticmethod
    def verify_email_token(token: str) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Verify direct email verification URL token.
        """
        if not token:
            return False, None, "Verification token is required."

        import hashlib
        token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        user = User.query.filter_by(email_verification_token_hash=token_hash).first()
        if not user:
            return False, None, "Invalid or expired verification link."

        is_valid, err = user.check_email_verification_token(token)
        db.session.commit()

        if not is_valid:
            return False, user, err or "Invalid or expired verification link."

        AuditService.log_event(
            event_type="EMAIL_VERIFICATION_COMPLETED",
            actor=user.email,
            action="GET /api/auth/verify-email",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={"method": "LINK_TOKEN"},
        )
        return True, user, None

    @staticmethod
    def verify_phone_otp(
        phone_or_email: Optional[str] = None,
        otp_code: Optional[str] = None,
        email: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Verify incoming 6-digit OTP against user's stored hash and activate phone verification.
        Supports multi-account phone sharing by resolving via user_id or email first.
        """
        import re
        if not otp_code:
            return False, None, "Verification OTP code is required."

        user = None
        # 1. Resolve by user_id if provided
        if user_id is not None:
            user = db.session.get(User, int(user_id))

        # 2. Resolve by email if explicitly provided
        if not user and email and str(email).strip():
            user = User.query.filter_by(email=str(email).strip().lower()).first()

        # 3. Resolve by phone_or_email identifier
        if not user and phone_or_email and str(phone_or_email).strip():
            clean_id = str(phone_or_email).strip()
            if "@" in clean_id:
                user = User.query.filter_by(email=clean_id.lower()).first()
            elif clean_id.lower().startswith("fs-"):
                user = User.query.filter_by(customer_account_id=clean_id.upper()).first()
            else:
                digits_only = re.sub(r"\D", "", clean_id)
                target_digits = digits_only[-10:] if len(digits_only) >= 10 else digits_only
                if len(target_digits) == 10:
                    # Look up all matching candidate users
                    candidates = User.query.filter(
                        User.phone_number.isnot(None),
                        (User.phone_number == target_digits) |
                        (User.phone_number == f"+91{target_digits}") |
                        (User.phone_number == f"91{target_digits}") |
                        (User.phone_number == f"+91 {target_digits[:5]} {target_digits[5:]}") |
                        (User.phone_number.like(f"%{target_digits}"))
                    ).all()

                    # Filter candidates whose active OTP matches or is pending verification
                    if len(candidates) == 1:
                        user = candidates[0]
                    elif len(candidates) > 1:
                        # Find candidates with unverified phone OTP set
                        unverified = [c for c in candidates if not c.is_phone_verified and c.phone_otp_hash]
                        if len(unverified) == 1:
                            user = unverified[0]
                        else:
                            # Try verifying against candidates to find the one matching the OTP
                            for cand in candidates:
                                if cand.phone_otp_hash:
                                    is_match, _ = cand.check_phone_otp(otp_code)
                                    if is_match:
                                        user = cand
                                        break

        if not user:
            return False, None, "No account found matching this identifier."

        if user.is_phone_verified:
            return True, user, "Mobile number is already verified."

        is_valid, err = user.check_phone_otp(otp_code)
        db.session.commit()

        if not is_valid:
            AuditService.log_event(
                event_type="PHONE_OTP_FAILED",
                actor=user.email,
                action="POST /api/auth/verify-phone-otp",
                result="FAILURE",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                details={"reason": err},
            )
            return False, user, err or "Invalid or expired verification code."

        AuditService.log_event(
            event_type="PHONE_OTP_VERIFIED",
            actor=user.email,
            action="POST /api/auth/verify-phone-otp",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={
                "phone_number": user.phone_number,
                "is_phone_verified": True,
                "is_fully_verified": user.is_fully_verified,
                "account_status": user.account_status,
            },
        )

        return True, user, None

    @staticmethod
    def resend_phone_otp(
        phone_or_email: Optional[str] = None,
        email: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Rate-limited resend of phone verification OTP code.
        Supports multi-account phone sharing by resolving via user_id or email first.
        """
        import re
        user = None

        if user_id is not None:
            user = db.session.get(User, int(user_id))

        if not user and email and str(email).strip():
            user = User.query.filter_by(email=str(email).strip().lower()).first()

        if not user and phone_or_email and str(phone_or_email).strip():
            clean_id = str(phone_or_email).strip()
            if "@" in clean_id:
                user = User.query.filter_by(email=clean_id.lower()).first()
            elif clean_id.lower().startswith("fs-"):
                user = User.query.filter_by(customer_account_id=clean_id.upper()).first()
            else:
                digits_only = re.sub(r"\D", "", clean_id)
                target_digits = digits_only[-10:] if len(digits_only) >= 10 else digits_only
                if len(target_digits) == 10:
                    candidates = User.query.filter(
                        User.phone_number.isnot(None),
                        (User.phone_number == target_digits) |
                        (User.phone_number == f"+91{target_digits}") |
                        (User.phone_number == f"91{target_digits}") |
                        (User.phone_number.like(f"%{target_digits}"))
                    ).all()
                    if len(candidates) == 1:
                        user = candidates[0]
                    elif len(candidates) > 1:
                        unverified = [c for c in candidates if not c.is_phone_verified]
                        if len(unverified) == 1:
                            user = unverified[0]
                        else:
                            user = candidates[-1]  # Most recent account

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

        # Check verification state (Either email or phone verified enables login)
        if not user.is_email_verified and not user.is_phone_verified:
            AuditService.log_event(
                event_type="LOGIN_FAILED",
                actor=clean_email,
                action="POST /api/auth/login",
                result="DENIED",
                user_id=user.id,
                severity="WARN",
                details={"reason": "Account is pending verification (neither email nor mobile verified)"},
            )
            return None, user, "Please verify your email address or mobile number before signing in."

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
    def find_user_by_phone(phone: str, exclude_user_id: Optional[int] = None) -> Optional[User]:
        """
        Find user matching normalized phone number across all database formats.
        Optionally excludes a specific user ID for update uniqueness validation.
        """
        from app.utils.validators import validate_phone_number
        if not phone or not str(phone).strip():
            return None

        is_valid, target_digits, _ = validate_phone_number(str(phone))
        if not is_valid or not target_digits:
            return None

        # Query potential matches matching standard variations and wildcard suffix
        query = User.query.filter(
            User.phone_number.isnot(None),
            (
                (User.phone_number == target_digits) |
                (User.phone_number == f"+91{target_digits}") |
                (User.phone_number == f"91{target_digits}") |
                (User.phone_number == f"+91 {target_digits[:5]} {target_digits[5:]}") |
                (User.phone_number == f"+91 {target_digits}") |
                (User.phone_number.like(f"%{target_digits}"))
            )
        )
        if exclude_user_id is not None:
            query = query.filter(User.id != exclude_user_id)

        candidates = query.all()
        for candidate in candidates:
            if candidate.phone_number:
                c_valid, c_digits, _ = validate_phone_number(candidate.phone_number)
                if c_valid and c_digits == target_digits:
                    return candidate
        return None

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

        # Build absolute reset URL using APP_PUBLIC_URL or request.host_url
        base_url = (
            (current_app.config.get("APP_PUBLIC_URL") if current_app else None)
            or os.environ.get("APP_PUBLIC_URL")
        )
        if not base_url:
            try:
                from flask import request
                if request and request.host_url:
                    base_url = request.host_url.rstrip("/")
            except Exception:
                base_url = "http://127.0.0.1:5000"

        reset_url = f"{str(base_url).rstrip('/')}/reset-password?token={raw_token}"
        email_ok, email_err = email_provider.send_password_reset_email(
            recipient_email=user.email,
            reset_url=reset_url,
            expires_at=expires_at,
            recipient_name=user.name,
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

    @staticmethod
    def update_user_profile(
        user_id: int,
        name: Optional[str] = None,
        phone_number: Optional[str] = None,
    ) -> Tuple[bool, Optional[User], str, int, bool]:
        """
        Update authenticated user profile information safely.
        """
        from app.utils.validators import validate_phone_number
        from app.providers.sms_provider import get_sms_provider

        user = db.session.get(User, user_id)
        if not user:
            return False, None, "User account not found.", 404, False

        changes_made = False
        phone_verification_required = False

        if name is not None:
            clean_name = str(name).strip()
            if len(clean_name) < 2 or len(clean_name) > 100:
                return False, user, "Name must be between 2 and 100 characters long.", 400, False
            if user.name != clean_name:
                user.name = clean_name
                changes_made = True

        if phone_number is not None:
            raw_phone = str(phone_number).strip()
            if not raw_phone:
                # User is clearing their phone number
                if user.phone_number is not None:
                    user.phone_number = None
                    user.is_phone_verified = False
                    user.phone_verified_at = None
                    user.phone_otp_hash = None
                    user.phone_otp_expires_at = None
                    changes_made = True
            else:
                is_valid, phone_digits, phone_err = validate_phone_number(raw_phone)
                if not is_valid:
                    return False, user, phone_err or "Invalid mobile number.", 400, False

                # Normalize current user's existing phone number if present
                curr_valid, curr_digits, _ = validate_phone_number(user.phone_number) if user.phone_number else (False, None, None)

                if curr_valid and curr_digits == phone_digits:
                    # User is submitting their OWN existing phone number!
                    # Normalize formatting in DB if it differed, but do NOT trigger OTP and do NOT revoke verification!
                    if user.phone_number != phone_digits:
                        user.phone_number = phone_digits
                        changes_made = True
                else:
                    # Genuinely changed or newly added phone number (phone reuse allowed)
                    user.phone_number = phone_digits
                    user.is_phone_verified = False
                    user.phone_verified_at = None
                    changes_made = True
                    phone_verification_required = True

                    # Generate and dispatch 6-digit SMS OTP challenge
                    raw_phone_otp = f"{secrets.randbelow(900000) + 100000}"
                    user.set_phone_otp(raw_phone_otp, expiry_seconds=300)

                    sms_provider = get_sms_provider()
                    sms_ok, sms_err = sms_provider.send_otp(
                        phone_number=f"+91{phone_digits}",
                        otp_code=raw_phone_otp,
                        purpose="PHONE_UPDATE"
                    )
                    if not sms_ok and current_app:
                        current_app.logger.warning("Phone update OTP dispatch returned: %s", sms_err)

        if changes_made:
            user.check_and_update_activation()
            db.session.commit()

            AuditService.log_event(
                event_type="PROFILE_UPDATED",
                actor=user.email,
                action="PUT /api/profile",
                result="SUCCESS",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="INFO",
                details={
                    "name": user.name,
                    "phone_number": user.phone_number,
                    "is_phone_verified": user.is_phone_verified,
                    "phone_verification_required": phone_verification_required,
                },
            )

        msg = "Profile updated successfully."
        if phone_verification_required:
            msg = f"Profile updated. A 6-digit verification code was sent to your mobile number (+91 {user.phone_number})."

        return True, user, msg, 200, phone_verification_required

