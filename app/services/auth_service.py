import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional
from flask import current_app
from flask_jwt_extended import create_access_token
from app.extensions import db
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken


class AuthService:
    """Service layer managing user accounts, authentication lifecycles, and secure password resets."""

    @staticmethod
    def register_user(
        name: str,
        email: str,
        password: str,
        role: str = "USER",
    ) -> Tuple[Optional[User], Optional[str]]:
        """
        Register a new user in the database with a hashed password.

        Returns:
            (User, None) on success
            (None, error_message) on failure
        """
        clean_email = email.strip().lower()
        clean_name = name.strip()

        # Check for existing email
        existing_user = User.query.filter_by(email=clean_email).first()
        if existing_user:
            return None, "Email is already registered"

        user_role = role.upper() if role in ["USER", "ADMIN"] else "USER"
        user = User(
            name=clean_name,
            email=clean_email,
            role=user_role,
            account_balance=100000.0 if user_role == "USER" else 0.0,
            is_phone_verified=True,
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

        db.session.commit()
        return user, None

    @staticmethod
    def authenticate_user(email: str, password: str) -> Tuple[Optional[str], Optional[User], Optional[str]]:
        """
        Authenticate user credentials and issue a JWT access token.

        Returns:
            (access_token, user, None) on success
            (None, None, error_message) on failure
        """
        clean_email = email.strip().lower()
        user = User.query.filter_by(email=clean_email).first()

        if not user or not user.check_password(password):
            return None, None, "Invalid email or password"

        # Generate JWT with user role in additional claims
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                "role": user.role,
                "email": user.email,
                "name": user.name,
            },
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
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Initiate a password reset flow for the given email.

        Security & Anti-Enumeration:
        - If the email does not exist, returns (True, None, None) without creating a token.
        - The caller always receives an identical generic success message.
        - Enforces rate limiting per account (max requests per window).
        - Invalidates all previous active reset tokens for this user.
        - Stores only SHA-256 token hash in database.
        - In dev mode, returns the raw token for local testing/demo. In prod, returns None for dev token.

        Returns:
            (success, dev_token_or_none, error_message_or_none)
        """
        clean_email = email.strip().lower()
        user = User.query.filter_by(email=clean_email).first()

        # Anti-enumeration: If user does not exist, silently return success
        if not user:
            return True, None, None

        # Configuration parameters
        expiry_minutes = current_app.config.get("PASSWORD_RESET_TOKEN_EXPIRY_MINUTES", 10)
        max_requests = current_app.config.get("PASSWORD_RESET_MAX_REQUESTS_PER_WINDOW", 3)
        window_minutes = current_app.config.get("PASSWORD_RESET_REQUEST_WINDOW_MINUTES", 15)
        dev_mode = current_app.config.get("PASSWORD_RESET_DEV_MODE", False)

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=window_minutes)

        # Rate limiting: count requests by this user in the active window
        recent_requests_count = PasswordResetToken.query.filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_at >= window_start,
        ).count()

        if recent_requests_count >= max_requests:
            return False, None, "Too many password reset requests. Please try again later."

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

        dev_token_out = raw_token if dev_mode else None
        return True, dev_token_out, None

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
            (success, error_message_or_none)
        """
        if not token or not isinstance(token, str) or not token.strip():
            return False, "Reset token is required"

        clean_token = token.strip()
        computed_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()

        # Look up token record
        reset_record = PasswordResetToken.query.filter_by(token_hash=computed_hash).first()
        if not reset_record:
            return False, "Invalid or expired reset token"

        max_attempts = current_app.config.get("PASSWORD_RESET_MAX_ATTEMPTS", 5)

        # Check attempt limits
        if reset_record.attempt_count >= max_attempts:
            return False, "Too many failed attempts. This reset token has been locked."

        # Check if already used
        if reset_record.used_at is not None:
            reset_record.record_failed_attempt()
            db.session.commit()
            return False, "This reset token has already been used"

        # Check expiration
        now = datetime.now(timezone.utc)
        expires = reset_record.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        if now >= expires:
            reset_record.record_failed_attempt()
            db.session.commit()
            return False, "This reset token has expired"

        # Fetch user
        user = db.session.get(User, reset_record.user_id)
        if not user:
            return False, "User account associated with this token no longer exists"

        # Password policy check (min 8 characters)
        if not new_password or len(new_password) < 8:
            reset_record.record_failed_attempt()
            db.session.commit()
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
        return True, None

