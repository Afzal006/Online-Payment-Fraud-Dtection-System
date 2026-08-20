"""
User Database Model.

Represents system users, authentication credentials, and role-based permissions (USER / ADMIN).
"""

from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


class User(db.Model):
    """User account model supporting secure authentication, payment identity, and role-based access control."""

    __tablename__ = "users"
    __table_args__ = (
        db.CheckConstraint("role IN ('USER', 'ADMIN')", name="check_user_role"),
        db.CheckConstraint("account_balance >= 0", name="check_user_balance_non_negative"),
        {"sqlite_autoincrement": True},
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="USER")  # 'USER' or 'ADMIN'

    # Customer Payment Identity & Security (Phase 1 & Phase 3 UPI)
    phone_number = db.Column(db.String(20), unique=True, nullable=True, index=True)
    customer_account_id = db.Column(db.String(30), unique=True, nullable=True, index=True)
    primary_upi_id = db.Column(db.String(100), unique=True, nullable=True, index=True)
    account_balance = db.Column(db.Float, nullable=False, default=100000.0)
    is_phone_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Real Phone Verification OTP Lifecycle
    phone_otp_hash = db.Column(db.String(255), nullable=True)
    phone_otp_expires_at = db.Column(db.DateTime, nullable=True)
    phone_otp_attempts = db.Column(db.Integer, default=0, nullable=False)
    phone_otp_last_sent_at = db.Column(db.DateTime, nullable=True)

    # Secure Payment PIN (Layer 1 Transaction Authentication)
    payment_pin_hash = db.Column(db.String(255), nullable=True)
    pin_failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    pin_locked_until = db.Column(db.DateTime, nullable=True)
    is_pin_set = db.Column(db.Boolean, default=False, nullable=False)
    payment_pin_updated_at = db.Column(db.DateTime, nullable=True)

    # Secure Payment PIN Reset OTP
    pin_reset_otp_hash = db.Column(db.String(255), nullable=True)
    pin_reset_otp_expires_at = db.Column(db.DateTime, nullable=True)
    pin_reset_otp_attempts = db.Column(db.Integer, default=0, nullable=False)
    pin_reset_otp_last_sent_at = db.Column(db.DateTime, nullable=True)
    pin_reset_request_count = db.Column(db.Integer, default=0, nullable=False)
    pin_reset_window_start = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    password_changed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    transactions = db.relationship("Transaction", foreign_keys="Transaction.user_id", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", foreign_keys="Alert.user_id", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    beneficiaries = db.relationship("Beneficiary", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    password_reset_tokens = db.relationship("PasswordResetToken", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash plaintext password with Werkzeug scrypt/pbkdf2."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify candidate password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def set_phone_otp(self, otp_code: str, expiry_seconds: int = 300) -> None:
        """
        Hash plaintext mobile verification OTP, set expiry and update dispatch timestamp.
        """
        from datetime import timedelta
        clean_otp = str(otp_code).strip()
        self.phone_otp_hash = generate_password_hash(clean_otp)
        self.phone_otp_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        self.phone_otp_attempts = 0
        self.phone_otp_last_sent_at = datetime.now(timezone.utc)

    def check_phone_otp(self, candidate_otp: str) -> tuple:
        """
        Verify candidate OTP against stored hash with expiry and attempt limiting.
        Returns: (is_valid: bool, error_message: Optional[str])
        """
        if not self.phone_otp_hash or not self.phone_otp_expires_at:
            return False, "No active verification OTP found. Please request a new code."

        now = datetime.now(timezone.utc)
        expires_at = self.phone_otp_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            self.phone_otp_hash = None
            return False, "Verification OTP has expired. Please request a new code."

        if self.phone_otp_attempts >= 3:
            self.phone_otp_hash = None
            return False, "Maximum verification attempts exceeded. Please request a new OTP."

        clean_candidate = str(candidate_otp).strip()
        if check_password_hash(self.phone_otp_hash, clean_candidate):
            self.mark_phone_verified()
            return True, None
        else:
            self.phone_otp_attempts += 1
            remaining = max(0, 3 - self.phone_otp_attempts)
            if self.phone_otp_attempts >= 3:
                self.phone_otp_hash = None
                return False, "Incorrect OTP. Maximum attempts reached. Please request a new OTP."
            return False, f"Incorrect verification code. {remaining} attempt(s) remaining."

    def set_pin_reset_otp(self, otp_code: str, expiry_seconds: int = 300) -> None:
        """Hash plaintext PIN reset OTP, set expiry and update dispatch timestamp."""
        from datetime import timedelta
        clean_otp = str(otp_code).strip()
        self.pin_reset_otp_hash = generate_password_hash(clean_otp)
        self.pin_reset_otp_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        self.pin_reset_otp_attempts = 0
        self.pin_reset_otp_last_sent_at = datetime.now(timezone.utc)

    def check_pin_reset_otp(self, candidate_otp: str) -> tuple:
        """Verify candidate PIN reset OTP against stored hash with expiry and attempt limiting."""
        if not self.pin_reset_otp_hash or not self.pin_reset_otp_expires_at:
            return False, "No active PIN reset OTP found. Please request a new code."

        now = datetime.now(timezone.utc)
        expires_at = self.pin_reset_otp_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            self.pin_reset_otp_hash = None
            return False, "PIN reset OTP has expired. Please request a new code."

        if self.pin_reset_otp_attempts >= 3:
            self.pin_reset_otp_hash = None
            return False, "Maximum PIN reset verification attempts exceeded. Please request a new OTP."

        clean_candidate = str(candidate_otp).strip()
        if check_password_hash(self.pin_reset_otp_hash, clean_candidate):
            self.pin_reset_otp_hash = None
            self.pin_reset_otp_expires_at = None
            self.pin_reset_otp_attempts = 0
            return True, None
        else:
            self.pin_reset_otp_attempts += 1
            remaining = max(0, 3 - self.pin_reset_otp_attempts)
            if self.pin_reset_otp_attempts >= 3:
                self.pin_reset_otp_hash = None
                return False, "Incorrect OTP. Maximum attempts reached. Please request a new OTP."
            return False, f"Incorrect verification code. {remaining} attempt(s) remaining."

    def mark_phone_verified(self) -> None:
        """Mark account phone number as verified and clear temporary OTP fields."""
        self.is_phone_verified = True
        self.phone_verified_at = datetime.now(timezone.utc)
        self.phone_otp_hash = None
        self.phone_otp_expires_at = None
        self.phone_otp_attempts = 0

    def set_payment_pin(self, pin: str) -> None:
        """Securely hash and persist 4-6 digit numeric payment PIN."""
        clean_pin = str(pin).strip()
        self.payment_pin_hash = generate_password_hash(clean_pin)
        self.is_pin_set = True
        self.pin_failed_attempts = 0
        self.pin_locked_until = None
        self.payment_pin_updated_at = datetime.now(timezone.utc)
        self.pin_reset_otp_hash = None
        self.pin_reset_otp_expires_at = None
        self.pin_reset_otp_attempts = 0

    def check_payment_pin(self, pin: str) -> tuple:
        """
        Verify payment PIN against stored hash with rate-limiting & lockout.
        Returns: (is_valid: bool, error_message: Optional[str])
        """
        if not self.is_pin_set or not self.payment_pin_hash:
            return False, "Payment PIN has not been set for this account."

        now = datetime.now(timezone.utc)
        if self.pin_locked_until:
            lock_time = self.pin_locked_until
            if lock_time.tzinfo is None:
                lock_time = lock_time.replace(tzinfo=timezone.utc)
            if now < lock_time:
                remaining_sec = int((lock_time - now).total_seconds())
                minutes = (remaining_sec + 59) // 60
                return False, f"Payment PIN is locked due to security attempts. Please try again in {minutes} minute(s)."
            else:
                # Lockout period has elapsed, reset counter
                self.pin_locked_until = None
                self.pin_failed_attempts = 0

        clean_pin = str(pin).strip()
        if check_password_hash(self.payment_pin_hash, clean_pin):
            self.pin_failed_attempts = 0
            self.pin_locked_until = None
            return True, None
        else:
            self.pin_failed_attempts += 1
            if self.pin_failed_attempts >= 3:
                from datetime import timedelta
                self.pin_locked_until = now + timedelta(minutes=15)
                return False, "Payment PIN locked for 15 minutes due to 3 consecutive failed attempts."
            remaining = 3 - self.pin_failed_attempts
            return False, f"Incorrect Payment PIN. {remaining} attempt(s) remaining before lockout."

    @property
    def is_pin_locked(self) -> bool:
        """Check if payment PIN is currently locked."""
        if not self.pin_locked_until:
            return False
        lock_time = self.pin_locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < lock_time

    @property
    def is_admin(self) -> bool:
        """Check if user has administrative privileges."""
        return self.role == "ADMIN"

    def to_dict(self, include_private: bool = False) -> dict:
        """
        Convert user instance to JSON-serializable dictionary.
        Guarantees sensitive fields (password_hash, payment_pin_hash) are strictly excluded.
        """
        data = {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "phone_number": self.phone_number,
            "customer_account_id": self.customer_account_id,
            "primary_upi_id": self.primary_upi_id,
            "account_balance": float(self.account_balance) if self.account_balance is not None else 0.0,
            "is_phone_verified": bool(self.is_phone_verified),
            "phone_verified_at": self.phone_verified_at.isoformat() if self.phone_verified_at else None,
            "is_active": bool(self.is_active),
            "is_pin_set": bool(self.is_pin_set),
            "is_pin_locked": self.is_pin_locked,
            "payment_pin_updated_at": self.payment_pin_updated_at.isoformat() if self.payment_pin_updated_at else None,
            "beneficiary_count": self.beneficiaries.count() if hasattr(self, "beneficiaries") and self.beneficiaries else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_private:
            data["is_admin"] = self.is_admin
            data["pin_failed_attempts"] = self.pin_failed_attempts
        return data

    def __repr__(self) -> str:
        return f"<User {self.id}: {self.email} ({self.role}) [{self.customer_account_id}]>"
