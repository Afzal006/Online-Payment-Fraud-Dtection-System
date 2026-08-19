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
    is_phone_verified = db.Column(db.Boolean, default=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Secure Payment PIN (Layer 1 Transaction Authentication)
    payment_pin_hash = db.Column(db.String(255), nullable=True)
    pin_failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    pin_locked_until = db.Column(db.DateTime, nullable=True)
    is_pin_set = db.Column(db.Boolean, default=False, nullable=False)

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

    def set_payment_pin(self, pin: str) -> None:
        """Securely hash and persist 4-6 digit numeric payment PIN."""
        clean_pin = str(pin).strip()
        self.payment_pin_hash = generate_password_hash(clean_pin)
        self.is_pin_set = True
        self.pin_failed_attempts = 0
        self.pin_locked_until = None

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
            "is_phone_verified": self.is_phone_verified,
            "is_active": self.is_active,
            "is_pin_set": bool(self.is_pin_set),
            "is_pin_locked": self.is_pin_locked,
            "beneficiary_count": self.beneficiaries.count() if hasattr(self, "beneficiaries") and self.beneficiaries else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_private:
            data["is_admin"] = self.is_admin
            data["pin_failed_attempts"] = self.pin_failed_attempts
        return data

    def __repr__(self) -> str:
        return f"<User {self.id}: {self.email} ({self.role}) [{self.customer_account_id}]>"
