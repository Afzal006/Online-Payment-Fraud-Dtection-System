r"""
Comprehensive Automated Test Suite for Real Mobile Number Registration and SMS Verification (Phase B).

Verifies:
1. Indian Mobile Number Format Validation (+91, 10 digits [6-9]\d{9})
2. Duplicate Mobile Number Conflict Prevention
3. Registration with Phone Sets is_phone_verified=False
4. Secure 6-Digit OTP Generation, Hashing & Storage
5. SmsProvider Interface and Provider Abstraction
6. Successful Phone Verification Endpoint (POST /api/auth/verify-phone-otp)
7. Incorrect OTP Rejection & Attempt Counter Decrement
8. OTP Invalidation after 3 Consecutive Failures
9. OTP Expiration Enforcement
10. Resend Rate-Limiting & 60-Second Cooldown (POST /api/auth/resend-phone-otp)
11. Unverified Account Login Prevention
12. Audit Trail Logging for Registration and Phone Verification Events
"""

from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.auth_service import AuthService
from app.providers.sms_provider import (
    DevelopmentSmsProvider,
    NullSmsProvider,
    TwilioSmsProvider,
    Msg91SmsProvider,
    get_sms_provider,
)
from app.utils.validators import validate_phone_number


@pytest.fixture
def app():
    """Create isolated testing application."""
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        DevelopmentSmsProvider.clear_history()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test HTTP client."""
    return app.test_client()


# ==========================================
# 1. Phone Number Validation Unit Tests
# ==========================================

def test_validate_indian_phone_number_formats():
    """Verify various standard Indian mobile number representations."""
    # 10-digit clean
    ok, digits, err = validate_phone_number("9876543210")
    assert ok is True
    assert digits == "9876543210"
    assert err is None

    # +91 with space
    ok, digits, err = validate_phone_number("+91 98765 43210")
    assert ok is True
    assert digits == "9876543210"

    # +91 without space
    ok, digits, err = validate_phone_number("+919876543210")
    assert ok is True
    assert digits == "9876543210"

    # 91 prefix without plus
    ok, digits, err = validate_phone_number("919876543210")
    assert ok is True
    assert digits == "9876543210"

    # Leading zero prefix
    ok, digits, err = validate_phone_number("09876543210")
    assert ok is True
    assert digits == "9876543210"


def test_validate_invalid_phone_numbers():
    """Verify rejection of invalid phone formats and non-Indian prefixes."""
    # Non-starting with 6-9
    ok, digits, err = validate_phone_number("1234567890")
    assert ok is False
    assert "start with 6, 7, 8, or 9" in err

    # Too short
    ok, digits, err = validate_phone_number("98765")
    assert ok is False

    # Too long
    ok, digits, err = validate_phone_number("9876543210123")
    assert ok is False

    # Empty
    ok, digits, err = validate_phone_number("")
    assert ok is False


# ==========================================
# 2. SMS Provider Abstraction Tests
# ==========================================

def test_development_sms_provider_capture():
    """Verify DevelopmentSmsProvider captures OTP in memory for test verification."""
    provider = DevelopmentSmsProvider()
    ok, err = provider.send_otp("+919876543210", "654321", purpose="REGISTRATION")
    assert ok is True
    assert err is None
    assert DevelopmentSmsProvider.get_last_otp("+919876543210") == "654321"


def test_null_sms_provider_fails_transparently():
    """Verify NullSmsProvider returns honest failure without fabricating success."""
    provider = NullSmsProvider()
    ok, err = provider.send_otp("+919876543210", "654321")
    assert ok is False
    assert "no sms provider configured" in err.lower()


# ==========================================
# 3. Registration with Phone OTP Flow Tests
# ==========================================

def test_user_registration_with_phone_creates_unverified_account(client):
    """Verify registering with a mobile number creates account in is_phone_verified=False state."""
    payload = {
        "name": "Priya Patel",
        "email": "priya.reg@example.com",
        "phone_number": "+91 98765 43210",
        "password": "SecurePassword123!",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["requires_phone_verification"] is True
    assert data["user"]["is_phone_verified"] is False
    assert data["user"]["phone_number"] == "9876543210"

    # Verify SMS was dispatched via provider
    last_otp = DevelopmentSmsProvider.get_last_otp("+919876543210")
    assert last_otp is not None
    assert len(last_otp) == 6

    # Verify plaintext OTP is NOT in database
    user = User.query.filter_by(email="priya.reg@example.com").first()
    assert user is not None
    assert user.is_phone_verified is False
    assert user.phone_otp_hash is not None
    assert last_otp not in user.phone_otp_hash  # Hashed


def test_duplicate_phone_number_rejection(client):
    """Verify that registering an already registered phone number returns 409 Conflict."""
    payload1 = {
        "name": "User One",
        "email": "user1@example.com",
        "phone_number": "9876543210",
        "password": "Password123!",
    }
    res1 = client.post("/api/auth/register", json=payload1)
    assert res1.status_code == 201

    payload2 = {
        "name": "User Two",
        "email": "user2@example.com",
        "phone_number": "+91 98765 43210",  # Same phone
        "password": "Password123!",
    }
    res2 = client.post("/api/auth/register", json=payload2)
    assert res2.status_code == 409
    assert "mobile number is already registered" in res2.get_json()["error"].lower()


def test_successful_phone_verification(client):
    """Verify POST /api/auth/verify-phone-otp activates user account."""
    # 1. Register
    payload = {
        "name": "Rahul Sharma",
        "email": "rahul.verify@example.com",
        "phone_number": "9876543211",
        "password": "Password123!",
    }
    res_reg = client.post("/api/auth/register", json=payload)
    assert res_reg.status_code == 201

    # Fetch dispatched OTP from test provider
    dispatched_otp = DevelopmentSmsProvider.get_last_otp("+919876543211")
    assert dispatched_otp is not None

    # 2. Verify OTP
    verify_payload = {
        "phone_number": "9876543211",
        "otp_code": dispatched_otp,
    }
    res_v = client.post("/api/auth/verify-phone-otp", json=verify_payload)
    assert res_v.status_code == 200
    data_v = res_v.get_json()
    assert data_v["is_phone_verified"] is True

    # 3. Check Database State
    user = User.query.filter_by(email="rahul.verify@example.com").first()
    assert user.is_phone_verified is True
    assert user.phone_verified_at is not None
    assert user.phone_otp_hash is None  # Cleared after use


def test_incorrect_otp_and_attempt_limits(client):
    """Verify incorrect OTP decrements attempts and locks after 3 failures."""
    payload = {
        "name": "Vikram Singh",
        "email": "vikram.otp@example.com",
        "phone_number": "9876543212",
        "password": "Password123!",
    }
    client.post("/api/auth/register", json=payload)

    # Attempt 1 (Wrong OTP)
    res1 = client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543212", "otp_code": "000000"})
    assert res1.status_code == 400
    assert "2 attempt(s) remaining" in res1.get_json()["error"]

    # Attempt 2 (Wrong OTP)
    res2 = client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543212", "otp_code": "000000"})
    assert res2.status_code == 400
    assert "1 attempt(s) remaining" in res2.get_json()["error"]

    # Attempt 3 (Wrong OTP - Lockout)
    res3 = client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543212", "otp_code": "000000"})
    assert res3.status_code == 400
    assert "maximum attempts" in res3.get_json()["error"].lower()

    # Verify that even the correct OTP is now rejected because challenge was locked
    correct_otp = DevelopmentSmsProvider.get_last_otp("+919876543212")
    res4 = client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543212", "otp_code": correct_otp})
    assert res4.status_code == 400


def test_otp_expiration_enforcement(client):
    """Verify expired OTP code is rejected."""
    payload = {
        "name": "Ananya Roy",
        "email": "ananya.exp@example.com",
        "phone_number": "9876543213",
        "password": "Password123!",
    }
    client.post("/api/auth/register", json=payload)
    correct_otp = DevelopmentSmsProvider.get_last_otp("+919876543213")

    user = User.query.filter_by(email="ananya.exp@example.com").first()
    # Artificially expire the OTP
    user.phone_otp_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db.session.commit()

    res = client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543213", "otp_code": correct_otp})
    assert res.status_code == 400
    assert "expired" in res.get_json()["error"].lower()


def test_resend_otp_rate_limiting_cooldown(client):
    """Verify 60-second cooldown is enforced between OTP resend requests."""
    payload = {
        "name": "Deepak Sen",
        "email": "deepak.resend@example.com",
        "phone_number": "9876543214",
        "password": "Password123!",
    }
    client.post("/api/auth/register", json=payload)

    # Immediate resend (should be throttled within 60s)
    res_throttled = client.post("/api/auth/resend-phone-otp", json={"phone_number": "9876543214"})
    assert res_throttled.status_code == 429
    assert "wait" in res_throttled.get_json()["error"].lower()

    # Simulate 65s passed
    user = User.query.filter_by(email="deepak.resend@example.com").first()
    user.phone_otp_last_sent_at = datetime.now(timezone.utc) - timedelta(seconds=65)
    db.session.commit()

    # Resend allowed
    res_ok = client.post("/api/auth/resend-phone-otp", json={"phone_number": "9876543214"})
    assert res_ok.status_code == 200


def test_unverified_phone_user_cannot_login(client):
    """Verify unverified user account cannot log in until both factors complete."""
    from app.providers.email_provider import DevelopmentEmailProvider
    payload = {
        "name": "Kavita Menon",
        "email": "kavita.login@example.com",
        "phone_number": "9876543215",
        "password": "Password123!",
    }
    client.post("/api/auth/register", json=payload)

    # Verify email first
    email_otp = DevelopmentEmailProvider.get_last_email_otp("kavita.login@example.com")
    client.post("/api/auth/verify-email-otp", json={"email": "kavita.login@example.com", "otp_code": email_otp})

    # Attempt login before phone verification (should fail with phone pending)
    res_login_fail = client.post("/api/auth/login", json={
        "email": "kavita.login@example.com",
        "password": "Password123!",
    })
    assert res_login_fail.status_code == 401
    assert "mobile number" in res_login_fail.get_json()["error"].lower() or "pending verification" in res_login_fail.get_json()["error"].lower()

    # Verify Phone
    phone_otp = DevelopmentSmsProvider.get_last_otp("+919876543215")
    client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543215", "otp_code": phone_otp})

    # Attempt login after both factors verified
    res_login_ok = client.post("/api/auth/login", json={
        "email": "kavita.login@example.com",
        "password": "Password123!",
    })
    assert res_login_ok.status_code == 200
    assert "access_token" in res_login_ok.get_json()


def test_phone_verification_audit_logging(client):
    """Verify audit events are recorded for registration, failed verification, and success."""
    payload = {
        "name": "Arjun Das",
        "email": "arjun.audit@example.com",
        "phone_number": "9876543216",
        "password": "Password123!",
    }
    client.post("/api/auth/register", json=payload)

    # Failed attempt
    client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543216", "otp_code": "000000"})

    # Successful attempt
    otp = DevelopmentSmsProvider.get_last_otp("+919876543216")
    client.post("/api/auth/verify-phone-otp", json={"phone_number": "9876543216", "otp_code": otp})

    # Check audit log records
    logs = AuditLog.query.filter_by(actor="arjun.audit@example.com").all()
    event_types = [l.event_type for l in logs]

    assert "USER_REGISTERED" in event_types
    assert any(et in event_types for et in ["PHONE_OTP_FAILED", "PHONE_VERIFICATION_FAILED"])
    assert any(et in event_types for et in ["PHONE_OTP_VERIFIED", "PHONE_VERIFIED"])
