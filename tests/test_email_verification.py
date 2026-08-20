"""
Phase 6 Automated Test Suite: Real Email Ownership Verification & Registration Hardening.

Test Coverage:
1. Email syntax and domain resolvability validation
2. Registration in PENDING_VERIFICATION state
3. Email OTP dispatch via EmailProvider (Development provider capture)
4. Email OTP submission, attempt limiting, and expiration
5. Resend email verification with cooldown rate-limiting
6. Direct URL token verification
7. Dual-factor activation gate (Email + Mobile)
8. Login restriction for unverified accounts (EMAIL_NOT_VERIFIED / PHONE_NOT_VERIFIED)
9. Security & Anti-Enumeration controls
10. Audit logging verification
"""

import pytest
import time
from datetime import datetime, timezone, timedelta
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.providers.email_provider import DevelopmentEmailProvider, get_email_provider
from app.services.auth_service import AuthService
from app.utils.validators import validate_email_syntax_and_domain


@pytest.fixture
def app():
    """Create test application configured with in-memory SQLite database."""
    app = create_app("testing")
    app.config["TESTING"] = True
    app.config["EMAIL_PROVIDER"] = "development"
    with app.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        yield app
        db.session.remove()
        db.drop_all()
        DevelopmentEmailProvider.clear_history()


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


# ============================================================================
# 1. Email Syntax & Domain Validation Tests
# ============================================================================

def test_email_syntax_and_domain_valid():
    """Verify legitimate email addresses pass syntax and domain validation."""
    valid_emails = [
        "user@gmail.com",
        "alex.smith@yahoo.com",
        "john+test@outlook.com",
        "security@fraudshield.ai",
        "test@example.com",
    ]
    for email in valid_emails:
        is_valid, clean, err = validate_email_syntax_and_domain(email, check_dns=False)
        assert is_valid is True, f"Failed for valid email: {email}, error: {err}"
        assert clean == email.strip().lower()


def test_email_syntax_invalid():
    """Verify structurally invalid email formats are rejected with clear errors."""
    invalid_emails = [
        "",
        "   ",
        "plainaddress",
        "@missinguser.com",
        "missingatsign.com",
        "two@@atsigns.com",
        "user@.com",
        "user@domain..com",
        "user name@domain.com",
    ]
    for email in invalid_emails:
        is_valid, clean, err = validate_email_syntax_and_domain(email, check_dns=False)
        assert is_valid is False, f"Expected invalid for: {email}"
        assert err is not None


def test_email_domain_dns_rejection():
    """Verify non-existent/unresolvable domains are rejected during registration."""
    # .invalid is reserved by RFC 2606 and guaranteed to fail resolution
    is_valid, _, err = validate_email_syntax_and_domain("user@nonexistentdomainxyz123456789.invalid", check_dns=True)
    assert is_valid is False
    assert "domain" in err.lower()


# ============================================================================
# 2. Registration & Email OTP Dispatch Tests
# ============================================================================

def test_registration_creates_pending_user_and_dispatches_otp(client):
    """Verify registration creates user in PENDING_VERIFICATION state and sends OTP."""
    payload = {
        "name": "Sarah Connor",
        "email": "sarah@example.com",
        "password": "StrongPassword2026!",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()

    assert data["requires_email_verification"] is True
    assert data["account_status"] == "PENDING_VERIFICATION"
    assert data["user"]["is_email_verified"] is False
    assert data["user"]["is_active"] is False

    # Check user in DB
    user = User.query.filter_by(email="sarah@example.com").first()
    assert user is not None
    assert user.is_email_verified is False
    assert user.account_status == "PENDING_VERIFICATION"
    assert user.email_verification_otp_hash is not None
    assert user.email_verification_token_hash is not None

    # Check that OTP was captured by DevelopmentEmailProvider
    last_otp = DevelopmentEmailProvider.get_last_email_otp("sarah@example.com")
    assert last_otp is not None
    assert len(last_otp) == 6
    assert last_otp.isdigit()


def test_login_blocked_for_unverified_email(client):
    """Verify unverified user cannot log in and receives EMAIL_NOT_VERIFIED code."""
    client.post("/api/auth/register", json={
        "name": "John Matrix",
        "email": "matrix@example.com",
        "password": "StrongPassword2026!",
    })

    login_res = client.post("/api/auth/login", json={
        "email": "matrix@example.com",
        "password": "StrongPassword2026!",
    })
    assert login_res.status_code == 401
    login_data = login_res.get_json()
    assert login_data["code"] == "EMAIL_NOT_VERIFIED"
    assert "verify your email" in login_data["error"].lower()


# ============================================================================
# 3. Email OTP Verification Tests
# ============================================================================

def test_verify_email_otp_success(client):
    """Verify submitting correct 6-digit OTP verifies email and activates single-factor account."""
    client.post("/api/auth/register", json={
        "name": "Ellen Ripley",
        "email": "ripley@example.com",
        "password": "StrongPassword2026!",
    })

    otp = DevelopmentEmailProvider.get_last_email_otp("ripley@example.com")
    assert otp is not None

    res = client.post("/api/auth/verify-email-otp", json={
        "email": "ripley@example.com",
        "otp_code": otp,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_email_verified"] is True
    assert data["account_status"] == "ACTIVE"

    # User should now be able to log in successfully
    login_res = client.post("/api/auth/login", json={
        "email": "ripley@example.com",
        "password": "StrongPassword2026!",
    })
    assert login_res.status_code == 200
    assert "access_token" in login_res.get_json()


def test_verify_email_otp_invalid_and_lockout(client):
    """Verify invalid OTP increments attempts and locks after 3 failures."""
    client.post("/api/auth/register", json={
        "name": "Kyle Reese",
        "email": "reese@example.com",
        "password": "StrongPassword2026!",
    })

    # Attempt 1: Wrong OTP
    res1 = client.post("/api/auth/verify-email-otp", json={
        "email": "reese@example.com",
        "otp_code": "000000",
    })
    assert res1.status_code == 400
    assert "attempt" in res1.get_json()["error"].lower()

    # Attempt 2: Wrong OTP
    res2 = client.post("/api/auth/verify-email-otp", json={
        "email": "reese@example.com",
        "otp_code": "111111",
    })
    assert res2.status_code == 400

    # Attempt 3: Wrong OTP -> Lockout
    res3 = client.post("/api/auth/verify-email-otp", json={
        "email": "reese@example.com",
        "otp_code": "222222",
    })
    assert res3.status_code == 400
    assert "maximum" in res3.get_json()["error"].lower() or "exceeded" in res3.get_json()["error"].lower()

    # Attempt with correct OTP after lockout should still fail
    correct_otp = DevelopmentEmailProvider.get_last_email_otp("reese@example.com")
    res_locked = client.post("/api/auth/verify-email-otp", json={
        "email": "reese@example.com",
        "otp_code": correct_otp,
    })
    assert res_locked.status_code == 400
    assert "request a new" in res_locked.get_json()["error"].lower() or "maximum" in res_locked.get_json()["error"].lower()


def test_verify_email_otp_expired(client):
    """Verify expired OTP is rejected."""
    client.post("/api/auth/register", json={
        "name": "Doc Brown",
        "email": "doc@example.com",
        "password": "StrongPassword2026!",
    })

    user = User.query.filter_by(email="doc@example.com").first()
    # Force expiry to the past
    user.email_verification_otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db.session.commit()

    otp = DevelopmentEmailProvider.get_last_email_otp("doc@example.com")
    res = client.post("/api/auth/verify-email-otp", json={
        "email": "doc@example.com",
        "otp_code": otp,
    })
    assert res.status_code == 400
    assert "expired" in res.get_json()["error"].lower()


# ============================================================================
# 4. Resend Email Verification Tests
# ============================================================================

def test_resend_email_verification_cooldown(client):
    """Verify 60-second cooldown is enforced on resending verification email."""
    client.post("/api/auth/register", json={
        "name": "Marty McFly",
        "email": "marty@example.com",
        "password": "StrongPassword2026!",
    })

    # Immediate resend should trigger 429
    res_cooldown = client.post("/api/auth/resend-email-verification", json={
        "email": "marty@example.com",
    })
    assert res_cooldown.status_code == 429
    assert "wait" in res_cooldown.get_json()["error"].lower()

    # Simulate 61 seconds passed
    user = User.query.filter_by(email="marty@example.com").first()
    user.email_verification_last_sent_at = datetime.now(timezone.utc) - timedelta(seconds=65)
    db.session.commit()

    res_allowed = client.post("/api/auth/resend-email-verification", json={
        "email": "marty@example.com",
    })
    assert res_allowed.status_code == 200


# ============================================================================
# 5. Direct URL Token Verification Tests
# ============================================================================

def test_direct_email_link_verification(client):
    """Verify clicking direct email verification link verifies email."""
    client.post("/api/auth/register", json={
        "name": "Luke Skywalker",
        "email": "luke@example.com",
        "password": "StrongPassword2026!",
    })

    token = DevelopmentEmailProvider.get_last_token("luke@example.com")
    assert token is not None

    # Request via API (JSON)
    res = client.get(f"/api/auth/verify-email?token={token}", headers={"Accept": "application/json"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_email_verified"] is True
    assert data["account_status"] == "ACTIVE"

    # User is now verified in DB
    user = User.query.filter_by(email="luke@example.com").first()
    assert user.is_email_verified is True


def test_direct_email_link_invalid_token(client):
    """Verify invalid token link returns 400 error."""
    res = client.get("/api/auth/verify-email?token=invalid-fake-token-12345", headers={"Accept": "application/json"})
    assert res.status_code == 400
    assert "invalid" in res.get_json()["error"].lower() or "expired" in res.get_json()["error"].lower()


# ============================================================================
# 6. Dual Factor Verification (Email + Mobile) Tests
# ============================================================================

def test_dual_factor_registration_flow(client):
    """Verify both email and mobile must be verified before account activates."""
    payload = {
        "name": "Princess Leia",
        "email": "leia@example.com",
        "phone_number": "9876543210",
        "password": "StrongPassword2026!",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["requires_email_verification"] is True
    assert data["requires_phone_verification"] is True
    assert data["account_status"] == "PENDING_VERIFICATION"

    email_otp = DevelopmentEmailProvider.get_last_email_otp("leia@example.com")
    user = User.query.filter_by(email="leia@example.com").first()

    # 1. Verify ONLY email
    res_email = client.post("/api/auth/verify-email-otp", json={
        "email": "leia@example.com",
        "otp_code": email_otp,
    })
    assert res_email.status_code == 200
    assert res_email.get_json()["is_email_verified"] is True
    assert res_email.get_json()["is_fully_verified"] is False
    assert res_email.get_json()["account_status"] == "PENDING_VERIFICATION"

    # Login should still fail because phone is pending
    res_login1 = client.post("/api/auth/login", json={
        "email": "leia@example.com",
        "password": "StrongPassword2026!",
    })
    assert res_login1.status_code == 401
    assert res_login1.get_json()["code"] == "PHONE_NOT_VERIFIED"

    # 2. Retrieve phone OTP dispatched during registration and verify phone
    from app.providers.sms_provider import DevelopmentSmsProvider
    phone_otp = DevelopmentSmsProvider.get_last_otp("+919876543210")
    assert phone_otp is not None

    res_phone = client.post("/api/auth/verify-phone-otp", json={
        "phone_number": "9876543210",
        "otp_code": phone_otp,
    })
    assert res_phone.status_code == 200
    assert res_phone.get_json()["is_phone_verified"] is True
    assert res_phone.get_json()["is_fully_verified"] is True
    assert res_phone.get_json()["account_status"] == "ACTIVE"

    # 3. Now login succeeds
    res_login2 = client.post("/api/auth/login", json={
        "email": "leia@example.com",
        "password": "StrongPassword2026!",
    })
    assert res_login2.status_code == 200
    assert "access_token" in res_login2.get_json()


# ============================================================================
# 7. Audit Logging Tests
# ============================================================================

def test_audit_logs_for_email_verification(client):
    """Verify security audit logs are recorded for all email verification events."""
    client.post("/api/auth/register", json={
        "name": "Audit Test User",
        "email": "audit_user@example.com",
        "password": "StrongPassword2026!",
    })

    otp = DevelopmentEmailProvider.get_last_email_otp("audit_user@example.com")

    # Wrong attempt
    client.post("/api/auth/verify-email-otp", json={
        "email": "audit_user@example.com",
        "otp_code": "000000",
    })

    # Correct attempt
    client.post("/api/auth/verify-email-otp", json={
        "email": "audit_user@example.com",
        "otp_code": otp,
    })

    logs = AuditLog.query.filter_by(actor="audit_user@example.com").all()
    event_types = [l.event_type for l in logs]

    assert "USER_REGISTERED" in event_types
    assert "EMAIL_VERIFICATION_SENT" in event_types
    assert "EMAIL_VERIFICATION_FAILED" in event_types
    assert "EMAIL_VERIFICATION_COMPLETED" in event_types
