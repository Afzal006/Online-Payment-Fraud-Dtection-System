"""
Comprehensive Security Test Suite for Real Password Recovery and Hardening (Phase C).

Verifies all 15 Phase C security requirements:
1. Registered email reset request
2. Unknown email reset request (Anti-enumeration)
3. Reset token expiration
4. Invalid token rejection
5. Reused token rejection
6. Token cryptographic entropy & randomness
7. Raw token not stored in database (SHA-256 hash only)
8. Password successfully changed
9. Old password rejected after reset
10. Reset request rate limiting (3 requests / 15 minutes)
11. Password reset audit events
12. Reset token not exposed through API response
13. Reset token not exposed through frontend templates
14. Payment PIN remains separate & required after password reset
15. Payment PIN failure produces zero ledger balance debit
"""

import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.models.audit_log import AuditLog
from app.services.auth_service import AuthService
from app.providers.email_provider import (
    DevelopmentEmailProvider,
    NullEmailProvider,
    SmtpEmailProvider,
)


@pytest.fixture
def app():
    """Create isolated test application."""
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def test_user(app):
    """Seed user with payment PIN set."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Vikramaditya Roy",
            email="vikram.real@example.com",
            password="OriginalSecretPassword123!",
            role="USER",
        )
        user.is_email_verified = True
        user.is_phone_verified = True
        user.is_active = True
        user.account_status = "ACTIVE"
        user.set_payment_pin("123456")
        user.account_balance = 50000.0
        db.session.commit()
        return {
            "id": user.id,
            "email": user.email,
            "password": "OriginalSecretPassword123!",
            "pin": "123456",
            "balance": 50000.0,
        }


# ==============================================================================
# 1. Registered Email Reset Request
# ==============================================================================
def test_1_registered_email_reset_request(client, app, test_user):
    """Registered email receives email with reset link and generic 200 response."""
    res = client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    assert res.status_code == 200
    data = res.get_json()
    assert "password reset link has been sent" in data["message"].lower()

    # Email was dispatched
    last_email = DevelopmentEmailProvider.get_last_email(test_user["email"])
    assert last_email is not None
    assert "/reset-password?token=" in last_email["reset_url"]


# ==============================================================================
# 2. Unknown Email Reset Request (Anti-Enumeration)
# ==============================================================================
def test_2_unknown_email_anti_enumeration(client, app):
    """Non-existent email returns identical generic 200 response without creating token."""
    res = client.post("/api/auth/forgot-password", json={"email": "nonexistent.ghost@example.com"})
    assert res.status_code == 200
    data = res.get_json()
    assert "password reset link has been sent" in data["message"].lower()

    # No token or email record created
    with app.app_context():
        assert PasswordResetToken.query.count() == 0
    assert DevelopmentEmailProvider.get_last_email("nonexistent.ghost@example.com") is None


# ==============================================================================
# 3. Reset Token Expiration
# ==============================================================================
def test_3_reset_token_expiration(client, app, test_user):
    """Expired reset token is rejected."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])
    assert raw_token is not None

    # Manually expire the token in database
    with app.app_context():
        tok = PasswordResetToken.query.filter_by(user_id=test_user["id"]).first()
        tok.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.session.commit()

    res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "NewValidPassword123!",
        "confirm_password": "NewValidPassword123!",
    })
    assert res.status_code == 400
    assert "expired" in res.get_json()["error"].lower()


# ==============================================================================
# 4. Invalid Token Rejection
# ==============================================================================
def test_4_invalid_token_rejected(client):
    """Forged or non-existent token is rejected."""
    res = client.post("/api/auth/reset-password", json={
        "token": "completely_fake_and_forged_token_xyz",
        "new_password": "NewValidPassword123!",
        "confirm_password": "NewValidPassword123!",
    })
    assert res.status_code == 400
    assert "invalid or expired" in res.get_json()["error"].lower()


# ==============================================================================
# 5. Reused Token Rejection
# ==============================================================================
def test_5_reused_token_rejected(client, app, test_user):
    """Once used, a reset token cannot be reused for a second password update."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])

    # First reset succeeds
    res1 = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "FirstNewPassword123!",
        "confirm_password": "FirstNewPassword123!",
    })
    assert res1.status_code == 200

    # Second reset with same token must fail
    res2 = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "SecondNewPassword123!",
        "confirm_password": "SecondNewPassword123!",
    })
    assert res2.status_code == 400
    assert "already been used" in res2.get_json()["error"].lower()


# ==============================================================================
# 6. Token Cannot Be Guessed (Entropy)
# ==============================================================================
def test_6_token_cryptographic_entropy(client, app, test_user):
    """Generated tokens are cryptographically random with at least 32 url-safe chars."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    token1 = DevelopmentEmailProvider.get_last_token(test_user["email"])
    assert len(token1) >= 40

    # Request second token
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    token2 = DevelopmentEmailProvider.get_last_token(test_user["email"])
    assert token1 != token2


# ==============================================================================
# 7. Raw Token Is NOT Stored in Database
# ==============================================================================
def test_7_raw_token_not_in_database(client, app, test_user):
    """Database stores only the SHA-256 hash, never the raw token."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])

    with app.app_context():
        token_record = PasswordResetToken.query.filter_by(user_id=test_user["id"]).first()
        assert token_record.token_hash != raw_token
        computed_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        assert token_record.token_hash == computed_hash


# ==============================================================================
# 8. Password Successfully Changed
# ==============================================================================
def test_8_password_successfully_changed(client, app, test_user):
    """User can reset password and immediately log in with the new password."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])

    res_reset = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "NewStrongPassword2026!",
        "confirm_password": "NewStrongPassword2026!",
    })
    assert res_reset.status_code == 200

    # Authenticate with new password
    res_login = client.post("/api/auth/login", json={
        "email": test_user["email"],
        "password": "NewStrongPassword2026!",
    })
    assert res_login.status_code == 200
    assert "access_token" in res_login.get_json()


# ==============================================================================
# 9. Old Password Rejected After Reset
# ==============================================================================
def test_9_old_password_rejected_after_reset(client, app, test_user):
    """Authenticating with original password after reset returns 401."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])

    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "NewStrongPassword2026!",
        "confirm_password": "NewStrongPassword2026!",
    })

    res_old = client.post("/api/auth/login", json={
        "email": test_user["email"],
        "password": test_user["password"],
    })
    assert res_old.status_code == 401


# ==============================================================================
# 10. Reset Request Rate Limiting
# ==============================================================================
def test_10_reset_request_rate_limiting(client, test_user):
    """Exceeding 3 reset requests in 15 minutes returns 429 Too Many Requests."""
    for _ in range(3):
        res = client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
        assert res.status_code == 200

    res_excess = client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    assert res_excess.status_code == 429
    assert "too many" in res_excess.get_json()["error"].lower()


# ==============================================================================
# 11. Password Reset Audit Events
# ==============================================================================
def test_11_password_reset_audit_events(client, app, test_user):
    """Audit logs are recorded for request, dispatch, and completion."""
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])

    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "AuditedNewPassword2026!",
        "confirm_password": "AuditedNewPassword2026!",
    })

    with app.app_context():
        req_event = AuditLog.query.filter_by(actor=test_user["email"], event_type="PASSWORD_RESET_REQUESTED").first()
        assert req_event is not None

        email_event = AuditLog.query.filter_by(actor=test_user["email"], event_type="PASSWORD_RESET_EMAIL_SENT").first()
        assert email_event is not None

        comp_event = AuditLog.query.filter_by(actor=test_user["email"], event_type="PASSWORD_RESET_COMPLETED").first()
        assert comp_event is not None


# ==============================================================================
# 12. Reset Token NOT Exposed Through API
# ==============================================================================
def test_12_reset_token_not_exposed_in_api_response(client, test_user):
    """POST /api/auth/forgot-password response does not contain any token or raw code."""
    res = client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    data = res.get_json()
    assert "token" not in data
    assert "reset_token" not in data
    assert "dev_reset_token" not in data
    assert "dev_token" not in data
    assert "code" not in data


# ==============================================================================
# 13. Reset Token NOT Exposed Through Frontend Templates
# ==============================================================================
def test_13_reset_token_not_in_frontend_templates(client):
    """Forgot password and reset password templates do not contain demo mode token banners."""
    res_forgot = client.get("/forgot-password")
    assert res_forgot.status_code == 200
    html_forgot = res_forgot.get_data(as_text=True)
    assert "dev-token-banner" not in html_forgot
    assert "[Demo Mode Token]" not in html_forgot

    res_reset = client.get("/reset-password")
    assert res_reset.status_code == 200
    html_reset = res_reset.get_data(as_text=True)
    assert "[Demo Mode Token]" not in html_reset


# ==============================================================================
# 14. Payment PIN Remains Separate & Required After Password Reset
# ==============================================================================
def test_14_payment_pin_separate_and_required_after_password_reset(client, app, test_user):
    """Changing password does not overwrite or remove Payment PIN."""
    # 1. Reset password
    client.post("/api/auth/forgot-password", json={"email": test_user["email"]})
    raw_token = DevelopmentEmailProvider.get_last_token(test_user["email"])

    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "NewSecretLoginPassword2026!",
        "confirm_password": "NewSecretLoginPassword2026!",
    })

    # 2. Log in with new password
    res_login = client.post("/api/auth/login", json={
        "email": test_user["email"],
        "password": "NewSecretLoginPassword2026!",
    })
    token = res_login.get_json()["access_token"]

    # 3. Verify user's Payment PIN is still set and valid
    with app.app_context():
        user = db.session.get(User, test_user["id"])
        assert user.is_pin_set is True
        ok, err = user.check_payment_pin("123456")
        assert ok is True
        assert err is None


# ==============================================================================
# 15. Payment PIN Failure Produces Zero Debit
# ==============================================================================
def test_15_payment_pin_failure_zero_debit(client, app, test_user):
    """Failed payment PIN verification causes zero deduction to user's account balance."""
    # 1. Login
    res_login = client.post("/api/auth/login", json={
        "email": test_user["email"],
        "password": test_user["password"],
    })
    token = res_login.get_json()["access_token"]

    # 2. Attempt payment with wrong payment PIN
    res_pay = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 2500.0,
            "destination_upi_id": "merchant@fraudshield",
            "payment_pin": "999999",  # WRONG PIN
        },
    )
    assert res_pay.status_code == 401
    assert "incorrect payment pin" in res_pay.get_json()["error"].lower()

    # 3. Verify balance is completely untouched
    with app.app_context():
        user = db.session.get(User, test_user["id"])
        assert user.account_balance == 50000.0
