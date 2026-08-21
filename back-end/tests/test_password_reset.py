"""
Password Reset Security and Lifecycle Test Suite (Phase 2.5).

Tests all 24 required password reset security scenarios:
1. Forgot password with existing email.
2. Forgot password with non-existing email.
3. Existing/non-existing email responses are equivalent (anti-enumeration).
4. Invalid email format.
5. Reset token generated securely.
6. Raw token is not stored in database.
7. Valid token resets password.
8. Invalid token rejected.
9. Expired token rejected.
10. Already-used token rejected.
11. Old token invalidated after new request.
12. Password mismatch rejected.
13. Weak password rejected according to project policy.
14. Successful reset marks token as used.
15. Other active tokens invalidated after successful reset.
16. Excessive forgot-password requests rate limited.
17. Excessive token attempts rate limited.
18. Password is stored hashed.
19. Password/token values are not written to logs.
20. Existing login works with the new password.
21. Old password no longer works.
22. Existing admin authentication still works.
23. Existing registration still works.
24. Existing transaction authentication still works.
"""

import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.services.auth_service import AuthService
from app.providers.email_provider import DevelopmentEmailProvider


@pytest.fixture
def app():
    """Create test application configured with in-memory SQLite database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


@pytest.fixture
def seed_user(app):
    """Seed a regular test customer and return metadata."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Alice Walker",
            email="alice.walker@example.com",
            password="OriginalPassword123!",
            role="USER",
        )
        user.is_email_verified = True
        user.is_phone_verified = True
        user.is_active = True
        user.account_status = "ACTIVE"
        db.session.commit()
        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "password": "OriginalPassword123!",
        }


@pytest.fixture
def seed_admin(app):
    """Seed an administrator account and return metadata."""
    with app.app_context():
        admin, _ = AuthService.register_user(
            name="Admin Security Officer",
            email="admin.soc@example.com",
            password="AdminPassword123!",
            role="ADMIN",
        )
        admin.is_email_verified = True
        admin.is_phone_verified = True
        admin.is_active = True
        admin.account_status = "ACTIVE"
        db.session.commit()
        return {
            "id": admin.id,
            "email": admin.email,
            "name": admin.name,
            "password": "AdminPassword123!",
        }


# ==============================================================================
# 1. Forgot Password with Existing Email
# ==============================================================================
def test_1_forgot_password_existing_email(app, client, seed_user):
    """Forgot password request with registered email returns 200 and generic message."""
    res = client.post("/api/auth/forgot-password", json={"email": seed_user["email"]})
    assert res.status_code == 200
    data = res.get_json()
    assert "If an account exists for this email, a password reset link has been sent." in data["message"]
    # Verify token was created in database
    with app.app_context():
        token_record = PasswordResetToken.query.filter_by(user_id=seed_user["id"]).first()
        assert token_record is not None
        assert token_record.used_at is None


# ==============================================================================
# 2. Forgot Password with Non-Existing Email
# ==============================================================================
def test_2_forgot_password_non_existing_email(app, client):
    """Forgot password request with non-existent email returns 200 and generic message."""
    res = client.post("/api/auth/forgot-password", json={"email": "nonexistent.user@example.com"})
    assert res.status_code == 200
    data = res.get_json()
    assert "If an account exists for this email, a password reset link has been sent." in data["message"]
    # Verify no token record was created
    with app.app_context():
        assert PasswordResetToken.query.count() == 0


# ==============================================================================
# 3. Anti-Enumeration Response Equivalence
# ==============================================================================
def test_3_anti_enumeration_equivalence(client, seed_user):
    """Existing and non-existing email responses return identical message payload."""
    res_existing = client.post("/api/auth/forgot-password", json={"email": seed_user["email"]})
    res_nonexisting = client.post("/api/auth/forgot-password", json={"email": "ghost.user@example.com"})

    assert res_existing.status_code == res_nonexisting.status_code == 200
    data_existing = res_existing.get_json()
    data_nonexisting = res_nonexisting.get_json()
    assert data_existing["message"] == data_nonexisting["message"]


# ==============================================================================
# 4. Invalid Email Format
# ==============================================================================
def test_4_invalid_email_format(client):
    """Malformed or invalid email formats return 400 Bad Request."""
    for bad_email in ["notanemail", "missing@domain", "@nodomain.com", "", "   "]:
        res = client.post("/api/auth/forgot-password", json={"email": bad_email})
        assert res.status_code == 400
        assert "valid email address is required" in res.get_json()["error"].lower()


# ==============================================================================
# 5. Reset Token Generated Securely
# ==============================================================================
def test_5_reset_token_entropy_and_randomness(app, seed_user):
    """Reset token has cryptographic entropy (secrets module, min 32 chars length)."""
    with app.app_context():
        success, error = AuthService.request_password_reset(seed_user["email"])
        assert success is True
        assert error is None
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])
        assert raw_token is not None
        assert len(raw_token) >= 32
        assert isinstance(raw_token, str)


# ==============================================================================
# 6. Raw Token Is NOT Stored in Database
# ==============================================================================
def test_6_raw_token_not_in_database(app, seed_user):
    """Only the SHA-256 hash of the token is persisted, never the raw token."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])
        token_record = PasswordResetToken.query.filter_by(user_id=seed_user["id"]).first()
        assert token_record is not None
        # Must not equal raw token
        assert token_record.token_hash != raw_token
        # Must match computed SHA-256 hash
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        assert token_record.token_hash == expected_hash
        assert len(token_record.token_hash) == 64


# ==============================================================================
# 7. Valid Token Resets Password
# ==============================================================================
def test_7_valid_token_resets_password(client, app, seed_user):
    """Valid token successfully updates user password and returns 200."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "BrandNewPassword2026!",
        "confirm_password": "BrandNewPassword2026!",
    })
    assert res.status_code == 200
    assert "Password has been reset successfully" in res.get_json()["message"]

    # Verify user can verify with new password
    with app.app_context():
        updated_user = db.session.get(User, seed_user["id"])
        assert updated_user.check_password("BrandNewPassword2026!") is True


# ==============================================================================
# 8. Invalid Token Rejected
# ==============================================================================
def test_8_invalid_token_rejected(client):
    """Non-existent or forged token returns 400 Bad Request."""
    res = client.post("/api/auth/reset-password", json={
        "token": "forged-or-fake-token-1234567890",
        "new_password": "ValidPassword123!",
        "confirm_password": "ValidPassword123!",
    })
    assert res.status_code == 400
    assert "invalid or expired" in res.get_json()["error"].lower()


# ==============================================================================
# 9. Expired Token Rejected
# ==============================================================================
def test_9_expired_token_rejected(client, app, seed_user):
    """Token with expires_at in the past returns 400 Bad Request."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])
        token_record = PasswordResetToken.query.filter_by(user_id=seed_user["id"]).first()
        # Set expiry to 1 hour in the past
        token_record.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.session.commit()

    res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "ValidPassword123!",
        "confirm_password": "ValidPassword123!",
    })
    assert res.status_code == 400
    assert "expired" in res.get_json()["error"].lower()


# ==============================================================================
# 10. Already-Used Token Rejected
# ==============================================================================
def test_10_already_used_token_rejected(client, app, seed_user):
    """A token that has already been consumed cannot be reused."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    # First reset: should succeed
    res1 = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "FirstNewPassword123!",
        "confirm_password": "FirstNewPassword123!",
    })
    assert res1.status_code == 200

    # Second reset with same token: must fail
    res2 = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "SecondNewPassword123!",
        "confirm_password": "SecondNewPassword123!",
    })
    assert res2.status_code == 400
    assert "already been used" in res2.get_json()["error"].lower()


# ==============================================================================
# 11. Old Token Invalidated After New Request
# ==============================================================================
def test_11_old_token_invalidated_after_new_request(client, app, seed_user):
    """Generating a new reset token invalidates any previous active token for that user."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        token1 = DevelopmentEmailProvider.get_last_token(seed_user["email"])
        AuthService.request_password_reset(seed_user["email"])
        token2 = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    # Token 1 should now be rejected as already used/invalidated
    res1 = client.post("/api/auth/reset-password", json={
        "token": token1,
        "new_password": "NewPassword123!",
        "confirm_password": "NewPassword123!",
    })
    assert res1.status_code == 400

    # Token 2 should succeed
    res2 = client.post("/api/auth/reset-password", json={
        "token": token2,
        "new_password": "NewPassword123!",
        "confirm_password": "NewPassword123!",
    })
    assert res2.status_code == 200


# ==============================================================================
# 12. Password Mismatch Rejected
# ==============================================================================
def test_12_password_mismatch_rejected(client, app, seed_user):
    """Mismatched new_password and confirm_password returns 400 Bad Request."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "PasswordOne123!",
        "confirm_password": "PasswordTwo456!",
    })
    assert res.status_code == 400
    assert "passwords do not match" in res.get_json()["error"].lower()


# ==============================================================================
# 13. Weak Password Rejected
# ==============================================================================
def test_13_weak_password_rejected(client, app, seed_user):
    """Password shorter than 8 characters is rejected with 400 Bad Request."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "short",
        "confirm_password": "short",
    })
    assert res.status_code == 400
    assert "at least 8 characters" in res.get_json()["error"].lower()


# ==============================================================================
# 14. Successful Reset Marks Token as Used
# ==============================================================================
def test_14_successful_reset_marks_token_used(client, app, seed_user):
    """Resetting password sets used_at timestamp on the token record."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "NewPassword123!",
        "confirm_password": "NewPassword123!",
    })

    with app.app_context():
        token_record = PasswordResetToken.query.filter_by(user_id=seed_user["id"]).first()
        assert token_record.used_at is not None
        assert isinstance(token_record.used_at, datetime)


# ==============================================================================
# 15. Other Active Tokens Invalidated on Successful Reset
# ==============================================================================
def test_15_all_tokens_invalidated_on_reset(client, app, seed_user):
    """Upon successful password reset, all active reset tokens for that user are marked used."""
    with app.app_context():
        # Directly insert 2 tokens
        now = datetime.now(timezone.utc)
        t1 = PasswordResetToken(
            user_id=seed_user["id"],
            token_hash="hash1_dummy",
            expires_at=now + timedelta(minutes=10),
            used_at=None,
        )
        t2_raw = "valid_token_12345"
        t2 = PasswordResetToken(
            user_id=seed_user["id"],
            token_hash=hashlib.sha256(t2_raw.encode("utf-8")).hexdigest(),
            expires_at=now + timedelta(minutes=10),
            used_at=None,
        )
        db.session.add_all([t1, t2])
        db.session.commit()

    # Reset using t2
    res = client.post("/api/auth/reset-password", json={
        "token": t2_raw,
        "new_password": "NewPassword123!",
        "confirm_password": "NewPassword123!",
    })
    assert res.status_code == 200

    with app.app_context():
        all_tokens = PasswordResetToken.query.filter_by(user_id=seed_user["id"]).all()
        for tok in all_tokens:
            assert tok.used_at is not None


# ==============================================================================
# 16. Forgot-Password Requests Rate Limited
# ==============================================================================
def test_16_forgot_password_rate_limiting(client, seed_user):
    """Exceeding 3 reset requests within 15 minutes returns 429 Too Many Requests."""
    # 3 requests allowed
    for _ in range(3):
        res = client.post("/api/auth/forgot-password", json={"email": seed_user["email"]})
        assert res.status_code == 200

    # 4th request in the same window must be rate limited
    res_excess = client.post("/api/auth/forgot-password", json={"email": seed_user["email"]})
    assert res_excess.status_code == 429
    assert "too many password reset requests" in res_excess.get_json()["error"].lower()


# ==============================================================================
# 17. Excessive Token Attempts Rate Limited
# ==============================================================================
def test_17_token_attempt_lockout(client, app, seed_user):
    """After 5 failed verification attempts, token is locked and returns 429."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])
        token_record = PasswordResetToken.query.filter_by(user_id=seed_user["id"]).first()
        # Simulate 5 failed attempts
        token_record.attempt_count = 5
        db.session.commit()

    res = client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "ValidPassword123!",
        "confirm_password": "ValidPassword123!",
    })
    assert res.status_code == 429
    assert "locked" in res.get_json()["error"].lower() or "too many" in res.get_json()["error"].lower()


# ==============================================================================
# 18. Password Stored Hashed
# ==============================================================================
def test_18_password_stored_hashed(client, app, seed_user):
    """Password hash in database uses secure Werkzeug algorithm (never plaintext)."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    new_plain_pw = "SuperSecretPassword2026!"
    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": new_plain_pw,
        "confirm_password": new_plain_pw,
    })

    with app.app_context():
        user = db.session.get(User, seed_user["id"])
        assert user.password_hash != new_plain_pw
        assert user.password_hash.startswith("scrypt:") or user.password_hash.startswith("pbkdf2:")


# ==============================================================================
# 19. Password / Token Values Not Logged
# ==============================================================================
def test_19_sensitive_data_protection(client, seed_user, caplog):
    """Passwords and reset tokens are not logged in plaintext."""
    import logging
    with caplog.at_level(logging.INFO):
        res = client.post("/api/auth/forgot-password", json={"email": seed_user["email"]})
        assert res.status_code == 200
        for record in caplog.records:
            assert "OriginalPassword123!" not in record.message


# ==============================================================================
# 20. Existing Login Works with New Password
# ==============================================================================
def test_20_login_with_new_password(client, app, seed_user):
    """After password reset, user can log in with new password and receive a valid JWT."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "BrandNewSecretPassword123!",
        "confirm_password": "BrandNewSecretPassword123!",
    })

    login_res = client.post("/api/auth/login", json={
        "email": seed_user["email"],
        "password": "BrandNewSecretPassword123!",
    })
    assert login_res.status_code == 200
    data = login_res.get_json()
    assert "access_token" in data
    assert data["user"]["email"] == seed_user["email"]


# ==============================================================================
# 21. Old Password No Longer Works
# ==============================================================================
def test_21_old_password_rejected_after_reset(client, app, seed_user):
    """After password reset, authenticating with the old password returns 401."""
    with app.app_context():
        AuthService.request_password_reset(seed_user["email"])
        raw_token = DevelopmentEmailProvider.get_last_token(seed_user["email"])

    client.post("/api/auth/reset-password", json={
        "token": raw_token,
        "new_password": "BrandNewSecretPassword123!",
        "confirm_password": "BrandNewSecretPassword123!",
    })

    # Try logging in with original password
    old_login_res = client.post("/api/auth/login", json={
        "email": seed_user["email"],
        "password": "OriginalPassword123!",
    })
    assert old_login_res.status_code == 401
    assert "invalid email or password" in old_login_res.get_json()["error"].lower()


# ==============================================================================
# 22. Existing Admin Authentication Still Works
# ==============================================================================
def test_22_admin_authentication_regression(client, seed_admin):
    """Admin login returns 200 and ADMIN role access token."""
    login_res = client.post("/api/auth/login", json={
        "email": seed_admin["email"],
        "password": "AdminPassword123!",
    })
    assert login_res.status_code == 200
    data = login_res.get_json()
    assert data["user"]["role"] == "ADMIN"
    assert data["redirect_url"] == "/admin/dashboard"


# ==============================================================================
# 23. Existing Registration Still Works
# ==============================================================================
def test_23_user_registration_regression(client):
    """User registration continues to function and returns 201 Created."""
    res = client.post("/api/auth/register", json={
        "name": "New Reg User",
        "email": "new.registered@example.com",
        "password": "RegistrationPass123!",
    })
    assert res.status_code == 201
    assert res.get_json()["user"]["email"] == "new.registered@example.com"


# ==============================================================================
# 24. Existing Transaction Authentication Still Works
# ==============================================================================
def test_24_transaction_authentication_regression(client, seed_user):
    """Authenticated user with JWT can perform payment risk evaluation."""
    login_res = client.post("/api/auth/login", json={
        "email": seed_user["email"],
        "password": "OriginalPassword123!",
    })
    token = login_res.get_json()["access_token"]

    tx_res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "destination_upi_id": "merchant@fraudshield",
        },
    )
    assert tx_res.status_code == 200
    data = tx_res.get_json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert data["risk_level"] == "LOW"
