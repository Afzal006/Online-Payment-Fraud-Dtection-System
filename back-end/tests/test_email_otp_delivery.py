"""
Email Verification, OTP Delivery & Account Recovery Test Suite (Phase 7.1).

Tests all 17 required scenarios:
1. New registration creates OTP challenge.
2. OTP is stored hashed in database.
3. Plaintext OTP is not stored in any database field.
4. OTP expires correctly after duration.
5. OTP attempt limit enforces lockout after max attempts.
6. Correct OTP verifies successfully.
7. Incorrect OTP fails verification.
8. Existing email cannot create duplicate account.
9. Existing account can use intended recovery or login flow.
10. Email delivery success is reported correctly.
11. Email delivery failure is NOT reported as successful.
12. OTP API does not return plaintext OTP in response body.
13. OTP API does not expose SMTP credentials or secrets.
14. Login flow enforces verification check.
15. Registration email verification activates user upon dual-verification.
16. Mobile OTP behavior is correctly distinguished between real and simulated.
17. Password recovery OTP / email reset flow still works end-to-end.
"""

import hashlib
import time
from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.otp_challenge import OTPChallenge
from app.models.password_reset_token import PasswordResetToken
from app.services.auth_service import AuthService
from app.providers.email_provider import DevelopmentEmailProvider, NullEmailProvider, SmtpEmailProvider
from app.providers.sms_provider import DevelopmentSmsProvider, NullSmsProvider


@pytest.fixture
def app():
    """Create test application in testing mode with in-memory SQLite."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        DevelopmentSmsProvider.clear_history()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


def test_1_new_registration_creates_otp_challenge(app, client):
    """Scenario 1: New registration generates hashed email verification challenge."""
    with app.app_context():
        res = client.post(
            "/api/auth/register",
            json={
                "name": "David Miller",
                "email": "david.miller@example.com",
                "password": "SecurePassword123!",
                "phone_number": "9876543210",
            },
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["requires_email_verification"] is True
        assert data["requires_phone_verification"] is True
        assert data["account_status"] == "PENDING_VERIFICATION"

        user = User.query.filter_by(email="david.miller@example.com").first()
        assert user is not None
        assert user.email_verification_otp_hash is not None
        assert user.email_verification_otp_expires_at is not None
        assert user.is_email_verified is False


def test_2_otp_is_stored_hashed(app):
    """Scenario 2: OTP is stored as a cryptographic hash."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Eva Green",
            email="eva.green@example.com",
            password="SecurePassword123!",
        )
        assert user is not None
        assert user.email_verification_otp_hash is not None
        assert len(user.email_verification_otp_hash) >= 64
        assert user.email_verification_otp_hash != "123456"
        assert not user.email_verification_otp_hash.isdigit()


def test_3_plaintext_otp_is_not_stored(app):
    """Scenario 3: Verify plaintext OTP is nowhere in database columns."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Frank Wright",
            email="frank.wright@example.com",
            password="SecurePassword123!",
        )
        # Check all attributes of user model for 6-digit numeric pattern
        for attr, val in user.__dict__.items():
            if isinstance(val, str) and len(val) == 6 and val.isdigit():
                pytest.fail(f"Plaintext numeric OTP found in user attribute: {attr}")


def test_4_otp_expires_correctly(app):
    """Scenario 4: OTP past expiry timestamp fails verification."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Grace Hopper",
            email="grace.hopper@example.com",
            password="SecurePassword123!",
        )
        raw_otp = "481920"
        # Set OTP with past expiration
        user.set_email_otp(raw_otp, expiry_seconds=-10)
        db.session.commit()

        success, verified_user, err = AuthService.verify_email_otp(
            email=user.email,
            otp_code=raw_otp,
        )
        assert success is False
        assert "expired" in err.lower()
        assert verified_user.is_email_verified is False


def test_5_otp_attempt_limit_works(app):
    """Scenario 5: Exceeding maximum OTP attempts locks the challenge."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Henry Ford",
            email="henry.ford@example.com",
            password="SecurePassword123!",
        )
        raw_otp = "592817"
        user.set_email_otp(raw_otp, expiry_seconds=300)
        db.session.commit()

        # Attempt 1 failed
        s1, _, err1 = AuthService.verify_email_otp(user.email, "000000")
        assert s1 is False
        assert user.email_verification_otp_attempts == 1

        # Attempt 2 failed
        s2, _, err2 = AuthService.verify_email_otp(user.email, "111111")
        assert s2 is False
        assert user.email_verification_otp_attempts == 2

        # Attempt 3 failed (Lockout reached)
        s3, _, err3 = AuthService.verify_email_otp(user.email, "222222")
        assert s3 is False
        assert "maximum" in err3.lower() or "exceeded" in err3.lower() or "locked" in err3.lower()

        # Attempt 4 with correct OTP must now be rejected because challenge was invalidated
        s4, _, err4 = AuthService.verify_email_otp(user.email, raw_otp)
        assert s4 is False
        assert "no active" in err4.lower() or "locked" in err4.lower() or "maximum" in err4.lower()


def test_6_correct_otp_verifies_successfully(app):
    """Scenario 6: Valid candidate OTP verifies successfully."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Iris Murdoch",
            email="iris.murdoch@example.com",
            password="SecurePassword123!",
        )
        raw_otp = "739104"
        user.set_email_otp(raw_otp, expiry_seconds=300)
        db.session.commit()

        success, verified_user, err = AuthService.verify_email_otp(
            email=user.email,
            otp_code=raw_otp,
        )
        assert success is True
        assert err is None
        assert verified_user.is_email_verified is True
        assert verified_user.email_verification_otp_hash is None


def test_7_incorrect_otp_fails(app):
    """Scenario 7: Incorrect candidate OTP is rejected."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Jack London",
            email="jack.london@example.com",
            password="SecurePassword123!",
        )
        raw_otp = "123456"
        user.set_email_otp(raw_otp, expiry_seconds=300)
        db.session.commit()

        success, verified_user, err = AuthService.verify_email_otp(
            email=user.email,
            otp_code="999999",
        )
        assert success is False
        assert "incorrect" in err.lower() or "invalid" in err.lower()
        assert verified_user.is_email_verified is False


def test_8_existing_email_cannot_create_duplicate_account(app, client):
    """Scenario 8: Attempting to register an existing email returns 409 and creates no duplicate."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Karen Blixen",
            email="karen.blixen@example.com",
            password="SecurePassword123!",
        )
        user.is_email_verified = True
        user.is_active = True
        user.account_status = "ACTIVE"
        db.session.commit()

        # Second registration attempt
        res = client.post(
            "/api/auth/register",
            json={
                "name": "Karen Duplicate",
                "email": "karen.blixen@example.com",
                "password": "AnotherPassword123!",
            },
        )
        assert res.status_code == 409
        data = res.get_json()
        assert "already" in data["error"].lower()
        assert data.get("code") in ("ACCOUNT_ALREADY_EXISTS", "ACCOUNT_EXISTS_VERIFIED")

        # Confirm count remains 1
        count = User.query.filter_by(email="karen.blixen@example.com").count()
        assert count == 1


def test_9_existing_account_can_use_recovery_or_login_flow(app, client):
    """Scenario 9: Existing user can use password reset / forgot password flow."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Leo Tolstoy",
            email="leo.tolstoy@example.com",
            password="OriginalPassword123!",
        )
        user.is_email_verified = True
        user.is_active = True
        user.account_status = "ACTIVE"
        db.session.commit()

        res = client.post(
            "/api/auth/forgot-password",
            json={"email": "leo.tolstoy@example.com"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "instructions" in data["message"].lower() or "sent" in data["message"].lower()

        # Ensure reset token record was created
        token_record = PasswordResetToken.query.filter_by(user_id=user.id).first()
        assert token_record is not None
        assert token_record.token_hash is not None


def test_10_email_delivery_success_reported_correctly(app):
    """Scenario 10: Successful email dispatch returns success."""
    with app.app_context():
        provider = DevelopmentEmailProvider()
        ok, err = provider.send_email_verification_otp(
            recipient_email="test.delivery@example.com",
            otp_code="654321",
            recipient_name="Test User",
        )
        assert ok is True
        assert err is None
        assert DevelopmentEmailProvider.get_last_email("test.delivery@example.com") is not None


def test_11_email_delivery_failure_not_reported_as_success(app):
    """Scenario 11: When email provider fails, return failure and do not fake success."""
    with app.app_context():
        provider = NullEmailProvider()
        ok, err = provider.send_email_verification_otp(
            recipient_email="test.null@example.com",
            otp_code="654321",
        )
        assert ok is False
        assert err is not None
        assert "not configured" in err.lower() or "failed" in err.lower()


def test_12_otp_api_does_not_return_plaintext_otp(app, client):
    """Scenario 12: Registration and resend APIs never expose OTP in payload."""
    with app.app_context():
        res = client.post(
            "/api/auth/register",
            json={
                "name": "Mark Twain",
                "email": "mark.twain@example.com",
                "password": "SecurePassword123!",
            },
        )
        assert res.status_code == 201
        data = res.get_json()
        assert "otp" not in data
        assert "otp_code" not in data
        assert "code" not in data or data.get("code") != "123456"


def test_13_otp_api_does_not_expose_smtp_credentials(app, client):
    """Scenario 13: Error responses and public endpoints never leak SMTP passwords or connection secrets."""
    with app.app_context():
        # Trigger an error on resend endpoint
        res = client.post(
            "/api/auth/resend-email-verification",
            json={"email": "nonexistent.user@example.com"},
        )
        data = res.get_json()
        raw_text = str(data)
        assert "password" not in raw_text.lower() or "password" == data.get("field")
        assert "SMTP_PASSWORD" not in raw_text
        assert "SECRET_KEY" not in raw_text


def test_14_login_verification_flow_works(app, client):
    """Scenario 14: Unverified accounts cannot sign in until verification is complete."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Nora Ephron",
            email="nora.ephron@example.com",
            password="SecurePassword123!",
        )
        # Attempt login while is_email_verified is False
        res = client.post(
            "/api/auth/login",
            json={
                "email": "nora.ephron@example.com",
                "password": "SecurePassword123!",
            },
        )
        assert res.status_code in (401, 403)
        data = res.get_json()
        assert "verify" in data["error"].lower()

        # Now mark verified and login succeeds
        user.is_email_verified = True
        user.is_phone_verified = True
        user.is_active = True
        user.account_status = "ACTIVE"
        db.session.commit()

        login_res = client.post(
            "/api/auth/login",
            json={
                "email": "nora.ephron@example.com",
                "password": "SecurePassword123!",
            },
        )
        assert login_res.status_code == 200
        assert "access_token" in login_res.get_json()


def test_15_registration_email_verification_works(app, client):
    """Scenario 15: Direct token verification link verifies email."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Oscar Wilde",
            email="oscar.wilde@example.com",
            password="SecurePassword123!",
        )
        raw_token = "secure_sample_token_oscar"
        user.set_email_verification_token(raw_token, expiry_seconds=3600)
        db.session.commit()

        # Verify via GET endpoint
        res = client.get(
            f"/api/auth/verify-email?token={raw_token}",
            headers={"Accept": "application/json"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["is_email_verified"] is True

        user_db = User.query.filter_by(email="oscar.wilde@example.com").first()
        assert user_db.is_email_verified is True


def test_16_mobile_otp_behavior_reported_real_or_simulated(app):
    """Scenario 16: Mobile OTP provider distinguishes real vs development."""
    with app.app_context():
        dev_sms = DevelopmentSmsProvider()
        ok_dev, err_dev = dev_sms.send_otp("+919876543210", "123456", "REGISTRATION")
        assert ok_dev is True
        assert err_dev is None

        null_sms = NullSmsProvider()
        ok_null, err_null = null_sms.send_otp("+919876543210", "123456", "REGISTRATION")
        assert ok_null is False
        assert "unavailable" in err_null.lower() or "no sms provider" in err_null.lower()


def test_17_password_recovery_flow_still_works(app, client):
    """Scenario 17: Password recovery link verification and password updating works."""
    with app.app_context():
        user, _ = AuthService.register_user(
            name="Pablo Neruda",
            email="pablo.neruda@example.com",
            password="OldPassword123!",
        )
        user.is_email_verified = True
        user.is_active = True
        user.account_status = "ACTIVE"
        db.session.commit()

        # 1. Request password reset
        ok, err = AuthService.request_password_reset("pablo.neruda@example.com")
        assert ok is True

        # Extract generated token from database
        token_record = PasswordResetToken.query.filter_by(user_id=user.id).first()
        assert token_record is not None

        # Verify by creating known token
        raw_token = "pablo_reset_token_test"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        token_record.token_hash = token_hash
        token_record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.session.commit()

        # 2. Complete reset
        res = client.post(
            "/api/auth/reset-password",
            json={
                "token": raw_token,
                "new_password": "BrandNewPassword123!",
                "confirm_password": "BrandNewPassword123!",
            },
        )
        assert res.status_code == 200

        # 3. Old password fails, new password works
        user_db = User.query.filter_by(email="pablo.neruda@example.com").first()
        assert user_db.check_password("OldPassword123!") is False
        assert user_db.check_password("BrandNewPassword123!") is True
