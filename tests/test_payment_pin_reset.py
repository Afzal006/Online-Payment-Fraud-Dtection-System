"""
Automated Integration Tests for Payment PIN Recovery ("Forgot Payment PIN?"),
Weak PIN Rejection, and Security Lockout Clearance.
"""

import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.services.payment_service import PaymentService
from app.services.auth_service import AuthService


@pytest.fixture
def app():
    """Create test application configured with in-memory database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def registered_user(app):
    """Create verified test user with existing payment PIN."""
    with app.app_context():
        user = User(
            name="PIN Test User",
            email="pintest@example.com",
            phone_number="9876543210",
            primary_upi_id="pintest@fraudshield",
            account_balance=50000.0,
            is_phone_verified=True,
        )
        user.set_password("SecretPass2026!")
        user.set_payment_pin("432109")  # Initial valid PIN
        db.session.add(user)
        db.session.commit()
        return user.id


def get_auth_token(client, email="pintest@example.com", password="SecretPass2026!"):
    """Helper to authenticate and retrieve JWT access token."""
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    return res.get_json()["access_token"]


def test_weak_pins_rejected(app, registered_user):
    """Ensure easily guessable and weak PINs are rejected."""
    with app.app_context():
        for weak_pin in ["0000", "1111", "1234", "123456", "000000"]:
            ok, err = PaymentService.set_user_pin(
                user_id=registered_user,
                current_password="SecretPass2026!",
                new_pin=weak_pin,
                confirm_pin=weak_pin,
            )
            assert not ok
            assert "weak" in err.lower() or "guessable" in err.lower() or "common" in err.lower()


def test_pin_cannot_equal_account_password(app, registered_user):
    """Ensure payment PIN cannot equal account password."""
    with app.app_context():
        user = db.session.get(User, registered_user)
        user.set_password("987654")
        db.session.commit()

        ok, err = PaymentService.set_user_pin(
            user_id=registered_user,
            current_password="987654",
            new_pin="987654",
            confirm_pin="987654",
        )
        assert not ok
        assert "login password" in err.lower()


def test_request_pin_reset_otp_success(client, registered_user):
    """Ensure authenticated user can request SMS OTP for PIN recovery."""
    token = get_auth_token(client)
    res = client.post(
        "/api/auth/payment-pin/forgot/request-otp",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "Verification OTP sent" in data["message"]


def test_request_pin_reset_otp_rate_limiting(client, registered_user):
    """Ensure rapid resend requests trigger cooldown rate limiting."""
    token = get_auth_token(client)
    # First request
    res1 = client.post(
        "/api/auth/payment-pin/forgot/request-otp",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res1.status_code == 200

    # Immediate second request triggers cooldown
    res2 = client.post(
        "/api/auth/payment-pin/forgot/request-otp",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 429
    assert "wait" in res2.get_json()["error"].lower()


def test_verify_and_reset_pin_wrong_password(app, client, registered_user):
    """Ensure PIN reset fails when account password is incorrect."""
    with app.app_context():
        user = db.session.get(User, registered_user)
        user.set_pin_reset_otp("654321")
        db.session.commit()

    token = get_auth_token(client)
    res = client.post(
        "/api/auth/payment-pin/forgot/verify-and-reset",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "otp_code": "654321",
            "password": "WrongPassword999!",
            "new_pin": "849201",
            "confirm_pin": "849201",
        },
    )
    assert res.status_code == 401
    assert "Incorrect account login password" in res.get_json()["error"]


def test_verify_and_reset_pin_wrong_otp(app, client, registered_user):
    """Ensure incorrect OTP code reduces attempt counter and rejects reset."""
    with app.app_context():
        user = db.session.get(User, registered_user)
        user.set_pin_reset_otp("654321")
        db.session.commit()

    token = get_auth_token(client)
    res = client.post(
        "/api/auth/payment-pin/forgot/verify-and-reset",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "otp_code": "000000",
            "password": "SecretPass2026!",
            "new_pin": "849201",
            "confirm_pin": "849201",
        },
    )
    assert res.status_code == 400
    assert "Incorrect verification code" in res.get_json()["error"]


def test_full_pin_reset_and_lockout_clearance_lifecycle(app, client, registered_user):
    """
    Complete Lifecycle Test:
    1. Lock PIN via 3 incorrect attempts.
    2. Request PIN reset OTP.
    3. Verify OTP + password and set new PIN (849201).
    4. Verify lockout state is cleared.
    5. Old PIN (432109) rejected.
    6. New PIN (849201) authorizes transaction.
    """
    token = get_auth_token(client)

    # 1. Trigger Lockout with 3 failed attempts
    for _ in range(3):
        client.post(
            "/api/transactions/predict",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "type": "TRANSFER",
                "amount": 500.0,
                "oldbalance_org": 50000.0,
                "newbalance_orig": 49500.0,
                "destination_upi_id": "merchant@paytm",
                "payment_pin": "999999",
            },
        )

    with app.app_context():
        user = db.session.get(User, registered_user)
        assert user.is_pin_locked is True

    # 2. Request PIN reset OTP
    with app.app_context():
        user = db.session.get(User, registered_user)
        # Clear cooldown timestamp for test execution
        user.pin_reset_otp_last_sent_at = None
        user.set_pin_reset_otp("582910")
        db.session.commit()

    # 3. Reset PIN with valid OTP + Password
    reset_res = client.post(
        "/api/auth/payment-pin/forgot/verify-and-reset",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "otp_code": "582910",
            "password": "SecretPass2026!",
            "new_pin": "849201",
            "confirm_pin": "849201",
        },
    )
    assert reset_res.status_code == 200
    assert reset_res.get_json()["success"] is True

    # 4. Check lockout state is cleared
    with app.app_context():
        user = db.session.get(User, registered_user)
        assert user.is_pin_locked is False
        assert user.pin_failed_attempts == 0

    # 5. Old PIN rejected
    old_pin_res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "TRANSFER",
            "amount": 500.0,
            "oldbalance_org": 50000.0,
            "newbalance_orig": 49500.0,
            "destination_upi_id": "merchant@paytm",
            "payment_pin": "432109",  # Old PIN
        },
    )
    assert old_pin_res.status_code == 401
    assert "Incorrect Payment PIN" in old_pin_res.get_json()["error"]

    # 6. New PIN accepted
    new_pin_res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "TRANSFER",
            "amount": 500.0,
            "oldbalance_org": 50000.0,
            "newbalance_orig": 49500.0,
            "destination_upi_id": "merchant@paytm",
            "payment_pin": "849201",  # New PIN
        },
    )
    assert new_pin_res.status_code == 200
    data = new_pin_res.get_json()
    assert data["success"] is True
