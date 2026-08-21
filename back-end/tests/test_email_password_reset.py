"""
Automated Integration Tests for Email Delivery, SMTP Provider Configuration,
and Password Recovery Token Lifecycles.
"""

import os
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.providers.email_provider import (
    DevelopmentEmailProvider,
    SmtpEmailProvider,
    NullEmailProvider,
    get_email_provider,
)
from app.services.auth_service import AuthService


@pytest.fixture
def app():
    """Create test application configured with in-memory database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def sample_user(app):
    with app.app_context():
        user = User(
            name="Alice Smith",
            email="alice@example.com",
            phone_number="9123456780",
            primary_upi_id="alice@fraudshield",
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
        )
        user.set_password("OldPassword2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def test_smtp_provider_initialization_defaults(app):
    """Test SmtpEmailProvider parameter and environment variable parsing."""
    with app.app_context():
        provider = SmtpEmailProvider(
            host="smtp.gmail.com",
            port=587,
            username="testuser@gmail.com",
            password="testpassword",
            use_tls=True,
            from_email="noreply@fraudshield.ai",
            from_name="FraudShield Security",
        )
        assert provider.host == "smtp.gmail.com"
        assert provider.port == 587
        assert provider.use_tls is True
        assert provider.use_ssl is False
        assert provider.from_email == "noreply@fraudshield.ai"
        assert provider.from_name == "FraudShield Security"


def test_smtp_provider_ssl_port_465(app):
    """Test SmtpEmailProvider auto-enables SSL when port is 465."""
    with app.app_context():
        provider = SmtpEmailProvider(
            host="smtp.gmail.com",
            port=465,
            username="testuser@gmail.com",
            password="testpassword",
        )
        assert provider.port == 465
        assert provider.use_ssl is True
        assert provider.use_tls is False


def test_get_email_provider_factory_resolution(app):
    """Test email provider factory based on config overrides."""
    with app.app_context():
        # In testing mode without explicit override, returns DevelopmentEmailProvider
        p1 = get_email_provider()
        assert isinstance(p1, DevelopmentEmailProvider)

        # Explicit SMTP config
        app.config["MAIL_PROVIDER"] = "smtp"
        p2 = get_email_provider()
        assert isinstance(p2, SmtpEmailProvider)

        # Explicit NULL config
        app.config["MAIL_PROVIDER"] = "null"
        p3 = get_email_provider()
        assert isinstance(p3, NullEmailProvider)


def test_forgot_password_dispatches_email_with_absolute_url(app, client, sample_user):
    """Ensure forgot-password dispatches email with recipient name and absolute URL."""
    app.config["APP_PUBLIC_URL"] = "https://fraudshield.ai"
    res = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    assert res.status_code == 200

    last_email = DevelopmentEmailProvider.get_last_email("alice@example.com")
    assert last_email is not None
    assert last_email["recipient_name"] == "Alice Smith"
    assert last_email["reset_url"].startswith("https://fraudshield.ai/reset-password?token=")

    # Verify no token in API response
    data = res.get_json()
    assert "token" not in data
    assert "reset_token" not in data


def test_forgot_password_anti_enumeration(app, client):
    """Ensure non-existent email returns neutral message without dispatching email."""
    res = client.post("/api/auth/forgot-password", json={"email": "nonexistent@example.com"})
    assert res.status_code == 200
    assert "password reset" in res.get_json()["message"].lower() or "account exists" in res.get_json()["message"].lower()

    last_email = DevelopmentEmailProvider.get_last_email("nonexistent@example.com")
    assert last_email is None


def test_password_reset_lifecycle_and_authentication(app, client, sample_user):
    """
    Complete Password Reset Lifecycle:
    1. Request reset link.
    2. Extract single-use token.
    3. Update password via POST /api/auth/reset-password.
    4. Sign in with new password succeeds.
    5. Sign in with old password fails.
    6. Token cannot be reused.
    """
    client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    token = DevelopmentEmailProvider.get_last_token("alice@example.com")
    assert token is not None

    # Reset password with valid token
    reset_res = client.post(
        "/api/auth/reset-password",
        json={
            "token": token,
            "new_password": "BrandNewPassword2026!",
            "confirm_password": "BrandNewPassword2026!",
        },
    )
    assert reset_res.status_code == 200
    assert "reset successfully" in reset_res.get_json()["message"]

    # Login with new password succeeds
    login_new = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "BrandNewPassword2026!"},
    )
    assert login_new.status_code == 200
    assert "access_token" in login_new.get_json()

    # Login with old password fails
    login_old = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "OldPassword2026!"},
    )
    assert login_old.status_code == 401

    # Reusing the same token fails
    reuse_res = client.post(
        "/api/auth/reset-password",
        json={
            "token": token,
            "new_password": "AnotherNewPassword2026!",
            "confirm_password": "AnotherNewPassword2026!",
        },
    )
    assert reuse_res.status_code == 400
    assert "already been used" in reuse_res.get_json()["error"]
