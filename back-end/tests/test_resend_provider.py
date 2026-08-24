"""
Unit and Integration Tests for Resend HTTPS Email API Provider.

Tests all operations using mocked Resend API calls:
1. ResendEmailProvider configuration & diagnostics (no secret leakage).
2. Registration verification OTP email dispatch.
3. Password reset email dispatch.
4. Transaction step-up OTP challenge email dispatch.
5. Diagnostic test email dispatch.
6. Error handling when API key is missing or Resend API returns an error.
7. Factory get_email_provider() resolution with EMAIL_PROVIDER=resend.
8. /api/health/email reporting for Resend provider.
"""

from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import pytest
from app import create_app
from app.providers.email_provider import (
    ResendEmailProvider,
    get_email_provider,
    EmailProvider,
)


@pytest.fixture
def app():
    """Create test application in testing mode."""
    app = create_app("testing")
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


def test_resend_provider_diagnostics_hides_api_key(app):
    """Verify get_diagnostics reports status without exposing the API key secret."""
    provider = ResendEmailProvider(
        api_key="re_secret_123456789",
        from_email="security@fraudshield.ai",
        from_name="FraudShield AI Security",
    )
    diag = provider.get_diagnostics()

    assert diag["provider"] == "ResendEmailProvider"
    assert diag["api_key_configured"] is True
    assert diag["from_email"] == "security@fraudshield.ai"
    assert diag["from_name"] == "FraudShield AI Security"
    assert "re_secret_123456789" not in str(diag)


def test_resend_send_email_verification_otp_success(app):
    """Verify send_email_verification_otp formats message and calls resend.Emails.send."""
    provider = ResendEmailProvider(
        api_key="re_test_key",
        from_email="onboarding@resend.dev",
        from_name="FraudShield AI Security",
    )

    with patch("resend.Emails.send") as mock_send:
        mock_send.return_value = {"id": "resend_msg_001"}

        success, err = provider.send_email_verification_otp(
            recipient_email="user@example.com",
            otp_code="654321",
            recipient_name="John Doe",
            verification_url="https://app.fraudshield.ai/verify?token=abc",
            expires_in_minutes=5,
        )

        assert success is True
        assert err is None
        mock_send.assert_called_once()
        params = mock_send.call_args[0][0]
        assert params["to"] == ["user@example.com"]
        assert "654 321" in params["html"] or "654321" in params["html"]
        assert "654321" in params["text"]
        assert "FraudShield AI — Verify Your Email Address" in params["subject"]


def test_resend_send_password_reset_email_success(app):
    """Verify send_password_reset_email dispatches via Resend API."""
    provider = ResendEmailProvider(
        api_key="re_test_key",
        from_email="onboarding@resend.dev",
    )

    with patch("resend.Emails.send") as mock_send:
        mock_send.return_value = {"id": "resend_msg_002"}

        success, err = provider.send_password_reset_email(
            recipient_email="user@example.com",
            reset_url="https://app.fraudshield.ai/reset-password?token=secret123",
            expires_at=datetime.now(timezone.utc),
            recipient_name="Jane Doe",
        )

        assert success is True
        assert err is None
        mock_send.assert_called_once()
        params = mock_send.call_args[0][0]
        assert params["to"] == ["user@example.com"]
        assert "https://app.fraudshield.ai/reset-password?token=secret123" in params["html"]
        assert "FraudShield AI — Password Reset" in params["subject"]


def test_resend_send_transaction_otp_success(app):
    """Verify send_transaction_otp dispatches via Resend API."""
    provider = ResendEmailProvider(
        api_key="re_test_key",
        from_email="onboarding@resend.dev",
    )

    with patch("resend.Emails.send") as mock_send:
        mock_send.return_value = {"id": "resend_msg_003"}

        success, err = provider.send_transaction_otp(
            recipient_email="user@example.com",
            otp_code="987654",
            transaction_id=1055,
            amount=75000.0,
            recipient_name="Alex",
            expires_in_minutes=3,
        )

        assert success is True
        assert err is None
        mock_send.assert_called_once()
        params = mock_send.call_args[0][0]
        assert params["to"] == ["user@example.com"]
        assert "987 654" in params["html"] or "987654" in params["html"]
        assert "#1055" in params["subject"]


def test_resend_send_test_email_success(app):
    """Verify send_test_email dispatches via Resend API."""
    provider = ResendEmailProvider(
        api_key="re_test_key",
        from_email="onboarding@resend.dev",
    )

    with patch("resend.Emails.send") as mock_send:
        mock_send.return_value = {"id": "resend_msg_004"}

        success, err = provider.send_test_email("admin@example.com")
        assert success is True
        assert err is None
        mock_send.assert_called_once()


def test_resend_api_error_handling(app):
    """Verify provider captures Resend API errors without raising unhandled exceptions."""
    provider = ResendEmailProvider(
        api_key="re_invalid_key",
        from_email="onboarding@resend.dev",
    )

    with patch("resend.Emails.send") as mock_send:
        mock_send.side_effect = Exception("API key is invalid or unauthorized")

        success, err = provider.send_test_email("admin@example.com")
        assert success is False
        assert err is not None
        assert "API key is invalid" in err or "Exception" in err


def test_resend_missing_api_key(app):
    """Verify provider returns honest failure when RESEND_API_KEY is not set."""
    provider = ResendEmailProvider(api_key="")
    success, err = provider.send_test_email("admin@example.com")
    assert success is False
    assert "RESEND_API_KEY is not configured" in err


def test_factory_resolves_resend_provider(app):
    """Verify get_email_provider returns ResendEmailProvider when EMAIL_PROVIDER=resend."""
    app.config["EMAIL_PROVIDER"] = "resend"
    app.config["RESEND_API_KEY"] = "re_test_key_123"

    with app.app_context():
        provider = get_email_provider()
        assert isinstance(provider, ResendEmailProvider)
        assert provider.api_key == "re_test_key_123"


def test_health_email_endpoint_with_resend(app, client):
    """Verify /api/health/email reports Resend configuration safely."""
    app.config["EMAIL_PROVIDER"] = "resend"
    app.config["RESEND_API_KEY"] = "re_test_key_123"
    app.config["RESEND_FROM_EMAIL"] = "onboarding@resend.dev"

    res = client.get("/api/health/email")
    assert res.status_code == 200
    data = res.get_json()

    assert data["provider"] == "ResendEmailProvider"
    assert data["status"] == "configured"
    assert data["transport"] == "HTTPS REST API (api.resend.com:443)"
    assert data["api_key_configured"] is True
    assert data["from_email"] == "onboarding@resend.dev"
    assert "re_test_key_123" not in str(data)
