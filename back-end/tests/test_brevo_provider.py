"""
Unit and Integration Tests for Brevo HTTPS Email REST API Provider.

Tests all operations using mocked Brevo API HTTP calls (zero network leak):
1. BrevoEmailProvider configuration & diagnostics (no secret leakage).
2. Registration verification OTP email dispatch.
3. Password reset email dispatch.
4. Transaction step-up OTP challenge email dispatch.
5. Diagnostic test email dispatch.
6. Error handling when API key is missing or Brevo API returns an HTTP error.
7. Factory get_email_provider() resolution with EMAIL_PROVIDER=brevo.
8. /api/health/email reporting for Brevo provider.
"""

from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import pytest
from app import create_app
from app.providers.email_provider import (
    BrevoEmailProvider,
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


def test_brevo_provider_diagnostics_hides_api_key(app):
    """Verify get_diagnostics reports status without exposing the API key secret."""
    provider = BrevoEmailProvider(
        api_key="xkeysib-secret-123456789",
        from_email="teamfraudsheildai@gmail.com",
        from_name="FraudShield AI Security",
    )
    diag = provider.get_diagnostics()

    assert diag["provider"] == "BrevoEmailProvider"
    assert diag["api_key_configured"] is True
    assert diag["from_email"] == "teamfraudsheildai@gmail.com"
    assert diag["from_name"] == "FraudShield AI Security"
    assert "xkeysib-secret-123456789" not in str(diag)


def test_brevo_send_email_verification_otp_success(app):
    """Verify send_email_verification_otp formats message and calls Brevo HTTPS endpoint."""
    provider = BrevoEmailProvider(
        api_key="xkeysib-test-key",
        from_email="teamfraudsheildai@gmail.com",
        from_name="FraudShield AI Security",
    )

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"messageId": "<brevo-msg-001@smtp-relay.mailin.fr>"}
        mock_resp.content = b'{"messageId": "123"}'
        mock_post.return_value = mock_resp

        success, err = provider.send_email_verification_otp(
            recipient_email="user@example.com",
            otp_code="654321",
            recipient_name="John Doe",
            verification_url="https://app.fraudshield.ai/verify?token=abc",
            expires_in_minutes=5,
        )

        assert success is True
        assert err is None
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://api.brevo.com/v3/smtp/email"
        assert kwargs["headers"]["api-key"] == "xkeysib-test-key"
        payload = kwargs["json"]
        assert payload["to"] == [{"email": "user@example.com", "name": "John Doe"}]
        assert payload["sender"]["email"] == "teamfraudsheildai@gmail.com"
        assert "654 321" in payload["htmlContent"] or "654321" in payload["htmlContent"]
        assert "654321" in payload["textContent"]
        assert "FraudShield AI — Verify Your Email Address" in payload["subject"]


def test_brevo_send_password_reset_email_success(app):
    """Verify send_password_reset_email dispatches via Brevo API."""
    provider = BrevoEmailProvider(
        api_key="xkeysib-test-key",
        from_email="teamfraudsheildai@gmail.com",
    )

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"messageId": "<brevo-msg-002@smtp-relay.mailin.fr>"}
        mock_resp.content = b'{"messageId": "456"}'
        mock_post.return_value = mock_resp

        success, err = provider.send_password_reset_email(
            recipient_email="user@example.com",
            reset_url="https://app.fraudshield.ai/reset-password?token=secret123",
            expires_at=datetime.now(timezone.utc),
            recipient_name="Jane Doe",
        )

        assert success is True
        assert err is None
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["to"] == [{"email": "user@example.com", "name": "Jane Doe"}]
        assert "https://app.fraudshield.ai/reset-password?token=secret123" in payload["htmlContent"]
        assert "FraudShield AI — Password Reset" in payload["subject"]


def test_brevo_send_transaction_otp_success(app):
    """Verify send_transaction_otp dispatches via Brevo API."""
    provider = BrevoEmailProvider(
        api_key="xkeysib-test-key",
        from_email="teamfraudsheildai@gmail.com",
    )

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"messageId": "<brevo-msg-003@smtp-relay.mailin.fr>"}
        mock_resp.content = b'{"messageId": "789"}'
        mock_post.return_value = mock_resp

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
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["to"] == [{"email": "user@example.com", "name": "Alex"}]
        assert "987 654" in payload["htmlContent"] or "987654" in payload["htmlContent"]
        assert "#1055" in payload["subject"]


def test_brevo_send_test_email_success(app):
    """Verify send_test_email dispatches via Brevo API."""
    provider = BrevoEmailProvider(
        api_key="xkeysib-test-key",
        from_email="teamfraudsheildai@gmail.com",
    )

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"messageId": "<brevo-msg-004@smtp-relay.mailin.fr>"}
        mock_resp.content = b'{"messageId": "101"}'
        mock_post.return_value = mock_resp

        success, err = provider.send_test_email("admin@example.com")
        assert success is True
        assert err is None
        mock_post.assert_called_once()


def test_brevo_api_error_handling(app):
    """Verify provider captures Brevo API error responses without unhandled crashes."""
    provider = BrevoEmailProvider(
        api_key="xkeysib-invalid-key",
        from_email="teamfraudsheildai@gmail.com",
    )

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"message": "Key not found", "code": "unauthorized"}
        mock_resp.content = b'{"message": "Key not found"}'
        mock_post.return_value = mock_resp

        success, err = provider.send_test_email("admin@example.com")
        assert success is False
        assert err is not None
        assert "HTTP 401" in err
        assert "Key not found" in err


def test_brevo_missing_api_key(app):
    """Verify provider returns honest failure when BREVO_API_KEY is not set."""
    provider = BrevoEmailProvider(api_key="")
    success, err = provider.send_test_email("admin@example.com")
    assert success is False
    assert "BREVO_API_KEY" in err


def test_factory_resolves_brevo_provider(app):
    """Verify get_email_provider returns BrevoEmailProvider when EMAIL_PROVIDER=brevo."""
    app.config["EMAIL_PROVIDER"] = "brevo"
    app.config["BREVO_API_KEY"] = "xkeysib-test-key-123"

    with app.app_context():
        provider = get_email_provider()
        assert isinstance(provider, BrevoEmailProvider)
        assert provider.api_key == "xkeysib-test-key-123"


def test_health_email_endpoint_with_brevo(app, client):
    """Verify /api/health/email reports Brevo configuration safely without leaking key."""
    app.config["EMAIL_PROVIDER"] = "brevo"
    app.config["BREVO_API_KEY"] = "xkeysib-test-key-123"
    app.config["BREVO_FROM_EMAIL"] = "teamfraudsheildai@gmail.com"

    res = client.get("/api/health/email")
    assert res.status_code == 200
    data = res.get_json()

    assert data["provider"] == "BrevoEmailProvider"
    assert data["status"] == "configured"
    assert data["transport"] == "HTTPS REST API (api.brevo.com:443)"
    assert data["api_key_configured"] is True
    assert data["from_email"] == "teamfraudsheildai@gmail.com"
    assert "xkeysib-test-key-123" not in str(data)
