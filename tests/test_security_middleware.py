"""
Test Suite for Security Middleware, Structured Audit Logging, and OWASP Headers (Phase 3 Milestone 1).
"""

import json
import uuid
import logging
from datetime import datetime, timezone
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService
from app.utils.sanitizer import sanitize_data
from app.utils.logging_config import StructuredJSONFormatter


@pytest.fixture
def app_instance():
    """Create test application instance with in-memory SQLite database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


@pytest.fixture
def admin_user(app_instance):
    """Seed an administrator account."""
    admin = User(
        name="SOC Analyst",
        email="soc_analyst@fraudshield.com",
        role="ADMIN",
        is_active=True,
    )
    admin.set_password("AdminPass123!")
    db.session.add(admin)
    db.session.commit()
    return admin


@pytest.fixture
def regular_user(app_instance):
    """Seed a regular consumer account."""
    user = User(
        name="John Customer",
        email="john_sec@example.com",
        role="USER",
        account_balance=500000.0,
        is_active=True,
    )
    user.set_password("SecurePassword123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def admin_token(client, admin_user):
    """Generate JWT for admin."""
    res = client.post("/api/auth/login", json={
        "email": admin_user.email,
        "password": "AdminPass123!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def user_token(client, regular_user):
    """Generate JWT for regular user."""
    res = client.post("/api/auth/login", json={
        "email": regular_user.email,
        "password": "SecurePassword123!",
    })
    return res.get_json()["access_token"]


# ==============================================================================
# 1. OWASP Security Headers Verification
# ==============================================================================

def test_security_headers_present_on_api_routes(client):
    """Verify OWASP security headers on API routes."""
    res = client.get("/api/health")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in headers
    assert "max-age=" in headers.get("Strict-Transport-Security")
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers.get("Content-Security-Policy")
    assert "Permissions-Policy" in headers


def test_security_headers_present_on_html_routes(client):
    """Verify OWASP security headers on frontend HTML pages."""
    res = client.get("/login")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers


# ==============================================================================
# 2. X-Request-ID Correlation Middleware
# ==============================================================================

def test_x_request_id_generated_automatically(client):
    """Verify a UUIDv4 correlation ID is attached to responses when none is supplied."""
    res = client.get("/api/health")
    assert "X-Request-ID" in res.headers
    req_id = res.headers.get("X-Request-ID")
    # Verify it is valid UUID
    uuid_obj = uuid.UUID(req_id, version=4)
    assert str(uuid_obj) == req_id


def test_x_request_id_propagated_from_client(client):
    """Verify custom client X-Request-ID is preserved and propagated."""
    custom_id = "client-trace-987654321"
    res = client.get("/api/health", headers={"X-Request-ID": custom_id})
    assert res.headers.get("X-Request-ID") == custom_id


# ==============================================================================
# 3. Sanitizer & Redaction Tests
# ==============================================================================

def test_sanitizer_redacts_passwords_and_tokens():
    """Verify sensitive fields are strictly redacted from audit payloads."""
    payload = {
        "user": "alice@example.com",
        "password": "PlaintextPassword123!",
        "new_password": "AnotherSecretPassword!",
        "token": "secret_raw_reset_token_value",
        "otp": "123456",
        "nested": {
            "token_hash": "64_hex_chars_secret",
            "access_token": "jwt.header.payload.signature",
            "amount": 5000.0,
            "currency": "INR",
        },
    }

    sanitized = sanitize_data(payload)
    assert sanitized["user"] == "alice@example.com"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["new_password"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["otp"] == "[REDACTED]"
    assert sanitized["nested"]["token_hash"] == "[REDACTED]"
    assert sanitized["nested"]["access_token"] == "[REDACTED]"
    assert sanitized["nested"]["amount"] == 5000.0
    assert sanitized["nested"]["currency"] == "INR"


# ==============================================================================
# 4. Structured JSON Formatter Tests
# ==============================================================================

def test_structured_json_formatter_output():
    """Verify JSON formatter outputs valid JSON with expected fields."""
    formatter = StructuredJSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_file.py",
        lineno=42,
        msg="Test log message",
        args=(),
        exc_info=None,
    )
    record.request_id = "test-req-id"
    record.event_type = "TEST_EVENT"

    formatted_str = formatter.format(record)
    parsed = json.loads(formatted_str)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test_logger"
    assert parsed["message"] == "Test log message"
    assert parsed["request_id"] == "test-req-id"
    assert parsed["event_type"] == "TEST_EVENT"
    assert "timestamp" in parsed


# ==============================================================================
# 5. AuditLog Model & Service Tests
# ==============================================================================

def test_audit_log_model_creation(app_instance):
    """Verify AuditLog model fields, JSON serialization, and queries."""
    with app_instance.app_context():
        entry = AuditService.log_event(
            event_type="TEST_SECURITY_EVENT",
            actor="admin@fraudshield.com",
            action="TEST_ACTION",
            result="SUCCESS",
            severity="INFO",
            details={"key": "value", "count": 10},
            request_id="custom-uuid-1234",
        )
        assert entry is not None
        assert entry.id is not None
        assert entry.event_type == "TEST_SECURITY_EVENT"
        assert entry.request_id == "custom-uuid-1234"
        assert entry.details["key"] == "value"

        entry_dict = entry.to_dict()
        assert entry_dict["event_type"] == "TEST_SECURITY_EVENT"
        assert entry_dict["actor"] == "admin@fraudshield.com"
        assert entry_dict["details"] == {"key": "value", "count": 10}


# ==============================================================================
# 6. Audit Logging on Lifecycle Operations
# ==============================================================================

def test_audit_logging_on_login(client, regular_user):
    """Verify login success and failure generate structured audit records."""
    # Failed login
    client.post("/api/auth/login", json={
        "email": regular_user.email,
        "password": "WrongPassword!",
    })
    fail_log = AuditLog.query.filter_by(event_type="LOGIN_FAILED").first()
    assert fail_log is not None
    assert fail_log.actor == regular_user.email
    assert fail_log.result == "FAILURE"
    assert fail_log.severity == "WARN"

    # Successful login
    client.post("/api/auth/login", json={
        "email": regular_user.email,
        "password": "SecurePassword123!",
    })
    success_log = AuditLog.query.filter_by(event_type="LOGIN_SUCCESS").first()
    assert success_log is not None
    assert success_log.actor == regular_user.email
    assert success_log.result == "SUCCESS"
    assert success_log.severity == "INFO"


def test_audit_logging_on_user_registration(client):
    """Verify user registration generates USER_REGISTERED audit record."""
    client.post("/api/auth/register", json={
        "name": "New Audit User",
        "email": "new_audit@example.com",
        "password": "NewUserPassword123!",
    })

    reg_log = AuditLog.query.filter_by(event_type="USER_REGISTERED").first()
    assert reg_log is not None
    assert reg_log.actor == "new_audit@example.com"
    assert reg_log.result == "SUCCESS"


def test_audit_logging_on_password_reset(client, regular_user):
    """Verify password reset request and completion create audit records."""
    # Request reset
    client.post("/api/auth/forgot-password", json={
        "email": regular_user.email,
    })
    req_log = AuditLog.query.filter_by(event_type="PASSWORD_RESET_REQUESTED").first()
    assert req_log is not None
    assert req_log.actor == regular_user.email


def test_audit_logging_on_transaction_evaluation(client, user_token, regular_user):
    """Verify transaction processing generates TRANSACTION_EVALUATED audit record."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "destination": "merchant@fraudshield",
        },
    )
    assert res.status_code == 200

    tx_log = AuditLog.query.filter_by(event_type="TRANSACTION_EVALUATED").first()
    assert tx_log is not None
    assert tx_log.actor == regular_user.email
    assert tx_log.user_id == regular_user.id
    assert tx_log.details["type"] == "PAYMENT"
    assert tx_log.details["amount"] == 250.0


def test_audit_logging_on_otp_operations(client, user_token, regular_user):
    """Verify OTP request and verify generate audit records without leaking OTP values."""
    # High-amount payment to trigger OTP
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "type": "TRANSFER",
            "amount": 75000.0,
            "destination": "friend@fraudshield",
        },
    )
    assert res.status_code == 200
    tx_id = res.get_json()["transaction_id"]

    # Request OTP challenge
    otp_req = client.post(
        "/api/otp/generate",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"transaction_id": tx_id},
    )
    assert otp_req.status_code == 200
    dev_otp = otp_req.get_json().get("_dev_simulated_otp")

    otp_log = AuditLog.query.filter_by(event_type="OTP_REQUESTED").first()
    assert otp_log is not None
    assert otp_log.target_resource == f"Transaction:{tx_id}"
    # Verify OTP value is NOT in details
    assert "otp" not in str(otp_log.details_json)
    assert "otp_code" not in str(otp_log.details_json)

    # Verify OTP
    if dev_otp:
        verify_req = client.post(
            "/api/otp/verify",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"transaction_id": tx_id, "otp_code": dev_otp},
        )
        assert verify_req.status_code == 200
        verify_log = AuditLog.query.filter_by(event_type="OTP_VERIFIED").first()
        assert verify_log is not None
        assert verify_log.result == "SUCCESS"
        assert "otp_code" not in str(verify_log.details_json)


def test_audit_logging_on_alert_resolution(client, admin_token, user_token, regular_user):
    """Verify alert resolution generates ALERT_RESOLVED audit record."""
    # Trigger critical transaction creating an alert
    client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "type": "TRANSFER",
            "amount": 250000.0,
            "destination": "suspicious@fraudshield",
        },
    )

    from app.models.alert import Alert
    alert = Alert.query.first()
    assert alert is not None

    # Resolve alert
    resolve_res = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"note": "Verified genuine high-value transfer with customer."},
    )
    assert resolve_res.status_code == 200

    alert_log = AuditLog.query.filter_by(event_type="ALERT_RESOLVED").first()
    assert alert_log is not None
    assert alert_log.actor == "soc_analyst@fraudshield.com"
    assert alert_log.details["note"] == "Verified genuine high-value transfer with customer."


# ==============================================================================
# 7. Admin Audit Log Query API Tests
# ==============================================================================

def test_admin_audit_logs_endpoint_authorized(client, admin_token, app_instance):
    """Verify admin can query paginated audit logs via /api/admin/audit-logs."""
    with app_instance.app_context():
        AuditService.log_event(
            event_type="SYSTEM_MAINTENANCE",
            actor="admin@fraudshield.com",
            action="REBOOT",
            severity="WARN",
        )

    res = client.get(
        "/api/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] >= 1
    assert isinstance(data["logs"], list)


def test_admin_audit_logs_forbidden_for_regular_users(client, user_token):
    """Verify regular consumer account cannot access /api/admin/audit-logs."""
    res = client.get(
        "/api/admin/audit-logs",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 403


def test_admin_audit_logs_filtering(client, admin_token, app_instance):
    """Verify filtering by event_type and severity."""
    with app_instance.app_context():
        AuditService.log_event(
            event_type="CUSTOM_FILTER_EVENT",
            actor="special_actor@fraudshield.com",
            action="FILTER_ACTION",
            severity="CRITICAL",
        )

    res = client.get(
        "/api/admin/audit-logs?event_type=CUSTOM_FILTER_EVENT&severity=CRITICAL",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] == 1
    assert data["logs"][0]["event_type"] == "CUSTOM_FILTER_EVENT"
    assert data["logs"][0]["severity"] == "CRITICAL"
