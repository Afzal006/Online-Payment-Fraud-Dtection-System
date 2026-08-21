"""
Test Suite for Device Intelligence, Trust Scoring, and Adaptive Authentication (Phase 3 Milestone 2).
"""

import json
import pytest
from datetime import datetime, timezone
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.device_profile import DeviceProfile
from app.models.audit_log import AuditLog
from app.services.device_trust_service import DeviceTrustService
from app.services.risk_signal_service import RiskSignalService
from app.utils.device_fingerprint import compute_device_hash, parse_user_agent, compute_ip_hash


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
def test_user(app_instance):
    """Create standard customer user."""
    user = User(
        name="Device Test User",
        email="device_user@example.com",
        role="USER",
        account_balance=100000.0,
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
    )
    user.set_password("SecurePassword123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def second_user(app_instance):
    """Create second customer user for tenant isolation testing."""
    user = User(
        name="Second Customer",
        email="second_user@example.com",
        role="USER",
        account_balance=50000.0,
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
    )
    user.set_password("SecurePassword123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def admin_user(app_instance):
    """Create admin user."""
    admin = User(
        name="SOC Admin",
        email="soc_admin@fraudshield.com",
        role="ADMIN",
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
    )
    admin.set_password("AdminSecurePassword123!")
    db.session.add(admin)
    db.session.commit()
    return admin


@pytest.fixture
def user_token(client, test_user):
    res = client.post("/api/auth/login", json={
        "email": test_user.email,
        "password": "SecurePassword123!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def admin_token(client, admin_user):
    res = client.post("/api/auth/login", json={
        "email": admin_user.email,
        "password": "AdminSecurePassword123!",
    })
    return res.get_json()["access_token"]


# ==============================================================================
# 1. Device Fingerprinting & Telemetry Parsing Tests
# ==============================================================================

def test_user_agent_parsing():
    """Verify parsing of various User-Agent strings into normalized components."""
    # Chrome on Windows
    chrome_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    parsed1 = parse_user_agent(chrome_win)
    assert parsed1["browser"] == "Chrome"
    assert parsed1["operating_system"] == "Windows"
    assert parsed1["device_type"] == "Desktop"

    # Safari on iPhone
    iphone_safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    parsed2 = parse_user_agent(iphone_safari)
    assert parsed2["browser"] == "Safari"
    assert parsed2["operating_system"] == "iOS"
    assert parsed2["device_type"] == "Mobile"

    # Firefox on Linux
    linux_ff = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"
    parsed3 = parse_user_agent(linux_ff)
    assert parsed3["browser"] == "Firefox"
    assert parsed3["operating_system"] == "Linux"
    assert parsed3["device_type"] == "Desktop"


def test_device_hash_pseudonymization():
    """Verify device hash generation is deterministic, irreversible, and length-64."""
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"
    telemetry = {"screen": "2560x1440", "timezone": "Asia/Kolkata", "language": "en-US"}

    hash1 = compute_device_hash(ua, telemetry)
    hash2 = compute_device_hash(ua, telemetry)
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex string

    # Different telemetry yields different hash
    hash3 = compute_device_hash(ua, {"screen": "1920x1080", "timezone": "Europe/London"})
    assert hash1 != hash3


# ==============================================================================
# 2. Device Registration & Trust Lifecycle Tests
# ==============================================================================

def test_device_registration_on_first_login(client, test_user):
    """Verify first login creates a DeviceProfile with UNKNOWN trust status."""
    ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"
    res = client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )
    assert res.status_code == 200

    profile = DeviceProfile.query.filter_by(user_id=test_user.id).first()
    assert profile is not None
    assert profile.browser == "Chrome"
    assert profile.operating_system == "Windows"
    assert profile.trust_status == "UNKNOWN"
    assert profile.successful_login_count == 1
    assert profile.failed_login_count == 0


def test_device_promotion_to_trusted(client, test_user):
    """Verify second successful login promotes device from UNKNOWN to TRUSTED."""
    ua_string = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"

    # Login 1
    client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )
    profile = DeviceProfile.query.filter_by(user_id=test_user.id).first()
    assert profile.trust_status == "UNKNOWN"
    assert profile.successful_login_count == 1

    # Login 2
    client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )
    db.session.refresh(profile)
    assert profile.trust_status == "TRUSTED"
    assert profile.successful_login_count == 2


def test_failed_login_demotes_device_to_suspicious(client, test_user):
    """Verify consecutive failed logins demote a trusted device to SUSPICIOUS."""
    ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/129.0"

    # 2 successful logins to make it trusted
    for _ in range(2):
        client.post(
            "/api/auth/login",
            headers={"User-Agent": ua_string},
            json={"email": test_user.email, "password": "SecurePassword123!"},
        )
    profile = DeviceProfile.query.filter_by(user_id=test_user.id).first()
    assert profile.trust_status == "TRUSTED"

    # 3 failed logins
    for _ in range(3):
        client.post(
            "/api/auth/login",
            headers={"User-Agent": ua_string},
            json={"email": test_user.email, "password": "WrongPassword!"},
        )

    db.session.refresh(profile)
    assert profile.failed_login_count == 3
    assert profile.trust_status == "SUSPICIOUS"


def test_blocked_device_denies_authentication(client, test_user, app_instance):
    """Verify access from a BLOCKED device is strictly denied."""
    ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/128.0.0.0"

    # Register device
    client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )
    profile = DeviceProfile.query.filter_by(user_id=test_user.id).first()

    # Block device
    profile.trust_status = "BLOCKED"
    profile.is_active = False
    db.session.commit()

    # Attempt login from blocked device
    res = client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )
    assert res.status_code == 401
    assert "blocked" in res.get_json()["error"].lower()


# ==============================================================================
# 3. Fraud Risk Engine & UNKNOWN_DEVICE_LOGIN Signal Tests
# ==============================================================================

def test_unknown_device_triggers_risk_signal():
    """Verify RiskSignalService generates UNKNOWN_DEVICE_LOGIN signal (+25 weight)."""
    features = {
        "amount": 2500.0,
        "tx_type": "PAYMENT",
        "is_unknown_device": 1,
        "device_trust_status": "UNKNOWN",
    }
    signals = RiskSignalService.evaluate_signals(features)
    codes = [s["code"] for s in signals]
    assert "UNKNOWN_DEVICE_LOGIN" in codes

    unknown_sig = next(s for s in signals if s["code"] == "UNKNOWN_DEVICE_LOGIN")
    assert unknown_sig["weight"] == 25
    assert unknown_sig["severity"] == "MEDIUM"


def test_suspicious_device_triggers_high_severity_signal():
    """Verify SUSPICIOUS device triggers HIGH severity signal."""
    features = {
        "amount": 2500.0,
        "tx_type": "PAYMENT",
        "is_unknown_device": 1,
        "device_trust_status": "SUSPICIOUS",
    }
    signals = RiskSignalService.evaluate_signals(features)
    unknown_sig = next(s for s in signals if s["code"] == "UNKNOWN_DEVICE_LOGIN")
    assert unknown_sig["severity"] == "HIGH"
    assert unknown_sig["weight"] == 25


def test_transaction_from_blocked_device_rejected(client, user_token, test_user):
    """Verify transaction from a BLOCKED device profile is rejected with 403."""
    ua_blocked = "Mozilla/5.0 (Linux; Android 14) Chrome/128.0.0.0"

    # Pre-register and block device
    with client.application.app_context():
        profile, status, _ = DeviceTrustService.evaluate_or_register_device(
            user_id=test_user.id,
            user_agent=ua_blocked,
        )
        profile.trust_status = "BLOCKED"
        profile.is_active = False
        db.session.commit()

    res = client.post(
        "/api/transactions/predict",
        headers={
            "Authorization": f"Bearer {user_token}",
            "User-Agent": ua_blocked,
        },
        json={
            "type": "PAYMENT",
            "amount": 100.0,
            "destination": "merchant@fraudshield",
        },
    )
    assert res.status_code == 403
    assert "blocked" in res.get_json()["error"].lower()


# ==============================================================================
# 4. Customer Device Management API Tests
# ==============================================================================

def test_customer_get_devices_list(client, user_token, test_user):
    """Verify GET /api/profile/devices returns active devices without leaking hash."""
    ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"
    ua2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Safari/605.1.15"

    DeviceTrustService.evaluate_or_register_device(user_id=test_user.id, user_agent=ua1)
    DeviceTrustService.evaluate_or_register_device(user_id=test_user.id, user_agent=ua2)

    res = client.get(
        "/api/profile/devices",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] >= 2

    # Verify safe fields and NO raw device_hash in customer response
    for dev in data["devices"]:
        assert "browser" in dev
        assert "operating_system" in dev
        assert "trust_status" in dev
        assert "device_hash" not in dev
        assert "password" not in dev


def test_customer_device_isolation_idor_protection(client, user_token, second_user):
    """Verify a user cannot revoke another user's device (IDOR protection)."""
    # Create device for second_user
    foreign_dev, _, _ = DeviceTrustService.evaluate_or_register_device(
        user_id=second_user.id,
        user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/128.0.0.0",
    )

    # First user attempts to revoke second user's device
    res = client.post(
        f"/api/profile/devices/{foreign_dev.id}/revoke",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 403


def test_customer_revoke_own_device(client, user_token, test_user):
    """Verify user can deactivate their own registered device."""
    dev, _, _ = DeviceTrustService.evaluate_or_register_device(
        user_id=test_user.id,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/129.0",
    )

    res = client.post(
        f"/api/profile/devices/{dev.id}/revoke",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200

    db.session.refresh(dev)
    assert dev.is_active is False
    assert dev.trust_status == "UNKNOWN"


# ==============================================================================
# 5. Admin / SOC Device Governance API Tests
# ==============================================================================

def test_admin_get_customer_devices(client, admin_token, test_user):
    """Verify admin can view customer devices with full telemetry."""
    DeviceTrustService.evaluate_or_register_device(
        user_id=test_user.id,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
    )

    res = client.get(
        f"/api/admin/customers/{test_user.id}/devices",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["customer_id"] == test_user.id
    assert data["total"] >= 1
    assert "failed_login_count" in data["devices"][0]


def test_admin_update_device_trust(client, admin_token, test_user):
    """Verify admin can manually update device trust status."""
    dev, _, _ = DeviceTrustService.evaluate_or_register_device(
        user_id=test_user.id,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
    )

    res = client.post(
        f"/api/admin/devices/{dev.id}/trust",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"trust_status": "BLOCKED"},
    )
    assert res.status_code == 200
    assert res.get_json()["new_trust_status"] == "BLOCKED"

    db.session.refresh(dev)
    assert dev.trust_status == "BLOCKED"
    assert dev.is_active is False


# ==============================================================================
# 6. Audit Logging Verification
# ==============================================================================

def test_device_audit_logging_events(client, test_user):
    """Verify DEVICE_REGISTERED, UNKNOWN_DEVICE_LOGIN, and DEVICE_TRUST_CHANGED logs."""
    ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"

    # 1. Login 1 -> DEVICE_REGISTERED & UNKNOWN_DEVICE_LOGIN
    client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )

    reg_log = AuditLog.query.filter_by(event_type="DEVICE_REGISTERED").first()
    assert reg_log is not None
    assert reg_log.actor == test_user.email

    unknown_log = AuditLog.query.filter_by(event_type="UNKNOWN_DEVICE_LOGIN").first()
    assert unknown_log is not None
    assert unknown_log.severity == "WARN"

    # 2. Login 2 -> DEVICE_TRUST_CHANGED (promotion to TRUSTED)
    client.post(
        "/api/auth/login",
        headers={"User-Agent": ua_string},
        json={"email": test_user.email, "password": "SecurePassword123!"},
    )

    trust_log = AuditLog.query.filter_by(event_type="DEVICE_TRUST_CHANGED").first()
    assert trust_log is not None
    assert trust_log.details["new_trust_status"] == "TRUSTED"
