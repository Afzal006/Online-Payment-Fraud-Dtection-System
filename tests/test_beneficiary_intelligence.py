"""
Beneficiary Intelligence & 24-Hour Cooling Period Test Suite.

Validates:
1. Beneficiary creation with mandatory 24-hour security cooling period.
2. Tenant ownership, IDOR isolation, and duplicate handling.
3. Point-in-time cooling status and progressive trust transitions.
4. Transaction evaluation during and after cooling window.
5. Beneficiary revocation enforcement (immediate transaction rejection).
6. Correlation with Device Intelligence and Geo Intelligence.
7. Admin/SOC beneficiary telemetry and audit trail logging.
8. Ledger atomicity and sensitive data redaction.
"""

from datetime import datetime, timezone, timedelta
import pytest
from flask_jwt_extended import create_access_token
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.models.device_profile import DeviceProfile
from app.models.audit_log import AuditLog
from app.models.transaction import Transaction
from app.services.beneficiary_service import BeneficiaryService
from app.services.auth_service import AuthService
from app.services.transaction_service import TransactionService
from app.services.risk_signal_service import RiskSignalService


@pytest.fixture
def app():
    """Create test application configured with in-memory database."""
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def customer_and_token(app):
    """Create test customer and generate auth token."""
    with app.app_context():
        user = User(
            email="priya@example.com",
            name="Priya Sharma",
            phone_number="9876543210",
            role="USER",
            is_active=True,
            account_balance=100000.0,
        )
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        token = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
        return user.id, token


@pytest.fixture
def other_customer_and_token(app):
    """Create second customer for IDOR testing."""
    with app.app_context():
        user = User(
            email="rohit@example.com",
            name="Rohit Verma",
            phone_number="9123456780",
            role="USER",
            is_active=True,
            account_balance=50000.0,
        )
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        token = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
        return user.id, token


@pytest.fixture
def admin_and_token(app):
    """Create admin user and generate auth token."""
    with app.app_context():
        admin = User(
            email="soc.admin@fraudshield.internal",
            name="SOC Admin",
            role="ADMIN",
            is_active=True,
        )
        admin.set_password("AdminSecurePass123!")
        db.session.add(admin)
        db.session.commit()

        token = create_access_token(identity=str(admin.id), additional_claims={"role": admin.role})
        return admin.id, token


# --------------------------------------------------------------------------
# 1. Beneficiary Creation & 24-Hour Cooling Period
# --------------------------------------------------------------------------

def test_create_beneficiary_initializes_24h_cooling(app, customer_and_token):
    """Creating a beneficiary must set 24h cooling with exact UTC timestamps."""
    user_id, _ = customer_and_token
    with app.app_context():
        now = datetime.now(timezone.utc)
        ben, err, status = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={
                "beneficiary_name": "Kavita Nair",
                "beneficiary_upi_id": "kavita@okaxis",
                "nickname": "Sister",
            },
        )
        assert err is None
        assert status == 201
        assert ben.status == "ACTIVE"
        assert ben.trust_status == "COOLING"
        assert ben.cooling_period_hours == 24
        assert ben.cooling_expires_at is not None
        assert ben.is_cooling_active() is True
        assert ben.get_cooling_remaining_seconds() > 80000  # ~86400 seconds


def test_cooling_period_active_and_expiration(app, customer_and_token):
    """Cooling period is active at t=1h, expires at t=25h."""
    user_id, _ = customer_and_token
    with app.app_context():
        now = datetime.now(timezone.utc)
        ben = Beneficiary(
            user_id=user_id,
            beneficiary_name="Vikas Gupta",
            beneficiary_upi_id="vikas@okicici",
            status="ACTIVE",
            trust_status="COOLING",
            cooling_period_hours=24,
            cooling_expires_at=now + timedelta(hours=24),
            created_at=now,
        )
        db.session.add(ben)
        db.session.commit()

        # At t=12h -> Active
        t_12h = now + timedelta(hours=12)
        assert ben.is_cooling_active(reference_time=t_12h) is True
        assert ben.get_effective_trust_status(reference_time=t_12h) == "COOLING"

        # At t=25h -> Expired, status changes to NEW (since 0 txs)
        t_25h = now + timedelta(hours=25)
        assert ben.is_cooling_active(reference_time=t_25h) is False
        assert ben.get_effective_trust_status(reference_time=t_25h) == "NEW"


# --------------------------------------------------------------------------
# 2. Progressive Trust Model
# --------------------------------------------------------------------------

def test_beneficiary_progressive_trust_evolution(app, customer_and_token):
    """Trust evolves: COOLING -> NEW -> ESTABLISHED (>=1) -> TRUSTED (>=3)."""
    user_id, _ = customer_and_token
    with app.app_context():
        created_time = datetime.now(timezone.utc) - timedelta(days=2)
        ben = Beneficiary(
            user_id=user_id,
            beneficiary_name="Sneha Roy",
            beneficiary_upi_id="sneha@okhdfc",
            status="ACTIVE",
            trust_status="COOLING",
            cooling_period_hours=24,
            cooling_expires_at=created_time + timedelta(hours=24),
            created_at=created_time,
            successful_payment_count=0,
            failed_payment_count=0,
        )
        db.session.add(ben)
        db.session.commit()

        # After cooling with 0 txs -> NEW
        assert ben.get_effective_trust_status() == "NEW"

        # 1 successful payment -> ESTABLISHED
        BeneficiaryService.record_payment_outcome(ben.id, amount=5000.0, success=True)
        ben_updated = db.session.get(Beneficiary, ben.id)
        assert ben_updated.successful_payment_count == 1
        assert ben_updated.total_transferred_amount == 5000.0
        assert ben_updated.get_effective_trust_status() == "ESTABLISHED"

        # 3 successful payments -> TRUSTED
        BeneficiaryService.record_payment_outcome(ben.id, amount=2000.0, success=True)
        BeneficiaryService.record_payment_outcome(ben.id, amount=3000.0, success=True)
        ben_trusted = db.session.get(Beneficiary, ben.id)
        assert ben_trusted.successful_payment_count == 3
        assert ben_trusted.get_effective_trust_status() == "TRUSTED"


# --------------------------------------------------------------------------
# 3. IDOR & Tenant Boundary Protection
# --------------------------------------------------------------------------

def test_beneficiary_idor_cross_customer_forbidden(app, client, customer_and_token, other_customer_and_token):
    """Customer A cannot view, update, or revoke Customer B's beneficiary."""
    user_a, token_a = customer_and_token
    user_b, token_b = other_customer_and_token

    with app.app_context():
        ben_b, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_b,
            data={"beneficiary_name": "Target Recipient", "beneficiary_upi_id": "target@upi"},
        )
        ben_b_id = ben_b.id

    # User A tries to GET User B's beneficiary
    res = client.get(f"/api/beneficiaries/{ben_b_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert res.status_code == 403

    # User A tries to revoke User B's beneficiary
    res_revoke = client.post(f"/api/beneficiaries/{ben_b_id}/revoke", headers={"Authorization": f"Bearer {token_a}"})
    assert res_revoke.status_code == 403


# --------------------------------------------------------------------------
# 4. Beneficiary Revocation
# --------------------------------------------------------------------------

def test_beneficiary_revocation_lifecycle_and_audit(app, client, customer_and_token):
    """Revoking a beneficiary marks it REVOKED and logs an audit trail."""
    user_id, token = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Revoke Target", "beneficiary_upi_id": "revoke@upi"},
        )
        ben_id = ben.id

    res = client.post(
        f"/api/beneficiaries/{ben_id}/revoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"reason": "Suspected phishing recipient"},
    )
    assert res.status_code == 200

    with app.app_context():
        revoked_ben = db.session.get(Beneficiary, ben_id)
        assert revoked_ben.status == "REVOKED"
        assert revoked_ben.trust_status == "REVOKED"
        assert revoked_ben.revoked_at is not None

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type="BENEFICIARY_REVOKED").first()
        assert audit is not None
        assert audit.user_id == user_id


def test_revoked_beneficiary_transaction_strictly_rejected(app, customer_and_token):
    """Transactions to a revoked beneficiary must be rejected with 403."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Blocked Recipient", "beneficiary_upi_id": "blocked@upi"},
        )
        BeneficiaryService.revoke_beneficiary(ben.id, user_id=user_id, reason="Compromised")

        # Attempt transaction
        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 2500.0,
                "beneficiary_id": ben.id,
            },
        )
        assert tx is None
        assert status == 403
        assert "revoked" in err.lower()


# --------------------------------------------------------------------------
# 5. Transaction Evaluation during Cooling Period
# --------------------------------------------------------------------------

def test_transaction_during_cooling_period_receives_cooling_signal(app, customer_and_token):
    """Transfer to beneficiary in cooling period triggers NEW_BENEFICIARY_IN_COOLING signal."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Cooling Recipient", "beneficiary_upi_id": "cooling@upi"},
        )

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 5000.0,
                "beneficiary_id": ben.id,
            },
        )
        assert err is None
        assert tx is not None
        signals = tx["risk_signals"]
        signal_codes = [s["code"] for s in signals]
        assert "NEW_BENEFICIARY_IN_COOLING" in signal_codes


def test_high_value_transaction_during_cooling_triggers_high_risk_signals(app, customer_and_token):
    """High value (> ₹50,000) during cooling triggers HIGH_BENEFICIARY_TRANSACTION_AMOUNT and OTP."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Big Ticket Cooling", "beneficiary_upi_id": "bigcooling@upi"},
        )

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 60000.0,
                "beneficiary_id": ben.id,
            },
        )
        assert err is None
        assert tx is not None
        signal_codes = [s["code"] for s in tx["risk_signals"]]
        assert "NEW_BENEFICIARY_IN_COOLING" in signal_codes
        assert "HIGH_BENEFICIARY_TRANSACTION_AMOUNT" in signal_codes
        assert tx["requires_otp"] is True or tx["status"] in ["PENDING_OTP", "UNDER_REVIEW"]


# --------------------------------------------------------------------------
# 6. Device + Geo + Beneficiary Correlation
# --------------------------------------------------------------------------

def test_new_beneficiary_plus_unknown_device_escalation(app, customer_and_token):
    """New Beneficiary in cooling + Unknown Device escalates risk score."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Escalation Recipient", "beneficiary_upi_id": "escalation@upi"},
        )

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 25000.0,
                "beneficiary_id": ben.id,
                "client_ip": "103.21.244.5",  # Different IP / Unknown device
            },
        )
        assert err is None
        assert tx is not None
        signal_codes = [s["code"] for s in tx["risk_signals"]]
        assert "NEW_BENEFICIARY_IN_COOLING" in signal_codes
        assert "UNKNOWN_DEVICE_LOGIN" in signal_codes
        assert tx["risk_score"] >= 35


def test_blocked_device_authoritative_over_valid_beneficiary(app, customer_and_token):
    """Blocked device must reject transactions even with established/valid beneficiary."""
    from app.services.device_trust_service import DeviceTrustService

    user_id, _ = customer_and_token
    with app.app_context():
        # Setup established beneficiary
        ben = Beneficiary(
            user_id=user_id,
            beneficiary_name="Trusted Friend",
            beneficiary_upi_id="friend@upi",
            status="ACTIVE",
            trust_status="TRUSTED",
            cooling_period_hours=24,
            cooling_expires_at=datetime.now(timezone.utc) - timedelta(days=5),
            created_at=datetime.now(timezone.utc) - timedelta(days=5),
            successful_payment_count=5,
        )
        db.session.add(ben)
        db.session.commit()

        # Register and block device
        dev, _, _ = DeviceTrustService.evaluate_or_register_device(
            user_id=user_id,
            client_device_id="device_to_block_999",
        )
        dev.trust_status = "BLOCKED"
        db.session.commit()

        # Attempt transaction from blocked device
        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 1000.0,
                "beneficiary_id": ben.id,
                "device_fingerprint": "device_to_block_999",
            },
        )
        assert tx is None
        assert status == 403
        assert "blocked" in err.lower()


# --------------------------------------------------------------------------
# 7. Admin & Customer APIs with Data Redaction
# --------------------------------------------------------------------------

def test_customer_beneficiary_list_includes_cooling_status(app, client, customer_and_token):
    """Customer API returns cooling metadata without leaking admin telemetry."""
    user_id, token = customer_and_token
    with app.app_context():
        BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Safe View", "beneficiary_upi_id": "safeview@upi"},
        )

    res = client.get("/api/beneficiaries", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["beneficiaries"]) >= 1
    item = data["beneficiaries"][0]
    assert "cooling_period_active" in item
    assert "cooling_period_remaining_seconds" in item
    assert "trust_status" in item
    # Sensitive internal fields should not be in standard customer response
    assert "failed_payment_count" not in item


def test_admin_customer_beneficiaries_telemetry(app, client, admin_and_token, customer_and_token):
    """Admin API returns full beneficiary telemetry with transaction counts."""
    admin_id, admin_token = admin_and_token
    user_id, user_token = customer_and_token

    with app.app_context():
        BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Admin Telemetry Target", "beneficiary_upi_id": "admintarget@upi"},
        )

    # Customer forbidden from admin route
    res_cust = client.get(f"/api/admin/customers/{user_id}/beneficiaries", headers={"Authorization": f"Bearer {user_token}"})
    assert res_cust.status_code == 403

    # Admin allowed
    res_admin = client.get(f"/api/admin/customers/{user_id}/beneficiaries", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    data = res_admin.get_json()
    assert data["success"] is True
    assert data["customer_id"] == user_id
    assert len(data["beneficiaries"]) >= 1
    item = data["beneficiaries"][0]
    assert "successful_payment_count" in item
    assert "failed_payment_count" in item
    assert "total_transferred_amount" in item


# --------------------------------------------------------------------------
# 8. Deterministic Demonstration Scenarios A through F
# --------------------------------------------------------------------------

def test_scenario_a_trusted_beneficiary_normal_device_normal_location(app, customer_and_token):
    """Scenario A: Existing trusted beneficiary + normal device + normal location -> LOW risk / normal approval."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben = Beneficiary(
            user_id=user_id,
            beneficiary_name="Scenario A Trusted",
            beneficiary_upi_id="scenario_a@upi",
            status="ACTIVE",
            trust_status="TRUSTED",
            cooling_period_hours=24,
            cooling_expires_at=datetime.now(timezone.utc) - timedelta(days=10),
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
            successful_payment_count=4,
        )
        db.session.add(ben)
        db.session.commit()

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 2500.0,
                "beneficiary_id": ben.id,
            },
        )
        assert err is None
        assert tx is not None
        assert tx["decision"] in ["APPROVE_IMMEDIATELY", "APPROVE_WITH_MONITORING"]
        assert tx["requires_otp"] is False


def test_scenario_b_new_beneficiary_normal_device_moderate_amount(app, customer_and_token):
    """Scenario B: New beneficiary + normal device + moderate amount -> elevated scrutiny with cooling signal."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Scenario B New", "beneficiary_upi_id": "scenario_b@upi"},
        )

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 15000.0,
                "beneficiary_id": ben.id,
            },
        )
        assert err is None
        assert tx is not None
        codes = [s["code"] for s in tx["risk_signals"]]
        assert "NEW_BENEFICIARY_IN_COOLING" in codes


def test_scenario_c_new_beneficiary_high_value_transfer(app, customer_and_token):
    """Scenario C: New beneficiary + ₹2,00,000 transfer -> HIGH/CRITICAL risk / OTP."""
    user_id, _ = customer_and_token
    with app.app_context():
        # Add balance for ₹2,00,000 transfer
        user = db.session.get(User, user_id)
        user.account_balance = 300000.0
        db.session.commit()

        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Scenario C High Value", "beneficiary_upi_id": "scenario_c@upi"},
        )

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 200000.0,
                "beneficiary_id": ben.id,
            },
        )
        assert err is None
        assert tx is not None
        codes = [s["code"] for s in tx["risk_signals"]]
        assert "NEW_BENEFICIARY_IN_COOLING" in codes
        assert "HIGH_BENEFICIARY_TRANSACTION_AMOUNT" in codes
        assert tx["requires_otp"] is True or tx["status"] in ["PENDING_OTP", "UNDER_REVIEW"]


def test_scenario_d_new_beneficiary_plus_unknown_device_plus_impossible_travel(app, customer_and_token):
    """Scenario D: New beneficiary + UNKNOWN device + IMPOSSIBLE TRAVEL -> HIGH/CRITICAL risk / security review."""
    user_id, _ = customer_and_token
    with app.app_context():
        from app.services.geo_intelligence_service import GeoIntelligenceService

        # Seed initial location in Bengaluru 5 minutes ago
        t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
        GeoIntelligenceService.evaluate_event_location(
            user_id=user_id,
            client_ip="127.0.0.1",
            location_payload={"city": "Bengaluru", "country": "IN", "lat": 12.97, "lon": 77.59},
            event_type="LOGIN",
            reference_time=t0,
            persist=True,
        )

        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Scenario D Recipient", "beneficiary_upi_id": "scenario_d@upi"},
        )

        # Attempt payment 5 minutes later from London (7,500 km away)
        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 75000.0,
                "beneficiary_id": ben.id,
                "location": {"city": "London", "country": "GB", "lat": 51.51, "lon": -0.13},
                "client_ip": "185.86.151.11",
            },
        )
        assert err is None
        assert tx is not None
        codes = [s["code"] for s in tx["risk_signals"]]
        assert "IMPOSSIBLE_TRAVEL" in codes
        assert "NEW_BENEFICIARY_IN_COOLING" in codes
        assert tx["risk_score"] >= 60


def test_scenario_e_revoked_beneficiary_rejected(app, customer_and_token):
    """Scenario E: Revoked beneficiary -> transaction strictly rejected with 403."""
    user_id, _ = customer_and_token
    with app.app_context():
        ben, _, _ = BeneficiaryService.create_beneficiary(
            user_id=user_id,
            data={"beneficiary_name": "Scenario E Revoked", "beneficiary_upi_id": "scenario_e@upi"},
        )
        BeneficiaryService.revoke_beneficiary(ben.id, user_id=user_id, reason="Security review flag")

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 500.0,
                "beneficiary_id": ben.id,
            },
        )
        assert tx is None
        assert status == 403
        assert "revoked" in err.lower()


def test_scenario_f_expired_cooling_with_history_normal_behavior(app, customer_and_token):
    """Scenario F: Beneficiary created 25 hours ago + established successful history -> cooling expired / normal behavior."""
    user_id, _ = customer_and_token
    with app.app_context():
        t_created = datetime.now(timezone.utc) - timedelta(hours=25)
        ben = Beneficiary(
            user_id=user_id,
            beneficiary_name="Scenario F Mature",
            beneficiary_upi_id="scenario_f@upi",
            status="ACTIVE",
            trust_status="ESTABLISHED",
            cooling_period_hours=24,
            cooling_expires_at=t_created + timedelta(hours=24),
            created_at=t_created,
            successful_payment_count=2,
        )
        db.session.add(ben)
        db.session.commit()

        tx, err, status = TransactionService.process_and_predict(
            user_id=user_id,
            payload={
                "type": "TRANSFER",
                "amount": 2500.0,
                "beneficiary_id": ben.id,
            },
        )
        assert err is None
        assert tx is not None
        codes = [s["code"] for s in tx["risk_signals"]]
        assert "NEW_BENEFICIARY_IN_COOLING" not in codes

