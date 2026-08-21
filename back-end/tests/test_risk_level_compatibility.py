"""
Test Risk Level Database Compatibility and Balance Invariants.
Validates that LOW, MEDIUM, HIGH, and CRITICAL risk levels are fully accepted
by the database schema and that no balance debits occur prior to required authentication.
"""
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.providers.email_provider import DevelopmentEmailProvider
from app.services.auth_service import AuthService
from app.services.transaction_service import TransactionService
from app.services.otp_service import OTPService


@pytest.fixture
def app():
    """Create test application."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test HTTP client."""
    return app.test_client()


@pytest.fixture
def test_users(app):
    """Create sender and receiver users."""
    sender, _ = AuthService.register_user(
        name="Sender User",
        email="sender.risk@example.com",
        password="Password123!",
        phone_number="9876543210",
        role="USER",
    )
    otp1 = DevelopmentEmailProvider.get_last_email_otp("sender.risk@example.com")
    AuthService.verify_email_otp("sender.risk@example.com", otp1)
    sender.account_balance = 100000.0
    sender.set_payment_pin("543210")

    receiver, _ = AuthService.register_user(
        name="Receiver User",
        email="receiver.risk@example.com",
        password="Password123!",
        phone_number="9876543211",
        role="USER",
    )
    otp2 = DevelopmentEmailProvider.get_last_email_otp("receiver.risk@example.com")
    AuthService.verify_email_otp("receiver.risk@example.com", otp2)
    receiver.account_balance = 50000.0

    db.session.commit()
    return sender, receiver


def test_database_accepts_all_four_risk_levels(app, test_users):
    """Verify database CheckConstraint accepts LOW, MEDIUM, HIGH, and CRITICAL risk levels."""
    sender, receiver = test_users
    
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        tx = Transaction(
            user_id=sender.id,
            recipient_user_id=receiver.id,
            step=12,
            type="TRANSFER",
            amount=100.0,
            oldbalance_org=100000.0,
            newbalance_orig=99900.0,
            oldbalance_dest=50000.0,
            newbalance_dest=50100.0,
            prediction=1 if level in ["HIGH", "CRITICAL"] else 0,
            fraud_probability=0.85 if level == "CRITICAL" else (0.65 if level == "HIGH" else 0.1),
            risk_score=85 if level == "CRITICAL" else (65 if level == "HIGH" else 10),
            risk_level=level,
            decision="TRIGGER_SECURITY_REVIEW" if level == "CRITICAL" else ("TRIGGER_OTP_VERIFICATION" if level == "HIGH" else "APPROVE"),
            status="UNDER_REVIEW" if level == "CRITICAL" else ("OTP_REQUIRED" if level == "HIGH" else "APPROVED"),
            requires_otp=level in ["HIGH", "CRITICAL"],
            reference_id=f"UPI_TEST_{level}",
            balance_before=100000.0,
            balance_after=100000.0 if level in ["HIGH", "CRITICAL"] else 99900.0,
        )
        db.session.add(tx)
        db.session.commit()
        assert tx.id is not None
        assert tx.risk_level == level


def test_test_a_low_risk_normal_payment(client, test_users):
    """TEST A: INR 500 normal transaction is approved with immediate atomic balance settlement."""
    sender, receiver = test_users
    login_res = client.post("/api/auth/login", json={"email": "sender.risk@example.com", "password": "Password123!"})
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 500.0,
        "destination": receiver.primary_upi_id,
        "payment_pin": "543210",
        "device_id": 1,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] in ["LOW", "MEDIUM"]
    if data["requires_otp"]:
        assert data["status"] == "OTP_REQUIRED"
        assert data["balance_after"] == 100000.0
        # Complete OTP verification
        client.post("/api/otp/generate", headers=headers, json={"transaction_id": data["transaction_id"]})
        otp = DevelopmentEmailProvider.get_last_email_otp("sender.risk@example.com")
        v_res = client.post("/api/otp/verify", headers=headers, json={
            "transaction_id": data["transaction_id"],
            "otp_code": otp,
        })
        assert v_res.status_code == 200
        assert v_res.get_json()["transaction"]["status"] == "APPROVED"
    else:
        assert data["status"] == "APPROVED"
        assert data["balance_after"] == 99500.0

    # Verify atomic debit
    db.session.expire_all()
    s = db.session.get(User, sender.id)
    r = db.session.get(User, receiver.id)
    assert s.account_balance == 99500.0
    assert r.account_balance == 50500.0


def test_test_b_high_risk_80k_transfer(client, test_users):
    """TEST B: INR 80,000 TRANSFER triggers HIGH risk, OTP_REQUIRED, zero debit before OTP, wrong OTP rejected, correct OTP settles."""
    sender, receiver = test_users
    login_res = client.post("/api/auth/login", json={"email": "sender.risk@example.com", "password": "Password123!"})
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 80000.0,
        "destination": receiver.primary_upi_id,
        "payment_pin": "543210",
        "device_id": 1,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["status"] == "OTP_REQUIRED"
    assert data["requires_otp"] is True
    tx_id = data["transaction_id"]

    # Verify zero debit before OTP
    db.session.expire_all()
    s = db.session.get(User, sender.id)
    assert s.account_balance == 100000.0

    # Wrong OTP
    gen_res = client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})
    assert gen_res.status_code == 200
    sim_otp = gen_res.get_json().get("_dev_simulated_otp")

    wrong_res = client.post("/api/otp/verify", headers=headers, json={"transaction_id": tx_id, "otp_code": "000000"})
    assert wrong_res.status_code == 400

    # Still zero debit
    db.session.expire_all()
    s = db.session.get(User, sender.id)
    assert s.account_balance == 100000.0

    # Correct OTP
    correct_res = client.post("/api/otp/verify", headers=headers, json={"transaction_id": tx_id, "otp_code": sim_otp})
    assert correct_res.status_code == 200
    assert correct_res.get_json()["transaction"]["status"] == "APPROVED"

    # Exactly one atomic debit
    db.session.expire_all()
    s = db.session.get(User, sender.id)
    r = db.session.get(User, receiver.id)
    assert s.account_balance == 20000.0
    assert r.account_balance == 130000.0


def test_test_c_critical_risk_transaction_flow(client, test_users):
    """TEST C: High fraud probability (risk_score >= 80) produces CRITICAL risk, UNDER_REVIEW, zero debit before authorization."""
    sender, receiver = test_users
    login_res = client.post("/api/auth/login", json={"email": "sender.risk@example.com", "password": "Password123!"})
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate transaction with account simulation drain parameters that trigger CRITICAL risk (risk_score >= 80)
    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 16000.0,
        "oldbalance_org": 16000.0,
        "newbalance_orig": 0.0,
        "oldbalance_dest": 0.0,
        "newbalance_dest": 0.0,
        "destination": receiver.primary_upi_id,
        "payment_pin": "543210",
        "device_id": 1,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_score"] >= 80
    assert data["risk_level"] == "CRITICAL"
    assert data["status"] == "UNDER_REVIEW"
    assert data["decision"] == "TRIGGER_SECURITY_REVIEW"
    assert data["requires_otp"] is True

    # Database records correctly with CRITICAL risk_level
    db.session.expire_all()
    tx = db.session.get(Transaction, data["transaction_id"])
    assert tx.risk_level == "CRITICAL"
    assert tx.status == "UNDER_REVIEW"

    # Verify zero debit
    s = db.session.get(User, sender.id)
    assert s.account_balance == 100000.0


def test_test_d_high_value_merchant_payment(client, test_users):
    """TEST D: INR 72,000 PAYMENT applies high-value risk signal, requires step-up, causes zero debit before authentication."""
    sender, receiver = test_users
    login_res = client.post("/api/auth/login", json={"email": "sender.risk@example.com", "password": "Password123!"})
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "PAYMENT",
        "amount": 72000.0,
        "destination": "merchant@hdfcbank",
        "destination_name": "Flipkart Merchant Gateway",
        "payment_pin": "543210",
        "device_id": 1,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["requires_otp"] is True
    assert data["status"] in ["OTP_REQUIRED", "UNDER_REVIEW"]

    # Verify zero debit before OTP
    db.session.expire_all()
    s = db.session.get(User, sender.id)
    assert s.account_balance == 100000.0
