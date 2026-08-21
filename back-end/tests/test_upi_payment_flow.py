from datetime import datetime, timezone, timedelta
import pytest
from flask_jwt_extended import create_access_token
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.models.transaction import Transaction
from app.services.payment_service import PaymentService
from app.services.transaction_service import TransactionService
from app.services.otp_service import OTPService


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
    """Create test client."""
    return app.test_client()


@pytest.fixture
def upi_users(client):
    """Fixture providing sender, recipient, and unconfigured users."""
    sender = User(
        name="Alice Sharma",
        email="alice.upi@example.com",
        phone_number="9876543210",
        customer_account_id="FS100001",
        primary_upi_id="alice@fraudshield",
        account_balance=50000.0,
        role="USER",
        is_active=True,
        is_phone_verified=True,
    )
    sender.set_password("SecurePass123!")
    sender.set_payment_pin("123456")

    recipient = User(
        name="Bob Verma",
        email="bob.upi@example.com",
        phone_number="9876543211",
        customer_account_id="FS100002",
        primary_upi_id="bob@fraudshield",
        account_balance=10000.0,
        role="USER",
        is_active=True,
        is_phone_verified=True,
    )
    recipient.set_password("SecurePass123!")
    recipient.set_payment_pin("654321")

    no_pin_user = User(
        name="Charlie Kumar",
        email="charlie.upi@example.com",
        phone_number="9876543212",
        customer_account_id="FS100003",
        primary_upi_id="charlie@fraudshield",
        account_balance=25000.0,
        role="USER",
        is_active=True,
        is_phone_verified=True,
    )
    no_pin_user.set_password("SecurePass123!")

    db.session.add_all([sender, recipient, no_pin_user])
    db.session.commit()

    return {"sender": sender, "recipient": recipient, "no_pin_user": no_pin_user}


# ==========================================
# 1. QR Code Parsing Tests
# ==========================================

def test_parse_valid_upi_qr():
    """Verify parsing a standard UPI QR URI string."""
    qr_uri = "upi://pay?pa=merchant@fraudshield&pn=SuperMart%20Retail&am=1250.50&cu=INR&tn=Weekly%20Groceries"
    is_valid, parsed, err = PaymentService.parse_upi_qr(qr_uri)
    assert is_valid is True
    assert err is None
    assert parsed["pa"] == "merchant@fraudshield"
    assert parsed["pn"] == "SuperMart Retail"
    assert parsed["am"] == 1250.50
    assert parsed["cu"] == "INR"
    assert parsed["tn"] == "Weekly Groceries"


def test_parse_qr_missing_pa():
    """Verify rejection when mandatory 'pa' (payee address) is missing."""
    qr_uri = "upi://pay?pn=Unknown&am=500"
    is_valid, parsed, err = PaymentService.parse_upi_qr(qr_uri)
    assert is_valid is False
    assert "missing mandatory payee" in err.lower()


def test_parse_qr_unsupported_currency():
    """Verify rejection when currency is not INR."""
    qr_uri = "upi://pay?pa=store@upi&pn=Store&am=10&cu=USD"
    is_valid, parsed, err = PaymentService.parse_upi_qr(qr_uri)
    assert is_valid is False
    assert "unsupported currency" in err.lower()


def test_parse_qr_invalid_amount():
    """Verify rejection when amount is negative or non-numeric."""
    qr_uri = "upi://pay?pa=store@upi&pn=Store&am=-50"
    is_valid, parsed, err = PaymentService.parse_upi_qr(qr_uri)
    assert is_valid is False
    assert "greater than zero" in err.lower()


# ==========================================
# 2. Recipient Resolution Tests
# ==========================================

def test_resolve_recipient_by_phone(upi_users):
    """Verify resolving internal user by 10-digit mobile number."""
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]

    is_resolved, rec, err = PaymentService.resolve_recipient(sender.id, "9876543211")
    assert is_resolved is True
    assert rec["recipient_name"] == "Bob Verma"
    assert rec["recipient_upi_id"] == "bob@fraudshield"
    assert rec["account_type"] == "INTERNAL_USER"
    assert rec["recipient_id"] == recipient.id


def test_resolve_recipient_by_upi_id(upi_users):
    """Verify resolving internal user by primary UPI ID."""
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]

    is_resolved, rec, err = PaymentService.resolve_recipient(sender.id, "bob@fraudshield")
    assert is_resolved is True
    assert rec["recipient_name"] == "Bob Verma"
    assert rec["recipient_id"] == recipient.id


def test_resolve_recipient_self_payment_prevention(upi_users):
    """Verify prevention of self-transfer."""
    sender = upi_users["sender"]
    is_resolved, rec, err = PaymentService.resolve_recipient(sender.id, sender.primary_upi_id)
    assert is_resolved is False
    assert "own account" in err.lower()


def test_resolve_simulated_merchant(upi_users):
    """Verify resolution of pre-configured verified demo merchants."""
    sender = upi_users["sender"]
    is_resolved, rec, err = PaymentService.resolve_recipient(sender.id, "merchant@fraudshield")
    assert is_resolved is True
    assert rec["account_type"] == "MERCHANT"
    assert "SuperMart" in rec["recipient_name"]


def test_resolve_external_upi_id(upi_users):
    """Verify fallback resolution for arbitrary valid external UPI handle."""
    sender = upi_users["sender"]
    is_resolved, rec, err = PaymentService.resolve_recipient(sender.id, "vendor.payments@icici")
    assert is_resolved is True
    assert rec["account_type"] == "EXTERNAL_UPI"
    assert rec["recipient_upi_id"] == "vendor.payments@icici"


# ==========================================
# 3. Payment PIN Security & Lockout Tests
# ==========================================

def test_set_payment_pin_success(upi_users):
    """Verify setting payment PIN with correct account password."""
    user = upi_users["no_pin_user"]
    success, err = PaymentService.set_user_pin(
        user_id=user.id,
        current_password="SecurePass123!",
        new_pin="987654",
        confirm_pin="987654",
    )
    assert success is True
    assert err is None
    assert user.is_pin_set is True

    # Test checking the newly set PIN
    is_valid, _ = user.check_payment_pin("987654")
    assert is_valid is True


def test_set_payment_pin_wrong_password(upi_users):
    """Verify failure to set PIN with incorrect account password."""
    user = upi_users["no_pin_user"]
    success, err = PaymentService.set_user_pin(
        user_id=user.id,
        current_password="WrongPassword999!",
        new_pin="987654",
        confirm_pin="987654",
    )
    assert success is False
    assert "incorrect account password" in err.lower()


def test_set_payment_pin_invalid_length(upi_users):
    """Verify PIN must be 4 to 6 numeric digits."""
    user = upi_users["no_pin_user"]
    success, err = PaymentService.set_user_pin(
        user_id=user.id,
        current_password="SecurePass123!",
        new_pin="12",  # Too short
        confirm_pin="12",
    )
    assert success is False
    assert "4 to 6 numeric digits" in err.lower()


def test_payment_pin_lockout_after_3_failures(upi_users):
    """Verify 3 consecutive failed PIN attempts lock the PIN for 15 minutes."""
    user = upi_users["sender"]

    # Attempt 1
    valid1, err1 = user.check_payment_pin("000000")
    assert valid1 is False
    assert user.pin_failed_attempts == 1
    assert "2 attempt(s) remaining" in err1

    # Attempt 2
    valid2, err2 = user.check_payment_pin("000000")
    assert valid2 is False
    assert user.pin_failed_attempts == 2
    assert "1 attempt(s) remaining" in err2

    # Attempt 3 (Triggers Lockout)
    valid3, err3 = user.check_payment_pin("000000")
    assert valid3 is False
    assert user.pin_failed_attempts == 3
    assert user.is_pin_locked is True
    assert "locked for 15 minutes" in err3.lower()

    # Attempt 4 with the CORRECT PIN while locked must still be rejected
    valid4, err4 = user.check_payment_pin("123456")
    assert valid4 is False
    assert "locked due to security attempts" in err4.lower()


# ==========================================
# 4. Atomic Ledger & UPI Payment Flow Tests
# ==========================================

def test_upi_atomic_payment_success(upi_users):
    """
    Verify successful low-risk UPI transfer atomically debits sender and credits recipient.
    """
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    sender_initial_bal = sender.account_balance
    recipient_initial_bal = recipient.account_balance

    transfer_amount = 500.0

    payload = {
        "amount": transfer_amount,
        "type": "PAYMENT",
        "destination": recipient.primary_upi_id,
        "destination_upi_id": recipient.primary_upi_id,
        "destination_name": recipient.name,
        "payment_method": "UPI_ID",
        "payment_pin": "123456",
        "idempotency_key": "IDEM-TEST-SUCCESS-001",
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert err is None
    assert status_code == 200
    assert res["success"] is True
    assert res["status"] == "APPROVED"
    assert res["reference_id"].startswith("UPI")
    assert res["security_checks"]["pin_authenticated"] is True
    assert res["security_checks"]["recipient_verified"] is True

    # Verify atomic balance movement
    db.session.refresh(sender)
    db.session.refresh(recipient)
    assert sender.account_balance == round(sender_initial_bal - transfer_amount, 2)
    assert recipient.account_balance == round(recipient_initial_bal + transfer_amount, 2)


def test_upi_payment_idempotency_double_debit_prevention(upi_users):
    """
    Verify submitting the same idempotency key twice returns cached result without double-debiting.
    """
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    sender_initial_bal = sender.account_balance
    transfer_amount = 200.0
    idem_key = "IDEM-DUPLICATE-CHECK-001"

    payload = {
        "amount": transfer_amount,
        "type": "PAYMENT",
        "destination": recipient.primary_upi_id,
        "payment_pin": "123456",
        "idempotency_key": idem_key,
    }

    # First Submission
    res1, err1, status1 = TransactionService.process_and_predict(sender.id, payload)
    assert status1 == 200
    assert res1["status"] == "APPROVED"

    db.session.refresh(sender)
    bal_after_first = sender.account_balance
    assert bal_after_first == round(sender_initial_bal - transfer_amount, 2)

    # Duplicate Re-Submission with same idempotency key
    res2, err2, status2 = TransactionService.process_and_predict(sender.id, payload)
    assert status2 == 200
    assert res2["idempotency_key"] == idem_key

    # Balance must NOT be debited again
    db.session.refresh(sender)
    assert sender.account_balance == bal_after_first


def test_upi_payment_wrong_pin_rejection(upi_users):
    """
    Verify payment with wrong PIN is rejected with 401 and does not move funds.
    """
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    sender_initial_bal = sender.account_balance
    recipient_initial_bal = recipient.account_balance

    payload = {
        "amount": 300.0,
        "type": "PAYMENT",
        "destination": recipient.primary_upi_id,
        "payment_pin": "000000",  # Wrong PIN
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert res is None
    assert status_code == 401
    assert "incorrect payment pin" in err.lower()

    # Balances must remain unchanged
    db.session.refresh(sender)
    db.session.refresh(recipient)
    assert sender.account_balance == sender_initial_bal
    assert recipient.account_balance == recipient_initial_bal


def test_upi_payment_adaptive_otp_atomic_completion(upi_users):
    """
    Verify transaction requiring OTP does not debit funds immediately,
    and atomically debits sender & credits recipient upon successful OTP verification.
    """
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    sender.account_balance = 150000.0
    db.session.commit()

    sender_initial_bal = sender.account_balance
    recipient_initial_bal = recipient.account_balance

    transfer_amount = 92000.0  # Amount triggering medium/high tier OTP challenge

    payload = {
        "amount": transfer_amount,
        "type": "TRANSFER",
        "destination": recipient.primary_upi_id,
        "payment_pin": "123456",
        "idempotency_key": "IDEM-OTP-FLOW-001",
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert status_code == 200
    assert res["requires_otp"] is True
    assert res["status"] in ["OTP_REQUIRED", "PENDING_OTP"]

    # Funds must NOT have moved yet
    db.session.refresh(sender)
    db.session.refresh(recipient)
    assert sender.account_balance == sender_initial_bal
    assert recipient.account_balance == recipient_initial_bal

    tx_id = res["transaction_id"]

    # Issue and verify OTP
    challenge, dev_otp, gen_err = OTPService.create_challenge(
        transaction_id=tx_id,
        user_id=sender.id,
    )
    assert gen_err is None
    assert dev_otp is not None

    is_verified, v_msg, v_status, updated_tx = OTPService.verify_challenge(
        transaction_id=tx_id,
        user_id=sender.id,
        candidate_otp=dev_otp,
    )
    assert is_verified is True
    assert updated_tx["status"] == "APPROVED"

    # Verify atomic balance movement after OTP verification
    db.session.refresh(sender)
    db.session.refresh(recipient)
    assert sender.account_balance == round(sender_initial_bal - transfer_amount, 2)
    assert recipient.account_balance == round(recipient_initial_bal + transfer_amount, 2)


# ==========================================
# 5. HTTP API Endpoint Tests
# ==========================================

def test_api_resolve_recipient(client, upi_users):
    """Verify POST /api/transactions/resolve-recipient endpoint."""
    sender = upi_users["sender"]
    token = create_access_token(identity=str(sender.id))
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    res = client.post("/api/transactions/resolve-recipient", headers=headers, json={"query": "9876543211"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["recipient"]["recipient_name"] == "Bob Verma"
    assert data["recipient"]["recipient_upi_id"] == "bob@fraudshield"


def test_api_parse_qr(client, upi_users):
    """Verify POST /api/transactions/parse-qr endpoint."""
    sender = upi_users["sender"]
    token = create_access_token(identity=str(sender.id))
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    qr_str = "upi://pay?pa=coffee@fraudshield&pn=Artisan%20Coffee&am=150.00&cu=INR&tn=Cappuccino"
    res = client.post("/api/transactions/parse-qr", headers=headers, json={"qr_data": qr_str})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["parsed_qr"]["pa"] == "coffee@fraudshield"
    assert data["parsed_qr"]["am"] == 150.00


def test_api_payment_pin_set_and_status(client, upi_users):
    """Verify POST /api/auth/payment-pin/set and GET /api/auth/payment-pin/status."""
    user = upi_users["no_pin_user"]
    token = create_access_token(identity=str(user.id))
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Initial status
    res1 = client.get("/api/auth/payment-pin/status", headers=headers)
    assert res1.status_code == 200
    assert res1.get_json()["is_pin_set"] is False

    # Set PIN
    res2 = client.post("/api/auth/payment-pin/set", headers=headers, json={
        "password": "SecurePass123!",
        "pin": "543210",
        "confirm_pin": "543210",
    })
    assert res2.status_code == 200
    assert res2.get_json()["is_pin_set"] is True

    # Check updated status
    res3 = client.get("/api/auth/payment-pin/status", headers=headers)
    assert res3.status_code == 200
    assert res3.get_json()["is_pin_set"] is True
    assert res3.get_json()["is_pin_locked"] is False


def test_api_predict_with_payment_pin(client, upi_users):
    """Verify POST /api/transactions/predict authenticates payment PIN via HTTP."""
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    token = create_access_token(identity=str(sender.id))
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {
        "amount": 250.0,
        "type": "PAYMENT",
        "destination": recipient.primary_upi_id,
        "payment_pin": "123456",
        "idempotency_key": "HTTP-IDEM-001",
    }

    res = client.post("/api/transactions/predict", headers=headers, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["reference_id"].startswith("UPI")
    assert data["security_checks"]["pin_authenticated"] is True


# ==========================================
# 6. Authoritative Security & Zero-Debit Tests
# ==========================================

def test_upi_insufficient_balance_rejected_before_settlement(upi_users):
    """Verify insufficient balance is rejected with 400 and zero balance movement."""
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    initial_sender_bal = sender.account_balance
    initial_rec_bal = recipient.account_balance

    payload = {
        "amount": initial_sender_bal + 5000.0,  # Exceeds available balance
        "type": "TRANSFER",
        "destination": recipient.primary_upi_id,
        "payment_pin": "123456",
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert res is None
    assert status_code == 400
    assert "insufficient account balance" in err.lower()

    # Balances must be completely untouched
    db.session.refresh(sender)
    db.session.refresh(recipient)
    assert sender.account_balance == initial_sender_bal
    assert recipient.account_balance == initial_rec_bal


def test_upi_revoked_beneficiary_rejected_before_settlement(upi_users):
    """Verify revoked beneficiary is rejected with 403 and zero balance movement."""
    sender = upi_users["sender"]
    initial_sender_bal = sender.account_balance

    # Create and revoke a beneficiary
    ben = Beneficiary(
        user_id=sender.id,
        beneficiary_name="Suspicious Actor",
        beneficiary_upi_id="scammer@fraudshield",
        trust_status="REVOKED",
        status="REVOKED",
        revocation_reason="Flagged as fraudulent by user",
    )
    db.session.add(ben)
    db.session.commit()

    payload = {
        "amount": 500.0,
        "type": "TRANSFER",
        "beneficiary_id": ben.id,
        "payment_pin": "123456",
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert res is None
    assert status_code == 403
    assert "revoked" in err.lower()

    # Balance untouched
    db.session.refresh(sender)
    assert sender.account_balance == initial_sender_bal


def test_upi_failed_otp_zero_balance_movement(upi_users):
    """Verify failed OTP attempts do not move any funds."""
    sender = upi_users["sender"]
    recipient = upi_users["recipient"]
    sender.account_balance = 150000.0
    db.session.commit()

    initial_sender_bal = sender.account_balance
    initial_rec_bal = recipient.account_balance

    payload = {
        "amount": 92000.0,
        "type": "TRANSFER",
        "destination": recipient.primary_upi_id,
        "payment_pin": "123456",
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert status_code == 200
    assert res["requires_otp"] is True
    tx_id = res["transaction_id"]

    # Issue challenge
    challenge, dev_otp, _ = OTPService.create_challenge(transaction_id=tx_id, user_id=sender.id)

    # Submit wrong OTP
    is_v, msg, st, updated_tx = OTPService.verify_challenge(
        transaction_id=tx_id,
        user_id=sender.id,
        candidate_otp="000000",
    )
    assert is_v is False

    # Balances must remain unchanged
    db.session.refresh(sender)
    db.session.refresh(recipient)
    assert sender.account_balance == initial_sender_bal
    assert recipient.account_balance == initial_rec_bal


def test_upi_critical_risk_blocked_zero_balance_movement(upi_users):
    """Verify critical account-drain transfer is blocked with zero balance deduction."""
    sender = upi_users["sender"]
    sender.account_balance = 900000.0
    db.session.commit()
    initial_bal = sender.account_balance

    payload = {
        "amount": 900000.0,
        "type": "TRANSFER",
        "destination": "C554433",
        "payment_pin": "123456",
        "oldbalance_org": 900000.0,
        "newbalance_orig": 0.0,
        "oldbalance_dest": 0.0,
        "newbalance_dest": 0.0,
    }

    res, err, status_code = TransactionService.process_and_predict(sender.id, payload)
    assert status_code == 200
    assert res["risk_level"] == "CRITICAL"
    assert res["status"] in ["UNDER_REVIEW", "FLAGGED"]

    # Balance must NOT be deducted
    db.session.refresh(sender)
    assert sender.account_balance == initial_bal


