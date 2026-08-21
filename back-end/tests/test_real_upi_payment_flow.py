"""
Comprehensive Phase D Test Suite: Real UPI Recipient Resolution, Real QR Payment & PIN Enforcement.

Verifies all 25 Phase D requirements:
1. QR URI parsing (standard upi://pay format)
2. Malformed QR payload rejection
3. Missing 'pa' parameter rejection
4. Invalid UPI ID format rejection
5. Valid registered UPI ID resolution
6. Unregistered external UPI ID resolution (safe fallback)
7. Registered verified mobile number resolution
8. Unregistered mobile number rejection (no fake mock generation)
9. Self-transfer prevention
10. Unverified mobile number account resolution handling
11. Payment PIN setup with correct account password
12. Payment PIN mismatch rejection
13. Correct Payment PIN verification
14. Incorrect Payment PIN rejection
15. Payment PIN lockout after 3 consecutive failures (15 min)
16. Payment rejected if Payment PIN is not provided
17. Payment accepted with correct Payment PIN
18. Zero balance debit before final decision
19. Successful settlement atomic debit & ledger record
20. OTP settlement completes step-up transfer
21. Critical/Blocked transaction results in zero debit
22. Duplicate payment request / Idempotency double-debit prevention
23. Recipient info isolation (no sensitive password/token leaks in response)
24. Unauthorized recipient lookup rejected (requires JWT)
25. QR amount extraction and precision handling
"""

import json
from datetime import datetime, timezone
import pytest
from flask_jwt_extended import create_access_token
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.beneficiary import Beneficiary
from app.services.payment_service import PaymentService
from app.services.auth_service import AuthService


@pytest.fixture
def app():
    """Create isolated testing application."""
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def seeded_users(app):
    """Seed sender, recipient, and unverified phone users."""
    with app.app_context():
        # Sender
        sender = User(
            name="Aarav Sen",
            email="aarav.sen@example.com",
            phone_number="9876543210",
            customer_account_id="FS-200001",
            primary_upi_id="aarav@fraudshield",
            account_balance=150000.0,
            role="USER",
            is_active=True,
            is_phone_verified=True,
        )
        sender.set_password("SecureSenderPass123!")
        sender.set_payment_pin("123456")

        # Verified Recipient
        recipient = User(
            name="Diya Kapoor",
            email="diya.kapoor@example.com",
            phone_number="9876543211",
            customer_account_id="FS-200002",
            primary_upi_id="diya@fraudshield",
            account_balance=15000.0,
            role="USER",
            is_active=True,
            is_phone_verified=True,
        )
        recipient.set_password("SecureReceiverPass123!")
        recipient.set_payment_pin("654321")

        # Unverified Phone User
        unverified_user = User(
            name="Rohan Joshi",
            email="rohan.joshi@example.com",
            phone_number="9876543212",
            customer_account_id="FS-200003",
            primary_upi_id="rohan@fraudshield",
            account_balance=10000.0,
            role="USER",
            is_active=True,
            is_phone_verified=False,  # NOT verified
        )
        unverified_user.set_password("SecureRohanPass123!")

        # User without PIN
        no_pin_user = User(
            name="Kabir Mehta",
            email="kabir.mehta@example.com",
            phone_number="9876543213",
            customer_account_id="FS-200004",
            primary_upi_id="kabir@fraudshield",
            account_balance=25000.0,
            role="USER",
            is_active=True,
            is_phone_verified=True,
            is_pin_set=False,
        )
        no_pin_user.set_password("SecureKabirPass123!")

        db.session.add_all([sender, recipient, unverified_user, no_pin_user])
        db.session.commit()

        return {
            "sender_id": sender.id,
            "sender_email": sender.email,
            "recipient_id": recipient.id,
            "recipient_email": recipient.email,
            "unverified_id": unverified_user.id,
            "no_pin_id": no_pin_user.id,
        }


# ==============================================================================
# 1. QR URI Parsing
# ==============================================================================
def test_1_qr_uri_parsing():
    """Verify standard UPI QR parsing with pa, pn, am, cu, tn."""
    uri = "upi://pay?pa=diya@fraudshield&pn=Diya%20Kapoor&am=1200.50&cu=INR&tn=Freelance%20Design"
    ok, data, err = PaymentService.parse_upi_qr(uri)
    assert ok is True
    assert err is None
    assert data["pa"] == "diya@fraudshield"
    assert data["pn"] == "Diya Kapoor"
    assert data["am"] == 1200.50
    assert data["cu"] == "INR"
    assert data["tn"] == "Freelance Design"


# ==============================================================================
# 2. Malformed QR Payload
# ==============================================================================
def test_2_malformed_qr_rejection():
    """Verify invalid non-UPI URI string is rejected."""
    bad_uri = "https://malicious-site.com/fake-pay?account=123"
    ok, data, err = PaymentService.parse_upi_qr(bad_uri)
    assert ok is False
    assert "Expected 'upi://pay" in err


# ==============================================================================
# 3. Missing Mandatory 'pa' (Payee Address)
# ==============================================================================
def test_3_missing_pa_rejection():
    """Verify rejection when 'pa' is missing from UPI QR."""
    uri = "upi://pay?pn=Unknown&am=500&cu=INR"
    ok, data, err = PaymentService.parse_upi_qr(uri)
    assert ok is False
    assert "missing mandatory payee UPI address" in err


# ==============================================================================
# 4. Invalid UPI ID Format
# ==============================================================================
def test_4_invalid_upi_id_format():
    """Verify rejection of malformed UPI handle."""
    bad_id = "invalid-handle-without-at-sign"
    ok, data, err = PaymentService.parse_upi_qr(f"upi://pay?pa={bad_id}")
    assert ok is False
    assert "Invalid payee UPI ID format" in err


# ==============================================================================
# 5. Valid Registered UPI ID Resolution
# ==============================================================================
def test_5_valid_registered_upi_id(app, seeded_users):
    """Verify resolving internal registered user by UPI ID."""
    with app.app_context():
        ok, rec, err = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "diya@fraudshield"
        )
        assert ok is True
        assert rec["recipient_name"] == "Diya Kapoor"
        assert rec["recipient_upi_id"] == "diya@fraudshield"
        assert rec["account_type"] == "INTERNAL_USER"
        assert rec["is_internal"] is True
        assert rec["is_verified"] is True


# ==============================================================================
# 6. Unregistered External UPI ID Resolution (Safe Fallback)
# ==============================================================================
def test_6_unregistered_external_upi_id(app, seeded_users):
    """Verify resolving arbitrary valid external UPI handle as EXTERNAL_UPI."""
    with app.app_context():
        ok, rec, err = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "external.merchant@hdfcbank"
        )
        assert ok is True
        assert rec["account_type"] == "EXTERNAL_UPI"
        assert rec["recipient_upi_id"] == "external.merchant@hdfcbank"
        assert rec["is_internal"] is False


# ==============================================================================
# 7. Registered Verified Mobile Number Resolution
# ==============================================================================
def test_7_registered_mobile_number_resolution(app, seeded_users):
    """Verify resolving user by 10-digit mobile number."""
    with app.app_context():
        ok, rec, err = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "9876543211"
        )
        assert ok is True
        assert rec["recipient_name"] == "Diya Kapoor"
        assert rec["recipient_phone"] == "9876543211"
        assert rec["account_type"] == "INTERNAL_USER"


# ==============================================================================
# 8. Unregistered Mobile Number Rejection
# ==============================================================================
def test_8_unregistered_mobile_rejection(app, seeded_users):
    """Verify non-existent mobile number returns clean not found error."""
    with app.app_context():
        ok, rec, err = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "9999999999"
        )
        assert ok is False
        assert "No FraudShield user registered with mobile number +91 9999999999" in err


# ==============================================================================
# 9. Self-Transfer Prevention
# ==============================================================================
def test_9_self_transfer_prevention(app, seeded_users):
    """Verify sender cannot send money to their own UPI ID or phone number."""
    with app.app_context():
        # Own UPI
        ok1, _, err1 = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "aarav@fraudshield"
        )
        assert ok1 is False
        assert "Cannot transfer funds to your own account" in err1

        # Own Phone
        ok2, _, err2 = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "9876543210"
        )
        assert ok2 is False
        assert "Cannot transfer funds to your own account" in err2


# ==============================================================================
# 10. Unverified Mobile Number Account Handling
# ==============================================================================
def test_10_unverified_mobile_handling(app, seeded_users):
    """Verify querying mobile of an account pending phone verification returns explicit error."""
    with app.app_context():
        ok, rec, err = PaymentService.resolve_recipient(
            seeded_users["sender_id"], "9876543212"  # Rohan's unverified phone
        )
        assert ok is False
        assert "pending mobile verification" in err.lower()


# ==============================================================================
# 11. Payment PIN Setup
# ==============================================================================
def test_11_payment_pin_setup_success(app, seeded_users):
    """Verify setting 6-digit payment PIN with current account password."""
    with app.app_context():
        ok, err = PaymentService.set_user_pin(
            user_id=seeded_users["no_pin_id"],
            current_password="SecureKabirPass123!",
            new_pin="456789",
            confirm_pin="456789",
        )
        assert ok is True
        assert err is None

        user = db.session.get(User, seeded_users["no_pin_id"])
        assert user.is_pin_set is True
        valid_pin, _ = user.check_payment_pin("456789")
        assert valid_pin is True


# ==============================================================================
# 12. Payment PIN Mismatch Rejection
# ==============================================================================
def test_12_payment_pin_mismatch_rejection(app, seeded_users):
    """Verify setting PIN with mismatching confirmation fails."""
    with app.app_context():
        ok, err = PaymentService.set_user_pin(
            user_id=seeded_users["no_pin_id"],
            current_password="SecureKabirPass123!",
            new_pin="112233",
            confirm_pin="112244",
        )
        assert ok is False
        assert "do not match" in err.lower()


# ==============================================================================
# 13. Correct Payment PIN Verification
# ==============================================================================
def test_13_correct_pin_verification(app, seeded_users):
    """Verify checking valid Payment PIN returns True."""
    with app.app_context():
        ok, err = PaymentService.check_user_pin(seeded_users["sender_id"], "123456")
        assert ok is True
        assert err is None


# ==============================================================================
# 14. Incorrect Payment PIN Rejection
# ==============================================================================
def test_14_incorrect_pin_rejection(app, seeded_users):
    """Verify checking wrong Payment PIN returns False and tracks attempts."""
    with app.app_context():
        ok, err = PaymentService.check_user_pin(seeded_users["sender_id"], "999999")
        assert ok is False
        assert "incorrect payment pin" in err.lower()
        user = db.session.get(User, seeded_users["sender_id"])
        assert user.pin_failed_attempts == 1


# ==============================================================================
# 15. Payment PIN Lockout After 3 Consecutive Failures
# ==============================================================================
def test_15_payment_pin_lockout_after_3_failures(app, seeded_users):
    """Verify 3 wrong PIN attempts trigger 15-minute account PIN lockout."""
    with app.app_context():
        for _ in range(3):
            PaymentService.check_user_pin(seeded_users["sender_id"], "000000")

        user = db.session.get(User, seeded_users["sender_id"])
        assert user.is_pin_locked is True

        # 4th attempt is locked out immediately even if PIN is correct
        ok4, err4 = PaymentService.check_user_pin(seeded_users["sender_id"], "123456")
        assert ok4 is False
        assert "locked" in err4.lower()


# ==============================================================================
# 16. Payment Without Configured PIN Rejection
# ==============================================================================
def test_16_payment_without_configured_pin_rejected(client, seeded_users):
    """Verify payment fails with 401 if user has not set up a Payment PIN."""
    token = create_access_token(identity=str(seeded_users["no_pin_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 500.0,
            "destination_upi_id": "diya@fraudshield",
            "payment_pin": "123456",
        },
    )
    assert res.status_code == 401
    assert "payment pin has not been configured" in res.get_json()["error"].lower()


# ==============================================================================
# 17. Payment Accepted With Configured PIN
# ==============================================================================
def test_17_payment_accepted_with_configured_pin(client, seeded_users):
    """Verify payment evaluates successfully when valid PIN is supplied."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "destination_upi_id": "diya@fraudshield",
            "payment_pin": "123456",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["status"] == "APPROVED"


# ==============================================================================
# 18. Zero Balance Debit Before Final Approval
# ==============================================================================
def test_18_zero_balance_debit_on_pin_failure(client, app, seeded_users):
    """Verify balance remains exactly 150000.0 if PIN verification fails."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 5000.0,
            "destination_upi_id": "diya@fraudshield",
            "payment_pin": "000000",  # WRONG PIN
        },
    )
    with app.app_context():
        sender = db.session.get(User, seeded_users["sender_id"])
        assert sender.account_balance == 150000.0


# ==============================================================================
# 19. Successful Settlement Atomic Debit & Ledger Record
# ==============================================================================
def test_19_successful_settlement_atomic_debit(client, app, seeded_users):
    """Verify low-risk transaction atomically debits sender and records in ledger."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 1500.0,
            "destination_upi_id": "diya@fraudshield",
            "payment_pin": "123456",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "APPROVED"

    with app.app_context():
        sender = db.session.get(User, seeded_users["sender_id"])
        assert sender.account_balance == 148500.0  # 150000 - 1500

        # Check transaction in database
        tx = Transaction.query.filter_by(user_id=sender.id).first()
        assert tx is not None
        assert tx.amount == 1500.0
        assert tx.status == "APPROVED"


# ==============================================================================
# 20. OTP Settlement Step-Up Transfer
# ==============================================================================
def test_20_otp_settlement_step_up_transfer(client, app, seeded_users):
    """Verify medium-risk challenge requires OTP before atomic balance debit."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    res_pay = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "TRANSFER",
            "amount": 92000.0,
            "destination_upi_id": "diya@fraudshield",
            "payment_pin": "123456",
        },
    )
    assert res_pay.status_code == 200
    data = res_pay.get_json()
    assert data["requires_otp"] is True
    tx_id = data["transaction_id"]

    # Balance MUST NOT be debited before OTP
    with app.app_context():
        sender = db.session.get(User, seeded_users["sender_id"])
        assert sender.account_balance == 150000.0

    # Generate OTP
    res_gen = client.post(
        "/api/otp/generate",
        headers={"Authorization": f"Bearer {token}"},
        json={"transaction_id": tx_id},
    )
    assert res_gen.status_code == 200
    otp_code = res_gen.get_json()["_dev_simulated_otp"]

    # Verify OTP
    res_ver = client.post(
        "/api/otp/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"transaction_id": tx_id, "otp_code": otp_code},
    )
    assert res_ver.status_code == 200
    assert res_ver.get_json()["success"] is True
    assert res_ver.get_json()["transaction"]["status"] == "APPROVED"

    # Now balance is debited
    with app.app_context():
        sender = db.session.get(User, seeded_users["sender_id"])
        assert sender.account_balance == 58000.0  # 150000 - 92000


# ==============================================================================
# 21. Critical / Blocked Transaction Zero Debit
# ==============================================================================
def test_21_critical_blocked_zero_debit(client, app, seeded_users):
    """Verify high-risk blocked transaction produces zero balance debit."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "CASH_OUT",
            "amount": 750000.0,
            "destination_upi_id": "atm.drain@upi",
            "oldbalance_org": 750000.0,
            "newbalance_orig": 0.0,
            "payment_pin": "123456",
        },
    )
    assert res.status_code == 200
    assert res.get_json()["status"] in ["REJECTED", "UNDER_REVIEW"]

    # Verify balance was NOT touched
    with app.app_context():
        sender = db.session.get(User, seeded_users["sender_id"])
        assert sender.account_balance == 150000.0


# ==============================================================================
# 22. Duplicate Payment / Idempotency Protection
# ==============================================================================
def test_22_duplicate_payment_idempotency_protection(client, app, seeded_users):
    """Verify duplicate submission with same idempotency key prevents double debit."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    payload = {
        "type": "PAYMENT",
        "amount": 1000.0,
        "destination_upi_id": "diya@fraudshield",
        "payment_pin": "123456",
        "idempotency_key": "IDEM-TEST-UNIQUE-KEY-001",
    }

    # 1st request
    res1 = client.post("/api/transactions/predict", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res1.status_code == 200

    # 2nd request with same idempotency key
    res2 = client.post("/api/transactions/predict", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res2.status_code == 200

    # Total debited must be exactly 1000.0 (150000 - 1000 = 149000), not 148000!
    with app.app_context():
        sender = db.session.get(User, seeded_users["sender_id"])
        assert sender.account_balance == 149000.0


# ==============================================================================
# 23. Recipient Information Isolation
# ==============================================================================
def test_23_recipient_info_isolation(client, seeded_users):
    """Verify resolve-recipient API never leaks password hashes or tokens."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    res = client.post(
        "/api/transactions/resolve-recipient",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "diya@fraudshield"},
    )
    assert res.status_code == 200
    data = res.get_json()["recipient"]
    assert "password" not in data
    assert "password_hash" not in data
    assert "payment_pin_hash" not in data
    assert "phone_otp_hash" not in data


# ==============================================================================
# 24. Unauthorized Recipient Lookup Rejection
# ==============================================================================
def test_24_unauthorized_recipient_lookup_rejected(client):
    """Verify resolve-recipient without JWT returns 401 Unauthorized."""
    res = client.post(
        "/api/transactions/resolve-recipient",
        json={"query": "diya@fraudshield"},
    )
    assert res.status_code == 401


# ==============================================================================
# 25. QR Amount Extraction & Precision Handling
# ==============================================================================
def test_25_qr_amount_handling(client, seeded_users):
    """Verify parsing QR code through API properly extracts float amount."""
    token = create_access_token(identity=str(seeded_users["sender_id"]))
    res = client.post(
        "/api/transactions/parse-qr",
        headers={"Authorization": f"Bearer {token}"},
        json={"qr_data": "upi://pay?pa=diya@fraudshield&pn=Diya&am=499.99&cu=INR&tn=Subscription"},
    )
    assert res.status_code == 200
    parsed = res.get_json()["parsed_qr"]
    assert parsed["am"] == 499.99
    assert parsed["cu"] == "INR"
    assert parsed["pa"] == "diya@fraudshield"
