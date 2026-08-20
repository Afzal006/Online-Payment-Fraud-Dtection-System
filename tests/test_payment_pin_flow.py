"""
Tests for Payment PIN Security Flow in FraudShield AI.

Covers end-to-end PIN lifecycle:
1. Set PIN successfully with valid password and matching 4-6 digit numeric PIN.
2. Non-numeric PIN rejected.
3. PIN shorter than 4 digits rejected.
4. PIN longer than 6 digits rejected.
5. PIN mismatch with confirm_pin rejected.
6. Wrong account password rejects PIN setup/change.
7. Unauthenticated PIN setup request rejected (401).
8. Payment PIN status endpoint reflects setup and lockout states.
9. Correct PIN verification succeeds.
10. Incorrect PIN verification fails with remaining attempt count.
11. 3 consecutive failed attempts trigger 15-minute PIN lockout.
12. Locked PIN rejects subsequent authentication attempts during cooldown.
13. Payment PIN recovers and authenticates after lockout expiry.
14. Payment request without PIN for configured user rejected (401).
15. Payment request for unconfigured PIN user rejected (401).
16. Payment with wrong PIN causes zero balance debit.
17. Payment with locked PIN causes zero balance debit.
18. Payment with correct PIN enters AI fraud detection engine.
19. High-risk payment with correct PIN triggers step-up OTP challenge.
20. Critical-risk payment with correct PIN triggers blocking/review policy with zero debit.
21. Successful low-risk payment with correct PIN atomically debits exactly once.
22. Duplicate payment submission with idempotency key prevents double debit.
23. Plaintext PIN is never stored in database (hashed with Werkzeug pbkdf2/scrypt).
24. Payment PIN is never returned in user profile or transaction API responses.
25. Payment PIN change with correct new password successfully updates PIN.
"""

from datetime import datetime, timezone, timedelta
import pytest
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.services.payment_service import PaymentService
from app.services.transaction_service import TransactionService


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
def test_users(app):
    """Seed sender, recipient, and unconfigured user."""
    with app.app_context():
        # User 1: Configured PIN
        sender = User(
            name="Vikram Rao",
            email="vikram.rao@example.com",
            phone_number="9876543001",
            customer_account_id="FS-300001",
            primary_upi_id="vikram@fraudshield",
            account_balance=100000.0,
            role="USER",
            is_active=True,
            is_phone_verified=True,
        )
        sender.set_password("AccountPass123!")
        sender.set_payment_pin("4829")

        # User 2: Recipient
        recipient = User(
            name="Ananya Sharma",
            email="ananya.sharma@example.com",
            phone_number="9876543002",
            customer_account_id="FS-300002",
            primary_upi_id="ananya@fraudshield",
            account_balance=25000.0,
            role="USER",
            is_active=True,
            is_phone_verified=True,
        )
        recipient.set_password("ReceiverPass123!")
        recipient.set_payment_pin("9988")

        # User 3: No PIN configured
        no_pin_user = User(
            name="Karan Verma",
            email="karan.verma@example.com",
            phone_number="9876543003",
            customer_account_id="FS-300003",
            primary_upi_id="karan@fraudshield",
            account_balance=50000.0,
            role="USER",
            is_active=True,
            is_phone_verified=True,
        )
        no_pin_user.set_password("KaranPass123!")

        db.session.add_all([sender, recipient, no_pin_user])
        db.session.commit()

        return {
            "sender_id": sender.id,
            "sender_email": sender.email,
            "recipient_id": recipient.id,
            "recipient_email": recipient.email,
            "no_pin_id": no_pin_user.id,
            "no_pin_email": no_pin_user.email,
        }


# ==============================================================================
# 1. Set PIN Successfully
# ==============================================================================
def test_1_set_pin_successfully(client, app, test_users):
    """Verify user can set 4-6 digit numeric payment PIN with valid password."""
    token = create_access_token(identity=str(test_users["no_pin_id"]))
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "KaranPass123!",
            "pin": "765432",
            "confirm_pin": "765432",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_pin_set"] is True
    assert "successfully" in data["message"].lower()

    # Verify database state
    with app.app_context():
        user = db.session.get(User, test_users["no_pin_id"])
        assert user.is_pin_set is True
        assert user.payment_pin_hash is not None
        assert user.payment_pin_hash != "765432"  # Must be hashed


# ==============================================================================
# 2-5. Invalid PIN Validations
# ==============================================================================
def test_2_non_numeric_pin_rejected(client, test_users):
    """Verify alphabetic or special character PIN is rejected."""
    token = create_access_token(identity=str(test_users["no_pin_id"]))
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "KaranPass123!",
            "pin": "12AB",
            "confirm_pin": "12AB",
        },
    )
    assert res.status_code == 400
    assert "numeric digits" in res.get_json()["error"].lower()


def test_3_short_pin_rejected(client, test_users):
    """Verify PIN shorter than 4 digits is rejected."""
    token = create_access_token(identity=str(test_users["no_pin_id"]))
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "KaranPass123!",
            "pin": "123",
            "confirm_pin": "123",
        },
    )
    assert res.status_code == 400
    assert "4 to 6" in res.get_json()["error"]


def test_4_long_pin_rejected(client, test_users):
    """Verify PIN longer than 6 digits is rejected."""
    token = create_access_token(identity=str(test_users["no_pin_id"]))
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "KaranPass123!",
            "pin": "1234567",
            "confirm_pin": "1234567",
        },
    )
    assert res.status_code == 400
    assert "4 to 6" in res.get_json()["error"]


def test_5_pin_mismatch_rejected(client, test_users):
    """Verify mismatch between pin and confirm_pin is rejected."""
    token = create_access_token(identity=str(test_users["no_pin_id"]))
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "KaranPass123!",
            "pin": "1234",
            "confirm_pin": "1235",
        },
    )
    assert res.status_code == 400
    assert "match" in res.get_json()["error"].lower()


# ==============================================================================
# 6-7. Authentication & Authorization Guards
# ==============================================================================
def test_6_wrong_password_rejected(client, test_users):
    """Verify wrong account password rejects PIN modification."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "IncorrectPassword123!",
            "pin": "9999",
            "confirm_pin": "9999",
        },
    )
    assert res.status_code == 400
    assert "incorrect" in res.get_json()["error"].lower() or "password" in res.get_json()["error"].lower()


def test_7_unauthenticated_pin_set_rejected(client):
    """Verify unauthenticated requests cannot set PIN."""
    res = client.post(
        "/api/auth/payment-pin/set",
        json={
            "password": "SomePassword123!",
            "pin": "1234",
            "confirm_pin": "1234",
        },
    )
    assert res.status_code == 401


# ==============================================================================
# 8. Status Endpoint
# ==============================================================================
def test_8_payment_pin_status_endpoint(client, test_users):
    """Verify GET /api/auth/payment-pin/status returns accurate state."""
    # Configured user
    token_sender = create_access_token(identity=str(test_users["sender_id"]))
    res_sender = client.get("/api/auth/payment-pin/status", headers={"Authorization": f"Bearer {token_sender}"})
    assert res_sender.status_code == 200
    assert res_sender.get_json()["is_pin_set"] is True
    assert res_sender.get_json()["is_pin_locked"] is False

    # Unconfigured user
    token_nopin = create_access_token(identity=str(test_users["no_pin_id"]))
    res_nopin = client.get("/api/auth/payment-pin/status", headers={"Authorization": f"Bearer {token_nopin}"})
    assert res_nopin.status_code == 200
    assert res_nopin.get_json()["is_pin_set"] is False


# ==============================================================================
# 9-13. PIN Verification, Failures, Lockout, and Recovery
# ==============================================================================
def test_9_correct_pin_verification(app, test_users):
    """Verify check_payment_pin succeeds with correct PIN."""
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        is_valid, err = user.check_payment_pin("4829")
        assert is_valid is True
        assert err is None
        assert user.pin_failed_attempts == 0


def test_10_wrong_pin_verification_failure(app, test_users):
    """Verify check_payment_pin fails with incorrect PIN and decrements attempts."""
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        is_valid, err = user.check_payment_pin("0000")
        assert is_valid is False
        assert "2 attempt(s) remaining" in err
        assert user.pin_failed_attempts == 1


def test_11_three_failed_attempts_trigger_lockout(app, test_users):
    """Verify 3 consecutive wrong attempts lock the PIN for 15 minutes."""
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        user.check_payment_pin("0001")
        user.check_payment_pin("0002")
        is_valid, err = user.check_payment_pin("0003")

        assert is_valid is False
        assert user.is_pin_locked is True
        assert "locked for 15 minutes" in err.lower()


def test_12_locked_pin_rejects_subsequent_attempts(app, test_users):
    """Verify locked PIN immediately rejects even the correct PIN during cooldown."""
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        user.pin_failed_attempts = 3
        user.pin_locked_until = datetime.now(timezone.utc) + timedelta(minutes=14)

        is_valid, err = user.check_payment_pin("4829")  # Correct PIN
        assert is_valid is False
        assert "locked" in err.lower()


def test_13_pin_recovers_after_lockout_cooldown(app, test_users):
    """Verify PIN automatically unlocks after lockout period elapses."""
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        user.pin_failed_attempts = 3
        user.pin_locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)  # Expired

        is_valid, err = user.check_payment_pin("4829")
        assert is_valid is True
        assert err is None
        assert user.is_pin_locked is False
        assert user.pin_failed_attempts == 0


# ==============================================================================
# 14-17. Payment Authorization & Zero-Debit Enforcement
# ==============================================================================
def test_14_payment_without_pin_rejected(client, test_users):
    """Verify payment request without PIN is rejected with 401."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "destination_upi_id": "ananya@fraudshield",
        },
    )
    assert res.status_code == 401
    assert "pin is required" in res.get_json()["error"].lower()


def test_15_payment_by_unconfigured_user_rejected(client, test_users):
    """Verify payment by user without configured PIN is rejected with 401."""
    token = create_access_token(identity=str(test_users["no_pin_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "1234",
        },
    )
    assert res.status_code == 401
    assert "payment pin has not been configured" in res.get_json()["error"].lower()


def test_16_wrong_pin_causes_zero_debit(client, app, test_users):
    """Verify payment with wrong PIN fails and leaves sender balance untouched."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 5000.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "0000",
        },
    )
    assert res.status_code == 401
    assert "incorrect" in res.get_json()["error"].lower()

    # Zero debit check
    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 100000.0


def test_17_locked_pin_payment_causes_zero_debit(client, app, test_users):
    """Verify locked PIN payment fails with 429 and causes zero balance debit."""
    token = create_access_token(identity=str(test_users["sender_id"]))

    # Exhaust 3 attempts
    for _ in range(3):
        client.post(
            "/api/transactions/predict",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "type": "PAYMENT",
                "amount": 100.0,
                "destination_upi_id": "ananya@fraudshield",
                "payment_pin": "0000",
            },
        )

    # 4th attempt with correct PIN while locked
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 1000.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "4829",
        },
    )
    assert res.status_code == 429
    assert "locked" in res.get_json()["error"].lower()

    # Verify balance was never touched
    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 100000.0


# ==============================================================================
# 18-22. AI Fraud Defense, Risk Engine & Atomic Ledger
# ==============================================================================
def test_18_correct_pin_enters_risk_engine(client, test_users):
    """Verify payment with correct PIN successfully reaches ML risk engine."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 350.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "4829",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "risk_score" in data
    assert "decision" in data
    assert data["status"] == "APPROVED"


def test_19_high_risk_step_up_otp_after_pin(client, app, test_users):
    """Verify high-risk payment with correct PIN triggers OTP challenge before debit."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "TRANSFER",
            "amount": 85000.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "4829",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["requires_otp"] is True
    assert data["status"] == "OTP_REQUIRED"
    tx_id = data["transaction_id"]

    # Balance NOT debited yet
    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 100000.0

    # Request and verify OTP
    res_gen = client.post(
        "/api/otp/generate",
        headers={"Authorization": f"Bearer {token}"},
        json={"transaction_id": tx_id},
    )
    otp_code = res_gen.get_json()["_dev_simulated_otp"]

    res_ver = client.post(
        "/api/otp/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"transaction_id": tx_id, "otp_code": otp_code},
    )
    assert res_ver.status_code == 200
    assert res_ver.get_json()["transaction"]["status"] == "APPROVED"

    # Now balance is debited
    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 15000.0  # 100000 - 85000


def test_20_critical_risk_blocked_zero_debit(client, app, test_users):
    """Verify account drain / critical risk payment is blocked with ₹0 debit."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "CASH_OUT",
            "amount": 1000000.0,
            "destination_upi_id": "drain.hacker@upi",
            "oldbalance_org": 1000000.0,
            "newbalance_orig": 0.0,
            "payment_pin": "4829",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] in ["REJECTED", "UNDER_REVIEW"]

    # Verify balance was NOT touched
    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 100000.0


def test_21_successful_low_risk_atomic_debit(client, app, test_users):
    """Verify approved payment atomically debits sender once and records transaction."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 2500.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "4829",
        },
    )
    assert res.status_code == 200
    assert res.get_json()["status"] == "APPROVED"

    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 97500.0  # 100000 - 2500

        tx = Transaction.query.filter_by(user_id=sender.id).first()
        assert tx is not None
        assert tx.amount == 2500.0


def test_22_idempotency_prevents_double_debit(client, app, test_users):
    """Verify duplicate submission with same idempotency key executes exactly once."""
    token = create_access_token(identity=str(test_users["sender_id"]))
    payload = {
        "type": "PAYMENT",
        "amount": 1000.0,
        "destination_upi_id": "ananya@fraudshield",
        "payment_pin": "4829",
        "idempotency_key": "PIN-IDEMPOTENCY-TEST-KEY-01",
    }

    res1 = client.post("/api/transactions/predict", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res1.status_code == 200

    res2 = client.post("/api/transactions/predict", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res2.status_code == 200

    with app.app_context():
        sender = db.session.get(User, test_users["sender_id"])
        assert sender.account_balance == 99000.0  # Debited only once (100000 - 1000)


# ==============================================================================
# 23-25. Cryptographic Security & Isolation
# ==============================================================================
def test_23_pin_never_stored_plaintext(app, test_users):
    """Verify payment PIN is hashed using secure cryptographic hash function."""
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        assert user.payment_pin_hash != "4829"
        assert check_password_hash(user.payment_pin_hash, "4829") is True
        assert check_password_hash(user.payment_pin_hash, "wrong") is False


def test_24_pin_never_returned_in_api_responses(client, test_users):
    """Verify PIN or PIN hash is never present in profile or transaction responses."""
    token = create_access_token(identity=str(test_users["sender_id"]))

    # Profile response
    res_prof = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    prof_data = res_prof.get_json()
    assert "payment_pin" not in prof_data.get("profile", {})
    assert "payment_pin_hash" not in prof_data.get("profile", {})

    # PIN status response
    res_status = client.get("/api/auth/payment-pin/status", headers={"Authorization": f"Bearer {token}"})
    status_data = res_status.get_json()
    assert "payment_pin" not in status_data
    assert "payment_pin_hash" not in status_data

    # Transaction predict response
    res_tx = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "type": "PAYMENT",
            "amount": 100.0,
            "destination_upi_id": "ananya@fraudshield",
            "payment_pin": "4829",
        },
    )
    tx_data = res_tx.get_json()
    assert "payment_pin" not in tx_data
    assert "payment_pin_hash" not in tx_data


def test_25_change_existing_pin_with_password(client, app, test_users):
    """Verify user can update their existing Payment PIN by supplying account password."""
    token = create_access_token(identity=str(test_users["sender_id"]))

    # Change PIN from 4829 to 5566
    res = client.post(
        "/api/auth/payment-pin/set",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "password": "AccountPass123!",
            "pin": "5566",
            "confirm_pin": "5566",
        },
    )
    assert res.status_code == 200

    # Old PIN should now fail
    with app.app_context():
        user = db.session.get(User, test_users["sender_id"])
        is_old_valid, _ = user.check_payment_pin("4829")
        assert is_old_valid is False

        # New PIN should succeed
        is_new_valid, _ = user.check_payment_pin("5566")
        assert is_new_valid is True
