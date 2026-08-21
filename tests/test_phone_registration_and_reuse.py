"""
Test Suite for Phase 7.3: Registration Mobile Verification & Phone Number Reuse.

Covers:
- Registration flow with phone number & SMS OTP verification
- Multiple accounts (different emails) sharing the same phone number
- My Profile phone updates and verification to any number
- OTP lifecycle (expiration, attempt limiting, reuse prevention, 60s cooldown)
- Non-interference with existing users, balances, PINs, payments, and risk detection
"""

import pytest
from datetime import datetime, timezone, timedelta
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.providers.sms_provider import DevelopmentSmsProvider


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def existing_user(app):
    with app.app_context():
        u = User(
            name="Existing Customer",
            email="existing.customer@example.com",
            phone_number="9876543210",
            role="USER",
            account_balance=100000.0,
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
            primary_upi_id="existing_customer@fraudshield",
            customer_account_id="FS-100001",
        )
        u.set_password("SecurePassword123!")
        u.set_payment_pin("123456")
        db.session.add(u)
        db.session.flush()

        # Add a prior transaction
        tx = Transaction(
            user_id=u.id,
            step=1,
            type="PAYMENT",
            amount=500.0,
            oldbalance_org=100500.0,
            newbalance_orig=100000.0,
            oldbalance_dest=0.0,
            newbalance_dest=500.0,
            risk_score=10,
            risk_level="LOW",
            decision="APPROVE_IMMEDIATELY",
            status="APPROVED",
        )
        db.session.add(tx)
        db.session.commit()
        return u


def get_token(client, email="existing.customer@example.com", password="SecurePassword123!"):
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    return res.get_json().get("access_token")


# =========================================================================
# TEST 1: New user can register with valid phone
# =========================================================================
def test_1_new_user_can_register_with_valid_phone(client):
    payload = {
        "name": "Alice Green",
        "email": "alice.green@example.com",
        "password": "Password123!",
        "phone_number": "9876123456",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["user"]["email"] == "alice.green@example.com"
    assert data["user"]["phone_number"] == "9876123456"
    assert data["user"]["is_phone_verified"] is False
    assert data["requires_phone_verification"] is True
    assert data["requires_email_verification"] is True


# =========================================================================
# TEST 2: Invalid phone number is rejected
# =========================================================================
def test_2_invalid_phone_number_is_rejected(client):
    # Invalid length (less than 10 digits)
    res = client.post("/api/auth/register", json={
        "name": "Invalid Phone User",
        "email": "invalid.phone@example.com",
        "password": "Password123!",
        "phone_number": "12345",
    })
    assert res.status_code == 400
    assert "mobile" in res.get_json()["error"].lower() or "phone" in res.get_json()["error"].lower()

    # Invalid characters
    res2 = client.post("/api/auth/register", json={
        "name": "Invalid Phone User 2",
        "email": "invalid.phone2@example.com",
        "password": "Password123!",
        "phone_number": "98765abcde",
    })
    assert res2.status_code == 400


# =========================================================================
# TEST 3: Phone OTP is generated
# =========================================================================
def test_3_phone_otp_is_generated(app, client):
    res = client.post("/api/auth/register", json={
        "name": "Bob Blue",
        "email": "bob.blue@example.com",
        "password": "Password123!",
        "phone_number": "9876998877",
    })
    assert res.status_code == 201

    with app.app_context():
        u = User.query.filter_by(email="bob.blue@example.com").first()
        assert u is not None
        assert u.phone_otp_hash is not None
        assert u.phone_otp_expires_at is not None
        # Check Development SMS provider caught the OTP
        last_otp = DevelopmentSmsProvider.get_last_otp("+919876998877")
        assert last_otp is not None
        assert len(last_otp) == 6
        assert last_otp.isdigit()


# =========================================================================
# TEST 4: Correct phone OTP verifies the user
# =========================================================================
def test_4_correct_phone_otp_verifies_the_user(client):
    client.post("/api/auth/register", json={
        "name": "Charlie Brown",
        "email": "charlie.brown@example.com",
        "password": "Password123!",
        "phone_number": "9876112233",
    })
    otp = DevelopmentSmsProvider.get_last_otp("+919876112233")
    assert otp is not None

    res = client.post("/api/auth/verify-phone-otp", json={
        "email": "charlie.brown@example.com",
        "phone_number": "9876112233",
        "otp_code": otp,
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_phone_verified"] is True
    assert data["user"]["is_phone_verified"] is True


# =========================================================================
# TEST 5: Incorrect OTP does not verify
# =========================================================================
def test_5_incorrect_otp_does_not_verify(client):
    client.post("/api/auth/register", json={
        "name": "David White",
        "email": "david.white@example.com",
        "password": "Password123!",
        "phone_number": "9876223344",
    })

    res = client.post("/api/auth/verify-phone-otp", json={
        "email": "david.white@example.com",
        "phone_number": "9876223344",
        "otp_code": "000000",
    })
    assert res.status_code == 400
    assert "incorrect" in res.get_json()["error"].lower()


# =========================================================================
# TEST 6: Expired OTP does not verify
# =========================================================================
def test_6_expired_otp_does_not_verify(app, client):
    client.post("/api/auth/register", json={
        "name": "Emma Gray",
        "email": "emma.gray@example.com",
        "password": "Password123!",
        "phone_number": "9876334455",
    })
    otp = DevelopmentSmsProvider.get_last_otp("+919876334455")

    # Fast forward OTP expiration time
    with app.app_context():
        u = User.query.filter_by(email="emma.gray@example.com").first()
        u.phone_otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        db.session.commit()

    res = client.post("/api/auth/verify-phone-otp", json={
        "email": "emma.gray@example.com",
        "phone_number": "9876334455",
        "otp_code": otp,
    })
    assert res.status_code == 400
    assert "expired" in res.get_json()["error"].lower()


# =========================================================================
# TEST 7: Phone OTP cannot be reused
# =========================================================================
def test_7_phone_otp_cannot_be_reused(client):
    client.post("/api/auth/register", json={
        "name": "Frank Black",
        "email": "frank.black@example.com",
        "password": "Password123!",
        "phone_number": "9876445566",
    })
    otp = DevelopmentSmsProvider.get_last_otp("+919876445566")

    # First verification succeeds
    res1 = client.post("/api/auth/verify-phone-otp", json={
        "email": "frank.black@example.com",
        "phone_number": "9876445566",
        "otp_code": otp,
    })
    assert res1.status_code == 200

    # Second attempt with same code returns already verified
    res2 = client.post("/api/auth/verify-phone-otp", json={
        "email": "frank.black@example.com",
        "phone_number": "9876445566",
        "otp_code": otp,
    })
    assert res2.status_code == 200
    assert "already verified" in res2.get_json()["message"].lower()


# =========================================================================
# TEST 8: OTP resend cooldown works
# =========================================================================
def test_8_otp_resend_cooldown_works(client):
    client.post("/api/auth/register", json={
        "name": "Grace Hopper",
        "email": "grace.hopper@example.com",
        "password": "Password123!",
        "phone_number": "9876556677",
    })

    # Immediate resend should trigger 429 rate limit (60s cooldown)
    res = client.post("/api/auth/resend-phone-otp", json={
        "email": "grace.hopper@example.com",
        "phone_number": "9876556677",
    })
    assert res.status_code == 429
    assert "wait" in res.get_json()["error"].lower()


# =========================================================================
# TEST 9: Two different email accounts can use the SAME phone number
# =========================================================================
def test_9_two_different_email_accounts_can_use_the_same_phone_number(client):
    shared_phone = "9876000111"

    # User 1 registration
    res1 = client.post("/api/auth/register", json={
        "name": "User One",
        "email": "user1.shared@example.com",
        "password": "Password123!",
        "phone_number": shared_phone,
    })
    assert res1.status_code == 201
    otp1 = DevelopmentSmsProvider.get_last_otp(f"+91{shared_phone}")

    # Verify User 1 phone
    v1 = client.post("/api/auth/verify-phone-otp", json={
        "email": "user1.shared@example.com",
        "phone_number": shared_phone,
        "otp_code": otp1,
    })
    assert v1.status_code == 200

    # User 2 registration with the EXACT SAME phone number MUST SUCCEED (Phase 7.3)
    res2 = client.post("/api/auth/register", json={
        "name": "User Two",
        "email": "user2.shared@example.com",
        "password": "Password123!",
        "phone_number": shared_phone,
    })
    assert res2.status_code == 201
    otp2 = DevelopmentSmsProvider.get_last_otp(f"+91{shared_phone}")

    # Verify User 2 phone
    v2 = client.post("/api/auth/verify-phone-otp", json={
        "email": "user2.shared@example.com",
        "phone_number": shared_phone,
        "otp_code": otp2,
    })
    assert v2.status_code == 200

    # Confirm both users exist independently with verified phones
    data1 = v1.get_json()["user"]
    data2 = v2.get_json()["user"]
    assert data1["email"] == "user1.shared@example.com"
    assert data2["email"] == "user2.shared@example.com"
    assert data1["id"] != data2["id"]
    assert data1["phone_number"] == shared_phone
    assert data2["phone_number"] == shared_phone


# =========================================================================
# TEST 10: Changing phone from My Profile works
# =========================================================================
def test_10_changing_phone_from_my_profile_works(client, existing_user):
    token = get_token(client)
    res = client.put(
        "/api/profile",
        json={"phone_number": "9111222333"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["phone_verification_required"] is True
    assert data["profile"]["phone_number"] == "9111222333"


# =========================================================================
# TEST 11: Changing phone to a number already used by another account works
# =========================================================================
def test_11_changing_phone_to_number_used_by_another_account_works(client, existing_user):
    # Register another user with phone "9998887776"
    client.post("/api/auth/register", json={
        "name": "Other Account",
        "email": "other.account@example.com",
        "password": "Password123!",
        "phone_number": "9998887776",
    })

    # Existing user changes their phone to "9998887776" -> MUST SUCCEED (Phase 7.3)
    token = get_token(client)
    res = client.put(
        "/api/profile",
        json={"phone_number": "9998887776"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["profile"]["phone_number"] == "9998887776"
    assert data["phone_verification_required"] is True


# =========================================================================
# TEST 12: Changing phone resets is_phone_verified to false
# =========================================================================
def test_12_changing_phone_resets_is_phone_verified_to_false(client, existing_user):
    token = get_token(client)
    res = client.put(
        "/api/profile",
        json={"phone_number": "9777888999"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    profile = res.get_json()["profile"]
    assert profile["is_phone_verified"] is False


# =========================================================================
# TEST 13: Correct OTP verifies the changed phone
# =========================================================================
def test_13_correct_otp_verifies_the_changed_phone(client, existing_user):
    token = get_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9666555444"},
        headers={"Authorization": f"Bearer {token}"},
    )
    otp = DevelopmentSmsProvider.get_last_otp("+919666555444")
    assert otp is not None

    res = client.post(
        "/api/profile/phone/verify-otp",
        json={"otp_code": otp},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_phone_verified"] is True
    assert data["profile"]["is_phone_verified"] is True


# =========================================================================
# TEST 14: Authenticated user cannot modify another user's profile
# =========================================================================
def test_14_authenticated_user_cannot_modify_another_users_profile(app, client, existing_user):
    # Register user 2
    client.post("/api/auth/register", json={
        "name": "User Two",
        "email": "user.two@example.com",
        "password": "Password123!",
        "phone_number": "9555444333",
    })
    token = get_token(client)  # Existing user token (User 1)

    # Put request updates ONLY the authenticated user (JWT identity)
    res = client.put(
        "/api/profile",
        json={"name": "Attacker Update", "user_id": 999},  # Injected ID should be ignored
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200

    with app.app_context():
        u2 = User.query.filter_by(email="user.two@example.com").first()
        assert u2.name == "User Two"  # Unchanged!


# =========================================================================
# TEST 15: Existing user's balance remains unchanged
# =========================================================================
def test_15_existing_user_balance_remains_unchanged(client, existing_user):
    token = get_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9444333222"},
        headers={"Authorization": f"Bearer {token}"},
    )
    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    profile = res.get_json()["profile"]
    assert profile["account_balance"] == 100000.0


# =========================================================================
# TEST 16: Existing transactions remain unchanged
# =========================================================================
def test_16_existing_transactions_remain_unchanged(app, client, existing_user):
    token = get_token(client)
    client.put(
        "/api/profile",
        json={"name": "New Name"},
        headers={"Authorization": f"Bearer {token}"},
    )
    with app.app_context():
        u = User.query.filter_by(email="existing.customer@example.com").first()
        txs = Transaction.query.filter_by(user_id=u.id).all()
        assert len(txs) == 1
        assert txs[0].amount == 500.0
        assert txs[0].type == "PAYMENT"


# =========================================================================
# TEST 17: Existing payment PIN remains unchanged
# =========================================================================
def test_17_existing_payment_pin_remains_unchanged(app, client, existing_user):
    token = get_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9333222111"},
        headers={"Authorization": f"Bearer {token}"},
    )
    with app.app_context():
        u = User.query.filter_by(email="existing.customer@example.com").first()
        assert u.is_pin_set is True
        is_valid, _ = u.check_payment_pin("123456")
        assert is_valid is True


# =========================================================================
# TEST 18: Existing email verification remains unchanged
# =========================================================================
def test_18_existing_email_verification_remains_unchanged(client, existing_user):
    token = get_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9222111000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    profile = res.get_json()["profile"]
    assert profile["is_email_verified"] is True


# =========================================================================
# TEST 19: Existing login still works
# =========================================================================
def test_19_existing_login_still_works(client, existing_user):
    res = client.post("/api/auth/login", json={
        "email": "existing.customer@example.com",
        "password": "SecurePassword123!",
    })
    assert res.status_code == 200
    assert "access_token" in res.get_json()


# =========================================================================
# TEST 20: Payment processing still works
# =========================================================================
def test_20_payment_processing_still_works(client, existing_user):
    token = get_token(client)
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "destination": "merchant123@fraudshield",
            "payment_pin": "123456",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["decision"] in ["APPROVE_IMMEDIATELY", "TRIGGER_OTP_VERIFICATION"]
    assert data["status"] in ["APPROVED", "OTP_REQUIRED"]


# =========================================================================
# TEST 21: Fraud detection still works
# =========================================================================
def test_21_fraud_detection_still_works(client, existing_user):
    token = get_token(client)
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "PAYMENT",
            "amount": 100.0,
            "destination": "store@fraudshield",
            "payment_pin": "123456",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert "explanation" in data


# =========================================================================
# TEST 22: HIGH risk transaction still triggers OTP
# =========================================================================
def test_22_high_risk_transaction_still_triggers_otp(client, existing_user):
    token = get_token(client)
    # Trigger High-Value Transfer Policy (> ₹50,000)
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "TRANSFER",
            "amount": 85000.0,
            "destination": "external@fraudshield",
            "payment_pin": "123456",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "HIGH"
    assert data["requires_otp"] is True
    assert data["decision"] == "TRIGGER_OTP_VERIFICATION"


# =========================================================================
# TEST 23: LOW/MEDIUM risk transaction behavior remains unchanged
# =========================================================================
def test_23_low_medium_risk_transaction_behavior_remains_unchanged(client, existing_user):
    token = get_token(client)
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "PAYMENT",
            "amount": 500.0,
            "destination": "trusted_merchant@fraudshield",
            "payment_pin": "123456",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] in ["LOW", "MEDIUM"]
    if data["risk_level"] == "MEDIUM":
        assert data["requires_otp"] is True
        assert data["status"] == "OTP_REQUIRED"
    else:
        assert data["requires_otp"] is False
        assert data["status"] == "APPROVED"
