"""
Unit and Integration Tests for Phase 1: Customer Payment Identity & Beneficiaries.
Tests all 22 required scenarios ensuring strict data integrity, tenant isolation,
financial ledger balance deductions, and error handling.
"""

import json
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.models.transaction import Transaction
from app.models.otp_challenge import OTPChallenge


@pytest.fixture
def app():
    """Create test application instance configured with in-memory SQLite database."""
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
def auth_users(app):
    """Seed test users with payment identities."""
    with app.app_context():
        user1 = User(
            name="Arjun Sharma",
            email="arjun@example.com",
            role="USER",
            customer_account_id="FS-100001",
            primary_upi_id="arjun@fraudshield",
            phone_number="+91 98765 43210",
            account_balance=150000.0,
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
        )
        user1.set_password("UserPass123!")

        user2 = User(
            name="Priya Patel",
            email="priya@example.com",
            role="USER",
            customer_account_id="FS-100002",
            primary_upi_id="priya@fraudshield",
            phone_number="+91 98765 43211",
            account_balance=85000.0,
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
        )
        user2.set_password("UserPass123!")

        admin = User(
            name="SOC Admin",
            email="admin@example.com",
            role="ADMIN",
            customer_account_id="FS-ADMIN-01",
            primary_upi_id="admin@fraudshield",
            phone_number="+91 98765 00000",
            account_balance=0.0,
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
        )
        admin.set_password("AdminPass123!")

        db.session.add_all([user1, user2, admin])
        db.session.commit()

        # Seed 1 beneficiary for user1
        b1 = Beneficiary(
            user_id=user1.id,
            beneficiary_name="Priya Patel",
            beneficiary_upi_id="priya@fraudshield",
            beneficiary_phone="+91 98765 43211",
            nickname="Colleague",
            is_verified=True,
            status="ACTIVE",
        )
        db.session.add(b1)
        db.session.commit()

        return {
            "user1_id": user1.id,
            "user2_id": user2.id,
            "admin_id": admin.id,
            "b1_id": b1.id,
        }


def login_user(client, email, password):
    """Helper to log in and return JWT token."""
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200
    data = res.get_json()
    return data.get("access_token") or data.get("token")


# ==============================================================================
# Scenario 1 - 6: Model & Database Constraints
# ==============================================================================

def test_user_model_payment_identity_fields(app, auth_users):
    """Scenario 1: Verify User model has all payment identity fields populated."""
    with app.app_context():
        u = db.session.get(User, auth_users["user1_id"])
        assert u.customer_account_id == "FS-100001"
        assert u.primary_upi_id == "arjun@fraudshield"
        assert u.phone_number == "+91 98765 43210"
        assert u.account_balance == 150000.0
        assert u.is_phone_verified is True
        assert u.beneficiaries.count() == 1


def test_user_balance_check(app, auth_users):
    """Scenario 2: Verify user balance cannot be set below zero directly in models."""
    with app.app_context():
        u = db.session.get(User, auth_users["user1_id"])
        u.account_balance = -500.0
        # In SQLite/Postgres with CheckConstraint, commit raises an IntegrityError
        with pytest.raises(Exception):
            db.session.commit()
        db.session.rollback()


def test_beneficiary_model_creation(app, auth_users):
    """Scenario 3: Verify creating a Beneficiary model instance."""
    with app.app_context():
        b = Beneficiary(
            user_id=auth_users["user1_id"],
            beneficiary_name="Vikram Malhotra",
            beneficiary_upi_id="vikram@fraudshield",
            beneficiary_phone="+91 98765 43212",
            nickname="Brother",
            is_verified=True,
            status="ACTIVE",
        )
        db.session.add(b)
        db.session.commit()
        assert b.id is not None
        assert b.user.name == "Arjun Sharma"
        assert b.to_dict()["beneficiary_name"] == "Vikram Malhotra"


def test_beneficiary_unique_constraint_per_user(app, auth_users):
    """Scenario 4: Verify UniqueConstraint prevents duplicate UPI ID for the same user."""
    with app.app_context():
        dup = Beneficiary(
            user_id=auth_users["user1_id"],
            beneficiary_name="Priya Alternate",
            beneficiary_upi_id="priya@fraudshield",  # Already exists for user1
        )
        db.session.add(dup)
        with pytest.raises(Exception):
            db.session.commit()
        db.session.rollback()


def test_beneficiaries_can_have_same_upi_across_different_users(app, auth_users):
    """Scenario 5: Verify User A and User B can both save the same merchant/recipient UPI ID."""
    with app.app_context():
        b2 = Beneficiary(
            user_id=auth_users["user2_id"],
            beneficiary_name="Electricity Board",
            beneficiary_upi_id="merchant@fraudshield",
        )
        b1 = Beneficiary(
            user_id=auth_users["user1_id"],
            beneficiary_name="Electricity Board Office",
            beneficiary_upi_id="merchant@fraudshield",
        )
        db.session.add_all([b1, b2])
        db.session.commit()
        assert b1.id != b2.id


def test_beneficiary_cascade_deletion(app, auth_users):
    """Scenario 6: Verify deleting a user cascades and removes their beneficiaries."""
    with app.app_context():
        u = db.session.get(User, auth_users["user1_id"])
        b_id = auth_users["b1_id"]
        db.session.delete(u)
        db.session.commit()
        assert db.session.get(Beneficiary, b_id) is None


# ==============================================================================
# Scenario 7 - 10: Auth & Profile Endpoints
# ==============================================================================

def test_user_registration_generates_payment_identity(client):
    """Scenario 7: Registering a new customer auto-generates customer_account_id, primary_upi_id, and starting balance."""
    payload = {
        "name": "Kavita Rao",
        "email": "kavita@example.com",
        "password": "Password123!",
        "role": "USER",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    user_data = data["user"]
    assert user_data["customer_account_id"].startswith("FS-")
    assert user_data["primary_upi_id"] == "kavita@fraudshield"
    assert user_data["account_balance"] == 100000.0


def test_get_profile_authenticated_user(client, auth_users):
    """Scenario 8: GET /api/profile returns complete customer payment identity."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    profile = data["profile"]
    assert profile["customer_account_id"] == "FS-100001"
    assert profile["primary_upi_id"] == "arjun@fraudshield"
    assert profile["account_balance"] == 150000.0
    assert profile["phone_number"] == "+91 98765 43210"
    assert profile["beneficiary_count"] == 1


def test_get_profile_unauthorized(client):
    """Scenario 9: GET /api/profile without token returns 401."""
    res = client.get("/api/profile")
    assert res.status_code == 401


def test_update_profile_phone_and_name(client, auth_users):
    """Scenario 10: PUT /api/profile safely updates phone and name without mutating balance or ID."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "name": "Arjun K. Sharma",
        "phone_number": "+91 91111 22222",
        "account_balance": 9999999.0,  # Should be ignored/immutable
    }
    res = client.put("/api/profile", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    profile = data["profile"]
    assert profile["name"] == "Arjun K. Sharma"
    assert profile["phone_number"] in ["+91 91111 22222", "9111122222", "+919111122222"]
    assert profile["account_balance"] == 150000.0  # Balance untouched!


# ==============================================================================
# Scenario 11 - 18: Beneficiary REST APIs & IDOR Protection
# ==============================================================================

def test_create_beneficiary_success(client, auth_users):
    """Scenario 11: POST /api/beneficiaries creates a new beneficiary successfully."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "beneficiary_name": "Rohan Gupta",
        "beneficiary_upi_id": "rohan@fraudshield",
        "beneficiary_phone": "+91 98765 00001",
        "nickname": "Gym Trainer",
    }
    res = client.post("/api/beneficiaries", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    b = data["beneficiary"]
    assert b["beneficiary_name"] == "Rohan Gupta"
    assert b["beneficiary_upi_id"] == "rohan@fraudshield"
    assert b["is_verified"] is True


def test_create_beneficiary_invalid_upi(client, auth_users):
    """Scenario 12: POST /api/beneficiaries rejects invalid UPI formats with 400."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "beneficiary_name": "Invalid UPI",
        "beneficiary_upi_id": "invalid_upi_without_at_symbol",
    }
    res = client.post("/api/beneficiaries", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 400
    assert "UPI ID must contain" in res.get_json()["error"]


def test_create_beneficiary_duplicate_rejected(client, auth_users):
    """Scenario 13: POST /api/beneficiaries rejects duplicate UPI for same customer with 409."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "beneficiary_name": "Priya Duplicate",
        "beneficiary_upi_id": "priya@fraudshield",
    }
    res = client.post("/api/beneficiaries", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 409
    assert "already exists" in res.get_json()["error"]


def test_list_beneficiaries_customer_isolation(client, auth_users):
    """Scenario 14: GET /api/beneficiaries returns strictly the authenticated user's beneficiaries."""
    token1 = login_user(client, "arjun@example.com", "UserPass123!")
    token2 = login_user(client, "priya@example.com", "UserPass123!")

    res1 = client.get("/api/beneficiaries", headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 200
    assert len(res1.get_json()["beneficiaries"]) == 1

    res2 = client.get("/api/beneficiaries", headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 200
    assert len(res2.get_json()["beneficiaries"]) == 0


def test_get_single_beneficiary_success(client, auth_users):
    """Scenario 15: GET /api/beneficiaries/<id> returns beneficiary details."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    b_id = auth_users["b1_id"]
    res = client.get(f"/api/beneficiaries/{b_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.get_json()["beneficiary"]["id"] == b_id


def test_get_single_beneficiary_idor_forbidden(client, auth_users):
    """Scenario 16: GET /api/beneficiaries/<id> for another customer's beneficiary returns 403 Forbidden."""
    token2 = login_user(client, "priya@example.com", "UserPass123!")
    b_id = auth_users["b1_id"]  # Belongs to user1
    res = client.get(f"/api/beneficiaries/{b_id}", headers={"Authorization": f"Bearer {token2}"})
    assert res.status_code == 403


def test_update_beneficiary_idor_forbidden(client, auth_users):
    """Scenario 17: PUT /api/beneficiaries/<id> for another customer's beneficiary returns 403 Forbidden."""
    token2 = login_user(client, "priya@example.com", "UserPass123!")
    b_id = auth_users["b1_id"]  # Belongs to user1
    res = client.put(f"/api/beneficiaries/{b_id}", json={"beneficiary_name": "Hacked Name"}, headers={"Authorization": f"Bearer {token2}"})
    assert res.status_code == 403


def test_delete_beneficiary_success_and_idor(client, auth_users):
    """Scenario 18: Customer can delete own beneficiary and cannot delete another's."""
    token2 = login_user(client, "priya@example.com", "UserPass123!")
    b_id = auth_users["b1_id"]

    # User 2 tries to delete User 1's beneficiary -> 403
    res_idor = client.delete(f"/api/beneficiaries/{b_id}", headers={"Authorization": f"Bearer {token2}"})
    assert res_idor.status_code == 403

    # User 1 deletes own beneficiary -> 200
    token1 = login_user(client, "arjun@example.com", "UserPass123!")
    res_del = client.delete(f"/api/beneficiaries/{b_id}", headers={"Authorization": f"Bearer {token1}"})
    assert res_del.status_code == 200
    assert res_del.get_json()["success"] is True


# ==============================================================================
# Scenario 19 - 22: Simulated Financial Ledger & Transaction Processing
# ==============================================================================

def test_transaction_with_valid_beneficiary_deducts_balance_on_approval(client, auth_users):
    """Scenario 19: Low-risk payment to saved beneficiary deducts balance atomically and updates last_used_at."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "type": "PAYMENT",
        "amount": 250.0,
        "beneficiary_id": auth_users["b1_id"],
        "payment_note": "Coffee & Snack",
    }
    res = client.post("/api/transactions/predict", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "APPROVED"
    assert data["balance_before"] == 150000.0
    assert data["balance_after"] == 149750.0
    assert data["account_balance"] == 149750.0


def test_transaction_with_foreign_beneficiary_id_rejected(client, auth_users):
    """Scenario 20: Submitting transaction with another customer's beneficiary ID returns 403 Forbidden."""
    token2 = login_user(client, "priya@example.com", "UserPass123!")
    payload = {
        "type": "TRANSFER",
        "amount": 500.0,
        "beneficiary_id": auth_users["b1_id"],  # Belongs to user1
    }
    res = client.post("/api/transactions/predict", json=payload, headers={"Authorization": f"Bearer {token2}"})
    assert res.status_code == 403
    assert "Forbidden" in res.get_json()["error"]


def test_transaction_insufficient_funds_rejected(client, auth_users, app):
    """Scenario 21: Submitting transaction where amount > account_balance returns 400 Insufficient Funds."""
    with app.app_context():
        u = db.session.get(User, auth_users["user1_id"])
        u.account_balance = 200.0
        db.session.commit()

    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "type": "PAYMENT",
        "amount": 5000.0,  # Balance is ₹200.0
        "destination": "M123456",
    }
    res = client.post("/api/transactions/predict", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 400
    data = res.get_json()
    assert "Insufficient account balance" in data["error"]


def test_transaction_otp_flow_holds_balance_until_verification(client, auth_users):
    """Scenario 22: ₹92,000 transfer requires OTP; balance is held (undeducted) until OTP verification completes."""
    token = login_user(client, "arjun@example.com", "UserPass123!")
    payload = {
        "type": "TRANSFER",
        "amount": 92000.0,
        "beneficiary_id": auth_users["b1_id"],
        "payment_note": "Laptop purchase",
    }
    # 1. Initial submission -> OTP_REQUIRED
    res = client.post("/api/transactions/predict", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "OTP_REQUIRED"
    assert data["requires_otp"] is True
    tx_id = data["transaction_id"]
    # Balance should NOT be deducted yet
    assert data["balance_before"] == 150000.0
    assert data["balance_after"] == 150000.0

    # 2. Issue OTP challenge
    otp_gen = client.post("/api/otp/generate", json={"transaction_id": tx_id}, headers={"Authorization": f"Bearer {token}"})
    assert otp_gen.status_code == 200
    dev_otp = otp_gen.get_json()["_dev_simulated_otp"]

    # 3. Verify OTP -> Status transitions to APPROVED & balance is deducted atomically
    otp_verify = client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": dev_otp}, headers={"Authorization": f"Bearer {token}"})
    assert otp_verify.status_code == 200
    v_data = otp_verify.get_json()
    assert v_data["transaction"]["status"] == "APPROVED"
    assert v_data["transaction"]["balance_after"] == 58000.0  # 150,000 - 92,000
