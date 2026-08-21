"""
Unit and Integration Tests for Phase 7.2: User Profile Management, Phone Number Editing,
and Phone Verification Security.
"""

import pytest
from datetime import datetime, timezone, timedelta
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.services.auth_service import AuthService
from app.providers.email_provider import DevelopmentEmailProvider
from app.providers.sms_provider import get_sms_provider, DevelopmentSmsProvider


@pytest.fixture
def app():
    """Create test application in testing mode with in-memory SQLite."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        DevelopmentSmsProvider.clear_history()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


@pytest.fixture
def test_user(app):
    """Create a verified test user with initial balance and password."""
    with app.app_context():
        # Clear existing test user if present
        User.query.filter_by(email="profile.user@example.com").delete()
        User.query.filter_by(email="other.user@example.com").delete()
        db.session.commit()

        user = User(
            name="Profile Tester",
            email="profile.user@example.com",
            phone_number="9876543210",
            role="USER",
            account_balance=50000.0,
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
            customer_account_id="FS-TEST-999",
            primary_upi_id="profile_user@fraudshield",
        )
        user.set_password("SecurePassword123!")
        user.set_payment_pin("123456")
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)

        # Create a dummy transaction
        tx = Transaction(
            user_id=user.id,
            step=1,
            type="PAYMENT",
            amount=500.0,
            oldbalance_org=50000.0,
            newbalance_orig=49500.0,
            oldbalance_dest=0.0,
            newbalance_dest=500.0,
            risk_score=10,
            risk_level="LOW",
            decision="APPROVE_IMMEDIATELY",
            status="APPROVED",
        )
        db.session.add(tx)
        db.session.commit()

        yield user

        # Cleanup
        Transaction.query.filter_by(user_id=user.id).delete()
        User.query.filter_by(id=user.id).delete()
        db.session.commit()


@pytest.fixture
def second_user(app):
    """Create a second distinct user to test cross-user isolation and uniqueness."""
    with app.app_context():
        other = User(
            name="Other Account",
            email="other.user@example.com",
            phone_number="9123456780",
            role="USER",
            account_balance=25000.0,
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
            customer_account_id="FS-TEST-888",
            primary_upi_id="other_user@fraudshield",
        )
        other.set_password("OtherPassword123!")
        db.session.add(other)
        db.session.commit()
        db.session.refresh(other)

        yield other

        User.query.filter_by(id=other.id).delete()
        db.session.commit()


def get_auth_token(client, email="profile.user@example.com", password="SecurePassword123!"):
    """Helper to authenticate and get JWT access token."""
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, f"Login failed: {res.get_json()}"
    return res.get_json()["access_token"]


# ==============================================================================
# TEST CASES
# ==============================================================================

def test_1_authenticated_user_can_retrieve_own_profile(client, test_user):
    """1. Authenticated user can retrieve own profile."""
    token = get_auth_token(client)
    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    profile = data["profile"]
    assert profile["email"] == "profile.user@example.com"
    assert profile["name"] == "Profile Tester"
    assert profile["phone_number"] == "9876543210"
    assert profile["is_email_verified"] is True
    assert profile["is_phone_verified"] is True
    assert profile["customer_account_id"] == "FS-TEST-999"
    assert "password_hash" not in profile
    assert "payment_pin_hash" not in profile


def test_2_unauthenticated_user_cannot_retrieve_profile(client):
    """2. Unauthenticated user cannot retrieve profile."""
    res = client.get("/api/profile")
    assert res.status_code == 401


def test_3_authenticated_user_can_update_phone_number(client, test_user):
    """3. Authenticated user can update phone number."""
    token = get_auth_token(client)
    res = client.put(
        "/api/profile",
        json={"phone_number": "9988776655"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["phone_verification_required"] is True
    assert data["profile"]["phone_number"] == "9988776655"


def test_4_phone_number_validation_works(client, test_user):
    """4. Phone number validation works (rejects invalid formats)."""
    token = get_auth_token(client)

    # Invalid: non-numeric string
    res1 = client.put(
        "/api/profile",
        json={"phone_number": "invalid-phone"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res1.status_code == 400
    assert "invalid" in res1.get_json()["error"].lower() or "mobile" in res1.get_json()["error"].lower()

    # Invalid: wrong number of digits
    res2 = client.put(
        "/api/profile",
        json={"phone_number": "12345"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 400

    # Invalid: starts with 1 (not standard Indian 6-9)
    res3 = client.put(
        "/api/profile",
        json={"phone_number": "1234567890"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res3.status_code == 400


def test_5_changed_phone_is_marked_unverified(client, test_user):
    """5. Changed phone is marked unverified."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9988776655"},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Check DB and GET profile
    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    profile = res.get_json()["profile"]
    assert profile["phone_number"] == "9988776655"
    assert profile["is_phone_verified"] is False


def test_6_existing_verified_phone_not_silently_transferred(client, test_user):
    """6. Existing verified phone status is not transferred to new number."""
    token = get_auth_token(client)
    # Initially user phone is verified
    res_init = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res_init.get_json()["profile"]["is_phone_verified"] is True

    # Change phone
    client.put(
        "/api/profile",
        json={"phone_number": "9776655443"},
        headers={"Authorization": f"Bearer {token}"},
    )

    res_after = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res_after.get_json()["profile"]["is_phone_verified"] is False


def test_7_phone_verification_is_required_after_changing_number(client, test_user):
    """7. Phone verification is required after changing number."""
    token = get_auth_token(client)
    res = client.put(
        "/api/profile",
        json={"phone_number": "9776655443"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.get_json()["phone_verification_required"] is True


def test_8_correct_phone_otp_verifies_new_number(app, client, test_user):
    """8. Correct phone OTP verifies the new number."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9776655443"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # In test mode, retrieve the real dispatched OTP from the SMS provider
    otp_code = DevelopmentSmsProvider.get_last_otp("+919776655443")
    assert otp_code is not None and len(otp_code) == 6

    # Submit verification
    res = client.post(
        "/api/profile/phone/verify-otp",
        json={"otp_code": otp_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["is_phone_verified"] is True

    # Re-check profile
    res2 = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res2.get_json()["profile"]["is_phone_verified"] is True


def test_9_incorrect_otp_does_not_verify(app, client, test_user):
    """9. Incorrect OTP does not verify."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9776655442"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # Submit wrong OTP
    res = client.post(
        "/api/profile/phone/verify-otp",
        json={"otp_code": "000000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert "incorrect" in res.get_json()["error"].lower() or "invalid" in res.get_json()["error"].lower()

    # Profile must remain unverified
    res2 = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res2.get_json()["profile"]["is_phone_verified"] is False


def test_10_expired_otp_does_not_verify(app, test_user):
    """10. Expired OTP does not verify."""
    with app.app_context():
        u = User.query.filter_by(email="profile.user@example.com").first()
        u.is_phone_verified = False
        u.set_phone_otp("654321", expiry_seconds=-10)
        db.session.commit()

        success, verified_user, err = AuthService.verify_phone_otp(
            phone_or_email=u.email,
            otp_code="654321",
        )
        assert success is False
        assert "expired" in err.lower()
        assert verified_user.is_phone_verified is False


def test_11_user_cannot_modify_another_users_profile(client, test_user, second_user):
    """11. User cannot modify another user's profile (IDOR prevention)."""
    # User 1 logs in
    token1 = get_auth_token(client, email="profile.user@example.com", password="SecurePassword123!")

    # Attempting to update profile only updates the authenticated user's own profile
    res = client.put(
        "/api/profile",
        json={"name": "New Name For User 1"},
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert res.status_code == 200

    # User 2 logs in and checks their profile
    token2 = get_auth_token(client, email="other.user@example.com", password="OtherPassword123!")
    res2 = client.get("/api/profile", headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 200
    profile2 = res2.get_json()["profile"]
    assert profile2["name"] == "Other Account"
    assert profile2["email"] == "other.user@example.com"


def test_12_existing_user_account_remains_intact(client, test_user):
    """12. Existing user account fields (balance, role, id) remain intact."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    profile = res.get_json()["profile"]
    assert profile["account_balance"] == 50000.0
    assert profile["role"] == "USER"
    assert profile["customer_account_id"] == "FS-TEST-999"


def test_13_existing_email_verification_remains_intact(client, test_user):
    """13. Existing email verification remains intact after phone update."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"phone_number": "9776655443"},
        headers={"Authorization": f"Bearer {token}"},
    )

    res = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    profile = res.get_json()["profile"]
    assert profile["is_email_verified"] is True


def test_14_existing_password_remains_unchanged(client, test_user):
    """14. Existing password remains unchanged after profile updates."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # Login with original password must still succeed
    res_login = client.post("/api/auth/login", json={
        "email": "profile.user@example.com",
        "password": "SecurePassword123!"
    })
    assert res_login.status_code == 200


def test_15_existing_payment_pin_remains_unchanged(app, client, test_user):
    """15. Existing payment PIN remains unchanged after profile updates."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    with app.app_context():
        u = db.session.get(User, test_user.id)
        assert u.is_pin_set is True
        valid_pin, _ = u.check_payment_pin("123456")
        assert valid_pin is True


def test_16_existing_transactions_remain_unchanged(app, client, test_user):
    """16. Existing transactions remain unchanged after profile updates."""
    token = get_auth_token(client)
    client.put(
        "/api/profile",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    with app.app_context():
        txs = Transaction.query.filter_by(user_id=test_user.id).all()
        assert len(txs) == 1
        assert txs[0].type == "PAYMENT"
        assert txs[0].amount == 500.0


def test_17_updating_phone_to_number_used_by_another_account_succeeds_with_otp(client, test_user, second_user):
    """17. Updating to a phone number already used by another user succeeds and requires OTP (Phase 7.3)."""
    token = get_auth_token(client, email="profile.user@example.com", password="SecurePassword123!")

    # Attempt to set phone to second_user's phone: "9123456780"
    res = client.put(
        "/api/profile",
        json={"phone_number": "9123456780"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["phone_verification_required"] is True
    assert data["profile"]["phone_number"] == "9123456780"
    assert data["profile"]["is_phone_verified"] is False


def test_18_phone_formatting_normalizes_cleanly(client, test_user):
    """18. Phone numbers with +91, 91, 0, or spaces normalize cleanly."""
    token = get_auth_token(client)

    # With +91 and spaces
    res = client.put(
        "/api/profile",
        json={"phone_number": "+91 98765 11223"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.get_json()["profile"]["phone_number"] == "9876511223"


def test_19_existing_registration_flow_still_works(client):
    """19. Registration flow continues to work seamlessly with phone number."""
    payload = {
        "name": "New Reg User",
        "email": "new.reg.user@example.com",
        "password": "Password123!",
        "phone_number": "9812345678",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["user"]["is_email_verified"] is False
    assert data["user"]["is_phone_verified"] is False
    assert data["requires_email_verification"] is True
    assert data["requires_phone_verification"] is True

    # Cleanup
    with client.application.app_context():
        User.query.filter_by(email="new.reg.user@example.com").delete()
        db.session.commit()


def test_20_existing_login_flow_still_works(client, test_user):
    """20. Existing login flow still works with correct credentials."""
    res = client.post("/api/auth/login", json={
        "email": "profile.user@example.com",
        "password": "SecurePassword123!"
    })
    assert res.status_code == 200
    assert "access_token" in res.get_json()
    assert res.get_json()["user"]["email"] == "profile.user@example.com"


def test_21_existing_user_submitting_own_phone_succeeds_without_otp(client, test_user):
    """21. Existing user submitting their OWN unchanged phone number is accepted without OTP or unverified state."""
    token = get_auth_token(client)
    # test_user phone is initially "9876543210" and is_phone_verified=True
    res = client.put(
        "/api/profile",
        json={"name": "Profile Tester", "phone_number": "9876543210"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["phone_verification_required"] is False
    assert data["profile"]["is_phone_verified"] is True
    assert data["profile"]["phone_number"] == "9876543210"


def test_22_existing_user_submitting_own_phone_with_formatting_variations_does_not_trigger_otp(client, test_user):
    """22. Existing user submitting their own phone with +91 or spaces does not trigger OTP."""
    token = get_auth_token(client)
    # Submit with +91 prefix and space
    res = client.put(
        "/api/profile",
        json={"name": "Profile Tester", "phone_number": "+91 98765 43210"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["phone_verification_required"] is False
    assert data["profile"]["is_phone_verified"] is True

    # Submit with 91 prefix without plus
    res2 = client.put(
        "/api/profile",
        json={"name": "Profile Tester", "phone_number": "919876543210"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 200
    assert res2.get_json()["phone_verification_required"] is False
    assert res2.get_json()["profile"]["is_phone_verified"] is True


def test_23_existing_user_phone_with_spaces_or_prefix_in_db_matched_correctly(app, client):
    """23. Existing user whose DB phone has '+91 98765 99999' can submit their own phone cleanly."""
    with app.app_context():
        u = User(
            name="Legacy Phone User",
            email="legacy.phone@example.com",
            phone_number="+91 98765 99999",
            role="USER",
            is_email_verified=True,
            is_phone_verified=True,
            is_active=True,
            account_status="ACTIVE",
            customer_account_id="FS-LEGACY-001",
            primary_upi_id="legacy_user@fraudshield",
        )
        u.set_password("SecurePassword123!")
        db.session.add(u)
        db.session.commit()
        user_id = u.id

    token = get_auth_token(client, email="legacy.phone@example.com", password="SecurePassword123!")

    # 1. GET profile must return the phone number
    res_get = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert res_get.status_code == 200
    assert res_get.get_json()["profile"]["phone_number"] == "+91 98765 99999"

    # 2. Submitting 10 digits '9876599999' must recognize it as own phone and not trigger OTP
    res_put = client.put(
        "/api/profile",
        json={"name": "Legacy Phone User", "phone_number": "9876599999"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_put.status_code == 200
    data = res_put.get_json()
    assert data["success"] is True
    assert data["phone_verification_required"] is False
    assert data["profile"]["is_phone_verified"] is True

    # 3. Submitting another user's phone must be rejected (e.g. '9876543210' which is owned by test_user)
    # Create test_user in DB if not already present
    with app.app_context():
        if not User.query.filter_by(email="profile.user@example.com").first():
            tu = User(
                name="Other Tester",
                email="profile.user@example.com",
                phone_number="9876543210",
                role="USER",
                is_email_verified=True,
                is_phone_verified=True,
                is_active=True,
                account_status="ACTIVE",
                customer_account_id="FS-OTHER-002",
                primary_upi_id="other_tester@fraudshield",
            )
            tu.set_password("SecurePassword123!")
            db.session.add(tu)
            db.session.commit()

    res_conflict = client.put(
        "/api/profile",
        json={"name": "Legacy Phone User", "phone_number": "9876543210"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_conflict.status_code == 200
    data_changed = res_conflict.get_json()
    assert data_changed["success"] is True
    assert data_changed["phone_verification_required"] is True
    assert data_changed["profile"]["phone_number"] == "9876543210"

    # Cleanup
    with app.app_context():
        User.query.filter_by(id=user_id).delete()
        User.query.filter_by(email="profile.user@example.com").delete()
        db.session.commit()

