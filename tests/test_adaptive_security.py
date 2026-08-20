import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.models.otp_challenge import OTPChallenge
from app.services.risk_service import RiskDecisionService, evaluate_transaction_risk
from app.services.otp_service import OTPService


@pytest.fixture
def app():
    """Create test application with in-memory SQLite database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client fixture."""
    return app.test_client()


@pytest.fixture
def user_token(client):
    """Register and login regular user, returning JWT."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "Normal User",
        "email": "user_adaptive@example.com",
        "password": "Password123!",
        "role": "USER",
    })
    otp = DevelopmentEmailProvider.get_last_email_otp("user_adaptive@example.com")
    if otp:
        client.post("/api/auth/verify-email-otp", json={"email": "user_adaptive@example.com", "otp_code": otp})
    res = client.post("/api/auth/login", json={
        "email": "user_adaptive@example.com",
        "password": "Password123!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def admin_token(client):
    """Register and login admin user, returning JWT."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "Security Officer",
        "email": "admin_adaptive@example.com",
        "password": "AdminPassword123!",
        "role": "ADMIN",
    })
    otp = DevelopmentEmailProvider.get_last_email_otp("admin_adaptive@example.com")
    if otp:
        client.post("/api/auth/verify-email-otp", json={"email": "admin_adaptive@example.com", "otp_code": otp})
    res = client.post("/api/auth/login", json={
        "email": "admin_adaptive@example.com",
        "password": "AdminPassword123!",
    })
    return res.get_json()["access_token"]


# =====================================================================
# 1. RISK DECISION ENGINE BOUNDARY TESTS
# =====================================================================

def test_risk_decision_engine_boundaries():
    """Verify explicit boundary conditions for 4 tiers: 0, 29, 30, 59, 60, 79, 80, 100."""
    # 0 -> LOW
    r0 = evaluate_transaction_risk(0)
    assert r0["risk_level"] == "LOW"
    assert r0["decision"] == "APPROVE_IMMEDIATELY"
    assert r0["requires_otp"] is False
    assert r0["create_alert"] is False

    # 29 -> LOW
    r29 = evaluate_transaction_risk(29)
    assert r29["risk_level"] == "LOW"
    assert r29["decision"] == "APPROVE_IMMEDIATELY"

    # 30 -> MEDIUM
    r30 = evaluate_transaction_risk(30)
    assert r30["risk_level"] == "MEDIUM"
    assert r30["decision"] == "APPROVE_WITH_MONITORING"
    assert r30["requires_otp"] is False
    assert r30["create_alert"] is False

    # 59 -> MEDIUM
    r59 = evaluate_transaction_risk(59)
    assert r59["risk_level"] == "MEDIUM"
    assert r59["decision"] == "APPROVE_WITH_MONITORING"

    # 60 -> HIGH
    r60 = evaluate_transaction_risk(60)
    assert r60["risk_level"] == "HIGH"
    assert r60["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert r60["requires_otp"] is True
    assert r60["create_alert"] is True

    # 79 -> HIGH
    r79 = evaluate_transaction_risk(79)
    assert r79["risk_level"] == "HIGH"
    assert r79["decision"] == "TRIGGER_OTP_VERIFICATION"

    # 80 -> CRITICAL
    r80 = evaluate_transaction_risk(80)
    assert r80["risk_level"] == "CRITICAL"
    assert r80["decision"] == "TRIGGER_SECURITY_REVIEW"
    assert r80["requires_otp"] is True
    assert r80["create_alert"] is True

    # 100 -> CRITICAL
    r100 = evaluate_transaction_risk(100)
    assert r100["risk_level"] == "CRITICAL"
    assert r100["decision"] == "TRIGGER_SECURITY_REVIEW"


# =====================================================================
# 2. LOW-RISK WORKFLOW TESTS
# =====================================================================

def test_low_risk_auto_approved(client, user_token):
    """Verify low-risk transaction is auto-approved and requires no OTP."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 25.0, "destination": "M112233"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "LOW"
    assert data["status"] == "APPROVED"
    assert data["requires_otp"] is False


# =====================================================================
# 3. MEDIUM-RISK OTP CHALLENGE & VERIFICATION TESTS
# =====================================================================

def test_medium_risk_otp_challenge_and_verification_flow(client, user_token, app):
    """Verify medium-risk transaction prompts OTP and transitions to APPROVED upon correct entry."""
    # Create transaction with medium risk parameters (or direct insertion for precise test)
    with app.app_context():
        user = User.query.filter_by(email="user_adaptive@example.com").first()
        tx = Transaction(
            user_id=user.id,
            type="TRANSFER",
            amount=5000.0,
            oldbalance_org=10000.0,
            newbalance_orig=5000.0,
            oldbalance_dest=0.0,
            newbalance_dest=5000.0,
            prediction=0,
            fraud_probability=0.45,
            risk_score=45,
            risk_level="MEDIUM",
            decision="TRIGGER_OTP_VERIFICATION",
            status="OTP_REQUIRED",
            requires_otp=True,
        )
        db.session.add(tx)
        db.session.commit()
        tx_id = tx.id

    # 1. Generate OTP
    gen_res = client.post(
        "/api/otp/generate",
        json={"transaction_id": tx_id},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert gen_res.status_code == 200
    gen_data = gen_res.get_json()
    assert gen_data["success"] is True
    assert "_dev_simulated_otp" in gen_data
    otp_code = gen_data["_dev_simulated_otp"]

    # Verify OTP is hashed in DB, not plaintext
    with app.app_context():
        challenge = OTPChallenge.query.filter_by(transaction_id=tx_id).first()
        assert challenge is not None
        assert challenge.otp_hash != otp_code
        assert challenge.status == "ACTIVE"

    # 2. Verify with wrong code first
    wrong_res = client.post(
        "/api/otp/verify",
        json={"transaction_id": tx_id, "otp_code": "000000"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert wrong_res.status_code == 400
    assert "Invalid OTP code" in wrong_res.get_json()["error"]

    # 3. Verify with correct code
    correct_res = client.post(
        "/api/otp/verify",
        json={"transaction_id": tx_id, "otp_code": otp_code},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert correct_res.status_code == 200
    corr_data = correct_res.get_json()
    assert corr_data["success"] is True
    assert corr_data["transaction"]["status"] == "APPROVED"

    # 4. Attempt to reuse verified OTP -> should fail
    reuse_res = client.post(
        "/api/otp/verify",
        json={"transaction_id": tx_id, "otp_code": otp_code},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert reuse_res.status_code == 400
    assert "no longer active" in reuse_res.get_json()["error"].lower()


def test_otp_exhaustion_after_max_attempts(client, user_token, app):
    """Verify challenge is revoked and transaction rejected after 3 invalid attempts."""
    with app.app_context():
        user = User.query.filter_by(email="user_adaptive@example.com").first()
        tx = Transaction(
            user_id=user.id,
            type="TRANSFER",
            amount=5000.0,
            oldbalance_org=10000.0,
            newbalance_orig=5000.0,
            oldbalance_dest=0.0,
            newbalance_dest=5000.0,
            risk_score=50,
            risk_level="MEDIUM",
            status="OTP_REQUIRED",
            requires_otp=True,
        )
        db.session.add(tx)
        db.session.commit()
        tx_id = tx.id

    client.post("/api/otp/generate", json={"transaction_id": tx_id}, headers={"Authorization": f"Bearer {user_token}"})

    # Attempt 1
    client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": "111111"}, headers={"Authorization": f"Bearer {user_token}"})
    # Attempt 2
    client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": "222222"}, headers={"Authorization": f"Bearer {user_token}"})
    # Attempt 3 -> Exhausted
    res3 = client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": "333333"}, headers={"Authorization": f"Bearer {user_token}"})

    assert res3.status_code == 429
    assert "exhausted" in res3.get_json()["error"].lower()

    with app.app_context():
        updated_tx = db.session.get(Transaction, tx_id)
        assert updated_tx.status == "REJECTED"


# =====================================================================
# 4. HIGH-RISK ALERT & REVIEW WORKFLOW TESTS
# =====================================================================

def test_high_risk_alert_and_admin_review_workflow(client, user_token, admin_token, app):
    """Verify high-risk transaction raises alert, requires OTP, and is resolvable by admin."""
    # 1. Submit high-risk transaction
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "TRANSFER",
            "amount": 850000.0,
            "destination": "C998877",
            "oldbalance_org": 850000.0,
            "newbalance_orig": 0.0,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    tx_id = res.get_json()["transaction_id"]

    # 2. Check that Alert exists
    with app.app_context():
        alert = Alert.query.filter_by(transaction_id=tx_id).first()
        assert alert is not None
        assert alert.status == "OPEN"
        alert_id = alert.id

    # 3. Regular user forbidden from admin alerts
    user_alert_res = client.get("/api/admin/alerts", headers={"Authorization": f"Bearer {user_token}"})
    assert user_alert_res.status_code == 403

    # 4. Admin can list alerts
    admin_alert_res = client.get("/api/admin/alerts", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_alert_res.status_code == 200
    alerts_data = admin_alert_res.get_json()
    assert alerts_data["total"] >= 1
    assert any(a["id"] == alert_id for a in alerts_data["alerts"])

    # 5. Admin resolves alert
    resolve_res = client.post(
        f"/api/admin/alerts/{alert_id}/resolve",
        json={"note": "Investigated and verified with cardholder."},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.get_json()["alert"]["status"] == "RESOLVED"


# =====================================================================
# 5. SECURITY & ACCESS ISOLATION TESTS
# =====================================================================

def test_user_cannot_access_other_users_otp_challenge(client, user_token, app):
    """Verify cross-user authorization block."""
    # Create User B and Transaction B
    with app.app_context():
        user_b = User(name="User B", email="user_b@example.com", role="USER", is_email_verified=True, is_phone_verified=True, is_active=True, account_status="ACTIVE")
        user_b.set_password("Password123!")
        db.session.add(user_b)
        db.session.commit()

        tx_b = Transaction(
            user_id=user_b.id,
            type="TRANSFER",
            amount=500.0,
            oldbalance_org=1000.0,
            newbalance_orig=500.0,
            oldbalance_dest=0.0,
            newbalance_dest=500.0,
            risk_score=50,
            risk_level="MEDIUM",
            status="OTP_REQUIRED",
            requires_otp=True,
        )
        db.session.add(tx_b)
        db.session.commit()
        tx_b_id = tx_b.id

    # User A tries to generate OTP for User B's transaction
    res = client.post(
        "/api/otp/generate",
        json={"transaction_id": tx_b_id},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 403
    assert "Forbidden" in res.get_json()["error"]
