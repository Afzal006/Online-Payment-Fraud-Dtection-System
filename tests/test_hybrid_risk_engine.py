"""
Unit and Integration Test Suite for the Hybrid Fraud Risk Engine,
Admin Customer Review Portal, and Adaptive Security Policies.
"""

import json
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.services.risk_service import RiskDecisionService


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
    """Register and authenticate standard test user."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "Arjun Sharma",
        "email": "arjun@example.com",
        "password": "UserPass2026!",
        "role": "USER",
    })
    otp = DevelopmentEmailProvider.get_last_email_otp("arjun@example.com")
    if otp:
        client.post("/api/auth/verify-email-otp", json={"email": "arjun@example.com", "otp_code": otp})
    res = client.post("/api/auth/login", json={
        "email": "arjun@example.com",
        "password": "UserPass2026!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def admin_token(client):
    """Register and authenticate administrator."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "SOC Admin Officer",
        "email": "admin@example.com",
        "password": "AdminPass2026!",
        "role": "ADMIN",
    })
    otp = DevelopmentEmailProvider.get_last_email_otp("admin@example.com")
    if otp:
        client.post("/api/auth/verify-email-otp", json={"email": "admin@example.com", "otp_code": otp})
    res = client.post("/api/auth/login", json={
        "email": "admin@example.com",
        "password": "AdminPass2026!",
    })
    return res.get_json()["access_token"]


# =====================================================================
# 1. HYBRID FRAUD RISK ENGINE DIRECT POLICY UNIT & BOUNDARY TESTS
# =====================================================================

def test_rule_risk_small_merchant_payment():
    """Verify small merchant payment (₹500) yields low rule score and LOW risk tier."""
    rule_score, factors = RiskDecisionService.calculate_rule_risk(
        amount=500.0,
        tx_type="PAYMENT",
        has_account_simulation=False,
        is_merchant_dest=True,
    )
    assert rule_score <= 20
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.01,
        amount=500.0,
        tx_type="PAYMENT",
        has_account_simulation=False,
        is_merchant_dest=True,
    )
    assert eval_res["risk_score"] <= 30
    assert eval_res["risk_level"] == "LOW"
    assert eval_res["decision"] == "APPROVE_IMMEDIATELY"
    assert eval_res["requires_otp"] is False


def test_boundary_10000_payment():
    """Verify ₹10,000 normal payment boundary remains in LOW risk tier."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.02,
        amount=10000.0,
        tx_type="PAYMENT",
        has_account_simulation=False,
        is_merchant_dest=True,
    )
    assert eval_res["risk_score"] <= 30
    assert eval_res["risk_level"] == "LOW"
    assert eval_res["decision"] == "APPROVE_IMMEDIATELY"
    assert eval_res["requires_otp"] is False


def test_boundary_10001_payment():
    """Verify ₹10,001 merchant payment remains in LOW risk tier."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.02,
        amount=10001.0,
        tx_type="PAYMENT",
        has_account_simulation=False,
        is_merchant_dest=True,
    )
    assert eval_res["risk_score"] <= 30
    assert eval_res["risk_level"] == "LOW"
    assert eval_res["requires_otp"] is False


def test_boundary_50000_transfer():
    """Verify ₹50,000 transfer boundary evaluates to MEDIUM risk (OTP challenge)."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.04,
        amount=50000.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert 31 <= eval_res["risk_score"] <= 70
    assert eval_res["risk_level"] == "MEDIUM"
    assert eval_res["requires_otp"] is False
    assert eval_res["decision"] == "APPROVE_WITH_MONITORING"


def test_boundary_50001_transfer():
    """Verify ₹50,001 transfer evaluates to HIGH risk in 4-tier model (OTP challenge)."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.04,
        amount=50001.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert 60 <= eval_res["risk_score"] <= 79
    assert eval_res["risk_level"] == "HIGH"
    assert eval_res["requires_otp"] is True
    assert eval_res["decision"] == "TRIGGER_OTP_VERIFICATION"


def test_boundary_92000_transfer():
    """Verify ₹92,000 transfer without simulation produces elevated risk requiring OTP."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.05,
        amount=92000.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert eval_res["risk_score"] >= 31
    assert eval_res["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]
    assert eval_res["requires_otp"] is True
    assert len(eval_res["risk_factors"]) > 0


def test_boundary_100000_transfer():
    """Verify ₹100,000 transfer (upper bound of significant tier) reaches HIGH tier."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.05,
        amount=100000.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert 60 <= eval_res["risk_score"] <= 79
    assert eval_res["risk_level"] == "HIGH"
    assert eval_res["requires_otp"] is True


def test_boundary_100001_transfer_high_value_category():
    """
    CRITICAL HIGH-VALUE BOUNDARY TEST:
    Verify ₹100,001 TRANSFER without simulation enters High-Value Category,
    achieving final_risk_score >= 71 and risk_level == 'HIGH'.
    """
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.05,
        amount=100001.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert eval_res["risk_score"] >= 71
    assert eval_res["risk_level"] in ["HIGH", "CRITICAL"]
    assert eval_res["decision"] in ["TRIGGER_OTP_VERIFICATION", "TRIGGER_SECURITY_REVIEW"]
    assert eval_res["requires_otp"] is True
    assert eval_res["create_alert"] is True


def test_boundary_250000_transfer():
    """Verify ₹2,50,000 TRANSFER without simulation produces HIGH risk."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.08,
        amount=250000.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert eval_res["risk_score"] >= 71
    assert eval_res["risk_level"] in ["HIGH", "CRITICAL"]
    assert eval_res["requires_otp"] is True
    assert eval_res["create_alert"] is True


def test_boundary_250001_transfer():
    """
    CRITICAL USER TEST CASE:
    Verify ₹250,001 TRANSFER without simulation produces final_risk_score >= 71
    and risk_level in ['HIGH', 'CRITICAL'].
    """
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.08,
        amount=250001.0,
        tx_type="TRANSFER",
        has_account_simulation=False,
        is_merchant_dest=False,
    )
    assert eval_res["risk_score"] >= 71
    assert eval_res["risk_level"] in ["HIGH", "CRITICAL"]
    assert eval_res["decision"] in ["TRIGGER_OTP_VERIFICATION", "TRIGGER_SECURITY_REVIEW"]
    assert eval_res["requires_otp"] is True
    assert eval_res["create_alert"] is True


def test_boundary_750000_account_drain():
    """Verify ₹750,000 account-drain pattern produces very high risk score >= 80."""
    eval_res = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.99,
        amount=750000.0,
        tx_type="TRANSFER",
        has_account_simulation=True,
        is_account_drain=True,
        is_merchant_dest=False,
    )
    assert eval_res["risk_score"] >= 80
    assert eval_res["risk_level"] in ["HIGH", "CRITICAL"]
    assert eval_res["decision"] in ["TRIGGER_OTP_VERIFICATION", "TRIGGER_SECURITY_REVIEW"]
    assert eval_res["create_alert"] is True


# =====================================================================
# 2. END-TO-END PREDICTION API WITH HYBRID RISK INTEGRATION
# =====================================================================

def test_api_predict_500_payment_flow(client, user_token):
    """Test ₹500 PAYMENT through API."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 500.0, "destination": "M98765"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["risk_level"] == "LOW"
    assert data["status"] == "APPROVED"
    assert data["requires_otp"] is False


def test_api_predict_92k_transfer_flow(client, user_token):
    """
    Test ₹92,000 TRANSFER without Account Simulation through API.
    Verifies elevated risk score and OTP challenge requirement.
    """
    res = client.post(
        "/api/transactions/predict",
        json={"type": "TRANSFER", "amount": 92000.0, "destination": "C99881122"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["risk_score"] >= 31
    assert data["risk_level"] in ["MEDIUM", "HIGH"]
    assert data["requires_otp"] is True
    assert data["status"] in ["OTP_REQUIRED", "UNDER_REVIEW"]
    assert "risk_factors" in data
    assert len(data["risk_factors"]) > 0


def test_api_predict_250001_transfer_elevates_to_high_risk(client, user_token, app):
    """
    Test ₹250,001 TRANSFER without Account Simulation through API.
    Verifies final risk score >= 71, HIGH/CRITICAL risk level, and security alert creation.
    """
    with app.app_context():
        u = User.query.filter_by(email="arjun@example.com").first()
        if u:
            u.account_balance = 500000.0
            db.session.commit()

    res = client.post(
        "/api/transactions/predict",
        json={"type": "TRANSFER", "amount": 250001.0, "destination": "C12345678"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["risk_score"] >= 71
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["requires_otp"] is True
    assert data["status"] in ["OTP_REQUIRED", "UNDER_REVIEW"]

    # Verify Alert persisted in DB
    tx_id = data["transaction_id"]
    with app.app_context():
        alert = Alert.query.filter_by(transaction_id=tx_id).first()
        assert alert is not None
        assert alert.status == "OPEN"


def test_api_predict_account_drain_creates_alert(client, user_token, app):
    """Test account-draining transaction through API creates HIGH/CRITICAL risk and Open Alert."""
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "TRANSFER",
            "amount": 800000.0,
            "destination": "C334455",
            "oldbalance_org": 800000.0,
            "newbalance_orig": 0.0,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    tx_id = data["transaction_id"]

    with app.app_context():
        alert = Alert.query.filter_by(transaction_id=tx_id).first()
        assert alert is not None
        assert alert.status == "OPEN"
        assert alert.severity in ["HIGH", "CRITICAL"]


# =====================================================================
# 3. ADMIN SOC REVIEW & GLOBAL AUDIT LEDGER TESTS
# =====================================================================

def test_admin_view_all_customer_transactions(client, user_token, admin_token):
    """Verify admin can view all customer transactions with user details (name, email)."""
    client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 1250.0, "destination": "M101"},
        headers={"Authorization": f"Bearer {user_token}"},
    )

    res = client.get("/api/admin/transactions", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] >= 1

    tx = data["transactions"][0]
    assert tx["user_name"] == "Arjun Sharma"
    assert tx["user_email"] == "arjun@example.com"
    assert tx["amount"] == 1250.0


def test_admin_search_and_filter_transactions(client, user_token, admin_token):
    """Verify admin search and filters (by email, destination, risk level, status)."""
    client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 500.0, "destination": "M_GROCERY"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    client.post(
        "/api/transactions/predict",
        json={"type": "TRANSFER", "amount": 92000.0, "destination": "C_SPECIAL_DEST"},
        headers={"Authorization": f"Bearer {user_token}"},
    )

    # Search by destination
    res = client.get("/api/admin/transactions?search=C_SPECIAL_DEST", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    txs = res.get_json()["transactions"]
    assert len(txs) == 1
    assert txs[0]["name_dest"] == "C_SPECIAL_DEST"

    # Search by customer email
    res_email = client.get("/api/admin/transactions?search=arjun@example.com", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_email.status_code == 200
    assert len(res_email.get_json()["transactions"]) >= 2

    # Filter by type
    res_type = client.get("/api/admin/transactions?type=TRANSFER", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_type.status_code == 200
    for t in res_type.get_json()["transactions"]:
        assert t["type"] == "TRANSFER"


def test_admin_transaction_detail_inspection(client, user_token, admin_token):
    """Verify admin transaction details modal payload includes customer info, SHAP, and alert."""
    pred_res = client.post(
        "/api/transactions/predict",
        json={
            "type": "TRANSFER",
            "amount": 750000.0,
            "destination": "C999",
            "oldbalance_org": 750000.0,
            "newbalance_orig": 0.0,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    tx_id = pred_res.get_json()["transaction_id"]

    res = client.get(f"/api/admin/transactions/{tx_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    detail = res.get_json()

    assert detail["success"] is True
    assert detail["transaction"]["id"] == tx_id
    assert detail["user"]["name"] == "Arjun Sharma"
    assert detail["user"]["email"] == "arjun@example.com"
    assert detail["alert"] is not None
    assert detail["alert"]["status"] == "OPEN"
    assert "explanation" in detail["transaction"]


def test_admin_resolve_alert_with_notes(client, user_token, admin_token, app):
    """Verify admin can resolve an alert and record resolution notes & resolver name."""
    pred_res = client.post(
        "/api/transactions/predict",
        json={
            "type": "TRANSFER",
            "amount": 850000.0,
            "destination": "C777",
            "oldbalance_org": 850000.0,
            "newbalance_orig": 0.0,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    tx_id = pred_res.get_json()["transaction_id"]

    with app.app_context():
        alert = Alert.query.filter_by(transaction_id=tx_id).first()
        alert_id = alert.id

    res = client.post(
        f"/api/admin/alerts/{alert_id}/resolve",
        json={"note": "Contacted account holder Arjun Sharma. Confirmed legitimate large wire transfer."},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    with app.app_context():
        updated_alert = db.session.get(Alert, alert_id)
        assert updated_alert.status == "RESOLVED"
        assert "Arjun Sharma" in updated_alert.notes
        assert "admin@example.com" in updated_alert.resolved_by


# =====================================================================
# 4. MULTI-TENANT ISOLATION & SERVER-SIDE RBAC TESTS
# =====================================================================

def test_tenant_isolation_regular_user_cannot_view_others(client, user_token):
    """Verify standard user can only see their own transactions, not another user's."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "User Two",
        "email": "user2@example.com",
        "password": "Password123!",
        "role": "USER",
    })
    otp2 = DevelopmentEmailProvider.get_last_email_otp("user2@example.com")
    if otp2:
        client.post("/api/auth/verify-email-otp", json={"email": "user2@example.com", "otp_code": otp2})
    res2 = client.post("/api/auth/login", json={
        "email": "user2@example.com",
        "password": "Password123!",
    })
    token2 = res2.get_json()["access_token"]

    tx_res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 100.0, "destination": "M1"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    tx1_id = tx_res.get_json()["transaction_id"]

    hist2 = client.get("/api/transactions/my-history", headers={"Authorization": f"Bearer {token2}"})
    assert hist2.status_code == 200
    assert hist2.get_json()["total"] == 0

    access_res = client.get(f"/api/transactions/{tx1_id}", headers={"Authorization": f"Bearer {token2}"})
    assert access_res.status_code in [403, 404]


def test_rbac_regular_user_cannot_access_admin_api(client, user_token):
    """Verify regular user receives 403 FORBIDDEN on all admin SOC endpoints."""
    res_overview = client.get("/api/admin/overview", headers={"Authorization": f"Bearer {user_token}"})
    assert res_overview.status_code == 403

    res_txs = client.get("/api/admin/transactions", headers={"Authorization": f"Bearer {user_token}"})
    assert res_txs.status_code == 403

    res_alerts = client.get("/api/admin/alerts", headers={"Authorization": f"Bearer {user_token}"})
    assert res_alerts.status_code == 403
