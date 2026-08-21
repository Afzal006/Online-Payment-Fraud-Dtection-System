import json
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert


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
def user_auth_token(client):
    """Register and authenticate standard test user, returning JWT token."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "Jane Doe",
        "email": "jane@example.com",
        "password": "Password123!",
        "role": "USER",
    })
    otp = DevelopmentEmailProvider.get_last_email_otp("jane@example.com")
    if otp:
        client.post("/api/auth/verify-email-otp", json={"email": "jane@example.com", "otp_code": otp})
    res = client.post("/api/auth/login", json={
        "email": "jane@example.com",
        "password": "Password123!",
    })
    return res.get_json()["access_token"]


# =====================================================================
# 1. AUTHENTICATION TESTS
# =====================================================================

def test_unauthenticated_predict_rejected(client):
    """Verify POST /api/transactions/predict rejects requests without JWT (401)."""
    res = client.post("/api/transactions/predict", json={
        "type": "PAYMENT",
        "amount": 50.0,
        "destination": "M123456",
    })
    assert res.status_code == 401
    assert res.get_json()["code"] == "AUTHORIZATION_REQUIRED"


def test_invalid_jwt_predict_rejected(client):
    """Verify POST /api/transactions/predict rejects invalid JWT (422)."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 50.0, "destination": "M123456"},
        headers={"Authorization": "Bearer invalid.jwt.token"},
    )
    assert res.status_code == 422
    assert res.get_json()["code"] == "INVALID_TOKEN"


# =====================================================================
# 2. INPUT VALIDATION TESTS
# =====================================================================

def test_predict_missing_amount(client, user_auth_token):
    """Verify 400 when amount is omitted."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "destination": "M123456"},
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 400
    assert "amount" in res.get_json()["error"].lower()


def test_predict_zero_or_negative_amount(client, user_auth_token):
    """Verify 400 when amount is <= 0."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": -25.0, "destination": "M123456"},
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 400
    assert "positive number" in res.get_json()["error"].lower()


def test_predict_unsupported_type(client, user_auth_token):
    """Verify 400 when transaction type is unsupported."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "BITCOIN_TRANSFER", "amount": 100.0, "destination": "M123456"},
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 400
    assert "invalid transaction type" in res.get_json()["error"].lower()


def test_predict_missing_destination(client, user_auth_token):
    """Verify 400 when destination is omitted."""
    res = client.post(
        "/api/transactions/predict",
        json={"type": "TRANSFER", "amount": 100.0},
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 400
    assert "destination" in res.get_json()["error"].lower()


# =====================================================================
# 3. ML INFERENCE & SHAP EXPLANATION TESTS
# =====================================================================

def test_predict_legitimate_payment(client, user_auth_token):
    """Verify legitimate payment produces LOW risk score, APPROVE_IMMEDIATELY decision, and SHAP factors."""
    payload = {
        "type": "PAYMENT",
        "amount": 42.50,
        "destination": "M987654",
        "sender_balance": 3500.0,
    }
    res = client.post(
        "/api/transactions/predict",
        json=payload,
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()

    assert data["success"] is True
    assert data["prediction"] == 0
    assert data["predicted_class_name"] == "Legitimate"
    assert 0.0 <= data["fraud_probability"] <= 0.30
    assert 0.70 <= data["legitimate_probability"] <= 1.0
    assert 0 <= data["risk_score"] <= 30
    assert data["risk_level"] == "LOW"
    assert data["decision"] == "APPROVE_IMMEDIATELY"
    assert data["requires_otp"] is False
    assert data["status"] == "APPROVED"

    # SHAP assertions
    exp = data["explanation"]
    assert len(exp["top_features"]) > 0
    assert "human_readable_summary" in exp
    assert "approved" in exp["human_readable_summary"].lower() or "normal" in exp["human_readable_summary"].lower()


def test_predict_fraudulent_draining_transfer(client, user_auth_token):
    """Verify account-draining transfer produces HIGH risk score, security alert, and SHAP top drivers."""
    payload = {
        "type": "TRANSFER",
        "amount": 900000.0,
        "destination": "C554433",
        "oldbalance_org": 900000.0,
        "newbalance_orig": 0.0,
        "oldbalance_dest": 0.0,
        "newbalance_dest": 0.0,
    }
    res = client.post(
        "/api/transactions/predict",
        json=payload,
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()

    assert data["success"] is True
    assert data["prediction"] == 1
    assert data["predicted_class_name"] == "Fraudulent"
    assert data["fraud_probability"] >= 0.70
    assert data["risk_score"] >= 70
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["requires_otp"] is True
    assert data["status"] in ["UNDER_REVIEW", "FLAGGED", "OTP_REQUIRED"]

    # SHAP assertions
    exp = data["explanation"]
    assert len(exp["top_features"]) > 0
    assert len(exp["positive_risk_factors"]) > 0
    summary_lower = exp["human_readable_summary"].lower()
    assert any(term in summary_lower for term in ["verification", "security", "risk", "protect"])

    # Leakage check: ensure excluded features are absent
    excluded = ["isFraud", "isFlaggedFraud", "nameOrig", "nameDest"]
    for feat in exp["top_features"]:
        for exc in excluded:
            assert exc != feat["feature"]


# =====================================================================
# 4. DATABASE PERSISTENCE & HISTORY RETRIEVAL TESTS
# =====================================================================

def test_predict_persists_transaction_and_alert(client, user_auth_token, app):
    """Verify transactions and alerts are correctly recorded in the database."""
    payload = {
        "type": "TRANSFER",
        "amount": 750000.0,
        "destination": "C112233",
        "oldbalance_org": 750000.0,
        "newbalance_orig": 0.0,
    }
    res = client.post(
        "/api/transactions/predict",
        json=payload,
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    assert res.status_code == 200
    tx_id = res.get_json()["transaction_id"]

    with app.app_context():
        tx = db.session.get(Transaction, tx_id)
        assert tx is not None
        assert tx.amount == 750000.0
        assert tx.type == "TRANSFER"
        assert tx.risk_level in ["HIGH", "CRITICAL"]

        # Check alert creation for high risk
        alert = Alert.query.filter_by(transaction_id=tx_id).first()
        assert alert is not None
        assert alert.severity in ["HIGH", "CRITICAL"]
        assert alert.status == "OPEN"


def test_user_transaction_history_and_detail(client, user_auth_token):
    """Verify GET /api/transactions/my-history and GET /api/transactions/<id>."""
    # Submit 2 transactions
    client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 15.0, "destination": "M100"},
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    res2 = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 30.0, "destination": "M200"},
        headers={"Authorization": f"Bearer {user_auth_token}"},
    )
    tx2_id = res2.get_json()["transaction_id"]

    # Fetch user history
    history_res = client.get("/api/transactions/my-history", headers={"Authorization": f"Bearer {user_auth_token}"})
    assert history_res.status_code == 200
    hist = history_res.get_json()
    assert hist["total"] == 2

    # Fetch individual detail
    detail_res = client.get(f"/api/transactions/{tx2_id}", headers={"Authorization": f"Bearer {user_auth_token}"})
    assert detail_res.status_code == 200
    detail = detail_res.get_json()
    assert detail["id"] == tx2_id
    assert detail["amount"] == 30.0
    assert "explanation" in detail
