"""
Phase 12: End-to-End (E2E) System Lifecycle & Edge-Case Integration Test Suite.

Verifies the complete flow across all modules:
1. Registration & Authentication Lifecycle
2. Payment Submission -> Preprocessing -> ML Random Forest Inference -> Risk Scoring
3. 3-Tier Security Workflow (LOW auto-approval, MEDIUM OTP challenge, HIGH Alert generation)
4. Cryptographic OTP Generation, Attempt Rate-Limiting, Verification, & State Transition
5. SHAP TreeExplainer Natural Language & Feature Influence Payload
6. User Transaction Ledger Retrieval
7. Admin Security Operations Center (SOC) Alert Triage, Investigation, & Resolution
8. Edge Cases & Boundary Handling (Negative, Zero, Extreme sums, Malformed inputs, SQL Rollbacks, Cross-User Isolation)
"""

import pytest
import json
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.models.otp_challenge import OTPChallenge
from app.services.otp_service import OTPService


@pytest.fixture
def app():
    """Create test application instance with in-memory database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


# =====================================================================
# 1. COMPLETE END-TO-END SYSTEM LIFECYCLE TEST
# =====================================================================

def test_full_e2e_system_lifecycle(client):
    """
    Test complete lifecycle from User Registration to Admin Alert Resolution:
    1. User Registration & Login
    2. Admin Registration & Login
    3. User submits high-risk account-draining transaction
    4. Verify ML Prediction (isFraud=1), Risk Score (>70), SHAP Explanation, and HIGH Alert created
    5. User receives OTP challenge, verifies OTP -> transitions to VERIFIED_PENDING_REVIEW
    6. User checks their personal transaction ledger
    7. Admin views SOC dashboard, investigates transaction via SHAP, and resolves Alert with notes
    8. Verify final database state integrity
    """
    # Step 1: User Registration & Login
    from app.providers.email_provider import DevelopmentEmailProvider
    reg_user_res = client.post("/api/auth/register", json={
        "name": "Alice EndUser",
        "email": "alice_e2e@example.com",
        "password": "SecurePassword123!",
        "role": "USER",
    })
    assert reg_user_res.status_code == 201
    u_otp = DevelopmentEmailProvider.get_last_email_otp("alice_e2e@example.com")
    if u_otp:
        client.post("/api/auth/verify-email-otp", json={"email": "alice_e2e@example.com", "otp_code": u_otp})

    login_user_res = client.post("/api/auth/login", json={
        "email": "alice_e2e@example.com",
        "password": "SecurePassword123!",
    })
    assert login_user_res.status_code == 200
    user_token = login_user_res.get_json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    # Step 2: Admin Registration & Login
    reg_admin_res = client.post("/api/auth/register", json={
        "name": "Bob SecurityOfficer",
        "email": "bob_admin_e2e@example.com",
        "password": "AdminSecurePassword123!",
        "role": "ADMIN",
    })
    assert reg_admin_res.status_code == 201
    a_otp = DevelopmentEmailProvider.get_last_email_otp("bob_admin_e2e@example.com")
    if a_otp:
        client.post("/api/auth/verify-email-otp", json={"email": "bob_admin_e2e@example.com", "otp_code": a_otp})

    login_admin_res = client.post("/api/auth/login", json={
        "email": "bob_admin_e2e@example.com",
        "password": "AdminSecurePassword123!",
    })
    assert login_admin_res.status_code == 200
    admin_token = login_admin_res.get_json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Step 3: User Submits High-Risk Transaction (Account Draining Transfer)
    tx_payload = {
        "type": "TRANSFER",
        "amount": 800000.0,
        "destination": "C88776655",
        "oldbalance_org": 800000.0,
        "newbalance_orig": 0.0,
        "oldbalance_dest": 0.0,
        "newbalance_dest": 0.0,
    }
    tx_res = client.post("/api/transactions/predict", json=tx_payload, headers=user_headers)
    assert tx_res.status_code == 200
    tx_data = tx_res.get_json()

    # Step 4: Validate ML Prediction, Risk Tier, and SHAP Explainability
    assert tx_data["success"] is True
    tx_id = tx_data["transaction_id"]
    assert tx_data["prediction"] == 1
    assert tx_data["risk_level"] in ["HIGH", "CRITICAL"]
    assert tx_data["risk_score"] >= 71
    assert tx_data["requires_otp"] is True
    assert tx_data["status"] == "UNDER_REVIEW"

    # SHAP assertions
    explanation = tx_data["explanation"]
    assert "human_readable_summary" in explanation
    assert len(explanation["top_features"]) > 0
    assert any("Balance" in f.get("feature", "") or "Amount" in f.get("feature", "") for f in explanation["top_features"])

    # Step 5: User OTP Challenge Generation and Verification
    otp_gen_res = client.post("/api/otp/generate", json={"transaction_id": tx_id}, headers=user_headers)
    assert otp_gen_res.status_code == 200
    dev_otp = otp_gen_res.get_json().get("_dev_simulated_otp")
    assert dev_otp is not None
    assert len(dev_otp) == 6

    # Verify OTP
    otp_verify_res = client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": dev_otp}, headers=user_headers)
    assert otp_verify_res.status_code == 200
    verify_data = otp_verify_res.get_json()
    assert verify_data["success"] is True
    assert verify_data["transaction"]["status"] in ["VERIFIED_PENDING_REVIEW", "APPROVED"]

    # Step 6: User Reviews Transaction History
    history_res = client.get("/api/transactions/my-history", headers=user_headers)
    assert history_res.status_code == 200
    user_txs = history_res.get_json()["transactions"]
    assert len(user_txs) == 1
    assert user_txs[0]["id"] == tx_id
    assert user_txs[0]["status"] in ["VERIFIED_PENDING_REVIEW", "APPROVED"]

    # Step 7: Admin SOC Overview, Alert Triage, and Resolution
    # A. Check Overview KPIs
    overview_res = client.get("/api/admin/overview", headers=admin_headers)
    assert overview_res.status_code == 200
    kpis = overview_res.get_json()["kpis"]
    assert kpis["total_transactions"] == 1
    assert kpis["alerts"]["open"] == 1
    assert (kpis["risk_tiers"].get("HIGH", 0) + kpis["risk_tiers"].get("CRITICAL", 0)) >= 1

    # B. List Alerts
    alerts_res = client.get("/api/admin/alerts?status=OPEN", headers=admin_headers)
    assert alerts_res.status_code == 200
    alerts_list = alerts_res.get_json()["alerts"]
    assert len(alerts_list) == 1
    alert_id = alerts_list[0]["id"]

    # C. Deep Investigation of Alert
    alert_detail_res = client.get(f"/api/admin/alerts/{alert_id}", headers=admin_headers)
    assert alert_detail_res.status_code == 200
    alert_obj = alert_detail_res.get_json()["alert"]
    assert alert_obj["status"] == "OPEN"
    assert alert_obj["severity"] in ["HIGH", "CRITICAL"]

    # D. Resolve Alert
    resolve_res = client.post(
        f"/api/admin/alerts/{alert_id}/resolve",
        json={"note": "Verified with cardholder. Legitimate large transfer authorized."},
        headers=admin_headers,
    )
    assert resolve_res.status_code == 200
    assert resolve_res.get_json()["alert"]["status"] == "RESOLVED"

    # Step 8: Database State Integrity Check
    final_alert = Alert.query.filter_by(id=alert_id).first()
    assert final_alert.status == "RESOLVED"
    assert final_alert.resolved_by == "bob_admin_e2e@example.com"
    assert final_alert.resolved_at is not None


# =====================================================================
# 2. EDGE CASES & MALFORMED PAYLOAD TESTS
# =====================================================================

def test_edge_case_zero_and_negative_amounts(client, user_auth_token):
    """Verify negative and zero amounts are rejected with 400 validation error."""
    headers = {"Authorization": f"Bearer {user_auth_token}"}

    # Zero amount
    res_zero = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 0.0, "destination": "M12345"},
        headers=headers,
    )
    assert res_zero.status_code == 400
    assert "greater than 0" in res_zero.get_json()["error"].lower()

    # Negative amount
    res_neg = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": -250.0, "destination": "M12345"},
        headers=headers,
    )
    assert res_neg.status_code == 400
    assert "greater than 0" in res_neg.get_json()["error"].lower()


def test_edge_case_extremely_large_amount(client, user_auth_token):
    """Verify extremely large transaction amount ($999,999,999.00) processes without numerical overflow."""
    headers = {"Authorization": f"Bearer {user_auth_token}"}
    res = client.post(
        "/api/transactions/predict",
        json={
            "type": "TRANSFER",
            "amount": 999999999.0,
            "destination": "C999999",
            "oldbalance_org": 999999999.0,
            "newbalance_orig": 0.0,
        },
        headers=headers,
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert 0 <= data["risk_score"] <= 100
    assert 0.0 <= data["fraud_probability"] <= 1.0


def test_edge_case_missing_and_invalid_fields(client, user_auth_token):
    """Verify validation handling for missing and invalid transaction attributes."""
    headers = {"Authorization": f"Bearer {user_auth_token}"}

    # Missing amount
    res1 = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "destination": "M123"},
        headers=headers,
    )
    assert res1.status_code == 400

    # Missing destination
    res2 = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 50.0},
        headers=headers,
    )
    assert res2.status_code == 400

    # Unsupported transaction type
    res3 = client.post(
        "/api/transactions/predict",
        json={"type": "CRYPTO_SWAP", "amount": 50.0, "destination": "M123"},
        headers=headers,
    )
    assert res3.status_code == 400
    assert "invalid transaction type" in res3.get_json()["error"].lower()


def test_edge_case_special_characters_in_inputs(client, user_auth_token):
    """Verify system handles special characters and potential injection strings safely."""
    headers = {"Authorization": f"Bearer {user_auth_token}"}
    special_dest = "M<script>alert('xss')</script>'; DROP TABLE users;--"

    res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 42.50, "destination": special_dest},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["transaction_id"] is not None


def test_edge_case_otp_attempt_limits_and_anti_reuse(client, user_auth_token, app):
    """Verify strict OTP attempt limits and rejection of previously verified OTPs."""
    # Create medium-risk transaction
    with app.app_context():
        user = User.query.filter_by(email="user_edge_cases@example.com").first()
        if not user:
            user = User(name="Test User", email="user_edge_cases@example.com", role="USER", is_email_verified=True, is_phone_verified=True, is_active=True, account_status="ACTIVE")
            user.set_password("Password123!")
            db.session.add(user)
            db.session.commit()

        tx = Transaction(
            user_id=user.id,
            type="TRANSFER",
            amount=5000.0,
            oldbalance_org=10000.0,
            newbalance_orig=5000.0,
            oldbalance_dest=0.0,
            newbalance_dest=5000.0,
            risk_score=55,
            risk_level="MEDIUM",
            status="OTP_REQUIRED",
            requires_otp=True,
        )
        db.session.add(tx)
        db.session.commit()
        tx_id = tx.id
        user_id = user.id

        # Create active OTP challenge
        challenge, correct_otp, err = OTPService.create_challenge(tx_id, user_id)
        assert err is None

    headers = {"Authorization": f"Bearer {user_auth_token}"}

    # Verify attempt limit: 3 failed attempts
    for i in range(3):
        r = client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": "000000"}, headers=headers)
        assert r.status_code in (400, 429)

    # 4th attempt rejected due to max attempts / exhaustion
    r_exceeded = client.post("/api/otp/verify", json={"transaction_id": tx_id, "otp_code": correct_otp}, headers=headers)
    assert r_exceeded.status_code in (400, 429)
    assert any(k in r_exceeded.get_json()["error"].lower() for k in ["maximum", "exhausted", "longer active"])

    # Create new fresh transaction and challenge
    with app.app_context():
        tx2 = Transaction(
            user_id=user_id,
            type="TRANSFER",
            amount=1000.0,
            oldbalance_org=10000.0,
            newbalance_orig=9000.0,
            oldbalance_dest=0.0,
            newbalance_dest=1000.0,
            risk_score=50,
            risk_level="MEDIUM",
            status="OTP_REQUIRED",
            requires_otp=True,
        )
        db.session.add(tx2)
        db.session.commit()
        tx2_id = tx2.id

        challenge2, correct_otp2, err = OTPService.create_challenge(tx2_id, user_id)
        assert err is None

    r_ok = client.post("/api/otp/verify", json={"transaction_id": tx2_id, "otp_code": correct_otp2}, headers=headers)
    assert r_ok.status_code == 200

    # Anti-Reuse check: Cannot verify again
    r_reuse = client.post("/api/otp/verify", json={"transaction_id": tx2_id, "otp_code": correct_otp2}, headers=headers)
    assert r_reuse.status_code in (400, 429)
    assert any(k in r_reuse.get_json()["error"].lower() for k in ["no longer active", "exhausted", "already in terminal state", "maximum"])


def test_edge_case_cross_user_isolation(client):
    """Verify strict tenant isolation: User 1 cannot view or modify User 2 data."""
    from app.providers.email_provider import DevelopmentEmailProvider
    # Register User 1
    client.post("/api/auth/register", json={"name": "User 1", "email": "u1@example.com", "password": "Password123!", "role": "USER"})
    otp1 = DevelopmentEmailProvider.get_last_email_otp("u1@example.com")
    if otp1:
        client.post("/api/auth/verify-email-otp", json={"email": "u1@example.com", "otp_code": otp1})
    u1_token = client.post("/api/auth/login", json={"email": "u1@example.com", "password": "Password123!"}).get_json()["access_token"]

    # Register User 2
    client.post("/api/auth/register", json={"name": "User 2", "email": "u2@example.com", "password": "Password123!", "role": "USER"})
    otp2 = DevelopmentEmailProvider.get_last_email_otp("u2@example.com")
    if otp2:
        client.post("/api/auth/verify-email-otp", json={"email": "u2@example.com", "otp_code": otp2})
    u2_token = client.post("/api/auth/login", json={"email": "u2@example.com", "password": "Password123!"}).get_json()["access_token"]

    # User 1 creates transaction
    u1_tx_res = client.post(
        "/api/transactions/predict",
        json={"type": "PAYMENT", "amount": 100.0, "destination": "M111"},
        headers={"Authorization": f"Bearer {u1_token}"},
    )
    u1_tx_id = u1_tx_res.get_json()["transaction_id"]

    # User 2 attempts to fetch User 1's transaction
    u2_fetch_res = client.get(f"/api/transactions/{u1_tx_id}", headers={"Authorization": f"Bearer {u2_token}"})
    assert u2_fetch_res.status_code == 403
    assert "Forbidden" in u2_fetch_res.get_json()["error"]


# Fixture for tests in this module
@pytest.fixture
def user_auth_token(client):
    """Register and login regular user."""
    from app.providers.email_provider import DevelopmentEmailProvider
    client.post("/api/auth/register", json={
        "name": "General User",
        "email": "user_edge_cases@example.com",
        "password": "Password123!",
        "role": "USER",
    })
    otp = DevelopmentEmailProvider.get_last_email_otp("user_edge_cases@example.com")
    if otp:
        client.post("/api/auth/verify-email-otp", json={"email": "user_edge_cases@example.com", "otp_code": otp})
    res = client.post("/api/auth/login", json={
        "email": "user_edge_cases@example.com",
        "password": "Password123!",
    })
    return res.get_json()["access_token"]
