"""
Admin Security Operations Center (SOC) Test Suite.

Verifies RBAC protection, analytics aggregation, Chart.js datasets,
alert triage lifecycle, transaction inspection, and model drift telemetry.
"""

import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.services.admin_analytics_service import AdminAnalyticsService


@pytest.fixture
def app():
    """Create test application."""
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


@pytest.fixture
def user_auth_token(client):
    """Register and login regular user, returning JWT."""
    client.post("/api/auth/register", json={
        "name": "Regular User",
        "email": "user_soc@example.com",
        "password": "Password123!",
        "role": "USER",
    })
    res = client.post("/api/auth/login", json={
        "email": "user_soc@example.com",
        "password": "Password123!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def admin_auth_token(client):
    """Register and login administrator, returning JWT."""
    client.post("/api/auth/register", json={
        "name": "SOC Lead",
        "email": "admin_soc@example.com",
        "password": "AdminPassword123!",
        "role": "ADMIN",
    })
    res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPassword123!",
    })
    return res.get_json()["access_token"]


# =====================================================================
# 1. RBAC AUTHORIZATION TESTS
# =====================================================================

def test_admin_endpoints_reject_unauthenticated(client):
    """Verify unauthenticated requests to admin APIs receive 401."""
    assert client.get("/api/admin/overview").status_code == 401
    assert client.get("/api/admin/analytics").status_code == 401
    assert client.get("/api/admin/alerts").status_code == 401
    assert client.get("/api/admin/transactions").status_code == 401
    assert client.get("/api/admin/model-info").status_code == 401


def test_admin_endpoints_reject_regular_user(client, user_auth_token):
    """Verify USER role requests to admin APIs receive 403 Forbidden."""
    headers = {"Authorization": f"Bearer {user_auth_token}"}
    assert client.get("/api/admin/overview", headers=headers).status_code == 403
    assert client.get("/api/admin/analytics", headers=headers).status_code == 403
    assert client.get("/api/admin/alerts", headers=headers).status_code == 403
    assert client.get("/api/admin/transactions", headers=headers).status_code == 403
    assert client.get("/api/admin/model-info", headers=headers).status_code == 403


def test_admin_endpoints_accept_admin(client, admin_auth_token):
    """Verify ADMIN role requests are authorized with 200 OK."""
    headers = {"Authorization": f"Bearer {admin_auth_token}"}
    assert client.get("/api/admin/check", headers=headers).status_code == 200
    assert client.get("/api/admin/overview", headers=headers).status_code == 200
    assert client.get("/api/admin/analytics", headers=headers).status_code == 200
    assert client.get("/api/admin/alerts", headers=headers).status_code == 200
    assert client.get("/api/admin/transactions", headers=headers).status_code == 200
    assert client.get("/api/admin/model-info", headers=headers).status_code == 200


# =====================================================================
# 2. ANALYTICS DATA AGGREGATION TESTS
# =====================================================================

def test_admin_analytics_empty_database(client, admin_auth_token):
    """Verify analytics and KPIs return safely on clean/empty database."""
    headers = {"Authorization": f"Bearer {admin_auth_token}"}
    res = client.get("/api/admin/overview", headers=headers)
    assert res.status_code == 200
    data = res.get_json()["kpis"]
    assert data["total_transactions"] == 0
    assert data["total_volume_usd"] == 0.0
    assert data["risk_tiers"]["LOW"] == 0

    analytics_res = client.get("/api/admin/analytics", headers=headers)
    assert analytics_res.status_code == 200
    charts = analytics_res.get_json()["charts"]
    assert "volume_by_type" in charts
    assert "risk_distribution" in charts
    assert "class_distribution" in charts


def test_admin_analytics_with_transactions(client, admin_auth_token, app):
    """Verify SQL aggregation accurately counts risk tiers and volume."""
    with app.app_context():
        user = User.query.filter_by(email="admin_soc@example.com").first()
        t1 = Transaction(
            user_id=user.id,
            type="PAYMENT",
            amount=100.0,
            oldbalance_org=100.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=100.0,
            prediction=0,
            risk_score=10,
            risk_level="LOW",
            status="APPROVED",
        )
        t2 = Transaction(
            user_id=user.id,
            type="TRANSFER",
            amount=500000.0,
            oldbalance_org=500000.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=500000.0,
            prediction=1,
            risk_score=95,
            risk_level="HIGH",
            status="UNDER_REVIEW",
        )
        db.session.add_all([t1, t2])
        db.session.commit()

    headers = {"Authorization": f"Bearer {admin_auth_token}"}
    res = client.get("/api/admin/overview", headers=headers)
    assert res.status_code == 200
    kpis = res.get_json()["kpis"]
    assert kpis["total_transactions"] == 2
    assert kpis["risk_tiers"]["LOW"] == 1
    assert kpis["risk_tiers"]["HIGH"] == 1
    assert kpis["total_volume_usd"] == 500100.0


# =====================================================================
# 3. ALERT TRIAGE & RESOLUTION TESTS
# =====================================================================

def test_admin_alert_lifecycle(client, admin_auth_token, app):
    """Verify viewing alert details, resolving with notes, and dismissing."""
    with app.app_context():
        user = User.query.filter_by(email="admin_soc@example.com").first()
        tx = Transaction(
            user_id=user.id,
            type="TRANSFER",
            amount=250000.0,
            oldbalance_org=250000.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=250000.0,
            prediction=1,
            risk_score=88,
            risk_level="HIGH",
            status="UNDER_REVIEW",
        )
        db.session.add(tx)
        db.session.flush()

        alert = Alert(
            transaction_id=tx.id,
            user_id=user.id,
            alert_type="FRAUD_ALERT",
            severity="HIGH",
            message="High-value transfer flagged.",
            status="OPEN",
        )
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id
        tx_id = tx.id

    headers = {"Authorization": f"Bearer {admin_auth_token}"}

    # 1. View Alert Detail
    detail_res = client.get(f"/api/admin/alerts/{alert_id}", headers=headers)
    assert detail_res.status_code == 200
    detail_data = detail_res.get_json()
    assert detail_data["alert"]["id"] == alert_id
    assert detail_data["transaction"]["id"] == tx_id

    # 2. Resolve Alert with Note
    resolve_res = client.post(
        f"/api/admin/alerts/{alert_id}/resolve",
        json={"note": "Verified with cardholder. Transaction approved."},
        headers=headers,
    )
    assert resolve_res.status_code == 200
    assert resolve_res.get_json()["alert"]["status"] == "RESOLVED"

    # 3. Dismiss Alert
    dismiss_res = client.post(f"/api/admin/alerts/{alert_id}/dismiss", headers=headers)
    assert dismiss_res.status_code == 200
    assert dismiss_res.get_json()["alert"]["status"] == "DISMISSED"


# =====================================================================
# 4. MODEL BENCHMARKS & DRIFT TESTS
# =====================================================================

def test_admin_model_info_and_drift_telemetry(client, admin_auth_token):
    """Verify model metadata and feature drift indicator responses."""
    headers = {"Authorization": f"Bearer {admin_auth_token}"}
    res = client.get("/api/admin/model-info", headers=headers)
    assert res.status_code == 200
    data = res.get_json()

    # Verify model metadata
    assert "model_metadata" in data
    meta = data["model_metadata"]
    assert "Random Forest" in meta.get("model_name", "") or "Tuned" in meta.get("model_name", "")

    # Verify drift telemetry
    assert "data_drift" in data
    drift = data["data_drift"]
    assert drift["status"] in ["NORMAL", "WARNING", "DRIFT DETECTED"]
    assert "drift_score" in drift


# =====================================================================
# 5. ADMIN WEB TEMPLATES RENDERING TESTS
# =====================================================================

def test_admin_web_pages_render(client):
    """Verify admin HTML template routes render successfully."""
    # /admin redirects to /admin/dashboard
    root_res = client.get("/admin")
    assert root_res.status_code == 302
    assert "/admin/dashboard" in root_res.headers["Location"]

    # Pages render 200 OK
    dash_res = client.get("/admin/dashboard")
    assert dash_res.status_code == 200
    assert "Security Operations Center" in dash_res.get_data(as_text=True)

    alerts_res = client.get("/admin/alerts")
    assert alerts_res.status_code == 200
    assert "Security Incident Alert Triage" in alerts_res.get_data(as_text=True)

    model_res = client.get("/admin/model")
    assert model_res.status_code == 200
    assert "ML Model Telemetry" in model_res.get_data(as_text=True)

    cust_res = client.get("/admin/customers")
    assert cust_res.status_code == 200
    assert "Customer Accounts Directory" in cust_res.get_data(as_text=True)

    cust_detail_res = client.get("/admin/customers/1")
    assert cust_detail_res.status_code == 200
    assert "Customer Profile" in cust_detail_res.get_data(as_text=True)


# =====================================================================
# 6. ADMIN CUSTOMERS API TESTS
# =====================================================================

def test_admin_customers_api_lifecycle(client, admin_auth_token, app):
    """Verify admin can list all registered customers and view detailed customer profile."""
    # 1. Create multiple customers and transactions
    with app.app_context():
        c1 = User(name="Priya Patel", email="priya@example.com", role="USER")
        c1.set_password("UserPass2026!")
        c2 = User(name="Vikram Malhotra", email="vikram@example.com", role="USER")
        c2.set_password("UserPass2026!")
        db.session.add_all([c1, c2])
        db.session.flush()

        t1 = Transaction(
            user_id=c1.id,
            type="PAYMENT",
            amount=2500.0,
            oldbalance_org=2500.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=2500.0,
            prediction=0,
            risk_score=15,
            risk_level="LOW",
            status="APPROVED",
        )
        t2 = Transaction(
            user_id=c2.id,
            type="TRANSFER",
            amount=250001.0,
            oldbalance_org=250001.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=250001.0,
            prediction=1,
            risk_score=78,
            risk_level="HIGH",
            status="UNDER_REVIEW",
        )
        db.session.add_all([t1, t2])
        db.session.commit()
        c1_id = c1.id
        c2_id = c2.id

    headers = {"Authorization": f"Bearer {admin_auth_token}"}

    # 2. Query /api/admin/customers
    res = client.get("/api/admin/customers", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] >= 2
    emails = [c["email"] for c in data["customers"]]
    assert "priya@example.com" in emails
    assert "vikram@example.com" in emails

    # 3. Query /api/admin/customers/<c2_id>
    detail_res = client.get(f"/api/admin/customers/{c2_id}", headers=headers)
    assert detail_res.status_code == 200
    detail_data = detail_res.get_json()
    assert detail_data["success"] is True
    assert detail_data["customer"]["email"] == "vikram@example.com"
    assert detail_data["summary"]["total_transactions"] == 1
    assert detail_data["summary"]["total_amount"] == 250001.0
    assert detail_data["summary"]["high_risk_transactions"] == 1
    assert len(detail_data["transactions"]) == 1

