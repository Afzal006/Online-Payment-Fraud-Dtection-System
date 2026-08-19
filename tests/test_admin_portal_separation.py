"""
Regression Test Suite for Admin/User Portal Separation and Multi-Customer RBAC.

Verifies:
1. Admin login redirects to /admin/dashboard.
2. User login redirects to /dashboard.
3. Admin can access /admin/customers.
4. Admin can see multiple customers.
5. Admin can see transactions belonging to multiple users.
6. Admin can open customer details.
7. Admin can open transaction details.
8. Admin can see alerts belonging to multiple customers.
9. User cannot access /admin/dashboard (or admin APIs receive 403).
10. User cannot access /api/admin/customers.
11. User cannot access /api/admin/transactions.
12. User cannot access another customer's transaction.
13. Admin global transaction query does NOT filter by admin user_id.
"""

import json
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert


@pytest.fixture
def app():
    """Create test application with in-memory database."""
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
def setup_multi_customers_and_admin(client, app):
    """Seed 3 distinct customers, 1 admin, and transactions for each."""
    with app.app_context():
        # Customer 1
        c1 = User(name="Arjun Sharma", email="customer1@example.com", role="USER")
        c1.set_password("UserPass2026!")

        # Customer 2
        c2 = User(name="Priya Patel", email="customer2@example.com", role="USER")
        c2.set_password("UserPass2026!")

        # Customer 3
        c3 = User(name="Vikram Malhotra", email="customer3@example.com", role="USER")
        c3.set_password("UserPass2026!")

        # Admin
        admin = User(name="SOC Lead Officer", email="admin_soc@example.com", role="ADMIN")
        admin.set_password("AdminPass2026!")

        db.session.add_all([c1, c2, c3, admin])
        db.session.flush()

        # Customer 1 Transaction (LOW)
        t1 = Transaction(
            user_id=c1.id,
            type="PAYMENT",
            amount=1500.0,
            oldbalance_org=1500.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=1500.0,
            prediction=0,
            risk_score=10,
            risk_level="LOW",
            status="APPROVED",
        )

        # Customer 2 Transaction (HIGH with Alert)
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

        # Customer 3 Transaction (MEDIUM)
        t3 = Transaction(
            user_id=c3.id,
            type="TRANSFER",
            amount=50000.0,
            oldbalance_org=50000.0,
            newbalance_orig=0.0,
            oldbalance_dest=0.0,
            newbalance_dest=50000.0,
            prediction=0,
            risk_score=49,
            risk_level="MEDIUM",
            status="OTP_REQUIRED",
        )

        db.session.add_all([t1, t2, t3])
        db.session.flush()

        # Alert on Customer 2 tx
        a2 = Alert(
            transaction_id=t2.id,
            user_id=c2.id,
            severity="HIGH",
            status="OPEN",
            message="High-value transfer exceeding ₹1,00,000 threshold.",
        )
        db.session.add(a2)
        db.session.commit()

        return {
            "c1_id": c1.id,
            "c2_id": c2.id,
            "c3_id": c3.id,
            "admin_id": admin.id,
            "t1_id": t1.id,
            "t2_id": t2.id,
            "t3_id": t3.id,
            "a2_id": a2.id,
        }


# =====================================================================
# 1 & 2: LOGIN REDIRECTION TESTS
# =====================================================================

def test_1_admin_login_redirects_to_admin_dashboard(client, setup_multi_customers_and_admin):
    """1. Verify Admin login returns redirect_url to /admin/dashboard."""
    res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["user"]["role"] == "ADMIN"
    assert data["redirect_url"] == "/admin/dashboard"


def test_2_user_login_redirects_to_user_dashboard(client, setup_multi_customers_and_admin):
    """2. Verify User login returns redirect_url to /dashboard."""
    res = client.post("/api/auth/login", json={
        "email": "customer1@example.com",
        "password": "UserPass2026!",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["user"]["role"] == "USER"
    assert data["redirect_url"] == "/dashboard"


# =====================================================================
# 3, 4 & 5: ADMIN ACCESS & MULTI-CUSTOMER VISIBILITY TESTS
# =====================================================================

def test_3_admin_can_access_admin_customers_page(client):
    """3. Verify admin web route /admin/customers renders 200 OK."""
    res = client.get("/admin/customers")
    assert res.status_code == 200
    assert "Customer Accounts Directory" in res.get_data(as_text=True)


def test_4_admin_can_see_multiple_customers(client, setup_multi_customers_and_admin):
    """4. Verify Admin API /api/admin/customers lists multiple customers."""
    login_res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/customers", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] == 3

    emails = [c["email"] for c in data["customers"]]
    assert "customer1@example.com" in emails
    assert "customer2@example.com" in emails
    assert "customer3@example.com" in emails


def test_5_admin_can_see_transactions_belonging_to_multiple_users(client, setup_multi_customers_and_admin):
    """5. Verify Admin API /api/admin/transactions returns transactions across all customers."""
    login_res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/transactions", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] == 3

    user_emails = {tx["user_email"] for tx in data["transactions"]}
    assert "customer1@example.com" in user_emails
    assert "customer2@example.com" in user_emails
    assert "customer3@example.com" in user_emails


# =====================================================================
# 6, 7 & 8: CUSTOMER DETAILS, TRANSACTION DETAILS, AND ALERTS TESTS
# =====================================================================

def test_6_admin_can_open_customer_details(client, setup_multi_customers_and_admin):
    """6. Verify Admin can query /api/admin/customers/<id> to view specific customer telemetry."""
    info = setup_multi_customers_and_admin
    login_res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get(f"/api/admin/customers/{info['c2_id']}", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["customer"]["name"] == "Priya Patel"
    assert data["customer"]["email"] == "customer2@example.com"
    assert data["summary"]["total_transactions"] == 1
    assert data["summary"]["total_amount"] == 250001.0
    assert data["summary"]["high_risk_transactions"] == 1
    assert len(data["transactions"]) == 1


def test_7_admin_can_open_transaction_details(client, setup_multi_customers_and_admin):
    """7. Verify Admin can inspect full transaction audit telemetry with SHAP and alert info."""
    info = setup_multi_customers_and_admin
    login_res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get(f"/api/admin/transactions/{info['t2_id']}", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["transaction"]["id"] == info["t2_id"]
    assert data["user"]["email"] == "customer2@example.com"
    assert data["alert"] is not None
    assert data["alert"]["id"] == info["a2_id"]


def test_8_admin_can_see_alerts_belonging_to_multiple_customers(client, setup_multi_customers_and_admin, app):
    """8. Verify Admin alerts endpoint aggregates alerts across multiple customers."""
    info = setup_multi_customers_and_admin

    # Add a second alert for Customer 3
    with app.app_context():
        a3 = Alert(
            transaction_id=info["t3_id"],
            user_id=info["c3_id"],
            severity="MEDIUM",
            status="OPEN",
            message="Step-up OTP verification challenge.",
        )
        db.session.add(a3)
        db.session.commit()

    login_res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/alerts", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] == 2

    alert_users = {a["user_email"] for a in data["alerts"]}
    assert "customer2@example.com" in alert_users
    assert "customer3@example.com" in alert_users


# =====================================================================
# 9, 10, 11 & 12: USER ACCESS RESTRICTIONS & MULTI-TENANT ISOLATION
# =====================================================================

def test_9_user_cannot_access_admin_overview_api(client, setup_multi_customers_and_admin):
    """9. Verify standard user receives 403 Forbidden on admin overview."""
    login_res = client.post("/api/auth/login", json={
        "email": "customer1@example.com",
        "password": "UserPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/overview", headers=headers)
    assert res.status_code == 403


def test_10_user_cannot_access_api_admin_customers(client, setup_multi_customers_and_admin):
    """10. Verify standard user receives 403 Forbidden on /api/admin/customers."""
    login_res = client.post("/api/auth/login", json={
        "email": "customer1@example.com",
        "password": "UserPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/customers", headers=headers)
    assert res.status_code == 403


def test_11_user_cannot_access_api_admin_transactions(client, setup_multi_customers_and_admin):
    """11. Verify standard user receives 403 Forbidden on /api/admin/transactions."""
    login_res = client.post("/api/auth/login", json={
        "email": "customer1@example.com",
        "password": "UserPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/transactions", headers=headers)
    assert res.status_code == 403


def test_12_user_cannot_access_another_customers_transaction(client, setup_multi_customers_and_admin):
    """12. Verify User 1 cannot retrieve User 2's transaction through consumer transaction API."""
    info = setup_multi_customers_and_admin
    login_res = client.post("/api/auth/login", json={
        "email": "customer1@example.com",
        "password": "UserPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # User 1 attempts to fetch User 2's transaction (t2_id)
    res = client.get(f"/api/transactions/{info['t2_id']}", headers=headers)
    assert res.status_code in [403, 404]


def test_13_admin_global_transaction_query_does_not_filter_by_admin_id(client, setup_multi_customers_and_admin):
    """13. Verify admin query returns transactions from all other users even when admin has 0 transactions."""
    login_res = client.post("/api/auth/login", json={
        "email": "admin_soc@example.com",
        "password": "AdminPass2026!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/admin/transactions", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    # Admin has 0 transactions created by themselves, but global ledger returns 3 transactions!
    assert data["total"] == 3
