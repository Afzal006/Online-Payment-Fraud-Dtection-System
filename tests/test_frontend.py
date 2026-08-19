"""
Frontend User Portal Web Route & Asset Integration Tests.
"""

import pytest
from app import create_app
from app.extensions import db


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


def test_index_redirects_to_dashboard(client):
    """Verify root / redirects to dashboard."""
    res = client.get("/")
    assert res.status_code == 302
    assert "/dashboard" in res.headers["Location"]


def test_login_page_renders(client):
    """Verify /login renders correctly with auth form and demo buttons."""
    res = client.get("/login")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Sign In" in html
    assert "login-form" in html
    assert "email" in html
    assert "password" in html
    assert "autofillDemoUser" in html


def test_register_page_renders(client):
    """Verify /register renders correctly with name, email, password."""
    res = client.get("/register")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Create Account" in html
    assert "register-form" in html
    assert "reg-email" in html
    assert "reg-password" in html


def test_dashboard_page_renders(client):
    """Verify /dashboard renders structure, stat counters, and recent table."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Dashboard" in html
    assert "dash-total-tx" in html or "stat-total-tx" in html
    assert "dash-recent-tx-tbody" in html or "recent-transactions-tbody" in html
    assert "shap-drawer-overlay" in html


def test_payment_simulator_page_renders(client):
    """Verify /payment renders transfer form, preset scenarios, and result modal."""
    res = client.get("/payment")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Payment Transfer Simulation" in html
    assert "payment-form" in html
    assert "tx-type" in html
    assert "tx-amount" in html
    assert "loadScenario" in html
    assert "result-modal-overlay" in html
    assert "otp-modal-overlay" in html


def test_history_ledger_page_renders(client):
    """Verify /history renders ledger table and audit trail controls."""
    res = client.get("/history")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Personal Transaction Ledger" in html or "Payment Ledger" in html
    assert "history-tx-tbody" in html or "history-tbody" in html


def test_static_assets_served(client):
    """Verify core CSS and JS static assets are accessible."""
    css_res = client.get("/static/css/style.css")
    assert css_res.status_code == 200
    assert len(css_res.get_data(as_text=True)) > 0

    api_res = client.get("/static/js/api.js")
    assert api_res.status_code == 200
    assert "ApiClient" in api_res.get_data(as_text=True)

    shap_res = client.get("/static/js/shap_drawer.js")
    assert shap_res.status_code == 200
    assert "ShapDrawer" in shap_res.get_data(as_text=True)
