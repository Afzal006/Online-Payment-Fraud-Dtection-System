import json
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User


@pytest.fixture
def app():
    """Create test application configured with in-memory SQLite database."""
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


def test_health_check(client):
    """Verify GET /api/health returns 200 and system health metadata."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert "ml_engine" in data


def test_user_registration_success(client):
    """Verify successful user registration returns 201 and user payload."""
    payload = {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "password": "SecurePassword123!",
        "role": "USER",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["message"] == "User registered successfully"
    assert data["user"]["email"] == "alice@example.com"
    assert data["user"]["role"] == "USER"
    assert "password_hash" not in data["user"]


def test_user_registration_duplicate_email(client):
    """Verify registering an already registered email returns 409 Conflict."""
    payload = {
        "name": "Bob Smith",
        "email": "bob@example.com",
        "password": "Password123!",
    }
    res1 = client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/auth/register", json=payload)
    assert res2.status_code == 409
    assert "already registered" in res2.get_json()["error"].lower()


def test_user_registration_validation_errors(client):
    """Verify validation errors for short passwords, invalid emails, and empty names."""
    # Short password (< 8 chars)
    res_short_pw = client.post("/api/auth/register", json={
        "name": "Short Pass",
        "email": "test@example.com",
        "password": "short",
    })
    assert res_short_pw.status_code == 400
    assert "at least 8 characters" in res_short_pw.get_json()["error"]

    # Invalid email
    res_bad_email = client.post("/api/auth/register", json={
        "name": "Bad Email",
        "email": "not-an-email",
        "password": "ValidPassword123!",
    })
    assert res_bad_email.status_code == 400

    # Empty name
    res_bad_name = client.post("/api/auth/register", json={
        "name": " ",
        "email": "valid@example.com",
        "password": "ValidPassword123!",
    })
    assert res_bad_name.status_code == 400


def test_user_login_success(client):
    """Verify valid login returns 200 and a JWT access token."""
    client.post("/api/auth/register", json={
        "name": "Charlie Day",
        "email": "charlie@example.com",
        "password": "Password123!",
    })

    res = client.post("/api/auth/login", json={
        "email": "charlie@example.com",
        "password": "Password123!",
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["user"]["email"] == "charlie@example.com"


def test_user_login_invalid_password(client):
    """Verify login with incorrect password returns 401 Unauthorized."""
    client.post("/api/auth/register", json={
        "name": "David Miller",
        "email": "david@example.com",
        "password": "CorrectPassword123!",
    })

    res = client.post("/api/auth/login", json={
        "email": "david@example.com",
        "password": "WrongPassword123!",
    })
    assert res.status_code == 401
    assert "invalid email or password" in res.get_json()["error"].lower()


def test_user_login_nonexistent_user(client):
    """Verify login with non-existent email returns 401 Unauthorized."""
    res = client.post("/api/auth/login", json={
        "email": "ghost@example.com",
        "password": "SomePassword123!",
    })
    assert res.status_code == 401


def test_get_current_user_profile(client):
    """Verify GET /api/auth/me returns current user's profile when authenticated."""
    client.post("/api/auth/register", json={
        "name": "Eve Adams",
        "email": "eve@example.com",
        "password": "Password123!",
    })

    login_res = client.post("/api/auth/login", json={
        "email": "eve@example.com",
        "password": "Password123!",
    })
    token = login_res.get_json()["access_token"]

    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["user"]["email"] == "eve@example.com"
    assert data["user"]["name"] == "Eve Adams"


def test_missing_jwt_token(client):
    """Verify accessing protected endpoint without JWT returns 401."""
    res = client.get("/api/auth/me")
    assert res.status_code == 401
    assert res.get_json()["code"] == "AUTHORIZATION_REQUIRED"


def test_invalid_jwt_token(client):
    """Verify accessing protected endpoint with invalid JWT returns 422."""
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.fake.token"})
    assert res.status_code == 422
    assert res.get_json()["code"] == "INVALID_TOKEN"


def test_rbac_admin_access_allowed(client):
    """Verify ADMIN role can access admin-protected routes."""
    client.post("/api/auth/register", json={
        "name": "Admin User",
        "email": "admin@example.com",
        "password": "AdminPassword123!",
        "role": "ADMIN",
    })

    login_res = client.post("/api/auth/login", json={
        "email": "admin@example.com",
        "password": "AdminPassword123!",
    })
    token = login_res.get_json()["access_token"]

    res = client.get("/api/admin/check", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.get_json()["admin_access"] is True


def test_rbac_user_access_forbidden_on_admin_route(client):
    """Verify regular USER role receives 403 Forbidden on admin-protected routes."""
    client.post("/api/auth/register", json={
        "name": "Standard User",
        "email": "user@example.com",
        "password": "UserPassword123!",
        "role": "USER",
    })

    login_res = client.post("/api/auth/login", json={
        "email": "user@example.com",
        "password": "UserPassword123!",
    })
    token = login_res.get_json()["access_token"]

    res = client.get("/api/admin/check", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "administrative privileges required" in res.get_json()["error"].lower()
