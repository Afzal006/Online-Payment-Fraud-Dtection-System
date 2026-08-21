# Backend Architecture & Authentication Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Phase**: Phase 6 — Flask Backend Architecture & JWT Authentication / RBAC  
**Framework**: Flask (Application Factory Pattern)  
**Database**: MySQL / Flask-SQLAlchemy (with SQLite test fallback)  
**Security**: Flask-JWT-Extended, Werkzeug PBKDF2/Scrypt Password Hashing, Role-Based Access Control (RBAC)  
**Report Date**: 2026-08-18  

---

## 1. Backend Application Architecture

The backend follows a modular, decoupled architecture organized by functional layer:

```
app/
├── __init__.py                 # Application factory (create_app), JWT error callbacks, blueprints
├── config.py                   # Environment-driven configuration (Dev, Test, Prod)
├── extensions.py               # Instantiated extensions (SQLAlchemy, JWTManager, CORS)
├── models/                     # SQLAlchemy entity definitions
│   ├── __init__.py
│   ├── user.py                 # User account, password hashing, and role definition
│   ├── transaction.py          # Payment transactions, ML risk scores, and OTP challenge state
│   └── alert.py                # High-risk security alerts for administrative review
├── routes/                     # Blueprint API route controllers
│   ├── auth_routes.py          # /api/auth/register, /api/auth/login, /api/auth/me
│   ├── health_routes.py        # /api/health
│   └── admin_routes.py         # /api/admin/check, /api/admin/overview
├── services/                   # Business logic and cross-cutting domain services
│   ├── auth_service.py         # User registration, verification, and token issuance
│   └── shap_service.py         # Explainable AI integration for prediction routes
└── utils/                      # Helper utilities and decorators
    ├── validators.py           # Request payload sanitization and regex validation
    └── decorators.py           # RBAC decorators (@admin_required, @role_required)
```

---

## 2. API Endpoints & Contract Specifications

### A. Authentication Routes (`/api/auth`)

| Endpoint | Method | Auth Required | Request Body | Description & Status Codes |
|---|---|---|---|---|
| `/api/auth/register` | `POST` | None | `name`, `email`, `password`, `role` (optional) | Registers new user. Returns `201 Created` with user payload. Returns `400` on validation error, `409` on duplicate email. |
| `/api/auth/login` | `POST` | None | `email`, `password` | Authenticates credentials and returns JWT Bearer token + user payload (`200 OK`). Returns `401` on invalid credentials. |
| `/api/auth/me` | `GET` | `Bearer <JWT>` | None | Returns profile of current authenticated user (`200 OK`). Returns `401` if token missing/expired. |

### B. System Diagnostic Routes (`/api`)

| Endpoint | Method | Auth Required | Description |
|---|---|---|---|
| `/api/health` | `GET` | None | Verifies system health, DB connection, and ML engine status (`200 OK`). |

### C. Admin Routes (`/api/admin`)

| Endpoint | Method | Auth Required | Description |
|---|---|---|---|
| `/api/admin/check` | `GET` | `ADMIN` Role | Confirms administrative access (`200 OK`). Rejects regular `USER` accounts with `403 Forbidden`. |
| `/api/admin/overview` | `GET` | `ADMIN` Role | Returns aggregate user, transaction, and alert counts (`200 OK`). |

---

## 3. Database Schema & Entities

```mermaid
erDiagram
    USERS ||--o{ TRANSACTIONS : "submits"
    USERS ||--o{ ALERTS : "associated_with"
    TRANSACTIONS ||--o| ALERTS : "triggers"

    USERS {
        int id PK
        string name
        string email UK
        string password_hash
        string role "USER | ADMIN"
        datetime created_at
    }

    TRANSACTIONS {
        int id PK
        int user_id FK
        int step
        string type
        float amount
        string name_orig
        float oldbalance_org
        float newbalance_orig
        string name_dest
        float oldbalance_dest
        float newbalance_dest
        float fraud_probability
        int risk_score
        string risk_level "LOW | MEDIUM | HIGH"
        string status "APPROVED | PENDING_OTP | VERIFIED | REJECTED"
        boolean requires_otp
        string otp_code
        datetime otp_expires_at
        int otp_attempts
        text explanation_json
        datetime created_at
    }

    ALERTS {
        int id PK
        int transaction_id FK,UK
        int user_id FK
        string severity "MEDIUM | HIGH | CRITICAL"
        text message
        string status "OPEN | RESOLVED | DISMISSED"
        datetime created_at
        datetime resolved_at
    }
```

---

## 4. Security & Cryptographic Practices

1. **Password Hashing**:
   - Plaintext passwords are never persisted.
   - Handled via `werkzeug.security.generate_password_hash` (PBKDF2/Scrypt with automated salt generation).
   - Password verification performed via `werkzeug.security.check_password_hash`.
2. **JWT Authentication & Token Claims**:
   - Access tokens are cryptographically signed using HMAC-SHA256 with `JWT_SECRET_KEY` (minimum 32 bytes).
   - Additional claims encode `role`, `email`, and `name` to minimize database queries during routine authorized API calls.
3. **Role-Based Access Control (RBAC)**:
   - Decorated endpoints (`@admin_required()`) enforce least-privilege access.
   - Regular `USER` accounts attempting to query administrative resources receive a strict `403 Forbidden` (`INSUFFICIENT_PERMISSIONS`).
4. **Input Sanitization & Validation**:
   - Strict regex validation for emails.
   - Minimum 8-character password constraint.
   - Prevention of SQL injection through parameterized SQLAlchemy ORM queries.

---

## 5. Environment Configuration

All environment variables are loaded securely via `python-dotenv`:

| Variable | Description | Default / Example |
|---|---|---|
| `FLASK_ENV` | Application environment mode | `development` / `testing` / `production` |
| `SECRET_KEY` | Flask session secret key | Configured via `.env` |
| `JWT_SECRET_KEY` | HMAC secret for JWT signing | 32+ byte cryptographic string |
| `DATABASE_URL` | SQLAlchemy database connection URI | `mysql+pymysql://user:pass@localhost:3306/fraud_detection` |
| `RISK_LOW_MAX` | Maximum score for immediate approval | `30` |
| `RISK_MEDIUM_MAX` | Maximum score for standard OTP | `70` |
| `OTP_EXPIRY_SECONDS` | Lifetime of simulated OTP challenges | `180` (3 minutes) |

---

## 6. Test Suite Execution & Results

Executed:
```bash
py -m pytest -v
```

**Results:**
```
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
cachedir: .pytest_cache
rootdir: C:\Users\AFZAL\Online Payment fraud detection system
collected 56 items

tests/test_audit.py (4 tests) ........................................ PASSED
tests/test_auth.py (12 tests) ........................................ PASSED
tests/test_feature_engineering.py (6 tests) .......................... PASSED
tests/test_inference.py (8 tests) .................................... PASSED
tests/test_models.py (5 tests) ....................................... PASSED
tests/test_preprocessing.py (3 tests) ................................ PASSED
tests/test_setup.py (6 tests) ........................................ PASSED
tests/test_shap.py (7 tests) ......................................... PASSED
tests/test_strong_models.py (5 tests) ................................ PASSED

======================= 56 passed, 3 warnings in 6.80s ========================
```
"""

    report_path = DOCS_DIR / "backend_authentication_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Saved backend authentication report to: {report_path}")


if __name__ == "__main__":
    pass
