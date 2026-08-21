# High-Level Design (HLD) & System Architecture

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  

---

## 1. System Architecture Overview

AegisGuard AI follows a layered, service-oriented architecture (SOA) emphasizing modular decoupling, stateless API communication, and high-performance ML inference.

```
+─────────────────────────────────────────────────────────────────────────────────────────────+
|                                    PRESENTATION LAYER                                       |
|  +───────────────────────────────────────────────+   +───────────────────────────────────+  |
|  |             Customer User Portal              |   |   Admin Security Operations (SOC) |  |
|  |  • Login / Register Views                     |   |  • SOC Dashboard & KPI Cards      |  |
|  |  • Payment Transfer Simulator                 |   |  • Interactive Chart.js Telemetry |  |
|  |  • Real-Time Risk Modal & OTP Challenge Modal |   |  • Alert Triage & Notes Resolver  |  |
|  |  • SHAP "Why was this flagged?" Drawer        |   |  • Global Transaction Ledger      |  |
|  |  • Personal Transaction Ledger                |   |  • Model Registry & Drift Monitor |  |
|  +───────────────────────────────────────────────+   +───────────────────────────────────+  |
+──────────────────────────────────────────────┬──────────────────────────────────────────────+
                                               │ HTTP / REST / JSON (JWT Bearer Auth)
                                               ▼
+─────────────────────────────────────────────────────────────────────────────────────────────+
|                                    APPLICATION API LAYER                                    |
|  +──────────────────+   +──────────────────+   +─────────────────+   +───────────────────+  |
|  | Auth Blueprint   |   | Transaction BP   |   | OTP Blueprint   |   | Admin Blueprint   |  |
|  | /api/auth/*      |   | /api/transactions|   | /api/otp/*      |   | /api/admin/*      |  |
|  +──────────────────+   +──────────────────+   +─────────────────+   +───────────────────+  |
+──────────────────────────────────────────────┬──────────────────────────────────────────────+
                                               │ Python Service Invocations
                                               ▼
+─────────────────────────────────────────────────────────────────────────────────────────────+
|                                    BUSINESS & ML SERVICE LAYER                              |
|  +──────────────────+   +──────────────────+   +─────────────────+   +───────────────────+  |
|  | ML Inference Svc |   | SHAP Explain Svc |   | Risk Policy Svc |   | OTP Security Svc  |  |
|  | (Random Forest)  |   | (TreeExplainer)  |   | (3-Tier Engine) |   | (Secrets/PBKDF2)  |  |
|  +──────────────────+   +──────────────────+   +─────────────────+   +───────────────────+  |
|  +─────────────────────────────────────────+   +─────────────────────────────────────────+  |
|  | Alert Incident Management Service       |   | Admin SQL Analytics & Drift Service     |  |
|  +─────────────────────────────────────────+   +─────────────────────────────────────────+  |
+──────────────────────────────────────────────┬──────────────────────────────────────────────+
                                               │ SQLAlchemy ORM & Model Artifacts
                                               ▼
+─────────────────────────────────────────────────────────────────────────────────────────────+
|                                    PERSISTENCE & ARTIFACT LAYER                             |
|  +─────────────────────────────────────────+   +─────────────────────────────────────────+  |
|  | Relational Database (MySQL / SQLite)    |   | Serialized ML & Configuration Artifacts |  |
|  | • users           • transactions        |   | • model.joblib (Tuned Random Forest)    |  |
|  | • alerts          • otp_challenges      |   | • preprocessor.joblib (ColumnTransformer|  |
|  |                                         |   | • model_metadata.json & risk_policy.json|  |
|  +─────────────────────────────────────────+   +─────────────────────────────────────────+  |
+─────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Architectural Subsystems & Component Responsibilities

### 2.1 Presentation Subsystem (`frontend/`)
- **Technology**: Semantic HTML5, Vanilla CSS3 (Custom Glassmorphism Design System), Vanilla JavaScript (ES6 Modules), Chart.js 4.4.
- **Components**:
  - `ApiClient` ([frontend/static/js/api.js](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/frontend/static/js/api.js)): Encapsulates all AJAX communications, manages local token storage, handles global 401 expiration redirects, and triggers toast notifications.
  - `ShapDrawer` ([frontend/static/js/shap_drawer.js](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/frontend/static/js/shap_drawer.js)): Renders dynamic horizontal feature contribution bars and backend natural language narratives.
  - `OtpModal` ([frontend/static/js/otp.js](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/frontend/static/js/otp.js)): Manages the 180s countdown timer, attempt counter, and verification request.
  - `AdminSOC` ([frontend/static/js/admin/admin_dashboard.js](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/frontend/static/js/admin/admin_dashboard.js)): Renders real-time Chart.js charts, drift divergence meters, and alert triage tables.

### 2.2 Application Controller Subsystem (`app/routes/`)
- **`auth_routes.py`**: `/api/auth/register`, `/api/auth/login`, `/api/auth/me`.
- **`transaction_routes.py`**: `/api/transactions/predict`, `/api/transactions/my-history`, `/api/transactions/<id>`.
- **`otp_routes.py`**: `/api/otp/generate`, `/api/otp/verify`.
- **`admin_routes.py`**: `/api/admin/overview`, `/api/admin/analytics`, `/api/admin/alerts`, `/api/admin/alerts/<id>/resolve`, `/api/admin/transactions`, `/api/admin/model-info`.
- **`web_routes.py`**: Serves all HTML views for the User Portal and Admin SOC.

### 2.3 Business Logic & AI Engine Subsystem (`app/services/` & `ml/`)
- **`InferenceService`** ([ml/inference.py](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/ml/inference.py)): Singleton loader for `model.joblib` and `preprocessor.joblib`; transforms raw transaction inputs and generates predictions.
- **`ShapService`** ([app/services/shap_service.py](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/app/services/shap_service.py)): Uses `shap.TreeExplainer` to calculate local Shapley values, maps features to financial descriptions, and synthesizes natural language summaries.
- **`RiskDecisionService`** ([app/services/risk_service.py](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/app/services/risk_service.py)): Evaluates integer risk scores ($0-100$) into 3 tiers (`LOW`, `MEDIUM`, `HIGH`).
- **`OTPService`** ([app/services/otp_service.py](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/app/services/otp_service.py)): Handles cryptographic OTP generation, PBKDF2 hashing, expiration verification, and rate limiting.
- **`AlertService`** ([app/services/alert_service.py](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/app/services/alert_service.py)): Creates, retrieves, and resolves security incident records.
- **`AdminAnalyticsService`** ([app/services/admin_analytics_service.py](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/app/services/admin_analytics_service.py)): Computes SQL database aggregations and evaluates feature drift.

### 2.4 Persistence Subsystem (`app/models/` & `database/`)
- **`User`**: Account identity, hashed passwords, roles (`USER`, `ADMIN`).
- **`Transaction`**: Transaction financial details, ML predictions, risk scores, statuses, and serialized SHAP payloads.
- **`Alert`**: Security incidents linked to high-risk transactions with resolution notes.
- **`OTPChallenge`**: Hashed multi-factor tokens, expiration timestamps, attempt counters, and status states.

---

## 3. Technology Stack Reference

| Layer | Technology / Library | Version / Specification | Rationale |
|---|---|---|---|
| **Backend Framework** | Flask | $\ge 3.0.0$ | Lightweight, modular WSGI application factory architecture. |
| **Persistence ORM** | Flask-SQLAlchemy | $\ge 3.1.0$ | Relational ORM supporting MySQL in production and SQLite in test. |
| **Database Migrations** | Flask-Migrate (Alembic) | $\ge 4.1.0$ | Reproducible, versioned database schema migrations. |
| **Authentication** | Flask-JWT-Extended | $\ge 4.6.0$ | Stateless JSON Web Token authentication with RBAC. |
| **Password Security** | Werkzeug Security | Built-in | Cryptographic PBKDF2/Scrypt password and OTP hashing. |
| **Machine Learning** | Scikit-Learn | $\ge 1.4.0$ | Tuned Random Forest Classifier ($F_1 = 0.9985$). |
| **Secondary Benchmark**| XGBoost | $\ge 2.0.0$ | Gradient-boosted decision trees benchmark ($F_1 = 0.9976$). |
| **Explainable AI** | SHAP | $\ge 0.44.0$ | `TreeExplainer` providing mathematical attribution. |
| **Data Processing** | Pandas / NumPy | $\ge 2.1.0$ | Vectorized feature engineering and chunked dataset auditing. |
| **Frontend Core** | HTML5 / CSS3 / JS | Vanilla ES6+ | High performance, zero framework overhead, custom fintech theme. |
| **Visual Analytics** | Chart.js | $4.4.0$ | Interactive canvas charts for SOC telemetry. |
| **Testing Framework** | Pytest | $\ge 8.0.0$ | 100% automated test coverage across 15 test modules. |
