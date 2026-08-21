# FraudShield AI — Online Payment Fraud Detection & Explainable Risk Assessment System

> **Enterprise-Grade AI/ML FinTech Defense Platform**  
> Real-Time Machine Learning Inference • Dual-Perspective Explainable AI (SHAP) • Adaptive Step-Up Multi-Factor Authentication • Multi-Tier Risk Engine • SOC Analyst Dashboard

[![Python](https://img.shields.io/badge/Python-3.11%2B%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20XGBoost-orange.svg)](https://scikit-learn.org/)
[![Explainability](https://img.shields.io/badge/XAI-SHAP%20TreeExplainer-red.svg)](https://shap.readthedocs.io/)
[![Testing](https://img.shields.io/badge/Tests-484%20Passed%20%7C%20100%25-brightgreen.svg)](https://docs.pytest.org/)
[![Security](https://img.shields.io/badge/Security-PBKDF2%2FArgon2%20%7C%20JWT%20%7C%20SMTP%20TLS-success.svg)](https://owasp.org/)

---

## 1. Executive Summary & Problem Statement

Online digital payment ecosystems (UPI, P2P Transfers, Merchant QR Payments, Cards, and Net Banking) process billions of financial transactions daily. Traditional static rule-based fraud detection systems face critical limitations:
* **High False Positive Rates**: Legitimate customer transactions are erroneously blocked, causing severe user friction.
* **Inability to Adapt**: Hardcoded heuristics cannot detect novel, zero-day fraud patterns or complex account-draining schemes.
* **Black-Box Opacity**: Many modern neural networks lack actionable interpretability, leaving customers confused and fraud analysts unable to justify transaction holds.

**FraudShield AI** solves these challenges by combining **Machine Learning classification trained on financial payment datasets**, **dynamic behavioral risk scoring (0–100)**, **dual-perspective SHAP feature explanations**, and **adaptive step-up email OTP authentication**.

---

## 2. Key Features & Capabilities

### 🛡️ Core Fraud & Risk Engine
* **Hybrid Risk Assessment**: Combines machine learning probability (`0.0 – 1.0`), behavioral signals (e.g. account draining ratio, destination velocity, velocity spikes), and transaction context into a standardized `0–100` risk score.
* **Multi-Tier Decision Policies**:
  * **LOW (`0 – 29`)**: Instantly approved with zero user friction.
  * **MEDIUM (`30 – 59`)**: Transaction held in pending state; step-up Email OTP challenge generated; zero balance deducted until verified.
  * **HIGH (`60 – 84`)**: High-risk trigger; step-up Email OTP required + automated security alert generated for audit.
  * **CRITICAL (`85 – 100`)**: Blocked from automatic clearance; routed to Security Operations Center (SOC) review.
* **Dual-View Explainable AI (SHAP)**:
  * **Customer-Facing View**: Jargon-free, natural-language explanation of risk factors (e.g., unusual amount compared to average balance, unfamiliar recipient).
  * **Analyst/SOC Technical View**: Interactive SHAP waterfall chart displaying exact feature values and mathematical contributions ($E[f(x)]$ vs $f(x)$).

### ⚡ UPI Payment Simulation & Banking Workflows
* **Simulated Instant UPI Transfer**:
  * Scan QR Code (auto-parses standard UPI payload: `upi://pay?pa=...&am=...`).
  * UPI ID / VPA transfers (`recipient@fraudshield` or external VPAs).
  * Mobile Number recipient lookup (`+91 98765 XXXXX`).
* **Multi-Factor Payment Security**:
  * Mandatory 4–6 digit numeric Payment PIN authorization.
  * Account lockout protection after 3 consecutive failed PIN attempts.
  * Atomic balance updates wrapped in ACID database transactions with double-debit prevention.

### 🔐 Authentication & Session Security
* **JWT Token-Based API Security**: Secure 24-hour access tokens with strict Role-Based Access Control (`USER` vs `ADMIN`).
* **Real Email Ownership Verification**: 6-digit registration verification delivered via RFC-compliant SMTP.
* **Secure Password Recovery**: Cryptographically random single-use reset tokens with SHA-256 database hashing and 15-minute expiration.
* **Protected Public Interface**: Public sign-in surfaces contain zero exposed credentials or demo autofill shortcuts.

### 📊 Security Operations Center (SOC) Dashboard
* **Real-Time SOC Case Management**: Alert lifecycle tracking (`PENDING`, `INVESTIGATING`, `CONFIRMED_FRAUD`, `FALSE_POSITIVE`, `RESOLVED`).
* **KPI Metrics & Risk Trends**: Visual charts for fraud rates, risk distribution, transaction volume, and model precision/recall.
* **Audit Trail**: Complete immutable event logging capturing actor IP, user agent, timestamp, device fingerprint, and decision rationale.

---

## 3. System Architecture

```
                                  ┌───────────────────────────────────┐
                                  │      Client (Browser / PWA)       │
                                  └─────────────────┬─────────────────┘
                                                    │ HTTPS / JSON REST
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       Flask REST Backend API                                           │
│                                                                                                        │
│  ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐   ┌─────────────────┐  │
│  │    Authentication    │   │  Transaction Engine  │   │     Risk Engine      │   │  SOC Dashboard  │  │
│  │ (JWT, Passwords, PIN)│   │ (UPI, QR, Balances)  │   │(Rules + ML + Policy) │   │ (Alerts, Audit) │  │
│  └──────────┬───────────┘   └──────────┬───────────┘   └──────────┬───────────┘   └────────┬────────┘  │
└─────────────┼──────────────────────────┼──────────────────────────┼────────────────────────┼───────────┘
              │                          │                          │                        │
              ▼                          ▼                          ▼                        ▼
┌───────────────────────────┐  ┌───────────────────┐  ┌──────────────────────────┐  ┌───────────────────┐
│     Email / SMTP Layer    │  │   SQLite / MySQL  │  │    Machine Learning      │  │  Explainable AI   │
│(TLS OTP, Password Resets) │  │(ACID Data Store)  │  │ (Tuned Random Forest/XGB)│  │ (SHAP Explainer)  │
└───────────────────────────┘  └───────────────────┘  └──────────────────────────┘  └───────────────────┘
```

---

## 4. Technology Stack

* **Backend Engine**: Python 3.11+ / 3.14, Flask, Flask-SQLAlchemy, Flask-Migrate, Flask-JWT-Extended, Flask-CORS.
* **Machine Learning**: Scikit-learn, XGBoost, Pandas, NumPy, Joblib.
* **Explainable AI**: SHAP (`TreeExplainer`).
* **Frontend Interface**: Semantic HTML5, Vanilla CSS3 (Glassmorphism design tokens), Vanilla Modern JavaScript (ES6+), Chart.js.
* **Database**: SQLite (local development & testing) / MySQL compatible.
* **Email & Telephony**: RFC-5322 SMTP Provider with TLS/SSL encryption & MSG91 SMS gateway integration.
* **Testing & QA**: Pytest, Pytest-cov (484 automated unit, integration, and security tests).

---

## 5. Repository Structure

```
Online-Payment-Fraud-Dtection-System/
├── app/
│   ├── config.py                     # Configuration loader & risk threshold definitions
│   ├── extensions.py                 # SQLAlchemy, Migrate, JWT, CORS instances
│   ├── models/                       # Database models (User, Transaction, Alert, OTP, etc.)
│   ├── providers/                    # SMTP email & SMS providers
│   ├── routes/                       # REST API blueprints (Auth, Payments, Admin, SOC)
│   ├── services/                     # Business logic, Risk Signal engine, SHAP service
│   └── utils/                        # Security middleware, rate limiters, structured logging
├── database/
│   ├── init_db.py                    # Database table initialization
│   └── seed_db.py                    # Idempotent demo and account seeding
├── docs/                             # Architecture diagrams, specifications, live runbooks
├── frontend/
│   ├── static/                       # Custom CSS design system, modular JS controllers
│   └── templates/                    # Jinja2 HTML templates (Dashboard, Payment, Login, etc.)
├── ml/
│   ├── artifacts/                    # Serialized model, preprocessor, and feature names
│   ├── feature_engineering.py        # Financial domain feature transformations
│   ├── preprocessing.py              # Data cleaning and scaling pipeline
│   ├── train.py                      # Candidate model training & evaluation
│   └── explain.py                    # SHAP explainer generator
├── tests/                            # 484 comprehensive pytest test suites
├── .env.example                      # Template for environment configuration
├── .gitignore                        # Standard rules ignoring secrets, caches, and temp files
├── requirements.txt                  # Python dependencies
├── run.py                            # Flask application entrypoint
└── README.md                         # Project documentation
```

---

## 6. Installation & Local Setup (Windows / Linux / macOS)

### Prerequisites
* **Python 3.11+** installed and added to `PATH`.
* **Git** installed on your machine.

### Step 1: Clone the Repository
```bash
git clone https://github.com/Afzal006/Online-Payment-Fraud-Dtection-System.git
cd Online-Payment-Fraud-Dtection-System
```

### Step 2: Create and Activate Virtual Environment
```bash
# Windows (PowerShell)
py -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env` and adjust settings as required:
```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

*For live email OTP delivery, set `MAIL_PROVIDER=smtp`, `MAIL_SERVER=smtp.gmail.com`, `MAIL_PORT=587`, `MAIL_USE_TLS=true`, `MAIL_USERNAME=your-email@gmail.com`, and `MAIL_PASSWORD=your-app-password`.*

### Step 5: Initialize the Database
```bash
py -c "from app import create_app; from database.init_db import init_database; init_database(create_app())"
```

---

## 7. Running the Application

Start the local Flask development server:
```bash
py run.py
```

* The application will start at **`http://127.0.0.1:5000`**.
* Open **`http://127.0.0.1:5000/login`** in any modern web browser.

---

## 8. Running the Automated Test Suite

FraudShield AI contains **484 automated unit, integration, and security tests** covering authentication, OTP generation, balance protection, ML inference, and SOC case workflows:

```bash
# Run all tests
py -m pytest -v

# Run targeted authentication & risk tests
py -m pytest tests/test_auth.py tests/test_risk_engine.py -v
```

---

## 9. Security & Governance

* **Zero Hardcoded Secrets**: All sensitive tokens, app passwords, database credentials, and secret keys are loaded exclusively from `.env`.
* **Isolated Testing**: Automated tests run against in-memory SQLite (`sqlite:///:memory:`), ensuring zero test pollution in development/production databases.
* **Cryptographic Standards**: Passwords and PINs are securely hashed using modern cryptographic algorithms (`Scrypt` / `PBKDF2`).
* **Enumeration Protection**: Forgot Password and registration endpoints return uniform timing and messages to prevent username harvesting.

---

## 10. License

This project is developed for educational, academic, and portfolio demonstration purposes. All rights reserved.
