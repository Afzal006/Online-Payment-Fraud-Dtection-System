# Software Requirements Specification (SRS)

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  
**Status**: Approved & Implemented  

---

## 1. Introduction

### 1.1 Purpose
This document provides the formal Software Requirements Specification (SRS) for **AegisGuard AI**, an enterprise-grade financial security web application designed to detect, assess, explain, and mitigate fraudulent online payment transactions in real time using machine learning, Explainable AI (SHAP), dynamic multi-factor authentication, and an administrative Security Operations Center (SOC).

### 1.2 Project Scope
AegisGuard AI ingests synthetic and real-time payment transactions derived from the PaySim benchmark dataset ($6,362,620$ rows), performs leakage-free feature engineering, executes sub-millisecond inference using a tuned Random Forest classifier ($F_1 = 0.9985$, $100\%$ precision), synthesizes explainability narratives via `shap.TreeExplainer`, applies a 3-tier adaptive security policy (LOW, MEDIUM, HIGH), and enables administrative incident resolution.

### 1.3 Definitions, Acronyms, and Abbreviations
- **AUC-ROC**: Area Under the Receiver Operating Characteristic Curve
- **DFD**: Data Flow Diagram
- **ERD**: Entity Relationship Diagram
- **JWT**: JSON Web Token
- **MFA / 2FA**: Multi-Factor Authentication
- **ML**: Machine Learning
- **OTP**: One-Time Password
- **PR-AUC**: Precision-Recall Area Under Curve
- **RBAC**: Role-Based Access Control
- **SHAP**: SHapley Additive exPlanations
- **SOC**: Security Operations Center
- **SRS**: Software Requirements Specification
- **UML**: Unified Modeling Language
- **XAI**: Explainable Artificial Intelligence

---

## 2. Overall Description

### 2.1 Product Perspective
AegisGuard AI is a standalone, client-server web application architected with a decoupled Flask REST backend, a responsive HTML5/CSS3/Vanilla JavaScript frontend, and a relational MySQL/SQLite persistence layer.

### 2.2 User Classes and Characteristics
1. **Registered Customer / Regular User (`USER`)**:
   - Authenticated account holder submitting payment transactions (`PAYMENT`, `TRANSFER`, `CASH_OUT`, `DEBIT`).
   - Receives real-time risk assessments, completes OTP challenges for medium/high-risk transactions, and reviews personal transaction history and SHAP explainability insights.
2. **Security Analyst / Administrator (`ADMIN`)**:
   - Privileged security officer with access to the SOC dashboard.
   - Monitors aggregate volume, risk distributions, temporal fraud trends, feature drift telemetry, and investigates/resolves high-risk incident alerts with audit notes.

### 2.3 Operating Environment
- **Server Runtime**: Python 3.14+ on Windows / Linux / macOS.
- **Web Server**: Flask WSGI application factory.
- **Database**: Relational DBMS (MySQL in production / SQLite for testing & development).
- **Client Runtime**: Modern web browsers supporting ECMAScript 6+ (Chrome, Firefox, Edge, Safari).

---

## 3. Specific System Requirements

### 3.1 Functional Requirements (FR)

#### Module 1: Authentication & Access Control (FR-AUTH)
- **FR-AUTH-01**: The system shall allow users to register with `name`, `email`, and `password`. The `role` shall strictly default to `USER`.
- **FR-AUTH-02**: Passwords shall be hashed using Werkzeug PBKDF2/Scrypt prior to database persistence. Plaintext passwords must never be stored.
- **FR-AUTH-03**: The system shall authenticate users via `POST /api/auth/login` and issue signed JWT access tokens.
- **FR-AUTH-04**: The system shall enforce RBAC via decorators (`@admin_required()`), returning HTTP 403 Forbidden to non-admin users attempting privileged routes.
- **FR-AUTH-05**: The system shall provide an anti-enumeration password reset request endpoint (`POST /api/auth/forgot-password`) that returns identical generic responses for existing and non-existing email addresses, throttled to a maximum of 3 requests per account per 15 minutes.
- **FR-AUTH-06**: Password reset tokens shall be single-use, 43-character cryptographically secure tokens expiring in 10 minutes, persisted exclusively as SHA-256 hashes (`password_reset_tokens.token_hash`), locked after 5 failed attempts, and invalidating all prior active tokens upon issuance or successful reset.

#### Module 2: Machine Learning Inference & Real-Time Risk Engine (FR-ML)
- **FR-ML-01**: The system shall calculate multi-window velocity metrics (1m, 10m, 1h, 24h), customer behavioral baselines (historical average/max, amount deviation ratio), and beneficiary trust scores using strict point-in-time timestamp filtering ($t < t_{\text{tx}}$) to guarantee zero future-data leakage.
- **FR-ML-02**: The inference pipeline shall exclude target labels (`isFraud`, `isFlaggedFraud`), high-cardinality IDs (`nameOrig`, `nameDest`), and raw temporal step (`step`).
- **FR-ML-03**: The packaged Random Forest model (`model.joblib`) shall output binary prediction ($0$ or $1$) and continuous calibrated fraud probability ($P(\text{fraud}) \in [0.0, 1.0]$).
- **FR-ML-04**: The system shall combine ML probabilities and structured rule signals into a transparent, bounded integer risk score $\in [0, 100]$.

#### Module 3: Explainable AI (SHAP Integration) (FR-XAI)
- **FR-XAI-01**: For every evaluated transaction, the system shall compute local SHAP feature contributions using `shap.TreeExplainer`.
- **FR-XAI-02**: Feature keys shall be mapped to human-readable financial terminology (e.g., `amount_to_oldbalance_orig_ratio` $\rightarrow$ `"Amount-to-Sender-Balance Ratio"`).
- **FR-XAI-03**: The system shall synthesize dual-view explanations: a safe customer-facing narrative without revealing internal weights or adversarial triggers, and an exhaustive technical deep-dive for SOC analysts with raw SHAP attributions and structured signal breakdown.

#### Module 4: Adaptive Multi-Factor Security & 4-Tier Decision Engine (FR-SEC)
- **FR-SEC-01**: The system shall enforce a 4-tier adaptive risk decision policy:
  - **LOW (`0 – 29`)**: `APPROVE_IMMEDIATELY`, transaction status `APPROVED`, atomically deduct ledger balance.
  - **MEDIUM (`30 – 59`)**: `APPROVE_WITH_MONITORING`, transaction status `APPROVED`, routine telemetry logging, atomically deduct ledger balance.
  - **HIGH (`60 – 79`)**: `TRIGGER_OTP_VERIFICATION`, transaction status `OTP_REQUIRED`, issue OTP challenge, create `HIGH` severity alert, hold balance undeducted until valid OTP submission.
  - **CRITICAL (`80 – 100`)**: `TRIGGER_SECURITY_REVIEW`, transaction status `UNDER_REVIEW`, issue OTP challenge, create `CRITICAL` severity incident alert, hold balance undeducted pending administrative authorization.
- **FR-SEC-02**: OTPs shall be 6-digit cryptographically secure numeric strings generated via Python `secrets`.
- **FR-SEC-03**: OTPs must be hashed in `otp_challenges.otp_hash`. Plaintext OTPs must never be stored in the database.
- **FR-SEC-04**: OTP challenges shall expire after 180 seconds and strictly enforce a maximum of 3 verification attempts.

#### Module 5: Transaction Persistence & Ledger (FR-DATA)
- **FR-DATA-01**: All evaluated transactions shall be persisted to the `transactions` table with foreign key reference to `users.id`.
- **FR-DATA-02**: Users shall be able to retrieve only their own transactions via `GET /api/transactions/my-history`. Cross-user inspection is strictly blocked (HTTP 403).

#### Module 6: Admin Security Operations Center (SOC) (FR-SOC)
- **FR-SOC-01**: Administrators shall have access to aggregated KPI metrics (`total_transactions`, `flagged_volume`, `open_alerts`, `risk_tier_counts`).
- **FR-SOC-02**: The SOC shall render interactive Chart.js visualizations for transaction volume by type, risk tier distributions, and score trends.
- **FR-SOC-03**: Administrators shall be able to inspect security alerts, view SHAP narratives, resolve alerts with investigation notes, or dismiss alerts.
- **FR-SOC-04**: The system shall calculate live feature divergence against the PaySim baseline and report data drift status (`NORMAL`, `WARNING`, `DRIFT DETECTED`).

---

### 3.2 Non-Functional Requirements (NFR)

- **NFR-PERF-01 (Inference Latency)**: End-to-end transaction prediction and SHAP explanation shall complete in $< 150$ milliseconds under standard load.
- **NFR-PERF-02 (SQL Optimization)**: Admin dashboard KPIs and analytics shall use SQL database aggregations (`COUNT`, `SUM`, `GROUP BY`) rather than full table scans.
- **NFR-SEC-01 (Zero Secret Leakage)**: Passwords, password hashes, JWT secrets, and plaintext OTPs shall never be serialized in client API responses.
- **NFR-SEC-02 (Session Security)**: JWT access tokens shall expire automatically and force client re-authentication.
- **NFR-REL-01 (Database Integrity)**: Database transactions shall utilize rollback safety upon exception to prevent orphaned or corrupted state.
- **NFR-ACC-01 (Accessibility)**: User and admin interfaces shall maintain WCAG 2.1 AA compliant contrast ratios and keyboard navigability.
