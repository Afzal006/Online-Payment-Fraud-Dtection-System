# Project Presentation Script, Final Checklist & Feature Classification

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  

---

## 1. 5–10 Minute Spoken Presentation & Demonstration Script

*Use this script word-for-word or as a guide during your final year project presentation / viva defense.*

---

### [0:00 – 1:30] Introduction & Problem Formulation
> *"Good morning, respected examiners and faculty members. Today, I am presenting **AegisGuard AI**, an AI-powered real-time online payment fraud detection and explainable risk assessment system.*
>
> *Online financial transactions are expanding rapidly, but financial fraud costs institutions billions of dollars annually. Traditional fraud systems rely on static, rule-based thresholds that produce high false-positive rates, frustrating legitimate customers. On the other hand, modern machine learning models often act as 'black boxes'—they give a fraud score, but neither the bank nor the customer knows **why** a payment was flagged, violating regulatory compliance such as GDPR's Right to Explanation.*
>
> *To solve this, AegisGuard AI combines high-precision machine learning, mathematical Explainable AI using SHAP, an adaptive 3-tier multi-factor security flow, and an enterprise Security Operations Center."*

---

### [1:30 – 3:30] Dataset, ML Pipeline & Explainable AI (SHAP)
> *"Our machine learning subsystem was trained on the PaySim benchmark dataset containing over 6.36 million transactions with an extreme class imbalance of 774 to 1.*
>
> *To eliminate data leakage, we strictly excluded target labels, high-cardinality identifiers, and raw timestamps. We engineered 11 domain-specific financial features, including balance discrepancy tracking, account depletion ratios, and cyclic temporal hours.*
>
> *Using 5-fold stratified cross-validation on 1 million records, we evaluated multiple models. Our tuned Random Forest model achieved a 99.85% F1-score, 99.76% recall, and 100% precision with zero false positives on the untouched test partition, outperforming baseline models and our secondary XGBoost benchmark.*
>
> *For explainability, we integrated `shap.TreeExplainer`. For every single transaction, the system computes exact game-theoretic Shapley values, translates technical feature indices into human-readable financial terminology, and synthesizes an automated natural language narrative explaining why a payment was flagged."*

---

### [3:30 – 6:00] Live Demonstration Walkthrough
*(Switch screen to the live web browser at `http://127.0.0.1:5000`)*

> *"Let us look at the live application in action.*
>
> **1. Low-Risk Legitimate Payment**:
> *First, I will submit a standard $45.50 merchant payment. Notice that the system evaluates it in under 50 milliseconds, assigns a risk score of 4 out of 100, and immediately approves it with zero customer friction.*
>
> **2. Medium-Risk Transaction with Step-Up OTP**:
> *Next, I will submit a $5,000 transfer. The risk score rises to 52 (Medium Risk). In response, our adaptive security engine challenges the user with a 6-digit cryptographic OTP token. The token expires in 180 seconds and limits attempts to 3. Upon correct entry, the transaction is verified and approved.*
>
> **3. High-Risk Account Draining Transfer & SHAP Explainability**:
> *Now, I will simulate an account-draining wire transfer of $750,000. The model detects suspicious balance depletion and outputs a risk score of 95 (High Risk). Notice the red critical alert modal.*
>
> *If I click 'Why was this flagged?', our slide-out SHAP drawer displays the exact factors: the high balance depletion ratio contributed +0.38 to the fraud score, and the wire transfer type added +0.28, accompanied by a clear natural language explanation.*
>
> *This transaction is placed under review and automatically creates an incident alert in the Security Operations Center."*

---

### [6:00 – 8:00] Security Operations Center (SOC) & Model Governance
*(Log out and log in as `admin@aegisguard.com`)*

> *"Now, let us switch to the Administrator's perspective.*
>
> *Our Security Operations Center (SOC) dashboard is protected by server-side Role-Based Access Control (RBAC). It aggregates millions of dollars in volume using optimized SQL aggregation queries (`COUNT`, `SUM`, `GROUP BY`) rather than heavy table scans.*
>
> *Here, the security team can observe:
> 1. Live Chart.js telemetry showing transaction volumes and risk breakdowns.
> 2. An Alert Triage Center where analysts can inspect our flagged $750,000 transfer, examine the SHAP feature contributions, and resolve the alert with audit notes.
> 3. Real-time Feature Drift Telemetry, which continuously tracks statistical divergence between live transaction distributions and the training baseline."*

---

### [8:00 – 9:00] Conclusion & Test Verification
> *"In conclusion, AegisGuard AI provides a complete, robust, and explainable fraud detection solution. The entire system is validated by an automated test suite of 101 tests across 15 modules with a 100% pass rate.*
>
> *Thank you, and I am now ready to answer any questions."*

---

## 2. Final Project Readiness Checklist

| Component | Item Verified | Status |
|---|---|---|
| **Software Runtime** | Python 3.14.3, Flask 3.0+, Pytest 9.1+ | **VERIFIED** |
| **Dependencies** | All packages in `requirements.txt` installed & verified | **VERIFIED** |
| **Dataset** | PaySim dataset validated via `ml/check_dataset.py` & `ml/data_audit.py` | **VERIFIED** |
| **Model Artifacts** | `model.joblib`, `preprocessor.joblib`, `model_metadata.json`, `risk_policy.json` | **VERIFIED** |
| **Database** | SQLite / MySQL schemas, Alembic migrations, indexes, seed utility (`database/seed_db.py`) | **VERIFIED** |
| **Authentication** | PBKDF2 password hashing, JWT token issuance, RBAC decorators | **VERIFIED** |
| **ML & XAI Engine** | Random Forest inference singleton, `shap.TreeExplainer`, natural language synthesis | **VERIFIED** |
| **Security Layer** | 3-tier risk engine, cryptographic OTP challenge, 180s timeout, attempt rate limits | **VERIFIED** |
| **Frontend Portal** | Customer dashboard, payment simulator, OTP modal, SHAP drawer, ledger | **VERIFIED** |
| **Admin SOC** | Chart.js analytics, alert triage with notes, global ledger, drift telemetry | **VERIFIED** |
| **Automated Tests** | 101 automated tests across 15 test suites with 100% pass rate | **VERIFIED** |
| **Documentation** | SRS, HLD, DFDs, ERD, UMLs, API Reference, ML Report, Master Report | **VERIFIED** |

---

## 3. Clear Classification of System Features

### A. Fully Implemented Features
1. **Machine Learning Pipeline**: Complete end-to-end training, 11-feature engineering, stratified cross-validation, hyperparameter tuning, model packaging, and singleton inference.
2. **Explainable AI (SHAP)**: Local Shapley value calculation via `TreeExplainer`, index-to-financial-feature mapping, and natural language narrative synthesis.
3. **Adaptive 3-Tier Security Policy**: Dynamic risk scoring ($0-100$) with routing to `LOW`, `MEDIUM`, and `HIGH` tiers.
4. **Multi-Factor OTP Engine**: Cryptographic random token generation via Python `secrets`, PBKDF2 token hashing, 180-second TTL countdown, and strict 3-attempt ceiling.
5. **Database & Schema Integrity**: Normalized schema (`users`, `transactions`, `alerts`, `otp_challenges`) with check constraints, foreign keys, compound indexes, and ACID transaction rollback safety.
6. **Authentication & Authorization**: PBKDF2 password hashing, stateless JWT authorization, and server-side RBAC (`@admin_required()`).
7. **Customer User Portal**: Responsive glassmorphism interface, transaction submission with preset scenarios, interactive risk modal, slide-out SHAP drawer, and personal transaction ledger.
8. **Admin Security Operations Center (SOC)**: SQL-aggregated KPI counters, Chart.js visual analytics, incident alert triage with investigation notes, global ledger auditing, and statistical feature drift telemetry.

### B. Simulated Features (For Academic / Offline Defense)
- **OTP Delivery Channel**: To ensure the project runs reliably in an academic or offline viva environment without incurring recurring costs or relying on external telecom networks, OTP codes are logged to the backend console and provided via a simulated developer banner rather than via paid external SMS/Email APIs (e.g. Twilio / SendGrid).

### C. Future Enhancements (Production Roadmap)
- **Streaming Data Ingestion**: Integration with Apache Kafka / Apache Flink for real-time high-throughput message streaming ($100,000+\text{ TPS}$).
- **Continuous Online Retraining**: Automated retraining pipeline triggered when statistical drift scores exceed threshold.
- **Multimodal Biometric Telemetry**: Device fingerprinting, IP reputation scoring, and mouse/keystroke behavioral biometrics.
