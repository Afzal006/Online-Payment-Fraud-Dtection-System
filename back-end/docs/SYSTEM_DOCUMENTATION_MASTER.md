# AegisGuard AI: Consolidated System Engineering & Viva Master Reference

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Academic / Viva Reference**: Minor Project / Capstone Engineering Defense  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  
**Verification Status**: 100% Automated Test Pass Rate (101/101 Tests Verified)  

---

## 1. Executive Summary & Problem Formulation

Financial institutions and modern payment gateways process billions of online transactions daily. Fraudulent actors continuously evolve evasion tactics, costing global financial systems over $30 billion annually. 

Traditional rule-based fraud engines suffer from:
1. **High False Positive Rates (FPR)**: Declining legitimate customers and causing user frustration.
2. **Inflexibility**: Inability to adapt to non-linear fraud vectors.
3. **The "Black-Box" Deficit**: Modern deep learning and ensemble models generate risk scores without explainability, making regulatory compliance (GDPR Article 22, Right to Explanation) and security analyst auditing nearly impossible.

**AegisGuard AI** solves these challenges by combining:
- **High-Precision ML Classification**: Tuned Random Forest ($F_1 = 0.9985$, $100\%$ precision, zero false positives in test).
- **Mathematical Explainability**: Local feature attributions via `shap.TreeExplainer` and automated natural language narrative synthesis.
- **3-Tier Adaptive Security Architecture**: Dynamic automated approvals for low risk, cryptographic OTP challenges for medium risk, and administrative incident review for high risk.
- **Enterprise Security Operations Center (SOC)**: Real-time Chart.js telemetry, alert triage with investigation notes, and statistical feature drift detection.

---

## 2. Complete Project Architecture & Phase Breakdown

| Phase | Title | Core Deliverables | Verified Test Coverage |
|---|---|---|---|
| **Phase 0** | Scaffolding & Setup | Application factory, environment configs, dataset existence tool. | 6 tests in `test_setup.py` |
| **Phase 1** | Dataset Audit & EDA | Chunked audit of $6,362,620$ PaySim records, leakage identification. | 4 tests in `test_audit.py` |
| **Phase 2** | Baseline Modeling | Feature engineering, `ColumnTransformer`, Logistic Regression, Decision Tree. | 6 in `test_feature_engineering.py`, 3 in `test_preprocessing.py`, 5 in `test_models.py` |
| **Phase 3** | Strong Model Tuning | 5-Fold Stratified CV tuning for Random Forest & XGBoost. | 5 tests in `test_strong_models.py` |
| **Phase 4** | Model Packaging | Artifact packaging (`model.joblib`), metadata registry, risk policy. | 8 tests in `test_inference.py` |
| **Phase 5** | Explainable AI (SHAP) | `shap.TreeExplainer`, financial name translation, narrative synthesis. | 7 tests in `test_shap.py` |
| **Phase 6** | Flask Backend & Auth | Modular architecture, PBKDF2/Scrypt, JWT authentication, RBAC. | 12 tests in `test_auth.py` |
| **Phase 7** | Prediction API | `POST /api/transactions/predict`, input validation, rollback safety. | 10 tests in `test_prediction_api.py` |
| **Phase 8** | Database Hardening | Alembic migrations, check constraints, composite indexes, seed script. | 7 tests in `test_database.py` |
| **Phase 9** | Adaptive Security Flow | Cryptographic OTP challenges, 180s expiry, 3-attempt ceiling, alerts. | 6 tests in `test_adaptive_security.py` |
| **Phase 10**| Frontend User Portal | Glassmorphism UI, real-time result modal, OTP modal, SHAP drawer. | 7 tests in `test_frontend.py` |
| **Phase 11**| Admin SOC Dashboard | SQL aggregations, Chart.js analytics, alert triage, drift telemetry. | 8 tests in `test_admin_soc.py` |
| **Phase 12**| E2E Testing & Edge Cases| Complete user lifecycle, boundary tests, cross-user isolation. | 7 tests in `test_e2e_system.py` |
| **Phase 13**| Formal Documentation | SRS, HLD, DFD Level 0-2, ERD, UML Diagrams, API Specs, Master Report. | Complete Documentation Suite |

---

## 3. Machine Learning & Feature Engineering Summary

### 3.1 11-Feature Domain Specification
- `errorBalanceOrig = oldbalanceOrg - newbalanceOrig - amount`
- `errorBalanceDest = oldbalanceDest + amount - newbalanceDest`
- `amount_to_oldbalance_orig_ratio = amount / (oldbalanceOrg + 1.0)`
- `amount_to_oldbalance_dest_ratio = amount / (oldbalanceDest + 1.0)`
- `hourOfDay = step % 24`
- `is_merchant_dest = (nameDest starts with 'M')`
- `amount`, `oldbalanceOrg`, `newbalanceOrig`, `oldbalanceDest`, `newbalanceDest`
- `type` (OneHotEncoded to 5 binary columns)

### 3.2 Model Performance Matrix
- **Tuned Random Forest (Approved Primary)**: Precision: $100.0\%$, Recall: $99.76\%$, $F_1$: $0.9985$, PR-AUC: $0.9995$, ROC-AUC: $0.9999$, False Positives: $0$.
- **Tuned XGBoost (Secondary Benchmark)**: Precision: $99.88\%$, Recall: $99.64\%$, $F_1$: $0.9976$, PR-AUC: $0.9991$, ROC-AUC: $0.9998$.

---

## 4. Adaptive Security Decision Matrix

$$\text{RiskScore} = \text{round}(P(\text{fraud}) \times 100) \in [0, 100]$$

| Tier | Score Range | Operational Decision | Initial Transaction Status | Security Workflow |
|---|---|---|---|---|
| **LOW** | $0 – 30$ | `APPROVE_IMMEDIATELY` | `APPROVED` | Auto-approved; transaction completed immediately. |
| **MEDIUM**| $31 – 70$ | `TRIGGER_OTP_VERIFICATION` | `OTP_REQUIRED` | Cryptographic OTP challenge issued; correct code $\rightarrow$ `APPROVED`; 3 fails $\rightarrow$ `REJECTED`. |
| **HIGH** | $71 – 100$ | `TRIGGER_OTP_ALERT_AND_REVIEW` | `UNDER_REVIEW` | Security `Alert` generated for Admin SOC; OTP verified $\rightarrow$ `VERIFIED_PENDING_REVIEW`; Admin resolution required. |

---

## 5. Security & Cryptographic Controls

1. **Zero Secret Exposure**: Passwords and OTP codes are strictly stored as PBKDF2/Scrypt cryptographic hashes (`password_hash`, `otp_hash`).
2. **Strict RBAC Enforcement**: Decorated API endpoints (`@admin_required()`) enforce role separation between `USER` and `ADMIN`.
3. **Replay & Brute-Force Defense**:
   - OTP codes expire after 180 seconds (`OTP_EXPIRY_SECONDS = 180`).
   - Maximum 3 verification attempts allowed (`OTP_MAX_ATTEMPTS = 3`).
   - Verified OTPs are immediately revoked to prevent replay attacks.
4. **Cross-Tenant Isolation**: API endpoints enforce user identity checks from the signed JWT payload, preventing user $A$ from accessing or modifying user $B$'s data ($403$ Forbidden).

---

## 6. Full Automated Test Suite Verification

Executed across all 15 test modules:
```bash
py -m pytest -v
```

```
============================== 101 passed, 3 warnings in 18.47s ==============================
```

- **Total Test Cases**: **101**
- **Passing**: **101** (100.0%)
- **Failing**: **0**
- **Skipped**: **0**
- **Test Modules**:
  1. `test_audit.py` (Dataset Audit)
  2. `test_setup.py` (App Factory & Config)
  3. `test_preprocessing.py` (Pipeline Transformations)
  4. `test_feature_engineering.py` (Mathematical Formulations)
  5. `test_models.py` (Baseline Modeling)
  6. `test_strong_models.py` (Random Forest & XGBoost Tuning)
  7. `test_inference.py` (Packaged Inference Engine)
  8. `test_shap.py` (TreeExplainer & Explainability)
  9. `test_auth.py` (PBKDF2 Hashing, JWT, & RBAC)
  10. `test_prediction_api.py` (Transaction Controller)
  11. `test_database.py` (Database Constraints & Migrations)
  12. `test_adaptive_security.py` (3-Tier Risk & OTP Challenges)
  13. `test_frontend.py` (User Portal Web Templates)
  14. `test_admin_soc.py` (Admin SOC Analytics, Alerts, & Drift)
  15. `test_e2e_system.py` (E2E Lifecycle & Boundary Edge Cases)

---

## 7. Viva Q&A Quick Reference

**Q1: Why did you choose Random Forest over XGBoost as the primary model?**  
*A*: While both models demonstrated exceptional metrics ($F_1 > 0.997$), Random Forest achieved zero false positives ($100\%$ precision) and superior test recall ($99.76\%$) on the $254,505$-row untouched test partition with stable `shap.TreeExplainer` computational performance.

**Q2: How is data leakage prevented during feature engineering?**  
*A*: Target labels (`isFraud`, `isFlaggedFraud`), high-cardinality IDs (`nameOrig`, `nameDest`), and monotonically increasing time indices (`step`) are strictly excluded from model features. All transformations are fitted exclusively on training data within a Scikit-Learn `ColumnTransformer`.

**Q3: How does the system satisfy Explainable AI (XAI) requirements?**  
*A*: For every transaction evaluated, `shap.TreeExplainer` computes local Shapley values measuring the positive and negative contribution of each feature towards the fraud score. An index translation layer converts transformed columns to financial names, and a narrative engine synthesizes human-readable risk summaries.

**Q4: How does the 3-tier adaptive security flow mitigate fraud while preserving user experience?**  
*A*: Legitimate, low-risk transactions ($0-30$) are approved instantly with zero friction. Medium-risk transactions ($31-70$) present a lightweight 2FA/OTP challenge. Only high-risk transactions ($71-100$) trigger both a challenge and an automated incident alert in the administrative SOC for manual investigation.
