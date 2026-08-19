# AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System

> Machine Learning + Explainable AI (SHAP) + Risk Scoring + Adaptive Verification

---

## 1. Project Overview & Problem Statement

Online payment systems (such as UPI, credit cards, internet banking, and mobile wallets) are increasingly targeted by fraudulent actors. Traditional static rule-based fraud detection fails against evolving fraud mechanisms and often produces excessive false positives.

This system provides an end-to-end, inspectable academic prototype that:
1. **Predicts fraud in real-time** using machine learning trained on the PaySim online payment dataset.
2. **Generates a normalized 0–100 risk score** with three decision tiers (`LOW`, `MEDIUM`, `HIGH`).
3. **Explains predictions using SHAP (Explainable AI)** to highlight which features pushed the risk up or down.
4. **Applies adaptive security actions**: Instant approval for low risk, simulated OTP challenge for medium risk, and OTP + security alert + admin review for high risk.
5. **Provides interactive dashboards**: User dashboard for payment simulation and transaction tracking; Admin dashboard for fraud analytics, model metrics, and SHAP investigation.

---

## 2. System Architecture

```
User / Admin
    │
    ▼
Frontend (HTML5, CSS3, Bootstrap 5, JavaScript, Chart.js)
    │  HTTP / REST JSON
    ▼
Flask REST API Backend (Authentication, Transactions, Predictions, OTP, Alerts, Analytics)
    │
    ├─► Data Preprocessing & Feature Engineering Pipeline (Pandas, NumPy, Scikit-learn)
    ├─► ML Inference Engine (Random Forest / XGBoost / Baselines)
    ├─► Explainable AI Engine (SHAP TreeExplainer)
    ├─► Risk Scoring & Decision Engine (0-100 Score -> LOW / MEDIUM / HIGH)
    └─► MySQL Database (Users, Transactions, Predictions, Explanations, OTP, Alerts, Audit)
```

---

## 3. Project Structure

```
online-payment-fraud-detection/
├── app/
│   ├── __init__.py                 # Application factory & extension registration
│   ├── config.py                   # Environment configuration & risk thresholds
│   ├── routes/                     # REST API & Web blueprints
│   │   ├── auth.py
│   │   ├── transactions.py
│   │   ├── predictions.py
│   │   ├── otp.py
│   │   ├── alerts.py
│   │   └── admin.py
│   ├── services/                   # Business & ML logic
│   │   ├── fraud_service.py
│   │   ├── risk_service.py
│   │   ├── shap_service.py
│   │   ├── otp_service.py
│   │   └── analytics_service.py
│   ├── models/                     # SQLAlchemy models
│   │   ├── user.py
│   │   ├── transaction.py
│   │   ├── prediction.py
│   │   ├── alert.py
│   │   └── audit.py
│   └── utils/                      # Validators & security helpers
│       ├── validators.py
│       └── security.py
├── ml/
│   ├── data_audit.py               # Dataset audit & EDA
│   ├── preprocessing.py            # Feature transformation & cleaning
│   ├── feature_engineering.py      # Engineered domain features
│   ├── train.py                    # Candidate model training & comparison
│   ├── evaluate.py                 # Precision, Recall, F1, ROC-AUC, PR-AUC
│   ├── tune.py                     # Hyperparameter tuning
│   ├── explain.py                  # SHAP explanation generation
│   ├── predict.py                  # Standalone inference runner
│   ├── artifacts/                  # Serialized model & preprocessor artifacts
│   └── notebooks/                  # EDA & experiment notebooks
├── frontend/
│   ├── templates/                  # Jinja2 HTML templates
│   └── static/                     # CSS, JavaScript, and images
├── dataset/                        # PaySim dataset files
├── database/                       # SQL schema and seed scripts
├── tests/                          # Automated test suite (pytest)
├── docs/                           # Documentation (SRS, HLD, DFD, ERD)
├── .env.example                    # Environment variable template
├── .gitignore                      # Git ignore patterns
├── requirements.txt                # Python dependencies
├── run.py                          # Flask entrypoint
└── README.md                       # Master documentation
```

---

## 4. Feature Specification & Engineering

The model uses the PaySim dataset with exact engineered features:

| Feature | Type | Source / Formula | Meaning |
|---|---|---|---|
| `type` | Categorical | Raw (`CASH_OUT`, `TRANSFER`, `PAYMENT`, `CASH_IN`, `DEBIT`) | Payment mechanism |
| `amount` | Float | Raw | Transaction amount |
| `oldbalanceOrg` | Float | Raw | Sender initial balance |
| `newbalanceOrig` | Float | Raw | Sender balance after transaction |
| `oldbalanceDest` | Float | Raw | Receiver initial balance |
| `newbalanceDest` | Float | Raw | Receiver balance after transaction |
| `errorBalanceOrig` | Float | `oldbalanceOrg - amount - newbalanceOrig` | Sender balance discrepancy |
| `errorBalanceDest` | Float | `oldbalanceDest + amount - newbalanceDest` | Receiver balance discrepancy |
| `hourOfDay` | Integer | `step % 24` | 24-hour cycle time bucket |
| `isMerchantDest` | Binary | `1 if nameDest starts with "M" else 0` | Merchant vs customer destination |
| `amountToBalanceRatio` | Float | `amount / (oldbalanceOrg + 1)` | Account draining ratio |

---

## 5. Risk Scoring & Decision Policy

- **Risk Score Formula**: `risk_score = round(fraud_probability * 100)`
- **Decision Engine Matrix**:
  - `0 – 30` (**LOW**): Transaction approved immediately.
  - `31 – 70` (**MEDIUM**): Adaptive challenge triggered; simulated OTP verification required.
  - `71 – 100` (**HIGH**): High-risk flag; simulated OTP verification + security alert generated + flagged for Admin review.

---

## 6. Installation & Quickstart

```bash
# 1. Clone repository and navigate to folder
cd "Online Payment fraud detection system"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env

# 4. Run tests
pytest

# 5. Run Flask application
python run.py
```

---

## 7. Build Sequence

- **Phase 0**: Project setup & scaffold *(Completed)*
- **Phase 1**: Dataset audit & EDA
- **Phase 2**: ML baseline modeling (Logistic Regression & Decision Tree)
- **Phase 3**: Strong models (Random Forest & XGBoost) + Comparison
- **Phase 4**: Model packaging & pipeline persistence
- **Phase 5**: Explainable AI (SHAP TreeExplainer integration)
- **Phase 6**: Flask application factory & database connection
- **Phase 7**: Prediction & Risk Scoring API
- **Phase 8**: MySQL schema & persistence models
- **Phase 9**: Adaptive Security Flow (OTP, Alerts & Audit logs)
- **Phase 10**: User Frontend (Payment, History, Dashboard)
- **Phase 11**: Admin Frontend & Analytics Dashboards (Chart.js)
- **Phase 12**: Comprehensive Unit, Integration & Security Testing
- **Phase 13**: Formal Documentation (SRS, HLD, DFD, ERD, API Docs)
- **Phase 14**: Demo Hardening & Viva Preparation
