# Prediction API & Transaction Controller Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Phase**: Phase 7 — Prediction API & Transaction Controller  
**Endpoint**: `POST /api/transactions/predict`  
**Security**: JWT Bearer Authentication, Input Sanitization, Role-Based Access Control (RBAC)  
**Integrated Engines**: Packaged Random Forest Pipeline (`v1.0.0`), `shap.TreeExplainer` Explainability Service, MySQL Database Persistence  
**Report Date**: 2026-08-18  

---

## 1. Prediction API Architecture & Request Flow

```
Incoming Client Request (POST /api/transactions/predict)
       │
       ▼
[1. JWT Authentication] ─────► Verify Authorization: Bearer <token> & resolve user_id
       │
       ▼
[2. Input Validation] ───────► Validate amount > 0, supported type, recipient format
       │
       ▼
[3. Feature Derivation] ─────► Separate User Inputs vs System-Derived Features:
       │                       - Current hour / diurnal step
       │                       - Sender & receiver balance tracking
       │                       - Vectorized feature engineering (discrepancies, ratios)
       │
       ▼
[4. Model Inference] ────────► ML Pipeline (model.joblib) -> fraud_probability in [0, 1]
       │
       ▼
[5. SHAP Explainability] ────► TreeExplainer computes exact local Shapley attributions
       │                       - Identifies top positive & negative risk drivers
       │                       - Synthesizes grounded natural language summary
       │
       ▼
[6. Risk Policy Decision] ───► Calculates risk_score = round(fraud_prob * 100)
       │                       - LOW (0-30): APPROVED / APPROVE_IMMEDIATELY
       │                       - MEDIUM (31-70): PENDING_OTP / TRIGGER_OTP_VERIFICATION
       │                       - HIGH (71-100): FLAGGED / TRIGGER_OTP_ALERT_AND_REVIEW
       │
       ▼
[7. DB Persistence] ─────────► Transaction record committed to database
       │                       - High-risk transactions trigger Alert record
       ▼
JSON API Response (200 OK)
```

---

## 2. API Contract Specification

### `POST /api/transactions/predict`

#### Authentication
- **Header**: `Authorization: Bearer <JWT_ACCESS_TOKEN>`

#### Request Schema
```json
{
  "amount": 750000.00,
  "type": "TRANSFER",
  "destination": "C554433",
  "oldbalance_org": 750000.00,
  "newbalance_orig": 0.00,
  "oldbalance_dest": 0.00,
  "newbalance_dest": 0.00
}
```

*Note*: If balance fields (`oldbalance_org`, `newbalance_orig`, etc.) are omitted by a standard user UI, the service automatically derives them from the user's account state and system clock.

#### Response Schema (`200 OK`)
```json
{
  "success": true,
  "transaction_id": 104,
  "prediction": 1,
  "predicted_class_name": "Fraudulent",
  "fraud_probability": 0.9999,
  "legitimate_probability": 0.0001,
  "risk_score": 100,
  "risk_level": "HIGH",
  "decision": "TRIGGER_OTP_ALERT_AND_REVIEW",
  "status": "FLAGGED",
  "requires_otp": true,
  "explanation": {
    "top_features": [
      {
        "feature": "num__errorBalanceOrig",
        "display_name": "Sender Balance Discrepancy",
        "value": 0.0,
        "shap_value": 0.1541,
        "direction": "increases_risk"
      },
      {
        "feature": "num__amountToBalanceRatio",
        "display_name": "Amount-to-Balance Ratio",
        "value": 0.9999,
        "shap_value": 0.1420,
        "direction": "increases_risk"
      },
      {
        "feature": "cat__type_TRANSFER",
        "display_name": "Transaction Type (TRANSFER)",
        "value": 1.0,
        "shap_value": 0.1105,
        "direction": "increases_risk"
      }
    ],
    "positive_risk_factors": [ ... ],
    "negative_risk_factors": [ ... ],
    "human_readable_summary": "Flagged as HIGH RISK mainly due to draining a large proportion (99%) of the sender's total balance and the high-risk transaction mechanism (TRANSFER)."
  },
  "model_version": "1.0.0"
}
```

---

## 3. Supplementary Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/transactions/my-history` | `GET` | `Bearer JWT` | Returns list of recent transactions for the authenticated user (`200 OK`). |
| `/api/transactions/<id>` | `GET` | `Bearer JWT` | Returns details and full SHAP explanation of a specific transaction (`200 OK`, `403 Forbidden` if not owner/admin). |

---

## 4. Input Validation & Security Safeguards

1. **User Input vs System Features Separation**:
   - The user supplies financial intent (`amount`, `type`, `destination`).
   - The backend derives temporal parameters, balance discrepancies, merchant indicators, and ratio features to prevent client-side manipulation.
2. **Transaction Rollback Safety**:
   - If an unexpected error occurs during inference or explainability calculations, `db.session.rollback()` is invoked to prevent corrupted or half-written records.
3. **Information Disclosure Prevention**:
   - Internal stack traces, raw model weights, and database credentials are fully shielded from API consumers.

---

## 5. Test Suite Execution & Results

Executed:
```bash
py -m pytest -v
```

**Coverage Summary**:
- **Authentication**: Unauthenticated request rejected (401), invalid JWT rejected (422), authenticated requests processed.
- **Validation**: Missing amount (400), zero/negative amount (400), invalid type (400), missing destination (400).
- **ML & Risk Policy**: Real-time probability estimation, score bounding ($0\dots100$), decision tier mapping.
- **SHAP Engine**: Local attributions, feature display name translation, zero leakage check (`isFraud`, `nameOrig`, etc. verified absent).
- **Persistence**: Transaction committed with correct `user_id`, `Alert` generated for high-risk transactions, history and detail endpoints verified.
"""

    report_path = DOCS_DIR / "prediction_api_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Saved prediction API report to: {report_path}")


if __name__ == "__main__":
    pass
