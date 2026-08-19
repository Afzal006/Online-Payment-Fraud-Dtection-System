# Complete REST API Specification

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: FraudShield AI (Internal Payment Platform & Admin SOC Center)  
**Document Version**: 4.0.0 (Phase 2: Real-Time 4-Tier Fraud Risk Engine Upgrade)  
**Date**: 2026-08-19  

---

## 1. Authentication & Common Headers

All protected endpoints require a signed JSON Web Token (JWT) provided in the standard `Authorization` header:

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

### Standard Error Response Schema
```json
{
  "error": "Detailed error message",
  "code": "ERROR_CODE_IDENTIFIER"
}
```

---

## 2. Authentication & Profile Endpoints

### 2.1 User Registration
- **Route**: `POST /api/auth/register`
- **Access**: Public
- **Request Body**:
```json
{
  "name": "Arjun Sharma",
  "email": "arjun@example.com",
  "password": "SecurePassword123!",
  "role": "USER"
}
```
- **Response (`201 Created`)**:
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "name": "Arjun Sharma",
    "email": "arjun@example.com",
    "role": "USER",
    "customer_account_id": "FS-100001",
    "primary_upi_id": "arjun@fraudshield",
    "phone_number": null,
    "account_balance": 100000.0,
    "is_phone_verified": false,
    "beneficiary_count": 0,
    "created_at": "2026-08-19T10:00:00"
  }
}
```

### 2.2 User Login
- **Route**: `POST /api/auth/login`
- **Access**: Public
- **Request Body**:
```json
{
  "email": "arjun@example.com",
  "password": "SecurePassword123!"
}
```
- **Response (`200 OK`)**:
```json
{
  "message": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "redirect_url": "/dashboard",
  "user": {
    "id": 1,
    "name": "Arjun Sharma",
    "email": "arjun@example.com",
    "role": "USER",
    "customer_account_id": "FS-100001",
    "primary_upi_id": "arjun@fraudshield",
    "account_balance": 150000.0
  }
}
```

### 2.3 Forgot Password (Anti-Enumeration Request)
- **Route**: `POST /api/auth/forgot-password`
- **Access**: Public (Rate limited: max 3 requests per account per 15 minutes)
- **Request Body**:
```json
{
  "email": "arjun@example.com"
}
```
- **Response (`200 OK`)**:
```json
{
  "message": "If an account exists for this email, a password reset code has been sent."
}
```
*Note: In development demo mode (`PASSWORD_RESET_DEV_MODE=True`), `dev_reset_token` is also included for testing convenience.*

### 2.4 Reset Password (Token Verification & Update)
- **Route**: `POST /api/auth/reset-password`
- **Access**: Public (Locked after 5 failed token verification attempts)
- **Request Body**:
```json
{
  "token": "43-character-cryptographic-urlsafe-token",
  "new_password": "NewSecurePassword123!",
  "confirm_password": "NewSecurePassword123!"
}
```
- **Response (`200 OK`)**:
```json
{
  "message": "Password has been reset successfully. You may now sign in with your new password."
}
```
- **Error Responses**:
  - `400 Bad Request`: Token expired, token already used, password mismatch, or weak password (<8 characters).
  - `429 Too Many Requests`: Token locked after 5 failed verification attempts.

---

## 3. Beneficiary Management Endpoints (Tenant-Isolated CRUD)

### 3.1 List Saved Beneficiaries
- **Route**: `GET /api/beneficiaries`
- **Access**: Authenticated Customer
- **Response (`200 OK`)**:
```json
{
  "success": true,
  "total": 2,
  "beneficiaries": [
    {
      "id": 1,
      "beneficiary_name": "Priya Patel",
      "beneficiary_upi_id": "priya@fraudshield",
      "beneficiary_phone": "+91 98765 43211",
      "nickname": "Sister",
      "is_verified": true,
      "status": "ACTIVE",
      "created_at": "2026-08-19T10:00:00",
      "last_used_at": "2026-08-19T11:15:00"
    }
  ]
}
```

### 3.2 Add Beneficiary
- **Route**: `POST /api/beneficiaries`
- **Access**: Authenticated Customer

### 3.3 Get / Update / Delete Beneficiary
- **Routes**: `GET /api/beneficiaries/<id>`, `PUT /api/beneficiaries/<id>`, `DELETE /api/beneficiaries/<id>`
- **Access**: Authenticated Owner (Strict IDOR checks enforced)

---

## 4. Real-Time Transaction & 4-Tier Fraud Risk Engine Endpoints

### 4.1 Submit & Assess Transaction
- **Route**: `POST /api/transactions/predict`
- **Access**: Authenticated Customer
- **Request Body**:
```json
{
  "type": "TRANSFER",
  "amount": 92000.00,
  "beneficiary_id": 1,
  "payment_note": "Advance payment"
}
```
- **Response (`200 OK` - Elevated Risk Flow)**:
```json
{
  "success": true,
  "transaction_id": 108,
  "prediction": 0,
  "predicted_class_name": "Legitimate",
  "fraud_probability": 0.045,
  "legitimate_probability": 0.955,
  "ml_score": 5,
  "signals_score": 60,
  "risk_score": 65,
  "risk_level": "HIGH",
  "decision": "TRIGGER_OTP_VERIFICATION",
  "status": "OTP_REQUIRED",
  "requires_otp": true,
  "account_balance": 150000.0,
  "balance_before": 150000.0,
  "balance_after": 150000.0,
  "beneficiary_id": 1,
  "destination_upi_id": "priya@fraudshield",
  "destination_name": "Priya Patel",
  "structured_signals": [
    {
      "code": "SIG_AMT_SIGNIFICANT",
      "severity": "MEDIUM",
      "message": "Transaction amount (₹92,000.00) is in significant risk range (>₹50,000).",
      "weight": 25
    },
    {
      "code": "SIG_DEV_ELEVATED",
      "severity": "HIGH",
      "message": "Amount is 3.5x customer historical average.",
      "weight": 20
    }
  ],
  "customer_explanation": {
    "summary": "Transfer requires verification to protect full account balance. High-value payment requires additional security authorization.",
    "top_reasons": [
      "Transaction amount (₹92,000.00) is in significant risk range (>₹50,000).",
      "Amount is 3.5x customer historical average."
    ]
  },
  "explanation": {
    "top_features": [ ... ],
    "human_readable_summary": "Transfer requires verification to protect full account balance."
  },
  "model_version": "1.0.0"
}
```

### 4-Tier Adaptive Security Matrix:
| Tier | Score Range | Engine Action | Initial State | Balance Action | SOC Alert Generated |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`LOW`** | 0 – 29 | `APPROVE_IMMEDIATELY` | `APPROVED` | Deducted immediately | No |
| **`MEDIUM`** | 30 – 59 | `APPROVE_WITH_MONITORING` | `APPROVED` | Deducted immediately | No (Telemetry logged) |
| **`HIGH`** | 60 – 79 | `TRIGGER_OTP_VERIFICATION` | `OTP_REQUIRED` | Held (undeducted) | Yes (`HIGH` severity) |
| **`CRITICAL`** | 80 – 100 | `TRIGGER_SECURITY_REVIEW` | `UNDER_REVIEW` | Held (undeducted) | Yes (`CRITICAL` severity) |

---

## 5. Adaptive Security & OTP Challenge Endpoints

### 5.1 Generate OTP Challenge
- **Route**: `POST /api/otp/generate`
- **Access**: Authenticated Customer

### 5.2 Verify OTP Code & Atomic Ledger Deduction
- **Route**: `POST /api/otp/verify`
- **Access**: Authenticated Customer
- **Request Body**:
```json
{
  "transaction_id": 108,
  "otp_code": "492817"
}
```
- **Response (`200 OK`)**:
```json
{
  "success": true,
  "message": "OTP verified successfully. Transaction approved.",
  "transaction": {
    "id": 108,
    "status": "APPROVED",
    "balance_before": 150000.0,
    "balance_after": 58000.0,
    "risk_level": "MEDIUM",
    "risk_score": 65
  }
}
```

---

## 6. Admin SOC Endpoints (Global Customer Telemetry)

### 6.1 List All Registered Customers
- **Route**: `GET /api/admin/customers?search=priya&sort_by=newest&limit=100`
- **Access**: `ADMIN` Role Required
- **Response (`200 OK`)**:
```json
{
  "success": true,
  "total": 1,
  "customers": [
    {
      "id": 2,
      "name": "Priya Patel",
      "email": "priya@example.com",
      "customer_account_id": "FS-100002",
      "primary_upi_id": "priya@fraudshield",
      "phone_number": "+91 98765 43211",
      "account_balance": 85400.0,
      "beneficiary_count": 2,
      "transaction_count": 4,
      "total_volume": 12850.0,
      "high_risk_count": 0,
      "open_alert_count": 0,
      "is_active": true
    }
  ]
}
```

### 6.2 Customer Deep-Dive Profile & Beneficiary Trust Graph
- **Route**: `GET /api/admin/customers/<id>`
- **Access**: `ADMIN` Role Required
- **Response (`200 OK`)**: Returns customer profile, list of saved beneficiaries, aggregated transaction volume metrics, open alerts count, and complete chronological transaction history.
