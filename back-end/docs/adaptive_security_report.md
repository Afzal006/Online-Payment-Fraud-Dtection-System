# Adaptive Security Flow (OTP & Alert Workflow) Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Phase**: Phase 9 — Adaptive Security Flow (OTP Verification & Alert Workflow)  
**Security Mechanism**: 3-Tier Dynamic Decision Engine, Cryptographic OTP Hashing, Rate-Limiting, Admin Incident Resolution  
**Report Date**: 2026-08-18  

---

## 1. Three-Tier Adaptive Security Architecture

The system enforces a tiered operational response tailored to transaction risk:

```
Incoming Transaction
        │
        ▼
[ML Inference + SHAP Engine]
        │
        ▼
   Risk Score (0 – 100)
        │
        ├──► [0 – 30] LOW RISK:
        │       • Decision: APPROVE_IMMEDIATELY
        │       • Transaction Status: APPROVED
        │       • No challenge required
        │
        ├──► [31 – 70] MEDIUM RISK:
        │       • Decision: TRIGGER_OTP_VERIFICATION
        │       • Transaction Status: OTP_REQUIRED
        │       • Cryptographic OTP challenge generated
        │       • Verification:
        │           - Correct OTP   ──► APPROVED
        │           - Failed / Exp  ──► REJECTED
        │
        └──► [71 – 100] HIGH RISK:
                • Decision: TRIGGER_OTP_ALERT_AND_REVIEW
                • Transaction Status: UNDER_REVIEW
                • Generates security Alert record for Admin
                • Requires simulated OTP verification
                • Verification:
                    - Correct OTP   ──► VERIFIED_PENDING_REVIEW
                    - Admin Decision──► APPROVED or DISMISSED
```

---

## 2. Decision Policy & State Progression Matrix

| Risk Tier | Score Band | Operational Action | Initial Tx State | Post-OTP State | Security Alert Generated? |
|---|---|---|---|---|---|
| **LOW** | `0 – 30` | `APPROVE_IMMEDIATELY` | `APPROVED` | N/A | No |
| **MEDIUM** | `31 – 70` | `TRIGGER_OTP_VERIFICATION` | `OTP_REQUIRED` | `APPROVED` (if valid) / `REJECTED` (if exhausted) | No |
| **HIGH** | `71 – 100` | `TRIGGER_OTP_ALERT_AND_REVIEW` | `UNDER_REVIEW` | `VERIFIED_PENDING_REVIEW` (Awaiting Admin) | **Yes** (`severity = HIGH`) |

---

## 3. Cryptographic OTP Challenge Lifecycle & Security

1. **Generation**:
   - Built using Python's standard `secrets.randbelow()` module for cryptographically secure pseudo-random number generation.
   - Generates a 6-digit numeric token.
2. **Password-Grade Storage (Zero Plaintext)**:
   - Plaintext OTPs are **never stored in the database**.
   - Hashed using Werkzeug PBKDF2/Scrypt (`otp_challenges.otp_hash`).
3. **Expiration & Attempt Controls**:
   - Challenges expire automatically after **180 seconds** (`OTP_EXPIRY_SECONDS`).
   - Strict maximum limit of **3 verification attempts** (`OTP_MAX_ATTEMPTS`).
   - If 3 incorrect attempts occur, challenge status becomes `EXHAUSTED` and the transaction status transitions to `REJECTED`.
4. **Anti-Replay & Invalidation**:
   - Verified challenges immediately transition to `VERIFIED` and cannot be reused.
   - Requesting a new OTP for the same transaction invalidates previous active challenges.
5. **Simulated Delivery vs Production Separation**:
   - For local development and demonstration, the OTP is emitted through secure application logging (`[SIMULATOR]`).
   - The production API response suppresses the code, returning only delivery status and expiry countdown.

---

## 4. API Endpoints Specification

### A. `POST /api/otp/generate`
- **Auth**: `Bearer <JWT>`
- **Request Body**:
```json
{
  "transaction_id": 104
}
```
- **Response (`200 OK`)**:
```json
{
  "success": true,
  "transaction_id": 104,
  "message": "OTP verification code sent via simulated secure delivery channel",
  "expires_in_seconds": 180
}
```

### B. `POST /api/otp/verify`
- **Auth**: `Bearer <JWT>`
- **Request Body**:
```json
{
  "transaction_id": 104,
  "otp_code": "492817"
}
```
- **Response (`200 OK`)**:
```json
{
  "success": true,
  "message": "OTP verified successfully. Transaction approved.",
  "transaction": {
    "id": 104,
    "status": "APPROVED",
    "risk_level": "MEDIUM",
    "risk_score": 52
  }
}
```

### C. `GET /api/admin/alerts`
- **Auth**: `ADMIN` Role Required
- **Response (`200 OK`)**: Returns collection of open/resolved security alerts with transaction metadata and SHAP narrative.

### D. `POST /api/admin/alerts/<id>/resolve`
- **Auth**: `ADMIN` Role Required
- **Response (`200 OK`)**: Marks alert as `RESOLVED`.

---

## 5. Test Suite Execution & Results

Executed:
```bash
py -m pytest -v
```

**Coverage Summary**:
- **Risk Service Boundaries**: Explicit validation for scores $0, 30, 31, 70, 71, 100$.
- **Auto-Approval**: Confirmed LOW risk transactions require no OTP and commit as `APPROVED`.
- **OTP Challenge Flow**: Valid code verification, wrong code retry feedback, attempt exhaustion ($3$ failures $\rightarrow$ `REJECTED`), expiration timeout rejection ($410$), anti-reuse protection.
- **Cross-User Isolation**: Confirmed users cannot generate or verify OTPs for transactions owned by other accounts ($403$).
- **Admin Alert Workflow**: Confirmed high-risk transactions generate `Alert` records, accessible exclusively to `ADMIN` accounts, and resolvable.
"""

    report_path = DOCS_DIR / "adaptive_security_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Saved adaptive security report to: {report_path}")


if __name__ == "__main__":
    pass
