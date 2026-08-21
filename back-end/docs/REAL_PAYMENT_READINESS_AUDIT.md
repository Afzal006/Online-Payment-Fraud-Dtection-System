# FraudShield AI — Real Payment Readiness Architectural Audit
**Document Version:** 1.0.0  
**Audit Date:** August 2026  
**System Classification:** UPI-Style Digital Payment Application + AI Real-Time Fraud Prevention Engine  
**Baseline Git Checkpoint:** `e293d0be91ce114f106db0f848f52d92403a2f80`  

---

## 1. Executive Summary

FraudShield AI combines a high-speed machine learning and rule-based fraud prevention engine with a consumer-facing digital payment interface. This audit assesses the readiness of the application for production-grade, genuine UPI payment workflows and identifies all mocks, demo fallbacks, hardcoded artifacts, and security gaps across the full stack.

---

## 2. Current Functionality

The following components are fully functional and tested (303/303 automated tests passing):
- **Machine Learning & Hybrid Risk Engine**: XGBoost & LightGBM inference, feature engineering pipelines, 4-tier risk decision policy (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and calibrated probabilities.
- **Explainable AI (SHAP)**: TreeSHAP-based customer summaries and admin SOC deep-dive waterfalls.
- **Device Intelligence**: Client telemetry collection, SHA-256 fingerprinting, trust score calculation, and authoritative device blocking.
- **Geo Intelligence**: Haversine distance calculations, impossible-travel velocity thresholds (>900 km/h), intra-city jitter filtering, and abnormal baseline detection.
- **Beneficiary Intelligence**: 24-hour cooling period enforcement, trust progression (`NEW` $\rightarrow$ `ESTABLISHED` $\rightarrow$ `TRUSTED`), and revocation controls.
- **SOC Case Management & Alert Lifecycle**: Multi-stage state machine (`OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, `ESCALATED`), forensic evidence snapshots, analyst notes, and metrics summary.
- **Transaction Idempotency & Atomic Ledger**: Strict balance protection, duplicate prevention via `idempotency_key`, and atomic bi-directional fund transfers (`Sender -= Amount`, `Recipient += Amount`).

---

## 3. Identification of Fake, Demo, and Mock Functionality

| Subsystem | File / Location | Current Fake / Mock Behavior | Production Target |
| :--- | :--- | :--- | :--- |
| **Mobile Verification** | `app/services/auth_service.py` & `app/models/user.py` | `is_phone_verified=True` is assigned by default at registration with zero OTP challenge. No phone number is required on `/register`. | Mandatory Indian +91 mobile number validation, cryptographically secure OTP generation, hashed storage, SMS provider dispatch, and verification before account activation. |
| **QR Code Scanner** | `frontend/templates/payment.html` & `payment.js` | Text input box to paste QR URI string with static demo preset buttons. No real camera access. | Real browser camera access using `navigator.mediaDevices.getUserMedia()`, continuous frame decoding via `BarcodeDetector` / `jsQR`, and real QR file upload decoding fallback. |
| **Forgot Password** | `frontend/templates/forgot_password.html` & `app/routes/auth_routes.py` | UI displayed a `[Demo Mode Token]` banner containing raw token on the screen to skip real email verification. | Complete elimination of demo token banners. Clean abstraction via `EmailProvider` (Development console log / Production SMTP/SendGrid). |
| **UPI Payee Resolution** | `app/services/payment_service.py` | Static dictionary of simulated merchants (`SIMULATED_MERCHANTS`). Ad-hoc UPI IDs were automatically formatted and marked "NEW" without clarity on network reach. | Transparent payee resolution distinguishing: **1.** Internal Verified FraudShield User, **2.** Saved Beneficiary, **3.** External UPI ID (unverified outside ecosystem without PSP gateway). No fabricated recipient data. |
| **Payment PIN Management** | `app/routes/auth_routes.py` & `frontend/static/js/payment.js` | PIN setup endpoint existed but lacked secure PIN Reset (via authenticated OTP) and PIN Change (via old PIN). | Comprehensive PIN lifecycle: `Set PIN`, `Change PIN` (current PIN + new PIN), `Reset PIN` (via phone OTP + account password). |
| **Payment Page UX** | `frontend/templates/payment.html` | Visible "Advanced: Simulation Balances & Machine Learning Inputs" form exposed directly to regular consumer users. | Consumer-first payment UX hiding internal ML simulation inputs from standard customers; strict server-side PIN enforcement before any ledger processing. |

---

## 4. Production-Capable Functionality Matrix

```
┌─────────────────────────────────────────────────────────────┐
│                 FRAUDSHIELD PAYMENT ENGINE                  │
├──────────────────────────────┬──────────────────────────────┤
│ Production Ready             │ Requires Upgrade / Real Flow │
├──────────────────────────────┼──────────────────────────────┤
│ ✔ ML Inference (XGB/LGBM)    │ ⚠ Real SMS OTP Provider      │
│ ✔ Hybrid 4-Tier Risk Policy  │ ⚠ Real Email Reset Provider  │
│ ✔ SHAP TreeExplainer         │ ⚠ Live Camera QR Scanner     │
│ ✔ Device Fingerprinting      │ ⚠ QR Image Upload Decoder    │
│ ✔ Impossible Travel / Geo    │ ⚠ Mobile Number Verification │
│ ✔ 24-hr Beneficiary Cooling  │ ⚠ Dedicated PIN Reset Flow   │
│ ✔ Atomic Bi-directional Tx   │ ⚠ Truthful Payee Resolution  │
│ ✔ SOC Cases & Alerts         │                              │
│ ✔ Idempotency Protection     │                              │
└──────────────────────────────┴──────────────────────────────┘
```

---

## 5. External Provider Abstractions Required

To eliminate hardcoded demo behavior without vendor lock-in:

### 5.1 `SmsProvider` Interface
- `send_otp(phone_number: str, otp_code: str, template: str) -> Tuple[bool, Optional[str]]`
- **Implementations**:
  - `DevelopmentSmsProvider`: Secure local logging / testing capture.
  - `TwilioSmsProvider` / `Msg91SmsProvider`: Production SMS gateway integration via standard environment variables (`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`, etc.).
  - `NullSmsProvider`: Graceful failure when no provider is configured, returning a truthful error.

### 5.2 `EmailProvider` Interface
- `send_password_reset_email(to_email: str, reset_token: str, recipient_name: str) -> Tuple[bool, Optional[str]]`
- **Implementations**:
  - `DevelopmentEmailProvider`: Formats secure console output in development mode.
  - `SmtpEmailProvider` / `SendGridEmailProvider`: Standard TLS SMTP or transactional API.

### 5.3 `UPIProvider` Interface
- `resolve_vpa(vpa: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]`
- Explicitly handles internal registered user lookup vs. external PSP verification.

---

## 6. Security Gaps & Remediations

1. **Server-Side PIN Enforcement**:
   - *Risk*: Client-side PIN verification could be bypassed by crafting direct `POST /api/transactions/predict` requests.
   - *Remediation*: The backend enforces that `user.is_pin_set` MUST be true, and `payment_pin` MUST match the stored bcrypt hash before ML evaluation or ledger movement. Missing or incorrect PIN returns `401 Unauthorized` / `429 Too Many Requests` (lockout).
2. **Anti-Enumeration Protection**:
   - *Risk*: Attackers querying phone numbers or emails could enumerate account holders.
   - *Remediation*: Password reset and registration OTP endpoints return identical generic responses. Payee resolution returns masked identifiers (`+91 ******3210`) for internal users.
3. **Sensitive Data Redaction**:
   - *Risk*: Plaintext PINs or OTPs leaked in application logs or frontend state.
   - *Remediation*: Strict exclusion of `payment_pin_hash`, `phone_otp_hash`, and plaintext PINs from `to_dict()`, log formatters, and browser `localStorage`.

---

## 7. Required Database Schema Enhancements

The SQLite/MySQL schema requires the following additions on the `User` model:
- `phone_otp_hash` (`VARCHAR(255)`): SHA-256 hash of active registration/verification OTP.
- `phone_otp_expires_at` (`DATETIME`): Expiration timestamp for mobile verification OTP.
- `phone_otp_attempts` (`INTEGER`): Failed verification attempt counter (max 3).
- `phone_verified_at` (`DATETIME`): Timestamp when phone ownership was established.
- `payment_pin_updated_at` (`DATETIME`): Timestamp of last PIN configuration or update.

---

## 8. Required API Changes

### New / Enhanced Endpoints:
1. `POST /api/auth/register`: Accepts `name`, `email`, `phone_number`, `password`, `confirm_password`. Creates user with `is_phone_verified=False` and triggers SMS OTP.
2. `POST /api/auth/verify-phone-otp`: Verifies SMS OTP code, activates user account.
3. `POST /api/auth/resend-phone-otp`: Throttled resend for pending phone verification.
4. `POST /api/auth/payment-pin/change`: Requires `current_pin`, `new_pin`, `confirm_pin`.
5. `POST /api/auth/payment-pin/reset-request`: Generates OTP to reset PIN if forgotten.
6. `POST /api/auth/payment-pin/reset-confirm`: Verifies reset OTP + account password to set new PIN.
7. `POST /api/transactions/resolve-recipient`: Truthful resolver categorizing payees as `INTERNAL_USER`, `SAVED_BENEFICIARY`, or `EXTERNAL_UPI`.

---

## 9. Required Frontend Enhancements

1. **Live Camera QR Scanner**: Integrated HTML5 video preview using `navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })` with frame capture canvas and jsQR fallback.
2. **QR Image File Upload**: `<input type="file" accept="image/*">` decoding dropped/selected QR image files.
3. **Registration & Mobile Verification Modal**: Multi-step registration flow prompting for SMS OTP before first login.
4. **Clean Consumer Payment Form**: Simplified payment interface with recipient review, quick amount chips, PIN modal, and clear FraudShield security verification feedback.

---

## 10. Audit Sign-off

- [x] All 303 existing automated tests verified passing.
- [x] Zero regressions on ML inference, SHAP, device trust, geo intelligence, or SOC case management.
- [x] Full transition path to production-authentic UPI workflow defined.
