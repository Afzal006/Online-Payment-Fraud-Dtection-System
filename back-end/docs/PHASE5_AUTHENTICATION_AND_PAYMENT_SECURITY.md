# Phase 5: Authentication Hardening, Payment PIN Recovery, & Production Email Architecture

---

## 1. Executive Summary

FraudShield AI incorporates a defense-in-depth security model separating:
1. **Account Login Credentials (Password & SMS/Email MFA)**: Authorizes access to the user dashboard, settings, and transaction history.
2. **Payment PIN (4–6 Digit Cryptographic Transaction Factor)**: Required at Layer 1 before any financial transfer, QR transaction, or UPI payment enters the ML Fraud Intelligence Engine.

Phase 5 delivers production-ready implementations for:
- **Forgot Payment PIN Recovery Flow**: Complete multi-factor recovery using mobile SMS OTP and account password verification without ever exposing or retrieving the old PIN.
- **Weak PIN & Password Collision Prevention**: Enforces strong PIN policies (rejecting trivial patterns such as `0000`, `1234`, `1111`, etc.) and preventing PIN equality to login passwords.
- **Production SMTP & Email Delivery Engine**: Comprehensive SMTP provider supporting STARTTLS (Port 587) and SSL (Port 465), personalized templates, absolute URL generation via `APP_PUBLIC_URL`, and strict anti-enumeration protections.
- **Transparent UPI / QR Recipient Resolution**: Transparently marks external UPI VPAs (e.g. `someone@paytm`, `merchant@phonepe`) as external without false claims of internal registration, while routing all payments through AI risk scoring and atomic ledger controls.

---

## 2. Payment PIN Recovery Architecture ("Forgot Payment PIN?")

### High-Level State Diagram

```
[ User Forgets PIN ]
        │
        ▼
[ Click "Forgot Payment PIN?" ]
        │
        ▼
[ POST /api/auth/payment-pin/forgot/request-otp ]
        │
        ├── Enforce Rate Limiting (60s cooldown, max 3 / 15-min window)
        ├── Generate Cryptographic 6-digit OTP
        ├── Dispatch SMS via SMSProvider (Twilio / Development)
        └── Log Audit Event: PAYMENT_PIN_RESET_OTP_SENT
        │
        ▼
[ User Enters SMS OTP + Account Password + New 4-6 Digit PIN ]
        │
        ▼
[ POST /api/auth/payment-pin/forgot/verify-and-reset ]
        │
        ├── Verify Account Password (check_password_hash)
        ├── Verify SMS OTP (Single-Use, Expiry, 3 Max Attempts)
        ├── Validate New PIN (4-6 digits, not weak, != password, matches confirm)
        ├── PBKDF2/Scrypt Hash Storage (payment_pin_hash)
        ├── Clear Lockout State (pin_failed_attempts = 0, pin_locked_until = None)
        ├── Invalidate OTP Hash & Tokens
        └── Log Audit Event: PAYMENT_PIN_RESET_COMPLETED
        │
        ▼
[ Payment PIN Reset Successfully ]
```

### Security Guarantees:
- **Zero Plaintext Storage**: PINs are never stored or logged in plaintext; only salted cryptographic hashes reside in the database.
- **Zero API Exposure**: PIN hashes are stripped from `to_dict()`, JSON serializers, audit details, and API responses.
- **Lockout Auto-Clearance**: Successfully completing the verified PIN reset lifecycle immediately unlocks the account from any previous 3-attempt lockout.
- **Separation of Concerns**: Password recovery and PIN recovery remain completely independent factors.

---

## 3. Email Delivery & Password Reset System

### Architecture & Provider Resolution
The application implements an extensible `EmailProvider` abstraction layer resolved dynamically via `get_email_provider()`:

```
Runtime Configuration (MAIL_PROVIDER / SMTP_HOST)
        │
        ├── If MAIL_PROVIDER == 'smtp' OR SMTP_HOST defined -> SmtpEmailProvider
        ├── If MAIL_PROVIDER == 'development' OR TESTING == True -> DevelopmentEmailProvider
        └── Otherwise -> NullEmailProvider (Honest technical rejection)
```

### Supported Environment Variables:
```env
# Email Provider Selection
MAIL_PROVIDER=smtp

# SMTP Server Details
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_FROM_EMAIL=security@fraudshield.ai
SMTP_FROM_NAME=FraudShield AI Security

# Public Application Domain (Used for absolute reset URL creation)
APP_PUBLIC_URL=https://your-domain.com
```

### Email Template Features:
- **Subject**: `FraudShield AI — Password Reset`
- **Body**: Personalized with user's full name, prominent CTA button pointing to `{APP_PUBLIC_URL}/reset-password?token={RAW_TOKEN}`, 15-minute expiration warning, and security notices.
- **Anti-Enumeration**: If an unregistered email is submitted, the API returns a generic success message while recording a private `NOT_FOUND` audit log on the server.

---

## 4. External UPI & QR Recipient Resolution

FraudShield distinguishes between:
1. **Internal FraudShield Users**: Resolved against database accounts (`account_type: "CUSTOMER"`).
2. **Saved Beneficiaries**: Pre-approved trusted payees (`account_type: "SAVED_BENEFICIARY"`).
3. **Simulated Merchants**: Recognized high-volume point-of-sale VPAs (`account_type: "MERCHANT"`).
4. **External UPI Addresses**: Valid UPI format VPAs on external banks/providers (e.g. `@paytm`, `@phonepe`, `@okaxis`, `@apl`). Labeled clearly as:
   - **Payee**: `merchant@paytm`
   - **Account Type**: `🌐 External UPI Address (Unregistered on FraudShield)`
   - **Format**: `Valid`
   - **Risk Evaluation**: Routed through ML Fraud Pipeline and atomic settlement.

---

## 5. Audit Logging Events Added

| Audit Event Type | Severity | Description |
| :--- | :---: | :--- |
| `PAYMENT_PIN_RESET_REQUESTED` | `INFO` | Customer initiated PIN recovery OTP request |
| `PAYMENT_PIN_RESET_OTP_SENT` | `INFO` | OTP dispatched via configured SMS provider |
| `PAYMENT_PIN_RESET_OTP_FAILED` | `WARN` | Incorrect or expired OTP submitted during PIN reset |
| `PAYMENT_PIN_RESET_RATE_LIMITED` | `WARN` | Excessive PIN reset attempts blocked |
| `PAYMENT_PIN_RESET_COMPLETED` | `INFO` | New Payment PIN securely hashed and lockouts cleared |
| `PASSWORD_RESET_EMAIL_SENT` | `INFO` | Password reset link dispatched via SMTP provider |
| `PASSWORD_RESET_FAILED` | `WARN` | Technical failure during email dispatch |

---

## 6. Verification & Test Suite Summary

- **PIN Recovery & Security Tests (`tests/test_payment_pin_reset.py`)**: 7/7 PASSED
- **Email & Password Reset Tests (`tests/test_email_password_reset.py`)**: 6/6 PASSED
- **Payment PIN End-to-End Tests (`tests/test_payment_pin_flow.py`)**: 25/25 PASSED
- **Regression Test Suite (`py -m pytest -v`)**: 393/393 PASSED (100%)
- **Health API Endpoint (`GET /api/health`)**: 200 OK (Healthy)
