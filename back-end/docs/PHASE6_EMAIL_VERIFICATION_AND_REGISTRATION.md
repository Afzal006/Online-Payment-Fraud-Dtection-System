# Phase 6: Real Email Ownership Verification & Registration Hardening

## Overview
FraudShield AI implements a production-grade dual-factor verification and registration hardening architecture. Accounts created via the customer registration flow start in `PENDING_VERIFICATION` status and are strictly prevented from logging in or executing transactions until **both** primary identity factors have been verified:
1. **Real Email Ownership Verification** (via cryptographically hashed 6-digit Email OTP or single-use verification URL token).
2. **Real Mobile Ownership Verification** (via SMS OTP challenge).

---

## 1. Core Architecture & Verification Lifecycle

```
                                 [ Customer Registration ]
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                         ▼
            [ Email Verification ]                      [ Mobile Verification ]
             • RFC Syntax Validation                     • E.164 Strict Format
             • MX / DNS Resolvability                    • 6-digit SMS OTP
             • 6-digit SHA-256 OTP (5m)                  • 3-Attempt Lockout
             • Single-Use URL Token                      • 60s Resend Cooldown
             • 60s Resend Cooldown                                │
                        │                                         │
                        ▼                                         ▼
             is_email_verified = True                    is_phone_verified = True
                        └────────────────────┬────────────────────┘
                                             ▼
                             [ Dual-Factor Gate Evaluator ]
                                             │
                       Both verified? ───────┼─────── Not yet?
                             │               │           │
                            YES              │           NO
                             ▼               │           ▼
                 account_status = "ACTIVE"   │   account_status = "PENDING_VERIFICATION"
                     is_active = True        │   Login Rejected (EMAIL/PHONE_NOT_VERIFIED)
```

---

## 2. Security & Hardening Controls

### 2.1 Email Syntax & Domain Resolvability Validation
- RFC 5322 regex validation enforcing valid local-part and domain labels.
- Maximum email length guard (254 characters) and local part length guard (64 characters).
- Explicit rejection of non-routable, reserved test domains (`.invalid`, `.test`, `.example`, `.localhost`, `.local`).
- Socket DNS resolution with strict 2.0s socket timeout to verify domain MX/A records before sending messages.

### 2.2 Dual Verification Channels
- **OTP Method**: 6-digit cryptographically generated numeric code valid for 5 minutes (`OTP_EMAIL_EXPIRY_SECONDS = 300`).
- **Direct Link Token**: 32-byte URL-safe crypto token (`secrets.token_urlsafe(32)`) valid for 24 hours.
- **Zero Plaintext Storage**: Both OTPs and URL tokens are stored strictly as SHA-256 hashes (`email_verification_otp_hash`, `email_verification_token_hash`).
- **Anti-Brute Force**: 3-attempt limit on OTP entries. On 3 failed attempts, the OTP is invalidated and requires a new code.
- **Rate-Limiting & Cooldown**: 60-second cooldown on resending email verification (`email_verification_last_sent_at`).

### 2.3 EmailProvider Architecture
- `SmtpEmailProvider`: Production SMTP transport delivering responsive HTML email templates with security warnings and direct confirmation buttons.
- `DevelopmentEmailProvider`: In-memory recorded provider for local testing and CI/CD test automation.
- `NullEmailProvider`: Fails gracefully with honest error reporting when SMTP credentials are not configured.

### 2.4 Login Gate Enforcement
The `/api/auth/login` endpoint strictly evaluates verification status before issuing JWT tokens:
- If `is_email_verified is False`: Rejects with HTTP 403 and `code: "EMAIL_NOT_VERIFIED"`.
- If `is_phone_verified is False`: Rejects with HTTP 403 and `code: "PHONE_NOT_VERIFIED"`.

---

## 3. API Endpoints Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Initiates dual-factor registration challenge | No |
| `POST` | `/api/auth/verify-email-otp` | Verifies 6-digit email OTP code | No |
| `POST` | `/api/auth/resend-email-verification` | Resends email OTP (enforces 60s cooldown) | No |
| `GET` | `/api/auth/verify-email?token=...` | Verifies email via single-use link token | No |
| `POST` | `/api/auth/verify-phone-otp` | Verifies 6-digit phone SMS OTP code | No |
| `POST` | `/api/auth/resend-phone-otp` | Resends phone SMS OTP (enforces 60s cooldown) | No |
| `GET` | `/api/health` | Diagnostic endpoint including `email_provider` status | No |

---

## 4. Audit Trail Events

All email verification lifecycle actions are logged in the tamper-evident audit trail:
- `USER_REGISTERED`: User account created in `PENDING_VERIFICATION` state.
- `EMAIL_VERIFICATION_SENT`: Verification OTP & Token dispatched.
- `EMAIL_VERIFICATION_RESEND`: Resend triggered following cooldown check.
- `EMAIL_VERIFICATION_FAILED`: Incorrect OTP or expired token submission.
- `EMAIL_VERIFICATION_COMPLETED`: Email marked verified, account promoted to `ACTIVE` upon dual factor completion.
