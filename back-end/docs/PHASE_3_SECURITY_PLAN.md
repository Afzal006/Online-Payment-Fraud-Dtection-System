# Phase 3 Security Architecture & Hardening Plan

**Project**: FraudShield AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-19  
**Status**: DRAFT — PENDING ARCHITECTURAL APPROVAL  

---

## 1. Security Architecture Principles

FraudShield AI operates under a **Zero-Trust Security Architecture** for financial transactions:
1. **Never Trust, Always Verify**: Every incoming transaction is subject to real-time risk scoring, device validation, and point-in-time behavioral baseline analysis.
2. **Defense-in-Depth**: Multiple layered controls (ML model, deterministic policy floors, MFA step-up challenges, human SOC oversight).
3. **Least Privilege**: Strict Role-Based Access Control (RBAC) segregating Consumer and Administrator capabilities.
4. **Non-Repudiation & Auditability**: Immutable, structured JSON audit logs linked via unique request identifiers (`X-Request-ID`).
5. **Data Privacy & Redaction**: Complete omission of plaintext credentials, tokens, and personal secrets from logs and API payloads.

---

## 2. Threat Modeling & Attack Vectors Addressed in Phase 3

```
+----------------------------------------------------------------------------------------------------+
|                                    PHASE 3 THREAT MATRIX & DEFENSES                                 |
+----------------------------------------------------------------------------------------------------+
| Threat Vector                  | Attack Scenario                          | Phase 3 Defense        |
+--------------------------------+------------------------------------------+------------------------+
| 1. Account Takeover (ATO)      | Stolen credentials used on attacker PC   | Device Fingerprinting  |
| 2. Impossible Travel           | Login from Mumbai followed by London 15m | Geolocation Velocity   |
| 3. Mule Account Draining       | Adding mule payee and instant ₹2.5L tx   | 24h Cooling Period     |
| 4. Distributed Mule Syndicate  | 5 users sending money to same payee      | Multi-Sender Detection |
| 5. Cross-Site Scripting (XSS)  | Malicious injected JavaScript in inputs  | CSP & Sanitization     |
| 6. Clickjacking & Framing      | Embedding portal in malicious iframe     | X-Frame-Options: DENY  |
| 7. MIME-Type Sniffing          | Malicious payload disguised as static    | nosniff header         |
| 8. Credential Stuffing         | Automated high-rate login brute force    | IP Rate Limiting       |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. OWASP Top 10 Compliance Verification

| OWASP Top 10 Category | FraudShield AI Implementation & Hardening | Compliance Status |
| :--- | :--- | :---: |
| **A01: Broken Access Control** | `@jwt_required()`, `@admin_required()`, customer IDOR-safe database queries (`filter_by(user_id=current_user_id)`). | **COMPLIANT** |
| **A02: Cryptographic Failures** | Passwords hashed via PBKDF2/Scrypt; OTP and reset tokens hashed via SHA-256; HSTS enforced. | **COMPLIANT** |
| **A03: Injection** | SQLAlchemy ORM parameterized queries; strict input validation (`validators.py`). | **COMPLIANT** |
| **A04: Insecure Design** | 4-tier risk decision matrix with automatic step-up authentication and fraud holds. | **COMPLIANT** |
| **A05: Security Misconfiguration** | OWASP HTTP headers injected automatically; debug disabled in production config. | **COMPLIANT** |
| **A06: Vulnerable Components** | Minimal dependencies pinned in `requirements.txt`; automated GitHub security alerts. | **COMPLIANT** |
| **A07: Identification & Auth** | Anti-enumeration endpoints, attempt limits (5 max), token expiration (10m), single-use invalidation. | **COMPLIANT** |
| **A08: Software & Data Integrity**| ML artifacts versioned with metadata hashes; signed JWT tokens. | **COMPLIANT** |
| **A09: Logging & Monitoring** | Structured JSON audit logging with `X-Request-ID` and admin SOC telemetry. | **COMPLIANT** |
| **A10: Server-Side Request Forgery**| Zero external SSRF endpoints; all internal payment calls strictly local. | **COMPLIANT** |

---

## 4. HTTP Security Headers Specification

Every HTTP response emitted by FraudShield AI is intercepted by the security header middleware:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

---

## 5. Device Fingerprinting Privacy & Security

1. **Client-Side Telemetry**:
   - Computes SHA-256 hash over: `navigator.userAgent`, `screen.width`, `screen.height`, `screen.colorDepth`, `Intl.DateTimeFormat().resolvedOptions().timeZone`, and WebGL renderer string.
   - PII (Personally Identifiable Information) is never stored directly; only the one-way irreversible `device_hash` is recorded.
2. **Device Trust Lifecycle**:
   - `TRUSTED` (Score 1.0): Known device used successfully with prior OTP verifications.
   - `SUSPICIOUS` (Score 0.5): Device with modified browser properties or user-agent change.
   - `NEW / UNKNOWN` (Score 0.0): Unrecognized device hash $\rightarrow$ triggers $+25$ risk score increment and OTP challenge.
   - `BLOCKED` (Score -1.0): Blacklisted device flagged during SOC fraud investigation.

---

## 6. Regulatory & Banking Guidelines Alignment

- **RBI Digital Payment Security Controls (2021)**:
  - Adaptive Two-Factor Authentication for payments exceeding threshold limits.
  - Beneficiary cooling periods for newly registered payees.
  - Logging of customer IP, timestamp, transaction ID, and decision audit trail.
- **PCI-DSS v4.0 Requirement 10**:
  - Implement automated audit trails for all system components to reconstruct all user actions.
