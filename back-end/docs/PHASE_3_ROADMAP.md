# Phase 3 Engineering Roadmap & Execution Sequence

**Project**: FraudShield AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-19  
**Status**: DRAFT — PENDING ARCHITECTURAL APPROVAL  

---

## 1. Roadmap Overview

The Phase 3 roadmap is organized into **5 sequential, decoupled development sprints**. Each sprint delivers self-contained, fully tested capabilities that build upon the existing 199 passing tests without causing regressions.

```
+----------------------------------------------------------------------------------------------------+
|                                    PHASE 3 EXECUTION TIMELINE                                      |
+----------------------------------------------------------------------------------------------------+
| Sprint 1: Security Headers, Request Tracing & Structured Audit Logs (P0)                          |
|   └── OWASP Middleware, UUIDv4 X-Request-ID, AuditLog Model & Service                              |
+----------------------------------------------------------------------------------------------------+
| Sprint 2: Device Fingerprinting & Client Telemetry (P0)                                           |
|   └── DeviceProfile Model, Frontend Hash Telemetry, Unknown Device Risk Signal                     |
+----------------------------------------------------------------------------------------------------+
| Sprint 3: Geolocation Intelligence & Beneficiary Cooling Period Rules (P0/P1)                     |
|   └── Impossible Travel Engine (Haversine), 24h Cooling Period, Mule Account Intelligence          |
+----------------------------------------------------------------------------------------------------+
| Sprint 4: SOC Case Management & Closed-Loop Fraud Feedback Loop (P0/P1)                           |
|   └── Multi-State Investigation Lifecycle, Analyst Assignment, Dynamic Baseline Updates           |
+----------------------------------------------------------------------------------------------------+
| Sprint 5: Production Containerization & CI/CD Pipeline (P1/P2)                                    |
|   └── Dockerfile, docker-compose.yml (Flask + MySQL + Redis), GitHub Actions CI, Benchmark Update  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Sprint-by-Sprint Implementation Breakdown

### Sprint 1: Security Middleware & Audit Logging (P0)
- **Objective**: Establish immutable request tracing and enterprise security headers.
- **Deliverables**:
  - `app/models/audit_log.py`: `AuditLog` database model.
  - `app/services/audit_service.py`: Centralized audit logging helper.
  - `app/utils/security_headers.py`: OWASP compliant response headers.
  - Request Context Middleware: Injects `X-Request-ID` into every HTTP transaction.
  - Test Suite: `tests/test_audit_logging.py` (7 tests).
- **Estimated Tests Added**: +7 tests (Total: 206).

---

### Sprint 2: Device Fingerprinting & Telemetry (P0)
- **Objective**: Enable zero-trust client device verification on login and payments.
- **Deliverables**:
  - `app/models/device_profile.py`: Device identity, trust scores, and last-seen timestamps.
  - `frontend/static/js/fingerprint.js`: Canvas, WebGL, Screen, and User-Agent client hashing.
  - `app/services/device_service.py`: Registration, trust score evaluation, and anomaly detection.
  - `RiskSignalService` extension: `UNKNOWN_DEVICE_LOGIN` signal ($+25$ risk score).
  - Test Suite: `tests/test_device_fingerprinting.py` (8 tests).
- **Estimated Tests Added**: +8 tests (Total: 214).

---

### Sprint 3: Geolocation Velocity & Beneficiary Intelligence (P0 / P1)
- **Objective**: Protect against Account Takeover (ATO) and rapid account draining.
- **Deliverables**:
  - `app/services/geo_service.py`: Haversine distance and speed calculation ($>800\text{ km/h} \rightarrow \text{Impossible Travel}$).
  - `app/services/beneficiary_intelligence_service.py`: 24-hour cooling-period limits and mule recipient pattern detection.
  - `RiskSignalService` extensions: `IMPOSSIBLE_TRAVEL_VELOCITY`, `BENEFICIARY_COOLING_PERIOD`, `MULE_ACCOUNT_RECIPIENT`.
  - Test Suite: `tests/test_geo_and_beneficiary_intelligence.py` (10 tests).
- **Estimated Tests Added**: +10 tests (Total: 224).

---

### Sprint 4: SOC Case Management & Fraud Feedback Loop (P0 / P1)
- **Objective**: Provide enterprise incident investigation tools and continuous learning.
- **Deliverables**:
  - `app/models/case_investigation.py`: Case lifecycle management table.
  - `app/services/case_management_service.py`: Assignment, investigative notes, status transitions.
  - `app/services/feedback_loop_service.py`: Automatic recalculation of customer baseline fraud rates and export of training samples.
  - `frontend/templates/admin/admin_case_detail.html`: Analyst case triage UI.
  - Test Suite: `tests/test_case_management.py` (8 tests).
- **Estimated Tests Added**: +8 tests (Total: 232).

---

### Sprint 5: Production Containerization & CI/CD Automation (P1 / P2)
- **Objective**: Package FraudShield for scalable, reproducible production deployment.
- **Deliverables**:
  - `Dockerfile`: Multi-stage lightweight Python 3.14 container.
  - `docker-compose.yml`: Multi-service orchestration (Flask API, MySQL 8.0, Redis 7).
  - `.github/workflows/ci.yml`: Automated testing, linting, and security scan workflow.
  - `gunicorn.conf.py`: Production WSGI worker configuration.
  - Test Suite: `tests/test_deployment_readiness.py` (4 tests).
- **Estimated Tests Added**: +4 tests (Total: 236+).

---

## 3. Dependency & Risk Analysis

| Risk Factor | Severity | Mitigation Strategy |
| :--- | :---: | :--- |
| **Breaking Existing 199 Tests** | High | Every sprint runs the full pytest regression suite before merging. Zero breaking changes to existing route schemas. |
| **False Positives on Device Changes** | Medium | First-time devices trigger `MEDIUM` / `HIGH` step-up OTP challenge rather than immediate rejection. |
| **Missing Geolocation Data in Tests** | Low | Geolocation service supports fallback headers and coordinates with mock testing fixtures. |
| **Database Migration Locking** | Low | New columns and tables use non-locking SQLite/MySQL DDL with default values. |

---

## 4. Milestone Checkpoint Targets

- **Checkpoint 1 (Sprint 1 & 2)**: `feat: security middleware and device fingerprinting` ($\approx 214$ tests).
- **Checkpoint 2 (Sprint 3 & 4)**: `feat: geo intelligence and soc case management` ($\approx 232$ tests).
- **Checkpoint 3 (Sprint 5 & Final)**: `feat: production containerization and full phase 3 integration` ($\ge 236$ tests).
