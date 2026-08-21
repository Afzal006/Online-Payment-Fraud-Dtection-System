# Phase 3 Quality Assurance & Master Test Plan

**Project**: FraudShield AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-19  
**Status**: DRAFT — PENDING ARCHITECTURAL APPROVAL  

---

## 1. Quality Assurance Objective & Zero-Regression Mandate

The Phase 3 Quality Assurance framework guarantees:
1. **Zero-Regression Mandate**: All **199 existing automated tests** must maintain a 100% passing status across every stage of Phase 3.
2. **Comprehensive New Coverage**: A minimum of **37 new automated tests** will be developed to validate all Phase 3 capabilities.
3. **Target Suite Size**: Total test count expanding from **199 $\rightarrow \ge 236$ tests**.
4. **Sub-2-Minute Execution**: Full test suite execution maintained under 120 seconds on standard development and CI environments.

---

## 2. Test Suite Architecture

```
tests/
├── Existing Suites (199 Tests Passing)
│   ├── test_adaptive_security.py         (6 tests)
│   ├── test_admin_portal_separation.py   (13 tests)
│   ├── test_admin_soc.py                 (13 tests)
│   ├── test_audit.py                     (4 tests)
│   ├── test_auth.py                      (11 tests)
│   ├── test_database.py                  (7 tests)
│   ├── test_e2e_system.py                (7 tests)
│   ├── test_feature_engineering.py       (6 tests)
│   ├── test_frontend.py                  (7 tests)
│   ├── test_hybrid_risk_engine.py        (19 tests)
│   ├── test_inference.py                 (9 tests)
│   ├── test_models.py                    (5 tests)
│   ├── test_password_reset.py            (24 tests)
│   ├── test_payment_identity.py          (22 tests)
│   ├── test_prediction_api.py            (11 tests)
│   ├── test_preprocessing.py             (3 tests)
│   ├── test_risk_engine.py               (17 tests)
│   ├── test_setup.py                     (6 tests)
│   ├── test_shap.py                      (7 tests)
│   └── test_strong_models.py             (5 tests)
│
└── Phase 3 Planned Suites (+37 New Tests)
    ├── test_security_middleware.py       (+7 tests: OWASP headers, X-Request-ID, structured logs)
    ├── test_device_fingerprinting.py     (+8 tests: Device registration, trust score, unknown device signal)
    ├── test_geo_intelligence.py          (+8 tests: Haversine distance, speed, impossible-travel signal)
    ├── test_beneficiary_intelligence.py  (+6 tests: 24h cooling period, mule recipient detection)
    ├── test_soc_case_management.py       (+8 tests: Analyst assign, investigation lifecycle, feedback loop)
    └── test_deployment_readiness.py      (+4 tests: Docker configs, environment sanity, CI contracts)
```

---

## 3. Detailed Phase 3 Test Specifications

### Module A: Security Headers & Request Tracing (`tests/test_security_middleware.py`)
1. `test_security_headers_present_on_all_routes`: Verifies `CSP`, `HSTS`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
2. `test_request_id_injected_in_response_headers`: Confirms `X-Request-ID` is present on all API responses.
3. `test_request_id_propagated_to_audit_logs`: Verifies correlation between HTTP request header and `AuditLog.request_id`.
4. `test_audit_log_created_on_login_attempt`: Confirms successful and failed logins generate structured audit records.
5. `test_audit_log_created_on_transaction_evaluation`: Confirms risk decision events are recorded in `audit_logs`.
6. `test_audit_log_filters_and_pagination`: Verifies admin query API `/api/admin/audit-logs`.
7. `test_audit_log_sanitization`: Verifies sensitive parameters (passwords, tokens) are omitted from `audit_logs.details`.

### Module B: Device Fingerprinting (`tests/test_device_fingerprinting.py`)
8. `test_device_registration_on_login`: Creates `DeviceProfile` record on first login.
9. `test_known_device_maintains_high_trust`: Repeated logins from same device hash maintain `trust_score = 1.0`.
10. `test_unknown_device_triggers_risk_signal`: Transaction from new device hash generates `UNKNOWN_DEVICE_LOGIN` signal.
11. `test_unknown_device_elevates_risk_score`: Score incremented by $+25$ and sets floor to $40$.
12. `test_device_list_customer_isolation`: User can only view their own registered devices (`GET /api/profile/devices`).
13. `test_revoke_device_trust`: User revoking a device resets its trust score.
14. `test_blocked_device_rejection`: Device flagged as `is_blocked = True` is rejected on transaction evaluation.
15. `test_device_hash_tamper_resistance`: Altered screen/UA components produce distinct hash and trigger verification.

### Module C: Geolocation & Impossible Travel (`tests/test_geo_intelligence.py`)
16. `test_haversine_distance_calculation`: Mathematical verification of spherical distance calculations between coordinates.
17. `test_normal_travel_velocity_accepted`: Legitimate travel speed ($<100\text{ km/h}$) produces zero geo anomaly signal.
18. `test_impossible_travel_triggers_critical_signal`: Speed $>800\text{ km/h}$ triggers `IMPOSSIBLE_TRAVEL_VELOCITY`.
19. `test_impossible_travel_elevates_to_critical_tier`: Floor set to $80$ (`CRITICAL`), triggering `TRIGGER_SECURITY_REVIEW`.
20. `test_geo_missing_headers_graceful_fallback`: Missing client coordinates defaults safely to zero anomaly score.
21. `test_geo_point_in_time_isolation`: Prior location queries enforce $t < t_{\text{tx}}$.
22. `test_cross_country_anomaly`: Login from foreign country flagged as high-risk event.
23. `test_geo_telemetry_in_admin_detail`: SOC analyst can view transaction origin location and travel speed in admin portal.

### Module D: Beneficiary Intelligence & Cooling Period (`tests/test_beneficiary_intelligence.py`)
24. `test_new_beneficiary_cooling_period_high_amount`: Transfer $> ₹25,000$ to beneficiary created $<24$ hours ago triggers `BENEFICIARY_COOLING_PERIOD`.
25. `test_cooling_period_elevates_to_high_risk`: Triggers `TRIGGER_OTP_VERIFICATION` and holds balance.
26. `test_mature_beneficiary_exempt_from_cooling`: Beneficiary $>24$ hours old processes without cooling-period penalty.
27. `test_small_amount_exempt_from_cooling`: Transfer $< ₹25,000$ to new beneficiary does not trigger cooling penalty.
28. `test_mule_account_multi_sender_detection`: Payee receiving transfers from $\ge 3$ distinct accounts within 1h triggers `MULE_ACCOUNT_RECIPIENT`.
29. `test_mule_signal_elevates_risk_floor`: Mule signal sets floor to $75$ (`HIGH` risk).

### Module E: SOC Case Management & Fraud Feedback Loop (`tests/test_soc_case_management.py`)
30. `test_analyst_case_assignment`: Admin analyst can assign open alert to their user account (`POST /api/admin/alerts/<id>/assign`).
31. `test_case_status_transition_investigating`: Status updates from `OPEN` $\rightarrow$ `UNDER_INVESTIGATION`.
32. `test_case_resolution_with_structured_category`: Resolves alert with `CONFIRMED_FRAUD` and audit notes.
33. `test_feedback_loop_updates_customer_fraud_rate`: Confirming fraud automatically increments `user_fraud_rate` in customer baseline.
34. `test_feedback_loop_queues_retraining_sample`: Confirmed fraud transaction is written to retraining dataset queue.
35. `test_false_positive_resolution_clears_customer_flag`: Marking `FALSE_POSITIVE` restores customer trust score.
36. `test_case_history_audit_trail`: Case updates are permanently logged with timestamps and analyst IDs.
37. `test_unauthorized_user_cannot_access_case_management`: Non-admin users attempting case assignment receive `403 Forbidden`.

---

## 4. Test Execution Commands

```powershell
# Run only new Phase 3 tests
py -m pytest tests/test_security_middleware.py tests/test_device_fingerprinting.py tests/test_geo_intelligence.py tests/test_beneficiary_intelligence.py tests/test_soc_case_management.py -v

# Run complete regression suite (All 236+ tests)
py -m pytest -v
```
