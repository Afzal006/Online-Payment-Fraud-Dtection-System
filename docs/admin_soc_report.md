# Admin Security Operations Center (SOC) & Analytics Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Phase**: Phase 11 — Admin Analytics & Security Operations Dashboard  
**Security Architecture**: Role-Based Access Control (`ADMIN` role enforced), SQL Database Aggregations, Chart.js Visualizations, SHAP Triage, Statistical Feature Drift Monitor  
**Report Date**: 2026-08-18  

---

## 1. SOC Administrative Architecture & RBAC

The Security Operations Center (SOC) dashboard provides privileged security analysts and administrators with global situational awareness, ML performance telemetry, and incident response tooling.

```
                  [ADMIN User Request (JWT)]
                              │
                              ▼
            [@admin_required Decorator Enforcement]
             ├── Role != 'ADMIN' ──► HTTP 403 Forbidden
             └── Role == 'ADMIN' ──► Authorized Access
                              │
                              ▼
             +─────────────────────────────────+
             │   Admin SOC Operations Portal   │
             +─────────────────────────────────+
             │ • Overview KPIs & Volume        │
             │ • Chart.js Telemetry Trends     │
             │ • Alert Triage (Investigate/    │
             │   Resolve with Notes/Dismiss)   │
             │ • Global Transaction Ledger     │
             │ • ML Benchmarks & Drift Monitor │
             +─────────────────────────────────+
```

---

## 2. SQL Data Aggregation & Analytics Service

All dashboard metrics are computed using optimized database-level aggregation queries (`COUNT`, `SUM`, `GROUP BY`) through [AdminAnalyticsService](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/app/services/admin_analytics_service.py) rather than loading unneeded rows into memory:

- **Volume by Transaction Type**: Aggregates counts and total USD volume across `PAYMENT`, `TRANSFER`, `CASH_OUT`, `DEBIT`.
- **Risk Tier Distribution**: Grouped counts for `LOW` ($0-30$), `MEDIUM` ($31-70$), `HIGH` ($71-100$).
- **Legitimate vs Fraudulent Predictions**: Compares binary model classifications ($0$ vs $1$).
- **Chronological Score Trend**: Temporal variance in incoming transaction risk scores.

---

## 3. Incident Alert Triage & Investigation Lifecycle

1. **Alert Generation**: Triggered automatically when transaction risk score falls in the HIGH tier ($71-100$).
2. **Investigation**: Security officers can click "Investigate (SHAP)" to inspect the exact transaction inputs, prediction probabilities, and dynamic SHAP feature driver bars.
3. **Resolution**:
   - **Resolve with Notes**: Transitions alert status from `OPEN` to `RESOLVED`, recording the investigator's resolution rationale.
   - **Dismiss**: Records status as `DISMISSED` without deleting records from the audit trail.

---

## 4. Model Performance Registry & Drift Telemetry

- **Validation Benchmark Metrics** (Loaded from [ml/artifacts/model_metadata.json](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/ml/artifacts/model_metadata.json)):
  - **Precision**: $100.0\%$ (Zero False Positives on untouched test set)
  - **Recall**: $99.7\%$ (Detects $828/830$ fraud cases)
  - **F1-Score**: $0.9985$
  - **PR-AUC**: $0.9995$
  - **ROC-AUC**: $0.9999$
- **Feature & Data Drift Monitor**:
  - Compares the mean amount and high-risk proportion of recent transactions against the PaySim training baseline ($180,000$ USD mean, $0.13\%$ fraud rate).
  - Categorizes divergence into three operational states:
    - **`NORMAL`** (Divergence score $< 0.35$)
    - **`WARNING`** (Divergence score $0.35 - 0.70$)
    - **`DRIFT DETECTED`** (Divergence score $> 0.70$)

---

## 5. API Endpoints Specification

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/api/admin/check` | `GET` | `ADMIN` | Verifies administrative permissions. |
| `/api/admin/overview` | `GET` | `ADMIN` | Returns aggregated KPI counters and financial volume. |
| `/api/admin/analytics` | `GET` | `ADMIN` | Returns Chart.js structured datasets for volume, tiers, and trends. |
| `/api/admin/alerts` | `GET` | `ADMIN` | Returns filtered/paginated security incident alerts. |
| `/api/admin/alerts/<id>` | `GET` | `ADMIN` | Returns full alert detail with linked transaction and SHAP payload. |
| `/api/admin/alerts/<id>/resolve` | `POST` | `ADMIN` | Marks alert resolved with optional investigation notes. |
| `/api/admin/alerts/<id>/dismiss` | `POST` | `ADMIN` | Marks alert dismissed. |
| `/api/admin/transactions` | `GET` | `ADMIN` | Global transaction audit ledger with type and risk filters. |
| `/api/admin/model-info` | `GET` | `ADMIN` | Returns model registry metadata and real-time data drift telemetry. |

---

## 6. Test Suite Execution & Results

Executed:
```bash
py -m pytest -v
```

**SOC Test Module Coverage (`tests/test_admin_soc.py`)**:
- RBAC validation: Unauthenticated ($401$) and regular USER ($403$) access rejections.
- Analytics aggregations: Verified KPI counters on clean/empty databases and populated datasets.
- Alert triage lifecycle: Verified alert detail inspection, resolution with notes, and dismissal.
- Model telemetry & drift monitoring: Verified metadata retrieval and drift state scoring.
- Web route rendering: Verified `/admin/dashboard`, `/admin/alerts`, `/admin/transactions`, `/admin/model`.

All 93 tests across 13 test modules passed with 100% success.
