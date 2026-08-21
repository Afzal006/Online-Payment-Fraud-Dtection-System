# Frontend User Portal Architecture & Verification Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Phase**: Phase 10 — Frontend User Portal  
**Tech Stack**: HTML5, Vanilla CSS3 (Custom Fintech/Cybersecurity Design System), Vanilla JavaScript (Modular API Clients), Flask Jinja2 Templates  
**Report Date**: 2026-08-18  

---

## 1. Frontend System Architecture

The frontend is constructed using a modular, lightweight vanilla architecture served directly through Flask routing without heavyweight dependencies.

```
frontend/
├── static/
│   ├── css/
│   │   └── style.css            # Core design system tokens, glassmorphism, responsive styles
│   └── js/
│       ├── api.js               # Centralized API client, JWT token storage, toast notifications
│       ├── auth.js              # Login and registration form validation and handlers
│       ├── dashboard.js         # User dashboard metrics, recent transactions table
│       ├── payment.js           # Payment simulator form, live ML submission, result modal
│       ├── otp.js               # Adaptive OTP modal, 180s countdown timer, verification
│       ├── shap_drawer.js       # SHAP "Why was this flagged?" explainability drawer
│       └── history.js           # Full transaction ledger, search filters, detail inspection
└── templates/
    ├── base.html                # Global layout, navigation, modals, and drawers
    ├── login.html               # Sign in screen with test account autofill helper
    ├── register.html            # User registration form with client-side validation
    ├── dashboard.html           # User overview with stat cards and recent activity
    ├── payment.html             # Payment transfer simulator with quick test scenario presets
    └── history.html             # Transaction history table with search and risk filters
```

---

## 2. Core User Components & Interaction Flows

### A. Real-Time Transaction Result Modal
- **Dynamic Decision Display**: Immediately reflects backend classification after `POST /api/transactions/predict`:
  - `LOW` (0–30): Emerald green badge, auto-approved state (`APPROVED`).
  - `MEDIUM` (31–70): Amber badge, triggers interactive OTP verification button (`OTP_REQUIRED`).
  - `HIGH` (71–100): High-alert crimson badge, triggers OTP + flags administrative security alert (`UNDER_REVIEW`).
- **Explainability Launcher**: "Explain AI (SHAP)" button opens the slide-in explainability drawer.

### B. Adaptive OTP Challenge Modal
- **Countdown Timer**: 180-second visual countdown (`03:00`).
- **Cryptographic Security**: Zero plaintext OTPs in frontend storage; uses `POST /api/otp/verify`.
- **Attempt Tracking**: Displays remaining attempts; automatically displays rejection upon exhaustion.
- **Simulated Delivery Helper**: Emits debug preview in local development/testing while keeping production clean.

### C. SHAP "Why was this flagged?" Explainability Drawer
- **Visual Factor Bars**: Scaled horizontal indicator bars representing positive risk drivers (red/coral) vs legitimate factors (emerald).
- **Natural Language Synthesis**: Synthesizes the backend narrative describing the exact financial rationale behind the score.

### D. Payment Simulator with Quick Scenario Presets
- Allows seamless switching between predefined test scenarios:
  1. **Low Risk**: Coffee Payment ($15.50 to Merchant `M182390234`).
  2. **Medium Risk**: Mid-size Transfer ($3,500.00 to `C99881122`).
  3. **High Risk**: Complete Account Drain ($750,000.00 to `C44332211`).

---

## 3. Security & State Management Controls

1. **Zero Secret Exposure**: Passwords, hashes, and internal keys are never exposed or rendered in the DOM.
2. **Session Lifecycles**: Expired JWT tokens automatically clear `localStorage` and gracefully redirect the user to `/login?expired=1` with an explanatory toast.
3. **Role Enforcement**: Registration strictly assigns `role: 'USER'`. Admin capabilities are isolated from the client portal.

---

## 4. Verification & Testing

Executed complete test suite:
```bash
py -m pytest -v
```

**Automated Test Modules Tested**:
- `tests/test_frontend.py`: Verified template rendering for all pages (`/login`, `/register`, `/dashboard`, `/payment`, `/history`) and static asset delivery.
- `tests/test_adaptive_security.py`: Verified OTP challenge generation, rate limiting, and verification endpoints.
- `tests/test_prediction_api.py`: Verified ML inference & SHAP API contracts.
- `tests/test_auth.py` & `tests/test_database.py`: Verified authentication and schema integrity.

All 86 test cases across 12 test suites passed with 100% success.
