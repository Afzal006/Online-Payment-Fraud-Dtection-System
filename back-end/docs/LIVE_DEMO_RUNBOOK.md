# Live Demonstration Runbook (Step-by-Step Examiner Walkthrough)

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: FraudShield AI (with Internal Payment Platform & Admin SOC Center)  
**Document Version**: 3.0.0 (Customer Payment Identity, Beneficiaries, & Internal Payment Platform)  
**Date**: 2026-08-19  

---

## 1. Startup & Environment Preparation

### Step A: Start the Application & Seed Demo Data
1. Open a terminal in the project root: `c:\Users\AFZAL\Online Payment fraud detection system`
2. Ensure the virtual environment is active.
3. Initialize and seed the demo database with payment identities, demo customers, beneficiaries, and sample transactions:
   ```powershell
   py database/init_db.py; py database/seed_db.py
   ```
   *Expected Output*:
   ```
   [*] Initializing database for environment 'development'...
   [+] Successfully verified tables: ['alerts', 'beneficiaries', 'otp_challenges', 'transactions', 'users']
   [*] Seeding demo accounts for environment 'development'...
   [OK] Customer payment identities & balances seeded (FS-100001 .. FS-100004).
   [OK] Seeded 6 verified beneficiaries across demo customers.
   [OK] Admin user created: admin@example.com (Password: AdminDemo2026!)
   ```
4. Start the Flask web application:
   ```powershell
   py run.py
   ```
   *Expected Output*:
   ```
   * Running on http://127.0.0.1:5000
   * Application environment: development
   ```
5. Open your web browser and navigate to: `http://127.0.0.1:5000`

---

## 2. Customer User Demonstration Scenarios (Phase 1: Payment Identity & Beneficiaries)

### Demo Credentials Summary
| Role | Email | Password | Name | Customer Account ID | Primary UPI ID | Starting Balance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **User 1 (Primary)** | `user@example.com` | `UserDemo2026!` | Arjun Sharma | `FS-100001` | `arjun@fraudshield` | `₹1,50,000.00` |
| **Customer 1** | `customer1@example.com` | `UserDemo2026!` | Priya Patel | `FS-100002` | `priya@fraudshield` | `₹85,400.00` |
| **Customer 2** | `customer2@example.com` | `UserDemo2026!` | Vikram Malhotra | `FS-100003` | `vikram@fraudshield` | `₹2,40,000.00` |
| **Customer 3** | `customer3@example.com` | `UserDemo2026!` | Ananya Roy | `FS-100004` | `ananya@fraudshield` | `₹1,10,000.00` |
| **SOC Admin** | `admin@example.com` | `AdminDemo2026!` | SOC Admin Officer | `FS-ADMIN-01` | `admin@fraudshield` | `₹0.00` |

---

### Scenario B: Customer Payment Identity on Dashboard
- **URL**: `http://127.0.0.1:5000/login`
- **Actions**:
  1. Log in with `user@example.com` / `UserDemo2026!`.
  2. Observe the **Customer Payment Identity Card** at the top of the dashboard.
- **Expected UI Elements**:
  - **Account Holder**: `Arjun Sharma`
  - **Customer Account ID**: `FS-100001`
  - **Primary UPI ID**: `arjun@fraudshield`
  - **Phone Number**: `+91 98765 43210` with `✓ Verified` badge.
  - **Live Available Balance**: `₹1,50,000.00`
- **Examiner Commentary**:
  > *"Every registered customer receives an internal payment identity comprising a unique alphanumeric account identifier (FS-100001), primary UPI handle (username@fraudshield), verified phone number, and a live financial ledger balance."*

---

### Scenario C: Saved Beneficiaries Management (CRUD & IDOR Protection)
- **URL**: `http://127.0.0.1:5000/dashboard`
- **Actions**:
  1. View the **Saved Beneficiaries Directory** grid showing Priya Patel (`priya@fraudshield`) and Vikram Malhotra (`vikram@fraudshield`).
  2. Click **"+ Add Beneficiary"**.
  3. Enter:
     - **Beneficiary Full Name**: `Rohan Gupta`
     - **Beneficiary UPI ID**: `rohan@fraudshield`
     - **Phone Number**: `+91 98765 99999`
     - **Nickname**: `Gym Trainer`
  4. Click **"Save Beneficiary"** $\rightarrow$ Card appears instantly in grid.
  5. Click **"✏️"** to edit the nickname or name.
  6. Click **"🗑️"** to test beneficiary deletion.
- **Examiner Commentary**:
  > *"Beneficiaries are strictly isolated per customer (tenant isolation). The backend enforces server-side ownership checks on all GET, POST, PUT, and DELETE operations to prevent Insecure Direct Object Reference (IDOR) attacks."*

---

### Scenario D: Instant Approved Payment to Beneficiary with Balance Ledger Deduction
- **URL**: `http://127.0.0.1:5000/payment`
- **Actions**:
  1. Observe the **From Account** banner showing Available Balance: `₹1,50,000.00`.
  2. In the **To Recipient / Beneficiary** dropdown, select `👤 Priya Patel (Sister) — priya@fraudshield`.
  3. Notice the green **Verified Beneficiary** preview card appears automatically.
  4. Enter:
     - **Transaction Type**: `PAYMENT`
     - **Amount (₹ INR)**: `500.00`
     - **Payment Description**: `Dinner split`
  5. Click **"Submit & Verify Payment"**.
- **Expected Outcome**:
  - **Risk Score**: `< 15 / 100` (`LOW`)
  - **Status**: `APPROVED`
  - **Balance Before**: `₹1,50,000.00`
  - **Balance After**: `₹1,49,500.00` (Atomically deducted from ledger!)
  - Available balance on page updates immediately.
- **Examiner Commentary**:
  > *"When a transaction is classified as LOW risk and auto-approved, the backend financial ledger atomically deducts the transfer amount, records immutable balance snapshots (balance_before & balance_after), and updates the beneficiary's last_used_at timestamp."*

---

### Scenario E: Adaptive Step-up OTP with Ledger Hold & Atomic Deduction (HIGH Tier)
- **URL**: `http://127.0.0.1:5000/payment`
- **Actions**:
  1. Click preset **"🟡 ₹92,000 Transfer (Adaptive OTP)"**.
  2. Select `👤 Priya Patel — priya@fraudshield`.
  3. Click **"Submit & Verify Payment"**.
- **Expected Outcome**:
  - **Risk Tier**: `HIGH` (`60 – 79 / 100`, typically ~`65`)
  - **Engine Action**: `TRIGGER_OTP_VERIFICATION`
  - **Status**: `OTP_REQUIRED`
  - **Balance State**: Available balance remains `₹1,49,500.00` (funds are held, NOT deducted yet!).
  - **Security Alert**: `HIGH` severity alert created in SOC triage queue.
  4. Click **"Proceed to OTP Verification"**.
  5. In the OTP modal, enter the simulated 6-digit OTP code shown on screen.
  6. Click **"Verify & Authorize"**.
- **Expected Outcome**:
  - OTP verifies successfully.
  - Transaction transitions to `APPROVED`.
  - Balance is atomically deducted: `₹1,49,500.00 - ₹92,000.00 = ₹57,500.00`.
- **Examiner Commentary**:
  > *"For high-risk transfers requiring multi-factor authentication, funds are protected in the ledger and never deducted until the customer successfully validates their one-time challenge."*

---

### Scenario F: Critical-Risk Alert Triage & SOC Investigation (CRITICAL Tier)
- **URL**: `http://127.0.0.1:5000/payment`
- **Actions**:
  1. Click preset **"🔴 ₹2,50,001 High-Value Transfer"** (or ₹8,00,000 account drain).
  2. Click **"Submit & Verify Payment"**.
- **Expected Outcome**:
  - **Risk Tier**: `HIGH` or `CRITICAL` (`Risk Score ≥ 75/100`)
  - **Status**: `OTP_REQUIRED` or `UNDER_REVIEW`
  - **Balance**: Undeducted.
  - **Security Alert**: Created in SOC queue with `CRITICAL` severity for administrative review.
  3. Click **"🔍 Why Flagged? (SHAP)"** to inspect game-theoretic feature explanations (Customer Safe View).
  4. Notice the customer view provides natural language reasons without leaking internal weights.

---

## 3. Security Operations Center (SOC) Admin Walkthrough

### Scenario G: Global Customer Payment Identities Directory
- **URL**: `http://127.0.0.1:5000/admin/customers`
- **Actions**:
  1. Log in with `admin@example.com` / `AdminDemo2026!`.
  2. Click **"Customer Directory"** in the SOC navbar.
  3. Observe global customer list displaying:
     - Account ID (`FS-100001`, `FS-100002`, etc.)
     - Customer Name & Email
     - Primary UPI ID (`arjun@fraudshield`, etc.)
     - Phone with verification status
     - Current Live Ledger Balance
     - Number of Saved Beneficiaries
     - Total Volume & High-Risk Flags count
  4. Search dynamically by name, email, or UPI handle.
  5. Click **"View Customer →"** on Arjun Sharma.
- **Expected Customer Detail View**:
  - Full Payment Identity summary.
  - Customer's saved beneficiary network.
  - Complete chronological transaction history with balance after snapshots and audit controls.

### Scenario H: Model Comparison & Benchmark Inspection
- **Artifact**: `ml/artifacts/model_comparison.json`
- **Actions**:
  1. Review the model benchmark comparison across Logistic Regression, Decision Tree, Random Forest, and XGBoost:
     - **Random Forest (Champion)**: $F_1 = 0.9985$, $\text{Precision} = 1.0000$, $\text{Recall} = 0.9970$, $\text{PR-AUC} = 0.9971$.
     - **XGBoost**: $F_1 = 0.9896$, $\text{Precision} = 0.9824$, $\text{Recall} = 0.9970$, $\text{PR-AUC} = 0.9969$.
     - **Decision Tree**: $F_1 = 0.9265$, $\text{Precision} = 0.8653$, $\text{Recall} = 0.9970$.
     - **Logistic Regression**: $F_1 = 0.0445$, $\text{Precision} = 0.0228$, $\text{Recall} = 0.9582$.

### Scenario I: Secure Forgot Password & Password Reset Flow (Phase 2.5)
- **URL**: `http://127.0.0.1:5000/login`
- **Actions**:
  1. Click **"Forgot Password?"** link on the sign-in card.
  2. On `/forgot-password`, enter registered email: `user@example.com`.
  3. Click **"Send Reset Instructions"**.
  4. Observe the anti-enumeration confirmation panel and the Demo Mode Token banner.
  5. Click **"Proceed to Reset Password →"** (or open `/reset-password`).
  6. On `/reset-password`, note the auto-populated reset token.
  7. Enter new password: `NewPassword2026!` and confirm.
  8. Click **"Reset Password"** and observe the success confirmation.
  9. Log in with the updated password `NewPassword2026!` $\rightarrow$ observe successful sign-in.
  10. Attempt login with old password `UserDemo2026!` $\rightarrow$ observe 401 Unauthorized rejection.

---

## 4. Summary of Verification & Test Coverage

All test modules and **199 comprehensive automated tests** pass with a 100% success rate:
- **`tests/test_password_reset.py`** (24 Phase 2.5 security scenarios):
  - Anti-enumeration, cryptographic token hashing (SHA-256), token expiration (10m), single-use invalidation, attempt lockout (5 max), rate limiting (3 requests / 15m), and regression authentication.
- **`tests/test_risk_engine.py`** (17 test cases / 20 Phase 2 scenarios):
  - Multi-window velocity (1m, 10m, 1h, 24h), behavioral baselines, first-time beneficiary, rapid transactions, unusual off-hours, zero future-data leakage, 4-tier decision routing, dual-view explainability, and atomic balance deduction.
- **`tests/test_payment_identity.py`** (22 scenarios):
  - Models, balance check constraints, duplicate prevention, cascade deletion, profile APIs, beneficiary CRUD with strict IDOR protection.
- **`tests/test_admin_soc.py` & `tests/test_admin_portal_separation.py`** (26 scenarios):
  - Strict admin/consumer portal separation and multi-customer visibility.
- **`tests/test_hybrid_risk_engine.py` & `tests/test_shap.py`** (40 scenarios):
  - Machine learning Random Forest inference, policy floors, and TreeExplainer explainability.
