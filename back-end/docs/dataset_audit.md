# PaySim Dataset Audit & Exploratory Data Analysis Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Dataset File**: `PS_20174392719_1491204439457_log.csv`  
**File Size**: 470.67 MB (493,534,783 bytes)  
**Total Records**: 6,362,620 rows  
**Total Columns**: 11  
**Audit Date**: 2026-08-18  

---

## 1. Dataset Verification & Schema Integrity

All 11 expected PaySim columns are present and correctly structured:

| Column Name | Inferred Dtype | Expected Type | Status | Missing Values | Null % |
|---|---|---|---|---|---|
| `step` | `int64` | `int64` | Verified | 0 | 0.00% |
| `type` | `object` | `object` | Verified | 0 | 0.00% |
| `amount` | `float64` | `float64` | Verified | 0 | 0.00% |
| `nameOrig` | `object` | `object` | Verified | 0 | 0.00% |
| `oldbalanceOrg` | `float64` | `float64` | Verified | 0 | 0.00% |
| `newbalanceOrig` | `float64` | `float64` | Verified | 0 | 0.00% |
| `nameDest` | `object` | `object` | Verified | 0 | 0.00% |
| `oldbalanceDest` | `float64` | `float64` | Verified | 0 | 0.00% |
| `newbalanceDest` | `float64` | `float64` | Verified | 0 | 0.00% |
| `isFraud` | `int64` | `int64` | Verified | 0 | 0.00% |
| `isFlaggedFraud` | `int64` | `int64` | Verified | 0 | 0.00% |

- **Missing / Null Values**: 0 nulls detected across all 6,362,620 rows.
- **Duplicate Rows**: No exact duplicate rows were detected across the 11 available columns. (Note: The PaySim dataset does not provide a dedicated transaction ID column; account identifiers `nameOrig` and `nameDest` represent participating parties).

---

## 2. Target Variable Analysis (`isFraud`)

- **Total Transactions**: 6,362,620
- **Legitimate Transactions (Class 0)**: 6,354,407 (99.8709%)
- **Fraudulent Transactions (Class 1)**: 8,213 (0.1291%)
- **Imbalance Ratio**: **773.7 : 1** (Approximately 1 fraud per 774 transactions)

### Transaction Types and Fraud Breakdown

| Transaction Type | Total Count | % of Dataset | Fraud Count | Fraud Rate |
|---|---|---|---|---|
| `CASH_OUT` | 2,237,500 | 35.17% | 4,116 | 0.1840% |
| `PAYMENT` | 2,151,495 | 33.81% | 0 | 0.0000% |
| `CASH_IN` | 1,399,284 | 21.99% | 0 | 0.0000% |
| `TRANSFER` | 532,909 | 8.38% | 4,097 | 0.7688% |
| `DEBIT` | 41,432 | 0.65% | 0 | 0.0000% |

> **Dataset-Specific Observation**: In the synthetic PaySim dataset, labeled fraud occurs **only** in `TRANSFER` and `CASH_OUT` transactions (split roughly 50/50). This is a characteristic of how the PaySim simulation was constructed; in real-world payment environments, payment card and debit mechanisms can also experience fraud.

---

## 3. Analysis of Rule-Based Indicator (`isFlaggedFraud`)

- **Total Transactions Flagged by Naive Rule**: 16
- **Flagged & Actually Fraud**: 16
- **Flagged & Legitimate (False Positive)**: 0
- **Unflagged but Actually Fraud (False Negative)**: 8,197
- **Rule Definition**: The dataset flags `TRANSFER` transactions where `amount > 200,000`.
- **Target Leakage / Dependency Assessment**:
  `isFlaggedFraud` detects only 16 out of 8,213 fraudulent transactions (0.19% recall). Including `isFlaggedFraud` as an input feature would introduce artificial reliance on a trivial rule. 
  **Recommendation**: `isFlaggedFraud` is **EXCLUDED** from the primary ML model input, but retained as a separate rule-based baseline for comparison and auditing.

---

## 4. Numerical Features Summary Statistics

| Feature | Min | Max | Mean | Std | 25% | Median | 75% | Zero Count (%) |
|---|---|---|---|---|---|---|---|---|
| `step` | 1.00 | 743.00 | 243.40 | 142.33 | 156.00 | 239.00 | 335.00 | 0 (0.0%) |
| `amount` | 0.00 | 92,445,516.64 | 179,861.90 | 603,858.18 | 13,306.53 | 74,907.91 | 209,130.52 | 16 (0.0%) |
| `oldbalanceOrg` | 0.00 | 59,585,040.37 | 833,883.10 | 2,888,242.45 | 0.00 | 14,321.50 | 107,692.75 | 2,102,449 (33.0%) |
| `newbalanceOrig` | 0.00 | 49,585,040.37 | 855,113.67 | 2,924,048.27 | 0.00 | 0.00 | 144,850.20 | 3,609,566 (56.7%) |
| `oldbalanceDest` | 0.00 | 356,015,889.35 | 1,100,701.67 | 3,399,179.85 | 0.00 | 131,092.55 | 941,609.90 | 2,704,388 (42.5%) |
| `newbalanceDest` | 0.00 | 356,179,278.92 | 1,224,996.40 | 3,674,128.65 | 0.00 | 213,245.52 | 1,113,301.32 | 2,439,433 (38.3%) |

---

## 5. Temporal & Step Feature Analysis

In PaySim, `step` represents simulation hours ($1 \text{ step} = 1 \text{ hour}$, spanning 743 steps $\approx 31$ days).
Rather than making an arbitrary choice, we will empirically evaluate three candidate temporal representations during ML baseline and model validation:
1. **Option A (`hourOfDay = step % 24`)**: Cyclical 24-hour diurnal pattern ($0 \dots 23$).
2. **Option B (`raw step`)**: Continuous time counter across the simulation duration.
3. **Option C (`raw step + hourOfDay`)**: Combined representation capturing both macro-trend and diurnal cycle.

The final temporal feature selection will be determined by validation evidence and real-time operational feasibility.

---

## 6. Real-Time Feature Availability Matrix & Production Limitations

In real-world payment authorization, there is a fundamental distinction between:
- **Pre-authorization features**: Features known *before* the transaction is authorized (e.g., requested amount, transaction type, sender account balance, recipient identifier, time).
- **Post-authorization features**: Features that materialize only *after* the transaction has completed settlement or ledger reconciliation (e.g., recipient actual balance, post-transaction ledger state).

### Comprehensive Feature Availability Matrix

| Feature | Available Before Authorization? | Derived? | Data Source | Recommended Use in Pipeline |
|---|---|---|---|---|
| `type` | **Yes** | No | Payment form selection / API payload | **Include** as primary categorical feature (One-Hot Encoded) |
| `amount` | **Yes** | No | Payment form / API payload | **Include** as primary numeric feature |
| `nameOrig` | **Yes** | No | Authenticated user session | **Exclude** from ML input (high-cardinality string; prevents memorization) |
| `nameDest` | **Yes** | No | Recipient identifier input | **Exclude** raw string; distill into binary `isMerchantDest` |
| `oldbalanceOrg` | **Yes** | No | Internal core banking ledger / DB | **Include** as primary numeric feature |
| `newbalanceOrig` | **Conditionally / Post-Tx** | No (in raw) / Yes (simulated) | Post-tx ledger state / estimated pre-tx | **Include** in PaySim baseline, but prioritize pre-tx balance features for inference |
| `oldbalanceDest` | **No (External) / Yes (Internal)** | No | Recipient ledger (often unavailable externally) | **Include** in PaySim baseline; document cross-bank availability limitation |
| `newbalanceDest` | **No (Post-Tx)** | No | Post-tx recipient ledger | **Include** in PaySim baseline; document post-tx settlement limitation |
| `step` | **Yes** | No | Simulation timestamp | **Evaluate** across Options A/B/C during Phase 2 |
| `hourOfDay` | **Yes** | Yes (`step % 24` or system clock) | System clock / timestamp derivation | **Include** as diurnal temporal feature |
| `isMerchantDest` | **Yes** | Yes (`nameDest.startswith('M')`) | Recipient ID prefix check | **Include** as binary indicator |
| `errorBalanceOrig` | **Yes** | Yes (`oldbalanceOrg - amount - newbalanceOrig`) | Mathematical balance check | **Include** (identifies balance draining / anomalies) |
| `errorBalanceDest` | **Conditional** | Yes (`oldbalanceDest + amount - newbalanceDest`) | Mathematical balance check | **Include** for PaySim alignment; document ledger assumption |
| `amountToBalanceRatio` | **Yes** | Yes (`amount / (oldbalanceOrg + 1)`) | Pre-tx calculation | **Include** (classic account drain signal) |
| `isFraud` | **No** | No | Supervised ground truth | **Target Variable** (strictly excluded from input) |
| `isFlaggedFraud` | **Yes** (Rule output) | Yes | Static heuristic (`amount > 200k`) | **Exclude** from primary ML model; retain for baseline comparison |

> **Documented PaySim Limitation**: In a real-world multi-bank payment gateway, recipient balances (`oldbalanceDest`, `newbalanceDest`) are not disclosed to the sender's bank before authorization. Similarly, `newbalanceOrig` in PaySim reflects simulation ledger changes rather than a simple mathematical subtraction `oldbalanceOrg - amount`. The system acknowledges this simulation characteristic while prioritizing pre-authorization signals.

---

## 7. Logical Features vs. Transformed Matrix Columns

The project specifies **11 logical domain features**:
1. `type` (Categorical: `CASH_OUT`, `TRANSFER`, `PAYMENT`, `CASH_IN`, `DEBIT`)
2. `amount` (Numeric)
3. `oldbalanceOrg` (Numeric)
4. `newbalanceOrig` (Numeric)
5. `oldbalanceDest` (Numeric)
6. `newbalanceDest` (Numeric)
7. `errorBalanceOrig` (Engineered Numeric)
8. `errorBalanceDest` (Engineered Numeric)
9. `hourOfDay` (Engineered Numeric, with raw `step` evaluated in tuning)
10. `isMerchantDest` (Engineered Binary)
11. `amountToBalanceRatio` (Engineered Numeric)

When `type` is one-hot encoded via `OneHotEncoder(handle_unknown='ignore')`, the resulting model input matrix expands to **15 numerical columns** (5 one-hot columns + 10 numeric features).

---

## 8. Target Leakage & Feature Decisions

### Features EXCLUDED from Model Input:
1. `isFraud`: Target variable (supervised ground truth).
2. `isFlaggedFraud`: Naive baseline rule; causes leakage and trivial reliance.
3. `nameOrig`: High-cardinality account IDs (unique per user; causes memorization and overfitting).
4. `nameDest`: High-cardinality recipient IDs (distilled into `isMerchantDest`).

---

## 9. Real-Time Inference Availability & Frontend Mapping

During an online payment request, the frontend form and backend session supply:
- `amount` (User input)
- `type` (User dropdown selection)
- `nameDest` (Recipient account / merchant ID)
- `oldbalanceOrg` (Retrieved from authenticated user's current account balance in DB)
- `newbalanceOrig` (Estimated for PaySim compatibility: `max(0, oldbalanceOrg - amount)`)
- `oldbalanceDest` (Retrieved or default `0.0` for external accounts)
- `newbalanceDest` (Estimated: `oldbalanceDest + amount`)
- `hourOfDay` / `step` (Derived from current system clock `datetime.now().hour`)

The feature service computes `errorBalanceOrig`, `errorBalanceDest`, `isMerchantDest`, and `amountToBalanceRatio` on the fly before passing the feature vector to the ML inference pipeline.

---

## 10. Recommended Preprocessing & Imbalance Strategy

1. **Preprocessing Pipeline**:
   - `ColumnTransformer` with `OneHotEncoder(handle_unknown='ignore')` for `type`.
   - Passthrough for tree models (Random Forest, Decision Tree, XGBoost); `StandardScaler` for Logistic Regression baseline.
2. **Class Imbalance Strategy**:
   - Use `stratify=y` on train/test split.
   - Tree models: `class_weight='balanced'` or `scale_pos_weight`.
   - SMOTE / undersampling evaluated only on the training split (never across test set).
3. **Split & Random Seed**:
   - Stratified Split: 80% Train, 20% Test.
   - Fixed `random_state = 42`.
4. **Primary Evaluation Metrics**:
   - Precision, Recall, F1-Score, PR-AUC, ROC-AUC, and Confusion Matrix.
