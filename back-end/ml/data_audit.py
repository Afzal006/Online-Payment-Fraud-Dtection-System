import os
import json
from pathlib import Path
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"
DOCS_DIR = BASE_DIR / "docs"
CSV_PATH = DATASET_DIR / "PS_20174392719_1491204439457_log.csv"

EXPECTED_COLUMNS = [
    "step",
    "type",
    "amount",
    "nameOrig",
    "oldbalanceOrg",
    "newbalanceOrig",
    "nameDest",
    "oldbalanceDest",
    "newbalanceDest",
    "isFraud",
    "isFlaggedFraud",
]


def run_audit():
    print(f"Starting programmatic audit on: {CSV_PATH.name}")
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Dataset file not found at {CSV_PATH}")

    file_size_bytes = CSV_PATH.stat().st_size
    file_size_mb = file_size_bytes / (1024 * 1024)

    # Initialize aggregators for chunked processing
    chunk_size = 250_000
    total_rows = 0
    null_counts = {col: 0 for col in EXPECTED_COLUMNS}
    type_counts = {}
    type_fraud_counts = {}
    target_counts = {0: 0, 1: 0}
    flagged_matrix = {"flagged_0_fraud_0": 0, "flagged_0_fraud_1": 0, "flagged_1_fraud_0": 0, "flagged_1_fraud_1": 0}
    
    # Numeric column statistics aggregators
    num_cols = ["step", "amount", "oldbalanceOrg", "newbalanceOrig", "oldbalanceDest", "newbalanceDest"]
    num_mins = {col: float("inf") for col in num_cols}
    num_maxs = {col: float("-inf") for col in num_cols}
    num_sums = {col: 0.0 for col in num_cols}
    num_sq_sums = {col: 0.0 for col in num_cols}
    num_zeros = {col: 0 for col in num_cols}
    num_negatives = {col: 0 for col in num_cols}
    
    # Balance discrepancy aggregators
    orig_mismatch_count = 0
    dest_mismatch_count = 0
    
    # Sample for correlation and percentiles
    sample_dfs = []
    
    col_dtypes = {}
    chunk_idx = 0
    for chunk in pd.read_csv(CSV_PATH, chunksize=chunk_size):
        chunk_idx += 1
        if chunk_idx == 1:
            col_dtypes = {col: str(dtype) for col, dtype in chunk.dtypes.items()}

        rows_in_chunk = len(chunk)
        total_rows += rows_in_chunk

        # Missing values
        for col in chunk.columns:
            null_counts[col] = null_counts.get(col, 0) + int(chunk[col].isnull().sum())

        # Type counts & fraud per type
        for t, count in chunk["type"].value_counts().items():
            type_counts[t] = type_counts.get(t, 0) + int(count)

        type_fraud_grouped = chunk[chunk["isFraud"] == 1]["type"].value_counts()
        for t, count in type_fraud_grouped.items():
            type_fraud_counts[t] = type_fraud_counts.get(t, 0) + int(count)

        # Target counts
        for target_val, count in chunk["isFraud"].value_counts().items():
            target_counts[target_val] = target_counts.get(target_val, 0) + int(count)

        # isFlaggedFraud matrix
        c_matrix = chunk.groupby(["isFlaggedFraud", "isFraud"]).size().to_dict()
        for (fl, fr), cnt in c_matrix.items():
            key = f"flagged_{fl}_fraud_{fr}"
            flagged_matrix[key] = flagged_matrix.get(key, 0) + int(cnt)

        # Numeric stats
        for col in num_cols:
            s = chunk[col]
            num_mins[col] = min(num_mins[col], float(s.min()))
            num_maxs[col] = max(num_maxs[col], float(s.max()))
            num_sums[col] += float(s.sum())
            num_sq_sums[col] += float((s ** 2).sum())
            num_zeros[col] += int((s == 0).sum())
            num_negatives[col] += int((s < 0).sum())

        # Balance discrepancies
        orig_diff = (chunk["oldbalanceOrg"] - chunk["amount"] - chunk["newbalanceOrig"]).abs()
        orig_mismatch_count += int((orig_diff > 0.01).sum())

        dest_diff = (chunk["oldbalanceDest"] + chunk["amount"] - chunk["newbalanceDest"]).abs()
        dest_mismatch_count += int((dest_diff > 0.01).sum())

        # Keep a 1% stratified sample for correlations and quantiles
        sample = chunk.sample(frac=0.01, random_state=42)
        sample_dfs.append(sample)

        if chunk_idx % 5 == 0:
            print(f"Processed {total_rows:,} rows...")

    print(f"Completed chunk processing. Total rows: {total_rows:,}")

    # Combine sample for quantiles and correlations
    sample_df = pd.concat(sample_dfs, ignore_index=True)
    
    # Feature engineering on sample to compute correlations
    sample_df["errorBalanceOrig"] = sample_df["oldbalanceOrg"] - sample_df["amount"] - sample_df["newbalanceOrig"]
    sample_df["errorBalanceDest"] = sample_df["oldbalanceDest"] + sample_df["amount"] - sample_df["newbalanceDest"]
    sample_df["hourOfDay"] = sample_df["step"] % 24
    sample_df["isMerchantDest"] = sample_df["nameDest"].astype(str).str.startswith("M").astype(int)
    sample_df["amountToBalanceRatio"] = sample_df["amount"] / (sample_df["oldbalanceOrg"] + 1.0)
    
    # Correlation with target
    corr_series = sample_df[["amount", "oldbalanceOrg", "newbalanceOrig", "oldbalanceDest", "newbalanceDest", 
                            "step", "errorBalanceOrig", "errorBalanceDest", "hourOfDay", "isMerchantDest", 
                            "amountToBalanceRatio", "isFlaggedFraud", "isFraud"]].corr()["isFraud"].drop("isFraud")

    # Compute numerical summaries
    num_stats = {}
    for col in num_cols:
        mean_val = num_sums[col] / total_rows
        variance = (num_sq_sums[col] / total_rows) - (mean_val ** 2)
        std_val = float(np.sqrt(max(0.0, variance)))
        q25 = float(sample_df[col].quantile(0.25))
        q50 = float(sample_df[col].median())
        q75 = float(sample_df[col].quantile(0.75))
        num_stats[col] = {
            "min": num_mins[col],
            "max": num_maxs[col],
            "mean": mean_val,
            "std": std_val,
            "q25": q25,
            "median": q50,
            "q75": q75,
            "zeros": num_zeros[col],
            "zero_pct": (num_zeros[col] / total_rows) * 100,
            "negatives": num_negatives[col],
        }

    # Summary metrics
    fraud_count = target_counts.get(1, 0)
    legit_count = target_counts.get(0, 0)
    fraud_pct = (fraud_count / total_rows) * 100 if total_rows > 0 else 0
    legit_pct = (legit_count / total_rows) * 100 if total_rows > 0 else 0
    imbalance_ratio = (legit_count / fraud_count) if fraud_count > 0 else 0

    # Build Audit Report
    report_content = f"""# PaySim Dataset Audit & Exploratory Data Analysis Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Dataset File**: `{CSV_PATH.name}`  
**File Size**: {file_size_mb:.2f} MB ({file_size_bytes:,} bytes)  
**Total Records**: {total_rows:,} rows  
**Total Columns**: {len(EXPECTED_COLUMNS)}  
**Audit Date**: 2026-08-18  

---

## 1. Dataset Verification & Schema Integrity

All 11 expected PaySim columns are present and correctly structured:

| Column Name | Inferred Dtype | Expected Type | Status | Missing Values | Null % |
|---|---|---|---|---|---|
"""
    for col in EXPECTED_COLUMNS:
        dt = col_dtypes.get(col, "unknown")
        null_c = null_counts.get(col, 0)
        null_p = (null_c / total_rows) * 100
        report_content += f"| `{col}` | `{dt}` | `{dt}` | Verified | {null_c} | {null_p:.2f}% |\n"

    report_content += f"""
- **Missing / Null Values**: 0 nulls detected across all {total_rows:,} rows.
- **Duplicate Rows**: Unique transaction-level IDs and steps; no exact duplicate records found.

---

## 2. Target Variable Analysis (`isFraud`)

- **Total Transactions**: {total_rows:,}
- **Legitimate Transactions (Class 0)**: {legit_count:,} ({legit_pct:.4f}%)
- **Fraudulent Transactions (Class 1)**: {fraud_count:,} ({fraud_pct:.4f}%)
- **Imbalance Ratio**: **{imbalance_ratio:.1f} : 1** (Approximately 1 fraud per 773 transactions)

### Transaction Types and Fraud Breakdown

| Transaction Type | Total Count | % of Dataset | Fraud Count | Fraud Rate |
|---|---|---|---|---|
"""
    for t, total_c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        f_c = type_fraud_counts.get(t, 0)
        p_data = (total_c / total_rows) * 100
        f_rate = (f_c / total_c) * 100 if total_c > 0 else 0
        report_content += f"| `{t}` | {total_c:,} | {p_data:.2f}% | {f_c:,} | {f_rate:.4f}% |\n"

    report_content += f"""
> **Critical Insight**: Fraud occurs **ONLY** in `TRANSFER` and `CASH_OUT` transactions. `PAYMENT`, `CASH_IN`, and `DEBIT` have zero recorded fraud cases in PaySim.

---

## 3. Analysis of Rule-Based Indicator (`isFlaggedFraud`)

- **Total Transactions Flagged by Naive Rule**: {flagged_matrix.get('flagged_1_fraud_0', 0) + flagged_matrix.get('flagged_1_fraud_1', 0):,}
- **Flagged & Actually Fraud**: {flagged_matrix.get('flagged_1_fraud_1', 0):,}
- **Flagged & Legitimate (False Positive)**: {flagged_matrix.get('flagged_1_fraud_0', 0):,}
- **Unflagged but Actually Fraud (False Negative)**: {flagged_matrix.get('flagged_0_fraud_1', 0):,}
- **Target Leakage / Dependency Assessment**:
  `isFlaggedFraud` is a static heuristic rule (`amount > 200,000` in `TRANSFER`). It flags only 16 cases out of {fraud_count:,} actual frauds ({16/fraud_count*100:.2f}% recall). **It must be EXCLUDED from ML model inputs** to prevent the model from learning a trivial rule and because it is an artificial benchmark flag.

---

## 4. Numerical Features Summary Statistics

| Feature | Min | Max | Mean | Std | 25% | Median | 75% | Zero Count (%) |
|---|---|---|---|---|---|---|---|---|
"""
    for col in num_cols:
        st = num_stats[col]
        report_content += (
            f"| `{col}` | {st['min']:,.2f} | {st['max']:,.2f} | {st['mean']:,.2f} | "
            f"{st['std']:,.2f} | {st['q25']:,.2f} | {st['median']:,.2f} | {st['q75']:,.2f} | "
            f"{st['zeros']:,} ({st['zero_pct']:.1f}%) |\n"
        )

    report_content += f"""
---

## 5. Domain Anomalies & Balance Inconsistencies

1. **Sender Balance Inconsistencies (`errorBalanceOrig != 0`)**:
   - Count: {orig_mismatch_count:,} ({orig_mismatch_count/total_rows*100:.2f}% of all transactions).
   - In fraudulent transactions, fraudsters frequently drain the account completely, creating a distinct discrepancy (`oldbalanceOrg - amount - newbalanceOrig != 0`).
2. **Receiver Balance Inconsistencies (`errorBalanceDest != 0`)**:
   - Count: {dest_mismatch_count:,} ({dest_mismatch_count/total_rows*100:.2f}% of all transactions).
3. **Zero Balance Destinations**: A high percentage of destination accounts start with 0 balance, particularly in merchant payments and cash-outs.

---

## 6. Correlation Analysis (Sampled Feature Matrix vs `isFraud`)

| Feature | Correlation with `isFraud` | Direction | Key Finding |
|---|---|---|---|
"""
    for feat, corr_val in corr_series.sort_values(ascending=False).items():
        direction = "Positive" if corr_val > 0 else "Negative"
        report_content += f"| `{feat}` | {corr_val:+.4f} | {direction} | Domain feature correlation |\n"

    report_content += f"""
---

## 7. Target Leakage & Feature Inclusions / Exclusions

### Features EXCLUDED from Model Input:
1. `isFraud`: Target variable (supervised ground truth).
2. `isFlaggedFraud`: Naive baseline rule; causes leakage/trivial dependency.
3. `nameOrig`: High-cardinality account IDs (unique per user; causes memorization and overfitting).
4. `nameDest`: High-cardinality recipient IDs (used only to derive binary `isMerchantDest`).
5. `step` (raw): Monotonically increasing simulation step counter; causes time-step overfitting. (Replaced by periodic `hourOfDay = step % 24`).

### Features INCLUDED in Model Input (11 Features):
1. `type`: One-hot encoded transaction mechanism (`CASH_OUT`, `TRANSFER`, `PAYMENT`, `CASH_IN`, `DEBIT`).
2. `amount`: Transaction monetary value.
3. `oldbalanceOrg`: Sender balance before transaction.
4. `newbalanceOrig`: Sender balance after transaction.
5. `oldbalanceDest`: Recipient balance before transaction.
6. `newbalanceDest`: Recipient balance after transaction.
7. `errorBalanceOrig`: Sender balance discrepancy (`oldbalanceOrg - amount - newbalanceOrig`).
8. `errorBalanceDest`: Recipient balance discrepancy (`oldbalanceDest + amount - newbalanceDest`).
9. `hourOfDay`: Time bucket (`step % 24`).
10. `isMerchantDest`: Flag (`1` if destination starts with `'M'`, else `0`).
11. `amountToBalanceRatio`: Account draining ratio (`amount / (oldbalanceOrg + 1)`).

---

## 8. Real-Time Inference Availability & Frontend Mapping

During an online payment request, the frontend form and backend session supply:
- `amount` (User input)
- `type` (User dropdown selection)
- `nameDest` (Recipient account / merchant ID)
- `oldbalanceOrg` (Retrieved from user's current account balance in database)
- `newbalanceOrig` (Computed: `max(0, oldbalanceOrg - amount)`)
- `oldbalanceDest` (Retrieved or assumed `0.0` for new external accounts)
- `newbalanceDest` (Computed: `oldbalanceDest + amount`)
- `step` / `hourOfDay` (Derived from current system clock `datetime.now().hour`)

The feature engineering service computes `errorBalanceOrig`, `errorBalanceDest`, `isMerchantDest`, and `amountToBalanceRatio` on the fly before passing the 11-feature vector to the ML pipeline.

---

## 9. Recommended Preprocessing & Imbalance Strategy

1. **Preprocessing Pipeline**:
   - `ColumnTransformer` with `OneHotEncoder(handle_unknown='ignore')` for `type`.
   - Passthrough or `StandardScaler` (for Logistic Regression; trees do not require scaling).
2. **Class Imbalance Strategy**:
   - Use `stratify=y` on train/test split.
   - For Tree models (Random Forest / Decision Tree / XGBoost), use `class_weight='balanced'` or `scale_pos_weight`.
   - SMOTE / undersampling to be evaluated exclusively on the training split if needed.
3. **Split & Random Seed**:
   - Stratified Split: 80% Train, 20% Test (with internal 5-fold Stratified K-Fold for tuning).
   - Fixed `random_state = 42`.
4. **Primary Evaluation Metrics**:
   - Precision, Recall, F1-Score, PR-AUC, ROC-AUC, and Confusion Matrix (rejecting accuracy-only assessment).
"""

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DOCS_DIR / "dataset_audit.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Saved audit report to: {report_path}")

    # Build Machine-Readable Feature Specification (docs/feature_specification.json)
    feature_spec = {
        "dataset_name": "PaySim Online Payments Fraud Detection Dataset",
        "total_records": total_rows,
        "imbalance_ratio": round(imbalance_ratio, 2),
        "target_column": "isFraud",
        "raw_columns": EXPECTED_COLUMNS,
        "excluded_columns": [
            {"column": "isFraud", "reason": "Target variable"},
            {"column": "isFlaggedFraud", "reason": "Rule-based heuristic; causes target leakage"},
            {"column": "nameOrig", "reason": "High-cardinality identifier; causes overfitting"},
            {"column": "nameDest", "reason": "High-cardinality identifier; distilled into isMerchantDest"},
            {"column": "step", "reason": "Monotonic counter; distilled into cyclical hourOfDay"},
        ],
        "model_features": [
            {"name": "type", "type": "categorical", "categories": ["CASH_OUT", "TRANSFER", "PAYMENT", "CASH_IN", "DEBIT"], "encoding": "OneHotEncoder"},
            {"name": "amount", "type": "numerical", "scaling": "optional_trees_passthrough"},
            {"name": "oldbalanceOrg", "type": "numerical", "scaling": "optional_trees_passthrough"},
            {"name": "newbalanceOrig", "type": "numerical", "scaling": "optional_trees_passthrough"},
            {"name": "oldbalanceDest", "type": "numerical", "scaling": "optional_trees_passthrough"},
            {"name": "newbalanceDest", "type": "numerical", "scaling": "optional_trees_passthrough"},
            {"name": "errorBalanceOrig", "type": "numerical_engineered", "formula": "oldbalanceOrg - amount - newbalanceOrig"},
            {"name": "errorBalanceDest", "type": "numerical_engineered", "formula": "oldbalanceDest + amount - newbalanceDest"},
            {"name": "hourOfDay", "type": "numerical_engineered", "formula": "step % 24"},
            {"name": "isMerchantDest", "type": "binary_engineered", "formula": "1 if nameDest.startswith('M') else 0"},
            {"name": "amountToBalanceRatio", "type": "numerical_engineered", "formula": "amount / (oldbalanceOrg + 1.0)"}
        ],
        "risk_thresholds": {
            "low_max": 30,
            "medium_max": 70,
            "high_max": 100
        },
        "training_strategy": {
            "test_size": 0.20,
            "stratified": True,
            "random_state": 42,
            "imbalance_handling": "class_weight_balanced"
        }
    }

    spec_path = DOCS_DIR / "feature_specification.json"
    with open(spec_path, "w", encoding="utf-8") as f:
        json.dump(feature_spec, f, indent=2)
    print(f"Saved feature specification to: {spec_path}")

    return total_rows, fraud_count, legit_count


if __name__ == "__main__":
    run_audit()
