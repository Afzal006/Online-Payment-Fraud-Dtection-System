# PaySim Dataset Setup Instructions

## 1. Required Dataset
This project requires the **PaySim synthetic online payments fraud detection dataset**:
- **Dataset Name**: Kaggle — *"Online Payments Fraud Detection Dataset"* (PaySim Synthetic Financial Datasets for Fraud Detection)
- **Source**: Kaggle / Academic Open Source
- **Size**: ~6.3 million transactions (~470MB uncompressed CSV)

---

## 2. Where to Place the Dataset
Place the raw CSV file inside the project's `dataset/` directory:
```
Online Payment fraud detection system/
└── dataset/
    ├── .gitkeep
    └── PS_20174392719_1491204439457_log.csv   <-- Place your dataset file here
```

### Accepted Filenames
The dataset discovery utility will automatically search for any of the following standard filenames in `dataset/`:
1. `PS_20174392719_1491204439457_log.csv` (Default Kaggle filename)
2. `fraud_detection.csv`
3. `onlinefraud.csv`
4. `paysim.csv`
5. `dataset.csv`
6. Any `.csv` file placed inside `dataset/`

---

## 3. Expected Dataset Format & Columns
The CSV file must contain the following 11 raw columns:

| Column Name | Data Type | Description |
|---|---|---|
| `step` | Integer | Time step unit (1 step = 1 hour of simulation) |
| `type` | String | Transaction type: `CASH_OUT`, `TRANSFER`, `PAYMENT`, `CASH_IN`, `DEBIT` |
| `amount` | Float | Amount of the transaction in local currency |
| `nameOrig` | String | Customer who started the transaction |
| `oldbalanceOrg` | Float | Initial balance of sender before the transaction |
| `newbalanceOrig` | Float | New balance of sender after the transaction |
| `nameDest` | String | Recipient ID of the transaction |
| `oldbalanceDest` | Float | Initial balance of recipient before the transaction |
| `newbalanceDest` | Float | New balance of recipient after the transaction |
| `isFraud` | Integer (0 or 1) | Ground truth target (1 = Fraudulent, 0 = Legitimate) |
| `isFlaggedFraud` | Integer (0 or 1) | Rule-based flag (excluded from ML features) |

---

## 4. Dataset Audit Requirement
Before proceeding to ML model training (Phase 1+), the actual dataset placed in `dataset/` will be audited for:
- Exact column schema match
- Missing values and null handling
- Duplicate rows
- Class imbalance distribution (~0.1% fraud rate expected)
- Data types and range validation

---

## 5. Verification Command
To verify whether the dataset is present without running a full training pipeline:
```bash
python ml/check_dataset.py
```
