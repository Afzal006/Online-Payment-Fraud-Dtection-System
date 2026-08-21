# Machine Learning & Explainable AI (SHAP) Architecture

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  

---

## 1. Dataset Characteristics & Audit Findings

The machine learning subsystem is trained on the comprehensive **PaySim financial simulation benchmark dataset**:

- **Total Transactions**: $6,362,620$ records
- **Class Distribution**:
  - Legitimate Transactions ($y=0$): $6,354,407$ ($99.8709\%$)
  - Fraudulent Transactions ($y=1$): $8,213$ ($0.1291\%$)
  - **Severe Class Imbalance Ratio**: $\approx 773.7 : 1$
- **Audit Findings**:
  - Zero missing/null values across all columns.
  - Fraud instances occur exclusively within `TRANSFER` and `CASH_OUT` transaction types.
  - No exact duplicate records found across the 11 raw columns.
  - Target labels (`isFraud`, `isFlaggedFraud`), high-cardinality IDs (`nameOrig`, `nameDest`), and monotonically increasing simulation timestamps (`step`) were identified as leakage hazards and excluded from model inputs.

---

## 2. Leakage-Safe Feature Engineering Pipeline

The system engineers **11 domain-specific financial features** ([feature_specification.json](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/docs/feature_specification.json)) transformed into a 15-dimensional numeric space via `ColumnTransformer`:

### Feature Engineering Formulas:
1. **`errorBalanceOrig`**: Discrepancy in sender balance after transfer:
   $$\text{errorBalanceOrig} = \text{oldbalanceOrg} - \text{newbalanceOrig} - \text{amount}$$
2. **`errorBalanceDest`**: Discrepancy in recipient balance after transfer:
   $$\text{errorBalanceDest} = \text{oldbalanceDest} + \text{amount} - \text{newbalanceDest}$$
3. **`amount_to_oldbalance_orig_ratio`**: Proportion of sender's balance being moved (division-by-zero protected):
   $$\text{ratio}_{\text{orig}} = \frac{\text{amount}}{\text{oldbalanceOrg} + 1.0}$$
4. **`amount_to_oldbalance_dest_ratio`**: Proportion of recipient's balance being credited:
   $$\text{ratio}_{\text{dest}} = \frac{\text{amount}}{\text{oldbalanceDest} + 1.0}$$
5. **`hourOfDay`**: Cyclic temporal hour extracted from simulation step:
   $$\text{hourOfDay} = \text{step} \pmod{24}$$
6. **`is_merchant_dest`**: Boolean indicator identifying commercial merchant recipients ($1$ if `nameDest` starts with `'M'`, else $0$).
7. **Raw Financial Columns Retained**: `amount`, `oldbalanceOrg`, `newbalanceOrig`, `oldbalanceDest`, `newbalanceDest`.
8. **Categorical Feature**: `type` (`PAYMENT`, `TRANSFER`, `CASH_OUT`, `DEBIT`, `CASH_IN`) transformed via `OneHotEncoder(handle_unknown='ignore')`.

---

## 3. Model Benchmark Comparison & Final Selection

5-fold stratified cross-validation was conducted across $1,018,019$ training records, evaluated against an untouched test partition of $254,505$ records:

| Model Architecture | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | False Positives | Test Status |
|---|---|---|---|---|---|---|---|
| **Logistic Regression (Baseline)** | $0.0880$ | $0.8855$ | $0.1601$ | $0.5186$ | $0.9845$ | $7,639$ | Baseline |
| **Decision Tree (Baseline)** | $0.7816$ | $0.7952$ | $0.7883$ | $0.7820$ | $0.8974$ | $185$ | Baseline |
| **Tuned XGBoost (Benchmark)** | $0.9988$ | $0.9964$ | $0.9976$ | $0.9991$ | $0.9998$ | $1$ | Secondary Benchmark |
| **Tuned Random Forest (Primary)** | **1.0000** | **0.9976** | **0.9985** | **0.9995** | **0.9999** | **0** | **PRIMARY APPROVED** |

### Selected Model Specifications:
- **Algorithm**: `RandomForestClassifier` (`n_estimators=100`, `max_depth=20`, `class_weight='balanced_subsample'`, `random_state=42`)
- **Primary Packaged Artifact**: [ml/artifacts/model.joblib](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/ml/artifacts/model.joblib)
- **Feature Pipeline Artifact**: [ml/artifacts/preprocessor.joblib](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/ml/artifacts/preprocessor.joblib)
- **Metadata Registry**: [ml/artifacts/model_metadata.json](file:///c:/Users/AFZAL/Online%20Payment%20fraud%20detection%20system/ml/artifacts/model_metadata.json)

---

## 4. Explainable AI (SHAP) Architecture

```
                       Transformed Feature Vector (15 Dimensions)
                                          │
                                          ▼
                         [shap.TreeExplainer Engine]
                                          │
                                          ▼
                            Raw SHAP Values $\phi_i$
                                          │
                                          ▼
              [Index-to-Financial Feature Name Translation Layer]
                                          │
                                          ▼
              [Top-5 Feature Extraction & Narrative Synthesizer]
                                          │
                                          ▼
               Output Payload (Natural Language Summary + Factor Bars)
```

### 4.1 Index-to-Feature Mapping
Transformed indices generated by the OneHotEncoder are translated to human-readable financial concepts:
- `cat__type_TRANSFER` $\rightarrow$ `"Transaction Type: TRANSFER"`
- `cat__type_CASH_OUT` $\rightarrow$ `"Transaction Type: CASH_OUT"`
- `remainder__amount_to_oldbalance_orig_ratio` $\rightarrow$ `"Amount-to-Sender-Balance Ratio"`
- `remainder__errorBalanceOrig` $\rightarrow$ `"Sender Balance Error (Discrepancy)"`
- `remainder__errorBalanceDest` $\rightarrow$ `"Recipient Balance Error (Discrepancy)"`

### 4.2 Natural Language Synthesis Engine
The narrative engine analyzes the top positive risk contributors and generates clear domain explanations:
- *Example High-Risk Narrative*: `"Transaction flagged due to high balance depletion ratio (1.00) and zero post-transaction account balance on a wire TRANSFER."`
- *Example Legitimate Narrative*: `"Transaction aligns with legitimate historical merchant payment patterns."`

---

## 5. Statistical Data Drift Monitoring Methodology

The SOC continuously monitors feature divergence of incoming transactions ($N=50$) against the reference baseline ($180,000$ USD mean, $0.13\%$ fraud rate):

$$\text{DriftScore} = \min\left(1.0, 0.4 \times \frac{|\mu_{\text{amount}} - \mu_{\text{ref}}|}{\mu_{\text{ref}}} + 0.1 \times \frac{|r_{\text{fraud}} - r_{\text{ref}}|}{r_{\text{ref}} + 0.01}\right)$$

### Operational Thresholds:
- **`NORMAL`** ($\text{DriftScore} < 0.35$): Inference distribution matches baseline.
- **`WARNING`** ($0.35 \le \text{DriftScore} \le 0.70$): Moderate shift detected; alert security team.
- **`DRIFT DETECTED`** ($\text{DriftScore} > 0.70$): Significant statistical divergence; model retraining recommended.
