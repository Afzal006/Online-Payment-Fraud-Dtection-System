# ML Baseline Modeling & Evaluation Report

**Project**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**Phase**: Phase 2 — Baseline ML Pipeline & Candidate Benchmarking  
**Evaluation Date**: 2026-08-18  
**Dataset Rows Processed**: 1,272,524 (Training: 1,018,019 | Testing: 254,505)  
**Class Imbalance Ratio**: ~774 : 1 (Stratified split preserved)  

---

## 1. Executive Summary & Model Comparison

Three candidate baseline models were trained on identical stratified training splits and evaluated on an untouched 20% holdout test set:

| Model | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | Accuracy* | True Positives (TP) | False Positives (FP) | False Negatives (FN) | True Negatives (TN) |
|---|---|---|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 0.0228 | 0.9582 | **0.0445** | 0.5279 | 0.9872 | 0.94580 | 321 | 13,780 | 14 | 240,390 |
| **Decision Tree** | 0.8698 | 0.9970 | **0.9291** | 0.9970 | 0.9985 | 0.99980 | 334 | 50 | 1 | 254,120 |
| **Random Forest** | 1.0000 | 0.9970 | **0.9985** | 0.9970 | 0.9984 | 1.00000 | 334 | 0 | 1 | 254,170 |

*Note: Accuracy is reported for completeness only. Due to extreme class imbalance (99.87% legitimate transactions), accuracy is not an informative fraud detection metric.*

---

## 2. In-Depth Metric Analysis & Key Findings

### A. Best Performing Baseline Model
**Random Forest** achieved the highest overall performance:
- Highest **F1-Score** and highest **PR-AUC (Precision-Recall Area Under Curve)**.
- Maintains high recall (detecting fraudulent attacks) while sharply reducing false positive alerts compared to linear baselines.

### B. Trade-Off: Fraud Detection (Recall) vs. False Positive Friction (Precision)
1. **Logistic Regression (Baseline Linear)**:
   - Achieves moderate recall with `class_weight='balanced'`, but produces thousands of **False Positives (FP)**. In a commercial payment gateway, this volume of false alerts would cause unacceptable customer friction and alert fatigue.
2. **Decision Tree (Baseline Tree)**:
   - Drastically improves precision and decision boundaries by segmenting non-linear balance discrepancies (`errorBalanceOrig`, `errorBalanceDest`).
3. **Random Forest (Ensemble Tree Baseline)**:
   - Provides superior stability, reducing tree variance and capturing nuanced multi-feature interactions without overfitting.

### C. Why Accuracy is Insufficient
A trivial dummy classifier predicting "Legitimate" for every transaction achieves **99.87% accuracy** while missing 100% of fraud cases. For this reason, model selection and risk scoring prioritize **Precision, Recall, F1-Score, and PR-AUC**.

---

## 3. Feature Transformation Details

- **Logical Domain Features (Input)**: 11 features (`type`, `amount`, `oldbalanceOrg`, `newbalanceOrig`, `oldbalanceDest`, `newbalanceDest`, `errorBalanceOrig`, `errorBalanceDest`, `hourOfDay`, `isMerchantDest`, `amountToBalanceRatio`).
- **Transformed Feature Matrix (Model Input)**: **15 columns** generated via `OneHotEncoder(handle_unknown='ignore')` on `type` + numerical features:
  `cat__type_CASH_OUT, cat__type_TRANSFER, cat__type_PAYMENT, cat__type_CASH_IN, cat__type_DEBIT, num__amount, num__oldbalanceOrg, num__newbalanceOrig, num__oldbalanceDest, num__newbalanceDest, num__errorBalanceOrig, num__errorBalanceDest, num__isMerchantDest, num__amountToBalanceRatio, num__hourOfDay`

---

## 4. Strict Data Leakage Checklist

| Check | Verification Status | Rationale |
|---|---|---|
| Target variable `isFraud` removed from $X$ | **PASSED** | Target is separated prior to feature matrix construction. |
| Naive rule `isFlaggedFraud` excluded | **PASSED** | Static heuristic rule removed from model input to prevent artificial dependency. |
| Account IDs `nameOrig` / `nameDest` excluded | **PASSED** | Raw strings excluded to prevent identity memorization/overfitting. |
| Preprocessing fitted strictly on train set | **PASSED** | `ColumnTransformer` is fitted exclusively on `X_train` and applied to `X_test` via `Pipeline`. |
| Test set isolation | **PASSED** | Test data remained strictly untouched during preprocessing fitting and model training. |
| Safe numerical operations | **PASSED** | `amountToBalanceRatio` uses `+ 1.0` denominator to eliminate division-by-zero risks. |

---

## 5. Visual Artifacts Generated

1. `ml/artifacts/logistic_regression_confusion_matrix.png`
2. `ml/artifacts/decision_tree_confusion_matrix.png`
3. `ml/artifacts/random_forest_confusion_matrix.png`
4. `ml/artifacts/baseline_metrics.json`
5. `ml/artifacts/preprocessor.joblib`
6. `ml/artifacts/random_forest_baseline.joblib`

---

## 6. Recommendation for Phase 3 (Strong Models & Tuning)

1. Advance **Random Forest** and introduce **XGBoost (Extreme Gradient Boosting)** as candidate advanced models.
2. Conduct focused hyperparameter tuning (tree depth, min samples split, class weighting / scale pos weight) using Stratified Cross-Validation on the training split.
3. Compare tuned Random Forest vs. tuned XGBoost on PR-AUC, F1, and SHAP Explainability compatibility before packaging the final approved model artifact.
