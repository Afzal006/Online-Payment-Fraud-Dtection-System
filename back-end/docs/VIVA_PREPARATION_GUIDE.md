# Comprehensive College Viva & Technical Defense Guide (40+ Questions & Answers)

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Academic Level**: Final Year Major Project / Capstone Technical Defense  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  

---

## 1. Project Conceptual Overview

### 1.1 Problem Statement
Online payment systems face unprecedented levels of financial fraud. Traditional rule-based fraud engines suffer from rigid thresholds, high false-positive rates that disrupt legitimate users, and an inability to detect novel fraud patterns. Conversely, deep learning and black-box ensemble models lack explainability, making regulatory compliance (such as GDPR's "Right to Explanation") and human security analysis infeasible.

### 1.2 Proposed Solution (AegisGuard AI)
AegisGuard AI provides an integrated, end-to-end financial fraud detection system combining:
1. **High-Performance Machine Learning**: Leakage-safe 11-feature engineering pipeline with a tuned Random Forest classifier ($F_1 = 0.9985$, $100\%$ precision).
2. **Explainable AI (XAI)**: `shap.TreeExplainer` calculating exact feature attributions and synthesizing automated natural language narratives.
3. **Adaptive 3-Tier Security Policy**: Dynamic risk scoring ($0-100$) triggering instant approvals for low risk, cryptographic OTP challenges for medium risk, and administrative review for high risk.
4. **Security Operations Center (SOC)**: Administrative dashboard with SQL aggregations, Chart.js telemetry, incident alert triage, and feature drift detection.

---

## 2. Machine Learning, Preprocessing, & Imbalance Defense

### 2.1 Why PaySim Dataset?
PaySim is an internationally recognized financial simulation benchmark generated from real mobile money transaction logs. It contains $6,362,620$ transactions with an extreme class imbalance ($773.7:1$), accurately mimicking real-world banking environments.

### 2.2 Mathematical Feature Engineering Formulas
1. **`errorBalanceOrig`**: Discrepancy in sender balance:
   $$\text{errorBalanceOrig} = \text{oldbalanceOrg} - \text{newbalanceOrig} - \text{amount}$$
2. **`errorBalanceDest`**: Discrepancy in recipient balance:
   $$\text{errorBalanceDest} = \text{oldbalanceDest} + \text{amount} - \text{newbalanceDest}$$
3. **`amount_to_oldbalance_orig_ratio`**: Account drainage ratio:
   $$\text{ratio}_{\text{orig}} = \frac{\text{amount}}{\text{oldbalanceOrg} + 1.0}$$
4. **`hourOfDay`**: Cyclic temporal hour ($\text{step} \pmod{24}$).
5. **`is_merchant_dest`**: Indicator ($1$ if `nameDest` starts with `'M'`, else $0$).

---

## 3. 40+ Likely Viva Questions & Model Answers

### Category 1: Machine Learning, Evaluation & Dataset

#### Q1: Why is Accuracy an invalid evaluation metric for fraud detection?
- **Short Answer**: Due to severe class imbalance ($773.7:1$), a naive dummy model predicting "legitimate" for all transactions achieves $99.87\%$ accuracy while missing $100\%$ of fraud.
- **Detailed Answer**: In the PaySim dataset, only $0.129\%$ of records are fraudulent. An accuracy metric treats false positives and false negatives equally. Missing a $\$500,000$ fraudulent transfer has catastrophic consequences compared to briefly challenging a legitimate user. Therefore, Precision, Recall, $F_1\text{-score}$, and Precision-Recall AUC (PR-AUC) must be used.
- **Keywords**: *Class Imbalance, Base Rate Fallacy, Cost of False Negatives, PR-AUC, F1-Score*.

---

#### Q2: What is Data Leakage, and how did you prevent it?
- **Short Answer**: Data leakage occurs when information from outside the training partition or future target information is included in model training, artificially inflating performance.
- **Detailed Answer**: We prevented leakage by:
  1. Excluding `isFraud` (target) and `isFlaggedFraud` (heuristic business rule target).
  2. Excluding high-cardinality transaction IDs (`nameOrig`, `nameDest`) which would allow memorization of synthetic account strings.
  3. Excluding the raw `step` counter which increases monotonically over time.
  4. Fitting the `ColumnTransformer` (scaling and OneHotEncoding) strictly on training folds within cross-validation.
- **Keywords**: *Target Leakage, Identifier Memorization, Train-Test Contamination, ColumnTransformer*.

---

#### Q3: Why did your Random Forest model achieve such high metrics ($F_1 = 0.9985$, $100\%$ Precision)?
- **Short Answer**: Fraud in the PaySim dataset follows distinct financial patterns (e.g. complete balance depletion via `TRANSFER` and `CASH_OUT`) captured effectively by our 11 engineered features.
- **Detailed Answer**: The engineered features (`errorBalanceOrig`, `amount_to_oldbalance_orig_ratio`, and recipient balance tracking) created clear decision boundaries. Random Forest with 100 estimators and `balanced_subsample` class weighting separated the fraud clusters completely on the untouched test partition without producing a single false positive.
- **Keywords**: *Feature Discriminative Power, Decision Boundaries, Class Weighting, Subsample Ensemble*.

---

#### Q4: Why select Random Forest over XGBoost as the primary model?
- **Short Answer**: Random Forest achieved zero false positives ($100\%$ precision) with $99.76\%$ recall on the test set, and integrates seamlessly with `shap.TreeExplainer`.
- **Detailed Answer**: Both models performed exceptionally well ($F_1 > 0.997$), but Random Forest eliminated false positives completely ($0$ FP vs $1$ FP in XGBoost). In financial production, avoiding friction on legitimate users while maintaining $99.76\%$ detection makes Random Forest superior. XGBoost was retained as a secondary benchmark.
- **Keywords**: *Zero False Positives, Model Precision, TreeExplainer Stability, Secondary Benchmark*.

---

#### Q5: How did you handle the extreme 773.7:1 class imbalance?
- **Short Answer**: We used cost-sensitive algorithmic learning via `class_weight='balanced_subsample'` and evaluated stratified cross-validation.
- **Detailed Answer**: Instead of dangerous synthetic oversampling (SMOTE) on large data which can synthesize unrealistic financial balance combinations, we used cost-sensitive learning. The algorithm penalizes misclassifications of the minority fraud class proportionally to its inverse class frequency during tree splitting.
- **Keywords**: *Cost-Sensitive Learning, Balanced Subsample, Inverse Frequency Weighting, Stratified Folds*.

---

#### Q6: What is the difference between ROC-AUC and PR-AUC?
- **Short Answer**: ROC-AUC evaluates True Positive Rate vs False Positive Rate, whereas PR-AUC evaluates Precision vs Recall.
- **Detailed Answer**: In highly imbalanced datasets, ROC-AUC can be misleadingly optimistic because the large number of true negatives keeps the False Positive Rate very low. PR-AUC focuses exclusively on the minority positive class, providing a true measure of fraud detection performance. Our model achieved $0.9995$ PR-AUC.
- **Keywords**: *True Negatives Masking, Precision-Recall Curve, Minority Class Focus*.

---

### Category 2: Explainable AI & SHAP

#### Q7: What is SHAP and why is it used?
- **Short Answer**: SHAP (SHapley Additive exPlanations) is a game-theoretic approach to explain individual predictions by computing the exact marginal contribution of each feature.
- **Detailed Answer**: SHAP calculates Shapley values ($\phi_i$) rooted in cooperative game theory. It satisfies desirable mathematical properties: Local Accuracy, Missingness, and Consistency. In AegisGuard AI, it transforms a black-box Random Forest prediction into human-understandable financial drivers (e.g. *"Amount-to-Balance ratio increased fraud score by +0.38"*).
- **Keywords**: *Shapley Values, Cooperative Game Theory, Local Accuracy, Additive Feature Attribution*.

---

#### Q8: How does `shap.TreeExplainer` differ from `KernelExplainer`?
- **Short Answer**: `TreeExplainer` is an exact, polynomial-time algorithm optimized for tree ensembles ($O(TLD^2)$), whereas `KernelExplainer` is an exponential model-agnostic sampling approximation.
- **Detailed Answer**: `TreeExplainer` directly exploits the tree structure of Random Forest, allowing sub-100ms real-time explanation generation during payment processing. `KernelExplainer` requires thousands of model evaluations and is too slow for real-time transactions.
- **Keywords**: *Tree-Structure Exploitation, Polynomial Complexity, Real-Time Low Latency*.

---

#### Q9: How are OneHotEncoded categorical features explained to non-technical users?
- **Short Answer**: An index-to-name translation layer aggregates one-hot encoded dummy variables and maps technical column names to natural financial terminology.
- **Detailed Answer**: Transformed indices like `cat__type_TRANSFER` and `remainder__amount_to_oldbalance_orig_ratio` are mapped to `"Transaction Type: TRANSFER"` and `"Amount-to-Sender-Balance Ratio"`. These are then fed into our natural language narrative synthesizer.
- **Keywords**: *Feature Mapping Layer, Narrative Synthesizer, Domain Translation*.

---

### Category 3: Security, OTP & Architecture

#### Q10: How does the 3-tier adaptive security decision policy work?
- **Short Answer**: It routes transactions into LOW ($0-30$, Auto-Approve), MEDIUM ($31-70$, OTP Challenge), and HIGH ($71-100$, OTP Challenge + Admin SOC Alert).
- **Detailed Answer**: The calibrated fraud probability $P(\text{fraud})$ is converted to a risk score: $\text{round}(P \times 100)$. Low-risk transactions proceed instantly without user friction. Medium-risk transactions require 2FA OTP verification. High-risk transactions require OTP verification and place the transaction under administrative review with an open incident alert.
- **Keywords**: *Risk Tiering, Friction Reduction, Step-Up Authentication, Incident Escalation*.

---

#### Q11: How are OTP codes generated and secured?
- **Short Answer**: 6-digit numeric codes are generated using Python's cryptographically secure `secrets` module and stored exclusively as PBKDF2 hashes.
- **Detailed Answer**: The system never stores plaintext OTPs in the database. `otp_challenges.otp_hash` stores the PBKDF2 hash. Challenges expire after 180 seconds and strictly limit attempts to 3. Upon verification, the token status is immediately revoked to prevent replay attacks.
- **Keywords**: *Cryptographic Randomness (`secrets`), PBKDF2 Hashing, Zero Plaintext Storage, Anti-Replay*.

---

#### Q12: What happens if an attacker enters an incorrect OTP 3 times?
- **Short Answer**: The challenge transitions to `status='EXHAUSTED'`, further attempts are blocked (HTTP 429), and the transaction is permanently `REJECTED`.
- **Detailed Answer**: The database atomically increments `attempt_count`. Once `attempt_count >= max_attempts` (3), the challenge is invalidated. The transaction cannot be approved, and the user must initiate a fresh transaction.
- **Keywords**: *Rate Limiting, Exhausted State, Transaction Invalidation, Brute-Force Defense*.

---

#### Q13: How is Role-Based Access Control (RBAC) enforced?
- **Short Answer**: Through backend Python decorators (`@admin_required()`) verifying claims in the cryptographic JWT access token.
- **Detailed Answer**: Access control does not rely on frontend UI hiding. The `@admin_required()` decorator extracts the user identity from the verified JWT signature, queries the `users.role` attribute, and immediately returns HTTP 403 Forbidden if the role is not `ADMIN`.
- **Keywords**: *Decorator Enforcement, JWT Claims, Server-Side Authorization, HTTP 403 Forbidden*.

---

#### Q14: How does your system prevent cross-tenant data access?
- **Short Answer**: All data-retrieval endpoints extract `user_id` directly from the authenticated JWT token rather than trusting client-supplied URL parameters.
- **Detailed Answer**: When querying `/api/transactions/my-history` or `/api/transactions/<id>`, the backend verifies that `transaction.user_id == current_user_id`. An attempt by User A to view User B's transaction yields HTTP 403 Forbidden.
- **Keywords**: *Tenant Isolation, JWT Claim Scoping, Object-Level Permissions*.

---

#### Q15: How does the Admin SOC monitor Model & Data Drift?
- **Short Answer**: By calculating real-time statistical divergence of incoming transaction amounts and fraud ratios against the PaySim reference baseline.
- **Detailed Answer**: Over a rolling window ($N=50$), the system calculates a weighted distance metric comparing mean transaction amount and fraud rate against baseline training values ($180,000$ USD and $0.13\%$). Drift scores above $0.35$ trigger a `WARNING`, and above $0.70$ trigger `DRIFT DETECTED`.
- **Keywords**: *Statistical Divergence, Rolling Window, Baseline Distribution Shift, Retraining Telemetry*.

---

### Category 4: Difficult & Edge-Case Examiner Questions

#### Q16: How would this system work on a real bank's production transaction stream?
- **Short Answer**: It would ingest streaming messages via Apache Kafka, execute inference in a containerized microservice (Docker/Gunicorn), and log features to an enterprise feature store (e.g. Feast).
- **Detailed Answer**: In enterprise banking, the Flask REST endpoint would be supplemented by an asynchronous message broker (Kafka/RabbitMQ). Features would be computed in real time using a streaming engine (Flink/Spark Streaming), and the Random Forest inference service would scale horizontally behind a load balancer.
- **Keywords**: *Apache Kafka, Microservices Architecture, Horizontal Scalability, Streaming Inference*.

#### Q17: What are the main limitations of the PaySim dataset?
- **Short Answer**: PaySim is a synthetic agent-based simulation lacking real-world noise such as merchant category codes (MCC), geolocation coordinates, IP addresses, and device fingerprints.
- **Detailed Answer**: While PaySim accurately models balance depletion and flow of funds, it does not contain network-level telemetry (e.g. VPN detection, behavioral biometric typing speed, device ID changes). In production, incorporating these multi-modal features further hardens security.
- **Keywords**: *Synthetic Simulation, Lack of Network Telemetry, Multimodal Features*.

#### Q18: What happens if the database connection fails mid-transaction?
- **Short Answer**: SQLAlchemy database transactions utilize atomic commit and automatic rollback (`db.session.rollback()`) to prevent partial or corrupted state.
- **Detailed Answer**: Transaction submission, prediction logging, and alert creation are wrapped in a database transaction block. If an exception occurs at any point, the entire transaction rolls back, leaving no orphaned records.
- **Keywords**: *ACID Properties, Atomic Commits, Rollback Safety, Exception Boundary*.

#### Q19: Why did you choose Vanilla JS & Custom CSS over React / Bootstrap?
- **Short Answer**: To achieve zero framework overhead, instant page rendering, complete architectural transparency, and full control over our custom fintech glassmorphism design system.
- **Detailed Answer**: A vanilla HTML5/CSS3/ES6 stack demonstrates deep mastery of core web standards without relying on heavy third-party bundles. It guarantees fast load times, clean DOM manipulation, and native browser compatibility.
- **Keywords**: *Zero Dependency Overhead, Native Web Standards, Fast DOM Rendering, Custom Design System*.

#### Q20: What is the difference between Implemented, Simulated, and Future features in your project?
- **Short Answer**:
  - **Implemented**: Full ML training pipeline, tuned Random Forest, SHAP TreeExplainer, JWT authentication, RBAC, database schema with constraints, User Portal, and Admin SOC.
  - **Simulated**: The OTP delivery channel (simulated via secure API response and console logging rather than paid external SMS gateways like Twilio).
  - **Future Enhancements**: Live Kafka streaming ingestion, automated continuous retraining pipelines, and biometric device fingerprinting.
- **Keywords**: *Implemented vs Simulated, Offline Defense Readiness, Future Roadmap*.
