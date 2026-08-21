# Formal System Diagrams (DFD, ERD, UML)

**Project Title**: AI-Powered Real-Time Online Payment Fraud Detection and Explainable Risk Assessment System  
**System Name**: AegisGuard AI  
**Document Version**: 1.0.0  
**Date**: 2026-08-18  

---

## 1. Data Flow Diagrams (DFD)

### 1.1 DFD Level 0 — Context Diagram
```mermaid
graph TD
    User["Customer / Regular User"]
    Admin["SOC Security Officer / Admin"]
    System["AegisGuard AI Fraud Detection System"]
    
    User -->|"1. Register / Login Credentials"| System
    User -->|"2. Submit Payment Transaction (Type, Amount, Dest)"| System
    User -->|"3. Submit OTP Verification Code"| System
    
    System -->|"4. Real-time Risk Score, Status & SHAP Narrative"| User
    System -->|"5. OTP Challenge Request"| User
    System -->|"6. Personal Transaction History Ledger"| User
    
    Admin -->|"7. Admin Authentication Credentials"| System
    Admin -->|"8. Alert Investigation & Resolution Notes"| System
    
    System -->|"9. SOC Dashboard KPIs & Chart Analytics"| Admin
    System -->|"10. Security Incident Alerts & Model Drift Telemetry"| Admin
```

---

### 1.2 DFD Level 1 — Subsystem Data Flow Diagram
```mermaid
graph TD
    User["Customer / User"]
    Admin["SOC Admin"]
    
    subgraph "AegisGuard AI Core Platform"
        P1["1.0 Authentication & Access Control (JWT)"]
        P2["2.0 Transaction Ingestion & Preprocessing"]
        P3["3.0 ML Inference & Risk Scoring Engine"]
        P4["4.0 SHAP Explainability Engine"]
        P5["5.0 Adaptive Security & OTP Challenge Manager"]
        P6["6.0 SOC Analytics & Alert Management"]
    end
    
    D1[("Users Store")]
    D2[("Transactions Store")]
    D3[("Alerts Store")]
    D4[("OTP Challenges Store")]
    D5[("ML Artifacts (model.joblib)")]
    
    User -->|"Credentials"| P1
    P1 -->|"Read / Write Identity"| D1
    P1 -->|"JWT Token"| User
    
    User -->|"Payment Request"| P2
    P2 -->|"11 Engineered Features"| P3
    P3 -->|"Inference Query"| D5
    P5 -.->|"Read Model"| D5
    P3 -->|"Prediction & Probability"| P4
    P4 -->|"SHAP Feature Attribution"| P2
    
    P3 -->|"Risk Score (0-100)"| P5
    P5 -->|"Persist Transaction"| D2
    P5 -->|"Create High-Risk Alert"| D3
    P5 -->|"Issue OTP Challenge"| D4
    P5 -->|"Challenge Notification"| User
    
    User -->|"Verify OTP Code"| P5
    P5 -->|"Update Status"| D2
    P5 -->|"Final Confirmation"| User
    
    Admin -->|"SOC Queries & Notes"| P6
    P6 -->|"Aggregate Analytics"| D2
    P6 -->|"Fetch / Resolve Alerts"| D3
    P6 -->|"Telemetry Feed"| Admin
```

---

### 1.3 DFD Level 2 — ML Inference & Security Workflow
```mermaid
graph TD
    RawTx["Raw Transaction Payload: (Type, Amount, Destination, Balances)"]
    
    subgraph "Feature Engineering & Preprocessing"
        F1["Calculate errorBalanceOrig = oldbalanceOrg - newbalanceOrig - amount"]
        F2["Calculate errorBalanceDest = oldbalanceDest + amount - newbalanceDest"]
        F3["Calculate amount_to_oldbalance_orig_ratio with division-by-zero protection"]
        F4["Calculate amount_to_oldbalance_dest_ratio"]
        F5["Extract hourOfDay = step % 24"]
        F6["Detect is_merchant_dest = (nameDest starts with 'M')"]
        F7["Exclude Leakage: isFraud, isFlaggedFraud, nameOrig, nameDest, raw step"]
        F8["OneHotEncode Categorical Type via ColumnTransformer"]
    end
    
    RawTx --> F1 & F2 & F3 & F4 & F5 & F6
    F1 & F2 & F3 & F4 & F5 & F6 --> F7 --> F8
    
    subgraph "Machine Learning & XAI"
        M1["RandomForestClassifier.predict_proba(X_transformed)"]
        M2["Compute Fraud Probability P(fraud)"]
        M3["Compute Risk Score = round(P(fraud) * 100)"]
        M4["shap.TreeExplainer.shap_values(X_transformed)"]
        M5["Map Transformed Indices to Human-Readable Names"]
        M6["Synthesize Natural Language Risk Summary Narrative"]
    end
    
    F8 --> M1
    M1 --> M2 --> M3
    F8 --> M4
    M4 --> M5 --> M6
    
    subgraph "3-Tier Adaptive Security Routing"
        R1{"Risk Score Band?"}
        T1["0 – 30 (LOW RISK): Status APPROVED, APPROVE_IMMEDIATELY"]
        T2["31 – 70 (MEDIUM RISK): Status OTP_REQUIRED, Generate OTP Challenge"]
        T3["71 – 100 (HIGH RISK): Status UNDER_REVIEW, Generate Security Alert + OTP Challenge"]
    end
    
    M3 --> R1
    R1 -->|"Score <= 30"| T1
    R1 -->|"31 <= Score <= 70"| T2
    R1 -->|"Score >= 71"| T3
```

---

## 2. Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    USERS ||--o{ TRANSACTIONS : "places (1:N)"
    USERS ||--o{ ALERTS : "associated_with (1:N)"
    USERS ||--o{ OTP_CHALLENGES : "challenges (1:N)"
    TRANSACTIONS ||--o| ALERTS : "triggers (1:1)"
    TRANSACTIONS ||--o{ OTP_CHALLENGES : "secures (1:N)"

    USERS {
        int id PK "Auto Increment"
        string name "NOT NULL"
        string email "NOT NULL, UNIQUE, INDEX"
        string password_hash "NOT NULL, PBKDF2/Scrypt"
        string role "NOT NULL, CHECK: USER|ADMIN"
        datetime created_at "NOT NULL, INDEX"
    }

    TRANSACTIONS {
        int id PK "Auto Increment"
        int user_id FK "NOT NULL, INDEX"
        int step "NOT NULL, Default: 1"
        string type "NOT NULL"
        float amount "NOT NULL, CHECK: amount > 0"
        string name_orig "NULLABLE"
        float oldbalance_org "NOT NULL"
        float newbalance_orig "NOT NULL"
        string name_dest "NULLABLE"
        float oldbalance_dest "NOT NULL"
        float newbalance_dest "NOT NULL"
        int prediction "NOT NULL, INDEX"
        float fraud_probability "NOT NULL, CHECK: [0.0, 1.0]"
        int risk_score "NOT NULL, CHECK: [0, 100]"
        string risk_level "NOT NULL, CHECK: LOW|MEDIUM|HIGH, INDEX"
        string decision "NOT NULL"
        string status "NOT NULL, INDEX"
        boolean requires_otp "NOT NULL"
        string otp_code "NULLABLE"
        datetime otp_expires_at "NULLABLE"
        int otp_attempts "NOT NULL, Default: 0"
        text explanation_json "NULLABLE"
        datetime created_at "NOT NULL, INDEX"
    }

    ALERTS {
        int id PK "Auto Increment"
        int transaction_id FK "NOT NULL, UNIQUE, INDEX"
        int user_id FK "NOT NULL, INDEX"
        string alert_type "NOT NULL, Default: FRAUD_ALERT"
        string severity "NOT NULL, CHECK: MEDIUM|HIGH|CRITICAL"
        text message "NOT NULL"
        string status "NOT NULL, CHECK: OPEN|RESOLVED|DISMISSED, INDEX"
        datetime created_at "NOT NULL, INDEX"
        datetime resolved_at "NULLABLE"
    }

    OTP_CHALLENGES {
        int id PK "Auto Increment"
        int transaction_id FK "NOT NULL, INDEX"
        int user_id FK "NOT NULL, INDEX"
        string otp_hash "NOT NULL, PBKDF2/Scrypt"
        string purpose "NOT NULL, Default: TRANSACTION_VERIFICATION"
        datetime expires_at "NOT NULL"
        int attempt_count "NOT NULL, Default: 0"
        int max_attempts "NOT NULL, Default: 3"
        string status "NOT NULL, CHECK: ACTIVE|VERIFIED|EXPIRED|EXHAUSTED"
        datetime verified_at "NULLABLE"
        datetime created_at "NOT NULL, INDEX"
    }
```

---

## 3. Unified Modeling Language (UML) Diagrams

### 3.1 UML Use Case Diagram
```mermaid
graph LR
    User["Customer / User"]
    Admin["Security Analyst / Admin"]
    
    subgraph "Customer Capabilities"
        UC1(["Register Account"])
        UC2(["Login & Authenticate (JWT)"])
        UC3(["Submit Payment Transaction"])
        UC4(["View Real-Time AI Risk Assessment"])
        UC5(["Inspect SHAP 'Why Flagged?' Drawer"])
        UC6(["Complete Adaptive OTP Challenge"])
        UC7(["View Personal Transaction Ledger"])
    end
    
    subgraph "Security Operations Capabilities"
        UC8(["Access SOC Dashboard"])
        UC9(["View Interactive Chart.js Telemetry"])
        UC10(["Inspect High-Risk Security Alerts"])
        UC11(["Investigate Transaction SHAP Drivers"])
        UC12(["Resolve Alert with Audit Notes"])
        UC13(["Dismiss Non-Critical Alert"])
        UC14(["Audit Global Transaction Ledger"])
        UC15(["Monitor Statistical Feature Drift"])
    end
    
    User --> UC1
    User --> UC2
    User --> UC3
    User --> UC4
    User --> UC5
    User --> UC6
    User --> UC7
    
    Admin --> UC2
    Admin --> UC8
    Admin --> UC9
    Admin --> UC10
    Admin --> UC11
    Admin --> UC12
    Admin --> UC13
    Admin --> UC14
    Admin --> UC15
```

---

### 3.2 UML Class Diagram
```mermaid
classDiagram
    class User {
        +int id
        +string name
        +string email
        +string password_hash
        +string role
        +datetime created_at
        +set_password(password)
        +check_password(candidate)
        +to_dict() dict
    }

    class Transaction {
        +int id
        +int user_id
        +int step
        +string type
        +float amount
        +float oldbalance_org
        +float newbalance_orig
        +float oldbalance_dest
        +float newbalance_dest
        +int prediction
        +float fraud_probability
        +int risk_score
        +string risk_level
        +string decision
        +string status
        +bool requires_otp
        +string explanation_json
        +datetime created_at
        +to_dict() dict
    }

    class Alert {
        +int id
        +int transaction_id
        +int user_id
        +string alert_type
        +string severity
        +string message
        +string status
        +datetime created_at
        +datetime resolved_at
        +to_dict() dict
    }

    class OTPChallenge {
        +int id
        +int transaction_id
        +int user_id
        +string otp_hash
        +string purpose
        +datetime expires_at
        +int attempt_count
        +int max_attempts
        +string status
        +datetime verified_at
        +datetime created_at
        +set_otp(plaintext)
        +check_otp(candidate) bool
        +is_expired() bool
        +to_dict() dict
    }

    class InferenceService {
        -model
        -preprocessor
        -metadata
        +predict_transaction(data) dict
    }

    class ShapService {
        -explainer
        +explain_transaction(data, top_k) dict
    }

    class RiskDecisionService {
        +evaluate_risk(risk_score) dict
    }

    class OTPService {
        +create_challenge(tx_id, user_id) tuple
        +verify_challenge(tx_id, user_id, code) tuple
    }

    class AlertService {
        +create_security_alert(tx_id, user_id, severity, msg) Alert
        +get_all_alerts(status, severity) list
        +resolve_alert(alert_id, admin_id, note) Alert
        +dismiss_alert(alert_id, admin_id) Alert
    }

    class AdminAnalyticsService {
        +get_overview_kpis() dict
        +get_chart_analytics() dict
        +evaluate_data_drift() dict
    }

    User "1" *-- "0..*" Transaction : owns
    User "1" *-- "0..*" Alert : subject_of
    User "1" *-- "0..*" OTPChallenge : targets
    Transaction "1" *-- "0..1" Alert : generates
    Transaction "1" *-- "0..*" OTPChallenge : secures

    Transaction ..> InferenceService : invokes
    Transaction ..> ShapService : invokes
    Transaction ..> RiskDecisionService : consults
    Transaction ..> AlertService : triggers
    Transaction ..> OTPService : requests
    AlertService ..> AdminAnalyticsService : feeds
```

---

### 3.3 UML Sequence Diagram — Complete Transaction Lifecycle
```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Frontend as Web Client (JS)
    participant API as Transaction Controller
    participant ML as Inference Service
    participant SHAP as SHAP Engine
    participant Risk as Risk Decision Service
    participant OTP as OTP Service
    participant DB as Relational Database
    actor Admin

    User->>Frontend: Enter Payment Details ($800,000 Transfer)
    Frontend->>API: POST /api/transactions/predict (JWT)
    API->>ML: predict_transaction(features)
    ML-->>API: {prediction: 1, fraud_prob: 0.94}
    API->>SHAP: explain_transaction(features)
    SHAP-->>API: {risk_score: 94, top_features: [...], narrative: "..."}
    API->>Risk: evaluate_risk(94)
    Risk-->>API: {risk_level: "HIGH", decision: "TRIGGER_OTP_ALERT_AND_REVIEW", create_alert: true}
    
    API->>DB: INSERT INTO transactions (status='UNDER_REVIEW', ...)
    API->>DB: INSERT INTO alerts (status='OPEN', severity='HIGH', ...)
    API-->>Frontend: HTTP 200 {status: "UNDER_REVIEW", requires_otp: true, ...}
    Frontend-->>User: Render Result Modal & Prompt OTP Challenge
    
    User->>Frontend: Click "Proceed to OTP"
    Frontend->>API: POST /api/otp/generate (transaction_id)
    API->>OTP: create_challenge(tx_id, user_id)
    OTP->>DB: INSERT INTO otp_challenges (otp_hash, expires_in=180s)
    OTP-->>API: {challenge_id, expires_in: 180}
    API-->>Frontend: HTTP 200 {expires_in_seconds: 180}
    Frontend-->>User: Display Countdown & 6-Box Input
    
    User->>Frontend: Submit OTP Code
    Frontend->>API: POST /api/otp/verify (transaction_id, otp_code)
    API->>OTP: verify_challenge(tx_id, user_id, otp_code)
    OTP->>DB: UPDATE otp_challenges (status='VERIFIED')
    OTP->>DB: UPDATE transactions (status='VERIFIED_PENDING_REVIEW')
    OTP-->>API: Verification Success
    API-->>Frontend: HTTP 200 {status: "VERIFIED_PENDING_REVIEW"}
    Frontend-->>User: Verification Success Notice
    
    Admin->>API: GET /api/admin/alerts?status=OPEN (Admin JWT)
    API->>DB: SELECT * FROM alerts WHERE status='OPEN'
    DB-->>API: Open Alerts List
    API-->>Admin: Render Alert in SOC Dashboard
    
    Admin->>API: POST /api/admin/alerts/{id}/resolve (note="Verified with Cardholder")
    API->>DB: UPDATE alerts SET status='RESOLVED'
    API-->>Admin: Alert Resolved Confirmation
```

---

### 3.4 UML Activity Diagram — Adaptive 3-Tier Security Workflow
```mermaid
stateDiagram-v2
    [*] --> IngestTransaction
    IngestTransaction --> ValidatePayload
    
    state ValidatePayload {
        CheckFields --> CheckAmount: amount > 0
        CheckAmount --> CheckType: valid type
    }
    
    ValidatePayload --> FeatureEngineering: Valid
    ValidatePayload --> ReturnValidationError: Invalid (HTTP 400)
    ReturnValidationError --> [*]
    
    FeatureEngineering --> MLInference
    MLInference --> SHAPExplanation
    SHAPExplanation --> RiskScoring: Compute 0-100 Score
    
    state RiskDecisionRouting <<choice>>
    RiskScoring --> RiskDecisionRouting
    
    RiskDecisionRouting --> LowRiskFlow: Score <= 30 (LOW)
    RiskDecisionRouting --> MediumRiskFlow: 31 <= Score <= 70 (MEDIUM)
    RiskDecisionRouting --> HighRiskFlow: Score >= 71 (HIGH)
    
    state LowRiskFlow {
        SetStatusApproved --> PersistLowTx
    }
    PersistLowTx --> ReturnSuccessResponse
    
    state MediumRiskFlow {
        SetStatusOtpRequired --> PersistMedTx
        PersistMedTx --> IssueOtpChallengeMed
        IssueOtpChallengeMed --> AwaitOtpInputMed
        
        state VerifyOtpMed <<choice>>
        AwaitOtpInputMed --> VerifyOtpMed
        VerifyOtpMed --> ApproveAfterOtp: Correct Code
        VerifyOtpMed --> DecrementAttemptMed: Incorrect Code
        DecrementAttemptMed --> AwaitOtpInputMed: Attempts < 3
        DecrementAttemptMed --> RejectTxMed: Attempts >= 3
    }
    ApproveAfterOtp --> ReturnSuccessResponse
    RejectTxMed --> ReturnSuccessResponse
    
    state HighRiskFlow {
        SetStatusUnderReview --> CreateSecurityAlert
        CreateSecurityAlert --> PersistHighTx
        PersistHighTx --> IssueOtpChallengeHigh
        IssueOtpChallengeHigh --> AwaitOtpInputHigh
        
        state VerifyOtpHigh <<choice>>
        AwaitOtpInputHigh --> VerifyOtpHigh
        VerifyOtpHigh --> VerifiedPendingReview: Correct Code
        VerifyOtpHigh --> RejectTxHigh: Attempts >= 3
        VerifiedPendingReview --> AdminSocInvestigation
        AdminSocInvestigation --> ResolveAlertByAdmin
    }
    ResolveAlertByAdmin --> ReturnSuccessResponse
    RejectTxHigh --> ReturnSuccessResponse
    
    ReturnSuccessResponse --> [*]
```
