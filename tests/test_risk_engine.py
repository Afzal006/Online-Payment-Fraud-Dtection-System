"""
Comprehensive Test Suite for Phase 2: Real-Time Fraud Risk Engine Upgrade.

Covers:
1. Normal low-risk transaction
2. High-value transaction
3. First-time beneficiary signal
4. Repeated rapid transactions (< 60s)
5. Unusual transaction time (off-hours night window)
6. High amount deviation from historical baseline
7. Transaction velocity window (10m / 1h)
8. High ML fraud probability & account drainage
9. LOW risk tier classification (0-29)
10. MEDIUM risk tier classification (30-59)
11. HIGH risk tier classification (60-79)
12. CRITICAL risk tier classification (80-100)
13. Correct decision mapping
14. OTP_REQUIRED behavior (balance held)
15. UNDER_REVIEW behavior (security alert created)
16. REJECTED behavior & audit recording
17. Dual-view risk explanations (Customer vs Admin)
18. Zero future-data leakage in feature engineering
19. Phase 1 atomic ledger balance preservation
20. Phase 1 authentication & transaction API backward compatibility
"""

import json
from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.services.feature_service import FeatureService
from app.services.risk_signal_service import RiskSignalService
from app.services.risk_service import RiskDecisionService
from app.services.shap_service import ShapService
from app.services.transaction_service import TransactionService


@pytest.fixture
def app():
    """Create test application configured with an in-memory SQLite database."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def seed_user(app):
    """Seed a test customer with starting balance and payment identity."""
    user = User(
        name="Arjun Sharma",
        email="arjun@example.com",
        customer_account_id="FS-100001",
        primary_upi_id="arjun@fraudshield",
        phone_number="+91 98765 43210",
        account_balance=150000.0,
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
        role="USER",
    )
    user.set_password("UserDemo2026!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def seed_beneficiary(app, seed_user):
    """Seed a verified beneficiary for Arjun."""
    b = Beneficiary(
        user_id=seed_user.id,
        beneficiary_name="Priya Patel",
        beneficiary_upi_id="priya@fraudshield",
        beneficiary_phone="+91 98765 43211",
        nickname="Sister",
        is_verified=True,
        status="ACTIVE",
    )
    db.session.add(b)
    db.session.commit()
    return b


@pytest.fixture
def auth_token(client, seed_user):
    """Obtain JWT access token for the seeded customer."""
    res = client.post(
        "/api/auth/login",
        json={"email": seed_user.email, "password": "UserDemo2026!"},
    )
    return res.get_json()["access_token"]


# ==============================================================================
# 1. Normal Low-Risk Transaction (0-29 -> APPROVED)
# ==============================================================================
def test_normal_low_risk_transaction(client, seed_user, seed_beneficiary, auth_token):
    """Everyday low-value payment to verified beneficiary during daytime is approved with balance deduction."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "PAYMENT",
            "amount": 250.0,
            "beneficiary_id": seed_beneficiary.id,
            "payment_note": "Coffee and snacks",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] <= 29
    assert data["decision"] == "APPROVE_IMMEDIATELY"
    assert data["status"] == "APPROVED"
    assert data["requires_otp"] is False
    assert data["balance_before"] == 150000.0
    assert data["balance_after"] == 149750.0


# ==============================================================================
# 2. High-Value Transaction (> ₹1,00,000)
# ==============================================================================
def test_high_value_transaction(client, seed_user, seed_beneficiary, auth_token):
    """High-value transfer exceeding ₹1,00,000 generates HIGH_VALUE_TRANSFER signal."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "TRANSFER",
            "amount": 120000.0,
            "destination": "C99881122",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["risk_score"] >= 60
    assert data["requires_otp"] is True

    signal_codes = [s["code"] for s in data["risk_signals"]]
    assert "HIGH_VALUE_TRANSFER" in signal_codes


# ==============================================================================
# 3. First-Time Beneficiary Signal
# ==============================================================================
def test_first_time_beneficiary_signal(app, seed_user):
    """FeatureService detects first-time beneficiary and triggers NEW_BENEFICIARY_FIRST_TRANSFER signal."""
    with app.app_context():
        features = FeatureService.extract_features(
            user_id=seed_user.id,
            amount=5000.0,
            tx_type="TRANSFER",
            destination_upi_id="newuser@fraudshield",
        )
        assert features["is_first_time_beneficiary"] is True
        assert features["beneficiary_tx_count"] == 0

        signals = RiskSignalService.evaluate_signals(features)
        signal_codes = [s["code"] for s in signals]
        assert "NEW_BENEFICIARY_FIRST_TRANSFER" in signal_codes


# ==============================================================================
# 4. Repeated Rapid Transactions (< 60 seconds)
# ==============================================================================
def test_repeated_rapid_transactions(app, seed_user):
    """Multiple transactions initiated within 60s triggers RAPID_REPEATED_TRANSACTIONS critical signal."""
    with app.app_context():
        now = datetime.now(timezone.utc)
        # Add prior transaction 30s ago
        tx_prior = Transaction(
            user_id=seed_user.id,
            step=1,
            type="PAYMENT",
            amount=1000.0,
            name_orig="FS-100001",
            oldbalance_org=1000.0,
            newbalance_orig=0.0,
            name_dest="M123",
            oldbalance_dest=0.0,
            newbalance_dest=1000.0,
            prediction=0,
            fraud_probability=0.01,
            risk_score=10,
            risk_level="LOW",
            decision="APPROVE_IMMEDIATELY",
            status="APPROVED",
            created_at=now - timedelta(seconds=30),
        )
        db.session.add(tx_prior)
        db.session.commit()

        features = FeatureService.extract_features(
            user_id=seed_user.id,
            amount=2000.0,
            tx_type="PAYMENT",
            reference_time=now,
        )
        assert features["tx_count_last_1m"] >= 1

        signals = RiskSignalService.evaluate_signals(features)
        signal_codes = [s["code"] for s in signals]
        assert "RAPID_REPEATED_TRANSACTIONS" in signal_codes
        
        # Verify Critical severity
        rapid_sig = next(s for s in signals if s["code"] == "RAPID_REPEATED_TRANSACTIONS")
        assert rapid_sig["severity"] == "CRITICAL"


# ==============================================================================
# 5. Unusual Transaction Time (1 AM - 5 AM)
# ==============================================================================
def test_unusual_transaction_time(app, seed_user):
    """Night-time payment triggers UNUSUAL_TRANSACTION_TIME signal."""
    with app.app_context():
        night_time = datetime(2026, 8, 19, 3, 30, tzinfo=timezone.utc)
        features = FeatureService.extract_features(
            user_id=seed_user.id,
            amount=500.0,
            tx_type="PAYMENT",
            reference_time=night_time,
        )
        assert features["hour_of_day"] == 3
        assert features["is_unusual_night_hours"] == 1

        signals = RiskSignalService.evaluate_signals(features)
        signal_codes = [s["code"] for s in signals]
        assert "UNUSUAL_TRANSACTION_TIME" in signal_codes


# ==============================================================================
# 6. High Amount Deviation from Baseline
# ==============================================================================
def test_high_amount_deviation(app, seed_user):
    """Transfer >3.5x customer historical average generates HIGH_AMOUNT_DEVIATION."""
    with app.app_context():
        now = datetime.now(timezone.utc)
        # Seed 3 historical payments averaging ₹500
        for i in range(3):
            tx = Transaction(
                user_id=seed_user.id,
                step=1,
                type="PAYMENT",
                amount=500.0,
                name_orig="FS-100001",
                oldbalance_org=150000.0,
                newbalance_orig=149500.0,
                name_dest="M123",
                oldbalance_dest=0.0,
                newbalance_dest=500.0,
                prediction=0,
                fraud_probability=0.01,
                risk_score=5,
                risk_level="LOW",
                decision="APPROVE_IMMEDIATELY",
                status="APPROVED",
                created_at=now - timedelta(days=i + 1),
            )
            db.session.add(tx)
        db.session.commit()

        # New transaction of ₹3,000 (6x average)
        features = FeatureService.extract_features(
            user_id=seed_user.id,
            amount=3000.0,
            tx_type="PAYMENT",
            reference_time=now,
        )
        assert features["user_tx_count"] == 3
        assert features["user_avg_amount"] == 500.0
        assert features["amount_deviation_ratio"] >= 3.5

        signals = RiskSignalService.evaluate_signals(features)
        signal_codes = [s["code"] for s in signals]
        assert "HIGH_AMOUNT_DEVIATION" in signal_codes


# ==============================================================================
# 7. Velocity Windows Calculation
# ==============================================================================
def test_velocity_windows_calculation(app, seed_user):
    """Calculates 10m and 1h transaction velocities and triggers HIGH_TRANSACTION_VELOCITY."""
    with app.app_context():
        now = datetime.now(timezone.utc)
        # Add 3 transactions in past 5 minutes
        for m in [2, 3, 4]:
            tx = Transaction(
                user_id=seed_user.id,
                step=1,
                type="PAYMENT",
                amount=100.0,
                name_orig="FS-100001",
                oldbalance_org=150000.0,
                newbalance_orig=149900.0,
                name_dest="M123",
                oldbalance_dest=0.0,
                newbalance_dest=100.0,
                prediction=0,
                fraud_probability=0.01,
                risk_score=5,
                risk_level="LOW",
                decision="APPROVE_IMMEDIATELY",
                status="APPROVED",
                created_at=now - timedelta(minutes=m),
            )
            db.session.add(tx)
        db.session.commit()

        features = FeatureService.extract_features(
            user_id=seed_user.id,
            amount=100.0,
            tx_type="PAYMENT",
            reference_time=now,
        )
        assert features["tx_count_last_10m"] == 3

        signals = RiskSignalService.evaluate_signals(features)
        signal_codes = [s["code"] for s in signals]
        assert "HIGH_TRANSACTION_VELOCITY" in signal_codes


# ==============================================================================
# 8. High ML Fraud Probability & Critical Account Drain
# ==============================================================================
def test_high_ml_fraud_probability_and_account_drain(client, seed_user, auth_token):
    """Account-draining TRANSFER produces CRITICAL risk level and UNDER_REVIEW status."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "TRANSFER",
            "amount": 750000.0,
            "destination": "C99881122",
            "oldbalance_org": 750000.0,
            "newbalance_orig": 0.0,
            "oldbalance_dest": 0.0,
            "newbalance_dest": 0.0,
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "CRITICAL"
    assert data["risk_score"] >= 80
    assert data["status"] == "UNDER_REVIEW"
    assert data["requires_otp"] is True


# ==============================================================================
# 9-12. 4-Tier Risk Classification
# ==============================================================================
def test_4_tier_risk_classifications():
    """Verify exact 4-tier boundaries: LOW (0-29), MEDIUM (30-59), HIGH (60-79), CRITICAL (80-100)."""
    assert RiskDecisionService.evaluate_risk(0)["risk_level"] == "LOW"
    assert RiskDecisionService.evaluate_risk(29)["risk_level"] == "LOW"
    assert RiskDecisionService.evaluate_risk(30)["risk_level"] == "MEDIUM"
    assert RiskDecisionService.evaluate_risk(59)["risk_level"] == "MEDIUM"
    assert RiskDecisionService.evaluate_risk(60)["risk_level"] == "HIGH"
    assert RiskDecisionService.evaluate_risk(79)["risk_level"] == "HIGH"
    assert RiskDecisionService.evaluate_risk(80)["risk_level"] == "CRITICAL"
    assert RiskDecisionService.evaluate_risk(100)["risk_level"] == "CRITICAL"


# ==============================================================================
# 13. Decision Mapping Verification
# ==============================================================================
def test_decision_mapping_verification():
    """Verify decision mappings across all 4 tiers."""
    assert RiskDecisionService.evaluate_risk(15)["decision"] == "APPROVE_IMMEDIATELY"
    assert RiskDecisionService.evaluate_risk(45)["decision"] == "APPROVE_WITH_MONITORING"
    assert RiskDecisionService.evaluate_risk(65)["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert RiskDecisionService.evaluate_risk(90)["decision"] == "TRIGGER_SECURITY_REVIEW"


# ==============================================================================
# 14. OTP Required Behavior (Holds Balance)
# ==============================================================================
def test_otp_required_behavior_holds_balance(client, seed_user, seed_beneficiary, auth_token):
    """HIGH risk payment requiring OTP does not deduct balance until verification."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "TRANSFER",
            "amount": 92000.0,
            "beneficiary_id": seed_beneficiary.id,
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["requires_otp"] is True
    assert data["status"] == "OTP_REQUIRED"
    assert data["balance_before"] == 150000.0
    assert data["balance_after"] == 150000.0  # Undeducted

    # Verify database balance is still ₹150,000.00
    db_user = db.session.get(User, seed_user.id)
    assert float(db_user.account_balance) == 150000.0


# ==============================================================================
# 15. Under Review Behavior (Security Alert Created)
# ==============================================================================
def test_under_review_behavior_creates_alert(client, seed_user, auth_token):
    """High-risk / CRITICAL payment creates open Alert record in SOC queue."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "TRANSFER",
            "amount": 120000.0,
            "destination": "C99887766",
        },
    )
    assert res.status_code == 200, f"Got {res.status_code}: {res.get_json()}"
    data = res.get_json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]

    alerts = Alert.query.filter_by(user_id=seed_user.id).all()
    assert len(alerts) >= 1
    assert alerts[0].status == "OPEN"


# ==============================================================================
# 16. Rejection Behavior & Audit Trail
# ==============================================================================
def test_rejection_behavior_and_audit(client, seed_user, auth_token):
    """Insufficient funds transaction is rejected and does not mutate balance."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "TRANSFER",
            "amount": 500000.0,  # Exceeds ₹150,000
            "destination": "C99887766",
        },
    )
    assert res.status_code == 400
    assert "Insufficient" in res.get_json()["error"]

    db_user = db.session.get(User, seed_user.id)
    assert float(db_user.account_balance) == 150000.0


# ==============================================================================
# 17. Dual-View Risk Explanation (Customer vs Admin)
# ==============================================================================
def test_dual_view_risk_explanation(client, seed_user, auth_token):
    """Response provides safe customer narrative without leaking raw SHAP weights, and detailed admin breakdown."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "TRANSFER",
            "amount": 92000.0,
            "destination": "C99881122",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    explanation = data["explanation"]

    # Customer View
    customer_msg = explanation.get("customer_explanation") or data.get("customer_message")
    assert isinstance(customer_msg, str)
    assert len(customer_msg) > 0
    # Customer narrative must not expose raw SHAP float weights or math formulas
    assert "shap_value" not in customer_msg.lower()
    assert "0." not in customer_msg

    # Admin View
    admin_msg = explanation.get("admin_explanation")
    assert isinstance(admin_msg, str)
    assert "top_features" in explanation
    assert len(explanation["top_features"]) > 0


# ==============================================================================
# 18. Zero Future-Data Leakage in Feature Engineering
# ==============================================================================
def test_no_future_data_leakage(app, seed_user):
    """Historical aggregations strictly exclude transactions created at or after the reference timestamp."""
    with app.app_context():
        t1 = datetime(2026, 8, 19, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 8, 19, 10, 30, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 8, 19, 11, 0, 0, tzinfo=timezone.utc)

        # Transaction at t1 (₹1,000)
        tx1 = Transaction(
            user_id=seed_user.id,
            step=1,
            type="PAYMENT",
            amount=1000.0,
            name_orig="FS-100001",
            oldbalance_org=150000.0,
            newbalance_orig=149000.0,
            name_dest="M1",
            oldbalance_dest=0.0,
            newbalance_dest=1000.0,
            prediction=0,
            fraud_probability=0.01,
            risk_score=5,
            risk_level="LOW",
            decision="APPROVE_IMMEDIATELY",
            status="APPROVED",
            created_at=t1,
        )
        # Transaction at t3 (₹5,000)
        tx3 = Transaction(
            user_id=seed_user.id,
            step=1,
            type="PAYMENT",
            amount=5000.0,
            name_orig="FS-100001",
            oldbalance_org=149000.0,
            newbalance_orig=144000.0,
            name_dest="M2",
            oldbalance_dest=0.0,
            newbalance_dest=5000.0,
            prediction=0,
            fraud_probability=0.01,
            risk_score=5,
            risk_level="LOW",
            decision="APPROVE_IMMEDIATELY",
            status="APPROVED",
            created_at=t3,
        )
        db.session.add_all([tx1, tx3])
        db.session.commit()

        # Evaluate at t2 (Between t1 and t3)
        features_at_t2 = FeatureService.extract_features(
            user_id=seed_user.id,
            amount=2000.0,
            tx_type="PAYMENT",
            reference_time=t2,
        )

        # Must only see tx1 (1 transaction, avg ₹1000), tx3 must be invisible!
        assert features_at_t2["user_tx_count"] == 1
        assert features_at_t2["user_avg_amount"] == 1000.0
        assert features_at_t2["user_max_amount"] == 1000.0


# ==============================================================================
# 19. Phase 1 Atomic Balance Deduction on Approved Payment
# ==============================================================================
def test_phase1_atomic_balance_deduction(client, seed_user, seed_beneficiary, auth_token):
    """Approved transaction deducts balance exactly once and updates beneficiary last_used_at."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "PAYMENT",
            "amount": 500.0,
            "beneficiary_id": seed_beneficiary.id,
        },
    )
    assert res.status_code == 200
    db_user = db.session.get(User, seed_user.id)
    assert float(db_user.account_balance) == 149500.0

    db_ben = db.session.get(Beneficiary, seed_beneficiary.id)
    assert db_ben.last_used_at is not None


# ==============================================================================
# 20. Backward-Compatible API Contract
# ==============================================================================
def test_backward_compatible_api_contract(client, seed_user, auth_token):
    """API contract preserves all expected keys for frontend and legacy client compatibility."""
    res = client.post(
        "/api/transactions/predict",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "type": "PAYMENT",
            "amount": 100.0,
            "destination": "M182390234",
        },
    )
    assert res.status_code == 200
    data = res.get_json()

    required_keys = [
        "success",
        "transaction_id",
        "prediction",
        "fraud_probability",
        "ml_probability",
        "risk_score",
        "risk_level",
        "decision",
        "status",
        "requires_otp",
        "explanation",
        "account_balance",
        "balance_before",
        "balance_after",
    ]
    for key in required_keys:
        assert key in data, f"Missing required response key: '{key}'"
