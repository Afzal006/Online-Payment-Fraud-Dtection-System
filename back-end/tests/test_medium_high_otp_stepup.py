"""
Test Suite: Medium & High Risk Email OTP Step-Up Authentication Policy
Tests the 4-tier risk decision engine and multi-factor email OTP step-up verification.
"""

import pytest
from datetime import datetime, timezone, timedelta
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.otp_challenge import OTPChallenge
from app.services.risk_service import RiskDecisionService
from app.services.otp_service import OTPService
from app.providers.email_provider import DevelopmentEmailProvider


@pytest.fixture
def app():
    """Create test application configured for testing with in-memory SQLite database."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        DevelopmentEmailProvider.clear_history()
        yield test_app
        db.session.remove()
        db.drop_all()
        DevelopmentEmailProvider.clear_history()


@pytest.fixture
def client(app):
    """Test HTTP client."""
    return app.test_client()


@pytest.fixture
def setup_user_and_token(client):
    """Create a verified user with initial balance and return auth headers."""
    client.post("/api/auth/register", json={
        "name": "StepUp Test User",
        "email": "stepup_user@example.com",
        "password": "Password123!",
        "role": "USER",
    })
    reg_otp = DevelopmentEmailProvider.get_last_email_otp("stepup_user@example.com")
    if reg_otp:
        client.post("/api/auth/verify-email-otp", json={
            "email": "stepup_user@example.com",
            "otp_code": reg_otp,
        })

    # Set known starting balance and payment PIN
    user = User.query.filter_by(email="stepup_user@example.com").first()
    user.account_balance = 200000.0
    user.set_payment_pin("123456")
    db.session.commit()

    login_res = client.post("/api/auth/login", json={
        "email": "stepup_user@example.com",
        "password": "Password123!",
    })
    token = login_res.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return user.id, headers


# ==============================================================================
# 1. 4-Tier Policy Direct Unit Tests
# ==============================================================================
def test_4tier_policy_definitions():
    """Verify exact boundaries across all 4 tiers."""
    # LOW (0-29)
    low_eval = RiskDecisionService.evaluate_risk(15)
    assert low_eval["risk_level"] == "LOW"
    assert low_eval["decision"] == "APPROVE_IMMEDIATELY"
    assert low_eval["initial_status"] == "APPROVED"
    assert low_eval["requires_otp"] is False
    assert low_eval["create_alert"] is False

    # MEDIUM (30-59)
    med_eval_30 = RiskDecisionService.evaluate_risk(30)
    assert med_eval_30["risk_level"] == "MEDIUM"
    assert med_eval_30["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert med_eval_30["initial_status"] == "OTP_REQUIRED"
    assert med_eval_30["requires_otp"] is True
    assert med_eval_30["create_alert"] is True
    assert med_eval_30["alert_severity"] == "MEDIUM"

    med_eval_59 = RiskDecisionService.evaluate_risk(59)
    assert med_eval_59["risk_level"] == "MEDIUM"
    assert med_eval_59["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert med_eval_59["requires_otp"] is True

    # HIGH (60-79)
    high_eval_60 = RiskDecisionService.evaluate_risk(60)
    assert high_eval_60["risk_level"] == "HIGH"
    assert high_eval_60["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert high_eval_60["initial_status"] == "OTP_REQUIRED"
    assert high_eval_60["requires_otp"] is True
    assert high_eval_60["create_alert"] is True
    assert high_eval_60["alert_severity"] == "HIGH"

    high_eval_79 = RiskDecisionService.evaluate_risk(79)
    assert high_eval_79["risk_level"] == "HIGH"
    assert high_eval_79["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert high_eval_79["requires_otp"] is True

    # CRITICAL (80-100)
    crit_eval_80 = RiskDecisionService.evaluate_risk(80)
    assert crit_eval_80["risk_level"] == "CRITICAL"
    assert crit_eval_80["decision"] == "TRIGGER_SECURITY_REVIEW"
    assert crit_eval_80["initial_status"] == "UNDER_REVIEW"
    assert crit_eval_80["requires_otp"] is True
    assert crit_eval_80["create_alert"] is True
    assert crit_eval_80["alert_severity"] == "CRITICAL"


# ==============================================================================
# 2. Scenario A: LOW Risk (Score 0-29) -> Immediate Auto-Approval
# ==============================================================================
def test_scenario_a_low_risk_immediate_approval(client, setup_user_and_token):
    """Low risk transaction is auto-approved with zero OTP and immediate atomic deduction."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "PAYMENT",
        "amount": 250.0,
        "destination": "groceries@fraudshield",
        "payment_pin": "123456",
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "LOW"
    assert data["decision"] == "APPROVE_IMMEDIATELY"
    assert data["status"] == "APPROVED"
    assert data["requires_otp"] is False
    assert data["balance_before"] == 200000.0
    assert data["balance_after"] == 199750.0

    # User balance in DB is debited
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 199750.0

    # No OTP challenge was generated or emailed
    challenges = OTPChallenge.query.filter_by(transaction_id=data["transaction_id"]).all()
    assert len(challenges) == 0


# ==============================================================================
# 3. Scenario B, C, D: MEDIUM Risk (Score 30-59) -> Email OTP Step-Up Flow
# ==============================================================================
def test_scenario_b_medium_risk_enters_otp_required_zero_debit(client, setup_user_and_token):
    """MEDIUM risk transaction enters OTP_REQUIRED, zero balance is deducted, and email OTP challenge is dispatched."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    # ₹50,000 TRANSFER evaluates to MEDIUM risk
    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 50000.0,
        "destination": "vendor_med@fraudshield",
        "payment_pin": "123456",
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "MEDIUM"
    assert data["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert data["status"] == "OTP_REQUIRED"
    assert data["requires_otp"] is True

    # Critical invariant: Zero balance deduction
    assert data["balance_before"] == 200000.0
    assert data["balance_after"] == 200000.0
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 200000.0

    # Generate OTP challenge via endpoint
    tx_id = data["transaction_id"]
    otp_req = client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})
    assert otp_req.status_code == 200

    # Verify email was dispatched via DevelopmentEmailProvider
    sent = DevelopmentEmailProvider.get_last_email("stepup_user@example.com")
    assert sent is not None
    assert sent["type"] == "TRANSACTION_OTP"
    assert sent["transaction_id"] == tx_id
    assert len(sent["otp_code"]) == 6


def test_scenario_c_medium_risk_wrong_otp_rejected_balance_held(client, setup_user_and_token):
    """Wrong OTP attempt is rejected, transaction remains held, zero balance deducted."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 50000.0,
        "destination": "vendor_med@fraudshield",
        "payment_pin": "123456",
    })
    tx_id = res.get_json()["transaction_id"]

    # Generate challenge
    client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})

    # Submit invalid OTP code
    verify_res = client.post("/api/otp/verify", headers=headers, json={
        "transaction_id": tx_id,
        "otp_code": "000000",
    })
    assert verify_res.status_code == 400
    assert verify_res.get_json()["success"] is False

    # Transaction in DB is still held (not approved)
    tx = db.session.get(Transaction, tx_id)
    assert tx.status == "OTP_REQUIRED"

    # Balance is completely protected
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 200000.0


def test_scenario_d_medium_risk_correct_otp_approves_and_settles(client, setup_user_and_token):
    """Correct OTP approves MEDIUM transaction and atomically debits ledger balance exactly once."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 50000.0,
        "destination": "vendor_med@fraudshield",
        "payment_pin": "123456",
    })
    tx_id = res.get_json()["transaction_id"]

    # Request OTP
    client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})
    sent_otp = DevelopmentEmailProvider.get_last_email_otp("stepup_user@example.com")
    assert sent_otp is not None

    # Verify with correct code
    verify_res = client.post("/api/otp/verify", headers=headers, json={
        "transaction_id": tx_id,
        "otp_code": sent_otp,
    })
    assert verify_res.status_code == 200
    v_data = verify_res.get_json()
    assert v_data["success"] is True
    assert v_data["transaction"]["status"] == "APPROVED"

    # Transaction in DB is APPROVED and balance deducted atomically
    tx = db.session.get(Transaction, tx_id)
    assert tx.status == "APPROVED"
    assert tx.balance_before == 200000.0
    assert tx.balance_after == 150000.0

    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 150000.0


# ==============================================================================
# 4. Scenario E, F, G: HIGH Risk (Score 60-79) -> Email OTP Step-Up Flow
# ==============================================================================
def test_scenario_e_high_risk_enters_otp_required_zero_debit(client, setup_user_and_token):
    """HIGH risk payment (e.g. ₹72,000) enters OTP_REQUIRED, zero debit until verified."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "PAYMENT",
        "amount": 72000.0,
        "destination": "highrisk_dest@fraudshield",
        "payment_pin": "123456",
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "HIGH"
    assert data["decision"] == "TRIGGER_OTP_VERIFICATION"
    assert data["status"] == "OTP_REQUIRED"
    assert data["requires_otp"] is True

    # Balance held intact
    assert data["balance_before"] == 200000.0
    assert data["balance_after"] == 200000.0
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 200000.0


def test_scenario_g_high_risk_correct_otp_approves_and_settles(client, setup_user_and_token):
    """Correct OTP approves HIGH risk transaction and atomically deducts amount."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "PAYMENT",
        "amount": 72000.0,
        "destination": "highrisk_dest@fraudshield",
        "payment_pin": "123456",
    })
    tx_id = res.get_json()["transaction_id"]

    client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})
    sent_otp = DevelopmentEmailProvider.get_last_email_otp("stepup_user@example.com")

    verify_res = client.post("/api/otp/verify", headers=headers, json={
        "transaction_id": tx_id,
        "otp_code": sent_otp,
    })
    assert verify_res.status_code == 200
    assert verify_res.get_json()["transaction"]["status"] == "APPROVED"

    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 128000.0


# ==============================================================================
# 5. Scenario H: CRITICAL Risk (Score 80-100) -> Queued for Security Review
# ==============================================================================
def test_scenario_h_critical_risk_queued_for_security_review(client, setup_user_and_token):
    """CRITICAL risk transaction enters UNDER_REVIEW, requires admin review, zero debit."""
    user_id, headers = setup_user_and_token

    # 100% balance drain evaluates to CRITICAL risk
    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 200000.0,
        "destination": "drain_dest@fraudshield",
        "payment_pin": "123456",
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data["risk_level"] == "CRITICAL"
    assert data["decision"] == "TRIGGER_SECURITY_REVIEW"
    assert data["status"] == "UNDER_REVIEW"
    assert data["requires_otp"] is True

    # Zero deduction
    assert data["balance_before"] == 200000.0
    assert data["balance_after"] == 200000.0
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 200000.0


# ==============================================================================
# 6. Scenario I: OTP Replay Attack Prevention
# ==============================================================================
def test_scenario_i_otp_replay_attack_rejected(client, setup_user_and_token):
    """Submitting the same OTP code again after successful verification is rejected (no double debit)."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 50000.0,
        "destination": "replay_dest@fraudshield",
        "payment_pin": "123456",
    })
    tx_id = res.get_json()["transaction_id"]

    client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})
    sent_otp = DevelopmentEmailProvider.get_last_email_otp("stepup_user@example.com")

    # First verification (Success)
    v1 = client.post("/api/otp/verify", headers=headers, json={
        "transaction_id": tx_id,
        "otp_code": sent_otp,
    })
    assert v1.status_code == 200

    # Second verification attempt (Replay -> Rejected)
    v2 = client.post("/api/otp/verify", headers=headers, json={
        "transaction_id": tx_id,
        "otp_code": sent_otp,
    })
    assert v2.status_code == 400
    assert v2.get_json()["success"] is False

    # Balance debited exactly once (200,000 - 50,000 = 150,000)
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 150000.0


# ==============================================================================
# 7. Scenario J: OTP Expiration Rejection
# ==============================================================================
def test_scenario_j_expired_otp_rejected(client, setup_user_and_token):
    """Expired OTP challenge is rejected with HTTP 410 and zero balance deducted."""
    user_id, headers = setup_user_and_token
    DevelopmentEmailProvider.clear_history()

    res = client.post("/api/transactions/predict", headers=headers, json={
        "type": "TRANSFER",
        "amount": 50000.0,
        "destination": "expiry_dest@fraudshield",
        "payment_pin": "123456",
    })
    tx_id = res.get_json()["transaction_id"]

    client.post("/api/otp/generate", headers=headers, json={"transaction_id": tx_id})
    sent_otp = DevelopmentEmailProvider.get_last_email_otp("stepup_user@example.com")

    # Manually expire the challenge in the DB
    challenge = OTPChallenge.query.filter_by(transaction_id=tx_id).first()
    challenge.expires_at = datetime.now(timezone.utc) - timedelta(seconds=60)
    db.session.commit()

    # Attempt to verify with the expired OTP
    v_res = client.post("/api/otp/verify", headers=headers, json={
        "transaction_id": tx_id,
        "otp_code": sent_otp,
    })
    assert v_res.status_code == 410
    assert v_res.get_json()["success"] is False

    # Transaction remains held
    tx = db.session.get(Transaction, tx_id)
    assert tx.status == "OTP_REQUIRED"

    # Balance protected
    user = db.session.get(User, user_id)
    assert float(user.account_balance) == 200000.0
