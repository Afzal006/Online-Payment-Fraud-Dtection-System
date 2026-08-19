"""
Database Seed Script for Development and Demonstration.

Idempotently creates standard demo customer and administrator accounts:
- Regular User: user@example.com ("Arjun Sharma")
- Customer 1: customer1@example.com ("Priya Patel")
- Customer 2: customer2@example.com ("Vikram Malhotra")
- Customer 3: customer3@example.com ("Ananya Roy")
- Administrator: admin@example.com ("SOC Admin Officer")

Seeds initial realistic transactions and security alerts across customers so the
Admin SOC portal immediately displays global multi-customer data.
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import os
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.models.transaction import Transaction
from app.models.alert import Alert


def seed_database(app=None, config_name: str = "development") -> bool:
    """Idempotently seed demo accounts, payment identities, beneficiaries, and sample transactions."""
    if app is None:
        env = config_name if config_name else os.getenv("FLASK_ENV", "development")
        app = create_app(env)
    else:
        env = app.config.get("FLASK_ENV", "testing")

    with app.app_context():
        db.create_all()

        demo_user_password = os.getenv("DEMO_USER_PASSWORD", "UserDemo2026!")
        demo_admin_password = os.getenv("DEMO_ADMIN_PASSWORD", "AdminDemo2026!")

        demo_accounts = [
            {
                "name": "Arjun Sharma",
                "email": "user@example.com",
                "password": demo_user_password,
                "role": "USER",
                "phone_number": "+91 98765 43210",
                "customer_account_id": "FS-100001",
                "primary_upi_id": "arjun@fraudshield",
                "account_balance": 150000.0,
                "is_phone_verified": True,
            },
            {
                "name": "Priya Patel",
                "email": "customer1@example.com",
                "password": demo_user_password,
                "role": "USER",
                "phone_number": "+91 98765 11223",
                "customer_account_id": "FS-100002",
                "primary_upi_id": "priya@fraudshield",
                "account_balance": 85400.0,
                "is_phone_verified": True,
            },
            {
                "name": "Vikram Malhotra",
                "email": "customer2@example.com",
                "password": demo_user_password,
                "role": "USER",
                "phone_number": "+91 98765 33445",
                "customer_account_id": "FS-100003",
                "primary_upi_id": "vikram@fraudshield",
                "account_balance": 240000.0,
                "is_phone_verified": True,
            },
            {
                "name": "Ananya Roy",
                "email": "customer3@example.com",
                "password": demo_user_password,
                "role": "USER",
                "phone_number": "+91 98765 44556",
                "customer_account_id": "FS-100004",
                "primary_upi_id": "ananya@fraudshield",
                "account_balance": 110000.0,
                "is_phone_verified": True,
            },
            {
                "name": "SOC Admin Officer",
                "email": "admin@example.com",
                "password": demo_admin_password,
                "role": "ADMIN",
                "phone_number": "+91 98765 99999",
                "customer_account_id": "FS-ADMIN-01",
                "primary_upi_id": "admin@fraudshield",
                "account_balance": 0.0,
                "is_phone_verified": True,
            },
        ]

        print(f"[*] Seeding demo accounts for environment '{env}'...")
        user_map = {}
        for acc in demo_accounts:
            existing = User.query.filter_by(email=acc["email"]).first()
            if existing:
                print(f"[~] Account '{acc['email']}' already exists (Role: {existing.role}). Updating profile fields if empty...")
                if not existing.customer_account_id:
                    existing.customer_account_id = acc["customer_account_id"]
                if not existing.phone_number:
                    existing.phone_number = acc["phone_number"]
                if not existing.primary_upi_id:
                    existing.primary_upi_id = acc["primary_upi_id"]
                if existing.account_balance is None or (existing.role == "USER" and existing.account_balance == 0):
                    existing.account_balance = acc["account_balance"]
                existing.is_phone_verified = True
                user_map[acc["email"]] = existing
            else:
                user = User(
                    name=acc["name"],
                    email=acc["email"],
                    role=acc["role"],
                    phone_number=acc["phone_number"],
                    customer_account_id=acc["customer_account_id"],
                    primary_upi_id=acc["primary_upi_id"],
                    account_balance=acc["account_balance"],
                    is_phone_verified=acc["is_phone_verified"],
                    is_active=True,
                )
                user.set_password(acc["password"])
                db.session.add(user)
                db.session.flush()
                user_map[acc["email"]] = user
                print(f"[+] Created account: {acc['email']} ({acc['role']}) [{acc['customer_account_id']}]")

        db.session.commit()

        # Seed sample beneficiaries
        print("[*] Seeding sample beneficiaries for demo customers...")
        sample_beneficiaries = [
            # For Arjun Sharma (user@example.com)
            {
                "user_email": "user@example.com",
                "beneficiary_name": "Priya Patel",
                "beneficiary_upi_id": "priya@fraudshield",
                "beneficiary_phone": "+91 98765 11223",
                "nickname": "Priya (Colleague)",
                "is_verified": True,
            },
            {
                "user_email": "user@example.com",
                "beneficiary_name": "Rahul Verma",
                "beneficiary_upi_id": "rahul@fraudshield",
                "beneficiary_phone": "+91 98765 22334",
                "nickname": "Rahul (Brother)",
                "is_verified": True,
            },
            {
                "user_email": "user@example.com",
                "beneficiary_name": "Airtel Broadband",
                "beneficiary_upi_id": "airtel.broadband@fraudshield",
                "beneficiary_phone": "+91 98765 00001",
                "nickname": "Home Fiber Bill",
                "is_verified": True,
            },
            # For Priya Patel (customer1@example.com)
            {
                "user_email": "customer1@example.com",
                "beneficiary_name": "Arjun Sharma",
                "beneficiary_upi_id": "arjun@fraudshield",
                "beneficiary_phone": "+91 98765 43210",
                "nickname": "Arjun (Team Lead)",
                "is_verified": True,
            },
            {
                "user_email": "customer1@example.com",
                "beneficiary_name": "Vikram Malhotra",
                "beneficiary_upi_id": "vikram@fraudshield",
                "beneficiary_phone": "+91 98765 33445",
                "nickname": "Vikram",
                "is_verified": True,
            },
            # For Vikram Malhotra (customer2@example.com)
            {
                "user_email": "customer2@example.com",
                "beneficiary_name": "Ananya Roy",
                "beneficiary_upi_id": "ananya@fraudshield",
                "beneficiary_phone": "+91 98765 44556",
                "nickname": "Ananya",
                "is_verified": True,
            },
        ]

        beneficiary_count = 0
        for b_info in sample_beneficiaries:
            user = user_map.get(b_info["user_email"])
            if not user:
                continue

            existing_b = Beneficiary.query.filter_by(
                user_id=user.id,
                beneficiary_upi_id=b_info["beneficiary_upi_id"],
            ).first()

            if not existing_b:
                b = Beneficiary(
                    user_id=user.id,
                    beneficiary_name=b_info["beneficiary_name"],
                    beneficiary_upi_id=b_info["beneficiary_upi_id"],
                    beneficiary_phone=b_info.get("beneficiary_phone"),
                    nickname=b_info.get("nickname"),
                    is_verified=b_info.get("is_verified", True),
                    status="ACTIVE",
                    created_at=datetime.now(timezone.utc),
                )
                db.session.add(b)
                beneficiary_count += 1

        db.session.commit()
        if beneficiary_count > 0:
            print(f"[+] Seeded {beneficiary_count} verified beneficiaries across customers.")
        else:
            print("[~] Beneficiaries already present.")

        # Seed sample multi-customer transactions if customers have no transactions
        now = datetime.now(timezone.utc)
        sample_tx_data = [
            # User 1 (Arjun Sharma)
            {
                "email": "user@example.com",
                "type": "PAYMENT",
                "amount": 1250.00,
                "dest": "M100293",
                "risk_score": 12,
                "risk_level": "LOW",
                "decision": "APPROVE_IMMEDIATELY",
                "status": "APPROVED",
                "prob": 0.01,
                "rule_score": 10,
                "offset_mins": 120,
            },
            {
                "email": "user@example.com",
                "type": "TRANSFER",
                "amount": 45000.00,
                "dest": "C8821903",
                "risk_score": 45,
                "risk_level": "MEDIUM",
                "decision": "TRIGGER_OTP_VERIFICATION",
                "status": "APPROVED",
                "prob": 0.04,
                "rule_score": 55,
                "offset_mins": 90,
            },
            # Customer 1 (Priya Patel)
            {
                "email": "customer1@example.com",
                "type": "PAYMENT",
                "amount": 850.00,
                "dest": "M554433",
                "risk_score": 8,
                "risk_level": "LOW",
                "decision": "APPROVE_IMMEDIATELY",
                "status": "APPROVED",
                "prob": 0.01,
                "rule_score": 5,
                "offset_mins": 75,
            },
            {
                "email": "customer1@example.com",
                "type": "TRANSFER",
                "amount": 250001.00,
                "dest": "C998811",
                "risk_score": 78,
                "risk_level": "HIGH",
                "decision": "TRIGGER_OTP_ALERT_AND_REVIEW",
                "status": "UNDER_REVIEW",
                "prob": 0.08,
                "rule_score": 95,
                "offset_mins": 60,
                "create_alert": True,
                "alert_msg": "High-value transfer exceeding ₹1,00,000 threshold without balance verification.",
                "severity": "HIGH",
            },
            # Customer 2 (Vikram Malhotra)
            {
                "email": "customer2@example.com",
                "type": "TRANSFER",
                "amount": 92000.00,
                "dest": "C443322",
                "risk_score": 63,
                "risk_level": "MEDIUM",
                "decision": "TRIGGER_OTP_VERIFICATION",
                "status": "OTP_REQUIRED",
                "prob": 0.05,
                "rule_score": 77,
                "offset_mins": 45,
            },
            {
                "email": "customer2@example.com",
                "type": "CASH_OUT",
                "amount": 750000.00,
                "dest": "M991122",
                "risk_score": 96,
                "risk_level": "HIGH",
                "decision": "TRIGGER_OTP_ALERT_AND_REVIEW",
                "status": "UNDER_REVIEW",
                "prob": 0.99,
                "rule_score": 100,
                "offset_mins": 30,
                "create_alert": True,
                "alert_msg": "Critical balance drain pattern: entire account balance liquidated in single CASH_OUT.",
                "severity": "CRITICAL",
            },
            # Customer 3 (Ananya Roy)
            {
                "email": "customer3@example.com",
                "type": "PAYMENT",
                "amount": 4200.00,
                "dest": "M112233",
                "risk_score": 15,
                "risk_level": "LOW",
                "decision": "APPROVE_IMMEDIATELY",
                "status": "APPROVED",
                "prob": 0.02,
                "rule_score": 12,
                "offset_mins": 15,
            },
        ]

        print("[*] Checking sample multi-customer transaction records...")
        created_tx_count = 0
        for tx_info in sample_tx_data:
            user = user_map.get(tx_info["email"])
            if not user:
                continue

            # Check if this exact transaction already exists for user
            existing_tx = Transaction.query.filter_by(
                user_id=user.id,
                amount=tx_info["amount"],
                name_dest=tx_info["dest"],
            ).first()

            if not existing_tx:
                created_time = now - timedelta(minutes=tx_info["offset_mins"])
                narrative = f"The transaction was assessed with {tx_info['risk_level']} risk tier (Risk Score: {tx_info['risk_score']}/100)."
                exp_dict = {
                    "human_readable_summary": narrative,
                    "top_features": [
                        {"feature": "amount", "importance": 0.35, "display_name": "Transfer Amount (₹)"},
                        {"feature": "type", "importance": 0.25, "display_name": "Transaction Type"},
                    ],
                }

                tx = Transaction(
                    user_id=user.id,
                    step=1,
                    type=tx_info["type"],
                    amount=tx_info["amount"],
                    name_orig=f"C_{user.id}_ACC",
                    oldbalance_org=tx_info["amount"],
                    newbalance_orig=0.0 if tx_info["risk_level"] == "HIGH" else 10000.0,
                    name_dest=tx_info["dest"],
                    oldbalance_dest=0.0,
                    newbalance_dest=tx_info["amount"],
                    prediction=1 if tx_info["risk_level"] == "HIGH" else 0,
                    fraud_probability=tx_info["prob"],
                    risk_score=tx_info["risk_score"],
                    risk_level=tx_info["risk_level"],
                    decision=tx_info["decision"],
                    status=tx_info["status"],
                    requires_otp=(tx_info["risk_level"] in ["MEDIUM", "HIGH"]),
                    explanation_json=json.dumps(exp_dict),
                    created_at=created_time,
                )
                db.session.add(tx)
                db.session.flush()

                if tx_info.get("create_alert"):
                    alert = Alert(
                        transaction_id=tx.id,
                        user_id=user.id,
                        severity=tx_info.get("severity", "HIGH"),
                        status="OPEN",
                        message=tx_info.get("alert_msg", "Security alert"),
                        created_at=created_time,
                    )
                    db.session.add(alert)

                created_tx_count += 1

        db.session.commit()
        if created_tx_count > 0:
            print(f"[+] Successfully seeded {created_tx_count} sample multi-customer transactions and alerts.")
        else:
            print("[~] Multi-customer transaction records already present.")

        print("[+] Seed process completed successfully.")
        return True


if __name__ == "__main__":
    success = seed_database()
    sys.exit(0 if success else 1)
