"""
Database Initialization Script.

Creates all database tables, constraints, and indexes according to SQLAlchemy entity models.
Safe for both MySQL production/development and SQLite local testing.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import os
from app import create_app
from app.extensions import db
from app.models import (
    User,
    Beneficiary,
    Transaction,
    Alert,
    OTPChallenge,
    PasswordResetToken,
    AuditLog,
    DeviceProfile,
    GeoLocationRecord,
    SOCCase,
    CaseNote,
)


def init_database(app=None, config_name: str = "development") -> bool:
    """Initialize database tables and schema."""
    if app is None:
        env = config_name if config_name else os.getenv("FLASK_ENV", "development")
        app = create_app(env)

    with app.app_context():
        print(f"[*] Initializing database for environment '{app.config.get('FLASK_ENV', 'development')}'...")
        print(f"[*] Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI')}")

        db.create_all()

        # Verify and migrate columns if missing (e.g. SQLite schema evolution)
        inspector = db.inspect(db.engine)
        table_names = inspector.get_table_names()
        print(f"[+] Successfully verified tables: {table_names}")

        if "users" in table_names:
            user_cols = [c["name"] for c in inspector.get_columns("users")]
            with db.engine.connect() as conn:
                if "phone_number" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_number'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_number VARCHAR(20)"))
                if "customer_account_id" not in user_cols:
                    print("[*] Migrating users schema: adding column 'customer_account_id'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN customer_account_id VARCHAR(30)"))
                if "primary_upi_id" not in user_cols:
                    print("[*] Migrating users schema: adding column 'primary_upi_id'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN primary_upi_id VARCHAR(100)"))
                if "account_balance" not in user_cols:
                    print("[*] Migrating users schema: adding column 'account_balance'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN account_balance FLOAT DEFAULT 100000.0"))
                if "is_phone_verified" not in user_cols:
                    print("[*] Migrating users schema: adding column 'is_phone_verified'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_phone_verified BOOLEAN DEFAULT 1"))
                if "is_active" not in user_cols:
                    print("[*] Migrating users schema: adding column 'is_active'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1"))
                if "password_changed_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'password_changed_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN password_changed_at DATETIME"))
                if "payment_pin_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'payment_pin_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN payment_pin_hash VARCHAR(255)"))
                if "pin_failed_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_failed_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_failed_attempts INTEGER DEFAULT 0"))
                if "pin_locked_until" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_locked_until'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_locked_until DATETIME"))
                if "is_pin_set" not in user_cols:
                    print("[*] Migrating users schema: adding column 'is_pin_set'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_pin_set BOOLEAN DEFAULT 0"))
                if "payment_pin_updated_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'payment_pin_updated_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN payment_pin_updated_at DATETIME"))
                if "phone_otp_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_hash VARCHAR(255)"))
                if "phone_otp_expires_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_expires_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_expires_at DATETIME"))
                if "phone_otp_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_attempts INTEGER DEFAULT 0"))
                if "phone_verified_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_verified_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_verified_at DATETIME"))
                if "phone_otp_last_sent_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_last_sent_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_last_sent_at DATETIME"))
                if "pin_reset_otp_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_hash VARCHAR(255)"))
                if "pin_reset_otp_expires_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_expires_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_expires_at DATETIME"))
                if "pin_reset_otp_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_attempts INTEGER DEFAULT 0"))
                if "pin_reset_otp_last_sent_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_last_sent_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_last_sent_at DATETIME"))
                if "pin_reset_request_count" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_request_count'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_request_count INTEGER DEFAULT 0"))
                if "pin_reset_window_start" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_window_start'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_window_start DATETIME"))
                conn.commit()

        if "transactions" in table_names:
            tx_cols = [c["name"] for c in inspector.get_columns("transactions")]
            with db.engine.connect() as conn:
                if "beneficiary_id" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'beneficiary_id'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN beneficiary_id INTEGER"))
                if "destination_upi_id" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'destination_upi_id'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN destination_upi_id VARCHAR(100)"))
                if "destination_name" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'destination_name'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN destination_name VARCHAR(100)"))
                if "payment_note" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'payment_note'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN payment_note VARCHAR(255)"))
                if "balance_before" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'balance_before'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN balance_before FLOAT"))
                if "balance_after" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'balance_after'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN balance_after FLOAT"))
                if "explanation_json" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'explanation_json'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN explanation_json TEXT"))
                if "idempotency_key" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'idempotency_key'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN idempotency_key VARCHAR(64)"))
                if "recipient_user_id" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'recipient_user_id'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN recipient_user_id INTEGER"))
                if "payment_method" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'payment_method'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN payment_method VARCHAR(20) DEFAULT 'UPI_ID'"))
                if "reference_id" not in tx_cols:
                    print("[*] Migrating transactions schema: adding column 'reference_id'...")
                    conn.execute(db.text("ALTER TABLE transactions ADD COLUMN reference_id VARCHAR(40)"))
                conn.commit()

        if "alerts" in table_names:
            alert_cols = [c["name"] for c in inspector.get_columns("alerts")]
            with db.engine.connect() as conn:
                if "notes" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'notes'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN notes TEXT"))
                if "resolved_by" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'resolved_by'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN resolved_by VARCHAR(100)"))
                if "case_id" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'case_id'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN case_id INTEGER"))
                if "assigned_to_id" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'assigned_to_id'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN assigned_to_id INTEGER"))
                if "assigned_at" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'assigned_at'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN assigned_at DATETIME"))
                if "acknowledged_at" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'acknowledged_at'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN acknowledged_at DATETIME"))
                if "acknowledged_by" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'acknowledged_by'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN acknowledged_by VARCHAR(100)"))
                if "dedup_signature" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'dedup_signature'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN dedup_signature VARCHAR(64)"))
                if "correlation_count" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'correlation_count'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN correlation_count INTEGER DEFAULT 1"))
                conn.commit()

        if "beneficiaries" in table_names:
            ben_cols = [c["name"] for c in inspector.get_columns("beneficiaries")]
            with db.engine.connect() as conn:
                if "cooling_period_hours" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'cooling_period_hours'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN cooling_period_hours INTEGER DEFAULT 24"))
                if "cooling_expires_at" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'cooling_expires_at'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN cooling_expires_at DATETIME"))
                if "trust_status" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'trust_status'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN trust_status VARCHAR(32) DEFAULT 'COOLING'"))
                if "successful_payment_count" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'successful_payment_count'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN successful_payment_count INTEGER DEFAULT 0"))
                if "failed_payment_count" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'failed_payment_count'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN failed_payment_count INTEGER DEFAULT 0"))
                if "total_transferred_amount" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'total_transferred_amount'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN total_transferred_amount FLOAT DEFAULT 0.0"))
                if "first_payment_at" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'first_payment_at'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN first_payment_at DATETIME"))
                if "revoked_at" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'revoked_at'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN revoked_at DATETIME"))
                if "revocation_reason" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'revocation_reason'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN revocation_reason VARCHAR(255)"))
                conn.commit()

        required_tables = {"users", "transactions", "alerts", "beneficiaries"}
        missing = required_tables - set(table_names)
        if missing:
            print(f"[!] Warning: Missing expected tables: {missing}")
            return False

        print("[+] Database initialization completed successfully.")
        return True


if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
