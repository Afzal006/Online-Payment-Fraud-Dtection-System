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


def mask_db_url(url: str) -> str:
    """Mask credentials in database URI for secure logging."""
    if not url:
        return "None"
    try:
        if "@" in url and "://" in url:
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                creds, host_part = rest.split("@", 1)
                if ":" in creds:
                    user = creds.split(":", 1)[0]
                    return f"{scheme}://{user}:***@{host_part}"
                return f"{scheme}://***@{host_part}"
        return url
    except Exception:
        return "***"


def init_database(app=None, config_name: str = "development") -> bool:
    """Initialize database tables and schema."""
    if app is None:
        env = config_name if config_name else os.getenv("FLASK_ENV", "development")
        app = create_app(env)

    with app.app_context():
        raw_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        masked_uri = mask_db_url(raw_uri)
        print(f"[*] Initializing database for environment '{app.config.get('FLASK_ENV', 'development')}'...")
        print(f"[*] Database target: {masked_uri}")

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
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_phone_verified BOOLEAN DEFAULT FALSE"))
                if "is_active" not in user_cols:
                    print("[*] Migrating users schema: adding column 'is_active'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE"))
                if "password_changed_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'password_changed_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP"))
                if "payment_pin_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'payment_pin_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN payment_pin_hash VARCHAR(255)"))
                if "pin_failed_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_failed_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_failed_attempts INTEGER DEFAULT 0"))
                if "pin_locked_until" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_locked_until'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_locked_until TIMESTAMP"))
                if "is_pin_set" not in user_cols:
                    print("[*] Migrating users schema: adding column 'is_pin_set'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_pin_set BOOLEAN DEFAULT FALSE"))
                if "payment_pin_updated_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'payment_pin_updated_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN payment_pin_updated_at TIMESTAMP"))
                if "phone_otp_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_hash VARCHAR(255)"))
                if "phone_otp_expires_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_expires_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_expires_at TIMESTAMP"))
                if "phone_otp_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_attempts INTEGER DEFAULT 0"))
                if "phone_verified_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_verified_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_verified_at TIMESTAMP"))
                if "phone_otp_last_sent_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'phone_otp_last_sent_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN phone_otp_last_sent_at TIMESTAMP"))
                if "pin_reset_otp_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_hash VARCHAR(255)"))
                if "pin_reset_otp_expires_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_expires_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_expires_at TIMESTAMP"))
                if "pin_reset_otp_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_attempts INTEGER DEFAULT 0"))
                if "pin_reset_otp_last_sent_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_otp_last_sent_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_otp_last_sent_at TIMESTAMP"))
                if "pin_reset_request_count" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_request_count'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_request_count INTEGER DEFAULT 0"))
                if "pin_reset_window_start" not in user_cols:
                    print("[*] Migrating users schema: adding column 'pin_reset_window_start'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN pin_reset_window_start TIMESTAMP"))
                if "is_email_verified" not in user_cols:
                    print("[*] Migrating users schema: adding column 'is_email_verified'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN is_email_verified BOOLEAN DEFAULT FALSE"))
                if "email_verified_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'email_verified_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP"))
                if "email_verification_otp_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'email_verification_otp_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN email_verification_otp_hash VARCHAR(255)"))
                if "email_verification_otp_expires_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'email_verification_otp_expires_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN email_verification_otp_expires_at TIMESTAMP"))
                if "email_verification_otp_attempts" not in user_cols:
                    print("[*] Migrating users schema: adding column 'email_verification_otp_attempts'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN email_verification_otp_attempts INTEGER DEFAULT 0"))
                if "email_verification_last_sent_at" not in user_cols:
                    print("[*] Migrating users schema: adding column 'email_verification_last_sent_at'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN email_verification_last_sent_at TIMESTAMP"))
                if "email_verification_token_hash" not in user_cols:
                    print("[*] Migrating users schema: adding column 'email_verification_token_hash'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN email_verification_token_hash VARCHAR(255)"))
                if "account_status" not in user_cols:
                    print("[*] Migrating users schema: adding column 'account_status'...")
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN account_status VARCHAR(30) DEFAULT 'PENDING_VERIFICATION'"))
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

            # Verify and update check_tx_risk_level constraint in SQLite if needed
            if db.engine.dialect.name == "sqlite":
                with db.engine.connect() as conn:
                    tx_sql_row = conn.execute(db.text("SELECT sql FROM sqlite_master WHERE type='table' AND name='transactions'")).fetchone()
                    if tx_sql_row and tx_sql_row[0] and "CRITICAL" not in tx_sql_row[0]:
                        print("[*] Upgrading transactions check_tx_risk_level constraint to include 'CRITICAL'...")
                        conn.execute(db.text("PRAGMA foreign_keys = OFF"))
                        current_cols = [c["name"] for c in inspector.get_columns("transactions")]
                        current_cols_str = ", ".join(current_cols)
                        
                        create_tx_sql = """
                        CREATE TABLE transactions_new (
                            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
                            user_id INTEGER NOT NULL, 
                            step INTEGER NOT NULL, 
                            type VARCHAR(20) NOT NULL, 
                            amount FLOAT NOT NULL, 
                            name_orig VARCHAR(50), 
                            oldbalance_org FLOAT NOT NULL, 
                            newbalance_orig FLOAT NOT NULL, 
                            name_dest VARCHAR(50), 
                            oldbalance_dest FLOAT NOT NULL, 
                            newbalance_dest FLOAT NOT NULL, 
                            prediction INTEGER NOT NULL, 
                            fraud_probability FLOAT NOT NULL, 
                            risk_score INTEGER NOT NULL, 
                            risk_level VARCHAR(20) NOT NULL, 
                            decision VARCHAR(50) NOT NULL, 
                            status VARCHAR(30) NOT NULL, 
                            requires_otp BOOLEAN NOT NULL, 
                            otp_code VARCHAR(10), 
                            otp_expires_at DATETIME, 
                            otp_attempts INTEGER NOT NULL, 
                            explanation_json TEXT, 
                            created_at DATETIME NOT NULL, 
                            beneficiary_id INTEGER, 
                            destination_upi_id VARCHAR(100), 
                            destination_name VARCHAR(100), 
                            payment_note VARCHAR(255), 
                            balance_before FLOAT, 
                            balance_after FLOAT, 
                            idempotency_key VARCHAR(64), 
                            recipient_user_id INTEGER, 
                            payment_method VARCHAR(20) DEFAULT 'UPI_ID', 
                            reference_id VARCHAR(40), 
                            CONSTRAINT check_tx_amount_positive CHECK (amount > 0), 
                            CONSTRAINT check_tx_fraud_prob_range CHECK (fraud_probability >= 0.0 AND fraud_probability <= 1.0), 
                            CONSTRAINT check_tx_risk_score_range CHECK (risk_score >= 0 AND risk_score <= 100), 
                            CONSTRAINT check_tx_risk_level CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')), 
                            FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
                        )
                        """
                        conn.execute(db.text(create_tx_sql))
                        conn.execute(db.text(f"INSERT INTO transactions_new ({current_cols_str}) SELECT {current_cols_str} FROM transactions"))
                        conn.execute(db.text("DROP TABLE transactions"))
                        conn.execute(db.text("ALTER TABLE transactions_new RENAME TO transactions"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_transactions_user_id ON transactions (user_id)"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_transactions_user_id_created_at ON transactions (user_id, created_at)"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_transactions_created_at ON transactions (created_at)"))
                        conn.execute(db.text("PRAGMA foreign_keys = ON"))
                        conn.commit()
                        print("[+] Transactions check constraint successfully upgraded with 'CRITICAL'.")

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
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN assigned_at TIMESTAMP"))
                if "acknowledged_at" not in alert_cols:
                    print("[*] Migrating alerts schema: adding column 'acknowledged_at'...")
                    conn.execute(db.text("ALTER TABLE alerts ADD COLUMN acknowledged_at TIMESTAMP"))
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

            if db.engine.dialect.name == "sqlite":
                with db.engine.connect() as conn:
                    alert_sql_row = conn.execute(db.text("SELECT sql FROM sqlite_master WHERE type='table' AND name='alerts'")).fetchone()
                    if alert_sql_row and alert_sql_row[0] and "LOW" not in alert_sql_row[0]:
                        print("[*] Upgrading alerts check_alert_severity constraint to include 'LOW'...")
                        conn.execute(db.text("PRAGMA foreign_keys = OFF"))
                        current_alert_cols = [c["name"] for c in inspector.get_columns("alerts")]
                        current_alert_cols_str = ", ".join(current_alert_cols)
                        
                        create_alert_sql = """
                        CREATE TABLE alerts_new (
                            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
                            transaction_id INTEGER NOT NULL, 
                            user_id INTEGER NOT NULL, 
                            alert_type VARCHAR(50) NOT NULL, 
                            severity VARCHAR(20) NOT NULL, 
                            message TEXT NOT NULL, 
                            status VARCHAR(20) NOT NULL, 
                            created_at TIMESTAMP NOT NULL, 
                            resolved_at TIMESTAMP, 
                            notes TEXT, 
                            resolved_by VARCHAR(100), 
                            case_id INTEGER, 
                            assigned_to_id INTEGER, 
                            assigned_at TIMESTAMP, 
                            acknowledged_at TIMESTAMP, 
                            acknowledged_by VARCHAR(100), 
                            dedup_signature VARCHAR(64), 
                            correlation_count INTEGER DEFAULT 1, 
                            CONSTRAINT check_alert_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')), 
                            CONSTRAINT check_alert_status CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'ESCALATED', 'DISMISSED')), 
                            FOREIGN KEY(transaction_id) REFERENCES transactions (id) ON DELETE CASCADE, 
                            FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
                        )
                        """
                        conn.execute(db.text(create_alert_sql))
                        conn.execute(db.text(f"INSERT INTO alerts_new ({current_alert_cols_str}) SELECT {current_alert_cols_str} FROM alerts"))
                        conn.execute(db.text("DROP TABLE alerts"))
                        conn.execute(db.text("ALTER TABLE alerts_new RENAME TO alerts"))
                        conn.execute(db.text("CREATE UNIQUE INDEX IF NOT EXISTS ix_alerts_transaction_id ON alerts (transaction_id)"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_alerts_user_id ON alerts (user_id)"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status)"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_alerts_created_at ON alerts (created_at)"))
                        conn.execute(db.text("CREATE INDEX IF NOT EXISTS ix_alerts_user_id_status ON alerts (user_id, status)"))
                        conn.execute(db.text("PRAGMA foreign_keys = ON"))
                        conn.commit()
                        print("[+] Alerts check constraint successfully upgraded.")

        if "beneficiaries" in table_names:
            ben_cols = [c["name"] for c in inspector.get_columns("beneficiaries")]
            with db.engine.connect() as conn:
                if "cooling_period_hours" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'cooling_period_hours'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN cooling_period_hours INTEGER DEFAULT 24"))
                if "cooling_expires_at" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'cooling_expires_at'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN cooling_expires_at TIMESTAMP"))
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
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN first_payment_at TIMESTAMP"))
                if "revoked_at" not in ben_cols:
                    print("[*] Migrating beneficiaries schema: adding column 'revoked_at'...")
                    conn.execute(db.text("ALTER TABLE beneficiaries ADD COLUMN revoked_at TIMESTAMP"))
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
