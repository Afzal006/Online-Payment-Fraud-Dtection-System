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
from app.models import User, Transaction, Alert


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
