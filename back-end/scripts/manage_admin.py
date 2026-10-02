"""
Admin and User Account Management Utility.

Provides database-agnostic management of user and administrator accounts via SQLAlchemy.
Supports PostgreSQL (Render), MySQL, and SQLite.

Usage examples:
    # List all users & admins
    python scripts/manage_admin.py list

    # Create a new administrator account (or update existing)
    python scripts/manage_admin.py create-admin --name "SOC Administrator" --email teamfraudsheildai@gmail.com --password "AdminDemo2026!"

    # Reset password for any account
    python scripts/manage_admin.py reset-password --email teamfraudsheildai@gmail.com --password "AdminDemo2026!"

    # Promote an existing user to ADMIN
    python scripts/manage_admin.py make-admin --email afzalmohideen15@gmail.com

    # Initialize database tables and bootstrap admin
    python scripts/manage_admin.py init-db

    # Seed demo customers and realistic SOC transactions/alerts
    python scripts/manage_admin.py seed
"""

import os
import sys
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.extensions import db
from app.models.user import User
from database.init_db import init_database, mask_db_url
from database.seed_db import seed_database


def get_app(env_name: str = None):
    """Create Flask application context for CLI execution."""
    env = env_name or os.getenv("FLASK_ENV", "development")
    return create_app(env)


def list_users(app):
    """List all registered users and admin accounts across the active database."""
    with app.app_context():
        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        masked_uri = mask_db_url(db_uri)
        print("=" * 80)
        print("FraudShield AI — Registered User & Administrator Accounts")
        print(f"Target Database: {masked_uri}")
        print("=" * 80)

        try:
            users = User.query.order_by(User.id.asc()).all()
            if not users:
                print("  (No users found in database)")
            else:
                print(f"  {'ID':<5} {'Role':<8} {'Active':<8} {'Status':<16} {'Email Verified':<16} {'Email':<32} {'Name'}")
                print("  " + "-" * 105)
                for u in users:
                    active_str = "Yes" if u.is_active else "No"
                    email_v_str = "Yes" if u.is_email_verified else "No"
                    status_str = u.account_status or ("ACTIVE" if u.is_active else "INACTIVE")
                    role_badge = f"[{u.role}]"
                    print(f"  {u.id:<5} {role_badge:<8} {active_str:<8} {status_str:<16} {email_v_str:<16} {u.email:<32} {u.name}")
        except Exception as e:
            print(f"[-] Error querying users table: {e}")
            print("    Hint: Has the database been initialized? Run 'python scripts/manage_admin.py init-db'")
        print("=" * 80)


def create_admin(app, name: str, email: str, password: str):
    """Create or update an Administrator account."""
    clean_email = email.strip().lower()
    clean_name = name.strip()

    with app.app_context():
        try:
            db.create_all()
            user = User.query.filter(db.func.lower(User.email) == clean_email).first()

            if user:
                user.name = clean_name
                user.role = "ADMIN"
                user.is_active = True
                user.is_email_verified = True
                user.is_phone_verified = True
                user.account_status = "ACTIVE"
                user.set_password(password)
                db.session.commit()
                print(f"[+] Updated existing account (ID: {user.id}) to ADMIN role.")
            else:
                user = User(
                    name=clean_name,
                    email=clean_email,
                    role="ADMIN",
                    customer_account_id="FS-ADMIN-01",
                    primary_upi_id="admin@fraudshield",
                    phone_number="+91 98765 99999",
                    account_balance=0.0,
                    is_active=True,
                    is_email_verified=True,
                    is_phone_verified=True,
                    account_status="ACTIVE",
                )
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                print(f"[+] Created new ADMIN account (ID: {user.id}) in database.")

            print("\n[SUCCESS] Administrator account is ready:")
            print(f"          Name:     {user.name}")
            print(f"          Email:    {user.email}")
            print(f"          Password: {password}")
            print(f"          Role:     {user.role}")
            print(f"          Status:   {user.account_status}")
        except Exception as e:
            db.session.rollback()
            print(f"[-] Error creating admin account: {e}")


def reset_password(app, email: str, new_password: str):
    """Reset the password for any user or administrator account."""
    clean_email = email.strip().lower()

    with app.app_context():
        try:
            user = User.query.filter(db.func.lower(User.email) == clean_email).first()
            if not user:
                print(f"\n[-] No account found with email '{clean_email}'.")
                return

            user.set_password(new_password)
            user.is_active = True
            user.account_status = "ACTIVE"
            user.is_email_verified = True
            db.session.commit()

            print(f"\n[SUCCESS] Password successfully reset for '{clean_email}':")
            print(f"          Email:        {user.email}")
            print(f"          New Password: {new_password}")
            print(f"          Role:         {user.role}")
            print(f"          Status:       {user.account_status}")
        except Exception as e:
            db.session.rollback()
            print(f"[-] Error resetting password: {e}")


def make_admin(app, email: str):
    """Promote an existing account to ADMIN role."""
    clean_email = email.strip().lower()

    with app.app_context():
        try:
            user = User.query.filter(db.func.lower(User.email) == clean_email).first()
            if not user:
                print(f"\n[-] No account found with email '{clean_email}'.")
                return

            user.role = "ADMIN"
            user.is_active = True
            user.is_email_verified = True
            user.is_phone_verified = True
            user.account_status = "ACTIVE"
            db.session.commit()

            print(f"\n[SUCCESS] '{clean_email}' (ID: {user.id}) has been promoted to ADMIN.")
        except Exception as e:
            db.session.rollback()
            print(f"[-] Error promoting user: {e}")


def main():
    parser = argparse.ArgumentParser(description="FraudShield AI User & Administrator Account Manager")
    parser.add_argument("--env", default=None, help="Flask environment configuration (development, production, testing)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list command
    subparsers.add_parser("list", help="List all registered accounts in the active database")

    # create-admin command
    ca_parser = subparsers.add_parser("create-admin", help="Create or update an ADMIN account with specified credentials")
    ca_parser.add_argument("--name", default="SOC Administrator", help="Display name for admin")
    ca_parser.add_argument("--email", default=os.getenv("ADMIN_EMAIL", "teamfraudsheildai@gmail.com"), help="Admin email address")
    ca_parser.add_argument("--password", default=os.getenv("ADMIN_PASSWORD", "AdminDemo2026!"), help="Admin password")

    # reset-password command
    rp_parser = subparsers.add_parser("reset-password", help="Reset password for an existing account")
    rp_parser.add_argument("--email", required=True, help="User or Admin email address")
    rp_parser.add_argument("--password", required=True, help="New password to set")

    # make-admin command
    ma_parser = subparsers.add_parser("make-admin", help="Promote an existing account to ADMIN role")
    ma_parser.add_argument("--email", required=True, help="Email address of account to promote")

    # init-db command
    subparsers.add_parser("init-db", help="Initialize all database tables and bootstrap admin")

    # seed command
    subparsers.add_parser("seed", help="Seed demo customers and realistic SOC alert/transaction data")

    args = parser.parse_args()
    app = get_app(args.env)

    if args.command == "list" or not args.command:
        list_users(app)
    elif args.command == "create-admin":
        create_admin(app, args.name, args.email, args.password)
    elif args.command == "reset-password":
        reset_password(app, args.email, args.password)
    elif args.command == "make-admin":
        make_admin(app, args.email)
    elif args.command == "init-db":
        init_database(app)
    elif args.command == "seed":
        seed_database(app)


if __name__ == "__main__":
    main()
