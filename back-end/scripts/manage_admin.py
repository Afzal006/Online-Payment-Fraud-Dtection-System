"""
Admin and User Account Management Utility.

Usage examples:
    # List all users
    python scripts/manage_admin.py list

    # Reset password for any account
    python scripts/manage_admin.py reset-password --email admin@fraudshield.ai --password "NewSecurePass123!"

    # Promote a user to ADMIN
    python scripts/manage_admin.py make-admin --email afzalmohideen15@gmail.com

    # Create a new administrator
    python scripts/manage_admin.py create-admin --name "Lead SOC Analyst" --email admin2@fraudshield.ai --password "AdminPass123!"
"""

import os
import sys
import argparse
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from werkzeug.security import generate_password_hash, check_password_hash

DB_PATHS = [
    BASE_DIR / "instance" / "fraud_detection.db",
    BASE_DIR.parent / "instance" / "fraud_detection.db",
]


def get_existing_db_paths():
    found = [p for p in DB_PATHS if p.exists()]
    if not found:
        # Fallback to creating/using base instance path
        default_p = BASE_DIR / "instance" / "fraud_detection.db"
        default_p.parent.mkdir(parents=True, exist_ok=True)
        return [default_p]
    return found


def list_users():
    print("=" * 70)
    print("FraudShield AI — Registered User & Admin Accounts")
    print("=" * 70)
    
    for db_path in get_existing_db_paths():
        print(f"\n[Database: {db_path.relative_to(BASE_DIR.parent) if BASE_DIR.parent in db_path.parents else db_path}]")
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, name, email, role, is_active, is_email_verified, account_status FROM users")
            rows = cursor.fetchall()
            if not rows:
                print("  (No users found)")
            else:
                print(f"  {'ID':<5} {'Role':<8} {'Active':<8} {'Status':<18} {'Email':<30} {'Name'}")
                print("  " + "-" * 75)
                for r in rows:
                    uid, name, email, role, active, verified, status = r
                    active_str = "Yes" if active else "No"
                    status_str = status or ("ACTIVE" if active else "INACTIVE")
                    role_badge = f"[{role}]"
                    print(f"  {uid:<5} {role_badge:<8} {active_str:<8} {status_str:<18} {email:<30} {name}")
        except Exception as e:
            print(f"  Error reading users: {e}")
        finally:
            conn.close()
    print("=" * 70)


def reset_password(email: str, new_password: str):
    clean_email = email.strip().lower()
    pwd_hash = generate_password_hash(new_password)
    updated_count = 0
    
    for db_path in get_existing_db_paths():
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE users SET password_hash = ?, is_active = 1, account_status = 'ACTIVE' WHERE LOWER(email) = ?",
                (pwd_hash, clean_email),
            )
            if cursor.rowcount > 0:
                conn.commit()
                updated_count += cursor.rowcount
                print(f"[+] Password successfully updated in {db_path.name} for: {clean_email}")
        except Exception as e:
            print(f"[-] Error updating {db_path.name}: {e}")
        finally:
            conn.close()

    if updated_count > 0:
        print(f"\n[SUCCESS] Password has been reset for '{clean_email}'.")
        print(f"          New password: {new_password}")
    else:
        print(f"\n[-] No account found with email '{clean_email}'.")


def make_admin(email: str):
    clean_email = email.strip().lower()
    updated_count = 0
    
    for db_path in get_existing_db_paths():
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE users SET role = 'ADMIN', is_active = 1, is_email_verified = 1, account_status = 'ACTIVE' WHERE LOWER(email) = ?",
                (clean_email,),
            )
            if cursor.rowcount > 0:
                conn.commit()
                updated_count += cursor.rowcount
                print(f"[+] User promoted to ADMIN in {db_path.name}: {clean_email}")
        except Exception as e:
            print(f"[-] Error updating {db_path.name}: {e}")
        finally:
            conn.close()

    if updated_count > 0:
        print(f"\n[SUCCESS] '{clean_email}' is now an ADMIN.")
    else:
        print(f"\n[-] No account found with email '{clean_email}'.")


def create_admin(name: str, email: str, password: str):
    clean_email = email.strip().lower()
    clean_name = name.strip()
    pwd_hash = generate_password_hash(password)
    
    for db_path in get_existing_db_paths():
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?", (clean_email,))
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE users SET name = ?, password_hash = ?, role = 'ADMIN', is_active = 1, is_email_verified = 1, account_status = 'ACTIVE' WHERE id = ?",
                    (clean_name, pwd_hash, row[0]),
                )
                conn.commit()
                print(f"[+] Updated existing account (ID {row[0]}) to ADMIN in {db_path.name}")
            else:
                cursor.execute(
                    """INSERT INTO users (name, email, password_hash, role, created_at, is_active, is_email_verified, account_status)
                       VALUES (?, ?, ?, 'ADMIN', datetime('now'), 1, 1, 'ACTIVE')""",
                    (clean_name, clean_email, pwd_hash),
                )
                conn.commit()
                print(f"[+] Created new ADMIN account (ID {cursor.lastrowid}) in {db_path.name}")
        except Exception as e:
            print(f"[-] Error in {db_path.name}: {e}")
        finally:
            conn.close()

    print(f"\n[SUCCESS] Admin account ready:")
    print(f"          Email:    {clean_email}")
    print(f"          Password: {password}")
    print(f"          Role:     ADMIN")


def main():
    parser = argparse.ArgumentParser(description="FraudShield AI User & Admin Account Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list command
    subparsers.add_parser("list", help="List all registered accounts")

    # reset-password command
    rp_parser = subparsers.add_parser("reset-password", help="Reset password for an existing account")
    rp_parser.add_argument("--email", required=True, help="User or Admin email address")
    rp_parser.add_argument("--password", required=True, help="New password to set")

    # make-admin command
    ma_parser = subparsers.add_parser("make-admin", help="Promote an existing account to ADMIN role")
    ma_parser.add_argument("--email", required=True, help="Email address of account to promote")

    # create-admin command
    ca_parser = subparsers.add_parser("create-admin", help="Create a brand new ADMIN account")
    ca_parser.add_argument("--name", default="SOC Administrator", help="Display name for admin")
    ca_parser.add_argument("--email", required=True, help="Admin email address")
    ca_parser.add_argument("--password", required=True, help="Admin password")

    args = parser.parse_args()

    if args.command == "list" or not args.command:
        list_users()
    elif args.command == "reset-password":
        reset_password(args.email, args.password)
    elif args.command == "make-admin":
        make_admin(args.email)
    elif args.command == "create-admin":
        create_admin(args.name, args.email, args.password)


if __name__ == "__main__":
    main()
