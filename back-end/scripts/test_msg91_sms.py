"""
Dedicated Safe Diagnostic Script for MSG91 Real Mobile SMS Delivery.

Usage:
    py scripts/test_msg91_sms.py --phone 9876543210
    py scripts/test_msg91_sms.py --status

Security Guardrails:
- NEVER prints Auth Keys, Template IDs, or secrets in plaintext.
- Masks mobile numbers (e.g. +91******3210).
- Does NOT persist test OTPs into the production database.
- Uses the application's Msg91SmsProvider implementation directly.
"""

import sys
import os
import argparse
import secrets
import re

# Fix Windows console encoding
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from app.providers.sms_provider import get_sms_provider, Msg91SmsProvider, DevelopmentSmsProvider, NullSmsProvider


def mask_phone(phone: str) -> str:
    """Mask phone number safely (e.g. +91******3210)."""
    digits = re.sub(r"\D", "", str(phone))
    if len(digits) >= 4:
        return f"+91******{digits[-4:]}"
    return "+91******"


def run_msg91_diagnostic(phone_arg: str = None, check_status_only: bool = False):
    print("\n" + "=" * 50)
    print("      MSG91 REAL SMS DELIVERY DIAGNOSTIC")
    print("=" * 50)

    app = create_app(os.getenv("FLASK_ENV", "development"))
    with app.app_context():
        sms_provider = get_sms_provider()
        provider_name = type(sms_provider).__name__

        auth_key = app.config.get("MSG91_AUTH_KEY") or os.getenv("MSG91_AUTH_KEY")
        template_id = app.config.get("MSG91_TEMPLATE_ID") or os.getenv("MSG91_TEMPLATE_ID")
        sender_id = app.config.get("MSG91_SENDER_ID") or os.getenv("MSG91_SENDER_ID", "FRDSHD")
        configured_provider = app.config.get("SMS_PROVIDER") or os.getenv("SMS_PROVIDER", "development")

        has_auth_key = bool(auth_key and auth_key.strip())
        has_template_id = bool(template_id and template_id.strip())
        has_sender = bool(sender_id and sender_id.strip())

        print(f"\nProvider Selected        : {provider_name}")
        print(f"SMS_PROVIDER Setting     : {configured_provider}")
        print(f"Credentials configured   : {'YES' if has_auth_key else 'NO (Missing MSG91_AUTH_KEY)'}")
        print(f"Template configured      : {'YES' if has_template_id else 'NO (Missing MSG91_TEMPLATE_ID)'}")
        print(f"Sender configured        : {'YES (' + sender_id + ')' if has_sender else 'NO (Missing MSG91_SENDER_ID)'}")

        if check_status_only:
            print("\n" + "=" * 50)
            return

        # Check configuration readiness
        if not has_auth_key or not has_template_id:
            print("\n" + "-" * 50)
            print("[CONFIGURATION REQUIRED]")
            print("To enable real SMS delivery via MSG91, configure your .env file:")
            print("")
            print("  SMS_PROVIDER=msg91")
            print("  MSG91_AUTH_KEY=your_msg91_auth_key_here")
            print("  MSG91_TEMPLATE_ID=your_dlt_template_id_here")
            print("  MSG91_SENDER_ID=your_sender_id_here (e.g. FRDSHD)")
            print("")
            print("After updating .env, restart the server and rerun this test.")
            print("-" * 50 + "\n")
            return

        # Prompt or parse destination number
        target_phone = phone_arg or os.getenv("TEST_PHONE_NUMBER")
        if not target_phone:
            print("\n[INPUT REQUIRED] Please supply a phone number to test.")
            print("Usage: py scripts/test_msg91_sms.py --phone 9876543210")
            print("=" * 50 + "\n")
            return

        digits = re.sub(r"\D", "", target_phone)
        if len(digits) < 10:
            print(f"\n[ERROR] Invalid phone number '{target_phone}'. Must be a 10-digit Indian mobile number.")
            print("=" * 50 + "\n")
            return

        masked = mask_phone(target_phone)
        print(f"Destination              : {masked}")

        # Instantiate provider
        msg91 = Msg91SmsProvider(
            auth_key=auth_key,
            template_id=template_id,
            sender_id=sender_id,
        )

        # Generate secure random test OTP
        test_otp = f"{secrets.randbelow(900000) + 100000}"

        print("\nSending test OTP via MSG91 API...")
        success, error_msg = msg91.send_otp(
            phone_number=target_phone,
            otp_code=test_otp,
            purpose="DIAGNOSTIC_VERIFICATION",
        )

        print("\n" + "-" * 50)
        if success:
            print("HTTP/API result          : SUCCESS")
            print("Provider accepted request: YES")
            print("")
            print(">>> Check your physical mobile phone for the SMS. <<<")
            print("Note: Handset delivery depends on Indian telecom operator DLT approval.")
        else:
            print("HTTP/API result          : FAILED")
            print("Provider accepted request: NO")
            print(f"Error Details            : {error_msg}")
            print("")
            print(">>> MSG91 rejected the request. Please check template ID and auth key. <<<")
        print("-" * 50)
        print("=" * 50 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test real SMS delivery via MSG91")
    parser.add_argument("--phone", "-p", help="10-digit Indian mobile number (e.g. 9876543210)")
    parser.add_argument("--status", "-s", action="store_true", help="Check SMS configuration status only")
    args = parser.parse_args()

    run_msg91_diagnostic(phone_arg=args.phone, check_status_only=args.status)
