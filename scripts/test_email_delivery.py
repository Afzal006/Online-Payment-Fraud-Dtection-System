"""
Safe Diagnostic CLI Script for Email & OTP Delivery Verification.

Usage:
    py scripts/test_email_delivery.py --email yourname@gmail.com
    py scripts/test_email_delivery.py --email yourname@gmail.com --type password_reset
    py scripts/test_email_delivery.py --status

Security Guardrails:
- NEVER prints SMTP passwords, API keys, or JWT secrets.
- Masks sensitive credentials in diagnostic output.
- Uses configured application email provider abstraction.
"""

import sys
import os
import argparse
import io
from datetime import datetime, timezone, timedelta

# Fix Windows console encoding if needed
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add parent directory to module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from app.providers.email_provider import (
    get_email_provider,
    SmtpEmailProvider,
    DevelopmentEmailProvider,
    NullEmailProvider,
)
from app.providers.sms_provider import (
    get_sms_provider,
    TwilioSmsProvider,
    Msg91SmsProvider,
    DevelopmentSmsProvider,
    NullSmsProvider,
)


def mask_string(val: str, show_start: int = 2, show_end: int = 2) -> str:
    """Safely mask sensitive strings."""
    if not val:
        return "<not set>"
    if len(val) <= show_start + show_end:
        return "****"
    return f"{val[:show_start]}****{val[-show_end:]}"


def inspect_status():
    """Print sanitized configuration status for Email and SMS providers."""
    app = create_app(os.getenv("FLASK_ENV", "development"))
    with app.app_context():
        email_provider = get_email_provider()
        sms_provider = get_sms_provider()

        print("\n" + "=" * 60)
        print("[FRAUDSHIELD AI] Communication Delivery Diagnostics")
        print("=" * 60)
        
        print("\n[EMAIL PROVIDER]")
        print(f"  Type: {type(email_provider).__name__}")
        if isinstance(email_provider, SmtpEmailProvider):
            print(f"  Host: {email_provider.host or '<not set>'}")
            print(f"  Port: {email_provider.port}")
            print(f"  User: {mask_string(email_provider.username, 3, 3) if email_provider.username else '<not set>'}")
            print(f"  Password: {'[CONFIGURED]' if email_provider.password else '<not set>'}")
            print(f"  TLS: {email_provider.use_tls}")
            print(f"  SSL: {email_provider.use_ssl}")
            print(f"  From: {email_provider.from_email}")
        elif isinstance(email_provider, DevelopmentEmailProvider):
            print("  Mode: Development Simulation (In-Memory Buffer)")
            print("  Note: Set MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD in .env for real SMTP delivery.")
        elif isinstance(email_provider, NullEmailProvider):
            print("  Mode: Null / Disabled (Fails honestly)")

        print("\n[SMS PROVIDER]")
        print(f"  Type: {type(sms_provider).__name__}")
        if isinstance(sms_provider, TwilioSmsProvider):
            print(f"  Account SID: {mask_string(sms_provider.account_sid, 4, 4)}")
            print(f"  From Number: {sms_provider.from_number or '<not set>'}")
        elif isinstance(sms_provider, Msg91SmsProvider):
            print(f"  Template ID: {sms_provider.template_id or '<not set>'}")
            print(f"  Sender ID: {sms_provider.sender_id}")
        elif isinstance(sms_provider, DevelopmentSmsProvider):
            print("  Mode: Development Simulation (In-Memory Buffer)")
        elif isinstance(sms_provider, NullSmsProvider):
            print("  Mode: Null / Disabled (Fails honestly)")

        print("=" * 60 + "\n")


def send_test_email(recipient_email: str, email_type: str = "verification_otp"):
    """Safely test email dispatch to recipient address."""
    app = create_app(os.getenv("FLASK_ENV", "development"))
    with app.app_context():
        email_provider = get_email_provider()
        provider_name = type(email_provider).__name__
        
        print(f"\n[INFO] Initialized {provider_name} for recipient: {recipient_email}")
        
        if email_type == "verification_otp":
            test_otp = "842915"
            print(f"[ACTION] Dispatching email verification challenge...")
            ok, err = email_provider.send_email_verification_otp(
                recipient_email=recipient_email,
                otp_code=test_otp,
                recipient_name="FraudShield Diagnostic Test",
                verification_url=f"http://127.0.0.1:5000/api/auth/verify-email?token=diagnostic_test_token",
                expires_in_minutes=5,
            )
        elif email_type == "password_reset":
            print(f"[ACTION] Dispatching password reset email...")
            ok, err = email_provider.send_password_reset_email(
                recipient_email=recipient_email,
                reset_url=f"http://127.0.0.1:5000/reset-password?token=diagnostic_test_token",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
                recipient_name="FraudShield Diagnostic Test",
            )
        else:
            print(f"[ERROR] Unknown email type: {email_type}")
            return False

        if ok:
            print(f"[SUCCESS] Email accepted by provider ({provider_name}).")
            if isinstance(email_provider, DevelopmentEmailProvider):
                print(f"   [DEV NOTE] Dispatched to Development in-memory buffer (Total queued: {len(DevelopmentEmailProvider._sent_emails)}).")
            else:
                print(f"   [DELIVERY NOTE] Check inbox / spam folder for '{recipient_email}'.")
            return True
        else:
            print(f"[FAILED] Provider returned error: {err}")
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FraudShield AI Email & OTP Delivery Diagnostic Tool")
    parser.add_argument("--status", action="store_true", help="Display current provider status")
    parser.add_argument("--email", type=str, help="Target email address for test dispatch")
    parser.add_argument("--type", type=str, default="verification_otp", choices=["verification_otp", "password_reset"], help="Email test type")

    args = parser.parse_args()

    if args.status or not args.email:
        inspect_status()
        if not args.email:
            print("Tip: Run with --email yourname@gmail.com to test email dispatch.")
    else:
        inspect_status()
        send_test_email(args.email, args.type)
