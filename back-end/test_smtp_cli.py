#!/usr/bin/env python
"""
Direct CLI Diagnostic Tool for FraudShield AI SMTP Email Delivery.

Usage:
    python test_smtp_cli.py <recipient-email>

Example:
    python test_smtp_cli.py test@example.com
"""

import os
import sys
from pathlib import Path

# Ensure backend root directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from dotenv import load_dotenv

# Load local environment if present (supports back-end/.env and root/.env)
if (BACKEND_DIR / ".env").exists():
    load_dotenv(BACKEND_DIR / ".env")
elif (BACKEND_DIR.parent / ".env").exists():
    load_dotenv(BACKEND_DIR.parent / ".env")
else:
    load_dotenv()

from app import create_app
from app.providers.email_provider import get_email_provider, SmtpEmailProvider


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_smtp_cli.py <recipient-email>")
        sys.exit(1)

    recipient = sys.argv[1].strip()
    if not recipient or "@" not in recipient:
        print(f"Error: Invalid recipient email address '{recipient}'")
        sys.exit(1)

    # Initialize Flask app in production configuration to test real SMTP provider
    env_name = os.getenv("FLASK_ENV", "production")
    app = create_app(env_name)

    with app.app_context():
        # Always test with SmtpEmailProvider for direct SMTP diagnostics
        provider = SmtpEmailProvider()
        diag = provider.get_diagnostics()

        print("=" * 65)
        print("FraudShield AI — Production SMTP Direct Diagnostic")
        print("=" * 65)
        print(f"Provider:            {diag['provider']}")
        print(f"SMTP Host:           {diag['smtp_host']}")
        print(f"SMTP Port:           {diag['smtp_port']}")
        print(f"TLS Enabled:         {diag['use_tls']}")
        print(f"SSL Enabled:         {diag['use_ssl']}")
        print(f"Username Configured: {'YES' if diag['username_configured'] else 'NO'}")
        print(f"Password Configured: {'YES' if diag['password_configured'] else 'NO'}")
        print(f"Sender Address:      {diag['sender_address']}")
        print(f"Target Recipient:    {recipient}")
        print("-" * 65)

        if not diag['smtp_host'] or diag['smtp_host'] == "NOT_CONFIGURED":
            print("SMTP TEST FAILED: SMTP host is not configured (MAIL_SERVER / SMTP_HOST is empty).")
            print("Please configure MAIL_SERVER, MAIL_USERNAME, and MAIL_PASSWORD in your environment.")
            sys.exit(1)

        print("[*] Initiating SMTP connection sequence (CONNECT -> EHLO -> STARTTLS -> EHLO -> AUTH -> SEND -> QUIT)...")
        success, error = provider.send_test_email(recipient)

        print("-" * 65)
        if success:
            print("SMTP TEST SUCCESS")
            print(f"[+] Message successfully accepted by SMTP server {diag['smtp_host']}:{diag['smtp_port']} for delivery to '{recipient}'.")
            print("=" * 65)
            sys.exit(0)
        else:
            print(f"SMTP TEST FAILED: {error}")
            print("=" * 65)
            sys.exit(1)


if __name__ == "__main__":
    main()
