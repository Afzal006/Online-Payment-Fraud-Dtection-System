#!/usr/bin/env python
"""
Direct CLI Diagnostic Tool for FraudShield AI Email Delivery (Resend / SMTP).

Usage:
    python test_email_cli.py <recipient-email>

Example:
    python test_email_cli.py test@example.com
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
from app.providers.email_provider import get_email_provider, ResendEmailProvider, SmtpEmailProvider


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_email_cli.py <recipient-email>")
        sys.exit(1)

    recipient = sys.argv[1].strip()
    if not recipient or "@" not in recipient:
        print(f"Error: Invalid recipient email address '{recipient}'")
        sys.exit(1)

    env_name = os.getenv("FLASK_ENV", "production")
    app = create_app(env_name)

    with app.app_context():
        provider = get_email_provider()
        diag = provider.get_diagnostics() if hasattr(provider, "get_diagnostics") else {"provider": type(provider).__name__}

        print("=" * 65)
        print("FraudShield AI — Email Delivery Direct Diagnostic")
        print("=" * 65)
        print(f"Provider:            {diag.get('provider')}")
        print(f"Transport:           {diag.get('transport', 'Default')}")
        if isinstance(provider, ResendEmailProvider):
            print(f"API Key Configured:  {'YES' if diag.get('api_key_configured') else 'NO'}")
            print(f"Sender Address:      {diag.get('from_email')}")
            print(f"Sender Name:         {diag.get('from_name')}")
        elif isinstance(provider, SmtpEmailProvider):
            print(f"SMTP Host:           {diag.get('smtp_host')}")
            print(f"SMTP Port:           {diag.get('smtp_port')}")
            print(f"TLS Enabled:         {diag.get('use_tls')}")
            print(f"SSL Enabled:         {diag.get('use_ssl')}")
            print(f"Username Configured: {'YES' if diag.get('username_configured') else 'NO'}")
            print(f"Password Configured: {'YES' if diag.get('password_configured') else 'NO'}")
            print(f"Sender Address:      {diag.get('sender_address')}")
        print(f"Target Recipient:    {recipient}")
        print("-" * 65)

        print("[*] Initiating email delivery test...")
        success, error = provider.send_test_email(recipient)

        print("-" * 65)
        if success:
            print("EMAIL TEST SUCCESS")
            print(f"[+] Message accepted by provider ({diag.get('provider')}) for delivery to '{recipient}'.")
            print("=" * 65)
            sys.exit(0)
        else:
            print(f"EMAIL TEST FAILED: {error}")
            print("=" * 65)
            sys.exit(1)


if __name__ == "__main__":
    main()
