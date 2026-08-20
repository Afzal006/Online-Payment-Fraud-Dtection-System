"""
Email Provider Abstraction Layer for FraudShield AI.

Provides modular email delivery services:
- EmailProvider (Abstract Base Class)
- DevelopmentEmailProvider (Secure logging + test in-memory storage)
- SmtpEmailProvider (Standard SMTP / TLS delivery)
- NullEmailProvider (Production fallback when credentials are unconfigured)
- get_email_provider() (Factory function)
"""

import os
import smtplib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple
from flask import current_app


class EmailProvider(ABC):
    """Abstract base interface for all email delivery providers."""

    @abstractmethod
    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Send a secure password reset email with reset link.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        pass


class DevelopmentEmailProvider(EmailProvider):
    """
    Development & Testing Email Provider.
    
    Security:
    - Never returns the reset token in the HTTP API response or frontend.
    - Captures messages in-memory for automated unit/integration test assertions.
    - Logs delivery details to server logger without exposing credentials.
    """

    _sent_emails: List[Dict[str, any]] = []

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        clean_email = str(recipient_email).strip().lower()
        expiry_str = expires_at.isoformat() if expires_at else "15 minutes"

        record = {
            "recipient_email": clean_email,
            "reset_url": reset_url,
            "expires_at": expires_at,
            "dispatched_at": datetime.now(timezone.utc),
        }
        self.__class__._sent_emails.append(record)

        try:
            if current_app:
                current_app.logger.info(
                    "[DEV-EMAIL] Password reset email queued for %s (Expires: %s).",
                    clean_email,
                    expiry_str,
                )
        except RuntimeError:
            pass

        return True, None

    @classmethod
    def get_last_email(cls, recipient_email: Optional[str] = None) -> Optional[Dict[str, any]]:
        """Retrieve the last captured email, optionally filtered by recipient."""
        if not cls._sent_emails:
            return None
        if recipient_email:
            clean = recipient_email.strip().lower()
            for item in reversed(cls._sent_emails):
                if item["recipient_email"] == clean:
                    return item
            return None
        return cls._sent_emails[-1]

    @classmethod
    def get_last_token(cls, recipient_email: Optional[str] = None) -> Optional[str]:
        """Extract the raw token from the last dispatched email's reset_url."""
        import urllib.parse
        last_email = cls.get_last_email(recipient_email)
        if not last_email or not last_email.get("reset_url"):
            return None
        url = last_email["reset_url"]
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        token_list = params.get("token")
        return token_list[0] if token_list else None

    @classmethod
    def clear_history(cls) -> None:
        """Clear captured email history between test runs."""
        cls._sent_emails.clear()


class SmtpEmailProvider(EmailProvider):
    """
    Standard SMTP Provider for Production & Staging Environments.
    
    Configured via environment variables:
    - SMTP_HOST / SMTP_SERVER
    - SMTP_PORT (default 587)
    - SMTP_USER / SMTP_USERNAME
    - SMTP_PASSWORD
    - SMTP_USE_TLS (default True)
    - EMAIL_FROM / MAIL_DEFAULT_SENDER
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        from_email: Optional[str] = None,
    ):
        self.host = host or os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER")
        self.port = int(port or os.environ.get("SMTP_PORT", 587))
        self.username = username or os.environ.get("SMTP_USER") or os.environ.get("SMTP_USERNAME")
        self.password = password or os.environ.get("SMTP_PASSWORD")
        self.use_tls = use_tls if use_tls is not None else (os.environ.get("SMTP_USE_TLS", "true").lower() == "true")
        self.from_email = from_email or os.environ.get("EMAIL_FROM") or os.environ.get("MAIL_DEFAULT_SENDER") or "no-reply@fraudshield.ai"

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        if not self.host:
            return False, "SMTP host is not configured."

        clean_recipient = str(recipient_email).strip().lower()

        subject = "FraudShield AI - Password Reset Request"
        expiry_info = f"This link will expire at {expires_at.strftime('%H:%M:%S UTC')}." if expires_at else "This link will expire in 15 minutes."

        text_body = (
            f"Hello,\n\n"
            f"We received a request to reset the password for your FraudShield account.\n"
            f"Please click the link below to set a new password:\n\n"
            f"{reset_url}\n\n"
            f"{expiry_info}\n"
            f"If you did not request this password reset, please ignore this email or contact security immediately.\n\n"
            f"FraudShield AI Security Team"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 30px; border: 1px solid #334155;">
    <h2 style="color: #38bdf8; margin-top: 0;">FraudShield AI Security</h2>
    <p>We received a request to reset the password for your account (<strong>{clean_recipient}</strong>).</p>
    <p>Click the button below to securely set your new password:</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="{reset_url}" style="background: #0284c7; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password</a>
    </div>
    <p style="font-size: 0.85em; color: #94a3b8;">{expiry_info}</p>
    <p style="font-size: 0.8em; color: #64748b; border-top: 1px solid #334155; padding-top: 15px; margin-top: 30px;">
      If you did not request this password reset, please ignore this message. Your password will remain unchanged.
    </p>
  </div>
</body>
</html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = clean_recipient
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.host, self.port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_email, [clean_recipient], msg.as_string())
            return True, None
        except Exception as exc:
            err_msg = f"SMTP dispatch failure: {str(exc)}"
            if current_app:
                current_app.logger.error(err_msg)
            return False, err_msg


class NullEmailProvider(EmailProvider):
    """Fallback provider when no valid email provider credentials are configured in production."""

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please contact system administrator."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send reset email with no provider configured.")
        return False, msg


def get_email_provider() -> EmailProvider:
    """
    Factory resolving active EmailProvider based on runtime configuration.
    
    Order of resolution:
    1. If app is TESTING or DEBUG (and no explicit override), use DevelopmentEmailProvider.
    2. If SMTP_HOST / SMTP_SERVER is defined in env/config, use SmtpEmailProvider.
    3. If EMAIL_PROVIDER == 'development', use DevelopmentEmailProvider.
    4. Otherwise, use NullEmailProvider (honest failure without simulated success).
    """
    try:
        if current_app:
            provider_override = current_app.config.get("EMAIL_PROVIDER")
            if provider_override == "development":
                return DevelopmentEmailProvider()
            elif provider_override == "smtp":
                return SmtpEmailProvider()
            elif provider_override == "null":
                return NullEmailProvider()

            if current_app.config.get("TESTING") or current_app.config.get("DEBUG"):
                return DevelopmentEmailProvider()

            if current_app.config.get("SMTP_HOST") or current_app.config.get("SMTP_SERVER"):
                return SmtpEmailProvider()
    except RuntimeError:
        pass

    # Direct environment variable check
    env_provider = os.environ.get("EMAIL_PROVIDER", "").lower()
    if env_provider == "development":
        return DevelopmentEmailProvider()
    if env_provider == "smtp" or os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER"):
        return SmtpEmailProvider()

    if os.environ.get("FLASK_ENV") in ("testing", "development") or os.environ.get("ENV") == "testing":
        return DevelopmentEmailProvider()

    return NullEmailProvider()
