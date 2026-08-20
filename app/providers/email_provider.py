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
        recipient_name: Optional[str] = None,
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
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        clean_email = str(recipient_email).strip().lower()
        expiry_str = expires_at.isoformat() if expires_at else "15 minutes"

        record = {
            "recipient_email": clean_email,
            "recipient_name": recipient_name or "User",
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
    - MAIL_PROVIDER / EMAIL_PROVIDER: 'smtp'
    - SMTP_HOST / SMTP_SERVER
    - SMTP_PORT (default 587, or 465 for SSL)
    - SMTP_USERNAME / SMTP_USER
    - SMTP_PASSWORD
    - SMTP_USE_TLS (default True)
    - SMTP_USE_SSL (default False, True if port 465)
    - SMTP_FROM_EMAIL / EMAIL_FROM / MAIL_DEFAULT_SENDER
    - SMTP_FROM_NAME
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: Optional[bool] = None,
        use_ssl: Optional[bool] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ):
        self.host = (
            host
            or (current_app.config.get("SMTP_HOST") if current_app else None)
            or os.environ.get("SMTP_HOST")
            or os.environ.get("SMTP_SERVER")
        )
        raw_port = (
            port
            or (current_app.config.get("SMTP_PORT") if current_app else None)
            or os.environ.get("SMTP_PORT")
            or 587
        )
        self.port = int(raw_port)
        self.username = (
            username
            or (current_app.config.get("SMTP_USERNAME") if current_app else None)
            or os.environ.get("SMTP_USERNAME")
            or os.environ.get("SMTP_USER")
        )
        self.password = (
            password
            or (current_app.config.get("SMTP_PASSWORD") if current_app else None)
            or os.environ.get("SMTP_PASSWORD")
        )
        
        # Determine SSL vs TLS
        if use_ssl is not None:
            self.use_ssl = use_ssl
        elif self.port == 465:
            self.use_ssl = True
        elif current_app and current_app.config.get("SMTP_USE_SSL"):
            self.use_ssl = str(current_app.config.get("SMTP_USE_SSL")).lower() in ("true", "1", "yes")
        elif os.environ.get("SMTP_USE_SSL"):
            self.use_ssl = os.environ.get("SMTP_USE_SSL", "false").lower() in ("true", "1", "yes")
        else:
            self.use_ssl = False

        if use_tls is not None:
            self.use_tls = use_tls
        elif self.use_ssl:
            self.use_tls = False
        elif current_app and current_app.config.get("SMTP_USE_TLS") is not None:
            self.use_tls = str(current_app.config.get("SMTP_USE_TLS")).lower() in ("true", "1", "yes")
        elif os.environ.get("SMTP_USE_TLS"):
            self.use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
        else:
            self.use_tls = True

        raw_from = (
            from_email
            or (current_app.config.get("SMTP_FROM_EMAIL") if current_app else None)
            or os.environ.get("SMTP_FROM_EMAIL")
            or os.environ.get("EMAIL_FROM")
            or os.environ.get("MAIL_DEFAULT_SENDER")
            or "security@fraudshield.ai"
        )
        self.from_name = (
            from_name
            or (current_app.config.get("SMTP_FROM_NAME") if current_app else None)
            or os.environ.get("SMTP_FROM_NAME")
            or "FraudShield AI Security"
        )
        self.from_email = raw_from

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        if not self.host:
            return False, "SMTP host is not configured."

        clean_recipient = str(recipient_email).strip().lower()
        display_name = (recipient_name or "FraudShield User").strip()

        subject = "FraudShield AI — Password Reset"
        expiry_info = f"This link expires in 15 minutes (at {expires_at.strftime('%H:%M UTC')}) and can only be used once." if expires_at else "This link expires in 15 minutes and can only be used once."

        text_body = (
            f"Hello {display_name},\n\n"
            f"We received a request to reset your FraudShield AI password.\n\n"
            f"Reset Password:\n"
            f"{reset_url}\n\n"
            f"{expiry_info}\n\n"
            f"If you did not request this reset, you can safely ignore this email.\n\n"
            f"FraudShield AI Security Team"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
    <div style="display: flex; align-items: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🛡️ FraudShield AI</h2>
    </div>
    <p style="font-size: 16px; line-height: 1.6; color: #f3f4f6; margin-bottom: 12px;">Hello <strong>{display_name}</strong>,</p>
    <p style="font-size: 15px; line-height: 1.6; color: #9ca3af; margin-bottom: 24px;">
      We received a request to reset your FraudShield AI account password. Click the secure button below to choose a new password:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <a href="{reset_url}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; display: inline-block; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.4);">Reset Password</a>
    </div>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px;">
      <p style="font-size: 13px; color: #fbbf24; margin: 0;">
        ⚠️ <strong>Security Notice:</strong> {expiry_info}
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      If you did not request this password reset, please ignore this message. Your account remains secure and your password will not be changed.
    </p>
  </div>
</body>
</html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.from_name} <{self.from_email}>" if self.from_name else self.from_email
        msg["To"] = clean_recipient
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.host, self.port, timeout=10) as server:
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.sendmail(self.from_email, [clean_recipient], msg.as_string())
            else:
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
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please contact system administrator."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send reset email with no provider configured.")
        return False, msg


def get_email_provider() -> EmailProvider:
    """
    Factory resolving active EmailProvider based on runtime configuration.
    
    Order of resolution:
    1. Explicit MAIL_PROVIDER / EMAIL_PROVIDER configuration ('smtp', 'development', 'null').
    2. If SMTP_HOST / SMTP_SERVER is defined in env/config, use SmtpEmailProvider.
    3. If app is TESTING or DEBUG (and no explicit SMTP defined), use DevelopmentEmailProvider.
    4. Otherwise, use NullEmailProvider (honest failure without simulated success).
    """
    # 1. Check Flask app config override
    try:
        if current_app:
            provider_override = (
                current_app.config.get("MAIL_PROVIDER")
                or current_app.config.get("EMAIL_PROVIDER")
            )
            if provider_override:
                p = str(provider_override).lower().strip()
                if p == "development":
                    return DevelopmentEmailProvider()
                elif p == "smtp":
                    return SmtpEmailProvider()
                elif p == "null":
                    return NullEmailProvider()

            # If explicit SMTP_HOST in config, prefer SmtpEmailProvider
            if current_app.config.get("SMTP_HOST") or current_app.config.get("SMTP_SERVER"):
                return SmtpEmailProvider()

            # If in automated testing, use DevelopmentEmailProvider
            if current_app.config.get("TESTING"):
                return DevelopmentEmailProvider()
    except RuntimeError:
        pass

    # 2. Check environment variables
    env_provider = (
        os.environ.get("MAIL_PROVIDER", "")
        or os.environ.get("EMAIL_PROVIDER", "")
    ).lower().strip()

    if env_provider == "development":
        return DevelopmentEmailProvider()
    if env_provider == "smtp":
        return SmtpEmailProvider()
    if env_provider == "null":
        return NullEmailProvider()

    if os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER"):
        return SmtpEmailProvider()

    if os.environ.get("FLASK_ENV") in ("testing", "development") or os.environ.get("ENV") == "testing":
        return DevelopmentEmailProvider()

    return NullEmailProvider()
