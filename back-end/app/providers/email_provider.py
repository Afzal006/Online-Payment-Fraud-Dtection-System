"""
Email Provider Abstraction Layer for FraudShield AI.

Provides modular email delivery services:
- EmailProvider (Abstract Base Class)
- DevelopmentEmailProvider (Secure logging + test in-memory storage)
- SmtpEmailProvider (Standard SMTP / TLS delivery with full error diagnostics)
- NullEmailProvider (Production fallback when credentials are unconfigured)
- get_email_provider() (Factory function)
"""

import email.utils
import logging
import os
import smtplib
import socket
import ssl
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple, Any
from flask import current_app

logger = logging.getLogger(__name__)


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

    @abstractmethod
    def send_email_verification_otp(
        self,
        recipient_email: str,
        otp_code: str,
        recipient_name: Optional[str] = None,
        verification_url: Optional[str] = None,
        expires_in_minutes: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        """
        Send an email ownership verification challenge containing a 6-digit OTP code and/or direct link.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        pass

    @abstractmethod
    def send_transaction_otp(
        self,
        recipient_email: str,
        otp_code: str,
        transaction_id: int,
        amount: Optional[float] = None,
        recipient_name: Optional[str] = None,
        expires_in_minutes: int = 3,
    ) -> Tuple[bool, Optional[str]]:
        """
        Send an OTP challenge email for high/medium-risk transaction verification.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        pass

    @abstractmethod
    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Send a diagnostic test email to verify SMTP functionality.

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

    _sent_emails: List[Dict[str, Any]] = []

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
            "type": "PASSWORD_RESET",
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

    def send_email_verification_otp(
        self,
        recipient_email: str,
        otp_code: str,
        recipient_name: Optional[str] = None,
        verification_url: Optional[str] = None,
        expires_in_minutes: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        clean_email = str(recipient_email).strip().lower()

        record = {
            "type": "EMAIL_VERIFICATION",
            "recipient_email": clean_email,
            "recipient_name": recipient_name or "User",
            "otp_code": str(otp_code).strip(),
            "verification_url": verification_url,
            "expires_in_minutes": expires_in_minutes,
            "dispatched_at": datetime.now(timezone.utc),
        }
        self.__class__._sent_emails.append(record)

        try:
            if current_app:
                current_app.logger.info(
                    "[DEV-EMAIL] Email verification OTP queued for %s (Expires in: %dm).",
                    clean_email,
                    expires_in_minutes,
                )
        except RuntimeError:
            pass

        return True, None

    def send_transaction_otp(
        self,
        recipient_email: str,
        otp_code: str,
        transaction_id: int,
        amount: Optional[float] = None,
        recipient_name: Optional[str] = None,
        expires_in_minutes: int = 3,
    ) -> Tuple[bool, Optional[str]]:
        clean_email = str(recipient_email).strip().lower()
        clean_otp = str(otp_code).strip()

        record = {
            "type": "TRANSACTION_OTP",
            "recipient_email": clean_email,
            "recipient_name": recipient_name or "User",
            "otp_code": clean_otp,
            "transaction_id": transaction_id,
            "amount": amount,
            "expires_in_minutes": expires_in_minutes,
            "dispatched_at": datetime.now(timezone.utc),
        }
        self.__class__._sent_emails.append(record)

        try:
            if current_app:
                current_app.logger.info(
                    "[DEV-EMAIL] Transaction #%s OTP queued for %s (Expires in: %dm).",
                    transaction_id,
                    clean_email,
                    expires_in_minutes,
                )
        except RuntimeError:
            pass

        return True, None

    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        clean_email = str(recipient_email).strip().lower()
        record = {
            "type": "TEST_EMAIL",
            "recipient_email": clean_email,
            "test_message": test_message or "Diagnostic test message",
            "dispatched_at": datetime.now(timezone.utc),
        }
        self.__class__._sent_emails.append(record)
        return True, None

    @classmethod
    def get_last_email(cls, recipient_email: Optional[str] = None) -> Optional[Dict[str, Any]]:
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
    def get_last_email_otp(cls, recipient_email: Optional[str] = None) -> Optional[str]:
        """Extract the OTP code from the last dispatched email verification or transaction OTP."""
        if not cls._sent_emails:
            return None
        clean = recipient_email.strip().lower() if recipient_email else None
        for item in reversed(cls._sent_emails):
            if item.get("type") in ["EMAIL_VERIFICATION", "TRANSACTION_OTP"]:
                if not clean or item["recipient_email"] == clean:
                    return item.get("otp_code")
        return None

    @classmethod
    def get_last_token(cls, recipient_email: Optional[str] = None) -> Optional[str]:
        """Extract the raw token from the last dispatched email's verification_url or reset_url."""
        import urllib.parse
        last_email = cls.get_last_email(recipient_email)
        if not last_email:
            return None
        url = last_email.get("verification_url") or last_email.get("reset_url")
        if not url:
            return None
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
    - MAIL_SERVER / SMTP_HOST / SMTP_SERVER
    - MAIL_PORT / SMTP_PORT (default 587, or 465 for SSL)
    - MAIL_USERNAME / SMTP_USERNAME / SMTP_USER
    - MAIL_PASSWORD / SMTP_PASSWORD
    - MAIL_USE_TLS / SMTP_USE_TLS (default True)
    - MAIL_USE_SSL / SMTP_USE_SSL (default False, True if port 465)
    - MAIL_DEFAULT_SENDER / SMTP_FROM_EMAIL / EMAIL_FROM
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
        raw_host = (
            host
            or (current_app.config.get("SMTP_HOST") if current_app else None)
            or (current_app.config.get("MAIL_SERVER") if current_app else None)
            or os.environ.get("MAIL_SERVER")
            or os.environ.get("SMTP_HOST")
            or os.environ.get("SMTP_SERVER")
        )
        self.host = str(raw_host).strip() if raw_host else None

        raw_port = (
            port
            or (current_app.config.get("SMTP_PORT") if current_app else None)
            or (current_app.config.get("MAIL_PORT") if current_app else None)
            or os.environ.get("MAIL_PORT")
            or os.environ.get("SMTP_PORT")
            or 587
        )
        try:
            self.port = int(raw_port)
        except (ValueError, TypeError):
            self.port = 587

        raw_user = (
            username
            or (current_app.config.get("SMTP_USERNAME") if current_app else None)
            or (current_app.config.get("MAIL_USERNAME") if current_app else None)
            or os.environ.get("MAIL_USERNAME")
            or os.environ.get("SMTP_USERNAME")
            or os.environ.get("SMTP_USER")
        )
        self.username = str(raw_user).strip() if raw_user else None

        raw_pass = (
            password
            or (current_app.config.get("SMTP_PASSWORD") if current_app else None)
            or (current_app.config.get("MAIL_PASSWORD") if current_app else None)
            or os.environ.get("MAIL_PASSWORD")
            or os.environ.get("SMTP_PASSWORD")
        )
        self.password = str(raw_pass).strip().strip('"').strip("'") if raw_pass else None

        # Determine SSL vs TLS
        if use_ssl is not None:
            self.use_ssl = use_ssl
        elif self.port == 465:
            self.use_ssl = True
        elif current_app and current_app.config.get("SMTP_USE_SSL") is not None:
            self.use_ssl = str(current_app.config.get("SMTP_USE_SSL")).lower() in ("true", "1", "yes")
        elif os.environ.get("MAIL_USE_SSL"):
            self.use_ssl = os.environ.get("MAIL_USE_SSL", "false").lower() in ("true", "1", "yes")
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
        elif os.environ.get("MAIL_USE_TLS"):
            self.use_tls = os.environ.get("MAIL_USE_TLS", "true").lower() in ("true", "1", "yes")
        elif os.environ.get("SMTP_USE_TLS"):
            self.use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
        else:
            self.use_tls = True

        raw_from = (
            from_email
            or (current_app.config.get("SMTP_FROM_EMAIL") if current_app else None)
            or os.environ.get("MAIL_DEFAULT_SENDER")
            or os.environ.get("SMTP_FROM_EMAIL")
            or os.environ.get("EMAIL_FROM")
            or (self.username if (self.username and "@" in self.username) else "security@fraudshield.ai")
        )
        # Parse clean address
        parsed_addr = email.utils.parseaddr(raw_from)[1]
        self.from_email = parsed_addr if parsed_addr else str(raw_from).strip()

        raw_from_name = (
            from_name
            or (current_app.config.get("SMTP_FROM_NAME") if current_app else None)
            or os.environ.get("SMTP_FROM_NAME")
            or "FraudShield AI Security"
        )
        self.from_name = str(raw_from_name).strip()

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return safe configuration status without exposing credentials."""
        return {
            "provider": "SmtpEmailProvider",
            "smtp_host": self.host or "NOT_CONFIGURED",
            "smtp_port": self.port,
            "use_tls": self.use_tls,
            "use_ssl": self.use_ssl,
            "username_configured": bool(self.username),
            "password_configured": bool(self.password),
            "sender_configured": bool(self.from_email),
            "sender_address": self.from_email or "NOT_CONFIGURED",
        }

    def _send_smtp_message(
        self,
        recipient_email: str,
        subject: str,
        text_body: str,
        html_body: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Execute the standard RFC 5322 / SMTP sequence:
        1. Connect to host:port with socket timeout
        2. EHLO
        3. STARTTLS (if TLS enabled)
        4. EHLO (post-STARTTLS)
        5. AUTH LOGIN
        6. sendmail
        7. QUIT
        """
        if not self.host:
            err = "SMTP host is not configured."
            if current_app:
                current_app.logger.warning("[SMTP] %s", err)
            return False, err

        clean_recipient = str(recipient_email).strip().lower()

        # Build MIME Message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.from_name} <{self.from_email}>" if self.from_name else self.from_email
        msg["To"] = clean_recipient
        msg["Reply-To"] = self.from_email
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid(domain="fraudshield.ai")

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        diag = self.get_diagnostics()
        if current_app:
            current_app.logger.info(
                "[SMTP] Dispatching email: host=%s, port=%d, tls=%s, ssl=%s, user_configured=%s, pass_configured=%s, from=%s, to=%s",
                diag["smtp_host"],
                diag["smtp_port"],
                diag["use_tls"],
                diag["use_ssl"],
                diag["username_configured"],
                diag["password_configured"],
                diag["sender_address"],
                clean_recipient,
            )

        server = None
        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=25)
                server.ehlo()
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=25)
                server.ehlo()
                if self.use_tls:
                    server.starttls()
                    server.ehlo()

            if self.username and self.password:
                # Handle Google App Passwords if internal spaces were preserved
                pwd = self.password
                if "gmail" in str(self.host).lower():
                    pwd = pwd.replace(" ", "")
                server.login(self.username, pwd)

            envelope_from = email.utils.parseaddr(self.from_email)[1] or self.from_email
            server.sendmail(envelope_from, [clean_recipient], msg.as_string())

            if current_app:
                current_app.logger.info(
                    "[SMTP] Email successfully dispatched to %s (Subject: '%s')",
                    clean_recipient,
                    subject,
                )
            return True, None

        except smtplib.SMTPAuthenticationError as exc:
            err_msg = f"SMTPAuthenticationError: Authentication failed ({exc.smtp_code}: {exc.smtp_error.decode('utf-8', errors='ignore') if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)})"
            if current_app:
                current_app.logger.error("[SMTP] Authentication failed: %s", err_msg)
            return False, err_msg
        except smtplib.SMTPServerDisconnected as exc:
            err_msg = f"SMTPServerDisconnected: {str(exc) or 'Server unexpectedly disconnected'}"
            if current_app:
                current_app.logger.error("[SMTP] Server disconnected (%s:%s): %s", self.host, self.port, err_msg)
            return False, err_msg
        except smtplib.SMTPSenderRefused as exc:
            err_msg = f"SMTPSenderRefused: Sender address rejected ({exc.smtp_code}: {exc.smtp_error})"
            if current_app:
                current_app.logger.error("[SMTP] Sender refused '%s': %s", self.from_email, err_msg)
            return False, err_msg
        except smtplib.SMTPRecipientsRefused as exc:
            err_msg = f"SMTPRecipientsRefused: Recipient address rejected: {str(exc.recipients)}"
            if current_app:
                current_app.logger.error("[SMTP] Recipient refused '%s': %s", clean_recipient, err_msg)
            return False, err_msg
        except smtplib.SMTPConnectError as exc:
            err_msg = f"SMTPConnectError: Connection to {self.host}:{self.port} failed ({exc.smtp_code}: {exc.smtp_error})"
            if current_app:
                current_app.logger.error("[SMTP] Connection error: %s", err_msg)
            return False, err_msg
        except ssl.SSLError as exc:
            err_msg = f"SSLError: SSL/TLS handshake failed ({str(exc)})"
            if current_app:
                current_app.logger.error("[SMTP] SSL Error: %s", err_msg)
            return False, err_msg
        except (socket.timeout, TimeoutError) as exc:
            err_msg = f"TimeoutError: Connection or read timed out connecting to {self.host}:{self.port}"
            if current_app:
                current_app.logger.error("[SMTP] Timeout error: %s", err_msg)
            return False, err_msg
        except OSError as exc:
            err_msg = f"NetworkError (OSError): {str(exc)}"
            if current_app:
                current_app.logger.error("[SMTP] Network error connecting to %s:%s: %s", self.host, self.port, err_msg)
            return False, err_msg
        except Exception as exc:
            exc_type = type(exc).__name__
            err_msg = f"{exc_type}: {str(exc)}"
            if current_app:
                current_app.logger.error("[SMTP] Unexpected SMTP error (%s): %s", exc_type, err_msg)
            return False, err_msg
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
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

        return self._send_smtp_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )

    def send_email_verification_otp(
        self,
        recipient_email: str,
        otp_code: str,
        recipient_name: Optional[str] = None,
        verification_url: Optional[str] = None,
        expires_in_minutes: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        clean_recipient = str(recipient_email).strip().lower()
        display_name = (recipient_name or "FraudShield User").strip()
        clean_otp = str(otp_code).strip()

        subject = "FraudShield AI — Verify Your Email Address"
        formatted_otp = f"{clean_otp[:3]} {clean_otp[3:]}" if len(clean_otp) == 6 else clean_otp

        button_html = ""
        button_text = ""
        if verification_url:
            button_text = f"\nOr verify directly via link:\n{verification_url}\n"
            button_html = f"""
    <div style="text-align: center; margin: 20px 0 10px 0;">
      <p style="font-size: 14px; color: #9ca3af; margin-bottom: 10px;">Alternatively, verify your email with one click:</p>
      <a href="{verification_url}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; display: inline-block;">Verify Email Address</a>
    </div>"""

        text_body = (
            f"Hello {display_name},\n\n"
            f"Thank you for registering with FraudShield AI.\n\n"
            f"Your 6-Digit Email Verification Code is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n"
            f"{button_text}\n"
            f"If you did not initiate this registration, please disregard this message.\n\n"
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
      Thank you for creating an account with FraudShield AI. Please enter the verification code below in your registration portal to verify ownership of this email address:
    </p>
    <div style="text-align: center; margin: 28px 0; background: #0f172a; padding: 24px; border-radius: 10px; border: 1px solid #1e293b;">
      <div style="font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; color: #94a3b8; margin-bottom: 8px; font-weight: 600;">Verification Code</div>
      <div style="font-size: 36px; font-weight: 800; letter-spacing: 10px; color: #38bdf8; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;">{formatted_otp}</div>
      <div style="font-size: 13px; color: #f59e0b; margin-top: 10px;">⏱️ Expires in {expires_in_minutes} minutes</div>
    </div>
    {button_html}
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      If you did not attempt to create a FraudShield AI account, you can safely ignore this email.
    </p>
  </div>
</body>
</html>"""

        return self._send_smtp_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )

    def send_transaction_otp(
        self,
        recipient_email: str,
        otp_code: str,
        transaction_id: int,
        amount: Optional[float] = None,
        recipient_name: Optional[str] = None,
        expires_in_minutes: int = 3,
    ) -> Tuple[bool, Optional[str]]:
        clean_recipient = str(recipient_email).strip().lower()
        display_name = (recipient_name or "FraudShield User").strip()
        clean_otp = str(otp_code).strip()
        formatted_otp = f"{clean_otp[:3]} {clean_otp[3:]}" if len(clean_otp) == 6 else clean_otp

        amount_str = f" of ₹{amount:,.2f}" if amount is not None else ""
        subject = f"FraudShield AI — Transaction Verification Code [#{transaction_id}]"

        text_body = (
            f"Hello {display_name},\n\n"
            f"A payment transaction{amount_str} (Ref #{transaction_id}) on your FraudShield AI account requires step-up security verification.\n\n"
            f"Your 6-Digit One-Time Password (OTP) is:\n"
            f"{clean_otp}\n\n"
            f"This code is valid for {expires_in_minutes} minutes. Do NOT share this code with anyone.\n\n"
            f"If you did not initiate this payment, please contact security immediately.\n\n"
            f"FraudShield AI Security Team"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
    <div style="display: flex; align-items: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🛡️ FraudShield AI Security</h2>
    </div>
    <p style="font-size: 16px; line-height: 1.6; color: #f3f4f6; margin-bottom: 12px;">Hello <strong>{display_name}</strong>,</p>
    <p style="font-size: 15px; line-height: 1.6; color: #9ca3af; margin-bottom: 24px;">
      A payment transaction{amount_str} (Transaction <strong>#{transaction_id}</strong>) requires step-up multi-factor authentication. Please enter this code in your payment window to complete the transaction:
    </p>
    <div style="text-align: center; margin: 28px 0; background: #0f172a; padding: 24px; border-radius: 10px; border: 1px solid #1e293b;">
      <div style="font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; color: #94a3b8; margin-bottom: 8px; font-weight: 600;">Transaction Verification Code</div>
      <div style="font-size: 36px; font-weight: 800; letter-spacing: 10px; color: #38bdf8; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;">{formatted_otp}</div>
      <div style="font-size: 13px; color: #f59e0b; margin-top: 10px;">⏱️ Expires in {expires_in_minutes} minutes</div>
    </div>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px;">
      <p style="font-size: 13px; color: #fbbf24; margin: 0;">
        🛡️ <strong>Escrow Protection:</strong> No funds will be deducted from your account until this code is successfully verified.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      If you did not authorize this transaction, do NOT enter this code and secure your account immediately.
    </p>
  </div>
</body>
</html>"""

        return self._send_smtp_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )

    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        clean_recipient = str(recipient_email).strip().lower()
        subject = "FraudShield AI — SMTP Diagnostic Test"
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        diag = self.get_diagnostics()

        text_body = (
            f"Hello,\n\n"
            f"This is an automated diagnostic test email from FraudShield AI.\n\n"
            f"Timestamp: {timestamp_str}\n"
            f"SMTP Host: {diag.get('smtp_host')}\n"
            f"SMTP Port: {diag.get('smtp_port')}\n"
            f"TLS Enabled: {diag.get('use_tls')}\n"
            f"SSL Enabled: {diag.get('use_ssl')}\n"
            f"Sender Address: {diag.get('sender_address')}\n\n"
            f"If you received this email, your FraudShield AI SMTP configuration is working correctly!\n\n"
            f"FraudShield AI Security"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 32px; border: 1px solid #1f2937;">
    <h2 style="color: #38bdf8; margin-top: 0;">🛡️ FraudShield AI — SMTP Diagnostic Test</h2>
    <p style="color: #34d399; font-weight: 600; font-size: 16px;">✅ SMTP Send Succeeded!</p>
    <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
      This diagnostic message confirms that your SMTP delivery channel is active, authenticated, and delivering real emails to inboxes.
    </p>
    <div style="background: #0f172a; border-radius: 8px; padding: 16px; border: 1px solid #1e293b; font-family: monospace; font-size: 13px; color: #cbd5e1; margin: 20px 0;">
      <div><strong>Timestamp:</strong> {timestamp_str}</div>
      <div><strong>Host:</strong> {diag.get('smtp_host')}</div>
      <div><strong>Port:</strong> {diag.get('smtp_port')}</div>
      <div><strong>TLS:</strong> {diag.get('use_tls')}</div>
      <div><strong>SSL:</strong> {diag.get('use_ssl')}</div>
      <div><strong>Sender:</strong> {diag.get('sender_address')}</div>
    </div>
    <p style="color: #64748b; font-size: 12px; margin-bottom: 0;">FraudShield AI Production Diagnostics</p>
  </div>
</body>
</html>"""

        return self._send_smtp_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )


class NullEmailProvider(EmailProvider):
    """Fallback provider when no valid email provider credentials are configured in production."""

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure SMTP credentials."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send reset email with no provider configured.")
        return False, msg

    def send_email_verification_otp(
        self,
        recipient_email: str,
        otp_code: str,
        recipient_name: Optional[str] = None,
        verification_url: Optional[str] = None,
        expires_in_minutes: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure SMTP credentials."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send email verification OTP with no provider configured.")
        return False, msg

    def send_transaction_otp(
        self,
        recipient_email: str,
        otp_code: str,
        transaction_id: int,
        amount: Optional[float] = None,
        recipient_name: Optional[str] = None,
        expires_in_minutes: int = 3,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure SMTP credentials."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send transaction OTP with no provider configured.")
        return False, msg

    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure SMTP credentials."
        return False, msg


def get_email_provider() -> EmailProvider:
    """
    Factory resolving active EmailProvider based on runtime configuration.
    
    Order of resolution:
    1. Explicit MAIL_PROVIDER / EMAIL_PROVIDER configuration ('smtp', 'development', 'null').
    2. If MAIL_SERVER / SMTP_HOST / SMTP_SERVER is defined in env/config and non-empty, use SmtpEmailProvider.
    3. If app is TESTING or DEBUG (and no explicit SMTP host defined), use DevelopmentEmailProvider.
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
                if p == "smtp":
                    return SmtpEmailProvider()
                elif p == "null":
                    return NullEmailProvider()
                elif p == "development":
                    return DevelopmentEmailProvider()

            # If in automated testing without explicit override, use DevelopmentEmailProvider
            if current_app.config.get("TESTING"):
                return DevelopmentEmailProvider()

            # If explicit SMTP_HOST / MAIL_SERVER in config, prefer SmtpEmailProvider
            smtp_host = (
                current_app.config.get("SMTP_HOST")
                or current_app.config.get("MAIL_SERVER")
                or current_app.config.get("SMTP_SERVER")
            )
            if smtp_host and str(smtp_host).strip():
                return SmtpEmailProvider()
    except RuntimeError:
        pass

    # 2. Check environment variables
    env_provider = (
        os.environ.get("MAIL_PROVIDER", "")
        or os.environ.get("EMAIL_PROVIDER", "")
    ).lower().strip()

    if env_provider == "smtp":
        return SmtpEmailProvider()
    if env_provider == "null":
        return NullEmailProvider()
    if env_provider == "development":
        env_host = os.environ.get("MAIL_SERVER") or os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER")
        if env_host and str(env_host).strip():
            return SmtpEmailProvider()
        return DevelopmentEmailProvider()

    env_host = os.environ.get("MAIL_SERVER") or os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER")
    if env_host and str(env_host).strip():
        return SmtpEmailProvider()

    if os.environ.get("FLASK_ENV") in ("testing", "development") or os.environ.get("ENV") == "testing":
        return DevelopmentEmailProvider()

    return NullEmailProvider()
