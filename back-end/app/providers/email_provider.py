"""
Email Provider Abstraction Layer for FraudShield AI.

Provides modular email delivery services:
- EmailProvider (Abstract Base Class)
- BrevoEmailProvider (Official Brevo HTTPS REST API - primary domain-free verified sender transport)
- ResendEmailProvider (Official Resend HTTPS REST API - secondary HTTPS transport)
- SmtpEmailProvider (Standard SMTP / TLS delivery - local/fallback transport)
- DevelopmentEmailProvider (Secure logging + test in-memory storage)
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
        Send a diagnostic test email to verify delivery functionality.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        pass


class BrevoEmailProvider(EmailProvider):
    """
    Official Brevo (formerly Sendinblue) HTTPS REST API Email Provider.

    Communicates via outbound HTTPS (https://api.brevo.com/v3/smtp/email on port 443).
    Bypasses PaaS SMTP port blocks (ports 25, 465, 587) on platforms like Render.
    Allows verifying a single Gmail address (e.g. teamfraudsheildai@gmail.com) to send
    transactional emails to arbitrary recipients without purchasing a custom domain.

    Configured via environment variables:
    - BREVO_API_KEY / MAIL_API_KEY: Brevo API Key (e.g. xkeysib-...)
    - BREVO_FROM_EMAIL / MAIL_DEFAULT_SENDER: Verified sender address (e.g. teamfraudsheildai@gmail.com)
    - BREVO_FROM_NAME / SMTP_FROM_NAME: Sender display name (default: 'FraudShield AI Security')
    - BREVO_REPLY_TO: Optional reply-to address
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None,
    ):
        raw_key = (
            api_key
            or (current_app.config.get("BREVO_API_KEY") if current_app else None)
            or (current_app.config.get("MAIL_API_KEY") if current_app else None)
            or os.environ.get("BREVO_API_KEY")
            or os.environ.get("MAIL_API_KEY")
            or ""
        )
        self.api_key = str(raw_key).strip().strip('"').strip("'")

        raw_from = (
            from_email
            or (current_app.config.get("BREVO_FROM_EMAIL") if current_app else None)
            or (current_app.config.get("MAIL_DEFAULT_SENDER") if current_app else None)
            or os.environ.get("BREVO_FROM_EMAIL")
            or os.environ.get("MAIL_DEFAULT_SENDER")
            or os.environ.get("SMTP_FROM_EMAIL")
            or os.environ.get("EMAIL_FROM")
            or "teamfraudsheildai@gmail.com"
        )
        parsed_addr = email.utils.parseaddr(str(raw_from))[1]
        self.from_email = parsed_addr if parsed_addr else str(raw_from).strip()

        raw_from_name = (
            from_name
            or (current_app.config.get("BREVO_FROM_NAME") if current_app else None)
            or (current_app.config.get("SMTP_FROM_NAME") if current_app else None)
            or os.environ.get("BREVO_FROM_NAME")
            or os.environ.get("SMTP_FROM_NAME")
            or "FraudShield AI Security"
        )
        self.from_name = str(raw_from_name).strip()

        raw_reply_to = (
            reply_to
            or (current_app.config.get("BREVO_REPLY_TO") if current_app else None)
            or os.environ.get("BREVO_REPLY_TO")
            or self.from_email
        )
        parsed_reply = email.utils.parseaddr(str(raw_reply_to))[1]
        self.reply_to = parsed_reply if parsed_reply else str(raw_reply_to).strip()

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return safe configuration status without exposing secrets."""
        return {
            "provider": "BrevoEmailProvider",
            "transport": "HTTPS REST API (api.brevo.com:443)",
            "api_key_configured": bool(self.api_key),
            "from_email": self.from_email,
            "from_name": self.from_name,
            "reply_to": self.reply_to,
        }

    def _send_brevo_message(
        self,
        recipient_email: str,
        subject: str,
        text_body: str,
        html_body: str,
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Dispatch an email through the Brevo HTTPS REST API."""
        if not self.api_key:
            err = "BREVO_API_KEY (or MAIL_API_KEY) is not configured in environment variables."
            if current_app:
                current_app.logger.warning("[BREVO] %s", err)
            return False, err

        clean_recipient = str(recipient_email).strip().lower()
        disp_name = (recipient_name or clean_recipient.split("@")[0]).strip()

        if current_app:
            current_app.logger.info(
                "[BREVO] Dispatching email: from='%s <%s>', to='%s', subject='%s'",
                self.from_name,
                self.from_email,
                clean_recipient,
                subject,
            )

        try:
            import requests

            url = "https://api.brevo.com/v3/smtp/email"
            payload: Dict[str, Any] = {
                "sender": {"name": self.from_name, "email": self.from_email},
                "to": [{"email": clean_recipient, "name": disp_name}],
                "subject": subject,
                "htmlContent": html_body,
                "textContent": text_body,
            }
            if self.reply_to and self.reply_to != self.from_email:
                payload["replyTo"] = {"email": self.reply_to}

            headers = {
                "api-key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            resp = requests.post(url, json=payload, headers=headers, timeout=15)

            if resp.status_code in (200, 201, 202):
                data = resp.json() if resp.content else {}
                msg_id = data.get("messageId")
                if current_app:
                    current_app.logger.info(
                        "[BREVO] SUCCESS: Email accepted by Brevo API for '%s' (Message ID: %s)",
                        clean_recipient,
                        msg_id,
                    )
                return True, None
            else:
                try:
                    err_json = resp.json()
                    raw_err = err_json.get("message") or err_json.get("code") or resp.text
                except Exception:
                    raw_err = resp.text[:200]
                err_msg = f"HTTP {resp.status_code}: {raw_err}"
                if current_app:
                    current_app.logger.error(
                        "[BREVO] FAILURE: Brevo API rejected email for '%s': %s",
                        clean_recipient,
                        err_msg,
                    )
                return False, err_msg
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {str(exc)}"
            if current_app:
                current_app.logger.error(
                    "[BREVO] FAILURE: Request exception for '%s': %s",
                    clean_recipient,
                    err_msg,
                )
            return False, err_msg

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
        expiry_info = (
            f"This link expires in 15 minutes (at {expires_at.strftime('%H:%M UTC')}) and can only be used once."
            if expires_at
            else "This link expires in 15 minutes and can only be used once."
        )

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

        return self._send_brevo_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            recipient_name=display_name,
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
        formatted_otp = f"{clean_otp[:3]} {clean_otp[3:]}" if len(clean_otp) == 6 else clean_otp

        subject = "FraudShield AI — Verify Your Email Address"

        text_body = (
            f"Hello {display_name},\n\n"
            f"Thank you for registering with FraudShield AI.\n\n"
            f"Your 6-digit email verification code is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
        )
        if verification_url:
            text_body += f"Or verify directly by clicking:\n{verification_url}\n\n"
        text_body += (
            f"If you did not attempt to register an account, please disregard this message.\n\n"
            f"FraudShield AI Security Team"
        )

        button_html = ""
        if verification_url:
            button_html = f"""
            <div style="text-align: center; margin: 24px 0 16px 0;">
              <p style="font-size: 14px; color: #9ca3af; margin-bottom: 12px;">Or verify your email directly with one click:</p>
              <a href="{verification_url}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; display: inline-block;">Verify Email Address</a>
            </div>
            """

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
      Thank you for creating an account with FraudShield AI. Please use the verification code below to confirm ownership of your email address:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <div style="background: #1e293b; border: 2px dashed #0284c7; border-radius: 10px; display: inline-block; padding: 16px 36px;">
        <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{formatted_otp}</span>
      </div>
      <p style="font-size: 13px; color: #9ca3af; margin-top: 10px;">Expires in {expires_in_minutes} minutes</p>
    </div>
    {button_html}
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-top: 24px;">
      <p style="font-size: 13px; color: #9ca3af; margin: 0;">
        🔒 <strong>Security Tip:</strong> FraudShield AI representatives will never ask you for this one-time code. Do not share it with anyone.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      If you did not request this verification, please safely ignore this email.
    </p>
  </div>
</body>
</html>"""

        return self._send_brevo_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            recipient_name=display_name,
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
        amount_display = f"₹{amount:,.2f}" if amount is not None else "your payment"

        subject = f"FraudShield AI — Transaction Verification OTP (Tx #{transaction_id})"

        text_body = (
            f"Hello {display_name},\n\n"
            f"A payment transaction of {amount_display} (Transaction ID: #{transaction_id}) has been initiated and requires step-up security verification.\n\n"
            f"Your Transaction OTP is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
            f"If you did not authorize this payment, please immediately contact security and block your account.\n\n"
            f"FraudShield AI Security Operations"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
    <div style="display: flex; align-items: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🛡️ FraudShield AI</h2>
    </div>
    <div style="background: #ef444415; border: 1px solid #ef444440; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px;">
      <p style="color: #f87171; margin: 0; font-size: 14px; font-weight: 600;">⚠️ Step-Up Security Challenge Required</p>
    </div>
    <p style="font-size: 16px; line-height: 1.6; color: #f3f4f6; margin-bottom: 12px;">Hello <strong>{display_name}</strong>,</p>
    <p style="font-size: 15px; line-height: 1.6; color: #9ca3af; margin-bottom: 20px;">
      A transaction of <strong>{amount_display}</strong> (ID: <code>#{transaction_id}</code>) triggered our adaptive fraud detection protocol. Please enter the one-time verification passcode below to confirm and authorize this transaction:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <div style="background: #1e293b; border: 2px dashed #38bdf8; border-radius: 10px; display: inline-block; padding: 16px 36px;">
        <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{formatted_otp}</span>
      </div>
      <p style="font-size: 13px; color: #9ca3af; margin-top: 10px;">Valid for {expires_in_minutes} minutes</p>
    </div>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-top: 24px;">
      <p style="font-size: 13px; color: #f87171; margin: 0;">
        🚨 <strong>Didn't make this payment?</strong> Do not share this OTP. Immediately log in to lock your payment credentials.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      FraudShield AI Real-Time Transaction Security Engine
    </p>
  </div>
</body>
</html>"""

        return self._send_brevo_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            recipient_name=display_name,
        )

    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        clean_recipient = str(recipient_email).strip().lower()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg_text = test_message or "Your FraudShield AI email delivery configuration is working correctly."

        subject = "FraudShield AI — Diagnostic Delivery Test (Brevo HTTPS API)"
        text_body = (
            f"FraudShield AI — Diagnostic Delivery Test\n\n"
            f"{msg_text}\n\n"
            f"Timestamp: {now_str}\n"
            f"Provider:  Brevo HTTPS REST API (Port 443)\n"
            f"Sender:    {self.from_name} <{self.from_email}>\n\n"
            f"FraudShield AI Diagnostic Tool"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937;">
    <h2 style="color: #22c55e; margin: 0 0 16px 0; font-size: 20px;">✅ Brevo HTTPS API Delivery Verified</h2>
    <p style="color: #f3f4f6; font-size: 15px; line-height: 1.6;">{msg_text}</p>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin: 20px 0; font-size: 13px; font-family: monospace;">
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Provider:</strong> BrevoEmailProvider (HTTPS:443)</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Sender:</strong> {self.from_name} &lt;{self.from_email}&gt;</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Recipient:</strong> {clean_recipient}</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Timestamp:</strong> {now_str}</p>
    </div>
  </div>
</body>
</html>"""

        return self._send_brevo_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )


class ResendEmailProvider(EmailProvider):
    """
    Official Resend HTTPS REST API Email Provider.
    
    Communicates via outbound HTTPS (api.resend.com:443).
    Bypasses PaaS SMTP port blocks (ports 25, 465, 587) on platforms like Render.
    
    Configured via environment variables:
    - RESEND_API_KEY: Resend API Key (e.g. re_123456789)
    - RESEND_FROM_EMAIL / MAIL_DEFAULT_SENDER: Sender address (e.g. onboarding@resend.dev or verified domain)
    - RESEND_FROM_NAME / SMTP_FROM_NAME: Sender display name (default: 'FraudShield AI Security')
    - RESEND_REPLY_TO: Optional reply-to address
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None,
    ):
        raw_key = (
            api_key
            or (current_app.config.get("RESEND_API_KEY") if current_app else None)
            or os.environ.get("RESEND_API_KEY")
            or ""
        )
        self.api_key = str(raw_key).strip().strip('"').strip("'")

        raw_from = (
            from_email
            or (current_app.config.get("RESEND_FROM_EMAIL") if current_app else None)
            or os.environ.get("RESEND_FROM_EMAIL")
            or os.environ.get("MAIL_DEFAULT_SENDER")
            or os.environ.get("SMTP_FROM_EMAIL")
            or os.environ.get("EMAIL_FROM")
            or "onboarding@resend.dev"
        )
        parsed_addr = email.utils.parseaddr(str(raw_from))[1]
        self.from_email = parsed_addr if parsed_addr else str(raw_from).strip()

        raw_from_name = (
            from_name
            or (current_app.config.get("RESEND_FROM_NAME") if current_app else None)
            or os.environ.get("RESEND_FROM_NAME")
            or os.environ.get("SMTP_FROM_NAME")
            or "FraudShield AI Security"
        )
        self.from_name = str(raw_from_name).strip()

        raw_reply_to = (
            reply_to
            or (current_app.config.get("RESEND_REPLY_TO") if current_app else None)
            or os.environ.get("RESEND_REPLY_TO")
            or self.from_email
        )
        parsed_reply = email.utils.parseaddr(str(raw_reply_to))[1]
        self.reply_to = parsed_reply if parsed_reply else str(raw_reply_to).strip()

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return safe configuration status without exposing credentials."""
        return {
            "provider": "ResendEmailProvider",
            "transport": "HTTPS REST API (api.resend.com:443)",
            "api_key_configured": bool(self.api_key),
            "from_email": self.from_email,
            "from_name": self.from_name,
            "reply_to": self.reply_to,
        }

    def _send_resend_message(
        self,
        recipient_email: str,
        subject: str,
        text_body: str,
        html_body: str,
    ) -> Tuple[bool, Optional[str]]:
        """Dispatch an email through the Resend HTTPS API."""
        if not self.api_key:
            err = "RESEND_API_KEY is not configured in environment variables."
            if current_app:
                current_app.logger.warning("[RESEND] %s", err)
            return False, err

        clean_recipient = str(recipient_email).strip().lower()
        from_header = f"{self.from_name} <{self.from_email}>" if self.from_name else self.from_email

        if current_app:
            current_app.logger.info(
                "[RESEND] Dispatching email: from='%s', to='%s', subject='%s'",
                from_header,
                clean_recipient,
                subject,
            )

        try:
            import resend

            resend.api_key = self.api_key

            params: Dict[str, Any] = {
                "from": from_header,
                "to": [clean_recipient],
                "subject": subject,
                "html": html_body,
                "text": text_body,
            }
            if self.reply_to and self.reply_to != self.from_email:
                params["reply_to"] = self.reply_to

            response = resend.Emails.send(params)

            msg_id = response.get("id") if isinstance(response, dict) else getattr(response, "id", None)
            if current_app:
                current_app.logger.info(
                    "[RESEND] SUCCESS: Email accepted by Resend API for '%s' (ID: %s)",
                    clean_recipient,
                    msg_id,
                )
            return True, None

        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {str(exc)}"
            if current_app:
                current_app.logger.error(
                    "[RESEND] FAILURE: Email delivery failed for '%s': %s",
                    clean_recipient,
                    err_msg,
                )
            return False, err_msg

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
        expiry_info = (
            f"This link expires in 15 minutes (at {expires_at.strftime('%H:%M UTC')}) and can only be used once."
            if expires_at
            else "This link expires in 15 minutes and can only be used once."
        )

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

        return self._send_resend_message(
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
        formatted_otp = f"{clean_otp[:3]} {clean_otp[3:]}" if len(clean_otp) == 6 else clean_otp

        subject = "FraudShield AI — Verify Your Email Address"

        text_body = (
            f"Hello {display_name},\n\n"
            f"Thank you for registering with FraudShield AI.\n\n"
            f"Your 6-digit email verification code is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
        )
        if verification_url:
            text_body += f"Or verify directly by clicking:\n{verification_url}\n\n"
        text_body += (
            f"If you did not attempt to register an account, please disregard this message.\n\n"
            f"FraudShield AI Security Team"
        )

        button_html = ""
        if verification_url:
            button_html = f"""
            <div style="text-align: center; margin: 24px 0 16px 0;">
              <p style="font-size: 14px; color: #9ca3af; margin-bottom: 12px;">Or verify your email directly with one click:</p>
              <a href="{verification_url}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; display: inline-block;">Verify Email Address</a>
            </div>
            """

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
      Thank you for creating an account with FraudShield AI. Please use the verification code below to confirm ownership of your email address:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <div style="background: #1e293b; border: 2px dashed #0284c7; border-radius: 10px; display: inline-block; padding: 16px 36px;">
        <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{formatted_otp}</span>
      </div>
      <p style="font-size: 13px; color: #9ca3af; margin-top: 10px;">Expires in {expires_in_minutes} minutes</p>
    </div>
    {button_html}
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-top: 24px;">
      <p style="font-size: 13px; color: #9ca3af; margin: 0;">
        🔒 <strong>Security Tip:</strong> FraudShield AI representatives will never ask you for this one-time code. Do not share it with anyone.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      If you did not request this verification, please safely ignore this email.
    </p>
  </div>
</body>
</html>"""

        return self._send_resend_message(
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
        amount_display = f"₹{amount:,.2f}" if amount is not None else "your payment"

        subject = f"FraudShield AI — Transaction Verification OTP (Tx #{transaction_id})"

        text_body = (
            f"Hello {display_name},\n\n"
            f"A payment transaction of {amount_display} (Transaction ID: #{transaction_id}) has been initiated and requires step-up security verification.\n\n"
            f"Your Transaction OTP is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
            f"If you did not authorize this payment, please immediately contact security and block your account.\n\n"
            f"FraudShield AI Security Operations"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
    <div style="display: flex; align-items: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🛡️ FraudShield AI</h2>
    </div>
    <div style="background: #ef444415; border: 1px solid #ef444440; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px;">
      <p style="color: #f87171; margin: 0; font-size: 14px; font-weight: 600;">⚠️ Step-Up Security Challenge Required</p>
    </div>
    <p style="font-size: 16px; line-height: 1.6; color: #f3f4f6; margin-bottom: 12px;">Hello <strong>{display_name}</strong>,</p>
    <p style="font-size: 15px; line-height: 1.6; color: #9ca3af; margin-bottom: 20px;">
      A transaction of <strong>{amount_display}</strong> (ID: <code>#{transaction_id}</code>) triggered our adaptive fraud detection protocol. Please enter the one-time verification passcode below to confirm and authorize this transaction:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <div style="background: #1e293b; border: 2px dashed #38bdf8; border-radius: 10px; display: inline-block; padding: 16px 36px;">
        <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{formatted_otp}</span>
      </div>
      <p style="font-size: 13px; color: #9ca3af; margin-top: 10px;">Valid for {expires_in_minutes} minutes</p>
    </div>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-top: 24px;">
      <p style="font-size: 13px; color: #f87171; margin: 0;">
        🚨 <strong>Didn't make this payment?</strong> Do not share this OTP. Immediately log in to lock your payment credentials.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      FraudShield AI Real-Time Transaction Security Engine
    </p>
  </div>
</body>
</html>"""

        return self._send_resend_message(
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
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg_text = test_message or "Your FraudShield AI email delivery configuration is working correctly."

        subject = "FraudShield AI — Diagnostic Delivery Test (Resend HTTPS API)"
        text_body = (
            f"FraudShield AI — Diagnostic Delivery Test\n\n"
            f"{msg_text}\n\n"
            f"Timestamp: {now_str}\n"
            f"Provider:  Resend HTTPS REST API (Port 443)\n"
            f"Sender:    {self.from_name} <{self.from_email}>\n\n"
            f"FraudShield AI Diagnostic Tool"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937;">
    <h2 style="color: #22c55e; margin: 0 0 16px 0; font-size: 20px;">✅ Resend HTTPS API Delivery Verified</h2>
    <p style="color: #f3f4f6; font-size: 15px; line-height: 1.6;">{msg_text}</p>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin: 20px 0; font-size: 13px; font-family: monospace;">
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Provider:</strong> ResendEmailProvider (HTTPS:443)</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Sender:</strong> {self.from_name} &lt;{self.from_email}&gt;</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Recipient:</strong> {clean_recipient}</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Timestamp:</strong> {now_str}</p>
    </div>
  </div>
</body>
</html>"""

        return self._send_resend_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )


class SmtpEmailProvider(EmailProvider):
    """
    Standard SMTP / TLS / SSL Email Provider for local environments or dedicated hosting.
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
        timeout: int = 10,
    ):
        raw_host = (
            host
            or (current_app.config.get("SMTP_HOST") if current_app else None)
            or (current_app.config.get("MAIL_SERVER") if current_app else None)
            or os.environ.get("MAIL_SERVER")
            or os.environ.get("SMTP_HOST")
            or os.environ.get("SMTP_SERVER")
            or ""
        )
        self.host = str(raw_host).strip().strip('"').strip("'")

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
            or ""
        )
        self.username = str(raw_user).strip().strip('"').strip("'")

        raw_pass = (
            password
            or (current_app.config.get("SMTP_PASSWORD") if current_app else None)
            or (current_app.config.get("MAIL_PASSWORD") if current_app else None)
            or os.environ.get("MAIL_PASSWORD")
            or os.environ.get("SMTP_PASSWORD")
            or ""
        )
        self.password = str(raw_pass).strip().strip('"').strip("'")

        if use_ssl is not None:
            self.use_ssl = bool(use_ssl)
        elif self.port == 465:
            self.use_ssl = True
        elif current_app and "SMTP_USE_SSL" in current_app.config:
            self.use_ssl = bool(current_app.config.get("SMTP_USE_SSL"))
        else:
            raw_ssl_env = os.environ.get("MAIL_USE_SSL", os.environ.get("SMTP_USE_SSL", "false"))
            self.use_ssl = str(raw_ssl_env).lower() in ["true", "1", "yes"]

        if use_tls is not None:
            self.use_tls = bool(use_tls)
        elif self.use_ssl:
            self.use_tls = False
        elif current_app and "SMTP_USE_TLS" in current_app.config:
            self.use_tls = bool(current_app.config.get("SMTP_USE_TLS"))
        else:
            raw_tls_env = os.environ.get("MAIL_USE_TLS", os.environ.get("SMTP_USE_TLS", "true"))
            self.use_tls = str(raw_tls_env).lower() in ["true", "1", "yes"]

        raw_from = (
            from_email
            or (current_app.config.get("SMTP_FROM_EMAIL") if current_app else None)
            or (current_app.config.get("MAIL_DEFAULT_SENDER") if current_app else None)
            or os.environ.get("MAIL_DEFAULT_SENDER")
            or os.environ.get("SMTP_FROM_EMAIL")
            or os.environ.get("EMAIL_FROM")
            or (self.username if self.username and "@" in self.username else "teamfraudsheildai@gmail.com")
        )
        parsed_addr = email.utils.parseaddr(str(raw_from))[1]
        self.from_email = parsed_addr if parsed_addr else str(raw_from).strip()

        raw_from_name = (
            from_name
            or (current_app.config.get("SMTP_FROM_NAME") if current_app else None)
            or os.environ.get("SMTP_FROM_NAME")
            or "FraudShield AI Security"
        )
        self.from_name = str(raw_from_name).strip()
        self.timeout = timeout

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return non-sensitive connection settings."""
        return {
            "provider": "SmtpEmailProvider",
            "smtp_host": self.host or "NOT_CONFIGURED",
            "smtp_port": self.port,
            "use_tls": self.use_tls,
            "use_ssl": self.use_ssl,
            "username_configured": bool(self.username),
            "password_configured": bool(self.password),
            "sender_address": self.from_email,
            "sender_name": self.from_name,
        }

    def _connect(self) -> smtplib.SMTP:
        """Establish connection, initiate TLS if enabled, and authenticate."""
        if not self.host:
            raise ValueError("SMTP host is not configured.")

        if self.use_ssl:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)

        server.ehlo()
        if self.use_tls and not self.use_ssl:
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo()

        if self.username and self.password:
            server.login(self.username, self.password)

        return server

    def _send_smtp_message(
        self,
        recipient_email: str,
        subject: str,
        text_body: str,
        html_body: str,
    ) -> Tuple[bool, Optional[str]]:
        """Construct MIME message and dispatch via SMTP."""
        if not self.host:
            return False, "SMTP server is not configured in environment variables."

        clean_recipient = str(recipient_email).strip().lower()
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.from_name} <{self.from_email}>" if self.from_name else self.from_email
        msg["To"] = clean_recipient

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        server = None
        try:
            server = self._connect()
            server.sendmail(self.from_email, [clean_recipient], msg.as_string())
            if current_app:
                current_app.logger.info("[SMTP] SUCCESS: Message delivered to '%s'", clean_recipient)
            return True, None
        except (socket.error, OSError) as net_err:
            err_msg = f"NetworkError ({type(net_err).__name__}): {str(net_err)}"
            if current_app:
                current_app.logger.error("[SMTP] FAILURE: %s", err_msg)
            return False, err_msg
        except smtplib.SMTPAuthenticationError as auth_err:
            err_msg = f"SMTPAuthenticationError: {auth_err.smtp_error.decode('utf-8', errors='ignore') if isinstance(auth_err.smtp_error, bytes) else str(auth_err.smtp_error)}"
            if current_app:
                current_app.logger.error("[SMTP] FAILURE: %s", err_msg)
            return False, err_msg
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {str(exc)}"
            if current_app:
                current_app.logger.error("[SMTP] FAILURE: %s", err_msg)
            return False, err_msg
        finally:
            if server:
                try:
                    server.quit()
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
        expiry_info = (
            f"This link expires in 15 minutes (at {expires_at.strftime('%H:%M UTC')}) and can only be used once."
            if expires_at
            else "This link expires in 15 minutes and can only be used once."
        )

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
        formatted_otp = f"{clean_otp[:3]} {clean_otp[3:]}" if len(clean_otp) == 6 else clean_otp

        subject = "FraudShield AI — Verify Your Email Address"

        text_body = (
            f"Hello {display_name},\n\n"
            f"Thank you for registering with FraudShield AI.\n\n"
            f"Your 6-digit email verification code is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
        )
        if verification_url:
            text_body += f"Or verify directly by clicking:\n{verification_url}\n\n"
        text_body += (
            f"If you did not attempt to register an account, please disregard this message.\n\n"
            f"FraudShield AI Security Team"
        )

        button_html = ""
        if verification_url:
            button_html = f"""
            <div style="text-align: center; margin: 24px 0 16px 0;">
              <p style="font-size: 14px; color: #9ca3af; margin-bottom: 12px;">Or verify your email directly with one click:</p>
              <a href="{verification_url}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 14px; display: inline-block;">Verify Email Address</a>
            </div>
            """

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
      Thank you for creating an account with FraudShield AI. Please use the verification code below to confirm ownership of your email address:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <div style="background: #1e293b; border: 2px dashed #0284c7; border-radius: 10px; display: inline-block; padding: 16px 36px;">
        <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{formatted_otp}</span>
      </div>
      <p style="font-size: 13px; color: #9ca3af; margin-top: 10px;">Expires in {expires_in_minutes} minutes</p>
    </div>
    {button_html}
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-top: 24px;">
      <p style="font-size: 13px; color: #9ca3af; margin: 0;">
        🔒 <strong>Security Tip:</strong> FraudShield AI representatives will never ask you for this one-time code. Do not share it with anyone.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      If you did not request this verification, please safely ignore this email.
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
        amount_display = f"₹{amount:,.2f}" if amount is not None else "your payment"

        subject = f"FraudShield AI — Transaction Verification OTP (Tx #{transaction_id})"

        text_body = (
            f"Hello {display_name},\n\n"
            f"A payment transaction of {amount_display} (Transaction ID: #{transaction_id}) has been initiated and requires step-up security verification.\n\n"
            f"Your Transaction OTP is:\n"
            f"{clean_otp}\n\n"
            f"This code will expire in {expires_in_minutes} minutes.\n\n"
            f"If you did not authorize this payment, please immediately contact security and block your account.\n\n"
            f"FraudShield AI Security Operations"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
    <div style="display: flex; align-items: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🛡️ FraudShield AI</h2>
    </div>
    <div style="background: #ef444415; border: 1px solid #ef444440; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px;">
      <p style="color: #f87171; margin: 0; font-size: 14px; font-weight: 600;">⚠️ Step-Up Security Challenge Required</p>
    </div>
    <p style="font-size: 16px; line-height: 1.6; color: #f3f4f6; margin-bottom: 12px;">Hello <strong>{display_name}</strong>,</p>
    <p style="font-size: 15px; line-height: 1.6; color: #9ca3af; margin-bottom: 20px;">
      A transaction of <strong>{amount_display}</strong> (ID: <code>#{transaction_id}</code>) triggered our adaptive fraud detection protocol. Please enter the one-time verification passcode below to confirm and authorize this transaction:
    </p>
    <div style="text-align: center; margin: 32px 0;">
      <div style="background: #1e293b; border: 2px dashed #38bdf8; border-radius: 10px; display: inline-block; padding: 16px 36px;">
        <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{formatted_otp}</span>
      </div>
      <p style="font-size: 13px; color: #9ca3af; margin-top: 10px;">Valid for {expires_in_minutes} minutes</p>
    </div>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin-top: 24px;">
      <p style="font-size: 13px; color: #f87171; margin: 0;">
        🚨 <strong>Didn't make this payment?</strong> Do not share this OTP. Immediately log in to lock your payment credentials.
      </p>
    </div>
    <p style="font-size: 13px; line-height: 1.5; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 20px; margin-top: 28px;">
      FraudShield AI Real-Time Transaction Security Engine
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
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg_text = test_message or "Your FraudShield AI email delivery configuration is working correctly."

        subject = "FraudShield AI — Diagnostic Delivery Test (SMTP)"
        text_body = (
            f"FraudShield AI — Diagnostic Delivery Test\n\n"
            f"{msg_text}\n\n"
            f"Timestamp: {now_str}\n"
            f"Provider:  SmtpEmailProvider\n"
            f"Host:      {self.host}:{self.port}\n"
            f"Sender:    {self.from_name} <{self.from_email}>\n\n"
            f"FraudShield AI Diagnostic Tool"
        )

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 24px; margin: 0;">
  <div style="max-width: 580px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 36px; border: 1px solid #1f2937;">
    <h2 style="color: #22c55e; margin: 0 0 16px 0; font-size: 20px;">✅ SMTP Delivery Verified</h2>
    <p style="color: #f3f4f6; font-size: 15px; line-height: 1.6;">{msg_text}</p>
    <div style="background: #1f2937; border-radius: 8px; padding: 14px 18px; margin: 20px 0; font-size: 13px; font-family: monospace;">
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Provider:</strong> SmtpEmailProvider ({self.host}:{self.port})</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Sender:</strong> {self.from_name} &lt;{self.from_email}&gt;</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Recipient:</strong> {clean_recipient}</p>
      <p style="margin: 4px 0; color: #9ca3af;"><strong>Timestamp:</strong> {now_str}</p>
    </div>
  </div>
</body>
</html>"""

        return self._send_smtp_message(
            recipient_email=clean_recipient,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
        )


class DevelopmentEmailProvider(EmailProvider):
    """
    In-memory simulation email provider for test suites and local offline development.
    """
    sent_emails: List[Dict[str, Any]] = []

    @classmethod
    def reset(cls) -> None:
        cls.sent_emails = []

    @classmethod
    def clear_history(cls) -> None:
        cls.sent_emails = []

    @classmethod
    def get_last_email(cls, recipient: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not recipient:
            return cls.sent_emails[-1] if cls.sent_emails else None
        clean_r = recipient.strip().lower()
        for m in reversed(cls.sent_emails):
            if m.get("recipient", "").strip().lower() == clean_r:
                return m
        return None

    @classmethod
    def get_last_email_otp(cls, recipient: Optional[str] = None) -> Optional[str]:
        email_data = cls.get_last_email(recipient)
        return email_data.get("otp_code") if email_data else None

    @classmethod
    def get_last_otp(cls, recipient: Optional[str] = None) -> Optional[str]:
        return cls.get_last_email_otp(recipient)

    @classmethod
    def get_last_token(cls, recipient: Optional[str] = None) -> Optional[str]:
        email_data = cls.get_last_email(recipient)
        if not email_data:
            return None
        if email_data.get("token"):
            return email_data.get("token")
        reset_url = email_data.get("reset_url") or ""
        if "token=" in reset_url:
            return reset_url.split("token=")[1].split("&")[0]
        verif_url = email_data.get("verification_url") or ""
        if "token=" in verif_url:
            return verif_url.split("token=")[1].split("&")[0]
        return None

    @classmethod
    def get_last_reset_url(cls, recipient: Optional[str] = None) -> Optional[str]:
        email_data = cls.get_last_email(recipient)
        return email_data.get("reset_url") if email_data else None

    @classmethod
    def get_sent_emails(cls, recipient: Optional[str] = None) -> List[Dict[str, Any]]:
        if not recipient:
            return list(cls.sent_emails)
        clean_r = recipient.strip().lower()
        return [m for m in cls.sent_emails if m.get("recipient", "").strip().lower() == clean_r]

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        entry = {
            "type": "PASSWORD_RESET",
            "recipient": recipient_email.strip().lower(),
            "recipient_name": recipient_name,
            "reset_url": reset_url,
            "expires_at": expires_at,
            "timestamp": datetime.now(timezone.utc),
        }
        DevelopmentEmailProvider.sent_emails.append(entry)
        if current_app:
            current_app.logger.info(
                "[DEV EMAIL] Password reset email recorded for '%s'",
                recipient_email,
            )
        return True, None

    def send_email_verification_otp(
        self,
        recipient_email: str,
        otp_code: str,
        recipient_name: Optional[str] = None,
        verification_url: Optional[str] = None,
        expires_in_minutes: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        entry = {
            "type": "EMAIL_VERIFICATION_OTP",
            "recipient": recipient_email.strip().lower(),
            "recipient_name": recipient_name,
            "otp_code": otp_code,
            "verification_url": verification_url,
            "expires_in_minutes": expires_in_minutes,
            "timestamp": datetime.now(timezone.utc),
        }
        DevelopmentEmailProvider.sent_emails.append(entry)
        if current_app:
            current_app.logger.info(
                "[DEV EMAIL] Verification OTP recorded for '%s'",
                recipient_email,
            )
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
        entry = {
            "type": "TRANSACTION_OTP",
            "recipient": recipient_email.strip().lower(),
            "recipient_name": recipient_name,
            "otp_code": otp_code,
            "transaction_id": transaction_id,
            "amount": amount,
            "expires_in_minutes": expires_in_minutes,
            "timestamp": datetime.now(timezone.utc),
        }
        DevelopmentEmailProvider.sent_emails.append(entry)
        if current_app:
            current_app.logger.info(
                "[DEV EMAIL] Transaction OTP recorded for Tx #%d to '%s'",
                transaction_id,
                recipient_email,
            )
        return True, None

    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        entry = {
            "type": "test_email",
            "recipient": recipient_email.strip().lower(),
            "message": test_message,
            "timestamp": datetime.now(timezone.utc),
        }
        DevelopmentEmailProvider.sent_emails.append(entry)
        return True, None


class NullEmailProvider(EmailProvider):
    """
    Fallback provider when no email service is configured. Returns honest failure.
    """

    def send_password_reset_email(
        self,
        recipient_email: str,
        reset_url: str,
        expires_at: Optional[datetime] = None,
        recipient_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure BREVO_API_KEY, RESEND_API_KEY, or SMTP credentials."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send password reset with no provider configured.")
        return False, msg

    def send_email_verification_otp(
        self,
        recipient_email: str,
        otp_code: str,
        recipient_name: Optional[str] = None,
        verification_url: Optional[str] = None,
        expires_in_minutes: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure BREVO_API_KEY, RESEND_API_KEY, or SMTP credentials."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send verification OTP with no provider configured.")
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
        msg = "Email delivery is not configured. Please configure BREVO_API_KEY, RESEND_API_KEY, or SMTP credentials."
        if current_app:
            current_app.logger.warning("[NullEmailProvider] Attempted to send transaction OTP with no provider configured.")
        return False, msg

    def send_test_email(
        self,
        recipient_email: str,
        test_message: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        msg = "Email delivery is not configured. Please configure BREVO_API_KEY, RESEND_API_KEY, or SMTP credentials."
        return False, msg


def get_email_provider() -> EmailProvider:
    """
    Factory resolving active EmailProvider based on runtime configuration.
    
    Order of resolution:
    1. Explicit EMAIL_PROVIDER / MAIL_PROVIDER configuration ('brevo', 'resend', 'smtp', 'development', 'null').
    2. If app is TESTING or DEBUG (and no explicit provider requested), use DevelopmentEmailProvider.
    3. If BREVO_API_KEY or MAIL_API_KEY is present in env/config and non-empty, use BrevoEmailProvider.
    4. If RESEND_API_KEY is present in env/config and non-empty, use ResendEmailProvider.
    5. If MAIL_SERVER / SMTP_HOST / SMTP_SERVER is defined and non-empty, use SmtpEmailProvider.
    6. If FLASK_ENV is development or testing, use DevelopmentEmailProvider.
    7. Otherwise, use NullEmailProvider (honest failure without simulated success).
    """
    # 1. Check Flask app config override
    try:
        if current_app:
            email_p = current_app.config.get("EMAIL_PROVIDER")
            mail_p = current_app.config.get("MAIL_PROVIDER")

            chosen = None
            # Check for explicit non-development overrides first
            for cand in (email_p, mail_p):
                if cand:
                    c = str(cand).lower().strip()
                    if c in ("brevo", "resend", "smtp", "null"):
                        chosen = c
                        break
                    elif c == "development" and chosen is None:
                        chosen = "development"

            if chosen == "brevo":
                return BrevoEmailProvider()
            elif chosen == "resend":
                return ResendEmailProvider()
            elif chosen == "smtp":
                return SmtpEmailProvider()
            elif chosen == "null":
                return NullEmailProvider()
            elif chosen == "development":
                return DevelopmentEmailProvider()

            # If in automated testing without explicit override, use DevelopmentEmailProvider
            if current_app.config.get("TESTING"):
                return DevelopmentEmailProvider()

            # If BREVO_API_KEY or MAIL_API_KEY is configured in app config, prefer BrevoEmailProvider
            brevo_key = current_app.config.get("BREVO_API_KEY") or current_app.config.get("MAIL_API_KEY")
            if brevo_key and str(brevo_key).strip():
                return BrevoEmailProvider()

            # If RESEND_API_KEY is configured in app config, prefer ResendEmailProvider
            resend_key = current_app.config.get("RESEND_API_KEY")
            if resend_key and str(resend_key).strip():
                return ResendEmailProvider()

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
        os.environ.get("EMAIL_PROVIDER", "")
        or os.environ.get("MAIL_PROVIDER", "")
    ).lower().strip()

    if env_provider == "brevo":
        return BrevoEmailProvider()
    if env_provider == "resend":
        return ResendEmailProvider()
    if env_provider == "smtp":
        return SmtpEmailProvider()
    if env_provider == "null":
        return NullEmailProvider()
    if env_provider == "development":
        if os.environ.get("BREVO_API_KEY") or os.environ.get("MAIL_API_KEY"):
            return BrevoEmailProvider()
        if os.environ.get("RESEND_API_KEY"):
            return ResendEmailProvider()
        env_host = os.environ.get("MAIL_SERVER") or os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER")
        if env_host and str(env_host).strip():
            return SmtpEmailProvider()
        return DevelopmentEmailProvider()

    # 3. Auto-detect based on available credentials
    if os.environ.get("BREVO_API_KEY") and str(os.environ.get("BREVO_API_KEY")).strip():
        return BrevoEmailProvider()
    if os.environ.get("MAIL_API_KEY") and str(os.environ.get("MAIL_API_KEY")).strip():
        return BrevoEmailProvider()
    if os.environ.get("RESEND_API_KEY") and str(os.environ.get("RESEND_API_KEY")).strip():
        return ResendEmailProvider()

    env_host = os.environ.get("MAIL_SERVER") or os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER")
    if env_host and str(env_host).strip():
        return SmtpEmailProvider()

    if os.environ.get("FLASK_ENV") in ("testing", "development") or os.environ.get("ENV") == "testing":
        return DevelopmentEmailProvider()

    return NullEmailProvider()
