"""
SMS Provider Abstraction Layer for FraudShield AI.

Provides modular interfaces and concrete implementations for real SMS gateways
(Twilio, MSG91) as well as isolated development/testing providers.
"""

import os
import re
import logging
from abc import ABC, abstractmethod
from typing import Tuple, Optional, Dict, Any
from flask import current_app

logger = logging.getLogger(__name__)


class SmsProvider(ABC):
    """Abstract interface defining required SMS dispatch capabilities."""

    @abstractmethod
    def send_otp(self, phone_number: str, otp_code: str, purpose: str = "REGISTRATION") -> Tuple[bool, Optional[str]]:
        """
        Dispatch a one-time verification code to the target phone number.

        Args:
            phone_number: Normalized E.164 phone number (e.g. +919876543210).
            otp_code: 6-digit numeric verification code.
            purpose: Context string ('REGISTRATION', 'PASSWORD_RESET', 'PIN_RESET', 'TRANSACTION_STEP_UP').

        Returns:
            (success: bool, error_message: Optional[str])
        """
        pass


class DevelopmentSmsProvider(SmsProvider):
    """
    Isolated development and test SMS provider.
    Logs OTP securely to development console and maintains in-memory inspection buffer for unit testing.
    """

    _sent_otps: Dict[str, str] = {}

    def send_otp(self, phone_number: str, otp_code: str, purpose: str = "REGISTRATION") -> Tuple[bool, Optional[str]]:
        clean_phone = phone_number.strip()
        DevelopmentSmsProvider._sent_otps[clean_phone] = otp_code
        logger.info(
            "[DEVELOPMENT SMS GATEWAY] Sent OTP '%s' to '%s' (Purpose: %s)",
            otp_code, clean_phone, purpose
        )
        return True, None

    @classmethod
    def get_last_otp(cls, phone_number: str) -> Optional[str]:
        """Retrieve last sent OTP for test verification."""
        return cls._sent_otps.get(phone_number.strip())

    @classmethod
    def clear_history(cls) -> None:
        """Clear in-memory buffer."""
        cls._sent_otps.clear()


class TwilioSmsProvider(SmsProvider):
    """
    Production Twilio SMS Gateway.
    Configured via TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER.
    """

    def __init__(self, account_sid: Optional[str] = None, auth_token: Optional[str] = None, from_number: Optional[str] = None):
        self.account_sid = account_sid or os.getenv("TWILIO_ACCOUNT_SID")
        self.auth_token = auth_token or os.getenv("TWILIO_AUTH_TOKEN")
        self.from_number = from_number or os.getenv("TWILIO_FROM_NUMBER")

    def send_otp(self, phone_number: str, otp_code: str, purpose: str = "REGISTRATION") -> Tuple[bool, Optional[str]]:
        if not self.account_sid or not self.auth_token or not self.from_number:
            logger.error("Twilio SMS credentials incomplete in environment configuration.")
            return False, "SMS gateway credentials unconfigured in production environment."

        try:
            import urllib.request
            import urllib.parse
            import base64

            url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
            message_body = f"Your FraudShield AI verification code is {otp_code}. Valid for 5 minutes. Do not share this code."
            payload = {
                "To": phone_number,
                "From": self.from_number,
                "Body": message_body,
            }
            data = urllib.parse.urlencode(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")

            auth_str = f"{self.account_sid}:{self.auth_token}"
            auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            req.add_header("Authorization", f"Basic {auth_b64}")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    logger.info("SMS successfully dispatched via Twilio to %s", phone_number)
                    return True, None
                return False, f"Twilio SMS delivery failed with HTTP status {resp.status}."
        except Exception as e:
            logger.error("Twilio SMS dispatch exception: %s", str(e))
            return False, f"Failed to deliver SMS: {str(e)}"


class Msg91SmsProvider(SmsProvider):
    """
    Production MSG91 SMS Gateway (optimized for Indian telecommunications).
    Configured via MSG91_AUTH_KEY, MSG91_TEMPLATE_ID, and MSG91_SENDER_ID.
    """

    def __init__(self, auth_key: Optional[str] = None, template_id: Optional[str] = None, sender_id: Optional[str] = None):
        self.auth_key = auth_key or os.getenv("MSG91_AUTH_KEY")
        self.template_id = template_id or os.getenv("MSG91_TEMPLATE_ID")
        self.sender_id = sender_id or os.getenv("MSG91_SENDER_ID", "FRDSHD")

    def send_otp(self, phone_number: str, otp_code: str, purpose: str = "REGISTRATION") -> Tuple[bool, Optional[str]]:
        if not self.auth_key or not self.template_id:
            logger.error("MSG91 SMS credentials incomplete in environment configuration.")
            return False, "SMS gateway credentials unconfigured in production environment."

        try:
            import urllib.request
            import json

            # MSG91 expects phone without leading '+'
            clean_phone = phone_number.replace("+", "").strip()
            url = "https://api.msg91.com/api/v5/otp"
            headers = {
                "authkey": self.auth_key,
                "content-type": "application/json",
            }
            body = {
                "template_id": self.template_id,
                "mobile": clean_phone,
                "otp": otp_code,
                "sender": self.sender_id,
            }
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    return True, None
                return False, f"MSG91 delivery returned status {resp.status}."
        except Exception as e:
            logger.error("MSG91 SMS dispatch exception: %s", str(e))
            return False, f"Failed to deliver SMS via MSG91: {str(e)}"


class NullSmsProvider(SmsProvider):
    """
    Production fallback when no real SMS gateway is configured.
    Fails honestly and transparently rather than fabricating a fake delivery.
    """

    def send_otp(self, phone_number: str, otp_code: str, purpose: str = "REGISTRATION") -> Tuple[bool, Optional[str]]:
        logger.error("Attempted to send SMS in production without an active SMS gateway configured.")
        return False, "SMS verification service is currently unavailable. No SMS provider configured."


def get_sms_provider() -> SmsProvider:
    """
    Factory function returning the configured SMS provider instance based on application settings.
    """
    provider_type = None
    try:
        if current_app:
            provider_type = current_app.config.get("SMS_PROVIDER")
    except RuntimeError:
        pass

    if not provider_type:
        provider_type = os.getenv("SMS_PROVIDER", "development").lower()

    if provider_type == "twilio":
        return TwilioSmsProvider()
    elif provider_type == "msg91":
        return Msg91SmsProvider()
    elif provider_type in ["development", "dev", "test", "testing"]:
        return DevelopmentSmsProvider()
    elif provider_type in ["null", "none"]:
        return NullSmsProvider()

    # In production without explicit provider, use NullSmsProvider to fail truthfully
    env = os.getenv("FLASK_ENV", "development").lower()
    if env == "production":
        return NullSmsProvider()

    return DevelopmentSmsProvider()
