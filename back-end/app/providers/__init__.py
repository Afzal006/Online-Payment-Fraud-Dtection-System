"""
External service provider abstractions for FraudShield AI.
"""

from app.providers.sms_provider import (
    SmsProvider,
    DevelopmentSmsProvider,
    TwilioSmsProvider,
    Msg91SmsProvider,
    NullSmsProvider,
    get_sms_provider,
)
from app.providers.email_provider import (
    EmailProvider,
    DevelopmentEmailProvider,
    SmtpEmailProvider,
    NullEmailProvider,
    get_email_provider,
)

__all__ = [
    "SmsProvider",
    "DevelopmentSmsProvider",
    "TwilioSmsProvider",
    "Msg91SmsProvider",
    "NullSmsProvider",
    "get_sms_provider",
    "EmailProvider",
    "DevelopmentEmailProvider",
    "SmtpEmailProvider",
    "NullEmailProvider",
    "get_email_provider",
]
