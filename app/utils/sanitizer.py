"""
Sanitization and Redaction Utility.

Recursively scrubs sensitive parameters (passwords, hashes, OTPs, raw tokens, auth headers)
from logs, audit records, and telemetry to prevent credential and secret leakage.
"""

from typing import Any, Set

SENSITIVE_FIELD_NAMES: Set[str] = {
    "password",
    "new_password",
    "confirm_password",
    "current_password",
    "password_hash",
    "token",
    "raw_token",
    "token_hash",
    "otp",
    "otp_code",
    "otp_hash",
    "secret",
    "secret_key",
    "jwt",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "cvv",
    "card_number",
    "pin",
    "credit_card",
}


def sanitize_data(data: Any, max_depth: int = 5) -> Any:
    """
    Recursively sanitize dictionaries, lists, or primitive data types,
    replacing sensitive values with '[REDACTED]'.
    """
    if max_depth <= 0:
        return "[TRUNCATED]"

    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            key_str = str(key).lower().strip()
            if any(sensitive in key_str for sensitive in SENSITIVE_FIELD_NAMES):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, (dict, list)):
                sanitized[key] = sanitize_data(value, max_depth=max_depth - 1)
            else:
                sanitized[key] = value
        return sanitized

    if isinstance(data, (list, tuple, set)):
        return [sanitize_data(item, max_depth=max_depth - 1) for item in data]

    return data
