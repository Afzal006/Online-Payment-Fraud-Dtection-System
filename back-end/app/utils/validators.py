"""
Input Validation Utilities for API Requests.
"""

import re
import socket
from typing import Dict, Any, Tuple, Optional
from flask import current_app

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
INDIAN_PHONE_REGEX = re.compile(r"^[6-9]\d{9}$")
OTP_REGEX = re.compile(r"^\d{6}$")

# Non-routable and RFC reserved test/invalid top-level domains and domains
RESERVED_INVALID_DOMAINS = {
    "example.invalid",
    "invalid",
    "localhost",
    "test",
    "local",
}
RESERVED_INVALID_TLDS = {
    "invalid",
    "test",
    "local",
    "localhost",
}


def validate_email_syntax_and_domain(
    email_str: Optional[str],
    check_dns: bool = True,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate email address syntax, domain structure, and DNS resolvability.

    Layers:
    1. Syntax & RFC compliance checks (length, valid characters, consecutive dots).
    2. Domain formatting & TLD length.
    3. Rejection of reserved and non-routable top-level domains.
    4. Optional DNS / MX / A record resolution using socket lookup with strict timeout.

    Returns:
        (is_valid: bool, normalized_email: Optional[str], error_message: Optional[str])
    """
    if not email_str or not isinstance(email_str, str) or not email_str.strip():
        return False, None, "Email address is required."

    clean_email = email_str.strip().lower()

    if len(clean_email) > 254 or len(clean_email) < 5:
        return False, None, "Email address length is invalid (must be between 5 and 254 characters)."

    if not EMAIL_REGEX.match(clean_email):
        return False, None, "Invalid email format. Please provide a standard address (e.g. user@domain.com)."

    parts = clean_email.split("@")
    if len(parts) != 2:
        return False, None, "Invalid email address structure."

    local_part, domain = parts[0], parts[1]

    if len(local_part) > 64 or local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        return False, None, "Invalid email local part."

    if domain.startswith("-") or domain.endswith("-") or domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return False, None, "Invalid email domain structure."

    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        return False, None, "Email domain must include a top-level domain extension (e.g. .com, .org, .in)."

    tld = domain_parts[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False, None, "Invalid top-level domain extension in email address."

    if domain in RESERVED_INVALID_DOMAINS or tld in RESERVED_INVALID_TLDS:
        return False, None, f"Domain '@{domain}' is a reserved or non-routable domain and cannot receive email."

    # DNS Domain Resolvability Check
    skip_dns = False
    if current_app:
        skip_dns = current_app.config.get("DISABLE_EMAIL_DNS_CHECK", False)

    if check_dns and not skip_dns:
        try:
            # Set default timeout for domain lookup to avoid hanging
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2.0)
            try:
                # Attempt socket resolution for domain
                socket.gethostbyname(domain)
            finally:
                socket.setdefaulttimeout(original_timeout)
        except (socket.gaierror, socket.herror):
            return False, None, f"Domain '@{domain}' does not exist or has no valid DNS records."
        except socket.timeout:
            # If DNS server timed out, do not hard-block if domain has standard valid structure
            if current_app:
                current_app.logger.warning("DNS lookup timed out for domain '%s'; allowing fallback.", domain)
        except Exception as e:
            if current_app:
                current_app.logger.warning("DNS resolution exception for domain '%s': %s", domain, str(e))

    return True, clean_email, None


def validate_phone_number(phone_str: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate and normalize Indian mobile phone number.

    Rules:
    - Strips spaces, dashes, parentheses.
    - Matches 10-digit Indian numbers starting with 6, 7, 8, or 9.
    - Handles +91, 91, or 0 prefixes cleanly.

    Returns:
        (is_valid: bool, normalized_phone: Optional[str], error_message: Optional[str])
    """
    if not phone_str or not isinstance(phone_str, str) or not phone_str.strip():
        return False, None, "Phone number is required."

    raw = phone_str.strip()
    digits = re.sub(r"\D", "", raw)

    if len(digits) == 10:
        if not INDIAN_PHONE_REGEX.match(digits):
            return False, None, "Invalid mobile number. Indian mobile numbers must start with 6, 7, 8, or 9."
        return True, digits, None
    elif len(digits) == 12 and digits.startswith("91"):
        sub_digits = digits[2:]
        if not INDIAN_PHONE_REGEX.match(sub_digits):
            return False, None, "Invalid mobile number. Indian mobile numbers must start with 6, 7, 8, or 9."
        return True, sub_digits, None
    elif len(digits) == 11 and digits.startswith("0"):
        sub_digits = digits[1:]
        if not INDIAN_PHONE_REGEX.match(sub_digits):
            return False, None, "Invalid mobile number. Indian mobile numbers must start with 6, 7, 8, or 9."
        return True, sub_digits, None
    else:
        return False, None, "Mobile number must be a valid 10-digit Indian number (e.g. 9876543210 or +91 98765 43210)."


def validate_registration_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate user registration payload.

    Requirements:
    - name: string, 2-100 characters
    - email: valid email syntax and domain
    - password: minimum 8 characters
    - phone_number: valid Indian mobile
    - role: 'USER' or 'ADMIN' (optional, defaults to 'USER')
    """
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    name = data.get("name")
    if not name or not isinstance(name, str) or len(name.strip()) < 2 or len(name.strip()) > 100:
        return False, "Name must be between 2 and 100 characters"

    email = data.get("email")
    is_valid_email, _, email_err = validate_email_syntax_and_domain(email)
    if not is_valid_email:
        return False, email_err

    password = data.get("password")
    if not password or not isinstance(password, str) or len(password) < 8:
        return False, "Password must be at least 8 characters long"

    phone = data.get("phone_number") or data.get("phone") or data.get("mobile")
    if phone:
        is_valid_phone, _, phone_err = validate_phone_number(str(phone))
        if not is_valid_phone:
            return False, phone_err

    role = data.get("role", "USER")
    if role not in ["USER", "ADMIN"]:
        return False, "Role must be either 'USER' or 'ADMIN'"

    return True, None


def validate_email_otp_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Validate email verification OTP submission payload."""
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    email = data.get("email")
    if not email or not isinstance(email, str) or not email.strip():
        return False, "Email address is required"

    otp_code = data.get("otp_code") or data.get("otp") or data.get("code")
    if not otp_code or not isinstance(otp_code, str) or not OTP_REGEX.match(str(otp_code).strip()):
        return False, "Verification OTP code must be exactly 6 numeric digits"

    return True, None


def validate_phone_otp_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Validate phone verification OTP submission payload."""
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    phone = data.get("phone_number") or data.get("phone") or data.get("email")
    if not phone or not isinstance(phone, str) or not phone.strip():
        return False, "Phone number or email identifier is required"

    otp_code = data.get("otp_code") or data.get("otp") or data.get("code")
    if not otp_code or not isinstance(otp_code, str) or not OTP_REGEX.match(str(otp_code).strip()):
        return False, "OTP verification code must be exactly 6 numeric digits"

    return True, None


def validate_resend_otp_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Validate phone/email verification OTP resend request payload."""
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    identifier = data.get("phone_number") or data.get("phone") or data.get("email") or data.get("identifier")
    if not identifier or not isinstance(identifier, str) or not identifier.strip():
        return False, "Phone number or email identifier is required"

    return True, None


def validate_login_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Validate user login payload."""
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    email = data.get("email")
    if not email or not isinstance(email, str) or not email.strip():
        return False, "Email is required"

    password = data.get("password")
    if not password or not isinstance(password, str) or not password:
        return False, "Password is required"

    return True, None


UPI_REGEX = re.compile(r"^[a-zA-Z0-9.\-_]{2,50}@[a-zA-Z0-9.\-_]{2,30}$")


def validate_upi_id(upi_id: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate UPI ID structure.

    Rules:
    - Non-empty string
    - Contains exactly one '@'
    - Username portion: 2-50 alphanumeric, dot, dash, underscore
    - Provider handle: 2-30 alphanumeric, dot, dash, underscore
    - Total length: between 5 and 80 characters
    - No dangerous characters or spaces
    """
    if not upi_id or not isinstance(upi_id, str):
        return False, "UPI ID is required"

    clean_upi = upi_id.strip().lower()
    if len(clean_upi) < 5 or len(clean_upi) > 80:
        return False, "UPI ID length must be between 5 and 80 characters"

    if "@" not in clean_upi or clean_upi.count("@") != 1:
        return False, "UPI ID must contain exactly one '@' delimiter (e.g. username@fraudshield)"

    if not UPI_REGEX.match(clean_upi):
        return False, "Invalid UPI ID format. Must contain valid username and handle (e.g. rahul@fraudshield)"

    return True, None


def validate_beneficiary_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate new or updated beneficiary payload.

    Requirements:
    - beneficiary_name: 2-100 characters
    - beneficiary_upi_id: valid UPI format
    - nickname: optional, max 50 characters
    - beneficiary_phone: optional, max 20 characters
    """
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    name = data.get("beneficiary_name")
    if not name or not isinstance(name, str) or len(name.strip()) < 2 or len(name.strip()) > 100:
        return False, "Beneficiary name is required and must be between 2 and 100 characters"

    upi_id = data.get("beneficiary_upi_id")
    is_valid_upi, upi_err = validate_upi_id(upi_id)
    if not is_valid_upi:
        return False, upi_err

    phone = data.get("beneficiary_phone")
    if phone is not None and isinstance(phone, str) and len(phone.strip()) > 20:
        return False, "Beneficiary phone number must not exceed 20 characters"

    nickname = data.get("nickname")
    if nickname is not None and isinstance(nickname, str) and len(nickname.strip()) > 50:
        return False, "Nickname must not exceed 50 characters"

    return True, None


def validate_forgot_password_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate forgot password request payload.

    Requirements:
    - email: non-empty string matching valid email regex
    """
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    email = data.get("email")
    if not email or not isinstance(email, str) or not EMAIL_REGEX.match(email.strip()):
        return False, "A valid email address is required"

    return True, None


def validate_reset_password_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate reset password request payload.

    Requirements:
    - token: non-empty string
    - new_password: at least 8 characters
    - confirm_password: must match new_password
    """
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    token = data.get("token")
    if not token or not isinstance(token, str) or not token.strip():
        return False, "Reset token is required"

    new_password = data.get("new_password")
    if not new_password or not isinstance(new_password, str) or len(new_password) < 8:
        return False, "Password must be at least 8 characters long"

    confirm_password = data.get("confirm_password")
    if confirm_password is None or new_password != confirm_password:
        return False, "Passwords do not match"

    return True, None


