"""
Input Validation Utilities for API Requests.
"""

import re
from typing import Dict, Any, Tuple, Optional

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_registration_input(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """
    Validate user registration payload.

    Requirements:
    - name: string, 2-100 characters
    - email: valid email format
    - password: minimum 8 characters
    - role: 'USER' or 'ADMIN' (optional, defaults to 'USER')
    """
    if not data or not isinstance(data, dict):
        return False, "Request body must be a JSON object"

    name = data.get("name")
    if not name or not isinstance(name, str) or len(name.strip()) < 2 or len(name.strip()) > 100:
        return False, "Name must be between 2 and 100 characters"

    email = data.get("email")
    if not email or not isinstance(email, str) or not EMAIL_REGEX.match(email.strip()):
        return False, "A valid email address is required"

    password = data.get("password")
    if not password or not isinstance(password, str) or len(password) < 8:
        return False, "Password must be at least 8 characters long"

    role = data.get("role", "USER")
    if role not in ["USER", "ADMIN"]:
        return False, "Role must be either 'USER' or 'ADMIN'"

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


