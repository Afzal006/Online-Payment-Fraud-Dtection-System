"""
Authentication API Endpoints.

Routes:
- POST /api/auth/register : Register a new user
- POST /api/auth/login    : Authenticate and obtain JWT
- GET  /api/auth/me       : Retrieve authenticated user profile
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.auth_service import AuthService
from app.utils.validators import (
    validate_registration_input,
    validate_login_input,
    validate_forgot_password_input,
    validate_reset_password_input,
    validate_phone_otp_input,
    validate_resend_otp_input,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account with phone OTP challenge."""
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_registration_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    phone = data.get("phone_number") or data.get("phone") or data.get("mobile")

    user, error = AuthService.register_user(
        name=data["name"],
        email=data["email"],
        password=data["password"],
        phone_number=phone,
        role=data.get("role", "USER"),
    )

    if error:
        return jsonify({"error": error}), 409

    requires_verification = bool(user.phone_number and not user.is_phone_verified)
    msg = (
        "User registered successfully. A 6-digit verification code has been sent to your mobile number."
        if requires_verification
        else "User registered successfully"
    )

    response_data = {
        "message": msg,
        "user": user.to_dict(),
        "requires_phone_verification": requires_verification,
    }

    return jsonify(response_data), 201


@auth_bp.route("/verify-phone-otp", methods=["POST"])
def verify_phone_otp():
    """Verify phone verification OTP code and activate account."""
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_phone_otp_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    identifier = data.get("phone_number") or data.get("phone") or data.get("email")
    otp_code = data.get("otp_code") or data.get("otp") or data.get("code")

    success, user, error = AuthService.verify_phone_otp(
        phone_or_email=identifier,
        otp_code=otp_code,
    )

    if not success:
        return jsonify({"error": error}), 400

    return jsonify({
        "message": "Mobile number verified successfully. You may now sign in to your account.",
        "user": user.to_dict() if user else None,
        "is_phone_verified": True,
    }), 200


@auth_bp.route("/resend-phone-otp", methods=["POST"])
def resend_phone_otp():
    """Request resend of phone verification OTP code."""
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_resend_otp_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    identifier = data.get("phone_number") or data.get("phone") or data.get("email")
    success, dev_otp, error = AuthService.resend_phone_otp(phone_or_email=identifier)

    if error:
        status_code = 429 if "wait" in error.lower() else 400
        return jsonify({"error": error}), status_code

    resp = {
        "message": "If an account exists, a new 6-digit verification code has been dispatched."
    }
    if dev_otp:
        resp["dev_otp"] = dev_otp

    return jsonify(resp), 200


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate credentials and issue JWT."""
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_login_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    token, user, error = AuthService.authenticate_user(
        email=data["email"],
        password=data["password"],
    )

    if error:
        return jsonify({"error": error}), 401

    redirect_url = "/admin/dashboard" if user.role == "ADMIN" else "/dashboard"

    return jsonify({
        "message": "Login successful",
        "access_token": token,
        "token_type": "Bearer",
        "user": user.to_dict(),
        "redirect_url": redirect_url,
    }), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    """Retrieve current authenticated user profile."""
    user_id = get_jwt_identity()
    user = AuthService.get_user_by_id(int(user_id))

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user": user.to_dict(),
    }), 200


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    """
    Request password reset instructions.
    
    Anti-Enumeration:
    Returns identical 200 OK generic response regardless of whether account exists.
    Never exposes raw reset token in API response.
    """
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_forgot_password_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    success, error = AuthService.request_password_reset(
        email=data["email"],
        remote_ip=request.remote_addr,
    )

    if error:
        return jsonify({"error": error}), 429

    return jsonify({
        "message": "If an account exists for this email, a password reset link has been sent."
    }), 200


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """
    Verify reset token and update account password.
    """
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_reset_password_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    success, error = AuthService.reset_password_with_token(
        token=data["token"],
        new_password=data["new_password"],
    )

    if not success:
        status_code = 429 if "locked" in (error or "").lower() or "too many" in (error or "").lower() else 400
        return jsonify({"error": error}), status_code

    return jsonify({
        "message": "Password has been reset successfully. You may now sign in with your new password."
    }), 200


@auth_bp.route("/payment-pin/set", methods=["POST"])
@jwt_required()
def set_payment_pin():
    """
    Set or update 4-6 digit numeric payment PIN (requires account password authorization).
    """
    from app.services.payment_service import PaymentService
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    password = data.get("password") or data.get("current_password") or ""
    pin = data.get("pin") or data.get("new_pin") or data.get("payment_pin") or ""
    confirm_pin = data.get("confirm_pin") or data.get("confirmPin") or data.get("confirm_payment_pin") or ""

    success, error = PaymentService.set_user_pin(
        user_id=user_id,
        current_password=password,
        new_pin=pin,
        confirm_pin=confirm_pin,
    )

    if not success:
        return jsonify({"error": error}), 400

    return jsonify({
        "success": True,
        "message": "Payment PIN set successfully. You can now use your PIN to authenticate UPI payments.",
        "is_pin_set": True,
    }), 200


@auth_bp.route("/payment-pin/status", methods=["GET"])
@jwt_required()
def get_payment_pin_status():
    """
    Get user payment PIN configuration status and lockout state.
    """
    from app.extensions import db
    from app.models.user import User
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "is_pin_set": bool(user.is_pin_set),
        "is_pin_locked": user.is_pin_locked,
        "pin_failed_attempts": user.pin_failed_attempts,
    }), 200


@auth_bp.route("/payment-pin/forgot/request-otp", methods=["POST"])
@jwt_required()
def request_payment_pin_reset_otp():
    """
    Request SMS verification OTP to initiate Payment PIN recovery.
    """
    from app.services.payment_service import PaymentService
    user_id = int(get_jwt_identity())

    success, dev_otp, error = PaymentService.request_pin_reset_otp(user_id=user_id)
    if not success:
        status_code = 429 if "Too many" in (error or "") or "wait" in (error or "").lower() else 400
        return jsonify({"error": error}), status_code

    resp = {
        "success": True,
        "message": "Verification OTP sent to your registered mobile number for Payment PIN recovery.",
    }
    if dev_otp:
        resp["dev_simulated_otp"] = dev_otp

    return jsonify(resp), 200


@auth_bp.route("/payment-pin/forgot/verify-and-reset", methods=["POST"])
@jwt_required()
def verify_and_reset_payment_pin():
    """
    Verify SMS OTP + account password, then set new Payment PIN.
    """
    from app.services.payment_service import PaymentService
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    otp_code = data.get("otp_code") or data.get("otp") or ""
    password = data.get("password") or data.get("account_password") or ""
    new_pin = data.get("new_pin") or data.get("pin") or data.get("payment_pin") or ""
    confirm_pin = data.get("confirm_pin") or data.get("confirmPin") or data.get("confirm_payment_pin") or ""

    success, error = PaymentService.verify_and_reset_pin(
        user_id=user_id,
        otp_code=otp_code,
        password=password,
        new_pin=new_pin,
        confirm_pin=confirm_pin,
    )

    if not success:
        status_code = 400
        if "Incorrect account login password" in (error or ""):
            status_code = 401
        elif "Maximum" in (error or "") or "Too many" in (error or ""):
            status_code = 429
        return jsonify({"error": error}), status_code

    return jsonify({
        "success": True,
        "message": "Payment PIN reset successfully. You can now use your new PIN for payments.",
        "is_pin_set": True,
    }), 200


