"""
Authentication API Endpoints.

Routes:
- POST /api/auth/register : Register a new user
- POST /api/auth/login    : Authenticate and obtain JWT
- GET  /api/auth/me       : Retrieve authenticated user profile
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.auth_service import AuthService
from app.utils.validators import (
    validate_registration_input,
    validate_login_input,
    validate_forgot_password_input,
    validate_reset_password_input,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account."""
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_registration_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    user, error = AuthService.register_user(
        name=data["name"],
        email=data["email"],
        password=data["password"],
        role=data.get("role", "USER"),
    )

    if error:
        return jsonify({"error": error}), 409

    return jsonify({
        "message": "User registered successfully",
        "user": user.to_dict(),
    }), 201


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
    """
    data = request.get_json(silent=True)
    is_valid, error_msg = validate_forgot_password_input(data)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    success, dev_token, error = AuthService.request_password_reset(
        email=data["email"],
        remote_ip=request.remote_addr,
    )

    if error:
        return jsonify({"error": error}), 429

    response_payload = {
        "message": "If an account exists for this email, a password reset code has been sent."
    }
    if dev_token is not None:
        response_payload["dev_reset_token"] = dev_token

    return jsonify(response_payload), 200


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

    password = data.get("password", "")
    pin = data.get("pin", "")
    confirm_pin = data.get("confirm_pin", data.get("confirmPin", ""))

    success, error = PaymentService.set_user_pin(
        user_id=user_id,
        current_password=password,
        new_pin=pin,
        confirm_pin=confirm_pin,
    )

    if not success:
        return jsonify({"error": error}), 400

    return jsonify({
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


