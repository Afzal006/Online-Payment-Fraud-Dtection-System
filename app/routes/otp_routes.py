"""
One-Time Password (OTP) Adaptive Verification Endpoints.

Routes:
- POST /api/otp/generate : Issues a dynamic OTP challenge for challenged transactions.
- POST /api/otp/verify   : Verifies submitted OTP code and updates transaction state.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.otp_service import OTPService

otp_bp = Blueprint("otp", __name__, url_prefix="/api/otp")


@otp_bp.route("/generate", methods=["POST"])
@jwt_required()
def generate_otp():
    """Generate a multi-factor OTP challenge for a pending or review transaction."""
    data = request.get_json(silent=True)
    if not data or "transaction_id" not in data:
        return jsonify({"error": "Field 'transaction_id' is required", "code": "VALIDATION_ERROR"}), 400

    try:
        transaction_id = int(data["transaction_id"])
    except (ValueError, TypeError):
        return jsonify({"error": "Field 'transaction_id' must be an integer", "code": "VALIDATION_ERROR"}), 400

    user_id = int(get_jwt_identity())
    challenge, debug_otp, error = OTPService.create_challenge(transaction_id=transaction_id, user_id=user_id)

    if error:
        status_code = 403 if "Forbidden" in error else 400
        return jsonify({"error": error, "code": "CHALLENGE_GENERATION_FAILED"}), status_code

    response_payload = {
        "success": True,
        "message": "OTP verification code sent via simulated secure delivery channel",
        "transaction_id": transaction_id,
        "expires_in_seconds": current_app.config.get("OTP_EXPIRY_SECONDS", 180),
    }

    # In development / testing environments, include debug payload for verification testing
    if current_app.config.get("FLASK_ENV") == "development" or current_app.config.get("TESTING"):
        response_payload["_dev_simulated_otp"] = debug_otp

    return jsonify(response_payload), 200


@otp_bp.route("/verify", methods=["POST"])
@jwt_required()
def verify_otp():
    """Verify an OTP code submitted by the user."""
    data = request.get_json(silent=True)
    if not data or "transaction_id" not in data or "otp_code" not in data:
        return jsonify({"error": "Fields 'transaction_id' and 'otp_code' are required", "code": "VALIDATION_ERROR"}), 400

    try:
        transaction_id = int(data["transaction_id"])
    except (ValueError, TypeError):
        return jsonify({"error": "Field 'transaction_id' must be an integer", "code": "VALIDATION_ERROR"}), 400

    otp_code = str(data["otp_code"]).strip()
    if not otp_code:
        return jsonify({"error": "Field 'otp_code' cannot be empty", "code": "VALIDATION_ERROR"}), 400

    user_id = int(get_jwt_identity())
    success, message, status_code, updated_tx = OTPService.verify_challenge(
        transaction_id=transaction_id,
        user_id=user_id,
        candidate_otp=otp_code,
    )

    if not success:
        return jsonify({"success": False, "error": message, "code": "OTP_VERIFICATION_FAILED"}), status_code

    return jsonify({
        "success": True,
        "message": message,
        "transaction": updated_tx,
    }), status_code
