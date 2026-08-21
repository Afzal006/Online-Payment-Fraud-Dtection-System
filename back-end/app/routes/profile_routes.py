"""
Customer Profile API Endpoints.

Routes:
- GET /api/profile : Retrieve authenticated user's payment identity profile
- PUT /api/profile : Update customer profile preferences / details
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.auth_service import AuthService
from app.extensions import db

profile_bp = Blueprint("profile", __name__, url_prefix="/api/profile")


@profile_bp.route("", methods=["GET"])
@jwt_required()
def get_profile():
    """Retrieve the authenticated user's payment identity profile."""
    user_id = int(get_jwt_identity())
    user = AuthService.get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "profile": user.to_dict(include_private=False),
    }), 200


@profile_bp.route("", methods=["PUT"])
@jwt_required()
def update_profile():
    """Update profile details (name, phone number) for authenticated user."""
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    name = data.get("name")
    phone_number = data.get("phone_number")

    if name is None and phone_number is None:
        return jsonify({"error": "No update fields provided."}), 400

    success, user, message_or_error, status_code, phone_verification_required = AuthService.update_user_profile(
        user_id=user_id,
        name=name,
        phone_number=phone_number,
    )

    if not success:
        return jsonify({"error": message_or_error}), status_code

    return jsonify({
        "success": True,
        "message": message_or_error,
        "phone_verification_required": phone_verification_required,
        "phone_number": user.phone_number,
        "profile": user.to_dict(include_private=False),
    }), status_code


@profile_bp.route("/phone/verify-otp", methods=["POST"])
@jwt_required()
def verify_profile_phone_otp():
    """Verify phone verification OTP code for the authenticated user."""
    user_id = int(get_jwt_identity())
    user = AuthService.get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User account not found."}), 404

    data = request.get_json(silent=True) or {}
    otp_code = data.get("otp_code") or data.get("otp") or data.get("code")

    if not otp_code or not str(otp_code).strip():
        return jsonify({"error": "Verification OTP code is required."}), 400

    success, user, error = AuthService.verify_phone_otp(
        phone_or_email=user.email,
        otp_code=str(otp_code).strip(),
    )

    if not success:
        return jsonify({"error": error or "Verification failed."}), 400

    return jsonify({
        "success": True,
        "message": "Mobile number verified successfully.",
        "is_phone_verified": True,
        "profile": user.to_dict(include_private=False),
    }), 200


@profile_bp.route("/phone/resend-otp", methods=["POST"])
@jwt_required()
def resend_profile_phone_otp():
    """Resend phone verification OTP for authenticated user's unverified phone number."""
    user_id = int(get_jwt_identity())
    user = AuthService.get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User account not found."}), 404

    if not user.phone_number:
        return jsonify({"error": "No phone number is configured on this profile."}), 400

    if user.is_phone_verified:
        return jsonify({"error": "Mobile number is already verified."}), 400

    success, dev_otp, error = AuthService.resend_phone_otp(phone_or_email=user.email)
    if error:
        status_code = 429 if "wait" in error.lower() else 400
        return jsonify({"error": error}), status_code

    resp = {
        "success": True,
        "message": f"A new 6-digit verification code has been dispatched to +91 {user.phone_number}."
    }
    return jsonify(resp), 200


@profile_bp.route("/devices", methods=["GET"])
@jwt_required()
def get_user_devices():
    """Retrieve all active registered devices for the authenticated user."""
    from app.services.device_trust_service import DeviceTrustService

    user_id = int(get_jwt_identity())
    devices = DeviceTrustService.get_user_devices(user_id)

    return jsonify({
        "success": True,
        "total": len(devices),
        "devices": devices,
    }), 200


@profile_bp.route("/devices/<int:device_id>/revoke", methods=["POST"])
@profile_bp.route("/devices/<int:device_id>", methods=["DELETE"])
@jwt_required()
def revoke_user_device(device_id: int):
    """Revoke/deactivate a registered device profile."""
    from app.services.device_trust_service import DeviceTrustService

    user_id = int(get_jwt_identity())
    success, error = DeviceTrustService.revoke_user_device(user_id=user_id, device_id=device_id)

    if not success:
        status_code = 403 if "Forbidden" in error else 404
        return jsonify({"error": error, "code": "DEVICE_REVOCATION_FAILED"}), status_code

    return jsonify({
        "success": True,
        "message": "Device access revoked successfully",
    }), 200


@profile_bp.route("/locations", methods=["GET"])
@jwt_required()
def get_user_locations():
    """Retrieve chronological geographic location events for the authenticated customer."""
    from app.services.geo_intelligence_service import GeoIntelligenceService

    user_id = int(get_jwt_identity())
    locations = GeoIntelligenceService.get_user_locations(user_id)

    return jsonify({
        "success": True,
        "total": len(locations),
        "locations": locations,
    }), 200


@profile_bp.route("/locations/summary", methods=["GET"])
@jwt_required()
def get_user_location_summary():
    """Retrieve recognized geographic locations and primary home region for customer."""
    from app.services.geo_intelligence_service import GeoIntelligenceService

    user_id = int(get_jwt_identity())
    summary = GeoIntelligenceService.get_user_location_summary(user_id)

    return jsonify({
        "success": True,
        "summary": summary,
    }), 200
