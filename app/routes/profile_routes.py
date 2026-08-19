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
    """Update profile details (name, phone number)."""
    user_id = int(get_jwt_identity())
    user = AuthService.get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found", "code": "NOT_FOUND"}), 404

    data = request.get_json(silent=True) or {}

    if "name" in data:
        name = str(data["name"]).strip()
        if len(name) < 2 or len(name) > 100:
            return jsonify({"error": "Name must be between 2 and 100 characters"}), 400
        user.name = name

    if "phone_number" in data:
        phone = str(data["phone_number"]).strip() if data["phone_number"] else None
        if phone and len(phone) > 20:
            return jsonify({"error": "Phone number must not exceed 20 characters"}), 400
        user.phone_number = phone

    try:
        db.session.commit()
        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
            "profile": user.to_dict(),
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to update profile: {str(e)}"}), 500


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
