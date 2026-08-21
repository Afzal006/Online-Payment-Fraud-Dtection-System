"""
Beneficiary API Endpoints.

Routes:
- GET    /api/beneficiaries     : List all saved beneficiaries for authenticated customer
- POST   /api/beneficiaries     : Add a new beneficiary
- GET    /api/beneficiaries/<id>: Get details of a specific beneficiary
- PUT    /api/beneficiaries/<id>: Update beneficiary nickname/phone/details
- DELETE /api/beneficiaries/<id>: Remove a saved beneficiary
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.beneficiary_service import BeneficiaryService
from app.models.user import User
from app.extensions import db

beneficiary_bp = Blueprint("beneficiaries", __name__, url_prefix="/api/beneficiaries")


@beneficiary_bp.route("", methods=["GET"])
@jwt_required()
def get_beneficiaries():
    """Retrieve all saved beneficiaries for the authenticated user."""
    user_id = int(get_jwt_identity())
    beneficiaries = BeneficiaryService.get_user_beneficiaries(user_id)
    return jsonify({
        "success": True,
        "total": len(beneficiaries),
        "beneficiaries": beneficiaries,
    }), 200


@beneficiary_bp.route("", methods=["POST"])
@jwt_required()
def add_beneficiary():
    """Add a new verified recipient to the customer's saved beneficiary directory."""
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    beneficiary, error_msg, status_code = BeneficiaryService.create_beneficiary(user_id, data)
    if error_msg:
        return jsonify({"error": error_msg}), status_code

    return jsonify({
        "success": True,
        "message": "Beneficiary saved successfully",
        "beneficiary": beneficiary.to_dict(),
    }), status_code


@beneficiary_bp.route("/<int:beneficiary_id>", methods=["GET"])
@jwt_required()
def get_single_beneficiary(beneficiary_id: int):
    """Retrieve a single beneficiary with tenant ownership verification."""
    user_id = int(get_jwt_identity())
    beneficiary, error_msg, status_code = BeneficiaryService.get_beneficiary_by_id(beneficiary_id, user_id)
    if error_msg:
        return jsonify({"error": error_msg}), status_code

    return jsonify({
        "success": True,
        "beneficiary": beneficiary.to_dict(),
    }), 200


@beneficiary_bp.route("/<int:beneficiary_id>", methods=["PUT"])
@jwt_required()
def update_beneficiary(beneficiary_id: int):
    """Update details for an existing saved beneficiary."""
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    beneficiary, error_msg, status_code = BeneficiaryService.update_beneficiary(beneficiary_id, user_id, data)
    if error_msg:
        return jsonify({"error": error_msg}), status_code

    return jsonify({
        "success": True,
        "message": "Beneficiary updated successfully",
        "beneficiary": beneficiary.to_dict(),
    }), 200


@beneficiary_bp.route("/<int:beneficiary_id>", methods=["DELETE"])
@jwt_required()
def delete_beneficiary(beneficiary_id: int):
    """Delete a saved beneficiary record."""
    user_id = int(get_jwt_identity())
    success, error_msg, status_code = BeneficiaryService.delete_beneficiary(beneficiary_id, user_id)
    if error_msg:
        return jsonify({"error": error_msg}), status_code

    return jsonify({
        "success": True,
        "message": "Beneficiary removed successfully",
    }), 200


@beneficiary_bp.route("/<int:beneficiary_id>/revoke", methods=["POST"])
@jwt_required()
def revoke_beneficiary(beneficiary_id: int):
    """Explicitly revoke a saved beneficiary."""
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "Customer self-service revocation")

    success, error_msg, status_code = BeneficiaryService.revoke_beneficiary(
        beneficiary_id=beneficiary_id,
        user_id=user_id,
        reason=reason,
    )
    if error_msg:
        return jsonify({"error": error_msg}), status_code

    return jsonify({
        "success": True,
        "message": "Beneficiary revoked successfully",
    }), 200
