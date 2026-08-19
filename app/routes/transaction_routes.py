"""
Transaction API Endpoints.

Routes:
- POST /api/transactions/predict : Evaluates fraud risk on payment transaction,
                                    generates SHAP explanation, and records transaction.
- GET  /api/transactions/my-history : Retrieves authenticated user's transaction history.
- GET  /api/transactions/<id> : Retrieves details & explanation of specific transaction.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.transaction_service import TransactionService
from app.models.transaction import Transaction
from app.extensions import db

transaction_bp = Blueprint("transactions", __name__, url_prefix="/api/transactions")


@transaction_bp.route("/predict", methods=["POST"])
@jwt_required()
def predict_transaction():
    """
    Evaluate fraud risk and generate SHAP explanations for an incoming transaction.

    Requires:
        JWT Bearer token.
    Payload:
        amount (float), type (string), destination/name_dest (string), optional balances.
    """
    data = request.get_json(silent=True)
    is_valid, error_msg = TransactionService.validate_prediction_payload(data)
    if not is_valid:
        return jsonify({"error": error_msg, "code": "VALIDATION_ERROR"}), 400

    user_id = int(get_jwt_identity())
    response_data, error, status_code = TransactionService.process_and_predict(user_id=user_id, payload=data)

    if error:
        return jsonify({"error": error, "code": "PREDICTION_FAILED"}), status_code

    return jsonify(response_data), status_code


@transaction_bp.route("/my-history", methods=["GET"])
@jwt_required()
def get_user_transactions():
    """Retrieve transaction history for the authenticated user."""
    user_id = int(get_jwt_identity())
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.created_at.desc()).limit(50).all()

    return jsonify({
        "total": len(transactions),
        "transactions": [t.to_dict() for t in transactions],
    }), 200


@transaction_bp.route("/<int:tx_id>", methods=["GET"])
@jwt_required()
def get_transaction_details(tx_id: int):
    """Retrieve transaction details including stored SHAP explanation."""
    user_id = int(get_jwt_identity())
    tx = db.session.get(Transaction, tx_id)

    if not tx:
        return jsonify({"error": "Transaction not found", "code": "NOT_FOUND"}), 404

    # Authorization: only transaction owner or ADMIN can view
    from app.models.user import User
    current_user = db.session.get(User, user_id)
    if tx.user_id != user_id and (not current_user or current_user.role != "ADMIN"):
        return jsonify({"error": "Forbidden: Access denied to this transaction", "code": "FORBIDDEN"}), 403

    import json
    data = tx.to_dict()
    data["explanation"] = json.loads(tx.explanation_json) if tx.explanation_json else None
    return jsonify(data), 200


@transaction_bp.route("/resolve-recipient", methods=["POST"])
@jwt_required()
def resolve_recipient():
    """
    Resolve payment recipient from UPI ID, 10-digit mobile number, or QR string.
    """
    from app.services.payment_service import PaymentService
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    query = data.get("query") or data.get("recipient") or data.get("identifier") or ""
    success, recipient_info, error_msg = PaymentService.resolve_recipient(
        current_user_id=user_id,
        query=str(query),
    )

    if not success:
        return jsonify({"error": error_msg, "code": "RESOLUTION_FAILED"}), 400

    return jsonify({
        "success": True,
        "recipient": recipient_info,
    }), 200


@transaction_bp.route("/parse-qr", methods=["POST"])
@jwt_required()
def parse_qr_code():
    """
    Parse and validate a standard UPI QR code URI payload.
    """
    from app.services.payment_service import PaymentService
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    qr_data = data.get("qr_data") or data.get("qrData") or data.get("qr") or ""
    success, parsed_payload, error_msg = PaymentService.parse_upi_qr(str(qr_data))

    if not success:
        return jsonify({"error": error_msg, "code": "INVALID_QR"}), 400

    return jsonify({
        "success": True,
        "parsed_qr": parsed_payload,
    }), 200

