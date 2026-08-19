"""
Admin API Endpoints.

Protected administrative routes requiring ADMIN role privileges.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.utils.decorators import admin_required
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.services.alert_service import AlertService
from app.services.admin_analytics_service import AdminAnalyticsService

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/check", methods=["GET"])
@admin_required()
def admin_check():
    """Verify administrator permissions and access."""
    return jsonify({
        "status": "success",
        "message": "Administrative access authorized",
        "admin_access": True,
    }), 200


@admin_bp.route("/overview", methods=["GET"])
@admin_required()
def admin_overview():
    """Summary KPI metrics for admin SOC dashboard."""
    kpis = AdminAnalyticsService.get_overview_kpis()
    return jsonify({
        "success": True,
        "kpis": kpis,
    }), 200


@admin_bp.route("/customers", methods=["GET"])
@admin_required()
def get_admin_customers():
    """Retrieve all registered customer accounts with aggregated metrics."""
    search = request.args.get("search", "")
    sort_by = request.args.get("sort_by", "newest")
    limit = int(request.args.get("limit", 100))

    customers = AdminAnalyticsService.get_customers_list(search=search, sort_by=sort_by, limit=limit)
    return jsonify({
        "success": True,
        "total": len(customers),
        "customers": customers,
    }), 200


@admin_bp.route("/customers/<int:customer_id>", methods=["GET"])
@admin_required()
def get_admin_customer_detail(customer_id: int):
    """Retrieve detailed customer profile and complete transaction history."""
    detail = AdminAnalyticsService.get_customer_detail(customer_id=customer_id)
    if not detail:
        return jsonify({"error": "Customer not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "customer": detail["customer"],
        "summary": detail["summary"],
        "transactions": detail["transactions"],
    }), 200


@admin_bp.route("/analytics", methods=["GET"])
@admin_required()
def admin_analytics():
    """Aggregated datasets tailored for Chart.js interactive visualizations."""
    charts = AdminAnalyticsService.get_chart_analytics()
    return jsonify({
        "success": True,
        "charts": charts,
    }), 200


@admin_bp.route("/alerts", methods=["GET"])
@admin_required()
def get_admin_alerts():
    """Retrieve security alerts for investigation."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = int(request.args.get("limit", 100))

    alerts = AlertService.get_all_alerts(status=status, severity=severity, limit=limit)
    return jsonify({
        "success": True,
        "total": len(alerts),
        "alerts": alerts,
    }), 200


@admin_bp.route("/alerts/<int:alert_id>", methods=["GET"])
@admin_required()
def get_admin_alert_detail(alert_id: int):
    """Retrieve deep investigation details for a specific security alert."""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    tx = alert.transaction
    user = alert.user

    return jsonify({
        "success": True,
        "alert": alert.to_dict(),
        "user": user.to_dict() if user else None,
        "transaction": tx.to_dict() if tx else None,
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@admin_required()
def resolve_admin_alert(alert_id: int):
    """Mark a security alert as resolved."""
    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    note = data.get("note")

    alert = AlertService.resolve_alert(alert_id=alert_id, admin_id=admin_id, note=note)
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} resolved successfully",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/dismiss", methods=["POST"])
@admin_required()
def dismiss_admin_alert(alert_id: int):
    """Dismiss a security alert."""
    admin_id = int(get_jwt_identity())
    alert = AlertService.dismiss_alert(alert_id=alert_id, admin_id=admin_id)
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} dismissed",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/transactions", methods=["GET"])
@admin_required()
def get_admin_transactions():
    """Retrieve global transaction ledger with search, filtering, and sorting."""
    limit = int(request.args.get("limit", 100))
    risk_level = request.args.get("risk_level")
    tx_type = request.args.get("type")
    status = request.args.get("status")
    search = request.args.get("search", "").strip()
    sort_by = request.args.get("sort_by", "newest")

    query = Transaction.query.join(User, Transaction.user_id == User.id)

    # Search filter (ID, destination, user email, user name)
    if search:
        if search.startswith("#"):
            search_num = search[1:]
        else:
            search_num = search
        
        search_filter = (
            Transaction.name_dest.ilike(f"%{search}%") |
            User.email.ilike(f"%{search}%") |
            User.name.ilike(f"%{search}%")
        )
        if search_num.isdigit():
            search_filter = search_filter | (Transaction.id == int(search_num))
        
        query = query.filter(search_filter)

    # Criteria filters
    if risk_level:
        query = query.filter(Transaction.risk_level == risk_level.upper())
    if tx_type:
        query = query.filter(Transaction.type == tx_type.upper())
    if status:
        query = query.filter(Transaction.status == status.upper())

    # Sorting
    if sort_by == "amount_desc":
        query = query.order_by(Transaction.amount.desc())
    elif sort_by == "amount_asc":
        query = query.order_by(Transaction.amount.asc())
    elif sort_by == "risk_desc":
        query = query.order_by(Transaction.risk_score.desc())
    elif sort_by == "risk_asc":
        query = query.order_by(Transaction.risk_score.asc())
    elif sort_by == "oldest":
        query = query.order_by(Transaction.created_at.asc())
    else:  # newest
        query = query.order_by(Transaction.created_at.desc())

    transactions = query.limit(limit).all()

    results = []
    for t in transactions:
        tx_dict = t.to_dict()
        tx_dict["user_name"] = t.user.name if t.user else "Unknown"
        tx_dict["user_email"] = t.user.email if t.user else "Unknown"
        tx_dict["has_alert"] = bool(t.alert)
        tx_dict["alert_status"] = t.alert.status if t.alert else None
        results.append(tx_dict)

    return jsonify({
        "success": True,
        "total": len(results),
        "transactions": results,
    }), 200


@admin_bp.route("/transactions/<int:tx_id>", methods=["GET"])
@admin_required()
def get_admin_transaction_detail(tx_id: int):
    """Retrieve comprehensive transaction audit details for deep admin SOC investigation."""
    tx = db.session.get(Transaction, tx_id)
    if not tx:
        return jsonify({"error": "Transaction not found", "code": "NOT_FOUND"}), 404

    import json
    from app.models.otp_challenge import OTPChallenge

    tx_dict = tx.to_dict()
    explanation_data = json.loads(tx.explanation_json) if tx.explanation_json else None
    tx_dict["explanation"] = explanation_data

    # Linked User Info
    user_dict = tx.user.to_dict() if tx.user else None

    # Linked Alert Info (with resolution notes & resolver)
    alert_dict = tx.alert.to_dict() if tx.alert else None

    # Linked OTP Challenges
    challenges = OTPChallenge.query.filter_by(transaction_id=tx.id).order_by(OTPChallenge.created_at.desc()).all()
    otp_list = [c.to_dict() for c in challenges]

    return jsonify({
        "success": True,
        "transaction": tx_dict,
        "user": user_dict,
        "alert": alert_dict,
        "otp_challenges": otp_list,
    }), 200


@admin_bp.route("/model-info", methods=["GET"])
@admin_required()
def get_admin_model_info():
    """Retrieve model registry packaging metadata, benchmark metrics, and drift analysis."""
    metadata = AdminAnalyticsService.get_model_information()
    drift = AdminAnalyticsService.evaluate_data_drift()

    return jsonify({
        "success": True,
        "model_metadata": metadata,
        "data_drift": drift,
    }), 200


@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required()
def get_admin_audit_logs():
    """Retrieve filtered, paginated structured audit log records."""
    from app.services.audit_service import AuditService

    event_type = request.args.get("event_type")
    severity = request.args.get("severity")
    user_id = request.args.get("user_id", type=int)
    request_id = request.args.get("request_id")
    search = request.args.get("search")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    result = AuditService.query_logs(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        request_id=request_id,
        search=search,
        page=page,
        per_page=per_page,
    )

    return jsonify({
        "success": True,
        **result,
    }), 200


@admin_bp.route("/customers/<int:customer_id>/devices", methods=["GET"])
@admin_required()
def get_admin_customer_devices(customer_id: int):
    """Retrieve all device profiles for a specific customer with admin telemetry."""
    from app.models.device_profile import DeviceProfile

    devices = DeviceProfile.query.filter_by(user_id=customer_id).order_by(DeviceProfile.last_seen_at.desc()).all()
    return jsonify({
        "success": True,
        "customer_id": customer_id,
        "total": len(devices),
        "devices": [d.to_dict(include_admin=True) for d in devices],
    }), 200


@admin_bp.route("/devices/<int:device_id>/trust", methods=["POST"])
@admin_required()
def admin_update_device_trust(device_id: int):
    """Update trust status of a device profile (TRUSTED, SUSPICIOUS, BLOCKED, UNKNOWN)."""
    from app.services.device_trust_service import DeviceTrustService

    data = request.get_json(silent=True) or {}
    new_status = data.get("trust_status")
    if not new_status:
        return jsonify({"error": "Field 'trust_status' is required"}), 400

    admin_id = int(get_jwt_identity())
    admin_user = db.session.get(User, admin_id)
    admin_identifier = admin_user.email if admin_user else f"Admin #{admin_id}"

    success, error = DeviceTrustService.admin_update_trust(
        device_id=device_id,
        new_status=new_status,
        admin_identifier=admin_identifier,
        admin_id=admin_id,
    )

    if not success:
        return jsonify({"error": error}), 400

    return jsonify({
        "success": True,
        "message": f"Device trust status updated to {new_status.upper()}",
        "device_id": device_id,
        "new_trust_status": new_status.upper(),
    }), 200


@admin_bp.route("/customers/<int:customer_id>/locations", methods=["GET"])
@admin_required()
def get_admin_customer_locations(customer_id: int):
    """Retrieve all geographic location events for a customer with admin-level physics telemetry."""
    from app.services.geo_intelligence_service import GeoIntelligenceService

    customer = db.session.get(User, customer_id)
    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    data = GeoIntelligenceService.get_admin_customer_locations(customer_id)
    return jsonify({
        "success": True,
        **data,
    }), 200
