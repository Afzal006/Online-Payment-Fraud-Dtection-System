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
    """Retrieve security alerts for investigation with filtering."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    assigned_to_id = request.args.get("assigned_to_id", type=int)
    case_id = request.args.get("case_id", type=int)
    customer_id = request.args.get("customer_id", type=int)
    limit = int(request.args.get("limit", 100))

    alerts = AlertService.get_all_alerts(
        status=status,
        severity=severity,
        assigned_to_id=assigned_to_id,
        case_id=case_id,
        customer_id=customer_id,
        limit=limit,
    )
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


@admin_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@admin_required()
def acknowledge_admin_alert(alert_id: int):
    """Acknowledge a security alert for triage."""
    admin_id = int(get_jwt_identity())
    alert = AlertService.acknowledge_alert(alert_id=alert_id, admin_id=admin_id)
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} acknowledged",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/assign", methods=["POST"])
@admin_required()
def assign_admin_alert(alert_id: int):
    """Assign an alert to a specific admin analyst."""
    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    assignee_id = data.get("assignee_id")
    if not assignee_id:
        return jsonify({"error": "assignee_id is required"}), 400

    alert = AlertService.assign_alert(alert_id=alert_id, admin_id=admin_id, assignee_id=int(assignee_id))
    if not alert:
        return jsonify({"error": "Alert or Assignee not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} assigned successfully",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/investigate", methods=["POST"])
@admin_required()
def investigate_admin_alert(alert_id: int):
    """Move alert to investigating status with investigator note."""
    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    note = data.get("note")

    alert = AlertService.investigate_alert(alert_id=alert_id, admin_id=admin_id, note=note)
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} moved to investigating",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/escalate", methods=["POST"])
@admin_required()
def escalate_admin_alert(alert_id: int):
    """Escalate alert and optionally link to a formal SOC case."""
    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    case_id = data.get("case_id")
    note = data.get("note")

    alert = AlertService.escalate_alert(
        alert_id=alert_id,
        admin_id=admin_id,
        case_id=int(case_id) if case_id else None,
        note=note,
    )
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} escalated",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@admin_required()
def resolve_admin_alert(alert_id: int):
    """Mark a security alert as resolved or false positive."""
    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    note = data.get("note")
    resolution_type = data.get("resolution_type", "RESOLVED")

    alert = AlertService.resolve_alert(
        alert_id=alert_id,
        admin_id=admin_id,
        resolution_type=resolution_type,
        note=note,
    )
    if not alert:
        return jsonify({"error": "Alert not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} marked as {alert.status}",
        "alert": alert.to_dict(),
    }), 200


@admin_bp.route("/alerts/<int:alert_id>/dismiss", methods=["POST"])
@admin_required()
def dismiss_admin_alert(alert_id: int):
    """Dismiss a security alert."""
    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    note = data.get("note")

    alert = AlertService.dismiss_alert(alert_id=alert_id, admin_id=admin_id, note=note)
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


@admin_bp.route("/customers/<int:customer_id>/beneficiaries", methods=["GET"])
@admin_required()
def get_admin_customer_beneficiaries(customer_id: int):
    """Retrieve all saved beneficiaries for a customer with cooling and payment telemetry."""
    from app.services.beneficiary_service import BeneficiaryService

    customer = db.session.get(User, customer_id)
    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    data = BeneficiaryService.get_admin_customer_beneficiaries(customer_id)
    return jsonify({
        "success": True,
        **data,
    }), 200


# =========================================================================
# SOC CASE MANAGEMENT & INCIDENT LIFECYCLE ENDPOINTS
# =========================================================================

@admin_bp.route("/cases", methods=["GET"])
@admin_required()
def get_admin_cases():
    """Retrieve filtered, paginated SOC investigation cases."""
    from app.services.soc_case_service import SOCCaseService

    status = request.args.get("status")
    priority = request.args.get("priority")
    analyst_id = request.args.get("analyst_id", type=int)
    customer_id = request.args.get("customer_id", type=int)
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    result = SOCCaseService.list_cases(
        status=status,
        priority=priority,
        analyst_id=analyst_id,
        customer_id=customer_id,
        page=page,
        per_page=per_page,
    )

    return jsonify({
        "success": True,
        **result,
    }), 200


@admin_bp.route("/cases", methods=["POST"])
@admin_required()
def create_admin_case():
    """Create a new formal SOC investigation case."""
    from app.services.soc_case_service import SOCCaseService

    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    customer_id = data.get("customer_id")
    title = data.get("title")
    priority = data.get("priority", "HIGH")
    lead_analyst_id = data.get("lead_analyst_id")
    description = data.get("description")
    alert_ids = data.get("alert_ids")

    if not customer_id or not title:
        return jsonify({"error": "customer_id and title are required"}), 400

    soc_case, error = SOCCaseService.create_case(
        customer_id=int(customer_id),
        title=str(title),
        priority=str(priority),
        lead_analyst_id=int(lead_analyst_id) if lead_analyst_id else None,
        description=str(description) if description else None,
        alert_ids=[int(aid) for aid in alert_ids] if alert_ids else None,
        actor_admin_id=admin_id,
    )

    if error or not soc_case:
        return jsonify({"error": error or "Failed to create case"}), 400

    return jsonify({
        "success": True,
        "message": f"Case {soc_case.case_number} created successfully",
        "case": soc_case.to_dict(include_evidence=True, include_notes=True),
    }), 201


@admin_bp.route("/cases/summary", methods=["GET"])
@admin_required()
def get_admin_cases_summary():
    """Retrieve operational high-level metrics for the SOC dashboard."""
    from app.services.soc_case_service import SOCCaseService

    metrics = SOCCaseService.get_soc_metrics()
    return jsonify({
        "success": True,
        "metrics": metrics,
    }), 200


@admin_bp.route("/cases/<int:case_id>", methods=["GET"])
@admin_required()
def get_admin_case_detail(case_id: int):
    """Retrieve complete dossier for a SOC investigation case."""
    from app.services.soc_case_service import SOCCaseService

    case_data = SOCCaseService.get_case_detail(case_id)
    if not case_data:
        return jsonify({"error": "Case not found", "code": "NOT_FOUND"}), 404

    return jsonify({
        "success": True,
        "case": case_data,
    }), 200


@admin_bp.route("/cases/<int:case_id>/status", methods=["POST"])
@admin_required()
def update_admin_case_status(case_id: int):
    """Advance case lifecycle status with optional security remediations."""
    from app.services.soc_case_service import SOCCaseService

    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "status is required"}), 400

    resolution_summary = data.get("resolution_summary")
    note = data.get("note")
    block_devices = bool(data.get("block_devices", False))
    revoke_beneficiaries = bool(data.get("revoke_beneficiaries", False))

    soc_case, error = SOCCaseService.update_case_status(
        case_id=case_id,
        new_status=new_status,
        actor_admin_id=admin_id,
        resolution_summary=resolution_summary,
        note=note,
        block_devices=block_devices,
        revoke_beneficiaries=revoke_beneficiaries,
    )

    if error or not soc_case:
        return jsonify({"error": error or "Failed to update case status"}), 400

    return jsonify({
        "success": True,
        "message": f"Case {soc_case.case_number} status transitioned to {soc_case.status}",
        "case": soc_case.to_dict(include_evidence=False, include_notes=True),
    }), 200


@admin_bp.route("/cases/<int:case_id>/assign", methods=["POST"])
@admin_required()
def assign_admin_case(case_id: int):
    """Assign or reassign lead investigator on a SOC case."""
    from app.services.soc_case_service import SOCCaseService

    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    analyst_id = data.get("analyst_id")
    if not analyst_id:
        return jsonify({"error": "analyst_id is required"}), 400

    soc_case, error = SOCCaseService.assign_lead_analyst(
        case_id=case_id,
        analyst_id=int(analyst_id),
        actor_admin_id=admin_id,
    )

    if error or not soc_case:
        return jsonify({"error": error or "Failed to assign case"}), 400

    return jsonify({
        "success": True,
        "message": f"Case assigned to lead analyst",
        "case": soc_case.to_dict(include_evidence=False, include_notes=True),
    }), 200


@admin_bp.route("/cases/<int:case_id>/notes", methods=["POST"])
@admin_required()
def add_admin_case_note(case_id: int):
    """Append an investigator note, step, or evidence note to the case timeline."""
    from app.services.soc_case_service import SOCCaseService

    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    content = data.get("content")
    note_type = data.get("note_type", "ANALYST_NOTE")

    if not content:
        return jsonify({"error": "content is required"}), 400

    note_obj, error = SOCCaseService.add_case_note(
        case_id=case_id,
        author_id=admin_id,
        content=content,
        note_type=note_type,
    )

    if error or not note_obj:
        return jsonify({"error": error or "Failed to add case note"}), 400

    return jsonify({
        "success": True,
        "message": "Case note added successfully",
        "note": note_obj.to_dict(),
    }), 201


@admin_bp.route("/cases/<int:case_id>/alerts/attach", methods=["POST"])
@admin_required()
def attach_admin_case_alert(case_id: int):
    """Attach an existing security alert to an ongoing SOC case."""
    from app.services.soc_case_service import SOCCaseService

    admin_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}

    alert_id = data.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id is required"}), 400

    alert_obj, error = SOCCaseService.attach_alert(
        case_id=case_id,
        alert_id=int(alert_id),
        actor_admin_id=admin_id,
    )

    if error or not alert_obj:
        return jsonify({"error": error or "Failed to attach alert"}), 400

    return jsonify({
        "success": True,
        "message": f"Alert #{alert_id} attached to case",
        "alert": alert_obj.to_dict(),
    }), 200

