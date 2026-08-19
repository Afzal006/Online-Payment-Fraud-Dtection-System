"""
Health check and system diagnostics endpoint.
"""

from datetime import datetime, timezone
from flask import Blueprint, jsonify, current_app
from app.extensions import db
from ml.inference import get_inference_service

health_bp = Blueprint("health", __name__, url_prefix="/api")


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Verify backend health, database connectivity, and ML artifact availability."""
    db_status = "healthy"
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    ml_status = "loaded"
    model_version = "unknown"
    try:
        service = get_inference_service()
        model_version = service.metadata.get("model_version", "1.0.0")
    except Exception as e:
        ml_status = f"unavailable: {str(e)}"

    return jsonify({
        "status": "healthy" if "unhealthy" not in db_status else "degraded",
        "project": "AI-Powered Real-Time Online Payment Fraud Detection System",
        "version": "1.0.0",
        "model_version": model_version,
        "database": db_status,
        "ml_engine": ml_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": current_app.config.get("FLASK_ENV", "development"),
    }), 200
