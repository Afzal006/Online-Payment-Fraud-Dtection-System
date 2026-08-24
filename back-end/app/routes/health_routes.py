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
        current_app.logger.error(f"Database health check failed: {str(e)}")
        db_status = "unhealthy"

    ml_status = "loaded"
    model_version = "unknown"
    try:
        service = get_inference_service()
        model_version = service.metadata.get("model_version", "1.0.0")
    except Exception as e:
        current_app.logger.error(f"ML engine health check failed: {str(e)}")
        ml_status = "unavailable"

    email_provider_status = "not_configured"
    try:
        from app.providers.email_provider import (
            get_email_provider,
            ResendEmailProvider,
            SmtpEmailProvider,
            DevelopmentEmailProvider,
        )
        provider = get_email_provider()
        if isinstance(provider, ResendEmailProvider):
            email_provider_status = "resend_configured" if provider.api_key else "resend_missing_key"
        elif isinstance(provider, SmtpEmailProvider):
            email_provider_status = "smtp_configured"
        elif isinstance(provider, DevelopmentEmailProvider):
            email_provider_status = "development"
        else:
            email_provider_status = "not_configured"
    except Exception:
        email_provider_status = "unknown"

    return jsonify({
        "status": "healthy" if "unhealthy" not in db_status else "degraded",
        "project": "AI-Powered Real-Time Online Payment Fraud Detection System",
        "version": "1.0.0",
        "model_version": model_version,
        "database": db_status,
        "ml_engine": ml_status,
        "email_provider": email_provider_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": current_app.config.get("FLASK_ENV", "development"),
    }), 200


@health_bp.route("/health/email", methods=["GET"])
def health_email():
    """Diagnostic endpoint for email provider configuration and status without exposing secrets."""
    from app.providers.email_provider import (
        get_email_provider,
        ResendEmailProvider,
        SmtpEmailProvider,
        DevelopmentEmailProvider,
        NullEmailProvider,
    )

    provider = get_email_provider()
    provider_name = type(provider).__name__

    if isinstance(provider, ResendEmailProvider):
        diag = provider.get_diagnostics()
        return jsonify({
            "status": "configured" if diag["api_key_configured"] else "not_configured",
            "provider": provider_name,
            "transport": diag["transport"],
            "api_key_configured": diag["api_key_configured"],
            "from_email": diag["from_email"],
            "from_name": diag["from_name"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": current_app.config.get("FLASK_ENV", "development"),
        }), 200
    elif isinstance(provider, SmtpEmailProvider):
        diag = provider.get_diagnostics()
        return jsonify({
            "status": "configured" if (diag["smtp_host"] != "NOT_CONFIGURED") else "not_configured",
            "provider": provider_name,
            "transport": "SMTP",
            "smtp_host": diag["smtp_host"],
            "smtp_port": diag["smtp_port"],
            "use_tls": diag["use_tls"],
            "use_ssl": diag["use_ssl"],
            "username_configured": diag["username_configured"],
            "password_configured": diag["password_configured"],
            "from_email": diag["sender_address"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": current_app.config.get("FLASK_ENV", "development"),
        }), 200
    elif isinstance(provider, DevelopmentEmailProvider):
        return jsonify({
            "status": "development",
            "provider": provider_name,
            "description": "In-memory test simulation active. Set EMAIL_PROVIDER=resend and RESEND_API_KEY for real email delivery.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": current_app.config.get("FLASK_ENV", "development"),
        }), 200
    else:
        return jsonify({
            "status": "not_configured",
            "provider": provider_name,
            "description": "No active email provider. Set EMAIL_PROVIDER=resend and RESEND_API_KEY.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": current_app.config.get("FLASK_ENV", "development"),
        }), 200
