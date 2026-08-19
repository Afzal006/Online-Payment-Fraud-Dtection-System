"""
Frontend Web Routing Blueprint.

Renders HTML pages for the user portal and the administrator Security Operations Center.
"""

from flask import Blueprint, render_template, redirect, url_for

web_bp = Blueprint("web", __name__)


# =====================================================================
# USER PORTAL ROUTES
# =====================================================================

@web_bp.route("/", methods=["GET"])
def index():
    """Default landing route redirecting to dashboard or login."""
    return redirect(url_for("web.dashboard"))


@web_bp.route("/login", methods=["GET"])
def login_page():
    """Render login page."""
    return render_template("login.html", active_page="login")


@web_bp.route("/register", methods=["GET"])
def register_page():
    """Render registration page."""
    return render_template("register.html", active_page="register")


@web_bp.route("/forgot-password", methods=["GET"])
def forgot_password_page():
    """Render password reset request page."""
    return render_template("forgot_password.html", active_page="forgot_password")


@web_bp.route("/reset-password", methods=["GET"])
def reset_password_page():
    """Render password reset verification and update page."""
    return render_template("reset_password.html", active_page="reset_password")


@web_bp.route("/dashboard", methods=["GET"])
def dashboard():
    """Render user overview dashboard."""
    return render_template("dashboard.html", active_page="dashboard")


@web_bp.route("/payment", methods=["GET"])
def payment_page():
    """Render payment transfer simulator."""
    return render_template("payment.html", active_page="payment")


@web_bp.route("/history", methods=["GET"])
def history_page():
    """Render transaction ledger history."""
    return render_template("history.html", active_page="history")


# =====================================================================
# ADMIN SECURITY OPERATIONS CENTER (SOC) ROUTES
# =====================================================================

@web_bp.route("/admin", methods=["GET"])
def admin_root():
    """Redirect /admin to SOC dashboard."""
    return redirect(url_for("web.admin_dashboard_page"))


@web_bp.route("/admin/dashboard", methods=["GET"])
def admin_dashboard_page():
    """Render administrator SOC overview dashboard."""
    return render_template("admin/admin_dashboard.html", active_page="admin_dashboard")


@web_bp.route("/admin/customers", methods=["GET"])
def admin_customers_page():
    """Render administrator customer accounts directory."""
    return render_template("admin/admin_customers.html", active_page="admin_customers")


@web_bp.route("/admin/customers/<int:customer_id>", methods=["GET"])
def admin_customer_detail_page(customer_id: int):
    """Render administrator deep-dive view for a specific customer."""
    return render_template("admin/admin_customer_detail.html", active_page="admin_customers", customer_id=customer_id)


@web_bp.route("/admin/alerts", methods=["GET"])
def admin_alerts_page():
    """Render administrator security alert triage center."""
    return render_template("admin/admin_alerts.html", active_page="admin_alerts")


@web_bp.route("/admin/transactions", methods=["GET"])
def admin_transactions_page():
    """Render administrator global transaction ledger."""
    return render_template("admin/admin_transactions.html", active_page="admin_transactions")


@web_bp.route("/admin/model", methods=["GET"])
def admin_model_page():
    """Render administrator model telemetry and drift monitoring panel."""
    return render_template("admin/admin_model.html", active_page="admin_model")
