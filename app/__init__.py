"""
Flask Application Factory for Online Payment Fraud Detection System.
"""

from flask import Flask, jsonify
from app.config import config_by_name
from app.extensions import db, migrate, jwt, cors


def create_app(config_name="development"):
    """Application factory initializing extensions, database models, and route blueprints."""
    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )

    # Load configuration
    config_class = config_by_name.get(config_name, config_by_name["development"])
    app.config.from_object(config_class)

    # Initialize extensions
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # JWT Error Handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            "error": "The token has expired",
            "code": "TOKEN_EXPIRED"
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            "error": "Signature verification failed or token is malformed",
            "code": "INVALID_TOKEN"
        }), 422

    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        return jsonify({
            "error": "Authorization token is missing",
            "code": "AUTHORIZATION_REQUIRED"
        }), 401

    from app.routes.health_routes import health_bp
    from app.routes.auth_routes import auth_bp
    from app.routes.profile_routes import profile_bp
    from app.routes.beneficiary_routes import beneficiary_bp
    from app.routes.admin_routes import admin_bp
    from app.routes.transaction_routes import transaction_bp
    from app.routes.otp_routes import otp_bp
    from app.routes.web_routes import web_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(beneficiary_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(transaction_bp)
    app.register_blueprint(otp_bp)
    app.register_blueprint(web_bp)

    # Global HTTP error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found", "code": "NOT_FOUND"}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({"error": "Method not allowed", "code": "METHOD_NOT_ALLOWED"}), 405

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error", "code": "INTERNAL_ERROR"}), 500

    return app
