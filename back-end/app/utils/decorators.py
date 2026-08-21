"""
Authentication and Authorization Decorators (RBAC).
"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity
from app.extensions import db
from app.models.user import User


def admin_required():
    """
    Decorator requiring an authenticated user with ADMIN role.
    Rejects unauthorized or regular USER requests with 403 Forbidden.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            role = claims.get("role")

            if role != "ADMIN":
                # Fallback: check database directly if role claim missing
                user_id = get_jwt_identity()
                user = db.session.get(User, int(user_id)) if user_id else None
                if not user or user.role != "ADMIN":
                    return jsonify({
                        "error": "Forbidden: Administrative privileges required",
                        "code": "INSUFFICIENT_PERMISSIONS"
                    }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def role_required(*allowed_roles):
    """
    Decorator requiring user to have one of the allowed roles.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            role = claims.get("role")

            if role not in allowed_roles:
                user_id = get_jwt_identity()
                user = db.session.get(User, int(user_id)) if user_id else None
                if not user or user.role not in allowed_roles:
                    return jsonify({
                        "error": f"Forbidden: One of roles {allowed_roles} required",
                        "code": "INSUFFICIENT_PERMISSIONS"
                    }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator
