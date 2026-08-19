"""
Security and Request Tracing Middleware.

Enforces OWASP recommended security headers, generates/propagates X-Request-ID
correlation identifiers, and provides zero-trust request context initialization.
"""

import time
import uuid
from flask import Flask, request, g, Response


def setup_security_middleware(app: Flask):
    """Register request context tracing and OWASP security headers on Flask application."""

    @app.before_request
    def initialize_request_context():
        """Initialize correlation ID and request tracking variables."""
        # Extract existing X-Request-ID or generate standard UUIDv4
        incoming_request_id = request.headers.get("X-Request-ID")
        if incoming_request_id and len(incoming_request_id.strip()) > 0:
            g.request_id = incoming_request_id.strip()[:64]  # Bounded length
        else:
            g.request_id = str(uuid.uuid4())

        # Extract client IP safely (support proxies and direct)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            g.client_ip = forwarded_for.split(",")[0].strip()
        else:
            g.client_ip = request.remote_addr or "127.0.0.1"

        g.request_start_time = time.time()

    @app.after_request
    def inject_security_headers(response: Response) -> Response:
        """Inject correlation ID and OWASP security headers into all HTTP responses."""
        # 1. Attach Request Correlation ID
        request_id = getattr(g, "request_id", None)
        if request_id:
            response.headers["X-Request-ID"] = request_id

        # 2. Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # 3. Prevent Clickjacking / Framing
        response.headers["X-Frame-Options"] = "DENY"

        # 4. Prevent MIME-Type Sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 5. Cross-Site Scripting Protection filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # 6. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 7. Permissions Policy (Restrict camera, mic, native payment)
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"

        # 8. Content Security Policy (Allow self, google fonts, cdnjs chart/icons)
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        return response
