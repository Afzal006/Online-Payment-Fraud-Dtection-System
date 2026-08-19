"""
Structured JSON Logging Configuration.

Provides RFC 5424 compliant structured JSON logging with request correlation IDs
and automatic credential scrubbing for enterprise observability.
"""

from datetime import datetime, timezone
import json
import logging
import sys
from flask import has_request_context, g
from app.utils.sanitizer import sanitize_data


class StructuredJSONFormatter(logging.Formatter):
    """Formats log records as structured JSON strings with request tracing."""

    def format(self, record: logging.LogRecord) -> str:
        # Base log payload
        log_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach request correlation ID if inside Flask request context
        if has_request_context():
            log_payload["request_id"] = getattr(g, "request_id", "N/A")
            log_payload["ip"] = getattr(g, "client_ip", "N/A")
        else:
            log_payload["request_id"] = getattr(record, "request_id", "SYSTEM")

        # Attach extra structured fields if present
        if hasattr(record, "event_type"):
            log_payload["event_type"] = record.event_type
        if hasattr(record, "actor"):
            log_payload["actor"] = record.actor
        if hasattr(record, "action"):
            log_payload["action"] = record.action
        if hasattr(record, "result"):
            log_payload["result"] = record.result
        if hasattr(record, "details"):
            log_payload["details"] = sanitize_data(record.details)

        # Attach exception info if present
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload)


def configure_structured_logging(app=None, log_level=logging.INFO):
    """Configure root and application loggers to output structured JSON."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJSONFormatter())

    root_logger = logging.getLogger()
    # Avoid duplicate handlers
    if not any(isinstance(h.formatter, StructuredJSONFormatter) for h in root_logger.handlers):
        root_logger.addHandler(handler)
        root_logger.setLevel(log_level)

    if app:
        app.logger.handlers = [handler]
        app.logger.setLevel(log_level)
