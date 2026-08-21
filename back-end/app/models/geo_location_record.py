"""
Geo Location Record Model for Privacy-Conscious Geographic Telemetry.

Stores coarse, pseudonymized location events for customer accounts without recording
precise continuous GPS tracks or sensitive PII.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from app.extensions import db


class GeoLocationRecord(db.Model):
    """Immutable audit trail of customer geographic authentication and transaction locations."""

    __tablename__ = "geo_location_records"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = db.Column(db.String(32), nullable=False, default="TRANSACTION")  # TRANSACTION, LOGIN, OTP
    event_id = db.Column(db.String(64), nullable=True)  # e.g., "TX-105"

    # Privacy-Preserving Geographic Telemetry
    ip_hash = db.Column(db.String(64), nullable=False, index=True)  # SHA-256 pseudonymized IP
    city = db.Column(db.String(64), nullable=False, default="Unknown")
    region = db.Column(db.String(64), nullable=False, default="Unknown")  # State / Province
    country_code = db.Column(db.String(3), nullable=False, default="IN")
    timezone = db.Column(db.String(64), nullable=False, default="Asia/Kolkata")

    # Coarse Coordinates (rounded to 2 decimal places ~ 1.1km radius)
    latitude = db.Column(db.Float, nullable=False, default=0.0)
    longitude = db.Column(db.Float, nullable=False, default=0.0)

    # Anomaly Flags and Physics Indicators
    is_impossible_travel = db.Column(db.Boolean, nullable=False, default=False)
    is_unusual_location = db.Column(db.Boolean, nullable=False, default=False)
    distance_from_last_km = db.Column(db.Float, nullable=True)
    speed_from_last_kmh = db.Column(db.Float, nullable=True)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relationships
    user = db.relationship("User", backref=db.backref("geo_locations", lazy="dynamic", cascade="all, delete-orphan"))

    def to_dict(self, include_admin: bool = False) -> Dict[str, Any]:
        """
        Serialize location record with strict tenant privacy controls.

        Customer views omit raw coordinates, IP hashes, and internal speed calculations.
        """
        base = {
            "id": self.id,
            "event_type": self.event_type,
            "city": self.city,
            "region": self.region,
            "country": self.country_code,
            "timezone": self.timezone,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

        if include_admin:
            base.update({
                "user_id": self.user_id,
                "event_id": self.event_id,
                "ip_hash": self.ip_hash,
                "latitude": round(self.latitude, 2) if self.latitude is not None else None,
                "longitude": round(self.longitude, 2) if self.longitude is not None else None,
                "distance_km": round(self.distance_from_last_km, 2) if self.distance_from_last_km is not None else None,
                "speed_kmh": round(self.speed_from_last_kmh, 1) if self.speed_from_last_kmh is not None else None,
                "is_impossible_travel": self.is_impossible_travel,
                "is_unusual_location": self.is_unusual_location,
            })

        return base

    def __repr__(self) -> str:
        return f"<GeoLocationRecord id={self.id} user={self.user_id} city='{self.city}' country='{self.country_code}' impossible={self.is_impossible_travel}>"
