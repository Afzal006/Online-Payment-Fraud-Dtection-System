"""
Geo Intelligence & Impossible Travel Detection Service.

Evaluates client geographic locations, establishes historical geographic baselines,
detects impossible travel anomalies using geodesic physics, and correlates with device trust.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import func

from app.extensions import db
from app.models.geo_location_record import GeoLocationRecord
from app.models.user import User
from app.utils.geo_provider import get_geo_provider, haversine_distance, GeoData
from app.utils.device_fingerprint import compute_ip_hash
from app.services.audit_service import AuditService

logger = logging.getLogger("fraudshield.geo_intelligence")


class GeoIntelligenceService:
    """Core engine for geographic risk assessment, impossible travel, and location profiling."""

    # Physics & Aviation Security Thresholds
    MAX_COMMERCIAL_SPEED_KMH = 900.0  # Commercial passenger aircraft velocity threshold
    MIN_DISTANCE_KM = 50.0            # Minimum distance to filter intra-city cellular/ISP bouncing
    MIN_TIME_SECONDS = 60             # Minimum elapsed seconds threshold

    @classmethod
    def evaluate_event_location(
        cls,
        user_id: int,
        client_ip: Optional[str] = None,
        location_payload: Optional[Dict[str, Any]] = None,
        event_type: str = "TRANSACTION",
        event_id: Optional[str] = None,
        reference_time: Optional[datetime] = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluate geographic location for an authenticated event and compute impossible travel.

        Enforces strict point-in-time querying (created_at < reference_time) to eliminate data leakage.
        """
        ref_time = reference_time or datetime.now(timezone.utc)
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        payload = location_payload or {}
        provider = get_geo_provider()

        # 1. Resolve Coarse Geographic Data
        geo_data: GeoData = provider.resolve(
            ip_address=client_ip or payload.get("client_ip"),
            city_hint=payload.get("city") or payload.get("location_city"),
            region_hint=payload.get("region") or payload.get("state"),
            country_hint=payload.get("country") or payload.get("country_code"),
            lat_hint=payload.get("latitude") or payload.get("lat"),
            lon_hint=payload.get("longitude") or payload.get("lon"),
        )

        ip_hash = compute_ip_hash(client_ip or "127.0.0.1")

        # 2. Retrieve Strictly Prior Location for this Customer (No Future Data Leakage)
        prior_record = (
            GeoLocationRecord.query.filter(
                GeoLocationRecord.user_id == user_id,
                GeoLocationRecord.created_at <= ref_time,
            )
            .order_by(GeoLocationRecord.created_at.desc(), GeoLocationRecord.id.desc())
            .first()
        )

        # 3. Calculate Geodesic Distance & Travel Physics
        distance_km = 0.0
        elapsed_seconds = 0.0
        speed_kmh = 0.0
        is_impossible = False
        is_rapid_geo_change = False
        is_unusual_location = False

        if prior_record:
            distance_km = haversine_distance(
                prior_record.latitude,
                prior_record.longitude,
                geo_data.latitude,
                geo_data.longitude,
            )

            # Calculate elapsed time in seconds
            prior_created = prior_record.created_at
            if prior_created.tzinfo is None:
                prior_created = prior_created.replace(tzinfo=timezone.utc)

            elapsed_seconds = max(0.0, (ref_time - prior_created).total_seconds())

            # Evaluate distance thresholds
            if distance_km >= cls.MIN_DISTANCE_KM:
                if elapsed_seconds <= 0.0:
                    is_impossible = True
                    speed_kmh = 9999.0
                else:
                    speed_kmh = round(distance_km / (elapsed_seconds / 3600.0), 1)
                    if speed_kmh > cls.MAX_COMMERCIAL_SPEED_KMH:
                        is_impossible = True
                        if elapsed_seconds < cls.MIN_TIME_SECONDS:
                            is_rapid_geo_change = True

            # 4. Evaluate Customer Geographic Baseline & Familiarity
            historical_cities = [
                r[0]
                for r in db.session.query(GeoLocationRecord.city)
                .filter(
                    GeoLocationRecord.user_id == user_id,
                    GeoLocationRecord.created_at < ref_time,
                )
                .distinct()
                .all()
            ]

            if len(historical_cities) >= 2 and geo_data.city not in historical_cities:
                is_unusual_location = True
        else:
            # First location recorded for customer
            is_impossible = False
            is_unusual_location = False

        # 5. Persist Immutable Record if Requested
        saved_record = None
        if persist:
            saved_record = GeoLocationRecord(
                user_id=user_id,
                event_type=event_type,
                event_id=event_id,
                ip_hash=ip_hash,
                city=geo_data.city,
                region=geo_data.region,
                country_code=geo_data.country_code,
                timezone=geo_data.timezone,
                latitude=geo_data.latitude,
                longitude=geo_data.longitude,
                is_impossible_travel=is_impossible,
                is_unusual_location=is_unusual_location,
                distance_from_last_km=distance_km if prior_record else None,
                speed_from_last_kmh=speed_kmh if prior_record else None,
                created_at=ref_time,
            )
            db.session.add(saved_record)
            db.session.commit()

            # Record Audit Events
            user = db.session.get(User, user_id)
            user_email = user.email if user else f"User:{user_id}"

            AuditService.log_event(
                event_type="GEO_LOCATION_RECORDED",
                actor=user_email,
                action=f"{event_type}_LOCATION_EVALUATION",
                result="SUCCESS",
                user_id=user_id,
                target_resource=f"GeoLocationRecord:{saved_record.id}",
                severity="INFO",
                details={
                    "city": geo_data.city,
                    "country": geo_data.country_code,
                    "event_type": event_type,
                },
            )

            if is_impossible:
                AuditService.log_event(
                    event_type="IMPOSSIBLE_TRAVEL_DETECTED",
                    actor=user_email,
                    action="GEO_PHYSICS_ANOMALY",
                    result="FLAGGED",
                    user_id=user_id,
                    target_resource=f"GeoLocationRecord:{saved_record.id}",
                    severity="CRITICAL",
                    details={
                        "city": geo_data.city,
                        "prior_city": prior_record.city if prior_record else "Unknown",
                        "distance_km": distance_km,
                        "elapsed_seconds": elapsed_seconds,
                        "speed_kmh": speed_kmh,
                    },
                )
            elif is_unusual_location:
                AuditService.log_event(
                    event_type="NEW_LOCATION_DETECTED",
                    actor=user_email,
                    action="GEO_BASELINE_ANOMALY",
                    result="FLAGGED",
                    user_id=user_id,
                    target_resource=f"GeoLocationRecord:{saved_record.id}",
                    severity="WARN",
                    details={"city": geo_data.city, "country": geo_data.country_code},
                )

        return {
            "record_id": saved_record.id if saved_record else None,
            "city": geo_data.city,
            "region": geo_data.region,
            "country_code": geo_data.country_code,
            "timezone": geo_data.timezone,
            "latitude": geo_data.latitude,
            "longitude": geo_data.longitude,
            "distance_km": distance_km,
            "elapsed_seconds": elapsed_seconds,
            "speed_kmh": speed_kmh,
            "is_impossible_travel": is_impossible,
            "is_unusual_location": is_unusual_location,
            "is_rapid_geo_change": is_rapid_geo_change,
        }

    @classmethod
    def get_user_locations(cls, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve customer-safe chronological location history (IDOR protected)."""
        records = (
            GeoLocationRecord.query.filter_by(user_id=user_id)
            .order_by(GeoLocationRecord.created_at.desc())
            .limit(limit)
            .all()
        )
        return [r.to_dict(include_admin=False) for r in records]

    @classmethod
    def get_user_location_summary(cls, user_id: int) -> Dict[str, Any]:
        """Generate geographic baseline profile summary for customer profile."""
        total_events = GeoLocationRecord.query.filter_by(user_id=user_id).count()
        recent_record = (
            GeoLocationRecord.query.filter_by(user_id=user_id)
            .order_by(GeoLocationRecord.created_at.desc())
            .first()
        )

        distinct_cities = [
            r[0]
            for r in db.session.query(GeoLocationRecord.city)
            .filter_by(user_id=user_id)
            .distinct()
            .all()
        ]

        # Find top most frequent city
        top_city_query = (
            db.session.query(
                GeoLocationRecord.city,
                func.count(GeoLocationRecord.id).label("city_count"),
            )
            .filter_by(user_id=user_id)
            .group_by(GeoLocationRecord.city)
            .order_by(func.count(GeoLocationRecord.id).desc())
            .first()
        )
        primary_city = top_city_query[0] if top_city_query else "Unknown"

        return {
            "total_location_events": total_events,
            "distinct_cities_count": len(distinct_cities),
            "recognized_cities": distinct_cities,
            "primary_home_city": primary_city,
            "last_active_city": recent_record.city if recent_record else None,
            "last_active_country": recent_record.country_code if recent_record else None,
            "last_active_at": recent_record.created_at.isoformat() if recent_record else None,
        }

    @classmethod
    def get_admin_customer_locations(cls, customer_id: int, limit: int = 100) -> Dict[str, Any]:
        """Admin/SOC query for complete customer geographic telemetry with distance metrics."""
        records = (
            GeoLocationRecord.query.filter_by(user_id=customer_id)
            .order_by(GeoLocationRecord.created_at.desc())
            .limit(limit)
            .all()
        )

        impossible_count = sum(1 for r in records if r.is_impossible_travel)
        unusual_count = sum(1 for r in records if r.is_unusual_location)

        return {
            "customer_id": customer_id,
            "total_events": len(records),
            "impossible_travel_events": impossible_count,
            "unusual_location_events": unusual_count,
            "locations": [r.to_dict(include_admin=True) for r in records],
        }
