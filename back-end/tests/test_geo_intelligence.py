"""
Test Suite for Geo Intelligence, Impossible Travel Detection, and Device-Geo Correlation (Phase 3 Milestone 3).
"""

from datetime import datetime, timezone, timedelta
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.geo_location_record import GeoLocationRecord
from app.models.device_profile import DeviceProfile
from app.models.audit_log import AuditLog
from app.utils.geo_provider import haversine_distance, get_geo_provider
from app.services.geo_intelligence_service import GeoIntelligenceService
from app.services.risk_signal_service import RiskSignalService
from app.services.risk_service import RiskDecisionService
from app.services.device_trust_service import DeviceTrustService


@pytest.fixture
def app_instance():
    """Create test application instance with in-memory SQLite database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


@pytest.fixture
def test_user(app_instance):
    """Create standard customer user."""
    user = User(
        name="Geo Customer",
        email="geo_customer@example.com",
        role="USER",
        account_balance=100000.0,
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
    )
    user.set_password("SecurePassword123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def second_user(app_instance):
    """Create second customer for tenant boundary verification."""
    user = User(
        name="Second Geo Customer",
        email="second_geo@example.com",
        role="USER",
        account_balance=50000.0,
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
    )
    user.set_password("SecurePassword123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def admin_user(app_instance):
    """Create admin user."""
    admin = User(
        name="SOC Geo Admin",
        email="soc_geo_admin@fraudshield.com",
        role="ADMIN",
        is_email_verified=True,
        is_phone_verified=True,
        is_active=True,
        account_status="ACTIVE",
    )
    admin.set_password("AdminSecurePassword123!")
    db.session.add(admin)
    db.session.commit()
    return admin


@pytest.fixture
def user_token(client, test_user):
    res = client.post("/api/auth/login", json={
        "email": test_user.email,
        "password": "SecurePassword123!",
    })
    return res.get_json()["access_token"]


@pytest.fixture
def admin_token(client, admin_user):
    res = client.post("/api/auth/login", json={
        "email": admin_user.email,
        "password": "AdminSecurePassword123!",
    })
    return res.get_json()["access_token"]


# ==============================================================================
# 1. Haversine Distance & Provider Unit Tests
# ==============================================================================

def test_haversine_distance_calculations():
    """Verify spherical distance accuracy on major global hubs."""
    # Bengaluru (12.97, 77.59) -> Chennai (13.08, 80.27) ~ 290 km
    d_blr_maa = haversine_distance(12.97, 77.59, 13.08, 80.27)
    assert 270.0 <= d_blr_maa <= 310.0

    # Mumbai (19.08, 72.88) -> Delhi (28.61, 77.21) ~ 1148 km
    d_bom_del = haversine_distance(19.08, 72.88, 28.61, 77.21)
    assert 1100.0 <= d_bom_del <= 1200.0

    # London (51.51, -0.13) -> New York (40.71, -74.01) ~ 5570 km
    d_lon_nyc = haversine_distance(51.51, -0.13, 40.71, -74.01)
    assert 5500.0 <= d_lon_nyc <= 5650.0

    # Identical coordinates -> 0.0 km
    d_same = haversine_distance(12.97, 77.59, 12.97, 77.59)
    assert d_same == 0.0


def test_mock_geo_provider_resolution():
    """Verify deterministic provider lookup across city hints and IPs."""
    provider = get_geo_provider()

    # City hint
    blr = provider.resolve(city_hint="Bengaluru")
    assert blr.city == "Bengaluru"
    assert blr.country_code == "IN"

    # London
    lon = provider.resolve(city_hint="London")
    assert lon.city == "London"
    assert lon.country_code == "GB"

    # Unknown IP fallback
    fallback = provider.resolve(ip_address="127.0.0.1")
    assert fallback.city == "Bengaluru"


# ==============================================================================
# 2. Impossible Travel Engine Physics Tests
# ==============================================================================

def test_first_ever_location_registration(test_user):
    """Verify first event for customer creates baseline with zero distance/speed."""
    now = datetime.now(timezone.utc)
    res = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        event_type="LOGIN",
        reference_time=now,
        persist=True,
    )
    assert res["is_impossible_travel"] is False
    assert res["is_unusual_location"] is False
    assert res["distance_km"] == 0.0


def test_same_city_repeated_transactions(test_user):
    """Verify repeated transactions in same city produce zero distance and no anomaly."""
    t1 = datetime.now(timezone.utc) - timedelta(minutes=10)
    t2 = datetime.now(timezone.utc)

    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=t1,
        persist=True,
    )

    res2 = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=t2,
        persist=True,
    )
    assert res2["is_impossible_travel"] is False
    assert res2["is_unusual_location"] is False
    assert res2["distance_km"] == 0.0


def test_legitimate_travel_with_sufficient_elapsed_time(test_user):
    """Verify realistic travel (Bengaluru to Chennai in 5 hours) is approved without impossible travel flag."""
    t1 = datetime.now(timezone.utc) - timedelta(hours=5)
    t2 = datetime.now(timezone.utc)

    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=t1,
        persist=True,
    )

    res2 = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Chennai"},
        reference_time=t2,
        persist=True,
    )
    assert res2["is_impossible_travel"] is False
    assert res2["speed_kmh"] < 100.0  # ~58 km/h


def test_impossible_travel_cross_continent(test_user):
    """Verify impossible travel detection (Bengaluru to London in 20 minutes: ~22,500 km/h)."""
    t1 = datetime.now(timezone.utc) - timedelta(minutes=20)
    t2 = datetime.now(timezone.utc)

    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=t1,
        persist=True,
    )

    res2 = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "London"},
        reference_time=t2,
        persist=True,
    )
    assert res2["is_impossible_travel"] is True
    assert res2["speed_kmh"] > 900.0


def test_intra_city_jitter_suppression(test_user):
    """Verify distance < 50 km (e.g. coarse intra-city coordinate shifts) does not trigger impossible travel."""
    t1 = datetime.now(timezone.utc) - timedelta(seconds=10)
    t2 = datetime.now(timezone.utc)

    # 10 km shift within Bengaluru area
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"latitude": 12.97, "longitude": 77.59},
        reference_time=t1,
        persist=True,
    )

    res2 = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"latitude": 13.00, "longitude": 77.62},  # ~4.6 km shift
        reference_time=t2,
        persist=True,
    )
    assert res2["is_impossible_travel"] is False
    assert res2["distance_km"] < 50.0


def test_zero_elapsed_time_handling(test_user):
    """Verify simultaneous/zero-elapsed-time events across distant cities trigger impossible travel."""
    now = datetime.now(timezone.utc)

    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=now - timedelta(seconds=1),
        persist=True,
    )

    res2 = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Delhi"},
        reference_time=now - timedelta(seconds=1),  # Identical timestamp
        persist=True,
    )
    assert res2["is_impossible_travel"] is True


def test_unusual_location_baseline_detection(test_user):
    """Verify unusual location flag when customer with established baseline initiates payment from new hub."""
    t1 = datetime.now(timezone.utc) - timedelta(days=2)
    t2 = datetime.now(timezone.utc) - timedelta(days=1)
    t3 = datetime.now(timezone.utc)

    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Bengaluru"}, reference_time=t1, persist=True
    )
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Chennai"}, reference_time=t2, persist=True
    )

    res3 = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "London"}, reference_time=t3, persist=True
    )
    assert res3["is_unusual_location"] is True


def test_point_in_time_data_leakage_protection(test_user):
    """Verify historical queries only see records created strictly before the reference timestamp."""
    past_time = datetime.now(timezone.utc) - timedelta(hours=2)
    future_time = datetime.now(timezone.utc) + timedelta(hours=2)

    # Insert a future record
    future_rec = GeoLocationRecord(
        user_id=test_user.id,
        city="Tokyo",
        region="Tokyo",
        country_code="JP",
        ip_hash="future_hash",
        latitude=35.68,
        longitude=139.69,
        created_at=future_time,
    )
    db.session.add(future_rec)
    db.session.commit()

    # Query at past_time -> Tokyo must NOT exist in prior history
    res = GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=past_time,
        persist=False,
    )
    assert res["distance_km"] == 0.0
    assert res["is_impossible_travel"] is False


# ==============================================================================
# 3. Risk Signals & Hybrid Decision Engine Integration
# ==============================================================================

def test_impossible_travel_signal_triggers_floor_60():
    """Verify IMPOSSIBLE_TRAVEL signal triggers +35 weight and enforces a minimum floor of 60."""
    features = {
        "amount": 500.0,
        "tx_type": "PAYMENT",
        "is_impossible_travel": 1,
        "geo_distance_km": 7500.0,
        "geo_elapsed_seconds": 1200.0,
        "geo_speed_kmh": 22500.0,
    }
    signals = RiskSignalService.evaluate_signals(features)
    codes = [s["code"] for s in signals]
    assert "IMPOSSIBLE_TRAVEL" in codes

    imp_sig = next(s for s in signals if s["code"] == "IMPOSSIBLE_TRAVEL")
    assert imp_sig["weight"] == 35
    assert imp_sig["severity"] == "CRITICAL"

    # Evaluate hybrid risk: even for small amount, final score must be >= 60 (High Tier / OTP)
    hybrid = RiskDecisionService.evaluate_hybrid_risk(
        ml_fraud_prob=0.05,
        amount=500.0,
        tx_type="PAYMENT",
        features=features,
    )
    assert hybrid["risk_score"] >= 60
    assert hybrid["risk_level"] in ["HIGH", "CRITICAL"]
    assert hybrid["requires_otp"] is True


def test_device_plus_geo_correlation_elevation(client, user_token, test_user):
    """Verify Unknown Device + Impossible Travel significantly elevates transaction risk."""
    t1 = datetime.now(timezone.utc) - timedelta(minutes=10)

    # Establish previous location in Bengaluru
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id,
        location_payload={"city": "Bengaluru"},
        reference_time=t1,
        persist=True,
    )

    # Transaction from London on a new device header
    res = client.post(
        "/api/transactions/predict",
        headers={
            "Authorization": f"Bearer {user_token}",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605.1.15",
            "X-Device-Fingerprint": "new_random_device_id_999",
            "X-Client-City": "London",
            "X-Client-Country": "GB",
        },
        json={
            "type": "PAYMENT",
            "amount": 2500.0,
            "destination": "merchant@fraudshield",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["requires_otp"] is True

    # Customer safe explanation must mention anomalous location or verification
    assert "location" in data["explanation"]["customer_explanation"].lower() or "verification" in data["explanation"]["customer_explanation"].lower()


def test_blocked_device_remains_authoritative_over_geo(client, user_token, test_user):
    """Verify blocked device rejects transaction immediately regardless of legitimate location."""
    ua_blocked = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/128.0.0.0"

    dev, _, _ = DeviceTrustService.evaluate_or_register_device(
        user_id=test_user.id,
        user_agent=ua_blocked,
    )
    dev.trust_status = "BLOCKED"
    dev.is_active = False
    db.session.commit()

    res = client.post(
        "/api/transactions/predict",
        headers={
            "Authorization": f"Bearer {user_token}",
            "User-Agent": ua_blocked,
            "X-Client-City": "Bengaluru",  # Normal home city
        },
        json={"type": "PAYMENT", "amount": 100.0, "destination": "merchant@fraudshield"},
    )
    assert res.status_code == 403
    assert "blocked" in res.get_json()["error"].lower()


# ==============================================================================
# 4. Customer & Admin API Endpoint Tests
# ==============================================================================

def test_customer_get_locations_and_idor_protection(client, user_token, test_user, second_user):
    """Verify customer can view only their own location history and not another user's."""
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Bengaluru"}, persist=True
    )
    GeoIntelligenceService.evaluate_event_location(
        user_id=second_user.id, location_payload={"city": "Delhi"}, persist=True
    )

    res = client.get(
        "/api/profile/locations",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] >= 1

    # Ensure no data from second_user
    for loc in data["locations"]:
        assert loc["city"] == "Bengaluru"
        assert "latitude" not in loc  # Coordinates redacted for customer
        assert "ip_hash" not in loc   # IP hash redacted for customer


def test_customer_get_location_summary(client, user_token, test_user):
    """Verify customer location summary returns recognized cities and primary home city."""
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Bengaluru"}, persist=True
    )
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Bengaluru"}, persist=True
    )
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Chennai"}, persist=True
    )

    res = client.get(
        "/api/profile/locations/summary",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["summary"]["primary_home_city"] == "Bengaluru"
    assert data["summary"]["distinct_cities_count"] == 2


def test_admin_get_customer_locations(client, admin_token, test_user):
    """Verify admin can view complete customer location history with speed and distance telemetry."""
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Bengaluru"}, persist=True
    )

    res = client.get(
        f"/api/admin/customers/{test_user.id}/locations",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["customer_id"] == test_user.id
    assert "locations" in data
    assert "latitude" in data["locations"][0]
    assert "ip_hash" in data["locations"][0]


# ==============================================================================
# 5. Audit Logging Verification
# ==============================================================================

def test_geo_audit_logging_events(client, test_user):
    """Verify GEO_LOCATION_RECORDED and IMPOSSIBLE_TRAVEL_DETECTED audit logs."""
    t1 = datetime.now(timezone.utc) - timedelta(minutes=15)
    t2 = datetime.now(timezone.utc)

    # 1. Normal location login
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "Bengaluru"}, reference_time=t1, persist=True
    )
    rec_log = AuditLog.query.filter_by(event_type="GEO_LOCATION_RECORDED").first()
    assert rec_log is not None
    assert rec_log.actor == test_user.email

    # 2. Impossible travel event
    GeoIntelligenceService.evaluate_event_location(
        user_id=test_user.id, location_payload={"city": "London"}, reference_time=t2, persist=True
    )
    imp_log = AuditLog.query.filter_by(event_type="IMPOSSIBLE_TRAVEL_DETECTED").first()
    assert imp_log is not None
    assert imp_log.severity == "CRITICAL"
