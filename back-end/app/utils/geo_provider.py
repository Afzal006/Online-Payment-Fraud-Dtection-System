"""
Geolocation Provider Abstraction and Geodesic Mathematics.

Provides spherical Haversine distance calculations and pluggable geographic resolution
for client IP addresses and location telemetry.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import math
from typing import Optional, Dict, Any


@dataclass
class GeoData:
    """Standardized coarse geographic entity."""
    city: str
    region: str
    country_code: str
    timezone: str
    latitude: float
    longitude: float


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great-circle distance between two points on the Earth's surface
    using the spherical Haversine formula.

    Parameters:
        lat1, lon1: Latitude and longitude of point 1 in degrees
        lat2, lon2: Latitude and longitude of point 2 in degrees

    Returns:
        Distance in kilometers (km)
    """
    # Defensive coordinate bounds clipping
    lat1 = max(-90.0, min(90.0, float(lat1)))
    lat2 = max(-90.0, min(90.0, float(lat2)))
    lon1 = max(-180.0, min(180.0, float(lon1)))
    lon2 = max(-180.0, min(180.0, float(lon2)))

    # If coordinates are virtually identical, distance is 0.0
    if abs(lat1 - lat2) < 1e-6 and abs(lon1 - lon2) < 1e-6:
        return 0.0

    # Mean Earth radius in kilometers
    earth_radius_km = 6371.0

    # Convert decimal degrees to radians
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    # Haversine formula
    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    # Clamp 'a' to [0, 1] to prevent domain errors with math.sqrt
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return round(earth_radius_km * c, 2)


class GeoLocationProvider(ABC):
    """Abstract interface for IP and location telemetry resolution."""

    @abstractmethod
    def resolve(
        self,
        ip_address: Optional[str] = None,
        city_hint: Optional[str] = None,
        region_hint: Optional[str] = None,
        country_hint: Optional[str] = None,
        lat_hint: Optional[float] = None,
        lon_hint: Optional[float] = None,
    ) -> GeoData:
        """Resolve geographic metadata from IP or telemetry hints."""
        pass


class MockGeoLocationProvider(GeoLocationProvider):
    """
    Deterministic development and testing provider.

    Maps common city names, country codes, and IP subnet conventions to standard coordinates.
    """

    KNOWN_HUBS: Dict[str, GeoData] = {
        # Major Indian Cities
        "bengaluru": GeoData("Bengaluru", "Karnataka", "IN", "Asia/Kolkata", 12.97, 77.59),
        "bangalore": GeoData("Bengaluru", "Karnataka", "IN", "Asia/Kolkata", 12.97, 77.59),
        "chennai": GeoData("Chennai", "Tamil Nadu", "IN", "Asia/Kolkata", 13.08, 80.27),
        "mumbai": GeoData("Mumbai", "Maharashtra", "IN", "Asia/Kolkata", 19.08, 72.88),
        "delhi": GeoData("Delhi", "Delhi", "IN", "Asia/Kolkata", 28.61, 77.21),
        "new delhi": GeoData("Delhi", "Delhi", "IN", "Asia/Kolkata", 28.61, 77.21),
        "hyderabad": GeoData("Hyderabad", "Telangana", "IN", "Asia/Kolkata", 17.38, 78.49),
        "kolkata": GeoData("Kolkata", "West Bengal", "IN", "Asia/Kolkata", 22.57, 88.36),
        "pune": GeoData("Pune", "Maharashtra", "IN", "Asia/Kolkata", 18.52, 73.86),

        # Global Major Hubs
        "london": GeoData("London", "England", "GB", "Europe/London", 51.51, -0.13),
        "new york": GeoData("New York", "New York", "US", "America/New_York", 40.71, -74.01),
        "dubai": GeoData("Dubai", "Dubai", "AE", "Asia/Dubai", 25.20, 55.27),
        "singapore": GeoData("Singapore", "Singapore", "SG", "Asia/Singapore", 1.35, 103.82),
        "tokyo": GeoData("Tokyo", "Tokyo", "JP", "Asia/Tokyo", 35.68, 139.69),
        "sydney": GeoData("Sydney", "New South Wales", "AU", "Australia/Sydney", -33.87, 151.21),
    }

    KNOWN_IP_PREFIXES: Dict[str, str] = {
        "103.": "bengaluru",
        "49.": "mumbai",
        "106.": "delhi",
        "82.": "london",
        "198.": "new york",
        "185.": "dubai",
    }

    def resolve(
        self,
        ip_address: Optional[str] = None,
        city_hint: Optional[str] = None,
        region_hint: Optional[str] = None,
        country_hint: Optional[str] = None,
        lat_hint: Optional[float] = None,
        lon_hint: Optional[float] = None,
    ) -> GeoData:
        """Resolve IP and hints into deterministic GeoData."""
        # 1. Check explicit city hint
        if city_hint:
            clean_city = str(city_hint).strip().lower()
            if clean_city in self.KNOWN_HUBS:
                return self.KNOWN_HUBS[clean_city]

        # 2. Check explicit coordinates
        if lat_hint is not None and lon_hint is not None:
            try:
                lat = round(float(lat_hint), 2)
                lon = round(float(lon_hint), 2)
                return GeoData(
                    city=city_hint or "Custom Location",
                    region=region_hint or "Unknown",
                    country_code=country_hint or "IN",
                    timezone="Asia/Kolkata",
                    latitude=lat,
                    longitude=lon,
                )
            except (ValueError, TypeError):
                pass

        # 3. Check IP Address prefix
        if ip_address:
            clean_ip = str(ip_address).strip()
            for prefix, hub_key in self.KNOWN_IP_PREFIXES.items():
                if clean_ip.startswith(prefix):
                    return self.KNOWN_HUBS[hub_key]

        # 4. Default baseline (Bengaluru, India)
        return self.KNOWN_HUBS["bengaluru"]


# Global Singleton Provider Instance
_geo_provider_instance: Optional[GeoLocationProvider] = None


def get_geo_provider() -> GeoLocationProvider:
    """Retrieve global Geolocation Provider instance."""
    global _geo_provider_instance
    if _geo_provider_instance is None:
        _geo_provider_instance = MockGeoLocationProvider()
    return _geo_provider_instance
