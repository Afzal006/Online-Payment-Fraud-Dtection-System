"""
Device Telemetry and Privacy-Conscious Fingerprint Utilities.

Generates pseudonymized device hashes from safe client telemetry without collecting
PII or sensitive authentication secrets.
"""

import hashlib
from typing import Dict, Any, Optional


def parse_user_agent(user_agent: Optional[str]) -> Dict[str, str]:
    """
    Parse a User-Agent string into normalized device, browser, and OS components.
    """
    if not user_agent or not isinstance(user_agent, str):
        return {
            "device_type": "Desktop",
            "browser": "Unknown",
            "operating_system": "Unknown",
        }

    ua_lower = user_agent.lower()

    # 1. Operating System Detection (check mobile Apple before desktop Mac)
    os_name = "Unknown"
    if "iphone" in ua_lower or "ipad" in ua_lower or "ipod" in ua_lower or "ios" in ua_lower:
        os_name = "iOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "windows" in ua_lower:
        os_name = "Windows"
    elif "macintosh" in ua_lower or "mac os x" in ua_lower or "mac_powerpc" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"

    # 2. Device Type Detection
    device_type = "Desktop"
    if "ipad" in ua_lower or "tablet" in ua_lower:
        device_type = "Tablet"
    elif "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
        device_type = "Mobile"

    # 3. Browser Detection (order matters due to UA token overlap)
    browser_name = "Unknown"
    if "edg/" in ua_lower or "edge/" in ua_lower:
        browser_name = "Edge"
    elif "opr/" in ua_lower or "opera" in ua_lower:
        browser_name = "Opera"
    elif "chrome/" in ua_lower and "chromium" not in ua_lower:
        browser_name = "Chrome"
    elif "firefox/" in ua_lower:
        browser_name = "Firefox"
    elif "safari/" in ua_lower and "chrome" not in ua_lower:
        browser_name = "Safari"

    return {
        "device_type": device_type,
        "browser": browser_name,
        "operating_system": os_name,
    }


def compute_device_hash(
    user_agent: Optional[str],
    client_telemetry: Optional[Dict[str, Any]] = None,
    client_device_id: Optional[str] = None,
) -> str:
    """
    Compute a deterministic SHA-256 device identifier from safe telemetry attributes.

    Never incorporates passwords, OTPs, or financial secrets.
    """
    normalized_ua = (user_agent or "UnknownUserAgent").strip()
    telemetry = client_telemetry or {}

    # Extract non-sensitive display & environment tokens
    screen_res = str(telemetry.get("screen", "1920x1080")).strip()
    tz = str(telemetry.get("timezone", "UTC")).strip()
    lang = str(telemetry.get("language", "en")).strip()
    canvas_token = str(telemetry.get("canvas_token", "")).strip()

    # Combine into canonical fingerprint string
    canonical_components = [
        f"ua={normalized_ua}",
        f"res={screen_res}",
        f"tz={tz}",
        f"lang={lang}",
    ]

    if client_device_id:
        canonical_components.append(f"client_id={client_device_id.strip()}")

    if canvas_token:
        canonical_components.append(f"canvas={canvas_token}")

    raw_signature = "|".join(canonical_components)
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()


def compute_ip_hash(ip_address: Optional[str]) -> str:
    """Compute privacy-preserving SHA-256 hash of client IP address."""
    if not ip_address:
        return hashlib.sha256(b"127.0.0.1").hexdigest()
    return hashlib.sha256(ip_address.strip().encode("utf-8")).hexdigest()
