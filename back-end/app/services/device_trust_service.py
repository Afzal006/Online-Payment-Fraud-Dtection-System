"""
Device Trust and Identity Intelligence Service.

Manages device profile registration, continuous trust scoring, anomaly detection,
and administrative device governance.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, Any, List, Optional, Tuple
from app.extensions import db
from app.models.device_profile import DeviceProfile
from app.models.user import User
from app.utils.device_fingerprint import compute_device_hash, parse_user_agent, compute_ip_hash
from app.services.audit_service import AuditService

logger = logging.getLogger("fraudshield.device_trust")


class DeviceTrustService:
    """Service layer managing device registration, risk scoring, and trust states."""

    TRUST_STATES = {"TRUSTED", "SUSPICIOUS", "UNKNOWN", "BLOCKED"}

    @classmethod
    def evaluate_or_register_device(
        cls,
        user_id: int,
        user_agent: Optional[str] = None,
        client_ip: Optional[str] = None,
        client_telemetry: Optional[Dict[str, Any]] = None,
        client_device_id: Optional[str] = None,
    ) -> Tuple[DeviceProfile, str, bool]:
        """
        Identify or register a client device profile for the given user.

        Returns:
            (DeviceProfile, trust_status, is_new_device)
        """
        device_hash = compute_device_hash(
            user_agent=user_agent,
            client_telemetry=client_telemetry,
            client_device_id=client_device_id,
        )
        ip_hash = compute_ip_hash(client_ip)
        now = datetime.now(timezone.utc)

        # Check existing device registration for this user
        profile = DeviceProfile.query.filter_by(
            user_id=user_id,
            device_hash=device_hash,
        ).first()

        user = db.session.get(User, user_id)
        user_email = user.email if user else f"User:{user_id}"

        if not profile:
            # 1. New Unrecognized Device Registration
            parsed_ua = parse_user_agent(user_agent)
            profile = DeviceProfile(
                user_id=user_id,
                device_hash=device_hash,
                device_type=parsed_ua["device_type"],
                browser=parsed_ua["browser"],
                operating_system=parsed_ua["operating_system"],
                trust_status="UNKNOWN",
                last_ip_hash=ip_hash,
                failed_login_count=0,
                successful_login_count=0,
                first_seen_at=now,
                last_seen_at=now,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            db.session.add(profile)
            db.session.commit()

            # Record Audit Events
            AuditService.log_event(
                event_type="DEVICE_REGISTERED",
                actor=user_email,
                action="DEVICE_IDENTIFICATION",
                result="SUCCESS",
                user_id=user_id,
                target_resource=f"DeviceProfile:{profile.id}",
                severity="INFO",
                details={
                    "device_id": profile.id,
                    "device_type": profile.device_type,
                    "browser": profile.browser,
                    "operating_system": profile.operating_system,
                    "trust_status": "UNKNOWN",
                },
            )

            AuditService.log_event(
                event_type="UNKNOWN_DEVICE_LOGIN",
                actor=user_email,
                action="DEVICE_RISK_EVALUATION",
                result="FLAGGED",
                user_id=user_id,
                target_resource=f"DeviceProfile:{profile.id}",
                severity="WARN",
                details={
                    "device_id": profile.id,
                    "message": "Unrecognized device detected for customer account",
                },
            )

            return profile, "UNKNOWN", True

        # 2. Existing Device Profile Evaluation
        profile.last_seen_at = now
        profile.last_ip_hash = ip_hash

        # Blocked check
        if not profile.is_active or profile.trust_status == "BLOCKED":
            profile.trust_status = "BLOCKED"
            db.session.commit()
            return profile, "BLOCKED", False

        # Suspicious check based on failed login burst
        if profile.failed_login_count >= 5 and profile.trust_status != "BLOCKED":
            if profile.trust_status != "SUSPICIOUS":
                profile.trust_status = "SUSPICIOUS"
                AuditService.log_event(
                    event_type="DEVICE_TRUST_CHANGED",
                    actor="SYSTEM",
                    action="DEVICE_ANOMALY_DETECTION",
                    result="FLAGGED",
                    user_id=user_id,
                    target_resource=f"DeviceProfile:{profile.id}",
                    severity="WARN",
                    details={"device_id": profile.id, "new_trust_status": "SUSPICIOUS", "reason": "Failed login threshold exceeded"},
                )

        db.session.commit()
        return profile, profile.trust_status, False

    @classmethod
    def record_login_attempt(cls, profile_id: int, success: bool) -> Optional[DeviceProfile]:
        """Update login statistics and evaluate automatic trust transitions."""
        profile = db.session.get(DeviceProfile, profile_id)
        if not profile:
            return None

        now = datetime.now(timezone.utc)
        profile.last_seen_at = now

        user = db.session.get(User, profile.user_id)
        user_email = user.email if user else f"User:{profile.user_id}"

        if success:
            profile.successful_login_count += 1
            profile.failed_login_count = 0  # Reset failed count on successful auth

            # Promotion: UNKNOWN -> TRUSTED after 2 successful logins
            if profile.trust_status == "UNKNOWN" and profile.successful_login_count >= 2:
                profile.trust_status = "TRUSTED"
                AuditService.log_event(
                    event_type="DEVICE_TRUST_CHANGED",
                    actor="SYSTEM",
                    action="AUTOMATIC_TRUST_PROMOTION",
                    result="SUCCESS",
                    user_id=profile.user_id,
                    target_resource=f"DeviceProfile:{profile.id}",
                    severity="INFO",
                    details={"device_id": profile.id, "new_trust_status": "TRUSTED"},
                )
            elif profile.trust_status == "SUSPICIOUS" and profile.successful_login_count >= 3:
                # Re-promote after sustained genuine activity
                profile.trust_status = "TRUSTED"
        else:
            profile.failed_login_count += 1

            # Demotion: TRUSTED -> SUSPICIOUS after 3 failed logins
            if profile.trust_status == "TRUSTED" and profile.failed_login_count >= 3:
                profile.trust_status = "SUSPICIOUS"
                AuditService.log_event(
                    event_type="DEVICE_TRUST_CHANGED",
                    actor="SYSTEM",
                    action="AUTOMATIC_TRUST_DEMOTION",
                    result="FLAGGED",
                    user_id=profile.user_id,
                    target_resource=f"DeviceProfile:{profile.id}",
                    severity="WARN",
                    details={"device_id": profile.id, "new_trust_status": "SUSPICIOUS"},
                )
            elif profile.failed_login_count >= 10:
                profile.trust_status = "BLOCKED"
                AuditService.log_event(
                    event_type="DEVICE_BLOCKED",
                    actor="SYSTEM",
                    action="BRUTE_FORCE_LOCKOUT",
                    result="DENIED",
                    user_id=profile.user_id,
                    target_resource=f"DeviceProfile:{profile.id}",
                    severity="CRITICAL",
                    details={"device_id": profile.id, "reason": "10 consecutive failed logins"},
                )

        db.session.commit()
        return profile

    @classmethod
    def get_user_devices(cls, user_id: int) -> List[Dict[str, Any]]:
        """Retrieve all active registered devices for a customer account."""
        devices = (
            DeviceProfile.query.filter_by(user_id=user_id, is_active=True)
            .order_by(DeviceProfile.last_seen_at.desc())
            .all()
        )
        return [d.to_dict(include_admin=False) for d in devices]

    @classmethod
    def revoke_user_device(cls, user_id: int, device_id: int) -> Tuple[bool, Optional[str]]:
        """
        Deactivate/revoke a registered device with IDOR tenant isolation.
        """
        device = db.session.get(DeviceProfile, device_id)
        if not device:
            return False, "Device not found"

        if device.user_id != user_id:
            return False, "Forbidden: Access denied to this device"

        device.is_active = False
        device.trust_status = "UNKNOWN"
        db.session.commit()

        user = db.session.get(User, user_id)
        user_email = user.email if user else f"User:{user_id}"

        AuditService.log_event(
            event_type="DEVICE_REVOKED",
            actor=user_email,
            action="POST /api/profile/devices/revoke",
            result="SUCCESS",
            user_id=user_id,
            target_resource=f"DeviceProfile:{device.id}",
            severity="INFO",
            details={"device_id": device.id, "browser": device.browser, "os": device.operating_system},
        )

        return True, None

    @classmethod
    def admin_update_trust(
        cls,
        device_id: int,
        new_status: str,
        admin_identifier: str = "ADMIN",
        admin_id: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Admin/SOC update of device trust status."""
        status_clean = new_status.upper().strip()
        if status_clean not in cls.TRUST_STATES:
            return False, f"Invalid trust status. Allowed: {sorted(list(cls.TRUST_STATES))}"

        device = db.session.get(DeviceProfile, device_id)
        if not device:
            return False, "Device not found"

        old_status = device.trust_status
        device.trust_status = status_clean
        if status_clean == "BLOCKED":
            device.is_active = False
        else:
            device.is_active = True

        db.session.commit()

        AuditService.log_event(
            event_type="DEVICE_BLOCKED" if status_clean == "BLOCKED" else "DEVICE_TRUST_CHANGED",
            actor=admin_identifier,
            action=f"POST /api/admin/devices/{device_id}/trust",
            result="SUCCESS",
            user_id=admin_id,
            target_resource=f"DeviceProfile:{device.id}",
            severity="WARN" if status_clean in ["SUSPICIOUS", "BLOCKED"] else "INFO",
            details={"device_id": device.id, "old_status": old_status, "new_status": status_clean},
        )

        return True, None
