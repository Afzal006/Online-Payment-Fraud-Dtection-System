"""
UPI Payment Service.

Coordinates:
1. Standard UPI QR payload decoding (upi://pay?pa=...&pn=...&am=...&cu=INR)
2. Dynamic multi-identifier Recipient Resolution (UPI ID, 10-digit Mobile, QR, Saved Beneficiaries)
3. Secure Payment PIN management (hashing, attempt tracking, lockout)
"""

import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

from app.extensions import db
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.services.audit_service import AuditService

# Pre-configured simulated merchants for realistic payment demo
SIMULATED_MERCHANTS: Dict[str, Dict[str, Any]] = {
    "merchant@fraudshield": {
        "name": "SuperMart Retail POS",
        "category": "Retail & Groceries",
        "verified": True,
    },
    "coffee@fraudshield": {
        "name": "Artisan Coffee House",
        "category": "Food & Beverage",
        "verified": True,
    },
    "amazon@upi": {
        "name": "Amazon India Payments",
        "category": "E-Commerce",
        "verified": True,
    },
    "swiggy@upi": {
        "name": "Swiggy Food Delivery",
        "category": "Food Delivery",
        "verified": True,
    },
    "zomato@upi": {
        "name": "Zomato Online",
        "category": "Food Delivery",
        "verified": True,
    },
    "utility@upi": {
        "name": "National Power & Electricity",
        "category": "Utilities",
        "verified": True,
    },
}


class PaymentService:
    """Service layer managing UPI payloads, recipient identification, and payment PIN security."""

    UPI_ID_REGEX = re.compile(r"^[a-zA-Z0-9.\-_]{2,50}@[a-zA-Z0-9.\-_]{2,30}$")
    PHONE_REGEX = re.compile(r"^(\+91)?[6-9]\d{9}$")
    PIN_REGEX = re.compile(r"^\d{4,6}$")

    @classmethod
    def parse_upi_qr(cls, qr_data: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Parse and validate a standard UPI QR code URI string.
        Format: upi://pay?pa=recipient@upi&pn=Payee%20Name&am=500&cu=INR&tn=Note

        Returns:
            (is_valid, parsed_data, error_message)
        """
        if not qr_data or not isinstance(qr_data, str):
            return False, None, "Invalid or empty QR payload."

        clean_qr = qr_data.strip()

        # Handle UPI URL scheme
        if not clean_qr.startswith("upi://pay?") and not clean_qr.startswith("upi://pay"):
            # Check if raw UPI ID was provided
            if cls.UPI_ID_REGEX.match(clean_qr):
                return True, {
                    "pa": clean_qr,
                    "pn": clean_qr.split("@")[0].capitalize(),
                    "am": None,
                    "cu": "INR",
                    "tn": None,
                    "raw_uri": f"upi://pay?pa={clean_qr}&cu=INR",
                }, None
            return False, None, "Invalid QR scheme. Expected 'upi://pay?...' standard format."

        try:
            parsed_url = urllib.parse.urlparse(clean_qr)
            params = urllib.parse.parse_qs(parsed_url.query)

            # Payee VPA / UPI ID (Mandatory)
            pa_list = params.get("pa")
            if not pa_list or not pa_list[0].strip():
                return False, None, "QR code missing mandatory payee UPI address ('pa')."
            pa = pa_list[0].strip()

            if not cls.UPI_ID_REGEX.match(pa):
                return False, None, f"Invalid payee UPI ID format in QR: '{pa}'"

            # Payee Name
            pn_list = params.get("pn")
            pn = pn_list[0].strip() if pn_list and pn_list[0].strip() else pa.split("@")[0].capitalize()

            # Amount (Optional)
            amount = None
            am_list = params.get("am")
            if am_list and am_list[0].strip():
                try:
                    amount_val = float(am_list[0].strip())
                    if amount_val > 0:
                        amount = round(amount_val, 2)
                    else:
                        return False, None, "QR code amount must be greater than zero."
                except ValueError:
                    return False, None, "Invalid amount value in QR payload."

            # Currency (Optional, default INR)
            cu_list = params.get("cu")
            cu = cu_list[0].strip().upper() if cu_list and cu_list[0].strip() else "INR"
            if cu != "INR":
                return False, None, f"Unsupported currency '{cu}'. Only 'INR' is supported in UPI simulation."

            # Transaction Note (Optional)
            tn_list = params.get("tn")
            tn = tn_list[0].strip() if tn_list and tn_list[0].strip() else None

            return True, {
                "pa": pa,
                "pn": pn,
                "am": amount,
                "cu": cu,
                "tn": tn,
                "raw_uri": clean_qr,
            }, None

        except Exception as e:
            return False, None, f"Error parsing QR payload: {str(e)}"

    @classmethod
    def resolve_recipient(cls, current_user_id: int, query: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Dynamically resolve a payment recipient from UPI ID, 10-digit mobile number, or QR payload.

        Returns:
            (resolved: bool, recipient_data: Optional[Dict], error_message: Optional[str])
        """
        if not query or not isinstance(query, str) or not query.strip():
            return False, None, "Recipient identifier is required (UPI ID, mobile number, or QR data)."

        clean_query = query.strip()
        suggested_amount = None
        suggested_note = None

        # Check if query is a QR URI
        if clean_query.startswith("upi://pay"):
            is_valid_qr, qr_dict, qr_err = cls.parse_upi_qr(clean_query)
            if not is_valid_qr:
                return False, None, qr_err
            clean_query = qr_dict["pa"]
            suggested_amount = qr_dict.get("am")
            suggested_note = qr_dict.get("tn")

        current_user = db.session.get(User, current_user_id)
        if not current_user:
            return False, None, "Authenticated user not found."

        # Self-payment check
        if (
            (current_user.primary_upi_id and clean_query.lower() == current_user.primary_upi_id.lower())
            or (current_user.phone_number and clean_query == current_user.phone_number)
            or (current_user.email and clean_query.lower() == current_user.email.lower())
            or (current_user.customer_account_id and clean_query.upper() == current_user.customer_account_id.upper())
        ):
            return False, None, "Cannot transfer funds to your own account."

        # 1. Search Internal Registered Users
        user_match = None
        is_phone_query = False
        digits_only = re.sub(r"\D", "", clean_query)
        if len(digits_only) == 10:
            is_phone_query = True
            user_match = User.query.filter(
                (User.phone_number == digits_only) | (User.phone_number == f"+91{digits_only}")
            ).first()
        elif len(digits_only) == 12 and digits_only.startswith("91"):
            is_phone_query = True
            user_match = User.query.filter(
                (User.phone_number == digits_only[2:]) | (User.phone_number == f"+{digits_only}")
            ).first()

        if not user_match and not is_phone_query:
            user_match = User.query.filter(
                (User.primary_upi_id == clean_query)
                | (User.email == clean_query)
                | (User.customer_account_id == clean_query.upper())
            ).first()

        if user_match:
            if user_match.id == current_user_id:
                return False, None, "Cannot transfer funds to your own account."

            if not user_match.is_active:
                return False, None, "Recipient account is inactive or restricted."

            if is_phone_query and not user_match.is_phone_verified:
                return False, None, "User account is registered but pending mobile verification."

            # Check if this user is in saved beneficiaries
            beneficiary = Beneficiary.query.filter_by(
                user_id=current_user_id,
                beneficiary_upi_id=user_match.primary_upi_id,
            ).first()

            is_cooling = beneficiary.is_cooling_active() if beneficiary else False
            trust_status = beneficiary.get_effective_trust_status() if beneficiary else "NEW"

            return True, {
                "resolved": True,
                "recipient_id": user_match.id,
                "recipient_name": user_match.name,
                "recipient_upi_id": user_match.primary_upi_id or f"{user_match.name.lower().replace(' ', '')}@fraudshield",
                "recipient_phone": user_match.phone_number,
                "account_type": "INTERNAL_USER",
                "is_internal": True,
                "is_verified": bool(user_match.is_phone_verified),
                "is_saved_beneficiary": bool(beneficiary),
                "beneficiary_id": beneficiary.id if beneficiary else None,
                "trust_status": trust_status,
                "is_cooling_active": is_cooling,
                "suggested_amount": suggested_amount,
                "suggested_note": suggested_note,
            }, None

        # 2. Search Saved Beneficiaries Directory for current user
        ben_match = Beneficiary.query.filter_by(user_id=current_user_id).filter(
            (Beneficiary.beneficiary_upi_id == clean_query)
            | (Beneficiary.beneficiary_phone == clean_query)
        ).first()

        if ben_match:
            return True, {
                "resolved": True,
                "recipient_id": None,
                "recipient_name": ben_match.beneficiary_name,
                "recipient_upi_id": ben_match.beneficiary_upi_id,
                "recipient_phone": ben_match.beneficiary_phone,
                "account_type": "SAVED_BENEFICIARY",
                "is_internal": False,
                "is_verified": True,
                "is_saved_beneficiary": True,
                "beneficiary_id": ben_match.id,
                "trust_status": ben_match.get_effective_trust_status(),
                "is_cooling_active": ben_match.is_cooling_active(),
                "suggested_amount": suggested_amount,
                "suggested_note": suggested_note,
            }, None

        # 3. Search Known Verified Merchants Registry
        query_lower = clean_query.lower()
        if query_lower in SIMULATED_MERCHANTS:
            merchant_info = SIMULATED_MERCHANTS[query_lower]
            return True, {
                "resolved": True,
                "recipient_id": None,
                "recipient_name": merchant_info["name"],
                "recipient_upi_id": query_lower,
                "recipient_phone": None,
                "account_type": "MERCHANT",
                "is_internal": False,
                "is_verified": True,
                "is_saved_beneficiary": False,
                "beneficiary_id": None,
                "trust_status": "ESTABLISHED",
                "is_cooling_active": False,
                "suggested_amount": suggested_amount,
                "suggested_note": suggested_note,
            }, None

        # 4. If query was a phone number and not found, return explicit not found (no fallback)
        if is_phone_query:
            return False, None, f"No FraudShield user registered with mobile number +91 {digits_only}."

        # 5. Generic Valid UPI ID Format (External / Ad-hoc Payee)
        if cls.UPI_ID_REGEX.match(clean_query):
            handle_name = clean_query.split("@")[0].replace(".", " ").replace("_", " ").title()
            return True, {
                "resolved": True,
                "recipient_id": None,
                "recipient_name": handle_name,
                "recipient_upi_id": clean_query,
                "recipient_phone": None,
                "account_type": "EXTERNAL_UPI",
                "is_internal": False,
                "is_verified": False,
                "is_saved_beneficiary": False,
                "beneficiary_id": None,
                "trust_status": "NEW",
                "is_cooling_active": False,
                "suggested_amount": suggested_amount,
                "suggested_note": suggested_note,
            }, None

        return False, None, f"Could not resolve recipient '{clean_query}'. Please verify the UPI ID or 10-digit mobile number."

    @classmethod
    def set_user_pin(
        cls,
        user_id: int,
        current_password: str,
        new_pin: str,
        confirm_pin: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Set or update 4-6 digit numeric payment PIN after verifying current account password.

        Returns:
            (success: bool, error_message: Optional[str])
        """
        user = db.session.get(User, user_id)
        if not user:
            return False, "User not found."

        if not current_password:
            return False, "Current account password is required to set or update Payment PIN."

        if not user.check_password(current_password):
            return False, "Incorrect account password."

        clean_pin = str(new_pin).strip()
        clean_confirm = str(confirm_pin).strip()

        if not clean_pin:
            return False, "Payment PIN cannot be blank."

        if not cls.PIN_REGEX.match(clean_pin):
            return False, "Payment PIN must be exactly 4 to 6 numeric digits."

        if clean_pin != clean_confirm:
            return False, "Payment PIN and Confirm PIN do not match."

        user.set_payment_pin(clean_pin)
        db.session.commit()

        AuditService.log_event(
            event_type="PAYMENT_PIN_SET",
            actor=user.email,
            action="POST /api/auth/payment-pin/set",
            result="SUCCESS",
            user_id=user.id,
            target_resource=f"User:{user.id}",
            severity="INFO",
            details={"is_pin_set": True},
        )

        return True, None

    @classmethod
    def check_user_pin(cls, user_id: int, pin: str) -> Tuple[bool, Optional[str]]:
        """
        Verify payment PIN against user's stored hash. Enforces lockout.
        """
        user = db.session.get(User, user_id)
        if not user:
            return False, "User not found."

        is_valid, err = user.check_payment_pin(pin)
        db.session.commit()

        if not is_valid:
            AuditService.log_event(
                event_type="PAYMENT_PIN_FAILED",
                actor=user.email,
                action="AUTH /payment-pin/verify",
                result="FAILURE",
                user_id=user.id,
                target_resource=f"User:{user.id}",
                severity="WARN",
                details={"pin_failed_attempts": user.pin_failed_attempts, "is_pin_locked": user.is_pin_locked},
            )

        return is_valid, err
