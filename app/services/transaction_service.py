"""
Transaction Prediction and Processing Service.

Coordinates:
1. Input validation and recipient/beneficiary authorization
2. Centralized Feature Engineering (behavioral, velocity, temporal, beneficiary)
3. ML Inference (calibrated fraud probability P_fraud)
4. Structured Risk Signal Engine & 4-Tier Decision Engine
5. Dual-View Explainable AI (Customer Safe View vs Admin SOC Deep-Dive)
6. Financial Balance Ledger Processing
7. Audit persistence and Security Alert generation
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

from app.extensions import db
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.models.user import User
from app.models.beneficiary import Beneficiary
from app.services.feature_service import FeatureService
from app.services.risk_service import RiskDecisionService
from app.services.shap_service import ShapService, get_shap_service

logger = logging.getLogger(__name__)

VALID_TRANSACTION_TYPES = {"TRANSFER", "CASH_OUT", "PAYMENT", "CASH_IN", "DEBIT"}


class TransactionService:
    """Service layer coordinating real-time risk assessment, SHAP, and financial ledger."""

    @staticmethod
    def validate_prediction_payload(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
        """
        Validate incoming transaction prediction request.
        """
        if not data or not isinstance(data, dict):
            return False, "Request body must be a valid JSON object"

        # Amount validation
        amount = data.get("amount")
        if amount is None:
            return False, "Field 'amount' is required"
        try:
            amount_val = float(amount)
            if amount_val <= 0:
                return False, "Field 'amount' must be a positive number greater than 0"
        except (ValueError, TypeError):
            return False, "Field 'amount' must be a valid numeric value"

        # Transaction type validation
        tx_type = data.get("type")
        if not tx_type or not isinstance(tx_type, str):
            return False, "Field 'type' is required"
        clean_type = tx_type.strip().upper()
        if clean_type not in VALID_TRANSACTION_TYPES:
            return False, f"Invalid transaction type '{tx_type}'. Supported types: {sorted(list(VALID_TRANSACTION_TYPES))}"

        # Destination validation
        dest = (
            data.get("name_dest")
            or data.get("destination")
            or data.get("destination_upi_id")
            or data.get("nameDest")
        )
        beneficiary_id = data.get("beneficiary_id")
        if not dest and not beneficiary_id:
            return False, "Recipient destination ('destination' / 'destination_upi_id' / 'beneficiary_id') is required"

        return True, None

    @staticmethod
    def process_and_predict(user_id: int, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str], int]:
        """
        Execute full fraud risk assessment pipeline and atomically record transaction.
        Coordinates PIN verification, feature extraction, ML/SHAP, hybrid risk decision, and atomic ledger.
        """
        try:
            import secrets
            user = db.session.get(User, user_id)
            if not user:
                return None, "Authenticated user not found", 404

            # 1. Idempotency Check (Prevent Double-Debit)
            idempotency_key = payload.get("idempotency_key") or payload.get("idempotencyKey")
            if idempotency_key:
                clean_idempotency = str(idempotency_key).strip()
                existing_tx = Transaction.query.filter_by(user_id=user_id, idempotency_key=clean_idempotency).first()
                if existing_tx:
                    explanation_obj = json.loads(existing_tx.explanation_json) if existing_tx.explanation_json else {}
                    return {
                        "success": True,
                        "transaction_id": existing_tx.id,
                        "reference_id": existing_tx.reference_id,
                        "idempotency_key": existing_tx.idempotency_key,
                        "prediction": existing_tx.prediction,
                        "predicted_class_name": "Fraudulent" if existing_tx.prediction == 1 else "Legitimate",
                        "fraud_probability": existing_tx.fraud_probability,
                        "ml_probability": existing_tx.fraud_probability,
                        "risk_score": existing_tx.risk_score,
                        "risk_level": existing_tx.risk_level,
                        "decision": existing_tx.decision,
                        "status": existing_tx.status,
                        "requires_otp": existing_tx.requires_otp,
                        "account_balance": float(user.account_balance) if user.account_balance is not None else 0.0,
                        "balance_before": float(existing_tx.balance_before) if existing_tx.balance_before is not None else None,
                        "balance_after": float(existing_tx.balance_after) if existing_tx.balance_after is not None else None,
                        "destination_upi_id": existing_tx.destination_upi_id,
                        "destination_name": existing_tx.destination_name,
                        "customer_message": explanation_obj.get("customer_explanation", "Transaction previously processed."),
                        "explanation": explanation_obj,
                    }, None, 200

            # 2. Payment PIN Authentication Check (Layer 1 Transaction Security)
            payment_pin = payload.get("payment_pin") or payload.get("pin")
            pin_verified = False
            if user.is_pin_set:
                if not payment_pin:
                    return None, "Payment PIN is required to authorize this transaction.", 401
                is_pin_valid, pin_err = user.check_payment_pin(str(payment_pin).strip())
                db.session.commit()
                if not is_pin_valid:
                    status_code = 429 if user.is_pin_locked else 401
                    return None, pin_err or "Invalid Payment PIN", status_code
                pin_verified = True
            elif payment_pin is not None:
                # User provided a PIN but account has not configured one
                return None, "Payment PIN has not been configured for this account. Please set a Payment PIN first.", 401

            # 3. Extract & Sanitize User Inputs
            amount = float(payload["amount"])
            tx_type = str(payload["type"]).strip().upper()
            beneficiary_id = payload.get("beneficiary_id")
            payment_method = str(payload.get("payment_method") or "UPI_ID").strip().upper()
            payment_note = str(payload.get("payment_note") or payload.get("description") or "").strip() or None

            dest_upi = str(payload.get("destination_upi_id") or "").strip() or None
            dest_name = str(payload.get("destination_name") or "").strip() or None
            dest = str(
                payload.get("name_dest")
                or payload.get("destination")
                or payload.get("destination_upi_id")
                or payload.get("nameDest")
                or ""
            ).strip()

            # Handle Beneficiary reference and verification (IDOR protection)
            beneficiary = None
            if beneficiary_id:
                try:
                    b_id = int(beneficiary_id)
                    beneficiary = db.session.get(Beneficiary, b_id)
                    if not beneficiary or beneficiary.user_id != user_id:
                        return None, "Forbidden: Invalid or unauthorized beneficiary selection", 403

                    if beneficiary.status in ["REVOKED", "INACTIVE"] or beneficiary.trust_status == "REVOKED":
                        return None, "Transaction rejected: Beneficiary handle has been revoked/deactivated", 403

                    dest_upi = beneficiary.beneficiary_upi_id
                    dest_name = beneficiary.beneficiary_name
                    if not dest:
                        dest = beneficiary.beneficiary_upi_id
                except (ValueError, TypeError):
                    return None, "Invalid beneficiary ID", 400
            elif dest_upi and not dest:
                dest = dest_upi

            # Resolve Internal Recipient User (if applicable)
            recipient_user = None
            if dest_upi:
                recipient_user = User.query.filter(
                    (User.primary_upi_id == dest_upi) | (User.email == dest_upi)
                ).first()
            if not recipient_user and dest:
                recipient_user = User.query.filter(
                    (User.primary_upi_id == dest) | (User.phone_number == dest) | (User.customer_account_id == dest.upper())
                ).first()

            if recipient_user and recipient_user.id == user_id:
                return None, "Cannot transfer funds to your own account", 400

            if recipient_user and not dest_name:
                dest_name = recipient_user.name

            orig = str(payload.get("name_orig") or payload.get("nameOrig") or user.customer_account_id or f"C{user_id:09d}").strip()
            is_merchant = dest.upper().startswith("M") or (dest_name and "MERCHANT" in dest_name.upper())

            # 4. Check Account Balances
            has_sim_orig = ("oldbalance_org" in payload or "oldbalanceOrg" in payload)
            has_sim_dest = ("oldbalance_dest" in payload or "oldbalanceDest" in payload)
            has_account_simulation = bool(has_sim_orig or has_sim_dest)

            # Check user balance for debit transactions
            if not has_account_simulation and user.role == "USER" and tx_type in ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"]:
                curr_bal = float(user.account_balance) if user.account_balance is not None else 0.0
                if curr_bal < amount:
                    return None, f"Insufficient account balance. Available balance: ₹{curr_bal:,.2f}, required: ₹{amount:,.2f}", 400

            current_time = datetime.now(timezone.utc)
            current_hour = current_time.hour
            step = int(payload.get("step", current_hour if current_hour > 0 else 12))

            # Sender Balances
            if has_sim_orig:
                oldbalance_org = float(payload.get("oldbalance_org", payload.get("oldbalanceOrg", 0.0)))
                newbalance_orig = float(payload.get("newbalance_orig", payload.get("newbalanceOrig", 0.0)))
            else:
                oldbalance_org = float(user.account_balance) if user.account_balance is not None else amount + 1000.0
                if tx_type in ["TRANSFER", "CASH_OUT", "PAYMENT", "DEBIT"]:
                    newbalance_orig = max(0.0, oldbalance_org - amount)
                else:  # CASH_IN
                    newbalance_orig = oldbalance_org + amount

            # Receiver Balances
            if has_sim_dest:
                oldbalance_dest = float(payload.get("oldbalance_dest", payload.get("oldbalanceDest", 0.0)))
                newbalance_dest = float(payload.get("newbalance_dest", payload.get("newbalanceDest", 0.0)))
            else:
                oldbalance_dest = float(recipient_user.account_balance) if recipient_user and recipient_user.account_balance is not None else float(payload.get("receiver_balance", 0.0))
                if tx_type in ["TRANSFER", "CASH_IN", "PAYMENT"]:
                    newbalance_dest = oldbalance_dest + amount
                else:
                    newbalance_dest = oldbalance_dest

            is_account_drain = bool(has_account_simulation and oldbalance_org > 0 and newbalance_orig == 0.0)

            # 5. Centralized Feature Engineering Layer (No Data Leakage)
            features = FeatureService.extract_features(
                user_id=user_id,
                amount=amount,
                tx_type=tx_type,
                beneficiary_id=beneficiary.id if beneficiary else None,
                destination_upi_id=dest_upi or dest,
                is_merchant_dest=is_merchant,
                reference_time=current_time,
            )

            # 5b. Device Intelligence & Telemetry Check
            from flask import has_request_context, request, g
            from app.services.device_trust_service import DeviceTrustService

            resolved_ua = payload.get("user_agent")
            resolved_ip = payload.get("client_ip")
            resolved_dev_id = payload.get("device_fingerprint")
            client_telemetry = payload.get("client_telemetry")

            if has_request_context():
                if not resolved_ua:
                    resolved_ua = request.headers.get("User-Agent", "")
                if not resolved_ip:
                    resolved_ip = getattr(g, "client_ip", request.remote_addr)
                if not resolved_dev_id:
                    resolved_dev_id = request.headers.get("X-Device-Fingerprint")

            dev_profile, dev_trust_status, is_new_dev = DeviceTrustService.evaluate_or_register_device(
                user_id=user_id,
                user_agent=resolved_ua,
                client_ip=resolved_ip,
                client_telemetry=client_telemetry,
                client_device_id=resolved_dev_id,
            )

            if dev_trust_status == "BLOCKED":
                return None, "Transaction rejected: Device is blocked due to security violations", 403

            features["is_unknown_device"] = 1 if is_new_dev or dev_trust_status in ["UNKNOWN", "SUSPICIOUS"] else 0
            features["device_trust_status"] = dev_trust_status
            features["device_id"] = dev_profile.id if dev_profile else None

            # 5c. Geo Intelligence & Impossible Travel Check
            from app.services.geo_intelligence_service import GeoIntelligenceService

            loc_payload = payload.get("location") or {
                "city": payload.get("city") or (request.headers.get("X-Client-City") if has_request_context() else None),
                "state": payload.get("state") or payload.get("region"),
                "country": payload.get("country") or (request.headers.get("X-Client-Country") if has_request_context() else None),
                "lat": payload.get("latitude") or payload.get("lat"),
                "lon": payload.get("longitude") or payload.get("lon"),
            }

            geo_eval = GeoIntelligenceService.evaluate_event_location(
                user_id=user_id,
                client_ip=resolved_ip,
                location_payload=loc_payload,
                event_type="TRANSACTION",
                reference_time=current_time,
                persist=True,
            )

            features["is_impossible_travel"] = 1 if geo_eval["is_impossible_travel"] else 0
            features["is_unusual_location"] = 1 if geo_eval["is_unusual_location"] else 0
            features["is_rapid_geo_change"] = 1 if geo_eval["is_rapid_geo_change"] else 0
            features["geo_distance_km"] = geo_eval["distance_km"]
            features["geo_elapsed_seconds"] = geo_eval["elapsed_seconds"]
            features["geo_speed_kmh"] = geo_eval["speed_kmh"]
            features["geo_city"] = geo_eval["city"]
            features["geo_country"] = geo_eval["country_code"]

            # 5d. Beneficiary Intelligence & 24h Cooling Period Check
            if beneficiary:
                is_cooling = beneficiary.is_cooling_active(reference_time=current_time)
                features["is_beneficiary_in_cooling"] = 1 if is_cooling else 0
                features["beneficiary_cooling_remaining_sec"] = beneficiary.get_cooling_remaining_seconds(reference_time=current_time)
                features["beneficiary_trust_status"] = beneficiary.get_effective_trust_status(reference_time=current_time)
                features["beneficiary_successful_count"] = beneficiary.successful_payment_count
                features["is_first_time_beneficiary"] = 1 if beneficiary.successful_payment_count == 0 else 0
            else:
                features["is_beneficiary_in_cooling"] = 0
                features["beneficiary_cooling_remaining_sec"] = 0
                features["beneficiary_trust_status"] = "NEW"

            # 6. ML Inference Payload & SHAP Explainer
            ml_input = {
                "type": tx_type,
                "amount": amount,
                "oldbalanceOrg": oldbalance_org,
                "newbalanceOrig": newbalance_orig,
                "oldbalanceDest": oldbalance_dest,
                "newbalanceDest": newbalance_dest,
                "nameDest": dest,
                "step": step,
                "hourOfDay": step % 24,
            }

            shap_service = get_shap_service()
            explanation_data = shap_service.explain_transaction(ml_input, top_k=5)

            raw_prediction = explanation_data["prediction"]
            fraud_prob = float(explanation_data["fraud_probability"])
            legit_prob = float(explanation_data["legitimate_probability"])
            top_features = explanation_data["top_features"]
            pos_factors = explanation_data["positive_risk_factors"]
            neg_factors = explanation_data["negative_risk_factors"]

            # 7. Hybrid Risk Policy & 4-Tier Decision Engine
            hybrid_eval = RiskDecisionService.evaluate_hybrid_risk(
                ml_fraud_prob=fraud_prob,
                amount=amount,
                tx_type=tx_type,
                has_account_simulation=has_account_simulation,
                is_account_drain=is_account_drain,
                hour_of_day=step % 24,
                is_merchant_dest=is_merchant,
                features=features,
            )

            ml_score = hybrid_eval["ml_score"]
            rule_score = hybrid_eval["rule_score"]
            final_risk_score = hybrid_eval["risk_score"]
            risk_level = hybrid_eval["risk_level"]
            decision = hybrid_eval["decision"]
            status = hybrid_eval["initial_status"]
            requires_otp = hybrid_eval["requires_otp"]
            rule_risk_factors = hybrid_eval["risk_factors"]
            risk_signals = hybrid_eval["risk_signals"]

            # 8. Generate Dual-View Explanations
            customer_narrative = ShapService.generate_customer_explanation(
                risk_level=risk_level,
                transaction_data=ml_input,
                risk_signals=risk_signals,
            )

            admin_shap_summary = explanation_data.get("explanation_text", "")
            if rule_risk_factors:
                factors_str = "; ".join(rule_risk_factors)
                admin_narrative = f"{admin_shap_summary} [Risk Signals: {factors_str}]"
            else:
                admin_narrative = admin_shap_summary

            # 9. Atomic Financial Balance Ledger Handling
            balance_before = float(user.account_balance) if user.account_balance is not None else 0.0
            balance_after = balance_before

            if status == "APPROVED":
                # Check sufficient funds before approving transfer
                if not has_account_simulation and user.role == "USER" and tx_type in ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"]:
                    if balance_before < amount:
                        return None, f"Insufficient account balance. Available balance: ₹{balance_before:,.2f}, required: ₹{amount:,.2f}", 400

                # Atomically deduct sender balance on immediate approval
                if user.role == "USER" and tx_type in ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"]:
                    if not has_account_simulation:
                        user.account_balance = round(user.account_balance - amount, 2)
                        balance_after = float(user.account_balance)
                    else:
                        balance_after = newbalance_orig

                # Atomically credit recipient if internal user
                if recipient_user and recipient_user.id != user_id and not has_account_simulation:
                    curr_rec_bal = float(recipient_user.account_balance) if recipient_user.account_balance is not None else 0.0
                    recipient_user.account_balance = round(curr_rec_bal + amount, 2)

                if beneficiary:
                    from app.services.beneficiary_service import BeneficiaryService
                    BeneficiaryService.record_payment_outcome(beneficiary.id, amount, success=True)

            # Generate Unique UPI Reference ID
            ref_id = f"UPI{current_time.strftime('%Y%m%d%H%M%S')}{secrets.randbelow(9000) + 1000}"

            # 10. Database Persistence with Transaction Safety
            tx_record = Transaction(
                user_id=user_id,
                recipient_user_id=recipient_user.id if recipient_user else None,
                reference_id=ref_id,
                idempotency_key=str(idempotency_key).strip() if idempotency_key else None,
                payment_method=payment_method,
                step=step,
                type=tx_type,
                amount=amount,
                name_orig=orig,
                oldbalance_org=oldbalance_org,
                newbalance_orig=newbalance_orig,
                name_dest=dest,
                oldbalance_dest=oldbalance_dest,
                newbalance_dest=newbalance_dest,
                prediction=raw_prediction,
                fraud_probability=fraud_prob,
                risk_score=final_risk_score,
                risk_level=risk_level,
                decision=decision,
                status=status,
                requires_otp=requires_otp,
                beneficiary_id=beneficiary.id if beneficiary else None,
                destination_upi_id=dest_upi,
                destination_name=dest_name,
                payment_note=payment_note,
                balance_before=balance_before,
                balance_after=balance_after,
                explanation_json=json.dumps({
                    "explanation_text": admin_narrative,
                    "customer_explanation": customer_narrative,
                    "admin_explanation": admin_narrative,
                    "top_features": top_features,
                    "positive_risk_factors": pos_factors,
                    "negative_risk_factors": neg_factors,
                    "rule_risk_factors": rule_risk_factors,
                    "risk_signals": risk_signals,
                    "ml_fraud_probability": fraud_prob,
                    "ml_score": ml_score,
                    "rule_score": rule_score,
                    "final_risk_score": final_risk_score,
                    "has_account_simulation": has_account_simulation,
                    "behavioral_context": {
                        "user_tx_count": features.get("user_tx_count", 0),
                        "user_avg_amount": features.get("user_avg_amount", 0.0),
                        "amount_deviation_ratio": features.get("amount_deviation_ratio", 1.0),
                        "tx_count_last_10m": features.get("tx_count_last_10m", 0),
                    },
                }),
            )
            db.session.add(tx_record)
            db.session.flush()

            # Create security alert if high/critical risk
            if hybrid_eval["create_alert"]:
                from app.services.alert_service import AlertService
                AlertService.create_security_alert(
                    transaction_id=tx_record.id,
                    user_id=user_id,
                    severity=hybrid_eval.get("alert_severity", "CRITICAL"),
                    message=f"Critical-risk {tx_type} payment of ₹{amount:,.2f} flagged (Risk Score: {final_risk_score}/100). {admin_narrative}",
                    alert_type="FRAUD_ALERT",
                )

            db.session.commit()

            logger.info(
                "Processed UPI transaction %d (%s) for user %d: type=%s, amount=%.2f, balance_after=%.2f, risk=%d (%s), decision=%s",
                tx_record.id, ref_id, user_id, tx_type, amount, balance_after, final_risk_score, risk_level, decision
            )

            # Audit Trail Recording
            from app.services.audit_service import AuditService
            AuditService.log_event(
                event_type="TRANSACTION_EVALUATED",
                actor=user.email if user else f"User:{user_id}",
                action="POST /api/transactions/predict",
                result="FLAGGED" if decision in ["TRIGGER_SECURITY_REVIEW", "DECLINE_TRANSACTION"] else "SUCCESS",
                user_id=user_id,
                target_resource=f"Transaction:{tx_record.id}",
                severity="CRITICAL" if risk_level == "CRITICAL" else ("WARN" if risk_level in ["HIGH", "MEDIUM"] else "INFO"),
                details={
                    "transaction_id": tx_record.id,
                    "reference_id": ref_id,
                    "payment_method": payment_method,
                    "type": tx_type,
                    "amount": amount,
                    "risk_score": final_risk_score,
                    "risk_level": risk_level,
                    "decision": decision,
                    "status": status,
                    "pin_verified": pin_verified,
                },
            )

            # 11. Build Standardized API Response
            response_payload = {
                "success": True,
                "transaction_id": tx_record.id,
                "reference_id": ref_id,
                "idempotency_key": tx_record.idempotency_key,
                "payment_method": payment_method,
                "prediction": raw_prediction,
                "predicted_class_name": "Fraudulent" if raw_prediction == 1 else "Legitimate",
                "fraud_probability": fraud_prob,
                "ml_probability": fraud_prob,
                "legitimate_probability": legit_prob,
                "ml_score": ml_score,
                "rule_score": rule_score,
                "signals_score": rule_score,
                "risk_score": final_risk_score,
                "risk_level": risk_level,
                "decision": decision,
                "status": status,
                "requires_otp": requires_otp,
                "has_account_simulation": has_account_simulation,
                "risk_factors": rule_risk_factors,
                "risk_signals": risk_signals,
                "account_balance": float(user.account_balance) if user.account_balance is not None else 0.0,
                "balance_before": balance_before,
                "balance_after": balance_after,
                "beneficiary_id": beneficiary.id if beneficiary else None,
                "destination_upi_id": dest_upi,
                "destination_name": dest_name,
                "recipient_user_id": recipient_user.id if recipient_user else None,
                "customer_message": customer_narrative,
                "security_checks": {
                    "recipient_verified": True,
                    "pin_authenticated": pin_verified,
                    "device_trust_verified": dev_trust_status != "BLOCKED",
                    "geo_location_verified": not geo_eval.get("is_impossible_travel", False),
                    "beneficiary_cooling_verified": not features.get("is_beneficiary_in_cooling", 0),
                    "ai_model_evaluated": True,
                },
                "explanation": {
                    "top_features": top_features,
                    "positive_risk_factors": pos_factors,
                    "negative_risk_factors": neg_factors,
                    "human_readable_summary": customer_narrative,
                    "customer_explanation": customer_narrative,
                    "admin_explanation": admin_narrative,
                    "text": admin_narrative,
                },
                "behavioral_context": {
                    "user_tx_count": features.get("user_tx_count", 0),
                    "user_avg_amount": features.get("user_avg_amount", 0.0),
                    "amount_deviation_ratio": features.get("amount_deviation_ratio", 1.0),
                    "tx_count_last_10m": features.get("tx_count_last_10m", 0),
                },
                "model_version": explanation_data.get("model_version", "1.0.0"),
            }

            return response_payload, None, 200

        except Exception as e:
            db.session.rollback()
            logger.exception("Error in process_and_predict for user %d: %s", user_id, str(e))
            return None, f"Internal error evaluating transaction: {str(e)}", 500
