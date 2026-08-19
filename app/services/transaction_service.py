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
        """
        try:
            user = db.session.get(User, user_id)
            if not user:
                return None, "Authenticated user not found", 404

            # 1. Extract & Sanitize User Inputs
            amount = float(payload["amount"])
            tx_type = str(payload["type"]).strip().upper()
            beneficiary_id = payload.get("beneficiary_id")
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

                    dest_upi = beneficiary.beneficiary_upi_id
                    dest_name = beneficiary.beneficiary_name
                    if not dest:
                        dest = beneficiary.beneficiary_upi_id
                except (ValueError, TypeError):
                    return None, "Invalid beneficiary ID", 400
            elif dest_upi and not dest:
                dest = dest_upi

            orig = str(payload.get("name_orig") or payload.get("nameOrig") or user.customer_account_id or f"C{user_id:09d}").strip()
            is_merchant = dest.upper().startswith("M") or (dest_name and "MERCHANT" in dest_name.upper())

            # 2. Check if Account Simulation Balances Were Explicitly Provided
            has_sim_orig = ("oldbalance_org" in payload or "oldbalanceOrg" in payload)
            has_sim_dest = ("oldbalance_dest" in payload or "oldbalanceDest" in payload)
            has_account_simulation = bool(has_sim_orig or has_sim_dest)

            # Check user balance for debit transactions (when simulation balance is not explicitly provided)
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
                oldbalance_dest = float(payload.get("receiver_balance", 0.0))
                if tx_type in ["TRANSFER", "CASH_IN"]:
                    newbalance_dest = oldbalance_dest + amount
                else:
                    newbalance_dest = oldbalance_dest

            is_account_drain = bool(has_account_simulation and oldbalance_org > 0 and newbalance_orig == 0.0)

            # 3. Centralized Feature Engineering Layer (No Data Leakage)
            features = FeatureService.extract_features(
                user_id=user_id,
                amount=amount,
                tx_type=tx_type,
                beneficiary_id=beneficiary.id if beneficiary else None,
                destination_upi_id=dest_upi or dest,
                is_merchant_dest=is_merchant,
                reference_time=current_time,
            )

            # 3b. Device Intelligence & Telemetry Check
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

            # 4. ML Inference Payload & SHAP Explainer
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

            # 5. Hybrid Risk Policy & 4-Tier Decision Engine
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

            # 6. Generate Dual-View Explanations
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

            # 7. Atomic Financial Balance Ledger Handling
            balance_before = float(user.account_balance) if user.account_balance is not None else 0.0
            balance_after = balance_before

            if status == "APPROVED":
                # Check sufficient funds before approving transfer
                if not has_account_simulation and user.role == "USER" and tx_type in ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"]:
                    if balance_before < amount:
                        return None, f"Insufficient account balance. Available balance: ₹{balance_before:,.2f}, required: ₹{amount:,.2f}", 400

                # Atomically deduct balance on immediate approval
                if user.role == "USER" and tx_type in ["TRANSFER", "PAYMENT", "CASH_OUT", "DEBIT"]:
                    if not has_account_simulation:
                        user.account_balance = round(user.account_balance - amount, 2)
                        balance_after = float(user.account_balance)
                    else:
                        balance_after = newbalance_orig

                if beneficiary:
                    beneficiary.last_used_at = datetime.now(timezone.utc)

            # 8. Database Persistence with Transaction Safety
            tx_record = Transaction(
                user_id=user_id,
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
                "Processed transaction %d for user %d: type=%s, amount=%.2f, balance_after=%.2f, risk=%d (%s), decision=%s",
                tx_record.id, user_id, tx_type, amount, balance_after, final_risk_score, risk_level, decision
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
                    "type": tx_type,
                    "amount": amount,
                    "risk_score": final_risk_score,
                    "risk_level": risk_level,
                    "decision": decision,
                    "status": status,
                },
            )

            # 9. Build Standardized API Response
            response_payload = {
                "success": True,
                "transaction_id": tx_record.id,
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
                "customer_message": customer_narrative,
                "explanation": {
                    "top_features": top_features,
                    "positive_risk_factors": pos_factors,
                    "negative_risk_factors": neg_factors,
                    "rule_risk_factors": rule_risk_factors,
                    "human_readable_summary": customer_narrative,
                    "customer_explanation": customer_narrative,
                    "admin_explanation": admin_narrative,
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
            logger.error("Transaction prediction failed for user %d: %s", user_id, str(e), exc_info=True)
            return None, f"Prediction processing error: {str(e)}", 500
