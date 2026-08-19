"""
Comprehensive Test Suite for Phase 3 — Milestone 5: SOC Case Management & Alert Lifecycle.

Tests:
1. Alert lifecycle state machine (OPEN -> ACKNOWLEDGED -> INVESTIGATING -> ESCALATED -> RESOLVED / FALSE_POSITIVE / DISMISSED)
2. Alert deduplication & correlation signature
3. SOC Case creation with automatic forensic snapshot compilation
4. Case assignment to lead analyst
5. Case status transitions and automatic alert cascading resolution
6. Confirmed fraud automated remediations (device blocking & beneficiary revocation)
7. Chronological timeline notes and investigation steps
8. Multi-alert correlation and attachment
9. SOC operational metrics summary
10. Case filtering, priority sorting, and pagination
11. Strict RBAC / IDOR protection (customer 403 Forbidden)
12. Audit trail logging for all SOC actions
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.transaction import Transaction
from app.models.alert import Alert
from app.models.soc_case import SOCCase
from app.models.case_note import CaseNote
from app.models.device_profile import DeviceProfile
from app.models.geo_location_record import GeoLocationRecord
from app.models.beneficiary import Beneficiary
from app.models.audit_log import AuditLog
from app.services.alert_service import AlertService
from app.services.soc_case_service import SOCCaseService


@pytest.fixture
def app():
    """Create test application configured with in-memory database."""
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def soc_setup(app):
    """Fixture providing an admin analyst, customer, transaction, and security alert."""
    with app.app_context():
        # Clean existing test data
        CaseNote.query.delete()
        SOCCase.query.delete()
        Alert.query.delete()
        Transaction.query.delete()
        Beneficiary.query.delete()
        DeviceProfile.query.delete()
        GeoLocationRecord.query.delete()
        AuditLog.query.delete()
        User.query.delete()
        db.session.commit()

        # Create Admin Analyst 1
        admin1 = User(
            name="SOC Lead Analyst",
            email="lead.analyst@fraudshield.internal",
            role="ADMIN",
        )
        admin1.set_password("AdminSecurePass123!")
        db.session.add(admin1)

        # Create Admin Analyst 2
        admin2 = User(
            name="Junior Investigator",
            email="junior.analyst@fraudshield.internal",
            role="ADMIN",
        )
        admin2.set_password("AdminSecurePass123!")
        db.session.add(admin2)

        # Create Customer
        customer = User(
            name="Vikram Seth",
            email="vikram.seth@example.com",
            role="USER",
            account_balance=500000.0,
        )
        customer.set_password("CustomerPass123!")
        db.session.add(customer)
        db.session.commit()

        # Create Device Profile
        device = DeviceProfile(
            user_id=customer.id,
            device_hash="mock_device_hash_12345",
            browser="Chrome",
            operating_system="Windows",
            trust_status="TRUSTED",
        )
        db.session.add(device)

        # Create Geo Record
        geo = GeoLocationRecord(
            user_id=customer.id,
            ip_hash="mock_ip_hash_123",
            city="Mumbai",
            country_code="IN",
            latitude=19.07,
            longitude=72.87,
        )
        db.session.add(geo)

        # Create Beneficiary
        ben = Beneficiary(
            user_id=customer.id,
            beneficiary_name="Rahul Sharma",
            beneficiary_upi_id="rahul@okhdfc",
            trust_status="ESTABLISHED",
        )
        db.session.add(ben)

        # Create Trigger Transaction
        tx = Transaction(
            user_id=customer.id,
            amount=85000.0,
            type="TRANSFER",
            name_orig=f"C{customer.id:09d}",
            name_dest="M9876543210",
            oldbalance_org=500000.0,
            newbalance_orig=415000.0,
            oldbalance_dest=0.0,
            newbalance_dest=85000.0,
            risk_score=82,
            risk_level="HIGH",
            fraud_probability=0.88,
            status="BLOCKED",
            explanation_json=json.dumps({
                "rule_triggers": ["LARGE_AMOUNT", "IMPOSSIBLE_TRAVEL_SPEED"],
                "top_shap_factors": [{"feature": "amount", "value": 85000.0, "impact": "+0.45"}],
            }),
        )
        db.session.add(tx)
        db.session.commit()

        # Create Security Alert
        alert = AlertService.create_security_alert(
            transaction_id=tx.id,
            user_id=customer.id,
            alert_type="FRAUD_ALERT",
            severity="CRITICAL",
            message="High risk transaction blocked by rule engine.",
        )

        yield {
            "admin1_id": admin1.id,
            "admin1_email": admin1.email,
            "admin2_id": admin2.id,
            "admin2_email": admin2.email,
            "customer_id": customer.id,
            "customer_email": customer.email,
            "tx_id": tx.id,
            "alert_id": alert.id,
            "device_id": device.id,
            "ben_id": ben.id,
        }


def get_jwt_header(client, email, password="AdminSecurePass123!"):
    """Helper to login and retrieve Bearer authorization header."""
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}: {res.get_json()}"
    token = res.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestSOCAlertLifecycle:
    """Tests for Alert state machine transitions and deduplication."""

    def test_alert_lifecycle_state_machine(self, client, soc_setup):
        """Test full alert status sequence: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])
        alert_id = soc_setup["alert_id"]

        # 1. Acknowledge Alert
        res = client.post(f"/api/admin/alerts/{alert_id}/acknowledge", headers=admin_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["alert"]["status"] == "ACKNOWLEDGED"
        assert data["alert"]["acknowledged_by"] == soc_setup["admin1_email"]

        # 2. Move to Investigating with Note
        res = client.post(
            f"/api/admin/alerts/{alert_id}/investigate",
            headers=admin_headers,
            json={"note": "Examining geo speed anomaly from Mumbai to London."},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["alert"]["status"] == "INVESTIGATING"
        assert "Mumbai to London" in data["alert"]["notes"]

        # 3. Resolve Alert as False Positive
        res = client.post(
            f"/api/admin/alerts/{alert_id}/resolve",
            headers=admin_headers,
            json={"resolution_type": "FALSE_POSITIVE", "note": "Customer verified via phone call."},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["alert"]["status"] == "FALSE_POSITIVE"
        assert data["alert"]["resolved_by"] == soc_setup["admin1_email"]
        assert "Customer verified" in data["alert"]["notes"]

    def test_alert_assignment(self, client, soc_setup):
        """Test assigning an alert to an analyst."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])
        alert_id = soc_setup["alert_id"]
        junior_id = soc_setup["admin2_id"]

        res = client.post(
            f"/api/admin/alerts/{alert_id}/assign",
            headers=admin_headers,
            json={"assignee_id": junior_id},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["alert"]["assigned_to_id"] == junior_id
        assert data["alert"]["assigned_to_email"] == soc_setup["admin2_email"]

    def test_alert_deduplication(self, app, soc_setup):
        """Test alert deduplication correlation count increment."""
        with app.app_context():
            # Create a second transaction for same user
            tx2 = Transaction(
                user_id=soc_setup["customer_id"],
                amount=90000.0,
                type="TRANSFER",
                name_orig="C000000001",
                name_dest="M9876543210",
                oldbalance_org=415000.0,
                newbalance_orig=325000.0,
                oldbalance_dest=0.0,
                newbalance_dest=90000.0,
                risk_score=85,
                risk_level="HIGH",
                status="BLOCKED",
            )
            db.session.add(tx2)
            db.session.commit()

            # Create alert with same type and severity
            alert2 = AlertService.create_security_alert(
                transaction_id=tx2.id,
                user_id=soc_setup["customer_id"],
                severity="CRITICAL",
                message="Another critical transfer alert.",
                alert_type="FRAUD_ALERT",
            )

            # Check that initial alert's correlation_count was incremented
            alert1 = db.session.get(Alert, soc_setup["alert_id"])
            assert alert1.correlation_count == 2
            assert alert2.dedup_signature == alert1.dedup_signature


class TestSOCCaseManagement:
    """Tests for SOC Case creation, evidence compilation, notes, and lifecycle."""

    def test_create_soc_case_with_evidence_snapshot(self, client, soc_setup):
        """Test creating a SOC Case and verifying automatic forensic evidence capture."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        payload = {
            "customer_id": soc_setup["customer_id"],
            "title": "Account Takeover Investigation - Speed Anomaly",
            "priority": "CRITICAL",
            "lead_analyst_id": soc_setup["admin1_id"],
            "description": "Customer flagged for impossible travel and sudden large transfer.",
            "alert_ids": [soc_setup["alert_id"]],
        }

        res = client.post("/api/admin/cases", headers=admin_headers, json=payload)
        assert res.status_code == 201
        data = res.get_json()
        case_dict = data["case"]

        assert case_dict["case_number"].startswith("CASE-")
        assert case_dict["priority"] == "CRITICAL"
        assert case_dict["status"] == "TRIAGED"
        assert case_dict["customer_name"] == "Vikram Seth"
        assert case_dict["lead_analyst_email"] == soc_setup["admin1_email"]
        assert case_dict["alert_count"] == 1

        # Check Forensic Evidence Snapshot
        evidence = case_dict["evidence"]
        assert evidence["customer_identity"]["user_id"] == soc_setup["customer_id"]
        assert evidence["primary_trigger"]["amount"] == 85000.0
        assert evidence["primary_trigger"]["risk_score"] == 82
        assert len(evidence["device_telemetry"]) >= 1
        assert len(evidence["geo_telemetry"]) >= 1
        assert len(evidence["beneficiary_telemetry"]) >= 1

        # Check Initial Timeline Note
        assert len(case_dict["notes"]) == 1
        assert "opened with priority CRITICAL" in case_dict["notes"][0]["content"]

    def test_soc_case_notes_timeline(self, client, soc_setup):
        """Test appending structured notes (investigation step, analyst note) to timeline."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # Create case first
        res = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={
                "customer_id": soc_setup["customer_id"],
                "title": "Suspected Mule Account",
                "priority": "HIGH",
            },
        )
        case_id = res.get_json()["case"]["id"]

        # Add Investigation Step Note
        res_note = client.post(
            f"/api/admin/cases/{case_id}/notes",
            headers=admin_headers,
            json={
                "note_type": "INVESTIGATION_STEP",
                "content": "Step 1: Cross-referenced recipient account against national mule registry.",
            },
        )
        assert res_note.status_code == 201
        note_data = res_note.get_json()["note"]
        assert note_data["note_type"] == "INVESTIGATION_STEP"
        assert "Step 1" in note_data["content"]

        # Add Analyst Assessment Note
        res_note2 = client.post(
            f"/api/admin/cases/{case_id}/notes",
            headers=admin_headers,
            json={
                "note_type": "ANALYST_NOTE",
                "content": "High likelihood of social engineering. Requesting customer callback.",
            },
        )
        assert res_note2.status_code == 201

        # Retrieve Full Case Dossier
        res_detail = client.get(f"/api/admin/cases/{case_id}", headers=admin_headers)
        assert res_detail.status_code == 200
        detail_data = res_detail.get_json()["case"]
        assert len(detail_data["notes"]) == 3  # Initial creation note + 2 added notes

    def test_case_status_transition_and_remediation(self, client, app, soc_setup):
        """Test transitioning case to RESOLVED_CONFIRMED_FRAUD with device & beneficiary remediations."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # Create case with alert
        res = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={
                "customer_id": soc_setup["customer_id"],
                "title": "Confirmed Fraud Syndicate Attack",
                "priority": "CRITICAL",
                "alert_ids": [soc_setup["alert_id"]],
            },
        )
        case_id = res.get_json()["case"]["id"]

        # Transition to IN_PROGRESS
        res_prog = client.post(
            f"/api/admin/cases/{case_id}/status",
            headers=admin_headers,
            json={"status": "IN_PROGRESS", "note": "Active investigation initiated."},
        )
        assert res_prog.status_code == 200
        assert res_prog.get_json()["case"]["status"] == "IN_PROGRESS"

        # Resolve as CONFIRMED FRAUD with automated remediations
        res_resolve = client.post(
            f"/api/admin/cases/{case_id}/status",
            headers=admin_headers,
            json={
                "status": "RESOLVED_CONFIRMED_FRAUD",
                "resolution_summary": "Confirmed unauthorized access via credential stuffing.",
                "block_devices": True,
                "revoke_beneficiaries": True,
            },
        )
        assert res_resolve.status_code == 200
        resolved_case = res_resolve.get_json()["case"]
        assert resolved_case["status"] == "RESOLVED_CONFIRMED_FRAUD"
        assert resolved_case["resolved_at"] is not None

        with app.app_context():
            # Verify Device was atomically BLOCKED
            device = db.session.get(DeviceProfile, soc_setup["device_id"])
            assert device.trust_status == "BLOCKED"

            # Verify Beneficiary was atomically REVOKED
            ben = db.session.get(Beneficiary, soc_setup["ben_id"])
            assert ben.trust_status == "REVOKED"

            # Verify Alert was cascaded to RESOLVED
            alert = db.session.get(Alert, soc_setup["alert_id"])
            assert alert.status == "RESOLVED"

    def test_attach_alert_to_case(self, client, app, soc_setup):
        """Test linking an existing alert to a SOC Case."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # Create case without alerts
        res = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={
                "customer_id": soc_setup["customer_id"],
                "title": "Unlinked Alert Aggregation Case",
                "priority": "MEDIUM",
            },
        )
        case_id = res.get_json()["case"]["id"]

        # Attach alert
        res_attach = client.post(
            f"/api/admin/cases/{case_id}/alerts/attach",
            headers=admin_headers,
            json={"alert_id": soc_setup["alert_id"]},
        )
        assert res_attach.status_code == 200

        with app.app_context():
            alert = db.session.get(Alert, soc_setup["alert_id"])
            assert alert.case_id == case_id
            assert alert.status == "ESCALATED"

    def test_soc_metrics_summary(self, client, soc_setup):
        """Test /api/admin/cases/summary endpoint."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # Create a critical case
        client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={
                "customer_id": soc_setup["customer_id"],
                "title": "Test Metrics Case",
                "priority": "CRITICAL",
            },
        )

        res = client.get("/api/admin/cases/summary", headers=admin_headers)
        assert res.status_code == 200
        metrics = res.get_json()["metrics"]
        assert metrics["cases"]["total"] >= 1
        assert metrics["cases"]["by_priority"]["CRITICAL"] >= 1
        assert metrics["alerts"]["total"] >= 1


class TestSOCCaseSecurityAndRBAC:
    """Tests verifying role-based access control and IDOR protection."""

    def test_customer_cannot_access_soc_endpoints(self, client, soc_setup):
        """Verify regular customer cannot access any SOC or alert management APIs."""
        customer_headers = get_jwt_header(
            client,
            soc_setup["customer_email"],
            password="CustomerPass123!",
        )

        # 1. Cannot list cases
        res = client.get("/api/admin/cases", headers=customer_headers)
        assert res.status_code == 403

        # 2. Cannot create cases
        res = client.post(
            "/api/admin/cases",
            headers=customer_headers,
            json={"customer_id": soc_setup["customer_id"], "title": "Hacked Case"},
        )
        assert res.status_code == 403

        # 3. Cannot get SOC metrics
        res = client.get("/api/admin/cases/summary", headers=customer_headers)
        assert res.status_code == 403

        # 4. Cannot acknowledge alerts
        res = client.post(
            f"/api/admin/alerts/{soc_setup['alert_id']}/acknowledge",
            headers=customer_headers,
        )
        assert res.status_code == 403

    def test_soc_audit_trail_logging(self, client, app, soc_setup):
        """Verify audit logs are recorded for case creation, status transition, and notes."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # 1. Create Case
        res = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={
                "customer_id": soc_setup["customer_id"],
                "title": "Audit Logging Test Case",
                "priority": "HIGH",
            },
        )
        case_id = res.get_json()["case"]["id"]

        # 2. Add Note
        client.post(
            f"/api/admin/cases/{case_id}/notes",
            headers=admin_headers,
            json={"content": "Testing audit generation for notes."},
        )

        with app.app_context():
            created_log = AuditLog.query.filter_by(event_type="CASE_CREATED").first()
            assert created_log is not None
            assert str(case_id) in created_log.target_resource

            note_log = AuditLog.query.filter_by(event_type="CASE_NOTE_ADDED").first()
            assert note_log is not None
            assert note_log.actor == soc_setup["admin1_email"]

    def test_case_validation_and_error_handling(self, client, soc_setup):
        """Test validation errors on case creation, status transition, and notes."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # 1. Missing customer_id or title
        res = client.post("/api/admin/cases", headers=admin_headers, json={"title": "Missing Customer"})
        assert res.status_code == 400

        # 2. Non-existent customer
        res = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={"customer_id": 99999, "title": "Ghost Customer"},
        )
        assert res.status_code == 400

        # 3. Invalid priority
        res = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={"customer_id": soc_setup["customer_id"], "title": "Bad Priority", "priority": "SUPER_CRITICAL"},
        )
        assert res.status_code == 400

        # 4. Non-existent case detail (404)
        res = client.get("/api/admin/cases/99999", headers=admin_headers)
        assert res.status_code == 404

        # 5. Invalid status update
        res = client.post("/api/admin/cases/99999/status", headers=admin_headers, json={"status": "CLOSED"})
        assert res.status_code == 400

        # 6. Assign non-admin user as lead analyst
        # Create case first
        res_c = client.post(
            "/api/admin/cases",
            headers=admin_headers,
            json={"customer_id": soc_setup["customer_id"], "title": "Valid Case"},
        )
        case_id = res_c.get_json()["case"]["id"]

        res_bad_assign = client.post(
            f"/api/admin/cases/{case_id}/assign",
            headers=admin_headers,
            json={"analyst_id": soc_setup["customer_id"]},  # Customer is not an ADMIN
        )
        assert res_bad_assign.status_code == 400

        # 7. Add empty note
        res_empty_note = client.post(
            f"/api/admin/cases/{case_id}/notes",
            headers=admin_headers,
            json={"content": ""},
        )
        assert res_empty_note.status_code == 400

    def test_case_listing_filtering_and_pagination(self, client, soc_setup):
        """Test listing SOC cases with priority, status, and analyst filters."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])

        # Create 3 cases with different priorities
        for p in ["LOW", "HIGH", "CRITICAL"]:
            client.post(
                "/api/admin/cases",
                headers=admin_headers,
                json={
                    "customer_id": soc_setup["customer_id"],
                    "title": f"Test Case Priority {p}",
                    "priority": p,
                },
            )

        # 1. Filter by Priority
        res_crit = client.get("/api/admin/cases?priority=CRITICAL", headers=admin_headers)
        assert res_crit.status_code == 200
        cases_crit = res_crit.get_json()["cases"]
        assert all(c["priority"] == "CRITICAL" for c in cases_crit)

        # 2. Filter by Customer ID
        res_cust = client.get(f"/api/admin/cases?customer_id={soc_setup['customer_id']}", headers=admin_headers)
        assert res_cust.status_code == 200
        assert res_cust.get_json()["total"] >= 3

        # 3. Pagination check
        res_page = client.get("/api/admin/cases?page=1&per_page=2", headers=admin_headers)
        assert res_page.status_code == 200
        assert len(res_page.get_json()["cases"]) == 2

    def test_alert_lifecycle_dismiss_and_legacy_endpoints(self, client, soc_setup):
        """Test dismissing alert and backward-compatibility of legacy endpoints."""
        admin_headers = get_jwt_header(client, soc_setup["admin1_email"])
        alert_id = soc_setup["alert_id"]

        # Dismiss alert with note
        res = client.post(
            f"/api/admin/alerts/{alert_id}/dismiss",
            headers=admin_headers,
            json={"note": "Dismissed as expected test drill."},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["alert"]["status"] == "DISMISSED"
        assert "expected test drill" in data["alert"]["notes"]

        # Verify alert appears in filtered list
        res_list = client.get("/api/admin/alerts?status=DISMISSED", headers=admin_headers)
        assert res_list.status_code == 200
        assert any(a["id"] == alert_id for a in res_list.get_json()["alerts"])

