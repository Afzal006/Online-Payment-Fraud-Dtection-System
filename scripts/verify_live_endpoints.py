"""
Live End-to-End HTTP Endpoint Verification Script for Phase 7.1.
Tests against active running Flask server at http://127.0.0.1:5000.
"""

import urllib.request
import urllib.parse
import json
import sys


def run_test(name, fn):
    print(f"\n[RUNNING] {name}...")
    try:
        fn()
        print(f"  [PASS] {name}")
        return True
    except AssertionError as ae:
        print(f"  [FAIL] {name}: {ae}")
        return False
    except Exception as e:
        print(f"  [ERROR] {name}: {e}")
        return False


def test_health():
    req = urllib.request.Request("http://127.0.0.1:5000/api/health")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data["status"] == "healthy"
        assert data["database"] == "healthy"


def test_active_account_registration_collision():
    # Attempting to register existing active account: afzalabu777@gmail.com
    payload = {
        "name": "Afzal Abu",
        "email": "afzalabu777@gmail.com",
        "password": "SecurePassword123!",
    }
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/auth/register",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        urllib.request.urlopen(req)
        assert False, "Expected 409 Conflict"
    except urllib.error.HTTPError as err:
        assert err.code == 409
        data = json.loads(err.read().decode())
        assert "already" in data["error"].lower()
        assert data.get("code") in ("ACCOUNT_ALREADY_EXISTS", "ACCOUNT_EXISTS_VERIFIED")


def test_password_reset_for_active_account():
    payload = {"email": "afzalabu777@gmail.com"}
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/auth/forgot-password",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "instructions" in data["message"].lower() or "sent" in data["message"].lower()


def test_unverified_account_registration_collision():
    # Attempting to register existing pending account: afzalabu@gmail.com
    payload = {
        "name": "Afzal Abu",
        "email": "afzalabu@gmail.com",
        "password": "SecurePassword123!",
    }
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/auth/register",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        urllib.request.urlopen(req)
        assert False, "Expected 409 Conflict"
    except urllib.error.HTTPError as err:
        assert err.code == 409
        data = json.loads(err.read().decode())
        assert "pending verification" in data["error"].lower()
        assert data.get("code") == "ACCOUNT_EXISTS_UNVERIFIED"


def test_resend_verification_otp_for_pending_account():
    payload = {"email": "afzalabu@gmail.com"}
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/auth/resend-email-verification",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status in (200, 429)  # 429 if rate limited within cooldown window, 200 otherwise
        data = json.loads(resp.read().decode())
        assert "message" in data or "error" in data


def test_zero_leakage_in_health_and_public_apis():
    req = urllib.request.Request("http://127.0.0.1:5000/api/health")
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode()
        assert "password" not in body.lower()
        assert "otp" not in body.lower()
        assert "secret" not in body.lower()


if __name__ == "__main__":
    print("=" * 60)
    print("FRAUDSHIELD AI — LIVE API VERIFICATION SUITE")
    print("=" * 60)

    tests = [
        ("Health Check Endpoint", test_health),
        ("Active Account Registration Collision", test_active_account_registration_collision),
        ("Password Reset Request for Active Account", test_password_reset_for_active_account),
        ("Unverified Account Registration Collision", test_unverified_account_registration_collision),
        ("Resend Email Verification for Pending Account", test_resend_verification_otp_for_pending_account),
        ("Zero Secret Leakage Verification", test_zero_leakage_in_health_and_public_apis),
    ]

    results = [run_test(name, fn) for name, fn in tests]

    print("\n" + "=" * 60)
    print(f"RESULTS: {sum(results)} / {len(results)} live tests passed")
    print("=" * 60)

    if not all(results):
        sys.exit(1)
