"""
test_api.py
---------------------------------------------------------------------------
Automated pytest suite for SpendPulse FastAPI + SQLite backend.
Run locally after `py -m pip install -r requirements.txt`:
    py -m pytest -v
"""

import os
import tempfile
from fastapi.testclient import TestClient

# Point FastAPI to a fresh temporary SQLite database for testing
_tmp_dir = tempfile.TemporaryDirectory(prefix="spendpulse_fastapi_test_")
os.environ["SPENDPULSE_DB_PATH"] = os.path.join(_tmp_dir.name, "test.db")

from main import app  # noqa: E402

client = TestClient(app)


def test_health_and_auth_guard():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["framework"] == "fastapi"
    assert res.json()["currency"] == "INR"

    unauth = client.get("/api/transactions")
    assert unauth.status_code == 401


def test_demo_login_and_seeded_inr_rows():
    bad = client.post("/api/auth/login", json={"user_id": "demo", "password": "wrong"})
    assert bad.status_code == 401

    ok = client.post("/api/auth/login", json={"user_id": "demo", "password": "demo1234"})
    assert ok.status_code == 200
    token = ok.json()["token"]

    txns = client.get("/api/transactions", headers={"Authorization": f"Bearer {token}"})
    assert txns.status_code == 200
    assert txns.json()["count"] == 8


def test_register_sql_crud_and_summary():
    reg = client.post(
        "/api/auth/register",
        json={"user_id": "rohan_dev", "full_name": "Rohan Dev", "password": "mypassword"},
    )
    assert reg.status_code == 201
    headers = {"Authorization": f"Bearer {reg.json()['token']}"}

    # SQL INSERT income + expense (in INR)
    r1 = client.post(
        "/api/transactions",
        headers=headers,
        json={
            "title": "Internship Stipend",
            "amount": 25000,
            "type": "income",
            "category": "Salary",
            "date": "2026-11-20",
            "notes": "Monthly payout",
        },
    )
    assert r1.status_code == 201

    r2 = client.post(
        "/api/transactions",
        headers=headers,
        json={
            "title": "Hostel Mess & Chai",
            "amount": 3500,
            "type": "expense",
            "category": "Food & Dining",
            "date": "2026-11-21",
            "notes": "Monthly mess",
        },
    )
    assert r2.status_code == 201
    txn_id = r2.json()["data"]["id"]

    # SQL UPDATE
    upd = client.put(
        f"/api/transactions/{txn_id}",
        headers=headers,
        json={
            "title": "Hostel Mess & Snacks",
            "amount": 4000,
            "type": "expense",
            "category": "Food & Dining",
            "date": "2026-11-21",
            "notes": "Updated",
        },
    )
    assert upd.status_code == 200
    assert upd.json()["data"]["amount"] == 4000.0

    # SQL SUM / GROUP BY summary
    summary = client.get("/api/summary", headers=headers).json()
    assert summary["totalIncome"] == 25000.0
    assert summary["totalExpense"] == 4000.0
    assert summary["balance"] == 21000.0
    assert summary["categoryBreakdown"][0]["category"] == "Food & Dining"

    # SQL DELETE
    deleted = client.delete(f"/api/transactions/{txn_id}", headers=headers)
    assert deleted.status_code == 200
