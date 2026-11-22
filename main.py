"""
main.py
---------------------------------------------------------------------------
Clean FastAPI backend for SpendPulse (INR + SQLite + Auth).
Run locally with:
    py -m uvicorn main:app --reload
Then open http://127.0.0.1:8000 in Chrome/Edge (and /docs for Swagger UI).
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from db import ALLOWED_CATEGORIES, Database

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SPENDPULSE_DB_PATH") or os.path.join(BASE_DIR, "data", "spendpulse.db")
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
SECRET_KEY = (os.environ.get("SPENDPULSE_SECRET") or secrets.token_hex(32)).encode("utf-8")
TOKEN_TTL_SECONDS = 60 * 60 * 24  # 24 hours

db = Database(DB_PATH)

app = FastAPI(
    title="SpendPulse INR API",
    description="Full-stack Personal Finance REST API powered by FastAPI + SQLite",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- PYDANTIC SCHEMAS (AUTOMATIC VALIDATION) ----------------

class RegisterRequest(BaseModel):
    user_id: str = Field(..., min_length=3, max_length=32)
    full_name: str = Field(default="", max_length=80)
    password: str = Field(..., min_length=6, max_length=128)


class LoginRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class TransactionPayload(BaseModel):
    title: str = Field(..., min_length=2, max_length=100)
    amount: float = Field(..., gt=0, le=1_000_000_000)
    type: Literal["income", "expense"]
    category: str
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    notes: str = Field(default="", max_length=250)


# ---------------- TOKEN HELPERS & AUTH DEPENDENCY ----------------

def create_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "uid": user["user_id"],
        "name": user["full_name"],
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")
    sig = hmac.new(SECRET_KEY, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{sig}"


def verify_token(token: str) -> dict | None:
    try:
        encoded, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(SECRET_KEY, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    if payload.get("exp", 0) < int(time.time()):
        return None
    return payload


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required. Please log in.")
    claims = verify_token(authorization[7:].strip())
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    user = db.get_user_by_pk(int(claims["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="User account no longer exists.")
    return user


# ---------------- FRONTEND ROUTE ----------------

@app.get("/", include_in_schema=False)
def serve_frontend():
    return FileResponse(os.path.join(PUBLIC_DIR, "index.html"))


# ---------------- HEALTH & AUTH ROUTES ----------------

@app.get("/api/health")
def health_check():
    return {"status": "ok", "framework": "fastapi", "database": "sqlite3", "currency": "INR"}


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterRequest):
    user, err = db.create_user(payload.user_id, payload.password, payload.full_name)
    if err:
        code = 409 if "already registered" in err else 400
        raise HTTPException(status_code=code, detail=err)
    return {"token": create_token(user), "user": user}


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    user = db.authenticate_user(payload.user_id, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid User ID or password.")
    return {"token": create_token(user), "user": user}


@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return {"user": user}


# ---------------- TRANSACTION CRUD & ANALYTICS ROUTES ----------------

@app.get("/api/transactions")
def list_transactions(
    type: str | None = Query(default=None),
    category: str | None = Query(default=None),
    search: str | None = Query(default=None),
    user: dict = Depends(get_current_user),
):
    items = db.list_transactions(owner_id=user["id"], txn_type=type, category=category, search=search)
    return {"count": len(items), "data": items}


@app.post("/api/transactions", status_code=201)
def create_transaction(payload: TransactionPayload, user: dict = Depends(get_current_user)):
    if payload.category not in ALLOWED_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Category must be one of: {', '.join(ALLOWED_CATEGORIES)}")
    created = db.insert_transaction(user["id"], payload.model_dump())
    return {"data": created}


@app.put("/api/transactions/{txn_id}")
def update_transaction(txn_id: int, payload: TransactionPayload, user: dict = Depends(get_current_user)):
    if payload.category not in ALLOWED_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Category must be one of: {', '.join(ALLOWED_CATEGORIES)}")
    updated = db.update_transaction(user["id"], txn_id, payload.model_dump())
    if not updated:
        raise HTTPException(status_code=404, detail="Transaction not found.")
    return {"data": updated}


@app.delete("/api/transactions/{txn_id}")
def delete_transaction(txn_id: int, user: dict = Depends(get_current_user)):
    deleted = db.delete_transaction(user["id"], txn_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Transaction not found.")
    return {"deleted": deleted}


@app.get("/api/summary")
def get_summary(user: dict = Depends(get_current_user)):
    return db.get_summary(user["id"])


@app.get("/api/sql-log")
def get_sql_log(user: dict = Depends(get_current_user)):
    return {"logs": db.sql_log}
