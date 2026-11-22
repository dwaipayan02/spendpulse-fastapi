"""
db.py
---------------------------------------------------------------------------
Relational SQLite database layer for SpendPulse (FastAPI + INR Edition).
Uses parameterized SQL commands (CREATE TABLE, INSERT, SELECT, UPDATE,
DELETE, SUM/GROUP BY) and closes every connection cleanly (Windows-safe).
"""

from contextlib import contextmanager
import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timezone

ALLOWED_TYPES = ("income", "expense")
ALLOWED_CATEGORIES = (
    "Salary",
    "Freelance",
    "Investments",
    "Food & Dining",
    "Housing",
    "Transport",
    "Utilities",
    "Entertainment",
    "Shopping",
    "Health",
    "Other",
)

# Realistic Indian Rupee (INR) seed transactions for the demo account
SEED_TRANSACTIONS = [
    ("Monthly Software Engineer Salary", 65000.00, "income", "Salary", "2026-11-01", "Direct bank credit"),
    ("Flat Rent & Maintenance", 18000.00, "expense", "Housing", "2026-11-02", "Monthly house rent"),
    ("Freelance React UI Project", 12000.00, "income", "Freelance", "2026-11-05", "Client dashboard milestone"),
    ("Groceries & Fresh Vegetables", 4200.00, "expense", "Food & Dining", "2026-11-07", "Supermarket & local market"),
    ("Metro Card & Auto Commute", 1850.00, "expense", "Transport", "2026-11-09", "Daily office travel"),
    ("Broadband & Electricity Bill", 2600.00, "expense", "Utilities", "2026-11-12", "Monthly UPI autopay"),
    ("Team Dinner & Filter Coffee", 1450.00, "expense", "Food & Dining", "2026-11-15", "Weekend outing"),
    ("Gym Membership & Pharmacy", 1500.00, "expense", "Health", "2026-11-17", "Monthly fitness plan"),
]


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with a random 16-byte salt using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return salt, dk.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Constant-time password verification against stored salt and hash."""
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected_hash)


class Database:
    """SQLite database wrapper with live SQL query logging."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.sql_log: list[dict] = []
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()
        self._seed_demo_account()

    @contextmanager
    def _connect(self):
        """Open SQLite connection, commit/rollback, and always close cleanly."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _record_sql(self, sql: str, params: tuple = ()) -> None:
        compact = " ".join(sql.strip().split())
        self.sql_log.insert(
            0,
            {
                "sql": compact,
                "params": [str(p) for p in params],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        del self.sql_log[30:]

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL UNIQUE,
                    full_name TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    amount REAL NOT NULL CHECK(amount > 0),
                    type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
                    category TEXT NOT NULL,
                    date TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_txn_owner_date ON transactions(owner_id, date DESC)")

    def _seed_demo_account(self) -> None:
        """Seed demo user (demo / demo1234) with INR sample rows if missing."""
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM users WHERE user_id = ?", ("demo",)).fetchone()
            if row:
                return
            salt, pw_hash = hash_password("demo1234")
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.execute(
                "INSERT INTO users (user_id, full_name, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                ("demo", "Demo Developer", salt, pw_hash, now),
            )
            demo_pk = cur.lastrowid
            for title, amount, txn_type, category, date_str, notes in SEED_TRANSACTIONS:
                conn.execute(
                    """
                    INSERT INTO transactions (owner_id, title, amount, type, category, date, notes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (demo_pk, title, amount, txn_type, category, date_str, notes, now),
                )

    # ---------------- USER AUTH SQL ----------------

    def create_user(self, user_id: str, password: str, full_name: str = "") -> tuple[dict | None, str | None]:
        clean_uid = (user_id or "").strip().lower()
        clean_name = (full_name or clean_uid).strip()[:80]
        if len(clean_uid) < 3 or len(clean_uid) > 32 or not clean_uid.replace("_", "").replace("-", "").isalnum():
            return None, "User ID must be 3-32 letters, numbers, underscores, or hyphens."
        if len(password or "") < 6:
            return None, "Password must be at least 6 characters long."

        salt, pw_hash = hash_password(password)
        now = datetime.now(timezone.utc).isoformat()
        sql = "INSERT INTO users (user_id, full_name, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
        self._record_sql(sql, (clean_uid, clean_name, "<salt>", "<hash>", now))
        try:
            with self._connect() as conn:
                cur = conn.execute(sql, (clean_uid, clean_name, salt, pw_hash, now))
                return {"id": cur.lastrowid, "user_id": clean_uid, "full_name": clean_name}, None
        except sqlite3.IntegrityError:
            return None, "That User ID is already registered."

    def authenticate_user(self, user_id: str, password: str) -> dict | None:
        clean_uid = (user_id or "").strip().lower()
        sql = "SELECT id, user_id, full_name, password_salt, password_hash FROM users WHERE user_id = ?"
        self._record_sql(sql, (clean_uid,))
        with self._connect() as conn:
            row = conn.execute(sql, (clean_uid,)).fetchone()
        if not row:
            return None
        if not verify_password(password or "", row["password_salt"], row["password_hash"]):
            return None
        return {"id": row["id"], "user_id": row["user_id"], "full_name": row["full_name"]}

    def get_user_by_pk(self, pk: int) -> dict | None:
        sql = "SELECT id, user_id, full_name, created_at FROM users WHERE id = ?"
        with self._connect() as conn:
            row = conn.execute(sql, (pk,)).fetchone()
        return dict(row) if row else None

    # ---------------- TRANSACTION SQL ----------------

    def list_transactions(
        self, owner_id: int, txn_type: str | None = None, category: str | None = None, search: str | None = None
    ) -> list[dict]:
        clauses = ["owner_id = ?"]
        params: list = [owner_id]

        if txn_type and txn_type.lower() in ALLOWED_TYPES:
            clauses.append("type = ?")
            params.append(txn_type.lower())
        if category and category != "All":
            clauses.append("category = ?")
            params.append(category)
        if search and search.strip():
            pattern = f"%{search.strip()}%"
            clauses.append("(title LIKE ? OR category LIKE ? OR notes LIKE ?)")
            params.extend([pattern, pattern, pattern])

        sql = (
            "SELECT id, title, amount, type, category, date, notes, created_at "
            f"FROM transactions WHERE {' AND '.join(clauses)} "
            "ORDER BY date DESC, id DESC"
        )
        self._record_sql(sql, tuple(params))
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_transaction(self, owner_id: int, txn_id: int) -> dict | None:
        sql = "SELECT id, title, amount, type, category, date, notes, created_at FROM transactions WHERE id = ? AND owner_id = ?"
        self._record_sql(sql, (txn_id, owner_id))
        with self._connect() as conn:
            row = conn.execute(sql, (txn_id, owner_id)).fetchone()
        return dict(row) if row else None

    def insert_transaction(self, owner_id: int, data: dict) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        sql = (
            "INSERT INTO transactions (owner_id, title, amount, type, category, date, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        params = (
            owner_id,
            data["title"].strip(),
            round(float(data["amount"]), 2),
            data["type"].lower(),
            data["category"],
            data["date"],
            (data.get("notes") or "").strip()[:250],
            now,
        )
        self._record_sql(sql, params)
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            row = conn.execute(
                "SELECT id, title, amount, type, category, date, notes, created_at FROM transactions WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
        return dict(row)

    def update_transaction(self, owner_id: int, txn_id: int, data: dict) -> dict | None:
        sql = (
            "UPDATE transactions "
            "SET title = ?, amount = ?, type = ?, category = ?, date = ?, notes = ? "
            "WHERE id = ? AND owner_id = ?"
        )
        params = (
            data["title"].strip(),
            round(float(data["amount"]), 2),
            data["type"].lower(),
            data["category"],
            data["date"],
            (data.get("notes") or "").strip()[:250],
            txn_id,
            owner_id,
        )
        self._record_sql(sql, params)
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT id, title, amount, type, category, date, notes, created_at FROM transactions WHERE id = ?",
                (txn_id,),
            ).fetchone()
        return dict(row)

    def delete_transaction(self, owner_id: int, txn_id: int) -> dict | None:
        existing = self.get_transaction(owner_id, txn_id)
        if not existing:
            return None
        sql = "DELETE FROM transactions WHERE id = ? AND owner_id = ?"
        self._record_sql(sql, (txn_id, owner_id))
        with self._connect() as conn:
            conn.execute(sql, (txn_id, owner_id))
        return existing

    def get_summary(self, owner_id: int) -> dict:
        totals_sql = (
            "SELECT "
            "COALESCE(SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END), 0) AS total_income, "
            "COALESCE(SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END), 0) AS total_expense, "
            "COUNT(*) AS txn_count "
            "FROM transactions WHERE owner_id = ?"
        )
        group_sql = (
            "SELECT category, ROUND(SUM(amount), 2) AS amount "
            "FROM transactions WHERE owner_id = ? AND type = 'expense' "
            "GROUP BY category ORDER BY amount DESC"
        )
        self._record_sql(totals_sql, (owner_id,))
        self._record_sql(group_sql, (owner_id,))

        with self._connect() as conn:
            totals = conn.execute(totals_sql, (owner_id,)).fetchone()
            groups = conn.execute(group_sql, (owner_id,)).fetchall()

        total_income = round(float(totals["total_income"]), 2)
        total_expense = round(float(totals["total_expense"]), 2)
        balance = round(total_income - total_expense, 2)
        savings_rate = round(((total_income - total_expense) / total_income) * 100, 1) if total_income > 0 else 0.0

        category_breakdown = [
            {
                "category": r["category"],
                "amount": round(float(r["amount"]), 2),
                "share": round((float(r["amount"]) / total_expense) * 100, 1) if total_expense > 0 else 0.0,
            }
            for r in groups
        ]

        return {
            "totalIncome": total_income,
            "totalExpense": total_expense,
            "balance": balance,
            "savingsRate": savings_rate,
            "transactionCount": int(totals["txn_count"]),
            "categoryBreakdown": category_breakdown,
        }
