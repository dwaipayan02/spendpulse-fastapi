# SpendPulse ₹ — Full-Stack React.js + FastAPI + SQLite App

**Tech Stack:** React.js + Chart.js (Frontend) | FastAPI + Pydantic (Backend API) | SQLite (Relational SQL Database) | Indian Rupees (₹ INR)

---

## Run Locally on Windows (3 Commands)

```bat
py -m pip install -r requirements.txt
py -m pytest -v
py -m uvicorn main:app --reload
```

Then **open Chrome or Edge** and paste these URLs directly into the address bar:
- **Web App:** `http://127.0.0.1:8000`
- **Interactive Swagger API Docs:** `http://127.0.0.1:8000/docs`

**Demo Login:** User ID `demo` | Password `demo1234` (or click **Create Account** to register your own user in SQLite).

---

## How the Project Works

1. **React Frontend (`public/index.html`):**
   - Renders the Login / Create Account screen, INR KPI cards, Add/Edit form, live **Chart.js Donut/Pie Chart**, filtered transaction list, and live SQL command log.
   - Whenever you add, edit, or delete a transaction, React sends a `fetch()` request to FastAPI and re-fetches `/api/summary`, causing the Pie Chart to animate and recalculate immediately.
2. **FastAPI Backend (`main.py`):**
   - Validates every request automatically using **Pydantic** models (`RegisterRequest`, `LoginRequest`, `TransactionPayload`).
   - Protects transaction routes using FastAPI's `Depends(get_current_user)` dependency, which verifies the signed Bearer token.
   - Automatically generates live interactive API documentation at `/docs`.
3. **SQLite Database (`db.py` → `data/spendpulse.db`):**
   - Stores accounts in the `users` table (with salted PBKDF2-SHA256 password hashes) and transactions in the `transactions` table linked via `FOREIGN KEY (owner_id) REFERENCES users(id)`.
   - Uses parameterized SQL `INSERT`, `SELECT ... LIKE`, `UPDATE`, `DELETE`, and `SUM() / GROUP BY` queries and closes every connection cleanly on Windows.
