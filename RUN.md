# How to run the Compliance Scanner

## Prerequisites

1. **Python 3.10+** (and `pip` or `py -m pip`)
2. **PostgreSQL** running with a database `dpdp_scanner_db` (create it if needed; set `DB_*` in `.env`)
3. **Node.js** (for frontend)
4. **`.env`** at project root with `DB_*`, `SECRET_KEY`, and `GEMINI_API_KEY`

## First-time setup

From project root:

```powershell
# Backend deps
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Frontend deps (new terminal or after backend deps)
cd frontend
npm install
cd ..
```

Create the DB in PostgreSQL:

```sql
CREATE DATABASE dpdp_scanner_db;
```

## One-command run (Windows PowerShell)

From project root (with venv activated if you use it):

```powershell
.\run.ps1
```

This opens two windows:
- **Backend** at http://127.0.0.1:8000
- **Frontend** at http://127.0.0.1:5173

Open http://127.0.0.1:5173 in your browser to use the app.

---

## Manual run

### 1. Database

Create the DB (first time only):

```bash
# In psql or pgAdmin:
CREATE DATABASE dpdp_scanner_db;
```

Ensure PostgreSQL is running and `.env` has correct `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `DB_NAME`.

### PostgreSQL: `password authentication failed`

1. **`DB_PASSWORD` in `.env` must match** the real password for user `DB_USER` in PostgreSQL (set in pgAdmin or when you installed Postgres).
2. **Use `127.0.0.1` instead of `localhost`** for `DB_HOST` if you still get auth errors on Windows (avoids IPv6 `::1` vs IPv4 mismatch).
3. **Or use SQLite for local dev** (no Postgres): add to `.env`:
   ```env
   USE_SQLITE=1
   ```
   Tables are created in `backend/compliance_local.db` automatically.

4. **Or set a full URL** (good if the password has special characters):
   ```env
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@127.0.0.1:5432/compliance_scanner_db
   ```

### 2. Backend

From **project root** (`Compliance_Scanner`):

```bash
# Optional: create and activate venv
python -m venv venv
.\venv\Scripts\Activate.ps1   # Windows
# source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

API: http://127.0.0.1:8000  
Docs: http://127.0.0.1:8000/docs

### 3. Frontend

In a **second terminal**, from project root:

```bash
cd frontend
npm install
npm run dev
```

App: http://127.0.0.1:5173

---

## CLI scanner (no backend)

To run the DPDP scanner from the command line (e.g. local repo or GitHub URL):

```bash
python main.py scan /path/to/repo
python main.py scan https://github.com/user/repo
```

Options: `--output report`, `--no-llm`, etc. Run `python main.py scan --help` for details.
