# DPDP Compliance Scanner

**Terminal-only (CLI)** static analysis tool for **Digital Personal Data Protection Act 2023** compliance. Scans codebases for consent, PII handling, audit trails, security, and children's data rules; optionally enriches findings with an LLM and produces PDF or JSON reports.

---

## Features

- **Rule engine**: Consent collection/withdrawal, PII in logs, password hashing, audit trails, deletion/export/breach alerting, data access, children's data (Section 9), third-party sharing, cross-border.
- **LLM pipeline** (optional): Repo summary, route classification (user-facing vs internal), finding enrichment with fix steps and DPDP references, gap analysis, skeptic review, deep compliance review.
- **Scan history**: SQLite-backed history, delta scans, remediation tracking. Clear or delete via `scan_history.clear_db()` / `delete_db()` or CLI.
- **Reports**: PDF with cover page (repo name, score bar, metadata), executive summary, finding cards with severity bars and DPDP badges, page headers/footers; or JSON output for automation.

---

## Requirements

- **Python 3.10+**
- Optional: **`CLAUDE_API_KEY`** in a `.env` file (project root or next to `dpdp_scanner`) for LLM enrichment and route classification.

---

## Installation

```bash
cd dpdp-scanner
pip install -r requirements.txt
# Optional: copy .env.example to .env and set CLAUDE_API_KEY
```

---

## Usage

```bash
# Scan a local path or GitHub repo URL
python main.py /path/to/repo
python main.py https://github.com/owner/repo

# Options
python main.py /path/to/repo --output report          # PDF report (default: report.pdf)
python main.py /path/to/repo --no-llm                  # Skip LLM (faster; rules only)
python main.py /path/to/repo --json                    # JSON to stdout, no PDF
python main.py /path/to/repo --history-db path/to.db   # Custom scan history DB
python main.py /path/to/repo --no-deep-review          # Skip Layer 5 deep review (fewer API calls)
python main.py /path/to/repo --debug                   # Per-rule debug: what each rule checked and findings count (env: DPDP_DEBUG=1)
```

### Cost controls (API usage)

To reduce Claude API cost you can:

- **Limit enriched findings**  
  Set `DPDP_MAX_ENRICH` (default `25`). Only the first N findings by severity (HIGH → MEDIUM → LOW) are sent for LLM enrichment; the rest get fallback text and no Layer 2 call.
- **Batch Layer 2 calls**  
  Set `DPDP_ENRICH_BATCH_SIZE` (default `4`). Findings within the cap are sent in batches of this size (one API call per batch instead of one per finding).
- **Skip deep review**  
  Use `--no-deep-review` to skip Layer 5 (Deep Compliance Review), saving roughly 6 API calls per run.

Other possible optimizations (not yet implemented): larger route-classifier batch (e.g. 15), batching ambiguous-route deep reviews, or response caching for repeated scans.

**Scan history** is stored by default in `.dpdp-history/history.db` (or `DPDP_HISTORY_DB`). Clear all data and remove the DB file programmatically:

```python
from dpdp_scanner.scan_history import clear_db   # wipe tables only
from dpdp_scanner.scan_history import delete_db # wipe tables + delete DB file
delete_db()
```

---

## Updates (changelog)

- **Terminal-only**: All Electron/React frontend and `gui_bridge` removed; CLI only.
- **PDF**: Encoding fix for corrupted characters (e.g. em dash); cover page with repo name, score bar, files indexed, languages; executive risk statement; finding cards with left severity bar and DPDP section badge; summary table with wrapped cells; header/footer and page numbers on every page.
- **Rules**:  
  - **PASSWORD_NOT_HASHED**: Skip DB connection/config files (e.g. `DriverManager.getConnection`, HikariCP, DBCP, c3p0).  
  - **CONSENT_MISSING**: After LLM route classification, findings for internal routes and utility files (*Util*, *Helper*, *Client*, *Processor*, *Filter*, *Config*, etc.) are removed or reconciled.  
  - **Children's data**: Extra path skip patterns (sidebar, navbar, layout, etc.) and data-processing signal check to avoid UI-only false positives; when AGE_VERIFICATION_PRESENT is present, CHILDRENS_DATA_PATTERN is downgraded to INFO.
- **LLM Layer 2**: “Stay on topic” rules and context header for repo-wide vs file-specific findings; no “rule engine flagged…” or “generic scan result” phrasing.
- **Scan history**: `clear_db()` and `delete_db()` for wiping history and removing the DB file.

---

## License

See repository license file.

## Backend SetUp
```bash
cd compliance_scanner
uvicorn backend.main:app --reload
```

## Frontend Setup
```bash
cd compliance_scanner
cd frontend 
npm run dev
```