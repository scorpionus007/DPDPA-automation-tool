# DPDPA Automation Tool

> A static-analysis tool that scans source code for **Digital Personal Data Protection Act, 2023 (DPDP)** compliance — detecting personal data (PII), consent and rights gaps, security and retention issues — and produces an auditable compliance report. Runs as a **CLI** on a single repository or as a **web platform** that scans an entire GitHub organization.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/UI-React%2019%20%2B%20Vite-61DAFB?logo=react&logoColor=black">
  <img alt="DPDP" src="https://img.shields.io/badge/Framework-DPDP%20Act%202023-1f6feb">
  <img alt="Status" src="https://img.shields.io/badge/Status-MVP%20baseline-orange">
</p>

> **Academic note:** This repository is the **MVP baseline** for a minor project on DPDP compliance automation. It is derived from the open-source `compliance_scanner` project; the minor-project contribution builds on top of this baseline (see **[Roadmap / Planned Contributions](#6-roadmap--planned-contributions-minor-project)**). Please read that section alongside the project report.

---

## 1. Problem

India's DPDP Act, 2023 requires every organization that processes personal data to obtain valid consent, publish notices, honour data-principal rights (access/correction/erasure), secure the data, limit retention, and report breaches — with penalties up to ₹250 crore. Most of these obligations are ultimately **implemented (or violated) in source code**, yet compliance today is assessed through manual questionnaires and audits that never look at the code.

This tool answers: **"Does this codebase meet its DPDP obligations, and where exactly are the gaps?"** — automatically, from the source.

---

## 2. What it does (current MVP)

- **PII discovery** — detects personal data in code (emails, phone, government IDs, etc.) and where it is collected, stored, and shared.
- **Rule engine — 14 DPDP detectors** mapped to specific sections of the Act (see the table below).
- **Data-flow analysis** — traces PII from collection points to sinks (analytics, logging, third parties) to flag flows without consent.
- **Optional LLM enrichment** — an advisory pipeline (repo summary → route classification → finding enrichment with fix steps and DPDP references → gap analysis → skeptic review → deep review). AI is **advisory only**; the deterministic rules produce the verdict.
- **Compliance score & grade** — a weighted 0–100 score with a per-section breakdown and remediation-effort estimate.
- **Organization-wide scanning** — a FastAPI backend + GitHub App can scan every repo in a GitHub org (bulk-scan queue) and merge results into an org-level knowledge base.
- **Reports** — PDF (cover page, score, finding cards with severity + DPDP badges), an HTML companion, or JSON for automation.
- **Scan history** — SQLite-backed history with **delta scans** (only re-report what changed) and remediation tracking.
- **Web dashboard** — a React UI for org dashboards, repositories, bulk scans, and data-flow views.

### DPDP obligations covered by the rule engine

| Rule | DPDP obligation |
|---|---|
| `consent` | Consent for processing (Sec 6) |
| `consent_withdrawal` | Withdrawal of consent (Sec 6) |
| `security` | Reasonable security safeguards — plaintext PII in logs, hardcoded secrets, unhashed passwords (Sec 8) |
| `retention` | Retention limitation (Sec 8) |
| `deletion` | Right to erasure (Sec 8/12) |
| `data_access` | Right to access & data portability (Sec 11) |
| `audit_trail` | Records of processing / audit trail (Sec 8) |
| `breach` | Breach detection & logging (Sec 8) |
| `childrens_data` | Children's data & age verification (Sec 9) |
| `cross_border` | Cross-border transfer (Sec 16) |
| `grievance` | Grievance redressal / DPO contact (Sec 13) |
| `third_party` | Third-party data sharing (Sec 5) |
| `purpose` | Purpose limitation (Sec 5) |
| `data_flow` | PII flow to analytics/marketing/logging without consent |

---

## 3. Architecture

```
┌──────────────────────────────┐
│  Frontend (React + Vite)     │  org dashboard · repos · bulk scans · data-flows
└──────────────┬───────────────┘
               │ REST / JSON
┌──────────────▼───────────────┐
│  Backend (FastAPI + Postgres)│  auth · GitHub App · bulk-scan queue (Redis/RQ)
└──────────────┬───────────────┘
               │ calls
┌──────────────▼───────────────┐
│  Engine (dpdp_scanner/)      │  also runs standalone as a CLI
│  ingest → extract → 14 rules │
│  → LLM enrich → score → report
└──────────────────────────────┘
```

- **Engine** (`dpdp_scanner/`) — the reusable core: `ingestor` (clone/read code), `extractor` (PII + data-flow graph), `rule_engine` + `rules/` (the 14 detectors), `llm_layer` (optional AI), `reporter`/`html_reporter`/`org_reporter`, `scan_history`, `kb` (org knowledge-base merge).
- **Backend** (`backend/`) — FastAPI app: users/auth, GitHub App org connection, bulk-scan workers on a Redis/RQ queue, Alembic migrations.
- **Frontend** (`frontend/`) — React 19 + Vite dashboard.
- **CLI** (`main.py`) — scan a single repo or local path without the web stack.

**Tech stack:** Python 3.10+, Click, GitPython, ReportLab (PDF), FastAPI, SQLAlchemy + PostgreSQL, Alembic, Redis + RQ, React 19 + Vite. LLM via Gemini/Claude API (optional).

---

## 4. Getting started

### Option A — CLI (scan one repo, no web stack)

```bash
pip install -r requirements.txt
# optional: copy .env.example to .env and set an LLM API key (GEMINI_API_KEY / CLAUDE_API_KEY)

# scan a local path or a GitHub URL
python main.py ./path/to/repo
python main.py https://github.com/owner/repo --html          # PDF + HTML report
python main.py ./repo --no-llm                               # deterministic only, no AI
python main.py ./repo --json                                 # JSON to stdout (automation)
```

Useful flags: `--no-llm` (skip AI), `--no-deep-review` (cheaper AI), `--json`, `--html`, `--token` (private repos), `--debug` (per-rule output).
Cost controls for LLM runs: `DPDP_MAX_ENRICH` (default 25 findings enriched) and `DPDP_ENRICH_BATCH_SIZE` (default 4 per API call).

### Option B — Full web platform (org-wide scanning)

Prerequisites: Python 3.10+, **PostgreSQL**, **Node.js**, and **Redis** (for the scan queue). See **[RUN.md](RUN.md)** for the complete walkthrough.

```bash
# backend
python -m venv venv && source venv/bin/activate      # (Windows: .\venv\Scripts\Activate.ps1)
pip install -r requirements.txt
# create the Postgres DB + a .env with DB_*, SECRET_KEY, and an LLM API key
alembic upgrade head
uvicorn backend.main:app --reload                    # API on http://localhost:8000

# frontend (new terminal)
cd frontend && npm install && npm run dev            # UI on http://localhost:5173
```

---

## 5. Project structure

```
dpdp_scanner/       # the engine (ingest, extract, rules, LLM, reports, KB)
  rules/            # the 14 DPDP detectors
backend/            # FastAPI app: auth, GitHub App, org scanning, RQ workers
frontend/           # React + Vite dashboard
alembic/            # database migrations
main.py             # CLI entry point
tests/              # test suite
docs/               # design notes
RUN.md              # full setup & run guide
```

---

## 6. Roadmap / Planned Contributions (minor project)

Building on this MVP baseline, the minor project will add (and *measure*):

- [ ] **DPDP-native control library** — a single source of truth mapping rules → controls → DPDP sections, with an ISO 27701 / SOC 2 crosswalk.
- [ ] **Completeness / gap panel** — surface DPDP obligations that have *no detector* (e.g. Notice §5, correction §12, nomination §14), so silent gaps can't be hidden.
- [ ] **Higher-precision PII detection** — AST-based (tree-sitter) analysis to remove comment/string false positives that limit regex scanning.
- [ ] **Cross-repo knowledge base** — link the same data entity/subject across repositories.
- [ ] **Bring-your-own-model (BYOM) AI** — pluggable, in-region-capable models with a zero-network `rules_only` mode.
- [ ] **Evaluation** — a labelled corpus + precision/recall metrics comparing against a per-repo baseline (the core academic deliverable).

*(See the project report for the full problem statement, literature review, and gap analysis.)*

---

## 7. Provenance & license

This project is derived from the open-source **`compliance_scanner`** MVP; the baseline engine and platform are the prior open-source work, and the minor-project contributions listed above are built on top. The upstream project is licensed under **AGPL-3.0**; any redistribution should preserve that license and attribution.

> **Disclaimer:** This tool generates compliance findings for informational purposes only and does not constitute legal advice. Always consult a qualified professional before relying on any output.
