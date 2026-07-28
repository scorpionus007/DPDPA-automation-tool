"""
Scan history management for DPDP Scanner.
Uses SQLite stored at .dpdp-history/history.db in working directory.

Repo identity: git commit hash (primary), URL-based fallback.
Delta scanning: compares file SHA256 hashes between runs.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

def _resolve_db_path() -> tuple[Path, Path]:
    """Resolve DB_DIR and DB_PATH from env or default."""
    env_db = os.environ.get("DPDP_HISTORY_DB")
    if env_db:
        p = Path(env_db)
        return p.parent, p
    d = Path(".dpdp-history")
    return d, d / "history.db"


DB_DIR, DB_PATH = _resolve_db_path()


def set_db_path(path: str | Path) -> None:
    """Override DB path (e.g. from --history-db). Affects all subsequent calls."""
    global DB_DIR, DB_PATH
    p = Path(path)
    DB_PATH = p
    DB_DIR = p.parent


def _get_conn() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_key       TEXT NOT NULL,
            repo_url       TEXT,
            repo_name      TEXT,
            commit_hash    TEXT,
            scan_date      TEXT NOT NULL,
            finding_count  INTEGER DEFAULT 0,
            high_count     INTEGER DEFAULT 0,
            medium_count   INTEGER DEFAULT 0,
            low_count      INTEGER DEFAULT 0,
            output_file    TEXT,
            scan_mode      TEXT,
            is_delta       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER NOT NULL,
            finding_key      TEXT NOT NULL,
            rule             TEXT NOT NULL,
            severity         TEXT NOT NULL,
            file_path        TEXT,
            description      TEXT,
            confidence       REAL,
            status           TEXT DEFAULT 'open',
            first_seen_date  TEXT,
            last_seen_date   TEXT,
            resolved_date    TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS file_hashes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            sha256    TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_key  ON findings(finding_key);
        CREATE INDEX IF NOT EXISTS idx_scans_repo    ON scans(repo_key);
        CREATE INDEX IF NOT EXISTS idx_hashes_scan   ON file_hashes(scan_id);
    """)
    try:
        conn.execute("ALTER TABLE scans ADD COLUMN score REAL")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    conn.commit()


def clear_db() -> None:
    """Delete all scan history (scans, findings, file_hashes). Keeps schema."""
    conn = _get_conn()
    try:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM file_hashes")
        conn.execute("DELETE FROM scans")
        conn.commit()
    finally:
        conn.close()


def delete_db() -> None:
    """Clear all scan history and delete the database file from disk."""
    clear_db()
    path = Path(DB_PATH)
    if path.exists():
        path.unlink()
    if DB_DIR.exists() and not any(DB_DIR.iterdir()):
        DB_DIR.rmdir()


def init_git_repo(repo_path: str) -> bool:
    """
    Initialize a git repository at repo_path if it isn't one.
    Returns True if it's now a git repo with at least one commit.
    """
    abs_path = os.path.abspath(repo_path)
    try:
        # 1. Already a git repo?
        if os.path.exists(os.path.join(abs_path, ".git")):
            # Check if it has any commits
            res = subprocess.run(
                ["git", "-C", abs_path, "rev-parse", "--is-inside-work-tree"],
                capture_output=True, text=True, timeout=5
            )
            if res.returncode == 0:
                return True

        # 2. Not a repo — initialize
        env = os.environ.copy()
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"})
        
        subprocess.run(["git", "init", abs_path], env=env, capture_output=True, check=True, timeout=10)
        
        # 3. Add files and commit so we have a HEAD
        subprocess.run(["git", "-C", abs_path, "add", "."], env=env, capture_output=True, check=True, timeout=20)
        # Configure a dummy user if none exists
        subprocess.run(["git", "-C", abs_path, "config", "user.email", "scanner@dpdp.local"], env=env, capture_output=True, timeout=5)
        subprocess.run(["git", "-C", abs_path, "config", "user.name", "DPDP Scanner"], env=env, capture_output=True, timeout=5)
        
        subprocess.run(
            ["git", "-C", abs_path, "commit", "-m", "Initial commit for compliance history"],
            env=env, capture_output=True, check=True, timeout=20
        )
        return True
    except Exception as e:
        # Standardize error reporting
        if not any(x in str(e).lower() for x in ["timeout", "file not found"]):
            print(f"DEBUG: git init failed for {abs_path}: {e}")
        return False


def get_commit_hash(repo_path: str, auto_init: bool = False) -> str | None:
    """Get HEAD commit hash. Returns None if not a git repo."""
    try:
        # Suppress interactive prompts
        env = os.environ.copy()
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"})

        result = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env
        )
        if result.returncode == 0:
            return result.stdout.strip()
        
        if auto_init:
            if init_git_repo(repo_path):
                # Try again after init
                result = subprocess.run(
                    ["git", "-C", repo_path, "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=env
                )
                return result.stdout.strip() if result.returncode == 0 else None

        return None
    except Exception:
        return None


def get_changed_files_from_git(repo_path: str, since_hash: str) -> list[str] | None:
    """
    Get list of files changed between since_hash and HEAD.
    Returns None if git command fails.
    """
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "diff", "--name-only", since_hash, "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except Exception:
        pass
    return None


def get_changed_files_git_native(
    repo_path: str,
    since_hash: str,
    current_hash: str,
) -> list[str] | None:
    """
    Use git diff to get changed files between two commits.
    Returns list of relative file paths, or None if git unavailable.
    """
    if not since_hash or not current_hash or since_hash == current_hash:
        return []

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                repo_path,
                "diff",
                "--name-only",
                since_hash,
                current_hash,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except Exception:
        pass
    return None


def compute_delta_with_git(
    repo_path: str,
    current_findings: list,
    previous_findings: list,
    current_hashes: dict[str, str],
    previous_hashes: dict[str, str],
    current_hash: str | None = None,
    previous_hash: str | None = None,
) -> dict[str, Any]:
    """
    Enhanced delta with git-native changed file detection.
    Falls back to hash comparison if git diff unavailable.
    """
    git_changed = None
    if current_hash and previous_hash:
        git_changed = get_changed_files_git_native(
            repo_path, previous_hash, current_hash
        )

    if git_changed is not None:
        changed_files = git_changed
        unchanged_files = [
            p for p in current_hashes if p not in set(changed_files)
        ]
        method = "git_diff"
    else:
        all_paths = set(current_hashes) | set(previous_hashes)
        changed_files = [
            p for p in all_paths
            if current_hashes.get(p) != previous_hashes.get(p)
        ]
        unchanged_files = [
            p for p in all_paths
            if current_hashes.get(p) == previous_hashes.get(p)
            and p in current_hashes
        ]
        method = "hash_comparison"

    prev_by_key = {f["finding_key"]: f for f in previous_findings}
    curr_by_key = {make_finding_key(f): f for f in current_findings}

    new_findings = [f for k, f in curr_by_key.items() if k not in prev_by_key]
    resolved_findings = [f for k, f in prev_by_key.items() if k not in curr_by_key]
    unchanged_findings = [f for k, f in curr_by_key.items() if k in prev_by_key]

    return {
        "is_first_scan": False,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
        "changed_files": changed_files,
        "unchanged_files": unchanged_files,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "unchanged_count": len(unchanged_findings),
        "changed_files_count": len(changed_files),
        "delta_method": method,
    }


def _extract_repo_name(target: str) -> str:
    if "github.com" in target:
        match = re.search(r"github\.com[:/][^/]+/([^/]+?)(?:\.git)?$", target)
        if match:
            return match.group(1)
    return os.path.basename(os.path.abspath(target))


def make_repo_key(target: str, commit_hash: str | None = None) -> tuple[str, str, str]:
    """
    Returns (repo_key, repo_name, repo_url).
    Priority: commit hash -> GitHub URL -> local path.
    """
    target = target.rstrip("/")
    repo_name = _extract_repo_name(target)

    if commit_hash:
        return f"commit:{commit_hash[:12]}", repo_name, target

    if "github.com" in target:
        match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", target)
        if match:
            slug = match.group(1).lower()
            return f"github:{slug}", slug.split("/")[-1], target

    return f"local:{repo_name}", repo_name, target


def make_finding_key(finding: dict[str, Any]) -> str:
    """Stable key for a finding across scans (rule + normalized file path)."""
    rule = finding.get("rule", "")
    file_path = (finding.get("file") or "N/A").lstrip("/").lower()
    raw = f"{rule}::{file_path}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def hash_file_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def build_file_hash_map(repo_files: list[dict]) -> dict[str, str]:
    """Returns {file_path: sha256} for all repo files."""
    out: dict[str, str] = {}
    for f in repo_files:
        if not isinstance(f, dict):
            continue
        path = f.get("path")
        if not path or not isinstance(path, str):
            continue
        out[path] = hash_file_content(f.get("content", "") or "")
    return out


def get_last_scan(repo_key: str) -> dict[str, Any] | None:
    """Return most recent scan for this repo key, or None."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE repo_key = ? ORDER BY id DESC LIMIT 1",
            (repo_key,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_last_scan_by_repo_name(repo_name: str) -> dict[str, Any] | None:
    """Fallback lookup by repo name when commit hash changes."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE repo_name = ? ORDER BY id DESC LIMIT 1",
            (repo_name,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    """Return one scan row by id, or None."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_scan_findings(scan_id: int) -> list[dict[str, Any]]:
    """Return all findings for a scan (with finding_key, file_path, etc.)."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_file_hashes(scan_id: int) -> dict[str, str]:
    """Return {file_path: sha256} for a scan."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT file_path, sha256 FROM file_hashes WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        return {r["file_path"]: r["sha256"] for r in rows}
    finally:
        conn.close()


def compute_delta(
    current_findings: list[dict],
    previous_findings: list[dict],
    current_hashes: dict[str, str],
    previous_hashes: dict[str, str],
) -> dict[str, Any]:
    """
    Compare current scan against previous scan.
    Returns new_findings, resolved_findings, unchanged_findings, changed_files, etc.
    """
    prev_by_key = {f["finding_key"]: f for f in previous_findings}
    curr_by_key = {make_finding_key(f): f for f in current_findings}

    new_findings = [f for k, f in curr_by_key.items() if k not in prev_by_key]
    resolved_findings = [f for k, f in prev_by_key.items() if k not in curr_by_key]
    unchanged_findings = [f for k, f in curr_by_key.items() if k in prev_by_key]

    all_paths = set(current_hashes) | set(previous_hashes)
    changed_files = [
        p for p in all_paths
        if current_hashes.get(p) != previous_hashes.get(p)
    ]
    unchanged_files = [
        p for p in all_paths
        if current_hashes.get(p) == previous_hashes.get(p) and p in current_hashes
    ]

    return {
        "is_first_scan": False,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
        "changed_files": changed_files,
        "unchanged_files": unchanged_files,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "unchanged_count": len(unchanged_findings),
        "changed_files_count": len(changed_files),
    }


def save_scan(
    repo_key: str,
    repo_url: str,
    repo_name: str,
    commit_hash: str | None,
    findings: list[dict],
    file_hashes: dict[str, str],
    output_file: str,
    scan_mode: str,
    is_delta: bool = False,
    score: float | None = None,
) -> int:
    """Persist current scan. Returns new scan_id."""
    now = datetime.utcnow().isoformat()
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")

    conn = _get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO scans
              (repo_key, repo_url, repo_name, commit_hash, scan_date,
               finding_count, high_count, medium_count, low_count,
               output_file, scan_mode, is_delta, score)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                repo_key,
                repo_url,
                repo_name,
                commit_hash or "",
                now,
                len(findings),
                high,
                medium,
                low,
                output_file,
                scan_mode,
                int(is_delta),
                score if score is not None else None,
            ),
        )
        scan_id = cur.lastrowid

        for f in findings:
            key = make_finding_key(f)
            conn.execute(
                """
                INSERT INTO findings
                  (scan_id, finding_key, rule, severity, file_path,
                   description, confidence, status,
                   first_seen_date, last_seen_date)
                VALUES (?,?,?,?,?,?,?,'open',?,?)
                """,
                (
                    scan_id,
                    key,
                    f.get("rule", ""),
                    f.get("severity", ""),
                    f.get("file", "N/A"),
                    (f.get("description") or "")[:500],
                    f.get("confidence"),
                    now,
                    now,
                ),
            )

        for path, sha in file_hashes.items():
            conn.execute(
                "INSERT INTO file_hashes (scan_id, file_path, sha256) VALUES (?,?,?)",
                (scan_id, path, sha),
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


def mark_resolved(scan_id: int, finding_keys: list[str]) -> None:
    if not finding_keys:
        return
    now = datetime.utcnow().isoformat()
    conn = _get_conn()
    try:
        for key in finding_keys:
            conn.execute(
                """
                UPDATE findings SET status='resolved', resolved_date=?
                WHERE scan_id=? AND finding_key=?
                """,
                (now, scan_id, key),
            )
        conn.commit()
    finally:
        conn.close()


def get_scan_history(repo_name: str, limit: int = 10) -> list[dict[str, Any]]:
    """Return last N scans for a repo name, newest first."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT id, scan_date, commit_hash, finding_count,
                   high_count, medium_count, low_count, scan_mode, is_delta
            FROM scans WHERE repo_name = ?
            ORDER BY id DESC LIMIT ?
            """,
            (repo_name, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_all_scans(limit: int = 50) -> list[dict[str, Any]]:
    """Return last N scans across all repos, newest first."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT id, repo_key, repo_url, repo_name, commit_hash, scan_date,
                   finding_count, high_count, medium_count, low_count,
                   output_file, scan_mode, is_delta
            FROM scans ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
