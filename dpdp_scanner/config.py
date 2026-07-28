"""
DPDP Scanner configuration.

Loads optional .dpdp.yaml / dpdp-scanner.yaml / .dpdp.yml from repo root for:
- consent_skip_path_segments: path segments that suggest internal audit/compliance (Section 7);
  only full path segments are matched to avoid false negatives (e.g. "audit" matches "app/audit/page.tsx", not "auditor.py").
- suppressions: list of { rule, path_glob } to drop findings matching rule + path (use sparingly).
- overrides: list of { rule, path_glob, severity?, confidence? } to downscope noisy findings without hiding them.
- deployment_class: override inferred deployment class (saas, self_hosted_oss, library, unknown).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Default path segments that suggest internal audit/compliance/reporting (DPDP Section 7 legitimate use).
# Conservative: only unambiguous directory names. "admin" is NOT included by default (can be user-facing).
DEFAULT_CONSENT_SKIP_PATH_SEGMENTS = (
    "audit",
    "audits",
    "compliance",
    "reporting",
    "reports",
    "internal",
)


def _normalize_path(path: str) -> str:
    """Use forward slashes for consistent matching."""
    return path.replace("\\", "/").lstrip("/")


def _path_segments(path: str) -> List[str]:
    """Return list of path segments (dirs and file)."""
    return [s for s in _normalize_path(path).split("/") if s]


def path_has_segment(path: str, segment: str, case_sensitive: bool = False) -> bool:
    """
    Return True if path contains the given string as a full path segment (not substring).
    E.g. segment "audit" matches "app/dashboard/audit/page.tsx" but not "auditor.py".
    """
    segments = _path_segments(path)
    if not segment:
        return False
    if not case_sensitive:
        segment = segment.lower()
        segments = [s.lower() for s in segments]
    return segment in segments


def path_matches_glob(file_path: str, pattern: str) -> bool:
    """
    Return True if file_path matches the given glob pattern.
    Supports * (any chars in segment) and ** (any path segments).
    Pattern uses forward slashes; file_path is normalized to forward slashes.
    """
    normalized = _normalize_path(file_path)
    # Escape regex specials except * and ?
    pattern_esc = re.escape(pattern)
    # Restore ** and * for our meaning
    pattern_esc = pattern_esc.replace(r"\*\*", "\0")
    pattern_esc = pattern_esc.replace(r"\*", "\1")
    pattern_esc = pattern_esc.replace("\0", r".*")
    pattern_esc = pattern_esc.replace("\1", r"[^/]*")
    regex = re.compile(r"^" + pattern_esc + r"$")
    return bool(regex.match(normalized))


def is_finding_suppressed(finding: Dict, suppressions: List[Dict]) -> bool:
    """
    Return True if the finding should be suppressed by config.
    Suppressions are list of { "rule": str, "path_glob": str }.
    """
    rule = (finding.get("rule") or "").strip()
    file_val = finding.get("file") or ""
    if not rule or file_val in ("REPO-WIDE", "MULTIPLE"):
        return False
    for sup in suppressions:
        if (sup.get("rule") or "").strip() != rule:
            continue
        path_glob = (sup.get("path_glob") or "").strip()
        if not path_glob:
            continue
        if path_matches_glob(file_val, path_glob):
            return True
    return False


def get_finding_override(finding: Dict, overrides: List[Dict]) -> Optional[Dict]:
    """Return the first matching override entry for a finding, if any."""
    rule = (finding.get("rule") or "").strip()
    file_val = finding.get("file") or ""
    if not rule or not file_val:
        return None
    for override in overrides:
        if (override.get("rule") or "").strip() != rule:
            continue
        path_glob = (override.get("path_glob") or "").strip()
        if path_glob and path_matches_glob(file_val, path_glob):
            return override
    return None


def load_config(repo_path: Optional[str]) -> Dict[str, Any]:
    """
    Load config from repo root. Tries .dpdp.yaml, dpdp-scanner.yaml, .dpdp.yml.
    Returns dict with keys: consent_skip_path_segments (list), suppressions (list).
    """
    try:
        import yaml
    except ImportError:
        yaml = None

    result: Dict[str, Any] = {
        "consent_skip_path_segments": list(DEFAULT_CONSENT_SKIP_PATH_SEGMENTS),
        "suppressions": [],
        "overrides": [],
        "deployment_class": None,
    }

    root = None
    if repo_path and os.path.isdir(repo_path):
        root = Path(repo_path)
    for candidate in (".dpdp.yaml", "dpdp-scanner.yaml", ".dpdp.yml"):
        if not root:
            break
        path = root / candidate
        if not path.is_file():
            continue
        raw: Dict[str, Any] = {}
        try:
            if yaml:
                with open(path, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
            else:
                break
        except Exception:
            break
        if isinstance(raw, dict):
            if "consent_skip_path_segments" in raw and isinstance(raw["consent_skip_path_segments"], list):
                result["consent_skip_path_segments"] = [
                    str(s).strip() for s in raw["consent_skip_path_segments"] if s
                ]
            if "suppressions" in raw and isinstance(raw["suppressions"], list):
                result["suppressions"] = []
                for item in raw["suppressions"]:
                    path_glob = item.get("path_glob") or item.get("files")
                    if isinstance(item, dict) and item.get("rule") and path_glob:
                        result["suppressions"].append({
                            "rule": str(item["rule"]).strip(),
                            "path_glob": str(path_glob).strip(),
                            "reason": str(item.get("reason") or "").strip(),
                        })
            if "overrides" in raw and isinstance(raw["overrides"], list):
                result["overrides"] = []
                for item in raw["overrides"]:
                    path_glob = item.get("path_glob") or item.get("files")
                    if not (isinstance(item, dict) and item.get("rule") and path_glob):
                        continue
                    result["overrides"].append({
                        "rule": str(item["rule"]).strip(),
                        "path_glob": str(path_glob).strip(),
                        "severity": str(item.get("severity") or "").strip().upper() or None,
                        "confidence": item.get("confidence"),
                        "reason": str(item.get("reason") or "").strip(),
                    })
            if raw.get("deployment_class"):
                result["deployment_class"] = str(raw["deployment_class"]).strip()
        break

    return result
