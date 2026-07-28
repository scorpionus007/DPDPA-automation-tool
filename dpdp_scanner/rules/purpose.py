"""
Purpose limitation rule — DPDP Section 5.
Data collected for one purpose must not be used for another.
"""

from __future__ import annotations

import re
from typing import Dict, List


def _get_content(extracted: Dict, filepath: str) -> str:
    """Retrieve file content from extracted._file_contents."""
    return (extracted.get("_file_contents") or {}).get(filepath, "")


# Path segments — regex so "signer-conversion" / get-signer-conversion.ts does not match bare "conversion"
MARKETING_PATH_PATTERNS = [
    r"marketing[/_\-]",
    r"[/_\-]analytics[/_\-]",
    r"[/_\-]reporting[/_\-]",
    r"campaign[/_\-]",
    r"tracking[/_\-]",
    r"segment[/_\-]",
    r"mixpanel",
    r"amplitude",
    r"telemetry[/_\-]",
    r"[/_\-]ads[/_\-]",
    r"advertising[/_\-]",
    r"attribution[/_\-]",
    r"pixel[/_\-]",
    r"marketing.*conversion",
    r"conversion.*rate",
    r"conversion.*funnel",
    r"ab[/_\-]test",
    r"growth[/_\-]hack",
    r"[/_\-]metrics[/_\-]",
]

# Comprehensive UI layout exclusions — check BEFORE MARKETING_PATH_PATTERNS
PURPOSE_HARD_EXCLUSIONS = [
    r"issue-layouts?/",
    r"issues?/.*layout",
    r"task-layouts?/",
    r"board[_\-]?layout",
    r"gantt[_\-]?view",
    r"calendar[_\-]?view",
    r"kanban",
    r"sprint[_\-]?view",
    r"spreadsheet/.*row",
    r"spreadsheet/.*cell",
    r"spreadsheet/.*column",
    r"data[_\-]?grid",
    r"ag[_\-]?grid",
    r"table[_\-]?row",
    r"table[_\-]?cell",
    r"components/issues/",
    r"components/tasks/",
    r"components/projects/",
    r"layouts/",
    r"/ui/",
    r"\.tsx$",
    r"\.jsx$",
    r"\.test\.",
    r"\.spec\.",
    r"__tests__/",
    r"__mocks__/",
    r"fixtures?/",
    r"seeds?/",
    r"factories?/",
    r"\.config\.",
    r"vite\.config",
    r"next\.config",
    r"webpack\.config",
    r"EmptyState",
    r"empty[_-]state",
    r"Placeholder",
    r"NoData",
    r"no[_-]data",
    # Document signing / conversion — not marketing analytics
    r"get[_\-]?signer[_\-]?conversion",
    r"signer[_\-]?conversion",
    r"[_\-]?conversion\.(ts|js|py|rb)$",
    r"document[_\-]?conversion",
    r"file[_\-]?conversion",
    r"format[_\-]?conversion",
    r"type[_\-]?conversion",
    r"data[_\-]?conversion",
    r"currency[_\-]?conversion",
    r"unit[_\-]?conversion",
    # Server / framework setup files — never analytics
    r"trpc\.ts$",
    r"hono\.ts$",
    r"server\.ts$",
    r"app\.ts$",
    r"main\.ts$",
    r"index\.ts$",
    r"router\.ts$",
    r"middleware\.ts$",
    r"context\.ts$",
    r"cors\.(ts|js|py)$",
    # Growth utilities (metrics, not marketing)
    r"get[_\-]?growth\b",
    r"growth[_\-]?metric",
    r"growth[_\-]?rate",
    r"user[_\-]?growth",
    # Test / mock files
    r"\.test\.(ts|js|tsx|jsx)$",
    r"\.spec\.(ts|js|tsx|jsx)$",
    r"__tests__/",
    r"__mocks__/",
    r"mock\.(ts|js)$",
    r"fixture\.(ts|js)$",
    r"stub\.(ts|js)$",
    # Config / types
    r"\.config\.(ts|js)$",
    r"types\.(ts|tsx)$",
    r"schema\.(ts|tsx)$",
    r"constants\.(ts|js)$",
    r"enums?\.(ts|js)$",
]

ANALYTICS_CONTENT_SIGNALS = [
    r"\.track\s*\(",
    r"\.identify\s*\(",
    r"\.capture\s*\(",
    r"analytics\.\w+\s*\(",
    r"mixpanel\.\w+\s*\(",
    r"segment\.\w+\s*\(",
    r"amplitude\.\w+\s*\(",
    r"posthog\.\w+\s*\(",
    r"gtag\s*\(",
    r"fbq\s*\(",
    r"ga\s*\(",
    r"\.page\s*\(",
]


def _has_analytics_content(content: str) -> bool:
    """File must actually call an analytics SDK / tag to trigger purpose rule."""
    return any(re.search(p, content, re.IGNORECASE) for p in ANALYTICS_CONTENT_SIGNALS)

# UI layout/display components — not analytics or reporting systems
PURPOSE_EXCLUSIONS = [
    r"issue-layouts/spreadsheet",
    r"issue-layouts/gantt",
    r"issue-layouts/calendar",
    r"issue-layouts/board",
    r"components/issues/",
    r"layouts/",
]


def check_purpose(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []
    pii_fields = extracted.get("pii_fields", []) or []
    third_party_imports = extracted.get("third_party_imports", []) or []
    route_files = set(extracted.get("route_files") or [])
    model_files = set(extracted.get("model_files") or [])
    file_contents = extracted.get("_file_contents") or {}

    if not third_party_imports:
        findings.append(
            {
                "rule": "NO_THIRD_PARTY_DATA_SHARING",
                "dpdp_section": "Section 5 — Purpose Limitation",
                "severity": "INFO",
                "confidence": 0.90,
                "file": "N/A",
                "evidence": {},
                "description": "No third-party data sharing detected.",
                "fix": None,
            }
        )
        return findings

    third_party_files = {t.get("file") for t in third_party_imports if t.get("file")}
    pii_files = {p.get("file") for p in pii_fields if p.get("file")}
    expected_pii_locations = route_files | model_files
    seen_paths: set = set()

    for path, content in file_contents.items():
        if not content:
            continue
        if path in seen_paths:
            continue
        path_norm = path.replace("\\", "/")

        if any(re.search(p, path_norm, re.IGNORECASE) for p in PURPOSE_HARD_EXCLUSIONS):
            continue
        if any(re.search(pex, path_norm, re.IGNORECASE) for pex in PURPOSE_EXCLUSIONS):
            continue
        if any(re.search(mp, path_norm, re.IGNORECASE) for mp in MARKETING_PATH_PATTERNS):
            pii_in_file = [p for p in pii_fields if p.get("file") == path]
            if pii_in_file and _has_analytics_content(content):
                seen_paths.add(path)
                findings.append(
                    {
                        "rule": "PURPOSE_LIMITATION_RISK",
                        "dpdp_section": "Section 5 — Purpose Limitation",
                        "severity": "MEDIUM",
                        "confidence": 0.55,
                        "file": path,
                        "evidence": {
                            "pii_files": pii_in_file,
                            "path_suggests": "marketing/analytics/reporting",
                        },
                        "description": "PII appears in file whose path suggests marketing/analytics/reporting. Data may be used for purposes beyond collection.",
                        "fix": None,
                        "requires_human_validation": True,
                    }
                )

        if path not in expected_pii_locations and path in pii_files:
            if path in third_party_files:
                lines = content.splitlines()
                for i, line in enumerate(lines):
                    for pii in pii_fields:
                        if pii.get("file") != path:
                            continue
                        pii_line = pii.get("line_number", 0)
                        for j in range(max(0, i - 5), min(len(lines), i + 6)):
                            if abs(j + 1 - pii_line) <= 5:
                                if any(re.search(lib, lines[j], re.I) for lib in ["mixpanel", "segment", "amplitude", "analytics", "tracking"]):
                                    if path in seen_paths:
                                        break
                                    seen_paths.add(path)
                                    findings.append(
                                        {
                                            "rule": "PURPOSE_LIMITATION_RISK",
                                            "dpdp_section": "Section 5 — Purpose Limitation",
                                            "severity": "MEDIUM",
                                            "confidence": 0.55,
                                            "file": path,
                                            "evidence": {
                                                "pii_line": pii_line,
                                                "third_party_line": j + 1,
                                                "line_content": lines[j][:200].strip(),
                                            },
                                            "description": "PII variable near third-party analytics call. Data may be shared for purposes beyond original collection.",
                                            "fix": None,
                                            "requires_human_validation": True,
                                        }
                                    )
                                    break

    return findings
