"""
Rule: DATA_ACCESS_MISSING / DATA_PORTABILITY_MISSING
DPDP Section 11 — Right of Data Principal to access and obtain information

Checks:
1. Does the app expose a "get my data" endpoint for authenticated users?
2. Does the app expose a data export/download endpoint?

Only fires when PII storage is confirmed (model files with PII exist).
Does not fire on repos with no user accounts (no auth files).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


# ── Access endpoint signals ────────────────────────────────────────────────
ACCESS_ROUTE_PATTERNS = [
    r"/users?/me\b",
    r"/users?/profile\b",
    r"/users?/account\b",
    r"/users?/my[-_]data\b",
    r"/users?/self\b",
    r"/account/me\b",
    r"/profile/me\b",
    r"/me\b",
    r"/my[-_]profile\b",
    r"/my[-_]account\b",
    r"def\s+get_current_user_profile",
    r"def\s+get_my_data",
    r"def\s+user_profile\b",
    r"async\s+getProfile\b",
    r"async\s+getMe\b",
    r"getCurrentUser\s*\(",
    r"getMyData\s*\(",
    r"current_user\b.*\breturn\b",
    r"request\.user\b.*\breturn\b",
    r"req\.user\b.*\bres\.json\b",
]

# ── Export/portability signals ─────────────────────────────────────────────
EXPORT_ROUTE_PATTERNS = [
    r"/users?/export\b",
    r"/users?/download\b",
    r"/account/export\b",
    r"/data[-_]export\b",
    r"/export[-_]data\b",
    r"/my[-_]data/export\b",
    r"/gdpr[-_]export\b",
    r"/dpdp[-_]export\b",
    r"/privacy/export\b",
    r"def\s+export_user_data",
    r"def\s+download_user_data",
    r"def\s+export_my_data",
    r"def\s+data_export",
    r"exportUserData\s*\(",
    r"downloadUserData\s*\(",
    r"generateExport\s*\(",
    r"application/zip",
    r"text/csv.*user",
    r"Content-Disposition.*attachment.*user",
    r"zipfile\.ZipFile.*user",
    r"csv\.writer.*email",
]

# Job/queue-based export (Laravel ExportAccount, Celery, etc.)
JOB_BASED_EXPORT_PATTERNS = [
    r"[Ee]xport[A-Z]\w*Job\b",
    r"[Ee]xport[A-Z]\w*Command\b",
    r"dispatch.*[Ee]xport",
    r"[Ee]xport.*::dispatch",
    r"Queue::push.*[Ee]xport",
    r"Mail::queue.*[Ee]xport",
    r"class\s+Export[A-Z]\w+",
    r"[Ii]mplements.*[Ee]xportable",
    r"use\s+Exportable\b",
    r"[Ss]houldQueue.*[Ee]xport",
    r"@shared_task.*export",
    r"export_user_data\.delay",
    r"export.*\.apply_async",
    r"exportQueue\.add\s*\(",
    r"new\s+[Ee]xport[A-Z]\w+Worker",
]
EXPORT_JOB_PATH_PATTERNS = [
    r"[Ee]xport[A-Z]\w+\.php$",
    r"[Jj]obs/.*[Ee]xport",
    r"[Cc]ommands/.*[Ee]xport",
    r"tasks/.*export",
]

# Patterns that look like data exports but are actually TypeScript module exports or code generation
CODE_EXPORT_FALSE_POSITIVES = [
    r"ExportFrom\.",
    r"ExportAll\.",
    r"ExportNamed\.",
    r"ExportDefault\.",
    r"ts-builders",
    r"ast.*[Ee]xport",
    r"codegen",
    r"code\.gen",
    r"generator",
    r"compiler",
    r"transpil",
    r"barrel",
    r"index\.ts$",
    r"\.d\.ts$",
    r"constants?/config",
    r"core/constants/",
    r"packages/editor/",
    r"editor/.*constants",
    r"\.config\.(ts|js)$",
    r"config\.ts$",
    r"types\.(ts|tsx)$",
    r"interfaces?\.(ts|tsx)$",
    r"enums?\.(ts|tsx)$",
    r"constants\.(ts|js|py)$",
    r"theme\.(ts|js)$",
    r"colors\.(ts|js)$",
    r"i18n/",
    r"locales?/",
    r"translations?/",
    r"\.stories\.",
    r"storybook/",
]

DATA_ACCESS_EVIDENCE_EXCLUSIONS = [
    r"/providers/",
    r"/provider\.",
    r"provider-",
    r"webauthn",
    r"config/",
    r"\.config\.",
    r"/adapters/",
    r"/adapter\.",
    r"adapter-",
    r"kakao", r"naver", r"vk",
    r"github", r"google", r"facebook",
    r"twitter", r"discord", r"slack",
    r"packages/editor/.*constants",
    r"editor.*constants/config",
    r"core/constants/",
    r"packages/editor/",
    r"editor/.*constants",
    r"\.config\.(ts|js)$",
    r"/public/",
    r"middleware\.(ts|js|py)$",
    r"/__tests__/",
    r"/test/",
    r"\.test\.(ts|js)$",
    r"\.spec\.(ts|js)$",
    r"kakao\.",
    r"naver\.",
    r"vk\.",
    r"line\.",
    r"wechat\.",
    r"webauthn",
    r"passkey",
    r"/adapters?/",
    r"adapter\.(ts|js|py)$",
    r"webhook\.",
    r"microsoft[_\-]?graph",
    r"graph[_\-]?auth",
    r"lib/.*auth\.",
    r"shared/constants/",
    r"constants/messages",
    r"constants/strings",
    r"shared/.*constants",
]

USER_DATA_SIGNALS = [
    r"\buser\b",
    r"\baccount\b",
    r"\bprofile\b",
    r"\bpersonal.*data\b",
    r"\bdata.*export\b",
    r"\buser_id\b",
    r"\bpii\b",
]


def _is_real_data_export(file_path: str, content: str) -> bool:
    """
    Returns True only if file is a genuine user data export mechanism.
    Requires BOTH a data export signal AND the absence of code-tool signals.
    Also requires at least one of: user/account reference, download trigger,
    or data serialization signal.
    """
    is_code_tool = any(
        re.search(p, file_path + "\n" + content[:500], re.IGNORECASE)
        for p in CODE_EXPORT_FALSE_POSITIVES
    )
    if is_code_tool:
        return False

    has_data_signal = any(
        re.search(p, content, re.IGNORECASE)
        for p in JOB_BASED_EXPORT_PATTERNS
    )
    if not has_data_signal:
        return False

    has_user_ref = any(
        re.search(p, content, re.IGNORECASE)
        for p in USER_DATA_SIGNALS
    )
    return has_user_ref


def _best_evidence_file(candidates: list, exclusions: list) -> str:
    """
    Select the most appropriate evidence file, excluding
    config/provider/adapter files that aren't real data access endpoints.
    """
    valid = [
        f for f in candidates
        if not any(
            re.search(p, f, re.IGNORECASE)
            for p in exclusions
        )
    ]
    return valid[0] if valid else (candidates[0] if candidates else "N/A")


def _file_has_pattern(content: str, patterns: List[str]) -> Tuple[bool, str | None, int | None]:
    """
    Check if content matches any pattern.
    Returns (True, matched_pattern, line_number) or (False, None, None).
    """
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True, pattern, i
    return False, None, None


def _has_user_accounts(extracted: Dict[str, Any]) -> bool:
    """
    Only flag access issues if the app actually has user accounts.
    """
    auth_files = extracted.get("auth_files", [])
    model_files = extracted.get("model_files", [])
    pii_fields = extracted.get("pii_fields", [])

    has_pii = len(pii_fields) >= 5
    has_models = len(model_files) >= 1
    return has_pii and has_models


def run(extracted: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Framework/library repos provide tools for apps to implement these controls.
    if extracted.get("is_framework_library", False):
        return []

    findings: List[Dict[str, Any]] = []

    if not _has_user_accounts(extracted):
        return findings

    file_contents = extracted.get("_file_contents", {})
    route_files = extracted.get("route_files", [])
    all_files = list(file_contents.keys())
    search_files = list(set(route_files + all_files))

    # ── Check 1: Right to Access ───────────────────────────────────
    access_found = False
    access_evidence: List[Dict[str, Any]] = []

    for path in search_files:
        content = file_contents.get(path, "")
        found, pattern, line_num = _file_has_pattern(content, ACCESS_ROUTE_PATTERNS)
        if found:
            access_found = True
            access_evidence.append({
                "file": path,
                "line_number": line_num,
                "pattern": pattern,
            })
            break

    if not access_found:
        findings.append({
            "rule": "DATA_ACCESS_MISSING",
            "dpdp_section": "Section 11 — Right to Access",
            "severity": "MEDIUM",
            "confidence": 0.65,
            "file": "N/A",
            "display_path": "N/A",
            "line_number": None,
            "description": (
                "No endpoint detected that allows authenticated users to "
                "retrieve their own personal data. Under DPDP Section 11, "
                "Data Principals have the right to access information about "
                "their personal data being processed."
            ),
            "evidence": {
                "searched_files": len(search_files),
                "access_patterns_checked": len(ACCESS_ROUTE_PATTERNS),
            },
            "fix": None,
            "requires_human_validation": False,
        })
    else:
        path_to_display = extracted.get("path_to_display", {})
        access_endpoint_files = [e["file"] for e in access_evidence]
        evidence_file = _best_evidence_file(
            access_endpoint_files,
            DATA_ACCESS_EVIDENCE_EXCLUSIONS,
        )
        display = path_to_display.get(evidence_file, evidence_file)
        findings.append({
            "rule": "DATA_ACCESS_PRESENT",
            "dpdp_section": "Section 11 — Right to Access",
            "severity": "PASS",
            "confidence": 0.80,
            "file": evidence_file,
            "display_path": display,
            "description": "Data access endpoint detected for authenticated users.",
            "evidence": access_evidence,
            "fix": None,
        })

    # ── Check 2: Data Portability ──────────────────────────────────
    export_found = False
    export_evidence: List[Dict[str, Any]] = []

    for path in search_files:
        if any(re.search(p, path.replace("\\", "/"), re.IGNORECASE) for p in DATA_ACCESS_EVIDENCE_EXCLUSIONS):
            continue
        content = file_contents.get(path, "")
        found, pattern, line_num = _file_has_pattern(content, EXPORT_ROUTE_PATTERNS)
        if found:
            export_found = True
            export_evidence.append({
                "file": path,
                "line_number": line_num,
                "pattern": pattern,
            })
            break

    # Job/queue-based export (e.g. Laravel ExportAccount, ExportData)
    if not export_found:
        for path in file_contents:
            if any(re.search(p, path, re.IGNORECASE) for p in EXPORT_JOB_PATH_PATTERNS):
                content = file_contents.get(path, "")
                if _is_real_data_export(path, content):
                    export_found = True
                    export_evidence.append({
                        "file": path,
                        "line_number": None,
                        "pattern": "export_job_path",
                    })
                    break
    if not export_found:
        for path, content in file_contents.items():
            if any(re.search(p, content, re.IGNORECASE) for p in JOB_BASED_EXPORT_PATTERNS):
                if _is_real_data_export(path, content):
                    export_found = True
                    export_evidence.append({
                        "file": path,
                        "line_number": None,
                        "pattern": "job_based_export",
                    })
                    break

    if not export_found:
        findings.append({
            "rule": "DATA_PORTABILITY_MISSING",
            "dpdp_section": "Section 11 — Data Portability",
            "severity": "LOW",
            "confidence": 0.60,
            "file": "N/A",
            "display_path": "N/A",
            "line_number": None,
            "description": (
                "No data export or portability endpoint detected. "
                "DPDP Section 11 requires Data Fiduciaries to provide "
                "personal data in a commonly used, machine-readable format "
                "upon request."
            ),
            "evidence": {
                "searched_files": len(search_files),
                "export_patterns_checked": len(EXPORT_ROUTE_PATTERNS),
            },
            "fix": None,
            "requires_human_validation": True,
        })
    else:
        path_to_display = extracted.get("path_to_display", {})
        export_files = [e["file"] for e in export_evidence]
        evidence_file = _best_evidence_file(export_files, DATA_ACCESS_EVIDENCE_EXCLUSIONS)
        first = export_evidence[0]
        display = path_to_display.get(evidence_file, evidence_file)
        is_job_based = first.get("pattern") in ("job_based_export", "export_job_path")
        findings.append({
            "rule": "DATA_PORTABILITY_PRESENT",
            "dpdp_section": "Section 11 — Data Portability",
            "severity": "PASS",
            "confidence": 0.75,
            "file": evidence_file,
            "display_path": display,
            "description": (
                "Data export mechanism detected (job/queue-based)."
                if is_job_based
                else "Data export/portability endpoint detected."
            ),
            "evidence": export_evidence,
            "fix": None,
        })

    return findings
