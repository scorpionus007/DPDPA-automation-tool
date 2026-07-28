"""
Breach indicator rule — DPDP Section 8(6).
Data breaches must be reported. Adequate logging/alerting must exist.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

from dpdp_scanner.extractor import _get_transitive_imports


def _get_content(extracted: Dict, filepath: str) -> str:
    """Retrieve file content from extracted._file_contents."""
    return (extracted.get("_file_contents") or {}).get(filepath, "")


# Files that by design never have try/catch — exclude from error handling check
AUTH_ROUTE_EXCLUSIONS = [
    r"urls\.py$",
    r"routes\.(ts|js|tsx)$",
    r"router\.(ts|js|tsx)$",
    r"routing\.py$",
    r"urlconf\b",
    r"app\.routes\.",
    r"routing\.module\.",
    r"\.server\.(ts|js|tsx)$",
    r"\+page\.server\.(ts|js)$",
    r"\+server\.(ts|js)$",
]

# STRONG signals — actual breach notification/detection infrastructure
STRONG_BREACH_SIGNALS = [
    "sentry",
    "bugsnag",
    "rollbar",
    "pagerduty",
    "opsgenie",
    "alertmanager",
    "datadog",
    "newrelic",
    "cloudwatch",
    "sendBreachNotification",
    "notifyDataPrincipal",
    "notifyAuthority",
    "breach_notification",
    "incident_report",
    "security_alert",
    "send_alert",
    "raise_alert",
    "SlackWebhook",
    "PagerDutyEvent",
    "security_incident",
    "data_breach",
    "breach_detected",
    "security_event",
]

# WEAK signals — have error handling but not breach-specific
WEAK_BREACH_SIGNALS = [
    "try:",
    "try {",
    "except ",
    "catch(",
    "catch (",
    "traceback",
    "logging.exception",
    "logger.error",
    "logger.exception",
    "console.error",
]

# Weak app logging — counts as “some logging” but not structured/forensic-grade alone
WEAK_APP_LOGGING_SIGNALS = [
    "console.log",
]

# STRUCTURED logging — breach forensics–oriented (not raw console.log)
STRUCTURED_LOGGING_SIGNALS = [
    "winston",
    "morgan",
    "pino",
    "bunyan",
    "pino(",
    # Python stdlib / Flask
    "import logging",
    "logging.basicConfig",
    "logging.getLogger",
    "from logging import",
    "logger = logging",
    "app.logger",
    "current_app.logger",
    "flask.logging",
    "structlog",
    "loguru",
    # Ruby
    "Rails.logger",
    "Logger.new",
    # Java
    "LoggerFactory",
    "log4j",
    "slf4j",
    "java.util.logging",
    # Go
    "log.Printf",
    "log.Fatal",
    "zap.New",
    "logrus",
    # Node (strong libs — not console.log)
    "console.error",
    "winston",
    # .NET / other
    "serilog",
    "log.info",
    "log.warn",
    "log.error",
]

DB_AUDIT_PATTERNS = [
    r"audit_log",
    r"audit_logs",
    r"AuditLog",
    r"audit_trail",
    r"security_events",
    r"access_log",
    r"event_log",
    r"activity_log",
]

NETWORK_IO_PATTERNS = [
    r"\bfetch\s*\(",
    r"\baxios\.",
    r"\bhttpx?\.",
    r"\brequests\.",
    r"\bunsafeGet",
    r"\bprisma\.",
    r"\bdb\.",
    r"\bquery\s*\(",
]

FRAMEWORK_ERROR_BOUNDARY_PATTERNS = [
    r"\bErrorBoundary\b",
    r"\bCatchBoundary\b",
    r"\bhandleError\b",
]


def _framework_markers(extracted: Dict) -> Set[str]:
    """Infer web frameworks from repo files and package metadata."""
    file_contents = extracted.get("_file_contents") or {}
    pkg_blobs = []
    for path, content in file_contents.items():
        base = path.replace("\\", "/").split("/")[-1].lower()
        if base in {
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
        }:
            pkg_blobs.append(content.lower())
    blob = "\n".join(pkg_blobs)
    markers: Set[str] = set()
    if "@remix-run/" in blob or any("/app/routes/" in p.replace("\\", "/").lower() for p in file_contents):
        markers.add("remix")
    if '"next"' in blob or "/pages/api/" in blob:
        markers.add("next")
    if "@sveltejs/kit" in blob:
        markers.add("sveltekit")
    if '"astro"' in blob or "@astrojs/" in blob:
        markers.add("astro")
    return markers


def _has_framework_error_boundary(path: str, content: str, extracted: Dict) -> bool:
    """
    True when a route belongs to a framework with first-class route error handling.

    We intentionally skip these route files unless they are dedicated API handlers,
    because framework pages/loaders commonly rely on ErrorBoundary/CatchBoundary
    rather than local try/catch blocks.
    """
    if not path or not content:
        return False
    path_norm = path.replace("\\", "/").lower()
    frameworks = _framework_markers(extracted)
    has_boundary_export = any(
        re.search(pattern, content, re.IGNORECASE)
        for pattern in FRAMEWORK_ERROR_BOUNDARY_PATTERNS
    )

    if "remix" in frameworks and "/app/routes/" in path_norm and path_norm.endswith((".ts", ".tsx", ".js", ".jsx")):
        return True
    if "sveltekit" in frameworks and (
        path_norm.endswith(("+page.server.ts", "+page.server.js", "+server.ts", "+server.js"))
    ):
        return True
    if "astro" in frameworks and "/src/pages/" in path_norm and path_norm.endswith((".astro", ".ts", ".js")):
        return True
    if "next" in frameworks:
        is_next_route = (
            re.search(r"/app/.+/route\.(ts|js)$", path_norm)
            or "/pages/api/" in path_norm
            or re.search(r"/app/.+/page\.(tsx|jsx)$", path_norm)
        )
        if is_next_route and (has_boundary_export or not re.search(r"\b(export\s+)?async\s+function\s+(get|post|put|delete|patch)\b", content, re.IGNORECASE)):
            return True
    return has_boundary_export


def check_breach_indicators(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []
    file_contents = extracted.get("_file_contents") or {}
    route_files = extracted.get("route_files") or []

    backend_path_signals = (
        "/backend/", "/server/", "/api/", "/routes/", "/controllers/",
        "/services/", "/middleware/", "/app/", "/src/",
    )

    def _is_backend_file(path: str) -> bool:
        p = path.replace("\\", "/").lower()
        if any(seg in p for seg in backend_path_signals):
            return True
        return p.endswith((".py", ".rb", ".java", ".go", ".rs", ".php", ".cs"))

    has_strong_breach = False
    for path, content in file_contents.items():
        if not _is_backend_file(path):
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*", "<!--")):
                continue
            lower_line = stripped.lower()
            if any(sig in lower_line for sig in STRONG_BREACH_SIGNALS):
                has_strong_breach = True
                break
        if has_strong_breach:
            break

    all_content = " ".join(file_contents.values()).lower()
    has_weak_breach = any(sig in all_content for sig in WEAK_BREACH_SIGNALS)
    has_structured_logging = any(sig in all_content for sig in STRUCTURED_LOGGING_SIGNALS)
    logging_found = has_structured_logging or any(
        sig in all_content for sig in WEAK_APP_LOGGING_SIGNALS
    )

    auth_route_files = [
        r for r in route_files
        if ("auth" in r.lower() or "login" in r.lower() or "signup" in r.lower())
        and not any(re.search(p, r.replace("\\", "/"), re.IGNORECASE) for p in AUTH_ROUTE_EXCLUSIONS)
    ]
    auth_without_try = []
    import_graph = extracted.get("import_graph", {})

    for path in auth_route_files:
        content = file_contents.get(path, "")
        if not content:
            continue
        if _has_framework_error_boundary(path, content, extracted):
            continue
        has_try = bool(re.search(r"try\s*\{|try\s*:|try\s*$", content, re.MULTILINE | re.IGNORECASE))
        has_except = bool(re.search(r"catch\s*\(|except\s+:", content, re.MULTILINE | re.IGNORECASE))
        if has_try or has_except:
            continue
        has_handler = bool(
            re.search(
                r"\b(loader|action)\b|"
                r"\bexport\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\b|"
                r"\bonRequest\b",
                content,
                re.IGNORECASE,
            )
        )
        if not has_handler:
            continue
        has_network_io = any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in NETWORK_IO_PATTERNS
        )
        if not has_network_io:
            continue
        transitive = _get_transitive_imports(path, import_graph, max_depth=2)
        error_handling_in_imports = any(
            "try:" in (extracted.get("_file_contents", {}).get(t, ""))
            or "try {" in (extracted.get("_file_contents", {}).get(t, ""))
            for t in transitive
        )
        if error_handling_in_imports:
            continue
        auth_without_try.append(path)

    db_audit_found = any(
        re.search(pat, content, re.IGNORECASE)
        for path, content in file_contents.items()
        for pat in DB_AUDIT_PATTERNS
    )

    if not has_strong_breach and not logging_found:
        if db_audit_found:
            findings.append(
                {
                    "rule": "DB_AUDIT_LOGGING_DETECTED",
                    "dpdp_section": "Section 8(6) — Breach",
                    "severity": "INFO",
                    "confidence": 0.70,
                    "file": "N/A",
                    "description": (
                        "Database audit logging detected. Consider adding "
                        "structured application-level logging (Winston/Pino) "
                        "for breach forensics."
                    ),
                    "fix": None,
                }
            )
        else:
            findings.append(
                {
                    "rule": "NO_LOGGING_DETECTED",
                    "dpdp_section": "Section 8(6) — Breach",
                    "severity": "MEDIUM",
                    "confidence": 0.65,
                    "file": "N/A",
                    "evidence": {"logging_signals_checked": STRUCTURED_LOGGING_SIGNALS},
                    "description": "No logging library detected anywhere. Breach detection and reporting may be inadequate.",
                    "fix": None,
                }
            )
    elif not has_strong_breach and logging_found:
        if has_structured_logging:
            findings.append(
                {
                    "rule": "NO_BREACH_ALERTING",
                    "dpdp_section": "Section 8(6) — Breach",
                    "severity": "LOW",
                    "confidence": 0.50,
                    "file": "N/A",
                    "evidence": {"alert_signals_checked": STRONG_BREACH_SIGNALS},
                    "description": (
                        "Structured logging detected but no breach notification mechanism found. "
                        "DPDP Section 8(6) requires notifying affected individuals and the Authority "
                        "without undue delay when a breach occurs. Logging alone is insufficient — "
                        "implement automated alerting (Sentry, PagerDuty, or equivalent) with "
                        "escalation to a compliance team."
                    ),
                    "fix": None,
                    "requires_human_validation": True,
                }
            )
        else:
            findings.append(
                {
                    "rule": "MINIMAL_CONSOLE_LOGGING",
                    "dpdp_section": "Section 8(6) — Breach",
                    "severity": "INFO",
                    "confidence": 0.55,
                    "file": "N/A",
                    "evidence": {"note": "console.log or similar only; no structured logging"},
                    "description": (
                        "Only minimal client logging (e.g. console.log) detected — not sufficient "
                        "for breach forensics or server-side audit trails. Add structured "
                        "application logging and breach alerting (Sentry, PagerDuty, or equivalent)."
                    ),
                    "fix": None,
                    "requires_human_validation": True,
                }
            )
    else:
        findings.append(
            {
                "rule": "BREACH_INDICATORS_ADEQUATE",
                "dpdp_section": "Section 8(6) — Breach",
                "severity": "PASS",
                "confidence": 0.75,
                "file": "N/A",
                "evidence": {
                    "logging_present": logging_found,
                    "breach_alerting_present": has_strong_breach,
                },
                "description": "Logging and/or breach alerting present.",
                "fix": None,
            }
        )

    if auth_without_try:
        findings.append(
            {
                "rule": "NO_ERROR_HANDLING_IN_AUTH",
                "dpdp_section": "Section 8(6) — Breach",
                "severity": "MEDIUM",
                "confidence": 0.70,
                "file": auth_without_try[0],
                "evidence": {
                    "auth_route_files": auth_route_files,
                    "files_without_try_catch": auth_without_try,
                },
                "description": "Auth routes have no try/catch or try/except blocks. Errors may go unlogged.",
                "fix": None,
            }
        )

    return findings
