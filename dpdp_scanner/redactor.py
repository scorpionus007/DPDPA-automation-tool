"""
Secret redaction before LLM API calls.

Replaces detected secrets with typed placeholders so the LLM still
understands code structure but never sees actual credentials.
"""

from __future__ import annotations

import os
import re
from typing import Callable, List, Tuple, Union

REDACTION_DEBUG = os.getenv("DPDP_DEBUG", "").strip().lower() in ("1", "true", "yes")

# (pattern, replacement) or (pattern, replacement, type_for_logging)
# replacement can be str or callable(match) -> str
REDACTION_PATTERNS: List[Tuple[Union[str, re.Pattern], Union[str, Callable], str]] = [
    # API keys
    (r"(sk_live_|sk_test_|rk_live_)[a-zA-Z0-9]{20,}", "REDACTED_STRIPE_KEY", "REDACTED_STRIPE_KEY"),
    (r"(AIza)[a-zA-Z0-9\-_]{35}", "REDACTED_GOOGLE_API_KEY", "REDACTED_GOOGLE_API_KEY"),
    (r"(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}", "REDACTED_GITHUB_TOKEN", "REDACTED_GITHUB_TOKEN"),
    (r"xox[baprs]-[a-zA-Z0-9\-]{10,}", "REDACTED_SLACK_TOKEN", "REDACTED_SLACK_TOKEN"),
    (r"(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}", "REDACTED_AWS_ACCESS_KEY", "REDACTED_AWS_ACCESS_KEY"),
    # Passwords in assignments (key = "value" or key: "value")
    (
        r"(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)"
        r"\s*[=:]\s*[\"'][^\"']{6,}[\"']",
        lambda m: (m.group(0).split("=")[0].split(":")[0].strip() + ' = "REDACTED_CREDENTIAL"'),
        "REDACTED_CREDENTIAL",
    ),
    # Connection strings
    (
        r"(postgresql|mysql|mongodb|redis):\/\/[^@]+@[^\s\"']+",
        lambda m: m.group(0).split("://")[0] + "://REDACTED_USER:REDACTED_PASS@REDACTED_HOST/REDACTED_DB",
        "REDACTED_CONNECTION_STRING",
    ),
    # Indian-specific
    (r"\b[2-9]{1}[0-9]{11}\b", "REDACTED_AADHAAR", "REDACTED_AADHAAR"),
    (r"[A-Z]{5}[0-9]{4}[A-Z]{1}", "REDACTED_PAN", "REDACTED_PAN"),
    # Generic high-entropy strings that look like secrets
    (r"[\"'][a-zA-Z0-9+/]{32,}={0,2}[\"']", "REDACTED_POSSIBLE_SECRET", "REDACTED_POSSIBLE_SECRET"),
]


def redact(content: str, file_path: str = "") -> Tuple[str, List[dict]]:
    """
    Redact secrets from content before sending to LLM.
    Returns (redacted_content, list_of_redaction_records).

    Uses typed placeholders so the LLM still understands code structure:
    - REDACTED_CREDENTIAL — password/key assignment
    - REDACTED_CONNECTION_STRING — database URL
    - REDACTED_AADHAAR — Indian Aadhaar number
    - REDACTED_PAN — Indian PAN card number
    """
    redactions: List[dict] = []
    result = content

    for item in REDACTION_PATTERNS:
        if len(item) == 3:
            pattern, replacement, type_str = item
        else:
            pattern, replacement = item[0], item[1]
            type_str = replacement if isinstance(replacement, str) else "REDACTED_CUSTOM"

        flags = 0 if isinstance(pattern, re.Pattern) else re.IGNORECASE
        if callable(replacement):
            new_result, count = re.subn(pattern, replacement, result, flags=flags)
        else:
            new_result, count = re.subn(pattern, replacement, result, flags=flags)

        if count > 0:
            redactions.append({"type": type_str, "count": count, "file": file_path})
            if REDACTION_DEBUG:
                matches = re.findall(pattern, result, flags=flags)
                samples = [str(m)[:40] + ("..." if len(str(m)) > 40 else "") for m in matches[:3]]
                from rich.console import Console
                Console().print(f"    [dim]Redacting in {file_path}: {type_str} — {samples}[/dim]")
        result = new_result

    # Redact 9–18 digit strings only when content suggests bank/account context
    if re.search(r"bank|account|ifsc", result, re.IGNORECASE):
        result, count = re.subn(
            r"\b[0-9]{9,18}\b", "REDACTED_POSSIBLE_ACCOUNT", result
        )
        if count > 0:
            redactions.append({
                "type": "REDACTED_POSSIBLE_ACCOUNT",
                "count": count,
                "file": file_path,
            })

    return result, redactions
