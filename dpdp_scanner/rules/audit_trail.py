"""
Rule: AUDIT_TRAIL_MISSING / AUDIT_TRAIL_PRESENT
DPDP Section 8(4) — Data Fiduciary must maintain complete and accurate records
of personal data processing activities.

Three sub-checks:
  1. Access logging — are PII access events logged?
  2. Audit table — is there a dedicated audit/activity log model?
  3. Change tracking — are model mutations tracked (updated_at, event sourcing)?

Only fires when PII storage confirmed (model files with PII exist).
"""

import re


# ── Access logging patterns ────────────────────────────────────────────────
ACCESS_LOG_PATTERNS = [
    r'audit_log\s*[\.(]',
    r'audit\.log\s*\(',
    r'AuditLog\s*[\.(]',
    r'AuditLogger\s*[\.(]',
    r'ActivityLog\s*[\.(]',
    r'activity_log\s*[\.(]',
    r'access_log\s*[\.(]',
    r'AccessLog\s*[\.(]',
    r'DataAccessLog\s*[\.(]',
    r'post_save\.connect',
    r'pre_delete\.connect',
    r'@receiver\s*\(\s*post_save',
    r'@receiver\s*\(\s*pre_delete',
    r'event\.listen\s*\(',
    r'@event\.listens_for',
    r'after_(?:create|update|destroy)\s+:log',
    r'around_(?:create|update|destroy)',
    r'acts_as_audited',
    r'audited\s+(?:only|except)?:',
    r'@Audit\b',
    r'@AuditLog\b',
    r'AuditAspect\b',
    r'@Around.*audit',
    r'AuditMiddleware\b',
    r'audit\.Record\s*\(',
    r'LogDataAccess\s*\(',
    r'OwenIt\\Auditing',
    r'use\s+Auditable\b',
    r'Audit::log\s*\(',
    r'IAuditLog\b',
    r'AuditEntry\b',
    r'\.AddAuditLog\s*\(',
    r'log(?:ger)?\.info.*(?:accessed|retrieved|fetched).*(?:user|profile|personal)',
    r'log(?:ger)?\.info.*user_id.*(?:access|view|export)',
]


# ── Audit table / model patterns ───────────────────────────────────────────
AUDIT_MODEL_PATTERNS = [
    r'class\s+\w*(?:Audit|Activity|Access|DataAccess|Event|Trail|History)Log\b',
    r'AuditLog\s*=\s*(?:db\.Model|Base|DeclarativeBase)',
    r'create_table\s+[\'"]audit',
    r'CREATE\s+TABLE.*audit_log',
    r'audit_logs\b.*migration',
    r'create_table\s+:audit',
    r'create_table\s+:activity_log',
    r'@Entity.*Audit',
    r'@Table.*audit',
    r'type\s+\w*(?:Audit|Activity|Event|Trail|History)Log\s+struct',
    r'DbSet<\w*(?:Audit|Activity|Event|Trail|History)Log>',
    r'^\s*model\s+\w*(?:Audit|Activity|Event|Trail|History)Log\b',
    r'(?:pgTable|sqliteTable|mysqlTable)\s*\(\s*[\'"]\w*(?:audit|activity|event)_log',
    r'export\s+const\s+\w*(?:Audit|Activity|Event|Trail|History)Log\s*=\s*(?:pgTable|sqliteTable|mysqlTable)',
    r'prisma\.\w*(?:Audit|Activity|Event|Trail|History)Log\.(?:create|createMany|findMany)',
]


# ── Change tracking patterns ───────────────────────────────────────────────
CHANGE_TRACKING_PATTERNS = [
    r'updated_at\b',
    r'updatedAt\b',
    r'updated_by\b',
    r'updatedBy\b',
    r'modified_at\b',
    r'modifiedAt\b',
    r'last_modified\b',
    r'lastModified\b',
    r'version\s*=\s*Column\(',
    r'@Version\b',
    r'optimistic_lock\b',
    r'acts_as_versioned\b',
    r'paper_trail\b',
    r'has_paper_trail\b',
    r'PaperTrail\b',
    r'deleted_by\b',
    r'deletedBy\b',
    r'EventStore\b',
    r'event_sourcing\b',
    r'DomainEvent\b',
    r'EventBus\b',
]

# Prefer audit model files over cleanup tasks for evidence
EVIDENCE_FILE_PREFERENCE = [
    r"audit[_\-]?log\.",
    r"audit[_\-]?trail\.",
    r"activity[_\-]?log\.",
    r"access[_\-]?log\.",
    r"event[_\-]?log\.",
    r"audit/",
    r"logging/",
]


def _best_audit_evidence(files_with_matches: list) -> dict:
    """Prefer actual audit model files over incidental matches."""
    if not files_with_matches:
        return {}
    for pattern in EVIDENCE_FILE_PREFERENCE:
        for match in files_with_matches:
            if re.search(pattern, match.get("file", ""), re.IGNORECASE):
                return match
    return files_with_matches[0]


def _scan_files(file_contents: dict, patterns: list, skip_comments: bool = True) -> list:
    """Return [{file, line_number, matched_text}] for first match per file."""
    results = []
    for path, content in file_contents.items():
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped:
                continue
            if skip_comments and stripped.startswith(
                ("#", "//", "*", "/*", "<!--", "--")
            ):
                continue
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append({
                        "file": path,
                        "line_number": i,
                        "matched_text": stripped[:120],
                    })
                    break
            else:
                continue
            break  # first match per file
    return results


def _has_pii_storage(extracted: dict) -> bool:
    """Only flag audit issues when PII is actually being stored in models."""
    return (
        len(extracted.get("pii_fields", [])) >= 5
        and len(extracted.get("model_files", [])) >= 1
    )


def run(extracted: dict) -> list:
    findings = []

    if not _has_pii_storage(extracted):
        return findings

    file_contents = extracted.get("_file_contents", {})

    access_logs = _scan_files(file_contents, ACCESS_LOG_PATTERNS)
    audit_models = _scan_files(file_contents, AUDIT_MODEL_PATTERNS)
    change_tracking = _scan_files(file_contents, CHANGE_TRACKING_PATTERNS)

    checks_passed = sum([
        bool(access_logs),
        bool(audit_models),
        bool(change_tracking),
    ])

    def _found_parts():
        parts = []
        if access_logs:
            parts.append("access logging")
        if audit_models:
            parts.append("audit model")
        if change_tracking:
            parts.append("change tracking")
        return parts

    all_matches = (access_logs or []) + (audit_models or []) + (change_tracking or [])
    best_evidence = _best_audit_evidence(all_matches)

    if checks_passed == 0:
        findings.append({
            "rule": "AUDIT_TRAIL_MISSING",
            "dpdp_section": "Section 8(4) — Audit Trail",
            "severity": "HIGH",
            "confidence": 0.70,
            "file": "N/A",
            "display_path": "N/A",
            "line_number": None,
            "description": (
                "No audit trail infrastructure detected. "
                "DPDP Section 8(4) requires complete records of personal data "
                "processing activities. No access logging, audit model, or "
                "change tracking found in the codebase."
            ),
            "evidence": {
                "access_logging": False,
                "audit_model": False,
                "change_tracking": False,
                "model_files_checked": len(extracted.get("model_files", [])),
            },
            "fix": None,
            "requires_human_validation": False,
        })

    elif bool(audit_models):
        first = best_evidence or (access_logs or audit_models)[0]
        findings.append({
            "rule": "AUDIT_TRAIL_PRESENT",
            "dpdp_section": "Section 8(4) — Audit Trail",
            "severity": "PASS",
            "confidence": 0.8 if checks_passed >= 2 else 0.72,
            "file": first.get("file", "N/A"),
            "display_path": first.get("file", "N/A"),
            "line_number": first.get("line_number"),
            "description": (
                f"Dedicated audit trail infrastructure detected ({checks_passed}/3 checks passed). "
                f"Access logging: {'✓' if access_logs else '✗'}  "
                f"Audit model: {'✓' if audit_models else '✗'}  "
                f"Change tracking: {'✓' if change_tracking else '✗'}"
            ),
            "evidence": {
                "access_logging": bool(access_logs),
                "audit_model": bool(audit_models),
                "change_tracking": bool(change_tracking),
                "audit_models_detected": audit_models[:5],
            },
            "fix": None,
        })

    elif checks_passed >= 2 and not bool(audit_models):
        found_parts = _found_parts()
        findings.append({
            "rule": "AUDIT_TRAIL_PARTIAL",
            "dpdp_section": "Section 8(4) — Audit Trail",
            "severity": "MEDIUM",
            "confidence": 0.65,
            "file": best_evidence.get("file", "N/A") if best_evidence else "N/A",
            "display_path": best_evidence.get("file", "N/A") if best_evidence else "N/A",
            "line_number": best_evidence.get("line_number") if best_evidence else None,
            "description": (
                "Partial audit trail detected. "
                f"Found: {', '.join(found_parts)}. "
                "Missing: dedicated audit model/table. "
                "DPDP Section 8(4) requires a structured audit trail with "
                "user identity, timestamp, action, and data accessed. "
                "A dedicated audit log table is required for proper compliance."
            ),
            "evidence": {
                "access_logging": bool(access_logs),
                "audit_model": False,
                "change_tracking": bool(change_tracking),
                "found_samples": (access_logs or change_tracking)[:2],
            },
            "fix": None,
            "requires_human_validation": True,
        })

    else:
        found_parts = _found_parts()
        missing_parts = []
        if not access_logs:
            missing_parts.append("access logging")
        if not audit_models:
            missing_parts.append("audit model")
        if not change_tracking:
            missing_parts.append("change tracking")
        samples = (access_logs or audit_models or change_tracking)[:2]
        findings.append({
            "rule": "AUDIT_TRAIL_PARTIAL",
            "dpdp_section": "Section 8(4) — Audit Trail",
            "severity": "MEDIUM",
            "confidence": 0.65,
            "file": "N/A",
            "display_path": "N/A",
            "line_number": None,
            "description": (
                "Partial audit trail detected. "
                f"Found: {', '.join(found_parts)}. "
                f"Missing: {', '.join(missing_parts)}."
            ),
            "evidence": {
                "access_logging": bool(access_logs),
                "audit_model": bool(audit_models),
                "change_tracking": bool(change_tracking),
                "found_samples": samples,
            },
            "fix": None,
            "requires_human_validation": True,
        })

    return findings
