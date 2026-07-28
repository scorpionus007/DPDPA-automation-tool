"""
Retention rule — DPDP Section 8(3).
Data must not be retained beyond the purpose it was collected for.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List

from dpdp_scanner.rules.security import _is_db_connection_class


def _get_content(extracted: Dict, filepath: str) -> str:
    """Retrieve file content from extracted._file_contents."""
    return (extracted.get("_file_contents") or {}).get(filepath, "")


def _is_migration_or_schema_only_path(path: str) -> bool:
    """Skip migration/schema dump files — they rarely define retention policy."""
    p = path.replace("\\", "/").lower()
    return (
        "/migrate/" in p
        or "/migrations/" in p
        or (p.endswith("schema.rb") and "/db/" in p)
        or ("/database/" in p and "migration" in p)
    )


VALIDATION_SCHEMA_SIGNALS = [
    "z.object(",
    "z.string(",
    "z.number(",
    "zod",
    "yup.object(",
    "Joi.object(",
    "vine.object(",
    "class-validator",
]

VALIDATION_FILENAME_PATTERNS = [
    "schema",
    "validation",
    "validator",
    "dto",
    "form-schema",
    "request",
    "input",
    "payload",
]


RETENTION_EXCLUSION_PATHS = [
    r"management/commands/",
    r"management\\commands\\",
    r"management[/\\]commands[/\\]",
    r"db[/\\]management[/\\]",
    r"management[/\\]\w+\.py$",
    r"migrations/",
    r"/runtime/",
    r"applyFluent",
    r"applyModel",
    r"test",
    r"fixture",
    r"seed",
    r"factory",
    r"concerns/",
    r"concerns\\",
    r"application_record",
    r"base_record",
    r"abstract_model",
]

MANAGEMENT_COMMAND_FILENAMES = {
    "activate_user.py",
    "create_dummy_data.py",
    "create_instance_admin.py",
    "create_project_member.py",
    "reset_password.py",
    "update_deleted_workspace_slug.py",
    "create_superuser.py",
    "create_admin.py",
    "seed_data.py",
    "import_data.py",
    "export_data.py",
    "flush_cache.py",
}


def _is_real_orm_model(content: str, filepath: str) -> bool:
    """Returns True only if file is a real ORM model with PII fields."""

    path_norm = filepath.replace("\\", "/").lower()
    if any(re.search(p, path_norm, re.IGNORECASE) for p in RETENTION_EXCLUSION_PATHS):
        return False

    base_name = os.path.basename(path_norm)
    if base_name in MANAGEMENT_COMMAND_FILENAMES:
        return False

    RUNTIME_INTERNAL_PATTERNS = [
        r"/runtime/",
        r"/internals/",
        r"applyFluent",
        r"applyModel",
        r"applyItx",
        r"QueryBuilder",
        r"queryBuilder",
        r"FluentApi",
        r"ModelDelegate",
        r"/query/",
        r"\.generated\.",
        r"generated/",
    ]
    if any(re.search(p, filepath, re.IGNORECASE) for p in RUNTIME_INTERNAL_PATTERNS):
        return False

    # Exclude DB connection/adapter/driver files (infra credentials, not user-data retention)
    if _is_db_connection_class(content, filepath):
        return False

    filename = filepath.replace("\\", "/").split("/")[-1]
    if filename == "__init__.py":
        return False

    filename_lower = filename.lower()
    if any(pat in filename_lower for pat in VALIDATION_FILENAME_PATTERNS):
        if any(sig in content for sig in VALIDATION_SCHEMA_SIGNALS):
            return False

    has_validation = any(sig in content for sig in VALIDATION_SCHEMA_SIGNALS)

    ORM_SIGNALS = [
        # Python
        "Column(",
        "mapped_column(",
        "db.Model",
        "DeclarativeBase",
        "mongoose.Schema",
        "DataTypes.",
        "@Entity",
        "@Column",
        "sequelize",
        "TypeORM",
        "prisma",
        # Java/Kotlin JPA
        "@Entity",
        "@Table",
        "@MappedSuperclass",
        "extends JpaRepository",
        "CrudRepository",
        "@Column",
        "@Id",
        "@GeneratedValue",
        # Go GORM
        "gorm.Model",
        'gorm:"',
        "AutoMigrate(",
        # Ruby ActiveRecord
        "ApplicationRecord",
        "ActiveRecord::Base",
        "has_many",
        "belongs_to",
        "has_one",
        # PHP Eloquent
        "extends Model",
        "HasFactory",
        "$fillable",
        "$guarded",
        "protected $table",
        # C# Entity Framework
        "DbContext",
        ": DbContext",
        "DbSet<",
        "HasKey(",
        "ToTable(",
        # Rust Diesel
        "#[derive(Queryable",
        "#[derive(Insertable",
        "table_name =",
        "diesel::table!",
        # Rust SQLx
        "#[derive(sqlx::FromRow",
        "sqlx::query!",
        # Kotlin Exposed
        "object",
        "IntIdTable",
        "UUIDTable",
        "Table(",
    ]
    has_orm = any(signal in content for signal in ORM_SIGNALS)
    if has_validation and not has_orm:
        return False
    return has_orm


RETENTION_SIGNALS = [
    "expires_at",
    "expiry",
    "ttl",
    "retention_period",
    "deleted_at",
    "auto_delete",
    "purge_after",
    "valid_until",
    "expires_on",
    "retention_days",
    "max_age",
    "maxAge",
    "expiresAt",
    "deletedAt",
    "retentionPeriod",
    "validUntil",
    "discard_at",
    "discarded_at",
    "expiry_date",
    "expiration_date",
    "valid_from",
    "valid_to",
    "archival_date",
    "archived_at",
    "archive_after",
    "purge_date",
    "scheduled_deletion",
    "deletion_scheduled_at",
    "data_retention",
    "retain_until",
    "retention_policy",
    "cleanup_at",
    "cleaned_at",
]

# Framework-specific retention patterns (regex)
LARAVEL_RETENTION_PATTERNS = [
    r"use\s+SoftDeletes\b",
    r"SoftDeletes;",
    r"withTrashed\s*\(",
    r"onlyTrashed\s*\(",
    r"forceDelete\s*\(",
    r"restore\s*\(\s*\)",
    r"'deleted_at'",
    r"ONLY_SOFT_DELETED",
    r"Prunable\b",
    r"MassPrunable\b",
    r"pruneBy\s*\(",
]

DJANGO_RETENTION_PATTERNS = [
    r"SoftDeleteModel",
    r"SoftDeleteModelMixin",
    r"deleted_at\s*=\s*models\.(DateTimeField|BooleanField)",
    r"is_deleted\s*=\s*models\.BooleanField",
    r"expires_at\s*=\s*models\.(DateTimeField|DateField)",
    r"auto_delete_after\b",
    r"CACHES\[.*TIMEOUT\b",
    r"SESSION_COOKIE_AGE\b",
    r"PASSWORD_RESET_TIMEOUT\b",
    r"cleanup_management\b",
    r"scheduled_task.*purge",
    r"celery.*beat.*delete",
    r"periodic.*delete",
]

PRISMA_TYPEORM_RETENTION_PATTERNS = [
    r"deletedAt\s*[?:]\s*(Date|DateTime)",
    r"@DeleteDateColumn",
    r"expiresAt\s*[?:]",
    r"@@index.*deletedAt",
]

GORM_GO_RETENTION_PATTERNS = [
    r"gorm\.DeletedAt",
    r"gorm\.Model",
    r"DeletedAt\s+time\.Time",
    r"ExpiresAt\s+time\.Time",
]


def _has_framework_retention(content: str) -> bool:
    """True if model uses framework retention (SoftDeletes, deleted_at, expiry, etc.)."""
    all_patterns = (
        LARAVEL_RETENTION_PATTERNS
        + DJANGO_RETENTION_PATTERNS
        + PRISMA_TYPEORM_RETENTION_PATTERNS
        + GORM_GO_RETENTION_PATTERNS
    )
    return any(re.search(p, content, re.IGNORECASE) for p in all_patterns)


def check_retention(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []
    pii_fields = extracted.get("pii_fields", []) or []
    model_files = extracted.get("model_files", []) or []
    # Use extractor's retention signals (broader patterns) as well
    retention_signals_from_extractor = extracted.get("retention_signals", []) or []
    retention_signal_files_from_extractor = {s["file"] for s in retention_signals_from_extractor if s.get("file")}

    model_keywords = ("model", "schema", "entity", "db")
    pii_in_models = [
        p
        for p in pii_fields
        if p.get("file")
        and any(kw in (p.get("file") or "").lower() for kw in model_keywords)
    ]
    model_files_from_pii = sorted(
        set(p.get("file") for p in pii_in_models if p.get("file"))
    )
    all_model_files = sorted(set(model_files) | set(model_files_from_pii))

    model_files_checked: List[str] = []
    pii_fields_in_models: List[Dict] = []
    retention_signals_found: List[Dict] = []
    retention_missing_files_seen: set = set()

    file_contents = extracted.get("_file_contents", {})
    for path in all_model_files:
        if _is_migration_or_schema_only_path(path):
            continue
        content = file_contents.get(path, "") or _get_content(extracted, path)
        if not content:
            continue
        if not _is_real_orm_model(content, path):
            continue
        model_files_checked.append(path)
        pii_in_file = [p for p in pii_in_models if p.get("file") == path]
        pii_fields_in_models.extend(pii_in_file)

        has_retention = False
        if _has_framework_retention(content):
            retention_signals_found.append(
                {"file": path, "signal": "framework_retention_or_soft_delete"}
            )
            has_retention = True
        for sig in RETENTION_SIGNALS:
            if re.search(rf"\b{re.escape(sig)}\b", content, re.IGNORECASE):
                retention_signals_found.append({"file": path, "signal": sig})
                has_retention = True
        if re.search(r"created_at|createdAt", content, re.IGNORECASE) and re.search(
            r"cleanup|purge|delete|retention", content, re.IGNORECASE
        ):
            retention_signals_found.append({"file": path, "signal": "created_at+cleanup"})
            has_retention = True
        if path in retention_signal_files_from_extractor:
            retention_signals_found.append({"file": path, "signal": "extractor_retention_signal"})
            has_retention = True

        if pii_in_file and not has_retention:
            if path in retention_missing_files_seen:
                continue
            retention_missing_files_seen.add(path)
            findings.append(
                {
                    "rule": "RETENTION_MISSING",
                    "dpdp_section": "Section 8(3) — Retention",
                    "severity": "MEDIUM",
                    "confidence": 0.70,
                    "file": path,
                    "evidence": {
                        "model_files_checked": model_files_checked,
                        "pii_fields_in_models": pii_in_file,
                        "retention_signals_found": [],
                    },
                    "description": "Model/schema file contains PII fields but no retention or expiry signals detected. Data may be retained indefinitely.",
                    "fix": None,
                }
            )

    if model_files_checked and retention_signals_found:
        retention_coverage: Dict[str, List[str]] = {}
        for sig in retention_signals_found:
            f = sig["file"]
            if f not in retention_coverage:
                retention_coverage[f] = []
            retention_coverage[f].append(sig["signal"])

        pii_files_set = {p.get("file") for p in pii_fields_in_models if p.get("file")}
        models_without_retention = [
            f for f in model_files_checked
            if f not in retention_coverage and f in pii_files_set
        ]

        if models_without_retention:
            findings.append({
                "rule": "RETENTION_PARTIAL",
                "dpdp_section": "Section 8(3) — Retention",
                "severity": "MEDIUM",
                "confidence": 0.70,
                "file": "N/A",
                "evidence": {
                    "models_with_retention": list(retention_coverage.keys()),
                    "models_without_retention": models_without_retention,
                },
                "description": (
                    f"Retention signals found in {len(retention_coverage)} model(s) "
                    f"but {len(models_without_retention)} PII model(s) have no retention policy. "
                    f"Uncovered: {', '.join(f.split('/')[-1] for f in models_without_retention[:3])}."
                ),
                "fix": None,
            })
        else:
            sample_signals = list(set(s for sigs in retention_coverage.values() for s in sigs[:2]))[:5]
            findings.append({
                "rule": "RETENTION_PRESENT",
                "dpdp_section": "Section 8(3) — Retention",
                "severity": "PASS",
                "confidence": 0.80,
                "file": "N/A",
                "evidence": {
                    "model_files_checked": model_files_checked,
                    "retention_coverage": retention_coverage,
                    "retention_signals_found": retention_signals_found,
                },
                "description": (
                    f"Retention signals detected across {len(retention_coverage)} model(s). "
                    f"Signals: {', '.join(sample_signals)}."
                ),
                "fix": None,
            })

    return findings

