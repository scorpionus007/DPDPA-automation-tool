"""
Security rule — DPDP Section 8(1).
Reasonable security safeguards must protect personal data.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List

from dpdp_scanner.extractor import is_noise_path


def _get_content(extracted: Dict, filepath: str) -> str:
    """Retrieve file content from extracted._file_contents."""
    return (extracted.get("_file_contents") or {}).get(filepath, "")


LOG_PATTERNS = [
    r"console\.log\s*\(",
    r"print\s*\(",
    r"logger\.\w+\s*\(",
    r"log\.(info|debug|warn|error)\s*\(",
    r"logging\.\w+\s*\(",
]
PII_KEYWORDS = ["email", "phone", "password", "token", "aadhaar"]
STRUCTURED_LOGGER_HINTS = ["io.logger", "pino", "winston", "bunyan", "structlog", "loguru"]
REDACTION_HINTS = [
    r"\bredact",
    r"\bsanitize",
    r"\bmask",
    r"\bhash",
    r"\btokeni[sz]e",
]

# Stricter: real credential assignments only — not type annotations, form fields, or HTML
HARDCODED_PATTERNS = [
    (
        r"(?:^|[\s;{(,])(?:password|passwd|pwd)\s*[=:]\s*"
        r'["\']'
        r"(?!"
        r"\s*[\"']|"
        r"required|optional|"
        r"string|str|int|bool|"
        r"password[\"']|passwd[\"']|pwd[\"']|"
        r"\*{3,}|x{3,}|redacted|"
        r"<[^>]{1,100}>|"
        r"\$\{[^}]+\}"
        r")"
        r'[^"\']{8,}["\']',
        "hardcoded_password",
    ),
    (
        r"(?<![\"'\w])(?:secret[_-]?key|api[_-]?secret|client[_-]?secret|auth[_-]?secret)\s*=\s*[\"']"
        r"(?![\"'])[a-zA-Z0-9+/._-]{12,}[\"']",
        "hardcoded_secret",
    ),
    (
        r"(?:api_key|apikey|access_key|private_key)\s*=\s*[\"'](?:[a-zA-Z0-9_\-]{20,})[\"']",
        "hardcoded_api_key",
    ),
    (r"sk_(?:live|test)_[a-zA-Z0-9]{20,}", "stripe_key"),
    (r"rzp_(?:live|test)_[a-zA-Z0-9]{14,}", "razorpay_key"),
    (r"AIza[a-zA-Z0-9_\-]{35}", "google_api_key"),
    (r"gh[pousr]_[a-zA-Z0-9]{36}", "github_token"),
    (r"sk-ant-[a-zA-Z0-9_\-]{20,}", "anthropic_key"),
    (r"xox[baprs]-[a-zA-Z0-9\-]{10,}", "slack_token"),
    (r"AKIA[A-Z0-9]{16}", "aws_access_key"),
    (r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9_\-]{43}", "sendgrid_key"),
    (
        r"rzp_(?:live|test)_[a-zA-Z0-9]+.*(?:ridewave|secret|key)",
        "razorpay_hardcoded",
    ),
]

SCHEMA_ANNOTATION_PATTERNS = [
    r":\s*z\.", r":\s*yup\.", r":\s*Joi\.", r":\s*string\b", r":\s*String\b",
    r'type\s*=\s*["\']password["\']', r'name\s*=\s*["\']password["\']',
    r"autocomplete\s*=", r"placeholder\s*=", r"\.CharField\s*\(", r"\.PasswordInput\b",
    r"forms\.\w+Field\s*\(", r"@Column\b", r"@Field\b", r"password\s*\?\s*:",
    r"//.*password", r"#.*password", r"password.*\bfield\b", r"\bvalidat",
    r"\brequired\b.*password", r"E_PASSWORD_STRENGTH", r"@plane/", r"password_strength",
    r"password_policy", r"password_rules", r"password_hint", r"password_confirm",
    r"confirm_password", r"current_password", r"new_password", r"old_password",
    r"password_label", r"password_placeholder", r"password_error",
    r"PASSWORD_MIN", r"PASSWORD_MAX", r"PASSWORD_REGEX",
]

ENCRYPTION_INDICATORS = ["hash", "bcrypt", "argon", "pbkdf2", "scrypt", "encrypt"]

LARAVEL_HASH_PATTERNS = [
    r"Hash::make\s*\(",
    r"Hash::check\s*\(",
    r"bcrypt\s*\(",
    r"'hashed'\s*=>",
    r"Hashed::class",
    r"\$casts\s*=.*password",
    r"protected\s+\$hidden\s*=\s*\[.*password",
    r"make\s*\(\s*\$.*password",
]

DB_CONNECTION_PATTERNS = [
    r"DriverManager\.getConnection",
    r"createConnection\s*\(",
    r"getConnection\s*\(",
    r"ConnectionPool\b",
    r"DataSource\b",
    r"\.setUrl\s*\(",
    r"db\.(?:host|user|name|port)\b",
    r"framework\.db\.",
    r"extends\s+DB\b",
    r"extends\s+BatchDB\b",
    r"extends\s+PoolDB\b",
    r"HikariConfig\b",
    r"BasicDataSource\b",
    r"c3p0\b",
    # MySQL / MariaDB specific
    r"mariadb\.createPool\s*\(",
    r"mariadb\.createConnection\s*\(",
    r"mysql\.createPool\s*\(",
    r"mysql\.createConnection\s*\(",
    r"mysql2\.createPool\s*\(",
    r"mysql2\.createConnection\s*\(",
    r"createPool\s*\(\s*\{",
    r"createConnection\s*\(\s*\{",
    r"host\s*:\s*[\'\"]([^\'\"]*)[\'\"]",
    r"socketPath\s*:",
    r"connectTimeout\s*:",
    r"acquireTimeout\s*:",
    r"waitForConnections\s*:",
    r"connectionLimit\s*:",
    r"queueLimit\s*:",
    # Node.js database driver patterns
    r"new\s+Pool\s*\(",
    r"new\s+Client\s*\(",
    r"neon\s*\(",
    r"drizzle\s*\(",
    r"knex\s*\(",
    r"mongoose\.connect\s*\(",
    r"sequelize\s*=\s*new\s+Sequelize",
    # Python database drivers
    r"psycopg2\.connect\s*\(",
    r"pymysql\.connect\s*\(",
    r"pymongo\.MongoClient\s*\(",
    r"create_engine\s*\(",
    r"engine\s*=\s*create_engine",
    # Java JDBC
    r"DriverManager\.getConnection\s*\(",
    # Go database drivers
    r"sql\.Open\s*\(",
    r"db\.Open\s*\(",
    r"pgx\.Connect\s*\(",
    r"sqlx\.Connect\s*\(",
    # PHP database
    r"new\s+PDO\s*\(",
    r"mysqli_connect\s*\(",
    r"pg_connect\s*\(",
    # Laravel config patterns
    r"'driver'\s*=>",
    r"'host'\s*=>",
    r"env\s*\(\s*['\"]DB_",
    r"DB_PASSWORD",
    r"DB_HOST",
    r"DB_USERNAME",
    r"framework\.db\.",
]

LARAVEL_DB_CONFIG_PATTERNS = [
    r"'driver'\s*=>",
    r"'host'\s*=>",
    r"'database'\s*=>",
    r"'username'\s*=>",
    r"config/database",
    r"env\s*\(\s*['\"]DB_",
    r"DB_PASSWORD",
]

PASSWORD_NOT_HASHED_EXCLUSIONS = [
    r"management/commands/",
    r"management\\commands\\",
    r"migrations/",
    r"migrate/",
    r"test",
    r"spec/",
    r"fixture",
    r"seed",
    r"factory",
    r"adapter-",
    r"\.config\.",
    r"scripts/",
]

DJANGO_PASSWORD_SAFE_PATTERNS = [
    r"set_password\s*\(",
    r"make_password\s*\(",
    r"check_password\s*\(",
    r"AbstractUser\b",
    r"AbstractBaseUser\b",
    r"BaseUserManager\b",
    r"PASSWORD_HASHERS\b",
    r"authenticate\s*\(",
    r"auth\.authenticate\b",
]

DEBUG_MODE_PATTERNS = [
    (r"app\.run\s*\([^)]*debug\s*=\s*True", "flask_debug_true"),
    (r"FLASK_DEBUG\s*=\s*[\"']?1[\"']?", "flask_debug_env"),
    (r"DEBUG\s*=\s*True", "debug_flag_true"),
    (r"NODE_ENV\s*[=:]\s*[\"']?development[\"']?", "node_dev_mode"),
    (r"debug\s*=\s*True(?!\s*if)", "debug_assignment_true"),
    (r"verbose\s*=\s*True", "verbose_true"),
]

DEBUG_FALSE_POSITIVE_PATHS = [
    r"test",
    r"spec",
    r"\.env\.example",
    r"\.env\.development",
    r"README",
    r"docs/",
    r"example",
    r"sample",
]


def _is_db_connection_class(content: str, file_path: str = "") -> bool:
    """
    Returns True if file is a DB connection/pool/adapter infrastructure file.
    password field in these files is an infrastructure credential,
    not a user password requiring hashing.
    """
    path_lower = (file_path or "").replace("\\", "/").lower()
    filename = os.path.basename(file_path).lower()

    # Fast path: filename strongly suggests DB infrastructure
    DB_INFRA_FILENAMES = [
        "db.py", "db.ts", "db.js", "db.go", "db.java",
        "database.py", "database.ts", "database.php",
        "connection.py", "connection.ts",
        "pool.py", "pool.ts",
        "mariadb.ts", "mysql.ts", "postgres.ts", "sqlite.ts",
        "mongodb.ts", "redis.ts",
        "batchdb.java", "pooldb.java",
        "datasource.java", "datasource.ts",
    ]
    if filename in DB_INFRA_FILENAMES:
        return True

    # Config file path patterns
    if re.search(
        r"config/database|database\.config|db\.config|"
        r"adapter-(?:mariadb|mysql|postgres|sqlite|mongodb)",
        file_path,
        re.IGNORECASE,
    ):
        return True

    # Content signal count
    signal_count = sum(
        1 for p in DB_CONNECTION_PATTERNS
        if re.search(p, content, re.IGNORECASE)
    )
    if signal_count >= 2:
        return True
    laravel_db_signals = sum(
        1 for p in LARAVEL_DB_CONFIG_PATTERNS
        if re.search(p, content, re.IGNORECASE)
        or (p == r"config/database" and "config/database" in path_lower)
    )
    if laravel_db_signals >= 3:
        return True
    return False


def _logger_context(file_path: str, content: str) -> str:
    path_norm = (file_path or "").replace("\\", "/").lower()
    if re.search(r"/jobs?/|/cron/|/workers?/|\.handler\.(ts|js)$", path_norm):
        return "job"
    if any(sig in (content or "").lower() for sig in ("bullmq", "inngest", "temporal", "trigger.dev", "io.logger")):
        return "job"
    if re.search(r"/(routes?|controllers?|api|trpc)/", path_norm):
        return "request"
    if any(sig in (content or "").lower() for sig in ("req.", "request.", "context.get(", "fastify", "express")):
        return "request"
    if re.search(r"/services?/", path_norm):
        return "service"
    return "unknown"


def _has_redaction_hint(line: str, content: str) -> bool:
    joined = f"{line}\n{content[:500]}"
    return any(re.search(pattern, joined, re.IGNORECASE) for pattern in REDACTION_HINTS)


def check_security(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []
    pii_in_logs_files_seen: set = set()
    hardcoded_files_seen: set = set()
    debug_mode_files_seen: set = set()
    is_library = bool(extracted.get("is_framework_library"))
    file_contents = extracted.get("_file_contents") or {}
    model_files = set(extracted.get("model_files") or [])
    route_files = set(extracted.get("route_files") or [])

    for path, content in file_contents.items():
        if not content or is_noise_path(path):
            continue
        path_lower = path.lower()
        is_env = ".env" in path_lower or path_lower.endswith(".env")
        is_test = "test" in path_lower or "spec" in path_lower or "__test__" in path_lower

        lines = content.splitlines()
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()

            # 1. Plaintext PII in logs — log call and PII keyword on same line (one finding per file)
            has_log = any(re.search(pat, stripped) for pat in LOG_PATTERNS)
            if has_log and path not in pii_in_logs_files_seen:
                for kw in PII_KEYWORDS:
                    if re.search(kw, stripped, re.IGNORECASE):
                        logger_context = _logger_context(path, content)
                        uses_structured_logger = any(
                            hint in content.lower() for hint in STRUCTURED_LOGGER_HINTS
                        )
                        has_redaction = _has_redaction_hint(stripped, content)
                        if has_redaction:
                            severity = "LOW"
                            confidence = 0.45
                            description = (
                                "PII keyword appears in a logging call, but nearby redaction/masking "
                                "signals suggest the value may be sanitized. Verify production log output."
                            )
                        elif logger_context == "job" and uses_structured_logger:
                            severity = "MEDIUM"
                            confidence = 0.60
                            description = (
                                "PII keyword appears in an internal job logger. Verify production log "
                                "retention, access controls, and PII redaction policy."
                            )
                        else:
                            severity = "HIGH"
                            confidence = 0.85
                            description = (
                                "PII keyword appears in logging call. Personal data may be written to "
                                "logs in plaintext."
                            )
                        pii_in_logs_files_seen.add(path)
                        findings.append(
                            {
                                "rule": "PLAINTEXT_PII_IN_LOGS",
                                "dpdp_section": "Section 8(1) — Security",
                                "severity": severity,
                                "confidence": confidence,
                                "file": path,
                                "evidence": {
                                    "file": path,
                                    "line_number": line_no,
                                    "line_content": stripped[:200],
                                    "pattern": f"log + {kw}",
                                    "all_pii_keywords_found": [],
                                    "logger_context": logger_context,
                                    "structured_logger": uses_structured_logger,
                                    "redaction_hint": has_redaction,
                                },
                                "description": description,
                                "fix": None,
                            }
                        )
                        break

            # 2. Hardcoded secrets (skip .env and test files; skip schema/type/HTML lines; one per file)
            if not is_env and not is_test and path not in hardcoded_files_seen:
                if any(re.search(ap, stripped, re.IGNORECASE) for ap in SCHEMA_ANNOTATION_PATTERNS):
                    pass  # skip this line for hardcoded check
                else:
                    for pat, name in HARDCODED_PATTERNS:
                        if re.search(pat, stripped, re.IGNORECASE):
                            hardcoded_files_seen.add(path)
                            findings.append(
                                {
                                    "rule": "HARDCODED_SECRET",
                                    "dpdp_section": "Section 8(1) — Security",
                                    "severity": "HIGH",
                                    "confidence": 0.90,
                                    "file": path,
                                    "evidence": {
                                        "file": path,
                                        "line_number": line_no,
                                        "line_content": stripped[:200],
                                        "pattern": name,
                                    },
                                    "description": f"Hardcoded {name} detected. Secrets should be in environment variables.",
                                    "fix": None,
                                }
                            )
                            break

        # 2b. Debug / dev mode enabled (file-level; skip fixtures & docs)
        # Framework repos document debug=True in API examples — not a production deployment risk.
        path_fwd = path.replace("\\", "/")
        if (
            not is_library
            and not any(re.search(p, path_fwd, re.IGNORECASE) for p in DEBUG_FALSE_POSITIVE_PATHS)
        ):
            if path not in debug_mode_files_seen:
                for pattern, pname in DEBUG_MODE_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        debug_mode_files_seen.add(path)
                        line_no = content[: match.start()].count("\n") + 1
                        line_list = content.splitlines()
                        line_content = (
                            line_list[line_no - 1][:200].strip()
                            if 0 < line_no <= len(line_list)
                            else ""
                        )
                        findings.append(
                            {
                                "rule": "DEBUG_MODE_ENABLED",
                                "dpdp_section": "Section 8(1) — Security",
                                "severity": "HIGH",
                                "confidence": 0.90,
                                "file": path,
                                "evidence": {
                                    "file": path,
                                    "line_number": line_no,
                                    "line_content": line_content,
                                    "pattern": pname,
                                },
                                "description": (
                                    "Debug mode is enabled. In production, this exposes "
                                    "interactive debuggers (Flask/Werkzeug), detailed stack traces, "
                                    "and internal system information to users. Flask debug mode "
                                    "specifically allows arbitrary code execution via the Werkzeug "
                                    "console. DPDP Section 8(1) requires appropriate security "
                                    "measures to protect personal data."
                                ),
                                "fix": [
                                    "Set debug=False or remove the debug parameter for production.",
                                    "Use environment variables: "
                                    "app.run(debug=os.getenv('FLASK_DEBUG', 'false') == 'true')",
                                    "Use a production WSGI server (gunicorn, uwsgi) instead of "
                                    "Flask's built-in development server.",
                                    "Set FLASK_ENV=production in your deployment environment.",
                                ],
                            }
                        )
                        break

        # 3. Password not hashed (model files with password field)
        if path in model_files or any(kw in path_lower for kw in ("model", "schema", "entity")):
            path_norm = path.replace("\\", "/")
            if any(re.search(p, path_norm, re.IGNORECASE) for p in PASSWORD_NOT_HASHED_EXCLUSIONS):
                continue
            if re.search(r"\bpassword\b", content, re.IGNORECASE):
                if _is_db_connection_class(content, path):
                    continue
                has_encryption = (
                    any(re.search(ind, content, re.IGNORECASE) for ind in ENCRYPTION_INDICATORS)
                    or any(re.search(p, content, re.IGNORECASE) for p in LARAVEL_HASH_PATTERNS)
                    or any(re.search(p, content, re.IGNORECASE) for p in DJANGO_PASSWORD_SAFE_PATTERNS)
                )
                if not has_encryption:
                    findings.append(
                        {
                            "rule": "PASSWORD_NOT_HASHED",
                            "dpdp_section": "Section 8(1) — Security",
                            "severity": "HIGH",
                            "confidence": 0.80,
                            "file": path,
                            "evidence": {
                                "file": path,
                                "line_number": 0,
                                "line_content": "",
                                "pattern": "password without hash/bcrypt/argon",
                            },
                            "description": "Model file has password field but no hash/bcrypt/argon/pbkdf2/scrypt/encrypt reference.",
                            "fix": None,
                        }
                    )

    return findings
