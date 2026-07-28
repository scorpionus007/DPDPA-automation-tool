"""
Extractor module.

Responsible for extracting relevant signals from ingested repository files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Set, Optional

from rich.console import Console


console = Console()
EXTRACTOR_VERSION = "trust-hardening-v1"

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


PACKAGE_TO_TECH_LABEL = {
    "@remix-run/react": "Remix",
    "@remix-run/node": "Remix",
    "next": "Next.js",
    "@sveltejs/kit": "SvelteKit",
    "astro": "Astro",
    "@astrojs/node": "Astro",
    "react": "React",
    "vue": "Vue",
    "svelte": "Svelte",
    "hono": "Hono",
    "fastify": "Fastify",
    "express": "Express",
    "nestjs": "NestJS",
    "prisma": "Prisma ORM",
    "@prisma/client": "Prisma ORM",
    "@trpc/server": "tRPC",
    "@trpc/client": "tRPC",
    "drizzle-orm": "Drizzle ORM",
    "mongoose": "MongoDB",
    "typeorm": "TypeORM",
    "sequelize": "Sequelize",
    "sqlalchemy": "SQLAlchemy",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "pydantic": "Pydantic",
    "uvicorn": "Uvicorn",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "redis": "Redis",
}


def _safe_json_loads(raw: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _repo_signature(repo_files: List[Dict]) -> str:
    hasher = hashlib.sha1()
    for item in sorted(repo_files, key=lambda f: f.get("path", "")):
        path = item.get("path", "")
        content = item.get("content") or ""
        hasher.update(path.encode("utf-8", errors="ignore"))
        hasher.update(str(len(content)).encode("utf-8"))
        hasher.update(hashlib.sha1(content.encode("utf-8", errors="ignore")).digest())
    hasher.update(EXTRACTOR_VERSION.encode("utf-8"))
    return hasher.hexdigest()


def _graph_cache_path(repo_files: List[Dict]) -> Path:
    cache_dir = Path(".dpdp-history") / "graph_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{_repo_signature(repo_files)}.json"


def _build_import_graph_cached(repo_files: List[Dict]) -> Dict[str, List[str]]:
    cache_path = _graph_cache_path(repo_files)
    if cache_path.is_file():
        try:
            cached = _safe_json_loads(cache_path.read_text(encoding="utf-8"))
            graph = cached.get("import_graph")
            if isinstance(graph, dict):
                return {
                    str(k): [str(x) for x in v if isinstance(x, str)]
                    for k, v in graph.items()
                    if isinstance(v, list)
                }
        except Exception:
            pass
    graph = _build_import_graph(repo_files)
    try:
        cache_path.write_text(
            json.dumps(
                {
                    "version": EXTRACTOR_VERSION,
                    "import_graph": graph,
                },
                ensure_ascii=True,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass
    return graph


def _readme_or_license_text(file_contents: Dict[str, str]) -> str:
    interesting = []
    for path, content in file_contents.items():
        base = path.replace("\\", "/").split("/")[-1].lower()
        if base.startswith("readme") or base in {"license", "license.md", "copying"}:
            interesting.append(content.lower())
    return "\n".join(interesting)


def _extract_tech_stack_deterministic(
    repo_files: List[Dict],
    file_contents: Dict[str, str],
) -> List[str]:
    tech: List[str] = []
    seen: Set[str] = set()

    def _add(label: str) -> None:
        if label and label not in seen:
            seen.add(label)
            tech.append(label)

    for path, content in file_contents.items():
        base = path.replace("\\", "/").split("/")[-1].lower()
        if base == "package.json":
            pkg = _safe_json_loads(content)
            deps = {}
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                raw = pkg.get(key) or {}
                if isinstance(raw, dict):
                    deps.update({str(k): str(v) for k, v in raw.items()})
            for pkg_name, label in PACKAGE_TO_TECH_LABEL.items():
                if pkg_name in deps:
                    _add(label)
        elif base == "requirements.txt":
            lowered = content.lower()
            for pkg_name, label in PACKAGE_TO_TECH_LABEL.items():
                if re.search(rf"^{re.escape(pkg_name)}([<>=]|$)", lowered, re.MULTILINE):
                    _add(label)
        elif base == "pyproject.toml" and tomllib is not None:
            try:
                parsed = tomllib.loads(content)
            except Exception:
                parsed = {}
            deps = []
            project = parsed.get("project") or {}
            poetry = (parsed.get("tool") or {}).get("poetry") or {}
            deps.extend(project.get("dependencies") or [])
            deps.extend(list((poetry.get("dependencies") or {}).keys()))
            for dep in deps:
                dep_name = str(dep).split()[0].lower()
                if dep_name in PACKAGE_TO_TECH_LABEL:
                    _add(PACKAGE_TO_TECH_LABEL[dep_name])
        elif base == "cargo.toml":
            _add("Rust")
        elif base == "go.mod":
            _add("Go")
        elif base == "gemfile":
            _add("Ruby")
            lowered = content.lower()
            if "rails" in lowered:
                _add("Rails")

    langs = {str(f.get("language") or "").strip().lower() for f in repo_files if f.get("language")}
    language_labels = {
        "typescript": "TypeScript",
        "javascript": "JavaScript",
        "python": "Python",
        "ruby": "Ruby",
        "go": "Go",
        "rust": "Rust",
        "php": "PHP",
        "java": "Java",
        "csharp": "C#",
        "tsx": "React",
    }
    for lang, label in language_labels.items():
        if lang in langs:
            _add(label)
    return tech[:12]


def _detect_deployment_class(
    repo_files: List[str],
    file_contents: Dict[str, str],
    is_framework_library: bool,
) -> str:
    if is_framework_library:
        return "library"
    paths = "\n".join(p.replace("\\", "/").lower() for p in repo_files)
    docs = _readme_or_license_text(file_contents)
    has_self_host_signals = any(
        token in docs or token in paths
        for token in (
            "self-host",
            "self host",
            "selfhost",
            "docker-compose",
            "dockerfile",
            "helm",
            "kubernetes",
            "agpl",
            "gpl",
        )
    )
    has_billing_signals = any(
        token in docs or token in paths or token in "\n".join(file_contents.values()).lower()
        for token in (
            "stripe",
            "subscription",
            "billing",
            "checkout",
            "plan upgrade",
            "customer portal",
        )
    )
    if has_self_host_signals and not has_billing_signals:
        return "self_hosted_oss"
    if has_billing_signals:
        return "saas"
    return "unknown"


def _build_import_graph(repo_files: List[Dict]) -> Dict[str, List[str]]:
    """
    Build a map of {file_path: [list of file_paths it imports from]}.
    Handles Python 'from x import y' and 'import x' patterns.
    Handles JS/TS 'import x from y' and 'require(y)' patterns.
    Only maps to files that actually exist in the repo (not stdlib/node_modules).
    """
    known_paths = {f["path"] for f in repo_files}
    known_basenames: Dict[str, List[str]] = {}
    for f in repo_files:
        base = os.path.splitext(os.path.basename(f["path"]))[0]
        known_basenames.setdefault(base, []).append(f["path"])

    def _resolve_basename(base: str, importer_path: str) -> Optional[str]:
        """Pick the closest match when multiple files share a basename."""
        candidates = known_basenames.get(base)
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        importer_dir = os.path.dirname(importer_path.replace("\\", "/"))
        best, best_score = candidates[0], -1
        for c in candidates:
            c_dir = os.path.dirname(c.replace("\\", "/"))
            common = len(os.path.commonprefix([importer_dir, c_dir]))
            if common > best_score:
                best, best_score = c, common
        return best

    graph: Dict[str, List[str]] = {}
    for f in repo_files:
        path = f["path"]
        content = f.get("content") or ""
        imports: List[str] = []

        if f.get("language") == "python":
            for match in re.finditer(
                r"from\s+([\w.]+)\s+import|import\s+([\w.]+)", content
            ):
                module = match.group(1) or match.group(2)
                parts = module.split(".")
                for part in reversed(parts):
                    resolved = _resolve_basename(part, path)
                    if resolved:
                        imports.append(resolved)
                        break

        elif f.get("language") in ("javascript", "typescript"):
            for match in re.finditer(
                r"from\s+[\'\"]([^\'\"]+)[\'\"]|require\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)",
                content,
            ):
                module_path = match.group(1) or match.group(2)
                base = os.path.splitext(os.path.basename(module_path))[0]
                resolved = _resolve_basename(base, path)
                if resolved:
                    imports.append(resolved)

        elif f.get("language") in ("java", "kotlin"):
            for match in re.finditer(r"import\s+([\w.]+);", content):
                module = match.group(1)
                class_name = module.split(".")[-1]
                resolved = _resolve_basename(class_name, path)
                if resolved:
                    imports.append(resolved)

        elif f.get("language") == "go":
            for match in re.finditer(r"[\"'][\w./]*/(\w+)[\"']", content):
                pkg_name = match.group(1)
                resolved = _resolve_basename(pkg_name, path)
                if resolved:
                    imports.append(resolved)

        elif f.get("language") == "ruby":
            for match in re.finditer(r"require(?:_relative)?\s+[\"']([^\"']+)[\"']", content):
                module_path = match.group(1)
                base = os.path.splitext(os.path.basename(module_path))[0]
                resolved = _resolve_basename(base, path)
                if resolved:
                    imports.append(resolved)

        elif f.get("language") == "php":
            for match in re.finditer(
                r"use\s+([\w\\]+);|require(?:_once)?\s+[\"']([^\"']+)[\"']",
                content,
            ):
                module = match.group(1) or match.group(2)
                class_name = (
                    module.split("\\")[-1]
                    if "\\" in module
                    else os.path.splitext(os.path.basename(module))[0]
                )
                resolved = _resolve_basename(class_name, path)
                if resolved:
                    imports.append(resolved)

        elif f.get("language") == "csharp":
            for match in re.finditer(r"using\s+([\w.]+);", content):
                module = match.group(1)
                class_name = module.split(".")[-1]
                resolved = _resolve_basename(class_name, path)
                if resolved:
                    imports.append(resolved)

        elif f.get("language") == "rust":
            for match in re.finditer(r"use\s+[\w:]+::(\w+)|mod\s+(\w+);", content):
                mod_name = match.group(1) or match.group(2)
                resolved = _resolve_basename(mod_name, path)
                if resolved:
                    imports.append(resolved)

        graph[path] = list(set(imports))

    return graph


def _get_transitive_imports(
    start_file: str,
    import_graph: Dict[str, List[str]],
    max_depth: int = 3,
) -> Set[str]:
    """
    Return all files reachable from start_file via imports, up to max_depth hops.
    max_depth=3 prevents infinite loops on circular imports.
    """
    visited: Set[str] = set()
    queue: List[tuple] = [(start_file, 0)]
    while queue:
        current, depth = queue.pop(0)
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        for imported in import_graph.get(current, []):
            if imported not in visited:
                queue.append((imported, depth + 1))
    visited.discard(start_file)
    return visited


def _classify_sink(import_name: str) -> Optional[str]:
    """Classify what kind of data sink a third-party import is."""
    name = (import_name or "").lower()
    ANALYTICS = (
        "mixpanel", "segment", "amplitude", "posthog",
        "heap", "fullstory", "hotjar", "ga4",
    )
    MARKETING = (
        "mailchimp", "sendgrid", "klaviyo", "hubspot",
        "brevo", "resend",
    )
    LOGGING = (
        "datadog", "sentry", "bugsnag", "rollbar",
        "logrocket", "newrelic",
    )
    PAYMENT = (
        "stripe", "razorpay", "payu", "cashfree",
        "phonepe", "braintree",
    )
    CLOUD = (
        "aws-sdk", "firebase", "supabase", "@google-cloud",
        "azure",
    )
    if any(s in name for s in ANALYTICS):
        return "analytics"
    if any(s in name for s in MARKETING):
        return "marketing_email"
    if any(s in name for s in LOGGING):
        return "error_logging"
    if any(s in name for s in PAYMENT):
        return "payment_processor"
    if any(s in name for s in CLOUD):
        return "cloud_storage"
    return None


def _has_logging_sink(content: str) -> bool:
    """True if file contains structured logging (not just print/console.log)."""
    if not content:
        return False
    structured_patterns = [
        r"logger\.\w+\s*\(",
        r"log\.(info|debug|warn|error)\s*\(",
        r"logging\.\w+\s*\(",
        r"sentry[_.]capture",
        r"Sentry\.capture",
        r"winston\.\w+\s*\(",
        r"bunyan\.\w+\s*\(",
        r"pino\.\w+\s*\(",
    ]
    return any(re.search(p, content, re.IGNORECASE) for p in structured_patterns)


def _find_path(
    start: str,
    end: str,
    import_graph: Dict[str, List[str]],
    max_hops: int = 5,
) -> Optional[List[str]]:
    """BFS path finding in import graph. Returns path from start to end or None."""
    if start == end:
        return [start]
    queue: deque = deque([[start]])
    visited: Set[str] = {start}
    while queue:
        path = queue.popleft()
        node = path[-1]
        if len(path) > max_hops + 1:
            continue
        for neighbor in import_graph.get(node, []):
            if neighbor in visited:
                continue
            new_path = path + [neighbor]
            if neighbor == end:
                return new_path
            visited.add(neighbor)
            queue.append(new_path)
    return None


def _pii_on_path(path: List[str], pii_fields_list: List[Dict]) -> List[str]:
    """Return list of PII field names (pattern_matched) from files on the path."""
    path_set = set(path)
    seen: Set[str] = set()
    out: List[str] = []
    for p in pii_fields_list:
        if p.get("file") not in path_set:
            continue
        pat = p.get("pattern_matched") or p.get("line_content", "")
        if pat and pat not in seen:
            seen.add(pat)
            out.append(pat if isinstance(pat, str) and len(pat) < 40 else "pii_field")
    return out[:10]


def _build_pii_flow_graph(
    extracted: Dict,
    file_contents: Dict[str, str],
) -> Dict:
    """
    Build a directed graph of PII flow through the codebase.
    Nodes: files. Edges: file A imports file B (data can flow A → B).
    Uses import graph + PII/third-party signals for heuristic flow mapping.
    """
    import_graph = extracted.get("import_graph", {})
    pii_fields = extracted.get("pii_fields", []) or []
    third_party = extracted.get("third_party_imports", []) or []
    user_facing = set(extracted.get("user_facing_route_files", []) or [])

    pii_files = {p["file"] for p in pii_fields if p.get("file")}
    files_with_collection = {p["file"] for p in pii_fields if p.get("direction") == "collection"}
    sources = {
        f for f in pii_files
        if f in user_facing or f in files_with_collection
    }

    sinks: Dict[str, str] = {}
    for imp in third_party:
        file_path = imp.get("file", "")
        lib = imp.get("library", "")
        if not file_path or not lib:
            continue
        sink_type = _classify_sink(lib)
        if sink_type:
            sinks[file_path] = sink_type

    for path, content in file_contents.items():
        if path not in sinks and _has_logging_sink(content):
            sinks[path] = "logging"

    flow_paths: List[Dict] = []
    for source in list(sources)[:30]:
        for sink_file, sink_type in sinks.items():
            path = _find_path(source, sink_file, import_graph, max_hops=5)
            if path:
                flow_paths.append({
                    "source": source,
                    "sink": sink_file,
                    "sink_type": sink_type,
                    "path": path,
                    "hop_count": len(path) - 1,
                    "pii_fields": _pii_on_path(path, pii_fields),
                })

    return {
        "sources": list(sources),
        "sinks": sinks,
        "flow_paths": flow_paths,
    }


PII_PATTERNS: List[str] = [
    "email",
    "phone",
    "mobile",
    "aadhaar",
    "aadhar",
    "pan_number",
    "pancard",
    "dob",
    "date_of_birth",
    "full_name",
    "firstname",
    "lastname",
    "address",
    "pincode",
    "zipcode",
    "passport",
    "voter_id",
    "gender",
    "password",
    "credit_card",
    "bank_account",
    "ifsc",
    # Java/Kotlin style (camelCase)
    r"(?i)\b(emailAddress|phoneNumber|mobileNumber|dateOfBirth|fullName|firstName|lastName)\b",
    r"(?i)\b(panNumber|aadhaarNumber|passportNumber|bankAccount|creditCard)\b",
    r"(?i)\b(userEmail|userPhone|userAddress|userPassword|hashedPassword)\b",
    # Go style (PascalCase exported fields)
    r"(?i)\b(Email|Phone|Mobile|Password|FullName|DateOfBirth|Aadhaar)\b\s*(?:string|int)",
    # Ruby style (symbols and instance vars)
    r"(?i)(?::email|:phone|:password|:full_name|:date_of_birth|@email|@phone|@password)",
    # PHP style ($variables)
    r"(?i)\$(?:email|phone|password|full_name|date_of_birth|aadhaar|pan_number)\b",
    # C# style (properties)
    r"(?i)public\s+\w+\s+(?:Email|Phone|Password|FullName|DateOfBirth|PhoneNumber)\s*\{",
    # Kotlin data class fields
    r"(?i)val\s+(?:email|phone|password|fullName|dateOfBirth|aadhaar)\s*:",
    r"(?i)var\s+(?:email|phone|password|fullName|dateOfBirth|aadhaar)\s*:",
]

THIRD_PARTY_LIBRARIES: List[str] = [
    "mixpanel",
    "segment",
    "firebase",
    "amplitude",
    "clevertap",
    "freshworks",
    "intercom",
    "hubspot",
    "sentry",
    "datadog",
    "hotjar",
    "fullstory",
    "heap",
    "posthog",
    "rudderstack",
    "moengage",
    "webengage",
    "branch",
    "appsflyer",
    "adjust",
    # Java/Kotlin SDK imports
    "com.mixpanel",
    "com.segment",
    "com.amplitude",
    "io.sentry",
    "com.google.firebase",
    "com.clevertap",
    "com.freshworks",
    "io.intercom",
    "com.hubspot",
    # Go packages
    "gopkg.in/segmentio",
    "github.com/getsentry",
    "github.com/mixpanel-go",
    # PHP Composer
    "segmentio/analytics-php",
    "sentry/sentry",
    "firebase/php-jwt",
    # Ruby gems
    "mixpanel-ruby",
    "analytics-ruby",
    "sentry-ruby",
    # C# NuGet
    "Segment.Analytics",
    "Sentry.AspNetCore",
    "FirebaseAdmin",
    # Additional analytics / tracking / support
    "logrocket",
    "crisp",
    "zendesk",
    "drift",
    "livechat",
    "tawk",
    "clarity",
    "matomo",
    "plausible",
    "fathom",
    "supabase",  # can be storage + auth; often PII
    "@supabase/supabase-js",
    "supabase-js",
]

# Context-aware consent patterns — code context only (assignments, calls, schema fields), not comments/i18n
CONSENT_CODE_PATTERNS: List[str] = [
    r"consent_given\s*[=:]",
    r"consent_timestamp\s*[=:]",
    r"is_agreed\s*[=:]",
    r"opted_in\s*[=:]",
    r"terms_accepted\s*[=:]",
    r"privacy_accepted\s*[=:]",
    r"record_consent\s*\(",
    r"log_consent\s*\(",
    r"save_consent\s*\(",
    r"grant_consent\s*\(",
    r"require_consent\s*\(",
    r"check_consent\s*\(",
    r"verify_consent\s*\(",
    r"ConsentService\s*\.",
    r"ConsentRepository\s*\.",
    r"[\'\"](?:consent_given|consent_timestamp|terms_accepted)[\'\"]",
    r":consent_given",
    r"consent_given:",
    r"consentGiven\s*[=:]",
    # Common app-specific consent field variants
    r"acceptedTerms\s*[=:]",
    r"termsAccepted\s*[=:]",
    r"policyAccepted\s*[=:]",
    r"privacyPolicyAccepted\s*[=:]",
    r"userConsent\s*[=:]",
    r"marketingOptIn\s*[=:]",
    r"newsletterOptIn\s*[=:]",
    r"trackingOptIn\s*[=:]",
    r"(?:optIn|optedIn)\s*[=:]",
    r"dpdp_consent",
    r"gdpr_consent",
    r"data_processing_agreement",
    r"@consent_required",
    r"@ConsentRequired",
    r"\[RequireConsent\]",
    r"ConsentMiddleware",
    r"ConsentFilter",
    r"ConsentInterceptor",
]

# Literal terms for deletion (matched with word-boundary where possible)
DELETION_TERMS: List[str] = [
    "delete_account",
    "delete_user",
    "deactivate_account",
    "right_to_erasure",
    "purge_user",
    "anonymize",
    "soft_delete",
    "hard_delete",
    "gdpr_delete",
    "account_deletion",
    "remove_user_data",
    "erase_user",
    "erase_account",
    "cancel_account",
    "close_account",
    "destroy_user",
    "destroy_account",
    "remove_account",
    "user_erasure",
    "data_erasure",
    # Java/Kotlin
    "deleteUser",
    "deleteAccount",
    "softDelete",
    "anonymizeUser",
    "UserDeletionService",
    "destroyUser",
    "removeUser",
    "eraseUser",
    # Go
    "DeleteUser",
    "DeleteAccount",
    "SoftDelete",
    "AnonymizeUser",
    "DestroyUser",
    "RemoveUser",
    # Ruby
    "destroy_account",
    "delete_account",
    "before_destroy",
    "erase_user_data",
    # PHP
    "deleteAccount",
    "destroyUser",
    "softDelete",
    "forceDelete",
    "eraseUser",
    # C#
    "DeleteAccount",
    "SoftDelete",
    "AnonymizeData",
    "EraseUser",
    "RemoveUser",
    # Rust
    "delete_account",
    "delete_user",
    "soft_delete",
    "erase_user",
    # Python/Django
    "delete_user",
    "erase_user",
    "anonymize_user",
    "purge_user_data",
    "User.objects.filter(...).delete",
    "Model.delete(",
    ".delete()",
    "destroy(",
    "force_delete",
    "hard_delete",
]

# Regex patterns for deletion (stronger: route names, method names, API path segments)
DELETION_REGEX_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(delete|destroy|erase|purge|remove|anonymize)\s*[\(\s]*(user|account|data|profile)\b", re.IGNORECASE),
    re.compile(r"\b(user|account|data)[_\.]*(delete|destroy|erase|remove)\b", re.IGNORECASE),
    re.compile(r"\.(delete|destroy|erase)\s*\(", re.IGNORECASE),
    re.compile(r"right_to_erasure", re.IGNORECASE),
    re.compile(r"@(delete|destroy)\s*\(|DeleteMapping|DestroyAction", re.IGNORECASE),
    re.compile(r"\/delete\/|\/destroy\/|\/erase\/|\/account\/delete|\/user\/delete|\/me\/delete", re.IGNORECASE),
]

RETENTION_SIGNAL_PATTERNS: List[str] = [
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
    # Java/Kotlin
    "retentionPeriod",
    "expiresAt",
    "deletedAt",
    "softDelete",
    "@PreRemove",
    "CascadeType.REMOVE",
    "orphanRemoval",
    "@Temporal",
    "TemporalType.TIMESTAMP",
    # Go
    "ExpiresAt",
    "DeletedAt",
    "RetentionPeriod",
    "gorm.DeletedAt",
    "gorm.Model",
    # Ruby
    "acts_as_paranoid",
    "discard_at",
    "discarded_at",
    # PHP / Laravel
    "SoftDeletes",
    "retention_expires_at",
    "Prunable",
    "MassPrunable",
    "deleted_at",
    # C#
    "IsDeleted",
    "DeletedAt",
    "ExpiresAt",
    "SoftDelete",
    # Rust
    "retention_expires_at",
    # Django
    "SoftDeleteModel",
    "deleted_at",
    "expires_at",
    # Prisma / TypeORM
    "deletedAt",
    "expiresAt",
    "@DeleteDateColumn",
    # Supabase / Postgres
    "retention",
    "expire_at",
]
RETENTION_REGEX_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(expires_at|expired_at|valid_until|retention_period|deleted_at)\b", re.IGNORECASE),
    re.compile(r"\b(expiresAt|deletedAt|retentionPeriod|validUntil)\b"),
    re.compile(r"SoftDeletes?|soft_delete|softDelete", re.IGNORECASE),
    re.compile(r"ttl\s*[=:]|max_age\s*[=:]|retention\s*[=:]", re.IGNORECASE),
    re.compile(r"@(Column|Field).*deleted|deleted_at|expires_at", re.IGNORECASE),
]


# Test/mock/fixture exclusion — applied at start of extract() so no rule sees these files
SKIP_TEST_DIRS = [
    "__tests__",
    "test_",
    "e2e",
    "cypress",
    "playwright",
    "storybook",
    ".storybook",
    "stories",
    "__mocks__",
    "mocks",
    "fixtures",
    "factories",
    "seeds",
    "seed",
    "fakes",
]
SKIP_TEST_FILE_PATTERNS = [
    re.compile(r"\.test\.(ts|tsx|js|jsx|py|java|go|rb|cs|kt|rs)$", re.IGNORECASE),
    re.compile(r"\.spec\.(ts|tsx|js|jsx|py|java|go|rb|cs|kt|rs)$", re.IGNORECASE),
    re.compile(r"_test\.(go|py|rb|java|kt|rs)$", re.IGNORECASE),
    re.compile(r"Test\.(java|kt|cs)$", re.IGNORECASE),
    re.compile(r"Tests\.(cs|java|kt)$", re.IGNORECASE),
    re.compile(r"Spec\.(rb|java|kt)$", re.IGNORECASE),
    re.compile(r"_spec\.rb$", re.IGNORECASE),
    re.compile(r"test_.*\.py$", re.IGNORECASE),
    re.compile(r"conftest\.py$", re.IGNORECASE),
    re.compile(r"jest\.config\.", re.IGNORECASE),
    re.compile(r"jest\.setup\.", re.IGNORECASE),
    re.compile(r"vitest\.config\.", re.IGNORECASE),
    re.compile(r"cypress\.config\.", re.IGNORECASE),
    re.compile(r"playwright\.config\.", re.IGNORECASE),
    re.compile(r"mock.*\.(ts|tsx|js|jsx|py)$", re.IGNORECASE),
    re.compile(r"Mock\.(java|kt|cs)$", re.IGNORECASE),
    re.compile(r"fixture.*\.(ts|js|py|rb)$", re.IGNORECASE),
    re.compile(r"factory.*\.(ts|js|py|rb)$", re.IGNORECASE),
    re.compile(r"seed.*\.(ts|js|py|rb|sql)$", re.IGNORECASE),
    re.compile(r"fake.*\.(ts|js|py)$", re.IGNORECASE),
    re.compile(r"stub.*\.(ts|js|py)$", re.IGNORECASE),
]

# General directory/file exclusions (build, tooling, docs — not app source)
SKIP_DIRS = [
    "sandbox",
    "scripts",
    "script",
    "ci",
    ".github",
    "benchmark",
    "benchmarks",
    "examples",
    "example",
    "demo",
    "docs",
    "doc",
    "dist",
    "build",
    "out",
    "coverage",
    ".turbo",
    ".nx",
    ".changeset",
    "storybook",
    ".storybook",
]
SKIP_FILE_PATTERNS = [
    re.compile(r"publish\.(ts|js)$", re.IGNORECASE),
    re.compile(r"release\.(ts|js)$", re.IGNORECASE),
    re.compile(r"deploy\.(ts|js)$", re.IGNORECASE),
    re.compile(r"jsdoc\.(ts|js)$", re.IGNORECASE),
    re.compile(r"rollup\.config\.", re.IGNORECASE),
    re.compile(r"tsup\.config\.", re.IGNORECASE),
    re.compile(r"vite\.config\.", re.IGNORECASE),
    re.compile(r"webpack\.config\.", re.IGNORECASE),
    re.compile(r"\.d\.ts$", re.IGNORECASE),
    re.compile(r"CHANGELOG", re.IGNORECASE),
    re.compile(r"turbo\.json$", re.IGNORECASE),
    re.compile(r"\.npmignore$", re.IGNORECASE),
    re.compile(r"tsconfig\.build\.json$", re.IGNORECASE),
    re.compile(r"workbox-[a-f0-9]+\.js$", re.IGNORECASE),
    re.compile(r"workbox-.*\.js$", re.IGNORECASE),
    re.compile(r"sw\.js$", re.IGNORECASE),
    re.compile(r"service-worker\.js$", re.IGNORECASE),
]
TEST_PATH_INDICATORS = [
    "/__tests__/",
    "/test/",
    "/tests/",
    "/spec/",
    "/cypress/",
    "/playwright/",
    "/e2e/",
    "/fixtures/",
    "/factories/",
    "/seeds/",
    "/mocks/",
    "/__mocks__/",
    "/storybook/",
    "/.storybook/",
]


def _is_test_or_mock_file(filepath: str) -> bool:
    """Return True if file should be excluded from extraction (test/mock/fixture)."""
    filename = os.path.basename(filepath)
    if any(p.search(filename) for p in SKIP_TEST_FILE_PATTERNS):
        return True
    path_lower = filepath.replace("\\", "/").lower()
    if any(ind in path_lower for ind in TEST_PATH_INDICATORS):
        return True
    for skip_dir in SKIP_TEST_DIRS:
        if f"/{skip_dir}/" in path_lower or path_lower.startswith(skip_dir + "/"):
            return True
    return False


def _is_skip_path(filepath: str) -> bool:
    """Return True if file is in SKIP_DIRS or matches SKIP_FILE_PATTERNS (tooling/docs/build)."""
    path_lower = filepath.replace("\\", "/").lower()
    for skip_dir in SKIP_DIRS:
        if f"/{skip_dir}/" in path_lower or path_lower.startswith(skip_dir + "/"):
            return True
    filename = os.path.basename(filepath)
    if any(p.search(filename) for p in SKIP_FILE_PATTERNS):
        return True
    return False


FRAMEWORK_LIBRARY_SIGNALS = [
    re.compile(r'"peerDependencies"'),
    re.compile(r'"publishConfig"'),
    re.compile(r"rollup\.config\."),
    re.compile(r"tsup\.config\."),
    re.compile(r"tsconfig\.build\.json"),
    re.compile(r"\.npmignore"),
    re.compile(r"packages/core/src/"),
    re.compile(r"packages/adapter"),
    re.compile(r"packages/frameworks-"),
    re.compile(r"packages/client/"),
]


# Strong negative signals — if present, repo is an application, not a library
# Note: Do not list requirements.txt here; published Python libraries commonly ship it for dev/ci.
APP_DISQUALIFIERS = [
    re.compile(r"(^|/)manage\.py$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"(^|/)wsgi\.py$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"(^|/)asgi\.py$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"(^|/)settings\.py$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"docker-compose", re.IGNORECASE),
    re.compile(r"(^|/)Dockerfile$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"apps/api/", re.IGNORECASE),
    re.compile(r"apps/web/", re.IGNORECASE),
    re.compile(r"(^|/)\.env\.example$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"/migrations/", re.IGNORECASE),
    re.compile(r"celery", re.IGNORECASE),
]


def _detect_framework_library(
    repo_files: List[str],
    file_contents: Dict[str, str],
) -> bool:
    """
    Returns True if this repo is a reusable framework/library
    rather than a deployable application.
    Libraries provide tools — they don't implement app-level
    consent, deletion, or data access controls themselves.
    Apps (e.g. Plane: Django + Next.js monorepo) are disqualified first.
    """
    all_paths = "\n".join(p.replace("\\", "/") for p in repo_files)
    norm_paths = [p.replace("\\", "/") for p in repo_files]
    basenames = {os.path.basename(p) for p in norm_paths}

    # If ANY app disqualifier is present, it's an app — return False immediately
    for pattern in APP_DISQUALIFIERS:
        if pattern.search(all_paths):
            return False

    signals = 0
    # Python packaging / src layout — typical of published libraries (Flask, Werkzeug, etc.)
    if "pyproject.toml" in basenames:
        signals += 2
    if "setup.py" in basenames or "setup.cfg" in basenames:
        signals += 1
    if any((p.startswith("src/") or "/src/" in p) and p.endswith(".py") for p in norm_paths):
        signals += 1

    for pattern in FRAMEWORK_LIBRARY_SIGNALS:
        if pattern.search(all_paths):
            signals += 1

    # package.json signals
    pkg = file_contents.get("package.json", "")
    if '"peerDependencies"' in pkg:
        signals += 2
    if '"private": false' in pkg or '"publishConfig"' in pkg:
        signals += 1

    # Monorepo with many packages/*/src/ paths = library (only if not already disqualified)
    pkg_src_count = sum(
        1 for p in repo_files
        if re.match(r"^packages/[^/]+/src/", p.replace("\\", "/"))
    )
    if pkg_src_count > 10:
        signals += 3

    return signals >= 3


# Path substrings that indicate i18n/vendored noise — skip for signals and certain rules
NOISE_PATH_SUBSTRINGS = (
    ".yarn/",
    "/lang/",
    "/locales/",
    "/locale/",
    "/i18n/",
    "/translations/",
)


def is_noise_path(path: str) -> bool:
    """
    True if path is likely i18n, vendored, or other non-app source (reduces false positives).
    Shared by extractor (signals) and rules (children's data, security).
    """
    p = path.replace("\\", "/").lower()
    if any(sub in p for sub in NOISE_PATH_SUBSTRINGS):
        return True
    # i18n validation files (e.g. lang/en/validation.php) — strings only, not app logic
    if "validation.php" in p and "/lang" in p:
        return True
    return False


def _extract_consent_signals(repo_files: List[Dict]) -> List[Dict]:
    """Extract consent signals using code-context patterns only; skip comments and noise paths."""
    results: List[Dict] = []
    for f in repo_files:
        path = f.get("path", "")
        if is_noise_path(path):
            continue
        content = f.get("content") or ""
        for i, line in enumerate(content.splitlines(), 1):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            if line_stripped.startswith(("#", "//", "*", "/*", "<!--", "--")):
                continue
            for pattern in CONSENT_CODE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append({
                        "file": path,
                        "line_number": i,
                        "line_content": line_stripped[:120],
                        "pattern_matched": pattern,
                    })
                    break
    return results


def _extract_middleware_consent(repo_files: List[Dict]) -> List[Dict]:
    """
    Detect consent/auth enforcement patterns at middleware or DI layer.
    Returns list of {file, line_number, pattern, framework} dicts.
    """
    MIDDLEWARE_PATTERNS = [
        (
            r"Depends\s*\(\s*[\w.]*(?:get_current|active_user|verify_token"
            r"|require_auth|authenticated|current_user)[\w.]*\s*\)",
            "fastapi_depends",
        ),
        (r"@login_required", "django_login_required"),
        (r"@permission_required", "django_permission_required"),
        (r"LoginRequiredMixin", "django_mixin"),
        (r"IsAuthenticated", "django_drf_permission"),
        (r"@login_required", "flask_login_required"),
        (r"@jwt_required", "flask_jwt_required"),
        (r"current_user", "flask_login_user"),
        (
            r"(?:app|router)\.use\s*\(\s*[\w.]*(?:auth|verify|authenticate"
            r"|requireAuth|ensureAuth|isAuthenticated)[\w.]*",
            "express_middleware",
        ),
        (
            r"(?:authenticate|verifyToken|requireAuth|ensureLoggedIn)\s*,",
            "express_middleware_inline",
        ),
        (r"@PreAuthorize", "spring_preauthorize"),
        (r"@Secured", "spring_secured"),
        (r"SecurityFilterChain", "spring_security_filter"),
        (r"antMatchers|requestMatchers", "spring_security_config"),
        (r"\.authenticated\(\)", "spring_authenticated"),
        (
            r"(?:AuthMiddleware|JWTMiddleware|RequireAuth|AuthRequired)\s*[\(\{]",
            "go_middleware",
        ),
        (
            r"c\.Set\s*\(\s*[\"'](?:user|current_user|claims)[\"']",
            "gin_context_user",
        ),
        (r"before_action\s+:authenticate_user", "devise_authenticate"),
        (r"before_action\s+:require_login", "clearance_require_login"),
        (r"before_filter\s+:authenticate", "rails_before_filter"),
        (r"->middleware\s*\(\s*['\"]auth['\"]", "laravel_auth_middleware"),
        (r"middleware\s*\(\s*['\"]auth", "laravel_auth_middleware_2"),
        (r"auth\s*:\s*true", "laravel_sanctum"),
        (r"\[Authorize\]", "aspnet_authorize"),
        (r"\[Authorize\s*\(", "aspnet_authorize_policy"),
        (r"RequireAuthorization", "aspnet_minimal_auth"),
        (r"from_request|FromRequest", "rust_extractor"),
        (
            r"layer\s*\(\s*(?:AuthLayer|JwtLayer|RequireAuth)",
            "rust_middleware",
        ),
        (
            r"consent_log|consent_audit|ConsentRecord|consent_given\s*=\s*True",
            "consent_storage",
        ),
        (
            r"INSERT.*consent|consent.*INSERT|save.*consent|consent.*save",
            "consent_db_write",
        ),
    ]
    results: List[Dict] = []
    for f in repo_files:
        content = f.get("content") or ""
        path = f.get("path", "")
        for pattern, framework in MIDDLEWARE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                results.append({
                    "file": path,
                    "line_number": line_num,
                    "pattern": match.group(0)[:80],
                    "framework": framework,
                })
                break
    return results


def get_file_content(extracted: Dict, filepath: str) -> str:
    """Retrieve raw file content by path from extracted data."""
    return extracted.get("_file_contents", {}).get(filepath, "")


def _extract_route_from_args(arg_text: str) -> str:
    """Try to extract the first string literal route from a function/decorator argument list."""
    if not arg_text:
        return "UNKNOWN"

    match = re.search(r'["\\\']([^"\\\']+)["\\\']', arg_text)
    if match:
        return match.group(1)
    return "UNKNOWN"


def _classify_route_intent(file_path: str, content: str) -> str:
    """
    Classify whether a route file is user-facing (collects PII from users)
    or internal (reads/displays existing data for admins/staff)
    or crm_entry (user enters data about third-party contacts — different legal framework).

    Returns:
      'user_facing'  — signup, login, profile, onboarding, checkout
      'internal'     — dashboard, admin, audit, reporting, staff views
      'crm_entry'    — CRM/contact management; user is data fiduciary entering data about others
      'unknown'      — cannot determine

    Used by consent.py to skip CONSENT_MISSING on internal and crm_entry routes.
    """
    path_lower = file_path.replace("\\", "/").lower()
    path_and_content = file_path + "\n" + (content[:2000] if content else "")

    # ── CRM / third-party data entry ────────────────────────────────
    CRM_DATA_ENTRY_PATTERNS = [
        r"/contact(s)?/",
        r"/person(s)?/",
        r"/people/",
        r"/relationship(s)?/",
        r"/address(es)?/",
        r"ContactController",
        r"PersonController",
        r"ManageContact",
        r"ManageRelationship",
        r"ManageAddress",
        r"ManageGender",
        r"PersonalizeAddress",
        r"PersonalizeContact",
        r"ManageSettings",
        r"SettingsController",
        r"StoreContact",
        r"UpdateContact",
        r"StoreRelationship",
        r"UpdateRelationship",
    ]
    CRM_APP_SIGNALS = [
        r"contact_id\b",
        r"ContactId\b",
        r"person_id\b",
        r"PersonId\b",
        r"linked_to\b",
        r"related_to\b",
        r"relationship_type\b",
        r"contact.*birthday",
        r"contact.*phone",
    ]
    crm_signals = sum(
        1 for p in CRM_DATA_ENTRY_PATTERNS
        if re.search(p, path_and_content, re.IGNORECASE)
    ) + sum(
        1 for p in CRM_APP_SIGNALS
        if re.search(p, path_and_content, re.IGNORECASE)
    )
    if crm_signals >= 2:
        return "crm_entry"

    # ── Internal path signals ──────────────────────────────────────
    INTERNAL_PATH_SEGMENTS = [
        "/dashboard/", "/admin/", "/audit/", "/audits/",
        "/compliance/", "/reporting/", "/reports/", "/internal/",
        "/staff/", "/backoffice/", "/back-office/", "/ops/",
        "/management/", "/panel/", "/control/", "/monitor/",
        "/analytics/", "/metrics/", "/logs/", "/events/",
        "/_components/", "/_internal/", "/_admin/",
    ]

    # ── User-facing path signals ───────────────────────────────────
    USER_FACING_PATH_SEGMENTS = [
        "/signup", "/register", "/onboard", "/checkout",
        "/profile", "/account", "/settings", "/preferences",
        "/login", "/auth/", "/verify", "/consent",
        "/submit", "/apply", "/enroll", "/join",
    ]

    # ── Internal code patterns ─────────────────────────────────────
    INTERNAL_CODE_PATTERNS = [
        r"\.select\s*\(",
        r"\.from\s*\([\"'](?:audit|log)",
        r"supabase\.from\s*\(",
        r"\.find(?:Many|All|One)\s*\(",
        r"fetch(?:User|Data|Record|Email)",
        r"getAll|getList|getLogs|getAudit",
        r"ListingPage|ListView|AdminView",
        r"DataTable|AdminTable|AuditTable",
        r"totalCount|totalData|pageLimit",
        r"searchParamsCache",
    ]

    # ── User-facing code patterns ──────────────────────────────────
    USER_FACING_CODE_PATTERNS = [
        r"req(?:uest)?\.body\.",
        r"request\.form\b",
        r"request\.data\b",
        r"body\[\s*[\"']\w+[\"']\s*\]",
        r"formData\.get\s*\(",
        r"<(?:input|form|textarea)",
        r"useState.*(?:email|phone|name)",
        r"\.post\s*\(",
        r"INSERT\s+INTO",
        r"\.create\s*\(",
        r"\.save\s*\(",
        r"new\s+User\s*\(",
    ]

    path_score = 0
    content_score = 0

    for seg in INTERNAL_PATH_SEGMENTS:
        if seg in path_lower:
            path_score += 2
    for seg in USER_FACING_PATH_SEGMENTS:
        if seg in path_lower:
            path_score -= 2

    for pattern in INTERNAL_CODE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            content_score += 1
    for pattern in USER_FACING_CODE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            content_score -= 1

    total = path_score + content_score

    if total >= 3:
        return "internal"
    elif total <= -2:
        return "user_facing"
    else:
        return "unknown"


def _detect_pii_direction(line: str, file_path: str) -> str:
    """
    Determine whether a PII field reference is:
      'collection' — actively receiving PII from a user (high risk)
      'display'    — reading/showing existing PII (lower risk)
      'query'      — filtering/searching on PII (medium risk)
      'schema'     — field definition in model/schema (context depends)
      'unknown'    — cannot determine

    Called per-line during PII extraction.
    """
    line_stripped = line.strip()

    COLLECTION_DIRECTION_PATTERNS_EXTRA = [
        r"request\.form\[",
        r"request\.form\.get\s*\(",
        r"request\.json\[",
        r"request\.json\.get\s*\(",
        r"request\.data\b",
        r"request\.get_json\s*\(",
        r"request\.args\[",
        r"request\.args\.get\s*\(",
        r"request\.files\[",
        r"request\.files\.get\s*\(",
        r"input\s*\(",
        r"getpass\s*\(",
        r"supabase\.auth\.sign_up\s*\(",
        r"supabase\.auth\.signUp\s*\(",
        r"POST.*email",
        r"POST.*password",
        r"form\[.*(email|password|name|phone)",
    ]

    COLLECTION_PATTERNS = [
        r"req(?:uest)?\.body\.",
        r"request\.form\[",
        r"request\.data\[",
        r"request\.POST\[",
        r"formData\.get\s*\(",
        r"req\.body\[",
        r"ctx\.body\.",
        r"@RequestBody",
        r"@FormParam",
        r"BindingResult",
        r"input\s+type=[\"'](?:text|email|tel|password)",
        r"useState\s*\(\s*[\"']\s*[\"']",
        r"onChange.*set[A-Z]",
        r"INSERT\s+INTO\s+.*VALUES",
        r"\.create\s*\(\s*\{",
        r"\.save\s*\(\s*\)",
        r"\.insert\s*\(\s*\{",
    ]
    COLLECTION_PATTERNS.extend(COLLECTION_DIRECTION_PATTERNS_EXTRA)

    DISPLAY_PATTERNS = [
        r"\?\.",
        r"\|\|\s*[\"'][^\"']*[\"']",
        r"\.map\s*\(",
        r"\.filter\s*\(",
        r"console\.\w+\s*\(",
        r"<[A-Z]\w+.*email",
        r"return\s+.*email",
        r"\.select\s*\(",
        r"\.findOne\s*\(",
        r"\.findMany\s*\(",
        r"supabase\.from\s*\(",
        r"\.eq\s*\(",
        r"json\s*\(",
        r"res\.json\s*\(",
        r"render\s*\(",
    ]

    QUERY_PATTERNS = [
        r"\.ilike\s*\(",
        r"\.like\s*\(",
        r"\.where\s*\(",
        r"filter(?:By|On)?\s*\(",
        r"search(?:Params|Query)?\s*",
        r"query\s*=",
        r"LIKE\s+[\"']%",
    ]

    SCHEMA_PATTERNS = [
        r"Column\s*\(",
        r"mapped_column\s*\(",
        r"models\.\w+Field\s*\(",
        r"DataTypes\.",
        r"@Column\b",
        r'gorm:"',
        r'db:"',
        r'json:"',
        r":\s+(?:String|Integer|Float|Boolean|Date)\s*[,\n]",
        r"val\s+\w+\s*:\s*String\b",
        r"\$fillable\s*=",
        r"protected\s+\$\w+\s*=\s*\[",
    ]

    for pattern in COLLECTION_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return "collection"

    for pattern in SCHEMA_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return "schema"

    for pattern in QUERY_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return "query"

    for pattern in DISPLAY_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return "display"

    return "unknown"


def extract(repo_files: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Extract relevant information from repository files.

    :param repo_files: Collection of repository files from the ingestor.
    :return: Extracted data suitable for rule evaluation.
    """
    # Extract skipped-files metadata if present from ingestor
    _ingest_skipped = []
    _real_files = []
    for f in repo_files:
        if "_skipped_files" in f:
            _ingest_skipped = f["_skipped_files"]
        else:
            _real_files.append(f)
    repo_files = _real_files

    # Exclude test/mock/fixture and tooling/docs/build files so no rule ever sees them
    _original_count = len(repo_files)
    repo_files = [
        f for f in repo_files
        if not _is_test_or_mock_file(f.get("path", ""))
        and not _is_skip_path(f.get("path", ""))
    ]
    test_excluded_count = _original_count - len(repo_files)

    pii_fields: List[Dict] = []
    api_endpoints: List[Dict] = []
    third_party_imports: List[Dict] = []
    consent_signals: List[Dict] = _extract_consent_signals(repo_files)
    deletion_signals: List[Dict] = []
    retention_signals: List[Dict] = []

    # Track per-file, per-PII-pattern counts to limit noise
    pii_limits: Dict[str, Dict[str, int]] = {}

    for file_info in repo_files:
        path = file_info.get("path", "<unknown>")
        content = file_info.get("content", "") or ""
        skip_signals = is_noise_path(path)

        try:
            # Ensure per-file structure exists for PII limits
            if path not in pii_limits:
                pii_limits[path] = {pattern: 0 for pattern in PII_PATTERNS}

            for line_number, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()

                # 1. PII fields (skip comment lines to reduce false positives)
                _is_comment = stripped.startswith(("#", "//", "*", "/*", "<!--", "--", "'''", '"""'))
                if not _is_comment:
                    for pattern in PII_PATTERNS:
                        if pii_limits[path][pattern] >= 3:
                            continue
                        if re.search(pattern, line, flags=re.IGNORECASE):
                            direction = _detect_pii_direction(line, path)
                            pii_fields.append(
                                {
                                    "file": path,
                                    "line_number": line_number,
                                    "line_content": stripped[:200],
                                    "pattern_matched": pattern,
                                    "direction": direction,
                                }
                            )
                            pii_limits[path][pattern] += 1

                # 2. API endpoints — new patterns first (Express, Django REST, FastAPI), then existing
                endpoint_added = False

                # Express: router.(get|post|put|patch|delete|all)( 'route' )
                m = re.search(
                    r'router\.(get|post|put|patch|delete|all)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    line,
                )
                if m:
                    api_endpoints.append(
                        {
                            "file": path,
                            "line_number": line_number,
                            "method": m.group(1).upper(),
                            "route": m.group(2),
                        }
                    )
                    endpoint_added = True
                if not endpoint_added:
                    m = re.search(
                        r'app\.(get|post|put|patch|delete|all)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": m.group(1).upper(),
                                "route": m.group(2),
                            }
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(r'Route\s*\(\s*[\'"]([^\'"]+)[\'"]', line)
                    if m:
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": "UNKNOWN",
                                "route": m.group(1),
                            }
                        )
                        endpoint_added = True
                if not endpoint_added:
                    if re.search(r'@action\s*\(', line):
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": "UNKNOWN",
                                "route": "UNKNOWN",
                            }
                        )
                        endpoint_added = True
                if not endpoint_added:
                    if re.search(r'class\s+\w+ViewSet', line):
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": "UNKNOWN",
                                "route": "UNKNOWN",
                            }
                        )
                        endpoint_added = True
                if not endpoint_added:
                    if re.search(r'class\s+\w+APIView', line):
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": "UNKNOWN",
                                "route": "UNKNOWN",
                            }
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(
                        r'@router\.(get|post|put|patch|delete)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": m.group(1).upper(),
                                "route": m.group(2),
                            }
                        )
                        endpoint_added = True

                # Flask/FastAPI style decorators: @app.route, @router.get, @router.post, @app.get, @app.post, @bp.route
                if not endpoint_added:
                    flask_fastapi_match = re.search(
                        r"@(app|router|bp)\.(route|get|post)\((?P<args>[^)]*)\)",
                        line,
                    )
                    if flask_fastapi_match:
                        method = flask_fastapi_match.group(2).upper()
                        route = _extract_route_from_args(flask_fastapi_match.group("args"))
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": method or "UNKNOWN",
                                "route": route,
                            }
                        )
                        endpoint_added = True

                # Django urls.py: path(, re_path(, url(
                if not endpoint_added:
                    django_match = re.search(
                        r"\b(path|re_path|url)\s*\((?P<args>[^)]*)\)", line
                    )
                    if django_match:
                        route = _extract_route_from_args(django_match.group("args"))
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": "UNKNOWN",
                                "route": route,
                            }
                        )
                        endpoint_added = True

                # Express (JS/TS) fallback: app.get(, app.post(, router.get(, router.post( with args
                if not endpoint_added:
                    express_match = re.search(
                        r"\b(app|router)\.(get|post)\s*\((?P<args>[^)]*)\)",
                        line,
                        flags=re.IGNORECASE,
                    )
                    if express_match:
                        method = express_match.group(2).upper()
                        route = _extract_route_from_args(express_match.group("args"))
                        api_endpoints.append(
                            {
                                "file": path,
                                "line_number": line_number,
                                "method": method or "UNKNOWN",
                                "route": route,
                            }
                        )
                        endpoint_added = True

                # Java Spring Boot
                if not endpoint_added:
                    m = re.search(
                        r"@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)"
                        r"\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        method = m.group(1).replace("Mapping", "").upper()
                        if method == "REQUEST":
                            method = "UNKNOWN"
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": method, "route": m.group(2)}
                        )
                        endpoint_added = True

                # Go Gin
                if not endpoint_added:
                    m = re.search(
                        r"(?:r|router|engine|group)\."
                        r"(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(
                        r"\w+\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # Go Echo
                if not endpoint_added:
                    m = re.search(
                        r"(?:e|echo|server)\."
                        r"(GET|POST|PUT|PATCH|DELETE)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # Go Fiber
                if not endpoint_added:
                    m = re.search(
                        r"(?:app|fiber)\."
                        r"(Get|Post|Put|Patch|Delete)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # Go Chi
                if not endpoint_added:
                    m = re.search(r"r\.(Get|Post|Put|Patch|Delete)\s*\(\s*[\"']([^\"']+)[\"']", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # Ruby Rails
                if not endpoint_added:
                    m = re.search(
                        r"(?:get|post|put|patch|delete|resources|resource)\s+[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True

                # Ruby Sinatra
                if not endpoint_added:
                    m = re.search(r"(?:get|post|put|patch|delete)\s+[\"']([^\"']+)[\"'\s]+do", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True

                # PHP Laravel
                if not endpoint_added:
                    m = re.search(
                        r"Route::(get|post|put|patch|delete|any)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                        re.IGNORECASE,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(
                        r"\$router->(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # PHP Symfony
                if not endpoint_added:
                    m = re.search(r"#\[Route\s*\(\s*[\"']([^\"']+)[\"']", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True

                # C# ASP.NET Core
                if not endpoint_added:
                    m = re.search(
                        r"\[Http(Get|Post|Put|Patch|Delete)\s*\(\s*[\"']?([^\"')\]]+)[\"']?\s*\)\]",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(r"\[Route\s*\(\s*[\"']([^\"']+)[\"']", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(
                        r"app\.Map(Get|Post|Put|Patch|Delete)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # Kotlin Ktor
                if not endpoint_added:
                    m = re.search(r"(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True
                if not endpoint_added:
                    m = re.search(r"route\s*\(\s*[\"']([^\"']+)[\"']", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True

                # Rust Actix
                if not endpoint_added:
                    m = re.search(
                        r"#\[(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # Rust Axum
                if not endpoint_added:
                    m = re.search(r"\.route\s*\(\s*[\"']([^\"']+)[\"']", line)
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": "UNKNOWN", "route": m.group(1)}
                        )
                        endpoint_added = True

                # Swift Vapor
                if not endpoint_added:
                    m = re.search(
                        r"(?:app|routes)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']",
                        line,
                    )
                    if m:
                        api_endpoints.append(
                            {"file": path, "line_number": line_number, "method": m.group(1).upper(), "route": m.group(2)}
                        )
                        endpoint_added = True

                # 3. Third-party imports
                if "import" in line or "require" in line:
                    for lib in THIRD_PARTY_LIBRARIES:
                        if re.search(lib, line, flags=re.IGNORECASE):
                            third_party_imports.append(
                                {
                                    "file": path,
                                    "line_number": line_number,
                                    "line_content": stripped,
                                    "library": lib,
                                }
                            )

                # 5. Deletion signals (terms + regex patterns)
                if not skip_signals:
                    for term in DELETION_TERMS:
                        if re.search(re.escape(term), line, flags=re.IGNORECASE):
                            deletion_signals.append(
                                {
                                    "file": path,
                                    "line_number": line_number,
                                    "line_content": stripped[:300],
                                    "signal_type": term,
                                }
                            )
                            break
                    else:
                        for pat in DELETION_REGEX_PATTERNS:
                            if pat.search(line):
                                deletion_signals.append(
                                    {
                                        "file": path,
                                        "line_number": line_number,
                                        "line_content": stripped[:300],
                                        "signal_type": "regex:" + pat.pattern[:40],
                                    }
                                )
                                break

                # 6. Retention signals (terms + regex)
                if not skip_signals:
                    for term in RETENTION_SIGNAL_PATTERNS:
                        if re.search(re.escape(term), line, re.IGNORECASE):
                            retention_signals.append(
                                {
                                    "file": path,
                                    "line_number": line_number,
                                    "line_content": stripped[:300],
                                    "signal_type": term,
                                }
                            )
                            break
                    else:
                        for pat in RETENTION_REGEX_PATTERNS:
                            if pat.search(line):
                                retention_signals.append(
                                    {
                                        "file": path,
                                        "line_number": line_number,
                                        "line_content": stripped[:300],
                                        "signal_type": "regex:" + pat.pattern[:40],
                                    }
                                )
                                break

        except Exception as exc:  # pragma: no cover - defensive guard
            console.print(
                f"[yellow]Warning:[/yellow] Failed to process file '{path}': {exc}"
            )
            continue

    route_files = sorted(set(e["file"] for e in api_endpoints))

    # Store file contents for route intent and rule engine
    _file_contents = {
        f["path"]: (f.get("content") or "")
        for f in repo_files
    }

    # Classify each route file's intent (user-facing vs internal)
    route_intent_map: Dict[str, str] = {}
    for path in route_files:
        route_intent_map[path] = _classify_route_intent(path, _file_contents.get(path, ""))

    pii_collection_files = {
        p.get("file") for p in pii_fields
        if p.get("direction") in ("collection", "schema", "unknown")
    }
    user_facing_route_files = [
        p for p in route_files
        if route_intent_map.get(p) == "user_facing"
    ]
    ambiguous_route_files = [
        p for p in route_files
        if route_intent_map.get(p) == "unknown" and p in pii_collection_files
    ]
    user_facing_route_files.extend(ambiguous_route_files)
    internal_route_files = [
        p for p in route_files
        if route_intent_map.get(p) == "internal"
    ]

    # PII by direction summary
    pii_by_direction: Dict[str, int] = {}
    for p in pii_fields:
        d = p.get("direction", "unknown")
        pii_by_direction[d] = pii_by_direction.get(d, 0) + 1

    model_keywords = (
        "model",
        "schema",
        "entity",
        "db",
        "database",
        "migration",
        # Java/Kotlin JPA
        "entity",
        "repository",
        "jparepository",
        "@table",
        # Go GORM
        "gorm",
        "automigrate",
        # Ruby ActiveRecord
        "activerecord",
        "applicationrecord",
        # PHP Eloquent
        "eloquent",
        "hasfactory",
        "fillable",
        # C# Entity Framework
        "dbcontext",
        "dbset",
        "ientitytypeconfiguration",
        # Rust Diesel/SQLx
        "queryable",
        "insertable",
        "sqlx",
    )
    model_files = sorted(
        set(
            f["path"]
            for f in repo_files
            if any(kw in f.get("path", "").lower() for kw in model_keywords)
        )
    )

    def _is_backend_auth_file(path: str) -> bool:
        """Return True only if this is a backend auth file, not a frontend API client."""
        path_lower = path.lower()
        auth_keywords = (
            "auth",
            "login",
            "signup",
            "register",
            "jwt",
            "oauth",
            "session",
            "middleware",
            # Java/Kotlin Spring Security
            "securityconfig",
            "websecurityconfig",
            "jwtfilter",
            "authenticationfilter",
            "userdetailsservice",
            "securityfilterchain",
            # Go
            "auth_middleware",
            "jwt_middleware",
            "auth_handler",
            # Ruby
            "authenticate_user",
            "devise",
            "warden",
            "doorkeeper",
            # PHP
            "authcontroller",
            "logincontroller",
            "authserviceprovider",
            # C#
            "authcontroller",
            "jwtmiddleware",
            "identityconfig",
            # Rust
            "auth_middleware",
            "jwt_layer",
            "auth_handler",
        )
        if not any(kw in path_lower for kw in auth_keywords):
            return False
        frontend_signals = (
            "/frontend/",
            "/client/",
            "/pages/",
            "/views/",
            "/components/",
            "/static/",
        )
        if any(sig in path_lower for sig in frontend_signals):
            return False
        if path_lower.endswith((".ts", ".js")):
            backend_signals = (
                "/backend/",
                "/server/",
                "/routes/",
                "/controllers/",
                "/endpoints/",
                "/middleware/",
            )
            in_api_dir = "/api/" in path_lower
            has_backend_signal = any(sig in path_lower for sig in backend_signals)
            if in_api_dir and not has_backend_signal:
                return False
        return True

    auth_files = sorted(
        list(
            {
                f["path"]
                for f in repo_files
                if _is_backend_auth_file(f.get("path", ""))
            }
        )
    )

    path_to_display = {
        f.get("path", ""): f.get("display_path", f.get("path", ""))
        for f in repo_files
    }

    repo_paths = [f.get("path", "") for f in repo_files]
    is_framework_library = _detect_framework_library(repo_paths, _file_contents)
    deployment_class = _detect_deployment_class(
        repo_paths, _file_contents, is_framework_library
    )
    tech_stack_deterministic = _extract_tech_stack_deterministic(
        repo_files, _file_contents
    )

    import_graph = _build_import_graph_cached(repo_files)
    middleware_consent = _extract_middleware_consent(repo_files)

    _for_flow = {
        "import_graph": import_graph,
        "pii_fields": pii_fields,
        "third_party_imports": third_party_imports,
        "user_facing_route_files": user_facing_route_files,
    }
    pii_flow_graph = _build_pii_flow_graph(_for_flow, _file_contents)

    # Endpoints that expose deletion (DELETE method or route path suggests delete/destroy/erase)
    _deletion_route_re = re.compile(
        r"delete|destroy|erase|erasure|purge|remove.*user|account.*delete|user.*delete|me/delete",
        re.IGNORECASE,
    )
    deletion_endpoints = [
        e for e in api_endpoints
        if (e.get("method") == "DELETE")
        or _deletion_route_re.search((e.get("route") or ""))
    ]

    files_count = len(repo_files)
    result = {
        "pii_fields": pii_fields,
        "api_endpoints": api_endpoints,
        "deletion_endpoints": deletion_endpoints,
        "third_party_imports": third_party_imports,
        "consent_signals": consent_signals,
        "deletion_signals": deletion_signals,
        "retention_signals": retention_signals,
        "route_files": route_files,
        "model_files": model_files,
        "auth_files": auth_files,
        "middleware_consent_signals": middleware_consent,
        "_file_contents": _file_contents,
        "path_to_display": path_to_display,
        "import_graph": import_graph,
        "route_intent_map": route_intent_map,
        "user_facing_route_files": user_facing_route_files,
        "internal_route_files": internal_route_files,
        "pii_by_direction": pii_by_direction,
        "test_files_excluded": test_excluded_count,
        "is_framework_library": is_framework_library,
        "deployment_class": deployment_class,
        "tech_stack_deterministic": tech_stack_deterministic,
        "pii_flow_graph": pii_flow_graph,
        "is_micro_app": files_count < 15,
        "files_count": files_count,
        "skipped_files": _ingest_skipped,
    }

    if is_framework_library:
        console.print(
            "  [dim cyan]ℹ Framework/library detected — "
            "app-level rules (deletion, data access, consent) "
            "will be scoped appropriately[/dim cyan]"
        )

    # Print a summary of findings
    console.print("\n[bold]Extraction summary:[/bold]")
    for key, val in result.items():
        if key == "test_files_excluded":
            console.print(f" - test_files_excluded: {val}")
        elif key == "_file_contents":
            console.print(f" - files_indexed: {len(val)}")
        elif key == "import_graph":
            total_edges = sum(len(v) for v in val.values())
            console.print(f" - import_graph: {len(val)} files, {total_edges} import edges")
        elif key == "pii_fields":
            by_dir = result.get("pii_by_direction", {})
            console.print(
                f" - pii_fields: {len(val)} found "
                f"({by_dir.get('collection', 0)} collection, "
                f"{by_dir.get('display', 0)} display, "
                f"{by_dir.get('schema', 0)} schema)"
            )
        elif key == "user_facing_route_files":
            console.print(f" - user_facing_routes: {len(val)} found")
        elif key == "internal_route_files":
            console.print(f" - internal_routes: {len(val)} found (regex; LLM classification may override after route classification)")
        elif key == "pii_flow_graph":
            flow = val if isinstance(val, dict) else {}
            n_sources = len(flow.get("sources", []))
            n_sinks = len(flow.get("sinks", {}))
            n_paths = len(flow.get("flow_paths", []))
            console.print(f" - pii_flow_graph: {n_sources} sources, {n_sinks} sinks, {n_paths} paths")
        elif key == "tech_stack_deterministic":
            console.print(f" - tech_stack_deterministic: {', '.join(val[:6]) if val else 'none'}")
        elif key in ("route_intent_map", "pii_by_direction"):
            console.print(f" - {key}: {len(val)} entries")
        elif isinstance(val, list):
            console.print(f" - {key}: {len(val)} found")
        elif isinstance(val, dict):
            console.print(f" - {key}: {len(val)} entries")

    return result


if __name__ == "__main__":
    # Allow running as a script: `python dpdp_scanner/extractor.py`
    # (When invoked this way, Python puts dpdp_scanner/ on sys.path, so importing
    # dpdp_scanner.* fails unless we add the repo root to sys.path.)
    import os
    import sys

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    from dpdp_scanner.ingestor import ingest

    repo_files, _repo_path = ingest(".")
    result = extract(repo_files)

    for key, val in result.items():
        print(f"{key}: {len(val)} found")

