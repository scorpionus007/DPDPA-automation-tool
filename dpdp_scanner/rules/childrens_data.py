"""
Children's data rule — DPDP Section 9.
Processing children's data requires verifiable parental consent.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List

from dpdp_scanner.extractor import is_noise_path

# Auth utility paths (login/utils) — not children's data processors
AUTH_UTILITY_PATTERNS = [
    r"authentication/utils/",
    r"auth/utils/",
    r"utils/auth",
    r"utils/login",
    r"helpers/auth",
    r"helpers/login",
]

# Paths that should never trigger children's data rules (i18n, config, tests, seeds, UI libs, mocks)
SKIP_PATH_PATTERNS = [
    r"/lang/",
    r"/locales?/",
    r"/i18n/",
    r"/translations?/",
    r"validation\.",
    r"/config/",
    r"/environments?/",
    r"seeds?\.",
    r"factories?/",
    r"fixtures?/",
    r"spec/",
    r"_test\.",
    r"test_",
    r"/components/ui/",
    r"/components/common/",
    r"/ui/",
    r"constants/",
    r"mock",
    r"fixture",
    r"\.stories\.",
    r"\.test\.",
    r"\.spec\.",
    r"sidebar",
    r"navbar",
    r"nav-bar",
    r"header",
    r"footer",
    r"layout",
    r"breadcrumb",
    r"menu",
    r"dropdown",
    r"button",
    r"badge",
    r"card\.",
    r"modal",
    r"toast",
    r"tooltip",
    r"avatar",
    r"icon",
    r"workbox-[a-f0-9]+\.js$",
    r"workbox-.*\.js$",
    r"sw\.js$",
    r"service-worker\.js$",
    r"precache-manifest\.",
    r"\.min\.js$",
    r"vendor\.js$",
    r"chunk\.[a-f0-9]+\.js$",
    r"bundle\.js$",
    r"scripts/ci/",
    r"scripts/release/",
    r"scripts/build/",
    r"\.d\.ts$",
    # Framework / server setup files
    r"trpc\.(ts|js)$",
    r"trpc\.server\.(ts|js)$",
    r"server/trpc\.(ts|js)$",
    r"hono\.(ts|js)$",
    r"express\.(ts|js)$",
    r"fastify\.(ts|js)$",
    r"koa\.(ts|js)$",
    r"nestjs\.(ts|js)$",
    # Entry points / barrel files
    r"^index\.(ts|js|tsx|jsx)$",
    r"/index\.(ts|js|tsx|jsx)$",
    r"^main\.(ts|js)$",
    r"/main\.(ts|js)$",
    r"^app\.(ts|js|tsx)$",
    r"/app\.(ts|js|tsx)$",
    r"^server\.(ts|js)$",
    r"/server\.(ts|js)$",
    # Router / middleware
    r"router\.(ts|js|tsx)$",
    r"middleware\.(ts|js|py|rb)$",
    r"context\.(ts|js)$",
    r"cors\.(ts|js|py)$",
    r"routes\.(ts|js|py|rb)$",
    # Build / generated
    r"bundle\.js$",
    r"chunk\.[a-f0-9]+\.js$",
    r"\.d\.ts$",
    # Config / tooling
    r"\.config\.(ts|js|mjs|cjs)$",
    r"next\.config\.",
    r"vite\.config\.",
    r"webpack\.config\.",
    r"rollup\.config\.",
    r"tsconfig",
    r"jest\.config\.",
    r"vitest\.config\.",
    r"eslint\.",
    # CI / scripts
    r"scripts/ci/",
    r"scripts/build/",
    r"scripts/release/",
    r"\.github/",
    r"publish\.(ts|js)$",
    r"release\.(ts|js)$",
    r"deploy\.(ts|js)$",
]

SERVER_SETUP_SIGNALS = [
    r"createTRPCRouter\b",
    r"initTRPC\b",
    r"new\s+Hono\s*\(",
    r"express\s*\(\s*\)",
    r"fastify\s*\(\s*\)",
    r"createExpressMiddleware\b",
    r"createNextApiHandler\b",
    r"appRouter\s*=",
    r"publicProcedure\b",
    r"protectedProcedure\b",
    r"t\.router\s*\(",
    r"t\.procedure\b",
    r"cors\s*\(\s*\{",
    r"helmet\s*\(\s*\)",
    r"app\.use\s*\(",
    r"router\.use\s*\(",
]


def _is_server_setup_file(content: str) -> bool:
    """True if file is framework/server setup — never children's data."""
    return sum(1 for p in SERVER_SETUP_SIGNALS if re.search(p, content, re.IGNORECASE)) >= 2

# Files with none of these signals are pure UI/constants — not data processors
DATA_PROCESSING_SIGNALS = [
    r"supabase\.",
    r"prisma\.",
    r"mongoose\.",
    r"fetch\s*\(",
    r"axios\.",
    r"useQuery\b",
    r"useMutation\b",
    r"INSERT\s+INTO",
    r"\.save\s*\(",
    r"\.create\s*\(",
    r"req\.body",
    r"request\.form",
    r"getServerSideProps",
    r"getStaticProps",
    r"export\s+async\s+function\s+GET",
    r"export\s+async\s+function\s+POST",
]


def _has_data_processing(content: str) -> bool:
    """Return True only if file actually processes or fetches data."""
    return any(
        re.search(pat, content, re.IGNORECASE) for pat in DATA_PROCESSING_SIGNALS
    )

# React/Next.js JSX children patterns — "children" = JSX child elements, not minors
REACT_JSX_PATTERNS = [
    r"React\.Children\b",
    r"React\.forwardRef\b",
    r"React\.cloneElement\b",
    r"React\.createContext\b",
    r"\bchildren\b\s*:\s*React\.ReactNode",
    r"\bchildren\b\s*:\s*ReactNode",
    r"\bchildren\b\s*\?\s*:\s*React",
    r"props\.children\b",
    r"\{\.\.\.props\}",
    r"ComponentProps\b",
    r"HTMLAttributes\b",
    r"PropsWithChildren\b",
    r"FC<",
    r"FunctionComponent<",
    r"ReactElement\b",
    r"JSX\.Element\b",
    r"useRef\b",
    r"useCallback\b",
    r"className\s*=",
    r"tailwind",
    r"tw`",
]
UI_ONLY_PATTERNS = [
    r"import.*from\s+[\"']react[\"']",
    r"from\s+[\"']@radix-ui",
    r"from\s+[\"']@shadcn",
    r"from\s+[\"']lucide-react[\"']",
    r"from\s+[\"']framer-motion[\"']",
    r"from\s+[\"']next/font[\"']",
    r"from\s+[\"']next/image[\"']",
    r"from\s+[\"']next/link[\"']",
    r"from\s+[\"']next/navigation[\"']",
    r"cva\s*\(",
    r"cn\s*\(",
    r"VariantProps\b",
    r"forwardRef\b",
    r"displayName\s*=",
]

REACT_CHILDREN_EXCLUSIONS = [
    r"React\.Children\b",
    r"React\.forwardRef\b",
    r"\bchildren\b\s*:",
    r"props\.children\b",
    r"\{\.\.\.props\}",
    r"ComponentProps",
    r"HTMLAttributes",
]


def _is_react_ui_component(content: str, file_path: str) -> bool:
    """True if file is a React UI component with no data processing; 'children' is JSX, not minors."""
    if any(
        ind in file_path.lower()
        for ind in ["/components/ui/", "/ui/components/", "/@/components/ui/"]
    ):
        return True
    react_signals = sum(1 for p in REACT_JSX_PATTERNS if re.search(p, content))
    ui_signals = sum(1 for p in UI_ONLY_PATTERNS if re.search(p, content))
    if _has_data_processing(content):
        return False
    return (react_signals + ui_signals) >= 2


def _is_constants_or_copy_file(file_path: str, content: str) -> bool:
    """True if file is constants/copy/i18n where 'child'/'minor' appear as UI strings."""
    path_lower = file_path.lower()
    filename = os.path.basename(path_lower)
    CONSTANTS_PATH_INDICATORS = [
        "constants",
        "const/",
        "/copy/",
        "/content/",
        "/strings/",
        "/i18n/",
        "/lang/",
        "/locale/",
        "/translations/",
        "messages.",
        "labels.",
    ]
    if any(ind in path_lower for ind in CONSTANTS_PATH_INDICATORS):
        return True
    CONSTANTS_FILENAME_PATTERNS = [
        r"^constants?\.",
        r"^config\.",
        r"^strings?\.",
        r"^labels?\.",
        r"^messages?\.",
        r"^copy\.",
        r"^content\.",
        r"^data\.",
        r"^mock[-_]",
        r"^fake[-_]",
        r"[-_]constants?\.",
        r"[-_]config\.",
        r"[-_]types?\.",
        r"[-_]enums?\.",
    ]
    if any(re.search(p, filename) for p in CONSTANTS_FILENAME_PATTERNS):
        return True
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if not lines:
        return False
    string_lines = sum(
        1
        for l in lines
        if re.match(r"^[\w\s]+[=:]\s*[\'\"`]", l)
        or re.match(r"^[\'\"`]\w", l)
        or re.match(r"^export\s+const\s+\w+\s*=\s*[\{\[]", l)
    )
    if len(lines) > 5 and (string_lines / len(lines)) > 0.6:
        return True
    return False


# Technical age terms (cache, JWT, ORM) — not demographic age
TECHNICAL_AGE_TERMS = [
    r"\bmax-age\b",
    r"\bmax_age\b",
    r"\bage\s*[:=]\s*\d+",
    r"\bcache[_\-]age\b",
    r"\bcache\b.*\bage\b",
    r"\biat\b",
    r"\btoken[_\-]age\b",
    r"\bexpir\b",
    r"\bttl\b",
    r"\bmax[_\-]age[_\-]second",
    r"\bage[_\-]rating\b",
    r"\bcontent[_\-]rating\b",
    r"\brated\s+[A-Z]\b",
    r"\bparental[_\-]rating\b",
    r"\bcertificate\b",
    r"\bcert[_\-]age\b",
    r"\bparent[_\-]?id\b",
    r"\bchild[_\-]?id\b",
    r"\bparent[_\-]?node\b",
    r"\bchild[_\-]?node\b",
    r"\btree[_\-]node\b",
    r"\bnested[_\-]set\b",
    r"\badjacency[_\-]list\b",
    r"\bhas[Mm]any\b",
    r"\bbelongs[Tt]o\b",
    r"\bhas[Oo]ne\b",
    r"\bchild[_\-]?process\b",
    r"\bspawn\b",
    r"\bfork\b",
    r"\bworker\b",
    r"@param\s+\{",
    r"@returns\s+\{",
    r"\/\*\*",
]

ORM_RELATIONSHIP_SIGNALS = [
    r"hasMany\s*\(",
    r"belongsTo\s*\(",
    r"hasOne\s*\(",
    r"belongsToMany\s*\(",
    r"@OneToMany\b",
    r"@ManyToOne\b",
    r"@OneToOne\b",
    r"childNodes?\b",
    r"parentNode\b",
    r"children\s*:\s*\[",
    r"parent\s*:\s*\{",
    r"child_issue",
    r"parent_issue",
    r"sub_issue",
    r"child_task",
    r"parent_task",
    r"subtask",
    r"sub_task",
    r"issue_parent",
    r"parent_id\s*=\s*models\.",
    r"parent\s*=\s*models\.ForeignKey",
    r"ForeignKey\s*\(\s*['\"]self['\"]",
    r"self\.id\s*==\s*parent",
    r"TreeForeignKey\b",
    r"mptt\b",
    r"treebeard\b",
    r"nested_set\b",
    r"path_enumeration",
    r"closure_table",
    r"adjacency_list",
    r"level\s*=\s*models\.",
    r"lft\s*=\s*models\.",
    r"rght\s*=\s*models\.",
    r"tree_id\s*=\s*models\.",
    r"reply_to\b",
    r"in_reply_to\b",
    r"thread_id\b",
    r"parent_comment\b",
    r"child_comment\b",
]


def _age_match_is_technical(content: str, match_start: int) -> bool:
    """
    Returns True if the age/child match at match_start is a technical
    term (cache, JWT, ORM relationship) rather than demographic data.
    Checks a 150-character window around the match.
    """
    window_start = max(0, match_start - 75)
    window_end = min(len(content), match_start + 75)
    context = content[window_start:window_end]
    return any(
        re.search(p, context, re.IGNORECASE)
        for p in TECHNICAL_AGE_TERMS
    )


def _has_real_demographic_age(content: str, age_matches: list) -> bool:
    """
    Returns True only if at least one age/DOB match in the file
    is a real demographic field, not a technical term.

    age_matches: list of re.Match objects from age/DOB detection.
    """
    for match in age_matches:
        if not _age_match_is_technical(content, match.start()):
            return True
    return False


def _is_orm_relationship_file(content: str, file_path: str = "") -> bool:
    """
    Returns True if 'child'/'parent' in this file refers to
    ORM/tree relationships, not real children/parents as people.
    Serializer files need only 1 signal; other files need 2+.
    """
    signal_count = sum(
        1 for p in ORM_RELATIONSHIP_SIGNALS
        if re.search(p, content, re.IGNORECASE)
    )
    is_serializer = "serializer" in (file_path or "").lower()
    threshold = 1 if is_serializer else 2
    return signal_count >= threshold


def _should_skip_file(file_path: str, content: str) -> bool:
    """Master exclusion gate — True if file should never be checked for children's data."""
    path_norm = file_path.replace("\\", "/")
    for pattern in AUTH_UTILITY_PATTERNS + SKIP_PATH_PATTERNS:
        if re.search(pattern, path_norm, re.IGNORECASE):
            return True
    if _is_server_setup_file(content):
        return True
    if not _has_data_processing(content):
        return True
    if _is_react_ui_component(content, file_path):
        return True
    if _is_constants_or_copy_file(file_path, content):
        return True
    if _is_orm_relationship_file(content, file_path):
        return True
    return False


def _should_skip_for_children(path: str) -> bool:
    path_norm = path.replace("\\", "/").lower()
    return any(re.search(pat, path_norm) for pat in SKIP_PATH_PATTERNS)


def _get_content(extracted: Dict, filepath: str) -> str:
    """Retrieve file content from extracted._file_contents."""
    return (extracted.get("_file_contents") or {}).get(filepath, "")


def _is_react_children_false_positive(content: str, matched_line: str) -> bool:
    """
    Returns True if the 'children' match is React JSX children prop,
    not actual DPDP children (minors) data.
    """
    if re.search(
        r"(?:React\.forwardRef|ComponentProps|HTMLAttributes|"
        r"props\.children|children\s*\?\s*:|React\.Children)",
        matched_line,
        re.IGNORECASE,
    ):
        return True
    react_signals = sum(
        1 for p in REACT_CHILDREN_EXCLUSIONS
        if re.search(p, content)
    )
    return react_signals >= 2


AGE_INDICATORS = [
    "age",
    "date_of_birth",
    "dob",
    "birth_date",
    "birthdate",
    "birth_year",
    "age_verified",
    "is_minor",
    "user_age",
]
AGE_DOB_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(x) for x in AGE_INDICATORS) + r")\b",
    re.IGNORECASE,
)

VERIFICATION_SIGNALS = [
    "age >= 18",
    "age > 17",
    ">= 18",
    "> 17",
    "is_adult",
    "age_check",
    "parental_consent",
    "guardian_consent",
    "coppa",
    "child_safe",
]


def check_childrens_data(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []
    file_contents = extracted.get("_file_contents") or {}
    model_files = set(extracted.get("model_files") or [])
    pii_fields = extracted.get("pii_fields", []) or []

    age_fields: List[Dict] = []
    verification_signals: List[Dict] = []

    for path, content in file_contents.items():
        if not content:
            continue
        if _should_skip_file(path, content):
            continue
        # Collect all age/DOB regex matches first; skip if all are technical terms
        age_matches = list(AGE_DOB_PATTERN.finditer(content))
        if age_matches and not _has_real_demographic_age(content, age_matches):
            continue
        content_lower = content.lower()
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for age_ind in AGE_INDICATORS:
                if re.search(rf"\b{re.escape(age_ind)}\b", stripped, re.IGNORECASE):
                    age_fields.append({"file": path, "line_number": i, "line_content": stripped[:200], "field": age_ind})

        for vs in VERIFICATION_SIGNALS:
            if vs.lower() in content_lower:
                for i, line in enumerate(lines, 1):
                    if vs.lower() in line.lower():
                        verification_signals.append({"file": path, "line_number": i, "signal": vs})
                        break

        if re.search(r"\b(child|minor|student)\b", content, re.IGNORECASE):
            pii_in_file = [p for p in pii_fields if p.get("file") == path]
            if pii_in_file:
                if not _has_data_processing(content):
                    continue
                has_non_react_match = False
                for line in lines:
                    if re.search(r"\b(child|minor|student)\b", line, re.IGNORECASE):
                        if _is_react_children_false_positive(content, line):
                            continue
                        has_non_react_match = True
                        break
                if not has_non_react_match:
                    continue
                findings.append(
                    {
                        "rule": "CHILDRENS_DATA_PATTERN",
                        "dpdp_section": "Section 9 — Children's Data",
                        "severity": "LOW",
                        "confidence": 0.50,
                        "file": path,
                        "evidence": {
                            "age_fields": age_fields,
                            "verification_signals": verification_signals,
                            "child_minor_student": True,
                        },
                        "description": "Child/minor/student term paired with PII collection in same file. Requires human validation.",
                        "fix": None,
                        "requires_human_validation": True,
                    }
                )

    files_with_age = {a["file"] for a in age_fields}
    files_with_verification = {v["file"] for v in verification_signals}

    for path in files_with_age:
        content = file_contents.get(path, "")
        if _should_skip_file(path, content or ""):
            continue
        if path not in files_with_verification:
            age_in_file = [a for a in age_fields if a["file"] == path]
            findings.append(
                {
                    "rule": "CHILDRENS_DATA_RISK",
                    "dpdp_section": "Section 9 — Children's Data",
                    "severity": "HIGH",
                    "confidence": 0.75,
                    "file": path,
                    "evidence": {
                        "age_fields": age_in_file,
                        "verification_signals": [],
                    },
                    "description": "Age/DOB field detected but no age verification or parental consent logic found.",
                    "fix": None,
                }
            )

    if age_fields and files_with_verification and not any(f.get("rule") == "CHILDRENS_DATA_RISK" for f in findings):
        findings.append(
            {
                "rule": "AGE_VERIFICATION_PRESENT",
                "dpdp_section": "Section 9 — Children's Data",
                "severity": "PASS",
                "confidence": 0.80,
                "file": "N/A",
                "evidence": {
                    "age_fields": age_fields,
                    "verification_signals": verification_signals,
                },
                "description": "Age/DOB collection with verification logic detected.",
                "fix": None,
            }
        )

    # If age verification present, downgrade CHILDRENS_DATA_PATTERN to INFO (advisory only)
    has_age_verification = any(
        f.get("rule") == "AGE_VERIFICATION_PRESENT" for f in findings
    )
    if has_age_verification:
        for f in findings:
            if f.get("rule") == "CHILDRENS_DATA_PATTERN":
                f["severity"] = "INFO"
                f["confidence"] = 0.50
                f["description"] = (
                    "Children's data term detected. Age verification "
                    "is present in this codebase — verify this specific "
                    "file is covered by the existing age verification flow."
                )
                f["requires_human_validation"] = True

    return findings
