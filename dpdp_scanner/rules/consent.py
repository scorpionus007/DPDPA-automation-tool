from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from dpdp_scanner.config import path_matches_glob
from dpdp_scanner.extractor import _get_transitive_imports


def _make_pass(
    file_path: str,
    extracted: Dict,
    reason: str,
    via_files: List[str] | None = None,
) -> Dict:
    display = extracted.get("path_to_display", {}).get(file_path, file_path)
    desc_map = {
        "direct": "Consent signal detected directly in this file.",
        "middleware_direct": "Framework auth/consent middleware detected in this file.",
        "via_import": "Consent covered via imported module: "
        + ", ".join((via_files or [])[:2])
        if via_files
        else "Consent covered via imported module.",
        "inline_auth": "Auth enforcement pattern detected inline — consent likely handled at registration.",
    }
    confidence_map = {
        "direct": 1.0,
        "middleware_direct": 0.90,
        "via_import": 0.75,
        "inline_auth": 0.70,
    }
    return {
        "rule": "CONSENT_PRESENT",
        "dpdp_section": "Section 6 — Consent",
        "severity": "PASS",
        "confidence": confidence_map.get(reason, 0.70),
        "file": file_path,
        "display_path": display,
        "description": desc_map.get(reason, "Consent coverage detected."),
        "evidence": {"reason": reason, "via_files": via_files or []},
        "fix": None,
    }


def _make_consent_missing(file_path: str, extracted: Dict) -> Dict:
    all_pii = extracted.get("pii_fields", []) or []
    endpoints = extracted.get("api_endpoints", []) or []

    file_pii = [p for p in all_pii if p.get("file") == file_path]
    file_eps = [e for e in endpoints if e.get("file") == file_path]

    directions: Dict[str, int] = {}
    for p in file_pii:
        d = p.get("direction", "unknown")
        directions[d] = directions.get(d, 0) + 1

    display = extracted.get("path_to_display", {}).get(file_path, file_path)
    return {
        "rule": "CONSENT_MISSING",
        "dpdp_section": "Section 6 — Consent",
        "severity": "HIGH",
        "confidence": 0.90,
        "file": file_path,
        "display_path": display,
        "line_number": None,
        "description": (
            "Personal data collection and API endpoint detected "
            "with no consent mechanism."
        ),
        "evidence": {
            "pii_fields": file_pii[:5],
            "endpoints": file_eps[:5],
            "pii_directions": directions,
        },
        "fix": None,
    }


def _make_repo_level_missing(extracted: Dict) -> Dict:
    pii_fields = extracted.get("pii_fields", []) or []
    return {
        "rule": "CONSENT_MISSING_REPO_LEVEL",
        "dpdp_section": "Section 6 — Consent",
        "severity": "HIGH",
        "confidence": 0.65,
        "file": "REPO-WIDE",
        "display_path": "REPO-WIDE",
        "description": "No consent mechanism detected anywhere in the repository.",
        "evidence": {
            "pii_files_count": len({p["file"] for p in pii_fields if p.get("file")}),
            "route_files": extracted.get("route_files", []),
            "consent_signals_found": 0,
        },
        "fix": None,
    }


AUTH_FORM_PATTERNS = [
    r"signIn\s*\(",
    r"signUp\s*\(",
    r"signInWithPassword",
    r"signUpWithPassword",
    r"auth\.signIn",
    r"auth\.signUp",
    r"createUserWithEmailAndPassword",
    r"signInWithEmailAndPassword",
    r"next-auth",
    r"NextAuth",
    r"getServerSession",
    r"useSession",
    r"credentials\.email",
    r"credentials\.password",
    r"authenticate\s*\(",
    r"login\s*\(\s*request",
    r"logout\s*\(\s*request",
    r"LoginView\b",
    r"LogoutView\b",
    r"AuthenticationForm\b",
    r"PasswordChangeForm\b",
    r"PasswordResetForm\b",
    r"SetPasswordForm\b",
    r"from\s+django\.contrib\.auth",
    r"from\s+django\.contrib\.auth\.views",
    r"flask_login\b",
    r"login_user\s*\(",
    r"logout_user\s*\(",
    r"current_user\b",
    r"@login_required\b",
    r"OAuth2PasswordRequestForm\b",
    r"HTTPBearer\b",
    r"Depends\s*\(\s*get_current_user",
    r"Auth::attempt\s*\(",
    r"auth\(\)\.attempt\s*\(",
    r"Auth::login\s*\(",
    r"Fortify\b",
    r"Sanctum\b",
    r"@AuthenticationPrincipal\b",
    r"UsernamePasswordAuthenticationToken\b",
    r"BCryptPasswordEncoder\b",
    r"magic[_-]?link\b",
    r"magic[_-]?code\b",
    r"send_magic\b",
    r"sendMagic\b",
    r"MagicLink\b",
    r"otp[_\-]?verify\b",
    r"verify[_\-]?otp\b",
]


def _is_auth_only_form(content: str) -> bool:
    """
    Returns True if this file is a pure authentication/session form —
    login, signup, password reset, magic link, OTP.
    Auth use of email qualifies as Section 7 legitimate use.
    """
    auth_signals = sum(
        1 for p in AUTH_FORM_PATTERNS
        if re.search(p, content)
    )
    return auth_signals >= 1


# Utility/helper/service class exclusion — process PII but are called BY routes, not routes
UTILITY_FILENAME_PATTERNS = [
    r"[Uu]til(s|ity)?\.",
    r"[Hh]elper(s)?\.",
    r"[Tt]ool(s)?\.",
    r"[Cc]lient\.",
    r"[Hh]andler\.",
    r"[Pp]rocessor\.",
    r"[Ff]ilter\.",
    r"[Ii]nterceptor\.",
    r"[Mm]iddleware\.",
    r"[Cc]onfig(uration)?\.",
    r"[Ss]etup\.",
    r"[Cc]onstants?\.",
    r"[Ee]xception(s)?\.",
    r"[Ee]rror(s)?\.",
    r"[Bb]ase\.",
    r"[Aa]bstract\.",
    r"[Mm]ixin(s)?\.",
    r"[Dd]ecorator(s)?\.",
    r"[Jj][Ww][Tt].*\.",
    r"[Kk]ms.*\.",
    r"[Ss]3.*\.",
    r"[Ee]mail.*\.(java|py|ts|js|go|rb|php|cs|kt)$",
    r"[Ss][Mm][Ss].*\.",
    r"[Cc]rypto.*\.",
    r"[Ee]ncrypt.*\.",
    r"[Hh]ash.*\.",
    r"[Tt]oken.*\.",
    r"[Jj]ob.*\.",
    r"[Tt]ask.*\.",
    r"[Ss]cheduler?\.",
    r"[Ww]orker\.",
    r"[Mm]igration.*\.",
    r"[Ss]eed.*\.",
    r"[Ff]ixture.*\.",
    r"[Dd][Bb]\.",
    r"[Bb]atch[Dd][Bb]\.",
    r"[Pp]ool[Dd][Bb]\.",
    r"[Dd]atabase\.",
    r"[Cc]onnection(s)?\.",
    r"[Rr]epository\.",
    r"[Dd]ao\.",
    r"[Mm]apper?\.",
    r"[Qq]uery.*\.",
]

SERVICE_NOT_ROUTE_PATTERNS = [
    r"@Injectable\b",
    r"@Service\b",
    r"Injectable\(\)",
    r"implements.*Service\b",
    r"extends.*Service\b",
    r"class.*Service\s*\{",
    r"class.*Repository\s*\{",
    r"class.*Manager\s*\{",
    r"class.*Helper\s*\{",
    r"class.*Util(s)?\s*\{",
    r"export\s+class.*Service",
    r"export\s+class.*Repository",
    r"export\s+default\s+class.*Service",
    r"def\s+__init__.*self.*repo",
]


# Path segments that indicate consent false positives (no PII collection at this layer)
CONSENT_SKIP_PATH_PATTERNS = [
    r"workbox",           # service worker / PWA — no user form collection
    r"service-worker",
    r"sw\.js",
    r"management/",       # Django management commands — not user-facing routes
    r"management\\\\",   # Windows path
]

# UI display components (list items, cards, sidebars) — not data collection endpoints
UI_COMPONENT_EXCLUSIONS = [
    r"components/.*list-item",
    r"components/.*listing",
    r"components/.*sidebar",
    r"components/.*card-item",
    r"components/.*menu",
    r"components/.*header",
    r"components/.*footer",
    r"components/.*layout",
    r"components/.*empty-state",
    r"components/.*skeleton",
    r"components/.*breadcrumb",
    r"components/.*pagination",
    r"components/.*badge",
    r"components/.*avatar",
    r"components/.*icon",
    r"urls\.py$",
    r"routes\.(ts|js|tsx)$",
    r"router\.(ts|js|tsx)$",
    r"management/commands/",
    r"migrations/",
    r"serializers/",
    r"types\.(ts|tsx)$",
    r"interfaces\.(ts|tsx)$",
    r"constants\.(ts|tsx|py)$",
    r"config/routes\.rb$",
    r"routes\.rb$",
    r"endPoints\.(js|ts)$",
    r"endpoints\.(js|ts)$",
    r"api_client\.(js|ts)$",
    r"api[_\-]?helper\.(js|ts)$",
]

CONSENT_ADDITIONAL_EXCLUSIONS = [
    r"password[_-]management",
    r"password[_-]reset",
    r"reset[_-]password",
    r"change[_-]password",
    r"forgot[_-]password",
    r"set[_-]password",
    r"new[_-]password",
    r"confirm[_-]password",
    r"update[_-]password",
    r"create[_-]password",
    r"provider/oauth/",
    r"provider/credentials/",
    r"provider/magic",
    r"adapter/",
    r"views/space/",
    r"views/common\.py$",
    r"check\.py$",
    r"setup[_-]form",
    r"setup[_-]instance",
    r"serializers/issue",
    r"serializers/cycle",
    r"serializers/module",
    r"serializers/intake",
    r"auth[_-]?wrapper",
    r"authentication[_-]?wrapper",
    r"auth[_-]?root",
    r"form[_-]?root",
    r"auth[_-]?layout",
    r"auth[_-]?guard",
    r"protected[_-]?route",
    r"private[_-]?route",
    r"require[_-]?auth",
    r"magic[_-]?link",
    r"magic[_-]?code",
    r"magic\.py$",
    r"otp\.",
    r"verify[_-]?email",
    r"email[_-]?verify",
    r"auth[_-]?helper",
    r"auth[_-]?util",
    r"auth[_-]?service",
    r"social[_-]?auth",
    r"social[_-]?login",
    # Document signing flows (consent is the signature)
    r"envelope[_\-]?signing",
    r"signing[_\-]?complete",
    r"signing[_\-]?page",
    r"envelope[_\-]?editor",
    r"template[_\-]?signing",
    r"direct[_\-]?template",
    r"document[_\-]?sign",
    r"sign[_\-]?document",
    r"recipient[_\-]?form",
    r"signer[_\-]?page",
    # Embed flows (consent obtained at embed config)
    r"embed\+/",
    r"embed/v[0-9]",
    r"embedding[_\-]?router",
    r"create[_\-]?embedding",
    # Team creation (admin action)
    r"team[_\-]?create[_\-]?dialog",
    r"create[_\-]?team",
    r"organisation[_\-]?create",
    r"create[_\-]?organisation",
    # Passkey / WebAuthn (browser-native, not PII collection)
    r"passkey\.",
    r"webauthn\.",
    r"two[_\-]?factor\.",
    r"2fa\.",
    r"totp\.",
    r"mfa\.",
]

WORKSPACE_ADMIN_ACTION_PATTERNS = [
    r"workspace.*invite",
    r"invite.*workspace",
    r"project.*invite",
    r"invite.*project",
    r"team.*invite",
    r"invite.*member",
    r"member.*invite",
    r"send.*invitation",
]


def _is_django_consent_false_positive(file_path: str) -> bool:
    """True if path is Django/Plane false positive: workbox, management commands, urls.py."""
    p = file_path.replace("\\", "/").lower()
    if "urls.py" in p and p.endswith("urls.py"):
        return True
    return any(re.search(pat, p) for pat in CONSENT_SKIP_PATH_PATTERNS)


def _is_utility_file(file_path: str) -> bool:
    """True if file is a utility/helper/infrastructure class, not a data collection endpoint."""
    filename = os.path.basename(file_path)
    if _is_django_consent_false_positive(file_path):
        return True
    return any(
        re.search(p, filename, re.IGNORECASE) for p in UTILITY_FILENAME_PATTERNS
    )


def _is_service_layer(content: str) -> bool:
    """True if file is a service layer (business logic) rather than a route/controller."""
    return sum(
        1 for p in SERVICE_NOT_ROUTE_PATTERNS
        if re.search(p, content, re.IGNORECASE)
    ) >= 1


OAUTH_CALLBACK_PATTERNS = [
    r"oauth.{0,30}callback",
    r"callback.{0,30}oauth",
    r"oidc.{0,30}callback",
    r"socialite",
    r"AttemptToAuthenticate",
    r"HandleProviderCallback",
    r"passport\.authenticate",
    r"oauth[_\-]token",
    r"oauth[_\-]access",
    r"token[_\-]exchange",
    r"/callback/oauth",
    r"/oauth/callback",
    r"/auth/callback",
]


def _is_oauth_callback(file_path: str, content: str) -> bool:
    """
    OAuth callbacks receive pre-authorized data from providers.
    Consent was obtained at the provider — not required here.
    Never fire CONSENT_MISSING on these files.
    """
    combined = file_path + "\n" + content[:1000]
    return any(
        re.search(p, combined, re.IGNORECASE)
        for p in OAUTH_CALLBACK_PATTERNS
    )


def _internal_route_description(file_path: str) -> str:
    """
    Generate an accurate description for INTERNAL_ROUTE_PII_ACCESS
    based on what the file actually is, not a generic template.
    """
    p = file_path.lower()

    if any(x in p for x in ["dashboard", "admin", "audit", "reporting"]):
        return (
            "Internal dashboard/admin route accesses PII. "
            "Verify: (1) access is restricted to authorised staff only "
            "via role-based middleware, (2) a Section 7 legitimate use "
            "basis is documented in your compliance register."
        )
    elif any(x in p for x in ["jwt", "token", "session", "cookie"]):
        return (
            "Authentication utility accesses PII as part of session "
            "management. Verify: (1) PII is not written to logs, "
            "(2) tokens are encrypted at rest, "
            "(3) token expiry is enforced."
        )
    elif any(x in p for x in ["credential", "convertcredential", "init", "setup"]):
        return (
            "Configuration or credential handler accesses connection PII. "
            "Verify: (1) credentials are loaded from environment variables "
            "not hardcoded, (2) connection strings are not logged in plaintext."
        )
    elif any(x in p for x in ["util", "helper", "service", "provider"]):
        return (
            "Internal service/utility accesses PII. "
            "Verify: (1) this file is only called from authorised contexts, "
            "(2) PII is not inadvertently exposed to logs or error messages."
        )
    elif any(x in p for x in ["middleware", "interceptor", "filter"]):
        return (
            "Middleware/interceptor processes PII for every request. "
            "Verify: (1) PII is not logged in request/response middleware, "
            "(2) middleware enforces authentication before PII access."
        )
    else:
        fname = os.path.basename(file_path)
        return (
            f"Internal file ({fname}) accesses PII. "
            f"Verify access is restricted to authorised contexts "
            f"and PII is not exposed to logs or error responses."
        )


def _is_config_suppressed(file_path: str, rule: str, config: Dict) -> bool:
    """Check if this file+rule is suppressed by .dpdp.yaml config."""
    suppressions = config.get("suppressions", [])
    for s in suppressions:
        if s.get("rule") == rule and path_matches_glob(file_path, s.get("path_glob", "")):
            return True
    return False


def check_consent(extracted: Dict, config: Optional[Dict] = None) -> List[Dict]:
    """
    Run consent rule using pre-computed route classification (LLM or regex).
    Only user-facing routes with PII collection are checked; internal routes are excluded.
    """
    findings: List[Dict] = []
    config = config or extracted.get("_config", {})

    # LLM-classified (or regex fallback if --no-llm) — trust directly
    user_facing_routes = set(extracted.get("user_facing_route_files", []))
    internal_routes = set(extracted.get("internal_route_files", []))
    crm_entry_routes = set(
        p for p, intent in (extracted.get("route_intent_map") or {}).items()
        if intent == "crm_entry"
    )
    route_intent_map = extracted.get("route_intent_map", {})
    consent_signals = extracted.get("consent_signals", []) or []
    middleware_signals = extracted.get("middleware_consent_signals", []) or []
    is_library = extracted.get("is_framework_library", False)
    LIBRARY_INTERNAL_PATTERNS = [
        r"/adapter",
        r"/adapters/",
        r"/provider",
        r"/providers/",
        r"/handler",
        r"/handlers/",
        r"/middleware",
        r"/runtime/",
        r"/internals/",
        r"adapter-",
        r"\.config\.",
    ]
    import_graph = extracted.get("import_graph", {})
    file_contents = extracted.get("_file_contents", {})
    all_pii = extracted.get("pii_fields", []) or []

    consent_signal_files = {s["file"] for s in consent_signals if s.get("file")}
    middleware_files = {s["file"] for s in middleware_signals if s.get("file")}
    all_consent_covered = consent_signal_files | middleware_files

    # Only files with COLLECTION or SCHEMA direction PII are real risks
    pii_collection_files = {
        p["file"] for p in all_pii
        if p.get("direction") in ("collection", "schema", "unknown")
    }
    pii_display_only_files = (
        {p["file"] for p in all_pii if p.get("direction") in ("display", "query")}
        - pii_collection_files
    )

    all_route_files = set(extracted.get("route_files", []) or [])

    # Base candidates: user-facing routes with PII collection
    candidates = pii_collection_files & user_facing_routes

    # Remove internal routes (LLM-classified)
    candidates -= internal_routes

    # Remove CRM data entry routes
    candidates -= crm_entry_routes

    # Remove utility/helper/infrastructure files
    candidates = {
        f for f in candidates
        if not _is_utility_file(f)
    }

    # Remove service layer files
    candidates = {
        f for f in candidates
        if not _is_service_layer(file_contents.get(f, ""))
    }

    # Remove OAuth callback files
    candidates = {
        f for f in candidates
        if not _is_oauth_callback(f, file_contents.get(f, ""))
    }

    # Framework library: additionally remove adapter/provider files
    if is_library:
        candidates = {
            f for f in candidates
            if not any(
                re.search(p, f, re.IGNORECASE)
                for p in LIBRARY_INTERNAL_PATTERNS
            )
        }

    # UI components, route defs, serializers — not collection endpoints
    candidates = {
        f for f in candidates
        if not any(
            re.search(p, f.replace("\\", "/"), re.IGNORECASE)
            for p in UI_COMPONENT_EXCLUSIONS
        )
    }

    # Password/OAuth/setup/serializer false positives
    candidates = {
        f for f in candidates
        if not any(
            re.search(p, f.replace("\\", "/"), re.IGNORECASE)
            for p in CONSENT_ADDITIONAL_EXCLUSIONS
        )
    }

    for file_path in candidates:
        if _is_config_suppressed(file_path, "CONSENT_MISSING", config):
            continue

        if file_path in consent_signal_files:
            findings.append(_make_pass(file_path, extracted, "direct"))
            continue
        if file_path in middleware_files:
            findings.append(_make_pass(file_path, extracted, "middleware_direct"))
            continue

        transitive = _get_transitive_imports(file_path, import_graph, max_depth=5)
        if transitive & all_consent_covered:
            findings.append(
                _make_pass(
                    file_path,
                    extracted,
                    "via_import",
                    via_files=list(transitive & all_consent_covered),
                )
            )
            continue

        content = file_contents.get(file_path, "")
        INLINE_AUTH_PATTERNS = [
            r"Depends\s*\(",
            r"@login_required",
            r"@jwt_required",
            r"\[Authorize\]",
            r"before_action\s+:authenticate",
            r"->middleware.*auth",
            r"@PreAuthorize",
            r"RequireAuth",
            r"current_user\b",
            r"get_current_user\b",
            r"useAuth\b",
            r"useSession\b",
            r"getServerSession\s*\(",
            r"getSession\s*\(",
            r"auth\s*\(",
            # Session providers — consent was obtained at auth time
            r"SessionProvider\b",
            r"useSession\b",
            r"getSession\b",
            r"getServerSession\b",
            r"getOptionalSession\b",
            r"requireSession\b",
            r"withSession\b",
            r"session\.user\b",
            r"session\.userId\b",
            # tRPC context — always authenticated
            r"protectedProcedure\b",
            r"ctx\.user\b",
            r"ctx\.session\b",
            r"ctx\.userId\b",
            # Remix loaders with auth
            r"requireAuthenticatedUser\b",
            r"requireUser\b",
            r"getOptionalUser\b",
            r"getUserOrRedirect\b",
            # Framework auth guards
            r"@UseGuards\b",
            r"@Roles\b",
            r"@RequireAuth\b",
            r"PrivateRoute\b",
            r"ProtectedRoute\b",
            r"AuthGuard\b",
            r"RoleGuard\b",
            # Supabase auth
            r"supabase\.auth\.getUser\b",
            r"supabase\.auth\.getSession\b",
            # Clerk auth
            r"auth\(\)\s*\.",
            r"currentUser\(\)\s*\.",
            r"clerkClient\b",
        ]
        if any(re.search(p, content) for p in INLINE_AUTH_PATTERNS):
            findings.append(_make_pass(file_path, extracted, "inline_auth"))
            continue

        if _is_auth_only_form(content):
            findings.append({
                **_make_consent_missing(file_path, extracted),
                "severity": "LOW",
                "confidence": 0.50,
                "description": (
                    "Authentication form collects email for login/signup. "
                    "Email use for authentication may qualify as Section 7 "
                    "legitimate use (contractual necessity). Verify: does the "
                    "app process this email for purposes beyond authentication? "
                    "If yes, explicit consent is required."
                ),
                "requires_human_validation": True,
            })
            continue

        # Display-only PII + unknown intent → downgrade to LOW, human validation
        if file_path in pii_display_only_files:
            intent = route_intent_map.get(file_path, "unknown")
            if intent == "unknown":
                findings.append({
                    **_make_consent_missing(file_path, extracted),
                    "severity": "LOW",
                    "confidence": 0.45,
                    "description": (
                        "PII detected but all references appear to be "
                        "display/read context rather than collection. "
                        "Verify whether this file collects data from users "
                        "or only displays existing data."
                    ),
                    "requires_human_validation": True,
                })
                continue

        is_workspace_invite = any(
            re.search(p, file_path + "\n" + content[:500], re.IGNORECASE)
            for p in WORKSPACE_ADMIN_ACTION_PATTERNS
        )
        if is_workspace_invite:
            findings.append({
                **_make_consent_missing(file_path, extracted),
                "severity": "MEDIUM",
                "confidence": 0.60,
                "description": (
                    "Workspace/team invite flow collects email addresses. "
                    "Verify: (1) invitees are notified their email is being collected, "
                    "(2) the privacy notice covers invite-based data collection, "
                    "(3) uninvited users can request deletion of their email from pending invites."
                ),
                "requires_human_validation": True,
            })
            continue

        findings.append(_make_consent_missing(file_path, extracted))

    # Internal routes with PII: Section 7 advisory (max 3)
    internal_with_pii = internal_routes & pii_collection_files
    for file_path in list(internal_with_pii)[:3]:
        findings.append({
            "rule": "INTERNAL_ROUTE_PII_ACCESS",
            "dpdp_section": "Section 7 — Legitimate Use",
            "severity": "INFO",
            "confidence": 0.70,
            "file": file_path,
            "display_path": extracted.get("path_to_display", {}).get(file_path, file_path),
            "description": _internal_route_description(file_path),
            "evidence": {"route_intent": "internal"},
            "fix": None,
            "requires_human_validation": True,
        })

    # CRM / third-party data entry — different legal framework (user is data fiduciary)
    if crm_entry_routes & pii_collection_files:
        findings.append({
            "rule": "CRM_DATA_ENTRY_PATTERN",
            "dpdp_section": "Section 6 — Consent",
            "severity": "INFO",
            "confidence": 0.70,
            "file": "N/A",
            "display_path": "N/A",
            "description": (
                "CRM or personal data management routes detected. "
                "When authenticated users enter data about third-party "
                "contacts (friends, colleagues, family), the app user "
                "acts as data fiduciary for that data. "
                "Verify: (1) users are informed they are responsible for "
                "obtaining consent from contacts whose data they store, "
                "(2) this is disclosed in your privacy policy."
            ),
            "evidence": {"crm_entry_routes": list(crm_entry_routes & pii_collection_files)[:10]},
            "fix": None,
            "requires_human_validation": True,
        })

    # Repo-level fallback
    if not any(
        f.get("severity") in ("HIGH", "MEDIUM")
        for f in findings
        if (f.get("rule") or "").startswith("CONSENT")
    ):
        all_pii_files = {p["file"] for p in all_pii if p.get("file")}
        if (
            all_pii_files
            and all_route_files
            and not all_consent_covered
            and user_facing_routes
        ):
            findings.append(_make_repo_level_missing(extracted))

    return findings
