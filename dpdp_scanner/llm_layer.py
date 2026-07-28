"""
LLM layer module.

LLM pipeline: repo summary, finding enrichment, gap analysis, skeptic pass, deep review (L5), deep-review validation (L6).
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import threading
import sys
import time
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import track

from dpdp_scanner.extractor import _get_transitive_imports
from dpdp_scanner.redactor import redact
from dpdp_scanner.section_mapping import (
    closest_valid_section,
    is_valid_dpdp_section,
    score_section_key_from_dpdp,
)

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:
    genai = None  # type: ignore[assignment]
    genai_types = None  # type: ignore[assignment]

# Ensure we can print emojis on Windows terminals that default to legacy encodings.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

console = Console()

# Load .env from current dir and from project root (next to main.py / dpdp_scanner package)
load_dotenv()
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_env_path)

# Google AI Studio (Gemini) — primary LLM backend
GEMINI_API_KEY = (
    os.getenv("GEMINI_API_KEY", "").strip()
    or os.getenv("GOOGLE_AI_API_KEY", "").strip()
    or None
)

if not GEMINI_API_KEY:
    if os.path.isfile(_env_path):
        console.print(
            f"[yellow]No GEMINI_API_KEY in env. Check that .env has GEMINI_API_KEY=... (from Google AI Studio, loaded from {_env_path})[/yellow]"
        )
    else:
        console.print(
            f"[yellow]No .env found at {_env_path}. Create it with GEMINI_API_KEY=your_key (get key at aistudio.google.com)[/yellow]"
        )
elif genai is None:
    console.print("[yellow]Gemini key found but google-genai not installed. Run: pip install google-genai[/yellow]")

# --- Model config: Gemini 2.5 Flash Lite everywhere ---
MODEL_FLASH_LITE = "gemini-2.5-flash-lite"

# Gemini 2.5 Flash-Lite max output is 65,536 tokens (64K). Use universally for all layers.
PROJECT_MAX_OUTPUT_TOKENS = max(2048, min(65536, int(os.getenv("DPDP_MAX_OUTPUT_TOKENS", "65536"))))

LLM_TIERS = {
    "layer1": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 50000},
    "layer1b": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 50000},
    "layer2": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 20000},
    "layer3": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 15000},
    "layer4": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 8000},
    "layer5_chunk": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 25000},
    "layer5_synthesis": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 25000},
    "layer6_validate": {"model": MODEL_FLASH_LITE, "max_tokens": PROJECT_MAX_OUTPUT_TOKENS, "context_limit": 20000},
}

# --- API cost controls (env) ---
# Cap how many findings get LLM enrichment; rest get fallback text. Reduces Layer 2 calls.
MAX_FINDINGS_TO_ENRICH = int(os.getenv("DPDP_MAX_ENRICH", "40"))
# Batch N findings per API call in Layer 2. 1 = one call per finding (current). 4–5 = big savings.
ENRICH_BATCH_SIZE = max(1, int(os.getenv("DPDP_ENRICH_BATCH_SIZE", "4")))

# --- Layer 1 — Repo Summarizer ---
SYSTEM_PROMPT_L1 = """You are a software architecture analyst specializing in data privacy compliance for Indian startups.

YOUR TASK: Analyze the provided codebase files and extract a precise, factual summary of how personal data flows through this application.

STRICT RULES:
- Only describe what you can directly see in the code provided
- Never invent frameworks, libraries, or behaviors not visible in the code
- Every claim must be traceable to a specific file or line
- If something is unclear from the code, say "not determinable from provided code"
- Be concise — one sentence per data flow, not paragraphs

OUTPUT FORMAT: Respond with ONLY a valid JSON object. No preamble, no explanation, no markdown fences.

The JSON must have exactly these keys:
{
  "data_flows": ["each entry: 'VERB noun via MECHANISM' e.g. 'User email collected via POST /signup stored in User model'"],
  "pii_storage_locations": ["file:line format where PII fields are defined e.g. 'models/user.py:14 — email field'"],
  "auth_mechanism": "one sentence describing auth approach visible in code, or 'not determinable'",
  "third_party_services": ["only services you can see imported or called, with file evidence"],
  "risk_surface_summary": "exactly 2 sentences: sentence 1 = what PII is collected, sentence 2 = biggest DPDP risk you can see",
  "dpdp_coverage_gaps": ["each entry must cite a specific file and line e.g. 'No consent field in UserCreate schema (schemas/user.py:23)'"]
}"""

# --- Layer 1b — LLM Route Classifier ---
SYSTEM_PROMPT_L1_ROUTE_CLASSIFIER = """You are a backend engineer reviewing a list of route/controller files
from a web application to classify each one as internal or user-facing.

DEFINITIONS:

USER-FACING routes directly interact with end users (customers, app users, members of the public):
- User registration, login, logout, password reset
- Profile creation or editing (user submits their own data)
- Consent collection or preference setting
- Checkout, payment, order placement
- Contact forms, support tickets, feedback submission
- Public API endpoints consumed by mobile apps or third-party clients
- Onboarding flows

INTERNAL routes are used by staff, admins, or automated systems — NOT end users:
- Admin panels and dashboards
- Audit logs and compliance views
- Reporting and analytics pages
- Staff management interfaces
- CRM views (admins viewing user data)
- Monitoring, health checks, metrics endpoints
- Background job triggers
- Internal APIs consumed only by the same org's services
- Data export tools used by staff
- Any route only accessible after staff/admin authentication

RULES:
- Judge by BOTH the file path AND the code snippet provided
- A file named users.py that only does SELECT queries for admin viewing = INTERNAL
- A file named dashboard.tsx that has a registration form = USER_FACING
- When genuinely ambiguous, prefer USER_FACING (conservative — better to over-check)
- Only return INTERNAL when you are confident the route is never directly used by end users
- No preamble, no markdown fences

OUTPUT FORMAT — you MUST respond with valid JSON only. Start with { and end with }.
No text before or after. No markdown code blocks.
{
  "classifications": [
    {
      "file": "path or filename of the file",
      "intent": "USER_FACING or INTERNAL or AMBIGUOUS",
      "confidence": 0.0 to 1.0,
      "reason": "one short sentence"
    }
  ]
}
The number of items in "classifications" must equal the number of files you were given."""

# --- Layer 6 — Deep finding validator ---
SYSTEM_PROMPT_L6_VALIDATE = """You are a strict compliance QA validator.

Given candidate deep-review findings and small code snippets, validate each finding conservatively.

Return ONLY JSON:
{
  "validated_findings": [
    {
      "title": "short title",
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "dpdp_section": "Section X — Name",
      "file": "path/or/N/A",
      "observation": "what is visible in code",
      "justification": "why this is valid or not",
      "confidence": 0.0,
      "valid": true
    }
  ]
}

Rules:
- Keep only findings with direct code evidence.
- If evidence is weak/ambiguous, set valid=false.
- Never invent files or facts not shown in snippets.
"""

# --- Layer 1b deep review for AMBIGUOUS routes (full file + imports) ---
SYSTEM_PROMPT_L1_ROUTE_DEEP = """You are a backend engineer doing a final classification of a route file that was previously marked AMBIGUOUS.

You are given:
1. The FULL source code of the route file
2. The list of files it imports (and optionally a short snippet of each import)
3. The folder path for context

Your job: Decide definitively between exactly two outcomes — no AMBIGUOUS allowed.

USER_FACING: The route is used by end users (customers, app users, public). Examples:
- Login/signup pages (email/password for authentication only)
- Registration, password reset, OTP verification
- Public API consumed by mobile app or third-party
- Contact form, feedback, checkout
- Any auth route that is "random user logs in" (not staff-only)

INTERNAL: The route is used only by staff, admins, or systems — never by end users. Examples:
- Admin panel, dashboard, backoffice
- Audit logs, compliance views, reporting
- Staff management, CRM (admin viewing user data)
- Metrics, health checks, internal APIs
- Routes that require staff/admin role or are under /admin/, /dashboard/, /audit/

RULES:
- If the file path contains /admin/, /dashboard/, /audit/, /staff/, /internal/ and the code only reads/displays data → INTERNAL
- If the file is a login or signup form (credentials.email, signIn, signUp) used for end-user authentication → USER_FACING
- Use imports to confirm: if it imports from auth middleware that restricts to admin role → INTERNAL; if it imports from public auth (NextAuth, signIn) → USER_FACING
- When in doubt between "login page for users" vs "admin login", prefer USER_FACING for generic auth routes

OUTPUT FORMAT — respond with ONLY valid JSON:
{
  "intent": "USER_FACING or INTERNAL",
  "confidence": float between 0.0 and 1.0,
  "reason": "one sentence explaining why"
}"""

# --- File relevance map — which file types matter for which rules ---
RULE_FILE_RELEVANCE = {
    "CONSENT_MISSING": ["route_files", "auth_files"],
    "CONSENT_MISSING_REPO_LEVEL": ["route_files", "auth_files"],
    "NO_DELETION_MECHANISM": ["route_files", "model_files"],
    "DELETION_MECHANISM_PRESENT": [],
    "THIRD_PARTY_PII_SHARING": ["route_files"],
    "RETENTION_MISSING": ["model_files"],
    "PLAINTEXT_PII_IN_LOGS": ["auth_files", "route_files"],
    "HARDCODED_SECRET": ["auth_files"],
    "PASSWORD_NOT_HASHED": ["model_files", "auth_files"],
    "PURPOSE_LIMITATION_RISK": ["route_files", "model_files"],
    "CHILDRENS_DATA_RISK": ["model_files", "route_files"],
    "NO_LOGGING_DETECTED": ["auth_files", "route_files"],
    "NO_ERROR_HANDLING_IN_AUTH": ["auth_files"],
    "CROSS_BORDER_TRANSFER_RISK": ["model_files"],
    "NON_INDIA_REGION_CONFIG": [],
}

TOKEN_BUDGET = 12000  # characters per LLM enrichment call


def _select_relevant_files(
    rule_name: str,
    finding: Dict,
    extracted: Dict,
    repo_files: List[Dict],
) -> str:
    """
    Select only files relevant to this specific rule.
    Returns a formatted string of file contents within TOKEN_BUDGET.
    """
    relevant_keys = RULE_FILE_RELEVANCE.get(rule_name, ["route_files"])

    candidate_paths: set = set()

    if finding.get("file") not in ("REPO-WIDE", "N/A", "CODEBASE-WIDE"):
        candidate_paths.add(finding["file"])

    for key in relevant_keys:
        val = extracted.get(key, [])
        if isinstance(val, list):
            candidate_paths.update(val[:5])

    evidence = finding.get("evidence", {}) or {}
    for ev_list in evidence.values():
        if isinstance(ev_list, list):
            for item in ev_list:
                if isinstance(item, dict) and "file" in item:
                    candidate_paths.add(item["file"])

    # Exclude internal routes from context when enriching consent findings
    if rule_name in ("CONSENT_MISSING", "CONSENT_WITHDRAWAL_MISSING"):
        internal_routes = set(extracted.get("internal_route_files", []))
        candidate_paths = candidate_paths - internal_routes

    file_contents_map = extracted.get("_file_contents", {})
    result_parts: List[str] = []
    budget_used = 0

    for path in list(candidate_paths)[:8]:
        content = file_contents_map.get(path, "")
        if not content:
            for rf in repo_files:
                if rf.get("path") == path:
                    content = rf.get("content") or ""
                    break
        if not content:
            continue

        # Redact before sending to LLM
        content, redactions = redact(content, path)
        if redactions:
            total = sum(r.get("count", 0) for r in redactions)
            console.print(
                f"  [dim yellow]  Redacted {total} secret(s) from {path} before LLM call[/dim yellow]"
            )

        remaining = TOKEN_BUDGET - budget_used
        if remaining < 500:
            break

        file_chunk = content[: remaining - 200]
        header = f"\n=== FILE: {_clean_template_path(path)} ===\n"
        result_parts.append(header + file_chunk)
        budget_used += len(header) + len(file_chunk)

    return "\n".join(result_parts)


# --- Layer 2 — Finding Enricher ---
SYSTEM_PROMPT_L2 = """You are a DPDP Act compliance engineer reviewing specific code violations detected by a rule engine.

YOUR TASK: Given a specific compliance finding with code evidence, produce actionable fix instructions with line-level citations.

STRICT RULES:
1. CITE LINE NUMBERS — every observation in evidence_review must reference an actual line number from the code provided
2. FRAMEWORK-SPECIFIC — your fix_steps must use the actual framework visible in the code (FastAPI, Django, Express etc), not generic pseudocode
3. NO LEGAL LANGUAGE — write for a developer, not a lawyer. No "pursuant to", no "hereinafter"
4. MAX 4 FIX STEPS — each step must be a single concrete engineering action completable in under 2 hours
5. CODE EXAMPLE — must be real runnable code in the detected language/framework, max 12 lines
6. FALSE POSITIVE CHECK — if the code evidence does NOT actually confirm the violation, set llm_confidence below 0.5 and explain why in risk_explanation
7. If you cannot find the cited line in the provided code, say so explicitly in evidence_review
8. NO INFRA GUESSES — do NOT claim infrastructure properties that cannot be verified from source code alone (e.g. “encryption at rest is missing”, “Supabase tables are unencrypted”, “backups are not encrypted”, “data is stored in region X”). If the issue is about encryption at rest / managed database defaults / hosting region, you MUST phrase it as: "Not verifiable from this codebase; confirm via provider settings/docs and your deployment configuration." Set false_positive_risk to "high" unless the code explicitly configures it.

SPECIAL RULE FOR PASSWORD_NOT_HASHED:
If the flagged file is a Pydantic schema or DTO (contains BaseModel, not Column() or mapped_column()),
the password field is almost certainly a transient input for verification — NOT stored.
In this case:
- Set llm_confidence to 0.3
- Set false_positive_risk to "high"
- In risk_explanation say: "This appears to be a DTO/input schema. Password is likely used for verification only and not stored. Verify in CRUD layer that hashing occurs before persistence."
- In fix_steps give only ONE step: "Verify crud layer hashes password before storage"
- Do NOT suggest adding Pydantic validators to hash passwords — this is architecturally incorrect

SPECIAL RULE FOR CONSENT_MISSING:
If the file path suggests an internal audit, compliance, or reporting view (e.g. path contains as a directory segment: audit, audits, compliance, reporting, reports, internal, or admin), and the code suggests access is restricted (e.g. dashboard, internal API, admin-only route), then processing may fall under DPDP Section 7 legitimate use (e.g. legal obligation for compliance records, not consent-based).
In that case:
- Set false_positive_risk to "high"
- Set llm_confidence to 0.4–0.5 (requires human validation)
- In risk_explanation say: "This may be an internal audit/compliance view under Section 7 legitimate use. Verify that (1) access is restricted to authorized staff only, and (2) the purpose is documented (e.g. legal obligation or compliance). If so, no consent mechanism is required for this processing."
- In fix_steps give at most 2 steps: document the legal basis and verify access control; do NOT suggest adding consent collection for this view
Only apply this if the code context clearly indicates internal/dashboard/audit use. If the file could be user-facing (e.g. public signup or profile page), do NOT set false_positive_risk to high.

CRITICAL RULE — STAY ON TOPIC:
Your analysis must be about the SPECIFIC FINDING being enriched, not about whatever files happen to be in context.

For repo-wide findings (file = N/A):
- The finding is about something MISSING from the entire codebase
- Do NOT say "this file does X" — there is no specific file
- DO say "no evidence of X was found anywhere in the codebase"
- Your risk_explanation must explain the DPDP consequence of the absence
- Your fix_steps must be concrete implementation steps, not observations

For file-specific findings:
- Analyze ONLY the named file
- Do NOT confuse the named file with other files shown in context
- If the code in context does not match the finding, say so explicitly and set false_positive_risk to "high"

NEVER start risk_explanation with "The rule engine flagged..."
NEVER say "a generic scan result" — that is not helpful to the customer
NEVER say "the provided code does not include those files"
These phrases signal you are confused about what you are analyzing.

OUTPUT FORMAT: Respond with ONLY a valid JSON object. No preamble, no markdown fences. Exactly these keys:
{
  "evidence_review": [
    {"file": "filename", "line_number": <int>, "observation": "what this line does that confirms/denies the violation"}
  ],
  "risk_explanation": "2 sentences max: what DPDP obligation is violated and what the real-world consequence is",
  "fix_steps": ["Step using actual framework syntax — max 4 items"],
  "code_example": "working code snippet in detected language, max 12 lines",
  "dpdp_reference": "Section X(Y) — one sentence stating the specific obligation",
  "llm_confidence": <float 0.0-1.0>,
  "false_positive_risk": "low|medium|high"
}"""

# Batched Layer 2: same rules, return a JSON array — one object per finding in order.
SYSTEM_PROMPT_L2_BATCH = SYSTEM_PROMPT_L2 + """

BATCH MODE: You will receive multiple findings (numbered FINDING 1, FINDING 2, ...). Produce one enrichment object per finding, in the same order.

Return a JSON array of objects. One object per finding.
Each object must have these exact keys: evidence_review, risk_explanation, fix_steps, code_example, dpdp_reference, llm_confidence, false_positive_risk.
Start your response with [ and end with ].
No markdown fences, no preamble, no explanation outside the JSON array.
The number of array elements must equal the number of findings provided."""

# --- Layer 3 — Gap Analyst ---
SYSTEM_PROMPT_L3 = """You are a DPDP Act gap analyst. Your job is to find compliance obligations the rule engine MISSED.

YOUR TASK: Review the repository context and rule engine coverage map. Identify up to 5 specific gaps — areas where the code suggests a DPDP obligation exists but the rule engine did not check for it.

STRICT RULES:
1. GAPS ONLY — do not repeat findings already in the rule engine output
2. CITE EVIDENCE — every gap must name a specific file, function, or pattern you observed
3. CONSERVATIVE CONFIDENCE — max confidence 0.7. You are an analyst, not a rule engine
4. NO HIGH SEVERITY — you may only use MEDIUM or LOW. HIGH is reserved for verified rule findings
5. MUST BE ACTIONABLE — every recommendation must be a specific engineering change, not "review your policies"
6. QUALITY OVER QUANTITY — 2 excellent specific gaps beat 5 vague ones. If you only find 2 real gaps, return 2.

DPDP SECTIONS TO CHECK FOR GAPS (that rules may have missed):
- Section 8 Right to Access: Can users download all their personal data?
- Section 6(6) Consent Withdrawal: Is there an endpoint to revoke consent?
- Section 9 Children: Is age verified before account creation?
- Section 8(4) Audit Trail: Are personal data access events logged?
- Section 5 Purpose: Is PII used in unexpected places (analytics, admin views)?
- Section 10 DPO: Is a Data Protection Officer contact exposed anywhere?

OUTPUT FORMAT: Respond with ONLY a valid JSON array. No preamble, no markdown fences.
[
  {
    "gap_id": "GAP-001",
    "dpdp_section": "Section X — Name",
    "severity": "MEDIUM or LOW only",
    "title": "short specific title under 10 words",
    "observation": "exactly what you saw in the code that reveals this gap — cite file/function",
    "recommendation": "specific engineering action: what file to edit, what to add",
    "confidence": <float 0.3-0.7>,
    "requires_human_validation": true
  }
]"""

# --- Layer 4 — Skeptic ---
SYSTEM_PROMPT_L4 = """You are a skeptical senior compliance reviewer. Your job is to quality-control AI-generated gap findings.

YOUR TASK: Review each gap finding. Keep, downgrade, or remove it based on evidence quality.

DECISION RULES — apply strictly:
KEEP (skeptic_verdict: "retained"): observation cites a specific file or function AND recommendation is a concrete engineering action
DOWNGRADE (skeptic_verdict: "downgraded"): observation is real but vague, OR recommendation is generic — lower confidence by 0.15
REMOVE: observation has no specific code evidence OR is a repeat of a rule engine finding OR is pure speculation

For retained and downgraded findings, add a "skeptic_note" field (one sentence) explaining your verdict.

OUTPUT FORMAT: Respond with ONLY a valid JSON array of retained/downgraded findings. Removed findings do not appear. No preamble, no markdown fences.
[
  {
    ...original gap finding fields...,
    "skeptic_verdict": "retained|downgraded",
    "skeptic_note": "one sentence explaining verdict",
    "confidence": <adjusted float>
  }
]"""

SYSTEM_PROMPT_L4_RULE_SANITY = """You are a skeptical senior reviewer checking whether high-confidence rule findings may still be false positives.

For each candidate finding:
- Keep it unchanged if the code evidence looks direct.
- Downgrade it only if framework conventions or architecture make the finding less certain.
- Never increase confidence.

Return ONLY valid JSON:
[
  {
    "rule": "exact rule name",
    "file": "exact file path",
    "downgrade_by": 0.0 to 0.15,
    "reason": "short explanation",
    "false_positive_risk": "low|medium|high"
  }
]
"""


# --- Layer 5 — Whole Repo Deep Review (DPDP-focused) ---
SYSTEM_PROMPT_L5_CHUNK = """You are a DPDP compliance architect reviewing a layer of application code.

YOUR FOCUS — find only these categories of issues:
1. DPDP controls that are architecturally missing or incorrectly implemented
2. Data flow patterns that create compliance risk (PII moving to unexpected places)
3. Code quality issues that directly undermine a compliance control
   (e.g. exception swallowing that kills audit logging, disabled middleware,
   commented-out consent checks, debug flags left enabled in production config)

DO NOT report:
- General security issues unrelated to data protection (SQL injection, XSS, SSRF)
- Performance issues, code style, naming conventions
- Issues already listed in the rule engine findings provided to you

STRICT RULES:
- Every finding must cite a specific file and line number
- Every finding must explain WHY it is a DPDP compliance risk specifically
- MAX 4 findings per layer — if you find more, pick the 4 most compliance-critical
- If a layer has no compliance issues return an empty findings array — do not invent
- Set confidence below 0.6 if you are not certain

YOUR RESPONSE MUST BE VALID JSON. No text before or after. No markdown fences.
{
  "chunk_name": "str — name of this architectural layer",
  "findings": [
    {
      "title": "str — concise title under 10 words",
      "severity": "HIGH|MEDIUM|LOW",
      "file": "str — exact file path",
      "line_number": "int or null",
      "observation": "str — what you observed in the code",
      "dpdp_relevance": "str — which DPDP section and why",
      "recommendation": "str — specific fix steps",
      "confidence": "float 0.0-1.0"
    }
  ],
  "architectural_note": "str — 1-2 sentence layer assessment"
}

If no findings exist, return: {"chunk_name": "...", "findings": [], "architectural_note": "No issues found."}
"""

SYSTEM_PROMPT_L5_SYNTHESIS = """You are a DPDP compliance architect writing an executive
risk summary for a CTO or compliance officer.

You have received findings from a multi-layer code review.
Your job:
1. Identify cross-cutting compliance themes appearing in multiple layers
2. Rank the top 5 most critical DPDP compliance findings
3. Write a 3-sentence architectural risk narrative focused on data protection
4. Name the single most important compliance fix — specific and actionable
5. Estimate realistic remediation effort in total engineering days

STRICT RULES:
- Only synthesize reported findings — do not invent new ones
- Cross-cutting themes (affecting multiple layers) rank higher than isolated findings
- Prioritize findings affecting user PII directly
- Write for a CTO — plain language, no legal jargon

YOUR RESPONSE MUST BE VALID JSON. No text before or after. No markdown fences.
{
  "overall_risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "risk_narrative": "str — 3-sentence executive summary",
  "cross_cutting_themes": [
    {
      "theme": "str",
      "layers_affected": ["str"],
      "severity": "HIGH|MEDIUM|LOW",
      "dpdp_section": "str"
    }
  ],
  "top_5_findings": [
    {
      "rank": "int",
      "title": "str",
      "severity": "HIGH|MEDIUM|LOW",
      "file": "str",
      "observation": "str",
      "dpdp_section": "str"
    }
  ],
  "single_most_important_fix": "str",
  "estimated_remediation_days": "int"
}
"""


def _extract_json(text: str) -> Any:
    """Extract and parse JSON from response text using balanced-brace parsing."""
    t = (text or "").strip()
    if t.startswith("```"):
        parts = t.split("```", 1)
        t = parts[1]
        if t.startswith("json"):
            t = t[4:]
    t = t.strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    # Balanced-brace extraction: find the last complete JSON object or array
    for opener, closer in [('{', '}'), ('[', ']')]:
        # Search backwards for the last closer, then find its matching opener
        last_close = t.rfind(closer)
        if last_close == -1:
            continue
        depth = 0
        start = None
        for i in range(last_close, -1, -1):
            if t[i] == closer:
                depth += 1
            elif t[i] == opener:
                depth -= 1
                if depth == 0:
                    start = i
                    break
        if start is not None:
            candidate = t[start:last_close + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass
    raise ValueError("No valid JSON found in response")


def _parse_json_safe(text: str | None) -> Dict:
    """Parse JSON from response; never raise. Returns {} on failure. Attempts truncation recovery for Layer 5."""
    if not text or not isinstance(text, str):
        return {}
    clean = (text or "").strip()
    if "```" in clean:
        clean = re.sub(r"```(?:json)?\n?", "", clean).strip()
        clean = re.sub(r"\n?```", "", clean).strip()
    try:
        parsed = json.loads(clean)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    for opener, closer in [('{', '}'), ('[', ']')]:
        last_close = clean.rfind(closer)
        if last_close == -1:
            continue
        depth = 0
        start = None
        for i in range(last_close, -1, -1):
            if clean[i] == closer:
                depth += 1
            elif clean[i] == opener:
                depth -= 1
                if depth == 0:
                    start = i
                    break
        if start is not None:
            candidate = clean[start:last_close + 1]
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                continue
    # Truncation recovery — salvage complete finding objects from truncated JSON
    findings_match = re.search(r'"findings"\s*:\s*\[', clean)
    if findings_match:
        findings_start = findings_match.end()
        salvaged: List[Dict] = []
        depth = 0
        obj_start: int | None = None
        for i, char in enumerate(clean[findings_start:], start=findings_start):
            if char == "{":
                if depth == 0:
                    obj_start = i
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0 and obj_start is not None:
                    try:
                        obj = json.loads(clean[obj_start : i + 1])
                        if isinstance(obj, dict):
                            salvaged.append(obj)
                    except json.JSONDecodeError:
                        pass
                    obj_start = None
        if salvaged:
            return {"findings": salvaged, "layer_summary": "Partial response recovered (truncation)."}
    return {}


def _parse_l2_batch_safe(raw: Any) -> List[Dict]:
    """
    Safely parse a Layer 2 batch response into a list of finding dicts.
    Handles ALL possible input types:
      - str (raw API response text)
      - dict (already parsed, wrapped in {"findings": [...]})
      - list (already parsed, direct array)
      - GenerateContentResponse (Gemini response object)
      - Message (Anthropic response object)
    Never raises. Always returns a list (empty list on failure).
    """
    # Step 1: extract text from whatever we received
    text: str | None = None
    parsed: Any = None
    if isinstance(raw, str):
        text = raw
    elif isinstance(raw, (dict, list)):
        parsed = raw
    elif hasattr(raw, "text"):
        text = getattr(raw, "text", "") or ""
    elif hasattr(raw, "content"):
        content = getattr(raw, "content", None)
        if isinstance(content, list) and content:
            first = content[0]
            text = getattr(first, "text", "") or str(first)
        elif isinstance(content, str):
            text = content
        else:
            text = str(content) if content is not None else ""
    else:
        text = str(raw) if raw is not None else ""

    # Step 2: parse text to JSON if we have text
    if text is not None and parsed is None:
        clean = text.strip()
        if "```" in clean:
            clean = re.sub(r"```(?:json)?\n?", "", clean).strip()
            clean = re.sub(r"\n?```", "", clean).strip()
        if not clean:
            return []
        try:
            parsed = json.loads(clean)
        except json.JSONDecodeError:
            parsed = None
            for pattern in (r"(\[[\s\S]*?\])", r"(\{[\s\S]*?\})"):
                m = re.search(pattern, clean)
                if m:
                    try:
                        parsed = json.loads(m.group(1))
                        break
                    except json.JSONDecodeError:
                        continue
        if parsed is None:
            console.print(
                f"  [yellow]L2 parse failed. First 200 chars: {clean[:200]}[/yellow]"
            )
            return []

    # Step 3: normalize to list regardless of wrapper format
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        for key in ("findings", "results", "enriched", "data", "items", "output"):
            val = parsed.get(key)
            if isinstance(val, list):
                out_list = [x for x in val if isinstance(x, dict)]
                if out_list or not val:
                    return out_list
                # List of non-dicts (e.g. strings) — treat as failed parse, fall through
        if any(k in parsed for k in ("rule", "description", "risk", "fix", "severity")):
            return [parsed]
        values = [v for v in parsed.values() if isinstance(v, dict)]
        if values:
            return values
    return []


def _parse_l2_batch(raw: Any) -> List[Dict]:
    """
    Parse Layer 2 batch enrichment response.
    raw can be: string, response object (with .text or .content), dict, or list.
    Never raises. Always returns a list of dicts.
    """
    return _parse_l2_batch_safe(raw)


def _parse_batch_response(raw: str | None) -> List[Dict]:
    """Legacy alias: parse Layer 2 batch from string. Use _parse_l2_batch for full handling."""
    return _parse_l2_batch(raw)


# --- Validation: stronger checks on LLM outputs ---

def _validate_l2_enrichment_response(result: Any) -> Dict | None:
    """
    Validate and sanitize Layer 2 (finding enricher) response.
    Returns sanitized dict suitable for merging into a finding, or None if invalid.
    """
    if not isinstance(result, dict):
        return None
    # Required / optional keys with sane defaults
    evidence_review = result.get("evidence_review")
    if not isinstance(evidence_review, list):
        evidence_review = []
    # Normalize evidence_review entries: must have file, line_number, observation
    validated_evidence = []
    for item in evidence_review:
        if not isinstance(item, dict):
            continue
        line_no = item.get("line_number")
        if line_no is not None and not isinstance(line_no, int):
            try:
                line_no = int(line_no)
            except (TypeError, ValueError):
                continue
        obs = item.get("observation") or item.get("observation_text")
        if isinstance(obs, str) and obs.strip():
            validated_evidence.append({
                "file": str(item.get("file", "")),
                "line_number": line_no,
                "observation": obs.strip()[:500],
            })
    # Clamp and validate llm_confidence
    try:
        conf = float(result.get("llm_confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))
    # false_positive_risk: only allow low | medium | high
    fpr = (result.get("false_positive_risk") or "medium").lower().strip()
    if fpr not in ("low", "medium", "high"):
        fpr = "medium"
    # fix_steps: list of non-empty strings
    fix_steps = result.get("fix_steps") or result.get("fix_step") or []
    if not isinstance(fix_steps, list):
        fix_steps = [fix_steps] if isinstance(fix_steps, str) and fix_steps.strip() else []
    fix_steps = [str(s).strip() for s in fix_steps if s and str(s).strip()][:6]
    if not fix_steps:
        fix_steps = ["Manual review required — LLM did not provide concrete fix steps."]
    return {
        "evidence_review": validated_evidence,
        "risk_explanation": str(result.get("risk_explanation") or "")[:1000],
        "fix_steps": fix_steps,
        "code_example": str(result.get("code_example") or "")[:3000],
        "dpdp_reference": str(result.get("dpdp_reference") or "")[:300],
        "llm_confidence": conf,
        "false_positive_risk": fpr,
    }


def _apply_llm_confidence_rules(finding: Dict, llm_confidence: float, false_positive_risk: str) -> None:
    """
    Apply stricter rules: low LLM confidence or high FP risk must downgrade or flag.
    Mutates finding in place.
    """
    severity = (finding.get("severity") or "").upper()
    rule_confidence = finding.get("confidence")
    if rule_confidence is None:
        rule_confidence = 0.90 if severity == "HIGH" else 0.65
    # Combined confidence: never exceed LLM confidence for display
    combined = min(rule_confidence, llm_confidence) if llm_confidence >= 0 else rule_confidence
    finding["confidence"] = round(combined, 2)
    # Require human validation when LLM is uncertain
    if llm_confidence < 0.4 or false_positive_risk == "high":
        finding["requires_human_validation"] = True
    if llm_confidence < 0.5 and severity == "HIGH":
        finding["severity"] = "MEDIUM"
        finding["confidence"] = min(finding.get("confidence", 0.5), 0.55)
    if false_positive_risk == "high":
        finding["confidence"] = min(finding.get("confidence", 0.5), 0.45)
        if severity == "MEDIUM":
            finding["severity"] = "LOW"


def _validate_gap_finding(g: Any) -> Dict | None:
    """Validate a single gap finding from Layer 3. Returns sanitized dict or None."""
    if not isinstance(g, dict):
        return None
    severity = (g.get("severity") or "").upper()
    if severity not in ("MEDIUM", "LOW"):
        severity = "LOW"
    try:
        confidence = float(g.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.3, min(0.65, confidence))
    title = str(g.get("title") or "").strip()[:120]
    observation = str(g.get("observation") or "").strip()[:800]
    recommendation = str(g.get("recommendation") or "").strip()[:800]
    if not title or not observation or not recommendation:
        return None
    return {
        "gap_id": str(g.get("gap_id") or "GAP-000").strip()[:20],
        "dpdp_section": str(g.get("dpdp_section") or "Section — Unknown")[:80],
        "severity": severity,
        "title": title,
        "observation": observation,
        "recommendation": recommendation,
        "confidence": round(confidence, 2),
        "requires_human_validation": True,
    }


def _validate_skeptic_gap(g: Any) -> Dict | None:
    """Validate a skeptic-reviewed gap. Must have verdict and note. Returns sanitized dict or None."""
    if not isinstance(g, dict):
        return None
    verdict = (g.get("skeptic_verdict") or "").lower().strip()
    if verdict not in ("retained", "downgraded"):
        return None
    note = str(g.get("skeptic_note") or "").strip()[:300]
    if not note:
        return None
    try:
        confidence = float(g.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    if verdict == "downgraded":
        confidence = max(0.0, confidence - 0.15)
    out = {
        "gap_id": str(g.get("gap_id") or "GAP-000")[:20],
        "dpdp_section": str(g.get("dpdp_section") or "")[:80],
        "severity": (g.get("severity") or "LOW").upper() if (g.get("severity") or "").upper() in ("MEDIUM", "LOW") else "LOW",
        "title": str(g.get("title") or "")[:120],
        "observation": str(g.get("observation") or "")[:800],
        "recommendation": str(g.get("recommendation") or "")[:800],
        "confidence": round(confidence, 2),
        "requires_human_validation": True,
        "skeptic_verdict": verdict,
        "skeptic_note": note,
    }
    return out


def _clean_template_path(path: str) -> str:
    """Replace Jinja/cookiecutter template placeholders with [project]."""
    return re.sub(r"\{\{[^}]+\}\}", "[project]", str(path))


def _build_context(finding: Dict) -> str:
    if finding.get("file") in ("N/A", "REPO-WIDE", "MULTIPLE", None):
        context_header = (
            f"THIS IS A REPO-WIDE FINDING — rule '{finding.get('rule', '')}' "
            "fired because NO evidence of the required control was found ANYWHERE in the codebase. "
            "Your job is to explain the risk of this absence and provide implementation steps to add the control.\n\n"
            "RELEVANT FILES FOR CONTEXT (to help you write specific fix steps):\n"
        )
    else:
        context_header = (
            f"THIS FINDING IS ABOUT THIS SPECIFIC FILE: {finding.get('file', '')}\n"
            "Analyze ONLY this file. Other files shown are for context only.\n\n"
        )

    evidence = finding.get("evidence", {}) or {}
    pii = evidence.get("pii_fields", []) or []
    endpoints = evidence.get("endpoints", []) or []
    libraries = evidence.get("libraries", []) or []

    file_path = _clean_template_path(finding.get("display_path", finding["file"]))

    pii_text_raw = "\n".join(
        [
            f"  Line {p.get('line_number', '?')}: pattern='{p.get('pattern_matched', '?')}' | code: {p.get('line_content', '')[:120]}"
            for p in pii[:5] if isinstance(p, dict)
        ]
    ) or "  None detected"
    pii_text, _ = redact(pii_text_raw, file_path)

    endpoint_text_raw = "\n".join(
        [
            f"  Line {e.get('line_number', '?')}: {e.get('method', '?')} {e.get('route', '?')} | code: {e.get('line_content', '')[:120]}"
            for e in endpoints[:5] if isinstance(e, dict)
        ]
    ) or "  None detected"
    endpoint_text, _ = redact(endpoint_text_raw, file_path)

    library_text_raw = "\n".join(
        [
            f"  Line {l.get('line_number', '?')}: {l.get('library', '?')} | code: {l.get('line_content', '')[:120]}"
            for l in libraries[:5] if isinstance(l, dict)
        ]
    ) or "  None detected"
    library_text, _ = redact(library_text_raw, file_path)

    extra_instruction = ""
    if (finding.get("rule") or "").upper() == "CONSENT_MISSING":
        extra_instruction = (
            "\n\nCONSENT_MISSING CONTEXT: If this file is an internal audit, compliance, or reporting view "
            "(path suggests audit/compliance/reports/admin) with restricted access, consider false_positive_risk: high "
            "and Section 7 legitimate use in your risk_explanation (see SPECIAL RULE FOR CONSENT_MISSING in system prompt)."
        )

    body = f"""=== COMPLIANCE FINDING ===
Rule: {finding['rule']}
DPDP Section: {finding['dpdp_section']}
Severity: {finding['severity']}
File: {file_path}
Description: {finding['description']}

RULE ENGINE EVIDENCE:
PII Fields Detected:
{pii_text}

API Endpoints Detected:
{endpoint_text}

Third-Party Libraries:
{library_text}

INSTRUCTION: Review the code below. Cite actual line numbers you can see. If the code below does not confirm this finding, set llm_confidence below 0.5.{extra_instruction}"""
    return context_header + body


def _layer1_repo_summary(repo_files: List[Dict], extracted: Dict) -> Dict:
    """Layer 1: Build structured repo context (tech stack, data flows, risk surface)."""
    console.print("Layer 1: Analyzing repository structure and data flows...")
    deterministic_stack = list(extracted.get("tech_stack_deterministic") or [])

    path_to_content: Dict[str, str] = {f.get("path", ""): f.get("content", "") or "" for f in repo_files}
    all_paths = list(path_to_content.keys())

    file_tree = "\n".join(sorted(all_paths))

    route_files = set(extracted.get("route_files") or [])
    model_files = set(extracted.get("model_files") or [])
    pii_files = set(p.get("file") for p in (extracted.get("pii_fields") or []) if p.get("file"))
    priority_keywords = ("config", "settings", "auth", "middleware", "app.py", "index.js", "server.js")

    selected: List[str] = []
    for p in list(route_files) + list(model_files) + list(pii_files):
        if p in path_to_content and p not in selected:
            selected.append(p)
    for p in all_paths:
        if len(selected) >= 15:
            break
        if p in selected:
            continue
        if any(kw in p.lower() for kw in priority_keywords):
            selected.append(p)

    while len(selected) < 15 and len(selected) < len(all_paths):
        for p in all_paths:
            if len(selected) >= 15:
                break
            if p not in selected:
                selected.append(p)
                break
        else:
            break

    tier1 = LLM_TIERS["layer1"]
    context_limit = tier1["context_limit"]
    key_parts = []
    for path in selected[:15]:
        raw = path_to_content.get(path, "")[:8000]
        content, redactions = redact(raw, path)
        if redactions:
            total = sum(r.get("count", 0) for r in redactions)
            console.print(
                f"  [dim yellow]  Redacted {total} secret(s) from {path} (Layer 1)[/dim yellow]"
            )
        key_parts.append(f"\n\n=== FILE: {path} ===\n{content}")
    key_files_content = "".join(key_parts)[:context_limit]

    flow_graph = extracted.get("pii_flow_graph") or {}
    flow_summary = ""
    if flow_graph.get("flow_paths"):
        paths = flow_graph["flow_paths"][:20]
        flow_lines = []
        for fp in paths:
            flow_lines.append(
                f"  {fp.get('source','?')} → {fp.get('sink_type','?')} ({fp.get('sink','?')})"
            )
        flow_summary = f"\n\nDETECTED PII DATA FLOWS ({len(flow_graph['flow_paths'])} total):\n" + "\n".join(flow_lines)

    user_message = f"""Analyze this codebase for DPDP compliance. Be precise and factual.

IMPORTANT: Only describe what you can directly see. Do not invent. Cite file names.

FILE TREE (all files in repo):
{file_tree}
{flow_summary}

KEY FILE CONTENTS:
{key_files_content}

DETERMINISTIC TECH STACK (ground truth from manifests; do not infer beyond this):
{json.dumps(deterministic_stack)}

Return ONLY the JSON object specified in your instructions. No other text."""
    result: Dict = {}
    if GEMINI_API_KEY and genai is not None:
        raw = None
        try:
            raw = _call_claude_raw(SYSTEM_PROMPT_L1, user_message, layer="layer1")
            if raw:
                result = _extract_json(raw)
                if not isinstance(result, dict):
                    result = {}
        except Exception:
            if raw:
                console.print(f"[red]Layer 1 raw response: {raw[:500]}[/red]")
            result = {}
    if not result or "error" in result:
        return {
            "tech_stack": deterministic_stack,
            "tech_stack_source": "deterministic",
            "data_flows": [],
            "pii_storage_locations": [],
            "auth_mechanism": "not detected",
            "third_party_services": [],
            "risk_surface_summary": "",
            "dpdp_coverage_gaps": [],
            "error": "Layer 1 failed",
        }
    result["tech_stack"] = deterministic_stack
    result["tech_stack_source"] = "deterministic"
    return result


def _classify_routes_with_llm(
    extracted: Dict,
    repo_files: List[Dict],
    model: str,
) -> Dict:
    """
    Use LLM to classify route files as INTERNAL or USER_FACING.

    Returns dict: {file_path: {'intent': str, 'confidence': float, 'reason': str}}

    Strategy:
      - Takes all route files from extracted
      - Sends file path + first 60 lines of content for each
      - Batches into groups of 10 to stay within token limits
      - Conservative: AMBIGUOUS is treated as USER_FACING downstream
    """
    route_files = extracted.get("route_files", [])
    file_contents = extracted.get("_file_contents", {})
    path_to_display = extracted.get("path_to_display", {})

    if not route_files:
        return {}

    def _snippet(path: str) -> str:
        raw = file_contents.get(path, "")
        content, _ = redact(raw, path)
        lines = content.splitlines()[:60]
        display = path_to_display.get(path, path)
        return f"FILE: {display}\n" + "\n".join(lines)

    BATCH_SIZE = 10
    batches = [
        route_files[i : i + BATCH_SIZE]
        for i in range(0, len(route_files), BATCH_SIZE)
    ]

    classifications: Dict = {}

    for batch_idx, batch in enumerate(batches):
        snippets = "\n\n---\n\n".join(_snippet(p) for p in batch)

        user_msg = (
            f"Classify the following {len(batch)} route/controller files "
            f"as USER_FACING, INTERNAL, or AMBIGUOUS.\n\n"
            f"For each file consider:\n"
            f"1. The file path (directory names like /admin/, /dashboard/, /audit/ suggest internal)\n"
            f"2. What the code actually does (SELECT queries = reading = likely internal, "
            f"form handling / INSERT = collecting from users = user-facing)\n"
            f"3. Auth patterns (admin-only middleware = internal, public route = user-facing)\n\n"
            f"FILES TO CLASSIFY:\n\n{snippets}"
        )

        try:
            raw = _call_claude_raw(
                SYSTEM_PROMPT_L1_ROUTE_CLASSIFIER,
                user_msg,
                layer="layer1b",
            )
            result = _parse_json_safe(raw) if raw else {}
            if not isinstance(result, dict):
                result = {}
            raw_classifications = result.get("classifications", [])
            if not isinstance(raw_classifications, list):
                raw_classifications = []
            for item in raw_classifications:
                if not isinstance(item, dict):
                    continue
                display_returned = item.get("file", "")
                matched_path = None
                for p in batch:
                    disp = path_to_display.get(p, p)
                    if disp.endswith(display_returned) or display_returned.endswith(
                        disp.split("/")[-1] if "/" in disp else disp
                    ):
                        matched_path = p
                        break
                if not matched_path:
                    fname = display_returned.split("/")[-1]
                    for p in batch:
                        if p.endswith(fname):
                            matched_path = p
                            break
                if matched_path:
                    classifications[matched_path] = {
                        "intent": item.get("intent", "AMBIGUOUS"),
                        "confidence": float(item.get("confidence", 0.5)),
                        "reason": str(item.get("reason", "")),
                        "source": "llm",
                    }
        except Exception as e:
            console.print(
                f"[yellow]  ⚠ Route classifier batch {batch_idx + 1} failed: {e}[/yellow]"
            )

    for path in route_files:
        if path not in classifications:
            classifications[path] = {
                "intent": "AMBIGUOUS",
                "confidence": 0.0,
                "reason": "Not classified — treated as user-facing",
                "source": "default",
            }

    # Deep review: for any AMBIGUOUS route, send full file + imports for definitive verdict
    classifications = _resolve_ambiguous_routes_with_llm(extracted, classifications)

    return classifications


def _resolve_ambiguous_routes_with_llm(
    extracted: Dict,
    classifications: Dict,
) -> Dict:
    """
    For every route still classified as AMBIGUOUS, run a second LLM call with
    full file content + import graph (and folder context) to get a definitive
    USER_FACING or INTERNAL verdict. Auth-related paths get full review.
    """
    file_contents = extracted.get("_file_contents", {})
    path_to_display = extracted.get("path_to_display", {})
    import_graph = extracted.get("import_graph", {})

    ambiguous_paths = [
        p for p, v in classifications.items()
        if (v.get("intent") or "").upper() == "AMBIGUOUS"
    ]
    if not ambiguous_paths:
        return classifications

    tier = LLM_TIERS.get("layer1", {})
    context_limit = tier.get("context_limit", 50000)

    for path in ambiguous_paths:
        raw_content = file_contents.get(path, "")
        if not raw_content.strip():
            continue
        content, redactions = redact(raw_content, path)
        if redactions:
            total = sum(r.get("count", 0) for r in redactions)
            console.print(
                f"  [dim yellow]  Redacted {total} secret(s) from {path} (route deep review)[/dim yellow]"
            )

        display = path_to_display.get(path, path)
        folder = "/".join(path.replace("\\", "/").split("/")[:-1]) if "/" in path else ""

        # Transitive imports (direct + 1 hop) for context
        imported_paths = list(_get_transitive_imports(path, import_graph, max_depth=2))
        import_snippets: List[str] = []
        for imp_path in imported_paths[:8]:
            imp_raw = file_contents.get(imp_path, "")
            if imp_raw:
                imp_content, _ = redact(imp_raw, imp_path)
                lines = imp_content.splitlines()[:25]
                import_snippets.append(
                    f"--- IMPORT: {imp_path} ---\n" + "\n".join(lines)
                )
        imports_block = "\n\n".join(import_snippets) if import_snippets else "(no imports captured)"

        user_msg = (
            f"This route file was classified as AMBIGUOUS. Provide a definitive verdict.\n\n"
            f"FILE PATH: {display}\n"
            f"FOLDER: {folder or '(root)'}\n\n"
            f"FULL FILE CONTENT:\n"
            f"---\n{content}\n---\n\n"
            f"IMPORTS (files this route imports, first ~25 lines each):\n\n"
            f"{imports_block}\n\n"
            f"Respond with ONLY a JSON object: intent (USER_FACING or INTERNAL), confidence (0-1), reason (one sentence)."
        )
        user_msg = user_msg[:context_limit]

        try:
            raw = _call_claude_raw(
                SYSTEM_PROMPT_L1_ROUTE_DEEP,
                user_msg,
                layer="layer1b",
            )
            result = _extract_json(raw) if raw else {}
            if isinstance(result, dict) and result.get("intent"):
                intent = (result.get("intent") or "").strip().upper()
                if intent in ("USER_FACING", "INTERNAL"):
                    classifications[path] = {
                        "intent": intent,
                        "confidence": min(1.0, max(0.0, float(result.get("confidence", 0.7)))),
                        "reason": str(result.get("reason", "Deep review verdict.")),
                        "source": "llm_deep",
                    }
                    console.print(
                        f"  [dim]  Deep review: {path.split('/')[-1]} → {intent}[/dim]"
                    )
        except Exception as e:
            console.print(
                f"[yellow]  ⚠ Deep review for {path.split('/')[-1]} failed: {e}[/yellow]"
            )

    return classifications


def _merge_route_classifications(
    regex_intent_map: Dict,
    llm_classifications: Dict,
) -> Dict:
    """
    Merge regex pre-classification with LLM classification.

    Rules:
      - If LLM says USER_FACING → always USER_FACING (override regex)
      - If BOTH regex and LLM say INTERNAL → INTERNAL (high confidence)
      - If LLM says INTERNAL, regex says unknown → INTERNAL if LLM confidence >= 0.75
      - If LLM says INTERNAL but low confidence → USER_FACING
      - If LLM says AMBIGUOUS → use regex result, or USER_FACING if regex also unknown
    """
    merged: Dict = {}
    all_paths = set(regex_intent_map) | set(llm_classifications)

    for path in all_paths:
        regex = regex_intent_map.get(path, "unknown")
        llm = llm_classifications.get(path, {})

        llm_intent = llm.get("intent", "AMBIGUOUS")
        llm_confidence = float(llm.get("confidence", 0.0))
        llm_reason = str(llm.get("reason", ""))

        if llm_intent == "USER_FACING":
            merged[path] = {
                "intent": "user_facing",
                "confidence": llm_confidence,
                "reason": f"LLM: {llm_reason}",
                "source": "llm",
            }
        elif llm_intent == "INTERNAL" and regex == "internal":
            merged[path] = {
                "intent": "internal",
                "confidence": min(1.0, llm_confidence + 0.15),
                "reason": f"LLM+regex: {llm_reason}",
                "source": "both",
            }
        elif llm_intent == "INTERNAL" and llm_confidence >= 0.75:
            merged[path] = {
                "intent": "internal",
                "confidence": llm_confidence,
                "reason": f"LLM (high confidence): {llm_reason}",
                "source": "llm",
            }
        elif llm_intent == "INTERNAL" and llm_confidence < 0.75:
            merged[path] = {
                "intent": "user_facing",
                "confidence": 0.5,
                "reason": f"LLM low confidence ({llm_confidence}) — defaulting to user-facing",
                "source": "conservative_default",
            }
        elif llm_intent == "AMBIGUOUS":
            if regex == "internal":
                merged[path] = {
                    "intent": "internal",
                    "confidence": 0.60,
                    "reason": "Regex classified internal; LLM ambiguous",
                    "source": "regex",
                }
            else:
                merged[path] = {
                    "intent": "user_facing",
                    "confidence": 0.5,
                    "reason": "Both ambiguous — defaulting to user-facing",
                    "source": "conservative_default",
                }
        else:
            merged[path] = {
                "intent": regex if regex != "unknown" else "user_facing",
                "confidence": 0.5,
                "reason": "Regex only",
                "source": "regex",
            }

    return merged


def _call_llm_raw(
    system_prompt: str,
    user_content: str,
    *,
    layer: str | None = None,
) -> str | None:
    """Call Gemini API (Google AI Studio) via google.genai; return raw text or None."""
    if genai is None or genai_types is None or not GEMINI_API_KEY:
        return None
    if layer and layer in LLM_TIERS:
        tier = LLM_TIERS[layer]
        model_id = tier["model"]
        max_tokens = tier["max_tokens"]
        context_limit = tier.get("context_limit", 100000)
        user_content = user_content[:context_limit]
    else:
        model_id = MODEL_FLASH_LITE
        max_tokens = 2048
    max_retries = 3
    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            config = genai_types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=max_tokens,
                temperature=0.2,
            )
            response = client.models.generate_content(
                model=model_id,
                contents=user_content,
                config=config,
            )
            if not response or not getattr(response, "text", None):
                return None
            return (response.text or "").strip()
        except Exception as e:
            last_error = e
            err_str = str(e).upper()
            # Retry on 503 / overload / resource exhaustion
            if attempt < max_retries - 1 and ("503" in err_str or "UNAVAILABLE" in err_str or "RESOURCE_EXHAUSTED" in err_str or "HIGH DEMAND" in err_str):
                delay = (2 ** attempt) + 1  # 2, 3, 5 s
                console.print(f"[dim]Gemini temporary error, retry in {delay}s: {e}[/dim]")
                time.sleep(delay)
                continue
            console.print(f"[dim]Gemini failed: {e}[/dim]")
            return None
    return None


def _call_claude_raw(
    system_prompt: str,
    user_content: str,
    *,
    layer: str | None = None,
) -> str | None:
    """Alias for _call_llm_raw (Gemini). Kept for compatibility."""
    return _call_llm_raw(system_prompt, user_content, layer=layer)


def _call_claude(system_prompt: str, context: str, *, layer: str | None = None) -> Dict | None:
    """Call LLM; return parsed JSON dict or None."""
    raw = _call_llm_raw(system_prompt, context, layer=layer)
    if not raw:
        return None
    try:
        parsed = _extract_json(raw)
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        return None


def _enrichment_fallback(finding: Dict) -> None:
    """Apply useful fallback text when LLM enrichment fails so customers aren't left with empty findings."""
    rule = finding.get("rule", "UNKNOWN_RULE")
    file_ref = finding.get("file") or finding.get("display_path") or "N/A"
    if file_ref in ("N/A", "REPO-WIDE", "MULTIPLE"):
        file_ref = "see finding scope"
    finding["risk_explanation"] = (
        f"Manual review required. Rule '{rule}' fired on {file_ref} — "
        f"see rule description for details."
    )
    finding["fix"] = [
        "Review the finding description above and apply fixes per your compliance process.",
    ]
    finding["code_example"] = ""
    finding["dpdp_reference"] = finding.get("dpdp_section") or ""
    finding["evidence_review"] = []
    finding["llm_confidence"] = 0.0
    finding["false_positive_risk"] = "medium"
    finding["requires_human_validation"] = True
    finding["llm_enrichment"] = "fallback"


def _enrich_single(
    finding: Dict,
    extracted: Dict,
    repo_files: List[Dict],
    repo_context: Dict,
) -> Dict:
    """Enrich one finding using smart file selection and repo context. Retries on failure."""
    finding_context = _build_context(finding)
    relevant_code = _select_relevant_files(
        finding.get("rule", ""),
        finding,
        extracted,
        repo_files,
    )
    ctx_preamble = ""
    if repo_context:
        stack = ", ".join(repo_context.get("tech_stack") or [])[:200]
        risk = (repo_context.get("risk_surface_summary") or "")[:300]
        if stack or risk:
            ctx_preamble = f"\nREPO CONTEXT: Stack: {stack}. Risk: {risk}\n"

    full_context = f"""{ctx_preamble}
{finding_context}

RELEVANT CODE FOR THIS FINDING:
{relevant_code}

Review the code above and produce your JSON response.
Cite specific line numbers from the code provided.
If the code does not confirm the violation, set llm_confidence below 0.5.
"""
    tier2 = LLM_TIERS["layer2"]
    context_limit = tier2["context_limit"]
    full_context = full_context.strip()[:context_limit]

    max_retries = 2
    validated = None

    if GEMINI_API_KEY and genai is not None:
        for attempt in range(max_retries + 1):
            try:
                result: Dict | None = _call_claude(
                    SYSTEM_PROMPT_L2, full_context, layer="layer2"
                )
                validated_first = _validate_l2_enrichment_response(result) if result else None
                if validated_first is not None:
                    validated = validated_first
                    break
                if result is not None and attempt < max_retries:
                    retry_context = (
                        full_context
                        + "\n\n[IMPORTANT: Your previous response was invalid. Reply with ONLY a valid JSON object. "
                        "Required keys: evidence_review (array of {file, line_number, observation}), "
                        "risk_explanation, fix_steps (array of strings), code_example, dpdp_reference, "
                        "llm_confidence (number 0-1), false_positive_risk (exactly one of: low, medium, high). "
                        "No markdown, no preamble.]"
                    )
                    result = _call_claude(
                        SYSTEM_PROMPT_L2,
                        retry_context[:context_limit],
                        layer="layer2",
                    )
                    validated = _validate_l2_enrichment_response(result) if result else None
                    if validated is not None:
                        break
                if attempt < max_retries:
                    time.sleep(1 * (attempt + 1))
            except Exception:
                if attempt < max_retries:
                    time.sleep(1 * (attempt + 1))
                else:
                    raise

    if validated:
        finding["fix"] = validated["fix_steps"]
        finding["risk_explanation"] = validated["risk_explanation"]
        finding["code_example"] = validated["code_example"]
        finding["dpdp_reference"] = validated["dpdp_reference"]
        finding["evidence_review"] = validated["evidence_review"]
        finding["llm_confidence"] = validated["llm_confidence"]
        finding["false_positive_risk"] = validated["false_positive_risk"]
        _apply_llm_confidence_rules(
            finding,
            validated["llm_confidence"],
            validated["false_positive_risk"],
        )
        finding["llm_enrichment"] = "full"
    else:
        _enrichment_fallback(finding)
        if "confidence" not in finding:
            finding["confidence"] = 0.0

    severity = (finding.get("severity") or "").upper()
    if "confidence" not in finding:
        finding["confidence"] = 0.90 if severity == "HIGH" else 0.65
    return finding


def _enrich_batch(
    batch: List[Tuple[int, Dict]],
    extracted: Dict,
    repo_files: List[Dict],
    repo_context: Dict,
) -> List[Tuple[int, Dict]]:
    """Enrich multiple findings in one API call. Returns [(idx, enriched_finding), ...]."""
    assert callable(_parse_l2_batch_safe), "Parser function not defined"
    tier2 = LLM_TIERS["layer2"]
    context_limit = tier2["context_limit"]
    ctx_preamble = ""
    if repo_context:
        stack = ", ".join(repo_context.get("tech_stack") or [])[:200]
        risk = (repo_context.get("risk_surface_summary") or "")[:300]
        if stack or risk:
            ctx_preamble = f"REPO CONTEXT: Stack: {stack}. Risk: {risk}\n\n"
    per_finding_limit = max(2000, (context_limit - 500 - len(ctx_preamble)) // len(batch))
    parts: List[str] = [ctx_preamble] if ctx_preamble else []
    for i, (idx, finding) in enumerate(batch):
        finding_context = _build_context(finding)
        relevant_code = _select_relevant_files(
            finding.get("rule", ""),
            finding,
            extracted,
            repo_files,
        )
        block = f"""
=== FINDING {i + 1} (index {idx}) ===
{finding_context}

RELEVANT CODE FOR THIS FINDING:
{relevant_code[:per_finding_limit]}
"""
        parts.append(block.strip())
    combined = "\n\n".join(parts)[:context_limit]
    combined += "\n\nRespond with a JSON array of exactly {} objects (one per finding above). Start with [ and end with ]. No markdown.".format(len(batch))

    raw_response = _call_claude_raw(SYSTEM_PROMPT_L2_BATCH, combined, layer="layer2")
    parsed_findings = _parse_l2_batch_safe(raw_response)
    console.print(
        f"  [dim]L2 batch: received {len(str(raw_response))} chars, "
        f"parsed {len(parsed_findings)} finding(s)[/dim]"
    )

    out: List[Tuple[int, Dict]] = []
    for i, (idx, finding) in enumerate(batch):
        copy_finding = finding.copy()
        if parsed_findings and i < len(parsed_findings):
            item = parsed_findings[i]
            validated = _validate_l2_enrichment_response(item) if isinstance(item, dict) else None
            if validated:
                try:
                    copy_finding["fix"] = validated.get("fix_steps") or []
                    copy_finding["risk_explanation"] = validated.get("risk_explanation") or ""
                    copy_finding["code_example"] = validated.get("code_example") or ""
                    copy_finding["dpdp_reference"] = validated.get("dpdp_reference") or ""
                    copy_finding["evidence_review"] = validated.get("evidence_review") or []
                    copy_finding["llm_confidence"] = validated.get("llm_confidence", 0.5)
                    copy_finding["false_positive_risk"] = validated.get("false_positive_risk") or "medium"
                    _apply_llm_confidence_rules(
                        copy_finding,
                        validated.get("llm_confidence", 0.5),
                        validated.get("false_positive_risk") or "medium",
                    )
                    severity = (copy_finding.get("severity") or "").upper()
                    copy_finding["confidence"] = 0.90 if severity == "HIGH" else 0.65
                    copy_finding["llm_enrichment"] = "full"
                    out.append((idx, copy_finding))
                    continue
                except (KeyError, TypeError, IndexError):
                    pass
        _enrichment_fallback(copy_finding)
        copy_finding.setdefault("confidence", 0.0)
        out.append((idx, copy_finding))
    return out


def _layer2_enrich_findings(
    findings: List[Dict],
    repo_context: Dict,
    extracted: Dict,
    repo_files: List[Dict],
) -> List[Dict]:
    """Layer 2: Enrich rule findings with repo context. Uses batching and cap to reduce API cost."""
    to_enrich_all = [
        (i, f)
        for i, f in enumerate(findings)
        if (f.get("severity") or "").upper() not in ("PASS", "INFO")
    ]
    # Sort by severity (HIGH first) and cap to reduce API calls
    SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    to_enrich_all.sort(key=lambda x: SEV_ORDER.get((x[1].get("severity") or "").upper(), 3))
    to_enrich = to_enrich_all[:MAX_FINDINGS_TO_ENRICH]
    skipped = len(to_enrich_all) - len(to_enrich)
    total = len(to_enrich_all)
    console.print(
        f"[cyan]Layer 2: Enriching {len(to_enrich)} findings"
        + (f" (capped from {total}, {skipped} get fallback)" if skipped else "")
        + (" in batches" if ENRICH_BATCH_SIZE >= 2 else " concurrently")
        + "...[/cyan]"
    )

    results: Dict[int, Dict] = {}

    if ENRICH_BATCH_SIZE >= 2 and len(to_enrich) > 0:
        # Batched: one API call per batch
        for start in range(0, len(to_enrich), ENRICH_BATCH_SIZE):
            batch = to_enrich[start : start + ENRICH_BATCH_SIZE]
            for idx, finding in batch:
                console.print(f"  → {finding.get('rule', 'UNKNOWN_RULE')}")
            batch_result = _enrich_batch(batch, extracted, repo_files, repo_context)
            for idx, enriched in batch_result:
                results[idx] = enriched
        # Apply fallback to any findings beyond cap (not in to_enrich)
        for idx, finding in to_enrich_all[MAX_FINDINGS_TO_ENRICH:]:
            copy_f = finding.copy()
            _enrichment_fallback(copy_f)
            copy_f.setdefault("confidence", 0.0)
            results[idx] = copy_f
    else:
        # One call per finding (original path)
        lock = threading.Lock()

        def enrich_one(item: tuple) -> tuple:
            idx, finding = item
            with lock:
                console.print(f"  → {finding.get('rule', 'UNKNOWN_RULE')}")
            copy_finding = finding.copy()
            try:
                _enrich_single(copy_finding, extracted, repo_files, repo_context)
            except Exception as e:
                console.print(f"  [dim yellow]  Enrichment error (after retries): {e}[/dim yellow]")
                _enrichment_fallback(copy_finding)
                copy_finding.setdefault("confidence", 0.0)
            return idx, copy_finding

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(enrich_one, item): item for item in to_enrich}
            for future in concurrent.futures.as_completed(futures):
                try:
                    idx, enriched = future.result()
                    results[idx] = enriched
                except Exception as e:
                    console.print(f"[red]Enrichment error: {e}[/red]")
        for idx, finding in to_enrich_all[MAX_FINDINGS_TO_ENRICH:]:
            copy_f = finding.copy()
            _enrichment_fallback(copy_f)
            copy_f.setdefault("confidence", 0.0)
            results[idx] = copy_f

    final = list(findings)
    for idx, enriched in results.items():
        final[idx] = enriched
    return final


def _layer3_gap_analysis(repo_context: Dict, findings: List[Dict], extracted: Dict | None = None) -> List[Dict]:
    """Layer 3: Identify DPDP gaps not covered by rules."""
    console.print("Layer 3: Identifying compliance gaps not covered by rules...")
    rules_fired = [f["rule"] for f in findings if (f.get("severity") or "").upper() not in ("PASS", "INFO")]
    coverage_map = {
        "consent_checked": any("CONSENT" in r for r in rules_fired),
        "deletion_checked": any("DELETION" in r for r in rules_fired),
        "third_party_checked": any("THIRD_PARTY" in r for r in rules_fired),
        "flow_checked": any("FLOW" in r for r in rules_fired),
        "rules_fired": rules_fired,
    }
    flow_section = ""
    if extracted:
        flow_graph = extracted.get("pii_flow_graph") or {}
        flow_paths = flow_graph.get("flow_paths") or []
        if flow_paths:
            flow_lines = [
                f"  {fp.get('source','?')} → {fp.get('sink_type','?')} ({fp.get('sink','?')})"
                for fp in flow_paths[:15]
            ]
            flow_section = f"\n\nDETECTED PII DATA FLOWS ({len(flow_paths)} total):\n" + "\n".join(flow_lines)

    user_msg = f"""Based on the repository analysis and rule engine coverage below, identify up to 5 
DPDP compliance gaps that the automated rules did not explicitly check.

REPOSITORY CONTEXT:
{json.dumps(repo_context, indent=2)}

RULE ENGINE COVERAGE:
{json.dumps(coverage_map, indent=2)}
{flow_section}

Return a JSON array where each element has:
{{
  "gap_id": "GAP-001" (increment),
  "dpdp_section": "relevant section name",
  "severity": "MEDIUM" or "LOW" only — never HIGH,
  "title": "short gap title",
  "observation": "what you observed in the codebase that suggests this gap",
  "recommendation": "specific actionable recommendation for the engineering team",
  "confidence": 0.3 to 0.7 only,
  "requires_human_validation": true
}}

Be conservative. 3 good gaps is better than 7 speculative ones."""
    tier3 = LLM_TIERS["layer3"]
    user_msg = user_msg[: tier3["context_limit"]]
    gap_findings: List[Dict] = []
    try:
        if GEMINI_API_KEY and genai is not None:
            raw = _call_claude_raw(SYSTEM_PROMPT_L3, user_msg, layer="layer3")
            if raw:
                raw_gaps = _extract_json(raw)
                if isinstance(raw_gaps, list):
                    gap_findings = []
                    for g in raw_gaps:
                        validated = _validate_gap_finding(g)
                        if validated:
                            gap_findings.append(validated)
    except Exception:
        pass
    if not isinstance(gap_findings, list):
        gap_findings = []
    return gap_findings


def _layer4_skeptic(gap_findings: List[Dict], repo_context: Dict) -> List[Dict]:
    """Layer 4: Downgrade or remove speculative gap findings."""
    console.print("Layer 4: Cross-examining gap findings for overreach...")
    if not gap_findings:
        console.print("[dim]  No gap findings from Layer 3 — nothing to validate.[/dim]")
        return []
    summary = {
        "tech_stack": repo_context.get("tech_stack", []),
        "risk_surface_summary": repo_context.get("risk_surface_summary", ""),
    }
    user_msg = f"""Review these AI-inferred compliance gap findings. For each one:
- If the observation is specific and grounded in code evidence: keep it, set "skeptic_verdict": "retained"
- If the observation is vague or speculative: lower confidence by 0.1 and set "skeptic_verdict": "downgraded"
- If the observation has no clear code basis: remove it entirely

Repository context for reference:
{json.dumps(summary, indent=2)}

Gap findings to review:
{json.dumps(gap_findings, indent=2)}

Return the filtered/modified array only."""
    tier4 = LLM_TIERS["layer4"]
    user_msg = user_msg[: tier4["context_limit"]]
    try:
        if GEMINI_API_KEY and genai is not None:
            raw = _call_claude_raw(SYSTEM_PROMPT_L4, user_msg, layer="layer4")
            if raw:
                raw_list = _extract_json(raw)
                if isinstance(raw_list, list):
                    validated_list = []
                    for g in raw_list:
                        v = _validate_skeptic_gap(g)
                        if v:
                            validated_list.append(v)
                    return validated_list
    except Exception:
        pass
    return gap_findings


def _layer4_rule_sanity_sweep(findings: List[Dict], repo_context: Dict) -> List[Dict]:
    """Sanity-check the top rule findings when Layer 3 produced no gaps."""
    if not findings:
        return findings
    candidates = [
        dict(f)
        for f in findings
        if (f.get("severity") or "").upper() in {"HIGH", "MEDIUM"}
    ]
    candidates.sort(
        key=lambda f: (
            -float(f.get("confidence") or f.get("llm_confidence") or 0.0),
            (f.get("severity") or "").upper() != "HIGH",
        )
    )
    candidates = candidates[:3]
    if not candidates:
        return findings
    summary = {
        "tech_stack": repo_context.get("tech_stack", []),
        "risk_surface_summary": repo_context.get("risk_surface_summary", ""),
    }
    user_msg = (
        "Review these high-confidence rule findings for false-positive risk. "
        "Downgrade only when framework conventions or repo architecture make the finding less certain.\n\n"
        f"Repository context:\n{json.dumps(summary, indent=2)}\n\n"
        f"Candidates:\n{json.dumps(candidates, indent=2)}\n"
    )
    tier4 = LLM_TIERS["layer4"]
    user_msg = user_msg[: tier4["context_limit"]]
    try:
        if GEMINI_API_KEY and genai is not None:
            raw = _call_claude_raw(
                SYSTEM_PROMPT_L4_RULE_SANITY, user_msg, layer="layer4"
            )
            raw_list = _extract_json(raw) if raw else []
            if not isinstance(raw_list, list):
                return findings
            adjustments = {}
            for item in raw_list:
                if not isinstance(item, dict):
                    continue
                rule = str(item.get("rule") or "")
                file_path = str(item.get("file") or "")
                if not rule or not file_path:
                    continue
                downgrade = max(0.0, min(0.15, float(item.get("downgrade_by", 0.0) or 0.0)))
                adjustments[(rule, file_path)] = {
                    "downgrade": downgrade,
                    "reason": str(item.get("reason") or ""),
                    "false_positive_risk": str(item.get("false_positive_risk") or "medium"),
                }
            if not adjustments:
                return findings
            out: List[Dict] = []
            for finding in findings:
                key = (str(finding.get("rule") or ""), str(finding.get("file") or ""))
                adj = adjustments.get(key)
                if not adj or adj["downgrade"] <= 0:
                    out.append(finding)
                    continue
                copy_f = dict(finding)
                old_conf = float(copy_f.get("confidence") or copy_f.get("llm_confidence") or 0.5)
                copy_f["confidence"] = round(max(0.0, old_conf - adj["downgrade"]), 2)
                copy_f["requires_human_validation"] = True
                if copy_f["confidence"] < 0.75:
                    copy_f["scorable"] = False
                evidence = copy_f.get("evidence")
                if not isinstance(evidence, dict):
                    evidence = {}
                    copy_f["evidence"] = evidence
                evidence["layer4_sanity"] = {
                    "reason": adj["reason"],
                    "false_positive_risk": adj["false_positive_risk"],
                    "downgrade_by": adj["downgrade"],
                }
                out.append(copy_f)
            return out
    except Exception:
        pass
    return findings


def _normalize_deep_review_section(section_text: str) -> str:
    raw = str(section_text or "").strip()
    if not raw:
        return ""
    mapped = score_section_key_from_dpdp(raw)
    if mapped:
        return mapped
    remapped = closest_valid_section(raw)
    if remapped:
        return remapped
    if is_valid_dpdp_section(raw):
        match = re.search(r"\bsection\s*\d+\b", raw, re.IGNORECASE)
        return match.group(0).title() if match else raw
    return "Advisory"


def _normalize_synthesis_sections(synthesis: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(synthesis, dict):
        return synthesis
    for key in ("cross_cutting_themes", "top_5_findings"):
        items = synthesis.get(key) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            raw = str(item.get("dpdp_section") or "")
            item["dpdp_section_raw"] = raw
            item["dpdp_section"] = _normalize_deep_review_section(raw)
    return synthesis


def _build_review_chunks(
    extracted: Dict,
    repo_files: List[Dict],
    changed_only: List[str] | None = None,
) -> Dict[str, str]:
    """
    Split repo into 5 logical chunks for parallel deep review.
    If changed_only is set, only include those file paths in effective_contents.
    """
    file_contents = extracted.get("_file_contents", {})
    path_to_display = extracted.get("path_to_display", {})

    if changed_only is not None:
        changed_set = set(changed_only)
        effective_contents = {
            p: c for p, c in file_contents.items() if p in changed_set
        }
    else:
        effective_contents = file_contents

    def _collect(paths: List[str], limit: int = 12000) -> str:
        parts = []
        budget = limit
        for path in paths:
            if path not in effective_contents:
                continue
            raw = effective_contents[path]
            if not raw or budget <= 0:
                continue
            content, redactions = redact(raw, path)
            if redactions:
                total = sum(r.get("count", 0) for r in redactions)
                console.print(
                    f"  [dim yellow]  Redacted {total} secret(s) from {path} (Layer 5)[/dim yellow]"
                )
            display = path_to_display.get(path, path)
            header = f"\n=== FILE: {_clean_template_path(display)} ===\n"
            space = budget - len(header) - 50
            if space <= 0:
                break
            parts.append(header + content[:space])
            budget -= len(header) + min(len(content), space)
        return "".join(parts)

    auth_files = extracted.get("auth_files", []) or []
    model_files = extracted.get("model_files", []) or []
    route_files = extracted.get("route_files", []) or []
    internal_routes = set(extracted.get("internal_route_files", []))
    user_facing_only_routes = [
        p for p in route_files
        if p not in internal_routes
    ]

    config_files = [
        f["path"]
        for f in repo_files
        if any(
            kw in f.get("path", "").lower()
            for kw in ["config", "settings", "env", ".env", "secrets", "constants"]
        )
        and f["path"] not in auth_files + model_files + route_files
    ][:8]

    third_party_paths = list(
        {s["file"] for s in extracted.get("third_party_imports", [])}
    )
    pii_extra = list(
        {
            p.get("file")
            for p in extracted.get("pii_fields", [])
            if p.get("file") not in auth_files + model_files + route_files
        }
    )[:5]
    pii_extra = [p for p in pii_extra if p]

    return {
        "Authentication & Session": _collect(auth_files),
        "Data Models & Storage": _collect(model_files[:8]),
        "API Routes & Controllers": _collect(user_facing_only_routes),
        "Third-Party & PII Flows": _collect(third_party_paths + pii_extra),
        "Configuration & Secrets": _collect(config_files),
    }


def _run_layer5_deep_review(
    findings: List[Dict],
    extracted: Dict,
    repo_files: List[Dict],
    repo_context: Dict,
    changed_files: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Layer 5 — Whole-repo (or delta) deep review.
    If changed_files is set, only those files are included in chunks (delta mode).
    """
    is_delta = changed_files is not None
    mode_label = (
        f"delta ({len(changed_files)} changed files)" if is_delta else "full repo"
    )
    console.print(f"[cyan]  Mode: {mode_label}[/cyan]")

    rules_summary = "\n".join(
        f"- {f['rule']} ({f['severity']}) in {f.get('display_path', f.get('file', 'N/A'))}"
        for f in findings
        if f.get("severity") in ("HIGH", "MEDIUM")
    ) or "None"

    chunks = _build_review_chunks(extracted, repo_files, changed_only=changed_files)
    active = {k: v for k, v in chunks.items() if v.strip()}

    if not active:
        console.print(
            "[yellow]  No changed files in any layer — skipping deep review[/yellow]"
        )
        return {
            "chunk_results": {},
            "synthesis": {},
            "total_findings": 0,
            "is_delta": is_delta,
            "skipped": True,
        }

    chunk_results: Dict[str, Any] = {}
    delta_note = (
        "\nNOTE: DELTA REVIEW — only changed files shown. "
        "Focus on what changed, not full architecture."
        if is_delta
        else ""
    )

    def _review_one(name: str, content: str) -> tuple:
        msg = (
            f"LAYER: {name}{delta_note}\n\n"
            f"ALREADY FOUND BY RULE ENGINE (do not repeat):\n{rules_summary}\n\n"
            f"CODE TO REVIEW:\n{content}"
        )
        raw = _call_claude_raw(SYSTEM_PROMPT_L5_CHUNK, msg, layer="layer5_chunk")
        if raw and os.getenv("DPDP_DEBUG"):
            console.print(f"[dim]Layer 5 {name} raw: {raw[:150]}[/dim]")
        result = _parse_json_safe(raw) if raw else {}
        if isinstance(result, dict) and ("findings" in result or "chunk_name" in result or "architectural_note" in result or "summary" in result or "layer_summary" in result):
            result.setdefault("chunk_name", name)
            result.setdefault("findings", [])
            result.setdefault("architectural_note", result.get("layer_summary") or result.get("summary", ""))
            return name, result
        # Parse failed — may be truncated; salvage already attempted inside _parse_json_safe
        if not result or not result.get("findings"):
            console.print(
                f"  [yellow]Layer 5 {name}: response may be truncated, attempting recovery...[/yellow]"
            )
            if not result:
                console.print(
                    f"  [yellow]Layer 5 {name}: could not parse response, "
                    "increase max_tokens if this persists[/yellow]"
                )
        note = (raw or "").strip()[:400] if raw else "No response."
        if len((raw or "").strip()) > 400:
            note += "..."
        return name, {
            "chunk_name": name,
            "findings": result.get("findings", []) if result else [],
            "architectural_note": result.get("layer_summary") or note if result else note,
        }

    console.print(f"[cyan]  Reviewing {len(active)} layer(s) concurrently...[/cyan]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(_review_one, n, c): n for n, c in active.items()
        }
        try:
            for future in concurrent.futures.as_completed(futures, timeout=120):
                name = futures[future]
                try:
                    _, result = future.result(timeout=30)
                    chunk_results[name] = result
                    raw_f = result.get("findings", []) if isinstance(result, dict) else []
                    count = len(raw_f) if isinstance(raw_f, list) else 0
                    console.print(f"  [green]✓[/green] {name}: {count} finding(s)")
                except concurrent.futures.TimeoutError:
                    console.print(f"  [yellow]⚠ {name} timed out[/yellow]")
                except Exception as e:
                    console.print(f"  [yellow]⚠ {name}: {e}[/yellow]")
        except concurrent.futures.TimeoutError:
            console.print(
                "[yellow]  Deep review overall timeout (120s) — continuing with partial results[/yellow]"
            )

    console.print("[cyan]  Synthesizing...[/cyan]")
    def _chunk_findings_list(r: Any) -> List[Dict]:
        raw = r.get("findings", []) if isinstance(r, dict) else []
        if not isinstance(raw, list):
            return []
        return [x for x in raw if isinstance(x, dict)]

    finding_lines = [
        f"[{cname}] {f.get('severity', '?')} — {f.get('title', '?')}: {(f.get('observation') or '')[:200]}"
        for cname, r in chunk_results.items()
        for f in _chunk_findings_list(r)
    ]
    arch_lines = [
        f"[{k}]: {v.get('architectural_note', '')}"
        for k, v in chunk_results.items()
    ]
    synth_msg = (
        f"REPO CONTEXT:\n"
        f"Tech stack: {', '.join(repo_context.get('tech_stack', []) or [])}\n"
        f"Risk surface: {repo_context.get('risk_surface_summary', 'N/A')}\n\n"
        f"CHUNK FINDINGS:\n{chr(10).join(finding_lines) or 'No findings.'}\n\n"
        f"ARCHITECTURAL NOTES:\n{chr(10).join(arch_lines)}"
    )
    context_limit = LLM_TIERS["layer5_synthesis"].get("context_limit", 15000)
    raw = _call_claude_raw(
        SYSTEM_PROMPT_L5_SYNTHESIS, synth_msg[:context_limit], layer="layer5_synthesis"
    )
    synthesis = _parse_json_safe(raw)
    # Normalize new synthesis format to reporter keys
    if synthesis:
        synthesis = _normalize_synthesis_sections(synthesis)
        synthesis.setdefault("overall_risk_level", synthesis.get("overall_risk"))
        synthesis.setdefault("risk_narrative", synthesis.get("summary", ""))
        synthesis.setdefault("single_most_important_fix", synthesis.get("critical_action", ""))
        days_min = synthesis.get("estimated_days_min")
        days_max = synthesis.get("estimated_days_max")
        if days_min is not None and days_max is not None:
            synthesis.setdefault("estimated_remediation_days", (days_min + days_max) // 2)
        elif days_min is not None or days_max is not None:
            synthesis.setdefault("estimated_remediation_days", days_max if days_max is not None else days_min)

    total = sum(len(_chunk_findings_list(r)) for r in chunk_results.values())
    return {
        "chunk_results": chunk_results,
        "synthesis": synthesis,
        "total_findings": total,
        "is_delta": is_delta,
        "skipped": False,
    }


def _layer6_validate_deep_review_findings(
    deep_review: Dict[str, Any] | None,
    extracted: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Validate Layer 5 findings and convert confirmed items into scored findings."""
    if not deep_review or deep_review.get("skipped"):
        return []
    chunk_results = deep_review.get("chunk_results") or {}
    candidates: List[Dict[str, Any]] = []
    for chunk in chunk_results.values():
        raw = chunk.get("findings", []) if isinstance(chunk, dict) else []
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, dict):
                candidates.append(item)
    if not candidates:
        return []

    candidates = candidates[:30]
    file_contents = extracted.get("_file_contents", {}) or {}
    indexed_files = set(file_contents.keys())
    context_items = []
    for c in candidates:
        fpath = str(c.get("file") or "N/A")
        code = file_contents.get(fpath, "") if fpath != "N/A" else ""
        context_items.append(
            {
                "candidate": c,
                "code_excerpt": (code[:800] if code else ""),
            }
        )

    payload = {"candidates": context_items}
    raw = _call_llm_raw(
        SYSTEM_PROMPT_L6_VALIDATE,
        json.dumps(payload),
        layer="layer6_validate",
    )
    parsed = _parse_json_safe(raw) if raw else {}
    validated = parsed.get("validated_findings", []) if isinstance(parsed, dict) else []
    if not isinstance(validated, list):
        return []

    out: List[Dict[str, Any]] = []
    dropped_invalid_sections = 0
    for v in validated:
        if not isinstance(v, dict):
            continue
        if not bool(v.get("valid")):
            continue
        conf = float(v.get("confidence", 0.0) or 0.0)
        if conf < 0.75:
            continue
        raw_section = str(v.get("dpdp_section") or "").strip()
        mapped_section = score_section_key_from_dpdp(raw_section)
        scorable = True
        if not mapped_section:
            remapped = closest_valid_section(raw_section)
            if remapped and score_section_key_from_dpdp(remapped):
                mapped_section = score_section_key_from_dpdp(remapped)
            elif not is_valid_dpdp_section(raw_section):
                dropped_invalid_sections += 1
                continue
            else:
                mapped_section = raw_section or "Advisory"
                scorable = False
        file_path = str(v.get("file") or "N/A")
        if file_path != "N/A" and file_path not in indexed_files:
            scorable = False
        justification = str(v.get("justification") or "")
        observation = str(v.get("observation") or v.get("title") or "").strip()
        if file_path != "N/A":
            code_excerpt = file_contents.get(file_path, "")
            if not code_excerpt.strip():
                continue
        if not observation:
            continue
        out.append(
            {
                "rule": "DEEP_REVIEW_VALIDATED",
                "dpdp_section": mapped_section,
                "severity": str(v.get("severity") or "MEDIUM").upper(),
                "file": file_path,
                "description": observation,
                "confidence": max(0.0, min(1.0, conf)),
                "scorable": scorable,
                "evidence": {
                    "layer": "layer6",
                    "title": str(v.get("title") or ""),
                    "justification": justification,
                    "dpdp_section_raw": raw_section,
                },
                "llm_enrichment": "deep_validated",
            }
        )

    # Remove near-duplicates (same file + section + normalized description).
    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for f in out:
        base = " ".join((f.get("description") or "").lower().split())
        fp = f"{f.get('file','')}|{f.get('dpdp_section','')}|{base[:220]}"
        key = hashlib.sha1(fp.encode("utf-8")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    deep_review["layer6_dropped_invalid_sections"] = dropped_invalid_sections
    return deduped


def run_route_classification(
    extracted: dict,
    repo_files: list,
) -> dict:
    """
    Standalone Layer 1b — LLM route classification.
    Runs BEFORE the rule engine so rules have accurate
    internal/user-facing route signals.

    Updates extracted in-place:
      - extracted['route_intent_map']
      - extracted['user_facing_route_files']
      - extracted['internal_route_files']
      - extracted['route_classification_detail']

    Returns the updated extracted dict.
    """
    tier = LLM_TIERS["layer1"]
    model = tier["model"]

    console.print("\n[bold cyan]🗺  Route Classification[/bold cyan]")
    try:
        llm_classifications = _classify_routes_with_llm(
            extracted, repo_files, model
        )
        regex_intent_map = extracted.get("route_intent_map", {})
        merged = _merge_route_classifications(
            regex_intent_map, llm_classifications
        )

        extracted["route_intent_map"] = {
            p: v["intent"] for p, v in merged.items()
        }
        extracted["route_classification_detail"] = merged
        extracted["user_facing_route_files"] = [
            p for p, v in merged.items()
            if v["intent"] == "user_facing"
        ]
        extracted["internal_route_files"] = [
            p for p, v in merged.items()
            if v["intent"] == "internal"
        ]

        internal_count = len(extracted["internal_route_files"])
        user_facing_count = len(extracted["user_facing_route_files"])
        total_routes = len(extracted.get("route_files", []))
        console.print(
            f"  [green]✓[/green] {total_routes} routes: "
            f"[red]{user_facing_count} user-facing[/red], "
            f"[blue]{internal_count} internal[/blue]"
        )
        for path in extracted["internal_route_files"][:5]:
            detail = merged.get(path, {})
            console.print(
                f"  [dim]  INTERNAL ({detail.get('confidence', 0):.0%}): "
                f"{path.split('/')[-1]} — "
                f"{detail.get('reason', '')[:70]}[/dim]"
            )
        if internal_count > 5:
            console.print(
                f"  [dim]  ... and {internal_count - 5} more[/dim]"
            )
    except Exception as e:
        console.print(
            f"[yellow]  ⚠ Route classification failed: {e} "
            f"— using regex only[/yellow]"
        )

    return extracted


def run_llm_pipeline(
    findings: List[Dict],
    extracted: Dict,
    repo_files: List[Dict],
    fast: bool = False,
    quality: bool = False,
    changed_files: List[str] | None = None,
    skip_deep_review: bool = False,
) -> Dict[str, Any]:
    """
    Layers 1, 2, 3, 4, 5, 6.
    NOTE: Route classification (formerly Layer 1b) has already run
    before this function is called — extracted already has accurate
    internal_route_files. Do NOT re-run it here.
    changed_files: if set, Layer 5 runs in delta mode (only changed files).
    Returns enriched_findings, gap_findings, repo_context, deep_review, pipeline_metadata.
    """
    if not GEMINI_API_KEY:
        console.print("[yellow]Warning: No API keys configured. Skipping LLM pipeline.[/yellow]")
        return {
            "enriched_findings": findings,
            "gap_findings": [],
            "repo_context": {},
            "pipeline_metadata": {"layers": {}, "total_time": 0},
            "deep_review": None,
        }
    is_micro = bool(extracted.get("is_micro_app", False))
    metadata: Dict[str, Any] = {"layers": {}, "total_time": 0, "micro_app": is_micro}
    start = time.time()

    t = time.time()
    repo_context = _layer1_repo_summary(repo_files, extracted)
    metadata["layers"]["layer1"] = {"success": "error" not in repo_context, "time": round(time.time() - t, 2)}

    t = time.time()
    enriched = _layer2_enrich_findings(findings, repo_context, extracted, repo_files)
    metadata["layers"]["layer2"] = {"success": True, "time": round(time.time() - t, 2)}

    t = time.time()
    gap_findings = _layer3_gap_analysis(repo_context, enriched, extracted=extracted)
    metadata["layers"]["layer3"] = {"success": isinstance(gap_findings, list), "time": round(time.time() - t, 2)}

    t = time.time()
    if is_micro:
        console.print(
            "\n[dim]Layer 4 — Skeptic pass skipped (micro app < 15 files)[/dim]"
        )
        metadata["layers"]["layer4"] = {
            "success": True,
            "time": 0.0,
            "skipped": "micro_app",
        }
    else:
        gap_findings = _layer4_skeptic(gap_findings, repo_context)
        if not gap_findings:
            enriched = _layer4_rule_sanity_sweep(enriched, repo_context)
        metadata["layers"]["layer4"] = {"success": True, "time": round(time.time() - t, 2)}

    deep_review_result = None
    if skip_deep_review:
        console.print("\n[dim]Layer 5 — Deep review skipped (--no-deep-review)[/dim]")
        deep_review_result = {"skipped": True, "total_findings": 0}
    elif is_micro:
        console.print(
            "\n[dim]Layer 5 — Deep review skipped (micro app < 15 files)[/dim]"
        )
        deep_review_result = {
            "overall_risk": "N/A",
            "findings": [],
            "skipped": "micro_app",
            "total_findings": 0,
        }
    else:
        console.print("\n[bold cyan]🔬 Layer 5 — Deep Compliance Review[/bold cyan]")
        try:
            deep_review_result = _run_layer5_deep_review(
                enriched, extracted, repo_files, repo_context,
                changed_files=changed_files,
            )
            if not deep_review_result.get("skipped"):
                console.print(
                    f"[green]✓ Deep review: {deep_review_result['total_findings']} additional finding(s)[/green]"
                )
        except Exception as e:
            console.print(f"[yellow]⚠ Deep review failed: {e}[/yellow]")

    t = time.time()
    layer6_findings = _layer6_validate_deep_review_findings(
        deep_review_result, extracted
    )
    if layer6_findings:
        enriched = enriched + layer6_findings
        console.print(
            f"[green]✓ Layer 6 validation: {len(layer6_findings)} confirmed deep-review finding(s)[/green]"
        )
    else:
        console.print("[dim]Layer 6 — No deep-review findings validated[/dim]")
    metadata["layers"]["layer6"] = {
        "success": True,
        "time": round(time.time() - t, 2),
        "validated_findings": len(layer6_findings),
    }

    metadata["total_time"] = round(time.time() - start, 2)
    console.print(f"\n[bold]Pipeline complete in {metadata['total_time']}s[/bold]")
    for layer, data in metadata["layers"].items():
        status = "[OK]" if data["success"] else "[FAIL]"
        console.print(f"  {status} {layer}: {data['time']}s")

    return {
        "enriched_findings": enriched,
        "gap_findings": gap_findings,
        "repo_context": repo_context,
        "deep_review": deep_review_result,
        "pipeline_metadata": metadata,
    }


def enrich_findings(findings: List[Dict], extracted: Dict) -> List[Dict]:
    """Backward-compat: run pipeline with no repo files and return enriched findings only."""
    result = run_llm_pipeline(findings, extracted, [])
    return result["enriched_findings"]


if __name__ == "__main__":
    import sys
    _repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

    test_findings: List[Dict] = [
        {
            "rule": "CONSENT_MISSING",
            "dpdp_section": "Section 6 — Consent",
            "severity": "HIGH",
            "file": "api/users.py",
            "evidence": {
                "pii_fields": [
                    {"line_number": 12, "pattern_matched": "email", "line_content": "user_email = request.data['email']"},
                ],
                "endpoints": [{"line_number": 8, "route": "/signup", "method": "POST"}],
                "libraries": [],
            },
            "description": "Personal data collected in API endpoint with no detectable consent mechanism.",
            "fix": None,
        }
    ]
    result = run_llm_pipeline(test_findings, {}, [])
    print(json.dumps(result["enriched_findings"][0], indent=2))

