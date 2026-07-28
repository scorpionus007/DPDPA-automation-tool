"""
Data flow rules — PII flow from sources to sinks.

Uses pii_flow_graph from extractor to find paths from collection points to
**analytics**, **marketing**, and **error/logging** sinks. Flows whose sink is
**cloud_storage** or **payment_processor** are intentionally not emitted here
as cross-border findings — Section 16 for foreign cloud / regions is handled by
cross_border.py to avoid duplicate PII_FLOW_CROSS_BORDER vs CROSS_BORDER_TRANSFER_RISK.

Enhanced with:
- Symbol-level PII tracking (field->arg continuity)
- Regex-based taint propagation across flow paths
- Consent-near-sink proximity detection
- FK/relationship graph for entity-aware deletion coverage
- ML-based flow validity classification
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Set, Tuple

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:
    genai = None  # type: ignore[assignment]
    genai_types = None  # type: ignore[assignment]

from dpdp_scanner.flow.symbol_tracker import compute_symbol_evidence
from dpdp_scanner.flow.taint_tracker import trace_taint_across_path
from dpdp_scanner.flow.consent_proximity import has_consent_near_sink, consent_proximity_score
from dpdp_scanner.flow.fk_graph import build_fk_graph, deletion_must_cover
from dpdp_scanner.flow.ml_classifier import classify_flow, build_feature_vector


GEMINI_API_KEY = (
    os.getenv("GEMINI_API_KEY", "").strip()
    or os.getenv("GOOGLE_AI_API_KEY", "").strip()
    or None
)
FLOW_VERIFY_MODEL = "gemini-2.5-flash-lite"
FLOW_VERIFY_MAX = max(0, int(os.getenv("DPDP_FLOW_VERIFY_MAX", "4")))


def _short_path(path: str) -> str:
    """Short display path (last two segments or filename)."""
    if not path:
        return "N/A"
    parts = path.replace("\\", "/").split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]


INFRASTRUCTURE_INTERMEDIATE_PATTERNS = [
    r"/router\.(ts|js|py|rb)$",
    r"/routes\.(ts|js|py|rb)$",
    r"/files\.(ts|js)$",
    r"/put-file\.(ts|js)$",
    r"/implementation\.(ts|js)$",
    r"/context\.(ts|js)$",
    r"/hono\.(ts|js)$",
]

UTILITY_INTERMEDIATE_PATTERNS = [
    r"/utils?/",
    r"/helpers?/",
    r"/lib/",
    r"/shared/",
]

ACTION_ENTITY_PREFIXES = (
    "create_",
    "update_",
    "delete_",
    "accept_",
    "reject_",
    "complete_",
    "cancel_",
    "send_",
    "process_",
    "sync_",
    "verify_",
    "create-",
    "update-",
    "delete-",
    "accept-",
    "reject-",
    "complete-",
    "cancel-",
    "send-",
    "process-",
    "sync-",
    "verify-",
)


def _is_reexport_only(content: str) -> bool:
    lines = [line.strip() for line in (content or "").splitlines() if line.strip()]
    if not lines:
        return False
    meaningful = [
        line for line in lines
        if not line.startswith(("//", "#", "/*", "*", "<!--"))
    ]
    return bool(meaningful) and all(
        line.startswith(("import ", "export ", "from "))
        for line in meaningful[:20]
    )


def _classify_intermediate(path: str, content: str) -> str:
    path_norm = (path or "").replace("\\", "/").lower()
    base = path_norm.split("/")[-1]
    if any(re.search(pattern, path_norm, re.IGNORECASE) for pattern in INFRASTRUCTURE_INTERMEDIATE_PATTERNS):
        return "infrastructure"
    if base == "index.ts" and _is_reexport_only(content):
        return "infrastructure"
    if any(re.search(pattern, path_norm, re.IGNORECASE) for pattern in UTILITY_INTERMEDIATE_PATTERNS):
        return "util"
    if re.search(r"/(services?|controllers?|routes?|trpc|server-only|api)/", path_norm):
        return "business_logic"
    return "unknown"


def _compute_flow_confidence(fp: Dict, extracted: Dict) -> float:
    """
    Multi-signal confidence score for a flow (0.0–1.0).

    Combines:
    - Structural evidence (path/sink/hop)
    - Symbol-level PII tracking (field→arg continuity)
    - Taint propagation analysis
    - Consent proximity (reduces violation confidence)
    - ML classifier adjudication
    """
    source = str(fp.get("source") or "")
    sink = str(fp.get("sink") or "")
    path = fp.get("path", []) or []
    pii_fields = {str(x).lower() for x in (fp.get("pii_fields") or [])}
    sink_type = str(fp.get("sink_type") or "")
    hop_count = int(fp.get("hop_count", 0) or 0)
    file_contents = extracted.get("_file_contents", {}) or {}

    # ── 1. Structural baseline ──────────────────────────────────
    structural = 0.0
    if source and sink and source != sink and path:
        structural += 0.30
    elif source and sink and source != sink:
        structural += 0.15

    if sink_type in {"analytics", "marketing_email", "error_logging"}:
        structural += 0.15

    if hop_count <= 2:
        structural += 0.10
    elif hop_count <= 4:
        structural += 0.07
    else:
        structural += 0.03

    sensitive = {"email", "phone", "aadhaar", "aadhar", "pan", "mobile", "name", "password"}
    if pii_fields & sensitive:
        structural += 0.08
    elif pii_fields:
        structural += 0.04

    sink_content = file_contents.get(sink, "") if sink else ""
    if sink_content:
        if sink_type == "analytics" and re.search(
            r"\.track\s*\(|\.identify\s*\(|analytics\.\w+\s*\(|mixpanel\.\w+\s*\(|segment\.\w+\s*\(|amplitude\.\w+\s*\(|posthog\.\w+\s*\(",
            sink_content, re.IGNORECASE,
        ):
            structural += 0.08
        elif sink_type == "marketing_email" and re.search(
            r"mailchimp|sendgrid|ses|postmark|customerio|braze|campaign",
            sink_content, re.IGNORECASE,
        ):
            structural += 0.08
        elif sink_type == "error_logging" and re.search(
            r"sentry|logger\.(info|warn|error|debug)|console\.(log|error|warn)",
            sink_content, re.IGNORECASE,
        ):
            structural += 0.08

    if len(path) >= 3:
        structural += 0.06

    # ── 2. Symbol-level tracking ─────────────────────────────────
    symbol_ev = compute_symbol_evidence(fp, file_contents)
    symbol_score = symbol_ev.get("symbol_continuity_score", 0.0)

    # ── 3. Taint propagation ─────────────────────────────────────
    taint_result = trace_taint_across_path(path, file_contents, pii_fields or None)
    taint_score = taint_result.get("confidence", 0.0)

    intermediate_nodes = path[1:-1] if len(path) > 2 else []
    intermediate_kinds = [
        _classify_intermediate(node, file_contents.get(node, ""))
        for node in intermediate_nodes
    ]
    infrastructure_intermediates = sum(1 for kind in intermediate_kinds if kind == "infrastructure")

    # ── 4. Consent proximity (reduces violation probability) ─────
    consent_prox = consent_proximity_score(sink_content, sink_type)

    # ── 5. Weighted combination ──────────────────────────────────
    combined = (
        0.35 * structural
        + 0.25 * symbol_score
        + 0.20 * taint_score
        + 0.20 * (1.0 - consent_prox)  # no consent = higher violation confidence
    )

    # ── 6. ML classifier adjudication ────────────────────────────
    ml_evidence = {
        "symbol_continuity_score": symbol_score,
        "taint_reached_sink": taint_result.get("reached_sink", False),
        "taint_confidence": taint_score,
        "taint_total_events": taint_result.get("total_events", 0),
        "consent_found_at_sink": consent_prox > 0,
        "consent_purpose_specific": consent_prox >= 0.7,
        "consent_proximity_score": consent_prox,
        "hop_count": hop_count,
        "sink_type": sink_type,
        "pii_field_count": len(pii_fields),
        "path_length": len(path),
        "sink_call_arg_pii_count": len(symbol_ev.get("sink_call_arg_pii", [])),
    }
    ml_result = classify_flow(ml_evidence)
    ml_prob = ml_result.get("ml_confidence", 0.5)

    # Blend: 60% multi-signal, 40% ML
    final = 0.60 * combined + 0.40 * ml_prob
    quality_penalty = 0.0
    quality_gate_suppressed = False
    if (
        hop_count >= 4
        and infrastructure_intermediates >= 2
        and symbol_score < 0.5
        and taint_score < 0.4
    ):
        quality_penalty = 0.30
        final = max(0.0, final - quality_penalty)
        quality_gate_suppressed = final < 0.45

    # Store evidence on the flow path for downstream use
    fp["_flow_evidence"] = {
        "structural": round(structural, 3),
        "structural_score": round(structural, 3),
        "symbol_score": round(symbol_score, 3),
        "symbol_tracking_score": round(symbol_score, 3),
        "taint_score": round(taint_score, 3),
        "taint_analysis_score": round(taint_score, 3),
        "consent_proximity": round(consent_prox, 3),
        "ml_confidence": round(ml_prob, 3),
        "ml_classifier": ml_result.get("classifier_type", ""),
        "combined": round(combined, 3),
        "final": round(final, 3),
        "quality_penalty": round(quality_penalty, 3),
        "quality_gate_suppressed": quality_gate_suppressed,
        "infrastructure_intermediates": infrastructure_intermediates,
        "intermediate_kinds": intermediate_kinds[:8],
        "taint_reached_sink": taint_result.get("reached_sink", False),
        "symbol_at_sink": symbol_ev.get("sink_call_arg_pii", []),
    }

    return max(0.0, min(1.0, round(final, 2)))


def _flow_is_scorable(confidence: float) -> bool:
    """Only high-confidence flows should directly affect scoring."""
    return confidence >= 0.75


PURPOSE_KEYWORDS = {
    "auth": [
        r"login", r"signup", r"auth", r"session", r"password", r"token", r"oauth",
    ],
    "profile": [
        r"profile", r"account", r"user", r"settings", r"me/",
    ],
    "analytics": [
        r"analytics", r"segment", r"mixpanel", r"amplitude", r"posthog", r"track", r"telemetry",
    ],
    "marketing": [
        r"marketing", r"campaign", r"mailchimp", r"sendgrid", r"braze", r"customerio", r"newsletter",
    ],
    "logging": [
        r"sentry", r"log", r"logger", r"error", r"monitor", r"trace",
    ],
}


def _infer_purpose_from_path_and_content(path: str, content: str) -> str:
    blob = f"{path or ''}\n{content or ''}".lower()
    for purpose, pats in PURPOSE_KEYWORDS.items():
        for p in pats:
            if re.search(p, blob, re.IGNORECASE):
                return purpose
    return "unknown"


def _check_purpose_mismatch(
    fp: Dict,
    extracted: Dict,
    findings: List[Dict],
    seen_keys: Set[str],
) -> None:
    """
    Flag likely purpose drift when source and sink purposes differ materially.
    This is advisory unless confidence is very high.
    """
    source = str(fp.get("source") or "")
    sink = str(fp.get("sink") or "")
    if not source or not sink:
        return
    file_contents = extracted.get("_file_contents", {}) or {}
    source_purpose = _infer_purpose_from_path_and_content(source, file_contents.get(source, ""))
    sink_purpose = _infer_purpose_from_path_and_content(sink, file_contents.get(sink, ""))
    if source_purpose in {"unknown", "logging"}:
        return
    if sink_purpose in {"unknown", "logging"}:
        return
    if source_purpose == sink_purpose:
        return
    # Only meaningful for analytics/marketing receiving data from auth/profile flows.
    if sink_purpose not in {"analytics", "marketing"}:
        return
    if source_purpose not in {"auth", "profile"}:
        return

    flow_confidence = _compute_flow_confidence(fp, extracted)
    if flow_confidence < 0.45:
        return
    key = f"{source}->{sink}:{source_purpose}->{sink_purpose}"
    if key in seen_keys:
        return
    seen_keys.add(key)

    severity = "MEDIUM" if flow_confidence < 0.85 else "HIGH"
    findings.append(
        {
            "rule": "PII_FLOW_PURPOSE_MISMATCH",
            "dpdp_section": "Section 5 — Purpose Limitation",
            "severity": severity,
            "confidence": flow_confidence,
            "file": sink,
            "display_path": _short_path(sink),
            "description": (
                f"PII appears to flow from {source_purpose} context "
                f"({_short_path(source)}) into {sink_purpose} processing "
                f"({_short_path(sink)}). Verify legal basis and purpose-specific notice/consent."
            ),
            "evidence": {
                "flow_path": fp.get("path", []),
                "source_purpose": source_purpose,
                "sink_purpose": sink_purpose,
                "sink_type": fp.get("sink_type", ""),
                "flow_confidence": flow_confidence,
            },
            "fix": [
                "Document explicit purpose for this transfer in privacy notice.",
                "Require purpose-specific consent before analytics/marketing transfer.",
                "Apply data minimization: send only fields strictly needed for that purpose.",
            ],
            "requires_human_validation": flow_confidence < 0.85,
            "scorable": flow_confidence >= 0.85,
        }
    )


def _verify_ambiguous_flow_finding(finding: Dict, extracted: Dict) -> Dict[str, Any]:
    """
    LLM verifier for ambiguous flow findings.
    Returns dict: {"verdict": confirmed|rejected|uncertain, "confidence": float, "reason": str}
    """
    if genai is None or genai_types is None or not GEMINI_API_KEY:
        return {"verdict": "uncertain", "confidence": 0.0, "reason": "llm_unavailable"}
    ev = finding.get("evidence") or {}
    flow_path = ev.get("flow_path", []) if isinstance(ev, dict) else []
    sink = finding.get("file") or "N/A"
    sink_content = ((extracted.get("_file_contents") or {}).get(sink, "") if sink != "N/A" else "")[:900]
    payload = {
        "rule": finding.get("rule"),
        "section": finding.get("dpdp_section"),
        "severity": finding.get("severity"),
        "description": finding.get("description"),
        "sink_type": ev.get("sink_type") if isinstance(ev, dict) else "",
        "flow_path": flow_path,
        "pii_fields": ev.get("pii_fields", []) if isinstance(ev, dict) else [],
        "sink_excerpt": sink_content,
    }
    system = (
        "You are a strict static-analysis verifier for privacy findings. "
        "Given one candidate finding and code context, decide if it is supported."
    )
    user = (
        "Return ONLY JSON:\n"
        '{"verdict":"confirmed|rejected|uncertain","confidence":0.0,"reason":"short"}\n'
        "Use confirmed only with direct evidence. Use rejected if evidence contradicts.\n\n"
        f"INPUT:\n{json.dumps(payload)}"
    )
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        cfg = genai_types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.0,
            max_output_tokens=512,
        )
        resp = client.models.generate_content(
            model=FLOW_VERIFY_MODEL,
            contents=user,
            config=cfg,
        )
        txt = (resp.text or "").strip() if resp else ""
        if not txt:
            return {"verdict": "uncertain", "confidence": 0.0, "reason": "empty_response"}
        try:
            parsed = json.loads(txt)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", txt, re.DOTALL)
            if not m:
                return {"verdict": "uncertain", "confidence": 0.0, "reason": "json_parse_failed"}
            parsed = json.loads(m.group(0))
        verdict = str(parsed.get("verdict") or "uncertain").lower()
        conf = float(parsed.get("confidence", 0.0) or 0.0)
        if verdict not in {"confirmed", "rejected", "uncertain"}:
            verdict = "uncertain"
        return {
            "verdict": verdict,
            "confidence": max(0.0, min(1.0, conf)),
            "reason": str(parsed.get("reason") or ""),
        }
    except Exception:
        return {"verdict": "uncertain", "confidence": 0.0, "reason": "llm_error"}


def _verify_ambiguous_flow_findings(findings: List[Dict], extracted: Dict) -> List[Dict]:
    """Run verifier on medium-confidence flow findings only and adjust scorable/severity."""
    if FLOW_VERIFY_MAX <= 0:
        return findings
    out: List[Dict] = []
    remaining = FLOW_VERIFY_MAX
    flow_rules = {
        "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT",
        "PII_FLOW_TO_MARKETING_WITHOUT_CONSENT",
        "PII_FLOW_TO_LOGGING",
    }
    for f in findings:
        conf = float(f.get("confidence", 0.0) or 0.0)
        if (
            f.get("rule") in flow_rules
            and 0.45 <= conf < 0.75
            and remaining > 0
        ):
            remaining -= 1
            verdict = _verify_ambiguous_flow_finding(f, extracted)
            f.setdefault("evidence", {})
            f["evidence"]["verifier"] = verdict
            if verdict["verdict"] == "rejected":
                # Drop rejected ambiguous findings.
                continue
            if verdict["verdict"] == "confirmed" and verdict["confidence"] >= 0.8:
                f["confidence"] = max(conf, verdict["confidence"])
                f["severity"] = "HIGH" if verdict["confidence"] >= 0.9 else f.get("severity", "MEDIUM")
                f["scorable"] = True
                f["requires_human_validation"] = False
            else:
                f["scorable"] = False
                f["requires_human_validation"] = True
            out.append(f)
        else:
            out.append(f)
    return out


def _has_analytics_consent_check(path_set: Set[str], extracted: Dict, sink_content: str = "", sink_type: str = "") -> bool:
    """
    True if analytics/tracking consent exists — checked at three levels:
    1. Same function as sink call (strongest)
    2. Same module as sink
    3. Anywhere on the flow path (weakest)
    """
    if sink_content:
        near_sink = has_consent_near_sink(sink_content, sink_type or "analytics")
        if near_sink.get("found") and near_sink.get("purpose_specific"):
            return True
        if near_sink.get("found") and near_sink.get("proximity") == "same_function":
            return True

    consent_signals = extracted.get("consent_signals", []) or []
    for s in consent_signals:
        if s.get("file") not in path_set:
            continue
        line = (s.get("line_content") or s.get("line_content", "")) or ""
        if re.search(
            r"analytics|segment|amplitude|mixpanel|tracking|profiling|consent.*track",
            line,
            re.IGNORECASE,
        ):
            return True
    return False


def _check_analytics_consent(
    fp: Dict,
    extracted: Dict,
    findings: List[Dict],
) -> None:
    """PII flowing to analytics SDK without analytics-specific consent."""
    path_set = set(fp.get("path", []))
    flow_confidence = _compute_flow_confidence(fp, extracted)
    file_contents = extracted.get("_file_contents", {}) or {}
    sink_content = file_contents.get(fp.get("sink", ""), "")
    if _has_analytics_consent_check(path_set, extracted, sink_content, "analytics"):
        return
    if flow_confidence < 0.45:
        return
    severity = "HIGH" if flow_confidence >= 0.75 else "MEDIUM"
    findings.append({
        "rule": "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT",
        "dpdp_section": "Section 6 — Consent / Section 5 — Purpose Limitation",
        "severity": severity,
        "confidence": flow_confidence,
        "file": fp.get("sink", "N/A"),
        "display_path": _short_path(fp.get("sink", "")),
        "description": (
            f"PII flows from {_short_path(fp.get('source', ''))} "
            f"to analytics service ({_short_path(fp.get('sink', ''))}) "
            f"through {fp.get('hop_count', 0)} intermediate file(s). "
            "No analytics-specific consent detected on this flow path. "
            "DPDP Section 6 requires explicit consent for analytics "
            "processing separate from functional/auth consent."
        ),
        "evidence": {
            "flow_path": fp.get("path", []),
            "pii_fields": fp.get("pii_fields", []),
            "sink_type": fp.get("sink_type", ""),
            "hop_count": fp.get("hop_count", 0),
            "flow_confidence": flow_confidence,
            "flow_evidence": fp.get("_flow_evidence", {}),
        },
        "fix": [
            f"Add analytics consent checkbox at {_short_path(fp.get('source', ''))} "
            "before user data is collected.",
            "Store analytics consent separately from auth consent "
            "in your consent table with purpose='analytics'.",
            f"Check analytics consent in {_short_path(fp.get('sink', ''))} "
            "before calling the analytics SDK.",
            "If analytics is essential, disclose it in your privacy notice "
            "under Section 5 and obtain consent under Section 6.",
        ],
        "requires_human_validation": flow_confidence < 0.75,
        "scorable": _flow_is_scorable(flow_confidence),
    })


def _check_marketing_consent(
    fp: Dict,
    extracted: Dict,
    findings: List[Dict],
) -> None:
    """PII flowing to marketing email platform without consent."""
    flow_confidence = _compute_flow_confidence(fp, extracted)
    file_contents = extracted.get("_file_contents", {}) or {}
    sink_content = file_contents.get(fp.get("sink", ""), "")
    if sink_content:
        near_sink = has_consent_near_sink(sink_content, "marketing")
        if near_sink.get("found") and (near_sink.get("purpose_specific") or near_sink.get("proximity") == "same_function"):
            return
    consent_files = {s["file"] for s in (extracted.get("consent_signals") or []) if s.get("file")}
    path_set = set(fp.get("path", []))
    if path_set & consent_files:
        return
    if flow_confidence < 0.45:
        return
    severity = "HIGH" if flow_confidence >= 0.75 else "MEDIUM"
    findings.append({
        "rule": "PII_FLOW_TO_MARKETING_WITHOUT_CONSENT",
        "dpdp_section": "Section 6 — Consent",
        "severity": severity,
        "confidence": flow_confidence,
        "file": fp.get("sink", "N/A"),
        "display_path": _short_path(fp.get("sink", "")),
        "description": (
            f"PII flows from {_short_path(fp.get('source', ''))} "
            f"to marketing platform ({_short_path(fp.get('sink', ''))}) "
            f"without consent on this flow path."
        ),
        "evidence": {
            "flow_path": fp.get("path", []),
            "sink_type": fp.get("sink_type", ""),
            "flow_confidence": flow_confidence,
            "flow_evidence": fp.get("_flow_evidence", {}),
        },
        "fix": [
            "Obtain marketing consent before sending PII to the marketing platform.",
            "Store marketing consent with purpose='marketing' and check before sync.",
        ],
        "requires_human_validation": flow_confidence < 0.75,
        "scorable": _flow_is_scorable(flow_confidence),
    })


def _check_logging_pii(
    fp: Dict,
    extracted: Dict,
    findings: List[Dict],
) -> None:
    """PII flows to error/logging service — risk of plaintext in logs."""
    flow_confidence = _compute_flow_confidence(fp, extracted)
    if flow_confidence < 0.45:
        return
    severity = "MEDIUM" if flow_confidence < 0.75 else "HIGH"
    findings.append({
        "rule": "PII_FLOW_TO_LOGGING",
        "dpdp_section": "Section 8(1) — Security",
        "severity": severity,
        "confidence": flow_confidence,
        "file": fp.get("sink", "N/A"),
        "display_path": _short_path(fp.get("sink", "")),
        "description": (
            f"PII flows from {_short_path(fp.get('source', ''))} to error/logging service "
            f"({_short_path(fp.get('sink', ''))}). Ensure PII is redacted or hashed in logs."
        ),
        "evidence": {
            "flow_path": fp.get("path", []),
            "sink_type": fp.get("sink_type", ""),
            "flow_confidence": flow_confidence,
            "flow_evidence": fp.get("_flow_evidence", {}),
        },
        "fix": [
            "Redact or hash PII before passing to logging/error reporting.",
            "Use structured logging with PII fields excluded or tokenized.",
        ],
        "requires_human_validation": flow_confidence < 0.75,
        "scorable": _flow_is_scorable(flow_confidence),
    })


NOT_A_TABLE = [
    r"components/",
    r"\.tsx$",
    r"\.jsx$",
    r"hooks/",
    r"helpers/",
    r"utils/",
    r"services/",
    r"pages/",
    r"app/",
    r"public/",
    r"styles/",
    r"assets/",
    r"mobile-header",
    r"activity-block",
    r"forgot-password",
    r"label-select",
    r"popover",
    r"modal",
    r"sidebar",
    r"header",
    r"footer",
    r"layout",
]

NOT_A_TABLE_ADDITIONAL = [
    r"urls/schema\.py$",
    r"openapi",
    r"dummy_data",
    r"create_dummy",
    r"fixtures/",
    r"seeds/",
    r"factories/",
    r"schema\.py$",
    r"urls\.py$",
    r"admin\.py$",
    r"apps\.py$",
    r"signals\.py$",
    r"celery\.py$",
    r"wsgi\.py$",
    r"asgi\.py$",
    r"packages/constants/",
    r"constants/src/",
    r"management/commands/",
    r"reset_password\.py$",
    r"activate_user\.py$",
    # API schema / type definitions (not storage)
    r"schema\.(ts|tsx|js|py)$",
    r"schemas\.(ts|tsx|js|py)$",
    r"schema/",
    r"schemas/",
    r"types\.(ts|tsx)$",
    r"interfaces?\.(ts|tsx)$",
    r"enums?\.(ts|tsx)$",
    r"\.types\.(ts|tsx)$",
    r"create[_\-].*\.types\.ts$",
    # Middleware / auth
    r"middleware\.(ts|js|py|rb)$",
    r"authenticated\.(ts|js)$",
    r"authorizer\.(ts|js)$",
    r"authorize\.(ts|js)$",
    r"auth[_\-]?middleware\.(ts|js)$",
    r"session[_\-]?middleware\.(ts|js)$",
    # API framework files
    r"implementation\.(ts|js)$",
    r"context\.(ts|js)$",
    r"router\.(ts|js)$",
    r"routes\.(ts|js|py|rb)$",
    r"trpc\.(ts|js)$",
    r"hono\.(ts|js)$",
    r"express\.(ts|js)$",
    # CORS / server config
    r"cors\.(ts|js|py)$",
    r"server\.(ts|js)$",
    r"app\.(ts|js)$",
    r"main\.(ts|js)$",
    # Django / Rails non-model files
    r"urls\.py$",
    r"views\.py$",
    r"serializers\.py$",
    r"forms\.py$",
    r"admin\.py$",
    r"apps\.py$",
    r"signals\.py$",
    r"config/routes\.rb$",
    r"routes\.rb$",
    r"concerns/",
    r"application_record",
    r"application_controller",
    # Config / initializers
    r"config/initializers/",
    r"config/environments/",
    r"initializers?/",
    r"\.config\.(ts|js|mjs)$",
    # Migration files (define schema changes, not current state)
    r"db/migrate/",
    r"db/schema\.",
    r"database/migrations/",
    r"migrations/.*\.rb$",
    r"\d{14}_.*\.rb$",
    r"\d{4}_.*\.py$",
    # Seed / fixture / factory
    r"seeds?\.(ts|js|rb|py)$",
    r"seed/",
    r"seeds/",
    r"fixtures?/",
    r"factories?/",
    r"factory\.(ts|js|rb|py)$",
    r"dummy[_\-]?data",
    r"fake[_\-]?data",
    # Email handlers / job definitions
    r"handlers?/(internal|external)/",
    r"\.handler\.(ts|js)$",
    r"handler\.(ts|js)$",
    r"email[_\-]?handler",
    r"webhook[_\-]?handler",
    # Legacy / compatibility shims
    r"legacy[_\-]?",
    r"compat[_\-]?",
    r"deprecated[_\-]?",
]


# Minimum ORM signals required for a non-model_file to be considered a table
MINIMUM_ORM_SIGNALS = [
    r"@PrimaryGeneratedColumn\b",
    r"@Entity\b",
    r"@Column\b",
    r"db\.Model\b",
    r"mongoose\.Schema\b",
    r"DataTypes\.",
    r"prisma\.\w+\.create\b",
    r"model\s+\w+\s*\{",
    r"ApplicationRecord\b",
    r"ActiveRecord::Base\b",
    r"has_many\b",
    r"belongs_to\b",
    r"Column\s*\(",
    r"mapped_column\s*\(",
]


def _has_orm_signals(content: str) -> bool:
    return any(re.search(p, content) for p in MINIMUM_ORM_SIGNALS)


def _normalize_entity_name(name: str) -> str:
    n = (name or "").strip().lower()
    n = re.sub(r"[^a-z0-9_]+", "_", n)
    n = re.sub(r"_+", "_", n).strip("_")
    if n.endswith("ies") and len(n) > 3:
        return n[:-3] + "y"
    if n.endswith("ses") and len(n) > 4:
        return n[:-2]
    if n.endswith("s") and not n.endswith("ss") and len(n) > 3:
        return n[:-1]
    return n


def _has_piiish_fields(content: str) -> bool:
    return bool(
        re.search(
            r"\b(email|name|phone|mobile|address|aadhaar|aadhar|pan|user_id|recipient_id)\b",
            content or "",
            re.IGNORECASE,
        )
    )


def _entity_from_path(path: str) -> str:
    base = (path or "").replace("\\", "/").split("/")[-1]
    base = re.sub(r"\.[a-z0-9]+$", "", base, flags=re.IGNORECASE)
    base = re.sub(r"^(user_|tbl_|table_)", "", base)
    return _normalize_entity_name(base)


def _entity_kind(file_path: str, content: str) -> str:
    path_norm = (file_path or "").replace("\\", "/").lower()
    entity_name = _entity_from_path(file_path)
    if entity_name.startswith(ACTION_ENTITY_PREFIXES):
        return "action_handler"
    if re.search(r"/handlers?/|/trpc/.*/router/|/server-only/.+/(create|update|delete)/", path_norm):
        return "action_handler"
    if re.search(r"/(routes?|pages?|app)/", path_norm):
        if _has_orm_signals(content):
            return "data_entity"
        return "view_route"
    if _has_orm_signals(content) or re.search(r"class\s+\w+\s*\(", content):
        return "data_entity" if _has_piiish_fields(content) or "model " in content.lower() else "service"
    if re.search(r"export\s+(async\s+)?function\b|def\s+\w+\(", content):
        return "action_handler"
    return "unknown"


def _entities_from_content(content: str) -> Set[str]:
    entities: Set[str] = set()
    if not content:
        return entities
    patterns = [
        r"class\s+([A-Z][A-Za-z0-9_]*)\s*\(",
        r"model\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
        r"create_table\(\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']",
        r"table\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']",
    ]
    for p in patterns:
        for m in re.findall(p, content):
            ent = _normalize_entity_name(str(m))
            if ent and len(ent) >= 3:
                entities.add(ent)
    return entities


def _find_all_pii_entities(
    extracted: Dict,
) -> Tuple[Set[str], Dict[str, List[str]], Dict[str, Any]]:
    """Infer PII-bearing entities and their source files (entity lineage core)."""
    model_files = set(extracted.get("model_files", []) or [])
    pii_fields = extracted.get("pii_fields", []) or []
    file_contents = extracted.get("_file_contents", {}) or {}
    pii_files = {p["file"] for p in pii_fields if p.get("file")}
    path_norm = lambda f: f.replace("\\", "/")
    excluded = NOT_A_TABLE + NOT_A_TABLE_ADDITIONAL

    entities: Set[str] = set()
    entity_to_files: Dict[str, List[str]] = {}
    action_handlers_seen: Set[str] = set()
    for f in (model_files | pii_files):
        if any(re.search(p, path_norm(f), re.IGNORECASE) for p in excluded):
            continue
        content = file_contents.get(f, "")
        kind = _entity_kind(f, content)
        if kind == "action_handler":
            action_handlers_seen.add(_entity_from_path(f))
            continue
        if kind == "data_entity" or f in model_files or (content and _has_orm_signals(content)):
            from_path = _entity_from_path(f)
            if from_path:
                entities.add(from_path)
                entity_to_files.setdefault(from_path, []).append(f)
            for ent in _entities_from_content(content):
                entities.add(ent)
                entity_to_files.setdefault(ent, []).append(f)

    return entities, entity_to_files, {"action_handlers_seen": sorted(action_handlers_seen)}


def _entities_covered_by_deletion(
    deletion_signals: List[Dict],
    extracted: Dict,
    all_entities: Set[str],
) -> Set[str]:
    """
    Infer which entities are covered by deletion logic using:
    - files that emit deletion signals
    - endpoint files containing explicit entity/table mentions
    """
    covered: Set[str] = set()
    file_contents = extracted.get("_file_contents", {}) or {}
    signal_files = {s.get("file") for s in deletion_signals if s.get("file")}
    endpoint_files = {
        e.get("file") for e in (extracted.get("deletion_endpoints") or []) if e.get("file")
    }
    for f in (signal_files | endpoint_files):
        if not f:
            continue
        content = (file_contents.get(f) or "").lower()
        ent_from_path = _entity_from_path(f)
        if ent_from_path in all_entities:
            covered.add(ent_from_path)
        for ent in all_entities:
            if re.search(rf"\b{re.escape(ent)}\b", content):
                covered.add(ent)
            if re.search(rf"\b{re.escape(ent)}_id\b", content):
                covered.add(ent)
    return covered


def _check_deletion_completeness(
    flow: Dict,
    extracted: Dict,
    findings: List[Dict],
) -> None:
    """Deletion mechanism may not cover all PII storage (FK-graph aware)."""
    deletion_signals = extracted.get("deletion_signals", []) or []
    if not deletion_signals:
        return
    file_contents = extracted.get("_file_contents", {}) or {}
    model_files = list(extracted.get("model_files", []) or [])

    all_entities, entity_to_files, lineage_meta = _find_all_pii_entities(extracted)

    # Build FK graph and expand required deletion set
    fk_graph = build_fk_graph(file_contents, model_files)
    must_delete = deletion_must_cover(fk_graph, all_entities) if fk_graph else set(all_entities)
    must_delete |= all_entities

    covered = _entities_covered_by_deletion(deletion_signals, extracted, must_delete)
    uncovered = must_delete - covered
    if not uncovered:
        return
    covered_sorted = sorted(covered)
    uncovered_sorted = sorted(uncovered)
    coverage_pct = round((len(covered) / len(must_delete)) * 100) if must_delete else 0

    fk_edges_display = {}
    for ent in uncovered_sorted[:8]:
        deps = fk_graph.get(ent, set())
        if deps:
            fk_edges_display[ent] = sorted(deps)

    findings.append({
        "rule": "INCOMPLETE_DELETION_COVERAGE",
        "dpdp_section": "Section 8 — Data Principal Rights",
        "severity": "HIGH" if coverage_pct < 40 else "MEDIUM",
        "confidence": 0.80 if coverage_pct < 40 else (0.72 if coverage_pct < 60 else 0.65),
        "file": "N/A",
        "display_path": "N/A",
        "description": (
            "Deletion mechanism detected but may not cover all PII storage. "
            f"Coverage: {coverage_pct}% of inferred PII entities "
            f"({len(covered)}/{len(must_delete)} including FK dependents). "
            f"Uncovered: {', '.join(uncovered_sorted[:5])}. "
            "DPDP Section 8 requires complete erasure across all systems."
        ),
        "evidence": {
            "covered_entities": covered_sorted,
            "uncovered_entities": uncovered_sorted,
            "coverage_pct": coverage_pct,
            "data_entities_total": len(all_entities),
            "data_entities_uncovered": len(uncovered),
            "action_handlers_seen": lineage_meta.get("action_handlers_seen", []),
            "entity_to_files": {
                k: sorted(set(v))[:5] for k, v in entity_to_files.items() if k in uncovered
            },
            "fk_graph_edges": fk_edges_display,
            "must_delete_count": len(must_delete),
        },
        "fix": [
            f"Audit deletion endpoint/service to ensure cascade coverage for entities: "
            f"{', '.join(uncovered_sorted[:5])}.",
            "Use database CASCADE DELETE or explicit multi-table deletion.",
            "Map foreign-key relationships and ensure dependent records are also purged.",
            "Add entity-level deletion checklist and test orphan records post-delete.",
        ],
    })


def run(extracted: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Data flow analysis rules using pii_flow_graph from extractor.
    """
    findings: List[Dict[str, Any]] = []
    flow = extracted.get("pii_flow_graph", {})

    if not flow:
        return findings

    flow_paths = flow.get("flow_paths", [])
    analytics_sinks_seen: Set[str] = set()
    logging_sinks_seen: Set[str] = set()
    purpose_mismatch_seen: Set[str] = set()
    flows_suppressed_by_quality = 0

    for fp in flow_paths:
        if fp.get("source") == fp.get("sink"):
            continue

        src = (fp.get("source") or "").replace("\\", "/")
        snk = (fp.get("sink") or "").replace("\\", "/")
        source_dir = "/".join(src.split("/")[:-1])
        sink_dir = "/".join(snk.split("/")[:-1])
        if source_dir and source_dir == sink_dir:
            continue

        sink_type = fp.get("sink_type", "")
        sink = fp.get("sink", "")

        if sink_type == "analytics":
            if sink not in analytics_sinks_seen:
                analytics_sinks_seen.add(sink)
                _check_analytics_consent(fp, extracted, findings)
                if (fp.get("_flow_evidence") or {}).get("quality_gate_suppressed"):
                    flows_suppressed_by_quality += 1
                _check_purpose_mismatch(fp, extracted, findings, purpose_mismatch_seen)
            else:
                for f in findings:
                    if f.get("rule") == "PII_FLOW_TO_ANALYTICS_WITHOUT_CONSENT" and f.get("file") == sink:
                        existing_paths = f.get("evidence", {}).get("additional_sources", [])
                        existing_paths.append(_short_path(fp.get("source", "")))
                        f.setdefault("evidence", {})["additional_sources"] = existing_paths
                        break
        elif sink_type == "marketing_email":
            _check_marketing_consent(fp, extracted, findings)
            if (fp.get("_flow_evidence") or {}).get("quality_gate_suppressed"):
                flows_suppressed_by_quality += 1
            _check_purpose_mismatch(fp, extracted, findings, purpose_mismatch_seen)
        elif sink_type == "error_logging":
            sensitive_pii = {"email", "phone", "aadhaar", "aadhar", "pan", "mobile"}
            pii_in_flow = {str(f).lower() for f in fp.get("pii_fields", [])}
            if pii_in_flow & sensitive_pii and sink not in logging_sinks_seen:
                logging_sinks_seen.add(sink)
                _check_logging_pii(fp, extracted, findings)
                if (fp.get("_flow_evidence") or {}).get("quality_gate_suppressed"):
                    flows_suppressed_by_quality += 1
        elif sink_type in ("cloud_storage", "payment_processor"):
            # Cross-border / foreign cloud is handled by cross_border.py — avoid duplicate PII_FLOW_CROSS_BORDER
            pass

    _check_deletion_completeness(flow, extracted, findings)
    extracted["_flow_quality_stats"] = {
        "flows_suppressed_by_quality": flows_suppressed_by_quality,
    }

    findings = _verify_ambiguous_flow_findings(findings, extracted)
    return findings
