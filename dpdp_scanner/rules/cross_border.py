"""
Cross-border transfer rule — DPDP Section 16.

This module owns **foreign cloud / CDN host strings** and **non-India region**
configuration signals for Section 16 reporting. It is the canonical place for
those findings; do not duplicate the same cross-border story from the PII
flow graph (see data_flow.py, which skips cloud_storage for that reason).
"""

from __future__ import annotations

import re
from typing import Dict, List

def _get_content(extracted: Dict, filepath: str) -> str:
    """Retrieve file content from extracted._file_contents."""
    return (extracted.get("_file_contents") or {}).get(filepath, "")


# File type priority for evidence selection (lower = better evidence)
FILE_PRIORITY_PATTERNS = [
    (r"service\.(ts|js|py)$", 1),
    (r"api/", 1),
    (r"adapter\.(ts|js|py)$", 2),
    (r"client\.(ts|js|py)$", 2),
    (r"views?\.(ts|js|py)$", 2),
    (r"controller\.(ts|js|py)$", 2),
    (r"route(s)?\.(ts|js|py)$", 3),
    (r"integration\.", 3),
    (r"lib/", 4),
    (r"utils?/", 5),
    (r"helpers?/", 5),
    (r"config\.", 6),
    (r"components?/", 8),
    (r"pages?/", 8),
    (r"\.tsx$", 9),
    (r"\.jsx$", 9),
    (r"header", 10),
    (r"footer", 10),
    (r"navbar", 10),
    (r"sidebar", 10),
]


def _score_evidence_file(file_path: str) -> int:
    """Lower score = better evidence file for cross-border finding."""
    path_norm = file_path.replace("\\", "/").lower()
    for pattern, score in FILE_PRIORITY_PATTERNS:
        if re.search(pattern, path_norm):
            return score
    return 5


def _best_cross_border_file(matches: list) -> dict:
    """
    From all cross-border matches, return the one in the most
    relevant file (service/API layer, not UI component).
    """
    if not matches:
        return {}
    return min(matches, key=lambda m: _score_evidence_file(m["file"]))


# Known services that specifically involve personal data transfer
HIGH_RISK_DOMAINS = [
    "mixpanel.com",
    "segment.",
    "segment.io",
    "amplitude.com",
    "posthog.com",
    "fullstory.com",
    "heap.io",
    "intercom.io",
    "hubspot.",
    "mailchimp.com",
    "sendgrid.com",
    "twilio.com",
]

INFRASTRUCTURE_ONLY_DOMAINS = [
    "cloudflare.com",
    "fastly.com",
    "akamai",
    "supabase.co",
]

SECURITY_ONLY_SERVICES = [
    "challenges.cloudflare.com",
    "turnstile",
    "hcaptcha.com",
    "www.google.com/recaptcha",
    "recaptcha.net",
]

FOREIGN_DOMAINS = [
    "amazonaws.com",
    "azure.com",
    "googleapis.com",
    "cloudflare.com",
    "fastly.com",
    "akamai",
    "supabase.co",
    "sentry.io",
    "datadoghq.com",
    "mixpanel.com",
    "segment.",
    "segment.io",
    "intercom.io",
    "hubspot.",
    "stripe.com",
    "twilio.com",
    "sendgrid.com",
    "mailchimp.com",
]

NON_INDIA_REGIONS = [
    "us-east",
    "us-west",
    "eu-west",
    "eu-central",
    "ap-southeast",
    "ap-northeast",
    "us-central",
    "europe-west",
    "asia-east",
]

INDIA_REGIONS = ["ap-south", "mumbai", "asia-south", "in-"]  # in- for india

PII_PAYLOAD_PATTERNS = [
    r"\b(email|name|phone|mobile|address|aadhaar|aadhar|pan)\b",
    r"(append|set)\s*\(\s*[\"'](?:email|name|phone|mobile|address|aadhaar|aadhar|pan)[\"']",
    r"[\"'](?:email|name|phone|mobile|address|aadhaar|aadhar|pan)[\"']\s*:",
]


def _classify_service(endpoint: str) -> str:
    lowered = (endpoint or "").lower()
    if any(token in lowered for token in SECURITY_ONLY_SERVICES):
        return "security"
    if any(token in lowered for token in INFRASTRUCTURE_ONLY_DOMAINS):
        return "infra"
    return "data"


def _has_pii_payload(content: str) -> bool:
    lowered = (content or "").lower()
    return any(re.search(pattern, lowered, re.IGNORECASE) for pattern in PII_PAYLOAD_PATTERNS)


def check_cross_border(extracted: Dict) -> List[Dict]:
    findings: List[Dict] = []
    file_contents = extracted.get("_file_contents") or {}
    model_files = set(extracted.get("model_files") or [])
    pii_fields = extracted.get("pii_fields", []) or []
    pii_files = {p.get("file") for p in pii_fields if p.get("file")}
    has_pii_models = bool(model_files & pii_files) or bool(pii_files)

    foreign_cloud_matches: List[Dict] = []
    non_india_region_matches: List[Dict] = []

    for path, content in file_contents.items():
        if not content:
            continue
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip().lower()

            for domain in FOREIGN_DOMAINS:
                if domain in stripped:
                    foreign_cloud_matches.append(
                        {
                            "file": path,
                            "line_number": i,
                            "matched_endpoint": domain,
                            "line_content": line.strip()[:200],
                            "match_type": _classify_service(line.strip()),
                        }
                    )
                    break

            for region in NON_INDIA_REGIONS:
                if region in stripped:
                    is_india = any(ir in stripped for ir in INDIA_REGIONS)
                    if not is_india:
                        non_india_region_matches.append(
                            {
                                "file": path,
                                "line_number": i,
                                "matched_endpoint": region,
                                "line_content": line.strip()[:200],
                            }
                        )
                    break

    if foreign_cloud_matches and has_pii_models:
        best_match = _best_cross_border_file(foreign_cloud_matches)
        detected_domains = {m["matched_endpoint"] for m in foreign_cloud_matches}
        match_types = {m.get("match_type", "data") for m in foreign_cloud_matches}
        has_high_risk_domain = any(
            hr_domain in detected for detected in detected_domains for hr_domain in HIGH_RISK_DOMAINS
        )
        has_non_india_region = bool(non_india_region_matches)
        infra_only = all(
            any(infra in detected for infra in INFRASTRUCTURE_ONLY_DOMAINS)
            for detected in detected_domains
        )
        security_only = match_types == {"security"}
        pii_payload_present = _has_pii_payload(file_contents.get(best_match.get("file", ""), ""))
        if security_only and not pii_payload_present:
            severity = "INFO"
            confidence = 0.40
            description = (
                "Security-only external verification service detected with no obvious PII payload. "
                "Review vendor hosting and DPA, but this looks lower risk than an analytics or data-sharing transfer."
            )
            note = "security-only service; IP + opaque token only"
        elif infra_only:
            severity = "INFO"
            confidence = 0.55
            description = "Foreign cloud storage/CDN detected with PII models in repo. Cross-border transfer risk."
            note = "infrastructure-only domain match"
        elif has_high_risk_domain or has_non_india_region:
            severity = "HIGH"
            confidence = 0.75 if has_high_risk_domain else 0.65
            description = "Foreign cloud storage/CDN detected with PII models in repo. Cross-border transfer risk."
            note = "high-risk analytics/vendor or non-India region config"
        else:
            severity = "MEDIUM"
            confidence = 0.65
            description = "Foreign cloud storage/CDN detected with PII models in repo. Cross-border transfer risk."
            note = "foreign service reference with potential PII exposure"
        findings.append(
            {
                "rule": "CROSS_BORDER_TRANSFER_RISK",
                "dpdp_section": "Section 16 — Cross-Border Transfer",
                "severity": severity,
                "confidence": confidence,
                "file": best_match["file"],
                "evidence": {
                    "file": best_match["file"],
                    "line_number": best_match["line_number"],
                    "matched_endpoint": best_match["matched_endpoint"],
                    "line_content": best_match.get("line_content", ""),
                    "total_foreign_service_references": len(foreign_cloud_matches),
                    "foreign_services_detected": list(detected_domains),
                    "match_types": sorted(match_types),
                    "pii_payload_present": pii_payload_present,
                    "cross_border_note": note,
                    "all_matches": foreign_cloud_matches[:10],
                },
                "description": description,
                "fix": None,
            }
        )
    if non_india_region_matches and not any(f.get("rule") == "CROSS_BORDER_TRANSFER_RISK" for f in findings):
        m = non_india_region_matches[0]
        findings.append(
            {
                "rule": "NON_INDIA_REGION_CONFIG",
                "dpdp_section": "Section 16 — Cross-Border Transfer",
                "severity": "MEDIUM",
                "confidence": 0.50,
                "file": m["file"],
                "evidence": {
                    "file": m["file"],
                    "line_number": m["line_number"],
                    "matched_endpoint": m["matched_endpoint"],
                    "line_content": m["line_content"],
                    "all_matches": non_india_region_matches,
                },
                "description": "Non-India region config detected (us-east, eu-west, etc.). Data may be transferred outside India.",
                "fix": None,
            }
        )

    if not foreign_cloud_matches and not non_india_region_matches:
        findings.append(
            {
                "rule": "NO_CROSS_BORDER_DETECTED",
                "dpdp_section": "Section 16 — Cross-Border Transfer",
                "severity": "INFO",
                "confidence": 0.70,
                "file": "N/A",
                "evidence": {},
                "description": "No foreign cloud or non-India region config detected.",
                "fix": None,
            }
        )

    return findings
