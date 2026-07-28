"""
Deletion rule — DPDP Section 8.
Data principals have the right to erasure. The app must expose a way to delete/erase user data.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

DELETION_FALSE_POSITIVE_FILES = [
    r"actionCable\.(js|ts)$",
    r"websocket\.(js|ts|rb)$",
    r"cable\.(js|ts|rb)$",
    r"socket\.(js|ts)$",
    r"realtime\.(js|ts)$",
    r"pubsub\.(js|ts)$",
    r"channels?/.*\.(js|ts|rb)$",
]

CASCADE_PATTERNS = [
    r"ON\s+DELETE\s+CASCADE",
    r"onDelete.*cascade",
    r"onDelete:\s*[\"']Cascade[\"']",
    r"cascade.*delete",
    r"delete.*cascade",
    r"dependent.*destroy",
    r"before_destroy\b",
    r"cascade=True",
    r"CascadeType\.ALL\b",
    r"CascadeType\.REMOVE\b",
    r"deleteMany\s*\(",
    r"deleteRelated\b",
    r"bulkDelete\b",
    r"destroyAll\b",
    r"forceDelete\b",
]


def check_deletion(extracted: Dict) -> List[Dict]:
    # Framework/library repos provide tools for apps to implement these controls.
    if extracted.get("is_framework_library", False):
        return []

    deletion_signals = extracted.get("deletion_signals", []) or []
    deletion_endpoints = extracted.get("deletion_endpoints", []) or []
    api_endpoints = extracted.get("api_endpoints", []) or []
    route_files: Set[str] = set(extracted.get("route_files", []) or [])
    user_facing_routes = set(extracted.get("user_facing_route_files", []) or route_files)
    pii_fields = extracted.get("pii_fields", []) or []
    model_files = set(extracted.get("model_files", []) or [])

    # Files that contain PII (collection/schema/display)
    pii_files = {p["file"] for p in pii_fields if p.get("file")}
    route_files_with_pii = route_files & pii_files
    model_files_with_pii = model_files & pii_files
    has_pii_in_app = bool(route_files_with_pii or model_files_with_pii)

    # Deletion signals in route/API layer (user-triggerable)
    # Exclude websocket/ActionCable and similar — not deletion endpoints
    deletion_signal_files = {
        s["file"] for s in deletion_signals
        if s.get("file")
        and not any(re.search(p, s["file"].replace("\\", "/"), re.IGNORECASE) for p in DELETION_FALSE_POSITIVE_FILES)
    }
    deletion_in_route_layer = bool(deletion_signal_files & route_files)
    deletion_in_user_facing_routes = bool(deletion_signal_files & user_facing_routes)

    # User-exposed deletion: DELETE endpoint or deletion logic in user-facing route
    has_deletion_endpoint = len(deletion_endpoints) > 0
    has_exposed_deletion = has_deletion_endpoint or deletion_in_user_facing_routes

    if not has_pii_in_app:
        # No PII → no obligation to expose deletion in this scan
        if deletion_signals or deletion_endpoints:
            return [
                {
                    "rule": "DELETION_MECHANISM_PRESENT",
                    "dpdp_section": "Section 8 — Data Principal Rights",
                    "severity": "PASS",
                    "file": "N/A",
                    "evidence": {"signals": deletion_signals[:20], "deletion_endpoints": deletion_endpoints[:10]},
                    "description": "Data deletion mechanism or endpoint detected.",
                    "fix": None,
                }
            ]
        return []

    if has_exposed_deletion:
        file_contents = extracted.get("_file_contents", {}) or {}
        all_content = " ".join(file_contents.values())
        has_cascade = any(
            re.search(p, all_content, re.IGNORECASE)
            for p in CASCADE_PATTERNS
        )
        deletion_endpoint_file = "N/A"
        for endpoint in deletion_endpoints:
            path = endpoint.get("file") or endpoint.get("path") or ""
            if path:
                deletion_endpoint_file = path
                break
        return [
            {
                "rule": "DELETION_MECHANISM_PRESENT",
                "dpdp_section": "Section 8 — Data Principal Rights",
                "severity": "PASS",
                "file": deletion_endpoint_file,
                "evidence": {
                    "deletion_endpoints": deletion_endpoints[:5],
                    "has_cascade_delete": has_cascade,
                    "deletion_signal_count": len(deletion_signals),
                },
                "description": (
                    "Data deletion mechanism detected. "
                    f"Found {len(deletion_endpoints)} deletion endpoint(s) and "
                    f"{len(deletion_signals)} deletion signal(s). "
                    + (
                        "Cascade delete patterns detected."
                        if has_cascade
                        else "Note: Verify deletion cascades to all PII tables (sessions, logs, related records)."
                    )
                ),
                "fix": None
                if has_cascade
                else [
                    "Verify deletion cascades to: sessions, audit_logs, third-party sync records.",
                    "Use database CASCADE DELETE or explicit multi-table deletion in deletion service.",
                    "Test deletion completeness: create account, delete, query all PII tables for orphaned data.",
                ],
            }
        ]

    # PII exists but no exposed deletion
    if deletion_in_route_layer and not deletion_in_user_facing_routes:
        # Deletion only in internal routes — still a gap for user-facing erasure
        severity = "MEDIUM"
        description = (
            "Deletion logic exists but only in internal/non–user-facing routes. "
            "Data principals need a way to request erasure (e.g. account settings, DELETE /me or /account)."
        )
    elif deletion_signals and not deletion_in_route_layer:
        severity = "MEDIUM"
        description = (
            "Deletion-related code detected in models/services but no user-facing deletion endpoint or route handler found. "
            "Expose an API or UI for account/data erasure (DPDP Section 8)."
        )
    else:
        severity = "HIGH"
        description = (
            "No data deletion or account erasure mechanism detected. "
            "Users may not be able to exercise their right to erasure under DPDP Section 8."
        )

    evidence: Dict = {
        "route_files_with_pii": list(route_files_with_pii)[:15],
        "model_files_with_pii": list(model_files_with_pii)[:15],
        "deletion_signals_count": len(deletion_signals),
        "deletion_endpoints_count": len(deletion_endpoints),
    }
    if deletion_signals:
        evidence["deletion_signal_files"] = list(deletion_signal_files)[:10]

    file_ref = "N/A"
    if route_files_with_pii:
        file_ref = next(iter(sorted(route_files_with_pii)))
    elif model_files_with_pii:
        file_ref = next(iter(sorted(model_files_with_pii)))

    return [
        {
            "rule": "NO_DELETION_MECHANISM",
            "dpdp_section": "Section 8 — Data Principal Rights",
            "severity": severity,
            "confidence": 0.75,
            "file": file_ref,
            "evidence": evidence,
            "description": description,
            "fix": [
                "Add a user-facing account or data deletion flow (e.g. DELETE /api/users/me or /account/delete).",
                "Ensure deletion cascades to all PII (profile, logs, third-party sync).",
                "Document retention of anonymised/aggregate data if any.",
            ],
        }
    ]
