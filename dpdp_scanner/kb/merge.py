"""Merge per-repo extraction into organization-wide knowledge base."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from dpdp_scanner.rules.data_flow import (
    _entity_kind,
    _entity_from_path,
    _entities_from_content,
    _find_all_pii_entities,
    _normalize_entity_name,
)

# Field extraction patterns for schema fingerprinting
_FIELD_PATTERNS = [
    re.compile(r"^\s*(\w+)\s+\w+.*$", re.MULTILINE),  # Prisma: email String
    re.compile(r"^\s*(\w+)\s*:\s*\w+", re.MULTILINE),  # Pydantic/TS
    re.compile(r"Column\s*\(\s*['\"](\w+)['\"]", re.IGNORECASE),
    re.compile(r"['\"](\w+)['\"]\s*:\s*\w+", re.MULTILINE),
]

PII_FIELD_HINTS = frozenset({
    "email", "phone", "name", "address", "password", "ssn", "aadhaar",
    "pan", "dob", "birth", "gender", "location", "ip", "token",
})


def compute_schema_fingerprint(
    entity_name: str,
    file_paths: List[str],
    file_contents: Dict[str, str],
) -> str:
    """Hash sorted field names found near entity definitions."""
    fields: Set[str] = set()
    name_lower = entity_name.lower()
    for path in file_paths:
        content = file_contents.get(path, "") or ""
        if name_lower not in content.lower() and entity_name not in content:
            continue
        for pat in _FIELD_PATTERNS:
            for m in pat.finditer(content):
                fn = m.group(1).lower()
                if len(fn) > 1 and not fn.startswith("_"):
                    fields.add(fn)
        for m in re.finditer(
            rf"(?:model|class|interface)\s+{re.escape(entity_name)}\s*{{([^}}]+)}}",
            content,
            re.IGNORECASE | re.DOTALL,
        ):
            block = m.group(1)
            for line in block.splitlines():
                parts = line.strip().split()
                if parts and parts[0][0].isalpha():
                    fields.add(parts[0].lower())
    if not fields:
        return ""
    raw = "|".join(sorted(fields))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _classify_occurrence_role(file_path: str, content: str, entity_name: str) -> str:
    kind = _entity_kind(file_path, content)
    if kind == "data_entity":
        return "definition"
    path_lower = (file_path or "").lower()
    if any(x in path_lower for x in ("/import", "/schema", "prisma", "/models/")):
        return "reference"
    if entity_name.lower() in (content or "").lower():
        if re.search(rf"(?:from|import).*{re.escape(entity_name)}", content, re.I):
            return "reference"
        if re.search(rf"(?:select|insert|update|delete).*{entity_name}", content, re.I):
            return "consumer"
    return "reference"


def _snippet_for_file(content: str, entity_name: str, max_len: int = 600) -> str:
    if not content:
        return ""
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if entity_name.lower() in line.lower():
            start = max(0, i - 2)
            end = min(len(lines), i + 3)
            return "\n".join(lines[start:end])[:max_len]
    return content[:max_len]


def _pii_fields_for_entity(
    entity_name: str,
    pii_fields: List[dict],
    file_paths: List[str],
) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    en = entity_name.lower()
    for pf in pii_fields:
        fp = pf.get("file", "")
        if fp not in file_paths:
            continue
        matched = (pf.get("pattern_matched") or "").lower()
        line = (pf.get("line_content") or "").lower()
        if en in matched or en in line or any(h in matched for h in PII_FIELD_HINTS):
            out.append((matched or "unknown", pf.get("direction", "unknown")))
    return out


def merge_into_org_kb(
    db_session,
    org_id: int,
    repository_id: int,
    scan_id: Optional[int],
    extracted: Dict[str, Any],
) -> Dict[str, int]:
    """
    Upsert entities, occurrences, fields, and cross-repo edges for one scan.
    Returns counters: entities, occurrences, edges.
    """
    from backend.models import (
        CrossRepoEdge,
        OrgEntity,
        OrgEntityField,
        OrgEntityOccurrence,
        Repository,
    )

    entities_set, entity_to_files, meta = _find_all_pii_entities(extracted)
    file_contents = extracted.get("_file_contents") or {}
    pii_fields = extracted.get("pii_fields") or []

    repo = db_session.query(Repository).filter(Repository.id == repository_id).first()
    if not repo:
        return {"entities": 0, "occurrences": 0, "edges": 0}

    # Clear prior occurrences for this repo+scan to keep idempotent merges
    if scan_id:
        db_session.query(OrgEntityOccurrence).filter(
            OrgEntityOccurrence.repository_id == repository_id,
            OrgEntityOccurrence.scan_id == scan_id,
        ).delete(synchronize_session=False)

    entity_ids_touched: Set[int] = set()
    counters = {"entities": 0, "occurrences": 0, "edges": 0}

    for raw_name in entities_set:
        canonical = _normalize_entity_name(raw_name)
        if not canonical:
            continue
        files = entity_to_files.get(raw_name, []) or entity_to_files.get(canonical, [])
        fingerprint = compute_schema_fingerprint(canonical, files, file_contents) or None

        org_entity = (
            db_session.query(OrgEntity)
            .filter(
                OrgEntity.org_id == org_id,
                OrgEntity.canonical_name == canonical,
                OrgEntity.schema_fingerprint == fingerprint,
            )
            .first()
        )
        if not org_entity:
            org_entity = OrgEntity(
                org_id=org_id,
                canonical_name=canonical,
                kind="data_entity",
                schema_fingerprint=fingerprint,
                first_seen_repo_id=repository_id,
            )
            db_session.add(org_entity)
            db_session.flush()
            counters["entities"] += 1

        entity_ids_touched.add(org_entity.id)
        occ_count = 0
        roles_seen: Set[str] = set()

        for fp in files:
            content = file_contents.get(fp, "") or ""
            role = _classify_occurrence_role(fp, content, canonical)
            roles_seen.add(role)
            snippet = _snippet_for_file(content, canonical)
            line_no = None
            for pf in pii_fields:
                if pf.get("file") == fp:
                    line_no = pf.get("line_number")
                    break

            occ = OrgEntityOccurrence(
                org_entity_id=org_entity.id,
                repository_id=repository_id,
                scan_id=scan_id,
                file_path=fp,
                line_number=line_no,
                role=role,
                snippet=snippet,
                confidence=0.9 if role == "definition" else 0.7,
            )
            db_session.add(occ)
            occ_count += 1
            counters["occurrences"] += 1

        # Fields
        for field_name, category in _pii_fields_for_entity(canonical, pii_fields, files):
            fn = field_name.split(".")[-1].lower() if "." in field_name else field_name.lower()
            existing_field = (
                db_session.query(OrgEntityField)
                .filter(
                    OrgEntityField.org_entity_id == org_entity.id,
                    OrgEntityField.field_name == fn,
                )
                .first()
            )
            if existing_field:
                existing_field.seen_in_repos = (existing_field.seen_in_repos or 1) + 1
            else:
                db_session.add(
                    OrgEntityField(
                        org_entity_id=org_entity.id,
                        field_name=fn,
                        pii_category=category,
                        seen_in_repos=1,
                    )
                )

        org_entity.occurrence_count = (
            db_session.query(OrgEntityOccurrence)
            .filter(OrgEntityOccurrence.org_entity_id == org_entity.id)
            .count()
        )
        org_entity.pii_field_count = (
            db_session.query(OrgEntityField)
            .filter(OrgEntityField.org_entity_id == org_entity.id)
            .count()
        )
        org_entity.updated_at = datetime.utcnow()

    db_session.flush()
    counters["edges"] = _rebuild_cross_repo_edges(db_session, org_id, entity_ids_touched)
    db_session.commit()
    return counters


def _rebuild_cross_repo_edges(
    db_session,
    org_id: int,
    entity_ids: Set[int],
) -> int:
    from backend.models import CrossRepoEdge, OrgEntity, OrgEntityOccurrence, Repository

    if not entity_ids:
        return 0

    edges_created = 0
    for entity_id in entity_ids:
        db_session.query(CrossRepoEdge).filter(
            CrossRepoEdge.org_id == org_id,
            CrossRepoEdge.org_entity_id == entity_id,
        ).delete(synchronize_session=False)

        occs = (
            db_session.query(OrgEntityOccurrence)
            .filter(OrgEntityOccurrence.org_entity_id == entity_id)
            .all()
        )
        defs = {o.repository_id for o in occs if o.role == "definition"}
        refs = {o.repository_id for o in occs if o.role in ("reference", "consumer")}
        if not defs and occs:
            defs = {occs[0].repository_id}

        entity = db_session.query(OrgEntity).filter(OrgEntity.id == entity_id).first()
        if not entity:
            continue

        for src in defs:
            for dst in refs:
                if src == dst:
                    continue
                src_repo = db_session.query(Repository).get(src)
                dst_repo = db_session.query(Repository).get(dst)
                evidence = {
                    "entity": entity.canonical_name,
                    "src": src_repo.full_name if src_repo else str(src),
                    "dst": dst_repo.full_name if dst_repo else str(dst),
                }
                edge = CrossRepoEdge(
                    org_id=org_id,
                    org_entity_id=entity_id,
                    src_repo_id=src,
                    dst_repo_id=dst,
                    edge_type="definition_consumed",
                    confidence=0.85 if entity.schema_fingerprint else 0.65,
                    evidence_json=evidence,
                )
                db_session.add(edge)
                edges_created += 1
    return edges_created
