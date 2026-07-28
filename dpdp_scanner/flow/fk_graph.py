"""
Foreign-key / relationship graph builder for deletion coverage.

Parses ORM relationship declarations (ForeignKey, has_many, belongs_to,
references, @ManyToOne, etc.) to build an entity dependency graph.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

RELATIONSHIP_PATTERNS = [
    (r"ForeignKey\(\s*['\"]?(\w+)", "fk"),
    (r"references\s*['\"](\w+)['\"]", "ref"),
    (r"has_many\s+:(\w+)", "has_many"),
    (r"belongs_to\s+:(\w+)", "belongs_to"),
    (r"has_one\s+:(\w+)", "has_one"),
    (r"@ManyToOne\b.*?(\w+)", "many_to_one"),
    (r"@OneToMany\b.*?(\w+)", "one_to_many"),
    (r"@ManyToMany\b.*?(\w+)", "many_to_many"),
    (r"\.hasMany\(\s*(\w+)", "sequelize_has_many"),
    (r"\.belongsTo\(\s*(\w+)", "sequelize_belongs_to"),
    (r"\.hasOne\(\s*(\w+)", "sequelize_has_one"),
    (r"relation\(\s*['\"](\w+)['\"]", "prisma_relation"),
    (r"@relation\(\s*fields.*?references.*?(\w+)", "prisma_relation2"),
    (r"add_foreign_key\s*\(\s*:(\w+)", "rails_fk"),
    (r"sa\.ForeignKey\(\s*['\"](\w+)\.", "sa_fk"),
]


def _normalize(name: str) -> str:
    n = re.sub(r"[^a-z0-9_]+", "_", (name or "").strip().lower())
    n = re.sub(r"_+", "_", n).strip("_")
    if n.endswith("ies") and len(n) > 3:
        return n[:-3] + "y"
    if n.endswith("ses") and len(n) > 4:
        return n[:-2]
    if n.endswith("s") and not n.endswith("ss") and len(n) > 3:
        return n[:-1]
    return n


def _extract_entity_name_from_content(content: str) -> Set[str]:
    entities: Set[str] = set()
    for m in re.finditer(r"class\s+([A-Z]\w+)\s*[\(:]", content):
        entities.add(_normalize(m.group(1)))
    for m in re.finditer(r'(?:create_table|model)\s*[\("\']+(\w+)', content):
        entities.add(_normalize(m.group(1)))
    return entities


def build_fk_graph(
    file_contents: Dict[str, str],
    model_files: List[str],
) -> Dict[str, Set[str]]:
    """
    Build adjacency graph: entity -> set of entities it depends on.
    Uses ORM/migration relationship declarations.
    """
    graph: Dict[str, Set[str]] = {}

    for path in model_files:
        content = file_contents.get(path, "")
        if not content:
            continue
        source_entities = _extract_entity_name_from_content(content)
        if not source_entities:
            base = path.replace("\\", "/").split("/")[-1]
            base = re.sub(r"\.[a-z0-9]+$", "", base, flags=re.IGNORECASE)
            source_entities = {_normalize(base)}

        for pattern, _kind in RELATIONSHIP_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                target = _normalize(m.group(1))
                if not target or len(target) < 2:
                    continue
                for src in source_entities:
                    graph.setdefault(src, set()).add(target)
                    graph.setdefault(target, set())

        for src in source_entities:
            graph.setdefault(src, set())

    return graph


def transitive_dependencies(
    graph: Dict[str, Set[str]],
    entity: str,
    max_depth: int = 5,
) -> Set[str]:
    """Return all entities reachable from `entity` in the FK graph."""
    visited: Set[str] = set()
    queue = [entity]
    depth = 0
    while queue and depth < max_depth:
        next_queue: List[str] = []
        for e in queue:
            if e in visited:
                continue
            visited.add(e)
            next_queue.extend(graph.get(e, set()) - visited)
        queue = next_queue
        depth += 1
    visited.discard(entity)
    return visited


def deletion_must_cover(
    graph: Dict[str, Set[str]],
    root_entities: Set[str],
) -> Set[str]:
    """
    Given root entities that hold PII, return the full set of entities
    that must be covered by deletion (root + all transitive dependents).
    """
    must_cover: Set[str] = set(root_entities)
    for ent in root_entities:
        must_cover |= transitive_dependencies(graph, ent)
    reverse: Dict[str, Set[str]] = {}
    for src, targets in graph.items():
        for t in targets:
            reverse.setdefault(t, set()).add(src)
    for ent in list(root_entities):
        for parent in reverse.get(ent, set()):
            must_cover.add(parent)
            must_cover |= transitive_dependencies(graph, parent)
    return must_cover
