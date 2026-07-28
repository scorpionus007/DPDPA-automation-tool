"""
File Context Builder — builds AI understanding of each file.

Before validating any finding, we need to understand what each file
actually does. This prevents false positives like:
- "reset_password.py has a password field" → it's a CLI tool, not a model
- "jsdoc.ts has age references" → it's a doc generator, not a data collector
- "urls.py has no error handling" → it's a routing file, not a handler

Context is built once per file per scan and cached in memory.
For large repos, only files involved in findings are analyzed.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any, Dict, List, Optional

from rich.console import Console

FILE_CONTEXT_SYSTEM_PROMPT = """You are a code analysis expert. Analyze the provided source file
and produce a structured understanding of what it does.

Be precise and factual. Only describe what is actually in the code.
Do not infer what the code should do — only what it does.

RESPONSE FORMAT — JSON ONLY:
{
  "file_type": "one of: orm_model|api_route|ui_component|utility|config|migration|test|cli_tool|auth_handler|middleware|types_definitions|service|framework_setup|other",
  "primary_purpose": "one sentence describing exactly what this file does",
  "collects_pii_from_users": true/false,
  "pii_collected": ["list of actual PII field names collected from users, empty if none"],
  "stores_pii": true/false,
  "pii_stored": ["list of PII field names stored to a database or file"],
  "sends_pii_externally": true/false,
  "external_services": ["list of external services this file sends data to"],
  "has_auth_check": true/false,
  "has_error_handling": true/false,
  "has_logging": true/false,
  "is_user_facing": true/false,
  "is_internal_only": true/false,
  "framework_patterns": ["list of frameworks/patterns detected e.g. Django CBV, Flask route, React component"],
  "why_not_a_violation": "if this file is commonly misidentified, explain why specific rules should not apply"
}"""


def build_file_context(
    file_path: str,
    file_content: str,
    llm_client: Any,
) -> Dict:
    """
    Build AI understanding of a single file.
    Returns a FileContext dict.
    """
    if not file_content or len(file_content.strip()) < 50:
        return _empty_context(file_path)

    user_prompt = f"""Analyze this file for DPDP compliance context:

File path: {file_path}

Full file content:
{file_content}

Produce the JSON context object as instructed."""

    result = llm_client.complete_json(
        system_prompt=FILE_CONTEXT_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        quality=False,
        layer="layer1",
    )

    if not isinstance(result, dict):
        return _empty_context(file_path)

    result["file_path"] = file_path
    result["content_hash"] = hashlib.md5(file_content.encode(errors="replace")).hexdigest()[:8]
    return result


def build_repo_memory(
    findings: List[Dict],
    file_contents: Dict[str, str],
    llm_client: Any,
    max_files: int = 40,
) -> Dict[str, Dict]:
    """
    Build context for every unique file involved in findings.
    Returns repo_memory: {file_path: FileContext}
    """
    console = Console()

    files_to_analyze: set = set()
    for finding in findings:
        f = finding.get("file", "")
        if f and f not in ("N/A", "REPO-WIDE", ""):
            files_to_analyze.add(f)
        evidence = finding.get("evidence") or {}
        if isinstance(evidence, dict):
            for key in ("pii_fields", "libraries", "found_samples", "found_instances"):
                for item in evidence.get(key) or []:
                    if isinstance(item, dict) and item.get("file"):
                        files_to_analyze.add(item["file"])
        elif isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, dict) and item.get("file"):
                    files_to_analyze.add(item["file"])
        for af in finding.get("affected_files") or []:
            if af and af not in ("N/A", ""):
                files_to_analyze.add(af)

    files_to_analyze = {f for f in files_to_analyze if file_contents.get(f)}

    high_files = {
        f.get("file", "")
        for f in findings
        if f.get("severity") == "HIGH"
        and f.get("file") not in ("N/A", "REPO-WIDE", "", None)
    }
    prioritized = [f for f in high_files if f in files_to_analyze]
    remaining = [f for f in files_to_analyze if f not in high_files]
    ordered = (prioritized + remaining)[:max_files]

    console.print(
        f"\n  [bold]Building repo memory[/bold]: analyzing {len(ordered)} file(s)..."
    )

    repo_memory: Dict[str, Dict] = {}

    async def analyze_file(fp: str):
        content = file_contents.get(fp, "")
        if not content:
            return fp, _empty_context(fp)
        loop = asyncio.get_event_loop()
        context = await loop.run_in_executor(
            None,
            lambda p=fp, c=content: build_file_context(p, c, llm_client),
        )
        console.print(
            f"  [dim]  ✓ {fp.split('/')[-1]}: "
            f"{context.get('file_type', 'unknown')} — "
            f"{str(context.get('primary_purpose', ''))[:60]}[/dim]"
        )
        return fp, context

    async def build_all():
        batch_size = 8
        for i in range(0, len(ordered), batch_size):
            batch = ordered[i : i + batch_size]
            results = await asyncio.gather(*[analyze_file(fp) for fp in batch])
            for fp, ctx in results:
                repo_memory[fp] = ctx

    asyncio.run(build_all())

    console.print(
        f"  [green]✓ Repo memory built: {len(repo_memory)} file(s) analyzed[/green]"
    )
    return repo_memory


def _empty_context(file_path: str) -> Dict:
    return {
        "file_path": file_path,
        "file_type": "unknown",
        "primary_purpose": "unknown",
        "collects_pii_from_users": False,
        "pii_collected": [],
        "stores_pii": False,
        "pii_stored": [],
        "sends_pii_externally": False,
        "external_services": [],
        "has_auth_check": False,
        "has_error_handling": False,
        "has_logging": False,
        "is_user_facing": False,
        "is_internal_only": True,
        "framework_patterns": [],
        "why_not_a_violation": "",
    }
