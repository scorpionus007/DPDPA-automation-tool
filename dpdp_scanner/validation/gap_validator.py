"""Dual-layer validator for AI-inferred compliance gaps."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Tuple

SKEPTIC_SYSTEM_PROMPT = """You are a compliance skeptic. Find reasons
why a proposed compliance gap might NOT be a real violation.

RESPONSE FORMAT — JSON ONLY:
{
  "survives_skepticism": true/false,
  "confidence": 0.0-1.0,
  "skeptic_reasoning": "specific reasons this might be a false positive",
  "fatal_objection": "the single strongest reason this gap might not be real, or null"
}"""

CONFIRMER_SYSTEM_PROMPT = """You are an independent DPDP Act 2023 compliance expert.
Assess whether this compliance gap is genuinely present.

RESPONSE FORMAT — JSON ONLY:
{
  "independently_confirmed": true/false,
  "confidence": 0.0-1.0,
  "evidence": "specific code evidence supporting or refuting this gap",
  "dpdp_section_applies": true/false,
  "recommended_severity": "HIGH|MEDIUM|LOW|INFO"
}"""


def _gap_description(gap: Dict) -> str:
    return str(
        gap.get("description")
        or gap.get("title")
        or gap.get("observation")
        or ""
    )


async def dual_validate_gap(
    gap: Dict,
    repo_memory: Dict,
    repo_context: str,
    llm_client: Any,
) -> Tuple[Dict, Dict, Dict]:
    relevant_contexts = []
    desc = _gap_description(gap)
    file_mentions = re.findall(
        r"[\w/\-]+\.(?:py|ts|js|tsx|jsx|rb|java|go)", desc
    )
    for fname in file_mentions[:5]:
        for fpath, ctx in repo_memory.items():
            if fname in fpath.replace("\\", "/"):
                relevant_contexts.append(
                    f"{fpath}: {ctx.get('primary_purpose', 'unknown')} "
                    f"(type: {ctx.get('file_type', 'unknown')}, "
                    f"user-facing: {ctx.get('is_user_facing', False)})"
                )
                break

    memory_context = (
        "\n".join(relevant_contexts)
        if relevant_contexts
        else "No specific file context available"
    )

    gap_text = f"""
Inferred Gap:
Section: {gap.get('dpdp_section', '')}
Title: {_gap_description(gap)}
Observation: {gap.get('observation', '')}
Recommendation: {gap.get('recommendation', '')}
Confidence: {gap.get('confidence', 0)}

Relevant file contexts from repo memory:
{memory_context}

Repository overview:
{repo_context[:2000]}
"""

    loop = asyncio.get_event_loop()

    def _skeptic():
        return llm_client.complete_json(
            system_prompt=SKEPTIC_SYSTEM_PROMPT,
            user_prompt=gap_text,
            quality=False,
            layer="layer3",
        )

    def _confirmer():
        return llm_client.complete_json(
            system_prompt=CONFIRMER_SYSTEM_PROMPT,
            user_prompt=gap_text,
            quality=False,
            layer="layer3",
        )

    skeptic_result, confirmer_result = await asyncio.gather(
        loop.run_in_executor(None, _skeptic),
        loop.run_in_executor(None, _confirmer),
    )

    sk = skeptic_result if isinstance(skeptic_result, dict) else {}
    cf = confirmer_result if isinstance(confirmer_result, dict) else {}
    return gap, sk, cf


def dual_validate_all_gaps(
    gaps: List[Dict],
    repo_memory: Dict,
    repo_context: str,
    llm_client: Any,
    confidence_threshold: float = 0.60,
) -> Tuple[List[Dict], List[Dict]]:
    from rich.console import Console

    console = Console()

    if not gaps:
        return [], []

    rc = repo_context
    if isinstance(rc, dict):
        rc = json.dumps(rc, indent=2)[:8000]
    elif not isinstance(rc, str):
        rc = str(rc)[:8000]

    console.print(f"\n  [bold]Dual-validating {len(gaps)} inferred gap(s)...[/bold]")

    async def run_all():
        tasks = [
            dual_validate_gap(gap, repo_memory, rc, llm_client)
            for gap in gaps
        ]
        return await asyncio.gather(*tasks)

    results = asyncio.run(run_all())

    survived: List[Dict] = []
    rejected: List[Dict] = []

    for gap, skeptic, confirmer in results:
        skeptic_confidence = float(skeptic.get("confidence", 0.5))
        skeptic_survives = bool(skeptic.get("survives_skepticism", True))
        skeptic_fatal = skeptic.get("fatal_objection")

        confirmer_confirmed = bool(
            confirmer.get("independently_confirmed", False)
        )
        confirmer_confidence = float(confirmer.get("confidence", 0.5))
        recommended_severity = confirmer.get(
            "recommended_severity", gap.get("severity", "MEDIUM")
        )
        if str(recommended_severity).upper() == "HIGH":
            recommended_severity = "MEDIUM"

        skeptic_killed = (
            not skeptic_survives
            and skeptic_confidence >= 0.75
            and bool(skeptic_fatal)
        )

        confirmer_passed = (
            confirmer_confirmed
            and confirmer_confidence >= confidence_threshold
        )

        integrated_confidence = (
            confirmer_confidence * (1 - (skeptic_confidence * 0.3))
        )

        if not skeptic_killed and confirmer_passed:
            gap["confidence"] = round(integrated_confidence, 2)
            gap["severity"] = str(recommended_severity).upper()
            gap["dual_validated"] = True
            gap["validation_detail"] = {
                "skeptic_verdict": "survived",
                "confirmer_verdict": "confirmed",
                "skeptic_confidence": skeptic_confidence,
                "confirmer_confidence": confirmer_confidence,
                "integrated_confidence": integrated_confidence,
                "skeptic_objection": skeptic_fatal,
                "confirmer_evidence": confirmer.get("evidence", ""),
            }
            if not gap.get("description"):
                gap["description"] = _gap_description(gap)
            survived.append(gap)
            console.print(
                f"  [green]✓ Survived ({integrated_confidence:.0%}): "
                f"{_gap_description(gap)[:70]}[/green]"
            )
        else:
            rejected.append(gap)
            reason = (
                skeptic_fatal or "Confirmer did not independently confirm"
            )
            console.print(
                f"  [dim red]✗ Rejected: {_gap_description(gap)[:70]}\n"
                f"    Reason: {str(reason)[:80]}[/dim red]"
            )

    console.print(
        f"\n  [bold]Gap validation:[/bold] "
        f"{len(survived)} survived, {len(rejected)} rejected"
    )

    return survived, rejected
