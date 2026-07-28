"""
Shared post–rule-engine pipeline: repo memory, finding validation, LLM layers, integrated score.
Used by CLI (main.py) and backend web scans.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from dpdp_scanner.lib.llm_client import LLMClient
from dpdp_scanner.llm_layer import GEMINI_API_KEY, genai, run_llm_pipeline
from dpdp_scanner.redactor import redact
from dpdp_scanner.rule_engine import (
    attach_remediation_effort,
    compute_compliance_score,
    compute_total_effort,
)
from dpdp_scanner.validation.file_context import build_repo_memory
from dpdp_scanner.validation.finding_validator import validate_all_findings
from dpdp_scanner.validation.integrated_scorer import compute_integrated_score


def run_post_rules_llm_with_validation(
    findings: List[Dict],
    extracted: Dict,
    repo_files: List[Dict],
    changed_files: Optional[List[str]] = None,
    skip_deep_review: bool = False,
) -> Tuple[
    List[Dict],
    List[Dict],
    Dict,
    Dict,
    List[Dict],
    Optional[Dict],
    Dict,
    Dict,
    Optional[Dict],
]:
    """
    Returns:
      findings (enriched),
      gap_findings,
      repo_context,
      llm_result (full dict from run_llm_pipeline),
      rejected_findings,
      repo_memory,
      compliance_score (merged with integrated score),
      remediation_effort,
      integrated_score_data (None if API key missing)
    """
    if not GEMINI_API_KEY or genai is None:
        llm_result = run_llm_pipeline(
            findings,
            extracted,
            repo_files,
            changed_files=changed_files,
            skip_deep_review=skip_deep_review,
        )
        f = llm_result["enriched_findings"]
        attach_remediation_effort(f)
        cs = compute_compliance_score(
            f, indexed_file_count=len(extracted.get("_file_contents") or {})
        )
        return (
            f,
            llm_result.get("gap_findings") or [],
            llm_result.get("repo_context") or {},
            llm_result,
            [],
            {},
            cs,
            compute_total_effort(f),
            None,
        )

    llm_client = LLMClient()
    fc = extracted.get("_file_contents") or {}
    redacted_contents = {}
    for path, content in fc.items():
        redacted_contents[path], _ = redact(content or "", path)

    max_mem = 10 if extracted.get("is_micro_app") else 30
    repo_memory = build_repo_memory(
        findings, redacted_contents, llm_client, max_files=max_mem
    )
    confirmed_findings, rejected_findings = validate_all_findings(
        findings, redacted_contents, repo_memory, llm_client
    )
    llm_result = run_llm_pipeline(
        confirmed_findings,
        extracted,
        repo_files,
        changed_files=changed_files,
        skip_deep_review=skip_deep_review,
    )
    enriched = llm_result["enriched_findings"]
    attach_remediation_effort(enriched)
    remediation_effort = compute_total_effort(enriched)
    gap_findings = llm_result.get("gap_findings") or []
    repo_context = llm_result.get("repo_context") or {}

    integrated = compute_integrated_score(
        rule_findings=enriched,
        ai_gaps=gap_findings,
        rejected_findings=rejected_findings,
        indexed_file_count=len(extracted.get("_file_contents") or {}),
    )
    base_cs = compute_compliance_score(
        enriched, indexed_file_count=len(extracted.get("_file_contents") or {})
    )
    compliance_score = dict(base_cs)
    compliance_score["score"] = integrated["integrated_score"]
    compliance_score["grade"] = integrated["grade"]
    compliance_score["grade_label"] = integrated.get(
        "grade_label", compliance_score.get("grade_label", "")
    )
    compliance_score["rule_engine_score"] = integrated["rule_engine_score"]
    compliance_score["integrated_score"] = integrated["integrated_score"]
    compliance_score["ai_penalty_applied"] = integrated["ai_penalty_applied"]
    compliance_score["ai_delta_applied"] = integrated.get("ai_delta_applied", 0)
    compliance_score["section_scores"] = integrated.get("section_scores", {})
    compliance_score["validation_stats"] = integrated["validation_stats"]
    compliance_score["penalty_exposure"] = integrated.get("penalty_exposure", {})

    return (
        enriched,
        gap_findings,
        repo_context,
        llm_result,
        rejected_findings,
        repo_memory,
        compliance_score,
        remediation_effort,
        integrated,
    )
