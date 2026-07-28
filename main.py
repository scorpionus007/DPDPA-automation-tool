import json
import os
import sys

import click
from rich.console import Console

from dpdp_scanner.config import load_config
from dpdp_scanner.feedback import record_false_positive
from dpdp_scanner.ingestor import ingest, SKIP_DIRS
from dpdp_scanner.extractor import extract
from dpdp_scanner.html_reporter import generate_html_report
from dpdp_scanner.rule_engine import (
    run_rules,
    compute_compliance_score,
    attach_remediation_effort,
    compute_total_effort,
)
from dpdp_scanner.llm_layer import run_route_classification, run_llm_pipeline
from dpdp_scanner.reporter import generate_report
from dpdp_scanner.validation.integrated_scorer import compute_integrated_score
from dpdp_scanner.scan_history import (
    get_commit_hash,
    make_repo_key,
    make_finding_key,
    build_file_hash_map,
    get_last_scan,
    get_last_scan_by_repo_name,
    get_scan_findings,
    get_scan_file_hashes,
    compute_delta_with_git,
    save_scan,
    mark_resolved,
    set_db_path,
)


# Ensure we can print emojis on Windows terminals that default to legacy encodings.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

console = Console()


@click.command(name="scan")
# Positional argument: target (GitHub URL or local path)
@click.argument("target")
# Option: --output (default: "report")
@click.option(
    "--output",
    default="report",
    show_default=True,
    help='Output identifier or path (default: "report").',
)
# Flag: --no-llm (skips LLM enrichment)
@click.option(
    "--no-llm",
    is_flag=True,
    default=False,
    help="Skip LLM enrichment of findings.",
)
# Flag: --no-deep-review (skips Layer 5; saves ~6 API calls)
@click.option(
    "--no-deep-review",
    is_flag=True,
    default=False,
    help="Skip Layer 5 deep compliance review to reduce API cost.",
)
# Flag: --json (machine-readable stdout; no PDF; use with GUI)
@click.option(
    "--json",
    "json_mode",
    is_flag=True,
    default=False,
    help="Output result as single JSON to stdout; no PDF. Use DPDP_HISTORY_DB or --history-db.",
)
# Option: override history DB path (for GUI)
@click.option(
    "--history-db",
    default=None,
    envvar="DPDP_HISTORY_DB",
    help="Path to SQLite history DB (default: .dpdp-history/history.db or DPDP_HISTORY_DB).",
)
# Flag: rule debug (print per-rule check summary to terminal)
@click.option(
    "--debug",
    "rule_debug",
    is_flag=True,
    default=False,
    envvar="DPDP_DEBUG",
    help="Print per-rule debug: what each rule checked and how many findings it produced.",
)
@click.option(
    "--include-tests",
    is_flag=True,
    default=False,
    help="Include *_test.go and *_spec.rb files (also set DPDP_INCLUDE_TESTS=1).",
)
@click.option(
    "--token",
    default=None,
    envvar="GITHUB_TOKEN",
    help="GitHub Personal Access Token for private repositories (or set GITHUB_TOKEN).",
)
@click.option(
    "--html",
    "html_mode",
    is_flag=True,
    default=False,
    help="Also generate an HTML companion report alongside the PDF.",
)
@click.option(
    "--report-fp",
    type=(str, str),
    default=None,
    metavar="<RULE> <FILE>",
    help="Record a false positive report without running a scan.",
)
def scan(target, output, no_llm, no_deep_review, json_mode, history_db, rule_debug, include_tests, token, html_mode, report_fp):
    """
    Scan a target repository or local path for compliance issues.

    TARGET can be a GitHub URL or a local filesystem path.
    """
    if history_db:
        set_db_path(history_db)

    # In JSON mode, redirect stdout to stderr so only the final JSON goes to stdout
    real_stdout = sys.stdout
    if json_mode:
        sys.stdout = sys.stderr

    def log(msg):
        if not json_mode:
            console.print(msg)
        else:
            print(msg, file=sys.stderr)

    if report_fp:
        rule_name, file_path = report_fp
        path = record_false_positive(rule_name, file_path, repo_hint=target)
        log(f"[green]Recorded false positive report in {path}[/green]")
        return


    try:
        # 1. Ingest
        log("[bold]Ingesting target...[/bold]")
        repo_files, repo_path = ingest(target, include_test_files=include_tests, github_token=token)
        if len(repo_files) == 0:
            log(
                "[yellow bold]Warning:[/yellow bold] No source files were indexed "
                "(wrong language, everything skipped, or empty tree). "
                "Compliance score is not meaningful until files match ingest rules."
            )

        # 2. Extract
        log("[bold]Extracting signals from repository files...[/bold]")
        extracted = extract(repo_files)
        extracted["is_micro_app"] = len(repo_files) < 15

        # Load optional config from repo root (consent skip segments, suppressions)
        config = load_config(repo_path)
        if config.get("deployment_class"):
            extracted["deployment_class"] = config["deployment_class"]

        # 3. Route classification (before rules — only when LLM enabled; skip for micro repos)
        if not no_llm:
            if not extracted.get("is_micro_app"):
                extracted = run_route_classification(extracted, repo_files)
                uf = len(extracted.get("user_facing_route_files") or [])
                internal = len(extracted.get("internal_route_files") or [])
                log(
                    f"  [dim]Rules will use {uf} user-facing, {internal} internal routes "
                    "(post-classification)[/dim]"
                )
            else:
                log(
                    "  [dim]Micro app (<15 files): skipping LLM route classification "
                    "(regex-based route intent only)[/dim]"
                )
        else:
            log(
                "[dim]  --no-llm: using regex route classification. "
                "Some false positives may appear. "
                "Run without --no-llm for accurate results.[/dim]"
            )

        # 4. Rule engine (runs with accurate route signals)
        log("[bold]Running compliance rules...[/bold]")
        findings, compliance_score, remediation_effort = run_rules(
            extracted, config, quiet=not no_llm, debug=rule_debug
        )

        # 5. Repo identity and delta
        commit_hash = get_commit_hash(repo_path, auto_init=True)
        repo_key, repo_name, repo_url = make_repo_key(target, commit_hash)
        current_hashes = build_file_hash_map(repo_files)

        last_scan = get_last_scan(repo_key)
        if not last_scan and commit_hash:
            last_scan = get_last_scan_by_repo_name(repo_name)

        delta = None
        changed_files_for_llm = None
        if last_scan:
            prev_findings = get_scan_findings(last_scan["id"])
            prev_hashes = get_scan_file_hashes(last_scan["id"])
            delta = compute_delta_with_git(
                repo_path=repo_path,
                current_findings=findings,
                previous_findings=prev_findings,
                current_hashes=current_hashes,
                previous_hashes=prev_hashes,
                current_hash=commit_hash,
                previous_hash=last_scan.get("commit_hash"),
            )
            changed_files_for_llm = delta["changed_files"]

            log(
                f"\n[bold]📊 Delta vs scan on {last_scan['scan_date'][:10]} "
                f"(commit {(last_scan.get('commit_hash') or 'unknown')[:8]}):[/bold]"
            )
            log(f"  [red]✦  {delta['new_count']} new finding(s)[/red]")
            log(f"  [green]✓  {delta['resolved_count']} resolved[/green]")
            log(f"  [grey]─  {delta['unchanged_count']} unchanged[/grey]")
            log(f"  [cyan]~  {delta['changed_files_count']} file(s) changed[/cyan]")
            method = delta.get("delta_method", "hash_comparison")
            log(f"  [dim]Delta method: {method}[/dim]")

            if delta["changed_files_count"] == 0:
                log(
                    "[green]  No file changes detected — deep review will be skipped[/green]"
                )
        else:
            log(
                f"\n[cyan]ℹ First scan for '{repo_name}' — running full review[/cyan]"
            )
            delta = {"is_first_scan": True}

        # 6. LLM pipeline (Layers 1, 2, 3, 4, 5 — no route classification)
        gap_findings = []
        repo_context = {}
        llm_result = None
        if not no_llm:
            log("[bold]Running LLM pipeline...[/bold]")
            llm_result = run_llm_pipeline(
                findings, extracted, repo_files,
                changed_files=changed_files_for_llm,
                skip_deep_review=no_deep_review,
            )
            findings = llm_result["enriched_findings"]
            findings = attach_remediation_effort(findings)
            compliance_score = compute_compliance_score(
                findings,
                indexed_file_count=len(extracted.get("_file_contents") or {}),
            )
            integrated_score = compute_integrated_score(
                rule_findings=findings,
                ai_gaps=llm_result["gap_findings"],
                rejected_findings=[],
                indexed_file_count=len(extracted.get("_file_contents") or {}),
            )
            compliance_score["score"] = integrated_score["integrated_score"]
            compliance_score["grade"] = integrated_score["grade"]
            compliance_score["grade_label"] = integrated_score["grade_label"]
            compliance_score["rule_engine_score"] = integrated_score["rule_engine_score"]
            compliance_score["integrated_score"] = integrated_score["integrated_score"]
            compliance_score["ai_penalty_applied"] = integrated_score["ai_penalty_applied"]
            compliance_score["ai_delta_applied"] = integrated_score.get("ai_delta_applied", 0)
            compliance_score["section_scores"] = integrated_score.get("section_scores", {})
            remediation_effort = compute_total_effort(findings)
            gap_findings = llm_result["gap_findings"]
            repo_context = llm_result["repo_context"]
            # Summary only after LLM (no output before LLM layers are done)
            if not json_mode:
                score_val = compliance_score.get("score")
                grade = compliance_score.get("grade", "—")
                if score_val is None:
                    reason = compliance_score.get("grade_label", "N/A")
                    log(
                        f"\n[bold]DPDP Compliance Score: N/A — {reason}[/bold]"
                    )
                else:
                    log(
                        f"\n[bold]DPDP Compliance Score: {score_val}/100 — Grade {grade}[/bold]"
                    )
        else:
            log("[bold]Skipping LLM pipeline (--no-llm set).[/bold]")
            if not json_mode:
                score_val = compliance_score.get("score")
                grade = compliance_score.get("grade", "—")
                if score_val is None:
                    log(
                        f"\n[bold]DPDP Compliance Score: N/A — "
                        f"{compliance_score.get('grade_label', 'N/A')}[/bold]"
                    )
                else:
                    log(
                        f"\n[bold]DPDP Compliance Score: {score_val}/100 — Grade {grade}[/bold]"
                    )

        # 7. Persist to history
        scan_mode = (
            "fast" if getattr(scan, "fast", False) else
            "quality" if getattr(scan, "quality", False) else
            "no-llm" if no_llm else "default"
        )
        is_delta_scan = last_scan is not None and not delta.get("is_first_scan", False)

        scan_id = save_scan(
            repo_key=repo_key,
            repo_url=repo_url,
            repo_name=repo_name,
            commit_hash=commit_hash or "",
            findings=findings,
            file_hashes=current_hashes,
            output_file=output if output.endswith(".pdf") else f"{output}.pdf",
            scan_mode=scan_mode,
            is_delta=is_delta_scan,
            score=compliance_score.get("score"),
        )

        if is_delta_scan:
            resolved_keys = [
                f["finding_key"] for f in delta.get("resolved_findings", [])
            ]
            mark_resolved(last_scan["id"], resolved_keys)

        # 8. Generate output (JSON or PDF report)
        if json_mode:
            sys.stdout = real_stdout

            def _serialize_finding(f):
                d = dict(f)
                h = d.get("remediation_hours", (0, 0))
                d["remediation_hours"] = [h[0], h[1]] if isinstance(h, (list, tuple)) else [0, 0]
                d["finding_key"] = make_finding_key(f)
                d.setdefault("status", "open")
                return d

            slim_delta = (
                {
                    "is_first_scan": delta.get("is_first_scan", True),
                    "new_count": delta.get("new_count", 0),
                    "resolved_count": delta.get("resolved_count", 0),
                    "unchanged_count": delta.get("unchanged_count", 0),
                    "changed_files_count": delta.get("changed_files_count", 0),
                    "delta_method": delta.get("delta_method", "hash_comparison"),
                    "new_findings": [
                        {
                            "rule": f.get("rule"),
                            "severity": f.get("severity"),
                            "file": f.get("file"),
                            "description": f.get("description"),
                        }
                        for f in delta.get("new_findings", [])
                        if (f.get("severity") or "").upper() in {"HIGH", "MEDIUM"}
                    ][:10],
                }
                if delta
                else {"is_first_scan": True}
            )
            payload = {
                "scan_id": scan_id,
                "repo_name": repo_name,
                "repo_key": repo_key,
                "commit_hash": commit_hash or "",
                "findings": [_serialize_finding(f) for f in findings],
                "compliance_score": compliance_score,
                "remediation_effort": remediation_effort,
                "delta": slim_delta,
                "path_to_display": extracted.get("path_to_display", {}),
            }
            print(json.dumps(payload), flush=True)
        else:
            console.print("[bold]Generating report...[/bold]")
            report_delta = delta
            if delta and last_scan and not delta.get("is_first_scan"):
                report_delta = {
                    **delta,
                    "previous_scan": {
                        "score": int(last_scan.get("score") or 0),
                        "scanned_at": last_scan.get("scan_date"),
                        "current_score": int(compliance_score.get("score") or 0),
                    },
                }

            skipped_files = []
            for rf in repo_files:
                if isinstance(rf, dict) and "_skipped_files" in rf:
                    skipped_files = rf["_skipped_files"]
                    break
            cli_parts = []
            if no_llm:
                cli_parts.append("--no-llm")
            if no_deep_review:
                cli_parts.append("--no-deep-review")
            if include_tests:
                cli_parts.append("--include-tests")

            _scan_metadata = {
                "commit_hash": commit_hash or "",
                "branch": "",
                "scanner_version": "1.0.0",
                "cli_flags": " ".join(cli_parts),
                "skipped_files": skipped_files,
                "dirs_skipped": sorted(SKIP_DIRS),
            }

            generate_report(
                findings,
                output,
                gap_findings=gap_findings,
                repo_context=repo_context,
                path_to_display=extracted.get("path_to_display", {}),
                deep_review=llm_result.get("deep_review") if llm_result else None,
                delta=report_delta,
                compliance_score=compliance_score,
                remediation_effort=remediation_effort,
                repo_name=repo_name,
                files_indexed=len(extracted.get("_file_contents") or {}),
                flow_graph=extracted.get("pii_flow_graph"),
                scan_metadata=_scan_metadata,
                acknowledged_findings=extracted.get("_acknowledged_findings") or [],
            )
            if html_mode:
                generate_html_report(
                    findings,
                    output[:-4] if output.endswith(".pdf") else output,
                    repo_name=repo_name,
                    compliance_score=compliance_score,
                    delta=report_delta,
                    repo_url=repo_url or "",
                    commit_hash=commit_hash or "",
                )

    finally:
        # Cleanup temporary clone if it was a remote repo
        if target.startswith("https://") or target.startswith("git@") or target.endswith(".git"):
            if 'repo_path' in locals() and repo_path and os.path.exists(repo_path):
                import shutil
                import tempfile
                if repo_path.startswith(tempfile.gettempdir()):
                    shutil.rmtree(repo_path, ignore_errors=True)


if __name__ == "__main__":
    scan()

