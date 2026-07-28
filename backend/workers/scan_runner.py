"""RQ worker: run a single repository scan for an organization bulk job."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from datetime import datetime
from functools import partial

from backend.database import SessionLocal
from backend.models import (
    GithubInstallation,
    Repository,
    Scan,
    ScanBatch,
    ScanJob,
)
from dpdp_scanner.config import load_config
from dpdp_scanner.extractor import extract
from dpdp_scanner.ingestor import ingest
from dpdp_scanner.kb.merge import merge_into_org_kb
from dpdp_scanner.llm_layer import run_llm_pipeline, run_route_classification
from dpdp_scanner.reporter import generate_report
from dpdp_scanner.rule_engine import (
    attach_remediation_effort,
    compute_compliance_score,
    compute_total_effort,
    run_rules,
)
from dpdp_scanner.scan_history import (
    build_file_hash_map,
    compute_delta_with_git,
    get_commit_hash,
    get_last_scan,
    get_last_scan_by_repo_name,
    get_scan_file_hashes,
    get_scan_findings,
    make_repo_key,
    mark_resolved,
    save_scan,
    set_db_path,
)
from dpdp_scanner.validation.integrated_scorer import compute_integrated_score


def _org_history_db(org_slug: str) -> str:
    base = os.path.join(".dpdp-history", org_slug)
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "history.db")


def run_scan_job(scan_job_id: int) -> dict:
    """Execute one ScanJob end-to-end. Called by RQ worker or inline fallback."""
    db = SessionLocal()
    repo_path = None
    target = None
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return {"error": "job not found"}
        if job.status == "cancelled":
            return {"status": "cancelled"}

        batch = db.query(ScanBatch).filter(ScanBatch.id == job.batch_id).first()
        repo_row = db.query(Repository).filter(Repository.id == job.repository_id).first()
        if not batch or not repo_row:
            job.status = "failed"
            job.error = "batch or repository missing"
            db.commit()
            return {"error": job.error}

        from backend.models import Organization

        org = db.query(Organization).filter(Organization.id == batch.org_id).first()
        if not org:
            job.status = "failed"
            job.error = "organization missing"
            db.commit()
            return {"error": job.error}
        set_db_path(_org_history_db(org.slug))

        job.status = "running"
        job.started_at = datetime.utcnow()
        if batch.status == "pending":
            batch.status = "running"
        db.commit()

        installation = (
            db.query(GithubInstallation)
            .filter(GithubInstallation.org_id == org.id)
            .order_by(GithubInstallation.id.desc())
            .first()
        )
        github_token = None
        if installation:
            import asyncio
            from backend.github_app_client import get_installation_token

            github_token = asyncio.run(
                get_installation_token(installation.installation_id)
            )

        target = repo_row.html_url or f"https://github.com/{repo_row.full_name}"
        skip_deep = batch.scan_mode == "fast"
        include_tests = False

        repo_files, repo_path = ingest(
            target,
            include_test_files=include_tests,
            github_token=github_token,
        )
        if not repo_files:
            raise ValueError("No supported source files found")

        extracted = extract(repo_files)
        config = load_config(repo_path)
        if config.get("deployment_class"):
            extracted["deployment_class"] = config["deployment_class"]
        extracted["is_micro_app"] = len(repo_files) < 15
        if not extracted.get("is_micro_app"):
            extracted = run_route_classification(extracted, repo_files)

        findings, compliance_score, remediation_effort = run_rules(
            extracted, config, True
        )

        commit_hash = get_commit_hash(repo_path, auto_init=True)
        current_hashes = build_file_hash_map(repo_files)
        repo_key, repo_name, repo_url = make_repo_key(target, commit_hash)
        last_scan = get_last_scan(repo_key)
        if not last_scan and commit_hash:
            last_scan = get_last_scan_by_repo_name(repo_name)
        delta = {"is_first_scan": True}
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
            changed_files_for_llm = delta.get("changed_files")

        llm_result = run_llm_pipeline(
            findings,
            extracted,
            repo_files,
            changed_files=changed_files_for_llm,
            skip_deep_review=skip_deep
            or os.environ.get("DPDP_SKIP_DEEP_REVIEW", "").strip().lower()
            in ("1", "true", "yes"),
        )
        findings = attach_remediation_effort(llm_result["enriched_findings"])
        compliance_score = compute_compliance_score(
            findings,
            indexed_file_count=len(extracted.get("_file_contents") or {}),
        )
        integrated = compute_integrated_score(
            rule_findings=findings,
            ai_gaps=llm_result.get("gap_findings") or [],
            rejected_findings=[],
            indexed_file_count=len(extracted.get("_file_contents") or {}),
        )
        compliance_score["score"] = integrated["integrated_score"]
        compliance_score["grade"] = integrated["grade"]
        compliance_score["grade_label"] = integrated["grade_label"]
        remediation_effort = compute_total_effort(findings)
        gap_findings = llm_result.get("gap_findings") or []
        repo_context = llm_result.get("repo_context") or {}
        deep_review = llm_result.get("deep_review")

        reports_dir = os.path.join("backend", "static", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        safe_repo = re.sub(r"[^\w\-.]+", "_", repo_name)[:80]
        pdf_filename = f"report_{safe_repo}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = os.path.join(reports_dir, pdf_filename)
        report_url = f"/static/reports/{pdf_filename}"

        generate_report(
            findings,
            pdf_path,
            gap_findings=gap_findings,
            repo_context=repo_context,
            path_to_display=extracted.get("path_to_display", {}),
            deep_review=deep_review,
            delta=delta,
            compliance_score=compliance_score,
            remediation_effort=remediation_effort,
            repo_name=repo_name,
            files_indexed=len(extracted.get("_file_contents") or {}),
            flow_graph=extracted.get("pii_flow_graph"),
            acknowledged_findings=extracted.get("_acknowledged_findings") or [],
        )

        is_delta_scan = last_scan is not None and not delta.get("is_first_scan", False)
        save_scan(
            repo_key,
            repo_url,
            repo_name,
            commit_hash or None,
            findings,
            current_hashes,
            pdf_filename,
            "org_bulk",
            is_delta_scan,
            compliance_score.get("score"),
        )
        if is_delta_scan and last_scan:
            mark_resolved(
                last_scan["id"],
                [f["finding_key"] for f in delta.get("resolved_findings", [])],
            )

        new_scan = Scan(
            repo_name=repo_name,
            repo_url=target,
            score=int(compliance_score.get("score") or 0),
            findings_count=len(findings),
            findings_high=sum(1 for f in findings if f.get("severity") == "HIGH"),
            findings_medium=sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            findings_low=sum(1 for f in findings if f.get("severity") == "LOW"),
            status="completed",
            report_path=report_url,
            owner_id=batch.requested_by_user_id,
            org_id=org.id,
            repository_id=repo_row.id,
            compliance_data={
                "remediation_effort": remediation_effort,
                "section_breakdown": compliance_score.get("section_breakdown", []),
                "findings": findings[:200],
            },
        )
        db.add(new_scan)
        db.flush()

        merge_into_org_kb(db, org.id, repo_row.id, new_scan.id, extracted)

        repo_row.last_scan_at = datetime.utcnow()
        repo_row.last_score = new_scan.score

        job.status = "completed"
        job.scan_id = new_scan.id
        job.finished_at = datetime.utcnow()
        batch.succeeded = (batch.succeeded or 0) + 1
        db.commit()

        _maybe_finish_batch(db, batch.id)
        return {"status": "completed", "scan_id": new_scan.id}

    except Exception as exc:
        db.rollback()
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job:
            job.status = "failed"
            job.error = str(exc)[:2000]
            job.finished_at = datetime.utcnow()
            batch = db.query(ScanBatch).filter(ScanBatch.id == job.batch_id).first()
            if batch:
                batch.failed = (batch.failed or 0) + 1
            db.commit()
            if batch:
                _maybe_finish_batch(db, batch.id)
        return {"status": "failed", "error": str(exc)}
    finally:
        if target and repo_path and os.path.exists(repo_path):
            if repo_path.startswith(tempfile.gettempdir()):
                shutil.rmtree(repo_path, ignore_errors=True)
        db.close()


def _maybe_finish_batch(db, batch_id: int) -> None:
    batch = db.query(ScanBatch).filter(ScanBatch.id == batch_id).first()
    if not batch:
        return
    done = (batch.succeeded or 0) + (batch.failed or 0)
    if done >= (batch.total or 0):
        batch.status = "completed" if (batch.failed or 0) == 0 else "completed"
        batch.finished_at = datetime.utcnow()
        db.commit()


def generate_org_report_job(org_report_id: int) -> dict:
    """RQ job wrapper for org-wide report generation."""
    from dpdp_scanner.org_reporter import generate_org_report

    db = SessionLocal()
    try:
        from backend.models import OrgReport

        report = db.query(OrgReport).filter(OrgReport.id == org_report_id).first()
        if not report:
            return {"error": "report not found"}
        report.status = "running"
        db.commit()
        result = generate_org_report(report.org_id, db, report_id=org_report_id)
        report.status = "completed"
        report.pdf_path = result.get("pdf_path")
        report.html_path = result.get("html_path")
        report.summary_json = result.get("summary")
        report.finished_at = datetime.utcnow()
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        from backend.models import OrgReport

        report = db.query(OrgReport).filter(OrgReport.id == org_report_id).first()
        if report:
            report.status = "failed"
            report.error = str(exc)[:2000]
            report.finished_at = datetime.utcnow()
            db.commit()
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()
