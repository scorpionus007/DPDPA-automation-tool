"""Organization-wide API routes (GitHub App, bulk scan, KB, org reports)."""

from __future__ import annotations

import asyncio
import base64
import json  # noqa: F401 — used in stream
import os
import re
import time
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    get_current_org,
    get_current_org_admin,
    get_current_user,
)
from backend.database import get_db
from backend.github_app_client import (
    app_install_url,
    get_installation,
    is_github_app_configured,
    list_installation_repos,
)
from backend.models import (
    CrossRepoEdge,
    GithubInstallation,
    OrgEntity,
    OrgEntityOccurrence,
    OrgMembership,
    OrgReport,
    Organization,
    Repository,
    Scan,
    ScanBatch,
    ScanJob,
    User,
)
from backend.queue import enqueue_org_report, enqueue_scan_job
from backend.schemas import (
    BulkScanRequest,
    CrossRepoEdgeResponse,
    OrganizationResponse,
    OrgEntityOccurrenceResponse,
    OrgEntitySummary,
    OrgMemberInvite,
    OrgReportResponse,
    RepositoryResponse,
    ScanBatchResponse,
    ScanJobResponse,
    UserResponse,
)
router = APIRouter(prefix="/orgs", tags=["organizations"])

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "org").lower()).strip("-")
    return s[:80] or "org"


async def _sync_repositories(db: Session, org: Organization, installation_id: str) -> int:
    repos = await list_installation_repos(installation_id)
    count = 0
    for gh in repos:
        gh_id = str(gh.get("id"))
        full_name = gh.get("full_name") or ""
        row = (
            db.query(Repository)
            .filter(Repository.org_id == org.id, Repository.github_repo_id == gh_id)
            .first()
        )
        if row:
            row.full_name = full_name
            row.default_branch = gh.get("default_branch") or "main"
            row.private = bool(gh.get("private"))
            row.language = gh.get("language")
            row.html_url = gh.get("html_url")
        else:
            db.add(
                Repository(
                    org_id=org.id,
                    github_repo_id=gh_id,
                    full_name=full_name,
                    default_branch=gh.get("default_branch") or "main",
                    private=bool(gh.get("private")),
                    language=gh.get("language"),
                    html_url=gh.get("html_url"),
                )
            )
            count += 1
    db.commit()
    return count


@router.get("/connect")
async def org_connect(
    current_user: User = Depends(get_current_user),
):
    if not is_github_app_configured():
        raise HTTPException(
            status_code=503,
            detail="GitHub App not configured. Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY.",
        )
    state_payload = {
        "user_id": current_user.id,
        "ts": int(time.time()),
    }
    state = base64.urlsafe_b64encode(json.dumps(state_payload).encode()).decode()
    return RedirectResponse(app_install_url(state))


github_app_router = APIRouter(tags=["github-app"])


@github_app_router.get("/github/app/callback", include_in_schema=False)
async def github_app_callback(
    installation_id: Optional[str] = None,
    setup_action: Optional[str] = None,
    state: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if not installation_id:
        return RedirectResponse(f"{FRONTEND_URL}/org/connect?error=missing_installation")
    try:
        if state:
            payload = json.loads(base64.urlsafe_b64decode(state + "==").decode())
            user_id = payload.get("user_id")
        else:
            user_id = None
    except Exception:
        user_id = None

    inst_data = await get_installation(installation_id)
    account = inst_data.get("account") or {}
    login = account.get("login") or "unknown"
    account_type = account.get("type") or "Organization"

    slug = _slugify(login)
    org = db.query(Organization).filter(Organization.slug == slug).first()
    if not org:
        org = Organization(slug=slug, display_name=login, github_login=login)
        db.add(org)
        db.flush()

    gh_inst = (
        db.query(GithubInstallation)
        .filter(GithubInstallation.installation_id == str(installation_id))
        .first()
    )
    if not gh_inst:
        gh_inst = GithubInstallation(
            org_id=org.id,
            installation_id=str(installation_id),
            account_login=login,
            account_type=account_type,
        )
        db.add(gh_inst)
    else:
        gh_inst.org_id = org.id
        gh_inst.account_login = login

    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            existing = (
                db.query(OrgMembership)
                .filter(OrgMembership.org_id == org.id, OrgMembership.user_id == user.id)
                .first()
            )
            if not existing:
                db.add(OrgMembership(org_id=org.id, user_id=user.id, role="owner"))

    db.commit()
    await _sync_repositories(db, org, installation_id)

    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            token = create_access_token(
                data={"sub": user.email},
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            )
            return RedirectResponse(
                f"{FRONTEND_URL}/auth/callback?token={token}&redirect=/org/repos&org_id={org.id}"
            )
    return RedirectResponse(f"{FRONTEND_URL}/org/repos?org_id={org.id}")


@router.get("", response_model=List[OrganizationResponse])
def list_orgs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Organization, OrgMembership.role)
        .join(OrgMembership, OrgMembership.org_id == Organization.id)
        .filter(OrgMembership.user_id == current_user.id)
        .all()
    )
    out = []
    for org, role in rows:
        out.append(
            OrganizationResponse(
                id=org.id,
                slug=org.slug,
                display_name=org.display_name,
                github_login=org.github_login,
                plan=org.plan or "free",
                role=role,
            )
        )
    return out


@router.get("/{org_id}/dashboard")
def org_dashboard(
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    repos = db.query(Repository).filter(Repository.org_id == org.id).all()
    scans = (
        db.query(Scan)
        .filter(Scan.org_id == org.id)
        .order_by(Scan.created_at.desc())
        .limit(500)
        .all()
    )
    latest_per_repo = {}
    for s in scans:
        key = s.repository_id or s.repo_name
        if key not in latest_per_repo:
            latest_per_repo[key] = s
    active = list(latest_per_repo.values())
    if not active:
        return {
            "score": 0,
            "grade": "N/A",
            "reposTotal": len(repos),
            "reposScanned": 0,
            "entityCount": db.query(OrgEntity).filter(OrgEntity.org_id == org.id).count(),
            "edgeCount": db.query(CrossRepoEdge).filter(CrossRepoEdge.org_id == org.id).count(),
            "topRisks": [],
            "repoScores": [],
        }
    avg = sum(s.score or 0 for s in active) / len(active)
    grade = "A" if avg >= 85 else "B" if avg >= 70 else "C" if avg >= 50 else "D"
    rule_counts: dict = {}
    for s in active:
        if not s.compliance_data:
            continue
        for f in s.compliance_data.get("findings") or []:
            rule = f.get("rule", "UNKNOWN")
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
    top_risks = sorted(rule_counts.items(), key=lambda x: -x[1])[:10]
    return {
        "score": int(avg),
        "grade": grade,
        "reposTotal": len(repos),
        "reposScanned": len(active),
        "entityCount": db.query(OrgEntity).filter(OrgEntity.org_id == org.id).count(),
        "edgeCount": db.query(CrossRepoEdge).filter(CrossRepoEdge.org_id == org.id).count(),
        "topRisks": [{"rule": r, "repoCount": c} for r, c in top_risks],
        "repoScores": [
            {
                "repoId": s.repository_id,
                "repoName": s.repo_name,
                "score": s.score,
                "scannedAt": s.created_at.isoformat() if s.created_at else None,
            }
            for s in active[:50]
        ],
    }


@router.post("/{org_id}/members", response_model=dict)
def invite_member(
    body: OrgMemberInvite,
    org_admin=Depends(get_current_org_admin),
    db: Session = Depends(get_db),
):
    org, _ = org_admin
    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found — they must sign up first")
    if body.role not in ("owner", "admin", "member"):
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = (
        db.query(OrgMembership)
        .filter(OrgMembership.org_id == org.id, OrgMembership.user_id == user.id)
        .first()
    )
    if existing:
        existing.role = body.role
    else:
        db.add(OrgMembership(org_id=org.id, user_id=user.id, role=body.role))
    db.commit()
    return {"message": "Member added", "user_id": user.id}


@router.get("/{org_id}/repositories", response_model=List[RepositoryResponse])
async def list_repositories(
    refresh: bool = False,
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    if refresh:
        inst = (
            db.query(GithubInstallation)
            .filter(GithubInstallation.org_id == org.id)
            .first()
        )
        if inst:
            await _sync_repositories(db, org, inst.installation_id)
    repos = (
        db.query(Repository)
        .filter(Repository.org_id == org.id)
        .order_by(Repository.full_name)
        .all()
    )
    return repos


@router.post("/{org_id}/bulk-scan", response_model=ScanBatchResponse)
def start_bulk_scan(
    body: BulkScanRequest,
    org_admin=Depends(get_current_org_admin),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org, _ = org_admin
    if not body.repository_ids:
        raise HTTPException(status_code=400, detail="repository_ids required")
    limit = org.bulk_scan_limit or 100
    if len(body.repository_ids) > limit:
        raise HTTPException(
            status_code=400,
            detail=f"Bulk scan limit is {limit} repositories for plan '{org.plan}'",
        )
    repos = (
        db.query(Repository)
        .filter(Repository.org_id == org.id, Repository.id.in_(body.repository_ids))
        .all()
    )
    if len(repos) != len(body.repository_ids):
        raise HTTPException(status_code=400, detail="Invalid repository id(s)")

    batch = ScanBatch(
        org_id=org.id,
        requested_by_user_id=current_user.id,
        status="pending",
        scan_mode=body.scan_mode if body.scan_mode in ("fast", "deep") else "fast",
        total=len(repos),
    )
    db.add(batch)
    db.flush()

    for repo in repos:
        job = ScanJob(batch_id=batch.id, repository_id=repo.id, status="queued")
        db.add(job)
        db.flush()
        rq_id = enqueue_scan_job(job.id)
        if rq_id:
            job.rq_job_id = rq_id
    batch.status = "running"
    db.commit()
    db.refresh(batch)
    return _batch_to_response(db, batch)


@router.get("/{org_id}/bulk-scan/{batch_id}", response_model=ScanBatchResponse)
def get_bulk_scan(
    batch_id: int,
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    batch = (
        db.query(ScanBatch)
        .filter(ScanBatch.id == batch_id, ScanBatch.org_id == org.id)
        .first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return _batch_to_response(db, batch)


@router.get("/{org_id}/bulk-scan/{batch_id}/stream")
async def stream_bulk_scan(
    batch_id: int,
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership

    from backend.database import SessionLocal

    async def generator():
        last_snapshot = ""
        while True:
            session = SessionLocal()
            try:
                batch = (
                    session.query(ScanBatch)
                    .filter(ScanBatch.id == batch_id, ScanBatch.org_id == org.id)
                    .first()
                )
                if not batch:
                    yield f"data: {json.dumps({'error': 'not found'})}\n\n"
                    break
                resp = _batch_to_response(session, batch)
                snap = json.dumps(resp.model_dump(), default=str)
                if snap != last_snapshot:
                    last_snapshot = snap
                    yield f"data: {snap}\n\n"
                if batch.status in ("completed", "failed", "cancelled"):
                    break
            finally:
                session.close()
            await asyncio.sleep(2)

    return StreamingResponse(generator(), media_type="text/event-stream")


@router.post("/{org_id}/bulk-scan/{batch_id}/cancel")
def cancel_bulk_scan(
    batch_id: int,
    org_admin=Depends(get_current_org_admin),
    db: Session = Depends(get_db),
):
    org, _ = org_admin
    batch = (
        db.query(ScanBatch)
        .filter(ScanBatch.id == batch_id, ScanBatch.org_id == org.id)
        .first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    for job in batch.jobs:
        if job.status in ("queued", "running"):
            job.status = "cancelled"
    batch.status = "cancelled"
    db.commit()
    return {"message": "Batch cancelled"}


@router.post("/{org_id}/bulk-scan/jobs/{job_id}/retry")
def retry_scan_job(
    job_id: int,
    org_admin=Depends(get_current_org_admin),
    db: Session = Depends(get_db),
):
    org, _ = org_admin
    job = (
        db.query(ScanJob)
        .join(ScanBatch)
        .filter(ScanJob.id == job_id, ScanBatch.org_id == org.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job.status = "queued"
    job.error = None
    job.rq_job_id = enqueue_scan_job(job.id)
    db.commit()
    return {"message": "Job re-queued", "job_id": job.id}


@router.get("/{org_id}/entities", response_model=List[OrgEntitySummary])
def list_entities(
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
    limit: int = 100,
    offset: int = 0,
):
    org, _ = org_membership
    entities = (
        db.query(OrgEntity)
        .filter(OrgEntity.org_id == org.id)
        .order_by(OrgEntity.occurrence_count.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    out = []
    for e in entities:
        repo_count = (
            db.query(func.count(func.distinct(OrgEntityOccurrence.repository_id)))
            .filter(OrgEntityOccurrence.org_entity_id == e.id)
            .scalar()
        ) or 0
        out.append(
            OrgEntitySummary(
                id=e.id,
                canonical_name=e.canonical_name,
                kind=e.kind or "data_entity",
                schema_fingerprint=e.schema_fingerprint,
                occurrence_count=e.occurrence_count or 0,
                pii_field_count=e.pii_field_count or 0,
                repo_count=repo_count,
            )
        )
    return out


@router.get("/{org_id}/entities/{entity_id}")
def get_entity_detail(
    entity_id: int,
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    entity = (
        db.query(OrgEntity)
        .filter(OrgEntity.id == entity_id, OrgEntity.org_id == org.id)
        .first()
    )
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    occs = (
        db.query(OrgEntityOccurrence, Repository.full_name)
        .join(Repository, Repository.id == OrgEntityOccurrence.repository_id)
        .filter(OrgEntityOccurrence.org_entity_id == entity.id)
        .all()
    )
    occurrences = [
        OrgEntityOccurrenceResponse(
            id=o.id,
            repository_id=o.repository_id,
            repo_full_name=fn,
            file_path=o.file_path,
            line_number=o.line_number,
            role=o.role,
            snippet=o.snippet,
            confidence=o.confidence or 0.7,
        )
        for o, fn in occs
    ]
    return {
        "entity": OrgEntitySummary(
            id=entity.id,
            canonical_name=entity.canonical_name,
            kind=entity.kind,
            schema_fingerprint=entity.schema_fingerprint,
            occurrence_count=entity.occurrence_count or 0,
            pii_field_count=entity.pii_field_count or 0,
            repo_count=len({o.repository_id for o, _ in occs}),
        ),
        "occurrences": occurrences,
    }


@router.get("/{org_id}/data-flows", response_model=List[CrossRepoEdgeResponse])
def list_data_flows(
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    edges = (
        db.query(CrossRepoEdge, OrgEntity)
        .join(OrgEntity, OrgEntity.id == CrossRepoEdge.org_entity_id)
        .filter(CrossRepoEdge.org_id == org.id)
        .all()
    )
    repo_cache = {
        r.id: r.full_name
        for r in db.query(Repository).filter(Repository.org_id == org.id).all()
    }
    out = []
    for edge, entity in edges:
        out.append(
            CrossRepoEdgeResponse(
                id=edge.id,
                org_entity_id=entity.id,
                entity_name=entity.canonical_name,
                src_repo_id=edge.src_repo_id,
                src_repo_name=repo_cache.get(edge.src_repo_id, str(edge.src_repo_id)),
                dst_repo_id=edge.dst_repo_id,
                dst_repo_name=repo_cache.get(edge.dst_repo_id, str(edge.dst_repo_id)),
                edge_type=edge.edge_type,
                confidence=edge.confidence or 0.7,
            )
        )
    return out


@router.post("/{org_id}/reports/generate", response_model=OrgReportResponse)
def generate_org_report_endpoint(
    org_admin=Depends(get_current_org_admin),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org, _ = org_admin
    report = OrgReport(
        org_id=org.id,
        requested_by_user_id=current_user.id,
        status="pending",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    enqueue_org_report(report.id)
    return report


@router.get("/{org_id}/reports", response_model=List[OrgReportResponse])
def list_org_reports(
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    return (
        db.query(OrgReport)
        .filter(OrgReport.org_id == org.id)
        .order_by(OrgReport.created_at.desc())
        .limit(50)
        .all()
    )


@router.get("/{org_id}/reports/{report_id}")
def download_org_report(
    report_id: int,
    download: bool = False,
    format: str = "pdf",
    org_membership=Depends(get_current_org),
    db: Session = Depends(get_db),
):
    org, _ = org_membership
    report = (
        db.query(OrgReport)
        .filter(OrgReport.id == report_id, OrgReport.org_id == org.id)
        .first()
    )
    if not report or report.status != "completed":
        raise HTTPException(status_code=404, detail="Report not ready")
    path_field = report.html_path if format == "html" else report.pdf_path
    if not path_field:
        raise HTTPException(status_code=404, detail="Report file missing")
    filename = path_field.split("/")[-1]
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(project_root, "backend", "static", "reports", filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File missing on disk")
    disposition = "attachment" if download else "inline"
    media = "text/html" if format == "html" else "application/pdf"
    return FileResponse(
        file_path,
        media_type=media,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'},
    )


def _batch_to_response(db: Session, batch: ScanBatch) -> ScanBatchResponse:
    jobs = db.query(ScanJob).filter(ScanJob.batch_id == batch.id).all()
    job_responses = []
    for j in jobs:
        repo = db.query(Repository).filter(Repository.id == j.repository_id).first()
        job_responses.append(
            ScanJobResponse(
                id=j.id,
                repository_id=j.repository_id,
                repo_full_name=repo.full_name if repo else "",
                status=j.status,
                error=j.error,
                scan_id=j.scan_id,
                started_at=j.started_at,
                finished_at=j.finished_at,
            )
        )
    return ScanBatchResponse(
        id=batch.id,
        status=batch.status,
        scan_mode=batch.scan_mode,
        total=batch.total or 0,
        succeeded=batch.succeeded or 0,
        failed=batch.failed or 0,
        created_at=batch.created_at,
        finished_at=batch.finished_at,
        jobs=job_responses,
    )
