from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import timedelta
import httpx
import asyncio
import os
import re
import sys
import json
from functools import partial
import base64
from typing import List, Optional, Any  # noqa: F401
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
import asyncio  # noqa: F401
import os  # noqa: F811

# Ensure we can print emojis on Windows terminals that default to legacy encodings.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# --- Scan Engine Imports ---
from dpdp_scanner.ingestor import ingest
from dpdp_scanner.extractor import extract
from dpdp_scanner.rule_engine import (
    run_rules,
    compute_compliance_score,
    attach_remediation_effort,
    compute_total_effort,
)
from dpdp_scanner.config import load_config
from dpdp_scanner.llm_layer import run_route_classification, run_llm_pipeline
from dpdp_scanner.reporter import generate_report
from dpdp_scanner.validation.integrated_scorer import compute_integrated_score
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
)

from sqlalchemy.exc import IntegrityError
from backend.database import engine, Base, get_db
from backend.models import User
from backend.schemas import UserCreate, UserLogin, UserResponse, Token
from backend.auth import (
    get_password_hash, 
    verify_password, 
    create_access_token, 
    ACCESS_TOKEN_EXPIRE_MINUTES,
    get_current_user
)
from backend.models import Scan

# Create tables + run Alembic migrations when available
Base.metadata.create_all(bind=engine)
try:
    from alembic import command
    from alembic.config import Config as AlembicConfig

    _alembic_ini = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alembic.ini")
    if os.path.isfile(_alembic_ini):
        _cfg = AlembicConfig(_alembic_ini)
        command.upgrade(_cfg, "head")
except Exception as _migrate_exc:
    print(f"INFO: Alembic upgrade skipped or failed: {_migrate_exc}")

def _web_scan_compute_delta(
    target: str, repo_path: str, repo_files: list, findings: list
) -> dict:
    """
    Same delta logic as CLI (SQLite scan history): repo key, last scan, changed files for Layer 5.
    """
    commit_hash = get_commit_hash(repo_path, auto_init=True)
    current_hashes = build_file_hash_map(repo_files)
    repo_key, repo_name, repo_url = make_repo_key(target, commit_hash)
    last_scan = get_last_scan(repo_key)
    if not last_scan and commit_hash:
        last_scan = get_last_scan_by_repo_name(repo_name)
    delta: dict = {"is_first_scan": True}
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
    return {
        "commit_hash": commit_hash or "",
        "current_hashes": current_hashes,
        "repo_key": repo_key,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "last_scan": last_scan,
        "delta": delta,
        "changed_files_for_llm": changed_files_for_llm,
    }


app = FastAPI(title="Compliance Scanner API", description="API for User Auth and Scans")

from backend.org_api import router as org_router, github_app_router  # noqa: E402

app.include_router(org_router)
app.include_router(github_app_router)


@app.get("/",include_in_schema=False)
def read_root():
    return {"message": "Welcome to the Compliance Scanner API"}

# Configure CORS so the React frontend can talk to the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-Org-Id"],
)

# Ensure static directory exists and mount it
os.makedirs(os.path.join("backend", "static", "reports"), exist_ok=True)
app.mount("/static", StaticFiles(directory="backend/static"), name="static")


@app.post("/auth/signup", response_model=UserResponse, status_code=status.HTTP_200_OK)
def signup(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    # Check if a user with given email or username already exists
    db_user_email = db.query(User).filter(User.email == user.email).first()
    if db_user_email:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    db_user_username = db.query(User).filter(User.username == user.username).first()
    if db_user_username:
        raise HTTPException(status_code=400, detail="Username already taken")

    # Hash the password & save user
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(new_user)
    
    # Check if request comes from React Frontend
    origin = request.headers.get("origin", "")
    referer = request.headers.get("referer", "")
    
    is_frontend = "localhost:5173" in origin or "localhost:5173" in referer or "localhost:3000" in origin or "localhost:3000" in referer
    
    if is_frontend:
        db.commit()
        db.refresh(new_user)
        return new_user
    else:
        # Request is from Swagger / API testing tool
        db.flush() # Generates an ID temporarily
        user_response = {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "is_active": new_user.is_active
        }
        db.rollback() # Rollback the transaction so it's not saved permanently
        return user_response


@app.post("/auth/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    # Verify User exists by email
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify Password
    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # Build JWT Payload
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/github/login")
async def github_login(redirect: str = "/dashboard", current_email: Optional[str] = None):
    client_id = os.environ.get("GITHUB_CLIENT_ID")
    # Encode state as a JSON string and base64 for safety
    state_data = {"redirect": redirect}
    if current_email:
        state_data["link_email"] = current_email
        
    state_b64 = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
    
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={client_id}&scope=public_repo,user:email&state={state_b64}"
    )

@app.get("/auth/github/callback")
async def github_callback(code: str, state: str = None, db: Session = Depends(get_db)):
    client_id = os.environ.get("GITHUB_CLIENT_ID")
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET")
    
    # Parse state
    redirect_target = "/dashboard"
    link_email = None
    if state:
        try:
            state_data = json.loads(base64.urlsafe_b64decode(state).decode())
            redirect_target = state_data.get("redirect", "/dashboard")
            link_email = state_data.get("link_email")
        except:  # noqa: E722
            redirect_target = state # Fallback for old state format
    
    # 1. Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            params={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to get access token from GitHub")
            
        # 2. Get user info from GitHub
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"}
        )
        github_user = user_response.json()
        
        # 3. Get user email (might be private)
        emails_response = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"token {access_token}"}
        )
        emails = emails_response.json()
        primary_email = next((e["email"] for e in emails if e["primary"]), emails[0]["email"])

    # 4. Handle User Linking / Social Login
    # Try to find a user already associated with this GitHub account
    github_id_str = str(github_user["id"]).strip()
    print(f"DEBUG: Processing GitHub ID: {github_id_str!r}")
    print(f"DEBUG: Link email from state: {link_email!r}")
    
    user_by_github = db.query(User).filter(User.github_id == github_id_str).first()
    if user_by_github:
        print(f"DEBUG: Found user by GitHub ID: {user_by_github.email} (ID: {user_by_github.id})")
    else:
        print("DEBUG: No user found by GitHub ID")
    
    if link_email:
        # User is already logged in (via Email/Password) and wants to connect GitHub
        target_user = db.query(User).filter(User.email == link_email).first()
        
        if user_by_github:
            # Check if this GitHub account belongs to the SAME user
            if user_by_github.id != target_user.id:
                # CONFLICT: This GitHub account is already linked to someone else!
                frontend_url = "http://localhost:5173/auth/callback"
                return RedirectResponse(f"{frontend_url}?error=github_already_linked")
            # If it's the same user, we'll just update the token below
            user = target_user
        else:
            # Not linked to anyone yet, link it to the current user
            user = target_user
    else:
        # Standard Social Login/Signup
        if user_by_github:
            # Login existing GitHub user
            user = user_by_github
        else:
            # Check if a user with the same email already exists
            user_by_email = db.query(User).filter(User.email == primary_email).first()
            if user_by_email:
                user = user_by_email
            else:
                # Create brand new user
                user = User(
                    username=github_user.get("login", "github_user"),
                    email=primary_email,
                    github_id=github_id_str,
                    github_access_token=access_token,
                    is_active=True
                )
                db.add(user)
                # We need to commit here to get the ID if we're generating JWT next
                db.commit()
                db.refresh(user)

    # Finalize: Update GitHub details on the found/created user
    if user:
        print(f"DEBUG: Finalizing user {user.email} (ID: {user.id}) with GitHub ID {github_id_str}")
        
        # Double check for collision before updating if we are changing github_id
        if user.github_id != github_id_str:
            existing = db.query(User).filter(User.github_id == github_id_str).first()
            if existing and existing.id != user.id:
                 print(f"DEBUG: Collision detected for user {user.id} - ID {github_id_str} already belongs to {existing.id}")
                 frontend_url = "http://localhost:5173/auth/callback"
                 return RedirectResponse(f"{frontend_url}?error=github_already_linked")
        
        user.github_id = github_id_str
        user.github_access_token = access_token
        try:
            db.commit()
            db.refresh(user)
        except IntegrityError:
            db.rollback()
            print(f"DEBUG: IntegrityError (UniqueViolation) caught for GitHub ID {github_id_str}")
            frontend_url = "http://localhost:5173/auth/callback"
            return RedirectResponse(f"{frontend_url}?error=github_already_linked")
        except Exception as e:
            print(f"DEBUG: DB Error during commit: {str(e)}")
            db.rollback()
            raise e
    else:
        # Safety fallback (should not happen)
        frontend_url = "http://localhost:5173/auth/callback"
        return RedirectResponse(f"{frontend_url}?error=auth_failed")

    # 5. Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jwt_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    # Redirect back to frontend with the token
    frontend_url = "http://localhost:5173/auth/callback"
    return RedirectResponse(f"{frontend_url}?token={jwt_token}&redirect={redirect_target}")

@app.post("/scans/start")
async def start_scan(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    body = await request.json()
    target = body.get("repo_url")
    if not target:
        raise HTTPException(status_code=400, detail="Repository URL is required")
    skip_deep_review = bool(body.get("skip_deep_review", False))
    include_test_files = bool(body.get("include_tests", False))

    async def run_scan_generator():
        from starlette.concurrency import run_in_threadpool

        try:
            # 1. Ingest (same as CLI)
            yield f"data: {json.dumps({'stage': 'Ingesting repository...', 'progress': 10})}\n\n"
            print(f"INFO: Starting ingestion for {target}")
            repo_files, repo_path = await run_in_threadpool(
                partial(ingest, target, include_test_files=include_test_files, github_token=current_user.github_access_token)
            )
            print(f"INFO: Ingested {len(repo_files)} files")

            if not repo_files:
                yield f"data: {json.dumps({'error': 'No supported source files found in the repository.', 'warning': 'Compliance score would be N/A — check language filters and skipped directories (e.g. test/, docs/).'})}\n\n"
                return

            # 2. Extract
            yield f"data: {json.dumps({'stage': 'Extracting compliance signals...', 'progress': 22})}\n\n"
            extracted = await run_in_threadpool(extract, repo_files)

            # 3. Repo config + LLM route classification (skip for micro apps, same as CLI)
            config = load_config(repo_path)
            if config.get("deployment_class"):
                extracted["deployment_class"] = config["deployment_class"]
            extracted["is_micro_app"] = len(repo_files) < 15
            if not extracted.get("is_micro_app"):
                yield f"data: {json.dumps({'stage': 'Classifying routes (LLM)...', 'progress': 32})}\n\n"
                extracted = await run_in_threadpool(
                    run_route_classification, extracted, repo_files
                )
            else:
                yield f"data: {json.dumps({'stage': 'Skipping route LLM (micro app)...', 'progress': 32})}\n\n"

            # 4. Rule engine
            yield f"data: {json.dumps({'stage': 'Running DPDP compliance rules...', 'progress': 45})}\n\n"
            print(f"INFO: Running rules on {len(repo_files)} files")
            findings, compliance_score, remediation_effort = await run_in_threadpool(
                run_rules, extracted, config, True
            )
            sc = compliance_score.get("score")
            print(
                f"INFO: Rules done: {len(findings)} findings. Score: "
                f"{sc if sc is not None else 'N/A (' + str(compliance_score.get('grade_label', '')) + ')'}"
            )

            # 5. Delta vs SQLite scan history (same as CLI — enables Layer 5 delta mode)
            yield f"data: {json.dumps({'stage': 'Computing scan delta...', 'progress': 52})}\n\n"
            delta_info = await run_in_threadpool(
                _web_scan_compute_delta, target, repo_path, repo_files, findings
            )
            repo_name = delta_info["repo_name"] or "unknown_repo"
            delta = delta_info["delta"]
            last_scan = delta_info["last_scan"]
            changed_files_for_llm = delta_info["changed_files_for_llm"]
            commit_hash = delta_info["commit_hash"]
            current_hashes = delta_info["current_hashes"]
            repo_key = delta_info["repo_key"]
            repo_url = delta_info["repo_url"]

            # 6. LLM pipeline — Layers 1–5
            yield f"data: {json.dumps({'stage': 'Running deep-layer LLM audit (Estimated: 2-3 mins)...', 'progress': 58})}\n\n"

            def _run_llm():
                return run_llm_pipeline(
                    findings,
                    extracted,
                    repo_files,
                    changed_files=changed_files_for_llm,
                    skip_deep_review=skip_deep_review
                    or os.environ.get("DPDP_SKIP_DEEP_REVIEW", "").strip().lower()
                    in ("1", "true", "yes"),
                )

            llm_result = await run_in_threadpool(_run_llm)
            findings = llm_result["enriched_findings"]
            findings = attach_remediation_effort(findings)
            compliance_score = compute_compliance_score(
                findings,
                indexed_file_count=len(extracted.get("_file_contents") or {}),
            )
            integrated_score = compute_integrated_score(
                rule_findings=findings,
                ai_gaps=llm_result.get("gap_findings") or [],
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
            gap_findings = llm_result.get("gap_findings") or []
            repo_context = llm_result.get("repo_context") or {}
            deep_review = llm_result.get("deep_review")

            print(
                f"INFO: LLM pipeline done. Enriched findings: {len(findings)}, gaps: {len(gap_findings)}"
            )

            # 7. PDF report (same extras as CLI)
            yield f"data: {json.dumps({'stage': 'Generating PDF report...', 'progress': 88})}\n\n"

            reports_dir = os.path.join("backend", "static", "reports")
            os.makedirs(reports_dir, exist_ok=True)

            safe_repo = re.sub(r"[^\w\-.]+", "_", repo_name)[:80]
            pdf_filename = f"report_{safe_repo}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = os.path.join(reports_dir, pdf_filename)
            report_url = f"/static/reports/{pdf_filename}"

            report_delta = delta
            if delta and last_scan and not delta.get("is_first_scan"):
                report_delta = {
                    **delta,
                    "previous_scan": {
                        "score": last_scan.get("score"),
                        "scanned_at": last_scan.get("scan_date"),
                        "current_score": compliance_score.get("score"),
                    },
                }

            await run_in_threadpool(
                generate_report,
                findings,
                pdf_path,
                gap_findings=gap_findings,
                repo_context=repo_context,
                path_to_display=extracted.get("path_to_display", {}),
                deep_review=deep_review,
                delta=report_delta,
                compliance_score=compliance_score,
                remediation_effort=remediation_effort,
                repo_name=repo_name,
                files_indexed=len(extracted.get("_file_contents") or {}),
                flow_graph=extracted.get("pii_flow_graph"),
                acknowledged_findings=extracted.get("_acknowledged_findings") or [],
            )

            # 8. Persist to SQLite history (same as CLI — next run gets delta / Layer 5 mode)
            yield f"data: {json.dumps({'stage': 'Saving scan history...', 'progress': 93})}\n\n"
            is_delta_scan = last_scan is not None and not delta.get("is_first_scan", False)
            await run_in_threadpool(
                save_scan,
                repo_key,
                repo_url,
                repo_name,
                commit_hash or None,
                findings,
                current_hashes,
                pdf_filename,
                "web",
                is_delta_scan,
                compliance_score.get("score"),
            )
            if is_delta_scan and last_scan:
                resolved_keys = [
                    f["finding_key"] for f in delta.get("resolved_findings", [])
                ]

                def _mark():
                    mark_resolved(last_scan["id"], resolved_keys)

                await run_in_threadpool(_mark)

            # 9. Postgres app record
            yield f"data: {json.dumps({'stage': 'Finalizing...', 'progress': 97})}\n\n"
            new_scan = Scan(
                repo_name=repo_name,
                repo_url=target,
                score=compliance_score.get("score", 0),
                findings_count=len(findings),
                findings_high=sum(1 for f in findings if f.get("severity") == "HIGH"),
                findings_medium=sum(1 for f in findings if f.get("severity") == "MEDIUM"),
                findings_low=sum(1 for f in findings if f.get("severity") == "LOW"),
                status="completed",
                report_path=report_url,
                owner_id=current_user.id,
                compliance_data={
                    "remediation_effort": remediation_effort,
                    "section_breakdown": compliance_score.get("section_breakdown", []),
                    "llm_pipeline": llm_result.get("pipeline_metadata"),
                },
            )
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)

            yield f"data: {json.dumps({'stage': 'Completed', 'progress': 100, 'scan_id': new_scan.id})}\n\n"

        except asyncio.CancelledError:
            print(f"INFO: Scan cancelled for {target}")
            # Do not yield further on cancelled transport
        except KeyboardInterrupt:
            print("INFO: Keyboard interrupt received during scan")
        except Exception as e:
            print(f"SCAN ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            try:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            except (asyncio.CancelledError, RuntimeError):
                pass
        finally:
            # Cleanup temporary clone if it was a remote repo
            if target.startswith("https://") or target.startswith("git@") or target.endswith(".git"):
                if 'repo_path' in locals() and repo_path and os.path.exists(repo_path):
                    import shutil
                    import tempfile
                    # Only delete if it resides in the system temp directory
                    if repo_path.startswith(tempfile.gettempdir()):
                        print(f"INFO: Cleaning up temporary directory: {repo_path}")
                        shutil.rmtree(repo_path, ignore_errors=True)

    return StreamingResponse(run_scan_generator(), media_type="text/event-stream")

@app.get("/auth/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return current_user

@app.get("/scans")
def get_scans(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.owner_id == current_user.id).order_by(Scan.created_at.desc()).all()
    return scans

@app.get("/scans/{scan_id}/report")
def get_scan_report(scan_id: int, download: bool = False, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        # 1. Fetch scan record
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_id == current_user.id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan report not found")
        
        if not scan.report_path:
            raise HTTPException(status_code=404, detail="No report associated with this scan")
        
        # We store as .pdf but we will serve as .dat to hide from IDM
        filename = scan.report_path.split("/")[-1]
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        file_path = os.path.join(project_root, "backend", "static", "reports", filename)
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="System file missing")

        # Use the actual filename for better browser recognition
        original_filename = filename
        
        from fastapi.responses import FileResponse
        
        # Determine disposition
        disposition = "attachment" if download else "inline"
        
        headers = {
            "Content-Type": "application/pdf",
            "Content-Disposition": f'{disposition}; filename="{original_filename}"',
            "Cache-Control": "no-store",
        }
        
        return FileResponse(
            file_path, 
            headers=headers, 
            media_type="application/pdf"
        )
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        print(f"REPORT FETCH ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail="Data error")

@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}

@app.get("/dashboard/stats")
def get_dashboard_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.owner_id == current_user.id).order_by(Scan.created_at.desc()).all()
    
    if not scans:
        return {
            "score": 0,
            "grade": "N/A",
            "gradeLabel": "No scans yet",
            "totalFindings": 0,
            "findingsHigh": 0,
            "findingsMed": 0,
            "findingsLow": 0,
            "reposScanned": 0,
            "reposNewThisWeek": 0,
            "recentScans": []
        }
    
    # Group scans by repo_name and take the latest one for each
    latest_per_repo = {}
    for s in scans:
        if s.repo_name not in latest_per_repo:
            latest_per_repo[s.repo_name] = s
            
    active_scans = list(latest_per_repo.values())
    
    avg_score = sum(s.score for s in active_scans) / len(active_scans)
    total_findings = sum(s.findings_count for s in active_scans)
    high = sum(s.findings_high for s in active_scans)
    med = sum(s.findings_medium for s in active_scans)
    low = sum(s.findings_low for s in active_scans)
    
    grade = 'A' if avg_score >= 85 else 'B' if avg_score >= 70 else 'C' if avg_score >= 50 else 'D'
    grade_label = "Strong protection" if grade == 'A' else "Adequate protection" if grade == 'B' else "Needs improvement"
    
    section_map = {}
    for scan in active_scans:
        if scan.compliance_data and "section_breakdown" in scan.compliance_data:
            for item in scan.compliance_data["section_breakdown"]:
                name = item["section"]
                if name not in section_map:
                    section_map[name] = {"sum": 0, "count": 0}
                section_map[name]["sum"] += item["pct"]
                section_map[name]["count"] += 1
    
    # Organizational debt across active repositories
    rem_min = sum(scan.compliance_data.get("remediation_effort", {}).get("total_hours_min", 0) for scan in active_scans if scan.compliance_data)
    rem_max = sum(scan.compliance_data.get("remediation_effort", {}).get("total_hours_max", 0) for scan in active_scans if scan.compliance_data)

    real_breakdown = []
    for name, data in section_map.items():
        avg_pct = round(data["sum"] / data["count"])
        status = "good" if avg_pct >= 80 else "moderate" if avg_pct >= 55 else "critical"
        real_breakdown.append({
            "name": name,
            "pct": avg_pct,
            "status": status
        })

    real_breakdown.sort(key=lambda x: x["name"])

    return {
        "score": int(avg_score),
        "grade": grade,
        "gradeLabel": grade_label,
        "totalFindings": total_findings,
        "findingsHigh": high,
        "findingsMed": med,
        "findingsLow": low,
        "reposScanned": len(active_scans),
        "reposNewThisWeek": len([s for s in active_scans if (datetime.utcnow() - s.created_at).days <= 7]),
        "recentScans": scans[:5],
        "complianceMatrix": real_breakdown,
        "remediationEffort": {
            "minHours": rem_min,
            "maxHours": rem_max,
            "minDays": round(rem_min / 8, 1),
            "maxDays": round(rem_max / 8, 1)
        }
    }

@app.get("/github/repos")
async def get_github_repos(current_user: User = Depends(get_current_user)):
    if not current_user.github_access_token:
        raise HTTPException(status_code=400, detail="GitHub account not connected")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user/repos",
            params={"sort": "updated", "per_page": 50, "visibility": "public"},
            headers={"Authorization": f"token {current_user.github_access_token}"}
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch repositories from GitHub")
        
        return response.json()

@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "Backend is running!"}
