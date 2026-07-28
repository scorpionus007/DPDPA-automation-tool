from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_active: bool
    github_id: Optional[str] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: int
    slug: str
    display_name: str
    github_login: Optional[str] = None
    plan: str
    role: Optional[str] = None

    class Config:
        from_attributes = True


class RepositoryResponse(BaseModel):
    id: int
    full_name: str
    default_branch: str
    private: bool
    language: Optional[str] = None
    html_url: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    last_score: Optional[int] = None

    class Config:
        from_attributes = True


class BulkScanRequest(BaseModel):
    repository_ids: List[int]
    scan_mode: str = "fast"  # fast | deep


class OrgMemberInvite(BaseModel):
    email: EmailStr
    role: str = "member"


class OrgEntitySummary(BaseModel):
    id: int
    canonical_name: str
    kind: str
    schema_fingerprint: Optional[str] = None
    occurrence_count: int
    pii_field_count: int
    repo_count: int = 0

    class Config:
        from_attributes = True


class OrgEntityOccurrenceResponse(BaseModel):
    id: int
    repository_id: int
    repo_full_name: str
    file_path: str
    line_number: Optional[int] = None
    role: str
    snippet: Optional[str] = None
    confidence: float

    class Config:
        from_attributes = True


class CrossRepoEdgeResponse(BaseModel):
    id: int
    org_entity_id: int
    entity_name: str
    src_repo_id: int
    src_repo_name: str
    dst_repo_id: int
    dst_repo_name: str
    edge_type: str
    confidence: float

    class Config:
        from_attributes = True


class ScanJobResponse(BaseModel):
    id: int
    repository_id: int
    repo_full_name: str
    status: str
    error: Optional[str] = None
    scan_id: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanBatchResponse(BaseModel):
    id: int
    status: str
    scan_mode: str
    total: int
    succeeded: int
    failed: int
    created_at: datetime
    finished_at: Optional[datetime] = None
    jobs: List[ScanJobResponse] = []

    class Config:
        from_attributes = True


class OrgReportResponse(BaseModel):
    id: int
    status: str
    pdf_path: Optional[str] = None
    html_path: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None
    summary_json: Optional[dict] = None

    class Config:
        from_attributes = True
