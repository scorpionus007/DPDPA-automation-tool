from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=True)
    github_id = Column(String, unique=True, index=True, nullable=True)
    github_access_token = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="owner")
    memberships = relationship("OrgMembership", back_populates="user")


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, index=True, nullable=False)
    display_name = Column(String, nullable=False)
    github_login = Column(String, nullable=True, index=True)
    plan = Column(String, default="free")  # free | pro | enterprise
    bulk_scan_limit = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.utcnow)

    installations = relationship("GithubInstallation", back_populates="organization")
    memberships = relationship("OrgMembership", back_populates="organization")
    repositories = relationship("Repository", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
    entities = relationship("OrgEntity", back_populates="organization")
    cross_repo_edges = relationship("CrossRepoEdge", back_populates="organization")
    scan_batches = relationship("ScanBatch", back_populates="organization")
    org_reports = relationship("OrgReport", back_populates="organization")


class GithubInstallation(Base):
    __tablename__ = "github_installations"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    installation_id = Column(String, unique=True, index=True, nullable=False)
    account_login = Column(String, nullable=False)
    account_type = Column(String, default="Organization")  # Organization | User
    suspended_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="installations")


class OrgMembership(Base):
    __tablename__ = "org_memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_org_user"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String, default="member")  # owner | admin | member
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User", back_populates="memberships")


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("org_id", "github_repo_id", name="uq_org_github_repo"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    github_repo_id = Column(String, nullable=False)
    full_name = Column(String, nullable=False, index=True)
    default_branch = Column(String, default="main")
    private = Column(Boolean, default=False)
    language = Column(String, nullable=True)
    html_url = Column(String, nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    last_score = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository")
    scan_jobs = relationship("ScanJob", back_populates="repository")
    entity_occurrences = relationship("OrgEntityOccurrence", back_populates="repository")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    repo_name = Column(String, nullable=False)
    repo_url = Column(String, nullable=False)
    branch = Column(String, default="main")
    score = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    findings_high = Column(Integer, default=0)
    findings_medium = Column(Integer, default=0)
    findings_low = Column(Integer, default=0)
    status = Column(String, default="completed")
    report_path = Column(String, nullable=True)
    compliance_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=True, index=True)

    owner = relationship("User", back_populates="scans")
    organization = relationship("Organization", back_populates="scans")
    repository = relationship("Repository", back_populates="scans")
    scan_job = relationship("ScanJob", back_populates="scan", uselist=False)


class ScanBatch(Base):
    __tablename__ = "scan_batches"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    requested_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String, default="pending")  # pending | running | completed | failed | cancelled
    scan_mode = Column(String, default="fast")  # fast | deep
    total = Column(Integer, default=0)
    succeeded = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="scan_batches")
    requested_by = relationship("User", foreign_keys=[requested_by_user_id])
    jobs = relationship("ScanJob", back_populates="batch")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(Integer, ForeignKey("scan_batches.id"), nullable=False, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    status = Column(String, default="queued")  # queued | running | completed | failed | cancelled
    error = Column(Text, nullable=True)
    rq_job_id = Column(String, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    batch = relationship("ScanBatch", back_populates="jobs")
    repository = relationship("Repository", back_populates="scan_jobs")
    scan = relationship("Scan", back_populates="scan_job")


class OrgEntity(Base):
    __tablename__ = "org_entities"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "canonical_name", "schema_fingerprint",
            name="uq_org_entity_fingerprint",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    canonical_name = Column(String, nullable=False, index=True)
    kind = Column(String, default="data_entity")
    schema_fingerprint = Column(String, nullable=True)
    first_seen_repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=True)
    pii_field_count = Column(Integer, default=0)
    occurrence_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="entities")
    occurrences = relationship("OrgEntityOccurrence", back_populates="entity")
    fields = relationship("OrgEntityField", back_populates="entity")
    cross_repo_edges = relationship("CrossRepoEdge", back_populates="entity")


class OrgEntityOccurrence(Base):
    __tablename__ = "org_entity_occurrences"

    id = Column(Integer, primary_key=True, index=True)
    org_entity_id = Column(Integer, ForeignKey("org_entities.id"), nullable=False, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=True)
    role = Column(String, default="reference")  # definition | reference | consumer
    snippet = Column(Text, nullable=True)
    confidence = Column(Float, default=0.7)

    entity = relationship("OrgEntity", back_populates="occurrences")
    repository = relationship("Repository", back_populates="entity_occurrences")


class OrgEntityField(Base):
    __tablename__ = "org_entity_fields"
    __table_args__ = (UniqueConstraint("org_entity_id", "field_name", name="uq_entity_field"),)

    id = Column(Integer, primary_key=True, index=True)
    org_entity_id = Column(Integer, ForeignKey("org_entities.id"), nullable=False, index=True)
    field_name = Column(String, nullable=False)
    pii_category = Column(String, nullable=True)
    seen_in_repos = Column(Integer, default=1)

    entity = relationship("OrgEntity", back_populates="fields")


class CrossRepoEdge(Base):
    __tablename__ = "cross_repo_edges"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "org_entity_id", "src_repo_id", "dst_repo_id", "edge_type",
            name="uq_cross_repo_edge",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    org_entity_id = Column(Integer, ForeignKey("org_entities.id"), nullable=False, index=True)
    src_repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    dst_repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    edge_type = Column(String, default="definition_consumed")
    confidence = Column(Float, default=0.7)
    evidence_json = Column(JSON, nullable=True)

    organization = relationship("Organization", back_populates="cross_repo_edges")
    entity = relationship("OrgEntity", back_populates="cross_repo_edges")


class OrgReport(Base):
    __tablename__ = "org_reports"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    requested_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String, default="pending")  # pending | running | completed | failed
    pdf_path = Column(String, nullable=True)
    html_path = Column(String, nullable=True)
    summary_json = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="org_reports")
