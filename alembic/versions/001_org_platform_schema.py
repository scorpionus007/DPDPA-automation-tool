"""Org platform schema: organizations, KB, bulk scan, org reports.

Revision ID: 001_org_platform
Revises:
Create Date: 2026-04-13

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_org_platform"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Legacy tables may exist from create_all; use batch mode for SQLite alters
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = set(inspector.get_table_names())

    if "organizations" not in existing:
        op.create_table(
            "organizations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("slug", sa.String(), nullable=False),
            sa.Column("display_name", sa.String(), nullable=False),
            sa.Column("github_login", sa.String(), nullable=True),
            sa.Column("plan", sa.String(), server_default="free"),
            sa.Column("bulk_scan_limit", sa.Integer(), server_default="100"),
            sa.Column("created_at", sa.DateTime(), nullable=True),
        )
        op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)
        op.create_index("ix_organizations_github_login", "organizations", ["github_login"])

    if "github_installations" not in existing:
        op.create_table(
            "github_installations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("installation_id", sa.String(), nullable=False),
            sa.Column("account_login", sa.String(), nullable=False),
            sa.Column("account_type", sa.String(), server_default="Organization"),
            sa.Column("suspended_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
        )
        op.create_index(
            "ix_github_installations_installation_id",
            "github_installations",
            ["installation_id"],
            unique=True,
        )

    if "org_memberships" not in existing:
        op.create_table(
            "org_memberships",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("role", sa.String(), server_default="member"),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("org_id", "user_id", name="uq_org_user"),
        )

    if "repositories" not in existing:
        op.create_table(
            "repositories",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("github_repo_id", sa.String(), nullable=False),
            sa.Column("full_name", sa.String(), nullable=False),
            sa.Column("default_branch", sa.String(), server_default="main"),
            sa.Column("private", sa.Boolean(), server_default="0"),
            sa.Column("language", sa.String(), nullable=True),
            sa.Column("html_url", sa.String(), nullable=True),
            sa.Column("last_scan_at", sa.DateTime(), nullable=True),
            sa.Column("last_score", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("org_id", "github_repo_id", name="uq_org_github_repo"),
        )

    if "scans" in existing:
        cols = {c["name"] for c in inspector.get_columns("scans")}
        if "org_id" not in cols:
            with op.batch_alter_table("scans") as batch:
                batch.add_column(sa.Column("org_id", sa.Integer(), nullable=True))
                batch.add_column(sa.Column("repository_id", sa.Integer(), nullable=True))
                batch.create_foreign_key("fk_scans_org", "organizations", ["org_id"], ["id"])
                batch.create_foreign_key("fk_scans_repo", "repositories", ["repository_id"], ["id"])

    for table_name, create_fn in [
        ("scan_batches", _create_scan_batches),
        ("scan_jobs", _create_scan_jobs),
        ("org_entities", _create_org_entities),
        ("org_entity_occurrences", _create_org_entity_occurrences),
        ("org_entity_fields", _create_org_entity_fields),
        ("cross_repo_edges", _create_cross_repo_edges),
        ("org_reports", _create_org_reports),
    ]:
        if table_name not in existing:
            create_fn()


def _create_scan_batches() -> None:
    op.create_table(
        "scan_batches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(), server_default="pending"),
        sa.Column("scan_mode", sa.String(), server_default="fast"),
        sa.Column("total", sa.Integer(), server_default="0"),
        sa.Column("succeeded", sa.Integer(), server_default="0"),
        sa.Column("failed", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )


def _create_scan_jobs() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("batch_id", sa.Integer(), sa.ForeignKey("scan_batches.id"), nullable=False),
        sa.Column("repository_id", sa.Integer(), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("status", sa.String(), server_default="queued"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("rq_job_id", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )


def _create_org_entities() -> None:
    op.create_table(
        "org_entities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("canonical_name", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), server_default="data_entity"),
        sa.Column("schema_fingerprint", sa.String(), nullable=True),
        sa.Column("first_seen_repo_id", sa.Integer(), sa.ForeignKey("repositories.id"), nullable=True),
        sa.Column("pii_field_count", sa.Integer(), server_default="0"),
        sa.Column("occurrence_count", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "org_id", "canonical_name", "schema_fingerprint", name="uq_org_entity_fingerprint"
        ),
    )


def _create_org_entity_occurrences() -> None:
    op.create_table(
        "org_entity_occurrences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_entity_id", sa.Integer(), sa.ForeignKey("org_entities.id"), nullable=False),
        sa.Column("repository_id", sa.Integer(), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("role", sa.String(), server_default="reference"),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.7"),
    )


def _create_org_entity_fields() -> None:
    op.create_table(
        "org_entity_fields",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_entity_id", sa.Integer(), sa.ForeignKey("org_entities.id"), nullable=False),
        sa.Column("field_name", sa.String(), nullable=False),
        sa.Column("pii_category", sa.String(), nullable=True),
        sa.Column("seen_in_repos", sa.Integer(), server_default="1"),
        sa.UniqueConstraint("org_entity_id", "field_name", name="uq_entity_field"),
    )


def _create_cross_repo_edges() -> None:
    op.create_table(
        "cross_repo_edges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("org_entity_id", sa.Integer(), sa.ForeignKey("org_entities.id"), nullable=False),
        sa.Column("src_repo_id", sa.Integer(), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("dst_repo_id", sa.Integer(), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("edge_type", sa.String(), server_default="definition_consumed"),
        sa.Column("confidence", sa.Float(), server_default="0.7"),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.UniqueConstraint(
            "org_id", "org_entity_id", "src_repo_id", "dst_repo_id", "edge_type",
            name="uq_cross_repo_edge",
        ),
    )


def _create_org_reports() -> None:
    op.create_table(
        "org_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(), server_default="pending"),
        sa.Column("pdf_path", sa.String(), nullable=True),
        sa.Column("html_path", sa.String(), nullable=True),
        sa.Column("summary_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    for t in (
        "org_reports",
        "cross_repo_edges",
        "org_entity_fields",
        "org_entity_occurrences",
        "org_entities",
        "scan_jobs",
        "scan_batches",
        "repositories",
        "org_memberships",
        "github_installations",
        "organizations",
    ):
        op.drop_table(t)
