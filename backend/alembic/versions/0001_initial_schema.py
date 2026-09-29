"""Initial schema — analyses and detection_results tables.

Revision ID: 0001
Revises: (none)
Create Date: 2026-09-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── analyses ─────────────────────────────────────────────────────────────
    op.create_table(
        "analyses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("artifact_id", sa.String(36), nullable=False, index=True),
        sa.Column("artifact_type", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("verdict", sa.String(30), nullable=True),
        sa.Column("primary_threat_type", sa.String(100), nullable=True),
        sa.Column("secondary_tags", sa.JSON(), nullable=True),
        sa.Column("nlp_backend_used", sa.String(20), nullable=True),
        sa.Column("risk_report_json", sa.JSON(), nullable=True),
        sa.Column("errors", sa.JSON(), nullable=True),
        sa.Column("skipped_components", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )

    op.create_index("ix_analyses_artifact_id", "analyses", ["artifact_id"])
    op.create_index("ix_analyses_status", "analyses", ["status"])
    op.create_index("ix_analyses_verdict", "analyses", ["verdict"])
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])

    # ── detection_results ────────────────────────────────────────────────────
    op.create_table(
        "detection_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.String(36),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("detector_id", sa.String(60), nullable=False),
        sa.Column("detector_name", sa.String(100), nullable=False),
        sa.Column("domain", sa.String(60), nullable=False),
        sa.Column("domain_id", sa.String(5), nullable=False),
        sa.Column("score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("verdict", sa.String(30), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("ran", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("signals_used", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_index("ix_detection_results_analysis_id", "detection_results", ["analysis_id"])
    op.create_index("ix_detection_results_detector_id", "detection_results", ["detector_id"])
    op.create_index("ix_detection_results_domain_id", "detection_results", ["domain_id"])


def downgrade() -> None:
    op.drop_table("detection_results")
    op.drop_table("analyses")
