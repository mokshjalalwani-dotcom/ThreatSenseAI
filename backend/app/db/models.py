"""
SQLAlchemy ORM models for THREAT-SENSE AI.

Tables:
  analyses          — one row per analysis run (artifact + final verdict)
  detection_results — one row per (analysis, detector) pair
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


def _uuid() -> str:
    return str(uuid.uuid4())


# Use JSONB on PostgreSQL, JSON elsewhere (SQLite)
_JSON = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


class Analysis(Base):
    """One analysis run — corresponds to one POST /analyze request."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    artifact_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Status lifecycle: pending → processing → complete | error
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")

    # Aggregate verdict
    risk_score: Mapped[float | None] = mapped_column(Float)
    verdict: Mapped[str | None] = mapped_column(String(30))
    primary_threat_type: Mapped[str | None] = mapped_column(String(100))
    secondary_tags: Mapped[list | None] = mapped_column(_JSON, default=list)

    # NLP backend used for this run
    nlp_backend_used: Mapped[str | None] = mapped_column(String(20))

    # Full risk report (JSON snapshot for retrieval without re-running)
    risk_report_json: Mapped[dict | None] = mapped_column(_JSON)

    # Metadata
    errors: Mapped[list | None] = mapped_column(_JSON, default=list)
    skipped_components: Mapped[list | None] = mapped_column(_JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Relationships
    detection_results: Mapped[list[DetectionResultDB]] = relationship(
        "DetectionResultDB",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Analysis id={self.id!r} verdict={self.verdict!r} status={self.status!r}>"


class DetectionResultDB(Base):
    """One detector's result within an analysis run."""

    __tablename__ = "detection_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    analysis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Detector metadata (denormalised for fast queries)
    detector_id: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    detector_name: Mapped[str] = mapped_column(String(100), nullable=False)
    domain: Mapped[str] = mapped_column(String(60), nullable=False)
    domain_id: Mapped[str] = mapped_column(String(5), nullable=False, index=True)

    # Result
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verdict: Mapped[str] = mapped_column(String(30), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    ran: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Evidence and signals (stored as JSON)
    evidence: Mapped[list | None] = mapped_column(_JSON, default=list)
    signals_used: Mapped[list | None] = mapped_column(_JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationship
    analysis: Mapped[Analysis] = relationship("Analysis", back_populates="detection_results")

    def __repr__(self) -> str:
        return (
            f"<DetectionResultDB detector={self.detector_id!r} "
            f"verdict={self.verdict!r} score={self.score:.2f}>"
        )
