"""POST /analyze (JSON + multipart) and GET /analyses/{id} endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.aggregator.aggregator import RiskAggregator
from app.core.config import settings
from app.core.context import AnalysisContext
from app.core.registry import get_all_detectors
from app.db.models import Analysis, DetectionResultDB
from app.db.session import get_db
from app.engines.nlp.engine import build_nlp_engine
from app.explain.explainer import Explainer
from app.input.normalizers import (
    EmailNormalizer,
    FileNormalizer,
    ImageNormalizer,
    QRNormalizer,
    SMSNormalizer,
    URLNormalizer,
    WebpageNormalizer,
)
from app.input.uploader import UploadValidationError, validate_upload
from app.schemas.schemas import (
    AnalysisStatus,
    AnalyzeRequest,
    Artifact,
    ArtifactType,
    DetectionResult,
    RiskReport,
    Verdict,
)

router = APIRouter()
logger = logging.getLogger(__name__)

_aggregator = RiskAggregator()
_explainer  = Explainer()

# ── Normalizer dispatch ───────────────────────────────────────────────────────

_TEXT_NORMALIZERS: dict[ArtifactType, object] = {
    ArtifactType.URL:   URLNormalizer(),
    ArtifactType.EMAIL: EmailNormalizer(),
    ArtifactType.SMS:   SMSNormalizer(),
}

_BINARY_NORMALIZERS: dict[ArtifactType, object] = {
    ArtifactType.IMAGE:   ImageNormalizer(),
    ArtifactType.QR:      QRNormalizer(),
    ArtifactType.FILE:    FileNormalizer(),
    ArtifactType.WEBPAGE: WebpageNormalizer(),
    ArtifactType.EMAIL:   EmailNormalizer(),
}


def _normalize_artifact(
    artifact_type: ArtifactType,
    raw_content: str = "",
    raw_bytes: bytes | None = None,
    filename: str = "",
    mime_type: str = "",
    metadata: dict | None = None,
) -> Artifact:
    """Dispatch to the correct normalizer based on artifact_type."""
    kwargs = {"filename": filename, "mime_type": mime_type}

    if raw_bytes is not None:
        normalizer = _BINARY_NORMALIZERS.get(artifact_type)
        if normalizer:
            artifact = normalizer.normalize(raw_bytes, **kwargs)  # type: ignore[union-attr]
        else:
            artifact = Artifact(
                type=artifact_type,
                raw_bytes=raw_bytes,
                metadata={"filename": filename, "mime_type": mime_type},
            )
    else:
        normalizer = _TEXT_NORMALIZERS.get(artifact_type)
        if normalizer:
            artifact = normalizer.normalize(raw_content, **kwargs)  # type: ignore[union-attr]
        else:
            artifact = Artifact(type=artifact_type, raw_content=raw_content)

    if metadata:
        artifact.metadata = {**artifact.metadata, **metadata}

    return artifact


# ── Pipeline ──────────────────────────────────────────────────────────────────


async def _run_pipeline(artifact: Artifact, db: AsyncSession) -> RiskReport:
    """Run the full analysis pipeline for *artifact* and persist to DB."""
    from app.engines.email.engine import EmailEngine
    from app.engines.intel.engine import IntelEngine
    from app.engines.media.engine import MediaEngine
    from app.engines.url.engine import URLEngine
    from app.engines.web.engine import WebEngine

    analysis_row = Analysis(
        id=str(uuid.uuid4()),
        artifact_id=artifact.id,
        artifact_type=artifact.type.value,
        status="processing",
        nlp_backend_used=settings.NLP_BACKEND.value,
        created_at=datetime.utcnow(),
    )
    db.add(analysis_row)
    await db.commit()

    errors: list[str] = []
    skipped: list[str] = []

    try:
        # ── Engine initialisation ─────────────────────────────────────────────
        try:
            nlp_engine = build_nlp_engine(settings.NLP_BACKEND.value)
        except (NotImplementedError, ValueError) as exc:
            errors.append(str(exc))
            nlp_engine = build_nlp_engine("rules")
            skipped.append("nlp_requested_backend")

        ctx = AnalysisContext(
            artifact=artifact,
            nlp_engine=nlp_engine,
            url_engine=URLEngine(),
            web_engine=WebEngine(),
            email_engine=EmailEngine(),
            media_engine=MediaEngine(),
            intel_provider=IntelEngine(),
        )

        # ── Detector loop ─────────────────────────────────────────────────────
        detection_results: list[DetectionResult] = []

        for detector in get_all_detectors():
            if not detector.accepts(artifact.type):
                detection_results.append(detector._skipped(artifact))
                skipped.append(detector.detector_id)
                continue
            try:
                result = await detector.detect(artifact, ctx)
            except Exception as exc:
                logger.exception("Detector %s raised unexpectedly", detector.detector_id)
                result = DetectionResult(
                    detector_id=detector.detector_id,
                    name=detector.name,
                    domain=detector.domain,
                    domain_id=detector.domain_id,
                    score=0.0,
                    verdict=Verdict.ERROR,
                    confidence=0.0,
                    error=f"{type(exc).__name__}: {exc}",
                    ran=True,
                )
                errors.append(f"{detector.detector_id}: {exc}")
            detection_results.append(result)

        # ── Aggregation + explainability ─────────────────────────────────────
        engine_signals = ctx.get_engine_signals_snapshot()
        report = await _aggregator.aggregate(
            artifact=artifact,
            results=detection_results,
            engine_signals=engine_signals,
            nlp_backend_used=ctx._nlp_engine.backend_name if ctx._nlp_engine else None,
            errors=errors,
            skipped=skipped,
        )
        report.analysis_id = analysis_row.id
        report = _explainer.explain(report)

        # ── Persist results ───────────────────────────────────────────────────
        for dr in detection_results:
            db.add(DetectionResultDB(
                analysis_id=analysis_row.id,
                detector_id=dr.detector_id,
                detector_name=dr.name,
                domain=dr.domain,
                domain_id=dr.domain_id,
                score=dr.score,
                verdict=dr.verdict.value,
                confidence=dr.confidence,
                ran=dr.ran,
                evidence=[e.model_dump() for e in dr.evidence],
                signals_used=dr.signals_used,
                error=dr.error,
            ))

        analysis_row.status = "complete"
        analysis_row.risk_score = report.risk_score
        analysis_row.verdict = report.verdict.value
        analysis_row.primary_threat_type = report.primary_threat_type
        analysis_row.secondary_tags = report.secondary_tags
        analysis_row.errors = errors
        analysis_row.skipped_components = skipped
        analysis_row.risk_report_json = report.model_dump(mode="json")
        analysis_row.completed_at = datetime.utcnow()
        await db.commit()

        return report

    except Exception as exc:
        logger.exception("Pipeline failed for artifact %s", artifact.id)
        analysis_row.status = "error"
        analysis_row.errors = [str(exc)]
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {exc}") from exc


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/analyze", response_model=RiskReport, tags=["Analysis"])
async def analyze(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RiskReport:
    """Submit an artifact for threat analysis.

    Accepts **JSON** (Content-Type: application/json) or
    **multipart/form-data** (for file uploads).

    ---
    **JSON body** (url / email text / sms):
    ```json
    {"type": "url", "raw_content": "https://example.com"}
    ```

    **Multipart form** (email .eml / image / file):
    - `type` (form field): artifact type string
    - `file` (file field): the upload
    - `metadata` (form field, optional): JSON object string
    """
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        return await _analyze_upload(request, db)
    return await _analyze_json(request, db)


async def _analyze_json(request: Request, db: AsyncSession) -> RiskReport:
    """Handle JSON-body POST /analyze."""
    try:
        body = await request.json()
        req = AnalyzeRequest.model_validate(body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON body: {exc}") from exc

    artifact = _normalize_artifact(
        artifact_type=req.type,
        raw_content=req.raw_content,
        metadata=req.metadata,
    )
    return await _run_pipeline(artifact, db)


async def _analyze_upload(request: Request, db: AsyncSession) -> RiskReport:
    """Handle multipart POST /analyze."""
    form = await request.form()

    type_str = form.get("type", "")
    if not type_str:
        raise HTTPException(status_code=422, detail="Form field 'type' is required.")

    try:
        artifact_type = ArtifactType(str(type_str).lower())
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown artifact type {type_str!r}. "
                   f"Must be one of: {[t.value for t in ArtifactType]}",
        ) from None

    upload: UploadFile | None = form.get("file")  # type: ignore[assignment]
    if upload is None:
        raise HTTPException(status_code=422, detail="Multipart field 'file' is required.")

    raw_bytes = await upload.read()
    original_filename = upload.filename or "upload.bin"
    declared_mime = upload.content_type or "application/octet-stream"

    try:
        validate_upload(
            data=raw_bytes,
            original_filename=original_filename,
            declared_mime=declared_mime,
            artifact_type=artifact_type.value,
        )
    except UploadValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    import json as _json

    metadata_str = form.get("metadata", "{}")
    try:
        extra_meta = _json.loads(str(metadata_str)) if metadata_str else {}
    except _json.JSONDecodeError:
        extra_meta = {}

    artifact = _normalize_artifact(
        artifact_type=artifact_type,
        raw_bytes=raw_bytes,
        filename=original_filename,
        mime_type=declared_mime,
        metadata=extra_meta,
    )
    return await _run_pipeline(artifact, db)


@router.get("/analyses/{analysis_id}", response_model=RiskReport, tags=["Analysis"])
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> RiskReport:
    """Retrieve a previously completed analysis by its ID."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    row = result.scalar_one_or_none()

    if row is None:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id!r} not found.")

    if row.risk_report_json:
        return RiskReport.model_validate(row.risk_report_json)

    return RiskReport(
        analysis_id=row.id,
        artifact_id=row.artifact_id,
        artifact_type=ArtifactType(row.artifact_type),
        status=AnalysisStatus(row.status),
        risk_score=row.risk_score or 0.0,
        verdict=Verdict(row.verdict) if row.verdict else Verdict.UNKNOWN,
        nlp_backend_used=row.nlp_backend_used,
        errors=row.errors or [],
        skipped_components=row.skipped_components or [],
        created_at=row.created_at,
        completed_at=row.completed_at,
    )
