"""
THREAT-SENSE AI — Canonical Pydantic v2 schemas.

These types are the contracts that every engine, detector, aggregator and API
route depends on.  Rules:
  - No model or library imports here (pure data shapes).
  - Every public type has a docstring.
  - All fields are typed; defaults must be explicit.
  - Forward-compatible: add optional fields freely; never remove/rename one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ─── Enumerations ─────────────────────────────────────────────────────────────


class ArtifactType(StrEnum):
    """Input modalities the platform can analyse."""

    URL = "url"
    EMAIL = "email"
    SMS = "sms"
    WEBPAGE = "webpage"
    IMAGE = "image"
    QR = "qr"
    FILE = "file"


class Verdict(StrEnum):
    """Final or per-detector risk verdict."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"
    NOT_IMPLEMENTED = "not_implemented"
    ERROR = "error"
    UNKNOWN = "unknown"


class EvidenceSeverity(StrEnum):
    """Severity level attached to each evidence item."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(StrEnum):
    """Lifecycle status of an analysis job."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"
    ERROR = "error"


class NLPBackendName(StrEnum):
    """Selectable NLP signal-backend identifiers."""

    RULES = "rules"
    ZEROSHOT = "zeroshot"
    FINETUNED = "finetuned"
    ENSEMBLE = "ensemble"


# ─── Stage 2: attachment and fetch types ─────────────────────────────────────


class AttachmentInfo(BaseModel):
    """Metadata for a file attachment (email or direct upload).

    Bytes are NOT stored here — they stay in the child Artifact's raw_bytes.
    """

    filename: str | None = None
    declared_mime: str | None = None   # MIME from Content-Type header
    detected_mime: str | None = None   # MIME from magic bytes
    extension: str | None = None
    size_bytes: int = 0
    sha256: str = ""
    is_suspicious_extension: bool = False


class FetchResult(BaseModel):
    """Result of a SafeFetcher.fetch() call."""

    url: str                                            # Original requested URL
    final_url: str                                      # URL after all redirects
    status_code: int = 0
    content_type: str = ""
    body: bytes = b""
    redirect_chain: list[str] = Field(default_factory=list)
    error: str | None = None

    model_config = {"json_encoders": {bytes: lambda b: b.hex()}}


class RouterPlan(BaseModel):
    """Decision made by the ArtifactRouter for one artifact.

    Detectors in *applicable_detector_ids* will be called for this artifact.
    *engines_to_prewarm* lists which engines the context should spin up.
    *sub_artifacts* holds child artifacts (e.g. extracted URLs from an email)
    that will each get their own RouterPlan and detector run.
    """

    artifact_id: str
    artifact_type: ArtifactType
    applicable_detector_ids: list[str] = Field(default_factory=list)
    engines_to_prewarm: list[str] = Field(default_factory=list)
    sub_artifacts: list[Artifact] = Field(default_factory=list)
    skip_reason: str | None = None


# ─── Core domain models ───────────────────────────────────────────────────────


class Artifact(BaseModel):
    """The unit of input that detectors operate on.

    An Artifact carries all raw material for analysis: the content itself
    (text or bytes), the declared type, and optional metadata the caller
    wants to pass through (e.g. sender email header fields, recipient profile
    for spear-phishing, file name, MIME type, …).
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ArtifactType
    raw_content: str = Field(
        default="",
        description="UTF-8 text content (URL string, message body, HTML, …).",
    )
    raw_bytes: bytes | None = Field(
        default=None,
        description="Binary payload for images, files, QR images, etc.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Caller-supplied context: filename, MIME type, sender address, "
            "recipient_profile, original_url, etc."
        ),
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # ── Populated by normalizers (Stage 2+) ──────────────────────────────────
    normalized_url: str | None = Field(
        default=None,
        description="Canonicalized URL (for url/webpage types).",
    )
    extracted_urls: list[str] = Field(
        default_factory=list,
        description="URLs extracted from the artifact body.",
    )
    attachments: list[AttachmentInfo] = Field(
        default_factory=list,
        description="Attachment metadata (email/file types).",
    )
    sha256: str | None = Field(
        default=None,
        description="SHA-256 hex digest of raw_bytes (file/image types).",
    )
    file_size_bytes: int | None = Field(
        default=None,
        description="Size of raw_bytes in bytes.",
    )
    detected_mime: str | None = Field(
        default=None,
        description="MIME type detected from magic bytes.",
    )

    model_config = {"json_encoders": {bytes: lambda b: b.hex()}}


class EvidenceSpan(BaseModel):
    """Character-level evidence span produced by the NLP engine."""

    signal: str = Field(description="The signal this span contributes to.")
    matched_text: str
    char_start: int
    char_end: int
    weight: float = Field(default=1.0, description="Contribution weight [0, 1].")


class Evidence(BaseModel):
    """A single concrete piece of evidence supporting a detection.

    Every detector and engine MUST express WHY it fired through Evidence
    objects.  Human-readable *description* is mandatory; the other fields add
    machine-readable precision for the UI and future analysis.
    """

    source_engine: str = Field(description="Which engine or rule produced this.")
    severity: EvidenceSeverity
    description: str = Field(description="Plain-language explanation shown to the user.")
    matched_text: str | None = Field(
        default=None, description="The exact substring that triggered this, if any."
    )
    char_start: int | None = Field(default=None, description="Start offset in the original text.")
    char_end: int | None = Field(
        default=None, description="End offset (exclusive) in the original text."
    )
    rule_id: str | None = Field(
        default=None, description="Identifier of the rule that fired, if applicable."
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """Output of a single detector run against one artifact.

    Detectors MUST NOT raise exceptions into the aggregator; all errors are
    captured in the *error* field and *verdict* is set to ERROR or
    NOT_IMPLEMENTED.  *ran=False* means the detector was intentionally skipped
    (e.g. wrong artifact type).
    """

    detector_id: str
    name: str
    domain: str
    domain_id: str
    score: float = Field(ge=0.0, le=1.0, description="Threat probability [0, 1].")
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the verdict [0, 1].")
    evidence: list[Evidence] = Field(default_factory=list)
    signals_used: list[str] = Field(
        default_factory=list, description="Engine signals consumed by this detector."
    )
    error: str | None = Field(
        default=None, description="Error message if the detector failed or is not implemented."
    )
    ran: bool = Field(
        default=True,
        description="False if the detector was skipped for this artifact type.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional per-detector diagnostic data (elapsed_ms, etc.).",
    )


# ─── Engine signal schemas ────────────────────────────────────────────────────


class NLPSignals(BaseModel):
    """Reusable semantic signals produced by the NLP Engine.

    All primary scores are in [0, 1].  Context-tag fields are binary-ish
    floats (0 or 1 for the rules backend; continuous for ML backends).
    *claimed_org* is extracted when *government_service_claim* is high.
    """

    # Primary threat signals
    urgency: float = Field(default=0.0, ge=0.0, le=1.0)
    fear: float = Field(default=0.0, ge=0.0, le=1.0)
    authority: float = Field(default=0.0, ge=0.0, le=1.0)
    reward_scarcity: float = Field(default=0.0, ge=0.0, le=1.0)
    financial_intent: float = Field(default=0.0, ge=0.0, le=1.0)
    credential_request: float = Field(default=0.0, ge=0.0, le=1.0)
    manipulation: float = Field(default=0.0, ge=0.0, le=1.0)
    phishing_intent: float = Field(default=0.0, ge=0.0, le=1.0)
    scam_intent: float = Field(default=0.0, ge=0.0, le=1.0)

    # Context tags
    investment_context: float = Field(default=0.0, ge=0.0, le=1.0)
    recruitment_context: float = Field(default=0.0, ge=0.0, le=1.0)
    tech_support_context: float = Field(default=0.0, ge=0.0, le=1.0)
    government_service_claim: float = Field(default=0.0, ge=0.0, le=1.0)
    claimed_org: str | None = Field(
        default=None,
        description="Extracted organisation name when government_service_claim is high.",
    )
    payment_request: float = Field(default=0.0, ge=0.0, le=1.0)
    remote_access_request: float = Field(default=0.0, ge=0.0, le=1.0)

    # Metadata
    evidence_spans: list[EvidenceSpan] = Field(default_factory=list)
    backend_used: str = Field(default="rules")
    language_hint: str | None = Field(default=None)
    text_length: int = Field(default=0)


class URLSignals(BaseModel):
    """Feature vector extracted by the URL/Domain Engine.

    Stub — will be fully populated in Stage 3.
    """

    url: str = ""
    domain: str = ""
    tld: str = ""
    subdomain: str = ""
    scheme: str = ""
    is_ip_host: bool = False
    is_https: bool = False
    url_length: int = 0
    domain_length: int = 0
    subdomain_count: int = 0
    digit_count: int = 0
    special_char_count: int = 0
    entropy: float = 0.0
    param_count: int = 0
    path_depth: int = 0
    has_punycode: bool = False
    suspicious_tokens: list[str] = Field(default_factory=list)
    risk_score: float | None = None
    shap_top_features: list[dict[str, Any]] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)


class WebSignals(BaseModel):
    """Parsed DOM/HTML signals from the Web Engine.

    Stub — will be fully populated in Stage 6.
    """

    has_password_field: bool = False
    has_otp_field: bool = False
    has_card_field: bool = False
    form_posts_to_external_domain: bool = False
    form_action_over_http: bool = False
    external_script_domains: list[str] = Field(default_factory=list)
    claimed_brand: str | None = None
    title: str | None = None
    link_density: float = 0.0
    has_eval_obfuscation: bool = False


class EmailSignals(BaseModel):
    """Header and authentication signals from the Email Engine.

    Stub — will be fully populated in Stage 7.
    """

    spf_pass: bool | None = None
    dkim_pass: bool | None = None
    dmarc_pass: bool | None = None
    from_reply_to_mismatch: bool = False
    display_name_spoofing: bool = False
    sender_domain: str | None = None
    reply_to_domain: str | None = None
    extracted_urls: list[str] = Field(default_factory=list)
    attachment_count: int = 0


class IntelSignals(BaseModel):
    """Threat-intelligence hits for an artifact.

    Stub — will be fully populated in Stage 9.
    """

    hits: list[dict[str, Any]] = Field(default_factory=list)
    providers_queried: list[str] = Field(default_factory=list)
    providers_failed: list[str] = Field(default_factory=list)
    offline_mode: bool = False


class EngineSignals(BaseModel):
    """Aggregated signals from all engines for one artifact.

    Fields are None when an engine was not run or failed gracefully.
    """

    nlp: NLPSignals | None = None
    url: URLSignals | None = None
    web: WebSignals | None = None
    email: EmailSignals | None = None
    intel: IntelSignals | None = None


# ─── Report schemas ───────────────────────────────────────────────────────────


class DomainBreakdown(BaseModel):
    """Per-domain aggregation inside a RiskReport."""

    domain_id: str
    domain_name: str
    score: float = Field(ge=0.0, le=1.0)
    detector_count: int = 0
    detectors_ran: int = 0
    detectors: list[DetectionResult] = Field(default_factory=list)


class RiskReport(BaseModel):
    """Top-level analysis output returned to the caller.

    *risk_score* is 0-100 (higher = more risky).  *verdict* is derived from
    the score and any hard-override rules.  *per_domain_scores* lets the UI
    show a breakdown by the 5 detection domains.
    """

    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_id: str
    artifact_type: ArtifactType
    status: AnalysisStatus = AnalysisStatus.COMPLETE

    # Core verdict
    risk_score: float = Field(ge=0.0, le=100.0, default=0.0)
    verdict: Verdict = Verdict.UNKNOWN
    primary_threat_type: str | None = None
    secondary_tags: list[str] = Field(default_factory=list)

    # Detail
    per_domain_scores: list[DomainBreakdown] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    top_evidence: list[Evidence] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    engine_signals: EngineSignals | None = None
    nlp_backend_used: str | None = None

    # Diagnostics
    skipped_components: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None


# ─── API request/response helpers ─────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze (JSON variant)."""

    type: ArtifactType
    raw_content: str = Field(default="", description="Text content (URL, message, etc.).")
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectorInfo(BaseModel):
    """Metadata about a registered detector, returned by GET /detectors."""

    detector_id: str
    name: str
    domain: str
    domain_id: str
    accepted_artifact_types: list[ArtifactType]
    required_engines: list[str]
    version: str = "0.1.0"


class DomainInfo(BaseModel):
    """A detection domain with its list of detectors."""

    domain_id: str
    domain_name: str
    detectors: list[DetectorInfo]


class DetectorListResponse(BaseModel):
    """Response schema for GET /detectors."""

    total: int
    domains: list[DomainInfo]


class HealthResponse(BaseModel):
    """Response schema for GET /health."""

    status: str
    version: str
    nlp_backend: str
    database: str
    detector_count: int = 0
