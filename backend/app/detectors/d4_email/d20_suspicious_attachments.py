"""Detector 20 — Suspicious Attachments (Domain 4: Email & Communication Security)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import (
    Artifact,
    ArtifactType,
    AttachmentInfo,
    DetectionResult,
    Evidence,
    EvidenceSeverity,
    Verdict,
)

if TYPE_CHECKING:
    from app.core.context import AnalysisContext

_SUSPICIOUS_EXTS = {
    ".exe", ".scr", ".bat", ".vbs", ".ps1", ".hta", ".js",
    ".jse", ".wsf", ".com", ".pif", ".jar", ".dll", ".msi",
    ".dmg", ".cmd", ".lnk",
}
_DOUBLE_EXT_RE = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|mp3|mp4)\.(exe|scr|bat|vbs|ps1|hta|js|jar)$", re.I)
_MACRO_EXTS = {".doc", ".docm", ".xlsm", ".xls", ".pptm"}


def _score_attachment(att: AttachmentInfo) -> tuple[float, str | None]:
    """Score a single attachment. Returns (score, description)."""
    fname = (att.filename or "").lower()
    if not fname:
        return 0.0, None

    # Double extension (invoice.pdf.exe)
    if _DOUBLE_EXT_RE.search(fname):
        return 0.90, f"Double-extension disguise: '{att.filename}'"

    ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""

    if ext in _SUSPICIOUS_EXTS:
        return 0.85, f"Executable/script attachment: '{att.filename}'"

    if ext in _MACRO_EXTS:
        return 0.45, f"Macro-capable document: '{att.filename}' (may contain malicious macros)"

    # Declared vs detected MIME mismatch
    if att.declared_mime and att.detected_mime:
        if att.declared_mime != att.detected_mime:
            return 0.60, (f"MIME type mismatch: declared '{att.declared_mime}' "
                          f"vs detected '{att.detected_mime}'")

    return 0.0, None


@register_detector
class SuspiciousAttachmentsDetector(BaseDetector):
    """Detects malicious email attachments: executables, double-extensions, macro docs."""

    detector_id = "d20_suspicious_attachments"
    name = "Suspicious Attachments"
    domain = "Email & Communication Security"
    domain_id = "d4"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.FILE]
    required_engines = ["email"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        evidence: list[Evidence] = []
        max_score = 0.0

        # Check structured attachments from normalizer
        for att in artifact.attachments:
            att_score, desc = _score_attachment(att)
            if desc:
                sev = EvidenceSeverity.CRITICAL if att_score >= 0.80 else EvidenceSeverity.HIGH
                evidence.append(Evidence(source_engine="email", severity=sev,
                    description=desc, matched_text=att.filename, rule_id="email_attachment"))
                max_score = max(max_score, att_score)

        # Also check EmailEngine extracted attachment count
        email_sig = await ctx.get_email_signals()
        if email_sig.attachment_count > 0 and not artifact.attachments:
            max_score = max(max_score, 0.20)
            evidence.append(Evidence(source_engine="email", severity=EvidenceSeverity.LOW,
                description=f"Email has {email_sig.attachment_count} attachment(s) (not analysed)",
                rule_id="email_attachment_count"))

        score = round(min(1.0, max_score), 4)
        verdict = (Verdict.MALICIOUS if score >= 0.80
                   else Verdict.LIKELY_MALICIOUS if score >= 0.50
                   else Verdict.SUSPICIOUS if score >= 0.20
                   else Verdict.SAFE)

        return self._result(artifact, score, verdict, evidence, signals=["email.attachment_count"])
