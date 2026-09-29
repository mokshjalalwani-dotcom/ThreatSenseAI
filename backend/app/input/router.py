"""
ArtifactRouter — decides which detectors apply to an artifact and which
engines should be pre-warmed before the detector loop runs.

Routing table (Stage 1 detector IDs are the ground truth):

  EMAIL   → D1 (d01,d02,d03,d04,d08,d09) + D4 (d18,d19,d20)
            + sub-artifact URL runs for each extracted URL (D2 detectors)
  SMS     → D1 (d02,d04,d05,d06,d07,d09)
            + sub-artifact URL runs
  URL     → D2 (d10,d11,d12,d13,d14)
  WEBPAGE → D2 (d10,d11) + D3 (d15,d16,d17)
            + sub-artifact URL runs
  IMAGE   → D5 (d22)  [OCR path; QR check also attempted]
  QR      → D5 (d21)  [payload extracted → re-enters router as URL]
  FILE    → D4 (d20)  [attachment analysis]

The router never imports detector classes directly — it uses string IDs.
This keeps the router decoupled from detector implementation stages.
"""

from __future__ import annotations

import logging

from app.schemas.schemas import Artifact, ArtifactType, RouterPlan

logger = logging.getLogger(__name__)

# ── Routing table ─────────────────────────────────────────────────────────────
# Maps ArtifactType → (detector_ids, engines_to_prewarm)
# Detector IDs here are the registered detector_id strings from Stage 1.

_ROUTING_TABLE: dict[ArtifactType, tuple[list[str], list[str]]] = {
    ArtifactType.URL: (
        [
            "d10_malicious_url",
            "d11_brand_impersonation",
            "d12_malicious_redirects",
            "d13_url_obfuscation",
            "d14_idn_homograph",
        ],
        ["url", "intel"],
    ),
    ArtifactType.EMAIL: (
        [
            "d01_email_phishing",
            "d02_social_engineering",
            "d03_spear_phishing",
            "d04_scam_fraud",
            "d08_recruitment_scams",
            "d09_tech_support_scams",
            "d18_bec",
            "d19_spam",
            "d20_suspicious_attachments",
        ],
        ["nlp", "email", "url", "intel"],
    ),
    ArtifactType.SMS: (
        [
            "d02_social_engineering",
            "d04_scam_fraud",
            "d05_smishing",
            "d06_government_scams",
            "d07_financial_investment",
            "d09_tech_support_scams",
        ],
        ["nlp", "url"],
    ),
    ArtifactType.WEBPAGE: (
        [
            "d10_malicious_url",
            "d11_brand_impersonation",
            "d15_credential_harvesting",
            "d16_fake_auth_pages",
            "d17_malicious_webpages",
        ],
        ["web", "url", "intel"],
    ),
    ArtifactType.IMAGE: (
        ["d22_screenshot_scam"],
        ["media", "nlp"],
    ),
    ArtifactType.QR: (
        ["d21_qr_phishing"],
        ["media", "url", "intel"],
    ),
    ArtifactType.FILE: (
        ["d20_suspicious_attachments"],
        ["intel"],
    ),
}

# Extra detectors triggered by NLP when artifact carries text
_NLP_EXTRA_BY_TYPE: dict[ArtifactType, list[str]] = {
    ArtifactType.EMAIL: [
        "d06_government_scams",
        "d07_financial_investment",
    ],
    ArtifactType.SMS: [],
    ArtifactType.WEBPAGE: [
        "d02_social_engineering",
        "d04_scam_fraud",
        "d09_tech_support_scams",
    ],
}


class ArtifactRouter:
    """Maps an Artifact to a RouterPlan.

    The plan contains:
    - ``applicable_detector_ids``: detectors that should be called.
    - ``engines_to_prewarm``: engines the AnalysisContext should init.
    - ``sub_artifacts``: child artifacts to route separately (e.g. URLs
      extracted from an email or webpage body).
    """

    def route(self, artifact: Artifact) -> RouterPlan:
        """Build a RouterPlan for *artifact*.

        Args:
            artifact: A normalised Artifact (with extracted_urls populated).

        Returns:
            A RouterPlan with detector IDs, engine names, and sub-artifacts.
        """
        atype = artifact.type

        if atype not in _ROUTING_TABLE:
            logger.warning("ArtifactRouter: unknown type %r — returning empty plan", atype)
            return RouterPlan(
                artifact_id=artifact.id,
                artifact_type=atype,
                skip_reason=f"No routing rule defined for artifact type {atype!r}",
            )

        detector_ids, engines = _ROUTING_TABLE[atype]

        # Add NLP-triggered detectors for text-bearing types
        extra = _NLP_EXTRA_BY_TYPE.get(atype, [])
        all_detectors = list(dict.fromkeys(detector_ids + extra))  # dedup + preserve order

        # Build sub-artifacts for extracted URLs
        sub_artifacts: list[Artifact] = []
        if artifact.extracted_urls:
            from app.input.normalizers.url import URLNormalizer

            url_norm = URLNormalizer()
            for url in artifact.extracted_urls:
                try:
                    sub = url_norm.normalize(url)
                    sub_artifacts.append(sub)
                except Exception as exc:
                    logger.debug("Router: failed to create URL sub-artifact for %r: %s", url[:80], exc)

        logger.debug(
            "ArtifactRouter: type=%s detectors=%d engines=%s sub_artifacts=%d",
            atype,
            len(all_detectors),
            engines,
            len(sub_artifacts),
        )

        return RouterPlan(
            artifact_id=artifact.id,
            artifact_type=atype,
            applicable_detector_ids=all_detectors,
            engines_to_prewarm=list(engines),
            sub_artifacts=sub_artifacts,
        )

    def route_many(self, artifacts: list[Artifact]) -> list[RouterPlan]:
        """Build RouterPlans for a list of artifacts (e.g. extracted URLs)."""
        return [self.route(a) for a in artifacts]


# Module-level singleton
_router = ArtifactRouter()


def get_router() -> ArtifactRouter:
    """Return the shared ArtifactRouter singleton."""
    return _router
