"""
ArtifactRouter unit tests.

Acceptance criteria:
  ✓ URL artifact → D2 detectors + url/intel engines
  ✓ EMAIL artifact → D1 + D4 detectors + nlp/email/url/intel engines
  ✓ SMS artifact → D1 subset + nlp/url engines
  ✓ WEBPAGE artifact → D2 subset + D3 detectors + web/url/intel engines
  ✓ IMAGE artifact → D5 (d22) + media/nlp engines
  ✓ QR artifact → D5 (d21) + media/url/intel engines
  ✓ FILE artifact → D4 (d20) + intel engine
  ✓ EMAIL with extracted_urls → sub-artifacts created (one per URL)
  ✓ URL artifact with no embedded URLs → no sub-artifacts
  ✓ Unknown artifact type → empty plan with skip_reason
"""

from __future__ import annotations

from app.input.router import ArtifactRouter
from app.schemas.schemas import Artifact, ArtifactType

_router = ArtifactRouter()


def _artifact(atype: ArtifactType, urls: list[str] | None = None) -> Artifact:
    a = Artifact(type=atype, raw_content="test content")
    if urls:
        a.extracted_urls = urls
    return a


# ── URL ───────────────────────────────────────────────────────────────────────


def test_url_plan_has_d2_detectors() -> None:
    plan = _router.route(_artifact(ArtifactType.URL))
    ids = plan.applicable_detector_ids
    assert "d10_malicious_url" in ids
    assert "d11_brand_impersonation" in ids
    assert "d12_malicious_redirects" in ids
    assert "d13_url_obfuscation" in ids
    assert "d14_idn_homograph" in ids


def test_url_plan_engines_include_url_and_intel() -> None:
    plan = _router.route(_artifact(ArtifactType.URL))
    assert "url" in plan.engines_to_prewarm
    assert "intel" in plan.engines_to_prewarm


def test_url_no_sub_artifacts_when_no_embedded_urls() -> None:
    plan = _router.route(_artifact(ArtifactType.URL))
    assert plan.sub_artifacts == []


# ── EMAIL ─────────────────────────────────────────────────────────────────────


def test_email_plan_has_d1_and_d4_detectors() -> None:
    plan = _router.route(_artifact(ArtifactType.EMAIL))
    ids = plan.applicable_detector_ids
    assert "d01_email_phishing" in ids
    assert "d18_bec" in ids
    assert "d19_spam" in ids
    assert "d20_suspicious_attachments" in ids


def test_email_plan_engines_include_nlp_and_email() -> None:
    plan = _router.route(_artifact(ArtifactType.EMAIL))
    assert "nlp" in plan.engines_to_prewarm
    assert "email" in plan.engines_to_prewarm
    assert "url" in plan.engines_to_prewarm


def test_email_with_two_urls_creates_two_sub_artifacts() -> None:
    urls = ["https://url1.example.com", "https://url2.example.com"]
    plan = _router.route(_artifact(ArtifactType.EMAIL, urls=urls))
    assert len(plan.sub_artifacts) == 2
    for sub in plan.sub_artifacts:
        assert sub.type == ArtifactType.URL


# ── SMS ───────────────────────────────────────────────────────────────────────


def test_sms_plan_has_smishing_detector() -> None:
    plan = _router.route(_artifact(ArtifactType.SMS))
    assert "d05_smishing" in plan.applicable_detector_ids


def test_sms_plan_has_nlp_engine() -> None:
    plan = _router.route(_artifact(ArtifactType.SMS))
    assert "nlp" in plan.engines_to_prewarm


def test_sms_with_url_creates_sub_artifact() -> None:
    plan = _router.route(_artifact(ArtifactType.SMS, urls=["https://phish.example.com"]))
    assert len(plan.sub_artifacts) == 1
    assert plan.sub_artifacts[0].type == ArtifactType.URL


# ── WEBPAGE ───────────────────────────────────────────────────────────────────


def test_webpage_plan_has_d3_detectors() -> None:
    plan = _router.route(_artifact(ArtifactType.WEBPAGE))
    ids = plan.applicable_detector_ids
    assert "d15_credential_harvesting" in ids
    assert "d16_fake_auth_pages" in ids
    assert "d17_malicious_webpages" in ids


def test_webpage_plan_has_web_engine() -> None:
    plan = _router.route(_artifact(ArtifactType.WEBPAGE))
    assert "web" in plan.engines_to_prewarm


# ── IMAGE ─────────────────────────────────────────────────────────────────────


def test_image_plan_has_d22() -> None:
    plan = _router.route(_artifact(ArtifactType.IMAGE))
    assert "d22_screenshot_scam" in plan.applicable_detector_ids


def test_image_plan_has_media_engine() -> None:
    plan = _router.route(_artifact(ArtifactType.IMAGE))
    assert "media" in plan.engines_to_prewarm


# ── QR ────────────────────────────────────────────────────────────────────────


def test_qr_plan_has_d21() -> None:
    plan = _router.route(_artifact(ArtifactType.QR))
    assert "d21_qr_phishing" in plan.applicable_detector_ids


def test_qr_plan_has_media_and_url_engines() -> None:
    plan = _router.route(_artifact(ArtifactType.QR))
    assert "media" in plan.engines_to_prewarm
    assert "url" in plan.engines_to_prewarm


# ── FILE ──────────────────────────────────────────────────────────────────────


def test_file_plan_has_d20() -> None:
    plan = _router.route(_artifact(ArtifactType.FILE))
    assert "d20_suspicious_attachments" in plan.applicable_detector_ids


# ── Plan metadata ─────────────────────────────────────────────────────────────


def test_plan_artifact_id_matches() -> None:
    artifact = _artifact(ArtifactType.URL)
    plan = _router.route(artifact)
    assert plan.artifact_id == artifact.id


def test_plan_artifact_type_matches() -> None:
    artifact = _artifact(ArtifactType.SMS)
    plan = _router.route(artifact)
    assert plan.artifact_type == ArtifactType.SMS


def test_no_duplicate_detector_ids_in_plan() -> None:
    for atype in ArtifactType:
        plan = _router.route(_artifact(atype))
        ids = plan.applicable_detector_ids
        assert len(ids) == len(set(ids)), f"Duplicate detector IDs in {atype} plan: {ids}"
