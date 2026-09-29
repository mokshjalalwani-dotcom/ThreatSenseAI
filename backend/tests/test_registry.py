"""
Tests for the detector registry.

Acceptance criteria:
  ✓ Registry contains exactly 22 detectors.
  ✓ All detector IDs are unique.
  ✓ Domain breakdown is exactly 9 / 5 / 3 / 3 / 2.
  ✓ Every detector has non-empty required fields.
  ✓ get_detector() returns the right instance.
"""

from __future__ import annotations

from collections import Counter

import pytest

import app.detectors  # noqa: F401 — trigger registration
from app.core.registry import (
    get_all_detectors,
    get_detector,
    get_detectors_for_domain,
)


def test_registry_has_exactly_22_detectors() -> None:
    """The global registry must contain exactly 22 registered detectors."""
    detectors = get_all_detectors()
    assert len(detectors) == 22, (
        f"Expected 22 detectors, got {len(detectors)}: "
        f"{[d.detector_id for d in detectors]}"
    )


def test_detector_ids_are_unique() -> None:
    """No two detectors may share a detector_id."""
    ids = [d.detector_id for d in get_all_detectors()]
    counts = Counter(ids)
    duplicates = {k: v for k, v in counts.items() if v > 1}
    assert not duplicates, f"Duplicate detector_ids found: {duplicates}"


def test_domain_breakdown_is_correct() -> None:
    """Domains must contain exactly 9 / 5 / 3 / 3 / 2 detectors."""
    expected = {"d1": 9, "d2": 5, "d3": 3, "d4": 3, "d5": 2}
    actual = Counter(d.domain_id for d in get_all_detectors())
    assert dict(actual) == expected, (
        f"Domain breakdown mismatch.\n  Expected: {expected}\n  Got: {dict(actual)}"
    )


def test_every_detector_has_required_fields() -> None:
    """Every registered detector must have non-empty id, name, domain, domain_id,
    and accepted_artifact_types."""
    for det in get_all_detectors():
        assert det.detector_id, f"{det.__class__.__name__} has empty detector_id"
        assert det.name, f"{det.detector_id} has empty name"
        assert det.domain, f"{det.detector_id} has empty domain"
        assert det.domain_id in {"d1", "d2", "d3", "d4", "d5"}, (
            f"{det.detector_id} has invalid domain_id {det.domain_id!r}"
        )
        assert det.accepted_artifact_types, (
            f"{det.detector_id} has no accepted_artifact_types"
        )


def test_get_detector_returns_correct_instance() -> None:
    """get_detector() must return the exact registered instance."""
    det = get_detector("d01_email_phishing")
    assert det is not None
    assert det.detector_id == "d01_email_phishing"
    assert det.name == "Email Phishing"
    assert det.domain_id == "d1"


def test_get_detector_returns_none_for_unknown_id() -> None:
    """get_detector() must return None for an unregistered id."""
    assert get_detector("nonexistent_detector") is None


def test_get_detectors_for_domain_d1() -> None:
    """Domain d1 must contain exactly 9 detectors."""
    d1 = get_detectors_for_domain("d1")
    assert len(d1) == 9


def test_get_detectors_for_domain_d5() -> None:
    """Domain d5 must contain exactly 2 detectors."""
    d5 = get_detectors_for_domain("d5")
    assert len(d5) == 2
    ids = {d.detector_id for d in d5}
    assert ids == {"d21_qr_phishing", "d22_screenshot_scam"}


@pytest.mark.parametrize("detector_id", [
    "d01_email_phishing",
    "d02_social_engineering",
    "d03_spear_phishing",
    "d04_scam_fraud",
    "d05_smishing",
    "d06_government_scams",
    "d07_financial_investment",
    "d08_recruitment_scams",
    "d09_tech_support_scams",
    "d10_malicious_url",
    "d11_brand_impersonation",
    "d12_malicious_redirects",
    "d13_url_obfuscation",
    "d14_idn_homograph",
    "d15_credential_harvesting",
    "d16_fake_auth_pages",
    "d17_malicious_webpages",
    "d18_bec",
    "d19_spam",
    "d20_suspicious_attachments",
    "d21_qr_phishing",
    "d22_screenshot_scam",
])
def test_all_22_detector_ids_registered(detector_id: str) -> None:
    """Each of the 22 expected detector IDs must be in the registry."""
    assert get_detector(detector_id) is not None, (
        f"Detector {detector_id!r} is not registered."
    )
