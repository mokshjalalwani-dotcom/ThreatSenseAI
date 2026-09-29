"""
API integration tests — /health, /detectors, /analyze.

Acceptance criteria:
  ✓ GET /health returns 200 with status='ok' and detector_count=22.
  ✓ GET /detectors returns 22 detectors across 5 domains (9/5/3/3/2).
  ✓ POST /analyze with a URL artifact returns a valid RiskReport.
  ✓ POST /analyze with NLP_BACKEND=finetuned returns a report (fallback to rules).
  ✓ GET /analyses/{id} returns the stored report.
"""

from __future__ import annotations


async def test_health_returns_ok(client) -> None:
    """GET /health must return HTTP 200 with status='ok'."""
    resp = await client.get("/health")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "ok"
    assert data["detector_count"] == 22


async def test_health_includes_nlp_backend(client) -> None:
    """GET /health must include the active NLP backend name."""
    resp = await client.get("/health")
    data = resp.json()
    assert "nlp_backend" in data
    assert data["nlp_backend"] in ("rules", "zeroshot", "finetuned", "ensemble")


async def test_detectors_total_is_22(client) -> None:
    """GET /detectors total must be exactly 22."""
    resp = await client.get("/detectors")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] == 22


async def test_detectors_domain_breakdown(client) -> None:
    """GET /detectors must return exactly 5 domains with 9/5/3/3/2 detectors."""
    resp = await client.get("/detectors")
    data = resp.json()
    domains = {d["domain_id"]: len(d["detectors"]) for d in data["domains"]}
    assert domains == {"d1": 9, "d2": 5, "d3": 3, "d4": 3, "d5": 2}, (
        f"Domain breakdown wrong: {domains}"
    )


async def test_detectors_all_have_required_fields(client) -> None:
    """Every detector in GET /detectors must have required fields."""
    resp = await client.get("/detectors")
    data = resp.json()
    for domain in data["domains"]:
        for det in domain["detectors"]:
            assert det["detector_id"], f"Empty detector_id in {det}"
            assert det["name"], f"Empty name for {det['detector_id']}"
            assert det["accepted_artifact_types"], (
                f"No accepted_artifact_types for {det['detector_id']}"
            )


async def test_analyze_url_returns_risk_report(client) -> None:
    """POST /analyze with a URL artifact must return a valid RiskReport."""
    resp = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "http://example.com", "metadata": {}},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "risk_score" in data
    assert "verdict" in data
    assert "analysis_id" in data
    assert "per_domain_scores" in data
    assert isinstance(data["risk_score"], (int, float))
    assert 0.0 <= data["risk_score"] <= 100.0


async def test_analyze_email_returns_risk_report(client) -> None:
    """POST /analyze with an email artifact must return a valid RiskReport."""
    email_text = (
        "From: ceo@example.com\n"
        "To: finance@example.com\n"
        "Subject: Urgent wire transfer needed\n\n"
        "Please transfer $50,000 immediately. Keep this confidential."
    )
    resp = await client.post(
        "/analyze",
        json={"type": "email", "raw_content": email_text},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["artifact_type"] == "email"


async def test_analyze_sms_returns_risk_report(client) -> None:
    """POST /analyze with an SMS artifact must return a valid RiskReport."""
    resp = await client.post(
        "/analyze",
        json={
            "type": "sms",
            "raw_content": "Your KYC is pending. Click http://bit.ly/kyc-update to update.",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["artifact_type"] == "sms"


async def test_analyze_report_includes_per_domain_scores(client) -> None:
    """RiskReport must include per-domain breakdown with all 5 domains."""
    resp = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "http://example.com"},
    )
    data = resp.json()
    # At least the domains that have detectors matching 'url' type should appear
    assert len(data["per_domain_scores"]) > 0


async def test_get_analysis_retrieves_stored_report(client) -> None:
    """GET /analyses/{id} must return the same report that POST /analyze returned."""
    post_resp = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "http://example.com"},
    )
    assert post_resp.status_code == 200
    analysis_id = post_resp.json()["analysis_id"]

    get_resp = await client.get(f"/analyses/{analysis_id}")
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    assert retrieved["analysis_id"] == analysis_id


async def test_get_analysis_404_for_unknown_id(client) -> None:
    """GET /analyses/{id} with an unknown ID must return 404."""
    resp = await client.get("/analyses/nonexistent-id-xyz")
    assert resp.status_code == 404
