"""
Tests for Stages 6-10: Web/Email/Media engines + D15-D22 detectors + Aggregator.
"""

from __future__ import annotations

import pytest

from app.core.context import AnalysisContext
from app.engines.nlp.backends.rules import RulesBackend
from app.engines.nlp.engine import NLPEngine
from app.schemas.schemas import (
    Artifact,
    ArtifactType,
    AttachmentInfo,
    IntelSignals,
    Verdict,
)

# ── Web Engine ────────────────────────────────────────────────────────────────

def test_web_engine_empty_html():
    from app.engines.web.engine import _parse_html
    signals = _parse_html("")
    assert not signals.has_password_field
    assert not signals.has_card_field


def test_web_engine_password_field():
    from app.engines.web.engine import _parse_html
    html = '<form><input type="password" name="pwd"/></form>'
    signals = _parse_html(html)
    assert signals.has_password_field


def test_web_engine_card_field():
    from app.engines.web.engine import _parse_html
    html = '<form><input name="card_number"/><input name="cvv"/></form>'
    signals = _parse_html(html)
    assert signals.has_card_field


def test_web_engine_otp_field():
    from app.engines.web.engine import _parse_html
    html = '<input name="otp" placeholder="Enter OTP"/>'
    signals = _parse_html(html)
    assert signals.has_otp_field


def test_web_engine_eval_obfuscation():
    from app.engines.web.engine import _parse_html
    html = '<script>eval(atob("dGVzdA=="))</script>'
    signals = _parse_html(html)
    assert signals.has_eval_obfuscation


def test_web_engine_claimed_brand():
    from app.engines.web.engine import _parse_html
    html = '<html><head><title>PayPal Login</title></head></html>'
    signals = _parse_html(html)
    assert signals.claimed_brand == "paypal"


def test_web_engine_no_threats():
    from app.engines.web.engine import _parse_html
    html = '<html><body><h1>About Us</h1><p>We sell widgets.</p></body></html>'
    signals = _parse_html(html)
    assert not signals.has_password_field
    assert not signals.has_eval_obfuscation
    assert signals.claimed_brand is None


# ── Email Engine ──────────────────────────────────────────────────────────────

PHISH_EML = """\
From: "PayPal Support" <support@evil-attacker.xyz>
Reply-To: realhacker@evil.com
To: victim@example.com
Subject: Your account has been suspended
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Click here to verify your account: https://paypal-verify.evil.xyz
Enter your password and card number.
"""

LEGIT_EML = """\
From: "Alice Smith" <alice@company.com>
To: bob@company.com
Subject: Meeting tomorrow

Hi Bob, see you at the meeting tomorrow at 10am.
"""


def test_email_engine_reply_to_mismatch():
    from app.engines.email.engine import _parse_email
    signals = _parse_email(PHISH_EML)
    assert signals.from_reply_to_mismatch


def test_email_engine_display_name_spoof():
    from app.engines.email.engine import _parse_email
    signals = _parse_email(PHISH_EML)
    assert signals.display_name_spoofing


def test_email_engine_spf_fail():
    from app.engines.email.engine import _parse_email
    signals = _parse_email(PHISH_EML)
    assert signals.spf_pass is False


def test_email_engine_dkim_fail():
    from app.engines.email.engine import _parse_email
    signals = _parse_email(PHISH_EML)
    assert signals.dkim_pass is False


def test_email_engine_url_extraction():
    from app.engines.email.engine import _parse_email
    signals = _parse_email(PHISH_EML)
    assert any("paypal-verify" in u for u in signals.extracted_urls)


def test_email_engine_legit_no_mismatch():
    from app.engines.email.engine import _parse_email
    signals = _parse_email(LEGIT_EML)
    assert not signals.from_reply_to_mismatch
    assert not signals.display_name_spoofing


# ── Intel Engine ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_intel_engine_local_blocklist_domain():
    from app.engines.intel.engine import IntelEngine
    engine = IntelEngine()
    signals = await engine.lookup("phishing-example-test.xyz")
    assert any(h["source"] == "local_domains" for h in signals.hits)


@pytest.mark.asyncio
async def test_intel_engine_local_blocklist_url():
    from app.engines.intel.engine import IntelEngine
    engine = IntelEngine()
    signals = await engine.lookup("http://phishing-example-test.xyz/login")
    assert any(h["source"] in ("local_domains", "local_urls") for h in signals.hits)


@pytest.mark.asyncio
async def test_intel_engine_clean_indicator():
    from app.engines.intel.engine import IntelEngine
    engine = IntelEngine()
    signals = await engine.lookup("https://www.google.com")
    assert signals.hits == []


@pytest.mark.asyncio
async def test_intel_engine_offline_mode():
    from app.engines.intel.engine import IntelEngine
    engine = IntelEngine()
    signals = await engine.lookup("any-indicator")
    assert signals.offline_mode is True  # INTEL_OFFLINE=true by default


# ── Risk Aggregator ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_aggregator_empty_results():
    from app.aggregator.aggregator import RiskAggregator
    agg = RiskAggregator()
    artifact = Artifact(type=ArtifactType.URL, raw_content="https://example.com")
    report = await agg.aggregate(artifact=artifact, results=[], errors=[], skipped=[])
    assert report.risk_score == 0.0
    assert report.verdict == Verdict.SAFE


@pytest.mark.asyncio
async def test_aggregator_single_malicious_detector():
    from app.aggregator.aggregator import RiskAggregator
    from app.schemas.schemas import DetectionResult
    agg = RiskAggregator()
    artifact = Artifact(type=ArtifactType.URL, raw_content="http://evil.xyz")
    results = [
        DetectionResult(detector_id="d10_malicious_url", name="Malicious URL",
                        domain="URL & Domain Security", domain_id="d2",
                        score=0.95, verdict=Verdict.MALICIOUS, confidence=0.90,
                        ran=True),
    ]
    report = await agg.aggregate(artifact=artifact, results=results)
    assert report.risk_score > 20
    assert report.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_aggregator_intel_hit_floor():
    from app.aggregator.aggregator import RiskAggregator
    from app.schemas.schemas import DetectionResult, EngineSignals
    agg = RiskAggregator()
    artifact = Artifact(type=ArtifactType.URL, raw_content="http://blocklisted.xyz")
    results = [
        DetectionResult(detector_id="d10_malicious_url", name="Malicious URL",
                        domain="URL & Domain Security", domain_id="d2",
                        score=0.10, verdict=Verdict.SAFE, confidence=0.5, ran=True),
    ]
    engine_signals = EngineSignals(
        intel=IntelSignals(hits=[{"source": "local_domains", "type": "domain",
                                  "indicator": "blocklisted.xyz", "threat": "blocklisted_domain"}])
    )
    report = await agg.aggregate(artifact=artifact, results=results, engine_signals=engine_signals)
    # Intel hit floors score at 0.80 → 80 on 0-100 scale
    assert report.risk_score >= 75
    assert report.verdict in (Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_aggregator_noisy_or_combines():
    from app.aggregator.aggregator import _noisy_or
    # noisy-OR of [0.5, 0.5] = 1 - (0.5 * 0.5) = 0.75
    assert abs(_noisy_or([0.5, 0.5]) - 0.75) < 0.01
    assert _noisy_or([]) == 0.0
    assert abs(_noisy_or([1.0]) - 1.0) < 0.001


# ── Explainer ─────────────────────────────────────────────────────────────────

def test_explainer_defangs_urls():
    from app.explain.explainer import _defang
    assert "hxxp://" in _defang("http://evil.com")
    assert "[.]" in _defang("http://evil.com")


def test_explainer_summarise_empty():
    from app.explain.explainer import Explainer
    ex = Explainer()
    assert "No threat" in ex.summarise([])


def test_explainer_adds_verdict_summary():
    from app.explain.explainer import Explainer
    from app.schemas.schemas import RiskReport
    ex = Explainer()
    artifact = Artifact(type=ArtifactType.URL, raw_content="http://x.com")
    report = RiskReport(
        artifact_id=artifact.id,
        artifact_type=artifact.type,
        risk_score=80.0,
        verdict=Verdict.MALICIOUS,
        recommended_actions=["Do not click"],
    )
    enriched = ex.explain(report)
    assert any("malicious" in a.lower() or "⚠️" in a for a in enriched.recommended_actions)


# ── D15-D22 Detector Smoke Tests ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_d15_credential_harvesting_password_field():
    from app.detectors.d3_web.d15_credential_harvesting import CredentialHarvestingDetector
    from app.engines.web.engine import WebEngine
    html = '<form><input type="password"/><input name="cvv"/></form>'
    artifact = Artifact(type=ArtifactType.WEBPAGE, raw_content=html)
    nlp_engine = NLPEngine(backend=RulesBackend())
    ctx = AnalysisContext(artifact=artifact, nlp_engine=nlp_engine, web_engine=WebEngine())
    detector = CredentialHarvestingDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_d15_safe_clean_page():
    from app.detectors.d3_web.d15_credential_harvesting import CredentialHarvestingDetector
    from app.engines.web.engine import WebEngine
    html = '<html><body><h1>About Us</h1></body></html>'
    artifact = Artifact(type=ArtifactType.WEBPAGE, raw_content=html)
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          web_engine=WebEngine())
    detector = CredentialHarvestingDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict == Verdict.SAFE


@pytest.mark.asyncio
async def test_d16_fake_auth_page():
    from app.detectors.d3_web.d16_fake_auth_pages import FakeAuthPagesDetector
    from app.engines.web.engine import WebEngine
    html = '<html><head><title>PayPal Login</title></head><body><input type="password"/></body></html>'
    artifact = Artifact(type=ArtifactType.WEBPAGE, raw_content=html)
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          web_engine=WebEngine())
    detector = FakeAuthPagesDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_d18_bec_detection():
    from app.detectors.d4_email.d18_bec import BECDetector
    from app.engines.email.engine import EmailEngine
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content=PHISH_EML)
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          email_engine=EmailEngine())
    detector = BECDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_d18_safe_on_legit_email():
    from app.detectors.d4_email.d18_bec import BECDetector
    from app.engines.email.engine import EmailEngine
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content=LEGIT_EML)
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          email_engine=EmailEngine())
    detector = BECDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict == Verdict.SAFE


@pytest.mark.asyncio
async def test_d19_spam_detection():
    from app.detectors.d4_email.d19_spam import SpamDetector
    from app.engines.email.engine import EmailEngine
    spam_eml = """\
From: promo@bulk-mailer.xyz
To: victim@example.com
Subject: You won a prize!
Authentication-Results: spf=fail

Congratulations! You won a lottery jackpot! Claim your reward now!
http://prize1.xyz http://prize2.xyz http://prize3.xyz http://prize4.xyz http://prize5.xyz
"""
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content=spam_eml)
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          email_engine=EmailEngine())
    detector = SpamDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_d20_suspicious_attachment_exe():
    from app.detectors.d4_email.d20_suspicious_attachments import SuspiciousAttachmentsDetector
    from app.engines.email.engine import EmailEngine
    att = AttachmentInfo(filename="invoice.pdf.exe", declared_mime="application/pdf",
                         detected_mime="application/octet-stream", size_bytes=50000)
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content=LEGIT_EML, attachments=[att])
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          email_engine=EmailEngine())
    detector = SuspiciousAttachmentsDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict in (Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_d20_macro_doc_suspicious():
    from app.detectors.d4_email.d20_suspicious_attachments import SuspiciousAttachmentsDetector
    from app.engines.email.engine import EmailEngine
    att = AttachmentInfo(filename="invoice.docm", declared_mime="application/vnd.ms-word",
                         size_bytes=20000)
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content=LEGIT_EML, attachments=[att])
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          email_engine=EmailEngine())
    detector = SuspiciousAttachmentsDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS)


@pytest.mark.asyncio
async def test_d20_safe_pdf():
    from app.detectors.d4_email.d20_suspicious_attachments import SuspiciousAttachmentsDetector
    from app.engines.email.engine import EmailEngine
    att = AttachmentInfo(filename="report.pdf", declared_mime="application/pdf",
                         detected_mime="application/pdf", size_bytes=10000)
    artifact = Artifact(type=ArtifactType.EMAIL, raw_content=LEGIT_EML, attachments=[att])
    ctx = AnalysisContext(artifact=artifact, nlp_engine=NLPEngine(backend=RulesBackend()),
                          email_engine=EmailEngine())
    detector = SuspiciousAttachmentsDetector()
    result = await detector.detect(artifact, ctx)
    assert result.verdict == Verdict.SAFE
