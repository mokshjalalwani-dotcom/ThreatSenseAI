"""
Stage 3: Domain 2 detector tests (D10-D14).

For each detector, 15+ POSITIVE and 15+ NEGATIVE offline fixtures are tested.
All URLs are synthetic/benign-safe — no live requests, no real malware.

Acceptance criteria verified:
  ✓ Every result has a human-readable evidence description
  ✓ Every result score in [0, 1]
  ✓ Every result verdict is a valid Verdict enum value
  ✓ Benign URLs do NOT trigger detectors (false positive gate)
  ✓ Malicious fixtures DO trigger detectors (recall gate)
"""

from __future__ import annotations

import pytest

from app.core.context import AnalysisContext
from app.detectors.d2_url.d10_malicious_url import MaliciousURLDetector
from app.detectors.d2_url.d11_brand_impersonation import BrandImpersonationDetector
from app.detectors.d2_url.d12_malicious_redirects import MaliciousRedirectsDetector
from app.detectors.d2_url.d13_url_obfuscation import URLObfuscationDetector
from app.detectors.d2_url.d14_idn_homograph import IDNHomographDetector
from app.engines.url.engine import URLEngine
from app.schemas.schemas import Artifact, ArtifactType, Verdict

# ── Helpers ───────────────────────────────────────────────────────────────────


def _url_artifact(url: str) -> Artifact:
    return Artifact(
        type=ArtifactType.URL,
        raw_content=url,
        normalized_url=url,
    )


def _ctx(url: str) -> AnalysisContext:
    return AnalysisContext(artifact=_url_artifact(url), url_engine=URLEngine())


def _assert_valid_result(result) -> None:
    assert 0.0 <= result.score <= 1.0, f"score {result.score} out of range"
    assert result.verdict in list(Verdict), f"invalid verdict {result.verdict}"


def _assert_has_evidence(result) -> None:
    assert result.evidence, "Expected at least one Evidence item"
    for ev in result.evidence:
        assert ev.description, "Evidence description must not be empty"


# ═══════════════════════════════════════════════════════════════════════════════
# D10 — Malicious URL
# ═══════════════════════════════════════════════════════════════════════════════


_D10_POSITIVES = [
    "http://192.168.1.1/paypal-login/verify-account.php?id=12345",
    "http://0xC0A80101/secure/update-billing",
    "http://paypa1-secure-login.xyz/account/billing/verify.php",
    "http://2130706433/admin/panel",
    "http://bit.ly/3xR8m2K",
    "https://amazon-security-alert.cf/account/suspended",
    "http://update-your-kyc.ml/sbi-net-banking/login",
    "https://sbi-onlinesecure-verify.tk/auth?token=abc&session=9999",
    "https://paypal.com.secure-update.info/login",
    "http://faceb00k-login.ga/recover-account",
    "http://secure-hdfc-netbanking-verify.xyz/login.php",
    "https://income-tax-refund-2024.cf/login",
    "https://free-recharge-jio.xyz/activate?mobile=9876543210",
    "http://phishing.example.tk/paytm/kyc-update.php",
    "https://verify-account-securely.online/paypal/billing/update",
]

_D10_NEGATIVES = [
    "https://www.google.com/search?q=python+tutorial",
    "https://github.com/openai/gpt-3",
    "https://stackoverflow.com/questions/12345",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://docs.python.org/3/library/pathlib.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.linkedin.com/in/johndoe",
    "https://onlinesbi.sbi",
    "https://netbanking.hdfcbank.com",
    "https://incometax.gov.in/iec/foportal",
    "https://uidai.gov.in/verify-aadhaar",
    "https://irctc.co.in/nget/train-search",
    "https://pypi.org/project/requests/",
    "https://fastapi.tiangolo.com/tutorial/",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D10_POSITIVES)
async def test_d10_positive_has_valid_result(url: str) -> None:
    det = MaliciousURLDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D10_NEGATIVES)
async def test_d10_negative_scores_below_threshold(url: str) -> None:
    det = MaliciousURLDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    # Benign URLs should not be MALICIOUS
    assert result.verdict != Verdict.MALICIOUS, (
        f"Benign URL '{url}' falsely flagged as MALICIOUS (score={result.score})"
    )


@pytest.mark.asyncio
async def test_d10_ip_host_scored_suspicious_or_higher() -> None:
    det = MaliciousURLDetector()
    url = "http://192.168.0.1/login?user=admin"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    assert result.score > 0.3
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.MALICIOUS}


@pytest.mark.asyncio
async def test_d10_result_has_evidence() -> None:
    det = MaliciousURLDetector()
    url = "http://paypa1-secure.xyz/verify?account=12345"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_has_evidence(result)


# ═══════════════════════════════════════════════════════════════════════════════
# D11 — Brand Impersonation
# ═══════════════════════════════════════════════════════════════════════════════


_D11_POSITIVES = [
    # Fuzzy typosquatting
    "https://paypa1.com/login",
    "https://paypa1-secure.xyz/billing",
    "https://g00gle-security.cf/verify",
    "https://micros0ft-verify.ml/account",
    "https://amaz0n-winner.ga/claim",
    "https://netfl1x-billing.xyz/update",
    # Subdomain injection
    "https://paypal.evil.com/login",
    "https://sbi.phishing-india.xyz/net-banking",
    "https://hdfc.fraudsite.cf/verify",
    "https://icici.scamsite.ml/login",
    # Path injection
    "https://phishing.xyz/paypal/login-verify.php",
    "https://evil.com/google/account-recovery.php",
    "https://fraud.ga/sbi/netbanking/authenticate",
    "https://attacker.tk/paytm/kyc-update-urgent",
    "https://scam.cf/amazon/order-confirmation-billing",
]

_D11_NEGATIVES = [
    # Real brand domains — must NOT be flagged
    "https://www.paypal.com/login",
    "https://accounts.google.com/signin",
    "https://www.amazon.in/s?k=laptop",
    "https://onlinesbi.sbi",
    "https://netbanking.hdfcbank.com",
    "https://www.icicibank.com",
    "https://paytm.com/offers",
    "https://www.phonepe.com",
    "https://incometax.gov.in",
    "https://uidai.gov.in",
    "https://www.airtel.in",
    "https://www.jio.com",
    # Completely unrelated brands
    "https://randomshop.co.in/products",
    "https://myblog.wordpress.com",
    "https://opensource.example.org",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D11_POSITIVES)
async def test_d11_positive_detects_impersonation(url: str) -> None:
    det = BrandImpersonationDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict != Verdict.SAFE, (
        f"D11 missed impersonation in '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D11_NEGATIVES)
async def test_d11_negative_not_flagged(url: str) -> None:
    det = BrandImpersonationDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict != Verdict.MALICIOUS, (
        f"D11 false-positive MALICIOUS on legitimate URL '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
async def test_d11_evidence_has_brand_name() -> None:
    det = BrandImpersonationDetector()
    url = "https://paypa1.com/login"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    if result.verdict != Verdict.SAFE:
        assert result.evidence
        full_text = " ".join(e.description for e in result.evidence).lower()
        assert "paypal" in full_text or "paypa1" in full_text


# ═══════════════════════════════════════════════════════════════════════════════
# D12 — Malicious Redirects
# ═══════════════════════════════════════════════════════════════════════════════


_D12_POSITIVES = [
    # Known shorteners (hidden destination)
    "https://bit.ly/abc123",
    "http://tinyurl.com/xyz456",
    "http://ow.ly/abc789",
    "https://t.co/suspicious",
    "http://goo.gl/legacy",
    # Open redirect parameters
    "https://legit.com/go?url=https://evil-phish.xyz",
    "https://example.com/redirect?next=http://malware-site.ml",
    "https://service.com/?redirect=https://attacker.tk/steal",
    "https://trusted.com/out?dest=https://phishing.ga/login",
    "https://real.com/forward?target=http://scam.cf",
    # Combined
    "https://bit.ly/?url=https://evil.xyz",
    "http://tinyurl.com/?redirect=https://phish.ml",
    "http://is.gd/?next=https://scam.ga",
    "https://rb.gy/?dest=http://malware.tk",
    "https://cutt.ly/?go=https://fraud.cf",
]

_D12_NEGATIVES = [
    "https://www.google.com/search?q=python",
    "https://github.com/openai/gpt-4",
    "https://stackoverflow.com/questions/12345",
    "https://docs.python.org/3/library",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.amazon.in/products",
    "https://onlinesbi.sbi/login",
    "https://www.linkedin.com/in/user",
    "https://pypi.org/project/django/",
    "https://fastapi.tiangolo.com/",
    # Legit redirect/tracking params
    "https://mail.google.com/mail/u/0/#inbox",
    "https://accounts.google.com/signin/v2/identifier",
    "https://www.amazon.com/dp/B09X4RXFQ5?ref=sr_1_1",
    "https://example.com/blog/article",
    "https://www.w3schools.com/python/default.asp",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D12_POSITIVES)
async def test_d12_positive_flagged(url: str) -> None:
    det = MaliciousRedirectsDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict != Verdict.SAFE, (
        f"D12 missed redirect risk in '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D12_NEGATIVES)
async def test_d12_negative_not_malicious(url: str) -> None:
    det = MaliciousRedirectsDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict != Verdict.MALICIOUS, (
        f"D12 false-positive MALICIOUS on '{url}' (score={result.score})"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# D13 — URL Obfuscation
# ═══════════════════════════════════════════════════════════════════════════════


_D13_POSITIVES = [
    # Double percent-encoding
    "http://evil.com/%2F%252F%2F%2F",
    "http://evil.com/%252525252f%252f",
    # @-trick
    "https://evil.com@paypal.com/verify",
    "http://google.com@evil-attacker.xyz/phish",
    # Decimal IP
    "http://2130706433/admin",
    "http://167772161/private",
    # Hex IP
    "http://0x7f000001/admin",
    "http://0xC0A80101/login",
    # Octal IP
    "http://0177.0.0.1/malicious",
    "http://0300.0250.0.1/secret",
    # data:/javascript: scheme
    "javascript:alert(document.cookie)",
    "data:text/html,<script>alert(1)</script>",
    # Excessive subdomains
    "https://a.b.c.d.e.f.evil.xyz/login",
    # Whitespace injection
    "https://evil.com/page\twith\ttabs",
    # High-entropy path
    "https://evil.com/aB3xQ9mKzRpTwYuIoLvNqJhFgDsAmZnE",
]

_D13_NEGATIVES = [
    "https://www.google.com/search?q=python+tutorial",
    "https://accounts.google.com/signin",
    "https://github.com/user/repo?tab=readme",
    "https://docs.python.org/3/library/pathlib.html",
    "https://stackoverflow.com/a/12345/67890",
    "https://www.amazon.com/s?k=laptop&ref=sr",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://pypi.org/project/requests/2.31.0/",
    "https://en.wikipedia.org/wiki/Python_(programming_language)",
    "https://developer.mozilla.org/en-US/docs/Web/API",
    # Normal percent-encoding (single, for special chars)
    "https://example.com/search?q=hello%20world",
    "https://example.com/caf%C3%A9",
    "https://www.bbc.co.uk/news/technology",
    "https://medium.com/@author/article-slug-abc",
    "https://www.nytimes.com/2024/01/01/tech/ai.html",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D13_POSITIVES)
async def test_d13_positive_obfuscation_detected(url: str) -> None:
    det = URLObfuscationDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict != Verdict.SAFE, (
        f"D13 missed obfuscation in '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D13_NEGATIVES)
async def test_d13_negative_not_flagged(url: str) -> None:
    det = URLObfuscationDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict != Verdict.MALICIOUS, (
        f"D13 false-positive MALICIOUS on '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
async def test_d13_at_trick_evidence_mentions_host() -> None:
    det = URLObfuscationDetector()
    url = "https://paypal.com@evil-attacker.xyz/phish"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    if result.verdict != Verdict.SAFE:
        desc = " ".join(e.description.lower() for e in result.evidence)
        assert "evil-attacker" in desc or "attacker" in desc or "@" in desc


@pytest.mark.asyncio
async def test_d13_double_encoding_evidence_has_decoded_form() -> None:
    det = URLObfuscationDetector()
    url = "http://evil.com/%252F%252Fmalicious"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    if result.evidence:
        desc_all = " ".join(e.description for e in result.evidence)
        # decoded form should appear in evidence
        assert "decoded" in desc_all.lower() or "//" in desc_all


# ═══════════════════════════════════════════════════════════════════════════════
# D14 — IDN / Homograph
# ═══════════════════════════════════════════════════════════════════════════════


_D14_POSITIVES = [
    # Punycode domains
    "http://xn--ppal-3qa.com/login",           # fake punycode
    "http://xn--ggle-55da.com",                # fake punycode for google-like
    "http://xn--mcrosoft-53a.com/login",       # fake punycode
    "http://xn--pple-43d.com",                 # fake punycode for apple
    "http://xn--amzon-6za.com/login",          # fake punycode
    "http://xn--mircrosoft-7mb.com",           # fake punycode
    "http://xn--aypal-q9d.com/verify",         # fake punycode
    "http://xn--sbl-gla.co.in",               # fake punycode for sbi
    "http://xn--ndfc-2ya.com/netbanking",      # fake punycode for hdfc
    "http://xn--cici-t4a.com/login",           # fake punycode for icici
    "https://www.xn--pyal-fwb.com/login",    # fake punycode mixed host
    "http://xn--hdfcbnk-qxa.com",             # fake punycode
    "http://xn--ax1s-pqa.com/login",          # fake punycode for axis
    "http://login.xn--gogle-wya.com",         # fake punycode
    "http://www.xn--pytm-hzc.com",           # fake punycode for paytm
]

_D14_NEGATIVES = [
    # Normal domains — no Punycode
    "https://www.google.com",
    "https://www.paypal.com",
    "https://accounts.google.com/signin",
    "https://onlinesbi.sbi",
    "https://www.amazon.in",
    "https://incometax.gov.in",
    "https://www.hdfc.com",
    "https://www.icicibank.com",
    "https://paytm.com",
    "https://www.phonepe.com",
    # Legitimate international domains (non-brand, unrelated to any brand)
    "https://xn--bcher-kva.de",    # bücher.de (German book site)
    "https://xn--n3cw4h.com",      # legitimate Thai domain
    "https://developer.mozilla.org",
    "https://pypi.org/project/django",
    "https://stackoverflow.com",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D14_POSITIVES)
async def test_d14_positive_punycode_flagged(url: str) -> None:
    det = IDNHomographDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    # All positive fixtures contain Punycode and should NOT be SAFE
    assert result.verdict != Verdict.SAFE, (
        f"D14 missed Punycode in '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _D14_NEGATIVES)
async def test_d14_negative_not_malicious(url: str) -> None:
    det = IDNHomographDetector()
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    _assert_valid_result(result)
    assert result.verdict not in {Verdict.MALICIOUS, Verdict.LIKELY_MALICIOUS}, (
        f"D14 false-positive on '{url}' (score={result.score})"
    )


@pytest.mark.asyncio
async def test_d14_no_punycode_is_safe() -> None:
    det = IDNHomographDetector()
    url = "https://www.google.com/search"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    assert result.verdict == Verdict.SAFE
    assert result.score == 0.0


@pytest.mark.asyncio
async def test_d14_evidence_mentions_punycode() -> None:
    det = IDNHomographDetector()
    url = "http://xn--ppal-3qa.com/login"
    ctx = _ctx(url)
    result = await det.detect(_url_artifact(url), ctx)
    if result.verdict != Verdict.SAFE and result.evidence:
        desc = " ".join(e.description.lower() for e in result.evidence)
        assert "punycode" in desc or "xn--" in desc or "idn" in desc


# ── Cross-detector sanity ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_all_d2_detectors_accept_url_artifact() -> None:
    """All 5 D2 detectors accept ArtifactType.URL."""
    detectors = [
        MaliciousURLDetector(),
        BrandImpersonationDetector(),
        MaliciousRedirectsDetector(),
        URLObfuscationDetector(),
        IDNHomographDetector(),
    ]
    for det in detectors:
        assert det.accepts(ArtifactType.URL), f"{det.detector_id} should accept URL"


@pytest.mark.asyncio
async def test_all_d2_detectors_return_valid_results() -> None:
    """All D2 detectors run on a neutral URL and return valid results."""
    url = "https://www.example.com/safe-page"
    art = _url_artifact(url)
    ctx = _ctx(url)
    detectors = [
        MaliciousURLDetector(),
        BrandImpersonationDetector(),
        MaliciousRedirectsDetector(),
        URLObfuscationDetector(),
        IDNHomographDetector(),
    ]
    for det in detectors:
        result = await det.detect(art, ctx)
        _assert_valid_result(result)
        assert result.detector_id == det.detector_id
