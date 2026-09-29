"""
Detectors package — imports all 22 detector modules to trigger @register_detector.

IMPORTANT: This file is the single place that must be imported at startup to
populate the registry.  It is imported by ``app.main`` on application startup.

Adding a new detector:
  1. Create ``dN_<domain>/<id>_<name>.py`` following the existing pattern.
  2. Decorate the class with ``@register_detector``.
  3. Add an import line here (alphabetical within domain).
"""

# ── Domain 1: Phishing & Social Engineering (9) ──────────────────────────────
from app.detectors.d1_phishing import (  # noqa: F401
    d01_email_phishing,
    d02_social_engineering,
    d03_spear_phishing,
    d04_scam_fraud,
    d05_smishing,
    d06_government_scams,
    d07_financial_investment,
    d08_recruitment_scams,
    d09_tech_support_scams,
)

# ── Domain 2: URL & Domain Security (5) ──────────────────────────────────────
from app.detectors.d2_url import (  # noqa: F401
    d10_malicious_url,
    d11_brand_impersonation,
    d12_malicious_redirects,
    d13_url_obfuscation,
    d14_idn_homograph,
)

# ── Domain 3: Web & Credential Security (3) ──────────────────────────────────
from app.detectors.d3_web import (  # noqa: F401
    d15_credential_harvesting,
    d16_fake_auth_pages,
    d17_malicious_webpages,
)

# ── Domain 4: Email & Communication Security (3) ─────────────────────────────
from app.detectors.d4_email import (  # noqa: F401
    d18_bec,
    d19_spam,
    d20_suspicious_attachments,
)

# ── Domain 5: Multimedia & Image-Based (2) ───────────────────────────────────
from app.detectors.d5_media import (  # noqa: F401
    d21_qr_phishing,
    d22_screenshot_scam,
)
