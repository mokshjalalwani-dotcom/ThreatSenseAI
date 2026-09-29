"""
URL/Domain Feature Extractor — Stage 3.

Computes a ~25-dimensional feature vector from a URL string alone (no HTTP
requests).  All features are numeric and suitable for XGBoost/LightGBM.

Optional network features (domain age via RDAP, DNS A/MX/NS record counts,
TTL) are computed only when ``ENABLE_NETWORK_FEATURES=true`` is set in the
environment.  When disabled (default), those fields are filled with sentinel
value -1.0 so the model can distinguish "unknown" from "zero".

Feature index is STABLE — do not reorder without bumping model version.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import tldextract

# ── Constants ─────────────────────────────────────────────────────────────────

_TLD = tldextract.TLDExtract(cache_dir=None)

_SUSPICIOUS_TOKENS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "validate", "validation",
    "secure", "security", "update", "confirm",
    "account", "accounts", "billing", "invoice",
    "banking", "bank", "paypal", "amazon", "apple",
    "microsoft", "google", "facebook", "instagram",
    "netflix", "ebay", "wallet", "crypto", "bitcoin",
    "urgent", "alert", "suspended", "blocked", "limited",
    "recover", "restore", "reactivate",
    "kyc", "upi", "aadhar", "aadhaar", "pan",
    "refund", "cashback", "reward", "winner", "prize",
    "free", "offer", "deal", "discount",
    "support", "helpdesk", "helpcenter",
    "password", "pwd", "cred", "credential",
    "otp", "2fa", "auth", "authorize",
    "track", "tracking", "parcel", "delivery",
    "tax", "irs", "income-tax", "epfo", "esic",
    "gov", "govt", "government", "official",
})

# TLD risk buckets: 0.0 = very safe, 1.0 = very risky
# Based on ICANN abuse statistics and Spamhaus data
_TLD_RISK: dict[str, float] = {
    # Very safe
    "gov": 0.0, "edu": 0.0, "mil": 0.0,
    "gov.in": 0.0, "edu.in": 0.0, "nic.in": 0.0,
    "ac.in": 0.0, "ac.uk": 0.0,
    "com": 0.1, "net": 0.1, "org": 0.1,
    "co.uk": 0.1, "co.in": 0.1,
    "in": 0.15, "uk": 0.1, "us": 0.1,
    "io": 0.2, "dev": 0.15, "app": 0.15,
    # Medium risk
    "info": 0.4, "biz": 0.4, "online": 0.5,
    "site": 0.5, "website": 0.5, "store": 0.4,
    "shop": 0.4, "club": 0.4, "pro": 0.3,
    # Higher risk (commonly abused)
    "xyz": 0.7, "top": 0.7, "gq": 0.8, "cf": 0.8,
    "tk": 0.8, "ml": 0.75, "ga": 0.75, "click": 0.7,
    "link": 0.6, "live": 0.5, "space": 0.65,
    "fun": 0.6, "win": 0.7, "vip": 0.65,
    "pw": 0.7, "cc": 0.6,
}
_TLD_RISK_DEFAULT = 0.35  # Unknown TLD

# URL shortener domains (always check the resolved destination)
_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "dlvr.it", "ift.tt", "is.gd", "v.gd",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
    "t.ly", "clck.ru", "qr.ae", "bc.vc",
    # Indian shorteners
    "in.d", "link.in",
})

# Punycode / IDNA detection
_PUNYCODE_RE = re.compile(r"xn--[a-z0-9-]+", re.IGNORECASE)

# IP address forms in hostnames
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
    r"|^\d{1,10}$"                 # Decimal form
    r"|^0x[0-9a-fA-F]{1,8}$"      # Hex form
)


# ── Feature dataclass ─────────────────────────────────────────────────────────


@dataclass
class URLFeatures:
    """Full feature vector for one URL.  All numeric, stable index order."""

    # ── Structural (always available)
    url_length: int = 0
    domain_length: int = 0
    subdomain_count: int = 0        # Number of subdomain labels
    digit_count: int = 0            # Digits in full URL
    special_char_count: int = 0     # @, -, _, !, ?, = etc. in URL
    entropy: float = 0.0            # Shannon entropy of URL string
    param_count: int = 0            # Query-string parameter count
    path_depth: int = 0             # Number of path segments
    is_https: float = 0.0           # 1.0 = https
    is_ip_host: float = 0.0         # 1.0 = IP address as host
    has_punycode: float = 0.0       # 1.0 = xn-- label present
    suspicious_token_count: int = 0 # Count of suspicious tokens
    tld_risk: float = 0.0           # TLD risk score [0, 1]
    has_at_sign: float = 0.0        # @ in URL (userinfo trick)
    double_slash_in_path: float = 0.0
    has_hex_encoding: float = 0.0   # %xx in URL path/query
    is_shortener: float = 0.0       # Known URL shortener
    path_has_exe: float = 0.0       # .exe/.php/.js/.zip etc. in path
    fragment_present: float = 0.0   # # fragment (often used to confuse parsers)
    dash_count: int = 0             # Hyphens in domain (e.g. paypa1-secure-login.com)
    token_length_max: int = 0       # Longest token in URL (long random strings)
    dot_count: int = 0              # Total dots in URL
    has_redirect_param: float = 0.0 # "url=", "redirect=", "next=" in query

    # ── Network features (optional, filled with -1.0 when offline)
    domain_age_days: float = -1.0   # Days since domain registration (RDAP)
    dns_a_count: float = -1.0       # Count of A records
    dns_mx_present: float = -1.0    # 1.0 if MX record exists
    dns_ns_count: float = -1.0      # Count of NS records
    dns_ttl: float = -1.0           # TTL of A record

    # ── Derived / metadata (not used as features)
    url: str = ""
    domain: str = ""
    subdomain: str = ""
    tld: str = ""
    registered_domain: str = ""
    scheme: str = ""
    path: str = ""

    def to_vector(self) -> list[float]:
        """Return the STABLE feature vector (structural features only)."""
        return [
            float(self.url_length),
            float(self.domain_length),
            float(self.subdomain_count),
            float(self.digit_count),
            float(self.special_char_count),
            self.entropy,
            float(self.param_count),
            float(self.path_depth),
            self.is_https,
            self.is_ip_host,
            self.has_punycode,
            float(self.suspicious_token_count),
            self.tld_risk,
            self.has_at_sign,
            self.double_slash_in_path,
            self.has_hex_encoding,
            self.is_shortener,
            self.path_has_exe,
            self.fragment_present,
            float(self.dash_count),
            float(self.token_length_max),
            float(self.dot_count),
            self.has_redirect_param,
            # Network features (will be -1 when offline)
            self.domain_age_days,
            self.dns_a_count,
            self.dns_mx_present,
            self.dns_ns_count,
            self.dns_ttl,
        ]

    @classmethod
    def feature_names(cls) -> list[str]:
        """STABLE list of feature names matching to_vector() order."""
        return [
            "url_length", "domain_length", "subdomain_count",
            "digit_count", "special_char_count", "entropy",
            "param_count", "path_depth", "is_https", "is_ip_host",
            "has_punycode", "suspicious_token_count", "tld_risk",
            "has_at_sign", "double_slash_in_path", "has_hex_encoding",
            "is_shortener", "path_has_exe", "fragment_present",
            "dash_count", "token_length_max", "dot_count",
            "has_redirect_param",
            "domain_age_days", "dns_a_count", "dns_mx_present",
            "dns_ns_count", "dns_ttl",
        ]


# ── Extractor ─────────────────────────────────────────────────────────────────


def extract_features(url: str) -> URLFeatures:
    """Extract the full feature vector from *url* (no network calls).

    Network features remain at sentinel -1.0.  Call ``enrich_network_features``
    separately to populate them when ENABLE_NETWORK_FEATURES=true.

    Args:
        url: Raw URL string.

    Returns:
        URLFeatures dataclass.
    """
    url = url.strip()

    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        # Strip port from netloc for domain analysis
        host = netloc.split(":")[0].strip("[]")

        ext = _TLD(host)
        domain = ext.domain or ""
        subdomain = ext.subdomain or ""
        tld = ext.suffix or ""
        registered_domain = ext.registered_domain or ""

        # Subdomain count (non-empty labels only)
        subdomain_count = len([p for p in subdomain.split(".") if p]) if subdomain else 0

        # Token extraction for suspicious token check
        full_text = url.lower()
        token_hits = sum(1 for t in _SUSPICIOUS_TOKENS if t in full_text)

        # Digit count in full URL
        digit_count = sum(1 for c in url if c.isdigit())

        # Special char count (characters that inflate URL suspicion)
        special_chars = set("@-_!?=&#+%~^")
        special_char_count = sum(1 for c in url if c in special_chars)

        # Shannon entropy
        entropy = _shannon_entropy(url)

        # Query parameters
        qs = parse_qs(query, keep_blank_values=True)
        param_count = len(qs)

        # Path depth
        path_segments = [p for p in path.split("/") if p]
        path_depth = len(path_segments)

        # Is IP host?
        is_ip = _is_ip_address(host)

        # Punycode
        has_punycode = 1.0 if _PUNYCODE_RE.search(netloc) else 0.0

        # TLD risk
        tld_risk = _TLD_RISK.get(tld.lower(), _TLD_RISK_DEFAULT)

        # @ sign trick
        has_at = 1.0 if "@" in netloc else 0.0

        # Double slash in path
        double_slash = 1.0 if "//" in path else 0.0

        # Hex encoding in path/query
        has_hex = 1.0 if re.search(r"%[0-9a-fA-F]{2}", path + query) else 0.0

        # URL shortener
        is_short = 1.0 if registered_domain in _SHORTENERS or netloc in _SHORTENERS else 0.0

        # Executable/script extensions in path
        path_lower = path.lower()
        exe_exts = {".exe", ".scr", ".bat", ".vbs", ".ps1", ".php", ".asp",
                    ".aspx", ".jsp", ".zip", ".jar", ".dll", ".hta"}
        path_has_exe = 1.0 if any(path_lower.endswith(e) for e in exe_exts) else 0.0

        # Fragment
        fragment_present = 1.0 if fragment else 0.0

        # Dash count in domain + subdomain
        dash_count = (domain + subdomain).count("-")

        # Longest token (split on non-alphanumeric)
        all_tokens = re.split(r"[^a-zA-Z0-9]", url)
        token_length_max = max((len(t) for t in all_tokens if t), default=0)

        # Total dots
        dot_count = url.count(".")

        # Redirect param names in query
        redirect_params = {"url", "redirect", "next", "goto", "dest",
                           "destination", "return", "returnurl", "rurl",
                           "forward", "link", "target", "out", "go"}
        has_redirect_param = 1.0 if any(k in redirect_params for k in qs) else 0.0

        return URLFeatures(
            url=url,
            url_length=len(url),
            domain_length=len(domain),
            subdomain_count=subdomain_count,
            digit_count=digit_count,
            special_char_count=special_char_count,
            entropy=round(entropy, 4),
            param_count=param_count,
            path_depth=path_depth,
            is_https=1.0 if scheme == "https" else 0.0,
            is_ip_host=1.0 if is_ip else 0.0,
            has_punycode=has_punycode,
            suspicious_token_count=token_hits,
            tld_risk=tld_risk,
            has_at_sign=has_at,
            double_slash_in_path=double_slash,
            has_hex_encoding=has_hex,
            is_shortener=is_short,
            path_has_exe=path_has_exe,
            fragment_present=fragment_present,
            dash_count=dash_count,
            token_length_max=token_length_max,
            dot_count=dot_count,
            has_redirect_param=has_redirect_param,
            domain=domain,
            subdomain=subdomain,
            tld=tld,
            registered_domain=registered_domain,
            scheme=scheme,
            path=path,
        )
    except Exception:
        # Return sentinel features for completely malformed URLs
        return URLFeatures(url=url, url_length=len(url))


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of string *s* in bits."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count
    )


def _is_ip_address(host: str) -> bool:
    """Return True if *host* is an IP address (any encoding)."""
    # Standard dotted notation
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Decimal integer
    try:
        val = int(host)
        if 0 <= val <= 0xFFFF_FFFF:
            return True
    except ValueError:
        pass

    # Hex
    if host.lower().startswith("0x"):
        try:
            int(host, 16)
            return True
        except ValueError:
            pass

    return False


# ── Optional network feature enrichment ──────────────────────────────────────


def enrich_network_features(feats: URLFeatures) -> URLFeatures:
    """Populate network features via RDAP and DNS lookups (sync, blocking).

    Only called when ENABLE_NETWORK_FEATURES=true.  Never called in tests.

    Args:
        feats: URLFeatures with network fields at -1.0.

    Returns:
        The same object with network fields updated in-place.
    """
    if not os.getenv("ENABLE_NETWORK_FEATURES", "false").lower() == "true":
        return feats

    host = feats.registered_domain or feats.domain
    if not host:
        return feats

    # DNS A records
    try:
        import socket
        addrs = socket.getaddrinfo(host, None, socket.AF_INET)
        feats.dns_a_count = float(len({a[4][0] for a in addrs}))
    except Exception:
        pass

    # DNS MX records (requires dnspython if installed)
    try:
        import dns.resolver  # type: ignore[import]
        answers = dns.resolver.resolve(host, "MX", lifetime=3.0)
        feats.dns_mx_present = 1.0 if answers else 0.0
    except Exception:
        feats.dns_mx_present = 0.0

    # Domain age via RDAP (httpx sync)
    try:
        from datetime import UTC, datetime

        import httpx

        resp = httpx.get(
            f"https://rdap.org/domain/{host}",
            timeout=5.0,
            follow_redirects=True,
            headers={"User-Agent": "ThreatSenseAI/0.1 (security-research)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    reg = datetime.fromisoformat(
                        event["eventDate"].replace("Z", "+00:00")
                    )
                    feats.domain_age_days = float(
                        (datetime.now(tz=UTC) - reg).days
                    )
                    break
    except Exception:
        pass

    return feats
