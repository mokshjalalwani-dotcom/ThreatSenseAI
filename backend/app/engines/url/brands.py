"""
Brand similarity checker for D11 (Brand Impersonation) and D14 (IDN/Homograph).

Loads brands.yaml once, then provides fast lookup via:
  - Exact label matching for subdomain/path checks
  - fuzz.ratio with leet-speak normalization for typosquatting
  - Known alias exact matching
  - Unicode skeleton comparison for confusable detection (D14)

Key design rules that prevent false positives:
  1. Brand roots are extracted with tldextract (not bd.split(".")[0]) so
     "www.paypal.com" yields root "paypal", not "www".
  2. Only fuzz.ratio is used (never partial_ratio) to prevent single-word
     substrings from triggering on unrelated strings.
  3. Subdomain and path checks use EXACT token matching (split by "." or "/").
  4. Aliases must match exactly as a complete domain token (not substring).
  5. Fuzzy matching requires minimum 4 chars for both target and brand root.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml
from rapidfuzz import distance, fuzz

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent / "config" / "brands.yaml"
_brands_loaded: list[BrandEntry] | None = None

# Leet-speak normalization table: digit → look-alike letter
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})

# tldextract instance (shared, cached)
try:
    import tldextract as _tldextract
    _TLD = _tldextract.TLDExtract(cache_dir=None)
except ImportError:
    _TLD = None  # type: ignore[assignment]

# Minimum chars for fuzzy matching (prevents "m", "x", "fb" from matching)
_MIN_FUZZY_LEN = 4


@dataclass
class BrandEntry:
    brand_key: str
    display_name: str
    domains: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    india_priority: bool = False


@dataclass
class BrandHit:
    brand_key: str
    display_name: str
    matched_term: str          # What was found in the URL
    matched_against: str       # Which legitimate domain/alias was matched
    match_type: str            # "subdomain", "path", "fuzzy", "alias", "skeleton"
    similarity: float          # 0-1
    edit_distance: int = 0
    evidence_text: str = ""


def load_brands() -> list[BrandEntry]:
    """Load brand definitions from brands.yaml (cached after first load)."""
    global _brands_loaded

    if _brands_loaded is not None:
        return _brands_loaded

    try:
        raw = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8"))
        entries = []
        for b in raw.get("brands", []):
            entries.append(BrandEntry(
                brand_key=b["brand_key"],
                display_name=b["display_name"],
                domains=[d.lower() for d in b.get("domains", [])],
                aliases=[a.lower() for a in b.get("aliases", [])],
                india_priority=bool(b.get("india_priority", False)),
            ))
        _brands_loaded = entries
        logger.debug("Loaded %d brand entries from brands.yaml", len(entries))
    except Exception as exc:
        logger.error("Failed to load brands.yaml: %s", exc)
        _brands_loaded = []

    return _brands_loaded


def _brand_domain_label(bd: str) -> str:
    """Extract the core domain label from a brand domain string.

    Uses tldextract so that 'www.paypal.com' → 'paypal', not 'www'.
    Falls back to splitting on '.' if tldextract unavailable.
    """
    if _TLD is not None:
        ext = _TLD(bd)
        return (ext.domain or "").lower()
    # Fallback: take second-to-last token if > 2 parts
    parts = bd.split(".")
    if len(parts) >= 2:
        return parts[-2].lower()
    return bd.lower()


def _brand_labels(brand: BrandEntry) -> set[str]:
    """Return deduplicated set of primary domain labels for a brand."""
    labels: set[str] = set()
    for bd in brand.domains:
        label = _brand_domain_label(bd)
        if label:
            labels.add(label)
    return labels


def _normalize_leet(s: str) -> str:
    """Apply leet-speak normalization: 0→o, 1→l, 3→e, 4→a, 5→s."""
    return s.translate(_LEET)


def _domain_from_url(url: str) -> str:
    """Extract the primary domain label from a URL using tldextract."""
    try:
        netloc = urlparse(url).netloc.split(":")[0].strip("[]")
        if _TLD is not None:
            return (_TLD(netloc).domain or "").lower()
        parts = netloc.split(".")
        return parts[-2].lower() if len(parts) >= 2 else netloc.lower()
    except Exception:
        return ""


def check_brand_impersonation(
    registered_domain: str,
    subdomain: str,
    path: str,
    url: str,
    domain: str = "",          # tldextract .domain (label only); derived if empty
    fuzzy_threshold: float = 0.85,
) -> list[BrandHit]:
    """Check URL components against the brand list for impersonation.

    Args:
        registered_domain: Full registered domain e.g. "paypal.com" or "paypa1.xyz"
        subdomain:          Subdomain labels e.g. "www" or "login.paypal"
        path:               URL path
        url:                Full URL (used for legitimacy cross-check)
        domain:             Domain label only (e.g. "paypa1") -- derived from URL if empty
        fuzzy_threshold:    Minimum fuzz.ratio [0-1] for fuzzy hits

    Returns:
        List of BrandHits sorted by similarity descending.
    """
    brands = load_brands()
    hits: list[BrandHit] = []

    # Derive target domain label if not supplied
    if not domain:
        domain = _domain_from_url(url)

    reg_lower = registered_domain.lower()
    sub_lower = subdomain.lower()
    path_lower = path.lower()
    domain_lower = domain.lower()

    # Split subdomain into individual labels (e.g. "login.paypal" → {"login","paypal"})
    sub_label_set: set[str] = {p for p in sub_lower.split(".") if p}

    # Split domain label by hyphens for token-based fuzzy matching
    # e.g. "amaz0n-winner" → ["amaz0n", "winner"]
    domain_tokens: set[str] = {
        t for t in re.split(r"[^a-z0-9]", domain_lower) if t
    }
    domain_tokens.add(domain_lower)  # also check the full label

    # Path tokens (split by non-alphanumeric, min 3 chars)
    path_token_set: set[str] = {
        t for t in re.split(r"[^a-z0-9]", path_lower) if len(t) >= 3
    }

    for brand in brands:
        # ── 1. Legitimacy pre-check ───────────────────────────────────────────
        # If the full host (subdomain + registered_domain) is in the brand's
        # own domain list, it's a legitimate URL → skip this brand.
        full_host = f"{sub_lower}.{reg_lower}" if sub_lower else reg_lower
        is_legit = any(
            full_host == d or full_host.endswith(f".{d}")
            for d in brand.domains
        )
        if is_legit:
            continue

        # Also skip if the registered_domain itself is a listed brand domain
        # (handles cases where subdomain is "www" but reg_domain is the brand)
        if reg_lower in brand.domains:
            continue

        # Brand's primary domain labels (via tldextract, deduplicated)
        brand_domain_labels = _brand_labels(brand)
        if not brand_domain_labels:
            continue

        found_hit = False

        # ── 2. Brand label in subdomain (exact label match) ──────────────────
        for bl in brand_domain_labels:
            if bl in sub_label_set:
                hits.append(BrandHit(
                    brand_key=brand.brand_key,
                    display_name=brand.display_name,
                    matched_term=sub_lower,
                    matched_against=bl,
                    match_type="subdomain",
                    similarity=1.0,
                    evidence_text=(
                        f"'{brand.display_name}' brand name '{bl}' found as "
                        f"subdomain label but registered domain is '{reg_lower}'"
                    ),
                ))
                found_hit = True
                break

        if found_hit:
            continue

        # ── 3. Brand label in path tokens (exact token match) ────────────────
        for bl in brand_domain_labels:
            if bl in path_token_set:
                hits.append(BrandHit(
                    brand_key=brand.brand_key,
                    display_name=brand.display_name,
                    matched_term=path_lower[:60],
                    matched_against=bl,
                    match_type="path",
                    similarity=0.9,
                    evidence_text=(
                        f"'{brand.display_name}' brand name '{bl}' found in URL "
                        f"path but registered domain is '{reg_lower}'"
                    ),
                ))
                found_hit = True
                break

        if found_hit:
            continue

        # ── 4. Fuzzy typosquat detection (fuzz.ratio + leet normalization) ───
        # Compares each target domain token (split by hyphen) against each
        # brand label. Only compares strings >= 4 chars to prevent short-token
        # false positives (e.g. "m", "x", "pay", "www").
        for dt in domain_tokens:
            if len(dt) < _MIN_FUZZY_LEN:
                continue
            norm_dt = _normalize_leet(dt)

            for bl in brand_domain_labels:
                if len(bl) < _MIN_FUZZY_LEN:
                    continue

                # Compare both normalized and raw forms; take best ratio
                ratio_norm = fuzz.ratio(norm_dt, bl) / 100.0
                ratio_raw  = fuzz.ratio(dt, bl) / 100.0
                best_ratio = max(ratio_norm, ratio_raw)

                if best_ratio >= fuzzy_threshold and dt != bl:
                    ed = distance.Levenshtein.distance(dt, bl)
                    hits.append(BrandHit(
                        brand_key=brand.brand_key,
                        display_name=brand.display_name,
                        matched_term=dt,
                        matched_against=bl,
                        match_type="fuzzy",
                        similarity=best_ratio,
                        edit_distance=ed,
                        evidence_text=(
                            f"'{dt}' is similar to '{bl}' ({brand.display_name}) "
                            f"— fuzzy ratio {best_ratio:.0%}, edit distance {ed}"
                        ),
                    ))
                    found_hit = True
                    break
            if found_hit:
                break

        if found_hit:
            continue

        # ── 5. Alias exact-token match ────────────────────────────────────────
        # Aliases must match the target domain label exactly (no substring).
        # This catches known common typosquats like "paytmm" → paytm alias.
        for alias in brand.aliases:
            if not alias:
                continue
            # Check alias equals the full domain label OR equals one of
            # the hyphen-split tokens (e.g. alias "g00gle" in "g00gle-security")
            if domain_lower == alias or alias in domain_tokens or alias in sub_label_set:
                hits.append(BrandHit(
                    brand_key=brand.brand_key,
                    display_name=brand.display_name,
                    matched_term=domain_lower,
                    matched_against=alias,
                    match_type="alias",
                    similarity=0.95,
                    evidence_text=(
                        f"Known typosquat alias '{alias}' for {brand.display_name} "
                        f"found in domain '{domain_lower}'"
                    ),
                ))
                found_hit = True
                break

    # Deduplicate by brand_key (keep highest similarity per brand)
    best: dict[str, BrandHit] = {}
    for h in hits:
        if h.brand_key not in best or h.similarity > best[h.brand_key].similarity:
            best[h.brand_key] = h

    return sorted(best.values(), key=lambda h: h.similarity, reverse=True)


def build_unicode_skeleton(text: str) -> str:
    """Compute the Unicode confusable skeleton of *text*.

    NFKD decomposition + ASCII approximation (reasonable for most homographs).
    """
    normalized = unicodedata.normalize("NFKD", text)
    return normalized.encode("ascii", "ignore").decode("ascii").lower()


def check_idn_homograph(
    netloc: str,
    registered_domain: str,
) -> list[BrandHit]:
    """Detect IDN homograph attacks against the brand list.

    Steps:
      1. Detect xn-- Punycode labels.
      2. Decode with idna.
      3. Build Unicode skeleton.
      4. Compare skeleton against brand domain skeletons.

    Args:
        netloc:            Full network location (host:port).
        registered_domain: Registered domain label only.

    Returns:
        List of BrandHits for skeleton confusables.
    """
    brands = load_brands()
    hits: list[BrandHit] = []

    labels = netloc.lower().split(".")
    decoded_parts: list[str] = []
    has_punycode = False

    for label in labels:
        if label.startswith("xn--"):
            has_punycode = True
            try:
                decoded = label.encode("ascii").decode("idna")
            except Exception:
                decoded = label
            decoded_parts.append(decoded)
        else:
            decoded_parts.append(label)

    if not has_punycode:
        return []

    decoded_netloc = ".".join(decoded_parts)
    decoded_skeleton = build_unicode_skeleton(decoded_netloc)

    for brand in brands:
        for bd in brand.domains:
            bd_skeleton = build_unicode_skeleton(bd)
            if decoded_skeleton == bd_skeleton and decoded_netloc != bd:
                hits.append(BrandHit(
                    brand_key=brand.brand_key,
                    display_name=brand.display_name,
                    matched_term=netloc,
                    matched_against=bd,
                    match_type="skeleton",
                    similarity=1.0,
                    evidence_text=(
                        f"IDN homograph: '{netloc}' decodes to '{decoded_netloc}' "
                        f"which is visually identical to '{bd}' ({brand.display_name})"
                    ),
                ))

    return hits
