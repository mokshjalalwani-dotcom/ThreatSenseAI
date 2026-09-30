"""Detector 13 — URL Obfuscation (Domain 2: URL & Domain Security).

Detects techniques used to hide the true destination of a URL:
  - Multi-layer percent-encoding (double/triple encoding)
  - @-userinfo tricks (https://evil.com@good.com)
  - IP address in decimal / hex / octal dotted form
  - Excessive subdomain nesting (> 4 labels)
  - data:/javascript: scheme in URL
  - Long random-looking strings (high entropy fragments)
  - Unicode confusable characters in domain
  - Tab/newline/space characters in URL (whitespace injection)
  - Authority confusion with //evil.com%2F@good.com
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.engines.url.features import _shannon_entropy
from app.schemas.schemas import (
    Artifact,
    ArtifactType,
    DetectionResult,
    Evidence,
    EvidenceSeverity,
    Verdict,
)

if TYPE_CHECKING:
    from app.core.context import AnalysisContext

# Patterns
_HEX_IP_RE = re.compile(r"^0[xX][0-9a-fA-F]{1,8}$")
# Octal octet: starts with 0 followed by 0-7 digits.  Bare "0" is also valid (= 0 decimal).
_OCTAL_OCTET_RE = re.compile(r"^0[0-7]*$")
_DECIMAL_IP_RE = re.compile(r"^\d{7,10}$")  # 7+ digits → possible 32-bit int
_DATA_JS_RE = re.compile(r"(?:data|javascript|vbscript)\s*:", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"[\t\r\n ]")


def _parse_octal_ip(octets: list[str]) -> tuple[bool, list[str]]:
    """Parse four dotted octets that may be octal-encoded.

    At least one octet must have a leading zero AND length > 1 to confirm
    octal intent (bare "0" can appear in normal IPs).
    Remaining octets can be plain decimal or octal.

    Returns (hit, decoded_octets).  hit=False if parsing fails or no octal
    octet found.
    """
    has_explicit_octal = False
    decoded: list[str] = []
    for o in octets:
        if _OCTAL_OCTET_RE.match(o):
            if len(o) > 1:          # e.g. "0177" — definitely octal intent
                has_explicit_octal = True
            try:
                val = int(o, 8)
            except ValueError:
                return False, []
            if not (0 <= val <= 255):
                return False, []
            decoded.append(str(val))
        elif o.isdigit() and 0 <= int(o) <= 255:
            decoded.append(o)       # plain decimal octet is fine
        else:
            return False, []        # not a parseable octet
    return has_explicit_octal, decoded


@register_detector
class URLObfuscationDetector(BaseDetector):
    """Detects URL obfuscation techniques and returns a decoded/normalised form
    as evidence so analysts can see what was hidden.
    """

    detector_id = "d13_url_obfuscation"
    name = "URL Obfuscation"
    domain = "URL & Domain Security"
    domain_id = "d2"
    accepted_artifact_types = [
        ArtifactType.URL,
        ArtifactType.EMAIL,
        ArtifactType.SMS,
        ArtifactType.WEBPAGE,
    ]
    required_engines = ["url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        url = _resolve_url(artifact).strip()
        if not url:
            return self._no_hit(artifact)

        findings: list[tuple[str, EvidenceSeverity, str, str]] = []
        # Each finding: (rule_id, severity, description, matched_text)

        # ── 1. Percent encoding ────────────────────────────────────────────────
        decoded1 = unquote(url)
        decoded2 = unquote(decoded1)

        if decoded2 != url:
            # Check if multiple rounds of decoding produce different results
            if decoded1 != url and decoded2 != decoded1:
                findings.append((
                    "double_encoding",
                    EvidenceSeverity.HIGH,
                    f"Double percent-encoding detected. Decoded form: '{decoded2[:100]}'",
                    url[:80],
                ))
            elif decoded1 != url:
                findings.append((
                    "percent_encoding",
                    EvidenceSeverity.LOW,
                    f"URL percent-encoding present. Decoded: '{decoded1[:100]}'",
                    url[:80],
                ))

        # ── 2. @-userinfo trick ────────────────────────────────────────────────
        parsed = urlparse(url)
        netloc = parsed.netloc or ""
        if "@" in netloc:
            userinfo, _, actual_host = netloc.rpartition("@")
            findings.append((
                "at_userinfo_trick",
                EvidenceSeverity.CRITICAL,
                (
                    f"@-trick detected: browser treats '{actual_host}' as the host "
                    f"but userinfo '{userinfo}' may look like a legitimate domain. "
                    f"Decoded form: {url[:80]}"
                ),
                netloc,
            ))

        # ── 3. IP address forms ────────────────────────────────────────────────
        host = netloc.split(":")[0].strip("[]")
        decoded_host = unquote(host)

        # Decimal integer IP
        if _DECIMAL_IP_RE.match(decoded_host):
            try:
                ip = ipaddress.IPv4Address(int(decoded_host))
                findings.append((
                    "decimal_ip",
                    EvidenceSeverity.HIGH,
                    f"Decimal IP address '{decoded_host}' decodes to '{ip}'",
                    decoded_host,
                ))
            except Exception:
                pass

        # Hex IP
        if _HEX_IP_RE.match(decoded_host):
            try:
                ip = ipaddress.IPv4Address(int(decoded_host, 16))
                findings.append((
                    "hex_ip",
                    EvidenceSeverity.HIGH,
                    f"Hex IP address '{decoded_host}' decodes to '{ip}'",
                    decoded_host,
                ))
            except Exception:
                pass

        # Octal dotted notation — at least one octet must have a leading zero
        # and length > 1 to confirm intent (e.g. 0177.0.0.1 → 127.0.0.1).
        octets = decoded_host.split(".")
        if len(octets) == 4:
            octal_hit, decoded_octets = _parse_octal_ip(octets)
            if octal_hit:
                findings.append((
                    "octal_ip",
                    EvidenceSeverity.HIGH,
                    f"Octal-encoded IP '{decoded_host}' decodes to '{'.'.join(decoded_octets)}'",
                    decoded_host,
                ))

        # ── 4. data: / javascript: schemes ────────────────────────────────────
        if _DATA_JS_RE.match(url):
            findings.append((
                "data_js_scheme",
                EvidenceSeverity.CRITICAL,
                f"Dangerous scheme detected: '{url[:40]}…' — data:/javascript:/vbscript: URLs can execute code",
                url[:40],
            ))

        # ── 5. Excessive subdomains ────────────────────────────────────────────
        # Count subdomain labels (excluding www)
        subdomain_labels = [
            p for p in (parsed.hostname or "").split(".") if p and p != "www"
        ]
        if len(subdomain_labels) > 5:
            findings.append((
                "excessive_subdomains",
                EvidenceSeverity.MEDIUM,
                f"Excessive subdomain nesting ({len(subdomain_labels)} labels) — may be used to obscure the real domain",
                parsed.hostname or "",
            ))

        # ── 6. Long random strings (high entropy path tokens) ─────────────────
        path = parsed.path or ""
        for segment in path.split("/"):
            if len(segment) >= 20:
                ent = _shannon_entropy(segment)
                if ent >= 4.2:
                    findings.append((
                        "high_entropy_path",
                        EvidenceSeverity.MEDIUM,   # was LOW; MEDIUM → SUSPICIOUS verdict
                        f"High-entropy path segment '{segment[:40]}' (entropy={ent:.2f}) may be obfuscated content",
                        segment[:40],
                    ))
                    break  # Only report first occurrence

        # ── 7. Whitespace injection ────────────────────────────────────────────
        if _WHITESPACE_RE.search(url):
            findings.append((
                "whitespace_injection",
                EvidenceSeverity.HIGH,
                "URL contains whitespace characters (tab/newline/space) — may bypass URL parsers",
                url[:80],
            ))

        # ── 8. Unicode non-ASCII in domain ────────────────────────────────────
        if parsed.hostname and any(ord(c) > 127 for c in (parsed.hostname or "")):
            findings.append((
                "unicode_in_domain",
                EvidenceSeverity.MEDIUM,
                f"Domain contains non-ASCII Unicode characters: '{parsed.hostname[:40]}'",
                parsed.hostname[:40],
            ))

        if not findings:
            return self._no_hit(artifact)

        # Compute score from highest-severity finding
        sev_scores = {
            EvidenceSeverity.CRITICAL: 0.85,
            EvidenceSeverity.HIGH: 0.65,
            EvidenceSeverity.MEDIUM: 0.45,
            EvidenceSeverity.LOW: 0.25,
            EvidenceSeverity.INFO: 0.1,
        }
        score = max(sev_scores.get(sev, 0.1) for _, sev, _, _ in findings)
        # Multiple findings compound
        if len(findings) >= 2:
            score = min(1.0, score + 0.1)

        verdict = (
            Verdict.MALICIOUS if score >= 0.75
            else Verdict.LIKELY_MALICIOUS if score >= 0.55
            else Verdict.SUSPICIOUS if score >= 0.35
            else Verdict.SAFE
        )

        evidence = [
            Evidence(
                source_engine="url",
                severity=sev,
                description=desc,
                matched_text=matched[:100] if matched else None,
                rule_id=rule_id,
            )
            for rule_id, sev, desc, matched in findings
        ]

        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=round(score, 4),
            verdict=verdict,
            confidence=round(min(0.9, score + 0.05), 3),
            evidence=evidence,
            signals_used=["url.has_hex_encoding", "url.has_at_sign", "url.entropy"],
        )

    def _no_hit(self, artifact: Artifact) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=0.0,
            verdict=Verdict.SAFE,
            confidence=0.75,
            evidence=[],
            signals_used=["url.has_hex_encoding"],
        )


def _resolve_url(artifact: Artifact) -> str:
    """Return a real URL from the artifact — never raw HTML or plain SMS/email body."""
    if artifact.type == ArtifactType.URL:
        return (artifact.normalized_url or artifact.raw_content or "").strip()
    if artifact.type in (ArtifactType.EMAIL, ArtifactType.SMS):
        urls = artifact.extracted_urls or []
        return urls[0].strip() if urls else ""
    if artifact.type == ArtifactType.WEBPAGE:
        return (artifact.normalized_url or "").strip()
    return ""
