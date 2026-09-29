"""
SafeFetcher + SSRF Guard unit tests.

Coverage:
  ✓ Allowed schemes (http, https)
  ✓ Blocked scheme (ftp, file, javascript, data)
  ✓ Loopback IPv4: 127.0.0.1, 127.x.x.x
  ✓ Private IPv4: 10.x, 172.16-31.x, 192.168.x
  ✓ Link-local / cloud metadata: 169.254.169.254
  ✓ IPv6 loopback: ::1
  ✓ IPv6 link-local: fe80::1
  ✓ Decimal IP encoding: 2130706433 → 127.0.0.1
  ✓ Hex IP encoding: 0x7f000001 → 127.0.0.1
  ✓ Octal dotted IP: 0177.0.0.1 → 127.0.0.1
  ✓ Redirect into private IP is blocked
  ✓ Multi-hop redirect chain is captured correctly
  ✓ Max-redirects exceeded raises TooManyRedirectsError
  ✓ Public IP is allowed
"""

from __future__ import annotations

import ipaddress

import httpx
import pytest
import respx

from app.fetcher.safe_fetcher import (
    DisallowedSchemeError,
    SafeFetcher,
    TooManyRedirectsError,
)
from app.fetcher.ssrf_guard import (
    SSRFError,
    assert_host_is_safe,
    check_ip_is_safe,
    resolve_host_to_ips,
)

# ── Helpers ────────────────────────────────────────────────────────────────────


def _resolver_for(ip: str):
    """Return an injectable resolver that always returns *ip*."""
    def _resolve(_host: str) -> list[str]:
        return [ip]
    return _resolve


def _public_resolver(_host: str) -> list[str]:
    """Simulates a safe public IP (1.1.1.1 — Cloudflare DNS)."""
    return ["1.1.1.1"]


# ── IP blocking — unit tests (no network) ─────────────────────────────────────


def test_loopback_127_is_blocked() -> None:
    with pytest.raises(SSRFError, match="blocked"):
        assert_host_is_safe("localhost", resolver=_resolver_for("127.0.0.1"))


def test_loopback_127_x_x_x_is_blocked() -> None:
    with pytest.raises(SSRFError):
        assert_host_is_safe("127.99.88.77", resolver=_resolver_for("127.99.88.77"))


def test_private_10_is_blocked() -> None:
    with pytest.raises(SSRFError):
        assert_host_is_safe("internal", resolver=_resolver_for("10.0.0.1"))


def test_private_172_16_is_blocked() -> None:
    with pytest.raises(SSRFError):
        assert_host_is_safe("internal", resolver=_resolver_for("172.16.0.1"))


def test_private_172_31_is_blocked() -> None:
    with pytest.raises(SSRFError):
        assert_host_is_safe("internal", resolver=_resolver_for("172.31.255.254"))


def test_private_192_168_is_blocked() -> None:
    with pytest.raises(SSRFError):
        assert_host_is_safe("router", resolver=_resolver_for("192.168.1.1"))


def test_link_local_metadata_169_254_is_blocked() -> None:
    """169.254.169.254 is the AWS/GCP/Azure IMDS endpoint — must be blocked."""
    with pytest.raises(SSRFError):
        assert_host_is_safe("169.254.169.254", resolver=_resolver_for("169.254.169.254"))


def test_link_local_any_169_254_is_blocked() -> None:
    with pytest.raises(SSRFError):
        assert_host_is_safe("169.254.1.1", resolver=_resolver_for("169.254.1.1"))


def test_ipv6_loopback_is_blocked() -> None:
    with pytest.raises(SSRFError):
        check_ip_is_safe(ipaddress.IPv6Address("::1"))


def test_ipv6_link_local_is_blocked() -> None:
    with pytest.raises(SSRFError):
        check_ip_is_safe(ipaddress.IPv6Address("fe80::1"))


def test_ipv6_unique_local_is_blocked() -> None:
    with pytest.raises(SSRFError):
        check_ip_is_safe(ipaddress.IPv6Address("fc00::1"))


def test_public_ip_is_allowed() -> None:
    """1.1.1.1 must pass the SSRF check."""
    ips = assert_host_is_safe("cloudflare", resolver=_public_resolver)
    assert len(ips) == 1
    assert str(ips[0]) == "1.1.1.1"


# ── Encoding attack tests (no DNS) ────────────────────────────────────────────


def test_decimal_ip_encoding_127_blocked() -> None:
    """2130706433 decimal == 127.0.0.1."""
    ips = resolve_host_to_ips("2130706433")
    assert str(ips[0]) == "127.0.0.1"
    with pytest.raises(SSRFError):
        check_ip_is_safe(ips[0])


def test_hex_ip_encoding_127_blocked() -> None:
    """0x7f000001 hex == 127.0.0.1."""
    ips = resolve_host_to_ips("0x7f000001")
    assert str(ips[0]) == "127.0.0.1"
    with pytest.raises(SSRFError):
        check_ip_is_safe(ips[0])


def test_octal_dotted_ip_127_blocked() -> None:
    """0177.0.0.1 octal dotted == 127.0.0.1."""
    ips = resolve_host_to_ips("0177.0.0.1")
    assert str(ips[0]) == "127.0.0.1"
    with pytest.raises(SSRFError):
        check_ip_is_safe(ips[0])


def test_decimal_ip_10_blocked() -> None:
    """167772161 decimal == 10.0.0.1."""
    ips = resolve_host_to_ips("167772161")
    assert str(ips[0]) == "10.0.0.1"
    with pytest.raises(SSRFError):
        check_ip_is_safe(ips[0])


def test_hex_ip_encoding_192_168_blocked() -> None:
    """0xc0a80001 hex == 192.168.0.1."""
    ips = resolve_host_to_ips("0xc0a80001")
    assert str(ips[0]) == "192.168.0.1"
    with pytest.raises(SSRFError):
        check_ip_is_safe(ips[0])


# ── Scheme checks ─────────────────────────────────────────────────────────────


async def test_ftp_scheme_blocked() -> None:
    fetcher = SafeFetcher(resolver=_public_resolver)
    with pytest.raises(DisallowedSchemeError):
        await fetcher.fetch("ftp://example.com/file.txt")


async def test_file_scheme_blocked() -> None:
    fetcher = SafeFetcher(resolver=_public_resolver)
    with pytest.raises(DisallowedSchemeError):
        await fetcher.fetch("file:///etc/passwd")


async def test_javascript_scheme_blocked() -> None:
    fetcher = SafeFetcher(resolver=_public_resolver)
    with pytest.raises(DisallowedSchemeError):
        await fetcher.fetch("javascript:alert(1)")


async def test_data_scheme_blocked() -> None:
    fetcher = SafeFetcher(resolver=_public_resolver)
    with pytest.raises(DisallowedSchemeError):
        await fetcher.fetch("data:text/html,<h1>hi</h1>")


# ── Redirect tests (respx mock) ───────────────────────────────────────────────


@respx.mock
async def test_redirect_into_private_ip_is_blocked() -> None:
    """A public URL that redirects to 10.x must be blocked after following the redirect."""
    # First hop: public URL (resolver returns public IP)
    # Second hop: private IP redirect (resolver returns 10.x)

    call_count = 0

    def _smart_resolver(host: str) -> list[str]:
        nonlocal call_count
        call_count += 1
        if host == "evil-redirect.example.com":
            return ["1.1.1.1"]  # First hop: public
        if host == "10.0.0.1":
            return ["10.0.0.1"]  # After redirect: private
        return ["1.1.1.1"]

    respx.get("http://evil-redirect.example.com/").mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "http://10.0.0.1/secret"},
        )
    )

    fetcher = SafeFetcher(resolver=_smart_resolver)
    with pytest.raises(SSRFError):
        await fetcher.fetch("http://evil-redirect.example.com/")


@respx.mock
async def test_multi_hop_redirect_chain_captured() -> None:
    """Full redirect chain must be recorded in FetchResult."""
    respx.get("http://hop1.example.com/").mock(
        return_value=httpx.Response(301, headers={"Location": "http://hop2.example.com/"})
    )
    respx.get("http://hop2.example.com/").mock(
        return_value=httpx.Response(302, headers={"Location": "http://hop3.example.com/"})
    )
    respx.get("http://hop3.example.com/").mock(
        return_value=httpx.Response(200, content=b"final content", headers={"content-type": "text/plain"})
    )

    fetcher = SafeFetcher(resolver=_public_resolver, max_redirects=5)
    result = await fetcher.fetch("http://hop1.example.com/")

    assert result.status_code == 200
    assert result.body == b"final content"
    assert result.redirect_chain == [
        "http://hop1.example.com/",
        "http://hop2.example.com/",
        "http://hop3.example.com/",
    ]
    assert result.final_url == "http://hop3.example.com/"


@respx.mock
async def test_too_many_redirects_raises() -> None:
    """Exceeding max_redirects must raise TooManyRedirectsError."""
    for i in range(1, 8):
        respx.get(f"http://loop{i}.example.com/").mock(
            return_value=httpx.Response(
                302, headers={"Location": f"http://loop{i+1}.example.com/"}
            )
        )

    fetcher = SafeFetcher(resolver=_public_resolver, max_redirects=3)
    with pytest.raises(TooManyRedirectsError):
        await fetcher.fetch("http://loop1.example.com/")


@respx.mock
async def test_successful_fetch_returns_body() -> None:
    """A simple successful fetch must return body and status code."""
    respx.get("http://example.com/").mock(
        return_value=httpx.Response(
            200,
            content=b"Hello, World!",
            headers={"content-type": "text/html"},
        )
    )

    fetcher = SafeFetcher(resolver=_public_resolver)
    result = await fetcher.fetch("http://example.com/")

    assert result.status_code == 200
    assert result.body == b"Hello, World!"
    assert result.content_type == "text/html"
    assert result.redirect_chain == ["http://example.com/"]
    assert result.final_url == "http://example.com/"
