"""
SSRF Guard — IP-range blocking for outbound requests.

This module is the security core of SafeFetcher.  Every outbound host is
resolved to IPs and each IP is checked against a hardened blocklist before
any connection is made.

Blocked ranges (RFC-based):
  127.0.0.0/8    Loopback
  10.0.0.0/8     RFC-1918 private
  172.16.0.0/12  RFC-1918 private
  192.168.0.0/16 RFC-1918 private
  169.254.0.0/16 Link-local (AWS/GCP/Azure metadata endpoint!)
  100.64.0.0/10  Shared address space (RFC-6598)
  0.0.0.0/8      This network
  192.0.0.0/24   IETF protocol assignments
  198.18.0.0/15  Benchmarking
  224.0.0.0/4    Multicast
  240.0.0.0/4    Reserved
  ::1/128        IPv6 loopback
  fc00::/7       IPv6 unique-local (ULA)
  fe80::/10      IPv6 link-local
  ::/128         IPv6 unspecified

Encoding attacks handled:
  - Decimal IP   (2130706433  → 127.0.0.1)
  - Hex IP       (0x7f000001  → 127.0.0.1)
  - Octal dotted (0177.0.0.1  → 127.0.0.1)
  - Standard dotted notation
  - IPv6 forms
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable

# ── Blocked networks ──────────────────────────────────────────────────────────

_BLOCKED_V4: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("0.0.0.0/8"),       # This network
    ipaddress.IPv4Network("10.0.0.0/8"),       # RFC-1918 private A
    ipaddress.IPv4Network("100.64.0.0/10"),    # Shared address space (RFC-6598)
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local / cloud metadata
    ipaddress.IPv4Network("172.16.0.0/12"),    # RFC-1918 private B
    ipaddress.IPv4Network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.IPv4Network("192.0.2.0/24"),     # Documentation TEST-NET-1
    ipaddress.IPv4Network("192.168.0.0/16"),   # RFC-1918 private C
    ipaddress.IPv4Network("198.18.0.0/15"),    # Benchmarking (RFC-2544)
    ipaddress.IPv4Network("198.51.100.0/24"),  # Documentation TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # Documentation TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved
    ipaddress.IPv4Network("255.255.255.255/32"), # Broadcast
]

_BLOCKED_V6: list[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::/128"),           # Unspecified
    ipaddress.IPv6Network("::1/128"),          # Loopback
    ipaddress.IPv6Network("::ffff:0:0/96"),    # IPv4-mapped
    ipaddress.IPv6Network("64:ff9b::/96"),     # NAT64 (may map to private)
    ipaddress.IPv6Network("fc00::/7"),         # Unique local address (ULA)
    ipaddress.IPv6Network("fe80::/10"),        # Link-local
    ipaddress.IPv6Network("ff00::/8"),         # Multicast
]

# ── Custom exception ──────────────────────────────────────────────────────────


class SSRFError(ValueError):
    """Raised when a URL or resolved IP is in a blocked range."""


# ── Encoding-attack normalizer ────────────────────────────────────────────────

_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
_OCTET_RE = re.compile(r"^0[0-7]+$")  # Leading zero → octet notation


def _try_parse_encoded_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Attempt to parse non-standard IPv4 encodings (decimal, hex, octal dotted).

    Returns None if the host is not a recognisable encoded IPv4 literal.
    """
    # ── Decimal integer (e.g. 2130706433 → 127.0.0.1) ──
    try:
        val = int(host)
        if 0 <= val <= 0xFFFF_FFFF:
            return ipaddress.IPv4Address(val)
    except ValueError:
        pass

    # ── Hex integer (e.g. 0x7f000001 → 127.0.0.1) ──
    if _HEX_RE.match(host):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFF_FFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # ── Octal dotted-quad (e.g. 0177.0.0.1 → 127.0.0.1) ──
    parts = host.split(".")
    if len(parts) == 4:
        try:
            int_parts = []
            has_octal = False
            for p in parts:
                if _OCTET_RE.match(p):
                    has_octal = True
                    int_parts.append(int(p, 8))
                else:
                    int_parts.append(int(p))
            if has_octal and all(0 <= v <= 255 for v in int_parts):
                return ipaddress.IPv4Address(".".join(str(v) for v in int_parts))
        except ValueError:
            pass

    return None


# ── Core functions ────────────────────────────────────────────────────────────


def resolve_host_to_ips(
    host: str,
    resolver: Callable[[str], list[str]] | None = None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve *host* to a list of IP addresses, handling encoded forms.

    Args:
        host:     Hostname or IP literal (any encoding).
        resolver: Optional DNS resolver callable ``host -> [ip_str, ...]``.
                  Defaults to ``socket.getaddrinfo``.  Injectable for tests.

    Returns:
        Non-empty list of IP address objects.

    Raises:
        SSRFError: If the host cannot be resolved.
    """
    stripped = host.strip("[]")  # Handle IPv6 bracket notation

    # ── Try direct IPv4/IPv6 parse ──
    for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        try:
            return [cls(stripped)]  # type: ignore[list-item]
        except ValueError:
            pass

    # ── Try encoded IPv4 forms ──
    encoded = _try_parse_encoded_ipv4(stripped)
    if encoded is not None:
        return [encoded]

    # ── DNS resolution ──
    if resolver is not None:
        ip_strings = resolver(host)
    else:
        try:
            results = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
        except socket.gaierror as exc:
            raise SSRFError(f"Cannot resolve host {host!r}: {exc}") from exc
        ip_strings = [r[4][0] for r in results]

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for ip_str in ip_strings:
        try:
            ips.append(ipaddress.ip_address(ip_str))
        except ValueError:
            pass

    if not ips:
        raise SSRFError(f"No IP addresses resolved for host {host!r}")

    return ips


def check_ip_is_safe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Assert that *ip* is not in any blocked range.

    Raises:
        SSRFError: If the IP belongs to a blocked range.
    """
    if isinstance(ip, ipaddress.IPv4Address):
        for net in _BLOCKED_V4:
            if ip in net:
                raise SSRFError(
                    f"IP {ip} is in blocked range {net} (SSRF protection)"
                )
    else:
        for net in _BLOCKED_V6:
            if ip in net:
                raise SSRFError(
                    f"IP {ip} is in blocked range {net} (SSRF protection)"
                )


def assert_host_is_safe(
    host: str,
    resolver: Callable[[str], list[str]] | None = None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve *host* and assert every resolved IP is safe.

    Args:
        host:     Hostname or IP literal (any encoding).
        resolver: Optional injectable DNS resolver for tests.

    Returns:
        The resolved IP address list (useful for logging).

    Raises:
        SSRFError: If any resolved IP is in a blocked range.
    """
    ips = resolve_host_to_ips(host, resolver=resolver)
    for ip in ips:
        check_ip_is_safe(ip)
    return ips
