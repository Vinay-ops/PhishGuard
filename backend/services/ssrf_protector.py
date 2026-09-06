"""Helpers that prevent outbound analysis requests to private networks."""

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFViolation(ValueError):
    """Raised when a URL resolves to an address that must not be contacted."""


# Special-purpose IPv4 ranges that Python's ipaddress does not mark private
# on every runtime (notably CGNAT/shared address space 100.64.0.0/10 before
# Python 3.13, and the benchmarking range 198.18.0.0/15 on some versions).
# Denied explicitly so blocking behavior is identical across runtimes.
_DENY_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),    # shared / CGNAT address space
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1 (documentation)
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (documentation)
)


# getaddrinfo can fail with several distinct exceptions depending on the
# runtime: gaierror (NXDOMAIN / no address), TimeoutError (slow/blocked DNS
# on serverless runtimes), and UnicodeError (non-ASCII / punycode hostnames).
# All are treated uniformly as "the hostname could not be resolved".
_UNRESOLVABLE_EXCEPTIONS = (socket.gaierror, TimeoutError, UnicodeError)


def _resolve_addresses(hostname: str):
    """Resolve a hostname to a set of IP strings.

    Returns None when the hostname cannot be resolved (NXDOMAIN, DNS
    timeout, or a non-ASCII hostname), so callers can decide whether that
    is a hard failure (network analyzer) or a soft one (string-only analysis).
    """
    try:
        return {
            result[4][0]
            for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except _UNRESOLVABLE_EXCEPTIONS:
        return None


def _assert_public(addresses) -> None:
    """Raise SSRFViolation if any resolved address is private/local/denied."""
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or any(ip in network for network in _DENY_NETWORKS)
        ):
            raise SSRFViolation("Requests to private or local network addresses are blocked.")


def validate_public_target(url: str, require_resolvable: bool = True) -> str:
    """Validate that a URL hostname may be contacted, returning the hostname.

    SSRF protection is never weakened: if the hostname resolves to a
    private/local/denied address, SSRFViolation is always raised.

    require_resolvable=True (default) is used by the network analyzers. It
    additionally rejects hostnames that cannot be resolved at all, so those
    checks report themselves unavailable.

    require_resolvable=False is used at the start of the analysis pipeline.
    It lets unresolvable hostnames (NXDOMAIN, DNS timeout) through so the
    URL-string analysis (ML, rules) can still run; the network analyzers then
    mark their checks unavailable instead of aborting the whole request. An
    unresolvable host cannot be contacted, so this creates no SSRF exposure.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFViolation("URL must contain a hostname.")

    addresses = _resolve_addresses(hostname)
    if addresses is None:
        if require_resolvable:
            raise SSRFViolation("The URL hostname could not be resolved.")
        return hostname

    _assert_public(addresses)
    return hostname