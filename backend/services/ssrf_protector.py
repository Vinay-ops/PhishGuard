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


def validate_public_target(url: str) -> str:
    """Resolve a URL hostname and reject private, local, or invalid targets."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFViolation("URL must contain a hostname.")

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise SSRFViolation("The URL hostname could not be resolved.") from exc

    if not addresses:
        raise SSRFViolation("The URL hostname has no usable address.")

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

    return hostname