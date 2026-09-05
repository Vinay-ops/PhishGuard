"""Helpers that prevent outbound analysis requests to private networks."""

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFViolation(ValueError):
    """Raised when a URL resolves to an address that must not be contacted."""


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
        ):
            raise SSRFViolation("Requests to private or local network addresses are blocked.")

    return hostname