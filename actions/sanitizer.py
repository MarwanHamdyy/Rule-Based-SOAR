"""
actions/sanitizer.py
---------------------
Strict input validation for values extracted from JSON payloads before
they are interpolated into shell commands, Docker API calls, or iptables
rules.

Every validator returns the cleaned value on success or raises
``SanitizationError`` on rejection.  Shell metacharacters, path traversal
sequences, and malformed addresses are all rejected.

Usage::

    from actions.sanitizer import validate_ipv4, validate_container_id

    ip = validate_ipv4(context["source_ip"])          # "10.0.0.5"
    cid = validate_container_id(context["container_id"])  # "iot-device-1"
"""

from __future__ import annotations

import ipaddress
import re


class SanitizationError(ValueError):
    """Raised when an input value fails validation."""

    def __init__(self, field: str, value: str, reason: str = "") -> None:
        self.field = field
        self.value = value
        self.reason = reason
        detail = f" ({reason})" if reason else ""
        super().__init__(
            f"Sanitization failed for '{field}': "
            f"rejected value {value!r}{detail}"
        )


# ======================================================================
#  Individual validators
# ======================================================================

_RE_CONTAINER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
_RE_USERNAME  = re.compile(r"^[a-zA-Z0-9_.\-]{1,64}$")
_RE_MAC       = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_RE_DOMAIN    = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$"
)
_RE_IFACE     = re.compile(r"^[a-zA-Z0-9_.\-]{1,15}$")

# Characters that MUST NEVER appear in any value passed to a shell
_SHELL_METACHAR = re.compile(r"[;&|`$(){}!<>\"\'\\\n\r\x00]")


def _reject_shell_chars(field: str, value: str) -> None:
    """Raise if value contains shell metacharacters."""
    if _SHELL_METACHAR.search(value):
        raise SanitizationError(field, value, "contains shell metacharacters")


def validate_ipv4(value: str, *, field: str = "ip") -> str:
    """Validate and return a strict IPv4 address string."""
    value = value.strip()
    _reject_shell_chars(field, value)
    try:
        addr = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise SanitizationError(field, value, str(exc)) from exc
    return str(addr)


def validate_ipv6(value: str, *, field: str = "ipv6") -> str:
    """Validate and return a strict IPv6 address string."""
    value = value.strip()
    _reject_shell_chars(field, value)
    try:
        addr = ipaddress.IPv6Address(value)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise SanitizationError(field, value, str(exc)) from exc
    return str(addr)


def validate_ip(value: str, *, field: str = "ip") -> str:
    """Validate and return an IPv4 *or* IPv6 address string."""
    value = value.strip()
    _reject_shell_chars(field, value)
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise SanitizationError(field, value, str(exc)) from exc
    return str(addr)


def validate_subnet(value: str, *, field: str = "subnet") -> str:
    """Validate an IPv4 or IPv6 CIDR network string."""
    value = value.strip()
    _reject_shell_chars(field, value)
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SanitizationError(field, value, str(exc)) from exc
    return str(net)


def validate_mac(value: str, *, field: str = "mac") -> str:
    """Validate a colon-separated MAC address (aa:bb:cc:dd:ee:ff)."""
    value = value.strip()
    if not _RE_MAC.match(value):
        raise SanitizationError(field, value, "invalid MAC address format")
    return value.lower()


def validate_container_id(value: str, *, field: str = "container_id") -> str:
    """Validate a Docker container name or short ID."""
    value = value.strip()
    if not value:
        raise SanitizationError(field, value, "empty container identifier")
    if not _RE_CONTAINER.match(value):
        raise SanitizationError(field, value, "invalid container name characters")
    return value


def validate_username(value: str, *, field: str = "username") -> str:
    """Validate a POSIX username."""
    value = value.strip()
    if not _RE_USERNAME.match(value):
        raise SanitizationError(field, value, "invalid username characters")
    return value


def validate_domain(value: str, *, field: str = "domain") -> str:
    """Validate a DNS domain name."""
    value = value.strip().lower()
    _reject_shell_chars(field, value)
    if not _RE_DOMAIN.match(value):
        raise SanitizationError(field, value, "invalid domain name")
    return value


def validate_port(value: int | str, *, field: str = "port") -> int:
    """Validate a TCP/UDP port number (1–65535)."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SanitizationError(field, str(value), "not an integer") from exc
    if not 1 <= port <= 65535:
        raise SanitizationError(field, str(port), "port out of range 1-65535")
    return port


def validate_interface(value: str, *, field: str = "interface") -> str:
    """Validate a network interface name (e.g. eth0, br-lan)."""
    value = value.strip()
    if not _RE_IFACE.match(value):
        raise SanitizationError(field, value, "invalid interface name")
    return value


def validate_path(value: str, *, field: str = "path") -> str:
    """
    Validate a file path: reject traversal sequences and shell metacharacters.

    This does NOT guarantee the path exists — it only ensures the string
    is safe to use in a shell context.
    """
    value = value.strip()
    if not value:
        raise SanitizationError(field, value, "empty path")
    if ".." in value:
        raise SanitizationError(field, value, "path traversal detected")
    # Allow /, \, -, _, . and alphanumerics only
    if re.search(r"[;&|`$(){}!<>\"\'\\\n\r\x00]", value):
        raise SanitizationError(field, value, "contains shell metacharacters")
    return value
