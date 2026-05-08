"""
tests/test_sanitizer.py
------------------------
Unit tests for the input sanitization module.

Verifies that all validators accept valid input and reject command
injection payloads, malformed addresses, and boundary violations.
"""

import pytest

from actions.sanitizer import (
    SanitizationError,
    validate_container_id,
    validate_domain,
    validate_interface,
    validate_ip,
    validate_ipv4,
    validate_ipv6,
    validate_mac,
    validate_path,
    validate_port,
    validate_subnet,
    validate_username,
)


# =====================================================================
#  IPv4
# =====================================================================

class TestValidateIPv4:
    def test_valid_ip(self):
        assert validate_ipv4("192.168.1.1") == "192.168.1.1"

    def test_valid_ip_with_whitespace(self):
        assert validate_ipv4("  10.0.0.5  ") == "10.0.0.5"

    def test_loopback(self):
        assert validate_ipv4("127.0.0.1") == "127.0.0.1"

    def test_zero(self):
        assert validate_ipv4("0.0.0.0") == "0.0.0.0"

    def test_broadcast(self):
        assert validate_ipv4("255.255.255.255") == "255.255.255.255"

    def test_rejects_injection_semicolon(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("192.168.1.1; rm -rf /")

    def test_rejects_injection_pipe(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("10.0.0.1 | cat /etc/passwd")

    def test_rejects_injection_backtick(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("`whoami`")

    def test_rejects_injection_dollar(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("$(cat /etc/shadow)")

    def test_rejects_out_of_range(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("999.999.999.999")

    def test_rejects_ipv6(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("::1")

    def test_rejects_empty(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("")

    def test_rejects_text(self):
        with pytest.raises(SanitizationError):
            validate_ipv4("not-an-ip")


# =====================================================================
#  IPv6
# =====================================================================

class TestValidateIPv6:
    def test_valid_ipv6(self):
        assert validate_ipv6("::1") == "::1"

    def test_full_ipv6(self):
        result = validate_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result == "2001:db8:85a3::8a2e:370:7334"

    def test_rejects_ipv4(self):
        with pytest.raises(SanitizationError):
            validate_ipv6("192.168.1.1")


# =====================================================================
#  Generic IP (v4 or v6)
# =====================================================================

class TestValidateIP:
    def test_accepts_ipv4(self):
        assert validate_ip("10.0.0.1") == "10.0.0.1"

    def test_accepts_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_rejects_garbage(self):
        with pytest.raises(SanitizationError):
            validate_ip("not-valid")


# =====================================================================
#  MAC Address
# =====================================================================

class TestValidateMAC:
    def test_valid_mac(self):
        assert validate_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_uppercase_mac(self):
        assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_rejects_short_mac(self):
        with pytest.raises(SanitizationError):
            validate_mac("aa:bb:cc")

    def test_rejects_injection(self):
        with pytest.raises(SanitizationError):
            validate_mac("aa:bb:cc:dd:ee:ff; rm -rf /")


# =====================================================================
#  Container ID
# =====================================================================

class TestValidateContainerID:
    def test_valid_name(self):
        assert validate_container_id("iot-device-1") == "iot-device-1"

    def test_valid_with_dots(self):
        assert validate_container_id("container.name_v2") == "container.name_v2"

    def test_rejects_empty(self):
        with pytest.raises(SanitizationError):
            validate_container_id("")

    def test_rejects_injection(self):
        with pytest.raises(SanitizationError):
            validate_container_id("container; rm -rf /")

    def test_rejects_starting_hyphen(self):
        with pytest.raises(SanitizationError):
            validate_container_id("-bad-name")


# =====================================================================
#  Username
# =====================================================================

class TestValidateUsername:
    def test_valid_user(self):
        assert validate_username("admin") == "admin"

    def test_valid_with_dots(self):
        assert validate_username("user.name-01") == "user.name-01"

    def test_rejects_injection(self):
        with pytest.raises(SanitizationError):
            validate_username("root; cat /etc/shadow")

    def test_rejects_empty(self):
        with pytest.raises(SanitizationError):
            validate_username("")


# =====================================================================
#  Domain
# =====================================================================

class TestValidateDomain:
    def test_valid_domain(self):
        assert validate_domain("evil.example.com") == "evil.example.com"

    def test_subdomain(self):
        assert validate_domain("c2.malware.io") == "c2.malware.io"

    def test_rejects_injection(self):
        with pytest.raises(SanitizationError):
            validate_domain("evil.com; rm -rf /")

    def test_rejects_no_tld(self):
        with pytest.raises(SanitizationError):
            validate_domain("localhost")


# =====================================================================
#  Port
# =====================================================================

class TestValidatePort:
    def test_valid_port(self):
        assert validate_port(80) == 80

    def test_string_port(self):
        assert validate_port("443") == 443

    def test_boundary_low(self):
        assert validate_port(1) == 1

    def test_boundary_high(self):
        assert validate_port(65535) == 65535

    def test_rejects_zero(self):
        with pytest.raises(SanitizationError):
            validate_port(0)

    def test_rejects_too_high(self):
        with pytest.raises(SanitizationError):
            validate_port(99999)

    def test_rejects_text(self):
        with pytest.raises(SanitizationError):
            validate_port("not-a-port")


# =====================================================================
#  Interface
# =====================================================================

class TestValidateInterface:
    def test_valid_eth0(self):
        assert validate_interface("eth0") == "eth0"

    def test_valid_br_lan(self):
        assert validate_interface("br-lan") == "br-lan"

    def test_rejects_injection(self):
        with pytest.raises(SanitizationError):
            validate_interface("eth0; rm -rf /")


# =====================================================================
#  Subnet
# =====================================================================

class TestValidateSubnet:
    def test_valid_cidr(self):
        assert validate_subnet("192.168.1.0/24") == "192.168.1.0/24"

    def test_host_cidr(self):
        assert validate_subnet("10.0.0.1/32") == "10.0.0.1/32"

    def test_rejects_garbage(self):
        with pytest.raises(SanitizationError):
            validate_subnet("not/valid")


# =====================================================================
#  Path
# =====================================================================

class TestValidatePath:
    def test_valid_path(self):
        assert validate_path("/var/log/syslog") == "/var/log/syslog"

    def test_rejects_traversal(self):
        with pytest.raises(SanitizationError):
            validate_path("/etc/../../../etc/shadow")

    def test_rejects_injection(self):
        with pytest.raises(SanitizationError):
            validate_path("/tmp/file; rm -rf /")

    def test_rejects_empty(self):
        with pytest.raises(SanitizationError):
            validate_path("")
