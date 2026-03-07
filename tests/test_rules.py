"""
tests/test_rules.py
--------------------
Unit tests for all 8 SOAR detection rules.
Rules are tested in isolation using mock stats and normalised events,
so no Elasticsearch or network access is required.
"""

from __future__ import annotations

import pytest

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import EventNormalizer, NormalizedEvent
from rules.port_scan import PortScanRule
from rules.ssh_bruteforce import SSHBruteForceRule
from rules.web_attack import WebAttackRule
from rules.malware_c2 import MalwareC2Rule
from rules.dns_suspicious import DNSSuspiciousRule
from rules.dos_flood import DoSFloodRule
from rules.lateral_movement import LateralMovementRule
from rules.generic_high_risk import GenericHighRiskRule
from tests.sample_events import (
    PORT_SCAN_EVENT, SSH_BRUTE_EVENT, WEB_ATTACK_EVENT,
    MALWARE_C2_EVENT, DNS_EVENT, DOS_EVENT, LATERAL_EVENT, GENERIC_HIGH_EVENT,
)

normalizer = EventNormalizer()

# ---- Default threshold config (mirrors thresholds.yaml) ----
RULE_CONFIG = {
    "port_scan": {
        "unique_dst_ports_threshold": 15,
        "event_count_threshold": 20,
        "confidence": 0.85,
        "priority": "HIGH",
    },
    "ssh_bruteforce": {
        "event_count_threshold": 8,
        "signatures_keywords": ["ssh", "brute", "authentication"],
        "confidence": 0.90,
        "priority": "HIGH",
    },
    "web_attack": {
        "event_count_threshold": 5,
        "category_keywords": ["web", "http", "sql", "xss"],
        "confidence": 0.80,
        "priority": "MEDIUM",
    },
    "malware_or_c2": {
        "event_count_threshold": 2,
        "category_keywords": ["malware", "trojan", "c2", "command", "botnet", "beacon", "rat"],
        "confidence": 0.88,
        "priority": "CRITICAL",
    },
    "dns_suspicious": {
        "event_count_threshold": 3,
        "category_keywords": ["dns", "domain", "tunnel", "exfil"],
        "confidence": 0.75,
        "priority": "MEDIUM",
    },
    "dos_or_flood": {
        "event_count_threshold": 50,
        "category_keywords": ["dos", "flood", "ddos", "amplification", "syn"],
        "confidence": 0.85,
        "priority": "HIGH",
    },
    "lateral_movement_suspicion": {
        "unique_dst_hosts_threshold": 5,
        "category_keywords": ["lateral", "smb", "rdp", "pass-the", "mimikatz"],
        "confidence": 0.78,
        "priority": "HIGH",
    },
    "generic_high_risk_alert": {
        "min_risk_score": 70,
        "severity_threshold": 2,
        "confidence": 0.70,
        "priority": "MEDIUM",
    },
}


def _stats_with(
    event_count: int = 0,
    unique_dst_ports: int = 0,
    unique_dst_ips: int = 0,
) -> dict[str, WindowStats]:
    """Helper to construct mock window stats."""
    s = WindowStats(
        event_count=event_count,
        unique_dst_ports=unique_dst_ports,
        unique_dst_ips=unique_dst_ips,
    )
    return {"short": s, "medium": s, "long": s, "extended": s}


def _norm(raw: dict) -> NormalizedEvent:
    ev = normalizer.normalize(raw)
    assert ev is not None
    return ev


# ---- SOAR-001 Port Scan ----

class TestPortScanRule:
    rule = PortScanRule()

    def test_fires_on_high_port_count(self) -> None:
        event = _norm(PORT_SCAN_EVENT)
        stats = _stats_with(event_count=25, unique_dst_ports=20)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.rule_id == "SOAR-001"
        assert match.attack_type == "port_scan"

    def test_does_not_fire_below_threshold(self) -> None:
        event = _norm(PORT_SCAN_EVENT)
        stats = _stats_with(event_count=3, unique_dst_ports=5)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is None

    def test_confidence_boosted_with_both_thresholds(self) -> None:
        event = _norm(PORT_SCAN_EVENT)
        stats = _stats_with(event_count=30, unique_dst_ports=20)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.confidence >= 0.85


# ---- SOAR-002 SSH Brute Force ----

class TestSSHBruteForceRule:
    rule = SSHBruteForceRule()

    def test_fires_on_port_22(self) -> None:
        event = _norm(SSH_BRUTE_EVENT)
        stats = _stats_with(event_count=10)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.rule_id == "SOAR-002"

    def test_does_not_fire_on_non_ssh(self) -> None:
        event = _norm(WEB_ATTACK_EVENT)   # port 80, no SSH keywords
        stats = _stats_with(event_count=20)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is None

    def test_does_not_fire_below_threshold(self) -> None:
        event = _norm(SSH_BRUTE_EVENT)
        stats = _stats_with(event_count=3)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is None


# ---- SOAR-003 Web Attack ----

class TestWebAttackRule:
    rule = WebAttackRule()

    def test_fires_on_sql_injection(self) -> None:
        event = _norm(WEB_ATTACK_EVENT)
        stats = _stats_with(event_count=8)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert "SQL" in " ".join(match.reasons)

    def test_does_not_fire_on_non_web(self) -> None:
        event = _norm(DNS_EVENT)
        stats = _stats_with(event_count=10)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is None


# ---- SOAR-004 Malware / C2 ----

class TestMalwareC2Rule:
    rule = MalwareC2Rule()

    def test_fires_on_malware_signature(self) -> None:
        event = _norm(MALWARE_C2_EVENT)
        stats = _stats_with(event_count=3)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.priority == "CRITICAL"

    def test_fires_on_high_risk_score_alone(self) -> None:
        """A very high risk_score should trigger even without malware keywords."""
        event = _norm(GENERIC_HIGH_EVENT)
        event = NormalizedEvent(
            src_ip="1.2.3.4", dst_ip="5.6.7.8",
            signature="Unknown Alert", category="Unknown",
            risk_score=90.0, severity=3, timestamp="2024-01-01T00:00:00Z",
        )
        stats = _stats_with(event_count=1)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None


# ---- SOAR-005 DNS Suspicious ----

class TestDNSSuspiciousRule:
    rule = DNSSuspiciousRule()

    def test_fires_on_dns_signature(self) -> None:
        event = _norm(DNS_EVENT)
        stats = _stats_with(event_count=5)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.attack_type == "dns_suspicious"


# ---- SOAR-006 DoS / Flood ----

class TestDoSFloodRule:
    rule = DoSFloodRule()

    def test_fires_on_dos_signature(self) -> None:
        event = _norm(DOS_EVENT)
        stats = _stats_with(event_count=10)   # sig keyword alone triggers
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.attack_type == "dos_or_flood"


# ---- SOAR-007 Lateral Movement ----

class TestLateralMovementRule:
    rule = LateralMovementRule()

    def test_fires_on_smb_signature(self) -> None:
        event = _norm(LATERAL_EVENT)
        stats = _stats_with(event_count=3, unique_dst_ips=2)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.attack_type == "lateral_movement_suspicion"

    def test_fires_on_many_unique_hosts(self) -> None:
        event = _norm(PORT_SCAN_EVENT)
        # Override with large unique host count
        event = NormalizedEvent(
            src_ip="10.0.0.50", dst_ip="10.0.0.60", dst_port=445,
            signature="Generic Alert", category="Lateral Movement",
            severity=2, timestamp="2024-01-01T00:00:00Z",
        )
        stats = _stats_with(event_count=5, unique_dst_ips=7)
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None


# ---- SOAR-008 Generic High Risk ----

class TestGenericHighRiskRule:
    rule = GenericHighRiskRule()

    def test_fires_on_severity_1(self) -> None:
        event = _norm(SSH_BRUTE_EVENT)   # severity 1
        stats = _stats_with()
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None
        assert match.priority == "CRITICAL"

    def test_fires_on_high_risk_score(self) -> None:
        event = NormalizedEvent(
            src_ip="5.5.5.5", dst_ip="192.168.1.1",
            risk_score=85.0, severity=3,
            signature="Generic", category="Generic",
            timestamp="2024-01-01T00:00:00Z",
        )
        stats = _stats_with()
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is not None

    def test_does_not_fire_on_low_risk(self) -> None:
        event = NormalizedEvent(
            src_ip="5.5.5.5", dst_ip="192.168.1.1",
            risk_score=30.0, severity=3,
            signature="Low Risk Alert", category="Misc",
            timestamp="2024-01-01T00:00:00Z",
        )
        stats = _stats_with()
        match = self.rule.evaluate(event, stats, RULE_CONFIG)
        assert match is None
