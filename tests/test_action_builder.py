"""
tests/test_action_builder.py
-----------------------------
Unit tests for ActionBuilder.
Verifies that all required fields are present and that optional
enrichment / framework mapping data is correctly attached.
"""

from __future__ import annotations

import pytest

from actions.action_builder import ActionBuilder
from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import EventNormalizer, NormalizedEvent
from rules.base_rule import RuleMatch
from tests.sample_events import MALWARE_C2_EVENT, PORT_SCAN_EVENT


normalizer = EventNormalizer()

REQUIRED_FIELDS = {
    "@timestamp", "action_id", "rule_id", "attack_type",
    "source_ip", "destination_ip", "priority", "confidence",
    "risk_score", "recommended_mitigation", "reasons", "original_event",
}


def _make_match(
    rule_id: str = "SOAR-001",
    attack_type: str = "port_scan",
    priority: str = "HIGH",
    confidence: float = 0.85,
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        attack_type=attack_type,
        priority=priority,
        confidence=confidence,
        recommended_mitigation="Block the source IP.",
        reasons=["Many ports scanned.", "High event count."],
        mitre_tactic="Discovery",
        mitre_technique="T1046",
    )


class TestActionBuilder:
    builder = ActionBuilder()

    def test_all_required_fields_present(self) -> None:
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        match = _make_match()
        doc = self.builder.build(event, match)
        for field in REQUIRED_FIELDS:
            assert field in doc, f"Missing field: {field}"

    def test_action_id_is_uuid(self) -> None:
        import uuid
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        doc = self.builder.build(event, _make_match())
        uid = doc["action_id"]
        # Should be parseable as UUID
        uuid.UUID(uid)

    def test_framework_mapping_attached_from_rule(self) -> None:
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        match = _make_match()
        doc = self.builder.build(event, match)
        assert "framework_mapping" in doc
        assert "mitre_tactic" in doc["framework_mapping"]

    def test_enrichment_attached_when_provided(self) -> None:
        event = normalizer.normalize(MALWARE_C2_EVENT)
        assert event is not None
        match = _make_match(rule_id="SOAR-004", attack_type="malware_or_c2", priority="CRITICAL")
        enrichment = {
            "malicious": 42, "suspicious": 3,
            "reputation": -50, "country": "XZ", "tags": ["c2"],
        }
        doc = self.builder.build(event, match, enrichment=enrichment)
        assert "enrichment" in doc
        assert doc["enrichment"]["malicious"] == 42
        assert doc["enrichment"]["country"] == "XZ"

    def test_no_enrichment_when_not_provided(self) -> None:
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        doc = self.builder.build(event, _make_match())
        assert "enrichment" not in doc

    def test_original_event_reference_present(self) -> None:
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        doc = self.builder.build(event, _make_match())
        orig = doc["original_event"]
        assert orig["es_id"] == "evt-001"
        assert "signature" in orig

    def test_confidence_rounded(self) -> None:
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        match = _make_match(confidence=0.856789)
        doc = self.builder.build(event, match)
        assert doc["confidence"] == round(0.856789, 4)
