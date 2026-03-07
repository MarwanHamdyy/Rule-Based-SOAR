"""
actions/action_builder.py
--------------------------
Builds structured SOAR action documents from a normalised event +
rule match + optional enrichment data.

The output document is ready to be indexed into Elasticsearch under
`soar-actions-YYYY.MM.DD`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import RuleMatch
from utils.logger import get_logger

logger = get_logger(__name__)


class ActionBuilder:
    """
    Stateless factory that produces action documents.

    Args:
        framework_mapper: Optional :class:`~mappings.framework_mapper.FrameworkMapper`
                          instance. If supplied, MITRE/OWASP/NIST metadata is
                          attached to every action doc.
    """

    def __init__(self, framework_mapper=None) -> None:
        self._mapper = framework_mapper

    def build(
        self,
        event: NormalizedEvent,
        match: RuleMatch,
        enrichment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Produce a fully structured SOAR action document.

        Args:
            event:      The normalised Suricata event that triggered the rule.
            match:      The :class:`RuleMatch` produced by the rule.
            enrichment: Optional enrichment data from VirusTotal or similar.

        Returns:
            Dict suitable for direct indexing into Elasticsearch.
        """
        now = datetime.now(timezone.utc).isoformat()
        action_id = str(uuid.uuid4())

        doc: dict[str, Any] = {
            # --- Temporal ---
            "@timestamp": now,

            # --- Identity ---
            "action_id": action_id,
            "rule_id": match.rule_id,
            "attack_type": match.attack_type,

            # --- Network context ---
            "source_ip": event.src_ip,
            "source_port": event.src_port,
            "destination_ip": event.dst_ip,
            "destination_port": event.dst_port,
            "protocol": event.proto,

            # --- Risk assessment ---
            "priority": match.priority,
            "confidence": round(match.confidence, 4),
            "risk_score": event.risk_score,

            # --- Human-readable output ---
            "recommended_mitigation": match.recommended_mitigation,
            "reasons": match.reasons,

            # --- Original event context ---
            "original_event": {
                "timestamp": event.timestamp,
                "signature": event.signature,
                "signature_id": event.signature_id,
                "category": event.category,
                "severity": event.severity,
                "hostname": event.hostname,
                "es_index": event.es_index,
                "es_id": event.es_id,
            },
        }

        # --- Framework mappings (from rule or from mapper) ---
        framework: dict[str, str] = {}
        if match.mitre_tactic:
            framework["mitre_tactic"] = match.mitre_tactic
        if match.mitre_technique:
            framework["mitre_technique"] = match.mitre_technique
        if match.owasp_ref:
            framework["owasp_ref"] = match.owasp_ref
        if match.nist_ref:
            framework["nist_ref"] = match.nist_ref

        # Supplement with the mapper when available
        if self._mapper:
            mapped = self._mapper.lookup(match.attack_type)
            framework.update({k: v for k, v in mapped.items() if k not in framework})

        if framework:
            doc["framework_mapping"] = framework

        # --- Optional enrichment summary ---
        if enrichment:
            doc["enrichment"] = {
                "provider": "virustotal",
                "malicious": enrichment.get("malicious", 0),
                "suspicious": enrichment.get("suspicious", 0),
                "reputation": enrichment.get("reputation"),
                "country": enrichment.get("country", ""),
                "as_owner": enrichment.get("as_owner", ""),
                "tags": enrichment.get("tags", []),
            }

        logger.debug(
            "Built action %s (rule=%s priority=%s confidence=%.2f) for src=%s",
            action_id, match.rule_id, match.priority, match.confidence, event.src_ip,
        )
        return doc
