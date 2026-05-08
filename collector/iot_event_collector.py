"""
collector/iot_event_collector.py
---------------------------------
Polls Elasticsearch for self-healing agent events that have been
escalated for SOAR handling. These events come from the IoT containers'
autonomous self-healing agents (FIM, BF Monitor, Service Monitor,
Process Monitor, Decision Engine) via Logstash.

Maintains its own checkpoint (separate from the Suricata collector)
so the two sources are polled independently.

Escalated event types (from self_healing_complete.pdf §7.2):
  - possible_brute_force_success
  - service_escalated
  - unwhitelisted_process
  - fim_violation (on /etc/passwd or /etc/shadow)
  - cve_no_fix
  - cve_remediation_failed
  - permanent_ip_block
  - credential_rotation
  - iptables_block_by_cve_engine
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError

from utils.checkpoint import Checkpoint
from utils.logger import get_logger

logger = get_logger(__name__)

# -----------------------------------------------------------------------
# Event types the self-healing agents deliberately escalate to SOAR.
# Maps event_type → SOAR attack_type key used in attack_names.json.
# -----------------------------------------------------------------------
_ESCALATED_EVENT_MAP: dict[str, str] = {
    "possible_brute_force_success":  "ssh_bruteforce",
    "service_escalated":             "generic_high_risk_alert",
    "unwhitelisted_process":         "malware_or_c2",
    "fim_violation":                 "malware_or_c2",
    "cve_no_fix":                    "generic_high_risk_alert",
    "cve_remediation_failed":        "generic_high_risk_alert",
    "permanent_ip_block":            "port_scan",
    "credential_rotation":           "ssh_bruteforce",
    "iptables_block_by_cve_engine":  "generic_high_risk_alert",
    # Logstash-tagged events from Group2 Logstash rules
    "brute_force":                   "ssh_bruteforce",
    "port_scan":                     "port_scan",
    "reconnaissance":                "port_scan",
    "iot_exploit":                   "malware_or_c2",
    "ddos_attack":                   "dos_or_flood",
    "unauthorized_access":           "generic_high_risk_alert",
    "command_injection":             "web_attack",
    "firmware_tampering":            "malware_or_c2",
    "network_anomaly":               "generic_high_risk_alert",
    "default_credentials":           "ssh_bruteforce",
    "iot_exploitation":              "malware_or_c2",
}

# Logstash indices written by the self-healing agents and Group2 rules
_SOURCE_INDICES = [
    "security-alerts-*",
    "critical-alerts-*",
    "iot-logs-*",
    "failed-logins-*",
]


class IoTEventCollector:
    """
    Polls Elasticsearch for self-healing escalation events and
    Logstash security alerts from IoT containers.

    Args:
        es_client:          Authenticated Elasticsearch client.
        checkpoint:         Checkpoint instance (separate from Suricata checkpoint).
        max_results:        Max events per poll cycle.
        source_indices:     List of ES index patterns to query.
    """

    def __init__(
        self,
        es_client: Elasticsearch,
        checkpoint: Checkpoint,
        max_results: int = 200,
        source_indices: list[str] | None = None,
    ) -> None:
        self._es = es_client
        self._checkpoint = checkpoint
        self._max_results = max_results
        self._source_indices = source_indices or _SOURCE_INDICES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def poll(self) -> list[dict[str, Any]]:
        """
        Fetch new escalated events since the last checkpoint.

        Returns:
            List of normalised IoT event dicts ready for the playbook engine.
        """
        last_ts = self._checkpoint.load()
        query = self._build_query(last_ts)

        try:
            response = self._es.search(
                index=",".join(self._source_indices),
                body=query,
                size=self._max_results,
                ignore_unavailable=True,
            )
        except ESConnectionError as exc:
            logger.error("IoTEventCollector: ES connection error: %s", exc)
            return []
        except Exception as exc:  # noqa: BLE001
            logger.error("IoTEventCollector: unexpected error: %s", exc)
            return []

        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return []

        events = []
        newest_ts: str | None = None

        for hit in hits:
            source = hit.get("_source", {})
            event = self._normalise(source, hit.get("_index", ""), hit.get("_id", ""))
            if event:
                events.append(event)
                ts = source.get("@timestamp") or source.get("timestamp")
                if ts and (newest_ts is None or ts > newest_ts):
                    newest_ts = ts

        if newest_ts:
            self._checkpoint.save(newest_ts)

        logger.info(
            "IoTEventCollector: polled %d events from indices %s",
            len(events),
            self._source_indices,
        )
        return events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_query(self, last_timestamp: str | None) -> dict:
        """Build ES DSL query for escalated self-healing events."""
        must_clauses: list[dict] = [
            {
                "bool": {
                    "should": [
                        # Self-healing escalated events
                        {"term": {"escalated": True}},
                        {"term": {"severity": "CRITICAL"}},
                        {"term": {"alert_severity": "critical"}},
                        {"term": {"alert_severity": "high"}},
                        {"exists": {"field": "event_type"}},
                        {"terms": {"tags": list(_ESCALATED_EVENT_MAP.keys())}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        ]

        if last_timestamp:
            must_clauses.append(
                {"range": {"@timestamp": {"gt": last_timestamp}}}
            )

        return {
            "query": {"bool": {"must": must_clauses}},
            "sort": [{"@timestamp": {"order": "asc"}}],
        }

    def _normalise(
        self,
        source: dict[str, Any],
        index: str,
        doc_id: str,
    ) -> dict[str, Any] | None:
        """
        Normalise a raw Elasticsearch document into a standard IoT event dict.
        Returns None if the event cannot be mapped to a known attack type.
        """
        # Determine event_type from multiple possible field layouts
        event_type = (
            source.get("event_type")
            or source.get("alert_category")
            or self._tags_to_event_type(source.get("tags", []))
            or "generic_high_risk_alert"
        )

        attack_type = _ESCALATED_EVENT_MAP.get(event_type, "generic_high_risk_alert")

        # Extract source IP from multiple field paths
        src_ip = (
            source.get("ip")
            or source.get("attacker_ip")
            or source.get("scanner_ip")
            or source.get("source_ip")
            or source.get("src_ip")
            or "unknown"
        )

        # Severity mapping
        raw_sev = (
            source.get("severity")
            or source.get("alert_severity")
            or "medium"
        ).lower()
        severity_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        severity = severity_map.get(raw_sev, 3)

        timestamp = source.get("@timestamp") or datetime.now(timezone.utc).isoformat()

        return {
            # Standard fields used by PlaybookEngine
            "event_source":  "iot_self_healing",
            "event_type":    event_type,
            "attack_type":   attack_type,
            "src_ip":        src_ip,
            "dst_ip":        source.get("target_ip") or source.get("dest_ip") or "unknown",
            "severity":      severity,
            "raw_severity":  raw_sev,
            "timestamp":     timestamp,
            "es_index":      index,
            "es_id":         doc_id,
            "container_id":  source.get("container_id") or source.get("hostname") or "unknown",
            "description":   source.get("alert_description") or source.get("action") or event_type,
            "raw":           source,
        }

    @staticmethod
    def _tags_to_event_type(tags: list[str]) -> str | None:
        """Map Logstash tag list to a known event_type key."""
        for tag in tags:
            if tag in _ESCALATED_EVENT_MAP:
                return tag
        return None
