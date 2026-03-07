"""
normalizer/event_normalizer.py
--------------------------------
Converts raw Elasticsearch Suricata documents into a clean, typed
internal event schema.

The normalizer handles two common Filebeat layouts:
  - Filebeat 7.x: fields nested under ``suricata.eve.*``
  - Filebeat 8.x / ECS: fields mostly at the top level with ECS naming

All field extractions are defensive (missing fields return safe defaults).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NormalizedEvent:
    """
    Canonical internal representation of a Suricata alert event.

    Every field has a safe default so downstream consumers never
    need to guard against KeyError / AttributeError.
    """

    # --- Temporal ---
    timestamp: str = ""                # ISO-8601, e.g. "2024-06-01T12:00:00Z"

    # --- Event classification ---
    event_type: str = "alert"          # always "alert" for our pipeline
    signature: str = ""                # e.g. "ET SCAN Nmap SYN Scan"
    signature_id: int = 0              # Suricata SID
    category: str = ""                 # Suricata rule category
    severity: int = 3                  # 1 (highest) – 3 (lowest)
    risk_score: float = 0.0            # pre-computed risk score if present

    # --- Network tuple ---
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    proto: str = ""                    # "tcp", "udp", "icmp", etc.

    # --- Host context ---
    hostname: str = ""                 # sensor/host name if available

    # --- Back-references to source ES document ---
    es_index: str = ""
    es_id: str = ""

    # --- Raw source (for debugging) ---
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "category": self.category,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "hostname": self.hostname,
            "es_index": self.es_index,
            "es_id": self.es_id,
        }


class EventNormalizer:
    """
    Stateless normalizer: converts a raw ES document into a
    :class:`NormalizedEvent`.

    Usage::

        normalizer = EventNormalizer()
        event = normalizer.normalize(raw_doc)
    """

    def normalize(self, raw: dict) -> NormalizedEvent | None:
        """
        Normalise a single raw ES document.

        Args:
            raw: The ``_source`` dict from an ES hit (with ``_es_index`` /
                 ``_es_id`` injected by the collector).

        Returns:
            :class:`NormalizedEvent` on success, or *None* if the document
            cannot be meaningfully parsed (e.g. it is not a Suricata alert).
        """
        try:
            return self._do_normalize(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Normalization failed for doc %s: %s", raw.get("_es_id", "?"), exc)
            return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _do_normalize(self, raw: dict) -> NormalizedEvent | None:
        """Core normalisation logic supporting multiple Filebeat schemas."""

        # Determine if this is a Filebeat 7 nested layout or ECS flat layout
        suricata_eve = raw.get("suricata", {}).get("eve", {})
        alert_block = suricata_eve.get("alert", {}) or raw.get("suricata", {}).get("alert", {})

        # ECS-style (Filebeat 8+): fields live at the top level
        rule_block = raw.get("rule", {})
        network_block = raw.get("network", {})
        source_block = raw.get("source", {})
        dest_block = raw.get("destination", {})
        event_block = raw.get("event", {})

        # --- Signature & category ---
        signature = (
            alert_block.get("signature")
            or rule_block.get("name")
            or raw.get("message", "")
        )
        signature_id = int(
            alert_block.get("signature_id")
            or rule_block.get("id")
            or 0
        )
        # Extract category with correct precedence
        _ev_cat = event_block.get("category", "")
        _ev_cat_str = _ev_cat[0] if isinstance(_ev_cat, list) else _ev_cat
        category = alert_block.get("category") or _ev_cat_str or ""
        severity = int(
            alert_block.get("severity")
            or raw.get("suricata", {}).get("eve", {}).get("alert", {}).get("severity")
            or event_block.get("severity", 3)
            or 3
        )

        # --- Network fields ---
        src_ip = (
            suricata_eve.get("src_ip")
            or source_block.get("ip")
            or raw.get("src_ip", "")
        )
        src_port = int(
            suricata_eve.get("src_port")
            or source_block.get("port")
            or raw.get("src_port", 0)
            or 0
        )
        dst_ip = (
            suricata_eve.get("dest_ip")
            or dest_block.get("ip")
            or raw.get("dest_ip", "")
        )
        dst_port = int(
            suricata_eve.get("dest_port")
            or dest_block.get("port")
            or raw.get("dest_port", 0)
            or 0
        )
        proto = (
            suricata_eve.get("proto")
            or network_block.get("transport")
            or raw.get("proto", "")
        ).lower()

        # --- Risk score ---
        risk_score = float(
            raw.get("risk_score")
            or raw.get("event", {}).get("risk_score")
            or 0.0
        )

        # --- Timestamp ---
        timestamp = (
            raw.get("@timestamp")
            or suricata_eve.get("timestamp")
            or ""
        )

        # --- Hostname ---
        hostname = (
            raw.get("host", {}).get("name")
            or raw.get("agent", {}).get("hostname")
            or ""
        )

        # Discard non-alert events
        event_kind = event_block.get("kind", "alert")
        event_type_val = event_block.get("type", "alert")
        if isinstance(event_type_val, list):
            event_type_val = event_type_val[0] if event_type_val else "alert"

        if event_kind not in ("alert", "") or event_type_val not in ("alert", ""):
            # Only a concern if explicitly set to something else
            if event_kind and event_kind != "alert":
                logger.debug("Skipping non-alert event (kind=%s)", event_kind)
                return None

        return NormalizedEvent(
            timestamp=timestamp,
            event_type="alert",
            signature=signature,
            signature_id=signature_id,
            category=category,
            severity=severity,
            risk_score=risk_score,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            hostname=hostname,
            es_index=raw.get("_es_index", ""),
            es_id=raw.get("_es_id", ""),
            raw=raw,
        )
