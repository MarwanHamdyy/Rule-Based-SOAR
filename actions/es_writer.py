"""
actions/es_writer.py
---------------------
Writes SOAR action documents to Elasticsearch.

Index names follow the pattern ``<prefix>-YYYY.MM.DD`` so that
daily indices are created automatically (matches ILM best practices).

Deduplication: tracks action_id values seen in recent seconds to
avoid writing duplicate actions for the same event within one cycle.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch, exceptions as es_exc

from utils.logger import get_logger

logger = get_logger(__name__)


class ESWriter:
    """
    Indexes SOAR action documents into Elasticsearch.

    Args:
        es_client:         Authenticated Elasticsearch client.
        index_prefix:      Prefix string, e.g. ``soar-actions``.
        dedup_window_secs: Actions with the same dedup key written within
                           this window (seconds) are silently skipped.
    """

    def __init__(
        self,
        es_client: Elasticsearch,
        index_prefix: str = "soar-actions",
        dedup_window_secs: int = 60,
    ) -> None:
        self.es = es_client
        self.index_prefix = index_prefix
        self.dedup_window_secs = dedup_window_secs
        # dedup cache: hash → expiry_epoch
        self._dedup: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, action_doc: dict[str, Any]) -> bool:
        """
        Index a single action document.

        Args:
            action_doc: Document produced by :class:`~actions.action_builder.ActionBuilder`.

        Returns:
            True if written, False if deduplicated or on error.
        """
        dedup_key = self._dedup_key(action_doc)
        if self._is_duplicate(dedup_key):
            logger.debug("Duplicate action skipped (rule=%s src=%s).",
                         action_doc.get("rule_id"), action_doc.get("source_ip"))
            return False

        index = self._index_name()
        try:
            self.es.index(
                index=index,
                document=action_doc,
                id=action_doc.get("action_id"),
            )
            self._register_dedup(dedup_key)
            logger.info(
                "Action written → %s | rule=%s | src=%s | priority=%s",
                index,
                action_doc.get("rule_id"),
                action_doc.get("source_ip"),
                action_doc.get("priority"),
            )
            return True
        except es_exc.ConnectionError as exc:
            logger.error("ES connection error writing action: %s", exc)
        except es_exc.TransportError as exc:
            logger.error("ES transport error writing action: %s", exc)
        return False

    def write_batch(self, action_docs: list[dict[str, Any]]) -> int:
        """
        Write multiple action documents using individual index calls.

        Returns:
            Number of documents successfully written.
        """
        written = 0
        for doc in action_docs:
            if self.write(doc):
                written += 1
        return written

    def ensure_index_template(self) -> None:
        """
        Create an index template so all ``soar-actions-*`` indices
        have proper field mappings.  Called once at startup.
        """
        template_name = "soar-actions-template"
        template_body = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp":     {"type": "date"},
                        "action_id":      {"type": "keyword"},
                        "rule_id":        {"type": "keyword"},
                        "attack_type":    {"type": "keyword"},
                        "source_ip":      {"type": "ip"},
                        "source_port":    {"type": "integer"},
                        "destination_ip": {"type": "ip"},
                        "destination_port": {"type": "integer"},
                        "protocol":       {"type": "keyword"},
                        "priority":       {"type": "keyword"},
                        "confidence":     {"type": "float"},
                        "risk_score":     {"type": "float"},
                        "recommended_mitigation": {"type": "text"},
                        "reasons":        {"type": "text"},
                    }
                }
            },
            "priority": 100,
        }
        try:
            self.es.indices.put_index_template(name=template_name, body=template_body)
            logger.info("Index template '%s' applied.", template_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not apply index template: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _index_name(self) -> str:
        """Build today's index name, e.g. ``soar-actions-2024.06.01``."""
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self.index_prefix}-{today}"

    @staticmethod
    def _dedup_key(doc: dict[str, Any]) -> str:
        """
        Hash (rule_id + source_ip + attack_type) to identify duplicate actions.
        """
        raw = f"{doc.get('rule_id')}:{doc.get('source_ip')}:{doc.get('attack_type')}"
        return hashlib.sha1(raw.encode()).hexdigest()  # noqa: S324 (non-cryptographic use)

    def _is_duplicate(self, key: str) -> bool:
        """Return True if *key* was seen within the dedup window."""
        expiry = self._dedup.get(key, 0)
        return time.time() < expiry

    def _register_dedup(self, key: str) -> None:
        """Record *key* as seen; it will be ignored until the window expires."""
        self._dedup[key] = time.time() + self.dedup_window_secs
        # Prune expired entries to avoid unbounded growth
        now = time.time()
        self._dedup = {k: v for k, v in self._dedup.items() if v > now}
