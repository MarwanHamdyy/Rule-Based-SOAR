"""
simulator/sim_publisher.py
---------------------------
Publishes synthetic Suricata alert documents to a dedicated Elasticsearch
simulation index.

The simulation index is separate from the live ``filebeat-*`` source so that
simulated traffic never pollutes real data.  The SOAR engine is pointed at
this index during testing by setting ``ES_SOURCE_INDEX=soar-simulation``.
"""

from __future__ import annotations

import time
from typing import Any

from elasticsearch import Elasticsearch, exceptions as es_exc
from elasticsearch.helpers import bulk

from utils.logger import get_logger

logger = get_logger(__name__)


class SimPublisher:
    """
    Indexes synthetic documents into an Elasticsearch simulation index.

    Args:
        es_client:       Authenticated Elasticsearch client.
        sim_index:       Target index name (e.g. ``soar-simulation``).
        rate_per_second: Maximum documents published per second (0 = unlimited).
    """

    def __init__(
        self,
        es_client: Elasticsearch,
        sim_index: str = "soar-simulation",
        rate_per_second: int = 10,
    ) -> None:
        self.es = es_client
        self.sim_index = sim_index
        self.rate_per_second = rate_per_second

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_index(self) -> None:
        """
        Create the simulation index with correct mappings if it does not exist.

        The mapping mirrors the fields the ``EventNormalizer`` reads, so the
        SOAR engine pipeline can consume documents from this index directly.
        """
        if self.es.indices.exists(index=self.sim_index):
            logger.debug("Simulation index '%s' already exists.", self.sim_index)
            return

        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp":   {"type": "date"},
                    "event":        {"properties": {"type": {"type": "keyword"}, "kind": {"type": "keyword"}}},
                    "risk_score":   {"type": "float"},
                    "host":         {"properties": {"name": {"type": "keyword"}}},
                    "_sim_scenario": {"type": "keyword"},
                    "suricata": {
                        "properties": {
                            "eve": {
                                "properties": {
                                    "src_ip":   {"type": "ip"},
                                    "src_port": {"type": "integer"},
                                    "dest_ip":  {"type": "ip"},
                                    "dest_port": {"type": "integer"},
                                    "proto":    {"type": "keyword"},
                                    "timestamp": {"type": "date"},
                                    "alert": {
                                        "properties": {
                                            "signature":    {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                                            "signature_id": {"type": "long"},
                                            "category":     {"type": "keyword"},
                                            "severity":     {"type": "integer"},
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
        try:
            self.es.indices.create(index=self.sim_index, body=mapping)
            logger.info("Created simulation index '%s'.", self.sim_index)
        except es_exc.RequestError as exc:
            # Race: another process created it between exists() and create()
            if "resource_already_exists" in str(exc).lower():
                logger.debug("Simulation index already created by another process.")
            else:
                logger.error("Failed to create simulation index: %s", exc)

    def publish(self, docs: list[dict[str, Any]]) -> int:
        """
        Bulk-index *docs* into the simulation index with optional rate limiting.

        Args:
            docs: List of raw ES ``_source`` dicts (with ``_es_index`` / ``_es_id``).

        Returns:
            Number of documents successfully indexed.
        """
        if not docs:
            return 0

        # Build bulk actions, stripping the simulator metadata keys from _source
        # but using _es_id as the document ID for easy dedup/replay
        actions = [
            {
                "_index": self.sim_index,
                "_id": doc.get("_es_id"),
                "_source": {k: v for k, v in doc.items() if not k.startswith("_es_")},
            }
            for doc in docs
        ]

        total_written = 0
        delay = (1.0 / self.rate_per_second) if self.rate_per_second > 0 else 0

        if delay == 0 or len(actions) <= 50:
            # Publish all at once
            total_written = self._bulk_index(actions)
        else:
            # Rate-limited chunked publishing
            chunk_size = max(1, self.rate_per_second)
            for i in range(0, len(actions), chunk_size):
                chunk = actions[i: i + chunk_size]
                written = self._bulk_index(chunk)
                total_written += written
                if i + chunk_size < len(actions):
                    time.sleep(1.0)

        logger.info(
            "Published %d/%d documents to index '%s'.",
            total_written, len(docs), self.sim_index,
        )
        return total_written

    def clear_index(self) -> int:
        """
        Delete all documents from the simulation index (keeps index + mappings).

        Returns:
            Number of documents deleted.
        """
        try:
            resp = self.es.delete_by_query(
                index=self.sim_index,
                body={"query": {"match_all": {}}},
                refresh=True,
            )
            deleted = resp.get("deleted", 0)
            logger.info("Cleared %d documents from '%s'.", deleted, self.sim_index)
            return deleted
        except es_exc.NotFoundError:
            logger.warning("Simulation index '%s' does not exist; nothing to clear.", self.sim_index)
            return 0
        except Exception as exc:  # noqa: BLE001
            logger.error("Error clearing simulation index: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _bulk_index(self, actions: list[dict]) -> int:
        """Run a bulk index request; return number of documents indexed."""
        try:
            success, errors = bulk(self.es, actions, raise_on_error=False, refresh=True)
            if errors:
                logger.warning("%d bulk indexing error(s): %s", len(errors), errors[:3])
            return success
        except es_exc.ConnectionError as exc:
            logger.error("ES connection error during bulk publish: %s", exc)
            return 0
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error during bulk publish: %s", exc)
            return 0
