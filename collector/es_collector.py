"""
collector/es_collector.py
--------------------------
Polls Elasticsearch for new Suricata alert events.

How it works:
  1. On startup, load the last checkpoint timestamp.
  2. Query ES for `event.type: alert` docs newer than that timestamp.
  3. Yield each raw document to the caller.
  4. After a batch is processed, save the newest timestamp as the new checkpoint.
  5. Sleep for `poll_interval` seconds, then repeat.

Replay mode: set ENGINE_MODE=replay and REPLAY_FROM to re-process historical data.
"""

import time
from datetime import datetime, timezone
from typing import Generator

from elasticsearch import Elasticsearch, exceptions as es_exc

from utils.checkpoint import Checkpoint
from utils.logger import get_logger

logger = get_logger(__name__)


class ESCollector:
    """
    Collects raw Suricata alert documents from Elasticsearch.

    Args:
        es_client:      Authenticated Elasticsearch client.
        source_index:   Index pattern to search (e.g. ``filebeat-*``).
        checkpoint:     Checkpoint instance for persisting progress.
        max_results:    Maximum documents to fetch per poll cycle.
        mode:           ``"live"`` or ``"replay"``.
        replay_from:    ISO-8601 string; only used when mode is ``"replay"``.
    """

    def __init__(
        self,
        es_client: Elasticsearch,
        source_index: str,
        checkpoint: Checkpoint,
        max_results: int = 500,
        mode: str = "live",
        replay_from: str | None = None,
    ) -> None:
        self.es = es_client
        self.source_index = source_index
        self.checkpoint = checkpoint
        self.max_results = max_results
        self.mode = mode
        self.replay_from = replay_from

        # Determine start timestamp
        if mode == "replay" and replay_from:
            self._last_timestamp: str | None = replay_from
            logger.info("Replay mode: starting from %s", replay_from)
        else:
            self._last_timestamp = checkpoint.load()
            logger.info("Live mode: resuming from checkpoint %s", self._last_timestamp)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def poll(self) -> list[dict]:
        """
        Fetch the next batch of unprocessed Suricata alert events.

        Returns:
            List of raw Elasticsearch ``_source`` documents enriched with
            ``_index`` and ``_id`` metadata fields.
        """
        query = self._build_query()
        try:
            resp = self.es.search(
                index=self.source_index,
                body=query,
                size=self.max_results,
            )
        except es_exc.ConnectionError as exc:
            logger.error("Elasticsearch connection error: %s", exc)
            return []
        except es_exc.TransportError as exc:
            logger.error("Elasticsearch transport error: %s", exc)
            return []

        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            logger.debug("No new events since %s", self._last_timestamp)
            return []

        documents = []
        latest_ts: str | None = None

        for hit in hits:
            source = hit.get("_source", {})
            # Inject ES metadata useful for deduplication & back-references
            source["_es_index"] = hit.get("_index", "")
            source["_es_id"] = hit.get("_id", "")
            documents.append(source)

            # Track the latest timestamp in this batch
            ts = self._extract_timestamp(source)
            if ts and (latest_ts is None or ts > latest_ts):
                latest_ts = ts

        if latest_ts:
            self._last_timestamp = latest_ts
            self.checkpoint.save(latest_ts)
            logger.info("Fetched %d events; new checkpoint: %s", len(documents), latest_ts)

        return documents

    def run_forever(self, poll_interval: int, callback) -> None:
        """
        Continuously poll ES and pass each batch to *callback*.

        Args:
            poll_interval: Seconds to sleep between polls.
            callback:      Callable that receives a list of raw documents.
        """
        logger.info("Starting continuous polling (interval=%ds)", poll_interval)
        while True:
            batch = self.poll()
            if batch:
                callback(batch)
            time.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_query(self) -> dict:
        """
        Build the Elasticsearch DSL query.

        Targets only alert-type events from Suricata and restricts to
        documents newer than the last checkpoint.
        """
        must_clauses: list[dict] = [
            {"term": {"event.type": "alert"}},
        ]

        # Also accept suricata-specific alert fields (Filebeat 7/8 schemas)
        filter_clauses: list[dict] = []

        if self._last_timestamp:
            filter_clauses.append({
                "range": {
                    "@timestamp": {"gt": self._last_timestamp}
                }
            })

        query = {
            "query": {
                "bool": {
                    "must": must_clauses,
                    "filter": filter_clauses,
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        return query

    @staticmethod
    def _extract_timestamp(doc: dict) -> str | None:
        """
        Extract the event timestamp from a raw document.

        Tries ``@timestamp`` first (standard ECS), falls back to
        ``suricata.eve.timestamp``.
        """
        return doc.get("@timestamp") or doc.get("suricata", {}).get("eve", {}).get("timestamp")
