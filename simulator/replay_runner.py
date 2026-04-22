"""
simulator/replay_runner.py
---------------------------
Replays pre-recorded Suricata alert events from a JSON file into the
simulation index, enabling deterministic, repeatable end-to-end tests.

The replayer re-timestamps all documents relative to *now* so that the
SOAR engine's timestamp-based polling (checkpoint) picks them up correctly.

Usage::

    runner = ReplayRunner(publisher=pub)
    count  = runner.replay("simulator/sample_data/sample_ssh_bruteforce.json")
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from simulator.sim_publisher import SimPublisher
from utils.logger import get_logger

logger = get_logger(__name__)


class ReplayRunner:
    """
    Loads a JSON array of raw Suricata documents and publishes them to ES.

    Timestamps in the loaded documents are overwritten to be relative to
    *now*, preserving the original inter-event intervals.

    Args:
        publisher:  A configured :class:`SimPublisher` instance.
    """

    def __init__(self, publisher: SimPublisher) -> None:
        self.publisher = publisher

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def replay(
        self,
        json_path: str | Path,
        rate_per_second: int | None = None,
        retimestamp: bool = True,
    ) -> int:
        """
        Replay events from a JSON file into the simulation index.

        Args:
            json_path:        Path to a JSON file containing a list of raw
                              Suricata ``_source`` documents.
            rate_per_second:  Override the publisher's rate limit for this
                              replay run.  ``None`` keeps the publisher default.
            retimestamp:      If True (default), rewrite ``@timestamp`` values
                              so they start from ``now – (total_span)`` and
                              end at ``now``.  This ensures the engine's
                              checkpoint-based poller sees them.

        Returns:
            Number of documents successfully published.
        """
        json_path = Path(json_path)
        if not json_path.exists():
            logger.error("Replay file not found: %s", json_path)
            return 0

        try:
            with json_path.open("r", encoding="utf-8") as fh:
                docs: list[dict[str, Any]] = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load replay file '%s': %s", json_path, exc)
            return 0

        if not isinstance(docs, list) or not docs:
            logger.warning("Replay file '%s' contains no documents.", json_path)
            return 0

        logger.info(
            "Replay: loaded %d documents from '%s'.",
            len(docs), json_path,
        )

        if retimestamp:
            docs = self._retimestamp(docs)

        # Apply temporary rate override if requested
        original_rate = self.publisher.rate_per_second
        if rate_per_second is not None:
            self.publisher.rate_per_second = rate_per_second

        try:
            published = self.publisher.publish(docs)
        finally:
            self.publisher.rate_per_second = original_rate

        logger.info(
            "Replay: published %d/%d documents from '%s'.",
            published, len(docs), json_path,
        )
        return published

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _retimestamp(docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Rewrite ``@timestamp`` fields relative to *now*.

        The first event gets timestamp ``now – total_span``, the last gets
        ``now``, preserving relative ordering and inter-event gaps.
        """
        # Parse existing timestamps to compute span
        parsed: list[datetime | None] = []
        for doc in docs:
            ts_str = doc.get("@timestamp", "") or doc.get(
                "suricata", {}
            ).get("eve", {}).get("timestamp", "")
            try:
                parsed.append(datetime.fromisoformat(ts_str.replace("Z", "+00:00")))
            except (ValueError, AttributeError):
                parsed.append(None)

        valid = [t for t in parsed if t is not None]
        if not valid:
            # No parseable timestamps – assign evenly spaced from now-60s
            base = datetime.now(timezone.utc) - timedelta(seconds=60)
            for i, doc in enumerate(docs):
                ts = base + timedelta(milliseconds=500 * i)
                ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                doc["@timestamp"] = ts_str
                _set_nested_ts(doc, ts_str)
            return docs

        t_min = min(valid)
        t_max = max(valid)
        span = (t_max - t_min).total_seconds()

        # New anchor: end at now
        new_end = datetime.now(timezone.utc)
        new_start = new_end - timedelta(seconds=max(span, 1))

        result = []
        for doc, orig_ts in zip(docs, parsed):
            doc = dict(doc)  # shallow copy
            if orig_ts is not None and span > 0:
                fraction = (orig_ts - t_min).total_seconds() / span
                new_ts: datetime = new_start + timedelta(seconds=fraction * span)
            else:
                new_ts = new_end
            ts_str = new_ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            doc["@timestamp"] = ts_str
            _set_nested_ts(doc, ts_str)
            result.append(doc)

        return result


def _set_nested_ts(doc: dict, ts_str: str) -> None:
    """Also update the nested suricata.eve.timestamp if present."""
    eve = doc.get("suricata", {}).get("eve")
    if isinstance(eve, dict) and "timestamp" in eve:
        eve["timestamp"] = ts_str
