"""
correlator/state_manager.py
-----------------------------
Manages multiple sliding windows (one per configured time-window) and
provides a unified interface for rules to query correlation statistics.

Windows maintained:
  - short   (30 s)
  - medium  (60 s)
  - long    (300 s  / 5 min)
  - extended(900 s  / 15 min)
"""

from __future__ import annotations

from datetime import datetime, timezone

from correlator.sliding_window import EventEntry, SlidingWindow, WindowStats
from normalizer.event_normalizer import NormalizedEvent
from utils.logger import get_logger

logger = get_logger(__name__)


class CorrelationState:
    """
    Central in-memory correlation state.

    Maintains one :class:`SlidingWindow` per configured time horizon.
    Rules call :meth:`query` to get statistics across all windows at once.

    Args:
        windows: Dict mapping window name → seconds, e.g.
                 ``{"short": 30, "medium": 60, "long": 300, "extended": 900}``
    """

    def __init__(self, windows: dict[str, int] | None = None) -> None:
        _default_windows = {
            "short": 30,
            "medium": 60,
            "long": 300,
            "extended": 900,
        }
        cfg = windows or _default_windows
        self._windows: dict[str, SlidingWindow] = {
            name: SlidingWindow(secs) for name, secs in cfg.items()
        }
        logger.info("CorrelationState initialised with windows: %s", list(cfg.keys()))

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, event: NormalizedEvent) -> None:
        """
        Add *event* to all sliding windows.

        Args:
            event: A successfully normalised event.
        """
        if not event.src_ip:
            # Can't correlate without a source IP
            return

        # Convert ISO-8601 timestamp to epoch float
        epoch = self._to_epoch(event.timestamp)

        entry = EventEntry(
            timestamp=epoch,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            signature=event.signature,
            signature_id=event.signature_id,
            category=event.category,
            severity=event.severity,
            risk_score=event.risk_score,
        )

        for window in self._windows.values():
            window.add(entry)

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query(self, src_ip: str) -> dict[str, WindowStats]:
        """
        Return correlation statistics for *src_ip* across all windows.

        Args:
            src_ip: Source IP to query.

        Returns:
            Dict mapping window name → :class:`WindowStats`.
        """
        now = datetime.now(timezone.utc).timestamp()
        return {
            name: window.stats(src_ip, as_of=now)
            for name, window in self._windows.items()
        }

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def purge_expired(self) -> None:
        """Remove expired entries from all windows to free memory."""
        total = sum(w.purge_old() for w in self._windows.values())
        if total:
            logger.debug("Purged %d expired correlation entries.", total)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    @staticmethod
    def _to_epoch(timestamp: str) -> float:
        """Convert ISO-8601 string to Unix epoch seconds."""
        if not timestamp:
            return datetime.now(timezone.utc).timestamp()
        try:
            # Python 3.11 fromisoformat handles 'Z' suffix
            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"
            dt = datetime.fromisoformat(timestamp)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            logger.warning("Cannot parse timestamp '%s'; using current time.", timestamp)
            return datetime.now(timezone.utc).timestamp()
