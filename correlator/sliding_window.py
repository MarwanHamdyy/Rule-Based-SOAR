"""
correlator/sliding_window.py
------------------------------
Thread-safe sliding window that tracks events per grouping key.

A window expires events older than `window_seconds` automatically.
Provides aggregated statistics used by rules to detect patterns.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EventEntry:
    """Minimal record stored in the sliding window per event."""
    timestamp: float       # Unix epoch seconds
    src_ip: str
    dst_ip: str
    dst_port: int
    signature: str
    signature_id: int
    category: str
    severity: int
    risk_score: float


@dataclass
class WindowStats:
    """Aggregated statistics derived from a sliding window."""
    event_count: int = 0
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    unique_signatures: int = 0
    unique_categories: int = 0
    max_risk_score: float = 0.0
    min_severity: int = 3          # lower value = higher Suricata severity
    signatures: set = field(default_factory=set)
    categories: set = field(default_factory=set)


class SlidingWindow:
    """
    Per-source-IP sliding window containing recent events.

    Args:
        window_seconds: Length of the observation window in seconds.
    """

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        # keyed by src_ip  →  deque[EventEntry] (oldest first)
        self._buckets: dict[str, Deque[EventEntry]] = defaultdict(deque)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, entry: EventEntry) -> None:
        """Add *entry* to the window for its source IP and expire stale events."""
        with self._lock:
            q = self._buckets[entry.src_ip]
            q.append(entry)
            self._expire(q, entry.timestamp)

    def stats(self, src_ip: str, as_of: float | None = None) -> WindowStats:
        """
        Return aggregated statistics for *src_ip*.

        Args:
            src_ip: Source IP to aggregate.
            as_of:  Unix timestamp to use as "now".  Defaults to current time.

        Returns:
            :class:`WindowStats` instance.
        """
        now = as_of or datetime.now(timezone.utc).timestamp()
        cutoff = now - self.window_seconds

        with self._lock:
            q = self._buckets.get(src_ip, deque())
            # Filter to entries within the window
            entries = [e for e in q if e.timestamp >= cutoff]

        if not entries:
            return WindowStats()

        dst_ports: set[int] = set()
        dst_ips: set[str] = set()
        sigs: set[str] = set()
        cats: set[str] = set()
        max_risk = 0.0
        min_sev = 3

        for e in entries:
            dst_ports.add(e.dst_port)
            dst_ips.add(e.dst_ip)
            if e.signature:
                sigs.add(e.signature)
            if e.category:
                cats.add(e.category)
            max_risk = max(max_risk, e.risk_score)
            min_sev = min(min_sev, e.severity)

        return WindowStats(
            event_count=len(entries),
            unique_dst_ports=len(dst_ports),
            unique_dst_ips=len(dst_ips),
            unique_signatures=len(sigs),
            unique_categories=len(cats),
            max_risk_score=max_risk,
            min_severity=min_sev,
            signatures=sigs,
            categories=cats,
        )

    def purge_old(self) -> int:
        """
        Remove all expired entries across all source IPs.

        Returns:
            Number of entries removed.
        """
        now = datetime.now(timezone.utc).timestamp()
        removed = 0
        with self._lock:
            for src_ip, q in list(self._buckets.items()):
                before = len(q)
                self._expire(q, now)
                removed += before - len(q)
                # Remove empty buckets to free memory
                if not q:
                    del self._buckets[src_ip]
        return removed

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _expire(self, q: Deque[EventEntry], now: float) -> None:
        """Pop stale entries from the left (oldest) of *q*."""
        cutoff = now - self.window_seconds
        while q and q[0].timestamp < cutoff:
            q.popleft()
