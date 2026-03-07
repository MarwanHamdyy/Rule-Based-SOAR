"""
tests/test_correlator.py
-------------------------
Unit tests for the sliding window and correlation state.
Uses freezegun to control time without sleeping.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from freezegun import freeze_time

from correlator.sliding_window import EventEntry, SlidingWindow, WindowStats
from correlator.state_manager import CorrelationState
from normalizer.event_normalizer import EventNormalizer, NormalizedEvent
from tests.sample_events import PORT_SCAN_EVENT, SSH_BRUTE_EVENT


def _make_entry(src_ip: str, dst_ip: str = "10.0.0.1",
                dst_port: int = 80, ts: float = 0.0) -> EventEntry:
    return EventEntry(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        signature="Test Signature",
        signature_id=9999,
        category="Test",
        severity=2,
        risk_score=50.0,
    )


# ---- SlidingWindow tests ----

class TestSlidingWindow:
    def test_add_and_count(self) -> None:
        win = SlidingWindow(window_seconds=60)
        now = 1_000_000.0
        for i in range(5):
            win.add(_make_entry("1.2.3.4", ts=now + i))
        stats = win.stats("1.2.3.4", as_of=now + 5)
        assert stats.event_count == 5

    def test_expiry_removes_old_events(self) -> None:
        win = SlidingWindow(window_seconds=30)
        old_ts = 1_000_000.0
        new_ts = old_ts + 60      # 60s later, old event is outside 30s window
        win.add(_make_entry("1.2.3.4", ts=old_ts))
        win.add(_make_entry("1.2.3.4", ts=new_ts))

        stats = win.stats("1.2.3.4", as_of=new_ts)
        # Only the new event should be within the 30s window
        assert stats.event_count == 1

    def test_unique_dst_ports(self) -> None:
        win = SlidingWindow(window_seconds=60)
        now = 1_000_000.0
        ports = [22, 80, 443, 8080, 3306]
        for p in ports:
            win.add(_make_entry("5.5.5.5", dst_port=p, ts=now))
        stats = win.stats("5.5.5.5", as_of=now + 1)
        assert stats.unique_dst_ports == len(ports)

    def test_unique_dst_ips(self) -> None:
        win = SlidingWindow(window_seconds=60)
        now = 1_000_000.0
        hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        for h in hosts:
            win.add(_make_entry("6.6.6.6", dst_ip=h, ts=now))
        stats = win.stats("6.6.6.6", as_of=now + 1)
        assert stats.unique_dst_ips == len(hosts)

    def test_empty_stats_for_unknown_ip(self) -> None:
        win = SlidingWindow(window_seconds=60)
        stats = win.stats("9.9.9.9")
        assert stats.event_count == 0
        assert stats.unique_dst_ports == 0

    def test_purge_old(self) -> None:
        win = SlidingWindow(window_seconds=10)
        old_ts = 1_000_000.0
        win.add(_make_entry("7.7.7.7", ts=old_ts))
        # Advance time beyond expiry using direct timestamp manipulation
        stats_before = win.stats("7.7.7.7", as_of=old_ts + 5)
        assert stats_before.event_count == 1
        stats_after = win.stats("7.7.7.7", as_of=old_ts + 20)
        assert stats_after.event_count == 0


# ---- CorrelationState tests ----

class TestCorrelationState:
    def test_ingest_and_query(self) -> None:
        state = CorrelationState()
        normalizer = EventNormalizer()
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        state.ingest(event)
        all_stats = state.query(event.src_ip)
        assert "short" in all_stats
        assert "medium" in all_stats
        assert "long" in all_stats
        assert "extended" in all_stats

    def test_ingest_multiple_events(self) -> None:
        """Ingesting 3 events with current timestamps should appear in all windows."""
        from datetime import datetime, timezone
        state = CorrelationState()
        normalizer = EventNormalizer()
        event = normalizer.normalize(PORT_SCAN_EVENT)
        assert event is not None
        # Use current time so events fall inside the sliding windows
        now_iso = datetime.now(timezone.utc).isoformat()
        event.timestamp = now_iso
        state.ingest(event)
        state.ingest(event)
        state.ingest(event)
        stats = state.query(event.src_ip)
        # All windows should see at least 3 events
        assert stats["medium"].event_count >= 3

    def test_no_src_ip_skipped(self) -> None:
        """Events without src_ip must not be indexed (no crash)."""
        state = CorrelationState()
        event = NormalizedEvent(src_ip="", dst_ip="10.0.0.1")
        state.ingest(event)   # should not raise
        stats = state.query("")
        assert stats["short"].event_count == 0

    def test_purge_expired_does_not_crash(self) -> None:
        state = CorrelationState()
        state.purge_expired()   # should not raise even when empty
