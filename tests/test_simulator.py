"""
tests/test_simulator.py
------------------------
Unit tests for the Simulation Mode module.

All tests run without a real Elasticsearch connection:
  - SimPublisher's ES calls are mocked via unittest.mock.
  - ReplayRunner uses a temporary JSON file on disk.
  - ScenarioRunner is integration-tested with a mocked publisher.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from simulator.event_generator import EventGenerator
from simulator.replay_runner import ReplayRunner, _set_nested_ts
from simulator.scenario_runner import ScenarioRunner
from simulator.sim_publisher import SimPublisher


# ============================================================
# Helpers
# ============================================================

def _make_publisher(rate: int = 0) -> tuple[SimPublisher, MagicMock]:
    """Return (publisher, mock_es_client)."""
    mock_es = MagicMock()
    # ensure_index check: indices.exists returns False so ensure_index creates
    mock_es.indices.exists.return_value = False
    mock_es.indices.create.return_value = {}
    pub = SimPublisher(es_client=mock_es, sim_index="soar-simulation", rate_per_second=rate)
    return pub, mock_es


# ============================================================
# TestEventGenerator
# ============================================================

class TestEventGenerator:
    gen = EventGenerator(interval_ms=100)

    # ---- count ----

    @pytest.mark.parametrize("scenario", EventGenerator.SCENARIOS)
    def test_correct_count(self, scenario: str) -> None:
        docs = self.gen.generate(scenario, count=10)
        assert len(docs) == 10

    # ---- required fields ----

    @pytest.mark.parametrize("scenario", EventGenerator.SCENARIOS)
    def test_required_fields_present(self, scenario: str) -> None:
        docs = self.gen.generate(scenario, count=3)
        for doc in docs:
            assert "@timestamp" in doc
            assert doc.get("event", {}).get("type") == "alert"
            eve = doc.get("suricata", {}).get("eve", {})
            assert "src_ip" in eve
            assert "dest_ip" in eve
            assert "alert" in eve
            assert "signature" in eve["alert"]
            assert "severity" in eve["alert"]

    # ---- src_ip injection ----

    def test_src_ip_set_correctly(self) -> None:
        docs = self.gen.generate("port_scan", src_ip="10.1.2.3", count=5)
        for doc in docs:
            assert doc["suricata"]["eve"]["src_ip"] == "10.1.2.3"

    # ---- timestamps monotonically increasing ----

    @pytest.mark.parametrize("scenario", EventGenerator.SCENARIOS)
    def test_timestamps_monotonically_increasing(self, scenario: str) -> None:
        docs = self.gen.generate(scenario, count=5)
        timestamps = [doc["@timestamp"] for doc in docs]
        assert timestamps == sorted(timestamps)

    # ---- unknown scenario raises ----

    def test_unknown_scenario_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown scenario"):
            self.gen.generate("not_a_real_scenario")

    # ---- _es_id unique per document ----

    def test_unique_es_ids(self) -> None:
        docs = self.gen.generate("ssh_bruteforce", count=20)
        ids = [doc["_es_id"] for doc in docs]
        assert len(ids) == len(set(ids)), "Duplicate _es_ids found"

    # ---- custom start_time respected ----

    def test_custom_start_time(self) -> None:
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        docs = self.gen.generate("dns_suspicious", count=3, start_time=t0)
        assert docs[0]["@timestamp"].startswith("2025-01-01T12:00:00")

    # ---- sim scenario metadata tag ----

    def test_sim_scenario_tag(self) -> None:
        docs = self.gen.generate("malware_or_c2", count=2)
        for doc in docs:
            assert doc.get("_sim_scenario") == "malware_or_c2"


# ============================================================
# TestSimPublisher
# ============================================================

class TestSimPublisher:

    def test_ensure_index_creates_when_missing(self) -> None:
        pub, mock_es = _make_publisher()
        mock_es.indices.exists.return_value = False
        pub.ensure_index()
        mock_es.indices.create.assert_called_once()

    def test_ensure_index_skips_when_exists(self) -> None:
        pub, mock_es = _make_publisher()
        mock_es.indices.exists.return_value = True
        pub.ensure_index()
        mock_es.indices.create.assert_not_called()

    def test_publish_returns_success_count(self) -> None:
        pub, mock_es = _make_publisher()
        docs = EventGenerator(interval_ms=50).generate("web_attack", count=5)

        # Mock the bulk helper to return (5 successes, 0 errors)
        with patch("simulator.sim_publisher.bulk", return_value=(5, [])) as mock_bulk:
            result = pub.publish(docs)

        assert result == 5
        mock_bulk.assert_called_once()

    def test_publish_empty_returns_zero(self) -> None:
        pub, _ = _make_publisher()
        assert pub.publish([]) == 0

    def test_publish_strips_es_metadata_keys(self) -> None:
        """_es_index and _es_id must not appear in the indexed _source."""
        pub, mock_es = _make_publisher()
        gen = EventGenerator()
        docs = gen.generate("port_scan", count=2)

        captured_actions: list[dict] = []

        def fake_bulk(es, actions, **kwargs):
            captured_actions.extend(actions)
            return (len(actions), [])

        with patch("simulator.sim_publisher.bulk", side_effect=fake_bulk):
            pub.publish(docs)

        for action in captured_actions:
            source = action.get("_source", {})
            assert "_es_index" not in source
            assert "_es_id" not in source

    def test_clear_index_calls_delete_by_query(self) -> None:
        pub, mock_es = _make_publisher()
        mock_es.delete_by_query.return_value = {"deleted": 10}
        result = pub.clear_index()
        assert result == 10
        mock_es.delete_by_query.assert_called_once()


# ============================================================
# TestReplayRunner
# ============================================================

class TestReplayRunner:

    def _write_temp(self, docs: list[dict], tmp_path: Path) -> Path:
        p = tmp_path / "events.json"
        p.write_text(json.dumps(docs), encoding="utf-8")
        return p

    def test_replay_publishes_correct_count(self, tmp_path: Path) -> None:
        gen = EventGenerator(interval_ms=50)
        docs = gen.generate("dos_or_flood", count=4)

        pub, _ = _make_publisher()
        with patch("simulator.sim_publisher.bulk", return_value=(4, [])):
            runner = ReplayRunner(publisher=pub)
            count = runner.replay(self._write_temp(docs, tmp_path))

        assert count == 4

    def test_replay_missing_file_returns_zero(self, tmp_path: Path) -> None:
        pub, _ = _make_publisher()
        runner = ReplayRunner(publisher=pub)
        result = runner.replay(tmp_path / "does_not_exist.json")
        assert result == 0

    def test_replay_invalid_json_returns_zero(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json!!", encoding="utf-8")
        pub, _ = _make_publisher()
        runner = ReplayRunner(publisher=pub)
        assert runner.replay(p) == 0

    def test_replay_retimestamps_to_now(self, tmp_path: Path) -> None:
        """After replay, all timestamps should be close to now."""
        gen = EventGenerator(interval_ms=50)
        docs = gen.generate("ssh_bruteforce", count=3)

        pub, _ = _make_publisher()
        retimestamped: list[dict] = []

        def capture_publish(captured_docs):
            retimestamped.extend(captured_docs)
            return len(captured_docs)

        with patch.object(pub, "publish", side_effect=capture_publish):
            runner = ReplayRunner(publisher=pub)
            runner.replay(self._write_temp(docs, tmp_path), retimestamp=True)

        now = datetime.now(timezone.utc)
        for doc in retimestamped:
            ts = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
            diff = abs((now - ts).total_seconds())
            assert diff < 10, f"Timestamp too far from now: {diff}s"

    def test_replay_no_retimestamp(self, tmp_path: Path) -> None:
        """With retimestamp=False, original timestamps are preserved."""
        gen = EventGenerator(interval_ms=50)
        docs = gen.generate("dns_suspicious", count=2)
        original_ts = docs[0]["@timestamp"]

        pub, _ = _make_publisher()
        published_docs: list[dict] = []

        def capture(d):
            published_docs.extend(d)
            return len(d)

        with patch.object(pub, "publish", side_effect=capture):
            runner = ReplayRunner(publisher=pub)
            runner.replay(self._write_temp(docs, tmp_path), retimestamp=False)

        assert published_docs[0]["@timestamp"] == original_ts


# ============================================================
# TestScenarioRunner
# ============================================================

class TestScenarioRunner:

    def _mocked_runner(self) -> tuple[ScenarioRunner, list[dict]]:
        pub, mock_es = _make_publisher()
        published_docs: list[dict] = []

        def capture(docs):
            published_docs.extend(docs)
            return len(docs)

        pub.publish = capture  # type: ignore[method-assign]
        gen = EventGenerator(interval_ms=50)
        runner = ScenarioRunner(publisher=pub, generator=gen)
        return runner, published_docs

    def test_run_returns_published_count(self) -> None:
        runner, docs = self._mocked_runner()
        result = runner.run("port_scan", count=10)
        assert result == 10

    def test_run_all_covers_every_scenario(self) -> None:
        runner, docs = self._mocked_runner()
        results = runner.run_all(count=5)
        assert set(results.keys()) == set(EventGenerator.SCENARIOS)
        assert all(v == 5 for v in results.values())

    def test_run_unknown_scenario_handled_gracefully(self) -> None:
        runner, _ = self._mocked_runner()
        results = runner.run_all(scenarios=["nonexistent"], count=5)
        assert results["nonexistent"] == 0

    def test_run_passes_correct_src_ip(self) -> None:
        runner, docs = self._mocked_runner()
        runner.run("malware_or_c2", src_ip="1.2.3.4", count=3)
        for doc in docs:
            assert doc["suricata"]["eve"]["src_ip"] == "1.2.3.4"


# ============================================================
# TestHelpers
# ============================================================

class TestHelpers:

    def test_set_nested_ts_updates_eve_timestamp(self) -> None:
        doc = {"suricata": {"eve": {"timestamp": "old"}}}
        _set_nested_ts(doc, "2025-01-01T00:00:00.000Z")
        assert doc["suricata"]["eve"]["timestamp"] == "2025-01-01T00:00:00.000Z"

    def test_set_nested_ts_safe_when_no_eve(self) -> None:
        doc: dict = {}
        _set_nested_ts(doc, "2025-01-01T00:00:00.000Z")  # must not raise
