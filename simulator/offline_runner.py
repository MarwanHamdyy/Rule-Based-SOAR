"""
simulator/offline_runner.py
----------------------------
Runs the full SOAR pipeline entirely in memory — no Elasticsearch required.

Flow:
    raw docs (EventGenerator or JSON file)
        → EventNormalizer
        → CorrelationState  (sliding windows)
        → RuleEngine         (8 detection rules)
        → ActionBuilder      (structured action doc)
        → console + optional JSON/CSV output file

Usage::

    runner = OfflineRunner(config_dir="./config")
    results = runner.run_docs(docs)
    runner.print_results(results)
    runner.save_results(results, "output/actions.json")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actions.action_builder import ActionBuilder
from correlator.state_manager import CorrelationState
from mappings.framework_mapper import FrameworkMapper
from normalizer.event_normalizer import EventNormalizer
from rules.rule_engine import RuleEngine
from utils.config_loader import load_settings
from utils.logger import get_logger

logger = get_logger(__name__)

# ANSI colour codes (safe on Windows 10+ terminals)
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_DIM    = "\033[2m"

_PRIORITY_COLOURS = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "MEDIUM":   _YELLOW,
    "LOW":      _CYAN,
}


class OfflineRunner:
    """
    Processes raw Suricata documents through the complete SOAR pipeline
    without any Elasticsearch connection.

    Args:
        config_dir: Path to the ``config/`` directory containing
                    ``settings.yaml`` and ``thresholds.yaml``.
    """

    def __init__(self, config_dir: str = "./config") -> None:
        cfg = load_settings(config_dir)
        thresholds = cfg.get("thresholds", {})

        window_cfg = thresholds.get("correlation", {}).get("windows", {})
        rule_config = thresholds.get("rules", {})

        self._normalizer     = EventNormalizer()
        self._correlation    = CorrelationState(
            windows={
                "short":    int(window_cfg.get("short",    30)),
                "medium":   int(window_cfg.get("medium",   60)),
                "long":     int(window_cfg.get("long",     300)),
                "extended": int(window_cfg.get("extended", 900)),
            } if window_cfg else None
        )
        self._rule_engine    = RuleEngine(rule_config)
        self._action_builder = ActionBuilder(framework_mapper=FrameworkMapper())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_docs(self, raw_docs: list[dict]) -> list[dict[str, Any]]:
        """
        Pass *raw_docs* through the full pipeline and return action docs.

        Args:
            raw_docs: List of raw Suricata ``_source`` dicts
                      (same format as what the ES collector returns).

        Returns:
            List of SOAR action documents (same schema as a real ES-backed run).
        """
        actions: list[dict[str, Any]] = []

        for raw in raw_docs:
            event = self._normalizer.normalize(raw)
            if event is None:
                continue

            self._correlation.ingest(event)
            stats = self._correlation.query(event.src_ip)
            matches = self._rule_engine.evaluate(event, stats)

            for match in matches:
                action_doc = self._action_builder.build(event, match, enrichment={})
                actions.append(action_doc)

        self._correlation.purge_expired()
        return actions

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def print_results(self, actions: list[dict[str, Any]], scenario: str = "") -> None:
        """Pretty-print action results to the terminal."""
        _enable_colour()
        header = f"  SOAR Engine — Offline Run Results  "
        if scenario:
            header = f"  SOAR Engine — Scenario: {scenario}  "

        width = max(60, len(header) + 4)
        bar   = "═" * width

        print(f"\n{_CYAN}{_BOLD}╔{bar}╗{_RESET}")
        print(f"{_CYAN}{_BOLD}║{header.center(width)}║{_RESET}")
        print(f"{_CYAN}{_BOLD}╚{bar}╝{_RESET}\n")

        if not actions:
            print(f"{_YELLOW}  ⚠  No rules triggered. Try a higher --count or different scenario.{_RESET}\n")
            return

        for i, action in enumerate(actions, start=1):
            priority     = action.get("priority", "?")
            colour       = _PRIORITY_COLOURS.get(priority, _RESET)
            rule_id      = action.get("rule_id", "?")
            attack_type  = action.get("attack_type", "?")
            src_ip       = action.get("source_ip", "?")
            dst_ip       = action.get("destination_ip", "?")
            dst_port     = action.get("destination_port", "?")
            confidence   = action.get("confidence", 0)
            risk_score   = action.get("risk_score", 0)
            mitigation   = action.get("recommended_mitigation", "")
            reasons      = action.get("reasons", [])
            framework    = action.get("framework_mapping", {})

            print(f"{colour}{'─' * width}{_RESET}")
            print(f"{colour}{_BOLD}  [{i}] {rule_id} │ {priority} │ {attack_type.upper()}{_RESET}")
            print(f"      Source IP   : {_BOLD}{src_ip}{_RESET}  →  {dst_ip}:{dst_port}")
            print(f"      Confidence  : {confidence:.0%}   Risk Score: {risk_score}")

            if framework:
                mitre = framework.get("mitre_technique", "")
                if mitre:
                    print(f"      MITRE       : {_DIM}{mitre}{_RESET}")

            print(f"\n      {_BOLD}Why it fired:{_RESET}")
            for r in reasons:
                print(f"        • {r}")

            print(f"\n      {_BOLD}Recommended action:{_RESET}")
            # Wrap long mitigation text to 70 chars
            words = mitigation.split()
            line, lines = [], []
            for w in words:
                if sum(len(x) + 1 for x in line) + len(w) > 70:
                    lines.append(" ".join(line))
                    line = [w]
                else:
                    line.append(w)
            if line:
                lines.append(" ".join(line))
            for ln in lines:
                print(f"        {_GREEN}{ln}{_RESET}")
            print()

        print(f"{_CYAN}{'─' * width}{_RESET}")
        print(f"{_BOLD}  Total actions triggered: {len(actions)}{_RESET}\n")

    def save_results(
        self,
        actions: list[dict[str, Any]],
        output_path: str | Path,
    ) -> None:
        """
        Save action documents to a JSON file.

        Args:
            actions:     Action docs returned by :meth:`run_docs`.
            output_path: File path to write (created if not exists).
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_actions": len(actions),
            "actions": actions,
        }
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

        print(f"  💾  Results saved → {output_path.resolve()}\n")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _enable_colour() -> None:
    """Enable ANSI escape codes on Windows."""
    if os.name == "nt":
        os.system("")  # noqa: S605 – needed to activate VT100 on Windows
