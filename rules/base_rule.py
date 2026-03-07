"""
rules/base_rule.py
-------------------
Abstract base class for all SOAR detection rules.

Every rule must:
  1. Declare a unique ``RULE_ID`` class attribute.
  2. Implement ``evaluate(event, correlation_stats)`` returning a
     :class:`RuleMatch` if triggered, or *None* if not.

This design means new rules can be added without touching any existing
code – just drop a new module in `rules/` and register it in
`rule_engine.py`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent


@dataclass
class RuleMatch:
    """
    Produced by a rule when it fires.

    All fields are used downstream in :class:`~actions.action_builder.ActionBuilder`
    to construct a structured SOAR action document.
    """
    rule_id: str                          # e.g. "SOAR-001"
    attack_type: str                      # e.g. "port_scan"
    priority: str                         # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: float                     # 0.0 – 1.0
    recommended_mitigation: str           # Human-readable suggestion
    reasons: list[str] = field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    owasp_ref: str = ""
    nist_ref: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class BaseRule(ABC):
    """
    Abstract base class for deterministic detection rules.

    Sub-classes must set:
      - ``RULE_ID``   – unique string identifier.
      - ``ATTACK_TYPE`` – attack category name (used in output docs).
    """

    RULE_ID: str = "SOAR-000"
    ATTACK_TYPE: str = "unknown"

    @abstractmethod
    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        """
        Evaluate whether this rule fires for *event*.

        Args:
            event:  The normalised Suricata event currently being processed.
            stats:  Correlation statistics from all windows for ``event.src_ip``.
            config: Rule-specific config from ``thresholds.yaml``.

        Returns:
            A :class:`RuleMatch` if the rule fires, or *None*.
        """

    # ------------------------------------------------------------------
    # Helper utilities available to all sub-classes
    # ------------------------------------------------------------------

    @staticmethod
    def _keyword_match(text: str, keywords: list[str]) -> bool:
        """Return True if any keyword appears (case-insensitive) in *text*."""
        lowered = text.lower()
        return any(kw.lower() in lowered for kw in keywords)

    @staticmethod
    def _priority_from_severity(severity: int) -> str:
        """Map Suricata severity (1–3) to SOAR priority label."""
        return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(severity, "LOW")
