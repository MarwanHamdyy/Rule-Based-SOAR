"""
rules/rule_engine.py
---------------------
Central dispatcher that evaluates every registered rule against each
incoming event and returns all matching :class:`~rules.base_rule.RuleMatch` objects.

Adding a new rule:
  1. Create a new module in `rules/` inheriting from `BaseRule`.
  2. Import it here and add an instance to ``RULES``.
  3. That's it — no other code needs to change.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch
from rules.port_scan import PortScanRule
from rules.ssh_bruteforce import SSHBruteForceRule
from rules.web_attack import WebAttackRule
from rules.malware_c2 import MalwareC2Rule
from rules.dns_suspicious import DNSSuspiciousRule
from rules.dos_flood import DoSFloodRule
from rules.lateral_movement import LateralMovementRule
from rules.generic_high_risk import GenericHighRiskRule
from utils.logger import get_logger

logger = get_logger(__name__)

# -----------------------------------------------------------------------
# All active rules — order matters only for logging clarity.
# Specific rules are listed before the generic catch-all (SOAR-008).
# -----------------------------------------------------------------------
RULES: list[BaseRule] = [
    PortScanRule(),
    SSHBruteForceRule(),
    WebAttackRule(),
    MalwareC2Rule(),
    DNSSuspiciousRule(),
    DoSFloodRule(),
    LateralMovementRule(),
    GenericHighRiskRule(),   # Must be last (catch-all)
]


class RuleEngine:
    """
    Evaluates all registered rules for a single normalised event.

    Args:
        rule_config: The ``thresholds.rules`` sub-dict from settings,
                     passed through to each rule's ``evaluate()`` call.
    """

    def __init__(self, rule_config: dict) -> None:
        self._config = rule_config
        logger.info(
            "RuleEngine initialised with %d rules: %s",
            len(RULES),
            [r.RULE_ID for r in RULES],
        )

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
    ) -> list[RuleMatch]:
        """
        Run all rules and return every match.

        Args:
            event: Normalised event to evaluate.
            stats: Correlation statistics from :class:`~correlator.state_manager.CorrelationState`.

        Returns:
            List of :class:`RuleMatch` (may be empty if no rule fires).
        """
        matches: list[RuleMatch] = []
        for rule in RULES:
            try:
                match = rule.evaluate(event, stats, self._config)
                if match:
                    logger.debug(
                        "Rule %s fired for %s → %s (priority=%s confidence=%.2f)",
                        match.rule_id,
                        event.src_ip,
                        match.attack_type,
                        match.priority,
                        match.confidence,
                    )
                    matches.append(match)
            except Exception as exc:  # noqa: BLE001
                logger.error("Rule %s raised exception: %s", rule.RULE_ID, exc, exc_info=True)

        return matches
