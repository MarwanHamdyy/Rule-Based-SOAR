"""
rules/generic_high_risk.py
---------------------------
SOAR-008: Generic High-Risk Alert

A catch-all rule that fires for any high-severity or high-risk-score
Suricata event that wasn't claimed by a more specific rule.
Ensures no severe alert goes unnoticed.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class GenericHighRiskRule(BaseRule):
    RULE_ID = "SOAR-008"
    ATTACK_TYPE = "generic_high_risk_alert"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("generic_high_risk_alert", {})
        min_risk_score = float(cfg.get("min_risk_score", 70))
        sev_threshold = int(cfg.get("severity_threshold", 2))

        is_high_risk = (
            event.risk_score >= min_risk_score
            or event.severity <= sev_threshold  # Suricata severity 1 or 2
        )

        if not is_high_risk:
            return None

        reasons: list[str] = []
        if event.severity <= sev_threshold:
            reasons.append(
                f"Suricata severity {event.severity} "
                f"(threshold ≤ {sev_threshold}) — high-priority alert."
            )
        if event.risk_score >= min_risk_score:
            reasons.append(
                f"risk_score={event.risk_score:.1f} exceeds threshold {min_risk_score}."
            )
        reasons.append(f"Signature: \"{event.signature}\".")

        priority = self._priority_from_severity(event.severity)

        # Confidence scales with how much thresholds were exceeded
        confidence = float(cfg.get("confidence", 0.70))
        if event.severity == 1 or event.risk_score >= 90:
            confidence = min(1.0, confidence + 0.15)
        elif event.severity == 2 or event.risk_score >= 75:
            confidence = min(1.0, confidence + 0.05)

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=priority,
            confidence=confidence,
            recommended_mitigation=(
                "Review this alert immediately in Kibana. "
                "Correlate with other events from the same source IP. "
                "Apply contextual threat intelligence to determine if escalation is warranted."
            ),
            reasons=reasons,
        )
