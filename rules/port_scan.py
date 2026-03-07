"""
rules/port_scan.py
-------------------
SOAR-001: Port Scan Detection

Fires when a single source IP probes an unusually large number of
distinct destination ports within a short time window.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class PortScanRule(BaseRule):
    RULE_ID = "SOAR-001"
    ATTACK_TYPE = "port_scan"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("port_scan", {})
        port_threshold = int(cfg.get("unique_dst_ports_threshold", 15))
        count_threshold = int(cfg.get("event_count_threshold", 20))
        window_name = "medium"   # use the 60-second window by default

        w = stats.get(window_name, WindowStats())
        reasons: list[str] = []

        triggered = False

        if w.unique_dst_ports >= port_threshold:
            reasons.append(
                f"Source scanned {w.unique_dst_ports} unique destination ports "
                f"(threshold: {port_threshold}) in the last 60 s."
            )
            triggered = True

        if w.event_count >= count_threshold:
            reasons.append(
                f"Source generated {w.event_count} alerts (threshold: {count_threshold}) "
                f"in the last 60 s."
            )
            triggered = True

        if not triggered:
            return None

        confidence = float(cfg.get("confidence", 0.85))
        # Boost confidence when BOTH thresholds exceeded
        if len(reasons) == 2:
            confidence = min(1.0, confidence + 0.05)

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=str(cfg.get("priority", "HIGH")),
            confidence=confidence,
            recommended_mitigation=(
                "Block outbound connections from this source IP at the perimeter firewall. "
                "Review whether this IP belongs to an authorised scanner. "
                "Capture full packet headers for forensic analysis."
            ),
            reasons=reasons,
            mitre_tactic="Discovery",
            mitre_technique="T1046 - Network Service Scanning",
        )
