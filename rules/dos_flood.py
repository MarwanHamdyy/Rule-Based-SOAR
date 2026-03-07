"""
rules/dos_flood.py
-------------------
SOAR-006: Denial-of-Service / Flood Detection

Fires when a source generates an extremely high volume of alerts in
a very short window — typical of SYN floods, UDP amplification attacks,
or other volumetric DoS/DDoS activity.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class DoSFloodRule(BaseRule):
    RULE_ID = "SOAR-006"
    ATTACK_TYPE = "dos_or_flood"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("dos_or_flood", {})
        count_threshold = int(cfg.get("event_count_threshold", 50))
        keywords: list[str] = cfg.get("category_keywords", [
            "dos", "flood", "ddos", "amplification", "syn"
        ])

        is_dos = (
            self._keyword_match(event.signature, keywords)
            or self._keyword_match(event.category, keywords)
        )

        w = stats.get("short", WindowStats())  # 30-second window – DoS is fast

        if not is_dos and w.event_count < count_threshold:
            return None
        if is_dos and w.event_count < max(5, count_threshold // 5):
            return None

        reasons = []
        if is_dos:
            reasons.append(
                f"DoS/flood signature: \"{event.signature}\" "
                f"(category: {event.category})."
            )
        if w.event_count >= count_threshold:
            reasons.append(
                f"Extreme alert volume: {w.event_count} events in 30 s "
                f"(threshold: {count_threshold})."
            )
        reasons.append(
            f"Target: {event.dst_ip}:{event.dst_port} proto={event.proto}."
        )

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=str(cfg.get("priority", "HIGH")),
            confidence=float(cfg.get("confidence", 0.85)),
            recommended_mitigation=(
                "Activate rate-limiting rules on the perimeter firewall targeting this source IP. "
                "Contact upstream ISP to null-route the source if DDoS is confirmed. "
                "Enable anti-spoofing BCP38 filtering. "
                "Scale up target service capacity or activate DDoS scrubbing service."
            ),
            reasons=reasons,
            mitre_tactic="Impact",
            mitre_technique="T1498 - Network Denial of Service",
            nist_ref="NIST SP 800-61 Rev 2 - DoS Incident Handling",
        )
