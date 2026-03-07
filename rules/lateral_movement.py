"""
rules/lateral_movement.py
--------------------------
SOAR-007: Lateral Movement Suspicion

Fires when an internal host begins communicating with an unusually
large number of other internal hosts — indicative of worm propagation,
PtH (Pass-the-Hash), or other lateral movement techniques.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class LateralMovementRule(BaseRule):
    RULE_ID = "SOAR-007"
    ATTACK_TYPE = "lateral_movement_suspicion"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("lateral_movement_suspicion", {})
        host_threshold = int(cfg.get("unique_dst_hosts_threshold", 5))
        keywords: list[str] = cfg.get("category_keywords", [
            "lateral", "smb", "rdp", "pass-the", "mimikatz"
        ])

        w = stats.get("long", WindowStats())   # 5-minute window

        is_lateral_sig = (
            self._keyword_match(event.signature, keywords)
            or self._keyword_match(event.category, keywords)
            or event.dst_port in (445, 135, 139, 3389)  # SMB / RPC / RDP
        )

        is_lateral_behaviour = w.unique_dst_ips >= host_threshold

        if not is_lateral_sig and not is_lateral_behaviour:
            return None

        reasons: list[str] = []
        if is_lateral_sig:
            reasons.append(
                f"Lateral movement signature matched: \"{event.signature}\" "
                f"(port {event.dst_port})."
            )
        if is_lateral_behaviour:
            reasons.append(
                f"Source {event.src_ip} contacted {w.unique_dst_ips} unique hosts "
                f"(threshold: {host_threshold}) in 5 min."
            )

        confidence = float(cfg.get("confidence", 0.78))
        if is_lateral_sig and is_lateral_behaviour:
            confidence = min(1.0, confidence + 0.10)

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=str(cfg.get("priority", "HIGH")),
            confidence=confidence,
            recommended_mitigation=(
                "Isolate the source host immediately for investigation. "
                "Audit Active Directory for credential compromise (check for suspicious logons). "
                "Enable network micro-segmentation to prevent further spread. "
                "Review EDR telemetry on the source host for process injection or credential dumping."
            ),
            reasons=reasons,
            mitre_tactic="Lateral Movement",
            mitre_technique="T1021 - Remote Services / T1550 - Use Alternate Authentication Material",
        )
