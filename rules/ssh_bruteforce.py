"""
rules/ssh_bruteforce.py
------------------------
SOAR-002: SSH Brute-Force Detection

Fires when repeated SSH-related Suricata alerts originate from the
same source IP within a short time window, indicating a credential
stuffing or dictionary attack against an SSH service.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class SSHBruteForceRule(BaseRule):
    RULE_ID = "SOAR-002"
    ATTACK_TYPE = "ssh_bruteforce"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("ssh_bruteforce", {})
        count_threshold = int(cfg.get("event_count_threshold", 8))
        keywords: list[str] = cfg.get("signatures_keywords", ["ssh", "brute", "authentication"])

        # Must be SSH-related alert
        is_ssh = (
            event.dst_port == 22
            or self._keyword_match(event.signature, keywords)
            or self._keyword_match(event.category, keywords)
        )
        if not is_ssh:
            return None

        w = stats.get("short", WindowStats())   # 30-second window
        if w.event_count < count_threshold:
            return None

        reasons = [
            f"SSH alert repeated {w.event_count} times (threshold: {count_threshold}) "
            f"in 30 s from {event.src_ip} → port {event.dst_port}.",
            f"Matched signature: \"{event.signature}\".",
        ]

        if event.risk_score > 0:
            reasons.append(f"Event risk_score: {event.risk_score:.1f}.")

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=str(cfg.get("priority", "HIGH")),
            confidence=float(cfg.get("confidence", 0.90)),
            recommended_mitigation=(
                "Immediately block the source IP via firewall ACL. "
                "Enforce SSH key-based authentication and disable password login. "
                "Notify the system owner and check for successful authentications in auth.log."
            ),
            reasons=reasons,
            mitre_tactic="Credential Access",
            mitre_technique="T1110 - Brute Force",
        )
