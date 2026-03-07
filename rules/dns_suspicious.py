"""
rules/dns_suspicious.py
------------------------
SOAR-005: Suspicious DNS Activity Detection

Fires on DNS tunnelling, excessive DNS queries, lookups to known
malicious domains, or other DNS-based anomalies.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class DNSSuspiciousRule(BaseRule):
    RULE_ID = "SOAR-005"
    ATTACK_TYPE = "dns_suspicious"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("dns_suspicious", {})
        count_threshold = int(cfg.get("event_count_threshold", 3))
        keywords: list[str] = cfg.get("category_keywords", ["dns", "domain", "tunnel", "exfil"])

        is_dns = (
            event.dst_port in (53, 5353)
            or event.proto == "udp"
            and self._keyword_match(event.signature, keywords)
            or self._keyword_match(event.category, keywords)
        )
        if not is_dns:
            return None

        w = stats.get("medium", WindowStats())  # 60-second window
        if w.event_count < count_threshold:
            return None

        sub_type = "Suspicious DNS Activity"
        if "tunnel" in event.signature.lower() or "tunnel" in event.category.lower():
            sub_type = "DNS Tunnelling"
        elif "exfil" in event.signature.lower():
            sub_type = "DNS Data Exfiltration"
        elif "dga" in event.signature.lower():
            sub_type = "Domain Generation Algorithm (DGA)"

        reasons = [
            f"{sub_type} detected: {w.event_count} DNS alerts from {event.src_ip} in 60 s.",
            f"Signature: \"{event.signature}\".",
        ]
        if event.dst_ip:
            reasons.append(f"Querying destination IP: {event.dst_ip}.")

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=str(cfg.get("priority", "MEDIUM")),
            confidence=float(cfg.get("confidence", 0.75)),
            recommended_mitigation=(
                "Block DNS queries to suspicious destinations at the DNS resolver/firewall. "
                "Enable DNS-over-HTTPS logging and monitor for long or high-entropy domain names. "
                "Investigate the querying host for malware indicators."
            ),
            reasons=reasons,
            mitre_tactic="Exfiltration",
            mitre_technique="T1048 - Exfiltration Over Alternative Protocol",
        )
