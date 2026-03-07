"""
rules/web_attack.py
--------------------
SOAR-003: Web Application Attack Detection

Fires for SQL injection, XSS, directory traversal, web scanners, and
other HTTP-based attack signatures.
"""

from __future__ import annotations

from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent
from rules.base_rule import BaseRule, RuleMatch


class WebAttackRule(BaseRule):
    RULE_ID = "SOAR-003"
    ATTACK_TYPE = "web_attack"

    def evaluate(
        self,
        event: NormalizedEvent,
        stats: dict[str, WindowStats],
        config: dict,
    ) -> RuleMatch | None:
        cfg = config.get("web_attack", {})
        count_threshold = int(cfg.get("event_count_threshold", 5))
        keywords: list[str] = cfg.get("category_keywords", ["web", "http", "sql", "xss"])

        is_web = (
            event.dst_port in (80, 443, 8080, 8443)
            or self._keyword_match(event.signature, keywords)
            or self._keyword_match(event.category, keywords)
        )
        if not is_web:
            return None

        w = stats.get("medium", WindowStats())  # 60-second window
        if w.event_count < count_threshold:
            return None

        # Identify the specific web attack sub-type for the reason narrative
        sub_type = "Generic Web Attack"
        sig_lower = event.signature.lower()
        cat_lower = event.category.lower()
        if "sql" in sig_lower or "sql" in cat_lower:
            sub_type = "SQL Injection"
        elif "xss" in sig_lower or "cross-site" in sig_lower:
            sub_type = "Cross-Site Scripting (XSS)"
        elif "traversal" in sig_lower or "path" in sig_lower:
            sub_type = "Directory / Path Traversal"
        elif "scan" in sig_lower or "nikto" in sig_lower:
            sub_type = "Web Scanner"

        reasons = [
            f"Detected {sub_type}: {w.event_count} web alerts from {event.src_ip} in 60 s.",
            f"Signature: \"{event.signature}\".",
            f"Category: \"{event.category}\".",
        ]

        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority=str(cfg.get("priority", "MEDIUM")),
            confidence=float(cfg.get("confidence", 0.80)),
            recommended_mitigation=(
                f"Block source IP at WAF/perimeter. "
                f"Review {sub_type} indicators in web server access logs. "
                "Patch vulnerable web endpoints and enable WAF rules targeting OWASP Top-10."
            ),
            reasons=reasons,
            mitre_tactic="Initial Access",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            owasp_ref="OWASP-A03:2021 Injection / OWASP-A01:2021 Broken Access Control",
        )
