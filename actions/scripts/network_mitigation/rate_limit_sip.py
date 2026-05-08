"""
ACT-032 — Rate-Limit SIP INVITE Requests

Applies iptables rate limiting on UDP port 5060 to throttle SIP
INVITE floods against VoIP services on the container.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RateLimitSIP(BaseAction):
    ACTION_ID = "ACT-032"
    ACTION_NAME = "Rate-Limit SIP INVITE Requests"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Rate-limiting SIP INVITE", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would rate-limit SIP")

        cmd = (
            "iptables -I INPUT -p udp --dport 5060 "
            "-m hashlimit --hashlimit-mode srcip "
            "--hashlimit-above 5/min --hashlimit-burst 10 "
            "--hashlimit-name sip_ratelimit -j DROP"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container, "port": 5060},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        cmd = (
            "iptables -D INPUT -p udp --dport 5060 "
            "-m hashlimit --hashlimit-name sip_ratelimit -j DROP"
        )
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
