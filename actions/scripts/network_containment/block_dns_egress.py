"""
ACT-013 — Block DNS Egress from Host

Prevents the container from sending DNS queries to external resolvers
by blocking outbound UDP and TCP port 53.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockDNSEgress(BaseAction):
    ACTION_ID = "ACT-013"
    ACTION_NAME = "Block DNS Egress from Host"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Blocking DNS egress", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would block DNS egress")

        cmd = (
            "iptables -I OUTPUT -p udp --dport 53 -j DROP && "
            "iptables -I OUTPUT -p tcp --dport 53 -j DROP"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        cmd = (
            "iptables -D OUTPUT -p udp --dport 53 -j DROP; "
            "iptables -D OUTPUT -p tcp --dport 53 -j DROP"
        )
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
