"""
ACT-001 — Block Source IP Address

Inserts an iptables DROP rule for the attacker's source IP inside
the targeted IoT container.  This is the primary containment action
used in most attack playbooks.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockSourceIP(BaseAction):
    ACTION_ID = "ACT-001"
    ACTION_NAME = "Block Source IP Address"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        src_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Blocking source IP", src_ip=src_ip, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would block IP")

        exit_code, output = self.docker.block_ip_in_container(container, src_ip)
        status = "success" if exit_code == 0 else "failure"

        return self._make_result(
            context,
            status=status,
            exit_code=exit_code,
            output=output,
            metadata={"blocked_ip": src_ip, "container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        src_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        self._log("Rolling back — unblocking IP", src_ip=src_ip)
        exit_code, output = self.docker.unblock_ip_in_container(container, src_ip)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
