"""
ACT-008 — Block C2 Destination IP

Blocks outbound traffic from the IoT container to a known C2 server
by inserting an iptables OUTPUT DROP rule.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockC2IP(BaseAction):
    ACTION_ID = "ACT-008"
    ACTION_NAME = "Block C2 Destination IP"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        dst_ip = self._sanitize_ipv4(self._get(context, "destination_ip"), "destination_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Blocking C2 destination IP", dst_ip=dst_ip, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would block C2 IP")

        exit_code, output = self.docker.block_outbound_ip(container, dst_ip)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"blocked_c2_ip": dst_ip, "container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        dst_ip = self._sanitize_ipv4(self._get(context, "destination_ip"), "destination_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        cmd = f"iptables -D OUTPUT -d {dst_ip} -j DROP"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
