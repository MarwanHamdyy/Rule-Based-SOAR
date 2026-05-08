"""
ACT-009 — Block DMZ-to-Internal Connection

Inserts an iptables FORWARD rule that blocks traffic from the DMZ
subnet to the internal subnet, preventing lateral movement from
compromised DMZ hosts.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockDMZInternal(BaseAction):
    ACTION_ID = "ACT-009"
    ACTION_NAME = "Block DMZ-to-Internal Connection"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_subnet = self._sanitize_subnet(
            self._get(context, "dmz_subnet", "172.20.0.0/24"), "dmz_subnet"
        )
        internal_subnet = self._sanitize_subnet(
            self._get(context, "internal_subnet", "192.168.1.0/24"), "internal_subnet"
        )

        self._log("Blocking DMZ-to-Internal", dmz=dmz_subnet, internal=internal_subnet)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would block DMZ→Internal")

        cmd = f"iptables -I FORWARD -s {dmz_subnet} -d {internal_subnet} -j DROP"
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"dmz_subnet": dmz_subnet, "internal_subnet": internal_subnet},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_subnet = self._sanitize_subnet(
            self._get(context, "dmz_subnet", "172.20.0.0/24"), "dmz_subnet"
        )
        internal_subnet = self._sanitize_subnet(
            self._get(context, "internal_subnet", "192.168.1.0/24"), "internal_subnet"
        )
        cmd = f"iptables -D FORWARD -s {dmz_subnet} -d {internal_subnet} -j DROP"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
