"""
ACT-003 — Block Source MAC Address

Inserts an iptables rule that drops frames from the specified MAC
address inside the container.  Used for layer-2 attacks such as
ARP spoofing and MAC flooding.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockSourceMAC(BaseAction):
    ACTION_ID = "ACT-003"
    ACTION_NAME = "Block Source MAC Address"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        mac = self._sanitize_mac(self._get(context, "source_mac"), "source_mac")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Blocking source MAC", mac=mac, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would block MAC")

        cmd = f"iptables -I INPUT -m mac --mac-source {mac} -j DROP"
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"blocked_mac": mac, "container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        mac = self._sanitize_mac(self._get(context, "source_mac"), "source_mac")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        cmd = f"iptables -D INPUT -m mac --mac-source {mac} -j DROP"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
