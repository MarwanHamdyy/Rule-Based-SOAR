"""
ACT-031 — Isolate Rogue DHCP Server Port

Blocks DHCP server traffic (UDP ports 67-68) from the compromised
container to prevent rogue DHCP responses on the network.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class IsolateRogueDHCP(BaseAction):
    ACTION_ID = "ACT-031"
    ACTION_NAME = "Isolate Rogue DHCP Server Port"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Isolating rogue DHCP server", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would isolate DHCP")

        # Block outbound DHCP offers (port 68) and inbound DHCP requests (port 67)
        cmds = [
            "iptables -I OUTPUT -p udp --sport 67 -j DROP",
            "iptables -I OUTPUT -p udp --sport 68 -j DROP",
            "iptables -I INPUT -p udp --dport 67 -j DROP",
        ]
        results = []
        for cmd in cmds:
            ec, out = self.docker.exec_command(container, cmd)
            results.append((ec, out))

        success = all(ec == 0 for ec, _ in results)
        output = " | ".join(out for _, out in results if out)

        return self._make_result(
            context,
            status="success" if success else "failure",
            exit_code=0 if success else 1,
            output=output,
            metadata={"container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        cmds = [
            "iptables -D OUTPUT -p udp --sport 67 -j DROP",
            "iptables -D OUTPUT -p udp --sport 68 -j DROP",
            "iptables -D INPUT -p udp --dport 67 -j DROP",
        ]
        for cmd in cmds:
            self.docker.exec_command(container, cmd)
        return self._make_result(context, status="success", output="DHCP isolation removed")
