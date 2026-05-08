"""
ACT-004 — Shutdown Switch Port

Administratively disables the network interface on the target container
to simulate shutting down a switch port in the EVE-NG topology.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class ShutdownSwitchPort(BaseAction):
    ACTION_ID = "ACT-004"
    ACTION_NAME = "Shutdown Switch Port"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        interface = self._sanitize_interface(
            self._get(context, "interface", "eth0"), "interface"
        )

        self._log("Shutting down interface", interface=interface, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would shut port")

        cmd = f"ip link set {interface} down"
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"interface": interface, "container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        interface = self._sanitize_interface(
            self._get(context, "interface", "eth0"), "interface"
        )
        cmd = f"ip link set {interface} up"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
