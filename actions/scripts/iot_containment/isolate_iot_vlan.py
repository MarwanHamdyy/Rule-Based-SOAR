"""
ACT-025 — Isolate IoT Device to Quarantine VLAN

Moves the IoT container from its operational network to the quarantine
network.  Delegates to the same quarantine logic as ACT-015 but is
semantically distinct for IoT devices.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class IsolateIoTVLAN(BaseAction):
    ACTION_ID = "ACT-025"
    ACTION_NAME = "Isolate IoT Device to Quarantine VLAN"
    ACTION_CLASS = "iot_containment"
    TIMEOUT_SECONDS = 25

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_network = self._get(context, "dmz_network", "dmz_net")
        quarantine_network = self._get(context, "quarantine_network", "quarantine_net")

        self._log("Isolating IoT device to quarantine VLAN", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would isolate IoT to quarantine VLAN")

        # Block all traffic first
        self.docker.exec_command(container, "iptables -P INPUT DROP")
        self.docker.exec_command(container, "iptables -P OUTPUT DROP")

        # Move to quarantine
        ok1 = self.docker.disconnect_network(container, dmz_network)
        ok2 = self.docker.connect_network(container, quarantine_network)

        success = ok1 and ok2
        return self._make_result(
            context,
            status="success" if success else "failure",
            output=f"IoT device moved: {dmz_network} → {quarantine_network}",
            metadata={
                "container": container,
                "from_network": dmz_network,
                "to_network": quarantine_network,
            },
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_network = self._get(context, "dmz_network", "dmz_net")
        quarantine_network = self._get(context, "quarantine_network", "quarantine_net")
        self.docker.disconnect_network(container, quarantine_network)
        ok = self.docker.connect_network(container, dmz_network)
        self.docker.exec_command(container, "iptables -P INPUT ACCEPT")
        self.docker.exec_command(container, "iptables -P OUTPUT ACCEPT")
        return self._make_result(
            context,
            status="success" if ok else "failure",
            output=f"IoT device restored to {dmz_network}",
        )
