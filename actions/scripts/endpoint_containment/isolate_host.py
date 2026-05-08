"""
ACT-014 — Isolate Host from Network

Disconnects the container from the DMZ network by setting iptables
policies to DROP and detaching the Docker network.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class IsolateHost(BaseAction):
    ACTION_ID = "ACT-014"
    ACTION_NAME = "Isolate Host from Network"
    ACTION_CLASS = "endpoint_containment"
    TIMEOUT_SECONDS = 20

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_network = self._get(context, "dmz_network", "dmz_net")

        self._log("Isolating container from DMZ", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would isolate host")

        # Set restrictive iptables policies
        self.docker.exec_command(container, "iptables -P INPUT DROP")
        self.docker.exec_command(container, "iptables -P OUTPUT DROP")
        self.docker.exec_command(container, "iptables -P FORWARD DROP")

        # Disconnect from DMZ
        success = self.docker.disconnect_network(container, dmz_network)

        return self._make_result(
            context,
            status="success" if success else "failure",
            output=f"container {container} disconnected from {dmz_network}",
            metadata={"container": container, "network": dmz_network},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_network = self._get(context, "dmz_network", "dmz_net")
        self.docker.exec_command(container, "iptables -P INPUT ACCEPT")
        self.docker.exec_command(container, "iptables -P OUTPUT ACCEPT")
        success = self.docker.connect_network(container, dmz_network)
        return self._make_result(
            context,
            status="success" if success else "failure",
            output=f"reconnected to {dmz_network}",
        )
