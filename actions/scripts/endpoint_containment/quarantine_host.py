"""
ACT-015 — Enforce Full Quarantine Isolation

Disconnects the container from DMZ and connects it to the quarantine
network.  The quarantine network has no internet access but allows
management from the SOAR engine for forensic collection.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class QuarantineHost(BaseAction):
    ACTION_ID = "ACT-015"
    ACTION_NAME = "Enforce Full Quarantine Isolation"
    ACTION_CLASS = "endpoint_containment"
    TIMEOUT_SECONDS = 25

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        dmz_network = self._get(context, "dmz_network", "dmz_net")
        quarantine_network = self._get(context, "quarantine_network", "quarantine_net")

        self._log("Full quarantine", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would quarantine")

        # Lock down iptables
        self.docker.exec_command(container, "iptables -P INPUT DROP")
        self.docker.exec_command(container, "iptables -P OUTPUT DROP")

        # Move networks
        ok1 = self.docker.disconnect_network(container, dmz_network)
        ok2 = self.docker.connect_network(container, quarantine_network)

        success = ok1 and ok2
        return self._make_result(
            context,
            status="success" if success else "failure",
            output=f"container moved: {dmz_network} → {quarantine_network}",
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
            output=f"restored to {dmz_network}",
        )
