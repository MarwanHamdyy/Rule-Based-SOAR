"""
ACT-010 — Flush Rogue DHCP Leases

Clears the DHCP lease file and restarts the DHCP service inside the
container to invalidate leases handed out by a rogue DHCP server.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class FlushDHCPLeases(BaseAction):
    ACTION_ID = "ACT-010"
    ACTION_NAME = "Flush Rogue DHCP Leases"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        lease_file = self._get(context, "dhcp_lease_file", "/var/lib/dhcp/dhcpd.leases")

        self._log("Flushing DHCP leases", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would flush DHCP leases")

        cmd = (
            f"> {lease_file} && "
            f"service isc-dhcp-server restart 2>/dev/null || "
            f"dhclient -r 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container, "lease_file": lease_file},
        )
