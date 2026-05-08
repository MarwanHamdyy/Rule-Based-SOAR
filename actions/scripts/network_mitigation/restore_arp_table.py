"""
ACT-012 — Restore ARP Table Entries

Restores static ARP entries from a known-good baseline to counteract
ARP spoofing / poisoning attacks.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RestoreARPTable(BaseAction):
    ACTION_ID = "ACT-012"
    ACTION_NAME = "Restore ARP Table Entries"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        gateway_ip = self._sanitize_ipv4(
            self._get(context, "gateway_ip", "192.168.1.1"), "gateway_ip"
        )
        gateway_mac = self._sanitize_mac(
            self._get(context, "gateway_mac", "00:00:00:00:00:00"), "gateway_mac"
        )

        self._log("Restoring ARP table", container=container, gateway=gateway_ip)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would restore ARP")

        # Flush ARP cache and set static entry for the gateway
        cmd = (
            f"ip neigh flush all && "
            f"arp -s {gateway_ip} {gateway_mac}"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={
                "gateway_ip": gateway_ip,
                "gateway_mac": gateway_mac,
                "container": container,
            },
        )
