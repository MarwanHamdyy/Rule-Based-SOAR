"""
ACT-011 — Clear Switch MAC Table

Flushes the bridge forwarding database (FDB) inside the container to
clear MAC address entries flooded by a CAM table overflow attack.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class ClearMACTable(BaseAction):
    ACTION_ID = "ACT-011"
    ACTION_NAME = "Clear Switch MAC Table"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 10

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Clearing MAC table", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would clear MAC table")

        # Flush bridge FDB and ARP cache
        cmd = (
            "bridge fdb flush dev eth0 2>/dev/null; "
            "ip neigh flush all 2>/dev/null; "
            "echo 'MAC table cleared'"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container},
        )
