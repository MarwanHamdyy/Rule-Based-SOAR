"""
ACT-028 — Restart IoT Device

Performs a clean Docker restart of the IoT container.  Self-healing
agents restart automatically on container start.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RestartIoT(BaseAction):
    ACTION_ID = "ACT-028"
    ACTION_NAME = "Restart IoT Device"
    ACTION_CLASS = "iot_response"
    TIMEOUT_SECONDS = 30

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Restarting IoT container", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would restart {container}")

        success = self.docker.restart_container(container, timeout=15)

        return self._make_result(
            context,
            status="success" if success else "failure",
            output=f"container {container} restarted" if success else "restart failed",
            metadata={"container": container},
        )
