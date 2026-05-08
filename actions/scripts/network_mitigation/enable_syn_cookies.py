"""
ACT-006 — Enable SYN Cookies on Server

Enables TCP SYN cookies via sysctl to mitigate SYN flood attacks
against the container.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class EnableSYNCookies(BaseAction):
    ACTION_ID = "ACT-006"
    ACTION_NAME = "Enable SYN Cookies on Server"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 10

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Enabling SYN cookies", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would enable SYN cookies")

        cmd = "sysctl -w net.ipv4.tcp_syncookies=1"
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container, "sysctl": "net.ipv4.tcp_syncookies=1"},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        cmd = "sysctl -w net.ipv4.tcp_syncookies=0"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
