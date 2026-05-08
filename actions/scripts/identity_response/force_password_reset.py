"""
ACT-022 — Force Password Reset

Expires the user's password using ``passwd -e`` so they must
change it at next login.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class ForcePasswordReset(BaseAction):
    ACTION_ID = "ACT-022"
    ACTION_NAME = "Force Password Reset"
    ACTION_CLASS = "identity_response"
    TIMEOUT_SECONDS = 10

    def execute(self, context: dict[str, Any]) -> ActionResult:
        username = self._sanitize_username(self._get(context, "username"), "username")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Forcing password reset", username=username, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would expire password for {username}")

        cmd = f"passwd -e {username}"
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"username": username, "container": container},
        )
