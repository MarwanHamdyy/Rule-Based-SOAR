"""
ACT-023 — Revoke Active Sessions for User

Terminates all active sessions (SSH, shell, etc.) for a compromised
user by killing their processes.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RevokeSessions(BaseAction):
    ACTION_ID = "ACT-023"
    ACTION_NAME = "Revoke Active Sessions for User"
    ACTION_CLASS = "identity_response"
    TIMEOUT_SECONDS = 10

    def execute(self, context: dict[str, Any]) -> ActionResult:
        username = self._sanitize_username(self._get(context, "username"), "username")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Revoking sessions", username=username, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would revoke sessions for {username}")

        # Kill all user processes and SSH sessions
        cmd = (
            f"pkill -KILL -u {username} 2>/dev/null; "
            f"loginctl terminate-user {username} 2>/dev/null; "
            f"echo 'Sessions revoked for {username}'"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"username": username, "container": container},
        )
