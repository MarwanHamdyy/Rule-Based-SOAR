"""
ACT-021 — Lock User Account After Brute Force

Locks the user account and terminates all active sessions for that
user after brute-force detection.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class LockUserBruteForce(BaseAction):
    ACTION_ID = "ACT-021"
    ACTION_NAME = "Lock User Account After Brute Force"
    ACTION_CLASS = "identity_response"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        username = self._sanitize_username(self._get(context, "username"), "username")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Locking account after brute force", username=username, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would lock {username}")

        # Lock account and kill all user processes
        cmds = [
            f"usermod -L {username}",
            f"pkill -u {username} 2>/dev/null || true",
        ]
        results = []
        for cmd in cmds:
            ec, out = self.docker.exec_command(container, cmd)
            results.append((ec, out))

        # Lock success is what matters (first command)
        success = results[0][0] == 0
        output = " | ".join(out for _, out in results if out)

        return self._make_result(
            context,
            status="success" if success else "failure",
            exit_code=results[0][0],
            output=output,
            metadata={"username": username, "container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        username = self._sanitize_username(self._get(context, "username"), "username")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        exit_code, output = self.docker.unlock_user_account(container, username)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
