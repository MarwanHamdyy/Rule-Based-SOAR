"""
ACT-020 — Disable User Account

Locks a user account using ``usermod -L`` inside the container to
prevent further login attempts.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class DisableUser(BaseAction):
    ACTION_ID = "ACT-020"
    ACTION_NAME = "Disable User Account"
    ACTION_CLASS = "identity_response"
    TIMEOUT_SECONDS = 10

    def execute(self, context: dict[str, Any]) -> ActionResult:
        username = self._sanitize_username(self._get(context, "username"), "username")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Disabling user account", username=username, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would disable {username}")

        exit_code, output = self.docker.lock_user_account(container, username)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
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
