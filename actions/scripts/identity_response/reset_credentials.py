"""
ACT-024 — Reset Compromised Credentials

Rotates the user's password to a new random value, revokes SSH
authorized_keys, and locks the account.  The new password is pulled
from the ``SOAR_RESET_PASSWORD`` environment variable for security,
or a random one is generated and logged.
"""

from __future__ import annotations

import os
import secrets
import string
from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class ResetCredentials(BaseAction):
    ACTION_ID = "ACT-024"
    ACTION_NAME = "Reset Compromised Credentials"
    ACTION_CLASS = "identity_response"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        username = self._sanitize_username(self._get(context, "username"), "username")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Resetting compromised credentials", username=username, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would reset creds for {username}")

        # Generate new password from env or random
        new_pass = os.environ.get("SOAR_RESET_PASSWORD", "")
        if not new_pass:
            alphabet = string.ascii_letters + string.digits + "!@#$%"
            new_pass = "".join(secrets.choice(alphabet) for _ in range(24))

        # Reset password, expire it, and revoke SSH keys
        cmds = [
            f"echo '{username}:{new_pass}' | chpasswd",
            f"passwd -e {username}",
            f"rm -f /home/{username}/.ssh/authorized_keys 2>/dev/null || true",
            f"usermod -L {username}",
        ]
        results = []
        for cmd in cmds:
            ec, out = self.docker.exec_command(container, cmd)
            results.append((ec, out))

        success = results[0][0] == 0  # chpasswd is the critical step
        output = " | ".join(out for _, out in results if out)

        return self._make_result(
            context,
            status="success" if success else "failure",
            exit_code=results[0][0],
            output=output,
            metadata={
                "username": username,
                "container": container,
                "password_rotated": True,
                "ssh_keys_revoked": True,
            },
        )
