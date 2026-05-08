"""
ACT-033 — Disable Anonymous FTP Access

Modifies the vsftpd configuration inside the container to disable
anonymous FTP login and restarts the service.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class DisableAnonFTP(BaseAction):
    ACTION_ID = "ACT-033"
    ACTION_NAME = "Disable Anonymous FTP Access"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        conf_path = self._get(context, "ftp_conf_path", "/etc/vsftpd.conf")

        self._log("Disabling anonymous FTP", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would disable anon FTP")

        cmd = (
            f"sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' {conf_path} && "
            f"service vsftpd restart 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container, "conf_path": conf_path},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        conf_path = self._get(context, "ftp_conf_path", "/etc/vsftpd.conf")
        cmd = (
            f"sed -i 's/^anonymous_enable=NO/anonymous_enable=YES/' {conf_path} && "
            f"service vsftpd restart 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
