"""
ACT-017 — Collect Endpoint Logs for Analysis

Copies critical log files from the container for forensic review.
Collects syslog, auth.log, application logs, and service logs.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class CollectLogs(BaseAction):
    ACTION_ID = "ACT-017"
    ACTION_NAME = "Collect Endpoint Logs for Analysis"
    ACTION_CLASS = "forensics"
    TIMEOUT_SECONDS = 45

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        action_id = self._get(context, "action_id", "unknown")
        output_dir = f"/tmp/logs_forensics_{action_id[:8]}"

        self._log("Collecting endpoint logs", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would collect logs")

        cmd = (
            f"mkdir -p {output_dir} && "
            f"cp /var/log/syslog {output_dir}/ 2>/dev/null; "
            f"cp /var/log/auth.log {output_dir}/ 2>/dev/null; "
            f"cp /var/log/messages {output_dir}/ 2>/dev/null; "
            f"cp /var/log/secure {output_dir}/ 2>/dev/null; "
            f"cp /var/log/apache2/*.log {output_dir}/ 2>/dev/null; "
            f"cp /var/log/nginx/*.log {output_dir}/ 2>/dev/null; "
            f"journalctl --no-pager -n 500 > {output_dir}/journal.txt 2>/dev/null; "
            f"last -50 > {output_dir}/last_logins.txt 2>/dev/null; "
            f"echo 'Log collection complete'"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"output_dir": output_dir, "container": container},
        )
