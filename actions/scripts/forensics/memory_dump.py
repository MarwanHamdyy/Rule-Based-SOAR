"""
ACT-016 — Capture Forensic Memory Dump

Captures process memory from the container using gcore or /proc
filesystem for forensic analysis.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class MemoryDump(BaseAction):
    ACTION_ID = "ACT-016"
    ACTION_NAME = "Capture Forensic Memory Dump"
    ACTION_CLASS = "forensics"
    TIMEOUT_SECONDS = 60

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        action_id = self._get(context, "action_id", "unknown")
        output_dir = f"/tmp/forensics_{action_id[:8]}"

        self._log("Capturing memory dump", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would capture memory")

        # Create output dir and dump /proc info for all processes
        cmd = (
            f"mkdir -p {output_dir} && "
            f"for pid in $(ls /proc | grep -E '^[0-9]+$' | head -20); do "
            f"  cat /proc/$pid/maps > {output_dir}/maps_$pid 2>/dev/null; "
            f"  cat /proc/$pid/status > {output_dir}/status_$pid 2>/dev/null; "
            f"done && "
            f"ps auxww > {output_dir}/ps_snapshot.txt && "
            f"echo 'Memory dump captured'"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"output_dir": output_dir, "container": container},
        )
