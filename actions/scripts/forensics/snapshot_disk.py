"""
ACT-018 — Snapshot Disk Image for Forensics

Creates a Docker commit of the container's current state to preserve
the filesystem as a forensic image for later analysis.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class SnapshotDisk(BaseAction):
    ACTION_ID = "ACT-018"
    ACTION_NAME = "Snapshot Disk Image for Forensics"
    ACTION_CLASS = "forensics"
    TIMEOUT_SECONDS = 120

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        action_id = self._get(context, "action_id", "unknown")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        image_tag = f"soar-forensic/{container}:{ts}_{action_id[:8]}"

        self._log("Creating forensic snapshot", container=container, tag=image_tag)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would snapshot as {image_tag}")

        # Use docker commit via exec — requires the Docker socket
        # In the SOAR context the DockerAdapter wraps the Docker SDK,
        # so we call exec_command to trigger a commit from within
        cmd = f"echo 'Snapshot initiated — tag: {image_tag}'"
        exit_code, output = self.docker.exec_command(container, cmd)

        # The actual commit happens via the Docker SDK if available
        if self.docker._client:
            try:
                c = self.docker._client.containers.get(container)
                c.commit(repository=f"soar-forensic/{container}", tag=f"{ts}_{action_id[:8]}")
                output = f"Forensic image created: {image_tag}"
                exit_code = 0
            except Exception as exc:  # noqa: BLE001
                output = f"Docker commit failed: {exc}"
                exit_code = 1
        else:
            output = "Docker client not available — snapshot skipped"
            exit_code = 1

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"image_tag": image_tag, "container": container},
        )
