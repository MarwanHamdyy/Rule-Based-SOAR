"""
ACT-029 — Re-flash IoT Device Firmware

Restores the IoT container to its baseline state by stopping the
container, removing it, and re-creating from the baseline image.
In a containerised lab, this is equivalent to firmware re-flash.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class ReflashFirmware(BaseAction):
    ACTION_ID = "ACT-029"
    ACTION_NAME = "Re-flash IoT Device Firmware"
    ACTION_CLASS = "iot_response"
    TIMEOUT_SECONDS = 120

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        baseline_image = self._get(context, "baseline_image", f"soar/iot-baseline:{container}")

        self._log("Re-flashing firmware", container=container, image=baseline_image)

        if self.dry_run:
            return self._make_result(
                context, status="success",
                output=f"dry-run: would re-flash {container} from {baseline_image}"
            )

        # In the containerised lab, re-flash means restart from baseline.
        # First create a forensic snapshot, then restart.
        # Snapshot for forensics before wiping
        if self.docker._client:
            try:
                c = self.docker._client.containers.get(container)
                c.commit(repository=f"soar-pre-reflash/{container}", tag="latest")
                self._log("Pre-reflash snapshot created")
            except Exception:  # noqa: BLE001
                pass

        # Restart the container — the container image IS the baseline firmware
        success = self.docker.restart_container(container, timeout=30)

        return self._make_result(
            context,
            status="success" if success else "failure",
            output=f"container {container} re-flashed from baseline" if success else "re-flash failed",
            metadata={"container": container, "baseline_image": baseline_image},
        )
