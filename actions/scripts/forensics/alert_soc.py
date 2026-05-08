"""
ACT-035 — Alert SOC Team

Emits a high-priority structured log event to alert the SOC team.
This is a notification-only action with no destructive side-effects.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class AlertSOC(BaseAction):
    ACTION_ID = "ACT-035"
    ACTION_NAME = "Alert SOC Team"
    ACTION_CLASS = "forensics"
    TIMEOUT_SECONDS = 5

    def execute(self, context: dict[str, Any]) -> ActionResult:
        attack_type = self._get(context, "attack_type", "unknown")
        source_ip = self._get(context, "source_ip", "unknown")
        container = self._get(context, "container_id", "unknown")

        self._log(
            "SOC ALERT",
            attack_type=attack_type,
            source_ip=source_ip,
            container=container,
        )

        return self._make_result(
            context,
            status="success",
            exit_code=0,
            output="SOC team alerted via structured log event",
            metadata={
                "alert_type": "soc_notification",
                "attack_type": attack_type,
                "source_ip": source_ip,
                "container": container,
            },
        )
