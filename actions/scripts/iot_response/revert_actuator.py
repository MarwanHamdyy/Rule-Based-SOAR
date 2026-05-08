"""
ACT-030 — Revert IoT Actuator to Safe State

Publishes a safe-state payload to the actuator's MQTT topic using
``mosquitto_pub`` inside the broker container.  Used when a compromised
device may have sent malicious actuator commands.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RevertActuator(BaseAction):
    ACTION_ID = "ACT-030"
    ACTION_NAME = "Revert IoT Actuator to Safe State"
    ACTION_CLASS = "iot_response"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        broker_container = self._get(context, "mqtt_broker_container", "iot-device-1")
        topic = self._get(context, "mqtt_safe_state_topic", "actuators/control")
        payload = self._get(context, "mqtt_safe_state_payload", "OFF")
        broker_port = self._sanitize_port(
            self._get(context, "mqtt_broker_port", "1883"), "mqtt_broker_port"
        )

        self._log("Reverting actuator to safe state", topic=topic, payload=payload)

        if self.dry_run:
            return self._make_result(
                context, status="success",
                output=f"dry-run: would publish '{payload}' to '{topic}'"
            )

        cmd = (
            f"mosquitto_pub -h localhost -p {broker_port} "
            f"-t '{topic}' -m '{payload}' -r"
        )
        exit_code, output = self.docker.exec_command(broker_container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"topic": topic, "payload": payload, "broker": broker_container},
        )
