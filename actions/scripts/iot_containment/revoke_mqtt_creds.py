"""
ACT-026 — Revoke MQTT Client Credentials

Blocks the compromised IoT device from reaching the MQTT broker at
the network level (iptables on the broker container) and restarts
Mosquitto to drop existing sessions.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RevokeMQTTCreds(BaseAction):
    ACTION_ID = "ACT-026"
    ACTION_NAME = "Revoke MQTT Client Credentials"
    ACTION_CLASS = "iot_containment"
    TIMEOUT_SECONDS = 20

    def execute(self, context: dict[str, Any]) -> ActionResult:
        broker_container = self._get(context, "mqtt_broker_container", "iot-device-1")
        client_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        broker_port = self._sanitize_port(
            self._get(context, "mqtt_broker_port", "1883"), "mqtt_broker_port"
        )

        self._log("Revoking MQTT credentials", client_ip=client_ip, broker=broker_container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would revoke MQTT for {client_ip}")

        # Block at network level
        block_cmd = f"iptables -I INPUT -s {client_ip} -p tcp --dport {broker_port} -j DROP"
        exit_code, output = self.docker.exec_command(broker_container, block_cmd)

        # Restart Mosquitto to drop existing sessions
        if exit_code == 0:
            restart_cmd = "service mosquitto restart || mosquitto -c /etc/mosquitto/mosquitto.conf -d"
            self.docker.exec_command(broker_container, restart_cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"client_ip": client_ip, "broker": broker_container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        broker_container = self._get(context, "mqtt_broker_container", "iot-device-1")
        client_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        broker_port = self._sanitize_port(
            self._get(context, "mqtt_broker_port", "1883"), "mqtt_broker_port"
        )
        cmd = f"iptables -D INPUT -s {client_ip} -p tcp --dport {broker_port} -j DROP"
        exit_code, output = self.docker.exec_command(broker_container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
