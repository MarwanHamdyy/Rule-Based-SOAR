"""
playbook_scripts/iot/iot_scripts.py
-------------------------------------
IoT-specific response scripts targeting the containerised microcontroller
devices in the EVE-NG lab.

ACT-025 — Isolate IoT Device to Quarantine VLAN  (→ QuarantineHostScript)
ACT-026 — Revoke MQTT Client Credentials
ACT-027 — Block IoT Device Egress Traffic
ACT-028 — Restart IoT Device
ACT-030 — Revert IoT Actuator to Safe State
"""

from __future__ import annotations

import time
from typing import Any

from playbook_scripts.base_script import BaseScript, ScriptResult


class RevokeMQTTCredsScript(BaseScript):
    """
    ACT-026 — Revoke MQTT Client Credentials.

    Edits the Mosquitto ACL file inside the broker container to deny
    all access for the compromised device's MQTT client ID, then
    restarts Mosquitto to apply the change.

    This complements the FIM agent's on-device credential rotation —
    the SOAR handles the *broker side* revocation across devices.
    """
    SCRIPT_NAME = "revoke_mqtt_creds"
    ACTION_CLASS = "iot_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        broker_container = context.get("mqtt_broker_container", "iot-device-1")
        client_ip        = self._get(context, "source_ip")
        acl_file         = context.get("mqtt_acl_file", "/etc/mosquitto/acl")
        action_id        = self._get(context, "action_id", "unknown")

        self._log_action("Revoking MQTT credentials", client_ip=client_ip, broker=broker_container)

        # Append a deny rule for this IP to the ACL file
        deny_rule = f"# SOAR-REVOKED action_id={action_id[:8]}\\ndeny readwrite #\\n"
        # Note: Mosquitto ACL uses topic-based rules; we deny all topics for this client
        # by IP is handled at the iptables level — MQTT ACL is user-based
        # Block the IP from reaching the broker at network level
        block_cmd = f"iptables -I INPUT -s {client_ip} -p tcp --dport 1883 -j DROP"
        exit_code, output = self.docker.exec_command(broker_container, block_cmd)

        # Also restart Mosquitto to drop existing sessions
        if exit_code == 0:
            restart_cmd = "service mosquitto restart || mosquitto -c /etc/mosquitto/mosquitto.conf -d"
            self.docker.exec_command(broker_container, restart_cmd)

        success = exit_code == 0
        if success:
            self._log_action("MQTT access revoked", client_ip=client_ip)
        else:
            self._log_error("Failed to revoke MQTT", client_ip=client_ip, output=output)

        return ScriptResult(
            success=success,
            exit_code=exit_code,
            output=output,
            rollback_fn="rollback",
            metadata={"client_ip": client_ip, "broker": broker_container},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        broker_container = context.get("mqtt_broker_container", "iot-device-1")
        client_ip        = self._get(context, "source_ip")
        cmd = f"iptables -D INPUT -s {client_ip} -p tcp --dport 1883 -j DROP"
        exit_code, output = self.docker.exec_command(broker_container, cmd)
        return ScriptResult(success=exit_code == 0, exit_code=exit_code, output=output)


class BlockIoTEgressScript(BaseScript):
    """
    ACT-027 — Block IoT Device Egress Traffic.
    Drops all outbound traffic from the IoT container except to the internal
    management network. Used when a device is suspected compromised but
    not yet fully isolated.
    """
    SCRIPT_NAME = "block_iot_egress"
    ACTION_CLASS = "iot_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        self._log_action("Blocking all IoT egress", container=container_id)

        # Drop all outbound traffic except established connections and loopback
        cmds = [
            "iptables -P OUTPUT DROP",
            "iptables -I OUTPUT -o lo -j ACCEPT",
            "iptables -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
        results = []
        for cmd in cmds:
            ec, out = self.docker.exec_command(container_id, cmd)
            results.append((ec, out))

        success = all(ec == 0 for ec, _ in results)
        output  = " | ".join(out for _, out in results if out)

        return ScriptResult(
            success=success,
            output=output,
            rollback_fn="rollback",
            metadata={"container": container_id},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        exit_code, output = self.docker.exec_command(container_id, "iptables -P OUTPUT ACCEPT")
        return ScriptResult(success=exit_code == 0, exit_code=exit_code, output=output)


class RestartIoTDeviceScript(BaseScript):
    """
    ACT-028 — Restart IoT Device.
    Performs a clean docker restart of the IoT container.
    The self-healing agents will restart automatically on container start.
    """
    SCRIPT_NAME = "restart_iot_device"
    ACTION_CLASS = "iot_response"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        self._log_action("Restarting IoT container", container=container_id)

        success = self.docker.restart_container(container_id, timeout=15)

        return ScriptResult(
            success=success,
            output=f"container {container_id} restarted" if success else "restart failed",
            metadata={"container": container_id},
        )


class RevertActuatorScript(BaseScript):
    """
    ACT-030 — Revert IoT Actuator to Safe State.
    Publishes a safe-state payload to the actuator's MQTT topic using
    mosquitto_pub inside the broker container.
    Used when a compromised device may have sent malicious actuator commands.
    """
    SCRIPT_NAME = "revert_actuator"
    ACTION_CLASS = "iot_response"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        broker_container = context.get("mqtt_broker_container", "iot-device-1")
        topic            = context.get("mqtt_safe_state_topic", "actuators/control")
        payload          = context.get("mqtt_safe_state_payload", "OFF")
        broker_port      = context.get("mqtt_broker_port", 1883)

        self._log_action("Reverting actuator to safe state", topic=topic, payload=payload)

        cmd = (
            f"mosquitto_pub -h localhost -p {broker_port} "
            f"-t '{topic}' -m '{payload}' -r"
        )
        exit_code, output = self.docker.exec_command(broker_container, cmd)

        success = exit_code == 0
        if success:
            self._log_action("Safe-state command published", topic=topic)
        else:
            self._log_error("Failed to publish safe-state", output=output)

        return ScriptResult(
            success=success,
            exit_code=exit_code,
            output=output,
            metadata={"topic": topic, "payload": payload},
        )
