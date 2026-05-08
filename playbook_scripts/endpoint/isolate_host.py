"""
playbook_scripts/endpoint/isolate_host.py
------------------------------------------
ACT-014 — Isolate Host from Network
ACT-015 — Enforce Full Quarantine Isolation
ACT-019 — Capture Network PCAP from Host

Endpoint containment scripts for IoT containers.
Isolation moves the container off the DMZ network.
Full quarantine additionally connects it to the quarantine network.
"""

from __future__ import annotations

import time
from typing import Any

from playbook_scripts.base_script import BaseScript, ScriptResult


class IsolateHostScript(BaseScript):
    """
    ACT-014 — Disconnect container from the DMZ network.
    The container loses all external connectivity but keeps loopback.
    """
    SCRIPT_NAME = "isolate_host"
    ACTION_CLASS = "endpoint_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        dmz_network  = context.get("dmz_network", "dmz_net")

        self._log_action("Isolating container from DMZ", container=container_id)

        # First, block all traffic to limit damage while we disconnect
        self.docker.exec_command(container_id, "iptables -P INPUT DROP")
        self.docker.exec_command(container_id, "iptables -P OUTPUT DROP")
        self.docker.exec_command(container_id, "iptables -P FORWARD DROP")

        success = self.docker.disconnect_network(container_id, dmz_network)

        if success:
            self._log_action("Container isolated successfully", container=container_id)
        else:
            self._log_error("Failed to disconnect container", container=container_id)

        return ScriptResult(
            success=success,
            output=f"container {container_id} disconnected from {dmz_network}",
            rollback_fn="rollback",
            metadata={"container": container_id, "network": dmz_network},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        dmz_network  = context.get("dmz_network", "dmz_net")
        self._log_action("Rolling back — reconnecting to DMZ", container=container_id)
        # Restore default policy first
        self.docker.exec_command(container_id, "iptables -P INPUT ACCEPT")
        self.docker.exec_command(container_id, "iptables -P OUTPUT ACCEPT")
        success = self.docker.connect_network(container_id, dmz_network)
        return ScriptResult(success=success, output=f"reconnected to {dmz_network}")


class QuarantineHostScript(BaseScript):
    """
    ACT-015 — Full quarantine: disconnect from DMZ + connect to quarantine network.
    The quarantine network has no internet access but allows management access
    from the SOAR engine for forensics.
    """
    SCRIPT_NAME = "quarantine_host"
    ACTION_CLASS = "endpoint_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        container_id        = self._get(context, "container_id")
        dmz_network         = context.get("dmz_network", "dmz_net")
        quarantine_network  = context.get("quarantine_network", "quarantine_net")

        self._log_action("Full quarantine", container=container_id)

        # Step 1: block all iptables
        self.docker.exec_command(container_id, "iptables -P INPUT DROP")
        self.docker.exec_command(container_id, "iptables -P OUTPUT DROP")

        # Step 2: disconnect from DMZ
        ok1 = self.docker.disconnect_network(container_id, dmz_network)

        # Step 3: connect to quarantine network
        ok2 = self.docker.connect_network(container_id, quarantine_network)

        success = ok1 and ok2
        if success:
            self._log_action("Container fully quarantined", container=container_id)
        else:
            self._log_error("Quarantine partially failed", container=container_id, ok1=ok1, ok2=ok2)

        return ScriptResult(
            success=success,
            output=f"container moved: {dmz_network} → {quarantine_network}",
            rollback_fn="rollback",
            metadata={
                "container": container_id,
                "from_network": dmz_network,
                "to_network": quarantine_network,
            },
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        container_id       = self._get(context, "container_id")
        dmz_network        = context.get("dmz_network", "dmz_net")
        quarantine_network = context.get("quarantine_network", "quarantine_net")
        self.docker.disconnect_network(container_id, quarantine_network)
        ok = self.docker.connect_network(container_id, dmz_network)
        self.docker.exec_command(container_id, "iptables -P INPUT ACCEPT")
        self.docker.exec_command(container_id, "iptables -P OUTPUT ACCEPT")
        return ScriptResult(success=ok, output=f"restored to {dmz_network}")


class CapturePCAPScript(BaseScript):
    """
    ACT-019 — Capture forensic network traffic from the container's interface.
    Runs tcpdump for 30 seconds inside the container.
    """
    SCRIPT_NAME = "capture_pcap"
    ACTION_CLASS = "forensics"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        action_id    = self._get(context, "action_id", "unknown")
        output_path  = f"/tmp/soar_pcap_{action_id[:8]}.pcap"

        self._log_action("Starting PCAP capture", container=container_id, path=output_path)

        exit_code, output = self.docker.capture_pcap(
            container_id,
            interface="eth0",
            duration=30,
            output_path=output_path,
        )

        return ScriptResult(
            success=exit_code == 0,
            exit_code=exit_code,
            output=output or f"PCAP capture started at {output_path}",
            metadata={"pcap_path": output_path, "container": container_id},
        )
