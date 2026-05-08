"""
playbook_scripts/network/block_source_ip.py
--------------------------------------------
ACT-001 — Block Source IP Address

Inserts an iptables DROP rule for the attacker's source IP inside
the targeted IoT container. This is the primary containment action
used in most attack playbooks.
"""

from __future__ import annotations

from typing import Any

from playbook_scripts.base_script import BaseScript, ScriptResult


class BlockSourceIPScript(BaseScript):
    SCRIPT_NAME = "block_source_ip"
    ACTION_CLASS = "network_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        src_ip       = self._get(context, "source_ip")
        container_id = self._get(context, "container_id")

        if not src_ip or src_ip == "unknown":
            return ScriptResult(success=False, output="source_ip not available in context")

        self._log_action("Blocking source IP", src_ip=src_ip, container=container_id)

        exit_code, output = self.docker.block_ip_in_container(container_id, src_ip)
        success = exit_code == 0

        if success:
            self._log_action("IP blocked successfully", src_ip=src_ip)
        else:
            self._log_error("Failed to block IP", src_ip=src_ip, output=output)

        return ScriptResult(
            success=success,
            exit_code=exit_code,
            output=output,
            rollback_fn="rollback",
            metadata={"blocked_ip": src_ip, "container": container_id},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        src_ip       = self._get(context, "source_ip")
        container_id = self._get(context, "container_id")
        self._log_action("Rolling back — unblocking IP", src_ip=src_ip)
        exit_code, output = self.docker.unblock_ip_in_container(container_id, src_ip)
        return ScriptResult(success=exit_code == 0, exit_code=exit_code, output=output)
