"""
ACT-034 — Disable SNMP Write Access

Removes SNMP write community strings and restarts the SNMP daemon
to prevent unauthorized configuration changes via SNMP SET.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class DisableSNMPWrite(BaseAction):
    ACTION_ID = "ACT-034"
    ACTION_NAME = "Disable SNMP Write Access"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        conf_path = self._get(context, "snmp_conf_path", "/etc/snmp/snmpd.conf")

        self._log("Disabling SNMP write access", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would disable SNMP write")

        # Comment out rwcommunity lines and restart SNMP
        cmd = (
            f"sed -i 's/^rwcommunity/#rwcommunity/' {conf_path} && "
            f"sed -i 's/^rwuser/#rwuser/' {conf_path} && "
            f"service snmpd restart 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"container": container, "conf_path": conf_path},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        conf_path = self._get(context, "snmp_conf_path", "/etc/snmp/snmpd.conf")
        cmd = (
            f"sed -i 's/^#rwcommunity/rwcommunity/' {conf_path} && "
            f"sed -i 's/^#rwuser/rwuser/' {conf_path} && "
            f"service snmpd restart 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
