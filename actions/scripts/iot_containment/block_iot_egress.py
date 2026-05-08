"""
ACT-027 — Block IoT Device Egress Traffic

Drops all outbound traffic from the IoT container except established
connections and loopback.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockIoTEgress(BaseAction):
    ACTION_ID = "ACT-027"
    ACTION_NAME = "Block IoT Device Egress Traffic"
    ACTION_CLASS = "iot_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Blocking all IoT egress", container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would block IoT egress")

        cmds = [
            "iptables -P OUTPUT DROP",
            "iptables -I OUTPUT -o lo -j ACCEPT",
            "iptables -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
        results = []
        for cmd in cmds:
            ec, out = self.docker.exec_command(container, cmd)
            results.append((ec, out))

        success = all(ec == 0 for ec, _ in results)
        output = " | ".join(out for _, out in results if out)

        return self._make_result(
            context,
            status="success" if success else "failure",
            output=output,
            metadata={"container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        exit_code, output = self.docker.exec_command(container, "iptables -P OUTPUT ACCEPT")
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
