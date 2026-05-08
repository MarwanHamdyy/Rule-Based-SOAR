"""
ACT-002 — Rate-Limit Source IP Traffic

Applies iptables hashlimit module to throttle traffic from a
scanning or flooding source IP inside the container.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class RateLimitIP(BaseAction):
    ACTION_ID = "ACT-002"
    ACTION_NAME = "Rate-Limit Source IP Traffic"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        src_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Rate-limiting source IP", src_ip=src_ip, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would rate-limit")

        hl_name = f"ratelimit_{src_ip.replace('.', '_')}"
        cmd = (
            f"iptables -I INPUT -s {src_ip} -m hashlimit "
            f"--hashlimit-mode srcip --hashlimit-above 10/min "
            f"--hashlimit-burst 20 --hashlimit-name {hl_name} "
            f"-j DROP"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"rate_limited_ip": src_ip, "hashlimit_name": hl_name},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        src_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        hl_name = f"ratelimit_{src_ip.replace('.', '_')}"
        cmd = f"iptables -D INPUT -s {src_ip} -m hashlimit --hashlimit-name {hl_name} -j DROP"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
