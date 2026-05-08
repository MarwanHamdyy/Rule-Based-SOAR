"""
ACT-005 — Add WAF Block Rule

Appends a deny rule to the web application firewall configuration
(Nginx deny directive) inside the container to block an offending IP
from HTTP/HTTPS access.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class AddWAFRule(BaseAction):
    ACTION_ID = "ACT-005"
    ACTION_NAME = "Add WAF Block Rule"
    ACTION_CLASS = "network_mitigation"
    TIMEOUT_SECONDS = 20

    def execute(self, context: dict[str, Any]) -> ActionResult:
        src_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        conf_path = self._get(context, "waf_conf_path", "/etc/nginx/conf.d/block.conf")

        self._log("Adding WAF block rule", src_ip=src_ip, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would add WAF rule")

        # Append deny directive and reload Nginx
        cmd = (
            f'echo "deny {src_ip};" >> {conf_path} && '
            f"nginx -s reload 2>/dev/null || service apache2 reload 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"blocked_ip": src_ip, "conf_path": conf_path},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        src_ip = self._sanitize_ipv4(self._get(context, "source_ip"), "source_ip")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        conf_path = self._get(context, "waf_conf_path", "/etc/nginx/conf.d/block.conf")
        cmd = (
            f"sed -i '/deny {src_ip}/d' {conf_path} && "
            f"nginx -s reload 2>/dev/null || true"
        )
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
