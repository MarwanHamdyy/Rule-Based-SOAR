"""
ACT-007 — Block DNS Domain via Sinkhole

Adds a sinkhole entry to ``/etc/hosts`` inside the container, redirecting
the malicious domain to ``127.0.0.1``.  Used for C2 domains, DGA domains,
and .onion resolution attempts.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class BlockDNSSinkhole(BaseAction):
    ACTION_ID = "ACT-007"
    ACTION_NAME = "Block DNS Domain via Sinkhole"
    ACTION_CLASS = "network_containment"
    TIMEOUT_SECONDS = 15

    def execute(self, context: dict[str, Any]) -> ActionResult:
        domain = self._sanitize_domain(self._get(context, "domain"), "domain")
        container = self._sanitize_container_id(self._get(context, "container_id"))

        self._log("Sinkholing domain", domain=domain, container=container)

        if self.dry_run:
            return self._make_result(context, status="success", output=f"dry-run: would sinkhole {domain}")

        # Add sinkhole entry and flush DNS cache if available
        cmd = (
            f'echo "127.0.0.1 {domain}" >> /etc/hosts && '
            f'echo "::1 {domain}" >> /etc/hosts'
        )
        exit_code, output = self.docker.exec_command(container, cmd)

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
            metadata={"sinkholed_domain": domain, "container": container},
        )

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        domain = self._sanitize_domain(self._get(context, "domain"), "domain")
        container = self._sanitize_container_id(self._get(context, "container_id"))
        # Remove sinkhole entries (grep -v to filter out the domain)
        cmd = f"sed -i '/{domain}/d' /etc/hosts"
        exit_code, output = self.docker.exec_command(container, cmd)
        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output,
        )
