"""
ACT-019 — Capture Network PCAP from Host

Runs tcpdump inside the container for a configurable duration to
capture network traffic for forensic analysis.
"""

from __future__ import annotations

from typing import Any

from actions.base_action import BaseAction
from actions.action_result import ActionResult


class CapturePCAP(BaseAction):
    ACTION_ID = "ACT-019"
    ACTION_NAME = "Capture Network PCAP from Host"
    ACTION_CLASS = "forensics"
    TIMEOUT_SECONDS = 60

    def execute(self, context: dict[str, Any]) -> ActionResult:
        container = self._sanitize_container_id(self._get(context, "container_id"))
        action_id = self._get(context, "action_id", "unknown")
        interface = self._sanitize_interface(
            self._get(context, "interface", "eth0"), "interface"
        )
        duration = int(self._get(context, "pcap_duration", "30"))
        output_path = f"/tmp/soar_pcap_{action_id[:8]}.pcap"

        self._log("Starting PCAP capture", container=container, path=output_path)

        if self.dry_run:
            return self._make_result(context, status="success", output="dry-run: would capture PCAP")

        exit_code, output = self.docker.capture_pcap(
            container, interface=interface, duration=duration, output_path=output_path
        )

        return self._make_result(
            context,
            status="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            output=output or f"PCAP capture started at {output_path}",
            metadata={
                "pcap_path": output_path,
                "container": container,
                "interface": interface,
                "duration": duration,
            },
        )
