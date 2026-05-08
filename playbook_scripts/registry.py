"""
playbook_scripts/registry.py
------------------------------
Central registry mapping action_type strings (from mitigation_catalog.json)
to concrete script classes.

To add a new script: import the class and add it to ACTION_REGISTRY.
"""

from __future__ import annotations

from typing import Type

from adapters.docker_adapter import DockerAdapter
from playbook_scripts.base_script import BaseScript, ScriptResult
from playbook_scripts.network.block_source_ip import BlockSourceIPScript
from playbook_scripts.network.block_c2_ip import (
    BlockC2IPScript,
    BlockDNSEgressScript,
    RateLimitIPScript,
)
from playbook_scripts.endpoint.isolate_host import (
    IsolateHostScript,
    QuarantineHostScript,
    CapturePCAPScript,
)
from playbook_scripts.iot.iot_scripts import (
    RevokeMQTTCredsScript,
    BlockIoTEgressScript,
    RestartIoTDeviceScript,
    RevertActuatorScript,
)


class _AlertSOCScript(BaseScript):
    """ACT-035 — Alert SOC Team (log-only action, no execution needed)."""
    SCRIPT_NAME = "alert_soc"
    ACTION_CLASS = "forensics"

    def execute(self, context):
        self._log_action(
            "SOC ALERT",
            attack_type=context.get("attack_type"),
            source_ip=context.get("source_ip"),
            container=context.get("container_id"),
        )
        return ScriptResult(success=True, output="SOC alerted via logs")


class _NoOpScript(BaseScript):
    """Fallback no-op for action types not yet implemented."""
    SCRIPT_NAME = "noop"
    ACTION_CLASS = "generic"

    def execute(self, context):
        self._log_action(
            "No script implemented for action_type",
            action_type=context.get("action_type", "unknown"),
        )
        return ScriptResult(success=True, output="no-op")


# -----------------------------------------------------------------------
# Master mapping: mitigation_catalog action_type → script class
# -----------------------------------------------------------------------
ACTION_REGISTRY: dict[str, Type[BaseScript]] = {
    # Network containment
    "block_source_ip":            BlockSourceIPScript,
    "rate_limit_source_ip":       RateLimitIPScript,
    "block_c2_destination_ip":    BlockC2IPScript,
    "block_dns_egress":           BlockDNSEgressScript,

    # Endpoint containment
    "isolate_host":               IsolateHostScript,
    "full_quarantine":            QuarantineHostScript,
    "capture_pcap":               CapturePCAPScript,

    # IoT response
    "revoke_mqtt_credentials":    RevokeMQTTCredsScript,
    "block_iot_egress":           BlockIoTEgressScript,
    "restart_iot_device":         RestartIoTDeviceScript,
    "revert_actuator":            RevertActuatorScript,
    "isolate_iot_quarantine":     QuarantineHostScript,  # same as endpoint quarantine

    # Notification
    "alert_soc_team":             _AlertSOCScript,

    # Aliases used in mitigation_catalog.json action_type field
    "block_source_ip_address":    BlockSourceIPScript,
    "rate-limit_source_ip":       RateLimitIPScript,
    "block_c2_ip":                BlockC2IPScript,
    "isolate_host_network":       IsolateHostScript,
    "quarantine_host":            QuarantineHostScript,
    "capture_forensic_pcap":      CapturePCAPScript,
}


class ScriptRegistry:
    """
    Resolves an action_type string to an instantiated script object.

    Args:
        docker:  Shared DockerAdapter instance.
        dry_run: If True, all scripts are in dry-run mode.
    """

    def __init__(self, docker: DockerAdapter, dry_run: bool = False) -> None:
        self._docker  = docker
        self._dry_run = dry_run
        self._cache:  dict[str, BaseScript] = {}

    def get(self, action_type: str) -> BaseScript:
        """
        Return (cached) script instance for the given action_type.
        Falls back to _NoOpScript if action_type is not registered.
        """
        key = action_type.lower().replace(" ", "_").replace("-", "_")
        if key not in self._cache:
            cls = ACTION_REGISTRY.get(key, _NoOpScript)
            self._cache[key] = cls(docker=self._docker, dry_run=self._dry_run)
        return self._cache[key]
