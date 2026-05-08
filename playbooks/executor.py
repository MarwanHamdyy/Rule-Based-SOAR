"""
playbooks/executor.py
----------------------
Runs the steps defined in a mitigation_catalog playbook entry against
the target IoT container.

Step execution flow:
    for each step in playbook.steps:
        1. Resolve action_type → script via ScriptRegistry
        2. Build context dict from action_doc + step params
        3. Execute script with timeout
        4. On success: log and continue
        5. On failure: retry up to max_retries, then escalate
        6. On final failure: execute rollback steps in reverse

All results are collected and returned for writing to soar-playbook-results-*.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from playbook_scripts.base_script import ScriptResult
from playbook_scripts.registry import ScriptRegistry
from utils.logger import get_logger

if TYPE_CHECKING:
    from actions.executor import ActionExecutor as _ActionExecutor

logger = get_logger(__name__)


@dataclass
class StepResult:
    """Result of a single playbook step execution."""
    step_index:  int
    phase:       str
    action_type: str
    success:     bool
    attempt:     int
    output:      str
    exit_code:   int = 0
    metadata:    dict[str, Any] = field(default_factory=dict)
    timestamp:   str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class PlaybookResult:
    """Aggregated result of a full playbook execution."""
    action_id:    str
    attack_type:  str
    attack_id:    str
    success:      bool
    step_results: list[StepResult]
    rollback_ran: bool = False
    total_steps:  int  = 0
    passed_steps: int  = 0
    timestamp:    str  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class PlaybookExecutor:
    """
    Executes the steps of a mitigation catalog playbook entry.

    Args:
        registry:    ScriptRegistry instance.
        max_retries: Number of retries per step before giving up.
        env_config:  Environment config dict (container names, networks, MQTT settings).
    """

    def __init__(
        self,
        registry:    ScriptRegistry,
        max_retries: int = 2,
        env_config:  dict[str, Any] | None = None,
        action_executor: "_ActionExecutor | None" = None,
    ) -> None:
        self._registry    = registry
        self._max_retries = max_retries
        self._env_config  = env_config or {}
        self._action_executor = action_executor

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        action_doc:   dict[str, Any],
        playbook_entry: dict[str, Any],
    ) -> PlaybookResult:
        """
        Execute the playbook for a SOAR action document.

        Args:
            action_doc:      SOAR action document (from soar-actions-* or IoT collector).
            playbook_entry:  Mitigation catalog entry for the detected attack type.

        Returns:
            PlaybookResult with all step outcomes.
        """
        action_id   = action_doc.get("action_id", "unknown")
        attack_type = action_doc.get("attack_type", "unknown")
        attack_id   = playbook_entry.get("attack_id", "unknown")

        logger.info(
            "PlaybookExecutor: starting playbook %s for action %s (attack_type=%s)",
            attack_id, action_id, attack_type,
        )

        playbook = playbook_entry.get("playbook", {})
        steps    = playbook.get("steps", [])

        if not steps:
            logger.warning("PlaybookExecutor: no steps defined for %s", attack_id)
            return PlaybookResult(
                action_id=action_id,
                attack_type=attack_type,
                attack_id=attack_id,
                success=True,
                step_results=[],
                total_steps=0,
                passed_steps=0,
            )

        # Build execution context from action doc + env config
        context = self._build_context(action_doc, playbook_entry)

        step_results: list[StepResult] = []
        rollback_stack: list[tuple[int, dict]] = []   # (step_index, context) for rollback
        overall_success = True

        for idx, step in enumerate(steps):
            phase       = step.get("phase", "response")
            action_type = step.get("action_type", "alert_soc_team")
            params      = step.get("parameters", {})

            # Merge step parameters into context
            step_context = {**context, **params, "action_type": action_type}

            result, attempt = self._execute_step_with_retry(
                step_index=idx,
                phase=phase,
                action_type=action_type,
                context=step_context,
            )

            step_results.append(StepResult(
                step_index=idx,
                phase=phase,
                action_type=action_type,
                success=result.success,
                attempt=attempt,
                output=result.output,
                exit_code=result.exit_code,
                metadata=result.metadata,
            ))

            if result.success and result.rollback_fn:
                rollback_stack.append((idx, step_context))

            if not result.success:
                overall_success = False
                logger.warning(
                    "Step %d (%s) failed after %d attempts — running rollback",
                    idx, action_type, attempt,
                )
                # Run rollback for completed steps in reverse
                self._run_rollback(rollback_stack, steps)
                break

        passed = sum(1 for r in step_results if r.success)

        logger.info(
            "PlaybookExecutor: completed %s — %d/%d steps passed, overall=%s",
            attack_id, passed, len(step_results), overall_success,
        )

        return PlaybookResult(
            action_id=action_id,
            attack_type=attack_type,
            attack_id=attack_id,
            success=overall_success,
            step_results=step_results,
            rollback_ran=not overall_success,
            total_steps=len(steps),
            passed_steps=passed,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_step_with_retry(
        self,
        step_index:  int,
        phase:       str,
        action_type: str,
        context:     dict[str, Any],
    ) -> tuple[ScriptResult, int]:
        """
        Execute a single step, retrying up to max_retries times.
        Returns (final ScriptResult, attempt_number).

        If an :class:`~actions.executor.ActionExecutor` was injected,
        execution is delegated to it for timeout enforcement and
        structured telemetry.  Otherwise falls back to direct
        :class:`~playbook_scripts.registry.ScriptRegistry` dispatch.
        """
        script = self._registry.get(action_type)
        attempt = 0

        for attempt in range(1, self._max_retries + 2):
            logger.debug(
                "Step %d phase=%s action=%s attempt=%d",
                step_index, phase, action_type, attempt,
            )
            try:
                # Route through ActionExecutor when available
                if self._action_executor and self._action_executor.has_action(
                    context.get("catalog_action_id", "")
                ):
                    ar = self._action_executor.execute(
                        context["catalog_action_id"], context
                    )
                    result = ScriptResult(
                        success=(ar.status == "success"),
                        exit_code=ar.exit_code,
                        output=ar.output,
                        metadata=ar.metadata,
                    )
                else:
                    result = script.execute(context)
            except Exception as exc:  # noqa: BLE001
                logger.error("Script %s raised exception: %s", action_type, exc)
                result = ScriptResult(success=False, output=str(exc))

            if result.success:
                return result, attempt

            if attempt <= self._max_retries:
                logger.warning(
                    "Step %d attempt %d failed — retrying in 2s", step_index, attempt
                )
                time.sleep(2)

        return result, attempt

    def _run_rollback(
        self,
        rollback_stack: list[tuple[int, dict]],
        steps: list[dict],
    ) -> None:
        """Execute rollback for completed steps in reverse order."""
        for step_index, ctx in reversed(rollback_stack):
            action_type = steps[step_index].get("action_type", "")
            script      = self._registry.get(action_type)
            logger.info("Rollback: step %d action=%s", step_index, action_type)
            try:
                script.rollback(ctx)
            except Exception as exc:  # noqa: BLE001
                logger.error("Rollback failed for step %d: %s", step_index, exc)

    def _build_context(
        self,
        action_doc:     dict[str, Any],
        playbook_entry: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Merge action document fields with environment config to produce
        the full execution context passed to each script.
        """
        docker_cfg = self._env_config.get("docker", {})
        mqtt_cfg   = self._env_config.get("mqtt", {})

        # Resolve container_id: try to map destination_ip to a known container
        container_id = action_doc.get("container_id") or "unknown"

        return {
            # From the action document
            "action_id":      action_doc.get("action_id", "unknown"),
            "attack_type":    action_doc.get("attack_type", "unknown"),
            "source_ip":      action_doc.get("source_ip") or action_doc.get("src_ip", "unknown"),
            "destination_ip": action_doc.get("destination_ip") or action_doc.get("dst_ip", "unknown"),
            "container_id":   container_id,
            "severity":       action_doc.get("raw_severity", "medium"),

            # From environment config
            "dmz_network":            docker_cfg.get("dmz_network", "dmz_net"),
            "quarantine_network":     docker_cfg.get("quarantine_network", "quarantine_net"),
            "mqtt_broker_container":  mqtt_cfg.get("broker_container", "iot-device-1"),
            "mqtt_acl_file":          mqtt_cfg.get("acl_file", "/etc/mosquitto/acl"),
            "mqtt_safe_state_topic":  mqtt_cfg.get("safe_state_topic", "actuators/control"),
            "mqtt_safe_state_payload": mqtt_cfg.get("safe_state_payload", "OFF"),
            "mqtt_broker_port":       mqtt_cfg.get("broker_port", 1883),
        }
