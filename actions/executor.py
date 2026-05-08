"""
actions/executor.py
--------------------
Central dispatcher for catalog-driven action execution.

The :class:`ActionExecutor` is the single entry point for running any
action from ``action_catalog.json``.  It provides:

* **Dynamic dispatch** — resolves ``ACT-NNN`` identifiers to concrete
  :class:`~actions.base_action.BaseAction` subclasses via the
  :class:`~actions.registry.ActionRegistry`.
* **Timeout enforcement** — runs each action in a
  :class:`~concurrent.futures.ThreadPoolExecutor` and enforces the
  action's ``TIMEOUT_SECONDS`` via ``future.result(timeout=...)``.
* **Structured telemetry** — emits a JSON telemetry record for every
  execution via :class:`~actions.telemetry.ActionTelemetry`.
* **Standardised results** — always returns an
  :class:`~actions.action_result.ActionResult`, regardless of success,
  failure, timeout, or missing implementation.

Usage::

    from actions.executor import ActionExecutor

    executor = ActionExecutor(docker=docker, env_config=env_config)
    result   = executor.execute("ACT-001", context={"source_ip": "10.0.0.5", ...})
"""

from __future__ import annotations

import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from typing import Any

from actions.action_result import ActionResult
from actions.registry import ActionRegistry
from actions.sanitizer import SanitizationError
from actions.telemetry import ActionTelemetry
from adapters.docker_adapter import DockerAdapter
from utils.logger import get_logger

logger = get_logger(__name__)


class ActionExecutor:
    """
    Dispatcher that resolves action IDs to implementations and
    executes them with timeout enforcement and telemetry.

    Args:
        docker:        Shared :class:`DockerAdapter` instance.
        env_config:    Environment configuration dict.
        catalog_path:  Path to ``action_catalog.json``.
        dry_run:       If ``True``, all actions run in dry-run mode.
        max_workers:   Thread pool size for parallel action execution.
        telemetry_log: Path to the JSONL telemetry output file.
    """

    def __init__(
        self,
        docker: DockerAdapter,
        env_config: dict[str, Any] | None = None,
        catalog_path: str = "simulator/sample_data/action_catalog.json",
        dry_run: bool = False,
        max_workers: int = 4,
        telemetry_log: str = "logs/action_telemetry.jsonl",
    ) -> None:
        self._env_config = env_config or {}
        self._dry_run = dry_run
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="action"
        )

        self._registry = ActionRegistry(
            docker=docker,
            dry_run=dry_run,
            catalog_path=catalog_path,
        )
        self._telemetry = ActionTelemetry(log_path=telemetry_log)

        logger.info(
            "ActionExecutor initialised. dry_run=%s  max_workers=%d  "
            "registered_actions=%d",
            dry_run,
            max_workers,
            len(self._registry.list_actions()),
        )

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        action_id: str,
        context: dict[str, Any],
        *,
        timeout_override: int | None = None,
    ) -> ActionResult:
        """
        Execute a single action by its ``ACT-NNN`` identifier.

        Args:
            action_id:        Catalog action ID (e.g. ``"ACT-001"``).
            context:          Execution context dict (IPs, container_id, etc.).
            timeout_override: Override the action's default timeout (seconds).

        Returns:
            :class:`ActionResult` — always returns, never raises.
        """
        action_id = action_id.upper()
        action = self._registry.get(action_id)

        if action is None:
            return self._result_not_found(action_id, context)

        timeout = timeout_override or action.TIMEOUT_SECONDS
        started_at = datetime.now(timezone.utc)

        logger.info(
            "ActionExecutor: dispatching %s (%s) timeout=%ds target=%s",
            action_id,
            action.ACTION_NAME,
            timeout,
            context.get("container_id", "?"),
        )

        # Submit to thread pool with timeout
        future: Future[ActionResult] = self._pool.submit(
            self._safe_execute, action, context, started_at.isoformat()
        )

        try:
            result = future.result(timeout=timeout)
        except TimeoutError:
            result = self._result_timeout(action, context, started_at)
        except Exception as exc:  # noqa: BLE001
            result = self._result_error(action, context, started_at, exc)

        # Calculate duration
        ended_at = datetime.now(timezone.utc)
        result.duration_ms = int(
            (ended_at - started_at).total_seconds() * 1000
        )
        result.completed_at = ended_at.isoformat()

        # Telemetry
        self._telemetry.record(result)

        logger.info(
            "ActionExecutor: %s → %s (%dms) exit=%d",
            action_id,
            result.status,
            result.duration_ms,
            result.exit_code,
        )

        return result

    def execute_by_name(
        self,
        action_name: str,
        context: dict[str, Any],
        **kwargs: Any,
    ) -> ActionResult:
        """
        Execute an action by its human-readable name.

        Resolves the name to an ``ACT-NNN`` ID via the registry, then
        delegates to :meth:`execute`.
        """
        action = self._registry.get_by_name(action_name)
        if action is None:
            return ActionResult(
                action_name=action_name,
                status="failure",
                error=f"No implementation found for action name: {action_name}",
                soar_action_id=str(context.get("action_id", "")),
            )
        return self.execute(action.ACTION_ID, context, **kwargs)

    def rollback(
        self,
        action_id: str,
        context: dict[str, Any],
        *,
        timeout_override: int | None = None,
    ) -> ActionResult:
        """Execute the rollback for an action."""
        action_id = action_id.upper()
        action = self._registry.get(action_id)
        if action is None:
            return self._result_not_found(action_id, context)

        timeout = timeout_override or action.TIMEOUT_SECONDS
        started_at = datetime.now(timezone.utc)

        logger.info("ActionExecutor: rollback %s", action_id)

        future = self._pool.submit(
            self._safe_rollback, action, context, started_at.isoformat()
        )

        try:
            result = future.result(timeout=timeout)
        except TimeoutError:
            result = self._result_timeout(action, context, started_at)
        except Exception as exc:  # noqa: BLE001
            result = self._result_error(action, context, started_at, exc)

        ended_at = datetime.now(timezone.utc)
        result.duration_ms = int(
            (ended_at - started_at).total_seconds() * 1000
        )
        result.completed_at = ended_at.isoformat()
        self._telemetry.record(result)

        return result

    def list_actions(self) -> list[dict[str, str]]:
        """Return all registered actions as a list of summary dicts."""
        return self._registry.list_actions()

    def has_action(self, action_id: str) -> bool:
        """Check whether an action is registered."""
        return self._registry.has(action_id)

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the internal thread pool."""
        self._pool.shutdown(wait=wait)

    # ------------------------------------------------------------------
    #  Internal execution wrappers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_execute(
        action: Any,
        context: dict[str, Any],
        started_at: str,
    ) -> ActionResult:
        """
        Execute action.execute(context) catching all exceptions so
        the caller always gets an ActionResult.
        """
        try:
            result = action.execute(context)
            result.started_at = started_at
            return result
        except SanitizationError as exc:
            return ActionResult(
                action_id=action.ACTION_ID,
                action_name=action.ACTION_NAME,
                action_class=action.ACTION_CLASS,
                status="failure",
                error=f"Input sanitization failed: {exc}",
                soar_action_id=str(context.get("action_id", "")),
                target_asset=str(context.get("container_id", "")),
                started_at=started_at,
            )
        except Exception as exc:  # noqa: BLE001
            return ActionResult(
                action_id=action.ACTION_ID,
                action_name=action.ACTION_NAME,
                action_class=action.ACTION_CLASS,
                status="failure",
                error=f"{type(exc).__name__}: {exc}",
                soar_action_id=str(context.get("action_id", "")),
                target_asset=str(context.get("container_id", "")),
                started_at=started_at,
            )

    @staticmethod
    def _safe_rollback(
        action: Any,
        context: dict[str, Any],
        started_at: str,
    ) -> ActionResult:
        """Execute action.rollback(context) with exception safety."""
        try:
            result = action.rollback(context)
            result.started_at = started_at
            return result
        except Exception as exc:  # noqa: BLE001
            return ActionResult(
                action_id=action.ACTION_ID,
                action_name=action.ACTION_NAME,
                action_class=action.ACTION_CLASS,
                status="failure",
                error=f"Rollback error: {exc}",
                started_at=started_at,
            )

    # ------------------------------------------------------------------
    #  Result factories for edge cases
    # ------------------------------------------------------------------

    @staticmethod
    def _result_not_found(
        action_id: str, context: dict[str, Any]
    ) -> ActionResult:
        return ActionResult(
            action_id=action_id,
            status="failure",
            error=f"No implementation registered for {action_id}",
            soar_action_id=str(context.get("action_id", "")),
            target_asset=str(context.get("container_id", "")),
        )

    @staticmethod
    def _result_timeout(
        action: Any,
        context: dict[str, Any],
        started_at: datetime,
    ) -> ActionResult:
        return ActionResult(
            action_id=action.ACTION_ID,
            action_name=action.ACTION_NAME,
            action_class=action.ACTION_CLASS,
            status="timeout",
            error=(
                f"Action exceeded timeout of {action.TIMEOUT_SECONDS}s"
            ),
            soar_action_id=str(context.get("action_id", "")),
            target_asset=str(context.get("container_id", "")),
            started_at=started_at.isoformat(),
        )

    @staticmethod
    def _result_error(
        action: Any,
        context: dict[str, Any],
        started_at: datetime,
        exc: Exception,
    ) -> ActionResult:
        return ActionResult(
            action_id=action.ACTION_ID,
            action_name=action.ACTION_NAME,
            action_class=action.ACTION_CLASS,
            status="failure",
            error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}",
            soar_action_id=str(context.get("action_id", "")),
            target_asset=str(context.get("container_id", "")),
            started_at=started_at.isoformat(),
        )
