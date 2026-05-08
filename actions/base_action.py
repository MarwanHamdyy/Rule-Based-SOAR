"""
actions/base_action.py
------------------------
Abstract base class for all catalog-driven action scripts.

Every action in ``action_catalog.json`` is implemented as a subclass of
:class:`BaseAction`.  The class provides:

* **Sanitisation helpers** — wrappers around :mod:`actions.sanitizer` that
  are available as ``self._sanitize_*()`` methods.
* **Timeout declaration** — each subclass sets ``TIMEOUT_SECONDS`` to
  control how long the :class:`~actions.executor.ActionExecutor` will
  wait before killing the action.
* **Structured results** — every ``execute()`` returns an
  :class:`~actions.action_result.ActionResult`.
* **Rollback contract** — optional ``rollback()`` method for undo logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from actions.action_result import ActionResult
from actions.sanitizer import (
    SanitizationError,
    validate_container_id,
    validate_domain,
    validate_interface,
    validate_ip,
    validate_ipv4,
    validate_mac,
    validate_path,
    validate_port,
    validate_subnet,
    validate_username,
)
from adapters.docker_adapter import DockerAdapter
from utils.logger import get_logger

logger = get_logger(__name__)


class BaseAction(ABC):
    """
    Abstract base for all SOAR action scripts.

    Subclasses **must** set the three class-level identifiers and implement
    :meth:`execute`.  Optionally override :meth:`rollback`.

    Class attributes:
        ACTION_ID:        Catalog identifier, e.g. ``"ACT-001"``.
        ACTION_NAME:      Human-readable label.
        ACTION_CLASS:     Category string (``network_containment``, etc.).
        TIMEOUT_SECONDS:  Maximum seconds before the executor kills this action.
    """

    ACTION_ID:   str = "ACT-000"
    ACTION_NAME: str = "unnamed_action"
    ACTION_CLASS: str = "generic"
    TIMEOUT_SECONDS: int = 30

    def __init__(self, docker: DockerAdapter, dry_run: bool = False) -> None:
        self.docker = docker
        self.dry_run = dry_run

    # ------------------------------------------------------------------
    #  Abstract contract
    # ------------------------------------------------------------------

    @abstractmethod
    def execute(self, context: dict[str, Any]) -> ActionResult:
        """
        Perform the remediation action.

        Args:
            context: Dictionary containing at minimum:
                - ``source_ip``      — attacker / offending IP
                - ``destination_ip`` — target IP
                - ``container_id``   — Docker container name
                - ``action_id``      — SOAR action document UUID
                - ``attack_type``    — detected attack category

        Returns:
            :class:`ActionResult` with outcome details.
        """

    def rollback(self, context: dict[str, Any]) -> ActionResult:
        """
        Undo the action performed by :meth:`execute`.

        Default implementation returns a no-op success.
        """
        logger.info("[%s] No rollback defined — skipping.", self.ACTION_ID)
        return self._make_result(
            context, status="skipped", output="no rollback defined"
        )

    # ------------------------------------------------------------------
    #  Result builder
    # ------------------------------------------------------------------

    def _make_result(
        self,
        context: dict[str, Any],
        *,
        status: str = "success",
        exit_code: int = 0,
        output: str = "",
        error: str = "",
        metadata: dict[str, Any] | None = None,
        started_at: str | None = None,
    ) -> ActionResult:
        """Convenience factory for building an ActionResult."""
        now = datetime.now(timezone.utc).isoformat()
        start = started_at or now
        return ActionResult(
            action_id=self.ACTION_ID,
            action_name=self.ACTION_NAME,
            action_class=self.ACTION_CLASS,
            soar_action_id=str(context.get("action_id", "")),
            target_asset=str(context.get("container_id", "")),
            target_ip=str(context.get("source_ip", context.get("destination_ip", ""))),
            status=status,
            exit_code=exit_code,
            output=output,
            error=error,
            started_at=start,
            completed_at=now,
            duration_ms=0,
            dry_run=self.dry_run,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    #  Sanitisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_ip(value: str, field: str = "ip") -> str:
        return validate_ip(value, field=field)

    @staticmethod
    def _sanitize_ipv4(value: str, field: str = "ip") -> str:
        return validate_ipv4(value, field=field)

    @staticmethod
    def _sanitize_mac(value: str, field: str = "mac") -> str:
        return validate_mac(value, field=field)

    @staticmethod
    def _sanitize_container_id(value: str, field: str = "container_id") -> str:
        return validate_container_id(value, field=field)

    @staticmethod
    def _sanitize_username(value: str, field: str = "username") -> str:
        return validate_username(value, field=field)

    @staticmethod
    def _sanitize_domain(value: str, field: str = "domain") -> str:
        return validate_domain(value, field=field)

    @staticmethod
    def _sanitize_port(value: int | str, field: str = "port") -> int:
        return validate_port(value, field=field)

    @staticmethod
    def _sanitize_interface(value: str, field: str = "interface") -> str:
        return validate_interface(value, field=field)

    @staticmethod
    def _sanitize_path(value: str, field: str = "path") -> str:
        return validate_path(value, field=field)

    @staticmethod
    def _sanitize_subnet(value: str, field: str = "subnet") -> str:
        return validate_subnet(value, field=field)

    # ------------------------------------------------------------------
    #  Context helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get(context: dict[str, Any], key: str, default: str = "") -> str:
        """Safe context field getter with default."""
        return str(context.get(key) or default)

    def _log(self, msg: str, **kwargs: Any) -> None:
        logger.info("[%s] %s  %s", self.ACTION_ID, msg, kwargs or "")

    def _log_error(self, msg: str, **kwargs: Any) -> None:
        logger.error("[%s] %s  %s", self.ACTION_ID, msg, kwargs or "")
