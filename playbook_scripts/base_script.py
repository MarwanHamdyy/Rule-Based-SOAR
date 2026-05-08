"""
playbook_scripts/base_script.py
--------------------------------
Abstract base class for all SOAR response scripts.

Every script receives a context dict built from the action document
and the mitigation catalog step, then returns a ScriptResult.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from adapters.docker_adapter import DockerAdapter
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScriptResult:
    """Result returned by every script's execute() method."""
    success:     bool
    exit_code:   int           = 0
    output:      str           = ""
    rollback_fn: str | None    = None   # name of rollback method if applicable
    metadata:    dict[str, Any] = field(default_factory=dict)
    timestamp:   str           = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class BaseScript(ABC):
    """
    Abstract base for all playbook response scripts.

    Subclasses implement execute() and optionally rollback().
    All scripts receive the shared DockerAdapter and a context dict.
    """

    # Override in subclasses to give a human-readable label
    SCRIPT_NAME: str = "base_script"
    ACTION_CLASS: str = "generic"

    def __init__(self, docker: DockerAdapter, dry_run: bool = False) -> None:
        self.docker  = docker
        self.dry_run = dry_run

    @abstractmethod
    def execute(self, context: dict[str, Any]) -> ScriptResult:
        """
        Execute the response action.

        Args:
            context: Dict containing at minimum:
                - source_ip (str)
                - destination_ip (str)
                - container_id (str)   — target IoT container name
                - attack_type (str)
                - action_id (str)      — SOAR action document ID
                - dry_run (bool)

        Returns:
            ScriptResult
        """

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        """
        Undo the action performed by execute().
        Default implementation is a no-op success.
        """
        logger.info("[%s] No rollback defined — skipping.", self.SCRIPT_NAME)
        return ScriptResult(success=True, output="no rollback defined")

    # ------------------------------------------------------------------
    # Helpers available to all scripts
    # ------------------------------------------------------------------

    def _log_action(self, msg: str, **kwargs: Any) -> None:
        logger.info("[%s] %s  %s", self.SCRIPT_NAME, msg, kwargs or "")

    def _log_error(self, msg: str, **kwargs: Any) -> None:
        logger.error("[%s] %s  %s", self.SCRIPT_NAME, msg, kwargs or "")

    def _get(self, context: dict, key: str, default: str = "") -> str:
        """Safe context field getter with default."""
        return str(context.get(key) or default)
