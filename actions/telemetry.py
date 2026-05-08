"""
actions/telemetry.py
---------------------
Structured JSON telemetry logger for action executions.

Writes one JSON object per line to a dedicated telemetry log file
(default: ``logs/action_telemetry.jsonl``).  The format is designed
for direct ingestion into an ELK stack via Filebeat → Elasticsearch,
with field names following ECS conventions.

This module is intentionally decoupled from the main SOAR logger
(``utils/logger.py``) so telemetry output is machine-readable and
never mixed with human-readable console logs.

Usage::

    from actions.telemetry import ActionTelemetry

    telemetry = ActionTelemetry()
    telemetry.record(action_result)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any

from actions.action_result import ActionResult


_DEFAULT_LOG_PATH = os.path.join("logs", "action_telemetry.jsonl")
_MAX_BYTES = 50 * 1024 * 1024   # 50 MB before rotation
_BACKUP_COUNT = 10


class ActionTelemetry:
    """
    Writes structured JSON telemetry for every action execution.

    Args:
        log_path:     Path to the JSONL telemetry file.
        max_bytes:    Maximum file size before rotation.
        backup_count: Number of rotated backups to keep.
    """

    def __init__(
        self,
        log_path: str = _DEFAULT_LOG_PATH,
        max_bytes: int = _MAX_BYTES,
        backup_count: int = _BACKUP_COUNT,
    ) -> None:
        self._logger = logging.getLogger("soar.action_telemetry")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False  # never mix with console

        # Prevent duplicate handlers on re-init
        if not self._logger.handlers:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            handler = RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            # Raw JSON — no formatter prefix
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def record(self, result: ActionResult) -> None:
        """
        Write an ActionResult as a single JSON line to the telemetry log.

        This method is safe to call from any thread.
        """
        doc = result.to_elk_doc()
        self._logger.info(json.dumps(doc, default=str))

    def record_custom(self, event: dict[str, Any]) -> None:
        """
        Write an arbitrary event dict (for non-action telemetry such as
        engine lifecycle events or error summaries).
        """
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.now(timezone.utc).isoformat()
        self._logger.info(json.dumps(event, default=str))
