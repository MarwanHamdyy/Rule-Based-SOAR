"""
actions — SOAR Action Execution Framework
-------------------------------------------
Production-grade action dispatch, execution, and telemetry layer.

Core exports:

* :class:`BaseAction`       — Abstract base class for all action scripts.
* :class:`ActionResult`     — Standardised result dataclass.
* :class:`ActionExecutor`   — Central dispatcher with timeout enforcement.
* :class:`ActionRegistry`   — Dynamic auto-discovery of action implementations.
* :class:`ActionTelemetry`  — Structured JSON telemetry logger.

Existing modules (unchanged):

* :class:`ActionBuilder`    — Builds SOAR action documents from rule matches.
* :class:`ESWriter`         — Indexes action documents into Elasticsearch.
"""

from actions.action_result import ActionResult
from actions.base_action import BaseAction
from actions.executor import ActionExecutor
from actions.registry import ActionRegistry
from actions.telemetry import ActionTelemetry
