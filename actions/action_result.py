"""
actions/action_result.py
--------------------------
Standardised result object returned by every action execution.

Every action — whether it succeeds, fails, times out, or is skipped —
produces an ActionResult.  The dataclass provides .to_dict() and
.to_elk_doc() helpers so results can be serialised for Elasticsearch
ingestion or structured JSON telemetry without any extra transformation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


@dataclass(slots=True)
class ActionResult:
    """Immutable result of a single action execution."""

    # --- Identity ---
    action_id: str = ""                     # ACT-NNN from catalog
    action_name: str = ""                   # Human-readable action name
    action_class: str = ""                  # e.g. "network_containment"
    soar_action_id: str = ""                # UUID from the SOAR action document

    # --- Target ---
    target_asset: str = ""                  # container_id or host identifier
    target_ip: str = ""                     # IP acted upon

    # --- Outcome ---
    status: Literal["success", "failure", "timeout", "skipped"] = "failure"
    exit_code: int = -1
    output: str = ""
    error: str = ""

    # --- Timing ---
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str = ""
    duration_ms: int = 0

    # --- Context ---
    dry_run: bool = False
    attempt: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Plain dict representation (all fields)."""
        return asdict(self)

    def to_elk_doc(self) -> dict[str, Any]:
        """
        ECS-aligned document suitable for indexing into Elasticsearch.

        Field names follow Elastic Common Schema (ECS) conventions where
        possible so Kibana dashboards can leverage default field mappings.
        """
        return {
            "@timestamp": self.completed_at or self.started_at,
            "event.kind": "action_execution",
            "event.outcome": self.status,

            # Action identity
            "action.id": self.action_id,
            "action.name": self.action_name,
            "action.class": self.action_class,

            # Target
            "target.container": self.target_asset,
            "target.ip": self.target_ip,

            # Execution
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output": (self.output or "")[:1000],   # cap for indexing
            "error": (self.error or "")[:1000],

            # SOAR context
            "soar.action_id": self.soar_action_id,
            "soar.dry_run": self.dry_run,
            "soar.attempt": self.attempt,
        }

    def to_json_line(self) -> str:
        """Single-line JSON string for JSONL telemetry files."""
        import json
        return json.dumps(self.to_elk_doc(), default=str)
