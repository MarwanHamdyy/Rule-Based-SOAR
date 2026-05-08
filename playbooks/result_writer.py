"""
playbooks/result_writer.py
---------------------------
Writes playbook execution results to a dedicated Elasticsearch index
(soar-playbook-results-YYYY.MM.DD) so results are visible in Kibana
alongside the original soar-actions-* documents.

Also marks the original soar-actions document as "playbook_executed"
so the engine does not reprocess it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError

from playbooks.executor import PlaybookResult
from utils.logger import get_logger

logger = get_logger(__name__)


class PlaybookResultWriter:
    """
    Indexes PlaybookResult objects into Elasticsearch and marks the
    originating action document as processed.

    Args:
        es_client:       Authenticated Elasticsearch client.
        index_prefix:    Prefix for the results index (default: soar-playbook-results).
        actions_index:   Index pattern for soar-actions docs to mark as executed.
    """

    def __init__(
        self,
        es_client:     Elasticsearch,
        index_prefix:  str = "soar-playbook-results",
        actions_index: str = "soar-actions-*",
    ) -> None:
        self._es           = es_client
        self._index_prefix = index_prefix
        self._actions_index = actions_index

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(
        self,
        result:    PlaybookResult,
        action_es_id: str | None = None,
    ) -> bool:
        """
        Index the playbook result and optionally mark the source action as executed.

        Args:
            result:       PlaybookResult from the executor.
            action_es_id: ES document ID of the source soar-actions doc (for marking).

        Returns:
            True if indexing succeeded.
        """
        index   = self._index_name()
        doc     = self._build_doc(result)

        try:
            self._es.index(index=index, body=doc)
            logger.info(
                "PlaybookResultWriter: wrote result for action_id=%s → index=%s",
                result.action_id, index,
            )

            if action_es_id:
                self._mark_executed(action_es_id, result)

            return True

        except ESConnectionError as exc:
            logger.error("PlaybookResultWriter: ES connection error: %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("PlaybookResultWriter: unexpected error: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _index_name(self) -> str:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self._index_prefix}-{today}"

    def _build_doc(self, result: PlaybookResult) -> dict[str, Any]:
        return {
            "@timestamp":   result.timestamp,
            "action_id":    result.action_id,
            "attack_type":  result.attack_type,
            "attack_id":    result.attack_id,
            "success":      result.success,
            "rollback_ran": result.rollback_ran,
            "total_steps":  result.total_steps,
            "passed_steps": result.passed_steps,
            "steps": [
                {
                    "index":       sr.step_index,
                    "phase":       sr.phase,
                    "action_type": sr.action_type,
                    "success":     sr.success,
                    "attempt":     sr.attempt,
                    "output":      sr.output[:500],  # truncate long output
                    "exit_code":   sr.exit_code,
                    "timestamp":   sr.timestamp,
                }
                for sr in result.step_results
            ],
        }

    def _mark_executed(self, es_id: str, result: PlaybookResult) -> None:
        """Update the source action document to record playbook execution."""
        try:
            # Find the actual index containing this document
            resp = self._es.search(
                index=self._actions_index,
                body={"query": {"ids": {"values": [es_id]}}},
                size=1,
                ignore_unavailable=True,
            )
            hits = resp.get("hits", {}).get("hits", [])
            if not hits:
                return

            hit = hits[0]
            self._es.update(
                index=hit["_index"],
                id=hit["_id"],
                body={
                    "doc": {
                        "playbook_executed": True,
                        "playbook_success":  result.success,
                        "playbook_at":       result.timestamp,
                        "playbook_attack_id": result.attack_id,
                    }
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not mark action as executed: %s", exc)
