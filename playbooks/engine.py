"""
playbooks/engine.py
--------------------
Main playbook engine loop.

Polls soar-actions-* for unprocessed SOAR action documents AND
polls security-alerts-* / iot-logs-* for escalated self-healing events.

For each unprocessed event:
    1. Look up the matching mitigation playbook from mitigation_catalog.json
    2. Execute the playbook steps via PlaybookExecutor
    3. Write results to soar-playbook-results-*
    4. Mark the source document as processed

Can be run as a standalone process (via playbook_runner.py) alongside
the main SOAR engine (main.py), or in a combined single-process mode.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from elasticsearch import Elasticsearch

from adapters.docker_adapter import DockerAdapter
from playbooks.executor import PlaybookExecutor
from playbooks.lookup import PlaybookLookup
from playbooks.result_writer import PlaybookResultWriter
from playbook_scripts.registry import ScriptRegistry
from utils.logger import get_logger

logger = get_logger(__name__)

# How long to wait between polls if there are no new events
_DEFAULT_POLL_INTERVAL = 15


class PlaybookEngine:
    """
    Continuously polls soar-actions-* for new action documents and
    executes the corresponding mitigation playbook for each one.

    Args:
        es_client:     Authenticated Elasticsearch client.
        docker:        DockerAdapter for container management.
        env_config:    Full environment.yaml config dict.
        dry_run:       If True, log steps but do not execute any commands.
        poll_interval: Seconds between polling cycles.
    """

    def __init__(
        self,
        es_client:     Elasticsearch,
        docker:        DockerAdapter,
        env_config:    dict[str, Any],
        dry_run:       bool = False,
        poll_interval: int = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._es           = es_client
        self._env_config   = env_config
        self._dry_run      = dry_run
        self._poll_interval = poll_interval

        # Playbook stack
        self._lookup   = PlaybookLookup()
        self._registry = ScriptRegistry(docker=docker, dry_run=dry_run)
        self._executor = PlaybookExecutor(
            registry=self._registry,
            max_retries=env_config.get("playbook_engine", {}).get("max_retries", 2),
            env_config=env_config,
        )
        self._writer = PlaybookResultWriter(
            es_client=es_client,
            index_prefix=env_config.get("playbook_engine", {})
                .get("results_index_prefix", "soar-playbook-results"),
        )

        logger.info(
            "PlaybookEngine initialised. dry_run=%s poll_interval=%ds",
            dry_run, poll_interval,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_once(self) -> int:
        """
        Execute one poll cycle.

        Returns:
            Number of playbooks executed.
        """
        action_docs = self._fetch_unprocessed_actions()
        if not action_docs:
            logger.debug("PlaybookEngine: no new actions to process.")
            return 0

        count = 0
        for action_doc, es_id, index in action_docs:
            executed = self._process_action(action_doc, es_id, index)
            if executed:
                count += 1

        return count

    def run_forever(self) -> None:
        """Continuous polling loop. Blocks until interrupted."""
        logger.info("PlaybookEngine: starting continuous loop.")
        try:
            while True:
                count = self.run_once()
                if count:
                    logger.info("PlaybookEngine: processed %d action(s) this cycle.", count)
                time.sleep(self._poll_interval)
        except KeyboardInterrupt:
            logger.info("PlaybookEngine: shutting down.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_unprocessed_actions(self) -> list[tuple[dict, str, str]]:
        """
        Fetch soar-actions-* documents that have not yet been processed
        by the playbook engine (no playbook_executed field).

        Returns list of (action_doc, es_id, index_name).
        """
        query = {
            "query": {
                "bool": {
                    "must_not": [
                        {"exists": {"field": "playbook_executed"}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
        }

        try:
            resp = self._es.search(
                index="soar-actions-*",
                body=query,
                size=50,
                ignore_unavailable=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("PlaybookEngine: failed to fetch actions: %s", exc)
            return []

        results = []
        for hit in resp.get("hits", {}).get("hits", []):
            results.append((hit["_source"], hit["_id"], hit["_index"]))
        return results

    def _process_action(
        self,
        action_doc: dict[str, Any],
        es_id:      str,
        index:      str,
    ) -> bool:
        """
        Look up and execute the playbook for one action document.
        Returns True if a playbook was found and executed.
        """
        attack_type = action_doc.get("attack_type", "")

        if not attack_type:
            logger.warning("PlaybookEngine: action %s has no attack_type — skipping", es_id)
            return False

        # Look up mitigation entry
        entry = self._lookup.resolve(attack_type)
        if not entry:
            logger.info(
                "PlaybookEngine: no playbook entry for attack_type=%r — skipping",
                attack_type,
            )
            # Still mark as processed so we don't retry endlessly
            self._mark_no_playbook(es_id, index, attack_type)
            return False

        logger.info(
            "PlaybookEngine: executing playbook %s for action %s (attack=%s)",
            entry.get("attack_id"), es_id, attack_type,
        )

        # Execute playbook
        result = self._executor.run(action_doc, entry)

        # Write result
        self._writer.write(result, action_es_id=es_id)

        return True

    def _mark_no_playbook(self, es_id: str, index: str, attack_type: str) -> None:
        """Mark a document as processed even if no playbook was found."""
        try:
            self._es.update(
                index=index,
                id=es_id,
                body={
                    "doc": {
                        "playbook_executed": True,
                        "playbook_success":  None,
                        "playbook_note":     f"no playbook entry for {attack_type}",
                    }
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not mark no-playbook: %s", exc)
