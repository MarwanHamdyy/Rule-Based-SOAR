"""
playbooks/lookup.py
--------------------
Loads mitigation_catalog.json and attack_names.json at startup and
provides fast lookup of playbook entries by attack_type or attack_id.

The mitigation_catalog contains 86 attacks (ATK-001 → ATK-086), each
with a full playbook including steps, verification logic, and rollback.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_CATALOG  = Path("simulator/sample_data/mitigation_catalog.json")
_DEFAULT_NAMES    = Path("simulator/sample_data/attack_names.json")
_DEFAULT_ACTIONS  = Path("simulator/sample_data/action_catalog.json")


class PlaybookLookup:
    """
    Resolves an attack_type string to its mitigation playbook entry.

    Lookup chain:
        attack_type  →  attack_id (via attack_names.json)
                     →  mitigation entry (via mitigation_catalog.json)
    """

    def __init__(
        self,
        catalog_path: str | Path = _DEFAULT_CATALOG,
        names_path:   str | Path = _DEFAULT_NAMES,
        actions_path: str | Path = _DEFAULT_ACTIONS,
    ) -> None:
        self._mitigation_by_id:    dict[str, dict] = {}
        self._attack_id_by_type:   dict[str, str]  = {}
        self._action_by_id:        dict[str, dict] = {}

        self._load_mitigation_catalog(Path(catalog_path))
        self._load_attack_names(Path(names_path))
        self._load_action_catalog(Path(actions_path))

        logger.info(
            "PlaybookLookup: loaded %d mitigation entries, %d attack-type mappings",
            len(self._mitigation_by_id),
            len(self._attack_id_by_type),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(self, attack_type: str) -> dict[str, Any] | None:
        """
        Return the mitigation playbook entry for a given attack_type string.

        The attack_type is the value produced by the SOAR rule engine
        (e.g. "ssh_bruteforce", "port_scan") or the IoT event collector
        (e.g. "possible_brute_force_success" mapped to "ssh_bruteforce").

        Returns:
            Full mitigation entry dict, or None if no entry found.
        """
        # Direct attack_type → attack_id lookup
        attack_id = self._attack_id_by_type.get(attack_type)
        if attack_id:
            return self._mitigation_by_id.get(attack_id)

        # Try case-insensitive partial match on attack_name
        attack_type_lower = attack_type.lower()
        for aid, entry in self._mitigation_by_id.items():
            name = entry.get("attack_name", "").lower()
            if attack_type_lower in name or name in attack_type_lower:
                return entry

        logger.debug("PlaybookLookup: no entry for attack_type=%r", attack_type)
        return None

    def resolve_by_id(self, attack_id: str) -> dict[str, Any] | None:
        """Return mitigation entry by explicit ATK-NNN id."""
        return self._mitigation_by_id.get(attack_id)

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        """Return action catalog entry by ACT-NNN id."""
        return self._action_by_id.get(action_id)

    def all_attack_types(self) -> list[str]:
        """Return all registered attack_type strings."""
        return list(self._attack_id_by_type.keys())

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def _load_mitigation_catalog(self, path: Path) -> None:
        if not path.exists():
            logger.warning("mitigation_catalog not found at %s", path)
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            for entry in data.get("mitigation_catalog", []):
                aid = entry.get("attack_id")
                if aid:
                    self._mitigation_by_id[aid] = entry
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load mitigation_catalog: %s", exc)

    def _load_attack_names(self, path: Path) -> None:
        """
        Build attack_type → attack_id mapping from attack_names.json.
        Also maps the class sim_scenario name to every attack_id in that class.
        """
        if not path.exists():
            logger.warning("attack_names not found at %s", path)
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            for cls in data.get("attack_classes", []):
                sim_scenario = cls.get("sim_scenario", "")
                for atk in cls.get("attack_types", []):
                    aid  = atk.get("attack_id", "")
                    name = atk.get("attack_name", "").lower().replace(" ", "_")
                    # Map both the sim_scenario and the individual attack name
                    if sim_scenario:
                        self._attack_id_by_type[sim_scenario] = aid
                    self._attack_id_by_type[name] = aid
                    self._attack_id_by_type[aid]  = aid  # direct id → id passthrough
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load attack_names: %s", exc)

    def _load_action_catalog(self, path: Path) -> None:
        if not path.exists():
            logger.warning("action_catalog not found at %s", path)
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            for action in data.get("action_catalog", []):
                aid = action.get("action_id")
                if aid:
                    self._action_by_id[aid] = action
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load action_catalog: %s", exc)
