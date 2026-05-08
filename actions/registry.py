"""
actions/registry.py
--------------------
Dynamic action registry that auto-discovers BaseAction subclasses from
the ``actions/scripts/`` package tree.

At startup the registry:

1. Imports every Python module under ``actions/scripts/*/``.
2. Finds all concrete subclasses of :class:`~actions.base_action.BaseAction`.
3. Builds lookup dicts keyed by ``ACTION_ID`` and normalised ``ACTION_NAME``.
4. Cross-references ``action_catalog.json`` to warn about any catalog
   entries that have no implementation.

Usage::

    from actions.registry import ActionRegistry

    registry = ActionRegistry(docker=docker_adapter)
    action   = registry.get("ACT-001")       # by ID
    action   = registry.get_by_name("Block Source IP Address")
"""

from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
from pathlib import Path
from typing import Any, Type

from actions.base_action import BaseAction
from adapters.docker_adapter import DockerAdapter
from utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_CATALOG = Path("simulator/sample_data/action_catalog.json")


def _normalise(name: str) -> str:
    """Lower-case, underscored key for fuzzy matching."""
    return name.lower().replace(" ", "_").replace("-", "_")


class ActionRegistry:
    """
    Central registry mapping ``ACT-NNN`` identifiers (and action names)
    to instantiated :class:`BaseAction` objects.

    Args:
        docker:       Shared :class:`DockerAdapter`.
        dry_run:      If ``True``, all actions run in dry-run mode.
        catalog_path: Path to ``action_catalog.json`` for completeness checks.
    """

    def __init__(
        self,
        docker: DockerAdapter,
        dry_run: bool = False,
        catalog_path: str | Path = _DEFAULT_CATALOG,
    ) -> None:
        self._docker = docker
        self._dry_run = dry_run

        # {ACTION_ID: BaseAction subclass}
        self._classes_by_id: dict[str, Type[BaseAction]] = {}
        # {normalised_name: ACTION_ID}
        self._id_by_name: dict[str, str] = {}
        # {ACTION_ID: instantiated BaseAction}
        self._cache: dict[str, BaseAction] = {}

        self._discover()
        self._check_catalog(Path(catalog_path))

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------

    def get(self, action_id: str) -> BaseAction | None:
        """
        Return an instantiated action by ``ACT-NNN`` identifier.

        Returns ``None`` if no implementation is registered.
        """
        action_id = action_id.upper()
        if action_id not in self._classes_by_id:
            logger.warning("ActionRegistry: no implementation for %s", action_id)
            return None
        if action_id not in self._cache:
            cls = self._classes_by_id[action_id]
            self._cache[action_id] = cls(
                docker=self._docker, dry_run=self._dry_run
            )
        return self._cache[action_id]

    def get_by_name(self, action_name: str) -> BaseAction | None:
        """Look up an action by its human-readable name."""
        key = _normalise(action_name)
        action_id = self._id_by_name.get(key)
        if action_id:
            return self.get(action_id)
        logger.warning("ActionRegistry: no action named %r", action_name)
        return None

    def list_actions(self) -> list[dict[str, str]]:
        """Return a summary list of all registered actions."""
        result = []
        for aid, cls in sorted(self._classes_by_id.items()):
            result.append({
                "action_id": aid,
                "action_name": cls.ACTION_NAME,
                "action_class": cls.ACTION_CLASS,
                "timeout": str(cls.TIMEOUT_SECONDS),
            })
        return result

    def has(self, action_id: str) -> bool:
        """Check whether an action ID is registered."""
        return action_id.upper() in self._classes_by_id

    # ------------------------------------------------------------------
    #  Discovery
    # ------------------------------------------------------------------

    def _discover(self) -> None:
        """
        Import all modules under ``actions.scripts.*`` and register
        every concrete :class:`BaseAction` subclass found.
        """
        import actions.scripts as scripts_pkg  # noqa: F811

        for importer, modname, ispkg in pkgutil.walk_packages(
            scripts_pkg.__path__, prefix="actions.scripts."
        ):
            try:
                module = importlib.import_module(modname)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to import %s: %s", modname, exc)
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseAction)
                    and obj is not BaseAction
                    and not inspect.isabstract(obj)
                    and obj.ACTION_ID != "ACT-000"
                ):
                    self._register(obj)

        logger.info(
            "ActionRegistry: discovered %d action implementations.",
            len(self._classes_by_id),
        )

    def _register(self, cls: Type[BaseAction]) -> None:
        """Register a single action class."""
        aid = cls.ACTION_ID.upper()
        if aid in self._classes_by_id:
            existing = self._classes_by_id[aid]
            logger.warning(
                "Duplicate ACTION_ID %s: %s vs %s — keeping first",
                aid, existing.__name__, cls.__name__,
            )
            return
        self._classes_by_id[aid] = cls
        self._id_by_name[_normalise(cls.ACTION_NAME)] = aid
        logger.debug("Registered %s → %s", aid, cls.__name__)

    # ------------------------------------------------------------------
    #  Catalog completeness check
    # ------------------------------------------------------------------

    def _check_catalog(self, path: Path) -> None:
        """Log warnings for catalog entries with no implementation."""
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            for entry in data.get("action_catalog", []):
                aid = entry.get("action_id", "")
                if aid and aid.upper() not in self._classes_by_id:
                    logger.debug(
                        "ActionRegistry: catalog entry %s (%s) has no implementation",
                        aid, entry.get("action_name", ""),
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not read action catalog for validation: %s", exc)
