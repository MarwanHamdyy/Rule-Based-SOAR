"""
mappings/framework_mapper.py
-----------------------------
Lightweight lookup mapper that attaches MITRE ATT&CK, OWASP, and NIST
reference metadata to SOAR action documents.

Data is loaded from static JSON files at startup.  These are reporting
enrichments only — no network calls are made at runtime.
"""

from __future__ import annotations

import json
import os
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

_BASE = os.path.dirname(__file__)


class FrameworkMapper:
    """
    Maps SOAR attack types to MITRE / OWASP / NIST reference strings.

    Args:
        mappings_dir: Directory containing mitre.json, owasp.json, nist.json.
                      Defaults to the ``mappings/`` package directory.
    """

    def __init__(self, mappings_dir: str | None = None) -> None:
        base = mappings_dir or _BASE
        self._mitre = self._load(os.path.join(base, "mitre.json"))
        self._owasp = self._load(os.path.join(base, "owasp.json"))
        self._nist = self._load(os.path.join(base, "nist.json"))
        logger.info("FrameworkMapper loaded (%d MITRE, %d OWASP, %d NIST entries).",
                    len(self._mitre), len(self._owasp), len(self._nist))

    def lookup(self, attack_type: str) -> dict[str, Any]:
        """
        Return combined framework references for *attack_type*.

        Args:
            attack_type: e.g. ``"port_scan"``, ``"ssh_bruteforce"``.

        Returns:
            Dict with keys: ``mitre_tactic``, ``mitre_technique``,
            ``owasp_ref``, ``nist_ref`` (any may be absent).
        """
        result: dict[str, Any] = {}
        m = self._mitre.get(attack_type, {})
        if m:
            result["mitre_tactic"] = m.get("tactic", "")
            result["mitre_technique"] = m.get("technique", "")

        o = self._owasp.get(attack_type, {})
        if o:
            result["owasp_ref"] = o.get("ref", "")

        n = self._nist.get(attack_type, {})
        if n:
            result["nist_ref"] = n.get("ref", "")

        return result

    @staticmethod
    def _load(path: str) -> dict:
        if not os.path.exists(path):
            logger.warning("Mapping file not found: %s", path)
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load mapping file %s: %s", path, exc)
            return {}
