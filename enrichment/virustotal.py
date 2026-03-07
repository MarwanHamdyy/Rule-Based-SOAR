"""
enrichment/virustotal.py
-------------------------
Optional VirusTotal integration.

When enabled (VT_ENABLED=true + VT_API_KEY set), the enricher looks up
IPs and domains against the VirusTotal API v3 and caches results to
avoid burning API quota on repeated lookups.

When disabled, every call to ``enrich()`` returns an empty dict,
and the rest of the engine continues normally.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import requests

from utils.logger import get_logger

logger = get_logger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalEnricher:
    """
    Enriches events with VirusTotal threat intelligence.

    Args:
        api_key:   VirusTotal API key.  Leave empty to disable.
        cache_ttl: Cache lifetime in seconds (default: 3600 s / 1 h).
        timeout:   HTTP request timeout in seconds.
        enabled:   Master on/off switch.
    """

    def __init__(
        self,
        api_key: str = "",
        cache_ttl: int = 3600,
        timeout: int = 10,
        enabled: bool = False,
    ) -> None:
        self._api_key = api_key
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._enabled = enabled and bool(api_key)

        # Simple in-memory cache: key → {expires_at, data}
        self._cache: dict[str, dict] = {}

        if self._enabled:
            logger.info("VirusTotal enrichment ENABLED (cache_ttl=%ds).", cache_ttl)
        else:
            logger.info("VirusTotal enrichment DISABLED.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, ip: str | None = None, domain: str | None = None) -> dict[str, Any]:
        """
        Look up *ip* or *domain* on VirusTotal.

        Returns empty dict silently if enrichment is disabled or on error.

        Args:
            ip:     IPv4/IPv6 address to look up.
            domain: Domain name to look up.

        Returns:
            Dict with enrichment details or empty dict.
        """
        if not self._enabled:
            return {}

        if ip:
            return self._lookup("ip_addresses", ip)
        if domain:
            return self._lookup("domains", domain)
        return {}

    def is_enabled(self) -> bool:
        """Return True if enrichment is active."""
        return self._enabled

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _lookup(self, resource_type: str, value: str) -> dict[str, Any]:
        """Perform (or return cached) VT API lookup."""
        cache_key = f"{resource_type}:{value}"

        # Check cache
        entry = self._cache.get(cache_key)
        if entry and entry["expires_at"] > time.time():
            logger.debug("VT cache HIT for %s", cache_key)
            return entry["data"]

        # Query API
        url = f"{_VT_BASE}/{resource_type}/{value}"
        headers = {"x-apikey": self._api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=self._timeout)
            if resp.status_code == 200:
                raw = resp.json().get("data", {}).get("attributes", {})
                result = self._parse_attributes(raw, resource_type)
                # Cache successful result
                self._cache[cache_key] = {
                    "expires_at": time.time() + self._cache_ttl,
                    "data": result,
                }
                logger.info("VT enrichment for %s: malicious=%s", value, result.get("malicious"))
                return result
            elif resp.status_code == 404:
                logger.debug("VT: %s not found.", value)
            elif resp.status_code == 429:
                logger.warning("VT: rate limit exceeded.")
            else:
                logger.warning("VT: unexpected status %d for %s", resp.status_code, value)
        except requests.RequestException as exc:
            logger.error("VT request failed for %s: %s", value, exc)

        return {}

    @staticmethod
    def _parse_attributes(attrs: dict, resource_type: str) -> dict[str, Any]:
        """Extract relevant fields from a VT API response attributes block."""
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "tags": attrs.get("tags", []),
            "last_analysis_date": attrs.get("last_analysis_date", 0),
            "resource_type": resource_type,
        }
