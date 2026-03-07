"""
utils/checkpoint.py
-------------------
Persists the last-processed Elasticsearch event timestamp to disk,
so the engine resumes correctly after restart without reprocessing
events that were already handled.
"""

import json
import os
from datetime import datetime, timezone

from utils.logger import get_logger

logger = get_logger(__name__)


class Checkpoint:
    """Read/write a JSON checkpoint file containing the last-seen timestamp."""

    def __init__(self, path: str) -> None:
        """
        Args:
            path: File path for the checkpoint JSON file.
                  Parent directories are created automatically.
        """
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def load(self) -> str | None:
        """
        Load the checkpoint timestamp.

        Returns:
            ISO-8601 timestamp string of the last successfully processed event,
            or *None* if no checkpoint exists yet.
        """
        if not os.path.exists(self.path):
            logger.info("No checkpoint file found at %s – starting from scratch.", self.path)
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            ts = data.get("last_timestamp")
            logger.info("Loaded checkpoint: last_timestamp=%s", ts)
            return ts
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read checkpoint (%s); resetting.", exc)
            return None

    def save(self, timestamp: str) -> None:
        """
        Persist *timestamp* as the new checkpoint.

        Args:
            timestamp: ISO-8601 string representing the latest processed event.
        """
        try:
            data = {
                "last_timestamp": timestamp,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            logger.debug("Checkpoint saved: %s", timestamp)
        except OSError as exc:
            logger.error("Could not save checkpoint: %s", exc)

    def reset(self) -> None:
        """Delete the checkpoint file to force a full re-run."""
        if os.path.exists(self.path):
            os.remove(self.path)
            logger.info("Checkpoint reset – file deleted.")
