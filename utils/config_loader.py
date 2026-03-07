"""
utils/config_loader.py
----------------------
Loads settings from YAML files + .env overrides.
All environment variable references in YAML are resolved at load time.
"""

import os
import re
from typing import Any

import yaml
from dotenv import load_dotenv

# Load .env once at import time
load_dotenv()

_ENV_PATTERN = re.compile(r"\$\{(\w+)(?::([^}]*))?\}")


def _resolve_env(value: str) -> str:
    """Replace ${VAR:default} placeholders with environment values."""
    def replacer(match: re.Match) -> str:
        var_name, default = match.group(1), match.group(2) or ""
        return os.environ.get(var_name, default)
    return _ENV_PATTERN.sub(replacer, value)


def _walk_and_resolve(obj: Any) -> Any:
    """Recursively resolve env-var placeholders throughout the config tree."""
    if isinstance(obj, dict):
        return {k: _walk_and_resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_resolve(i) for i in obj]
    if isinstance(obj, str):
        resolved = _resolve_env(obj)
        # Convert boolean-looking strings
        if resolved.lower() == "true":
            return True
        if resolved.lower() == "false":
            return False
        # Convert integer-looking strings
        if resolved.isdigit():
            return int(resolved)
        return resolved
    return obj


def load_yaml(path: str) -> dict:
    """
    Load a YAML file and resolve ${ENV_VAR:default} placeholders.

    Args:
        path: Absolute or relative path to the YAML file.

    Returns:
        Dictionary representation of the YAML with env vars resolved.

    Raises:
        FileNotFoundError: If the YAML file does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return _walk_and_resolve(raw or {})


def load_settings(config_dir: str = "./config") -> dict:
    """
    Load and merge settings.yaml + thresholds.yaml from *config_dir*.

    Returns:
        Merged configuration dictionary accessible via dot-like keys.
    """
    settings = load_yaml(os.path.join(config_dir, "settings.yaml"))
    thresholds = load_yaml(os.path.join(config_dir, "thresholds.yaml"))
    settings["thresholds"] = thresholds
    return settings
