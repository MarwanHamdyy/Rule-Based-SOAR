"""
utils/logger.py
---------------
Centralised logging setup for the SOAR engine.
Provides a colour-coded console logger and a rotating file handler.
Call `get_logger(__name__)` in every module.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

try:
    import colorlog  # optional pretty colours in terminal
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False


def setup_logging(level: str = "INFO", log_file: str | None = None,
                  max_bytes: int = 10_485_760, backup_count: int = 5) -> None:
    """
    Configure the root logger once at application start.

    Args:
        level:        Logging level string ("DEBUG", "INFO", "WARNING", "ERROR").
        log_file:     Optional path to write rotating log file.
        max_bytes:    Maximum log file size before rotation (default: 10 MB).
        backup_count: Number of rotated backup files to keep.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # ---- console handler ----
    if _HAS_COLOR:
        fmt = "%(log_color)s%(asctime)s [%(levelname)s] %(name)s%(reset)s: %(message)s"
        console_handler = colorlog.StreamHandler()
        console_handler.setFormatter(colorlog.ColoredFormatter(
            fmt,
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        ))
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))

    handlers: list[logging.Handler] = [console_handler]

    # ---- rotating file handler ----
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        handlers.append(file_handler)

    logging.basicConfig(level=numeric_level, handlers=handlers)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger.  Call ``setup_logging`` first."""
    return logging.getLogger(name)
