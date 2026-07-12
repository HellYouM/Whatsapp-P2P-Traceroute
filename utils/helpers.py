"""Shared helpers: logging, privilege checks, filesystem setup."""
import ctypes
import logging
import os
import sys
from pathlib import Path

import config


def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    return logging.getLogger("wit")


def ensure_dirs():
    """Create output/log/data dirs if missing."""
    for d in (config.LOG_DIR, config.OUTPUT_DIR, config.DATA_DIR):
        Path(d).mkdir(parents=True, exist_ok=True)


def is_admin() -> bool:
    """Packet capture needs root (POSIX) or Administrator (Windows)."""
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def require_admin(log):
    if not is_admin():
        log.error(
            "Packet capture requires elevated privileges. "
            "Re-run as Administrator (Windows) or with sudo (Linux/macOS)."
        )
        sys.exit(1)
