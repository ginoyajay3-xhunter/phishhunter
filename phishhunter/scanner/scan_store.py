"""Persistent scan-result storage, used by the PDF export route.

Fix: scan results were previously kept in a plain in-memory dict, which
meant every cached result (and the "Download PDF" link for it) became
invalid the moment the server process restarted — common during
development with --reload, or after any deploy. Storing each result as a
JSON file on disk means a scan_id keeps working across restarts as long
as the file is still there.
"""
import os
import json
import time
import glob

from config import logger

log = logger.getChild("scan_store")

STORE_DIR = "reports/_scan_cache"
MAX_AGE_SECONDS = 7 * 24 * 60 * 60  # prune anything older than 7 days
MAX_FILES = 200  # hard cap so this directory can't grow unbounded

os.makedirs(STORE_DIR, exist_ok=True)


def _path_for(scan_id: str) -> str:
    # scan_id is always a uuid4 string from app.py — safe to use directly
    # as a filename, but strip anything unexpected just in case.
    safe_id = "".join(c for c in scan_id if c.isalnum() or c == "-")
    return os.path.join(STORE_DIR, f"{safe_id}.json")


def save_scan_result(scan_id: str, result: dict) -> None:
    path = _path_for(scan_id)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f)
    except Exception as e:
        log.warning("Failed to persist scan result %s: %s", scan_id, e, exc_info=True)
    _prune_old_entries()


def load_scan_result(scan_id: str) -> dict | None:
    path = _path_for(scan_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.warning("Failed to load scan result %s: %s", scan_id, e, exc_info=True)
        return None


def _prune_old_entries() -> None:
    """Keep the cache directory bounded: drop anything older than
    MAX_AGE_SECONDS, and if still over MAX_FILES, drop the oldest first."""
    try:
        files = glob.glob(os.path.join(STORE_DIR, "*.json"))
        now = time.time()

        for f in files:
            try:
                if now - os.path.getmtime(f) > MAX_AGE_SECONDS:
                    os.remove(f)
            except OSError:
                pass

        files = glob.glob(os.path.join(STORE_DIR, "*.json"))
        if len(files) > MAX_FILES:
            files.sort(key=lambda f: os.path.getmtime(f))
            for f in files[: len(files) - MAX_FILES]:
                try:
                    os.remove(f)
                except OSError:
                    pass
    except Exception as e:
        log.debug("Cache pruning skipped due to error: %s", e)
