"""Startup cleanup: remove stale temp dirs from previous runs.

CodeQL databases and captured script dirs are created under the system
temp directory with known prefixes.  If the app crashes or Chrome is
closed without a clean shutdown, these dirs leak.  This module sweeps
them on startup.
"""

import os
import shutil
import tempfile
import time

# Prefixes used by ScriptStore and CodeQLRunner
_PREFIXES = ("codeql_js_src_", "codeql_work_")

# Don't delete dirs younger than this (seconds) — they might belong
# to another running instance.
_MIN_AGE_SECONDS = 60


def cleanup_stale_temp_dirs():
    """Remove temp dirs from previous runs that are older than _MIN_AGE_SECONDS."""
    tmp = tempfile.gettempdir()
    now = time.time()
    removed = 0

    try:
        entries = os.listdir(tmp)
    except OSError:
        return 0

    for name in entries:
        if not any(name.startswith(p) for p in _PREFIXES):
            continue
        path = os.path.join(tmp, name)
        if not os.path.isdir(path):
            continue
        try:
            age = now - os.path.getmtime(path)
            if age < _MIN_AGE_SECONDS:
                continue
            shutil.rmtree(path, ignore_errors=True)
            removed += 1
        except OSError:
            continue

    return removed
