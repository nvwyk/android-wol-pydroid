"""State that belongs to this server process, not to the database: when it started,
which port it listens on, whether launcher.py supervises it. Resets on every restart."""
import json
import os
import threading
import time
from datetime import datetime, timezone

from . import BASE_DIR, APP_VERSION

RESTART_EXIT_CODE = 3           # launcher.py restarts at once instead of treating it as a crash

started_monotonic = time.monotonic()
started_at = datetime.now(timezone.utc)
listening_port = None
build = None                    # short release id of the running files
database_error = None           # set when wol.db cannot be used; pages then show an error
database_warning = None         # PRAGMA quick_check findings, if any
setup_done = False              # cached once true; an installation never becomes un-set-up
setup_code = None               # printed to the console while setup is not done
setup_code_logged = 0.0         # monotonic time the code was last printed
internet = None                 # None until the first check, then True or False
internet_since = None
internet_latency = None         # seconds the latest successful internet check took


restart_hook = None             # tests replace the exit with a recorder


def request_restart(delay=1.0):
    """Exit with RESTART_EXIT_CODE shortly, after the current response has gone out.
    launcher.py starts the server again at once; the old launcher does too, after 5 s."""
    action = restart_hook or (lambda: os._exit(RESTART_EXIT_CODE))
    timer = threading.Timer(delay, action)
    timer.daemon = True
    timer.start()


def now_local():
    return datetime.now(timezone.utc).astimezone()


def uptime():
    return time.monotonic() - started_monotonic


def version_label():
    return "%s (build %s)" % (APP_VERSION, build) if build else APP_VERSION


def supervised():
    """True when a launcher.py started this process and restarts it when it exits."""
    return bool(os.environ.get("WOL_INSTANCE_TOKEN"))


def launcher_generation():
    """2 for the launcher that updates the whole application, 1 for the old one that
    only knew about server.py, None when run directly."""
    if not supervised():
        return None
    try:
        return int(os.environ.get("WOL_LAUNCHER_API", "1"))
    except ValueError:
        return 1


def launcher_state(base_dir=BASE_DIR):
    """What launcher.py last wrote to state.json, reduced to what the pages may show."""
    try:
        with open(os.path.join(base_dir, "state.json"), encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    return {
        "app_commit": str(state.get("app_commit") or "")[:7] or None,
        "last_check_at": state.get("last_check_at"),
        "last_check_result": state.get("last_check_result"),
        "last_update_at": state.get("last_update_at"),
        "launcher_update_available": bool(state.get("launcher_update_available")),
    }
