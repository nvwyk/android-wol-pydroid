"""Application settings, stored in the settings table and edited in Admin > Settings.

Every setting is declared once in DEFINITIONS with its type, default and limits. Code
reads values with settings.get("server_port"); the values are cached in memory and the
cache is refreshed whenever save() writes to the database.
"""
import threading

from . import db


class Setting(object):
    def __init__(self, key, kind, default, group, label, help="", minimum=None,
                 maximum=None, choices=None, unit=None, restart=False):
        self.key, self.kind, self.default, self.group = key, kind, default, group
        self.label, self.help, self.unit, self.restart = label, help, unit, restart
        self.minimum, self.maximum, self.choices = minimum, maximum, choices


GROUPS = [
    ("server", "Server", "How this device serves the web interface."),
    ("sessions", "Sign-in", "How long a signed-in browser stays signed in."),
    ("public", "Public status page",
     "What anyone who can reach this server may see at /status, without signing in."),
    ("monitoring", "Monitoring", "Background checks and how often pages refresh."),
    ("history", "History", "How long activity and wake history are kept."),
    ("updates", "Updates", "Automatic updates are run by launcher.py."),
]

DEFINITIONS = [
    Setting("server_port", "int", 5000, "server", "Server port",
            "The web interface listens on this TCP port on every network interface. "
            "Android apps can only use ports from 1024 up; the port is tested before "
            "it is saved.",
            minimum=1, maximum=65535, restart=True),
    Setting("session_days", "int", 30, "sessions", "Stay signed in for",
            "A browser that is not used for this long has to sign in again.",
            minimum=1, maximum=365, unit="days"),
    Setting("public_status_enabled", "bool", True, "public", "Publish the status page",
            "Off hides /status and /status.json completely."),
    Setting("public_pc_detail", "choice", "counts", "public", "PCs on the status page",
            "Names can reveal who owns which computer; addresses are never shown.",
            choices=[("counts", "Counts only"),
                     ("status", "Status of each PC, without names"),
                     ("names", "Names and status of each PC")]),
    Setting("public_show_wol_activity", "bool", True, "public", "Show wake activity",
            "Number of wake requests and the time and result of the latest one."),
    Setting("public_show_system", "bool", True, "public", "Show device load",
            "CPU, memory, battery and uptime of the device running this server."),
    Setting("public_show_internet", "bool", True, "public", "Show internet connectivity"),
    Setting("public_show_version", "bool", True, "public", "Show version and update status"),
    Setting("status_checks_enabled", "bool", True, "monitoring", "Check whether PCs are reachable",
            "Sends one ping or TCP probe per PC per interval. Each PC chooses its method."),
    Setting("status_check_interval", "int", 60, "monitoring", "PC check interval",
            "After a wake request the PC is checked every 10 seconds for three minutes.",
            minimum=15, maximum=3600, unit="seconds"),
    Setting("internet_check_enabled", "bool", True, "monitoring", "Check internet connectivity"),
    Setting("internet_check_interval", "int", 60, "monitoring", "Internet check interval",
            minimum=15, maximum=3600, unit="seconds"),
    Setting("metrics_interval", "int", 5, "monitoring", "Device load sample interval",
            "How often CPU, memory and network use are sampled for the System page.",
            minimum=2, maximum=60, unit="seconds"),
    Setting("page_refresh_interval", "int", 10, "monitoring", "Live page refresh",
            "How often the dashboard and status page update while open. 0 turns it off.",
            minimum=0, maximum=300, unit="seconds"),
    Setting("event_retention_days", "int", 90, "history", "Keep activity for",
            "Older sign-in, change and system events are deleted automatically.",
            minimum=1, maximum=3650, unit="days"),
    Setting("wol_retention_days", "int", 365, "history", "Keep wake history for",
            minimum=1, maximum=3650, unit="days"),
    Setting("log_client_addresses", "bool", True, "history", "Record which device sent a wake",
            "Stores the IP address of the browser that pressed Wake. Sign-in attempts always "
            "record it, because the brute-force lockout depends on it."),
    Setting("updates_enabled", "bool", True, "updates", "Install updates automatically",
            "launcher.py checks GitHub every five minutes and installs new releases, "
            "keeping the previous one for rollback. Your database is never replaced."),
]

BY_KEY = dict((setting.key, setting) for setting in DEFINITIONS)

_cache = {}
_lock = threading.Lock()


def parse(setting, raw):
    """The typed value of `raw` (form or database text) for `setting`, else ValueError."""
    if setting.kind == "bool":
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in ("1", "true", "on", "yes"):
            return True
        if text in ("0", "false", "off", "no", ""):
            return False
        raise ValueError("Choose on or off.")
    if setting.kind == "int":
        try:
            value = int(str(raw).strip())
        except ValueError:
            raise ValueError("Enter a whole number.")
        if setting.minimum is not None and value < setting.minimum:
            raise ValueError("Enter %d or more." % setting.minimum)
        if setting.maximum is not None and value > setting.maximum:
            raise ValueError("Enter %d or less." % setting.maximum)
        return value
    if setting.kind == "choice":
        value = str(raw).strip()
        if value not in [choice for choice, _ in setting.choices]:
            raise ValueError("Choose one of the options.")
        return value
    return str(raw)


def to_text(setting, value):
    if setting.kind == "bool":
        return "1" if value else "0"
    return str(value)


def load(conn):
    """Read every setting into the cache. A stored value that no longer parses falls back
    to its default instead of stopping the server."""
    values = dict((s.key, s.default) for s in DEFINITIONS)
    for row in conn.execute("SELECT key, value FROM settings"):
        setting = BY_KEY.get(row["key"])
        if setting is None:
            continue                    # left by a newer release; keep it, ignore it
        try:
            values[setting.key] = parse(setting, row["value"])
        except ValueError:
            pass
    with _lock:
        _cache.clear()
        _cache.update(values)


def get(key):
    value = _cache.get(key)
    return BY_KEY[key].default if value is None else value


def snapshot():
    return dict((s.key, get(s.key)) for s in DEFINITIONS)


def save(conn, changes):
    """Store typed values. Returns the keys whose value actually changed."""
    changed = [key for key, value in changes.items() if get(key) != value]
    if changed:
        stamp = db.now()
        with db.transaction(conn):
            for key in changed:
                conn.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) "
                             "VALUES (?, ?, ?)", (key, to_text(BY_KEY[key], changes[key]), stamp))
        with _lock:
            for key in changed:
                _cache[key] = changes[key]
    return changed


def describe(key, value):
    """A value as the settings page words it, for activity messages."""
    setting = BY_KEY[key]
    if setting.kind == "bool":
        return "on" if value else "off"
    if setting.kind == "choice":
        return dict(setting.choices).get(value, value)
    return "%s %s" % (value, setting.unit) if setting.unit else str(value)
