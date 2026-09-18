"""One-time import of config.json, the settings file used before wol.db existed.

At startup, when config.json exists and has not been imported yet, everything it held
moves into wol.db in one transaction: the password becomes a bcrypt password hash, the
secret key is kept (so the session cookie format stays valid), the server port becomes a
setting and the target becomes a PC. From then on config.json is never read again.

The file itself is left untouched for ten minutes. launcher.py can still roll back to
the previous release during that time, and that release needs config.json, password
included. After that the file is renamed to config.json.migrated with the password and
secret key removed, so no plaintext password stays on the device.
"""
import json
import os

from . import BASE_DIR, activity, db, passwords, pcs, runtime, settings

# What the pre-database server used for keys missing from config.json.
LEGACY_DEFAULTS = {
    "password": "CHANGE_YOUR_PASSWORD",
    "target_mac": "244BFE070CE2",
    "target_ips": ["192.168.1.25", "192.168.1.255"],
    "wol_ports": [7, 9],
    "server_port": 5000,
}
PLACEHOLDER_PASSWORD = "CHANGE_YOUR_PASSWORD"
PROVEN_AFTER = 600          # seconds; well past launcher.py's 90 s health check
LEGACY_PC_NAME = "My PC"


def config_path(base_dir=BASE_DIR):
    return os.path.join(base_dir, "config.json")


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _read(path):
    with open(path, encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise ValueError("it does not contain a JSON object")
    return loaded


def import_if_present(conn, base_dir=BASE_DIR):
    """Import config.json into an installation that has not been set up yet.

    Returns a one-line summary, or None when there was nothing to import. A file that
    cannot be read is reported and left alone; nothing is lost.
    """
    path = config_path(base_dir)
    if not os.path.exists(path) or db.get_meta(conn, "legacy_config_imported_at"):
        return None
    if db.get_meta(conn, "setup_completed_at"):
        db.set_meta(conn, "legacy_config_imported_at", "skipped " + db.now())
        activity.record(conn, "migration.config_failed",
                        "config.json was found but not imported: this installation was "
                        "already set up in the browser", level="warning", success=False)
        return None
    try:
        loaded = _read(path)
    except (OSError, ValueError) as e:
        activity.record(conn, "migration.config_failed",
                        "config.json could not be read (%s). Nothing was imported. Fix the "
                        "file and restart, or finish setup in the browser to start fresh." % e,
                        level="error", success=False)
        return None

    config = dict(LEGACY_DEFAULTS)
    config.update(loaded)
    notes = []

    password = config.get("password")
    password = "" if password is None else str(password)
    if not password or password == PLACEHOLDER_PASSWORD:
        password_hash = None
        notes.append("the password was still the default placeholder, so setup asks for a new one")
    elif len(password.encode("utf-8")) > passwords.MAX_BYTES or "\x00" in password:
        password_hash = None
        notes.append("the password is longer than bcrypt allows, so setup asks for a new one")
    else:
        password_hash = passwords.hash_password(password)

    secret = config.get("secret_key")
    port = config.get("server_port")
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        notes.append("server port %r is not valid, so the default 5000 is used" % (port,))
        port = 5000

    mac = pcs.parse_mac(config.get("target_mac"))
    mac_text = pcs.format_mac(mac) if mac else str(config.get("target_mac"))
    hosts, broadcasts = [], []
    for address in _as_list(config.get("target_ips")):
        address = str(address).strip()
        if not address:
            continue
        target = broadcasts if address.endswith(".255") else hosts
        if address not in target:
            target.append(address)
    ports = []
    for port_value in _as_list(config.get("wol_ports")):
        try:
            number = int(port_value)
        except (TypeError, ValueError):
            number = 0
        if 1 <= number <= 65535:
            if number not in ports:
                ports.append(number)
        else:
            notes.append("port %r was dropped because it is not a valid UDP port" % (port_value,))
    valid_hosts = [address for address in hosts if _valid_address(address)]
    enabled = bool(mac and (hosts or broadcasts) and ports)
    if not enabled:
        notes.append("the PC was imported disabled because its settings are incomplete or invalid")

    values = {
        "name": LEGACY_PC_NAME, "mac": mac_text, "hosts": hosts, "broadcasts": broadcasts,
        "ports": ports, "enabled": enabled, "status_port": None,
        "status_method": "ping" if valid_hosts else "none",
        "description": "Imported from config.json.",
    }
    stamp = db.now()
    with db.transaction(conn):
        if isinstance(secret, str) and len(secret) >= 16:
            db.set_meta(conn, "secret_key", secret)
        settings.save(conn, {"server_port": port})
        pc_id = pcs.create(conn, values)
        if password_hash:
            conn.execute("INSERT INTO users (username, password_hash, session_epoch, created_at, "
                         "password_changed_at) VALUES ('admin', ?, 1, ?, ?)",
                         (password_hash, stamp, stamp))
            db.set_meta(conn, "setup_completed_at", stamp)
        db.set_meta(conn, "legacy_config_imported_at", stamp)
        summary = ("Imported config.json: server port %d, PC \"%s\" (%s, %d addresses, ports %s)%s"
                   % (port, LEGACY_PC_NAME, mac_text, len(hosts) + len(broadcasts),
                      ", ".join(str(p) for p in ports) or "none",
                      ", password stored as a bcrypt password hash" if password_hash else ""))
        if notes:
            summary += ". Note: " + "; ".join(notes)
        activity.record(conn, "migration.config_imported", summary,
                        level="warning" if notes else "info", success=True,
                        pc={"id": pc_id, "name": LEGACY_PC_NAME})
    return summary


def _valid_address(address):
    try:
        pcs.check_address(address)
        return True
    except ValueError:
        return False


def retire_when_proven(base_dir=BASE_DIR, proven_after=PROVEN_AFTER):
    """Rename an imported config.json to config.json.migrated, minus its secrets, once
    no rollback to the release that read it can happen any more."""
    if runtime.uptime() < proven_after or runtime.launcher_generation() == 1:
        # The old launcher.py still reads config.json to find the server port.
        return False
    path = config_path(base_dir)
    if not os.path.exists(path):
        return False
    with db.session() as conn:
        imported = db.get_meta(conn, "legacy_config_imported_at")
        if not imported or imported.startswith("skipped"):
            return False
        try:
            content = _read(path)
        except (OSError, ValueError):
            content = {}
        content.pop("password", None)
        content.pop("secret_key", None)
        content["_note"] = ("Imported into wol.db on %s. WOL Controller no longer reads this "
                            "file. The password and secret key were removed." % imported[:10])
        target = path + ".migrated"
        temporary = target + ".tmp"
        with open(temporary, "w", encoding="utf-8") as f:
            json.dump(content, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, target)
        os.remove(path)
        db.set_meta(conn, "legacy_config_retired_at", db.now())
        activity.record(conn, "migration.config_retired",
                        "config.json renamed to config.json.migrated, without the password "
                        "and secret key. Its settings live in wol.db now.", success=True)
    return True
