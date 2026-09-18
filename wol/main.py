"""Startup: open the database, import config.json once, start the background threads
and serve the web interface. Also two maintenance commands for the device console:

    python server.py --reset-password   set a new admin password (signs everyone out)
    python server.py --set-port 5000    change the server port without the web interface
"""
import argparse
import getpass
import logging
import os
import secrets
import sqlite3

from . import BASE_DIR, activity, auth, db, legacy, monitor, passwords, release_id, runtime, \
    settings, system, web

logger = logging.getLogger("wol")

DATABASE_NAME = "wol.db"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # no 0/O or 1/I to mistype


def setup_logging():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s",
                        datefmt="%H:%M:%S")
    # Werkzeug logs every request; on a phone console that buries the events that matter.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def new_setup_code():
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return raw[:4] + "-" + raw[4:]


def prepare(base_dir=BASE_DIR, database=None):
    """Open and upgrade wol.db, import config.json if this is an old installation, load
    the settings. Returns the session secret key, or None if the database is unusable."""
    path = database or os.path.join(base_dir, DATABASE_NAME)
    try:
        before, after, problem = db.initialize(path)
        with db.session() as conn:
            if 0 < before < after:
                activity.record(conn, "migration.schema",
                                "Database upgraded from schema %d to %d" % (before, after),
                                success=True)
            if problem:
                runtime.database_warning = problem
                activity.record(conn, "system.database",
                                "Database integrity check reported: %s" % problem, level="error")
            summary = legacy.import_if_present(conn, base_dir)
            if summary:
                logger.info("Existing installation migrated from config.json to %s", DATABASE_NAME)
            settings.load(conn)
            secret = db.get_meta(conn, "secret_key")
            if not secret:
                # Persisted so sessions survive restarts caused by updates.
                secret = secrets.token_hex(32)
                db.set_meta(conn, "secret_key", secret)
            runtime.setup_done = auth.setup_complete(conn)
        return secret
    except (db.DatabaseUnavailable, sqlite3.Error) as e:
        runtime.database_error = ("The database file %s could not be opened or read (%s). "
                                  "Nothing was changed. See Recovery in the README."
                                  % (DATABASE_NAME, e))
        logger.error("%s", runtime.database_error)
        return None


def serve(base_dir=BASE_DIR):
    runtime.build = release_id(base_dir)[:7]
    secret = prepare(base_dir)
    app = web.create_app(secret or secrets.token_hex(32))
    port = settings.get("server_port")
    runtime.listening_port = port
    logger.info("Starting WOL Controller %s on port %d", runtime.version_label(), port)
    if secret:
        with db.session() as conn:
            activity.record(conn, "system.started", "Server started, version %s, port %d"
                            % (runtime.version_label(), port))
        if passwords.backend() == "builtin":
            logger.warning("The bcrypt package is not installed; using the built-in bcrypt. "
                           "Install it for stronger password hashes (see README).")
        if runtime.launcher_generation() == 1:
            logger.warning("This launcher.py only updates server.py. Copy the current "
                           "launcher.py from GitHub to keep updates working.")
        if not runtime.setup_done:
            runtime.setup_code = new_setup_code()
            logger.info("First-run setup: open http://%s:%d/setup and enter the setup code %s",
                        system.lan_address() or "this-device", port, runtime.setup_code)
        monitor.start()
    try:
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)
    except (OSError, SystemExit) as e:
        # Werkzeug reports a port it cannot bind and exits; say how to get out of it.
        if isinstance(e, SystemExit) and not e.code:
            raise
        logger.error("Cannot listen on port %d. Another app may be using it. Choose another "
                     "port with: python server.py --set-port 5000", port)
        return 1
    return 0


def reset_password(base_dir=BASE_DIR):
    """Set a new admin password from the device console, for a forgotten password."""
    if prepare(base_dir) is None:
        return 1
    password = getpass.getpass("New admin password: ")
    problem = passwords.problem(password, getpass.getpass("Repeat the new password: "))
    if problem:
        print(problem)
        return 1
    password_hash = passwords.hash_password(password)
    stamp = db.now()
    with db.session() as conn:
        with db.transaction(conn):
            user = auth.get_admin(conn)
            if user is None:
                conn.execute("INSERT INTO users (username, password_hash, session_epoch, "
                             "created_at, password_changed_at) VALUES (?, ?, 1, ?, ?)",
                             (auth.USERNAME, password_hash, stamp, stamp))
                db.set_meta(conn, "setup_completed_at", stamp)
            else:
                conn.execute("UPDATE users SET password_hash = ?, password_changed_at = ?, "
                             "session_epoch = session_epoch + 1 WHERE id = ?",
                             (password_hash, stamp, user["id"]))
            activity.record(conn, "auth.password_reset", "Admin password reset from the device "
                            "console; every browser was signed out", success=True)
    print("Password changed. Every browser has to sign in again; no restart is needed.")
    return 0


def set_port(value, base_dir=BASE_DIR):
    """Change the server port from the device console, for a port the web interface
    cannot be reached on any more."""
    if prepare(base_dir) is None:
        return 1
    try:
        port = settings.parse(settings.BY_KEY["server_port"], value)
    except ValueError as e:
        print("Port %s: %s" % (value, e))
        return 1
    with db.session() as conn:
        before = settings.get("server_port")
        if settings.save(conn, {"server_port": port}):
            activity.record(conn, "settings.changed", "Server port changed from %d to %d on the "
                            "device console" % (before, port), success=True)
    print("Server port is %d. Restart the launcher (or the server) to use it." % port)
    return 0


def self_check():
    """What launcher.py runs on a downloaded release before switching to it: every module
    imports (that already happened to get here) and every template compiles. Touches no
    database and opens no port."""
    app = web.create_app("self-check")
    templates = app.jinja_env.list_templates()
    for name in templates:
        app.jinja_env.get_template(name)
    static = os.path.join(os.path.dirname(os.path.abspath(web.__file__)), "static")
    missing = [name for name in ("app.css", "app.js") if not os.path.isfile(os.path.join(static, name))]
    if missing:
        print("Missing static files: %s" % ", ".join(missing))
        return 1
    print("Self-check passed: %d templates compiled" % len(templates))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="server.py", description="WOL Controller server")
    parser.add_argument("--reset-password", action="store_true",
                        help="set a new admin password and sign every browser out")
    parser.add_argument("--set-port", metavar="PORT", help="change the server port")
    parser.add_argument("--check", action="store_true",
                        help="check that this copy of the application can start (used by launcher.py)")
    args = parser.parse_args(argv)
    setup_logging()
    if args.check:
        return self_check()
    if args.reset_password:
        return reset_password()
    if args.set_port:
        return set_port(args.set_port)
    return serve()
