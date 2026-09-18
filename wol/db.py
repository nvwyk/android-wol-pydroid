"""SQLite storage. wol.db is the single source of truth for everything the device owns.

Every request and every background thread opens its own short-lived connection; nothing
shares one. Writes go through transaction(), which takes the write lock up front
(BEGIN IMMEDIATE) so two writers queue instead of failing halfway.

The schema version lives in PRAGMA user_version. Migrations only ever add tables,
columns and indexes, so an older release that launcher.py rolls back to can still read
a database a newer release has already upgraded.
"""
import contextlib
import logging
import os
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger("wol")

SCHEMA_VERSION = 1

# One list of statements per schema version. Never edit a released entry; append a new one.
MIGRATIONS = {
    1: [
        """CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
        """CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            session_epoch INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            password_changed_at TEXT NOT NULL,
            last_login_at TEXT,
            last_login_ip TEXT
        )""",
        """CREATE TABLE pcs (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            mac TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            status_method TEXT NOT NULL DEFAULT 'ping'
                CHECK (status_method IN ('none', 'ping', 'tcp')),
            status_port INTEGER CHECK (status_port IS NULL OR status_port BETWEEN 1 AND 65535),
            sort_order INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        "CREATE UNIQUE INDEX pcs_name ON pcs (name COLLATE NOCASE)",
        """CREATE TABLE pc_addresses (
            id INTEGER PRIMARY KEY,
            pc_id INTEGER NOT NULL REFERENCES pcs (id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK (kind IN ('host', 'broadcast')),
            address TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0
        )""",
        "CREATE INDEX pc_addresses_pc ON pc_addresses (pc_id)",
        """CREATE TABLE pc_ports (
            id INTEGER PRIMARY KEY,
            pc_id INTEGER NOT NULL REFERENCES pcs (id) ON DELETE CASCADE,
            port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            position INTEGER NOT NULL DEFAULT 0
        )""",
        "CREATE INDEX pc_ports_pc ON pc_ports (pc_id)",
        # History keeps a copy of the PC's name and MAC, so it still reads correctly after
        # the PC is renamed or deleted (deleting a PC only clears pc_id here).
        """CREATE TABLE wol_requests (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            pc_id INTEGER REFERENCES pcs (id) ON DELETE SET NULL,
            pc_name TEXT NOT NULL,
            mac TEXT NOT NULL,
            source TEXT NOT NULL,
            result TEXT NOT NULL CHECK (result IN ('sent', 'partial', 'failed')),
            packets_sent INTEGER NOT NULL DEFAULT 0,
            packets_total INTEGER NOT NULL DEFAULT 0,
            targets TEXT NOT NULL DEFAULT '',
            error TEXT,
            client_ip TEXT
        )""",
        "CREATE INDEX wol_requests_created ON wol_requests (created_at)",
        "CREATE INDEX wol_requests_pc ON wol_requests (pc_id, created_at)",
        """CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            created_at TEXT NOT NULL,
            type TEXT NOT NULL,
            level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info', 'warning', 'error')),
            success INTEGER CHECK (success IS NULL OR success IN (0, 1)),
            pc_id INTEGER REFERENCES pcs (id) ON DELETE SET NULL,
            pc_name TEXT,
            client_ip TEXT,
            message TEXT NOT NULL
        )""",
        "CREATE INDEX events_created ON events (created_at)",
        "CREATE INDEX events_type ON events (type, created_at)",
        "CREATE INDEX events_pc ON events (pc_id, created_at)",
        "CREATE INDEX events_client ON events (client_ip, type, created_at)",
    ],
}

_path = None


class DatabaseUnavailable(Exception):
    """The database file cannot be opened or read. The app keeps serving an error page."""


def configure(path):
    global _path
    _path = path


def path():
    return _path


def connect(database=None):
    """A new connection in autocommit mode; transaction() opens explicit transactions."""
    try:
        conn = sqlite3.connect(database or _path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
    except sqlite3.Error as e:
        raise DatabaseUnavailable(str(e))
    return conn


def get():
    """The current Flask request's connection, opened on first use and closed by
    close_request() when the request ends."""
    from flask import g
    if "_db" not in g:
        g._db = connect()
    return g._db


def close_request(exception=None):
    from flask import g
    conn = g.pop("_db", None)
    if conn is not None:
        conn.close()


@contextlib.contextmanager
def session(database=None):
    """A connection for code outside a request: background threads and startup."""
    conn = connect(database)
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def transaction(conn):
    """BEGIN IMMEDIATE ... COMMIT, or ROLLBACK on any exception.

    A transaction() inside another one on the same connection joins the outer one, so
    helpers can be combined into one atomic change.
    """
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def now():
    """The current time as stored in the database: UTC, ISO 8601, second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text):
    """A stored timestamp as an aware datetime, or None."""
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def schema_version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


def migrate(conn):
    """Bring the schema up to SCHEMA_VERSION. Returns (version before, version after)."""
    before = schema_version(conn)
    if before > SCHEMA_VERSION:
        # A newer release upgraded this database and launcher.py rolled back to this
        # one. Migrations are additive, so the tables this release knows still work.
        logger.warning("Database schema %d is newer than this release (%d); continuing",
                       before, SCHEMA_VERSION)
        return before, before
    for version in range(before + 1, SCHEMA_VERSION + 1):
        with transaction(conn):
            for statement in MIGRATIONS[version]:
                conn.execute(statement)
            conn.execute("PRAGMA user_version = %d" % version)
    return before, max(before, SCHEMA_VERSION)


def initialize(database):
    """Create or upgrade the database at startup. Raises DatabaseUnavailable."""
    configure(database)
    try:
        with session() as conn:
            before, after = migrate(conn)
            problem = conn.execute("PRAGMA quick_check").fetchone()[0]
    except sqlite3.Error as e:
        raise DatabaseUnavailable(str(e))
    try:
        os.chmod(database, 0o600)       # best effort: shared Android storage ignores it
    except OSError:
        pass
    return before, after, None if problem == "ok" else problem


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, str(value)))


def backup(destination, database=None):
    """Write a consistent copy of the database to `destination`, even while it is in use."""
    with session(database) as source:
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
        finally:
            target.close()


def health():
    """(ok, detail) for /health: can the database be opened and read right now?"""
    try:
        with session() as conn:
            conn.execute("SELECT count(*) FROM meta").fetchone()
            return True, schema_version(conn)
    except (sqlite3.Error, DatabaseUnavailable) as e:
        return False, str(e)
