"""The activity log (events table) and the wake history (wol_requests table).

Every event is also printed to the console, as before. Messages are written for people
and never contain passwords, hashes, session data or the secret key.
"""
import logging
from datetime import datetime, timedelta, timezone

from . import db, settings

logger = logging.getLogger("wol")

CATEGORIES = [
    ("auth", "Sign-in and security"),
    ("setup", "Setup"),
    ("pc", "PC changes"),
    ("wol", "Wake requests"),
    ("status", "PC reachability"),
    ("settings", "Settings"),
    ("system", "System"),
    ("migration", "Migration"),
]

TYPES = [
    ("auth.login_succeeded", "Signed in"),
    ("auth.login_failed", "Sign-in failed"),
    ("auth.lockout", "Sign-in locked"),
    ("auth.logout", "Signed out"),
    ("auth.password_changed", "Password changed"),
    ("auth.password_change_failed", "Password change refused"),
    ("auth.password_reset", "Password reset"),
    ("auth.sessions_revoked", "Other sessions signed out"),
    ("setup.completed", "Setup completed"),
    ("setup.code_failed", "Wrong setup code"),
    ("pc.created", "PC added"),
    ("pc.updated", "PC edited"),
    ("pc.deleted", "PC deleted"),
    ("pc.enabled", "PC enabled"),
    ("pc.disabled", "PC disabled"),
    ("wol.sent", "Wake sent"),
    ("wol.partial", "Wake partly sent"),
    ("wol.failed", "Wake failed"),
    ("status.online", "PC answered"),
    ("status.offline", "PC stopped answering"),
    ("settings.changed", "Settings changed"),
    ("system.started", "Server started"),
    ("system.restart", "Restart requested"),
    ("system.error", "Error"),
    ("system.database", "Database problem"),
    ("system.internet_up", "Internet reachable"),
    ("system.internet_down", "Internet unreachable"),
    ("system.backup", "Backup downloaded"),
    ("system.cleanup", "Old history deleted"),
    ("migration.config_imported", "config.json imported"),
    ("migration.config_retired", "config.json retired"),
    ("migration.config_failed", "config.json not imported"),
    ("migration.schema", "Database upgraded"),
]
TYPE_LABELS = dict(TYPES)
SECURITY_TYPES = ("auth.", "setup.", "system.backup", "migration.config")
MAX_EVENTS = 20000          # a hard ceiling on top of the retention period

_LOG_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}


def record(conn, type, message, level="info", success=None, pc=None, client_ip=None):
    """Log one event to the console and the database. `pc` is a PC row or dict."""
    logger.log(_LOG_LEVELS.get(level, logging.INFO), message)
    conn.execute(
        "INSERT INTO events (created_at, type, level, success, pc_id, pc_name, client_ip, message) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (db.now(), type, level, None if success is None else int(bool(success)),
         pc["id"] if pc else None, pc["name"] if pc else None, client_ip, message))


def record_safely(type, message, level="info", **extra):
    """record() from a background thread, which must never die because of a log line."""
    try:
        with db.session() as conn:
            record(conn, type, message, level, **extra)
    except Exception as e:
        logger.warning("Could not store event (%s): %s", e, message)


def category_of(type):
    return type.split(".", 1)[0]


def since_cutoff(period):
    hours = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(period)
    if hours is None:
        return None
    return db.to_iso(datetime.now(timezone.utc) - timedelta(hours=hours))


def query_events(conn, category=None, type=None, pc_id=None, period=None, outcome=None,
                 security=False, limit=50, offset=0):
    """(rows, has_more) for the Activity page and the per-PC and security views."""
    clauses, params = [], []
    if type:
        clauses.append("type = ?")
        params.append(type)
    elif category:
        clauses.append("type LIKE ?")
        params.append(category + ".%")
    if security:
        clauses.append("(" + " OR ".join("type LIKE ?" for _ in SECURITY_TYPES) + ")")
        params.extend(prefix + "%" for prefix in SECURITY_TYPES)
    if pc_id is not None:
        clauses.append("pc_id = ?")
        params.append(pc_id)
    cutoff = since_cutoff(period)
    if cutoff:
        clauses.append("created_at >= ?")
        params.append(cutoff)
    if outcome in ("success", "failure"):
        clauses.append("success = ?")
        params.append(1 if outcome == "success" else 0)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute("SELECT * FROM events%s ORDER BY id DESC LIMIT ? OFFSET ?" % where,
                        params + [limit + 1, offset]).fetchall()
    return rows[:limit], len(rows) > limit


def record_wol(conn, pc, source, result, sent, total, targets, error, client_ip):
    """Store one wake request. Returns its id."""
    if not settings.get("log_client_addresses"):
        client_ip = None
    return conn.execute(
        "INSERT INTO wol_requests (created_at, pc_id, pc_name, mac, source, result, "
        "packets_sent, packets_total, targets, error, client_ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (db.now(), pc["id"], pc["name"], pc["mac"], source, result, sent, total,
         " ".join(targets), error, client_ip)).lastrowid


def wol_requests(conn, pc_id=None, limit=20):
    if pc_id is None:
        return conn.execute("SELECT * FROM wol_requests ORDER BY id DESC LIMIT ?",
                            (limit,)).fetchall()
    return conn.execute("SELECT * FROM wol_requests WHERE pc_id = ? ORDER BY id DESC LIMIT ?",
                        (pc_id, limit)).fetchall()


def wol_summary(conn):
    """Totals over the kept history, for the dashboard, admin overview and status page."""
    row = conn.execute(
        "SELECT count(*) AS total, "
        "sum(result = 'sent') AS sent, sum(result = 'partial') AS partial, "
        "sum(result = 'failed') AS failed, sum(created_at >= ?) AS last_day, "
        "max(CASE WHEN result != 'failed' THEN created_at END) AS last_success_at "
        "FROM wol_requests", (since_cutoff("24h"),)).fetchone()
    last = conn.execute("SELECT created_at, result, pc_name FROM wol_requests "
                        "ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "total": row["total"] or 0,
        "sent": row["sent"] or 0,
        "partial": row["partial"] or 0,
        "failed": row["failed"] or 0,
        "last_day": row["last_day"] or 0,
        "last_success_at": row["last_success_at"],
        "last": dict(last) if last else None,
    }


def wol_per_pc(conn):
    """{pc_id: {"count", "last_at", "last_result"}} in two queries for the whole dashboard."""
    stats = {}
    for row in conn.execute("SELECT pc_id, count(*) AS count, max(id) AS last_id "
                            "FROM wol_requests WHERE pc_id IS NOT NULL GROUP BY pc_id"):
        stats[row["pc_id"]] = {"count": row["count"], "last_id": row["last_id"]}
    if stats:
        ids = [value["last_id"] for value in stats.values()]
        placeholders = ",".join("?" * len(ids))
        for row in conn.execute("SELECT id, pc_id, created_at, result FROM wol_requests "
                                "WHERE id IN (%s)" % placeholders, ids):
            stats[row["pc_id"]].update(last_at=row["created_at"], last_result=row["result"])
    return stats


def cleanup(conn):
    """Delete history older than the retention settings. Returns (events, wake requests)."""
    event_cutoff = db.to_iso(datetime.now(timezone.utc)
                             - timedelta(days=settings.get("event_retention_days")))
    wol_cutoff = db.to_iso(datetime.now(timezone.utc)
                           - timedelta(days=settings.get("wol_retention_days")))
    with db.transaction(conn):
        events = conn.execute("DELETE FROM events WHERE created_at < ?", (event_cutoff,)).rowcount
        events += conn.execute(
            "DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC "
            "LIMIT 1 OFFSET ?)", (MAX_EVENTS,)).rowcount
        wakes = conn.execute("DELETE FROM wol_requests WHERE created_at < ?",
                             (wol_cutoff,)).rowcount
    return events, wakes
