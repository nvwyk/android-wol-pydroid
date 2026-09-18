"""Sign-in, sessions, CSRF protection and brute-force protection for the admin account.

Sessions are Flask's signed cookies. Each one carries the user id and that user's
session epoch; bumping the epoch (password change, "sign out other devices") makes every
older cookie worthless at once, without keeping session state on the server.

Failed password attempts are stored as events, so the lockout survives restarts: five
failures from one address within fifteen minutes block that address until the oldest of
them is fifteen minutes old.
"""
import hmac
import secrets
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from . import db, passwords

USERNAME = "admin"
MAX_FAILURES = 5
LOCKOUT_WINDOW = 15 * 60
FAILURE_TYPES = ("auth.login_failed", "auth.password_change_failed", "setup.code_failed")

# A bcrypt check can take a second on a phone; at most two run at once, so a burst of
# guesses cannot tie up every request thread.
_checks = threading.BoundedSemaphore(2)


def client_address():
    # The server faces the LAN directly; no proxy headers are trusted.
    return request.remote_addr or "unknown"


def lockout_seconds(conn, client):
    """How long `client` must wait before another password attempt. 0 means go ahead."""
    now = datetime.now(timezone.utc)
    since = db.to_iso(now - timedelta(seconds=LOCKOUT_WINDOW))
    rows = conn.execute(
        "SELECT created_at FROM events WHERE client_ip = ? AND type IN (?, ?, ?) "
        "AND created_at > ? ORDER BY created_at DESC LIMIT ?",
        (client,) + FAILURE_TYPES + (since, MAX_FAILURES)).fetchall()
    if len(rows) < MAX_FAILURES:
        return 0
    oldest = db.parse_time(rows[-1]["created_at"])
    return max(1, int((oldest + timedelta(seconds=LOCKOUT_WINDOW) - now).total_seconds()) + 1)


def minutes(seconds):
    """Whole minutes, rounded up, so a wait of 30 seconds never reads as 0 min."""
    return -(-seconds // 60)


def check_password(stored, candidate):
    """verify_password() with at most two checks at a time. None when the server is busy."""
    if not _checks.acquire(timeout=15):
        return None
    try:
        return passwords.verify_password(candidate, stored)
    finally:
        _checks.release()


def get_admin(conn):
    return conn.execute("SELECT * FROM users ORDER BY id LIMIT 1").fetchone()


def setup_complete(conn):
    return db.get_meta(conn, "setup_completed_at") is not None


def start_session(user):
    """Sign this browser in as `user`. A fresh session also gets a fresh CSRF token."""
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    session["epoch"] = user["session_epoch"]
    session["since"] = db.now()
    session["csrf"] = secrets.token_urlsafe(32)
    g.pop("user", None)


def current_user():
    """The signed-in user for this request, or None. Checked against the database once."""
    if "user" not in g:
        g.user = None
        uid, epoch = session.get("uid"), session.get("epoch")
        if isinstance(uid, int) and isinstance(epoch, int):
            row = db.get().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            if row is not None and row["session_epoch"] == epoch:
                g.user = row
    return g.user


def revoke_other_sessions(conn, user):
    """Invalidate every session of `user`, then keep this browser signed in."""
    conn.execute("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?", (user["id"],))
    fresh = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    since = session.get("since")
    start_session(fresh)
    if since:
        session["since"] = since
    return fresh


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            if request.path.endswith(".json") or request.path.startswith("/api/"):
                return jsonify(error="Sign in required"), 401
            return redirect(url_for("main.login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)
    return wrapper


def safe_next(target):
    """Only local paths are followed after sign-in, never another site."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


def csrf_token():
    token = session.get("csrf")
    if not token:
        token = session["csrf"] = secrets.token_urlsafe(32)
    return token


def csrf_valid():
    expected = session.get("csrf", "")
    given = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    return bool(expected) and hmac.compare_digest(str(given).encode(), str(expected).encode())
