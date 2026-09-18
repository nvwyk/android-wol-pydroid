"""The Flask application: request hooks, security headers, template helpers, error pages.

Pages are server-rendered. The stylesheet and script are static files, so the Content
Security Policy allows no inline code at all. No CDN is used: the interface keeps
working on the LAN while the device has no internet.
"""
import logging
import sqlite3
from datetime import timedelta

from flask import Flask, flash, g, jsonify, redirect, render_template, request, url_for
from markupsafe import Markup, escape
from werkzeug.exceptions import HTTPException

from . import APP_NAME, activity, auth, db, formatting, icons, runtime, settings

logger = logging.getLogger("wol")

# Reachable without signing in, and before setup is done.
OPEN_ENDPOINTS = {"static", "main.health", "main.robots", "main.setup", "main.status",
                  "main.status_json"}
# Reachable while the database is unusable: everything else shows the error page.
DEGRADED_ENDPOINTS = {"static", "main.health", "main.robots"}


def create_app(secret_key, testing=False):
    app = Flask(__name__)
    app.secret_key = secret_key
    app.config.update(
        # Cookies ignore ports, so the default name would clash with other apps on this host.
        SESSION_COOKIE_NAME="wol_session",
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True,
        PERMANENT_SESSION_LIFETIME=timedelta(days=settings.get("session_days")),
        MAX_CONTENT_LENGTH=64 * 1024,
        # Static URLs carry the build id, so browsers may keep them for a year.
        SEND_FILE_MAX_AGE_DEFAULT=365 * 24 * 3600,
        TESTING=testing,
    )

    from . import admin, views
    app.register_blueprint(views.bp)
    app.register_blueprint(admin.bp, url_prefix="/admin")
    app.teardown_appcontext(db.close_request)

    @app.before_request
    def guard():
        endpoint = request.endpoint or ""
        if runtime.database_error:
            if endpoint in DEGRADED_ENDPOINTS:
                return None
            return render_template("error.html", code=503, title="Database unavailable",
                                   message=runtime.database_error), 503
        # A settings change from Admin takes effect on the next request.
        app.permanent_session_lifetime = timedelta(days=settings.get("session_days"))
        if request.method == "POST" and not auth.csrf_valid():
            flash("That form had expired, so nothing was changed. Please try again.", "warning")
            return redirect(_same_page_or_home())
        if endpoint not in OPEN_ENDPOINTS and not setup_done():
            return redirect(url_for("main.setup"))
        return None

    @app.after_request
    def security_headers(response):
        extra = " ".join(g.get("csp_connect", []))
        response.headers.setdefault("Content-Security-Policy", (
            "default-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'%s; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            % (" " + extra if extra else "")))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # A private control panel belongs in nobody's search index or crawler cache.
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        if request.endpoint != "static":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.context_processor
    def template_context():
        try:
            user = None if runtime.database_error else auth.current_user()
        except (sqlite3.Error, db.DatabaseUnavailable):
            user = None
        return {
            "app_name": APP_NAME,
            "version": runtime.version_label(),
            "build": runtime.build or "dev",
            "icons": icons.ICONS,
            "favicon": icons.FAVICON,
            "csrf_token": auth.csrf_token,
            "user": user,
            "setting": settings.get,
        }

    app.add_template_filter(formatting.clock, "clock")
    app.add_template_filter(formatting.ago, "ago")
    app.add_template_filter(formatting.duration, "duration")
    app.add_template_filter(formatting.format_bytes, "bytes")
    app.add_template_filter(_when, "when")
    app.add_template_filter(_event_label, "event_label")

    @app.errorhandler(HTTPException)
    def http_error(error):
        titles = {400: "Bad request", 404: "Page not found", 405: "Not available here",
                  413: "Request too large", 429: "Too many requests"}
        messages = {
            400: "The request could not be understood.",
            404: "Nothing lives at this address.",
            405: "This address does not accept that kind of request. Use the buttons in the "
                 "interface instead.",
            413: "The form sent more data than this server accepts.",
        }
        if _wants_json():
            return jsonify(error=titles.get(error.code, error.name)), error.code
        return render_template("error.html", code=error.code,
                               title=titles.get(error.code, error.name),
                               message=messages.get(error.code, error.description)), error.code

    @app.errorhandler(sqlite3.Error)
    @app.errorhandler(db.DatabaseUnavailable)
    def database_error(error):
        logger.error("Database error on %s: %s", request.path, error)
        if _wants_json():
            return jsonify(error="Database unavailable"), 503
        return render_template("error.html", code=503, title="Database unavailable",
                               message="The database could not be read or written just now. "
                                       "Try again in a moment. If it keeps happening, see "
                                       "Troubleshooting in the README."), 503

    @app.errorhandler(Exception)
    def unexpected_error(error):
        # Logged in full on the console; the browser only gets a plain message.
        logger.exception("Unexpected error on %s %s", request.method, request.path)
        activity.record_safely("system.error", "Unexpected %s on %s %s"
                               % (type(error).__name__, request.method, request.path),
                               level="error")
        if _wants_json():
            return jsonify(error="Internal error"), 500
        return render_template("error.html", code=500, title="Something went wrong",
                               message="The server hit an unexpected error. It was logged; "
                                       "nothing else is affected."), 500

    return app


def setup_done():
    """True once setup has completed. Cached: an installation never becomes un-set-up."""
    if not runtime.setup_done:
        runtime.setup_done = auth.setup_complete(db.get())
    return runtime.setup_done


def _wants_json():
    return request.path.endswith(".json") or request.path.startswith("/api/") \
        or request.endpoint == "main.health"


def _same_page_or_home():
    """Where to send a browser whose form was rejected: the same page if it can be
    shown with GET, otherwise the start page."""
    adapter = request.url_rule and request.url_rule.map.bind(request.host)
    try:
        adapter.match(request.path, method="GET")
        return request.path
    except Exception:
        return url_for("main.dashboard")


def _when(moment):
    """A <time> element that reads 19:12:28 today and 2026-09-16 19:12 before today."""
    local = formatting.local(moment)
    if local is None:
        return ""
    return Markup('<time datetime="%s" title="%s">%s</time>') % (
        escape(local.isoformat(timespec="seconds")),
        escape(local.strftime("%Y-%m-%d %H:%M:%S")),
        escape(formatting.clock(local)))


def _event_label(type):
    return activity.TYPE_LABELS.get(type, type)
