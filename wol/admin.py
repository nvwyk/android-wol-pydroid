"""Admin: overview, PC management, activity log, security and settings.

Every route in this blueprint needs a signed-in admin; require_admin() enforces that for
all of them at once, so a new route cannot forget it. Every change is written to the
activity log.
"""
import os
import platform
import socket
import tempfile

from flask import (Blueprint, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)

from . import activity, auth, db, formatting, monitor, passwords, pcs, runtime, settings, system, \
    wake

bp = Blueprint("admin", __name__)
PAGE_SIZE = 50


@bp.before_request
def require_admin():
    if auth.current_user() is None:
        return redirect(url_for("main.login", next=request.full_path.rstrip("?")))
    return None


def _pc_or_404(conn, pc_id):
    pc = pcs.get(conn, pc_id)
    if pc is None:
        abort(404)
    return pc


# --- Overview ----------------------------------------------------------------------------

def database_info(conn):
    try:
        size = os.path.getsize(db.path())
    except OSError:
        size = None
    counts = conn.execute("SELECT (SELECT count(*) FROM events) AS events, "
                          "(SELECT count(*) FROM wol_requests) AS wakes").fetchone()
    return {"path": db.path(), "size": formatting.format_bytes(size),
            "schema": db.schema_version(conn), "integrity": runtime.database_warning,
            "events": counts["events"], "wakes": counts["wakes"]}


def restart_pending():
    return runtime.listening_port is not None and settings.get("server_port") != runtime.listening_port


def notices(conn):
    found = []
    if runtime.database_warning:
        found.append(("error", "The database integrity check reported a problem: %s. Download "
                               "a backup, then see Recovery in the README."
                      % runtime.database_warning))
    if restart_pending():
        found.append(("warning", "The server port changes to %d after a restart. It still "
                                 "listens on %d." % (settings.get("server_port"),
                                                    runtime.listening_port)))
    if runtime.launcher_generation() == 1:
        found.append(("warning", "This server runs under an older launcher.py that only knows "
                                 "how to update server.py. Copy the current launcher.py to the "
                                 "device so updates keep working."))
    if runtime.supervised() and runtime.launcher_state()["launcher_update_available"]:
        found.append(("info", "A newer launcher.py is on GitHub. launcher.py never replaces "
                              "itself; copy the new one to the device when convenient."))
    if passwords.backend() == "builtin":
        found.append(("info", "The bcrypt package is not installed, so password hashes use "
                              "the built-in bcrypt at a lower cost. Install the package for "
                              "stronger hashes; see Dependencies in the README."))
    if db.get_meta(conn, "legacy_config_imported_at") and not db.get_meta(
            conn, "legacy_config_retired_at") and os.path.exists(
            os.path.join(os.path.dirname(db.path()), "config.json")):
        found.append(("info", "Settings from config.json were imported. The file stays "
                              "untouched until this release has run for ten minutes, then it is "
                              "renamed to config.json.migrated without the password."))
    return found


@bp.route("/")
def overview():
    conn = db.get()
    all_pcs = pcs.load_all(conn)
    states = [monitor.status_of(pc)["state"] for pc in all_pcs]
    recent, _ = activity.query_events(conn, limit=8)
    uptime, started = formatting.duration(runtime.uptime()), formatting.clock(runtime.started_at)
    server = [
        ("Version", runtime.version_label()),
        ("Started", started),
        ("Uptime", uptime),
        ("Listening on", "0.0.0.0:%s (every interface)" % runtime.listening_port),
        ("Local address", "http://%s:%s" % (system.lan_address() or "unknown",
                                            runtime.listening_port)),
        ("Python", platform.python_version()),
        ("Password hashing", passwords.describe()),
    ]
    return render_template(
        "admin/overview.html", notices=notices(conn), pcs_total=len(all_pcs),
        pcs_enabled=sum(1 for pc in all_pcs if pc["enabled"]),
        pcs_online=states.count("online"), wol=activity.wol_summary(conn), recent=recent,
        server=server, uptime=uptime, started=started,
        database=database_info(conn), launcher=runtime.launcher_state(),
        supervised=runtime.supervised(), generation=runtime.launcher_generation(),
        restart_pending=restart_pending())


# --- PCs ----------------------------------------------------------------------------------

@bp.route("/pcs")
def pcs_list():
    conn = db.get()
    stats = activity.wol_per_pc(conn)
    rows = [{"pc": pc, "status": monitor.status_of(pc), "wakes": stats.get(pc["id"], {}).get("count", 0),
             "problems": pcs.wake_plan(pc)[2]} for pc in pcs.load_all(conn)]
    return render_template("admin/pcs.html", rows=rows)


def _form_page(pc, form, errors, status=200):
    return render_template("admin/pc_form.html", pc=pc, form=form, errors=errors,
                           status_methods=pcs.STATUS_METHODS), status


@bp.route("/pcs/new", methods=["GET", "POST"])
def pc_new():
    conn = db.get()
    if request.method == "GET":
        return _form_page(None, {"ports": "9", "status_method": "ping", "enabled": "1"}, {})
    values, errors = pcs.validate(request.form)
    if "name" not in errors and pcs.name_taken(conn, values["name"]):
        errors["name"] = "Another PC already has this name."
    if errors:
        return _form_page(None, request.form, errors, 400)
    client = auth.client_address()
    with db.transaction(conn):
        pc_id = pcs.create(conn, values)
        activity.record(conn, "pc.created", "Added %s (%s)" % (values["name"], values["mac"]),
                        success=True, pc={"id": pc_id, "name": values["name"]}, client_ip=client)
    monitor.pcs_changed()
    flash("Added %s. Send a test packet to try it." % values["name"], "success")
    return redirect(url_for(".pc_detail", pc_id=pc_id))


@bp.route("/pcs/<int:pc_id>")
def pc_detail(pc_id):
    conn = db.get()
    pc = _pc_or_404(conn, pc_id)
    mac, targets, problems = pcs.wake_plan(pc)
    test = None
    test_id = request.args.get("test", type=int)
    if test_id:
        test = conn.execute("SELECT * FROM wol_requests WHERE id = ? AND pc_id = ?",
                            (test_id, pc_id)).fetchone()
    history = activity.wol_requests(conn, pc_id, limit=15)
    events, _ = activity.query_events(conn, pc_id=pc_id, limit=15)
    totals = conn.execute("SELECT count(*) AS total, sum(result != 'failed') AS sent, "
                          "max(created_at) AS last FROM wol_requests WHERE pc_id = ?",
                          (pc_id,)).fetchone()
    return render_template("admin/pc_detail.html", pc=pc, status=monitor.status_of(pc),
                           targets=targets, problems=problems,
                           hints=pcs.hints(pc, system.lan_address()), test=test,
                           history=history, events=events, totals=totals,
                           check_host=pcs.check_host(pc))


@bp.route("/pcs/<int:pc_id>/edit", methods=["GET", "POST"])
def pc_edit(pc_id):
    conn = db.get()
    pc = _pc_or_404(conn, pc_id)
    if request.method == "GET":
        return _form_page(pc, pcs.form_values(pc), {})
    values, errors = pcs.validate(request.form)
    if "name" not in errors and pcs.name_taken(conn, values["name"], exclude_id=pc_id):
        errors["name"] = "Another PC already has this name."
    if errors:
        return _form_page(pc, request.form, errors, 400)
    changed = pcs.changes(pc, values)
    if changed:
        with db.transaction(conn):
            pcs.update(conn, pc_id, values)
            activity.record(conn, "pc.updated", "Edited %s: %s" % (values["name"], ", ".join(changed)),
                            success=True, pc={"id": pc_id, "name": values["name"]},
                            client_ip=auth.client_address())
        monitor.pcs_changed()
        flash("Saved %s." % values["name"], "success")
    else:
        flash("Nothing changed.", "info")
    return redirect(url_for(".pc_detail", pc_id=pc_id))


@bp.route("/pcs/<int:pc_id>/enabled", methods=["POST"])
def pc_toggle(pc_id):
    conn = db.get()
    pc = _pc_or_404(conn, pc_id)
    enable = request.form.get("enabled") == "1"
    if enable != pc["enabled"]:
        with db.transaction(conn):
            pcs.set_enabled(conn, pc_id, enable)
            activity.record(conn, "pc.enabled" if enable else "pc.disabled",
                            "%s %s" % ("Enabled" if enable else "Disabled", pc["name"]),
                            success=True, pc=pc, client_ip=auth.client_address())
        monitor.pcs_changed()
    flash("%s is %s." % (pc["name"], "enabled" if enable else "disabled; its Wake button "
                                                               "and checks are off"), "success")
    return redirect(request.form.get("back") == "list" and url_for(".pcs_list")
                    or url_for(".pc_detail", pc_id=pc_id))


@bp.route("/pcs/<int:pc_id>/test", methods=["POST"])
def pc_test(pc_id):
    conn = db.get()
    pc = _pc_or_404(conn, pc_id)
    outcome = wake.wake(conn, pc, "test", auth.client_address())
    return redirect(url_for(".pc_detail", pc_id=pc_id, test=outcome.request_id, _anchor="test"))


@bp.route("/pcs/<int:pc_id>/check", methods=["POST"])
def pc_check(pc_id):
    conn = db.get()
    pc = _pc_or_404(conn, pc_id)
    if not pc["enabled"] or pc["status_method"] == "none":
        flash("Checks are off for %s. Choose a check method and enable the PC first."
              % pc["name"], "warning")
    else:
        status = monitor.check_now(pc)
        flash("%s: %s. %s" % (pc["name"], status["label"], status["detail"]),
              "success" if status["state"] == "online" else "info")
    return redirect(url_for(".pc_detail", pc_id=pc_id))


@bp.route("/pcs/<int:pc_id>/delete", methods=["GET", "POST"])
def pc_delete(pc_id):
    conn = db.get()
    pc = _pc_or_404(conn, pc_id)
    kept = conn.execute("SELECT count(*) FROM wol_requests WHERE pc_id = ?", (pc_id,)).fetchone()[0]
    if request.method == "GET":
        return render_template("admin/pc_delete.html", pc=pc, kept=kept)
    with db.transaction(conn):
        pcs.delete(conn, pc_id)
        activity.record(conn, "pc.deleted", "Deleted %s (%s). Its %s stay in the history."
                        % (pc["name"], pc["mac"], formatting.plural(kept, "wake request")),
                        success=True, pc={"id": None, "name": pc["name"]},
                        client_ip=auth.client_address())
    monitor.forget(pc_id)
    monitor.pcs_changed()
    flash("Deleted %s." % pc["name"], "success")
    return redirect(url_for(".pcs_list"))


# --- Activity -------------------------------------------------------------------------------

PERIODS = [("", "Any time"), ("1h", "Last hour"), ("24h", "Last 24 hours"),
           ("7d", "Last 7 days"), ("30d", "Last 30 days")]
OUTCOMES = [("", "Any result"), ("success", "Succeeded"), ("failure", "Failed")]


@bp.route("/activity")
def activity_log():
    conn = db.get()
    kind = request.args.get("kind", "")
    category = kind if kind in dict(activity.CATEGORIES) else None
    event_type = kind if kind in activity.TYPE_LABELS else None
    pc_id = request.args.get("pc", type=int)
    period = request.args.get("period", "")
    period = period if period in dict(PERIODS) else ""
    outcome = request.args.get("outcome", "")
    outcome = outcome if outcome in dict(OUTCOMES) else ""
    page = max(1, request.args.get("page", 1, type=int))
    rows, more = activity.query_events(conn, category=category, type=event_type, pc_id=pc_id,
                                       period=period or None, outcome=outcome or None,
                                       limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
    filters = {"kind": kind if (category or event_type) else "", "pc": pc_id or "",
               "period": period, "outcome": outcome}
    types_by_category = [(key, label, [(t, l) for t, l in activity.TYPES
                                      if activity.category_of(t) == key])
                         for key, label in activity.CATEGORIES]

    def page_url(number):
        args = dict((key, value) for key, value in filters.items() if value)
        return url_for(".activity_log", page=number, **args)

    return render_template("admin/activity.html", rows=rows, more=more, page=page,
                           filters=filters, pcs=pcs.load_all(conn), periods=PERIODS,
                           outcomes=OUTCOMES, types_by_category=types_by_category,
                           page_url=page_url, filtered=any(filters.values()))


# --- Security -----------------------------------------------------------------------------

def _security_page(conn, errors=None, status=200):
    user = auth.current_user()
    failures, _ = activity.query_events(conn, type="auth.login_failed", limit=10)
    failed_day = conn.execute("SELECT count(*) FROM events WHERE type = 'auth.login_failed' "
                              "AND created_at >= ?", (activity.since_cutoff("24h"),)).fetchone()[0]
    sign_ins, _ = activity.query_events(conn, type="auth.login_succeeded", limit=6)
    events, _ = activity.query_events(conn, security=True, limit=15)
    return render_template(
        "admin/security.html", user=user, failures=failures, failed_day=failed_day,
        sign_ins=sign_ins, events=events, errors=errors or {},
        hashing=passwords.describe(), cost=passwords.cost_of(user["password_hash"]),
        session_since=session.get("since"), min_length=passwords.MIN_LENGTH,
        session_days=settings.get("session_days")), status


@bp.route("/security")
def security():
    return _security_page(db.get())


@bp.route("/security/password", methods=["POST"])
def change_password():
    conn = db.get()
    user = auth.current_user()
    client = auth.client_address()
    wait = auth.lockout_seconds(conn, client)
    if wait:
        return _security_page(conn, {"current": "Too many wrong passwords. Try again in %d min."
                                     % auth.minutes(wait)}, 429)
    current = request.form.get("current", "")
    result = auth.check_password(user["password_hash"], current)
    if result is None:
        return _security_page(conn, {"current": "The server is busy. Try again in a moment."}, 503)
    if not result:
        activity.record(conn, "auth.password_change_failed",
                        "Password change refused: wrong current password from %s" % client,
                        level="warning", success=False, client_ip=client)
        return _security_page(conn, {"current": "That is not the current password."}, 400)
    new = request.form.get("password", "")
    problem = passwords.problem(new, request.form.get("confirm", ""))
    if not problem and new == current:
        problem = "Choose a password different from the current one."
    if problem:
        return _security_page(conn, {"password": problem}, 400)
    password_hash = passwords.hash_password(new)
    with db.transaction(conn):
        conn.execute("UPDATE users SET password_hash = ?, password_changed_at = ?, "
                     "session_epoch = session_epoch + 1 WHERE id = ?",
                     (password_hash, db.now(), user["id"]))
        activity.record(conn, "auth.password_changed", "Password changed from %s; every other "
                        "device was signed out" % client, success=True, client_ip=client)
    since = session.get("since")
    auth.start_session(conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone())
    if since:
        session["since"] = since
    flash("Password changed. Every other browser and device has to sign in again.", "success")
    return redirect(url_for(".security"))


@bp.route("/security/sessions", methods=["POST"])
def revoke_sessions():
    conn = db.get()
    client = auth.client_address()
    with db.transaction(conn):
        auth.revoke_other_sessions(conn, auth.current_user())
        activity.record(conn, "auth.sessions_revoked", "Signed out every other device from %s"
                        % client, success=True, client_ip=client)
    flash("Every other browser and device is signed out. This one stays signed in.", "success")
    return redirect(url_for(".security"))


# --- Settings and maintenance ----------------------------------------------------------------

def port_problem(port):
    """Why the server could not listen on `port`, tested by binding it now, or None."""
    if port == runtime.listening_port:
        return None
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as the server does
        probe.bind(("0.0.0.0", port))
    except OSError as e:
        return "Port %d cannot be used on this device (%s)." % (port, e.strerror or e)
    finally:
        probe.close()
    return None


def _settings_page(values=None, errors=None, status=200):
    groups = [(key, title, description, [s for s in settings.DEFINITIONS if s.group == key])
              for key, title, description in settings.GROUPS]
    return render_template("admin/settings.html", groups=groups,
                           values=values or settings.snapshot(), errors=errors or {},
                           restart_pending=restart_pending(), supervised=runtime.supervised(),
                           listening_port=runtime.listening_port,
                           database=database_info(db.get())), status


@bp.route("/settings")
def settings_page():
    return _settings_page()


@bp.route("/settings/<group>", methods=["POST"])
def save_settings(group):
    definitions = [s for s in settings.DEFINITIONS if s.group == group]
    if not definitions:
        abort(404)
    changes, errors = {}, {}
    for setting in definitions:
        if setting.kind == "bool":
            raw = "1" if request.form.get(setting.key) else "0"
        else:
            raw = request.form.get(setting.key, "")
        try:
            changes[setting.key] = settings.parse(setting, raw)
        except ValueError as e:
            errors[setting.key] = str(e)
    if "server_port" in changes and changes["server_port"] != settings.get("server_port"):
        problem = port_problem(changes["server_port"])
        if problem:
            errors["server_port"] = problem
    if errors:
        values = settings.snapshot()
        values.update(dict((s.key, request.form.get(s.key, "")) for s in definitions
                           if s.kind != "bool"))
        return _settings_page(values, errors, 400)
    before = settings.snapshot()
    conn = db.get()
    changed = settings.save(conn, changes)
    if changed:
        activity.record(conn, "settings.changed", "Changed %s" % "; ".join(
            "%s from %s to %s" % (settings.BY_KEY[key].label.lower(),
                                  settings.describe(key, before[key]),
                                  settings.describe(key, changes[key])) for key in changed),
            success=True, client_ip=auth.client_address())
        message = "Saved."
        if "server_port" in changed:
            message += " The new port takes effect after a restart."
        flash(message, "success")
    else:
        flash("Nothing changed.", "info")
    return redirect(url_for(".settings_page", _anchor=group))


@bp.route("/backup", methods=["POST"])
def backup():
    """A consistent copy of wol.db, downloaded. Contains the password hash and secret key,
    which is exactly why only a signed-in admin can make one."""
    directory = os.path.dirname(os.path.abspath(db.path()))
    handle, temporary = tempfile.mkstemp(prefix=".backup-", suffix=".db", dir=directory)
    os.close(handle)
    try:
        db.backup(temporary)
        with open(temporary, "rb") as f:
            data = f.read()
    finally:
        try:
            os.remove(temporary)
        except OSError:
            pass
    client = auth.client_address()
    activity.record(db.get(), "system.backup", "Database backup downloaded from %s" % client,
                    success=True, client_ip=client)
    name = "wol-backup-%s.db" % runtime.now_local().strftime("%Y%m%d-%H%M%S")
    return Response(data, mimetype="application/vnd.sqlite3", headers={
        "Content-Disposition": 'attachment; filename="%s"' % name, "Cache-Control": "no-store"})


def _without_port(host):
    if host.startswith("["):                        # [::1]:5000
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


@bp.route("/restart", methods=["POST"])
def restart():
    if not runtime.supervised():
        flash("This server was started without launcher.py, so it cannot restart itself. "
              "Stop it and start it again to apply the change.", "warning")
        return redirect(url_for(".settings_page"))
    port = settings.get("server_port")
    origin = "%s://%s:%d" % (request.scheme, _without_port(request.host), port)
    if port != runtime.listening_port:
        g.csp_connect = [origin]
    client = auth.client_address()
    activity.record(db.get(), "system.restart", "Restart requested from %s" % client,
                    success=True, client_ip=client)
    runtime.request_restart()
    return render_template("admin/restarting.html", target=origin + url_for(".overview"),
                           health=origin + url_for("main.health"), port=port,
                           port_changed=port != runtime.listening_port)
