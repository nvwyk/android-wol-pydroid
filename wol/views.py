"""The pages everyone uses: the dashboard with its Wake buttons, sign-in, first-run setup,
the System page, the public status page and the health check launcher.py polls."""
import hmac
import logging
import os
import platform
import sqlite3
import time

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template, request,
                   session, url_for)

from . import APP_VERSION, activity, auth, db, formatting, insights, monitor, passwords, pcs, \
    runtime, settings, system, wake, web

logger = logging.getLogger("wol")
bp = Blueprint("main", __name__)


# --- Dashboard --------------------------------------------------------------------

def target_summary(pc):
    """192.168.1.25, 192.168.1.255 broadcast, UDP 7 and 9: where a wake request goes."""
    places = list(pc["hosts"]) + ["%s broadcast" % address for address in pc["broadcasts"]]
    ports = [str(port) for port in pc["ports"]]
    port_text = " and ".join([", ".join(ports[:-1]), ports[-1]]) if len(ports) > 1 else "".join(ports)
    return "%s, UDP %s" % (", ".join(places) or "no address", port_text or "none")


def pc_cards(conn):
    stats = activity.wol_per_pc(conn)
    cards = []
    for pc in pcs.load_all(conn):
        numbers = stats.get(pc["id"], {})
        _, _, problems = pcs.wake_plan(pc)
        cards.append({"pc": pc, "status": monitor.status_of(pc), "wakes": numbers.get("count", 0),
                      "last_wake_at": numbers.get("last_at"),
                      "last_result": numbers.get("last_result"),
                      "problem": problems[0] if problems else None,
                      "targets": target_summary(pc)})
    return cards


def layout_key(cards):
    """Changes when the set of PCs or any PC's settings change, so an open dashboard
    knows to reload instead of patching figures into a stale layout."""
    return ",".join("%d:%s" % (card["pc"]["id"], card["pc"]["updated_at"]) for card in cards)


def last_seen(pc, status):
    if status["state"] == "online":
        return "Now"
    return formatting.ago(pc["last_seen_at"]).capitalize() if pc["last_seen_at"] else "Not yet"


def online_summary(cards):
    enabled = [card for card in cards if card["pc"]["enabled"]]
    online = sum(1 for card in enabled if card["status"]["state"] == "online")
    if not enabled:
        return "Every PC is disabled."
    if not settings.get("status_checks_enabled"):
        return "%s. Reachability checks are off." % formatting.plural(len(enabled), "PC")
    return "%d of %s online." % (online, formatting.plural(len(enabled), "PC"))


@bp.route("/")
@auth.login_required
def dashboard():
    cards = pc_cards(db.get())
    return render_template("dashboard.html", cards=cards, layout=layout_key(cards),
                           summary=online_summary(cards), last_seen=last_seen,
                           refresh=settings.get("page_refresh_interval"))


@bp.route("/api/dashboard")
@auth.login_required
def dashboard_json():
    cards = pc_cards(db.get())
    text, chip = {"online-summary": online_summary(cards)}, {}
    for card in cards:
        key = "pc-%d" % card["pc"]["id"]
        chip[key] = {"state": card["status"]["state"], "label": card["status"]["label"]}
        text[key + "-detail"] = card["status"]["detail"]
        text[key + "-last-wake"] = (formatting.clock(card["last_wake_at"])
                                    if card["last_wake_at"] else "Never")
        text[key + "-wakes"] = str(card["wakes"])
        text[key + "-last-seen"] = last_seen(card["pc"], card["status"])
    return jsonify(text=text, chip=chip, layout=layout_key(cards))


def wake_message(outcome):
    pc = outcome.pc
    if outcome.result == "sent":
        text = "Wake packet sent to %s (%s)." % (pc["name"], formatting.plural(outcome.sent, "packet"))
        if pc["status_method"] != "none" and settings.get("status_checks_enabled"):
            text += " Its card shows when the PC starts answering."
        return "success", text
    if outcome.result == "partial":
        return "warning", ("Wake packet partly sent to %s: %d of %d packets went out. "
                           "Not sent: %s." % (pc["name"], outcome.sent, outcome.total,
                                              "; ".join(outcome.errors)))
    if not outcome.targets or outcome.problems:
        return "error", ("The wake packet for %s did not go out: %s Fix the PC in Admin > PCs."
                         % (pc["name"], " ".join(outcome.problems)))
    return "error", ("The wake packet for %s did not go out: %s. Check that this device is "
                     "connected to the same network as the PC."
                     % (pc["name"], "; ".join(outcome.errors)))


@bp.route("/pcs/<int:pc_id>/wake", methods=["POST"])
@auth.login_required
def wake_pc(pc_id):
    conn = db.get()
    pc = pcs.get(conn, pc_id)
    if pc is None:
        flash("That PC no longer exists.", "warning")
        return redirect(url_for(".dashboard"))
    if not pc["enabled"]:
        flash("%s is disabled. Enable it in Admin > PCs to wake it." % pc["name"], "warning")
        return redirect(url_for(".dashboard", _anchor="pc-%d" % pc_id))
    kind, message = wake_message(wake.wake(conn, pc, "dashboard", auth.client_address()))
    flash(message, kind)
    return redirect(url_for(".dashboard", _anchor="pc-%d" % pc_id))


@bp.route("/wake", methods=["GET", "POST"])
def legacy_wake():
    # The single Wake button of the one-PC version posted here; each PC has its own now.
    if request.method == "POST":
        flash("Each PC now has its own Wake button. Nothing was sent; press it again below.",
              "warning")
    return redirect(url_for(".dashboard"))


# --- Sign-in and setup ----------------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
def login():
    conn = db.get()
    next_page = auth.safe_next(request.args.get("next"))
    if auth.current_user() is not None:
        return redirect(next_page or url_for(".dashboard"))
    admin = auth.get_admin(conn)
    if admin is None:
        return redirect(url_for(".setup"))

    client = auth.client_address()
    wait = auth.lockout_seconds(conn, client)
    error, status = None, 200
    if request.method == "POST" and not wait:
        result = auth.check_password(admin["password_hash"], request.form.get("password", ""))
        if result is None:
            error, status = "The server is busy checking other sign-ins. Try again in a moment.", 503
        elif result:
            stamp = db.now()
            # A hash made without the bcrypt package is upgraded now that it is available.
            # Hashing is slow, so it happens before the write lock is taken.
            upgraded = (passwords.hash_password(request.form.get("password", ""))
                        if passwords.needs_rehash(admin["password_hash"]) else None)
            with db.transaction(conn):
                if upgraded:
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                                 (upgraded, admin["id"]))
                conn.execute("UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?",
                             (stamp, client, admin["id"]))
                activity.record(conn, "auth.login_succeeded", "Signed in from %s" % client,
                                success=True, client_ip=client)
            auth.start_session(admin)
            return redirect(next_page or url_for(".dashboard"))
        else:
            activity.record(conn, "auth.login_failed", "Wrong password from %s" % client,
                            level="warning", success=False, client_ip=client)
            wait = auth.lockout_seconds(conn, client)
            if wait:
                activity.record(conn, "auth.lockout", "Sign-in from %s locked for %d min after "
                                "%d wrong passwords" % (client, auth.minutes(wait),
                                                        auth.MAX_FAILURES),
                                level="warning", success=False, client_ip=client)
            else:
                error = "Wrong password."

    if wait:
        error = "Too many wrong passwords. Try again in %d min." % auth.minutes(wait)
        return render_template("login.html", error=error, next_page=next_page), 429, \
            {"Retry-After": str(wait)}
    return render_template("login.html", error=error, next_page=next_page,
                           slow=passwords.slow_to_verify(admin["password_hash"])), status


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    # Only a form post signs out, so a link, a bookmark or a prefetch cannot do it by accident.
    if request.method == "POST":
        if auth.current_user() is not None:
            client = auth.client_address()
            activity.record(db.get(), "auth.logout", "Signed out from %s" % client,
                            client_ip=client)
        session.clear()
        return redirect(url_for(".login"))
    return redirect(url_for(".dashboard"))


def normalize_code(text):
    return "".join(c for c in str(text).upper() if c.isalnum())


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    conn = db.get()
    if auth.setup_complete(conn):
        # Setup runs once. Afterwards this address only points elsewhere.
        return redirect(url_for(".dashboard") if auth.current_user() else url_for(".login"))
    if runtime.setup_code and time.monotonic() - runtime.setup_code_logged > 60:
        runtime.setup_code_logged = time.monotonic()
        logger.info("Setup code: %s", runtime.setup_code)

    imported = pcs.load_all(conn)
    form = request.form if request.method == "POST" else {
        "add_pc": "1", "ports": "9", "status_method": "ping", "enabled": "1"}
    errors = {}
    if request.method == "POST":
        client = auth.client_address()
        wait = auth.lockout_seconds(conn, client)
        if wait:
            errors["code"] = "Too many wrong codes. Try again in %d min." % auth.minutes(wait)
        elif not runtime.setup_code or not hmac.compare_digest(
                normalize_code(form.get("code", "")).encode(),
                normalize_code(runtime.setup_code).encode()):
            activity.record(conn, "setup.code_failed", "Wrong setup code from %s" % client,
                            level="warning", success=False, client_ip=client)
            errors["code"] = "That is not the code shown in the console. Check it and try again."
        password = form.get("password", "")
        problem = passwords.problem(password, form.get("confirm", ""))
        if problem:
            errors["password"] = problem
        add_pc = not imported and bool(form.get("add_pc"))
        values = None
        if add_pc:
            # Setup keeps the PC short: it is enabled, and checked by ping when its own
            # IP address was given.
            fields = dict((key, form.get(key, "")) for key in ("name", "mac", "hosts",
                                                               "broadcasts", "ports"))
            fields.update(enabled="1", status_method="ping" if fields["hosts"].strip() else "none")
            values, pc_errors = pcs.validate(fields)
            errors.update(pc_errors)
        if not errors:
            password_hash = passwords.hash_password(password)    # slow; outside the write lock
            stamp = db.now()
            with db.transaction(conn):
                if auth.setup_complete(conn):
                    # Another browser finished setup while this one was hashing.
                    return redirect(url_for(".login"))
                user_id = conn.execute(
                    "INSERT INTO users (username, password_hash, session_epoch, created_at, "
                    "password_changed_at, last_login_at, last_login_ip) "
                    "VALUES (?, ?, 1, ?, ?, ?, ?)",
                    (auth.USERNAME, password_hash, stamp, stamp, stamp, client)).lastrowid
                if values:
                    pc_id = pcs.create(conn, values)
                    activity.record(conn, "pc.created", "Added %s during setup" % values["name"],
                                    success=True, pc={"id": pc_id, "name": values["name"]},
                                    client_ip=client)
                db.set_meta(conn, "setup_completed_at", stamp)
                activity.record(conn, "setup.completed", "Setup completed from %s" % client,
                                success=True, client_ip=client)
            runtime.setup_done, runtime.setup_code = True, None
            monitor.pcs_changed()
            auth.start_session(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
            if values or imported:
                flash("Setup is complete. Your PC is ready to wake.", "success")
                return redirect(url_for(".dashboard"))
            flash("Setup is complete. Add the first PC you want to wake.", "success")
            return redirect(url_for("admin.pc_new"))

    return render_template("setup.html", form=form, errors=errors, imported=imported,
                           status_methods=pcs.STATUS_METHODS,
                           min_length=passwords.MIN_LENGTH), 400 if errors else 200


# --- System page ------------------------------------------------------------------------

@bp.route("/system")
@auth.login_required
def system_page():
    snapshot = system.snapshot()
    text = snapshot["text"]
    cores = os.cpu_count()
    android, phone = system.android_name(), system.android_details()
    kernel = system.kernel_name()
    route = system.default_route()
    conn = db.get()
    all_pcs = pcs.load_all(conn)
    checked = [pc for pc in all_pcs if pc["enabled"] and pc["status_method"] != "none"]
    groups = [
        ("Device", [
            ("Model", None, phone["model"]),
            # On a phone the Android version and the kernel are both worth knowing.
            # Anywhere else they are the same fact, so the kernel row stays out.
            ("Operating system", None, ("%s, API %s" % (android.split(" (")[0], phone["api"])
                                        if android and phone["api"] else android or kernel)),
            ("Security patch", None, phone["patch"]),
            ("Kernel", None, kernel if android else None),
            ("Processor", None, phone["chip"] or system.processor_name()),
            ("Cores online", "cores-online", text.get("cores-online") or (str(cores) if cores else None)),
            ("CPU clock", "clock-range", text.get("clock-range")),
            ("Load average", "load", text.get("load")),
            ("Device uptime", "device-uptime", text.get("device-uptime")),
            ("Hottest sensor", "temperature", text.get("temperature")),
            ("Battery temperature", "battery-temp", text.get("battery-temp")),
        ]),
        ("Network", [
            ("Listening on", None, "%s:%d" % (system.lan_address() or "0.0.0.0",
                                              runtime.listening_port or 0)),
            ("Interface", None, route[0] if route else None),
            ("Gateway", None, route[1] if route else None),
            ("Internet", None, internet_text()),
            ("You reached it at", None, request.host),
            ("Your address", None, request.remote_addr),
            ("Received", "received", text.get("received")),
            ("Sent", "sent", text.get("sent")),
        ]),
        ("Reachability checks", [
            ("PCs online", None, "%d of %d checked" % (
                sum(1 for pc in checked if monitor.status_of(pc)["state"] == "online"),
                len(checked)) if settings.get("status_checks_enabled") else None),
            ("Check interval", None, "Every %s" % formatting.duration(settings.get(
                "status_check_interval")) if settings.get("status_checks_enabled") else "Off"),
            ("Latest round", None, round_text()),
            ("Ping", None, {True: "Available", False: "Not available on this device"}.get(
                monitor.capabilities["ping"], "Not tried yet")),
            ("Address table (ARP)", None, {"ip": "Readable (ip neigh)",
                                           "proc": "Readable (/proc/net/arp)",
                                           "": "Not readable on this device"}.get(
                monitor.capabilities["neighbour"], "Not needed yet")),
        ]),
        ("This server", [
            ("Version", None, runtime.version_label()),
            ("Started", None, formatting.clock(runtime.started_at)),
            ("Server uptime", "server-uptime", text.get("server-uptime")),
            ("Memory in use", "process-memory", text.get("process-memory")),
            ("CPU time used", "server-cpu-time", text.get("server-cpu-time")),
            ("Threads", "threads", text.get("threads")),
            ("Process id", None, str(os.getpid())),
            ("Python", None, platform.python_version()),
            ("Flask", None, package_version("flask")),
            ("SQLite", None, sqlite3.sqlite_version),
            ("Auto-update", None, update_status_text()),
            ("Last update check", None, update_check_text()),
        ]),
    ]
    groups = [(title, [row for row in rows if row[2]]) for title, rows in groups]
    return render_template("system.html", snapshot=snapshot, groups=groups,
                           insights=insights.collect(conn),
                           poll_interval=settings.get("metrics_interval"))


def internet_text():
    if not settings.get("internet_check_enabled"):
        return "Check off"
    if runtime.internet is None:
        return "Checking"
    if runtime.internet:
        latency = runtime.internet_latency
        return "Reachable, %d ms" % (latency * 1000) if latency is not None else "Reachable"
    since = runtime.internet_since
    return "Unreachable since %s" % formatting.clock(since) if since else "Unreachable"


def round_text():
    last = dict(monitor.last_round)
    if not last:
        return None
    return "%s, %s in %.1f s" % (formatting.clock(last["at"]),
                                 formatting.plural(last["pcs"], "PC"), last["seconds"])


def update_check_text():
    if not runtime.supervised():
        return None
    state = runtime.launcher_state()
    if not state["last_check_at"]:
        return "Not yet"
    return "%s, %s" % (formatting.clock(state["last_check_at"]),
                       (state["last_check_result"] or "no result").rstrip("."))


def package_version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:           # no metadata for this install; the row is left out
        return None


@bp.route("/system.json")
@auth.login_required
def system_json():
    # What the System page polls while it is open. Only the figures that change.
    snapshot = system.snapshot()
    snapshot.pop("tiles")
    return jsonify(snapshot)


def update_status_text():
    if not runtime.supervised():
        return "Off, started without launcher.py"
    if runtime.launcher_generation() == 1:
        return "Needs the new launcher.py"
    return "On, run by launcher.py" if settings.get("updates_enabled") else "Paused in Admin > Settings"


# --- Public status and health ------------------------------------------------------------

def public_status(conn):
    """Everything /status and /status.json show. Only what the admin chose to publish:
    never MAC or IP addresses, paths, account details or anything secret."""
    total, enabled = pcs.counts(conn)
    detail = settings.get("public_pc_detail")
    checking = settings.get("status_checks_enabled")
    listing, online = [], 0
    for index, pc in enumerate(pcs.load_all(conn), 1):
        status = monitor.status_of(pc)
        online += status["state"] == "online"
        if detail in ("status", "names"):
            listing.append({"key": "pc-%d" % index,
                            "name": pc["name"] if detail == "names" else "PC %d" % index,
                            "state": status["state"], "label": status["label"]})
    if total == 0:
        service = ("no_pcs", "No PCs configured")
    elif enabled == 0:
        service = ("all_disabled", "Every PC is disabled")
    else:
        service = ("ready", "Ready")
    now = runtime.now_local()
    data = {
        "server": {"status": "online", "time": now.isoformat(timespec="seconds"),
                   "started_at": runtime.started_at.astimezone().isoformat(timespec="seconds"),
                   "uptime_seconds": int(runtime.uptime()), "database": "ok"},
        "wake_on_lan": {"service": service[0], "pcs_configured": total, "pcs_enabled": enabled,
                        "pcs_online": online if checking else None},
    }
    text = {"server-time": formatting.clock(now), "uptime": formatting.duration(runtime.uptime()),
            "service": service[1],
            "pcs-online": ("%d of %d" % (online, enabled)) if checking else "Not checked"}
    chip = {}
    if detail in ("status", "names"):
        data["pcs"] = [{"name": item["name"], "status": item["state"]} for item in listing]
        for item in listing:
            chip[item["key"]] = {"state": item["state"], "label": item["label"]}
    if settings.get("public_show_wol_activity"):
        summary = activity.wol_summary(conn)
        last = summary["last"]
        data["wake_on_lan"].update(
            requests_total=summary["total"], requests_last_24h=summary["last_day"],
            last_request_at=formatting.local(last["created_at"]).isoformat(timespec="seconds") if last else None,
            last_request_result=last["result"] if last else None,
            last_request_pc=last["pc_name"] if last and detail == "names" else None,
            last_success_at=(formatting.local(summary["last_success_at"]).isoformat(timespec="seconds")
                             if summary["last_success_at"] else None))
        text.update({"requests-total": str(summary["total"]),
                     "requests-day": str(summary["last_day"]),
                     "last-request": formatting.clock(last["created_at"]) if last else "None yet",
                     "last-success": (formatting.clock(summary["last_success_at"])
                                      if summary["last_success_at"] else "None yet")})
        if last:
            chip["last-result"] = {"state": last["result"],
                                   "label": RESULT_LABELS.get(last["result"], last["result"])}
    if settings.get("public_show_internet"):
        if runtime.internet is None:
            state = "unknown" if settings.get("internet_check_enabled") else "off"
        else:
            state = "online" if runtime.internet else "offline"
        data["internet"] = {"status": state, "since": (runtime.internet_since.isoformat(
            timespec="seconds") if runtime.internet_since and runtime.internet is not None else None)}
        text["internet"] = {"online": "Reachable", "offline": "Unreachable", "unknown": "Checking",
                            "off": "Not checked"}[state]
        chip["internet"] = {"state": {"online": "online", "offline": "failed"}.get(state, "unknown"),
                            "label": text["internet"]}
    if settings.get("public_show_system"):
        figures = system.public_figures()
        data["device"] = [{"label": label, "value": value} for label, value in figures]
        for label, value in figures:
            text["device-" + label.lower().replace(" ", "-")] = value
    if settings.get("public_show_version"):
        launcher = runtime.launcher_state()
        data["version"] = {
            "app": APP_VERSION, "build": runtime.build,
            "supervised": runtime.supervised(),
            "automatic_updates": bool(runtime.supervised() and runtime.launcher_generation() != 1
                                      and settings.get("updates_enabled")),
            "last_update_check": launcher["last_check_at"] if runtime.supervised() else None,
        }
    data["display"] = {"text": text, "chip": chip}
    return data


RESULT_LABELS = {"sent": "Sent", "partial": "Partly sent", "failed": "Failed"}


@bp.route("/status")
def status():
    if not settings.get("public_status_enabled"):
        abort(404)
    data = public_status(db.get())
    return render_template("status.html", data=data, results=RESULT_LABELS,
                           refresh=settings.get("page_refresh_interval"))


@bp.route("/status.json")
def status_json():
    if not settings.get("public_status_enabled"):
        abort(404)
    data = public_status(db.get())
    display = data.pop("display")
    # The page's live refresh reads the same shape as every other live page.
    if request.args.get("view") == "live":
        return jsonify(text=display["text"], chip=display["chip"])
    return jsonify(data)


@bp.route("/health")
def health():
    """Liveness for launcher.py and anything else that watches this server."""
    if runtime.database_error:
        ok, schema = False, None
    else:
        ok, schema = db.health()
    body = {"ok": ok, "status": "ok" if ok else "error", "version": APP_VERSION,
            "build": runtime.build, "database": "ok" if ok else "error",
            "schema": schema if ok else None,
            "initialized": web.setup_done() if ok else None,
            "uptime": int(runtime.uptime())}
    # The token lets launcher.py tell its own child apart from a stale process on the
    # port. Only the device itself gets to see it.
    if request.remote_addr in ("127.0.0.1", "::1"):
        body["token"] = os.environ.get("WOL_INSTANCE_TOKEN")
    return jsonify(body), 200 if ok else 503


@bp.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain; charset=utf-8"}
