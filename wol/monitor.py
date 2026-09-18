"""Background threads: device load sampling, internet check, PC reachability checks,
history cleanup and the launcher watch.

PC reachability is kept separate from Wake-on-LAN on purpose. A PC is only called
online after it answered a ping or a TCP probe, never because a packet was sent to it.
After a wake request the PC is probed every 10 seconds for three minutes, so the
dashboard can show it coming up; otherwise one probe per PC per interval (a minute by
default) keeps the load on the network negligible.
"""
import logging
import os
import socket
import subprocess
import sys
import threading
import time

from . import activity, db, legacy, pcs, runtime, settings, system

logger = logging.getLogger("wol")

INTERNET_PROBES = [("1.1.1.1", 53), ("8.8.8.8", 53)]
WAKE_WATCH_SECONDS = 180
WAKE_WATCH_INTERVAL = 10
PC_LIST_MAX_AGE = 30
LAST_SEEN_WRITE_GAP = 300           # store "last seen" at most every 5 minutes per PC
CLEANUP_EVERY = 3600

_lock = threading.Lock()
_status = {}                        # pc_id -> latest check result
_watch_until = {}                   # pc_id -> monotonic deadline of fast checks after a wake
_woken_at = {}                      # pc_id -> monotonic time of the last sent wake packet
_pc_list = [0.0, None]              # [loaded at (monotonic), list of PCs]
_tick = threading.Event()


# --- Probes -----------------------------------------------------------------

def ping(address, timeout=1):
    """(answered, detail). answered is None when ping itself could not run."""
    if sys.platform == "win32":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), address]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), address]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, timeout=timeout + 5)
    except FileNotFoundError:
        return None, "ping is not available on this device. Choose a TCP check instead."
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return None, "ping could not run (%s)." % e
    output = completed.stdout.decode("utf-8", "replace").lower()
    # Windows also exits 0 when a router replies "destination host unreachable", so a
    # reply only counts when it carries the TTL that real echo replies have.
    if completed.returncode == 0 and "ttl=" in output:
        return True, "Answered ping"
    if "not permitted" in output or "permission denied" in output:
        return None, "This device does not allow ping. Choose a TCP check instead."
    return False, "No answer to ping"


def tcp_probe(address, port, timeout=2.0):
    """(answered, detail). A refused connection also proves the PC is up: the refusal
    comes from the PC itself."""
    try:
        socket.create_connection((address, port), timeout=timeout).close()
        return True, "Answered on TCP %d" % port
    except ConnectionRefusedError:
        return True, "Answered on TCP %d (port closed)" % port
    except socket.timeout:
        return False, "No answer on TCP %d" % port
    except OSError as e:
        return False, "No answer on TCP %d (%s)" % (port, e.strerror or e)


def probe(pc):
    address = pcs.check_host(pc)
    if address is None:
        return None, "No IP address to check."
    if pc["status_method"] == "tcp":
        if not pc["status_port"]:
            return None, "No TCP port to probe."
        return tcp_probe(address, pc["status_port"])
    return ping(address)


def internet_reachable():
    for address in INTERNET_PROBES:
        try:
            socket.create_connection(address, timeout=3).close()
            return True
        except OSError:
            pass
    return False


# --- PC status ----------------------------------------------------------------

def watch_after_wake(pc_id):
    """Probe this PC often for a while, so the dashboard shows it coming up."""
    with _lock:
        now = time.monotonic()
        _woken_at[pc_id] = now
        _watch_until[pc_id] = now + WAKE_WATCH_SECONDS
    _tick.set()


def pcs_changed():
    """Call after a PC is added, edited, enabled, disabled or deleted."""
    with _lock:
        _pc_list[0] = 0.0
    _tick.set()


def forget(pc_id):
    with _lock:
        for table in (_status, _watch_until, _woken_at):
            table.pop(pc_id, None)


def status_of(pc):
    """How the pages describe a PC right now.

    state is one of online, unreachable, waking (a packet was sent in the last three
    minutes and the PC has not answered yet), unknown or disabled.
    """
    if not pc["enabled"]:
        return {"state": "disabled", "label": "Disabled",
                "detail": "Disabled in Admin, so it is not woken or checked."}
    if pc["status_method"] == "none" or not settings.get("status_checks_enabled"):
        return {"state": "unknown", "label": "Not checked",
                "detail": "Reachability checks are off."}
    with _lock:
        entry = dict(_status.get(pc["id"]) or {})
        woken = _woken_at.get(pc["id"])
    recently_woken = woken is not None and time.monotonic() - woken < WAKE_WATCH_SECONDS
    state = entry.get("state")
    if state == "online":
        return {"state": "online", "label": "Online", "detail": entry["detail"],
                "checked_at": entry.get("checked_at")}
    if recently_woken:
        return {"state": "waking", "label": "Waiting for reply",
                "detail": "Wake packet sent. No answer yet.", "checked_at": entry.get("checked_at")}
    if state == "unreachable":
        return {"state": "unreachable", "label": "Unreachable", "detail": entry["detail"],
                "checked_at": entry.get("checked_at")}
    if state == "error":
        return {"state": "unknown", "label": "Unknown", "detail": entry["detail"],
                "checked_at": entry.get("checked_at")}
    return {"state": "unknown", "label": "Checking", "detail": "The first check is on its way."}


def _record_result(pc, answered, detail):
    now = time.monotonic()
    with _lock:
        entry = _status.setdefault(pc["id"], {"state": None, "misses": 0})
        previous = entry["state"]
        if answered is None:
            state = "error"
        elif answered:
            state, entry["misses"] = "online", 0
            _watch_until.pop(pc["id"], None)
        else:
            entry["misses"] += 1
            # One lost probe does not take an online PC offline; two in a row do.
            state = "online" if previous == "online" and entry["misses"] < 2 else "unreachable"
        entry.update(state=state, detail=detail, checked_at=db.now(), checked_mono=now)
        woken = _woken_at.get(pc["id"])
    if previous in ("online", "unreachable") and state in ("online", "unreachable") \
            and state != previous:
        if state == "online":
            after = (" %s after the wake request" % _short(now - woken)
                     if woken is not None and now - woken < WAKE_WATCH_SECONDS else "")
            activity.record_safely("status.online", "%s is reachable again%s: %s"
                                   % (pc["name"], after, detail.lower()), success=True, pc=pc)
        else:
            activity.record_safely("status.offline", "%s stopped answering: %s"
                                   % (pc["name"], detail.lower()), pc=pc)
    if state == "online":
        stored = db.parse_time(pc.get("last_seen_at"))
        if previous != "online" or stored is None or time.time() - stored.timestamp() > LAST_SEEN_WRITE_GAP:
            stamp = db.now()
            try:
                with db.session() as conn:
                    conn.execute("UPDATE pcs SET last_seen_at = ? WHERE id = ?", (stamp, pc["id"]))
                pc["last_seen_at"] = stamp
            except Exception as e:
                logger.warning("Could not store last seen time: %s", e)


def _short(seconds):
    return "%d s" % seconds if seconds < 120 else "%d min" % (seconds // 60)


def _current_pcs():
    with _lock:
        loaded_at, cached = _pc_list
    if cached is None or time.monotonic() - loaded_at > PC_LIST_MAX_AGE:
        with db.session() as conn:
            cached = pcs.load_all(conn)
        with _lock:
            _pc_list[0], _pc_list[1] = time.monotonic(), cached
            known = set(pc["id"] for pc in cached)
            for pc_id in [pc_id for pc_id in _status if pc_id not in known]:
                _status.pop(pc_id, None)
    return cached


def check_due_pcs():
    """Probe every PC whose next check is due. Returns how many were probed."""
    if not settings.get("status_checks_enabled"):
        return 0
    interval = settings.get("status_check_interval")
    probed = 0
    for pc in _current_pcs():
        if not pc["enabled"] or pc["status_method"] == "none":
            continue
        now = time.monotonic()
        with _lock:
            entry = _status.get(pc["id"])
            watching = _watch_until.get(pc["id"], 0) > now
        gap = WAKE_WATCH_INTERVAL if watching else interval
        if entry and now - entry["checked_mono"] < gap:
            continue
        answered, detail = probe(pc)
        _record_result(pc, answered, detail)
        probed += 1
    return probed


def check_now(pc):
    """An immediate probe for Admin > PCs > Check now. Returns status_of(pc)."""
    answered, detail = probe(pc)
    _record_result(pc, answered, detail)
    return status_of(pc)


def _run_status_checks():
    while True:
        try:
            check_due_pcs()
        except Exception as e:
            logger.warning("PC check failed: %s", e)
        _tick.wait(2)
        _tick.clear()


# --- Other loops --------------------------------------------------------------

def _run_internet_monitor():
    while True:
        if settings.get("internet_check_enabled"):
            online = internet_reachable()
            if online != runtime.internet:
                previous = runtime.internet
                # Timestamp first: a reader that sees the new state always has a time for it.
                runtime.internet_since, runtime.internet = runtime.now_local(), online
                if previous is not None:
                    if online:
                        activity.record_safely("system.internet_up", "Internet is reachable again")
                    else:
                        activity.record_safely("system.internet_down", "Internet is unreachable",
                                               level="warning")
        else:
            runtime.internet = runtime.internet_since = None
        time.sleep(settings.get("internet_check_interval"))


def _run_maintenance():
    """History cleanup once an hour, and retiring an imported config.json once this
    release has proven itself."""
    time.sleep(30)
    last_cleanup = None
    while True:
        try:
            if last_cleanup is None or time.monotonic() - last_cleanup > CLEANUP_EVERY:
                last_cleanup = time.monotonic()
                with db.session() as conn:
                    events, wakes = activity.cleanup(conn)
                    if events or wakes:
                        activity.record(conn, "system.cleanup",
                                        "Deleted %d old events and %d old wake requests"
                                        % (events, wakes))
            legacy.retire_when_proven()
        except Exception as e:
            logger.warning("Maintenance failed: %s", e)
        time.sleep(60)


def _watch_launcher():
    """Exit if launcher.py dies, so an orphan never keeps holding the port."""
    parent = os.getppid()
    while True:
        time.sleep(5)
        if os.getppid() != parent:
            logger.warning("Launcher is gone, exiting")
            os._exit(0)


def start():
    """Start every background thread. They are daemons: they end with the server."""
    loops = [system.run_sampler, _run_internet_monitor, _run_status_checks, _run_maintenance]
    if runtime.supervised():
        loops.append(_watch_launcher)
    for loop in loops:
        threading.Thread(target=loop, name=loop.__name__.strip("_"), daemon=True).start()
