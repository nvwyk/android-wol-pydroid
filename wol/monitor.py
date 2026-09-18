"""Background threads: device load sampling, internet check, PC reachability checks,
history cleanup and the launcher watch.

PC reachability is kept separate from Wake-on-LAN on purpose. A PC is only called
online after it answered a ping, ARP with its own MAC address, or a TCP probe, never
because a wake packet was sent to it.
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
last_round = {}                     # at, pcs, seconds of the latest round that probed a PC


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


# --- Neighbour table (ARP) --------------------------------------------------------
#
# Windows drops ping on networks it calls Public, and many PCs firewall every TCP port,
# but no PC can ignore ARP: it has to answer "who has 192.168.1.25?" to be on the network
# at all. The kernel keeps the answers in its neighbour table, and Android up to version 9
# lets apps read it. A table entry only counts when it carries this PC's own MAC address,
# so another device that took over the IP address is never mistaken for the PC.

ARP_SETTLE = 9.0        # Linux re-verifies a cached entry within 5 s delay + 3 probes of 1 s
ARP_POLL = 0.5
CACHED_STATES = ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "COMPLETE")
_neighbour_tool = [None]            # "ip" or "proc" once one worked, "" when neither does
capabilities = {"ping": None, "neighbour": None}    # what this device turned out to allow


def _ip_neighbour(address):
    """(state, mac) from `ip neigh`, ("NONE", None) without an entry, None if ip fails."""
    try:
        done = subprocess.run(["ip", "neigh", "show", address], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=5)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if parts and parts[0] == address:
            mac = parts[parts.index("lladdr") + 1] if "lladdr" in parts[:-1] else None
            return parts[-1].upper(), mac
    return "NONE", None


def _proc_neighbour(address):
    """(COMPLETE or INCOMPLETE, mac) from /proc/net/arp, which has no finer state."""
    text = system.read_file("/proc/net/arp") or system.read_file("/proc/self/net/arp")
    if not text:
        return None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == address:
            try:
                flags = int(parts[2], 16)
            except ValueError:
                flags = 0
            return ("COMPLETE" if flags & 0x2 else "INCOMPLETE"), parts[3]     # ATF_COM
    return "NONE", None


def neighbour(address):
    """What the kernel's neighbour table says about address: (state, mac), or None when
    this device does not let the app read the table."""
    tool = _neighbour_tool[0]
    if tool == "" or sys.platform == "win32":
        return None
    if tool in (None, "ip"):
        found = _ip_neighbour(address)
        if found is not None:
            _neighbour_tool[0] = capabilities["neighbour"] = "ip"
            return found
    found = _proc_neighbour(address)
    _neighbour_tool[0] = capabilities["neighbour"] = "proc" if found is not None else ""
    return found


def _nudge(address):
    """Make the kernel resolve address: one empty UDP datagram to the discard port. It is
    not a wake packet, and a firewall that drops it has already answered ARP by then."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"", (address, 9))
    except OSError:
        pass


def arp_check(address, mac, before=None, settle=ARP_SETTLE):
    """(answered, detail) from the neighbour table; answered is None when the table cannot
    be read. `before` is the entry as it was before this round's probes: an entry that
    appeared since is a fresh answer, one that was already cached has to survive the
    kernel re-verifying it."""
    if before is None:
        before = neighbour(address)
        if before is None:
            return None, "This device does not let apps read the network's address table."
    _nudge(address)
    cached = before[0] in CACHED_STATES
    deadline = time.monotonic() + settle
    found = before
    while time.monotonic() < deadline:
        time.sleep(ARP_POLL)
        found = neighbour(address) or ("NONE", None)
        state = found[0]
        if state in ("REACHABLE", "PERMANENT") or (state == "COMPLETE" and not cached):
            break
        if state == "FAILED":
            return False, "No answer to ARP"
    if found[0] not in ("REACHABLE", "PERMANENT", "COMPLETE"):
        return False, "No answer to ARP"
    seen = pcs.parse_mac(found[1] or "")
    if seen is None or seen == bytes(6):
        return False, "No answer to ARP"
    if seen != pcs.parse_mac(mac):
        return False, ("Another device (%s) has this IP address now. Check the PC's IP "
                       "address." % pcs.format_mac(seen))
    return True, "Seen on the network (ARP)"


def probe(pc):
    address = pcs.check_host(pc)
    if address is None:
        return None, "No IP address to check."
    if pc["status_method"] == "tcp":
        if not pc["status_port"]:
            return None, "No TCP port to probe."
        return tcp_probe(address, pc["status_port"])
    # Automatic: ping first; when ping gets no answer, the neighbour table decides.
    before = neighbour(address)
    answered, detail = ping(address)
    capabilities["ping"] = answered is not None
    if answered:
        return answered, detail
    if before is None:
        if answered is None:
            return None, ("This device can neither ping nor read the network's address "
                          "table. Choose a TCP check instead.")
        return answered, detail
    seen, arp_detail = arp_check(address, pc["mac"], before)
    if seen and answered is False:
        return True, "Seen on the network (ARP). It does not answer ping, probably its firewall."
    if seen:
        return True, arp_detail
    if arp_detail != "No answer to ARP":
        return False, arp_detail
    return False, "No answer to ping or ARP" if answered is False else arp_detail


def internet_latency():
    """Seconds a TCP connection to a public DNS server took, or None when none answered."""
    for address in INTERNET_PROBES:
        started = time.monotonic()
        try:
            socket.create_connection(address, timeout=3).close()
            return time.monotonic() - started
        except OSError:
            pass
    return None


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
        detail = "Wake packet sent. No answer yet."
        if entry.get("detail"):
            detail += " Last check: %s." % entry["detail"].rstrip(".")
        return {"state": "waking", "label": "Waiting for reply", "detail": detail,
                "checked_at": entry.get("checked_at")}
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
    probed, started = 0, time.monotonic()
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
    if probed:
        last_round.update(at=runtime.now_local(), pcs=probed, seconds=time.monotonic() - started)
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
            runtime.internet_latency = internet_latency()
            online = runtime.internet_latency is not None
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
            runtime.internet = runtime.internet_since = runtime.internet_latency = None
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
