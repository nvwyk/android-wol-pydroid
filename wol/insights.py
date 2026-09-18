"""Plain-language observations for the System page: what needs attention on this device,
its network and the PCs' reachability checks, and why a figure is missing.

Each insight is (kind, message) with kind one of error, warning, info or success, the
same kinds the notice macro draws. They are worked out from figures that already exist;
nothing here probes the network or writes to the database.
"""
from datetime import timedelta

from . import db, formatting, monitor, pcs, runtime, settings, system

MEMORY_WARN = 90
STORAGE_WARN, STORAGE_DANGER = 85, 95
BATTERY_WARN = 15
HOT = 70                    # degrees C on the hottest sensor
SLOW_INTERNET = 0.5         # seconds for a TCP connection to a public DNS server


def device():
    with system.lock:
        memory, storage, battery = system.host.memory, system.host.storage, system.host.battery
        heat, cpu = system.host.temperatures, system.host.cpu
    found = []
    if memory and memory[1] and 100.0 * memory[0] / memory[1] >= MEMORY_WARN:
        found.append(("warning", "Memory is %s full. Android closes background apps first when "
                                 "memory runs out; exclude Pydroid 3 from battery optimisation so "
                                 "the server is not among them."
                      % formatting.format_percent(100.0 * memory[0] / memory[1])))
    if storage and storage[1]:
        share = 100.0 * storage[0] / storage[1]
        if share >= STORAGE_WARN:
            found.append(("error" if share >= STORAGE_DANGER else "warning",
                          "Storage is %s full. The database, its backups and updates "
                          "need free space." % formatting.format_percent(share)))
    if battery and battery[0] <= BATTERY_WARN and (battery[1] or "").lower() != "charging":
        found.append(("warning", "The battery is at %s and not charging. The server stops when "
                                 "the phone switches off." % formatting.format_percent(battery[0])))
    if heat and heat[0][1] >= HOT:
        found.append(("warning", "The %s sensor reads %.0f °C. A phone kept running around the "
                                 "clock lasts longer out of direct sun and off a hot charger."
                      % (heat[0][0], heat[0][1])))
    if cpu is None and system.android_name():
        missing = "the total CPU load" + (" and the battery" if battery is None else "")
        found.append(("info", "Android does not let apps read %s, so this page shows the CPU "
                              "clock speed and this server's own CPU use instead." % missing))
    return found


def network():
    found = []
    if runtime.internet is False:
        since = formatting.clock(runtime.internet_since) if runtime.internet_since else None
        found.append(("warning", "The internet is unreachable%s. Waking PCs on the local network "
                                 "still works; access from outside does not."
                      % (" since %s" % since if since else "")))
    elif runtime.internet and runtime.internet_latency and runtime.internet_latency >= SLOW_INTERNET:
        found.append(("info", "The internet answers slowly (%d ms to a public DNS server). "
                              "Pages may load slowly from outside the home network."
                      % (runtime.internet_latency * 1000)))
    if not system.lan_address():
        found.append(("warning", "This device has no network address. Check that Wi-Fi is on "
                                 "and connected."))
    return found


def reachability(all_pcs):
    """What the checks found about each PC, and what this device allows them to do."""
    found = []
    checks_on = settings.get("status_checks_enabled")
    auto = [pc for pc in all_pcs if pc["enabled"] and pc["status_method"] == "ping"]
    if checks_on and auto:
        ping, table = monitor.capabilities["ping"], monitor.capabilities["neighbour"]
        if ping is False and table == "":
            found.append(("warning", "This device can neither ping nor read the network's address "
                                     "table, so automatic checks cannot tell whether a PC is on. "
                                     "Switch those PCs to a TCP check."))
        elif ping is False and table:
            found.append(("info", "Ping is not available on this device. Automatic checks use "
                                  "the network's address table (ARP) alone, which works as well."))
    for pc in all_pcs:
        if not pc["enabled"] or not checks_on or pc["status_method"] == "none":
            continue
        status = monitor.status_of(pc)
        detail = status.get("detail") or ""
        if status["state"] == "online" and "does not answer ping" in detail:
            found.append(("info", "%s blocks ping, most likely with the Windows firewall on a "
                                  "network set to Public. Its status comes from ARP instead, so "
                                  "nothing needs fixing. To allow ping as well, set the network to "
                                  "Private or turn on the firewall rule \"File and Printer Sharing "
                                  "(Echo Request - ICMPv4-In)\"." % pc["name"]))
        elif "Another device" in detail:
            found.append(("warning", "%s: %s" % (pc["name"], detail)))
    seen = {}
    for pc in all_pcs:
        seen.setdefault(pcs.parse_mac(pc["mac"]), []).append(pc["name"])
    for names in seen.values():
        if len(names) > 1:
            found.append(("warning", "%s share one MAC address, so they wake the same network "
                                     "adapter. Delete the extra entry, or correct the MAC if they "
                                     "are different PCs." % " and ".join(names)))
    return found


def security(conn):
    since = db.to_iso(runtime.now_local() - timedelta(hours=24))
    failures = conn.execute("SELECT count(*) FROM events WHERE type = 'auth.login_failed' "
                            "AND created_at > ?", (since,)).fetchone()[0]
    if failures:
        return [("warning", "%s in the last 24 hours. Admin > Security lists where they came "
                            "from." % formatting.plural(failures, "failed sign-in"))]
    return []


def server():
    found = []
    if runtime.database_warning:
        found.append(("error", "The database integrity check reported: %s. Download a backup "
                               "in Admin > Settings." % runtime.database_warning))
    if runtime.launcher_generation() == 1:
        found.append(("warning", "The launcher.py on this device is too old to install updates "
                                 "of the whole application. Copy the current launcher.py over."))
    elif runtime.supervised():
        result = runtime.launcher_state()["last_check_result"] or ""
        if "failed" in result or "postponed" in result:
            found.append(("warning", "Latest update check: %s." % result))
    return found


def collect(conn):
    """Every insight, most urgent first; one success line when nothing needs attention."""
    found = (server() + device() + network()
             + reachability(pcs.load_all(conn)) + security(conn))
    order = {"error": 0, "warning": 1, "info": 2}
    found.sort(key=lambda item: order.get(item[0], 3))
    if not any(kind in ("error", "warning") for kind, _ in found):
        found.insert(0, ("success", "Nothing needs attention."))
    return found

