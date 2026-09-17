"""WOL Controller: a small web app that wakes a PC with Wake-on-LAN magic packets.

launcher.py runs this file, restarts it when it exits and replaces it with newer versions from
GitHub. Only this file is updated, so the pages, styles and icons all live here: no templates
directory, no CDN, nothing to fetch. That also keeps the UI working on the LAN while the phone
has no internet. Device settings live in config.json, which updates never touch.
"""
import collections
import hashlib
import hmac
import json
import logging
import os
import platform
import secrets
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from types import SimpleNamespace
from urllib.parse import quote

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from jinja2 import DictLoader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# Device-local settings live in config.json, which updates never overwrite.
DEFAULT_CONFIG = {
    "password": "CHANGE_YOUR_PASSWORD",
    "target_mac": "244BFE070CE2",
    "target_ips": ["192.168.1.25", "192.168.1.255"],
    "wol_ports": [7, 9],
    "server_port": 5000,
}

SESSION_LIFETIME = timedelta(days=30)   # the phone stays logged in between wakes
MAX_LOGIN_FAILURES = 5                  # per client address...
LOGIN_WINDOW = 15 * 60                  # ...within this many seconds
INTERNET_PROBES = [("1.1.1.1", 53), ("8.8.8.8", 53)]
INTERNET_INTERVAL = 60
EVENT_LOG_SIZE = 50
HOST_INTERVAL = 5                       # seconds between load samples
HISTORY_SIZE = 60                       # 60 samples at 5 s: five minutes of trend
BYTE_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("wol")


# --- Config -----------------------------------------------------------------

def load_config():
    config = dict(DEFAULT_CONFIG)
    exists = os.path.exists(CONFIG_PATH)
    if exists:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            try:
                config.update(json.load(f))
            except ValueError as e:
                sys.exit("config.json is not valid JSON (%s). Fix it and run again." % e)
    if not exists or not config.get("secret_key"):
        # Persisted so sessions survive restarts caused by updates.
        config["secret_key"] = config.get("secret_key") or secrets.token_hex(32)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp, CONFIG_PATH)
    return config


def as_list(value):
    """Tolerate a single value where config.json documents a list."""
    return value if isinstance(value, list) else [value]


def parse_mac(value):
    """The 6 MAC bytes of 24-4B-FE-07-0C-E2, 24:4b:fe:07:0c:e2 or 244BFE070CE2, else None."""
    digits = "".join(c for c in str(value) if c not in "-:. ")
    if len(digits) != 12 or not all(c in string.hexdigits for c in digits):
        return None
    return bytes.fromhex(digits)


def file_version(path):
    """Short git blob hash: the same id launcher.py and the GitHub API use for this file."""
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()[:7]


config = load_config()
PASSWORD = str(config["password"])
MAC = parse_mac(config["target_mac"])
MAC_TEXT = "-".join("%02X" % byte for byte in MAC) if MAC else str(config["target_mac"])
TARGET_IPS = [str(ip) for ip in as_list(config["target_ips"])]
WOL_PORTS = [int(port) for port in as_list(config["wol_ports"])]
SERVER_PORT = int(config["server_port"])
VERSION = file_version(os.path.abspath(__file__))

# Shown on every page while something in config.json stops waking from working at all.
if MAC is None:
    WAKE_PROBLEM = ("“target_mac” in config.json is not a MAC address. Write it like "
                    "24-4B-FE-07-0C-E2, then restart the launcher.")
elif not TARGET_IPS or not WOL_PORTS:
    WAKE_PROBLEM = ("config.json needs at least one address in “target_ips” and one port in "
                    "“wol_ports”. Add them, then restart the launcher.")
else:
    WAKE_PROBLEM = None

SETUP_NOTICES = [("error", WAKE_PROBLEM)] if WAKE_PROBLEM else []
if PASSWORD == DEFAULT_CONFIG["password"]:
    SETUP_NOTICES.append(("warning", "This server still uses the default password. Change "
                                     "“password” in config.json, then restart the launcher."))

# Kept in the session cookie. It follows the password, so changing the password signs everyone out.
AUTH_TOKEN = hmac.new(str(config["secret_key"]).encode(), PASSWORD.encode(),
                      hashlib.sha256).hexdigest()
PASSWORD_DIGEST = hashlib.sha256(PASSWORD.encode()).digest()

app = Flask(__name__)
app.secret_key = config["secret_key"]
app.config.update(
    # Cookies ignore ports, so the default name would clash with other apps on this host.
    SESSION_COOKIE_NAME="wol_session",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=SESSION_LIFETIME,
    MAX_CONTENT_LENGTH=64 * 1024,
)


# --- Runtime state ----------------------------------------------------------
# Shared by the request threads and the monitor thread. All of it resets on restart.

lock = threading.Lock()
STARTED = time.monotonic()
state = SimpleNamespace(
    internet=None,          # None until the first check, then True or False
    internet_since=None,
    wake_count=0,
    last_wake=None,
)
events = collections.deque(maxlen=EVENT_LOG_SIZE)   # newest first: (time, message, is_warning)
login_failures = {}                                 # client address -> recent failure times

# Filled in by monitor_host. Anything this device will not report stays None and its row
# or tile is left out of the page rather than shown as a zero.
host = SimpleNamespace(
    sampled_at=None,
    cpu=None,
    cpu_history=collections.deque(maxlen=HISTORY_SIZE),
    memory=None,                        # (used, total) bytes
    memory_history=collections.deque(maxlen=HISTORY_SIZE),
    storage=None,                       # (used, total) bytes
    battery=None,                       # (percent, status, temperature C)
    network=None,                       # (received, sent) bytes since boot
    rates=None,                         # (received, sent) bytes per second
    load=None,
    device_uptime=None,
    process_memory=None,
)
device_facts = {}                       # cached answers that never change while we run


def right_now():
    return datetime.now().astimezone()


def record(message, warning=False):
    """Print an event to the console and keep it for the admin page."""
    logger.log(logging.WARNING if warning else logging.INFO, message)
    with lock:
        events.appendleft((right_now(), message, warning))


# --- Background threads -----------------------------------------------------

def internet_reachable():
    for address in INTERNET_PROBES:
        try:
            socket.create_connection(address, timeout=3).close()
            return True
        except OSError:
            pass
    return False


def monitor_internet():
    """Track internet reachability for the status page.

    Status only: the LAN web server keeps serving when the internet drops, and process-level
    restarts are handled by launcher.py.
    """
    while True:
        online = internet_reachable()
        if online != state.internet:
            # Timestamp first: a reader that sees the new state always has a time to show with it.
            state.internet_since, state.internet = right_now(), online
            record("Internet connection is up" if online else "Internet connection lost",
                   warning=not online)
        time.sleep(INTERNET_INTERVAL)


def monitor_host():
    """Sample how busy the machine is. CPU and network are counters, so they need two reads."""
    previous_cpu, previous_net = cpu_counters(), network_counters()
    previous_at, gap = time.monotonic(), 1          # short first gap: the page wants numbers now
    while True:
        time.sleep(gap)
        gap = HOST_INTERVAL
        current_at = time.monotonic()
        current_cpu, current_net = cpu_counters(), network_counters()
        percent = cpu_percent(previous_cpu, current_cpu)
        rates = byte_rates(previous_net, current_net, current_at - previous_at)
        memory, storage, battery = memory_bytes(), storage_bytes(), battery_state()
        load, uptime, rss = load_average(), device_uptime(), process_memory_bytes()
        with lock:
            host.cpu = percent
            if percent is not None:
                host.cpu_history.append(percent)
            host.memory = memory
            if memory and memory[1]:
                host.memory_history.append(100.0 * memory[0] / memory[1])
            host.storage, host.battery = storage, battery
            host.network, host.rates = current_net, rates
            host.load, host.device_uptime, host.process_memory = load, uptime, rss
            host.sampled_at = right_now()
        previous_at = current_at
        previous_cpu = current_cpu or previous_cpu
        previous_net = current_net or previous_net


def watch_launcher():
    """Exit if launcher.py dies, so an orphan never keeps holding the port."""
    parent = os.getppid()
    while True:
        time.sleep(5)
        if os.getppid() != parent:
            logger.warning("Launcher is gone, exiting")
            os._exit(0)


# --- Wake-on-LAN ------------------------------------------------------------

def send_magic_packet(mac, hosts, ports):
    """Send the magic packet to every host and port. Returns (packets sent, error messages)."""
    packet = b"\xff" * 6 + mac * 16
    sent, errors = 0, []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for host in hosts:
            for port in ports:
                try:
                    sock.sendto(packet, (host, port))
                    sent += 1
                except (OSError, OverflowError) as e:
                    errors.append("%s:%s (%s)" % (host, port, e))
    return sent, errors


# --- Host stats -------------------------------------------------------------
# Every reader here is best effort. Android hides parts of /proc, other systems have
# none of it, so each one returns None instead of raising and the page leaves that
# figure out. Nothing below is allowed to make a page fail to render.

def read_file(path, limit=65536):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except (OSError, ValueError):
        return None


def to_int(text):
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


def kb_fields(text):
    """{"MemTotal": bytes} from the "Name:  123 kB" lines of /proc/meminfo or self/status."""
    fields = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].endswith(":") and parts[2] == "kB":
            value = to_int(parts[1])
            if value is not None:
                fields[parts[0][:-1]] = value * 1024
    return fields


def cpu_counters():
    """(busy, total) processor ticks since boot, or None where they are not readable."""
    text = read_file("/proc/stat")
    if text:
        for line in text.splitlines():
            if line.startswith("cpu "):
                values = [to_int(value) or 0 for value in line.split()[1:]]
                if len(values) >= 5:
                    # Guest time is already counted inside user and nice, so drop it from
                    # the total; busy is everything that is not idle or waiting on io.
                    total = sum(values) - sum(values[8:10])
                    return total - values[3] - values[4], total
        return None
    if sys.platform == "win32":
        import ctypes
        idle, kernel, user = (ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong())
        if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel),
                                                 ctypes.byref(user)):
            total = kernel.value + user.value       # kernel time already includes idle
            return total - idle.value, total
    return None


def memory_bytes():
    """(used, total) bytes of system memory."""
    fields = kb_fields(read_file("/proc/meminfo"))
    total = fields.get("MemTotal")
    if total:
        free = fields.get("MemAvailable")
        if free is None:                            # older kernels
            free = sum(fields.get(name, 0) for name in ("MemFree", "Buffers", "Cached"))
        return max(0, total - free), total
    if sys.platform == "win32":
        import ctypes

        class Memory(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                        ("total", ctypes.c_ulonglong), ("available", ctypes.c_ulonglong),
                        ("total_page", ctypes.c_ulonglong), ("free_page", ctypes.c_ulonglong),
                        ("total_virtual", ctypes.c_ulonglong), ("free_virtual", ctypes.c_ulonglong),
                        ("free_extended", ctypes.c_ulonglong)]

        status = Memory()
        status.length = ctypes.sizeof(Memory)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return status.total - status.available, status.total
    return None


def storage_bytes():
    """(used, total) bytes on the filesystem this file lives on."""
    try:
        usage = shutil.disk_usage(BASE_DIR)
    except OSError:
        return None
    return (usage.total - usage.free, usage.total) if usage.total else None


def battery_state():
    """(percent, status, temperature C) from the kernel's power supply class."""
    try:
        names = sorted(os.listdir("/sys/class/power_supply"))
    except OSError:
        return None
    for name in names:
        base = "/sys/class/power_supply/" + name
        if (read_file(base + "/type") or "").strip() != "Battery":
            continue
        percent = to_int(read_file(base + "/capacity"))
        if percent is None:
            continue
        raw = to_int(read_file(base + "/temp"))
        # Phones report tenths of a degree, a few report thousandths.
        celsius = None if raw is None else (raw / 1000.0 if abs(raw) >= 1000 else raw / 10.0)
        if celsius is not None and not -20 <= celsius <= 100:
            celsius = None
        return percent, (read_file(base + "/status") or "").strip() or None, celsius
    return None


def network_counters():
    """(received, sent) bytes over every interface except loopback."""
    # /proc/self/net still answers on Android versions that hide /proc/net.
    text = read_file("/proc/self/net/dev") or read_file("/proc/net/dev")
    if not text:
        return None
    received = sent = 0
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        fields = rest.split()
        if name.strip() in ("lo", "") or len(fields) < 9:
            continue
        received += to_int(fields[0]) or 0
        sent += to_int(fields[8]) or 0
    return received, sent


def load_average():
    try:
        return os.getloadavg()
    except (OSError, AttributeError):               # no getloadavg on Windows
        return None


def device_uptime():
    text = read_file("/proc/uptime")
    if text:
        try:
            return float(text.split()[0])
        except (IndexError, ValueError):
            return None
    if sys.platform == "win32":
        import ctypes
        return ctypes.windll.kernel32.GetTickCount64() / 1000.0
    return None


def process_memory_bytes():
    return kb_fields(read_file("/proc/self/status")).get("VmRSS")


def processor_name():
    for line in (read_file("/proc/cpuinfo") or "").splitlines():
        label, _, value = line.partition(":")
        if label.strip() in ("Hardware", "model name", "Processor") and value.strip():
            return value.strip()
    return platform.processor() or None


def android_name():
    """"Android 14 (Pixel 7)" when getprop answers. Asked once: it cannot change."""
    if "android" not in device_facts:
        device_facts["android"] = read_android_props()
    return device_facts["android"]


def read_android_props():
    try:
        output = subprocess.run(["getprop"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    props = {}
    for line in output.decode("utf-8", "replace").splitlines():
        if line.startswith("[") and "]: [" in line:
            key, _, value = line[1:].partition("]: [")
            props[key] = value.rstrip("]")
    release = props.get("ro.build.version.release")
    model = props.get("ro.product.model") or props.get("ro.product.device")
    if not release:
        return None
    return "Android %s (%s)" % (release, model) if model else "Android " + release


def lan_address():
    """This device's address on the local network, as its router sees it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 53))          # nothing is sent, this only picks the route
            return probe.getsockname()[0]
    except OSError:
        return None


def cpu_percent(before, after):
    if not before or not after:
        return None
    busy, total = after[0] - before[0], after[1] - before[1]
    if total <= 0:
        return None
    return max(0.0, min(100.0, 100.0 * busy / total))


def byte_rates(before, after, elapsed):
    if not before or not after or elapsed <= 0:
        return None
    return tuple(max(0, after[index] - before[index]) / elapsed for index in (0, 1))


# --- Auth -------------------------------------------------------------------

def is_authenticated():
    return hmac.compare_digest(str(session.get("auth", "")).encode(), AUTH_TOKEN.encode())


def password_matches(candidate):
    # Comparing digests keeps the check's duration independent of the password.
    return hmac.compare_digest(hashlib.sha256(candidate.encode()).digest(), PASSWORD_DIGEST)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_valid():
    expected = session.get("csrf", "")
    return bool(expected) and hmac.compare_digest(
        request.form.get("csrf_token", "").encode(), expected.encode())


def lockout_seconds(client):
    """How long this client must wait before guessing again. 0 means it may try now."""
    cutoff = time.monotonic() - LOGIN_WINDOW
    with lock:
        recent = [moment for moment in login_failures.get(client, ()) if moment > cutoff]
        if recent:
            login_failures[client] = recent
        else:
            login_failures.pop(client, None)
    if len(recent) < MAX_LOGIN_FAILURES:
        return 0
    return int(recent[-MAX_LOGIN_FAILURES] - cutoff) + 1


def minutes_left(seconds):
    """Whole minutes, rounded up, so a wait of 30 seconds never reads as 0 min."""
    return -(-seconds // 60)


def record_login_failure(client):
    now = time.monotonic()
    with lock:
        login_failures.setdefault(client, []).append(now)
        # Forget clients whose failures all expired, so address churn cannot grow this forever.
        for other in [c for c, times in login_failures.items() if times[-1] <= now - LOGIN_WINDOW]:
            del login_failures[other]


# --- Responses --------------------------------------------------------------

def csp_nonce():
    """One nonce per response for the inline stylesheet and script."""
    if "csp_nonce" not in g:
        g.csp_nonce = secrets.token_urlsafe(16)
    return g.csp_nonce


@app.after_request
def add_security_headers(response):
    nonce = csp_nonce()
    response.headers.setdefault("Content-Security-Policy", (
        "default-src 'none'; img-src data:; style-src 'nonce-%s'; script-src 'nonce-%s'; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        % (nonce, nonce)))
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # A private control panel belongs in nobody's search index or crawler cache.
    response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.context_processor
def template_context():
    return {
        "authed": is_authenticated(),
        "csp_nonce": csp_nonce(),
        "csrf_token": csrf_token,
        "favicon": FAVICON,
        "icons": ICONS,
        "setup_notices": SETUP_NOTICES,
        "state": state,
        "version": VERSION,
        "wake_problem": WAKE_PROBLEM,
    }


@app.template_filter("clock")
def format_clock(moment):
    """19:12:28 for today, 2026-09-16 19:12 for earlier days."""
    return moment.strftime("%H:%M:%S" if moment.date() == right_now().date() else "%Y-%m-%d %H:%M")


@app.template_filter("duration")
def format_duration(seconds):
    """45 s, 12 min, 3 h 5 min or 2 d 4 h, with the number and unit kept on one line."""
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return "%d d %d h" % (days, hours)
    if hours:
        return "%d h %d min" % (hours, minutes)
    return "%d min" % minutes if minutes else "%d s" % seconds


# --- System page figures ----------------------------------------------------

def format_bytes(count):
    """340 MB, 1.2 GB, 57 GB. The number and its unit stay on one line."""
    if count is None:
        return None
    size = float(count)
    for unit in BYTE_UNITS:
        if size < 1000 or unit == BYTE_UNITS[-1]:
            return "%.*f %s" % (1 if size < 10 and unit != "B" else 0, size, unit)
        size /= 1000.0


def format_rate(per_second):
    return None if per_second is None else format_bytes(per_second) + "/s"


def format_percent(value):
    return None if value is None else "%d%%" % round(value)


def total_and_rate(total, rate):
    """"1.2 GB, 12 kB/s" for a counter that also has a current rate."""
    if total is None:
        return None
    if rate is None:
        return format_bytes(total)
    return "%s, %s" % (format_bytes(total), format_rate(rate))


def spark_points(values, width=100, height=28, pad=2):
    """Points for a 0-100 series, oldest first. The padding keeps the stroke inside the box."""
    if len(values) < 2:
        return []
    span = height - 2 * pad
    step = width / float(len(values) - 1)
    return ["%.1f,%.1f" % (index * step, pad + span - span * min(100.0, max(0.0, value)) / 100.0)
            for index, value in enumerate(values)]


def severity(percent, warn, danger, low=False):
    """ok, warn or danger. Pass low=True where a small number is the problem, like a battery."""
    if percent is None:
        return "ok"
    if percent <= danger if low else percent >= danger:
        return "danger"
    if percent <= warn if low else percent >= warn:
        return "warn"
    return "ok"


def trend_tile(key, label, value, detail, history, alt):
    points = spark_points(history)
    return {"key": key, "label": label, "value": value, "detail": detail, "alt": alt,
            # The line is de-emphasised grey; the last stretch carries the accent as "now".
            "spark": {"line": " ".join(points), "now": " ".join(points[-7:])}}


def host_snapshot():
    """Every live figure on the System page, formatted once for the page and for the poll."""
    with lock:
        cpu, cpu_history = host.cpu, list(host.cpu_history)
        memory, memory_history = host.memory, list(host.memory_history)
        storage, battery = host.storage, host.battery
        network, rates, load = host.network, host.rates, host.load
        booted, rss, sampled_at = host.device_uptime, host.process_memory, host.sampled_at

    tiles = []
    if cpu is not None:
        peak = format_percent(max(cpu_history or [cpu]))
        tiles.append(trend_tile("cpu", "CPU load", format_percent(cpu), "peak " + peak,
                                cpu_history, "CPU load over the last five minutes. Now %s, "
                                             "peak %s." % (format_percent(cpu), peak)))
    if memory:
        used, total = memory
        share = 100.0 * used / total
        tiles.append(trend_tile("memory", "Memory", format_bytes(used),
                                "%s of %s" % (format_percent(share), format_bytes(total)),
                                memory_history,
                                "Memory in use over the last five minutes. Now %s of %s."
                                % (format_bytes(used), format_bytes(total))))
    if storage:
        used, total = storage
        share = 100.0 * used / total
        tiles.append({"key": "storage", "label": "Storage", "value": format_bytes(used),
                      "detail": "%s of %s" % (format_percent(share), format_bytes(total)),
                      "meter": round(share, 1), "level": severity(share, 80, 92)})
    if battery:
        percent, status, _ = battery
        tiles.append({"key": "battery", "label": "Battery", "value": format_percent(percent),
                      "detail": (status or "Unknown").capitalize(),
                      "meter": percent, "level": severity(percent, 25, 10, low=True)})

    text = {tile["key"]: tile["value"] for tile in tiles}
    text.update(("%s-detail" % tile["key"], tile["detail"]) for tile in tiles)
    text.update({
        "load": ", ".join("%.2f" % value for value in load) if load else None,
        "device-uptime": format_duration(booted) if booted is not None else None,
        "battery-temp": "%.1f °C" % battery[2] if battery and battery[2] is not None else None,
        "received": total_and_rate(network[0] if network else None, rates[0] if rates else None),
        "sent": total_and_rate(network[1] if network else None, rates[1] if rates else None),
        "server-uptime": format_duration(time.monotonic() - STARTED),
        "process-memory": format_bytes(rss),
        "updated": format_clock(sampled_at) if sampled_at else None,
    })
    return {
        "tiles": tiles,
        "text": dict((key, value) for key, value in text.items() if value is not None),
        "meter": {tile["key"]: tile["meter"] for tile in tiles if "meter" in tile},
        "level": {tile["key"]: tile["level"] for tile in tiles if "level" in tile},
        "spark": {tile["key"]: tile["spark"] for tile in tiles if "spark" in tile},
        "ready": sampled_at is not None,
    }


# --- Routes -----------------------------------------------------------------

@app.route("/")
@login_required
def home():
    return render_template("dashboard.html", mac=MAC_TEXT, ip=TARGET_IPS[0] if TARGET_IPS else "")


@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect(url_for("home"))

    client = request.remote_addr or "unknown"
    wait = lockout_seconds(client)
    error = None
    if request.method == "POST" and not wait:
        if password_matches(request.form.get("password", "")):
            with lock:
                login_failures.pop(client, None)
            session.clear()
            session.permanent = True
            session["auth"] = AUTH_TOKEN
            record("Logged in from %s" % client)
            return redirect(url_for("home"))
        record_login_failure(client)
        wait = lockout_seconds(client)
        blocked = ", locked out for %d min" % minutes_left(wait) if wait else ""
        record("Failed login from %s%s" % (client, blocked), warning=True)
        error = "Wrong password. Check the “password” value in config.json."

    if wait:
        error = "Too many attempts. Try again in %d min." % minutes_left(wait)
        return render_template("login.html", error=error), 429, {"Retry-After": str(wait)}
    return render_template("login.html", error=error)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    # Only a form post signs out, so a link, a bookmark or a prefetch cannot do it by accident.
    if request.method == "POST" and csrf_valid():
        session.clear()
        return redirect(url_for("login"))
    return redirect(url_for("home"))


@app.route("/wake", methods=["GET", "POST"])
@login_required
def wake():
    # Same rule as signing out, and it matters more here: browsers prefetch links they expect
    # you to open, and that used to be enough to wake the PC.
    if request.method == "GET":
        return redirect(url_for("home"))
    if not csrf_valid():
        flash("That page was out of date. Press Wake Computer again.", "warning")
        return redirect(url_for("home"))
    if WAKE_PROBLEM:
        flash(WAKE_PROBLEM, "error")
        return redirect(url_for("home"))

    client = request.remote_addr or "unknown"
    try:
        sent, errors = send_magic_packet(MAC, TARGET_IPS, WOL_PORTS)
    except OSError as e:
        sent, errors = 0, [str(e)]
    if sent:
        with lock:
            state.wake_count += 1
            state.last_wake = right_now()

    expected = len(TARGET_IPS) * len(WOL_PORTS)
    if not sent:
        record("Wake failed for %s: %s" % (client, "; ".join(errors)), warning=True)
        flash("The wake packet did not go out: %s. Check that the phone is on the same network "
              "as your PC." % errors[0], "error")
    elif sent < expected:
        record("Wake sent by %s, %d of %d packets: %s"
               % (client, sent, expected, "; ".join(errors)), warning=True)
        flash("Sent %d of %d wake packets. These failed: %s." % (sent, expected, "; ".join(errors)),
              "warning")
    else:
        record("Wake sent by %s" % client)
        flash("Wake packet sent to %s." % " & ".join(TARGET_IPS), "success")
    return redirect(url_for("home"))


@app.route("/status")
def status():
    return render_template("status.html", uptime=time.monotonic() - STARTED)


@app.route("/system")
@login_required
def system():
    snapshot = host_snapshot()
    text = snapshot["text"]
    cores = os.cpu_count()
    android = android_name()
    kernel = "%s %s (%s)" % (platform.system(), platform.release(),
                             platform.machine() or "unknown")
    groups = [
        ("Device", [
            # On a phone the Android version and the kernel are both worth knowing.
            # Anywhere else they are the same fact, so the kernel row stays out.
            ("Operating system", None, android or kernel),
            ("Kernel", None, kernel if android else None),
            ("Processor", None, processor_name()),
            ("Cores", None, str(cores) if cores else None),
            ("Load average", "load", text.get("load")),
            ("Device uptime", "device-uptime", text.get("device-uptime")),
            ("Battery temperature", "battery-temp", text.get("battery-temp")),
        ]),
        ("Network", [
            ("Listening on", None, "%s:%d" % (lan_address() or "0.0.0.0", SERVER_PORT)),
            ("You reached it at", None, request.host),
            ("Your address", None, request.remote_addr),
            ("Received", "received", text.get("received")),
            ("Sent", "sent", text.get("sent")),
        ]),
        ("This server", [
            ("Version", None, VERSION),
            ("Server uptime", "server-uptime", text.get("server-uptime")),
            ("Memory in use", "process-memory", text.get("process-memory")),
            ("Process id", None, str(os.getpid())),
            ("Python", None, platform.python_version()),
            ("Auto-update", None, "On, run by launcher.py"
             if os.environ.get("WOL_INSTANCE_TOKEN") else "Off, started without launcher.py"),
        ]),
    ]
    groups = [(title, [row for row in rows if row[2]]) for title, rows in groups]
    return render_template("system.html", snapshot=snapshot, groups=groups,
                           poll_interval=HOST_INTERVAL * 1000)


@app.route("/system.json")
@login_required
def system_figures():
    # What the System page polls while it is open. Only the figures that change.
    snapshot = host_snapshot()
    snapshot.pop("tiles")
    return jsonify(snapshot)


@app.route("/admin")
@login_required
def admin():
    with lock:
        recent = list(events)
    return render_template("admin.html", events=recent, mac=MAC_TEXT, ips=TARGET_IPS,
                           ports=WOL_PORTS, server_port=SERVER_PORT, config_path=CONFIG_PATH)


@app.route("/health")
def health():
    # Token lets launcher.py tell its own child apart from a stale process on the port.
    return jsonify(ok=True, version=VERSION, token=os.environ.get("WOL_INSTANCE_TOKEN"))


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.errorhandler(404)
def not_found(error):
    return render_template("not_found.html"), 404


# --- Icons ------------------------------------------------------------------
# Phosphor Icons, bold weight, MIT licensed (phosphoricons.com), on a 256x256 grid.

ICONS = {
    "power": "M116,128V48a12,12,0,0,1,24,0v80a12,12,0,0,1-24,0Zm66.55-82a12,12,0,0,0-13.1,20.1C1"
             "91.41,80.37,204,103,204,128a76,76,0,0,1-152,0c0-25,12.59-47.63,34.55-61.95A12,12,0,"
             "0,0,73.45,46C44.56,64.78,28,94.69,28,128a100,100,0,0,0,200,0C228,94.69,211.44,64.78"
             ",182.55,46Z",
    "monitor": "M208,36H48A28,28,0,0,0,20,64V176a28,28,0,0,0,28,28H208a28,28,0,0,0,28-28V64A28,28,"
               "0,0,0,208,36Zm4,140a4,4,0,0,1-4,4H48a4,4,0,0,1-4-4V64a4,4,0,0,1,4-4H208a4,4,0,0,1"
               ",4,4Zm-40,52a12,12,0,0,1-12,12H96a12,12,0,0,1,0-24h64A12,12,0,0,1,172,228Z",
    "sign-out": "M124,216a12,12,0,0,1-12,12H48a12,12,0,0,1-12-12V40A12,12,0,0,1,48,28h64a12,12,0,"
                "0,1,0,24H60V204h52A12,12,0,0,1,124,216Zm108.49-96.49-40-40a12,12,0,0,0-17,17L195"
                ",116H112a12,12,0,0,0,0,24h83l-19.52,19.51a12,12,0,0,0,17,17l40-40A12,12,0,0,0,23"
                "2.49,119.51Z",
    "success": "M176.49,95.51a12,12,0,0,1,0,17l-56,56a12,12,0,0,1-17,0l-24-24a12,12,0,1,1,17-17L1"
               "12,143l47.51-47.52A12,12,0,0,1,176.49,95.51ZM236,128A108,108,0,1,1,128,20,108.12,"
               "108.12,0,0,1,236,128Zm-24,0a84,84,0,1,0-84,84A84.09,84.09,0,0,0,212,128Z",
    "warning": "M240.26,186.1,152.81,34.23h0a28.74,28.74,0,0,0-49.62,0L15.74,186.1a27.45,27.45,0,"
               "0,0,0,27.71A28.31,28.31,0,0,0,40.55,228h174.9a28.31,28.31,0,0,0,24.79-14.19A27.45"
               ",27.45,0,0,0,240.26,186.1Zm-20.8,15.7a4.46,4.46,0,0,1-4,2.2H40.55a4.46,4.46,0,0,1"
               "-4-2.2,3.56,3.56,0,0,1,0-3.73L124,46.2a4.77,4.77,0,0,1,8,0l87.44,151.87A3.56,3.56"
               ",0,0,1,219.46,201.8ZM116,136V104a12,12,0,0,1,24,0v32a12,12,0,0,1-24,0Zm28,40a16,16"
               ",0,1,1-16-16A16,16,0,0,1,144,176Z",
    "error": "M128,20A108,108,0,1,0,236,128,108.12,108.12,0,0,0,128,20Zm0,192a84,84,0,1,1,84-84A8"
             "4.09,84.09,0,0,1,128,212Zm-12-80V80a12,12,0,0,1,24,0v52a12,12,0,0,1-24,0Zm28,40a16,"
             "16,0,1,1-16-16A16,16,0,0,1,144,172Z",
}

# The power glyph on a dark tile, scaled and shifted to sit in the middle of the tile.
FAVICON = "data:image/svg+xml," + quote(
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>"
    "<rect width='256' height='256' rx='60' fill='#0a0b0d'/>"
    "<path fill='#54c97b' transform='translate(48.6 46.2) scale(0.62)' d='%s'/></svg>"
    % ICONS["power"])


# --- Pages ------------------------------------------------------------------
# Dark only, one green accent for the primary action, phone width first. Surfaces step from the
# canvas up through three lighter greys instead of using shadows, and hairlines carry every edge.

STYLE = """
:root {
  color-scheme: dark;
  --canvas: #0a0b0d;
  --surface: #111215;
  --surface-2: #17181c;
  --surface-3: #1e2025;
  --hairline: #23252a;
  --hairline-strong: #33363c;
  --ink: #f3f4f6;
  --body: #c5c7cc;
  --muted: #8b8e96;
  --accent: #54c97b;
  --accent-hover: #67d38b;
  --accent-press: #47b56c;
  --on-accent: #05190c;
  --accent-soft: rgba(84, 201, 123, 0.1);
  --accent-line: rgba(84, 201, 123, 0.3);
  --warn: #e2b04f;
  --warn-soft: rgba(226, 176, 79, 0.1);
  --warn-line: rgba(226, 176, 79, 0.3);
  --danger: #f07b7b;
  --danger-soft: rgba(240, 123, 123, 0.1);
  --danger-line: rgba(240, 123, 123, 0.32);
  --spark: #6d727a;
  --spark-wash: rgba(255, 255, 255, 0.05);
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", "Roboto Mono", Menlo, Consolas, monospace;
}

*, *::before, *::after { box-sizing: border-box; }

html {
  background: var(--canvas);
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
}

body {
  margin: 0;
  min-height: 100vh;
  min-height: 100dvh;
  background: var(--canvas);
  color: var(--body);
  font: 15px/1.5 var(--font);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

h1, h2, p, dl, dd, ol, ul { margin: 0; }
h1, h2 { color: var(--ink); font-weight: 600; text-wrap: balance; }
h1 { font-size: 22px; line-height: 28px; letter-spacing: -0.02em; }
h2 { font-size: 15px; line-height: 22px; letter-spacing: -0.01em; }
p { text-wrap: pretty; }
a { color: inherit; }
button, input { font: inherit; color: inherit; margin: 0; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
::selection { background: var(--accent); color: var(--on-accent); }

.sprite { position: absolute; width: 0; height: 0; overflow: hidden; }
.icon { width: 18px; height: 18px; flex: none; fill: currentColor; }
.mono { font-family: var(--mono); font-size: 0.92em; }
.num { font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); }
.line { display: block; }
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  border: 0;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}

.skip-link {
  position: absolute;
  top: 12px;
  left: 16px;
  z-index: 2;
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: var(--canvas);
  font-size: 14px;
  font-weight: 500;
  text-decoration: none;
  transform: translateY(-200%);
}
.skip-link:focus { transform: none; }

.shell {
  display: grid;
  align-content: start;
  gap: 16px;
  width: 100%;
  max-width: 480px;
  margin: 0 auto;
  padding:
    max(24px, env(safe-area-inset-top))
    max(16px, env(safe-area-inset-right))
    max(40px, env(safe-area-inset-bottom))
    max(16px, env(safe-area-inset-left));
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  min-height: 40px;
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  border-radius: var(--radius-sm);
  color: var(--ink);
  font-weight: 600;
  letter-spacing: -0.01em;
  text-decoration: none;
}
.brand-mark {
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border-radius: var(--radius-sm);
  background: var(--accent-soft);
  box-shadow: inset 0 0 0 1px var(--accent-line);
  color: var(--accent);
}
.brand-mark .icon { width: 17px; height: 17px; }

.tabs {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 4px;
  padding: 4px;
  border: 1px solid var(--hairline);
  border-radius: var(--radius-md);
  background: var(--surface);
}
.tabs a {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 40px;
  border-radius: var(--radius-sm);
  color: var(--muted);
  font-size: 14px;
  font-weight: 500;
  text-decoration: none;
  touch-action: manipulation;
  transition: background-color 0.15s ease, color 0.15s ease;
}
.tabs a:hover { background: var(--surface-2); color: var(--ink); }
.tabs a[aria-current="page"] {
  background: var(--surface-3);
  box-shadow: inset 0 0 0 1px var(--hairline-strong);
  color: var(--ink);
}

main { display: grid; gap: 16px; }
main:focus { outline: none; }

.card {
  display: grid;
  gap: 20px;
  padding: 20px;
  border: 1px solid var(--hairline);
  border-radius: var(--radius-lg);
  background: var(--surface);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}
.card-head { display: grid; gap: 4px; }
.card-head p { font-size: 14px; }
.group { display: grid; gap: 4px; }

.device { display: flex; align-items: center; gap: 14px; }
.device-icon {
  display: grid;
  place-items: center;
  flex: none;
  width: 48px;
  height: 48px;
  border-radius: var(--radius-md);
  background: var(--surface-2);
  box-shadow: inset 0 0 0 1px var(--hairline-strong);
}
.device-icon .icon { width: 24px; height: 24px; }
.device-meta { margin-top: 2px; color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 40px;
  padding: 0 14px;
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  font-size: 14px;
  font-weight: 500;
  line-height: 1;
  text-decoration: none;
  white-space: nowrap;
  cursor: pointer;
  touch-action: manipulation;
  -webkit-tap-highlight-color: transparent;
  transition: background-color 0.15s ease, border-color 0.15s ease, color 0.15s ease,
              transform 0.1s ease;
}
@media (pointer: coarse) { .btn, .tabs a { min-height: 44px; } }
.btn:active:not(:disabled) { transform: scale(0.98); }
.btn:disabled { cursor: not-allowed; opacity: 0.45; }
.btn[aria-busy="true"] { cursor: progress; }
.btn-primary { background: var(--accent); color: var(--on-accent); font-weight: 600; }
.btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
.btn-primary:active:not(:disabled) { background: var(--accent-press); }
.btn-secondary { background: var(--surface-2); border-color: var(--hairline-strong); color: var(--ink); }
.btn-secondary:hover { background: var(--surface-3); }
.btn-quiet { padding: 0 10px; background: transparent; color: var(--muted); }
.btn-quiet:hover { background: var(--surface-2); color: var(--ink); }
.btn-lg { width: 100%; min-height: 48px; font-size: 15px; }
.btn-xl { width: 100%; min-height: 56px; font-size: 16px; }

.btn-icon { display: grid; place-items: center; width: 20px; height: 20px; }
.spinner {
  display: none;
  width: 17px;
  height: 17px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
[aria-busy="true"] .btn-icon .icon { display: none; }
[aria-busy="true"] .spinner { display: block; }
@keyframes spin { to { transform: rotate(360deg); } }

.notice {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid;
  border-radius: var(--radius-md);
  color: var(--ink);
  font-size: 14px;
}
.notice .icon { margin-top: 1px; }
.notice-success { border-color: var(--accent-line); background: var(--accent-soft); }
.notice-success .icon { color: var(--accent); }
.notice-warning { border-color: var(--warn-line); background: var(--warn-soft); }
.notice-warning .icon { color: var(--warn); }
.notice-error { border-color: var(--danger-line); background: var(--danger-soft); }
.notice-error .icon { color: var(--danger); }

.form { display: grid; gap: 16px; }
.field { display: grid; gap: 8px; }
.field label { color: var(--ink); font-size: 14px; font-weight: 500; }
.input {
  width: 100%;
  height: 48px;
  padding: 0 14px;
  border: 1px solid var(--hairline-strong);
  border-radius: var(--radius-md);
  background: var(--surface-2);
  color: var(--ink);
  font-size: 16px;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
.input:hover { border-color: #464950; }
.input:focus {
  outline: 2px solid transparent;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.input[aria-invalid="true"] { border-color: var(--danger); }
.input[aria-invalid="true"]:focus { box-shadow: 0 0 0 3px var(--danger-soft); }
.input:-webkit-autofill {
  -webkit-text-fill-color: var(--ink);
  -webkit-box-shadow: 0 0 0 40px var(--surface-2) inset;
  caret-color: var(--ink);
}
.input:-webkit-autofill:focus {
  -webkit-box-shadow: 0 0 0 40px var(--surface-2) inset, 0 0 0 3px var(--accent-soft);
}
.field-error { color: var(--danger); font-size: 13px; }

.stats {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--hairline);
}
.stats > div { display: grid; gap: 2px; min-width: 0; }
.stats dt { color: var(--muted); font-size: 13px; }
/* Proportional figures on purpose: tabular digits read loose at this size. */
.stats dd { color: var(--ink); font-size: 17px; font-weight: 600; }

/* Live figures. Thin marks, a de-emphasised trend line with the accent only on the
   latest stretch, and meters whose track is a lighter step of the fill. */
.tiles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.tile {
  display: grid;
  align-content: start;
  gap: 8px;
  padding: 12px 14px;
  border: 1px solid var(--hairline);
  border-radius: var(--radius-md);
  background: var(--surface-2);
}
.tile-label { color: var(--muted); font-size: 12px; }
.tile-value { color: var(--ink); font-size: 20px; font-weight: 600; line-height: 1.15; }
.tile-detail { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12px; }
/* The icon is the second channel: green and red are 2.5 apart under deuteranopia. */
.tile-detail .icon { display: none; width: 13px; height: 13px; }
.level-warn .tile-detail { color: var(--warn); }
.level-danger .tile-detail { color: var(--danger); }
.level-warn .tile-detail .icon, .level-danger .tile-detail .icon { display: block; }

.spark { display: block; width: 100%; height: 28px; }
.spark-area { fill: var(--spark-wash); stroke: none; }
.spark-line, .spark-now {
  fill: none;
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
  vector-effect: non-scaling-stroke;
}
.spark-line { stroke: var(--spark); }
.spark-now { stroke: var(--accent); }

.meter {
  appearance: none;
  -webkit-appearance: none;
  display: block;
  width: 100%;
  height: 6px;
  margin: 11px 0;          /* matches the sparkline's height, so tiles line up */
  border: 0;
  border-radius: 999px;
  background: var(--meter-track);
  color: var(--meter-fill);
}
.meter::-webkit-progress-bar { background: var(--meter-track); border-radius: 999px; }
.meter::-webkit-progress-value { background: var(--meter-fill); border-radius: 999px; }
.meter::-moz-progress-bar { background: var(--meter-fill); border-radius: 999px; }
.level-ok { --meter-fill: var(--accent); --meter-track: rgba(84, 201, 123, 0.16); }
.level-warn { --meter-fill: var(--warn); --meter-track: rgba(226, 176, 79, 0.16); }
.level-danger { --meter-fill: var(--danger); --meter-track: rgba(240, 123, 123, 0.18); }

/* A refresh that fails holds the last figures at lower opacity instead of blanking. */
.tiles, .rows { transition: opacity 0.2s ease; }
.is-stale .tiles, .is-stale .rows { opacity: 0.5; }

.rows > div {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
  padding: 10px 0;
}
.rows > div + div { border-top: 1px solid var(--hairline); }
.rows dt { flex: none; color: var(--muted); font-size: 14px; }
.rows dd { min-width: 0; color: var(--ink); font-size: 14px; text-align: right; overflow-wrap: anywhere; }
/* A value too long to sit beside its label, such as a file path, stacks under it instead. */
.rows > div.stacked { display: grid; gap: 2px; }
.rows > div.stacked dd { text-align: left; }

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-right: 8px;
  border-radius: 50%;
  background: var(--muted);
  vertical-align: 1px;
}
.dot-ok { background: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
.dot-warn { background: var(--warn); box-shadow: 0 0 0 3px var(--warn-soft); }

.log { width: 100%; border-collapse: collapse; font-size: 14px; }
.log td { padding: 10px 0; vertical-align: baseline; }
.log tr + tr td { border-top: 1px solid var(--hairline); }
.log td:first-child {
  width: 1%;
  padding-right: 16px;
  color: var(--muted);
  font-size: 13px;
  white-space: nowrap;
}
.log .is-warning td:last-child { color: var(--warn); }
.empty { color: var(--muted); font-size: 14px; }

.aside { color: var(--muted); font-size: 14px; text-align: center; }
.link {
  display: inline-block;
  padding: 4px 2px;
  color: var(--body);
  text-decoration: underline;
  text-decoration-color: var(--hairline-strong);
  text-underline-offset: 4px;
  transition: color 0.15s ease, text-decoration-color 0.15s ease;
}
.link:hover { color: var(--ink); text-decoration-color: currentColor; }

@media (min-width: 640px) { .shell { padding-top: 72px; } }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition-duration: 0.01ms !important; }
  .btn:active:not(:disabled) { transform: none; }
  .spinner { animation-duration: 1.5s; }
}
"""

SCRIPT = """
// Show progress on the pressed button and swallow repeat presses until the next page arrives.
document.addEventListener('submit', function (event) {
  var button = event.target.querySelector('button[type=submit]');
  if (!button) return;
  if (button.getAttribute('aria-busy') === 'true') {
    event.preventDefault();
  } else {
    button.setAttribute('aria-busy', 'true');
  }
});

// A page restored from the back/forward cache comes back exactly as it was left, spinner included.
window.addEventListener('pageshow', function (event) {
  if (!event.persisted) return;
  var busy = document.querySelectorAll('[aria-busy=true]');
  for (var i = 0; i < busy.length; i++) busy[i].removeAttribute('aria-busy');
});

// The System page keeps its figures current while it is on screen. Without this script
// the page still shows the sample it was rendered with.
(function () {
  var live = document.querySelector('[data-live]');
  if (!live || !window.fetch) return;
  var timer = null;

  function each(values, selector, apply) {
    Object.keys(values || {}).forEach(function (key) {
      var nodes = live.querySelectorAll('[data-' + selector + '="' + key + '"]');
      for (var i = 0; i < nodes.length; i++) apply(nodes[i], values[key]);
    });
  }

  function refresh(data) {
    each(data.text, 'text', function (node, value) { node.textContent = value; });
    each(data.meter, 'meter', function (node, value) { node.value = value; });
    each(data.level, 'level', function (node, value) { node.className = 'tile level-' + value; });
    each(data.spark, 'spark', function (node, value) {
      node.querySelector('.spark-area').setAttribute('points', '0,28 ' + value.line + ' 100,28');
      node.querySelector('.spark-line').setAttribute('points', value.line);
      node.querySelector('.spark-now').setAttribute('points', value.now);
    });
  }

  function poll() {
    fetch(live.getAttribute('data-live'), {credentials: 'same-origin'}).then(function (response) {
      if (!response.ok) throw new Error(response.status);
      return response.json();
    }).then(function (data) {
      // Rendered before the first sample landed, so take the whole page once.
      if (live.getAttribute('data-ready') === '0' && data.ready) return location.reload();
      live.classList.remove('is-stale');
      refresh(data);
    }).catch(function () {
      live.classList.add('is-stale');
    });
  }

  function start() {
    if (timer) return;
    poll();
    timer = setInterval(poll, Number(live.getAttribute('data-interval')) || 5000);
  }

  function stop() {
    clearInterval(timer);
    timer = null;
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { stop(); } else { start(); }
  });
  if (!document.hidden) start();
})();
"""

MACROS = """
{% macro notice(kind, message) -%}
<div class="notice notice-{{ kind }}" role="{{ 'alert' if kind == 'error' else 'status' }}">
  <svg class="icon" aria-hidden="true"><use href="#i-{{ kind }}"></use></svg>
  <p>{{ message }}</p>
</div>
{%- endmacro %}

{% macro when(moment) -%}
<time datetime="{{ moment.isoformat(timespec='seconds') }}">{{ moment|clock }}</time>
{%- endmacro %}

{# One live figure: a trend gets a sparkline, a share of a limit gets a meter. #}
{% macro tile(item) -%}
<div class="tile{% if item.level %} level-{{ item.level }}{% endif %}"
     {%- if item.level %} data-level="{{ item.key }}"{% endif %}>
  <p class="tile-label">{{ item.label }}</p>
  <p class="tile-value" data-text="{{ item.key }}">{{ item.value }}</p>
  {%- if item.spark %}
  <svg class="spark" viewBox="0 0 100 28" preserveAspectRatio="none" role="img"
       aria-label="{{ item.alt }}" data-spark="{{ item.key }}">
    <title>{{ item.alt }}</title>
    <polygon class="spark-area" points="0,28 {{ item.spark.line }} 100,28"></polygon>
    <polyline class="spark-line" points="{{ item.spark.line }}"></polyline>
    <polyline class="spark-now" points="{{ item.spark.now }}"></polyline>
  </svg>
  {%- else %}
  <progress class="meter" max="100" value="{{ item.meter }}" aria-label="{{ item.label }}"
            data-meter="{{ item.key }}"></progress>
  {%- endif %}
  <p class="tile-detail">
    <svg class="icon" aria-hidden="true"><use href="#i-warning"></use></svg>
    <span data-text="{{ item.key }}-detail">{{ item.detail }}</span>
  </p>
</div>
{%- endmacro %}

{# Label and value rows. A value too long to sit beside its label stacks under it. #}
{% macro rows(entries, prose=[]) -%}
<dl class="rows">
  {%- for label, key, value in entries %}
  <div{% if value|length > 26 %} class="stacked"{% endif %}>
    <dt>{{ label }}</dt>
    <dd{% if label not in prose %} class="mono num" translate="no"{% endif %}
        {%- if key %} data-text="{{ key }}"{% endif %}>{{ value }}</dd>
  </div>
  {%- endfor %}
</dl>
{%- endmacro %}
"""

LAYOUT = """{% from "macros.html" import notice -%}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0a0b0d">
<meta name="robots" content="noindex, nofollow">
<title>{% block title %}{% endblock %} · WOL Controller</title>
<link rel="icon" href="{{ favicon }}">
<style nonce="{{ csp_nonce }}">""" + STYLE + """</style>
</head>
<body>
<svg class="sprite" aria-hidden="true" focusable="false">
  {%- for name, path in icons.items() %}
  <symbol id="i-{{ name }}" viewBox="0 0 256 256"><path d="{{ path }}"></path></symbol>
  {%- endfor %}
</svg>
<a class="skip-link" href="#main">Skip to Content</a>
<div class="shell">
  <header class="topbar">
    <a class="brand" href="{{ url_for('home') }}">
      <span class="brand-mark"><svg class="icon" aria-hidden="true"><use href="#i-power"></use></svg></span>
      WOL Controller
    </a>
    {%- if authed %}
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <button class="btn btn-quiet" type="submit">
        <svg class="icon" aria-hidden="true"><use href="#i-sign-out"></use></svg>Log Out
      </button>
    </form>
    {%- elif request.endpoint != 'login' %}
    <a class="btn btn-quiet" href="{{ url_for('login') }}">Log In</a>
    {%- endif %}
  </header>
  {%- if authed %}
  <nav class="tabs" aria-label="Pages">
    {%- for endpoint, label in [('home', 'Wake'), ('system', 'System'), ('admin', 'Admin')] %}
    <a href="{{ url_for(endpoint) }}"
       {%- if request.endpoint == endpoint %} aria-current="page"{% endif %}>{{ label }}</a>
    {%- endfor %}
  </nav>
  {%- endif %}
  <main id="main" tabindex="-1">
    {%- if authed %}
      {%- for kind, message in setup_notices %}{{ notice(kind, message) }}{% endfor %}
    {%- endif %}
    {%- for kind, message in get_flashed_messages(with_categories=true) %}
      {{- notice(kind, message) }}
    {%- endfor %}
    {% block content %}{% endblock %}
  </main>
</div>
<script nonce="{{ csp_nonce }}">""" + SCRIPT + """</script>
</body>
</html>
"""

DASHBOARD = """
{% extends "layout.html" %}
{% from "macros.html" import when %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<section class="card" aria-labelledby="device-name">
  <div class="device">
    <span class="device-icon"><svg class="icon" aria-hidden="true"><use href="#i-monitor"></use></svg></span>
    <div>
      <h1 id="device-name">Your PC</h1>
      <p class="device-meta mono" translate="no">{{ mac }}{% if ip %} · {{ ip }}{% endif %}</p>
    </div>
  </div>
  <form method="post" action="{{ url_for('wake') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button class="btn btn-primary btn-xl" type="submit"{% if wake_problem %} disabled{% endif %}>
      <span class="btn-icon" aria-hidden="true">
        <svg class="icon" aria-hidden="true"><use href="#i-power"></use></svg>
        <span class="spinner"></span>
      </span>
      Wake Computer
    </button>
  </form>
  <dl class="stats">
    <div>
      <dt>Last wake</dt>
      <dd>{% if state.last_wake %}{{ when(state.last_wake) }}{% else %}Not yet{% endif %}</dd>
    </div>
    <div>
      <dt>Wakes since start</dt>
      <dd>{{ state.wake_count }}</dd>
    </div>
  </dl>
</section>
{% endblock %}
"""

LOGIN = """
{% extends "layout.html" %}
{% block title %}Log In{% endblock %}
{% block content %}
<section class="card" aria-labelledby="page-title">
  <div class="card-head">
    <h1 id="page-title">Log In</h1>
    <p class="muted">Enter your password to wake and manage your PC.</p>
  </div>
  <form class="form" method="post" action="{{ url_for('login') }}">
    <input type="text" name="username" value="WOL Controller" autocomplete="username" hidden>
    <div class="field">
      <label for="password">Password</label>
      <input class="input" id="password" name="password" type="password" required autofocus
             autocomplete="current-password"
             {%- if error %} aria-invalid="true" aria-describedby="password-error"{% endif %}>
      {%- if error %}
      <p class="field-error" id="password-error">{{ error }}</p>
      {%- endif %}
    </div>
    <button class="btn btn-primary btn-lg" type="submit">Log In</button>
  </form>
</section>
<p class="aside"><a class="link" href="{{ url_for('status') }}">View Public Status</a></p>
{% endblock %}
"""

STATUS = """
{% extends "layout.html" %}
{% from "macros.html" import when %}
{% block title %}Status{% endblock %}
{% block content %}
<section class="card" aria-labelledby="page-title">
  <div class="card-head">
    <h1 id="page-title">Status</h1>
    <p class="muted">Public page. Anyone who can reach this address can read it.</p>
  </div>
  <dl class="rows">
    <div>
      <dt>Internet</dt>
      <dd>
        {%- if state.internet is none %}
        <span class="dot" aria-hidden="true"></span>Checking…
        {%- elif state.internet %}
        <span class="dot dot-ok" aria-hidden="true"></span>Online
        <span class="muted">since {{ when(state.internet_since) }}</span>
        {%- else %}
        <span class="dot dot-warn" aria-hidden="true"></span>Offline
        <span class="muted">since {{ when(state.internet_since) }}</span>
        {%- endif %}
      </dd>
    </div>
    <div><dt>Uptime</dt><dd>{{ uptime|duration }}</dd></div>
    <div><dt>Version</dt><dd class="mono" translate="no">{{ version }}</dd></div>
    <div><dt>Wakes since start</dt><dd class="num">{{ state.wake_count }}</dd></div>
    <div>
      <dt>Last wake</dt>
      <dd>{% if state.last_wake %}{{ when(state.last_wake) }}{% else %}Not yet{% endif %}</dd>
    </div>
  </dl>
</section>
{% endblock %}
"""

ADMIN = """
{% extends "layout.html" %}
{% from "macros.html" import when %}
{% block title %}Admin{% endblock %}
{% block content %}
<section class="card" aria-labelledby="page-title">
  <div class="card-head">
    <h1 id="page-title">Admin</h1>
    <p class="muted">Everything here comes from config.json. Edit that file on the device, then
      restart the launcher to apply it.</p>
  </div>
  <dl class="rows">
    <div><dt>MAC address</dt><dd class="mono" translate="no">{{ mac }}</dd></div>
    <div>
      <dt>Target addresses</dt>
      <dd class="mono" translate="no">{% for ip in ips %}<span class="line">{{ ip }}</span>{% endfor %}</dd>
    </div>
    <div><dt>WOL ports</dt><dd class="mono num">{{ ports|join(', ') }}</dd></div>
    <div><dt>Server port</dt><dd class="mono num">{{ server_port }}</dd></div>
    <div class="stacked"><dt>Config file</dt><dd class="mono" translate="no">{{ config_path }}</dd></div>
  </dl>
  <p class="aside"><a class="link" href="{{ url_for('status') }}">View the public status page</a></p>
</section>
<section class="card" aria-labelledby="activity-title">
  <div class="card-head">
    <h2 id="activity-title">Activity</h2>
    <p class="muted">Since the last restart, newest first.</p>
  </div>
  {%- if events %}
  <table class="log">
    <thead class="sr-only">
      <tr><th scope="col">Time</th><th scope="col">Event</th></tr>
    </thead>
    <tbody>
      {%- for moment, message, warning in events %}
      <tr{% if warning %} class="is-warning"{% endif %}>
        <td class="mono">{{ when(moment) }}</td>
        <td>{{ message }}</td>
      </tr>
      {%- endfor %}
    </tbody>
  </table>
  {%- else %}
  <p class="empty">Nothing yet. Wakes, logins & connection changes show up here.</p>
  {%- endif %}
</section>
{% endblock %}
"""

SYSTEM = """
{% extends "layout.html" %}
{% from "macros.html" import tile, rows %}
{% block title %}System{% endblock %}
{% block content %}
<section class="card" aria-labelledby="page-title" data-live="{{ url_for('system_figures') }}"
         data-interval="{{ poll_interval }}" data-ready="{{ 1 if snapshot.ready else 0 }}">
  <div class="card-head">
    <h1 id="page-title">System</h1>
    {%- if snapshot.ready %}
    <p class="muted">Load on the device running this server, over the last five minutes.
      Updated <span data-text="updated">{{ snapshot.text.updated }}</span>.</p>
    {%- else %}
    <p class="muted">Collecting the first sample. The figures appear in a moment.</p>
    {%- endif %}
  </div>
  {%- if snapshot.tiles %}
  <div class="tiles">
    {%- for item in snapshot.tiles %}
    {{ tile(item) }}
    {%- endfor %}
  </div>
  {%- endif %}
  {%- for title, entries in groups %}
  <div class="group">
    <h2>{{ title }}</h2>
    {{ rows(entries, prose=['Operating system', 'Processor', 'Auto-update']) }}
  </div>
  {%- endfor %}
</section>
{% endblock %}
"""

NOT_FOUND = """
{% extends "layout.html" %}
{% block title %}Page Not Found{% endblock %}
{% block content %}
<section class="card" aria-labelledby="page-title">
  <div class="card-head">
    <p class="mono muted">Error 404</p>
    <h1 id="page-title">Page Not Found</h1>
    <p class="muted">Nothing lives at this address.</p>
  </div>
  <a class="btn btn-secondary btn-lg" href="{{ url_for('home') }}">Back to Your PC</a>
</section>
{% endblock %}
"""

app.jinja_loader = DictLoader({
    "macros.html": MACROS,
    "layout.html": LAYOUT,
    "dashboard.html": DASHBOARD,
    "login.html": LOGIN,
    "status.html": STATUS,
    "system.html": SYSTEM,
    "admin.html": ADMIN,
    "not_found.html": NOT_FOUND,
})


if __name__ == "__main__":
    logger.info("Starting WOL Controller %s on port %d", VERSION, SERVER_PORT)
    logger.info("Target: %s -> %s ports %s", MAC_TEXT, ", ".join(TARGET_IPS) or "none",
                ", ".join(str(port) for port in WOL_PORTS) or "none")
    if WAKE_PROBLEM:
        logger.error("%s", WAKE_PROBLEM)
    if PASSWORD == DEFAULT_CONFIG["password"]:
        logger.warning("Default password in use, change it in %s", CONFIG_PATH)

    threading.Thread(target=monitor_internet, daemon=True).start()
    threading.Thread(target=monitor_host, daemon=True).start()
    if os.environ.get("WOL_INSTANCE_TOKEN"):
        threading.Thread(target=watch_launcher, daemon=True).start()

    record("Server started, version %s" % VERSION)
    app.run(host="0.0.0.0", port=SERVER_PORT, debug=False)
