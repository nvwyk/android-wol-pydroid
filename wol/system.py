"""Load figures for the device running this server: the System page and the status page.

Every reader is best effort. Android hides parts of /proc and other systems have none of
it, so each one returns None instead of raising and the page leaves that figure out.
Nothing here is allowed to make a page fail to render.
"""
import collections
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

from . import BASE_DIR, formatting, runtime, settings
from .formatting import format_bytes, format_percent, format_rate

HISTORY_SIZE = 60                       # samples kept for the trend lines

lock = threading.Lock()
# Filled in by run_sampler(). Anything this device will not report stays None.
host = SimpleNamespace(
    sampled_at=None,
    cpu=None,
    cpu_history=collections.deque(maxlen=HISTORY_SIZE),
    server_cpu=None,                    # this process, percent of all cores
    server_cpu_history=collections.deque(maxlen=HISTORY_SIZE),
    clock=None,                         # (average Hz, percent of maximum, top Hz)
    clock_history=collections.deque(maxlen=HISTORY_SIZE),
    cores_online=None,
    temperatures=None,                  # [(sensor, celsius)], hottest first
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
    """(used, total) bytes on the filesystem the application lives on."""
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
    # CLOCK_BOOTTIME counts time asleep too and needs no /proc, which Android 8 hides.
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        pass
    text = read_file("/proc/uptime")
    if text:
        try:
            return float(text.split()[0])
        except (IndexError, ValueError):
            return None
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
        return ctypes.windll.kernel32.GetTickCount64() / 1000.0
    return None


def process_cpu_seconds():
    """CPU time this server has used, in seconds. Always readable, even on Android."""
    times = os.times()
    return times.user + times.system


def cpu_clock():
    """(average Hz, percent of maximum, top Hz) of the online cores from cpufreq. Where
    Android hides the processor load, the clock speed still shows how hard it works."""
    current = maximum = top = cores = 0
    for index in range(os.cpu_count() or 0):
        base = "/sys/devices/system/cpu/cpu%d/cpufreq/" % index
        now, most = to_int(read_file(base + "scaling_cur_freq")), to_int(read_file(base + "cpuinfo_max_freq"))
        if now and most:
            current, maximum, top, cores = current + now, maximum + most, max(top, most), cores + 1
    if not cores:
        return None
    return current * 1000.0 / cores, min(100.0, 100.0 * current / maximum), top * 1000.0


def cores_online():
    """How many cores are switched on right now; phones park idle ones. "0-3,6" is 5."""
    text = (read_file("/sys/devices/system/cpu/online") or "").strip()
    if not text:
        return None
    count = 0
    try:
        for part in text.split(","):
            first, _, last = part.partition("-")
            count += int(last or first) - int(first) + 1
    except ValueError:
        return None
    return count


def temperatures(limit=40):
    """[(sensor, celsius)] from the kernel's thermal zones, hottest first."""
    found = []
    for index in range(limit):
        base = "/sys/class/thermal/thermal_zone%d/" % index
        raw = to_int(read_file(base + "temp"))
        if raw is None:
            if not os.path.isdir(base):
                break
            continue
        celsius = raw / 1000.0 if abs(raw) >= 1000 else float(raw)     # millidegrees or degrees
        if 1 <= celsius <= 130:
            found.append(((read_file(base + "type") or "zone %d" % index).strip(), celsius))
    found.sort(key=lambda item: -item[1])
    return found or None


def default_route():
    """(interface, gateway address) of the default route, from the kernel's route table."""
    text = read_file("/proc/self/net/route") or read_file("/proc/net/route")
    for line in (text or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000" and fields[2] != "00000000":
            try:
                gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
            except (ValueError, struct.error):
                continue
            return fields[0], gateway
    return None


def process_threads():
    return threading.active_count()


def process_memory_bytes():
    return kb_fields(read_file("/proc/self/status")).get("VmRSS")


def processor_name():
    for line in (read_file("/proc/cpuinfo") or "").splitlines():
        label, _, value = line.partition(":")
        if label.strip() in ("Hardware", "model name", "Processor") and value.strip():
            return value.strip()
    return platform.processor() or None


def android_props():
    """getprop's answers, asked once: they cannot change while the server runs."""
    if "props" not in device_facts:
        device_facts["props"] = read_android_props()
    return device_facts["props"]


def android_name():
    """"Android 14 (Pixel 7)" on a phone, otherwise None."""
    props = android_props()
    release = props.get("ro.build.version.release")
    if not release:
        return None
    model = props.get("ro.product.model") or props.get("ro.product.device")
    return "Android %s (%s)" % (release, model) if model else "Android " + release


def android_details():
    """The phone facts worth showing: maker and model, API level, security patch, chip."""
    props = android_props()
    maker = (props.get("ro.product.manufacturer") or "").strip()
    model = (props.get("ro.product.model") or "").strip()
    return {
        "model": " ".join(part for part in (maker, model) if part) or None,
        "api": props.get("ro.build.version.sdk"),
        "patch": props.get("ro.build.version.security_patch"),
        "chip": props.get("ro.board.platform") or props.get("ro.hardware"),
    }


def read_android_props():
    try:
        output = subprocess.run(["getprop"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    props = {}
    for line in output.decode("utf-8", "replace").splitlines():
        if line.startswith("[") and "]: [" in line:
            key, _, value = line[1:].partition("]: [")
            props[key] = value.rstrip("]")
    return props


def kernel_name():
    return "%s %s (%s)" % (platform.system(), platform.release(), platform.machine() or "unknown")


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


def run_sampler():
    """Sample how busy the machine is, forever. CPU and network are counters, so they
    need two reads; the interval comes from Admin > Settings > Monitoring."""
    previous_cpu, previous_net = cpu_counters(), network_counters()
    previous_own = process_cpu_seconds()
    previous_at, gap = time.monotonic(), 1          # short first gap: the page wants numbers now
    cores = os.cpu_count() or 1
    while True:
        time.sleep(gap)
        gap = settings.get("metrics_interval")
        current_at = time.monotonic()
        elapsed = current_at - previous_at
        current_cpu, current_net, current_own = cpu_counters(), network_counters(), process_cpu_seconds()
        percent = cpu_percent(previous_cpu, current_cpu)
        own = max(0.0, min(100.0, 100.0 * (current_own - previous_own) / (elapsed * cores)))             if elapsed > 0 else None
        rates = byte_rates(previous_net, current_net, elapsed)
        memory, storage, battery = memory_bytes(), storage_bytes(), battery_state()
        load, uptime, rss = load_average(), device_uptime(), process_memory_bytes()
        clock, online, heat = cpu_clock(), cores_online(), temperatures()
        with lock:
            host.cpu = percent
            if percent is not None:
                host.cpu_history.append(percent)
            host.server_cpu = own
            if own is not None:
                host.server_cpu_history.append(own)
            host.clock = clock
            if clock:
                host.clock_history.append(clock[1])
            host.cores_online, host.temperatures = online, heat
            host.memory = memory
            if memory and memory[1]:
                host.memory_history.append(100.0 * memory[0] / memory[1])
            host.storage, host.battery = storage, battery
            host.network, host.rates = current_net, rates
            host.load, host.device_uptime, host.process_memory = load, uptime, rss
            host.sampled_at = runtime.now_local()
        previous_at, previous_own = current_at, current_own
        previous_cpu = current_cpu or previous_cpu
        previous_net = current_net or previous_net


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


def cpu_time_text(seconds):
    return "%.1f s" % seconds if seconds < 60 else formatting.duration(seconds)


def format_hz(hz):
    return "%.2f GHz" % (hz / 1e9) if hz >= 1e9 else "%d MHz" % round(hz / 1e6)


def snapshot():
    """Every live figure on the System page, formatted once for the page and for the poll."""
    with lock:
        cpu, cpu_history = host.cpu, list(host.cpu_history)
        own, own_history = host.server_cpu, list(host.server_cpu_history)
        clock, clock_history = host.clock, list(host.clock_history)
        online, heat = host.cores_online, host.temperatures
        memory, memory_history = host.memory, list(host.memory_history)
        storage, battery = host.storage, host.battery
        network, rates, load = host.network, host.rates, host.load
        booted, rss, sampled_at = host.device_uptime, host.process_memory, host.sampled_at

    minutes = HISTORY_SIZE * settings.get("metrics_interval") // 60
    span = "the last %s" % formatting.plural(minutes, "minute") if minutes > 1 else "the last minute"
    tiles = []
    if cpu is not None:
        peak = format_percent(max(cpu_history or [cpu]))
        tiles.append(trend_tile("cpu", "CPU load", format_percent(cpu), "peak " + peak,
                                cpu_history, "CPU load over %s. Now %s, peak %s."
                                % (span, format_percent(cpu), peak)))
    elif clock:
        # Android 8 and later hide the processor load; its clock speed is the next best sign.
        tiles.append(trend_tile("clock", "CPU clock", format_hz(clock[0]),
                                "%s of top speed" % format_percent(clock[1]), clock_history,
                                "Average CPU clock speed over %s, as a share of its top "
                                "speed. Now %s." % (span, format_percent(clock[1]))))
    if own is not None:
        peak = format_percent(max(own_history or [own]))
        tiles.append(trend_tile("server-cpu", "Server CPU", format_percent(own),
                                "of all cores, peak " + peak, own_history,
                                "CPU used by this server over %s. Now %s, peak %s."
                                % (span, format_percent(own), peak)))
    if memory:
        used, total = memory
        share = 100.0 * used / total
        tiles.append(trend_tile("memory", "Memory", format_bytes(used),
                                "%s of %s" % (format_percent(share), format_bytes(total)),
                                memory_history,
                                "Memory in use over %s. Now %s of %s."
                                % (span, format_bytes(used), format_bytes(total))))
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
        "device-uptime": formatting.duration(booted) if booted is not None else None,
        "battery-temp": "%.1f °C" % battery[2] if battery and battery[2] is not None else None,
        "cores-online": ("%d of %d" % (online, os.cpu_count())) if online and os.cpu_count() else None,
        "clock-range": ("%s now, top %s" % (format_hz(clock[0]), format_hz(clock[2]))) if clock else None,
        "temperature": ("%.0f °C (%s)" % (heat[0][1], heat[0][0])) if heat else None,
        "server-cpu-time": cpu_time_text(process_cpu_seconds()),
        "threads": str(process_threads()),
        "received": total_and_rate(network[0] if network else None, rates[0] if rates else None),
        "sent": total_and_rate(network[1] if network else None, rates[1] if rates else None),
        "server-uptime": formatting.duration(runtime.uptime()),
        "process-memory": format_bytes(rss),
        "updated": formatting.clock(sampled_at) if sampled_at else None,
    })
    return {
        "tiles": tiles,
        "text": dict((key, value) for key, value in text.items() if value is not None),
        "meter": {tile["key"]: tile["meter"] for tile in tiles if "meter" in tile},
        "level": {tile["key"]: tile["level"] for tile in tiles if "level" in tile},
        "spark": {tile["key"]: tile["spark"] for tile in tiles if "spark" in tile},
        "ready": sampled_at is not None,
    }


def public_figures():
    """The coarse device figures the public status page may show: no names, no addresses."""
    with lock:
        cpu, memory, battery, booted = host.cpu, host.memory, host.battery, host.device_uptime
    figures = []
    if cpu is not None:
        figures.append(("CPU load", format_percent(cpu)))
    if memory and memory[1]:
        figures.append(("Memory in use", format_percent(100.0 * memory[0] / memory[1])))
    if battery:
        figures.append(("Battery", "%s, %s" % (format_percent(battery[0]),
                                               (battery[1] or "unknown").lower())))
    if booted is not None:
        figures.append(("Device uptime", formatting.duration(booted)))
    return figures
