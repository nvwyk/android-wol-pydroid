"""Supervisor for server.py: keeps it running and updates it from GitHub.

Run this file in Pydroid 3 instead of server.py. `python launcher.py --selftest`
checks whether this device supports everything the launcher relies on.
"""
import ast
import base64
import hashlib
import json
import os
import secrets
import signal
import ssl
import subprocess
import sys
import time
import urllib.request

REPO = "nvwyk/android-wol-pydroid"
BRANCH = "main"
CHECK_INTERVAL = 300    # 12 unauthenticated API calls/hour; GitHub allows 60
FIRST_CHECK_DELAY = 30
HTTP_TIMEOUT = 15
HEALTH_TIMEOUT = 90     # Flask import is slow on old phones
MAX_RESPONSE = 1024 * 1024
BACKOFF_MIN, BACKOFF_MAX = 5, 300
STABLE_AFTER = 600
TICK = 5

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(BASE_DIR, "server.py")
BACKUP = SERVER + ".bak"
CONFIG = os.path.join(BASE_DIR, "config.json")
STATE = os.path.join(BASE_DIR, "state.json")

LEGACY_SETTINGS = {"PASSWORD": "password", "TARGET_MAC": "target_mac",
                   "TARGET_IPS": "target_ips", "WOL_PORTS": "wol_ports",
                   "SERVER_PORT": "server_port"}


def log(tag, msg):
    print("%s [%s] %s" % (time.strftime("%H:%M:%S"), tag, msg), flush=True)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def blob_sha(data):
    """Same hash git and the GitHub API use for file contents."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def load_state():
    try:
        return json.loads(read(STATE))
    except (OSError, ValueError):
        return {}


def save_state(state):
    write_atomic(STATE, json.dumps(state).encode())


def server_port():
    try:
        return int(json.loads(read(CONFIG)).get("server_port", 5000))
    except (OSError, ValueError):
        return 5000


def migrate_config():
    """Copy settings hardcoded in an old server.py into config.json before it gets replaced."""
    if os.path.exists(CONFIG) or not os.path.exists(SERVER):
        return
    try:
        tree = ast.parse(read(SERVER))
    except SyntaxError:
        return
    found = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in LEGACY_SETTINGS):
            try:
                found[LEGACY_SETTINGS[node.targets[0].id]] = ast.literal_eval(node.value)
            except ValueError:
                pass
    if found:
        write_atomic(CONFIG, json.dumps(found, indent=2).encode())
        log("CONFIG", "Migrated %s from server.py into config.json" % ", ".join(sorted(found)))


# --- GitHub -----------------------------------------------------------------

def ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def github(path, accept):
    req = urllib.request.Request(
        "https://api.github.com/repos/%s/%s" % (REPO, path),
        headers={"Accept": accept, "User-Agent": "android-wol-pydroid-launcher"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ssl_context()) as r:
        body = r.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise ValueError("response too large")
    return body


def fetch_update(state):
    """Return (commit, blob sha, content) when server.py changed on GitHub, else None."""
    log("UPDATER", "Checking GitHub...")
    # Only the 40-char SHA comes back, so an idle poll costs almost nothing.
    commit = github("commits/" + BRANCH, "application/vnd.github.sha").decode().strip()
    if commit == state.get("last_commit"):
        log("UPDATER", "No update available (%s)." % commit[:7])
        return None

    # Pinned to the commit SHA: branch-name URLs on raw.githubusercontent.com are CDN-cached.
    meta = json.loads(github("contents/server.py?ref=" + commit, "application/vnd.github+json"))
    remote = meta["sha"]
    local = blob_sha(read(SERVER)) if os.path.exists(SERVER) else None
    if remote == local or remote == state.get("bad_blob"):
        log("UPDATER", "Commit %s: %s." % (commit[:7], "server.py unchanged" if remote == local
                                            else "server.py is the version that failed before, skipped"))
        state["last_commit"] = commit
        save_state(state)
        return None

    log("UPDATER", "New version detected: %s -> %s. Downloading..." % (
        (local or "none")[:7], remote[:7]))
    if meta.get("encoding") != "base64":
        raise ValueError("unexpected encoding %r" % meta.get("encoding"))
    data = base64.b64decode(meta["content"])
    if blob_sha(data) != remote:
        raise ValueError("download does not match GitHub hash")
    return commit, remote, data


# --- Process management -----------------------------------------------------

def start_server():
    token = secrets.token_hex(8)
    env = dict(os.environ, WOL_INSTANCE_TOKEN=token)
    log("WATCHDOG", "Starting server.py")
    proc = subprocess.Popen([sys.executable, SERVER], cwd=BASE_DIR, env=env)
    proc.token = token
    proc.started_at = time.time()
    return proc


def stop_server(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def wait_healthy(proc):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = "http://127.0.0.1:%d/health" % server_port()
    deadline = time.time() + HEALTH_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with opener.open(url, timeout=5) as r:
                if json.loads(r.read()).get("token") == proc.token:
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(2)
    return False


def confirm_or_rollback(proc, state):
    if wait_healthy(proc):
        log("UPDATER", "Health check passed. Update successful.")
        state.pop("pending", None)
        save_state(state)
        return proc

    log("UPDATER", "New version failed health check. Rolling back.")
    state["bad_blob"] = state.pop("pending")
    save_state(state)
    stop_server(proc)
    if not os.path.exists(BACKUP):
        log("UPDATER", "No backup available; watchdog will keep retrying.")
        return start_server()
    write_atomic(SERVER, read(BACKUP))
    proc = start_server()
    if wait_healthy(proc):
        log("UPDATER", "Previous version restored.")
    else:
        log("UPDATER", "Restored version is not healthy either; watchdog will keep retrying.")
    return proc


def apply_update(proc, state, commit, sha, data):
    try:
        compile(data, "server.py", "exec")
    except (SyntaxError, ValueError) as e:
        log("UPDATER", "Validation failed (%s). Keeping current version." % e)
        state.update(last_commit=commit, bad_blob=sha)
        save_state(state)
        return proc
    log("UPDATER", "Validation passed.")

    if os.path.exists(SERVER):
        write_atomic(BACKUP, read(SERVER))
        log("UPDATER", "Backup created.")
    state.update(last_commit=commit, pending=sha)
    save_state(state)

    log("UPDATER", "Activating update. Restarting server.")
    stop_server(proc)
    write_atomic(SERVER, data)
    return confirm_or_rollback(start_server(), state)


# --- Main loop --------------------------------------------------------------

def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    migrate_config()
    state = load_state()

    proc = start_server()
    if state.get("pending"):
        if os.path.exists(SERVER) and blob_sha(read(SERVER)) == state["pending"]:
            log("UPDATER", "Verifying update interrupted by a previous shutdown.")
            proc = confirm_or_rollback(proc, state)
        else:
            state.pop("pending")
            save_state(state)

    next_check = time.time() + FIRST_CHECK_DELAY
    backoff = BACKOFF_MIN
    restart_at = None
    try:
        while True:
            time.sleep(TICK)
            now = time.time()

            if proc.poll() is not None:
                if restart_at is None:
                    log("WATCHDOG", "server.py exited with code %s, restarting in %ds"
                        % (proc.returncode, backoff))
                    restart_at = now + backoff
                    backoff = min(backoff * 2, BACKOFF_MAX)
                elif now >= restart_at:
                    proc = start_server()
                    restart_at = None
            elif now - proc.started_at > STABLE_AFTER:
                backoff = BACKOFF_MIN

            if now >= next_check:
                try:
                    update = fetch_update(state)
                    if update:
                        proc = apply_update(proc, state, *update)
                        restart_at = None
                except Exception as e:
                    log("UPDATER", "Update check failed: %s" % e)
                next_check = time.time() + CHECK_INTERVAL
    except KeyboardInterrupt:
        pass
    finally:
        log("WATCHDOG", "Launcher stopping, stopping server.py")
        stop_server(proc)


def selftest():
    ok = True

    def check(name, fn):
        nonlocal ok
        try:
            log("SELFTEST", "PASS %s: %s" % (name, fn()))
        except Exception as e:
            ok = False
            log("SELFTEST", "FAIL %s: %s" % (name, e))

    log("SELFTEST", "Python %s at %s" % (sys.version.split()[0], sys.executable))
    log("SELFTEST", "Script dir %s, cwd %s" % (BASE_DIR, os.getcwd()))

    def child():
        p = subprocess.Popen([sys.executable, "-c", "import os, flask; print(os.getpid())"],
                             stdout=subprocess.PIPE)
        out = p.communicate(timeout=120)[0]
        if p.returncode != 0:
            raise RuntimeError("child exited with %s (is flask installed?)" % p.returncode)
        return "child pid %s, Popen pid %s, flask importable" % (out.decode().strip(), p.pid)

    check("subprocess", child)
    check("github", lambda: "main is at " + github("commits/" + BRANCH,
                                                   "application/vnd.github.sha").decode()[:7])
    def write():
        write_atomic(STATE + ".selftest", b"x")
        os.remove(STATE + ".selftest")
        return "atomic replace works in " + BASE_DIR

    check("write", write)
    log("SELFTEST", "All checks passed." if ok else "Some checks failed.")


if __name__ == "__main__":
    selftest() if "--selftest" in sys.argv else main()
