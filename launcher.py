"""Supervisor for server.py: keeps it running and updates the application from GitHub.

Run this file in Pydroid 3 instead of server.py. `python launcher.py --selftest` checks
whether this device supports everything the launcher relies on.

The application is server.py plus the wol/ folder. An update replaces them together as
one release: it is downloaded to .update/, checked by running `server.py --check` there,
and only then installed. The previous release stays in .backup/ and comes back if the
new one does not answer /health. wol.db (settings, PCs, history, the password hash) is
never replaced by an update. It is copied to wol.db.pre-update first, and that copy is
put back only if a failed release had already changed the database's schema.

launcher.py never updates itself. When GitHub has a newer one, the admin overview says so.
"""
import ast
import hashlib
import json
import os
import secrets
import shutil
import signal
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

LAUNCHER_API = "2"      # tells server.py this launcher installs whole releases
REPO = "nvwyk/android-wol-pydroid"
BRANCH = "main"
CHECK_INTERVAL = 300    # 12 unauthenticated API calls/hour at most; GitHub allows 60
FIRST_CHECK_DELAY = 30
HTTP_TIMEOUT = 15
HEALTH_TIMEOUT = 120    # Flask import is slow on old phones, and the first start migrates
CHECK_TIMEOUT = 180     # `server.py --check` imports Flask too
MAX_RESPONSE = 2 * 1024 * 1024
MAX_FILES = 300
BACKOFF_MIN, BACKOFF_MAX = 5, 300
STABLE_AFTER = 600
TICK = 5
RESTART_EXIT_CODE = 3   # server.py asks for a restart, e.g. after a port change
SERVER_OUTPUT = None    # None: server.py prints to this console, as the launcher does

LEGACY_SETTINGS = {"PASSWORD": "password", "TARGET_MAC": "target_mac",
                   "TARGET_IPS": "target_ips", "WOL_PORTS": "wol_ports",
                   "SERVER_PORT": "server_port"}


def configure(base_dir):
    """Point every path at `base_dir`. Tests call this with a scratch folder."""
    global BASE_DIR, SERVER, STATE, CONFIG, DATABASE, SNAPSHOT, BACKUP_DIR, STAGE_DIR
    BASE_DIR = base_dir
    SERVER = os.path.join(base_dir, "server.py")
    STATE = os.path.join(base_dir, "state.json")
    CONFIG = os.path.join(base_dir, "config.json")
    DATABASE = os.path.join(base_dir, "wol.db")
    SNAPSHOT = DATABASE + ".pre-update"
    BACKUP_DIR = os.path.join(base_dir, ".backup")
    STAGE_DIR = os.path.join(base_dir, ".update")


configure(os.path.dirname(os.path.abspath(__file__)))


def log(tag, msg):
    print("%s [%s] %s" % (time.strftime("%H:%M:%S"), tag, msg), flush=True)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def write_atomic(path, data):
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def blob_sha(data):
    """Same hash git and the GitHub API use for file contents."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_state():
    try:
        state = json.loads(read(STATE))
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state):
    write_atomic(STATE, json.dumps(state, indent=1).encode())


# --- The application's files ---------------------------------------------------

def is_managed(path):
    """True for the files a release consists of. Same rule as wol.is_managed()."""
    if path == "server.py":
        return True
    return (path.startswith("wol/") and "/__pycache__/" not in path
            and not path.endswith((".pyc", ".pyo")))


def files_in(root):
    """{relative path: blob sha} of the release files under `root`."""
    found = {}
    if os.path.isfile(os.path.join(root, "server.py")):
        found["server.py"] = blob_sha(read(os.path.join(root, "server.py")))
    for folder, dirs, names in os.walk(os.path.join(root, "wol")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in names:
            full = os.path.join(folder, name)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            if is_managed(relative) and not name.endswith(".tmp"):
                found[relative] = blob_sha(read(full))
    return found


def release_id(files):
    """Identifies a set of release files; wol.release_id() computes the same on disk."""
    digest = hashlib.sha1()
    for path in sorted(files):
        digest.update(("%s\0%s\n" % (path, files[path])).encode())
    return digest.hexdigest()


def remove_empty_dirs(root):
    for folder, _, _ in sorted(os.walk(os.path.join(root, "wol")), key=lambda item: -len(item[0])):
        if folder != os.path.join(root, "wol") and not os.listdir(folder):
            os.rmdir(folder)


def install_files(source, files):
    """Make the release in BASE_DIR exactly `files`, copied from the same paths under
    `source`. Files of the old release that the new one lacks are removed."""
    for path in files_in(BASE_DIR):
        if path not in files:
            os.remove(os.path.join(BASE_DIR, *path.split("/")))
    for path in sorted(files):
        write_atomic(os.path.join(BASE_DIR, *path.split("/")),
                     read(os.path.join(source, *path.split("/"))))
    remove_empty_dirs(BASE_DIR)


# --- What the server stores that the launcher needs --------------------------------

_last_port = [None]


def _setting(key):
    """A value from wol.db's settings table, or None. Opened read-only; the launcher
    never writes the database except to undo a failed update."""
    if not os.path.exists(DATABASE):
        return None
    uri = "file:%s?mode=ro" % urllib.request.pathname2url(os.path.abspath(DATABASE))
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def server_port():
    """Where /health answers: wol.db, else config.json (a release before the database),
    else the last port seen, else 5000."""
    try:
        value = _setting("server_port")
        if value is not None:
            _last_port[0] = int(value)
            return _last_port[0]
        if os.path.exists(DATABASE):
            _last_port[0] = 5000        # the database exists and uses the default
            return 5000
    except (sqlite3.Error, ValueError):
        if _last_port[0]:
            return _last_port[0]
    try:
        return int(json.loads(read(CONFIG)).get("server_port", 5000))
    except (OSError, ValueError, TypeError, AttributeError):
        return _last_port[0] or 5000


def updates_enabled():
    """Admin > Settings can pause automatic updates."""
    try:
        return _setting("updates_enabled") not in ("0",)
    except sqlite3.Error:
        return True


def schema_version(path):
    if not os.path.exists(path):
        return None
    try:
        conn = sqlite3.connect(path, timeout=10)
        try:
            return conn.execute("PRAGMA user_version").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return None


def copy_database(source, target):
    """A consistent copy through SQLite's backup API, never a raw file copy, so a
    half-written transaction can never be copied along."""
    src = sqlite3.connect(source, timeout=10)
    try:
        dst = sqlite3.connect(target, timeout=10)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def migrate_config():
    """Copy settings hardcoded in an old server.py into config.json before it gets replaced.
    The server imports config.json into wol.db on its first start."""
    if os.path.exists(CONFIG) or os.path.exists(DATABASE) or not os.path.exists(SERVER):
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


# --- GitHub ----------------------------------------------------------------------------

def ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def http_get(url, accept=None):
    headers = {"User-Agent": "android-wol-pydroid-launcher"}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ssl_context()) as r:
        body = r.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise ValueError("response too large")
    return body


def github(path, accept):
    return http_get("https://api.github.com/repos/%s/%s" % (REPO, path), accept)


def latest_commit():
    # Only the 40-char SHA comes back, so an idle poll costs almost nothing.
    commit = github("commits/" + BRANCH, "application/vnd.github.sha").decode().strip()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("unexpected commit id %r" % commit[:50])
    return commit


def fetch_tree(commit):
    """{path: blob sha} of every file in the repository at `commit`."""
    meta = json.loads(github("git/trees/%s?recursive=1" % commit, "application/vnd.github+json"))
    if meta.get("truncated"):
        raise ValueError("repository listing was truncated")
    return dict((item["path"], item["sha"]) for item in meta.get("tree", [])
                if item.get("type") == "blob")


def download(commit, path, sha):
    """One file, pinned to the commit (branch URLs on raw.githubusercontent.com are
    CDN-cached) and verified against the hash GitHub listed for it."""
    url = "https://raw.githubusercontent.com/%s/%s/%s" % (REPO, commit, urllib.parse.quote(path))
    data = http_get(url)
    if blob_sha(data) != sha:
        raise ValueError("%s does not match its GitHub hash" % path)
    return data


def safe_path(path):
    """Paths from GitHub must stay inside the release: no absolute paths, no '..'."""
    parts = path.split("/")
    return bool(path) and not path.startswith("/") and "\\" not in path and \
        all(part not in ("", ".", "..") for part in parts) and ":" not in parts[0]


def fetch_update(state):
    """Return (commit, {path: sha}) when GitHub has a different release, else None."""
    log("UPDATER", "Checking GitHub...")
    commit = latest_commit()
    if commit == state.get("last_commit"):
        log("UPDATER", "No update available (%s)." % commit[:7])
        state["last_check_result"] = "No update available"
        return None
    tree = fetch_tree(commit)
    wanted = dict((path, sha) for path, sha in tree.items() if is_managed(path))
    own = os.path.abspath(__file__)
    state["launcher_update_available"] = bool(
        tree.get("launcher.py") and os.path.exists(own) and tree["launcher.py"] != blob_sha(read(own)))
    if "server.py" not in wanted or not all(safe_path(p) for p in wanted) or len(wanted) > MAX_FILES:
        log("UPDATER", "Commit %s has no usable application; ignored." % commit[:7])
        state.update(last_commit=commit, last_check_result="Latest commit has no usable application")
        return None
    current = files_in(BASE_DIR)
    if wanted == current:
        log("UPDATER", "Commit %s: application unchanged." % commit[:7])
        state.update(last_commit=commit, app_commit=commit, last_check_result="No update available")
        return None
    if release_id(wanted) == state.get("bad_release"):
        log("UPDATER", "Commit %s: this release failed before, skipped." % commit[:7])
        state.update(last_commit=commit, last_check_result="Skipped a release that failed before")
        return None
    changed = [path for path in wanted if current.get(path) != wanted[path]]
    removed = [path for path in current if path not in wanted]
    log("UPDATER", "New version detected: %s. %d files to download, %d to remove." % (
        commit[:7], len(changed), len(removed)))
    return commit, wanted


# --- Staging and validation ------------------------------------------------------------

def stage(commit, wanted):
    """Build the complete new release in .update/: unchanged files are copied from the
    running release, changed ones downloaded and verified."""
    shutil.rmtree(STAGE_DIR, ignore_errors=True)
    current = files_in(BASE_DIR)
    downloaded = 0
    for path, sha in sorted(wanted.items()):
        if current.get(path) == sha:
            data = read(os.path.join(BASE_DIR, *path.split("/")))
        else:
            data = download(commit, path, sha)
            downloaded += 1
        write_atomic(os.path.join(STAGE_DIR, *path.split("/")), data)
    if files_in(STAGE_DIR) != wanted:
        raise ValueError("staged files do not match the release")
    log("UPDATER", "Downloaded and verified %d files; release of %d files staged."
        % (downloaded, len(wanted)))


def validate_stage():
    """Compile every Python file, then let the release check itself: `server.py --check`
    imports the whole application and compiles every template. Returns an error or None."""
    for path in files_in(STAGE_DIR):
        if path.endswith(".py"):
            try:
                compile(read(os.path.join(STAGE_DIR, *path.split("/"))), path, "exec")
            except (SyntaxError, ValueError) as e:
                return "%s: %s" % (path, e)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env.pop("WOL_INSTANCE_TOKEN", None)
    try:
        result = subprocess.run([sys.executable, os.path.join(STAGE_DIR, "server.py"), "--check"],
                                cwd=STAGE_DIR, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=CHECK_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        return "self-check could not run (%s)" % e
    if result.returncode != 0:
        lines = result.stdout.decode("utf-8", "replace").strip().splitlines()
        return "self-check failed: %s" % (lines[-1] if lines else "exit code %d" % result.returncode)
    return None


def make_backup():
    """Keep the running release in .backup/ so a failed update can bring it back."""
    current = files_in(BASE_DIR)
    if "server.py" not in current:
        return False
    temporary = BACKUP_DIR + ".tmp"
    shutil.rmtree(temporary, ignore_errors=True)
    for path in current:
        write_atomic(os.path.join(temporary, *path.split("/")),
                     read(os.path.join(BASE_DIR, *path.split("/"))))
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    os.replace(temporary, BACKUP_DIR)
    return True


def restore_backup():
    backup = files_in(BACKUP_DIR)
    if "server.py" not in backup:
        log("UPDATER", "No backup available.")
        return False
    install_files(BACKUP_DIR, backup)
    return True


def restore_database(pending):
    """Undo a failed release's database changes, but only if it changed the schema:
    otherwise everything written meanwhile (events, wake history) is kept."""
    before = pending.get("db_version")
    if before is None or not os.path.exists(SNAPSHOT):
        return
    after = schema_version(DATABASE)
    if after == before:
        return
    log("UPDATER", "The failed release changed the database schema (%s to %s). Restoring "
                   "the copy taken before the update." % (before, after))
    try:
        copy_database(SNAPSHOT, DATABASE)
    except sqlite3.Error as e:
        log("UPDATER", "Could not restore the database (%s). The copy is in %s."
            % (e, os.path.basename(SNAPSHOT)))


# --- Process management --------------------------------------------------------------

def start_server():
    token = secrets.token_hex(8)
    env = dict(os.environ, WOL_INSTANCE_TOKEN=token, WOL_LAUNCHER_API=LAUNCHER_API)
    log("WATCHDOG", "Starting server.py")
    proc = subprocess.Popen([sys.executable, SERVER], cwd=BASE_DIR, env=env,
                            stdout=SERVER_OUTPUT, stderr=SERVER_OUTPUT)
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


def wait_healthy(proc, timeout=None):
    """True once /health answers from this exact process with ok: true."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.time() + (timeout or HEALTH_TIMEOUT)
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            # The port is read each time: the new release may have just moved it into wol.db.
            with opener.open("http://127.0.0.1:%d/health" % server_port(), timeout=5) as r:
                body = json.loads(r.read())
                if body.get("token") == proc.token and body.get("ok", True) is True:
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(2)
    return False


def confirm_or_rollback(proc, state):
    pending = state.get("pending") or {}
    if wait_healthy(proc):
        log("UPDATER", "Health check passed. Update successful.")
        state.pop("pending", None)
        state.update(app_commit=pending.get("commit"), app_release=pending.get("release"),
                     last_update_at=now_iso(),
                     last_check_result="Updated to %s" % (pending.get("commit") or "?")[:7])
        save_state(state)
        shutil.rmtree(STAGE_DIR, ignore_errors=True)
        return proc

    log("UPDATER", "New version failed health check. Rolling back.")
    state.pop("pending", None)
    state["bad_release"] = pending.get("release")
    state["last_check_result"] = "Update to %s failed its health check and was rolled back" % (
        pending.get("commit") or "?")[:7]
    save_state(state)
    stop_server(proc)
    if not restore_backup():
        log("UPDATER", "Watchdog will keep retrying.")
        return start_server()
    restore_database(pending)
    proc = start_server()
    if wait_healthy(proc):
        log("UPDATER", "Previous version restored.")
    else:
        log("UPDATER", "Restored version is not healthy either; watchdog will keep retrying.")
    return proc


def apply_update(proc, state, commit, wanted):
    release = release_id(wanted)
    try:
        stage(commit, wanted)
    except Exception as e:
        # Network trouble or a hash mismatch: nothing was touched, try again next time.
        log("UPDATER", "Download failed (%s). Keeping current version." % e)
        state["last_check_result"] = "Download failed; will retry"
        shutil.rmtree(STAGE_DIR, ignore_errors=True)
        return proc
    problem = validate_stage()
    if problem:
        log("UPDATER", "Validation failed (%s). Keeping current version." % problem)
        state.update(last_commit=commit, bad_release=release,
                     last_check_result="Update to %s failed validation" % commit[:7])
        save_state(state)
        shutil.rmtree(STAGE_DIR, ignore_errors=True)
        return proc
    log("UPDATER", "Validation passed.")

    if make_backup():
        log("UPDATER", "Backup created.")
    log("UPDATER", "Activating update. Restarting server.")
    stop_server(proc)
    db_version = schema_version(DATABASE)
    if db_version is not None:
        try:
            copy_database(DATABASE, SNAPSHOT)
        except sqlite3.Error as e:
            log("UPDATER", "Could not copy the database before updating (%s). Update postponed." % e)
            state["last_check_result"] = "Update postponed: the database could not be copied"
            return start_server()
    # The journal entry comes before the first file changes, so an interruption at any
    # point after this is noticed and repaired at the next start.
    state.update(last_commit=commit, pending={"commit": commit, "release": release,
                                              "files": wanted, "db_version": db_version})
    save_state(state)
    install_files(STAGE_DIR, wanted)
    return confirm_or_rollback(start_server(), state)


def recover_interrupted(state):
    """Called before the first start. Returns True when a completed install still needs
    its health check; a half-finished install is undone right here."""
    pending = state.get("pending")
    if not pending:
        return False
    if not isinstance(pending, dict):
        # Left by the launcher that only updated server.py; its backup file is not ours.
        state.pop("pending")
        save_state(state)
        return False
    if files_in(BASE_DIR) == pending.get("files"):
        log("UPDATER", "Verifying update interrupted by a previous shutdown.")
        return True
    log("UPDATER", "An update was interrupted halfway. Restoring the previous version.")
    if restore_backup():
        restore_database(pending)
    state.pop("pending")
    save_state(state)
    return False


# --- Main loop -----------------------------------------------------------------------

def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    migrate_config()
    state = load_state()
    verify = recover_interrupted(state)

    proc = start_server()
    if verify:
        proc = confirm_or_rollback(proc, state)

    next_check = time.time() + FIRST_CHECK_DELAY
    backoff = BACKOFF_MIN
    restart_at = None
    paused = False
    try:
        while True:
            time.sleep(TICK)
            now = time.time()

            if proc.poll() is not None:
                if proc.returncode == RESTART_EXIT_CODE and now - proc.started_at > 30 \
                        and restart_at is None:
                    log("WATCHDOG", "server.py asked for a restart")
                    proc = start_server()
                    continue
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
                if not updates_enabled():
                    if not paused:
                        log("UPDATER", "Automatic updates are paused in Admin > Settings.")
                    paused = True
                    state["last_check_result"] = "Automatic updates are paused"
                else:
                    paused = False
                    state["last_check_at"] = now_iso()
                    try:
                        update = fetch_update(state)
                        if update:
                            proc = apply_update(proc, state, *update)
                            restart_at = None
                    except Exception as e:
                        log("UPDATER", "Update check failed: %s" % e)
                        state["last_check_result"] = "Check failed: %s" % e
                try:
                    save_state(state)
                except OSError as e:
                    log("UPDATER", "Could not save state.json: %s" % e)
                next_check = time.time() + CHECK_INTERVAL
    except KeyboardInterrupt:
        pass
    finally:
        log("WATCHDOG", "Launcher stopping, stopping server.py")
        stop_server(proc)


def selftest():
    ok = True

    def check(name, fn, required=True):
        nonlocal ok
        try:
            log("SELFTEST", "PASS %s: %s" % (name, fn()))
        except Exception as e:
            if required:
                ok = False
            log("SELFTEST", "%s %s: %s" % ("FAIL" if required else "INFO", name, e))

    log("SELFTEST", "Python %s at %s" % (sys.version.split()[0], sys.executable))
    log("SELFTEST", "Script dir %s, cwd %s" % (BASE_DIR, os.getcwd()))

    def child():
        p = subprocess.Popen([sys.executable, "-c", "import os, flask; print(os.getpid())"],
                             stdout=subprocess.PIPE)
        out = p.communicate(timeout=120)[0]
        if p.returncode != 0:
            raise RuntimeError("child exited with %s (is flask installed?)" % p.returncode)
        return "child pid %s, Popen pid %s, flask importable" % (out.decode().strip(), p.pid)

    def github_check():
        commit = latest_commit()
        tree = fetch_tree(commit)
        data = download(commit, "README.md", tree["README.md"])
        return "main is at %s, %d files listed, raw download verified (%d bytes)" % (
            commit[:7], len(tree), len(data))

    def write():
        write_atomic(STATE + ".selftest", b"x")
        os.remove(STATE + ".selftest")
        return "atomic replace works in " + BASE_DIR

    def database():
        path = os.path.join(BASE_DIR, ".selftest.db")
        try:
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE t (x)")
            conn.execute("INSERT INTO t VALUES (1)")
            conn.commit()
            conn.close()
            copy_database(path, path + ".copy")
            copy = sqlite3.connect(path + ".copy")
            try:
                count = copy.execute("SELECT count(*) FROM t").fetchone()[0]
            finally:
                copy.close()                # an open file cannot be removed on Windows
        finally:
            for leftover in (path, path + ".copy"):
                try:
                    os.remove(leftover)
                except OSError:
                    pass
        if count != 1:
            raise RuntimeError("backup copy is wrong")
        return "SQLite %s, write and backup work" % sqlite3.sqlite_version

    def password_hashing():
        try:
            import bcrypt
            return "bcrypt package %s installed" % getattr(bcrypt, "__version__", "")
        except ImportError:
            raise RuntimeError("bcrypt package not installed; the built-in bcrypt is used "
                               "(slower, lower cost). Try: pip install bcrypt")

    def application():
        if not os.path.exists(SERVER):
            raise RuntimeError("server.py not found next to launcher.py")
        result = subprocess.run([sys.executable, SERVER, "--check"], cwd=BASE_DIR,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=CHECK_TIMEOUT)
        lines = result.stdout.decode("utf-8", "replace").strip().splitlines()
        if result.returncode != 0:
            raise RuntimeError(lines[-1] if lines else "exit code %d" % result.returncode)
        return lines[-1] if lines else "ok"

    def ping():
        command = ["ping", "-n", "1", "127.0.0.1"] if sys.platform == "win32" else \
            ["ping", "-c", "1", "-W", "1", "127.0.0.1"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        if result.returncode != 0:
            raise RuntimeError("ping exits with %d; use TCP checks for PCs" % result.returncode)
        return "ping works; PCs can be checked by ping"

    check("subprocess", child)
    check("github", github_check)
    check("write", write)
    check("sqlite", database)
    check("application", application)
    check("bcrypt", password_hashing, required=False)
    check("ping", ping, required=False)
    log("SELFTEST", "All checks passed." if ok else "Some checks failed.")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    main()
