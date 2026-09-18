"""launcher.py: whole-release updates, validation, rollback, recovery and the database.

GitHub is replaced by a fake that serves releases built from this working tree. Everything
else is real: server processes, /health, backups, rollbacks and database snapshots.
"""
import http.cookiejar
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request

from helpers import ROOT, free_port

sys.path.insert(0, ROOT)
import launcher  # noqa: E402

LEGACY_COMMIT = "d83a172"           # the last single-file server.py that used config.json


def current_release():
    return dict((path, launcher.read(os.path.join(ROOT, *path.split("/"))))
                for path in launcher.files_in(ROOT))


def changed(files, path, old, new):
    """A copy of `files` with one text replacement that must apply."""
    text = files[path].decode("utf-8")
    assert old in text, "%s does not contain %r" % (path, old)
    copy = dict(files)
    copy[path] = text.replace(old, new, 1).encode("utf-8")
    return copy


def legacy_server():
    try:
        return subprocess.run(["git", "show", LEGACY_COMMIT + ":server.py"], cwd=ROOT,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


class FakeGitHub(object):
    def __init__(self):
        self.commit, self.files, self.downloads = None, {}, []
        self.extra = {"README.md": b"# readme\n", "launcher.py": b"# launcher\n"}

    def publish(self, files, name, extra=None):
        self.commit = (name * 40)[:40]
        self.files = dict(files)
        if extra:
            self.extra.update(extra)

    def latest_commit(self):
        return self.commit

    def fetch_tree(self, commit):
        assert commit == self.commit
        everything = dict(self.extra)
        everything.update(self.files)
        return dict((path, launcher.blob_sha(data)) for path, data in everything.items())

    def download(self, commit, path, sha):
        data = self.files.get(path, self.extra.get(path))
        if launcher.blob_sha(data) != sha:
            raise ValueError("%s does not match its GitHub hash" % path)
        self.downloads.append(path)
        return data


class LauncherTestCase(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="wol-launcher-")
        launcher.configure(self.base)
        launcher._last_port[0] = None
        launcher.SERVER_OUTPUT = subprocess.DEVNULL
        self.github = FakeGitHub()
        self.patches = []
        for name in ("latest_commit", "fetch_tree", "download"):
            original = getattr(launcher, name)
            setattr(launcher, name, getattr(self.github, name))
            self.patches.append((name, original))
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            launcher.stop_server(proc)
        for name, original in self.patches:
            setattr(launcher, name, original)
        launcher.configure(ROOT)
        launcher.SERVER_OUTPUT = None
        shutil.rmtree(self.base, ignore_errors=True)

    def install(self, files):
        for path, data in files.items():
            launcher.write_atomic(os.path.join(self.base, *path.split("/")), data)

    def start(self):
        proc = launcher.start_server()
        self.procs.append(proc)
        return proc

    def track(self, proc):
        if proc not in self.procs:
            self.procs.append(proc)
        return proc

    def health(self):
        with urllib.request.urlopen("http://127.0.0.1:%d/health" % launcher.server_port(), timeout=5) as r:
            return json.loads(r.read())


class ReleaseFilesTest(LauncherTestCase):
    def test_release_rules(self):
        self.install(current_release())
        launcher.write_atomic(os.path.join(self.base, "wol", "__pycache__", "x.cpython-311.pyc"), b"x")
        launcher.write_atomic(os.path.join(self.base, "README.md"), b"local")
        files = launcher.files_in(self.base)
        self.assertIn("server.py", files)
        self.assertIn("wol/templates/layout.html", files)
        self.assertFalse([path for path in files if "__pycache__" in path or path == "README.md"])
        sys.path.insert(0, self.base)
        self.assertEqual(launcher.release_id(files), __import__("wol").release_id(self.base))

    def test_unsafe_paths_are_refused(self):
        for path in ("../evil.py", "/abs.py", "wol/../../x", "C:/x", "wol\\x.py", ""):
            self.assertFalse(launcher.safe_path(path), path)
        self.assertTrue(launcher.safe_path("wol/templates/admin/base.html"))

    def test_server_port_sources(self):
        self.assertEqual(launcher.server_port(), 5000)
        launcher.write_atomic(launcher.CONFIG, b'{"server_port": 5071}')
        self.assertEqual(launcher.server_port(), 5071)       # a release before the database
        conn = sqlite3.connect(launcher.DATABASE)
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
        conn.commit()
        self.assertEqual(launcher.server_port(), 5000)       # the database wins, default port
        conn.execute("INSERT INTO settings VALUES ('server_port', '5072', 'x')")
        conn.commit()
        conn.close()
        self.assertEqual(launcher.server_port(), 5072)
        self.assertTrue(launcher.updates_enabled())

    def test_hardcoded_settings_of_the_oldest_version_move_to_config_json(self):
        launcher.write_atomic(launcher.SERVER, b'PASSWORD = "old secret"\nWOL_PORTS = [9]\nOTHER = 1\n')
        launcher.migrate_config()
        with open(launcher.CONFIG) as f:
            self.assertEqual(json.load(f), {"password": "old secret", "wol_ports": [9]})


class UpdateDecisionTest(LauncherTestCase):
    def setUp(self):
        super(UpdateDecisionTest, self).setUp()
        self.release = current_release()
        self.install(self.release)

    def test_unchanged_and_readme_only_commits_do_nothing(self):
        state = {}
        self.github.publish(self.release, "a")
        self.assertIsNone(launcher.fetch_update(state))
        self.assertEqual(state["app_commit"], self.github.commit)
        self.github.publish(self.release, "b", extra={"README.md": b"# new docs\n"})
        self.assertIsNone(launcher.fetch_update(state))
        self.assertIsNone(launcher.fetch_update(state))      # same commit: not even a tree fetch

    def test_changed_release_is_offered_and_a_bad_one_skipped(self):
        state = {}
        newer = changed(self.release, "wol/__init__.py", 'APP_VERSION = "3.0.0"', 'APP_VERSION = "3.0.1"')
        self.github.publish(newer, "c")
        commit, wanted = launcher.fetch_update(state)
        self.assertEqual(wanted["wol/__init__.py"], launcher.blob_sha(newer["wol/__init__.py"]))
        state["bad_release"] = launcher.release_id(wanted)
        self.assertIsNone(launcher.fetch_update(state))

    def test_launcher_update_is_noticed(self):
        state = {}
        self.github.publish(self.release, "d")
        launcher.fetch_update(state)
        self.assertTrue(state["launcher_update_available"])  # the fake launcher.py differs

    def test_a_commit_without_the_application_is_ignored(self):
        state = {}
        self.github.publish({"README.md": b"only docs"}, "e")
        self.assertIsNone(launcher.fetch_update(state))
        self.assertIn("no usable application", state["last_check_result"])

    def test_staging_downloads_only_what_changed_and_checks_hashes(self):
        newer = changed(self.release, "wol/pcs.py", "NAME_MAX = 60", "NAME_MAX = 61")
        self.github.publish(newer, "f")
        commit, wanted = launcher.fetch_update({})
        launcher.stage(commit, wanted)
        self.assertEqual(self.github.downloads, ["wol/pcs.py"])
        self.assertEqual(launcher.files_in(launcher.STAGE_DIR), wanted)
        self.github.files["wol/pcs.py"] = b"tampered"
        with self.assertRaises(ValueError):
            launcher.stage(commit, wanted)

    def test_validation(self):
        launcher.write_atomic(os.path.join(launcher.STAGE_DIR, "server.py"), launcher.read(launcher.SERVER))
        shutil.copytree(os.path.join(self.base, "wol"), os.path.join(launcher.STAGE_DIR, "wol"))
        self.assertIsNone(launcher.validate_stage())
        broken = os.path.join(launcher.STAGE_DIR, "wol", "templates", "status.html")
        with open(broken, "a", encoding="utf-8") as f:
            f.write("{% if %}")
        self.assertIn("self-check failed", launcher.validate_stage())
        with open(os.path.join(launcher.STAGE_DIR, "wol", "pcs.py"), "a", encoding="utf-8") as f:
            f.write("\ndef broken(:\n")
        self.assertIn("wol/pcs.py", launcher.validate_stage())


class RecoveryTest(LauncherTestCase):
    def test_interrupted_install_is_undone_at_the_next_start(self):
        old = current_release()
        self.install(old)
        self.assertTrue(launcher.make_backup())
        new = changed(old, "wol/__init__.py", 'APP_VERSION = "3.0.0"', 'APP_VERSION = "3.9.9"')
        new["wol/extra.py"] = b"X = 1\n"
        state = {"pending": {"commit": "c" * 40, "release": launcher.release_id(new),
                             "files": dict((p, launcher.blob_sha(d)) for p, d in new.items()),
                             "db_version": None}}
        # Only one of the new files made it before the phone died.
        launcher.write_atomic(os.path.join(self.base, "wol", "extra.py"), new["wol/extra.py"])
        self.assertFalse(launcher.recover_interrupted(state))
        self.assertEqual(launcher.files_in(self.base), dict((p, launcher.blob_sha(d)) for p, d in old.items()))
        self.assertNotIn("pending", state)

    def test_completed_install_is_verified_after_the_restart(self):
        files = current_release()
        self.install(files)
        state = {"pending": {"files": dict((p, launcher.blob_sha(d)) for p, d in files.items())}}
        self.assertTrue(launcher.recover_interrupted(state))

    def test_pending_left_by_the_old_launcher_is_dropped(self):
        state = {"pending": "0123456789abcdef"}
        launcher.write_atomic(launcher.STATE, b"{}")
        self.assertFalse(launcher.recover_interrupted(state))
        self.assertNotIn("pending", state)


class LiveUpdateTest(LauncherTestCase):
    """Real processes: update, runtime failure with rollback, broken downloads, and a
    release that changes the database schema before failing."""

    def test_update_rollback_and_database_restore(self):
        release = current_release()
        self.install(release)
        port = free_port()
        subprocess.run([sys.executable, launcher.SERVER, "--set-port", str(port)], cwd=self.base,
                       check=True, stdout=subprocess.DEVNULL)
        proc = self.start()
        self.assertTrue(launcher.wait_healthy(proc))
        self.assertEqual(launcher.server_port(), port)
        before = self.health()
        self.assertEqual(before["version"], "3.0.0")
        state = {}

        # 1. A good release is installed and verified.
        good = changed(release, "wol/__init__.py", 'APP_VERSION = "3.0.0"', 'APP_VERSION = "3.0.1"')
        self.github.publish(good, "1")
        proc = self.track(launcher.apply_update(proc, state, *launcher.fetch_update(state)))
        self.assertEqual(self.health()["version"], "3.0.1")
        self.assertEqual(state["app_commit"], self.github.commit)
        self.assertNotIn("pending", state)
        self.assertTrue(os.path.isfile(os.path.join(launcher.BACKUP_DIR, "server.py")))

        # 2. A release that passes validation but cannot start is rolled back.
        crashing = changed(good, "wol/main.py", "    secret = prepare(base_dir)\n",
                           "    raise SystemExit('broken release')\n    secret = prepare(base_dir)\n")
        self.github.publish(crashing, "2")
        proc = self.track(launcher.apply_update(proc, state, *launcher.fetch_update(state)))
        self.assertEqual(self.health()["version"], "3.0.1")
        self.assertEqual(launcher.files_in(self.base),
                         dict((p, launcher.blob_sha(d)) for p, d in good.items()))
        self.assertEqual(state["bad_release"], launcher.release_id(
            dict((p, launcher.blob_sha(d)) for p, d in crashing.items())))
        self.assertIsNone(launcher.fetch_update(state))       # not retried

        # 3. A release with a syntax error never stops the running server.
        pid = proc.pid
        broken = changed(good, "wol/pcs.py", "NAME_MAX = 60", "NAME_MAX = (")
        self.github.publish(broken, "3")
        proc = self.track(launcher.apply_update(proc, state, *launcher.fetch_update(state)))
        self.assertEqual(proc.pid, pid)
        self.assertIn("failed validation", state["last_check_result"])

        # 4. A failed release that already upgraded the schema: the database comes back.
        with sqlite3.connect(launcher.DATABASE) as conn:
            conn.execute("INSERT INTO meta (key, value) VALUES ('marker', 'kept')")
        schema = changed(good, "wol/db.py", "SCHEMA_VERSION = 1\n", "SCHEMA_VERSION = 2\n")
        schema = changed(schema, "wol/db.py", "MIGRATIONS = {\n",
                         "MIGRATIONS = {\n    2: [\"CREATE TABLE extra (x)\"],\n")
        schema = changed(schema, "wol/main.py", "    app = web.create_app(secret or secrets.token_hex(32))\n",
                         "    raise SystemExit('fails after migrating')\n")
        self.github.publish(schema, "4")
        proc = self.track(launcher.apply_update(proc, state, *launcher.fetch_update(state)))
        self.assertEqual(self.health()["version"], "3.0.1")
        self.assertEqual(launcher.schema_version(launcher.DATABASE), 1)
        with sqlite3.connect(launcher.DATABASE) as conn:
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master")]
            marker = conn.execute("SELECT value FROM meta WHERE key = 'marker'").fetchone()
        self.assertNotIn("extra", tables)
        self.assertEqual(marker[0], "kept")                   # data from before the update survives
        self.assertTrue(os.path.exists(launcher.SNAPSHOT))


@unittest.skipIf(legacy_server() is None, "git history with the old server.py is not available")
class ExistingInstallationTest(LauncherTestCase):
    """An installation of the single-file version with config.json, updated by launcher.py."""

    def setUp(self):
        super(ExistingInstallationTest, self).setUp()
        self.port = free_port()
        launcher.write_atomic(launcher.SERVER, legacy_server())
        launcher.write_atomic(launcher.CONFIG, json.dumps({
            "password": "hunter2 from 2024", "target_mac": "244BFE070CE2",
            "target_ips": ["192.168.1.25", "192.168.1.255"], "wol_ports": [7, 9],
            "server_port": self.port, "secret_key": "k" * 64}).encode())

    def sign_in(self, password):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                             urllib.request.ProxyHandler({}))
        base = "http://127.0.0.1:%d" % self.port
        page = opener.open(base + "/login", timeout=10).read().decode()
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        body = urllib.parse.urlencode({"password": password, "csrf_token": token}).encode()
        return opener.open(base + "/login", data=body, timeout=30).read().decode()

    def test_old_version_updates_and_migrates(self):
        proc = self.start()
        self.assertTrue(launcher.wait_healthy(proc))         # the old version, as it runs today
        self.assertFalse(os.path.exists(launcher.DATABASE))
        state = {}
        self.github.publish(current_release(), "5")
        proc = self.track(launcher.apply_update(proc, state, *launcher.fetch_update(state)))
        body = self.health()
        self.assertEqual((body["ok"], body["initialized"], body["version"]), (True, True, "3.0.0"))
        with sqlite3.connect(launcher.DATABASE) as conn:
            stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
            pc = conn.execute("SELECT name, mac FROM pcs").fetchone()
        self.assertTrue(stored.startswith("$2b$"))
        self.assertEqual(tuple(pc), ("My PC", "24-4B-FE-07-0C-E2"))
        # The old password still signs in, now checked against the bcrypt password hash.
        page = self.sign_in("hunter2 from 2024")
        self.assertIn("My PC", page)
        self.assertIn("Your PCs", page)
        # config.json stays untouched while a rollback to the old version is still possible.
        with open(launcher.CONFIG) as f:
            self.assertEqual(json.load(f)["password"], "hunter2 from 2024")

    def test_failed_first_update_returns_to_the_old_version_intact(self):
        proc = self.start()
        self.assertTrue(launcher.wait_healthy(proc))
        state = {}
        crashing = changed(current_release(), "wol/main.py",
                           "    app = web.create_app(secret or secrets.token_hex(32))\n",
                           "    raise SystemExit('fails after migrating')\n")
        self.github.publish(crashing, "6")
        proc = self.track(launcher.apply_update(proc, state, *launcher.fetch_update(state)))
        self.assertTrue(launcher.wait_healthy(proc))
        self.assertEqual(launcher.files_in(self.base), {"server.py": launcher.blob_sha(legacy_server())})
        with open(launcher.CONFIG) as f:
            self.assertEqual(json.load(f)["password"], "hunter2 from 2024")
        self.assertIn("rolled back", state["last_check_result"])


if __name__ == "__main__":
    unittest.main()
