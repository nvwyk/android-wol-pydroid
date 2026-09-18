"""The SQLite layer: schema, transactions, settings, and behaviour with a broken file."""
import os
import unittest

from helpers import AppTestCase, reset_process_state
from wol import activity, db, main, runtime, settings, web


class SchemaTest(AppTestCase):
    def test_fresh_database_has_every_table(self):
        with db.session() as conn:
            tables = set(row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"))
            self.assertTrue({"meta", "settings", "users", "pcs", "pc_addresses", "pc_ports",
                             "wol_requests", "events"} <= tables)
            self.assertEqual(db.schema_version(conn), db.SCHEMA_VERSION)
            self.assertTrue(db.get_meta(conn, "secret_key"))

    def test_migrating_twice_changes_nothing(self):
        with db.session() as conn:
            self.assertEqual(db.migrate(conn), (db.SCHEMA_VERSION, db.SCHEMA_VERSION))

    def test_a_newer_schema_is_tolerated(self):
        # launcher.py can roll back to this release after a newer one upgraded the file.
        with db.session() as conn:
            conn.execute("PRAGMA user_version = 99")
            self.assertEqual(db.migrate(conn), (99, 99))

    def test_secret_key_survives_restarts(self):
        with db.session() as conn:
            first = db.get_meta(conn, "secret_key")
        reset_process_state()
        self.prepare()
        with db.session() as conn:
            self.assertEqual(db.get_meta(conn, "secret_key"), first)

    def test_transaction_rolls_back_on_error(self):
        with db.session() as conn:
            with self.assertRaises(RuntimeError):
                with db.transaction(conn):
                    db.set_meta(conn, "probe", "1")
                    raise RuntimeError("boom")
            self.assertIsNone(db.get_meta(conn, "probe"))

    def test_nested_transactions_join_the_outer_one(self):
        with db.session() as conn:
            with self.assertRaises(RuntimeError):
                with db.transaction(conn):
                    with db.transaction(conn):
                        db.set_meta(conn, "inner", "1")
                    raise RuntimeError("outer fails")
            self.assertIsNone(db.get_meta(conn, "inner"))

    def test_deleting_a_pc_keeps_its_history(self):
        with db.session() as conn:
            conn.execute("INSERT INTO pcs (id, name, mac, created_at, updated_at) "
                         "VALUES (7, 'Old', '02-00-00-00-00-07', 'x', 'x')")
            conn.execute("INSERT INTO pc_ports (pc_id, port) VALUES (7, 9)")
            conn.execute("INSERT INTO wol_requests (created_at, pc_id, pc_name, mac, source, "
                         "result) VALUES ('x', 7, 'Old', 'm', 'dashboard', 'sent')")
            activity.record(conn, "wol.sent", "sent", pc={"id": 7, "name": "Old"})
            conn.execute("DELETE FROM pcs WHERE id = 7")
            self.assertEqual(conn.execute("SELECT count(*) FROM pc_ports").fetchone()[0], 0)
            row = conn.execute("SELECT pc_id, pc_name FROM wol_requests").fetchone()
            self.assertEqual((row[0], row[1]), (None, "Old"))
            event = conn.execute("SELECT pc_id, pc_name FROM events WHERE type = 'wol.sent'").fetchone()
            self.assertEqual((event[0], event[1]), (None, "Old"))


class SettingsTest(AppTestCase):
    def test_defaults(self):
        self.assertEqual(settings.get("server_port"), 5000)
        self.assertTrue(settings.get("public_status_enabled"))
        self.assertEqual(settings.get("public_pc_detail"), "counts")

    def test_save_and_reload(self):
        with db.session() as conn:
            changed = settings.save(conn, {"server_port": 5123, "session_days": 30})
            self.assertEqual(changed, ["server_port"])
            settings._cache.clear()
            settings.load(conn)
        self.assertEqual(settings.get("server_port"), 5123)

    def test_a_broken_stored_value_falls_back_to_the_default(self):
        with db.session() as conn:
            conn.execute("INSERT OR REPLACE INTO settings VALUES ('server_port', 'lots', 'x')")
            conn.execute("INSERT OR REPLACE INTO settings VALUES ('unknown_key', '1', 'x')")
            settings.load(conn)
        self.assertEqual(settings.get("server_port"), 5000)

    def test_parse(self):
        port = settings.BY_KEY["server_port"]
        self.assertEqual(settings.parse(port, " 8080 "), 8080)
        for bad in ("0", "65536", "http", ""):
            with self.assertRaises(ValueError):
                settings.parse(port, bad)
        flag = settings.BY_KEY["public_status_enabled"]
        self.assertIs(settings.parse(flag, "on"), True)
        self.assertIs(settings.parse(flag, "0"), False)
        with self.assertRaises(ValueError):
            settings.parse(settings.BY_KEY["public_pc_detail"], "everything")


class DamagedDatabaseTest(unittest.TestCase):
    """A file that is not a database must not crash the server or leak details."""

    def setUp(self):
        import tempfile
        self.base = tempfile.mkdtemp(prefix="wol-test-")
        reset_process_state()
        with open(os.path.join(self.base, "wol.db"), "wb") as f:
            f.write(b"this is not an sqlite database" * 100)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_degraded_mode(self):
        secret = main.prepare(self.base)
        self.assertIsNone(secret)
        self.assertIn("could not be opened", runtime.database_error)
        app = web.create_app("degraded", testing=True)
        client = app.test_client()
        health = client.get("/health", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(health.status_code, 503)
        self.assertFalse(health.get_json()["ok"])
        self.assertEqual(health.get_json()["database"], "error")
        for path in ("/", "/login", "/setup", "/status", "/admin/"):
            response = client.get(path)
            self.assertEqual(response.status_code, 503, path)
            page = response.get_data(as_text=True)
            self.assertIn("Database unavailable", page)
            self.assertNotIn(self.base, page)           # no filesystem paths
            self.assertNotIn("Traceback", page)
        # The file itself is left exactly as it was, for recovery.
        with open(os.path.join(self.base, "wol.db"), "rb") as f:
            self.assertTrue(f.read().startswith(b"this is not"))

    def test_database_error_during_a_request_is_a_plain_503(self):
        # A working installation whose database becomes unreachable while it runs.
        import shutil
        import tempfile
        base = tempfile.mkdtemp(prefix="wol-test-")
        try:
            secret = main.prepare(base)
            app = web.create_app(secret, testing=True)
            db.configure(os.path.join(base, "missing-folder", "wol.db"))
            response = app.test_client().get("/status")
            self.assertEqual(response.status_code, 503)
            page = response.get_data(as_text=True)
            self.assertIn("Database unavailable", page)
            self.assertNotIn("Traceback", page)
            self.assertNotIn(base, page)
        finally:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
