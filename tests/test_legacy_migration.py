"""Existing installations: config.json is imported into wol.db once, then retired."""
import json
import os
import unittest
from unittest import mock

from helpers import AppTestCase, reset_process_state
from wol import auth, db, legacy, passwords, pcs, runtime, settings

LEGACY = {
    "password": "hunter2 from 2024",
    "target_mac": "244BFE070CE2",
    "target_ips": ["192.168.1.25", "192.168.1.255"],
    "wol_ports": [7, 9],
    "server_port": 5055,
    "secret_key": "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184",
}


class LegacyMigrationTest(AppTestCase):
    def setUp(self):
        # Write config.json before the database exists, like an existing installation.
        import tempfile
        self.base = tempfile.mkdtemp(prefix="wol-test-")
        reset_process_state()
        self.config = os.path.join(self.base, "config.json")

    def write(self, content):
        with open(self.config, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))

    def test_full_import(self):
        self.write(LEGACY)
        self.prepare()
        with db.session() as conn:
            user = auth.get_admin(conn)
            self.assertTrue(user["password_hash"].startswith("$2b$"))
            self.assertTrue(passwords.verify_password(LEGACY["password"], user["password_hash"]))
            self.assertEqual(db.get_meta(conn, "secret_key"), LEGACY["secret_key"])
            self.assertTrue(auth.setup_complete(conn))
            imported = pcs.load_all(conn)
            self.assertEqual(len(imported), 1)
            pc = imported[0]
            self.assertEqual((pc["name"], pc["mac"], pc["hosts"], pc["broadcasts"], pc["ports"],
                              pc["enabled"], pc["status_method"]),
                             ("My PC", "24-4B-FE-07-0C-E2", ["192.168.1.25"], ["192.168.1.255"],
                              [7, 9], True, "ping"))
            event = conn.execute("SELECT message FROM events WHERE type = "
                                 "'migration.config_imported'").fetchone()[0]
            everything = "\n".join(str(tuple(r)) for t in ("events", "settings", "meta")
                                   for r in conn.execute("SELECT * FROM %s" % t))
        self.assertEqual(settings.get("server_port"), 5055)
        self.assertIn("password stored as a bcrypt password hash", event)
        self.assertNotIn(LEGACY["password"], everything)     # plaintext is stored nowhere
        # The old password signs in; setup is not shown again.
        self.assertEqual(self.get("/setup").status_code, 302)
        self.assertEqual(self.login(LEGACY["password"]).status_code, 302)
        self.assertIn("My PC", self.get("/").get_data(as_text=True))
        # config.json is untouched until the release has proven itself.
        with open(self.config, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["password"], LEGACY["password"])

    def test_import_runs_once(self):
        self.write(LEGACY)
        self.prepare()
        self.write(dict(LEGACY, server_port=6000, password="changed later"))
        reset_process_state()
        self.prepare()
        self.assertEqual(settings.get("server_port"), 5055)
        with db.session() as conn:
            self.assertEqual(pcs.counts(conn), (1, 1))
            self.assertTrue(passwords.verify_password(LEGACY["password"],
                                                      auth.get_admin(conn)["password_hash"]))

    def test_placeholder_password_goes_through_setup_with_the_pc_kept(self):
        self.write(dict(LEGACY, password="CHANGE_YOUR_PASSWORD"))
        self.prepare()
        with db.session() as conn:
            self.assertIsNone(auth.get_admin(conn))
            self.assertFalse(auth.setup_complete(conn))
            self.assertEqual(pcs.counts(conn), (1, 1))
        page = self.get("/setup").get_data(as_text=True)
        self.assertIn("imported", page)
        self.assertIn("My PC", page)
        self.assertNotIn('name="add_pc"', page)          # no second PC form
        response = self.post("/setup", {"code": runtime.setup_code, "password": "a new secret 77",
                                        "confirm": "a new secret 77"})
        self.assertEqual(response.status_code, 302)
        with db.session() as conn:
            self.assertEqual(pcs.counts(conn), (1, 1))

    def test_missing_keys_use_the_old_defaults(self):
        self.write({"password": "only a password"})
        self.prepare()
        with db.session() as conn:
            pc = pcs.load_all(conn)[0]
        self.assertEqual(pc["mac"], "24-4B-FE-07-0C-E2")
        self.assertEqual(pc["ports"], [7, 9])
        self.assertEqual(settings.get("server_port"), 5000)

    def test_invalid_values_are_imported_disabled_not_lost(self):
        self.write(dict(LEGACY, target_mac="not-a-mac", wol_ports=[9, "x", 70000], server_port="http"))
        self.prepare()
        with db.session() as conn:
            pc = pcs.load_all(conn)[0]
            message = conn.execute("SELECT message FROM events WHERE type = "
                                   "'migration.config_imported'").fetchone()[0]
        self.assertFalse(pc["enabled"])
        self.assertEqual(pc["mac"], "not-a-mac")
        self.assertEqual(pc["ports"], [9])
        self.assertEqual(settings.get("server_port"), 5000)
        self.assertIn("imported disabled", message)
        self.assertIn("'http' is not valid", message)

    def test_unreadable_file_is_reported_and_kept(self):
        self.write("{ this is not json")
        self.prepare()
        with db.session() as conn:
            self.assertFalse(auth.setup_complete(conn))
            self.assertIsNone(db.get_meta(conn, "legacy_config_imported_at"))
            message = conn.execute("SELECT message FROM events WHERE type = "
                                   "'migration.config_failed'").fetchone()[0]
        self.assertIn("could not be read", message)
        with open(self.config, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{ this is not json")

    def test_config_found_after_setup_is_ignored(self):
        self.prepare()
        self.complete_setup()
        self.write(LEGACY)
        reset_process_state()
        self.prepare()
        with db.session() as conn:
            self.assertEqual(pcs.counts(conn), (1, 1))
            self.assertTrue(db.get_meta(conn, "legacy_config_imported_at").startswith("skipped"))

    def test_retired_after_ten_minutes_without_secrets(self):
        self.write(LEGACY)
        self.prepare()
        self.assertFalse(legacy.retire_when_proven(self.base))           # too early
        with mock.patch("wol.runtime.uptime", return_value=legacy.PROVEN_AFTER + 1):
            with mock.patch.dict(os.environ, {"WOL_INSTANCE_TOKEN": "t", "WOL_LAUNCHER_API": "1"}):
                self.assertFalse(legacy.retire_when_proven(self.base))   # old launcher reads it
            with mock.patch.dict(os.environ, {"WOL_INSTANCE_TOKEN": "t", "WOL_LAUNCHER_API": "2"}):
                self.assertTrue(legacy.retire_when_proven(self.base))
        self.assertFalse(os.path.exists(self.config))
        with open(self.config + ".migrated", encoding="utf-8") as f:
            kept = json.load(f)
        self.assertNotIn("password", kept)
        self.assertNotIn("secret_key", kept)
        self.assertEqual(kept["target_mac"], LEGACY["target_mac"])
        self.assertIn("no longer reads this file", kept["_note"])
        # The database is still the source of truth afterwards.
        reset_process_state()
        self.prepare()
        self.assertEqual(settings.get("server_port"), 5055)
        self.assertEqual(self.login(LEGACY["password"]).status_code, 302)


if __name__ == "__main__":
    unittest.main()
