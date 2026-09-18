"""Admin settings, activity filtering, database backup, restart and the console commands."""
import os
import re
import socket
import sqlite3
import tempfile
import unittest
from unittest import mock

from helpers import PASSWORD, AppTestCase, free_port
from wol import activity, db, main, runtime, settings


class SettingsPageTest(AppTestCase):
    def setUp(self):
        super(SettingsPageTest, self).setUp()
        self.complete_setup()

    def test_every_setting_is_on_the_page(self):
        page = self.get("/admin/settings").get_data(as_text=True)
        for setting in settings.DEFINITIONS:
            self.assertIn('name="%s"' % setting.key, page)
        self.assertIn("Needs a restart", page)

    def test_invalid_values_are_refused_with_a_reason(self):
        response = self.post("/admin/settings/monitoring", {
            "status_checks_enabled": "1", "status_check_interval": "5",
            "internet_check_interval": "60", "metrics_interval": "abc", "page_refresh_interval": "10"},
            token_from="/admin/settings")
        self.assertEqual(response.status_code, 400)
        page = response.get_data(as_text=True)
        self.assertIn("Enter 15 or more.", page)
        self.assertIn("Enter a whole number.", page)
        self.assertEqual(settings.get("status_check_interval"), 60)

    def test_changes_apply_at_once_and_are_logged(self):
        self.post("/admin/settings/sessions", {"session_days": "7"}, token_from="/admin/settings")
        self.assertEqual(settings.get("session_days"), 7)
        self.get("/")
        self.assertEqual(self.app.permanent_session_lifetime.days, 7)
        with db.session() as conn:
            message = conn.execute("SELECT message FROM events WHERE type = 'settings.changed'").fetchone()[0]
        self.assertIn("stay signed in for from 30 days to 7 days", message)

    def test_port_change_needs_a_restart_and_is_tested_first(self):
        port = free_port()
        self.post("/admin/settings/server", {"server_port": str(port)}, token_from="/admin/settings")
        self.assertEqual(settings.get("server_port"), port)
        self.assertEqual(runtime.listening_port, 5000)
        self.assertIn("changes to %d after a restart" % port, self.get("/admin/").get_data(as_text=True))
        busy = socket.socket()
        busy.bind(("0.0.0.0", 0))
        busy.listen(1)
        try:
            taken = busy.getsockname()[1]
            response = self.post("/admin/settings/server", {"server_port": str(taken)},
                                 token_from="/admin/settings")
            self.assertEqual(response.status_code, 400)
            self.assertIn("cannot be used on this device", response.get_data(as_text=True))
            self.assertEqual(settings.get("server_port"), port)
        finally:
            busy.close()

    def test_restart_only_under_a_launcher(self):
        requests = []
        runtime.restart_hook = lambda: requests.append(1)
        response = self.post("/admin/restart", token_from="/admin/settings")
        self.assertEqual(response.status_code, 302)                  # not supervised
        with mock.patch.dict(os.environ, {"WOL_INSTANCE_TOKEN": "t", "WOL_LAUNCHER_API": "2"}):
            with mock.patch("wol.runtime.request_restart", lambda: requests.append(1)):
                response = self.post("/admin/restart", token_from="/admin/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Restarting", response.get_data(as_text=True))
        self.assertEqual(requests, [1])


class ActivityTest(AppTestCase):
    def setUp(self):
        super(ActivityTest, self).setUp()
        self.complete_setup()
        with db.session() as conn:
            activity.record(conn, "wol.failed", "failed wake", level="error", success=False,
                            pc={"id": 1, "name": "Office PC"})
            activity.record(conn, "system.internet_down", "internet gone", level="warning")

    def test_filters(self):
        def messages(query):
            # Only the table rows: the filter menus name every event type too.
            page = self.get("/admin/activity" + query).get_data(as_text=True)
            return re.findall(r'<span class="line">([^<]+)</span>', page)
        everything = messages("")
        self.assertEqual(everything[:2], ["internet gone", "failed wake"])       # newest first
        self.assertIn("Setup completed from 127.0.0.1", everything)
        self.assertEqual(messages("?kind=wol"), ["failed wake"])
        self.assertEqual(messages("?kind=system.internet_down"), ["internet gone"])
        self.assertEqual(messages("?pc=1"), ["failed wake", "Added Office PC during setup"])
        self.assertEqual(messages("?outcome=failure"), ["failed wake"])
        self.assertEqual(messages("?period=1h&kind=setup"), ["Setup completed from 127.0.0.1"])
        response = self.get("/admin/activity?kind=<script>&page=-3")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<script>&", response.get_data(as_text=True))

    def test_retention(self):
        with db.session() as conn:
            conn.execute("UPDATE events SET created_at = '2001-01-01T00:00:00Z' WHERE message = 'internet gone'")
            conn.execute("INSERT INTO wol_requests (created_at, pc_name, mac, source, result) "
                         "VALUES ('2001-01-01T00:00:00Z', 'Old', 'm', 'dashboard', 'sent')")
            self.assertEqual(activity.cleanup(conn), (1, 1))
            self.assertEqual(conn.execute("SELECT count(*) FROM events WHERE message = "
                                          "'internet gone'").fetchone()[0], 0)


class BackupTest(AppTestCase):
    def setUp(self):
        super(BackupTest, self).setUp()
        self.complete_setup()

    def test_backup_is_a_complete_database(self):
        response = self.post("/admin/backup", token_from="/admin/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        data = response.get_data()
        self.assertTrue(data.startswith(b"SQLite format 3\x00"))
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        try:
            with open(path, "wb") as f:
                f.write(data)
            conn = sqlite3.connect(path)
            self.assertEqual(conn.execute("SELECT name FROM pcs").fetchone()[0], "Office PC")
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            conn.close()
        finally:
            os.remove(path)
        leftovers = [name for name in os.listdir(self.base) if name.startswith(".backup-")]
        self.assertEqual(leftovers, [])

    def test_backup_needs_post_and_a_signed_in_admin(self):
        self.assertEqual(self.get("/admin/backup").status_code, 405)
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        response = self.post("/admin/backup", token_from="/login")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


class ConsoleCommandTest(AppTestCase):
    def test_reset_password_and_set_port(self):
        self.complete_setup()
        with mock.patch("getpass.getpass", side_effect=["recovered secret 1", "recovered secret 1"]):
            self.assertEqual(main.reset_password(self.base), 0)
        self.assertEqual(self.get("/").status_code, 302)        # every browser was signed out
        self.assertEqual(self.login(PASSWORD).status_code, 200)
        self.assertEqual(self.login("recovered secret 1").status_code, 302)
        self.assertEqual(main.set_port("5099", self.base), 0)
        self.assertEqual(settings.get("server_port"), 5099)
        self.assertEqual(main.set_port("99999", self.base), 1)

    def test_reset_password_can_finish_setup(self):
        with mock.patch("getpass.getpass", side_effect=["console password 1", "console password 1"]):
            self.assertEqual(main.reset_password(self.base), 0)
        runtime.setup_done = False
        self.assertEqual(self.login("console password 1").status_code, 302)

    def test_self_check(self):
        self.assertEqual(main.self_check(), 0)


if __name__ == "__main__":
    unittest.main()
