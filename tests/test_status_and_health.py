"""The public status page, /status.json and /health: useful, and never revealing."""
import json
import os
import unittest
from unittest import mock

from helpers import AppTestCase
from wol import auth, db, monitor


class PublicStatusTest(AppTestCase):
    def setUp(self):
        super(PublicStatusTest, self).setUp()
        self.complete_setup(name="Kasia's gaming PC")
        self.client.post("/logout", data={"csrf_token": self.token("/")})

    def secrets(self):
        with db.session() as conn:
            user = auth.get_admin(conn)
            secret = db.get_meta(conn, "secret_key")
        return [user["password_hash"], user["password_hash"][7:29], secret, "24-4B-FE-07-0C-E2",
                "192.168.1.25", "192.168.1.255", self.base, "wol.db", "correct horse"]

    def assert_nothing_private(self, text):
        for private in self.secrets():
            self.assertNotIn(private, text)

    def test_status_is_public_and_private_details_stay_out(self):
        page = self.get("/status")
        self.assertEqual(page.status_code, 200)
        text = page.get_data(as_text=True)
        self.assertIn("Online", text)
        self.assertIn("1 configured, 1 enabled", text)
        self.assert_nothing_private(text)
        self.assertNotIn("Kasia", text)                    # names are off by default
        data = self.get("/status.json").get_json()
        self.assertEqual(data["wake_on_lan"]["pcs_configured"], 1)
        self.assertEqual(data["server"]["database"], "ok")
        self.assert_nothing_private(json.dumps(data))
        self.assertNotIn("pcs", data)

    def test_visibility_settings(self):
        self.login()
        self.post("/admin/settings/public", {"public_status_enabled": "1", "public_pc_detail": "names"},
                  token_from="/admin/settings")
        data = self.get("/status.json").get_json()
        self.assertEqual(data["pcs"][0]["name"], "Kasia's gaming PC")
        for key in ("internet", "device", "version"):
            self.assertNotIn(key, data)                    # their boxes were left unticked
        self.assertNotIn("requests_total", data["wake_on_lan"])
        self.assert_nothing_private(json.dumps(data).replace("Kasia's gaming PC", ""))

        self.post("/admin/settings/public", {"public_status_enabled": "1", "public_pc_detail": "status",
                                             "public_show_wol_activity": "1", "public_show_version": "1",
                                             "public_show_system": "1", "public_show_internet": "1"},
                  token_from="/admin/settings")
        data = self.get("/status.json").get_json()
        self.assertEqual(data["pcs"][0]["name"], "PC 1")
        self.assertIn("requests_total", data["wake_on_lan"])
        self.assertIn("version", data)
        self.assertNotIn("Kasia", json.dumps(data))

        self.post("/admin/settings/public", {"public_pc_detail": "counts"}, token_from="/admin/settings")
        self.assertEqual(self.get("/status").status_code, 404)
        self.assertEqual(self.get("/status.json").status_code, 404)

    def test_status_distinguishes_sent_from_online(self):
        self.login()
        with mock.patch("wol.wake.send_packets", return_value=(4, [])):
            self.post("/pcs/1/wake", token_from="/")
        data = self.get("/status.json").get_json()
        self.assertEqual(data["wake_on_lan"]["last_request_result"], "sent")
        self.assertEqual(data["wake_on_lan"]["pcs_online"], 0)        # sent is not online
        monitor._record_result(dict(monitor._current_pcs()[0]), True, "Answered ping")
        self.assertEqual(self.get("/status.json").get_json()["wake_on_lan"]["pcs_online"], 1)

    def test_live_view_has_display_strings_only(self):
        live = self.get("/status.json?view=live").get_json()
        self.assertEqual(set(live), {"text", "chip"})
        self.assertIn("uptime", live["text"])


class HealthTest(AppTestCase):
    def test_health_fields(self):
        response = self.get("/health", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual((body["ok"], body["database"], body["initialized"]), (True, "ok", False))
        self.assertEqual(body["schema"], db.SCHEMA_VERSION)
        self.complete_setup()
        self.assertTrue(self.get("/health").get_json()["initialized"])

    def test_instance_token_only_for_the_device_itself(self):
        with mock.patch.dict(os.environ, {"WOL_INSTANCE_TOKEN": "abc123"}):
            local = self.get("/health", environ_base={"REMOTE_ADDR": "127.0.0.1"}).get_json()
            remote = self.get("/health", environ_base={"REMOTE_ADDR": "192.168.1.50"}).get_json()
        self.assertEqual(local["token"], "abc123")
        self.assertNotIn("token", remote)

    def test_security_headers(self):
        response = self.get("/status")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("noindex", response.headers["X-Robots-Tag"])
        page = response.get_data(as_text=True)
        self.assertNotIn("<script>", page)                  # no inline script anywhere
        self.assertNotIn("style=", page)

    def test_errors_do_not_leak_stack_traces(self):
        self.complete_setup()
        with mock.patch("wol.views.pc_cards", side_effect=RuntimeError("secret internals")):
            response = self.get("/")
        self.assertEqual(response.status_code, 500)
        page = response.get_data(as_text=True)
        self.assertNotIn("secret internals", page)
        self.assertNotIn("Traceback", page)
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM events WHERE type = 'system.error'")
                             .fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
