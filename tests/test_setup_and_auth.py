"""First-run setup, sign-in, brute-force lockout, sessions, CSRF and admin-only routes."""
import unittest

from helpers import PASSWORD, SETUP_CODE, AppTestCase, reset_process_state
from wol import auth, db, passwords, runtime


class SetupTest(AppTestCase):
    def test_fresh_install_shows_setup_instead_of_login(self):
        for path in ("/", "/login", "/admin/", "/system"):
            response = self.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/setup"), path)
        page = self.get("/setup").get_data(as_text=True)
        self.assertIn("Set up WOL Controller", page)
        self.assertNotIn("CHANGE_YOUR_PASSWORD", page)

    def test_setup_with_a_first_pc(self):
        response = self.complete_setup()
        self.assertTrue(response.headers["Location"].endswith("/"))
        page = self.get("/").get_data(as_text=True)      # signed in straight away
        self.assertIn("Office PC", page)
        self.assertIn("24-4B-FE-07-0C-E2", page)
        with db.session() as conn:
            user = auth.get_admin(conn)
            self.assertTrue(user["password_hash"].startswith("$2b$"))
            self.assertNotEqual(user["password_hash"], PASSWORD)
            self.assertTrue(passwords.verify_password(PASSWORD, user["password_hash"]))
            self.assertTrue(auth.setup_complete(conn))
            types = [row[0] for row in conn.execute("SELECT type FROM events")]
            self.assertIn("setup.completed", types)
            self.assertIn("pc.created", types)
            dump = "\n".join(str(tuple(row)) for row in conn.execute("SELECT * FROM events"))
            self.assertNotIn(PASSWORD, dump)
            self.assertNotIn(SETUP_CODE, dump)

    def test_setup_without_a_pc_leads_to_adding_one(self):
        response = self.complete_setup(add_pc=False)
        self.assertIn("/admin/pcs/new", response.headers["Location"])
        page = self.get("/").get_data(as_text=True)
        self.assertIn("No PCs yet", page)

    def test_wrong_setup_code_changes_nothing(self):
        response = self.post("/setup", {"code": "WRONG-CODE", "password": PASSWORD,
                                        "confirm": PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertIn("not the code shown in the console", response.get_data(as_text=True))
        with db.session() as conn:
            self.assertIsNone(auth.get_admin(conn))
            self.assertFalse(auth.setup_complete(conn))

    def test_setup_validation_keeps_input_and_saves_nothing(self):
        response = self.post("/setup", {"code": SETUP_CODE, "password": "short", "confirm": "short",
                                        "add_pc": "1", "name": "Office PC", "mac": "nope",
                                        "broadcasts": "192.168.1.300", "ports": "0"})
        self.assertEqual(response.status_code, 400)
        page = response.get_data(as_text=True)
        self.assertIn("Use at least 8 characters", page)
        self.assertIn("six pairs of hex digits", page)
        self.assertIn("192.168.1.300 is not an IPv4 address", page)
        self.assertIn('value="Office PC"', page)
        self.assertNotIn('value="short"', page)             # passwords are never echoed
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM pcs").fetchone()[0], 0)
            self.assertIsNone(auth.get_admin(conn))

    def test_setup_closes_for_good(self):
        self.complete_setup()
        response = self.get("/setup")
        self.assertEqual(response.status_code, 302)
        # Even a correct second submission cannot replace the admin.
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        runtime.setup_code = SETUP_CODE
        response = self.post("/setup", {"code": SETUP_CODE, "password": "another password 9",
                                        "confirm": "another password 9"}, token_from="/login")
        self.assertEqual(response.status_code, 302)
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM users").fetchone()[0], 1)
            self.assertTrue(passwords.verify_password(PASSWORD, auth.get_admin(conn)["password_hash"]))

    def test_setup_survives_a_restart_halfway(self):
        # A failed attempt leaves nothing behind; after a restart setup still works,
        # with the new code the console shows.
        self.post("/setup", {"code": SETUP_CODE, "password": PASSWORD, "confirm": "different 12345"})
        reset_process_state()
        runtime.setup_code = "NEWC-ODE2"
        self.prepare()
        response = self.post("/setup", {"code": SETUP_CODE, "password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(response.status_code, 400)
        response = self.post("/setup", {"code": "newc ode2", "password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(response.status_code, 302)

    def test_wrong_setup_codes_lock_out(self):
        for _ in range(auth.MAX_FAILURES):
            self.post("/setup", {"code": "WRONG", "password": PASSWORD, "confirm": PASSWORD})
        response = self.post("/setup", {"code": SETUP_CODE, "password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Too many wrong codes", response.get_data(as_text=True))


class AuthTest(AppTestCase):
    def setUp(self):
        super(AuthTest, self).setUp()
        self.complete_setup()
        self.client.post("/logout", data={"csrf_token": self.token("/")})

    def test_login_and_logout(self):
        self.assertEqual(self.get("/").status_code, 302)
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.get("/").status_code, 200)
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        self.assertEqual(self.get("/").status_code, 302)
        with db.session() as conn:
            types = [row[0] for row in conn.execute("SELECT type FROM events ORDER BY id")]
        self.assertIn("auth.login_succeeded", types)
        self.assertIn("auth.logout", types)

    def test_wrong_password(self):
        response = self.login("not the password")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Wrong password.", response.get_data(as_text=True))
        self.assertEqual(self.get("/").status_code, 302)

    def test_lockout_after_five_failures_and_it_survives_a_restart(self):
        for _ in range(auth.MAX_FAILURES):
            self.login("wrong password 1")
        response = self.login()                     # even the right password is refused now
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        reset_process_state()
        self.prepare()
        self.assertEqual(self.login().status_code, 429)
        # Another address is not affected.
        response = self.client.post("/login", data={"password": PASSWORD,
                                                    "csrf_token": self.token("/login")},
                                    environ_base={"REMOTE_ADDR": "192.168.1.77"})
        self.assertEqual(response.status_code, 302)

    def test_next_parameter_only_goes_to_local_pages(self):
        token = self.token("/login")
        response = self.client.post("/login?next=/admin/pcs", data={"password": PASSWORD, "csrf_token": token})
        self.assertTrue(response.headers["Location"].endswith("/admin/pcs"))
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        for evil in ("//evil.example/", "https://evil.example/", "/\\evil.example"):
            token = self.token("/login")
            response = self.client.post("/login?next=" + evil, data={"password": PASSWORD, "csrf_token": token})
            self.assertNotIn("evil", response.headers["Location"], evil)
            self.client.post("/logout", data={"csrf_token": self.token("/")})

    def test_password_change_signs_out_other_devices(self):
        self.login()
        other = self.app.test_client()
        other.post("/login", data={"password": PASSWORD, "csrf_token": self._token_for(other)})
        self.assertEqual(other.get("/").status_code, 200)
        response = self.post("/admin/security/password", {
            "current": PASSWORD, "password": "a brand new secret", "confirm": "a brand new secret"},
            token_from="/admin/security")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.get("/").status_code, 200)        # this browser stays in
        self.assertEqual(other.get("/").status_code, 302)       # the other one is out
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        self.assertEqual(self.login(PASSWORD).status_code, 200)
        self.assertEqual(self.login("a brand new secret").status_code, 302)

    def test_password_change_needs_the_current_password(self):
        self.login()
        response = self.post("/admin/security/password", {
            "current": "wrong", "password": "a brand new secret", "confirm": "a brand new secret"},
            token_from="/admin/security")
        self.assertEqual(response.status_code, 400)
        self.assertIn("not the current password", response.get_data(as_text=True))

    def test_sign_out_other_devices(self):
        self.login()
        other = self.app.test_client()
        other.post("/login", data={"password": PASSWORD, "csrf_token": self._token_for(other)})
        self.post("/admin/security/sessions", token_from="/admin/security")
        self.assertEqual(self.get("/").status_code, 200)
        self.assertEqual(other.get("/").status_code, 302)

    def test_security_page_never_shows_the_hash(self):
        self.login()
        page = self.get("/admin/security").get_data(as_text=True)
        with db.session() as conn:
            stored = auth.get_admin(conn)["password_hash"]
        self.assertNotIn(stored, page)
        self.assertNotIn(stored[7:29], page)                     # not even the salt
        self.assertIn("Change password", page)

    def _token_for(self, client):
        from helpers import csrf_from
        return csrf_from(client.get("/login").get_data(as_text=True))


class AuthorizationTest(AppTestCase):
    """Every admin page and action needs a signed-in admin."""

    def setUp(self):
        super(AuthorizationTest, self).setUp()
        self.complete_setup()
        self.client.post("/logout", data={"csrf_token": self.token("/")})

    def test_every_protected_route_refuses_anonymous_visitors(self):
        protected_get = ["/", "/system", "/system.json", "/api/dashboard", "/admin/",
                         "/admin/pcs", "/admin/pcs/new", "/admin/pcs/1", "/admin/pcs/1/edit",
                         "/admin/pcs/1/delete", "/admin/activity", "/admin/security",
                         "/admin/settings"]
        for path in protected_get:
            response = self.get(path)
            self.assertIn(response.status_code, (302, 401), path)
            if response.status_code == 302:
                self.assertIn("/login", response.headers["Location"], path)
        token = self.token("/login")
        protected_post = ["/pcs/1/wake", "/admin/pcs/new", "/admin/pcs/1/edit",
                          "/admin/pcs/1/enabled", "/admin/pcs/1/test", "/admin/pcs/1/check",
                          "/admin/pcs/1/delete", "/admin/security/password",
                          "/admin/security/sessions", "/admin/settings/server", "/admin/backup",
                          "/admin/restart"]
        for path in protected_post:
            response = self.client.post(path, data={"csrf_token": token})
            self.assertEqual(response.status_code, 302, path)
            self.assertIn("/login", response.headers["Location"], path)
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM pcs").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM wol_requests").fetchone()[0], 0)

    def test_json_endpoints_answer_401(self):
        self.assertEqual(self.get("/api/dashboard").status_code, 401)
        self.assertEqual(self.get("/system.json").status_code, 401)


class CsrfTest(AppTestCase):
    def setUp(self):
        super(CsrfTest, self).setUp()
        self.complete_setup()

    def test_posts_without_a_valid_token_change_nothing(self):
        actions = [("/pcs/1/wake", {}), ("/admin/pcs/1/delete", {}),
                   ("/admin/pcs/1/enabled", {"enabled": "0"}),
                   ("/admin/settings/server", {"server_port": "5999"}),
                   ("/admin/security/sessions", {}), ("/logout", {}),
                   ("/admin/security/password", {"current": PASSWORD, "password": "x" * 12,
                                                  "confirm": "x" * 12})]
        for path, form in actions:
            for token in (None, "forged-token"):
                data = dict(form)
                if token:
                    data["csrf_token"] = token
                response = self.client.post(path, data=data)
                self.assertEqual(response.status_code, 302, path)
        with db.session() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM pcs WHERE enabled = 1").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM wol_requests").fetchone()[0], 0)
            self.assertIsNone(conn.execute("SELECT value FROM settings WHERE key = 'server_port'").fetchone())
        self.assertEqual(self.get("/").status_code, 200)       # still signed in

    def test_login_form_is_protected_too(self):
        self.client.post("/logout", data={"csrf_token": self.token("/")})
        response = self.client.post("/login", data={"password": PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.get("/").status_code, 302)


if __name__ == "__main__":
    unittest.main()
