"""The web UI through Flask's test client, on a catalog built by real scans, under row-level security."""

import re
import time
import unittest

from tests.test_server import PGHOST, ServerCase, psycopg

try:
    from pinakes import auth, server_config, web
except ImportError:  # Flask missing
    web = None


@unittest.skipUnless(web is not None, "Flask not installed")
class TestWeb(ServerCase):
    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.scan("server-1", "store")
        self.secret = auth.new_totp_secret()
        for name, pw, secret in (("user-1", "correct horse battery", self.secret), ("user-2", "staple pony 12345", None)):
            pid = self.q("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))[0][0]
            self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash, totp_secret) "
                              "VALUES (%s, %s, %s)", (pid, auth.hash_password(pw), secret))
        cfg = server_config.loads(self.SERVER_WEB)
        app = web.create_app(cfg, connect=lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db))
        app.testing = True
        self.app = app

    SERVER_WEB = '[web]\nsecure_cookies = false\nsession_key = "test-key"\n'

    def client(self):
        return self.app.test_client()

    def csrf(self, c, url="/login"):
        return re.search(r'name="csrf" value="([^"]+)"', c.get(url).get_data(as_text=True)).group(1)

    def login(self, name, pw):
        c = self.client()
        r = c.post("/login", data={"csrf": self.csrf(c), "name": name, "password": pw})
        return c, r

    def file_id(self, rel):
        return self.file("store", rel)

    def test_sign_in(self):
        c, r = self.login("user-1", "wrong")
        self.assertIn("don&#39;t match", r.get_data(as_text=True))
        c, r = self.login("nobody", "whatever")
        self.assertIn("don&#39;t match", r.get_data(as_text=True))
        c, r = self.login("user-1", "correct horse battery")
        self.assertEqual(r.status_code, 302)
        self.assertIn("store", c.get("/").get_data(as_text=True))
        self.assertEqual(self.client().get("/").status_code, 302)          # signed out: to the sign-in page

    def test_csrf_required(self):
        c = self.client()
        c.get("/login")
        r = c.post("/login", data={"name": "user-1", "password": "correct horse battery"})
        self.assertEqual(r.status_code, 400)

    def test_people_see_only_their_own(self):
        c2, _ = self.login("user-2", "staple pony 12345")
        his = self.file_id("people/user-1/taxes.txt")
        self.assertEqual(c2.get("/file/%d" % his).status_code, 404)        # not yours: the same as not there
        self.assertEqual(c2.get("/file/%d" % self.file_id("people/user-1/shared-with-2/plan.txt")).status_code, 200)
        page = c2.get("/browse/store/people").get_data(as_text=True)
        self.assertIn("user-2/", page)
        found = c2.get("/find?q=taxes").get_data(as_text=True)
        self.assertNotIn("people/user-1/taxes.txt", found)                 # the query is echoed; the file isn't
        self.assertIn("No file you can see", found)
        c1, _ = self.login("user-1", "correct horse battery")
        self.assertEqual(c1.get("/file/%d" % self.file_id("people/user-2/diary.txt")).status_code, 404)

    def test_step_up_needs_code_and_reason_and_is_audited(self):
        c1, _ = self.login("user-1", "correct horse battery")
        hers = self.file_id("people/user-2/diary.txt")
        tok = self.csrf(c1, "/step-up")
        r = c1.post("/step-up", data={"csrf": tok, "reason": "checking", "code": "000000"})
        self.assertIn("didn&#39;t match", r.get_data(as_text=True))
        r = c1.post("/step-up", data={"csrf": tok, "reason": "", "code": auth.totp(self.secret)})
        self.assertIn("Give a reason", r.get_data(as_text=True))
        r = c1.post("/step-up", data={"csrf": tok, "reason": "finding the old version", "code": auth.totp(self.secret)})
        self.assertEqual(r.status_code, 302)
        page = c1.get("/file/%d" % hers)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Administrator step-up is on", page.get_data(as_text=True))
        # user-2 sees that it happened, and why
        c2, _ = self.login("user-2", "staple pony 12345")
        access = c2.get("/access").get_data(as_text=True)
        self.assertIn("view", access)
        self.assertIn("User One", access)
        # ending it closes the view again
        c1.post("/step-up", data={"csrf": tok, "action": "end"})
        self.assertEqual(c1.get("/file/%d" % hers).status_code, 404)

    def test_person_without_role_cannot_step_up(self):
        c2, _ = self.login("user-2", "staple pony 12345")
        self.assertEqual(c2.get("/step-up").status_code, 403)

    def test_reports_and_headers(self):
        c1, _ = self.login("user-1", "correct horse battery")
        r = c1.get("/reports/safe-to-delete?loc=store:people/user-1/")
        self.assertIn("Not safe", r.get_data(as_text=True))          # no backups yet
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertIn("a location is ROOT:PATH", c1.get("/reports/only-here?loc=nocolon").get_data(as_text=True))
        for url in ("/reports/dupes", "/reports/changes", "/reports/backed-up?loc=store:", "/access", "/account"):
            self.assertEqual(c1.get(url).status_code, 200, url)

    def test_totp_enrollment(self):
        c2, _ = self.login("user-2", "staple pony 12345")
        tok = self.csrf(c2, "/account")
        page = c2.post("/account", data={"csrf": tok, "action": "start-totp"}).get_data(as_text=True)
        secret = re.search(r'class="mono">([A-Z2-7]+)<', page).group(1)
        r = c2.post("/account", data={"csrf": tok, "action": "confirm-totp", "code": auth.totp(secret)})
        self.assertIn("Second factor saved", r.get_data(as_text=True))
        self.assertIn("A second factor is set up", c2.get("/account").get_data(as_text=True))


@unittest.skipUnless(web is not None, "Flask not installed")
class TestBehindProxy(TestWeb):
    SERVER_WEB = '[web]\nsecure_cookies = false\nsession_key = "test-key"\nbehind_proxy = true\n'

    def test_limit_is_per_visitor_not_per_proxy(self):
        def fail(addr, n):
            c = self.client()
            for _ in range(n):
                tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
                r = c.post("/login", data={"csrf": tok, "name": "user-1", "password": "wrong"},
                           headers={"X-Forwarded-For": addr}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
            return r.status_code
        self.assertEqual(fail("192.0.2.10", 5), 200)     # five failures from one visitor: still answered
        self.assertEqual(fail("192.0.2.10", 1), 429)     # the sixth is refused
        self.assertEqual(fail("192.0.2.11", 1), 200)     # another visitor behind the same proxy is not


class TestAuth(unittest.TestCase):
    def test_password_and_totp(self):
        from pinakes import auth
        h = auth.hash_password("pw one")
        self.assertTrue(auth.check_password("pw one", h))
        self.assertFalse(auth.check_password("pw two", h))
        # RFC 6238 test vector (SHA-1, secret "12345678901234567890", T = 59 s): 94287082 -> 287082 for six digits
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(auth.totp(secret, at=59, digits=8), "94287082")
        self.assertTrue(auth.check_totp(secret, auth.totp(secret, at=1000), at=1010))
        self.assertFalse(auth.check_totp(secret, auth.totp(secret, at=1000), at=1200))


if __name__ == "__main__":
    unittest.main()
