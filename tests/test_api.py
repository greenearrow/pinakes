"""The JSON API and person tokens (ROADMAP 34), through Flask's test client, on a catalog built by real scans."""

import contextlib
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from pinakes.ingest import Ingester
from tests.test_server import PGHOST, SERVER, UPGRADES, ServerCase, admin_conn, psycopg

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from pinakes import auth, server_config, web
except ImportError:  # Flask missing
    web = None

PASSWORDS = {"user-1": "correct horse battery", "user-2": "staple pony 12345"}


@unittest.skipUnless(web is not None, "Flask not installed")
class ApiCase(ServerCase):
    """A catalog by real scans, an app, and the helpers to make tokens and call the API."""

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.scan("server-1", "store")
        self.agent("laptop-1", "downloads", extra="protected = true")
        self.write("laptop-1", "downloads", "taxes-copy.txt", b"his")
        self.write("laptop-1", "downloads", "letter.txt", b"letter")
        self.scan("laptop-1", "downloads")
        self.secret = auth.new_totp_secret()
        for name, secret in (("user-1", self.secret), ("user-2", None)):
            self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash, totp_secret) "
                              "VALUES (%s, %s, %s)", (self.pid(name), auth.hash_password(PASSWORDS[name]), secret))
        cfg = server_config.loads('[web]\nsecure_cookies = false\nsession_key = "test-key"\n')
        self.app = web.create_app(cfg, connect=self.app_conn)
        self.app.testing = True

    def app_conn(self):
        return psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db)

    def pid(self, name):
        return self.q("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))[0][0]

    def root_id(self, label):
        return self.q("SELECT root_id FROM pinakes.roots WHERE label = %s", (label,))[0][0]

    def token(self, name, scopes=("read",), roots=None, days=None, client="laptop-1"):
        """A token made the way the account page makes one: as the person, through make_token()."""
        secret = "pinakes_test_%s_%s" % (name, os.urandom(8).hex())
        with self.app_conn() as c:
            c.execute("SELECT set_config('pinakes.person', %s, true)", (str(self.pid(name)),))
            c.execute("SELECT pinakes.make_token(%s, %s, %s, %s, %s)",
                      (client, hashlib.sha256(secret.encode()).digest(), list(scopes), roots, days))
        return secret

    def get(self, path, secret=None, client=None):
        c = client or self.app.test_client()
        headers = {"Authorization": "Bearer " + secret} if secret else {}
        r = c.get("/api/v1/" + path, headers=headers)
        return r.status_code, r.get_json()

    def paths(self, path, secret):
        status, body = self.get(path, secret)
        self.assertEqual(status, 200, body)
        return sorted("%s:%s" % (r["root"], r["relpath"]) for r in body["rows"])

    def login(self, name):
        c = self.app.test_client()
        page = c.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        c.post("/login", data={"csrf": csrf, "name": name, "password": PASSWORDS[name]})
        return c

    def csrf(self, c, url):
        return re.search(r'name="csrf" value="([^"]+)"', c.get(url).get_data(as_text=True)).group(1)



@unittest.skipUnless(web is not None, "Flask not installed")
class TestApi(ApiCase):
    # acting as exactly one person ----------------------------------------------------------------------------
    def test_a_token_acts_as_exactly_its_person(self):
        his, hers = self.token("user-1"), self.token("user-2")
        self.assertEqual(self.paths("find?q=*.txt", his),
                         ["store:people/user-1/shared-with-2/plan.txt", "store:people/user-1/taxes.txt"])
        self.assertEqual(self.paths("find?q=*.txt", hers),
                         ["store:people/user-1/shared-with-2/plan.txt", "store:people/user-2/diary.txt"])
        self.assertEqual(self.get("whoami", hers)[1],
                         {"person": "user-2", "display": "User Two", "kind": "person", "scopes": ["read"],
                          "roots": ["store"]})
        # someone else's file is not there at all, by path or by id
        diary = self.file("store", "people/user-2/diary.txt")
        for path in ("where?loc=store:people/user-2/diary.txt", "history?file=%d" % diary, "versions?file=%d" % diary):
            self.assertEqual(self.get(path, his), (404, {"error": "no file you can see there"}))
        self.assertEqual(self.paths("where?loc=store:people/user-2/diary.txt", hers), ["store:people/user-2/diary.txt"])
        self.assertEqual(self.get("only-here?loc=store:people/user-2/", his), (200, {"rows": []}))
        status, body = self.get("safe-to-delete?loc=store:people/user-1/", his)
        self.assertEqual((status, sorted(body)), (200, ["links_into", "not_safe"]))
        # bad arguments and unknown calls answer in JSON
        self.assertEqual(self.get("find", his), (400, {"error": "q=NAME-OR-GLOB is needed"}))
        self.assertEqual(self.get("meta?field=nodot&value=x", his), (400, {"error": "field is SCHEMA.FIELD"}))
        self.assertEqual(self.get("nothing-here", his), (404, {"error": "no such call"}))

    def test_no_token_a_wrong_one_or_a_session_cookie_is_refused(self):
        refused = (401, {"error": "a valid token is needed (Authorization: Bearer ...)"})
        self.assertEqual(self.get("find?q=*"), refused)
        self.assertEqual(self.get("find?q=*", "pinakes_not-a-token"), refused)
        # signed in on the web: the API still wants a token, never the cookie
        c = self.login("user-1")
        self.assertEqual(c.get("/").status_code, 200)
        self.assertEqual(self.get("find?q=*", client=c), refused)
        # an unknown call is refused the same, before it is looked up
        self.assertEqual(self.get("nothing-here"), refused)

    def test_refused_tokens_are_limited_per_address(self):
        good = self.token("user-1")
        for _ in range(web.LOGIN_LIMIT):
            self.assertEqual(self.get("whoami", "pinakes_guess")[0], 401)
        self.assertEqual(self.get("whoami", good)[0], 429)

    # revoked, expired, scopes ------------------------------------------------------------------------------------
    def test_a_revoked_or_expired_token_is_refused(self):
        secret = self.token("user-1", client="laptop-1")
        self.assertEqual(self.get("whoami", secret)[0], 200)
        c = self.login("user-1")
        tid = self.q("SELECT token_id FROM pinakes.tokens WHERE client = 'laptop-1'")[0][0]
        # someone else can't revoke it
        c2 = self.login("user-2")
        page = c2.post("/account", data={"csrf": self.csrf(c2, "/account"), "action": "revoke-token", "token": tid})
        self.assertIn("No such token of yours", page.get_data(as_text=True))
        self.assertEqual(self.get("whoami", secret)[0], 200)
        page = c.post("/account", data={"csrf": self.csrf(c, "/account"), "action": "revoke-token", "token": tid})
        self.assertIn("Token revoked.", page.get_data(as_text=True))
        self.assertEqual(self.get("whoami", secret)[0], 401)
        # expired
        later = self.token("user-1", days=30, client="workstation-1")
        self.assertEqual(self.get("whoami", later)[0], 200)
        self.conn.execute("UPDATE pinakes.tokens SET expires = now() - interval '1 second' "
                          "WHERE client = 'workstation-1'")
        self.assertEqual(self.get("whoami", later)[0], 401)

    def test_a_scope_the_token_lacks_is_refused(self):
        secret = self.token("user-1", scopes=("review",))
        self.assertEqual(self.get("find?q=*", secret),
                         (403, {"error": "this token doesn't have the read scope"}))
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.token("user-1", scopes=("everything",))

    # roots ---------------------------------------------------------------------------------------------------
    def test_protected_roots_are_left_out_unless_named_and_a_limit_hides_the_rest(self):
        his = self.token("user-1")
        # the default: every root but the protected ones (downloads)
        self.assertEqual([r["label"] for r in self.get("roots", his)[1]["rows"]], ["store"])
        self.assertNotIn("downloads:letter.txt", self.paths("find?q=*.txt", his))
        self.assertEqual(self.paths("where?loc=store:people/user-1/taxes.txt", his), ["store:people/user-1/taxes.txt"])
        self.assertEqual(self.get("find?q=letter.txt", his), (200, {"rows": []}))
        # the web session sees both copies
        with self.app_conn() as c:
            c.execute("SELECT set_config('pinakes.person', %s, true)", (str(self.pid("user-1")),))
            n = c.execute("SELECT count(*) FROM pinakes.present WHERE content_id = (SELECT content_id FROM "
                          "pinakes.present WHERE relpath = 'people/user-1/taxes.txt')").fetchone()[0]
        self.assertEqual(n, 2)
        # named: a token for the protected root alone sees it and nothing else
        only = self.token("user-1", roots=[self.root_id("downloads")], client="workstation-1")
        self.assertEqual(self.get("whoami", only)[1]["roots"], ["downloads"])
        self.assertEqual(self.paths("find?q=*.txt", only), ["downloads:letter.txt", "downloads:taxes-copy.txt"])
        self.assertEqual(self.get("where?loc=store:people/user-1/taxes.txt", only)[0], 404)
        self.assertEqual(self.paths("where?loc=downloads:taxes-copy.txt", only), ["downloads:taxes-copy.txt"])
        # a list of roots must name roots
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "not a root list"):
            self.token("user-1", roots=[999999])

    # never a step-up -----------------------------------------------------------------------------------------
    def test_a_token_never_steps_up(self):
        his = self.token("user-1")                      # user-1 is an administrator
        c = self.login("user-1")
        r = c.post("/step-up", data={"csrf": self.csrf(c, "/step-up"), "reason": "checking",
                                     "code": auth.totp(self.secret)})
        self.assertEqual(r.status_code, 302)
        diary = self.file("store", "people/user-2/diary.txt")
        self.assertEqual(c.get("/file/%d" % diary).status_code, 200)        # the web session is stepped up
        self.assertNotIn("store:people/user-2/diary.txt", self.paths("find?q=*.txt", his))
        self.assertEqual(self.get("history?file=%d" % diary, his)[0], 404)
        # no API route changes anything: GET only, but for signing in and out (pinakes --as)
        api = [r for r in self.app.url_map.iter_rules() if r.rule.startswith("/api/")]
        self.assertTrue(api)
        posts = {r.rule for r in api if r.methods - {"HEAD", "OPTIONS"} != {"GET"}}
        self.assertEqual(posts, {"/api/v1/session", "/api/v1/session/end", "/api/v1/review"})
        for rule in api:
            self.assertIn(rule.methods - {"HEAD", "OPTIONS"}, ({"GET"}, {"POST"}), rule.rule)
        # and the database refuses a step-up, or a token, from a token's transaction, whatever the application does
        with self.app_conn() as conn:
            row = conn.execute("SELECT * FROM pinakes.begin_token_call(%s, 'test')",
                               (hashlib.sha256(his.encode()).digest(),)).fetchone()
            self.assertEqual(row[0], self.pid("user-1"))
            self.assertFalse(conn.execute("SELECT pinakes.stepped_up()").fetchone()[0])
            for sql in ("SELECT pinakes.begin_step_up('from a token', 15)",
                        "SELECT pinakes.make_token('x', '\\x00'::bytea, '{read}', NULL, NULL)",
                        "SELECT pinakes.revoke_token(1)"):
                with self.assertRaisesRegex(psycopg.errors.RaiseException, "a token"):
                    with conn.transaction():
                        conn.execute(sql)

    # recorded --------------------------------------------------------------------------------------------------
    def test_every_call_is_recorded_for_the_person(self):
        secret = self.token("user-2", client="laptop-1")
        self.get("find?q=diary*", secret)
        self.get("whoami", secret)
        self.get("whoami", "pinakes_wrong")
        self.assertEqual(self.q("SELECT actor, detail->>'token', detail->>'call' FROM pinakes.audit "
                                "WHERE action = 'api' ORDER BY audit_id"),
                         [(self.pid("user-2"), "laptop-1", "find?q=diary*"),
                          (self.pid("user-2"), "laptop-1", "whoami")])
        c2 = self.login("user-2")
        access = c2.get("/access").get_data(as_text=True)
        self.assertIn("find?q=diary*", access)
        self.assertIn("token made", access)
        account = c2.get("/account").get_data(as_text=True)
        self.assertRegex(account, r"<td>laptop-1</td><td>person</td><td>read</td>"
                                  r"\s*<td>every root but the protected ones</td>"
                                  r"\s*<td>[\d-]+</td><td>never</td>\s*<td>[\d-]+ [\d:]+</td>")
        # nobody else sees them
        c1 = self.login("user-1")
        self.assertNotIn("diary", c1.get("/access").get_data(as_text=True))

    # the account page ----------------------------------------------------------------------------------------
    def test_the_account_page_makes_a_token_shown_once(self):
        c = self.login("user-1")
        form = {"csrf": self.csrf(c, "/account"), "action": "make-token", "client": "laptop-1", "scope": ["read"],
                "roots": "all", "days": "", "current": "wrong"}
        self.assertIn("The current password is wrong.", c.post("/account", data=form).get_data(as_text=True))
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.tokens")[0][0], 0)
        for bad, said in ((dict(scope=[]), "at least one scope"), (dict(client=" "), "Name the client"),
                          (dict(roots="some"), "Tick at least one root"), (dict(days="0"), "1 to 3650 days")):
            page = c.post("/account", data=dict(form, current=PASSWORDS["user-1"], **bad)).get_data(as_text=True)
            self.assertIn(said, page)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.tokens")[0][0], 0)
        page = c.post("/account", data=dict(form, current=PASSWORDS["user-1"], roots="some",
                                            root=[str(self.root_id("store"))], days="90")).get_data(as_text=True)
        secret = re.search(r'Your new token: <span class="mono">(pinakes_[\w-]+)</span>', page).group(1)
        self.assertNotIn(secret, c.get("/account").get_data(as_text=True))           # shown once
        stored = self.q("SELECT secret_sha256, scopes, roots, expires > now() + interval '89 days' FROM pinakes.tokens")
        self.assertEqual(stored, [(hashlib.sha256(secret.encode()).digest(), ["read"], [self.root_id("store")], True)])
        self.assertEqual(self.get("whoami", secret)[1]["roots"], ["store"])

    def test_upgrade_file_matches_the_schema(self):
        defs = ("SELECT (SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || "
                "        coalesce(column_default, '') ORDER BY ordinal_position) FROM information_schema.columns "
                "        WHERE table_schema = 'pinakes' AND table_name = 'tokens'), "
                "(SELECT array_agg(pg_get_constraintdef(oid) ORDER BY pg_get_constraintdef(oid)) FROM pg_constraint "
                " WHERE conrelid = to_regclass('pinakes.tokens')), "
                "(SELECT array_agg(policyname || ':' || cmd || ':' || qual ORDER BY policyname) FROM pg_policies "
                " WHERE schemaname = 'pinakes' AND tablename = 'files'), "
                "(SELECT array_agg(pg_get_functiondef(p.oid) ORDER BY p.proname) FROM pg_proc p "
                " WHERE p.pronamespace = 'pinakes'::regnamespace AND p.proname = ANY (%(fns)s)), "
                "(SELECT array_agg(grantee || ':' || routine_name || ':' || privilege_type "
                "                 ORDER BY grantee, routine_name, privilege_type) "
                " FROM information_schema.routine_privileges WHERE routine_schema = 'pinakes' "
                " AND routine_name = ANY (%(fns)s)), "
                "(SELECT array_agg(grantee || ':' || privilege_type ORDER BY grantee, privilege_type) "
                " FROM information_schema.table_privileges "
                " WHERE table_schema = 'pinakes' AND table_name = 'tokens')")
        new = ["current_token", "token_roots", "begin_token_call", "make_token", "my_tokens", "revoke_token",
               "begin_cli_session", "end_cli_session"]
        args = {"fns": new + ["stepped_up", "begin_step_up", "mark_changes"]}
        with admin_conn(self.db) as c:
            fresh = c.execute(defs, args).fetchone()
            # back to the catalog before it: the old policy, step-up functions and no tokens
            c.execute("DROP POLICY files_visible ON pinakes.files")
            c.execute("CREATE POLICY files_visible ON pinakes.files FOR SELECT USING "
                      "(acl_id = ANY (pinakes.visible_acls()))")
            c.execute("CREATE OR REPLACE FUNCTION pinakes.stepped_up() RETURNS boolean LANGUAGE sql STABLE "
                      "SECURITY DEFINER SET search_path = pinakes AS $$ SELECT false $$")
            c.execute("CREATE OR REPLACE FUNCTION pinakes.begin_step_up(reason text, minutes int DEFAULT 15) "
                      "RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pinakes "
                      "AS $$ SELECT now() $$")
            c.execute("DROP FUNCTION pinakes.token_roots(), pinakes.begin_token_call(bytea, text), "
                      "pinakes.make_token(text, bytea, text[], int[], int), pinakes.my_tokens(), "
                      "pinakes.revoke_token(int), pinakes.begin_cli_session(bytea, int, text), "
                      "pinakes.end_cli_session(), pinakes.current_token() CASCADE")
            c.execute("DROP TABLE pinakes.tokens")
            self.assertNotEqual(c.execute(defs, args).fetchone(), fresh)
            with open(os.path.join(UPGRADES, "api-tokens.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(defs, args).fetchone(), fresh)


# the CLI, as a client of the API (ROADMAP 35) ------------------------------------------------------------------------
class CliRun:
    """pinakes (the CLI) against a real HTTP server on 127.0.0.1, in this process, over the given test database;
    HOME and the client config point into the test's own folder, so no real token or config is ever read."""

    def __init__(self, case, person=None, scopes=("read",), roots=None):
        import threading
        from werkzeug.serving import make_server
        self.case = case
        cfg = server_config.loads('[web]\nsecure_cookies = false\nsession_key = "test-key"\n')
        app = web.create_app(cfg, connect=lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=case.db))
        self.app = app
        self.server = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_port
        self.home = tempfile.mkdtemp(prefix="home-", dir=case.tmp)
        self.client_toml = os.path.join(self.home, "client.toml")
        with open(self.client_toml, "w") as f:
            f.write('[client]\nurl = "%s"\n' % self.url)
        self.env = mock.patch.dict(os.environ, {"HOME": self.home, "PINAKES_CLIENT_CONFIG": self.client_toml,
                                                "PINAKES_AGENT_CONFIG": os.path.join(self.home, "none.toml")})
        self.env.start()
        if person:
            self.save(self.home_token(), make_token(case, person, scopes, roots))

    def home_token(self):
        return os.path.join(self.home, ".config", "pinakes", "token")

    @staticmethod
    def save(path, secret, mode=0o600):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(secret + "\n")
        os.chmod(path, mode)

    def close(self):
        self.env.stop()
        self.server.shutdown()
        self.server.server_close()

    def __call__(self, *args, cwd=None, code=0):
        """Run it; its output, or with code != 0 the message it exited with."""
        from pinakes import cli
        out = io.StringIO()
        old = os.getcwd()
        try:
            if cwd:
                os.chdir(cwd)
            with contextlib.redirect_stdout(out):
                try:
                    rc = cli.main(list(args))
                except SystemExit as e:
                    rc = e.code if isinstance(e.code, int) else 1
                    if code:
                        self.out = out.getvalue()                       # what it printed before it stopped
                        return str(e.code)
            self.case.assertEqual(rc, code, out.getvalue())
        finally:
            os.chdir(old)
        return out.getvalue()


def make_token(case, person, scopes=("read",), roots=None, client="laptop-1"):
    """A token for a person, made as the account page makes one; its secret."""
    secret = "pinakes_test_%s_%s" % (person, os.urandom(8).hex())
    with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=case.db) as c:
        pid = c.execute("SELECT person_id FROM pinakes.people WHERE name = %s", (person,)).fetchone()[0]
        c.execute("SELECT set_config('pinakes.person', %s, true)", (str(pid),))
        c.execute("SELECT pinakes.make_token(%s, %s, %s, %s, NULL)",
                  (client, hashlib.sha256(secret.encode()).digest(), list(scopes), roots))
    return secret


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCli(ServerCase):
    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.scan("server-1", "store")
        self.cli = CliRun(self, "user-1")
        self.addCleanup(self.cli.close)

    def test_every_query_through_the_api(self):
        """Each query of DESIGN.md "Queries", and roots, as the token's person."""
        cli = self.cli
        self.assertIn("people/user-1/taxes.txt", cli("find", "*.txt"))
        self.assertNotIn("diary", cli("find", "*.txt"))
        for cmd in ("where", "history", "versions", "lineage"):
            self.assertEqual(cli(cmd, "store:people/user-2/diary.txt", code=1),
                             "pinakes: no file you can see there")
        self.assertIn("people/user-1/taxes.txt", cli("where", "store:people/user-1/taxes.txt"))
        self.assertIn("new", cli("history", "store:people/user-1/taxes.txt"))
        self.assertEqual(len(json.loads(cli("versions", "store:people/user-1/taxes.txt", "--json"))), 1)
        self.assertEqual(json.loads(cli("lineage", "store:people/user-1/taxes.txt", "--down", "--json")), [])
        self.assertIn("people/user-1/taxes.txt", cli("only-here", "store:people/user-1/"))
        self.assertIn("people/user-1/taxes.txt", cli("safe-to-delete", "store:people/user-1/"))
        self.assertEqual(sorted(json.loads(cli("safe-to-delete", "store:people/user-1/", "--json"))),
                         ["links_into", "not_safe"])
        self.assertIn("people/user-1/taxes.txt", cli("backed-up", "store:people/user-1/"))
        self.assertEqual(cli("dupes"), "(none)\n")
        changes = cli("changes", "--days", "3", "--host", "server-1")
        self.assertIn("people/user-1/taxes.txt", changes)
        self.assertNotIn("diary", changes)
        self.assertIn("(none)", cli("meta", "dc.title=nothing"))
        self.assertEqual(cli("meta", "dc.title", code=1), "pinakes: pinakes meta needs SCHEMA.FIELD=VALUE")
        self.assertEqual(cli("stale").split()[:4], ["name", "last_scan", "expected_every", "server-2"])  # never seen
        roots = cli("roots").splitlines()
        self.assertEqual(roots[0].split(), ["label", "host", "kind", "protected", "last_complete_on", "files",
                                            "hidden_files"])
        self.assertEqual(roots[1].split()[:3], ["store", "server-1", "primary"])
        # times come back as ISO 8601 and are shown in this machine's time zone, as before
        row = json.loads(cli("where", "store:people/user-1/taxes.txt", "--json"))[0]
        mtime = datetime.datetime.fromisoformat(row["mtime"]).astimezone().strftime("%Y-%m-%d %H:%M")
        self.assertIn(mtime, cli("where", "store:people/user-1/taxes.txt"))

    def test_another_person_sees_their_own(self):
        self.cli.save(self.cli.home_token(), make_token(self, "user-2", client="laptop-2"))
        found = self.cli("find", "*.txt")
        self.assertIn("diary.txt", found)
        self.assertIn("plan.txt", found)                                # shared with user-2
        self.assertNotIn("taxes.txt", found)

    def test_the_token_is_found_in_its_order(self):
        """A .pinakes-token in the current folder or one above it comes before the home token; the first found is
        used, alone."""
        cli = self.cli
        top = os.path.join(self.tmp, "work")
        deep = os.path.join(top, "a", "b")
        os.makedirs(deep)
        self.assertIn("taxes.txt", cli("find", "*.txt", cwd=deep))      # the home token: user-1
        cli.save(os.path.join(top, ".pinakes-token"), make_token(self, "user-2", client="workstation-1"))
        found = cli("find", "*.txt", cwd=deep)                          # the folder above: user-2
        self.assertIn("diary.txt", found)
        self.assertNotIn("taxes.txt", found)
        cli.save(os.path.join(deep, ".pinakes-token"), make_token(self, "user-1", client="laptop-2"))
        self.assertIn("taxes.txt", cli("find", "*.txt", cwd=deep))      # the nearest wins
        self.assertIn("diary.txt", cli("find", "*.txt", cwd=os.path.join(top, "a")))
        # none anywhere
        os.remove(cli.home_token())
        self.assertIn("pinakes: no token: make one on the account page", cli("find", "*", cwd=self.tmp, code=1))

    def test_a_token_file_others_can_read_is_refused(self):
        cli = self.cli
        for mode in (0o640, 0o604, 0o660):
            os.chmod(cli.home_token(), mode)
            msg = cli("roots", cwd=self.tmp, code=1)
            self.assertEqual(msg, "pinakes: %s can be read by others: chmod 600 it, and revoke the token if anyone "
                                  "could have copied it" % cli.home_token())
        os.chmod(cli.home_token(), 0o400)
        self.assertIn("store", cli("roots", cwd=self.tmp))
        # refused, not skipped: an open folder token doesn't fall through to the home token
        folder = os.path.join(self.tmp, "open")
        os.makedirs(folder)
        cli.save(os.path.join(folder, ".pinakes-token"), "pinakes_whatever", mode=0o644)
        self.assertIn("can be read by others", cli("roots", cwd=folder, code=1))
        os.remove(os.path.join(folder, ".pinakes-token"))
        os.makedirs(os.path.join(folder, ".pinakes-token"))
        self.assertIn("is not a file", cli("roots", cwd=folder, code=1))

    def test_a_revoked_or_wrong_token_and_the_address(self):
        cli = self.cli
        cli.save(cli.home_token(), "pinakes_not-a-token")
        self.assertIn("a valid token is needed", cli("roots", cwd=self.tmp, code=1))
        self.assertIn("may be revoked or expired", cli("roots", cwd=self.tmp, code=1))
        # plain http only to this machine; no address at all
        cli.save(cli.home_token(), make_token(self, "user-1", client="workstation-1"))
        self.assertEqual(cli("--url", "http://192.0.2.10:8080", "roots", cwd=self.tmp, code=1),
                         "pinakes: http://192.0.2.10:8080: the token would cross the network unencrypted; use https")
        with open(cli.client_toml, "w") as f:
            f.write("[client]\n")
        self.assertIn("no catalog address", cli("roots", cwd=self.tmp, code=1))
        self.assertIn("store", cli("--url", cli.url, "roots", cwd=self.tmp))
        self.assertIn("can't reach the catalog", cli("--url", "http://127.0.0.1:9", "roots", cwd=self.tmp, code=1))

    def test_no_database_access_on_the_client(self):
        """The CLI's person commands need no database driver and no server config: psycopg can't be imported and
        no server.toml exists, and the questions are still answered."""
        script = ("import sys; sys.modules['psycopg'] = None; sys.path.insert(0, %r)\n"
                  "from pinakes import cli\nsys.exit(cli.main(['find', '*.txt']))" % TOP)
        env = dict(os.environ, PINAKES_CONFIG=os.path.join(self.tmp, "no-server.toml"))
        r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env, cwd=self.tmp,
                           timeout=60)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertIn("people/user-1/taxes.txt", r.stdout)
        import pinakes.cli
        with open(pinakes.cli.__file__) as f:
            src = f.read()
        self.assertNotIn("set_config", src)                             # no person set by the CLI itself

    def test_the_example_client_config(self):
        from pinakes import cli
        cfg = cli.client_config(os.path.join(TOP, "client.example.toml"))
        self.assertEqual(cfg, {"url": "https://pinakes.example.net"})
        cli.Api(cfg["url"], "pinakes_x")                                # an address the client accepts


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCliHere(ServerCase):
    """The commands from inside a folder (ROADMAP 33): a path here, or none for the current folder, as well as
    ROOT:PATH."""

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.scan("server-1", "store")
        self.cli = CliRun(self, "user-1")
        self.addCleanup(self.cli.close)
        with open(self.cli.client_toml, "a") as f:
            f.write('host = "server-1"\n')                              # this machine's name in the catalog
        self.mine = self.path("server-1", "store", "people/user-1")
        self.outside = os.path.join(self.tmp, "elsewhere")
        os.makedirs(self.outside)

    def test_each_command_from_inside_a_folder_and_given_one(self):
        cli, mine = self.cli, self.mine
        self.assertIn("people/user-1/taxes.txt", cli("where", "taxes.txt", cwd=mine))
        self.assertIn("new", cli("history", "taxes.txt", cwd=mine))
        self.assertEqual(len(json.loads(cli("versions", "taxes.txt", "--json", cwd=mine))), 1)
        self.assertEqual(json.loads(cli("lineage", "taxes.txt", "--down", "--json", cwd=mine)), [])
        here = [r["relpath"] for r in json.loads(cli("only-here", "--json", cwd=mine))]
        self.assertEqual(sorted(here), ["people/user-1/shared-with-2/plan.txt", "people/user-1/taxes.txt"])
        self.assertEqual([r["relpath"] for r in json.loads(cli("only-here", "shared-with-2", "--json", cwd=mine))],
                         ["people/user-1/shared-with-2/plan.txt"])
        self.assertIn("people/user-1/taxes.txt", cli("safe-to-delete", cwd=mine))
        self.assertIn("people/user-1/taxes.txt", cli("backed-up", cwd=mine))
        changes = cli("changes", cwd=mine)
        self.assertTrue(changes.startswith("changes under store:people/user-1 in the last 7 days:\n"), changes)
        self.assertIn("people/user-1/taxes.txt", changes)
        # given the folder or the file from somewhere else, by its path here, or as ROOT:PATH as before
        self.assertIn("people/user-1/taxes.txt", cli("only-here", mine, cwd=self.outside))
        self.assertIn("people/user-1/taxes.txt", cli("where", os.path.join(mine, "taxes.txt"), cwd=self.outside))
        self.assertIn("people/user-1/taxes.txt", cli("only-here", "store:people/user-1/", cwd=self.outside))
        self.assertIn("people/user-1/taxes.txt", cli("changes", mine, cwd=self.outside))
        # the whole root, from its top
        self.assertIn("people/user-1/taxes.txt", cli("only-here", cwd=self.path("server-1", "store", "")))

    def test_a_file_for_a_folder_report_and_a_folder_for_a_file(self):
        cli, mine = self.cli, self.mine
        # a folder report given a file answers for that file (nothing under a file would read as safe)
        for cmd in ("only-here", "safe-to-delete", "backed-up"):
            self.assertIn("people/user-1/taxes.txt", cli(cmd, "taxes.txt", cwd=mine))
            self.assertIn("people/user-1/taxes.txt", cli(cmd, "store:people/user-1/taxes.txt", cwd=self.outside))
        self.assertNotIn("plan.txt", cli("only-here", "taxes.txt", cwd=mine))
        for cmd in ("where", "history", "versions", "lineage"):
            self.assertEqual(cli(cmd, cwd=mine, code=1), "pinakes: pinakes %s needs a file; . is a folder" % cmd)
        self.assertIn("people/user-1/taxes.txt", cli("changes", "taxes.txt", cwd=mine))      # a file's own
        self.assertEqual(cli("where", "nothing.txt", cwd=mine, code=1),
                         "pinakes: nothing.txt is neither a path here nor ROOT:PATH")

    def test_a_folder_outside_every_root_is_refused(self):
        cli = self.cli
        with open(os.path.join(self.outside, "note.txt"), "w") as f:
            f.write("not scanned")
        refused = "pinakes: %s is not inside a root that server-1 reports; `pinakes roots` lists them"
        for cmd in ("only-here", "safe-to-delete", "backed-up"):
            self.assertEqual(cli(cmd, cwd=self.outside, code=1), refused % os.path.realpath(self.outside))
        self.assertEqual(cli("where", "note.txt", cwd=self.outside, code=1),
                         refused % os.path.join(os.path.realpath(self.outside), "note.txt"))
        self.assertEqual(cli("changes", ".", cwd=self.outside, code=1), refused % os.path.realpath(self.outside))
        # changes with no folder, outside every root: everything you can see, as before
        everything = cli("changes", cwd=self.outside)
        self.assertTrue(everything.startswith("changes everywhere you can see in the last 7 days:\n"))
        self.assertIn("people/user-1/taxes.txt", everything)
        # another machine's name: its roots, not this one's
        self.assertIn("not inside a root that laptop-1 reports",
                      cli("only-here", "--host", "laptop-1", cwd=self.mine, code=1))

    def test_another_persons_files_are_left_out(self):
        cli = self.cli
        theirs = self.path("server-1", "store", "people/user-2")
        self.assertEqual(cli("only-here", cwd=theirs), "(none)\n")
        self.assertEqual(cli("safe-to-delete", cwd=theirs),
                         "safe: every file under store:people/user-2 has a kept copy on another disk\n")
        self.assertEqual(cli("where", "diary.txt", cwd=theirs, code=1), "pinakes: no file you can see there")
        self.assertNotIn("diary", cli("changes", cwd=theirs))
        self.assertNotIn("diary", cli("changes", cwd=self.path("server-1", "store", "people")))
        self.assertIn("store:people/user-2: 0 file(s) you can see", cli(cwd=theirs))

    def test_bare_pinakes_sums_up_the_folder(self):
        cli = self.cli
        self.assertEqual(cli(cwd=self.mine), "store:people/user-1: 2 file(s) you can see, 2 with no backup, 2 with "
                                             "no copy on another disk, 2 change(s) in the last 7 days\n"
                                             "(pinakes --help for the commands)\n")
        # outside every root: how to use it, and why not here
        self.assertIn("is not inside a root that server-1 reports", cli(cwd=self.outside, code=1))
        self.assertTrue(cli.out.startswith("usage: pinakes "), cli.out)


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCliAs(ServerCase):
    """pinakes --as NAME (ROADMAP 36): signs in as NAME with their secret, for one command, seeing only their view."""

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.scan("server-1", "store")
        self.secret = auth.new_totp_secret()
        for name, totp in (("user-1", self.secret), ("user-2", None)):
            pid = self.q("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))[0][0]
            self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash, totp_secret) "
                              "VALUES (%s, %s, %s)", (pid, auth.hash_password(PASSWORDS[name]), totp))
        self.cli = CliRun(self, "user-1")                               # the caller's own token: user-1's
        self.addCleanup(self.cli.close)

    def as_(self, *args, answers, code=0):
        """Run pinakes with --as, the hidden prompts answered in turn; (output, the prompts asked)."""
        with mock.patch("getpass.getpass", side_effect=list(answers)) as asked:
            out = self.cli(*args, cwd=self.tmp, code=code)
        return out, [c.args[0] for c in asked.call_args_list]

    def test_the_session_sees_exactly_the_named_persons_files(self):
        before = sorted(os.listdir(self.cli.home))
        out, asked = self.as_("--as", "user-2", "find", "*.txt", answers=[PASSWORDS["user-2"], ""])
        self.assertEqual(asked, ["user-2's password, or a token of theirs: ",
                                 "user-2's second-factor code (empty if they have none): "])
        self.assertIn("people/user-2/diary.txt", out)
        self.assertIn("people/user-1/shared-with-2/plan.txt", out)     # shared with user-2
        self.assertNotIn("taxes.txt", out)                              # the caller's own, not added
        self.assertEqual(sorted(os.listdir(self.cli.home)), before)     # nothing written down
        # the session: read only, minutes long, ended by its command, not among the person's tokens
        self.assertEqual(self.q("SELECT p.name, t.scopes, t.expires <= now() + interval '10 minutes', "
                                "t.revoked IS NOT NULL FROM pinakes.tokens t JOIN pinakes.people p USING (person_id) "
                                "WHERE t.cli_session"), [("user-2", ["read"], True, True)])
        with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
            c.execute("SELECT set_config('pinakes.person', %s, true)",
                      (str(self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-2'")[0][0]),))
            self.assertEqual(c.execute("SELECT count(*) FROM pinakes.my_tokens()").fetchone()[0], 0)

    def test_the_callers_own_token_is_not_read(self):
        os.chmod(self.cli.home_token(), 0o644)                          # would be refused if it were read
        self.assertIn("can be read by others", self.cli("roots", cwd=self.tmp, code=1))
        out, _ = self.as_("--as", "user-2", "roots", answers=[PASSWORDS["user-2"], ""])
        self.assertIn("store", out)

    def test_the_second_factor_when_the_person_has_one(self):
        no_code, _ = self.as_("--as", "user-1", "roots", answers=[PASSWORDS["user-1"], ""], code=1)
        self.assertEqual(no_code, "pinakes: that name, password and code don't match")
        out, _ = self.as_("--as", "user-1", "find", "*.txt", answers=[PASSWORDS["user-1"], auth.totp(self.secret)])
        self.assertIn("taxes.txt", out)

    def test_a_wrong_secret_is_refused_and_limited_like_the_web_sign_in(self):
        for name, pw in (("user-2", "wrong"), ("nobody", "whatever"), ("user-1", PASSWORDS["user-2"])):
            out, _ = self.as_("--as", name, "roots", answers=[pw, ""], code=1)
            self.assertEqual(out, "pinakes: that name, password and code don't match")
        for _ in range(web.LOGIN_LIMIT - 3):
            self.as_("--as", "user-2", "roots", answers=["wrong", ""], code=1)
        out, _ = self.as_("--as", "user-2", "roots", answers=[PASSWORDS["user-2"], ""], code=1)
        self.assertEqual(out, "pinakes: too many attempts; wait a few minutes")
        # the web sign-in from that address is held by the same count
        c = self.cli.app.test_client()
        page = c.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        r = c.post("/login", data={"csrf": csrf, "name": "user-2", "password": PASSWORDS["user-2"]},
                   environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.tokens WHERE cli_session")[0][0], 0)

    def test_a_token_of_theirs_and_one_that_isnt(self):
        theirs = make_token(self, "user-2", client="laptop-2")
        out, asked = self.as_("--as", "user-2", "find", "*.txt", answers=[theirs])
        self.assertEqual(len(asked), 1)                                 # no second factor asked for a token
        self.assertIn("diary.txt", out)
        mine = make_token(self, "user-1", client="laptop-3")
        out, _ = self.as_("--as", "user-2", "find", "*.txt", answers=[mine], code=1)
        self.assertEqual(out, "pinakes: that token is not user-2's")

    def test_the_person_sees_the_sign_in_and_it_never_steps_up(self):
        # user-1, an administrator, in a web step-up: --as user-1 still sees only their own
        c = self.cli.app.test_client()
        page = c.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        c.post("/login", data={"csrf": csrf, "name": "user-1", "password": PASSWORDS["user-1"]})
        csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/step-up").get_data(as_text=True)).group(1)
        self.assertEqual(c.post("/step-up", data={"csrf": csrf, "reason": "checking",
                                                  "code": auth.totp(self.secret)}).status_code, 302)
        self.assertEqual(c.get("/file/%d" % self.file("store", "people/user-2/diary.txt")).status_code, 200)
        out, _ = self.as_("--as", "user-1", "find", "*.txt", answers=[PASSWORDS["user-1"], auth.totp(self.secret)])
        self.assertNotIn("diary.txt", out)
        # user-2's page shows the sign-in from the CLI, and what the session asked
        self.as_("--as", "user-2", "find", "diary*", answers=[PASSWORDS["user-2"], ""])
        c2 = self.cli.app.test_client()
        page = c2.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        c2.post("/login", data={"csrf": csrf, "name": "user-2", "password": PASSWORDS["user-2"]})
        access = c2.get("/access").get_data(as_text=True)
        self.assertIn("cli sign in", access)
        self.assertIn("from: 127.0.0.1", access)
        self.assertIn("call: find?q=diary*; token: pinakes --as", access)


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCliReview(ServerCase):
    """pinakes review intended|restore [PATH] (ROADMAP 37): from inside a folder, through mark_changes() and its
    rules, with the token's review scope and roots."""

    U = "people/user-1/"

    def setUp(self):
        super().setUp()
        self.scfg = server_config.loads(SERVER + """
[[ownership.enrollment]]
root = "store"
folder = "people/user-1/team"
person = "user-2"
as = "co-owner"
""")
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        for rel in ("cleanup/a.txt", "cleanup/b.txt", "cleanup/moved.txt", "team/t.txt", "shared-with-2/plan.txt"):
            self.write("server-1", "store", self.U + rel, b"content " + rel.encode())
        self.write("laptop-1", "downloads", "d.txt", b"downloads")
        self.scan("server-1", "store")
        self.scan("laptop-1", "downloads")
        for rel in ("cleanup/a.txt", "cleanup/b.txt", "team/t.txt", "shared-with-2/plan.txt"):
            os.remove(self.path("server-1", "store", self.U + rel))
        os.makedirs(self.path("server-1", "store", self.U + "kept"))
        os.rename(self.path("server-1", "store", self.U + "cleanup/moved.txt"),
                  self.path("server-1", "store", self.U + "kept/moved.txt"))
        os.remove(self.path("laptop-1", "downloads", "d.txt"))
        self.scan("server-1", "store")
        self.scan("laptop-1", "downloads")
        self.folder = self.path("server-1", "store", self.U + "cleanup")
        self.cli = None

    def as_(self, person, scopes=("read", "review"), roots=None):
        if self.cli:
            self.cli.close()
        self.cli = CliRun(self, person, scopes, roots)
        self.addCleanup(lambda: self.cli and self.cli.close())
        with open(self.cli.client_toml, "a") as f:
            f.write('host = "server-1"\n')
        return self.cli

    def marks(self):
        return dict(self.q("SELECT coalesce(hi.new_relpath, hi.old_relpath), m.mark FROM pinakes.review_marks m "
                           "JOIN pinakes.history hi USING (history_id)"))

    def test_the_owner_marks_from_inside_the_folder_once_asked(self):
        cli = self.as_("user-1")
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="n"):
            out = cli("review", "intended", cwd=self.folder)
        self.assertIn("3 unreviewed gone file(s) and move(s) under store:people/user-1/cleanup", out)
        self.assertTrue(out.endswith("not marked\n"), out)
        self.assertEqual(self.marks(), {})
        with mock.patch("sys.stdin.isatty", return_value=True), \
                mock.patch("builtins.input", return_value="y") as asked:
            out = cli("review", "intended", cwd=self.folder)
        self.assertEqual(asked.call_args.args[0], "Mark these 3 as intended? [y/N] ")
        self.assertIn("marked 3 of 3 as intended", out)
        self.assertEqual(self.marks(), {self.U + "cleanup/a.txt": "intended", self.U + "cleanup/b.txt": "intended",
                                        self.U + "kept/moved.txt": "intended"})
        self.assertEqual(cli("review", "intended", cwd=self.folder),
                         "nothing to review under store:people/user-1/cleanup in the last 7 days\n")
        # not asked without a terminal unless --yes; one file by its ROOT:PATH (gone: not a path here any more)
        self.assertIn("add --yes", cli("review", "restore", "store:" + self.U + "team/t.txt", code=1))
        out = cli("review", "restore", "store:" + self.U + "team/t.txt", "--yes", cwd=self.folder)
        self.assertIn("marked 1 of 1 as restore", out)
        self.assertEqual(self.marks()[self.U + "team/t.txt"], "restore")
        # shown on the web, on the restore list
        c = cli.app.test_client()
        page = c.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) SELECT person_id, %s "
                          "FROM pinakes.people WHERE name = 'user-1'", (auth.hash_password(PASSWORDS["user-1"]),))
        c.post("/login", data={"csrf": csrf, "name": "user-1", "password": PASSWORDS["user-1"]})
        self.assertIn(self.U + "team/t.txt", c.get("/reports/restore").get_data(as_text=True))
        changes = c.get("/reports/changes?loc=store:" + self.U + "cleanup/").get_data(as_text=True)
        self.assertIn("intended", changes)

    def test_a_co_owner_marks_and_a_reader_cant(self):
        cli = self.as_("user-2")
        team = "store:" + self.U + "team/"
        out = cli("review", "intended", team, "--yes", cwd=self.tmp)
        self.assertIn("marked 1 of 1 as intended", out)                 # co-owner of team/
        self.assertEqual(self.marks(), {self.U + "team/t.txt": "intended"})
        shared = "store:" + self.U + "shared-with-2/"
        out = cli("review", "intended", shared, "--yes", cwd=self.tmp)  # a reader sees the gone file, can't mark it
        self.assertIn("marked 0 of 1 as intended", out)
        self.assertIn("not yours or co-owned", out)
        self.assertNotIn(self.U + "shared-with-2/plan.txt", self.marks())

    def test_a_token_without_the_scope_or_outside_its_roots(self):
        cli = self.as_("user-1", scopes=("read",))
        self.assertEqual(cli("review", "intended", "--yes", cwd=self.folder, code=1),
                         "pinakes: this token doesn't have the review scope")
        self.assertEqual(self.marks(), {})
        # limited to downloads: the store's changes are out of sight, and their ids out of reach
        ids = [r[0] for r in self.q("SELECT history_id FROM pinakes.history WHERE kind = 'gone' "
                                    "AND old_relpath LIKE %s", (self.U + "cleanup/%",))]
        cli = self.as_("user-1", roots=[self.q("SELECT root_id FROM pinakes.roots WHERE label = 'downloads'")[0][0]])
        self.assertIn("not inside a root that server-1 reports", cli("review", "intended", "--yes", cwd=self.folder,
                                                                     code=1))
        self.assertEqual(cli("review", "intended", "store:" + self.U + "cleanup/", "--yes", cwd=self.tmp),
                         "nothing to review under store:people/user-1/cleanup/ in the last 7 days\n")
        status, body = self.post(cli, "review", {"mark": "intended", "ids": ids})
        self.assertEqual((status, body), (200, {"asked": 2, "marked": 0}))
        self.assertEqual(self.marks(), {})
        out = cli("review", "intended", "downloads:", "--yes", cwd=self.tmp)
        self.assertIn("marked 1 of 1 as intended", out)                 # its own root, yes
        # and the database itself refuses a token without the scope, whatever the application asks
        secret = make_token(self, "user-1", scopes=("read",), client="workstation-1")
        with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
            c.execute("SELECT * FROM pinakes.begin_token_call(%s, 'test')", (hashlib.sha256(secret.encode()).digest(),))
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "review scope"):
                c.execute("SELECT pinakes.mark_changes(%s, 'intended')", (ids,))

    def post(self, cli, call, body):
        import urllib.request
        with open(cli.home_token()) as f:
            token = f.read().strip()
        req = urllib.request.Request(cli.url + "/api/v1/" + call, data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)


@unittest.skipUnless(web is not None, "Flask not installed")
class TestOpsToken(ApiCase):
    """Ops tokens (ROADMAP 39): an operator's, acting as no person: releases and stale, and nothing that names a
    file, a root or a person."""

    def test_an_operator_makes_one_on_the_account_page_and_others_cant(self):
        c = self.login("user-1")                                        # an operator
        page = c.post("/account", data={"csrf": self.csrf(c, "/account"), "action": "make-ops-token",
                                        "client": "deploy", "days": "", "current": PASSWORDS["user-1"]})
        text = page.get_data(as_text=True)
        self.assertIn("Ops token made for deploy.", text)
        secret = re.search(r'Your new token: <span class="mono">(pinakes_[\w-]+)</span>', text).group(1)
        self.assertEqual(self.get("whoami", secret)[1], {"person": None, "kind": "ops", "scopes": ["ops"],
                                                         "roots": []})
        self.assertIn("<td>deploy</td><td>ops</td><td>ops</td>\n    <td>none</td>",
                      c.get("/account").get_data(as_text=True))
        # someone who isn't an operator: no form, refused by the page and by the database
        c2 = self.login("user-2")
        self.assertNotIn("make-ops-token", c2.get("/account").get_data(as_text=True))
        page = c2.post("/account", data={"csrf": self.csrf(c2, "/account"), "action": "make-ops-token",
                                         "client": "deploy", "days": "", "current": PASSWORDS["user-2"]})
        self.assertIn("Only an operator makes ops tokens.", page.get_data(as_text=True))
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "only an operator"):
            self.token("user-2", scopes=("ops",))
        # ops alone, and no roots
        for scopes, roots in ((("ops", "read"), None), (("ops",), [self.root_id("store")])):
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "the ops scope alone"):
                self.token("user-1", scopes=scopes, roots=roots)

    def test_it_answers_releases_and_stale_and_nothing_else(self):
        ops = self.token("user-1", scopes=("ops",), client="deploy")
        status, got = self.get("releases", ops)
        self.assertEqual(status, 200)
        self.assertEqual(sorted(got), ["agents", "server"])
        self.assertTrue(got["server"]["schema_applied"])
        self.assertEqual(sorted(a["host"] for a in got["agents"]), ["laptop-1", "server-1", "server-2"])
        self.assertEqual(self.get("stale", ops)[0], 200)
        # every other call, now and later: refused
        answered = {"whoami", "releases", "stale"}
        args = "?q=*&loc=store:people/user-1/&file=1&host=server-1&field=dc.title&value=x"
        calls = [r.rule[len("/api/v1/"):] for r in self.app.url_map.iter_rules()
                 if r.rule.startswith("/api/v1/") and "GET" in r.methods]
        self.assertGreater(len(calls), 15)
        for call in calls:
            if call not in answered:
                self.assertEqual(self.get(call + args, ops)[0], 403, call)
        r = self.app.test_client().post("/api/v1/review", json={"mark": "intended", "ids": [1]},
                                        headers={"Authorization": "Bearer " + ops})
        self.assertEqual(r.status_code, 403)
        # and a person's token doesn't get releases
        self.assertEqual(self.get("releases", self.token("user-1")),
                         (403, {"error": "this token doesn't have the ops scope"}))

    def test_the_database_gives_it_no_person(self):
        ops = self.token("user-1", scopes=("ops",), client="deploy")
        self.get("stale", ops)
        # its calls are its maker's record
        self.assertEqual(self.q("SELECT p.name, a.detail->>'token', a.detail->>'call' FROM pinakes.audit a "
                                "JOIN pinakes.people p ON p.person_id = a.actor WHERE a.action = 'api'"),
                         [("user-1", "deploy", "stale")])
        with self.app_conn() as conn:
            row = conn.execute("SELECT * FROM pinakes.begin_token_call(%s, 'test')",
                               (hashlib.sha256(ops.encode()).digest(),)).fetchone()
            self.assertEqual(row, (None, ["ops"]))
            self.assertEqual(conn.execute("SELECT pinakes.current_person(), count(*) FROM pinakes.files")
                             .fetchone(), (None, 0))
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "no person set"):
                conn.execute("SELECT pinakes.mark_changes('{1}', 'intended')")
