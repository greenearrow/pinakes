"""The JSON API and person tokens (ROADMAP 34), through Flask's test client, on a catalog built by real scans."""

import contextlib
import csv
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from pinakes import compat, queries
from pinakes.ingest import Ingester, schema_missing
from tests.test_server import PGHOST, SERVER, UPGRADES, ServerCase, admin_conn, psycopg, replaced_function

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from pinakes import auth, server_config, web
except ImportError:  # Flask missing
    web = None

NONE = {"rows": [], "total": 0, "limit": 100, "offset": 0}         # an empty list's answer (ROADMAP 61)
PASSWORDS = {"user-1": "correct horse battery", "user-2": "staple pony 12345", "user-3": "kettle lantern 909"}


@unittest.skipUnless(web is not None, "Flask not installed")
class ApiCase(ServerCase):
    """A catalog by real scans, an app, and the helpers to make tokens and call the API."""

    SERVER_EXTRA = ""                   # more of server.toml, for a class that needs other people, rules or groups

    def setUp(self):
        super().setUp()
        if self.SERVER_EXTRA:
            self.scfg = server_config.loads(SERVER + self.SERVER_EXTRA)
            self.ing = Ingester(self.conn, self.scfg)
            self.ing.seed()
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

    def token(self, name, scopes=("read",), roots=None, days=None, client="laptop-1", group=None):
        """A token made the way the account page makes one: as the person, through make_token(); with `group`, a
        group token of that group (ROADMAP 38)."""
        secret = "pinakes_test_%s_%s" % (name, os.urandom(8).hex())
        with self.app_conn() as c:
            c.execute("SELECT set_config('pinakes.person', %s, true)", (str(self.pid(name)),))
            c.execute("SELECT pinakes.make_token(%s, %s, %s, %s, %s, %s)",
                      (client, hashlib.sha256(secret.encode()).digest(), list(scopes), roots, days,
                       self.gid(group) if group else None))
        return secret

    def gid(self, name):
        return self.q("SELECT group_id FROM pinakes.groups WHERE name = %s", (name,))[0][0]

    def check_upgrade_matches_the_schema(self):
        """api-tokens.sql, run on the catalog as it was before release 5, gives what schema.sql gives: the tables,
        constraints, policy, functions and grants it touches, and the groups each ACL names."""
        tables = ["tokens", "acl_groups", "review_marks"]
        defs = ("SELECT (SELECT array_agg(table_name || ':' || column_name || ':' || data_type || ':' || is_nullable "
                "        || ':' || coalesce(column_default, '') ORDER BY table_name, ordinal_position) "
                "        FROM information_schema.columns "
                "        WHERE table_schema = 'pinakes' AND table_name = ANY (%(tables)s)), "
                "(SELECT array_agg(conrelid::regclass || ':' || pg_get_constraintdef(oid) "
                "                  ORDER BY conrelid::regclass::text, pg_get_constraintdef(oid)) FROM pg_constraint "
                " WHERE conrelid = ANY (SELECT to_regclass('pinakes.' || t) FROM unnest(%(tables)s::text[]) t)), "
                "(SELECT array_agg(indexdef ORDER BY indexdef) FROM pg_indexes "
                " WHERE schemaname = 'pinakes' AND tablename = ANY (%(tables)s)), "
                "(SELECT array_agg(policyname || ':' || cmd || ':' || qual ORDER BY policyname) FROM pg_policies "
                " WHERE schemaname = 'pinakes' AND tablename = 'files'), "
                "(SELECT array_agg(pg_get_functiondef(p.oid) ORDER BY p.proname) FROM pg_proc p "
                " WHERE p.pronamespace = 'pinakes'::regnamespace AND p.proname = ANY (%(fns)s)), "
                "(SELECT array_agg(grantee || ':' || routine_name || ':' || privilege_type "
                "                 ORDER BY grantee, routine_name, privilege_type) "
                " FROM information_schema.routine_privileges WHERE routine_schema = 'pinakes' "
                " AND routine_name = ANY (%(fns)s)), "
                "(SELECT array_agg(table_name || ':' || grantee || ':' || privilege_type "
                "                  ORDER BY table_name, grantee, privilege_type) "
                " FROM information_schema.table_privileges "
                " WHERE table_schema = 'pinakes' AND table_name = ANY (%(tables)s))")
        groups = ("SELECT array_agg(a.acl_key || ':' || g.name || ':' || ag.role ORDER BY a.acl_key, g.name) "
                  "FROM pinakes.acl_groups ag JOIN pinakes.acls a USING (acl_id) JOIN pinakes.groups g USING (group_id)")
        new = ["current_token", "token_roots", "begin_token_call", "make_token", "my_tokens", "revoke_token",
               "begin_cli_session", "end_cli_session", "current_group", "my_groups"]
        args = {"fns": new + ["stepped_up", "begin_step_up", "mark_changes", "visible_acls", "sensitive_visible"],
                "tables": tables}
        with admin_conn(self.db) as c:
            fresh = c.execute(defs, args).fetchone() + c.execute(groups).fetchone()
            # back to the catalog before it: the old policy and functions, no tokens or groups per ACL, marks by
            # people only
            c.execute("DROP POLICY files_visible ON pinakes.files")
            c.execute("CREATE POLICY files_visible ON pinakes.files FOR SELECT USING "
                      "(acl_id = ANY (pinakes.visible_acls()))")
            for fn, returns in (("stepped_up()", "boolean"), ("visible_acls()", "int[]"),
                                ("sensitive_visible(content bigint, file bigint)", "boolean"),
                                ("begin_step_up(reason text, minutes int DEFAULT 15)", "timestamptz")):
                c.execute("CREATE OR REPLACE FUNCTION pinakes.%s RETURNS %s LANGUAGE sql STABLE SECURITY DEFINER "
                          "SET search_path = pinakes AS $$ SELECT NULL::%s $$" % (fn, returns, returns))
            c.execute("DROP FUNCTION pinakes.token_roots(), pinakes.begin_token_call(bytea, text), "
                      "pinakes.make_token(text, bytea, text[], int[], int, int), pinakes.my_tokens(), "
                      "pinakes.revoke_token(int), pinakes.begin_cli_session(bytea, int, text), "
                      "pinakes.end_cli_session(), pinakes.my_groups(), pinakes.current_group(), "
                      "pinakes.current_token() CASCADE")
            c.execute("DROP TABLE pinakes.tokens, pinakes.acl_groups")
            c.execute("ALTER TABLE pinakes.review_marks DROP COLUMN marked_by_group, "
                      "ALTER COLUMN marked_by SET NOT NULL")
            self.assertNotEqual(c.execute(defs, args).fetchone(), fresh[:-1])
            with open(os.path.join(UPGRADES, "api-tokens.sql")) as f:
                c.execute(f.read())
            # then mark_changes() as scrub.sql, later in the order, replaces it (scrub findings reviewed, ROADMAP 41)
            with open(os.path.join(UPGRADES, "scrub.sql")) as f:
                scrub = f.read()
            start = scrub.index("CREATE OR REPLACE FUNCTION mark_changes")
            c.execute("SET search_path = pinakes; " + scrub[start:scrub.index("END $$;", start) + len("END $$;")])
            # and as edits.sql, last, replaces it again (each mark kept, ROADMAP 62)
            c.execute(replaced_function("edits.sql", "mark_changes"))
            c.execute("RESET search_path")
            # and the files policy as files-policy.sql, last in the order, wraps visible_acls() (ROADMAP 48)
            with open(os.path.join(UPGRADES, "files-policy.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            # and sensitive_visible() as person-metadata.sql, later still, replaces it (shared sensitive fields,
            # ROADMAP 16)
            with open(os.path.join(UPGRADES, "person-metadata.sql")) as f:
                later = re.search(r"^CREATE OR REPLACE FUNCTION sensitive_visible\(.*?^\$\$;$", f.read(), re.M | re.S)
            c.execute("SET search_path = pinakes; " + later.group(0))
            c.execute("RESET search_path")
            self.assertEqual(c.execute(defs, args).fetchone() + c.execute(groups).fetchone(), fresh)
        return fresh

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
        self.assertEqual(self.get("only-here?loc=store:people/user-2/", his), (200, NONE))
        status, body = self.get("safe-to-delete?loc=store:people/user-1/", his)
        self.assertEqual((status, sorted(body)),
                         (200, ["limit", "links_into", "links_into_total", "not_safe", "offset", "total"]))
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
        self.assertEqual(self.get("find?q=letter.txt", his), (200, NONE))
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
        # GET only, but for signing in and out (pinakes --as), the review marks and lineage decisions a token's
        # review scope allows, the tags its tag scope allows, and undoing either (the database checks the scope again)
        api = [r for r in self.app.url_map.iter_rules() if r.rule.startswith("/api/")]
        self.assertTrue(api)
        posts = {r.rule for r in api if r.methods - {"HEAD", "OPTIONS"} != {"GET"}}
        self.assertEqual(posts, {"/api/v1/session", "/api/v1/session/end", "/api/v1/review", "/api/v1/decide",
                                 "/api/v1/tag", "/api/v1/undo"})
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
        self.check_upgrade_matches_the_schema()

    # a person's export (ROADMAP 45) ----------------------------------------------------------------------------
    def test_an_export_is_the_persons_own_records_and_nobody_elses(self):
        # a change to her diary and his plan (which she reads), sensitive and plain metadata on each, and a gone
        # file of his, marked
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers, later")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan, later")
        self.write("server-1", "store", "people/user-1/old.txt", b"old")
        self.scan("server-1", "store")
        os.remove(os.path.join(self.agent("server-1", "store")[2], "people/user-1/old.txt"))
        self.scan("server-1", "store")
        for rel in ("people/user-2/diary.txt", "people/user-1/shared-with-2/plan.txt"):
            for sensitive, vals in ((True, '{"gps": [0, 0]}'), (False, '{"title": "x"}')):
                self.conn.execute("INSERT INTO pinakes.metadata (content_id, schema, vals, source, sensitive) "
                                  "SELECT content_id, 'exif', %s, 'embedded', %s FROM pinakes.present "
                                  "WHERE relpath = %s", (vals, sensitive, rel))
        self.conn.execute("INSERT INTO pinakes.review_marks (history_id, mark, marked_by) SELECT history_id, "
                          "'intended', %s FROM pinakes.history WHERE kind = 'gone'", (self.pid("user-1"),))
        owned = {name: {r[0] for r in self.q("SELECT f.file_id FROM pinakes.files f JOIN pinakes.roots r "
                                             "USING (root_id) WHERE f.owner_id = %s AND r.label = 'store'",
                                             (self.pid(name),))} for name in ("user-1", "user-2")}
        diary, plan = self.file("store", "people/user-2/diary.txt"), self.file("store", "people/user-1/shared-with-2/plan.txt")
        his, hers = self.token("user-1"), self.token("user-2")

        def ids(body):
            return ({r["file_id"] for p in ("files", "history", "reviews", "metadata") for r in body[p]}
                    | {i for r in body["lineage"] for i in (r["from_file_id"], r["to_file_id"])})

        status, mine = self.get("export", hers)
        self.assertEqual(status, 200, mine)
        self.assertEqual(sorted(mine), ["exported", "files", "history", "limit", "lineage", "metadata", "offset",
                                        "person", "reviews"])
        self.assertEqual((mine["person"], mine["limit"], mine["offset"]), ("user-2", web.API_PAGE, 0))
        self.assertEqual([(f["root"], f["relpath"], f["sha256"]) for f in mine["files"]],
                         [("store", "people/user-2/diary.txt", hashlib.sha256(b"hers, later").hexdigest())])
        self.assertEqual(sorted(h["kind"] for h in mine["history"]), ["changed", "new"])
        self.assertEqual(sorted((m["sensitive"], json.dumps(m["vals"])) for m in mine["metadata"]),
                         [(False, '{"title": "x"}'), (True, '{"gps": [0, 0]}')])
        self.assertEqual(ids(mine), {diary})            # not the plan she reads, nor anything of his
        self.assertNotIn("plan", json.dumps(mine))

        status, theirs = self.get("export", his)
        self.assertEqual(status, 200, theirs)
        self.assertEqual(sorted(f["relpath"] for f in theirs["files"]),      # the protected downloads left out
                         ["people/user-1/old.txt", "people/user-1/shared-with-2/plan.txt", "people/user-1/taxes.txt"])
        self.assertTrue(ids(theirs) <= owned["user-1"])
        self.assertNotIn(diary, ids(theirs))
        self.assertNotIn("diary", json.dumps(theirs))
        self.assertNotIn(hashlib.sha256(b"hers").hexdigest(), json.dumps(theirs))
        self.assertIn((plan, True), {(m["file_id"], m["sensitive"]) for m in theirs["metadata"]})
        self.assertEqual([(r["kind"], r["mark"], r["marked_by"]) for r in theirs["reviews"]],
                         [("gone", "intended", "user-1")])
        self.assertEqual([f["gone_on"] is not None for f in theirs["files"] if f["relpath"].endswith("old.txt")],
                         [True])
        # sensitive rows only where sensitive_visible() allows, under the token as the export ran
        with self.app_conn() as c:
            c.execute("SELECT pinakes.begin_token_call(%s, 'test')", (hashlib.sha256(his.encode()).digest(),))
            for m in theirs["metadata"]:
                if m["sensitive"]:
                    self.assertTrue(queries.sensitive_visible(c, m["file_id"], None), m)
        # an administrator's token exports their own, never stepped up: the same as above, with no step-up to use
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.step_ups")[0][0], 0)

        # a token limited to a root exports only that root's
        only = self.token("user-1", roots=[self.root_id("downloads")], client="workstation-1")
        self.assertEqual(sorted(f["relpath"] for f in self.get("export?part=files", only)[1]["files"]),
                         ["letter.txt", "taxes-copy.txt"])
        # one part, paged; and as CSV
        status, page = self.get("export?part=files&limit=1&offset=1", his)
        self.assertEqual((status, sorted(page)), (200, ["exported", "files", "limit", "offset", "person"]))
        self.assertEqual([f["file_id"] for f in page["files"]], [sorted(f["file_id"] for f in theirs["files"])[1]])
        r = self.app.test_client().get("/api/v1/export?part=metadata&format=csv",
                                       headers={"Authorization": "Bearer " + hers})
        self.assertEqual((r.status_code, r.mimetype), (200, "text/csv"))
        table = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
        self.assertEqual(sorted((t["file_id"], t["sensitive"], t["vals"]) for t in table),
                         [(str(diary), "False", '{"title": "x"}'), (str(diary), "True", '{"gps": [0, 0]}')])
        empty = self.app.test_client().get("/api/v1/export?part=reviews&format=csv",
                                           headers={"Authorization": "Bearer " + hers}).get_data(as_text=True)
        self.assertEqual(empty, "history_id,file_id,kind,mark,marked_at,marked_by,marked_by_group\n")
        # bad arguments, and tokens that aren't a person's with read
        for call, said in (("export?format=csv", "a CSV is one part"), ("export?part=everything", "part is one of"),
                           ("export?format=xml", "format is json or csv")):
            status, body = self.get(call, hers)
            self.assertEqual(status, 400)
            self.assertIn(said, body["error"])
        self.assertEqual(self.get("export", self.token("user-1", group="household", client="kitchen")),
                         (403, {"error": "an export is a person's own records: use a person's token"}))
        self.assertEqual(self.get("export", self.token("user-1", scopes=("review",), client="phone")),
                         (403, {"error": "this token doesn't have the read scope"}))
        # and every export is in the audit, the person's to see
        self.assertEqual(self.q("SELECT p.name, a.detail->>'call' FROM pinakes.audit a JOIN pinakes.people p "
                                "ON p.person_id = a.actor WHERE a.action = 'api' AND a.detail->>'call' LIKE 'export%%' "
                                "AND a.detail->>'token' = 'laptop-1' ORDER BY a.audit_id"),
                         [("user-2", "export"), ("user-1", "export"), ("user-1", "export?part=files&limit=1&offset=1"),
                          ("user-2", "export?part=metadata&format=csv"), ("user-2", "export?part=reviews&format=csv"),
                          ("user-2", "export?format=csv"), ("user-2", "export?part=everything"),
                          ("user-2", "export?format=xml")])
        self.assertIn("export?part=metadata&amp;format=csv", self.login("user-2").get("/access").get_data(as_text=True))


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
        self.scan("server-1", "store")      # empty: a root's first scan is not a change (ROADMAP 52), the next is
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
        self.assertEqual(len(json.loads(cli("versions", "store:people/user-1/taxes.txt", "--json"))["rows"]), 1)
        self.assertEqual(json.loads(cli("lineage", "store:people/user-1/taxes.txt", "--down", "--json")), [])
        self.assertIn("people/user-1/taxes.txt", cli("only-here", "store:people/user-1/"))
        self.assertIn("people/user-1/taxes.txt", cli("safe-to-delete", "store:people/user-1/"))
        self.assertEqual(sorted(json.loads(cli("safe-to-delete", "store:people/user-1/", "--json"))),
                         ["limit", "links_into", "links_into_total", "not_safe", "offset", "total"])
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
        row = json.loads(cli("where", "store:people/user-1/taxes.txt", "--json"))["rows"][0]
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
        self.scan("server-1", "store")      # empty: a root's first scan is not a change (ROADMAP 52), the next is
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
        self.assertEqual(len(json.loads(cli("versions", "taxes.txt", "--json", cwd=mine))["rows"]), 1)
        self.assertEqual(json.loads(cli("lineage", "taxes.txt", "--down", "--json", cwd=mine)), [])
        here = [r["relpath"] for r in json.loads(cli("only-here", "--json", cwd=mine))["rows"]]
        self.assertEqual(sorted(here), ["people/user-1/shared-with-2/plan.txt", "people/user-1/taxes.txt"])
        self.assertEqual([r["relpath"] for r in json.loads(cli("only-here", "shared-with-2", "--json",
                                                               cwd=mine))["rows"]],
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
        self.assertIn("3 unreviewed change(s) (gone, moved, or found by the scrub) under store:people/user-1/cleanup",
                      out)
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
class TestCliTag(ServerCase):
    """pinakes tag [PATH] (ROADMAP 37): a person's own tags and note from inside a folder, through
    set_file_metadata() and its rules, with the token's tag scope and roots."""

    U = "people/user-1/"

    def setUp(self):
        super().setUp()
        self.scfg = server_config.loads(SERVER + """
[[ownership.enrollment]]
root = "store"
folder = "people/user-1/notes"
person = "user-2"
as = "annotator"
""")
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        for rel in ("trip/a.jpg", "trip/b.jpg", "trip/day-2/c.txt", "notes/n.txt", "shared-with-2/plan.txt"):
            self.write("server-1", "store", self.U + rel, b"content " + rel.encode())
        self.write("laptop-1", "downloads", "d.txt", b"downloads")
        self.scan("server-1", "store")
        self.scan("laptop-1", "downloads")
        self.folder = self.path("server-1", "store", self.U + "trip")
        self.cli = None

    def as_(self, person, scopes=("read", "tag"), roots=None):
        if self.cli:
            self.cli.close()
        self.cli = CliRun(self, person, scopes, roots)
        self.addCleanup(lambda: self.cli and self.cli.close())
        with open(self.cli.client_toml, "a") as f:
            f.write('host = "server-1"\n')
        return self.cli

    def entered(self):
        """{(path, author): dc values} of every person-entered dc row."""
        return {(r[0], r[1]): r[2] for r in self.q(
            "SELECT f.relpath, p.name, m.vals FROM pinakes.metadata m JOIN pinakes.files f USING (file_id) "
            "JOIN pinakes.people p ON p.person_id = m.author WHERE m.source = 'person' AND m.schema = 'dc'")}

    def fid(self, rel):
        return self.q("SELECT file_id FROM pinakes.files WHERE relpath = %s", (rel,))[0][0]

    def post(self, cli, body):
        import urllib.request
        with open(cli.home_token()) as f:
            token = f.read().strip()
        req = urllib.request.Request(cli.url + "/api/v1/tag", data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_the_owner_tags_from_inside_the_folder_once_asked(self):
        cli = self.as_("user-1")
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="n"):
            out = cli("tag", "--add", "holiday", "--add", "2026", cwd=self.folder)
        self.assertIn("3 file(s) under store:people/user-1/trip to tag (add holiday, 2026):", out)
        self.assertTrue(out.endswith("not tagged\n"), out)
        self.assertEqual(self.entered(), {})
        with mock.patch("sys.stdin.isatty", return_value=True), \
                mock.patch("builtins.input", return_value="y") as asked:
            out = cli("tag", "--add", "holiday", "--add", "2026", cwd=self.folder)
        self.assertEqual(asked.call_args.args[0], "Tag these 3? [y/N] ")
        self.assertIn("tagged 3 of 3", out)
        trip = {(self.U + "trip/" + r, "user-1"): {"subject": ["holiday", "2026"]}
                for r in ("a.jpg", "b.jpg", "day-2/c.txt")}
        self.assertEqual(self.entered(), trip)
        # not asked without a terminal unless --yes; a file named alone at once; a note, a tag removed, the note gone
        self.assertIn("add --yes", cli("tag", "--add", "x", cwd=self.folder, code=1))
        out = cli("tag", "a.jpg", "--note", "the harbour at dawn", "--remove", "2026", cwd=self.folder)
        self.assertIn("tagged 1 of 1", out)
        trip[(self.U + "trip/a.jpg", "user-1")] = {"subject": ["holiday"], "description": "the harbour at dawn"}
        self.assertEqual(self.entered(), trip)
        cli("tag", "day-2", "--remove", "holiday", "--remove", "2026", "--yes", cwd=self.folder)
        del trip[(self.U + "trip/day-2/c.txt", "user-1")]               # nothing left: no row
        self.assertEqual(self.entered(), trip)
        cli("tag", "store:" + self.U + "trip/a.jpg", "--note", "", cwd=self.tmp)
        trip[(self.U + "trip/a.jpg", "user-1")] = {"subject": ["holiday"]}
        self.assertEqual(self.entered(), trip)
        # without an option, what is there; --json
        out = cli("tag", cwd=self.folder)
        self.assertIn("tags and notes on 3 file(s) under store:people/user-1/trip:", out)
        self.assertRegex(out, r"store:people/user-1/trip/b.jpg +owner +holiday")
        rows = json.loads(cli("tag", "b.jpg", "--json", cwd=self.folder))["rows"]
        self.assertEqual([(r["relpath"], r["role"], r["tags"], r["note"]) for r in rows],
                         [(self.U + "trip/b.jpg", "owner", ["holiday", "2026"], None)])
        # a tag with a comma, and nothing asked, refused by the API
        self.assertIn("a tag has no comma", cli("tag", "a.jpg", "--add", "a,b", cwd=self.folder, code=1))
        self.assertEqual(self.post(cli, {"ids": [self.fid(self.U + "trip/a.jpg")]}),
                         (400, {"error": "nothing to do: add, remove or note"}))
        # shown on the web, on the file's page, as entered by the person
        c = cli.app.test_client()
        page = c.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) SELECT person_id, %s "
                          "FROM pinakes.people WHERE name = 'user-1'", (auth.hash_password(PASSWORDS["user-1"]),))
        c.post("/login", data={"csrf": csrf, "name": "user-1", "password": PASSWORDS["user-1"]})
        page = c.get("/file/%d" % self.fid(self.U + "trip/b.jpg")).get_data(as_text=True)
        self.assertIn("holiday", page)
        self.assertIn("User One", page)
        # every call on the person's record, with the token
        calls = [r[0] for r in self.q("SELECT a.detail->>'call' FROM pinakes.audit a WHERE a.action = 'api' "
                                      "AND a.detail->>'call' = 'tag' ")]
        self.assertGreaterEqual(len(calls), 5)

    def test_an_annotator_tags_and_a_reader_cant(self):
        cli = self.as_("user-2")
        out = cli("tag", "store:" + self.U + "notes/", "--add", "draft", "--yes", cwd=self.tmp)
        self.assertIn("tagged 1 of 1", out)
        self.assertEqual(self.entered(), {(self.U + "notes/n.txt", "user-2"): {"subject": ["draft"]}})
        self.assertEqual(self.q("SELECT p.name, a.affects FROM pinakes.audit a JOIN pinakes.people p "
                                "ON p.person_id = a.actor WHERE a.action = 'metadata'"),
                         [("user-2", [self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-1'")[0][0]])])
        shared = "store:" + self.U + "shared-with-2/"
        self.assertEqual(cli("tag", shared, "--add", "mine", "--yes", cwd=self.tmp),
                         "nothing to tag under %s: no file you own, co-own or annotate (1 you only read)\n" % shared)
        plan = self.fid(self.U + "shared-with-2/plan.txt")
        self.assertEqual(self.post(cli, {"ids": [plan], "add": ["mine"]}), (200, {"asked": 1, "tagged": 0}))
        self.assertNotIn((self.U + "shared-with-2/plan.txt", "user-2"), self.entered())
        # the owner sees the annotator's tag as another's
        cli = self.as_("user-1")
        self.assertIn("User Two: draft", cli("tag", "store:" + self.U + "notes/", cwd=self.tmp))

    def test_a_token_without_the_scope_outside_its_roots_or_a_groups(self):
        cli = self.as_("user-1", scopes=("read",))
        self.assertEqual(cli("tag", "--add", "x", "--yes", cwd=self.folder, code=1),
                         "pinakes: this token doesn't have the tag scope")
        self.assertIn("tags and notes on 3 file(s)", cli("tag", cwd=self.folder))      # reading, yes
        self.assertEqual(self.entered(), {})
        # limited to downloads: the store's files are out of sight, and their ids out of reach
        a = self.fid(self.U + "trip/a.jpg")
        cli = self.as_("user-1", roots=[self.q("SELECT root_id FROM pinakes.roots WHERE label = 'downloads'")[0][0]])
        self.assertIn("not inside a root that server-1 reports", cli("tag", "--add", "x", "--yes",
                                                                     cwd=self.folder, code=1))
        self.assertEqual(cli("tag", "store:" + self.U + "trip/", "--add", "x", "--yes", cwd=self.tmp),
                         "nothing to tag under store:people/user-1/trip/: no file you own, co-own or annotate\n")
        self.assertEqual(self.post(cli, {"ids": [a], "add": ["x"]}), (200, {"asked": 1, "tagged": 0}))
        self.assertEqual(self.entered(), {})
        self.assertIn("tagged 1 of 1", cli("tag", "downloads:d.txt", "--add", "x", cwd=self.tmp))    # its own root
        # and the database itself refuses, whatever the application asks: no scope, outside the roots, a group
        R = psycopg.errors.RaiseException
        for scopes, roots, group, refused in (
                (["read"], None, None, "tag scope"),
                (["read", "tag"], [self.q("SELECT root_id FROM pinakes.roots WHERE label = 'downloads'")[0][0]],
                 None, "only the owner"),
                (["read", "tag"], None, "household", "a group token")):
            secret = "pinakes_test_%s" % os.urandom(8).hex()
            with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
                c.execute("SELECT set_config('pinakes.person', person_id::text, true) FROM pinakes.people "
                          "WHERE name = 'user-1'")
                c.execute("SELECT pinakes.make_token('workstation-1', %s, %s, %s, NULL, "
                          "(SELECT group_id FROM pinakes.groups WHERE name = %s))",
                          (hashlib.sha256(secret.encode()).digest(), scopes, roots, group))
            with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
                c.execute("SELECT * FROM pinakes.begin_token_call(%s, 'test')",
                          (hashlib.sha256(secret.encode()).digest(),))
                with self.assertRaisesRegex(R, refused):
                    c.execute("SELECT pinakes.set_file_metadata(%s, 'dc', '{\"subject\": [\"x\"]}', '{}')", (a,))
            if group:                                                   # and the API, before it asks
                CliRun.save(cli.home_token(), secret)
                self.assertEqual(self.post(cli, {"ids": [a], "add": ["x"]}),
                                 (403, {"error": "tags and notes are a person's own: use a person's token"}))
        self.assertEqual(self.entered(), {("d.txt", "user-1"): {"subject": ["x"]}})


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCliRelatives(ServerCase):
    """pinakes relatives FILE [--confirm|--reject|--clear OTHER] (ROADMAP 9): a file's direct relatives, and a
    decision on one, through decide_lineage() and its rules, with the token's review scope and roots."""

    X, Y = "people/user-1/x/notes.txt", "people/user-1/y/notes.txt"
    SA, SB = "people/user-1/shared-with-2/a/memo.txt", "people/user-1/shared-with-2/b/memo.txt"

    def setUp(self):
        super().setUp()
        t0 = time.time() - 86400
        self.write("server-1", "store", self.X, os.urandom(1000), mtime=t0)
        self.write("server-1", "store", self.SA, os.urandom(1200), mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", self.Y, os.urandom(1010), mtime=t0 + 1)
        self.write("server-1", "store", self.SB, os.urandom(1210), mtime=t0 + 1)
        self.scan("server-1", "store")
        self.assertEqual(self.decisions(), {(self.X, self.Y): None, (self.SA, self.SB): None})
        self.cli = None

    def decisions(self):
        return dict(((a, b), d) for a, b, d in self.q(
            "SELECT ff.relpath, ft.relpath, l.decision FROM pinakes.lineage l "
            "JOIN pinakes.files ff ON ff.file_id = l.from_file_id JOIN pinakes.files ft ON ft.file_id = l.to_file_id"))

    def as_(self, person, scopes=("read", "review"), roots=None):
        if self.cli:
            self.cli.close()
        self.cli = CliRun(self, person, scopes, roots)
        self.addCleanup(lambda: self.cli and self.cli.close())
        with open(self.cli.client_toml, "a") as f:
            f.write('host = "server-1"\n')
        return self.cli

    def test_the_owner_rejects_from_inside_the_folder_then_clears(self):
        cli = self.as_("user-1")
        out = cli("relatives", "store:" + self.Y)
        self.assertIn("direct relatives of store:" + self.Y, out)
        self.assertIn("came from  derived_from  store:" + self.X, out)
        out = cli("relatives", "notes.txt", "--reject", "../x/notes.txt", cwd=self.path("server-1", "store",
                                                                                         "people/user-1/y"))
        self.assertIn("rejected 1 link(s)", out)
        self.assertIn("rejected", out.splitlines()[-1])
        self.assertEqual(self.decisions()[(self.X, self.Y)], "rejected")
        self.assertIn("(none)", cli("lineage", "store:" + self.Y))                  # gone from the walk
        got = json.loads(cli("relatives", "store:" + self.X, "--clear", "store:" + self.Y, "--json"))
        self.assertEqual((got["decided"], got["decision"]), (1, None))
        self.assertEqual([(r["direction"], r["relpath"], r["decision"]) for r in got["rows"]],
                         [("down", self.Y, None)])
        self.assertEqual(self.decisions()[(self.X, self.Y)], None)
        self.assertIn("confirmed 1 link(s)", cli("relatives", "store:" + self.Y, "--confirm", "store:" + self.X))
        self.assertEqual(self.decisions()[(self.X, self.Y)], "confirmed")
        self.assertIn("takes one of", cli("relatives", "store:" + self.Y, "--confirm", "store:" + self.X,
                                          "--reject", "store:" + self.X, code=1))

    def test_a_reader_a_token_without_the_scope_or_outside_its_roots_decides_nothing(self):
        cli = self.as_("user-2")
        out = cli("relatives", "store:" + self.SB, "--reject", "store:" + self.SA)      # a reader sees it
        self.assertIn("nothing decided", out)
        self.assertIn("store:" + self.SA, out)
        self.assertIn("no file you can see", cli("relatives", "store:" + self.Y, "--reject", "store:" + self.X,
                                                 code=1))
        cli = self.as_("user-1", scopes=("read",))
        self.assertEqual(cli("relatives", "store:" + self.Y, "--reject", "store:" + self.X, code=1),
                         "pinakes: this token doesn't have the review scope")
        cli = self.as_("user-1", roots=[self.q("SELECT root_id FROM pinakes.roots WHERE label = 'store'")[0][0]])
        self.assertIn("rejected 1 link(s)", cli("relatives", "store:" + self.Y, "--reject", "store:" + self.X))
        self.assertEqual(self.decisions(), {(self.X, self.Y): "rejected", (self.SA, self.SB): None})
        # a group token never decides, and the API checks what it is given
        c = cli.app.test_client()
        group = make_kind_token(self, "user-1", scopes=("read", "review"), group="household")
        mine = make_token(self, "user-1", scopes=("read", "review"))
        for secret, body, want in (
                (group, {"files": ["store:" + self.SA, "store:" + self.SB], "decision": "rejected"}, 403),
                (mine, {"files": ["store:" + self.SA], "decision": "rejected"}, 400),
                (mine, {"files": ["store:" + self.SA, "store:" + self.SB], "decision": "maybe"}, 400),
                (mine, {"files": [True, 2], "decision": "rejected"}, 400),
                (mine, {"files": ["store:nothing here", "store:" + self.SB], "decision": "rejected"}, 404)):
            r = c.post("/api/v1/decide", json=body, headers={"Authorization": "Bearer " + secret})
            self.assertEqual(r.status_code, want, (body, r.get_json()))
        self.assertEqual(self.decisions()[(self.SA, self.SB)], None)
        ids = [self.file("store", self.SA), self.file("store", self.SB)]
        r = c.post("/api/v1/decide", json={"files": ids, "decision": "confirmed"},
                   headers={"Authorization": "Bearer " + mine})
        self.assertEqual((r.status_code, r.get_json()), (200, {"files": ids, "decision": "confirmed", "decided": 1}))


def make_kind_token(case, person, scopes=("read",), roots=None, client="laptop-1", group=None):
    """make_token() with a group: a group token of it (ROADMAP 38); scopes ("ops",): an ops token (39)."""
    secret = "pinakes_test_%s_%s" % (person, os.urandom(8).hex())
    with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=case.db) as c:
        pid = c.execute("SELECT person_id FROM pinakes.people WHERE name = %s", (person,)).fetchone()[0]
        gid = c.execute("SELECT group_id FROM pinakes.groups WHERE name = %s", (group,)).fetchone()[0] if group else None
        c.execute("SELECT set_config('pinakes.person', %s, true)", (str(pid),))
        c.execute("SELECT pinakes.make_token(%s, %s, %s, %s, NULL, %s)",
                  (client, hashlib.sha256(secret.encode()).digest(), list(scopes), roots, gid))
    return secret


@unittest.skipUnless(web is not None, "Flask not installed")
class TestEdits(ServerCase):
    """pinakes edits and pinakes undo (ROADMAP 62): every review mark, tag and note, and lineage decision kept as an
    edit with who made it, by which token or on the web, and the values before; an undo puts them back, refused
    where a value changed since. user-2 co-owns people/user-1/team; the household owns household/; user-3 is no
    member of it."""

    U = "people/user-1/"
    X, Y = U + "x/notes.txt", U + "y/notes.txt"
    P = U + "trip/p.jpg"
    server_toml = SERVER + """
[people.user-3]
display = "User Three"
roles = ["person"]
[[ownership.rule]]
root = "store"
folder = "household"
owner = "household"
[[ownership.enrollment]]
root = "store"
folder = "people/user-1/team"
person = "user-2"
as = "co-owner"
"""
    GONE = (U + "cleanup/a.txt", U + "cleanup/b.txt", U + "team/t.txt", "household/old.txt")

    def setUp(self):
        super().setUp()
        t0 = time.time() - 86400
        for rel in self.GONE + (self.P,):
            self.write("server-1", "store", rel, b"content of " + rel.encode())
        self.write("server-1", "store", self.X, os.urandom(1000), mtime=t0)
        self.write("laptop-1", "downloads", "d.txt", b"downloads")
        self.scan("server-1", "store")
        self.scan("laptop-1", "downloads")
        self.write("server-1", "store", self.Y, os.urandom(1010), mtime=t0 + 1)
        for rel in self.GONE:
            os.remove(self.path("server-1", "store", rel))
        self.scan("server-1", "store")
        self.cli = None

    def as_(self, person, scopes=("read", "review", "tag"), roots=None, secret=None):
        if self.cli:
            self.cli.close()
        self.cli = CliRun(self, person if not secret else None, scopes, roots)
        if secret:
            CliRun.save(self.cli.home_token(), secret)
        self.addCleanup(lambda: self.cli and self.cli.close())
        return self.cli

    def edits(self, cli, *args):
        return json.loads(cli("edits", "--json", *args))

    def marks(self):
        return dict(self.q("SELECT hi.old_relpath, m.mark FROM pinakes.review_marks m "
                           "JOIN pinakes.history hi USING (history_id)"))

    def tags(self, rel=None):
        got = self.q("SELECT m.vals->'subject' FROM pinakes.metadata m JOIN pinakes.files f USING (file_id) "
                     "WHERE f.relpath = %s AND m.source = 'person'", (rel or self.P,))
        return got[0][0] if got else None

    def decision(self):
        return self.q("SELECT decision FROM pinakes.lineage WHERE to_file_id = %s", (self.file("store", self.Y),))[0][0]

    def gone_id(self, rel):
        return self.q("SELECT history_id FROM pinakes.history WHERE kind = 'gone' AND old_relpath = %s", (rel,))[0][0]

    def post(self, cli, call, body):
        with open(cli.home_token()) as f:
            token = f.read().strip()
        r = cli.app.test_client().post("/api/v1/" + call, json=body, headers={"Authorization": "Bearer " + token})
        return r.status_code, r.get_json()

    def web_mark(self, cli, person, rel, mark):
        """A mark made on the web's Changes page, signed in as the person."""
        self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) SELECT person_id, %s "
                          "FROM pinakes.people WHERE name = %s ON CONFLICT DO NOTHING",
                          (auth.hash_password(PASSWORDS[person]), person))
        c = cli.app.test_client()
        csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
        c.post("/login", data={"csrf": csrf, "name": person, "password": PASSWORDS[person]})
        csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/reports/changes").get_data(as_text=True)).group(1)
        r = c.post("/reports/changes/mark", data={"csrf": csrf, "mark": mark, "id": self.gone_id(rel)})
        self.assertEqual(r.status_code, 302)

    def test_each_write_is_listed_with_its_token_and_undone(self):
        cli = self.as_("user-1")
        self.assertEqual(self.edits(cli), {"rows": [], "total": 0, "limit": 100, "offset": 0})
        cli("review", "intended", "store:" + self.U + "cleanup/", "--yes", cwd=self.tmp)
        cli("tag", "store:" + self.P, "--add", "holiday", cwd=self.tmp)
        cli("tag", "store:" + self.P, "--add", "holiday", cwd=self.tmp)             # the same again: no edit
        cli("relatives", "store:" + self.Y, "--reject", "store:" + self.X, cwd=self.tmp)
        self.web_mark(cli, "user-1", self.U + "team/t.txt", "restore")
        self.web_mark(cli, "user-1", self.U + "team/t.txt", "restore")              # unchanged: no edit
        got = self.edits(cli)
        self.assertEqual(got["total"], 4)
        rows = got["rows"]
        self.assertEqual([(r["action"], r["changes"], r["token"], r["mine"], r["before"], r["undone_by"])
                          for r in rows],
                         [("review", 1, None, True, None, None), ("lineage", 1, "laptop-1", True, None, None),
                          ("metadata", 1, "laptop-1", True, None, None), ("review", 2, "laptop-1", True, None, None)])
        self.assertEqual(rows[0]["after"]["mark"], "restore")
        self.assertEqual((rows[1]["other_relpath"], rows[1]["relpath"], rows[1]["after"]["decision"]),
                         (self.X, self.Y, "rejected"))
        self.assertEqual(rows[2]["after"], {"plain": {"subject": ["holiday"]}, "hidden": {}})
        review, lineage, tagged, web = rows[3]["edit"], rows[1]["edit"], rows[2]["edit"], rows[0]["edit"]
        out = cli("edits", cwd=self.tmp)
        self.assertIn("your edits in the last 7 days:", out)
        self.assertRegex(out, r"you, on the web +review +1 +store:%steam/t.txt +none -> restore" % self.U)
        self.assertRegex(out, r"you, laptop-1 +lineage +1 +store:%s \(from notes.txt\) +none -> rejected" % self.Y)
        self.assertRegex(out, r"you, laptop-1 +metadata +1 +store:%s +none -> subject holiday" % self.P)
        self.assertIn("4 of 4", out)
        # --token: that token's only; --days: an older edit only when asked
        self.assertEqual(self.edits(cli, "--token", "laptop-1")["total"], 3)
        self.assertEqual(self.edits(cli, "--token", "workstation-1")["total"], 0)
        with admin_conn(self.db) as c:
            c.execute("UPDATE pinakes.edits SET at = now() - interval '10 days' WHERE edit_id = %s", (review,))
        self.assertEqual(self.edits(cli)["total"], 3)
        self.assertEqual(self.edits(cli, "--days", "30")["total"], 4)
        # undo puts each value back, as an edit of its own, which can be undone in turn
        self.assertEqual(self.marks(), {self.U + "cleanup/a.txt": "intended", self.U + "cleanup/b.txt": "intended",
                                        self.U + "team/t.txt": "restore"})
        before = self.q("SELECT history_id, mark, marked_by, marked_at FROM pinakes.review_marks ORDER BY 1")
        out = cli("undo", str(review), str(lineage), str(tagged), cwd=self.tmp)
        lines = out.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertRegex(lines[0], r"undid edit %d: 1 value\(s\) put back, as edit \d+" % lineage)  # newest first
        self.assertRegex(lines[2], r"undid edit %d: 2 value\(s\) put back, as edit \d+" % review)
        self.assertEqual(self.marks(), {self.U + "team/t.txt": "restore"})
        self.assertIsNone(self.decision())
        self.assertIsNone(self.tags())
        got = self.edits(cli, "--days", "30")["rows"]
        undone = {r["edit"]: r["undone_by"] for r in got}
        undo_review = undone[review]
        self.assertEqual([r for r in got if r["edit"] == undo_review][0]["undoes"], review)
        self.assertIn("undo %d (review)" % review, cli("edits", "--days", "30", cwd=self.tmp))
        # the same undo again: its values changed since, by the undo
        msg = cli("undo", str(review), cwd=self.tmp, code=1)
        self.assertEqual(msg, "pinakes: 1 of 1 edit(s) not undone")
        self.assertRegex(cli.out, r"edit %d not undone: store:%scleanup/\w.txt changed since, by edit %d \("
                                  r"\d{4}-\d\d-\d\d \d\d:\d\d UTC, you, token laptop-1\)" % (review, self.U, undo_review))
        cli("undo", str(undo_review), cwd=self.tmp)                                 # the undo undone: back again
        self.assertEqual(self.q("SELECT history_id, mark, marked_by, marked_at FROM pinakes.review_marks ORDER BY 1"),
                         before)                                                    # as it was, its time too
        # two writes of one value: the earlier is refused until the later is undone, or both at once
        cli("tag", "store:" + self.P, "--add", "holiday", cwd=self.tmp)
        cli("tag", "store:" + self.P, "--add", "beach", cwd=self.tmp)
        first, second = [r["edit"] for r in self.edits(cli, "--token", "laptop-1")["rows"][:2]][::-1]
        self.assertIn("changed since, by edit %d" % second, cli("undo", str(first), cwd=self.tmp, code=1) + cli.out)
        self.assertEqual(self.tags(), ["holiday", "beach"])
        got = json.loads(cli("undo", str(first), str(second), "--json", cwd=self.tmp))
        self.assertEqual([(r["edit"], r["changes"]) for r in got["undone"]], [(second, 1), (first, 1)])
        self.assertEqual((got["asked"], got["refused"]), (2, []))
        self.assertIsNone(self.tags())
        self.assertIn("needs edit numbers", cli("undo", cwd=self.tmp, code=1))
        self.assertIn("x is not one", cli("undo", "x", cwd=self.tmp, code=1))

    def test_another_person_neither_sees_nor_undoes_them(self):
        cli = self.as_("user-1")
        cli("review", "restore", "store:" + self.U + "team/", "--yes", cwd=self.tmp)
        cli("tag", "store:" + self.U + "team/", "--add", "x", "--yes", cwd=self.tmp)   # a gone file: nothing tagged
        cli("tag", "store:" + self.P, "--note", "mine", cwd=self.tmp)
        mine = [r["edit"] for r in self.edits(cli)["rows"]]
        self.assertEqual(len(mine), 2)
        her = self.as_("user-2")
        self.assertEqual(self.edits(her)["total"], 0)
        status, body = self.post(her, "undo", {"edits": mine})
        self.assertEqual(status, 200)
        self.assertEqual(sorted((r["edit"], r["refused"], r["message"]) for r in body["refused"]),
                         sorted((e, "not_yours", "no edit %d of yours" % e) for e in mine))
        self.assertEqual(body["undone"], [])
        self.assertEqual((self.marks(), self.tags()), ({self.U + "team/t.txt": "restore"}, None))
        self.assertEqual(self.q("SELECT m.vals FROM pinakes.metadata m WHERE m.source = 'person'"),
                         [({"description": "mine"},)])
        # as a co-owner she marks the change again: his undo is refused, naming her edit without showing it
        self.assertEqual(self.post(her, "review", {"mark": "intended", "ids": [self.gone_id(self.U + "team/t.txt")]}),
                         (200, {"asked": 1, "marked": 1}))
        (hers,) = [r["edit"] for r in self.edits(her)["rows"]]
        cli = self.as_("user-1")
        self.assertNotIn(hers, [r["edit"] for r in self.edits(cli)["rows"]])
        cli("undo", str(mine[-1]), cwd=self.tmp, code=1)
        self.assertIn("store:%steam/t.txt changed since, by another person's edit %d" % (self.U, hers), cli.out)
        self.assertEqual(self.marks(), {self.U + "team/t.txt": "intended"})
        # and the database itself shows no one else's, and undoes none for no one
        with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
            c.execute("SELECT set_config('pinakes.person', person_id::text, true) FROM pinakes.people "
                      "WHERE name = 'user-3'")
            self.assertEqual(c.execute("SELECT count(*) FROM pinakes.edits").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT count(*) FROM pinakes.edit_items").fetchone()[0], 0)
        with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "no person set"):
                c.execute("SELECT * FROM pinakes.undo_edits(%s)", (mine,))

    def test_a_groups_writes_are_listed_for_its_members(self):
        grp = make_kind_token(self, "user-1", scopes=("read", "review"), group="household", client="tidy")
        cli = self.as_("user-1", secret=grp)
        out = cli("review", "intended", "store:household/", "--yes", cwd=self.tmp)
        self.assertIn("marked 1 of 1", out)
        (g,) = self.edits(cli)["rows"]
        self.assertEqual((g["group"], g["person"], g["token"], g["mine"]), ("household", None, "tidy", None))
        for person, sees in (("user-2", True), ("user-3", False)):
            got = self.edits(self.as_(person))["rows"]
            self.assertEqual([r["edit"] for r in got], [g["edit"]] if sees else [], person)
        self.assertIn("household, tidy", self.as_("user-2")("edits", cwd=self.tmp))
        status, body = self.post(self.as_("user-3"), "undo", {"edits": [g["edit"]]})
        self.assertEqual(body["refused"][0]["refused"], "not_yours")
        her = self.as_("user-2")                                    # a member undoes the group's mark
        self.assertIn("undid edit %d: 1 value(s) put back" % g["edit"], her("undo", str(g["edit"]), cwd=self.tmp))
        self.assertEqual(self.marks(), {})
        (undo,) = [r for r in self.edits(self.as_("user-1"))["rows"] if r["undoes"]]
        self.assertEqual((undo["person"], undo["group"], undo["mine"]), ("User Two", "household", False))
        self.assertIn("User Two for household, laptop-1", self.cli("edits", cwd=self.tmp))
        self.assertEqual(self.q("SELECT affects, detail FROM pinakes.audit WHERE action = 'undo'"),
                         [([self.pid("user-1"), self.pid("user-2")],
                           {"edit": g["edit"], "undone_by": undo["edit"], "action": "review", "changes": 1,
                            "token": "laptop-1", "group": "household"})])

    def pid(self, name):
        return self.q("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))[0][0]

    def test_a_token_undoes_only_with_its_scopes_and_in_its_roots(self):
        cli = self.as_("user-1")
        cli("review", "intended", "store:" + self.U + "cleanup/", "--yes", cwd=self.tmp)
        cli("tag", "store:" + self.P, "--add", "holiday", cwd=self.tmp)
        tagged, review = [r["edit"] for r in self.edits(cli)["rows"]]
        cli = self.as_("user-1", scopes=("read",))
        self.assertEqual(self.edits(cli)["total"], 2)                              # listed, yes
        self.assertEqual(cli("undo", str(review), cwd=self.tmp, code=1),
                         "pinakes: this token has neither the review nor the tag scope")
        cli = self.as_("user-1", scopes=("read", "review"))
        cli("undo", str(tagged), str(review), cwd=self.tmp, code=1)
        self.assertIn("edit %d not undone: this token doesn't have the tag scope" % tagged, cli.out)
        self.assertIn("undid edit %d" % review, cli.out)
        self.assertEqual((self.marks(), self.tags()), ({}, ["holiday"]))
        # limited to downloads: the store's edits are out of sight, and out of reach
        cli = self.as_("user-1", roots=[self.q("SELECT root_id FROM pinakes.roots WHERE label = 'downloads'")[0][0]])
        self.assertEqual(self.edits(cli)["total"], 0)
        cli("undo", str(tagged), cwd=self.tmp, code=1)
        self.assertIn("edit %d not undone: a file it changed is no longer yours to change, or outside this token's "
                      "roots" % tagged, cli.out)
        self.assertEqual(self.tags(), ["holiday"])
        cli("tag", "downloads:d.txt", "--add", "x", cwd=self.tmp)
        (d,) = [r for r in self.edits(cli)["rows"]]
        self.assertEqual((d["root"], d["relpath"]), ("downloads", "d.txt"))
        # an ops token has no edits
        ops = make_kind_token(self, "user-1", scopes=("ops",))
        cli = self.as_("user-1", secret=ops)
        self.assertEqual(cli("edits", cwd=self.tmp, code=1),
                         "pinakes: this token doesn't have the read or review or tag scope")

    def test_a_decision_on_a_link_gone_or_decided_since(self):
        cli = self.as_("user-1")
        cli("relatives", "store:" + self.Y, "--reject", "store:" + self.X, cwd=self.tmp)
        cli("relatives", "store:" + self.Y, "--confirm", "store:" + self.X, cwd=self.tmp)
        later, first = [r["edit"] for r in self.edits(cli)["rows"]]
        cli("undo", str(first), cwd=self.tmp, code=1)
        self.assertRegex(cli.out, r"edit %d not undone: store:%s changed since, by edit %d \(.*, you, token laptop-1\)"
                         % (first, self.Y, later))
        self.assertEqual(self.decision(), "confirmed")
        self.conn.execute("DELETE FROM pinakes.lineage")                # as tidy drops an edge
        cli("undo", str(later), cwd=self.tmp, code=1)
        self.assertIn("edit %d not undone: the link to store:%s is no longer in the catalog" % (later, self.Y),
                      cli.out)

    def test_nothing_overwrites_an_edit(self):
        cli = self.as_("user-1")
        cli("tag", "store:" + self.P, "--add", "holiday", cwd=self.tmp)
        for role in ("pinakes_app", "pinakes_ingest"):
            for sql in ("UPDATE pinakes.edits SET at = now()", "DELETE FROM pinakes.edit_items",
                        "UPDATE pinakes.edit_items SET after = NULL", "DELETE FROM pinakes.edits"):
                with psycopg.connect(host=PGHOST, user=role, dbname=self.db) as c:
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege, msg=(role, sql)):
                        c.execute(sql)
        with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db) as c:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("INSERT INTO pinakes.edits (person_id, action) VALUES (1, 'review')")
            c.rollback()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("SELECT pinakes.edit_now('review')")
        # a file's row going (as tidy deletes a backup's gone ones) leaves its edits, out of sight
        self.conn.execute("DELETE FROM pinakes.files WHERE file_id = %s", (self.file("store", self.P),))
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.edit_items")[0][0], 1)
        self.assertEqual(self.edits(cli)["total"], 0)

    def test_upgrade_file_matches_the_schema(self):
        tables = ["edits", "edit_items"]
        fns = ["review_value", "lineage_value", "metadata_value", "same_value", "edit_now", "my_edit", "undo_edits",
               "mark_changes", "decide_lineage", "set_file_metadata"]
        defs = ("SELECT (SELECT array_agg(table_name || ':' || column_name || ':' || data_type || ':' || is_nullable "
                "        || ':' || coalesce(column_default, '') ORDER BY table_name, ordinal_position) "
                "        FROM information_schema.columns "
                "        WHERE table_schema = 'pinakes' AND table_name = ANY (%(tables)s)), "
                "(SELECT array_agg(conrelid::regclass || ':' || pg_get_constraintdef(oid) "
                "                  ORDER BY conrelid::regclass::text, pg_get_constraintdef(oid)) FROM pg_constraint "
                " WHERE conrelid = ANY (SELECT to_regclass('pinakes.' || t) FROM unnest(%(tables)s::text[]) t)), "
                "(SELECT array_agg(indexdef ORDER BY indexdef) FROM pg_indexes "
                " WHERE schemaname = 'pinakes' AND tablename = ANY (%(tables)s)), "
                "(SELECT array_agg(tablename || ':' || policyname || ':' || cmd || ':' || qual ORDER BY policyname) "
                " FROM pg_policies WHERE schemaname = 'pinakes' AND tablename = ANY (%(tables)s)), "
                "(SELECT array_agg(relname || ':' || relrowsecurity ORDER BY relname) FROM pg_class "
                " WHERE relnamespace = 'pinakes'::regnamespace AND relname = ANY (%(tables)s)), "
                "(SELECT array_agg(pg_get_functiondef(p.oid) ORDER BY p.proname) FROM pg_proc p "
                " WHERE p.pronamespace = 'pinakes'::regnamespace AND p.proname = ANY (%(fns)s)), "
                "(SELECT array_agg(grantee || ':' || routine_name || ':' || privilege_type "
                "                 ORDER BY grantee, routine_name, privilege_type) "
                " FROM information_schema.routine_privileges WHERE routine_schema = 'pinakes' "
                " AND routine_name = ANY (%(fns)s)), "
                "(SELECT array_agg(table_name || ':' || grantee || ':' || privilege_type "
                "                  ORDER BY table_name, grantee, privilege_type) "
                " FROM information_schema.table_privileges "
                " WHERE table_schema = 'pinakes' AND table_name = ANY (%(tables)s)), "
                "(SELECT array_agg(sequence_name::text ORDER BY sequence_name) FROM information_schema.sequences "
                " WHERE sequence_schema = 'pinakes' AND sequence_name LIKE 'edit%%'), "
                "(SELECT array_agg(c.relname || ':' || has_sequence_privilege(r, c.oid, 'USAGE') ORDER BY c.relname, r) "
                " FROM pg_class c, unnest(ARRAY['pinakes_app', 'pinakes_ingest']) r "
                " WHERE c.relnamespace = 'pinakes'::regnamespace AND c.relkind = 'S' AND c.relname LIKE 'edit%%')")
        args = {"tables": tables, "fns": fns}

        def older(upgrade, name):
            with open(os.path.join(UPGRADES, upgrade)) as f:
                text = f.read()
            start = re.search(r"^CREATE (OR REPLACE )?FUNCTION %s\(" % name, text, re.M).start()
            fn = text[start:text.index("END $$;", start) + len("END $$;")]
            return "SET search_path = pinakes; " + re.sub(r"^CREATE (OR REPLACE )?FUNCTION",
                                                          "CREATE OR REPLACE FUNCTION", fn)
        with admin_conn(self.db) as c:
            fresh = c.execute(defs, args).fetchone()
            # back to the catalog before it: the writes as release 10's upgrades before this one left them
            c.execute(older("scrub.sql", "mark_changes"))
            c.execute(older("lineage-decisions.sql", "decide_lineage"))
            c.execute(older("person-metadata.sql", "set_file_metadata"))
            c.execute("DROP FUNCTION pinakes.undo_edits(bigint[]), pinakes.edit_now(text), "
                      "pinakes.review_value(bigint), pinakes.lineage_value(bigint, bigint, text), "
                      "pinakes.metadata_value(bigint, text, int), pinakes.same_value(jsonb, jsonb)")
            c.execute("DROP TABLE pinakes.edit_items, pinakes.edits")
            c.execute("DROP FUNCTION pinakes.my_edit(int, int)")
            c.execute("RESET search_path")
            self.assertNotEqual(c.execute(defs, args).fetchone(), fresh)
            self.assertFalse(c.execute("SELECT %s" % compat.UPGRADE_PROBES["edits.sql"]).fetchone()[0])
            self.assertEqual(schema_missing(c), ["edits.sql"])
            with open(os.path.join(UPGRADES, "edits.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(schema_missing(c), [])
            self.assertEqual(c.execute(defs, args).fetchone(), fresh)
        self.assertIn("pinakes_app:undo_edits:EXECUTE", fresh[6])
        self.assertNotIn("pinakes_app:edit_now:EXECUTE", fresh[6])
        # and the writes work as before, kept now
        cli = self.as_("user-1")
        cli("tag", "store:" + self.P, "--add", "holiday", cwd=self.tmp)
        self.assertEqual(self.edits(cli)["total"], 1)


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCliReports(ServerCase):
    """What the server answered before `pinakes` asked it (ROADMAP 53 to 59): each command through the API, as the
    token's person, another person's records left out."""

    GONE = "people/user-1/cleanup/a.txt"

    def setUp(self):
        super().setUp()
        self.scan("server-1", "store")      # empty: a root's first scan is not a change (ROADMAP 52), the next is
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", self.GONE, b"cleanup a")
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "letter.txt", b"letter")
        self.scan("laptop-1", "downloads")
        self.agent("server-2", "snapshots", kind="backup", extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-01_0140/" + self.GONE, b"cleanup a")
        self.scan("server-2", "snapshots")
        os.remove(self.path("server-1", "store", self.GONE))
        self.scan("server-1", "store")
        self.conn.execute("INSERT INTO pinakes.review_marks (history_id, mark, marked_by) SELECT history_id, "
                          "'restore', %s FROM pinakes.history WHERE kind = 'gone'",
                          (self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-1'")[0][0],))
        self.cli = CliRun(self, "user-1")
        self.addCleanup(self.cli.close)
        with open(self.cli.client_toml, "a") as f:
            f.write('host = "server-1"\n')                              # this machine's name in the catalog

    def as_token(self, secret):
        self.cli.save(self.cli.home_token(), secret)

    def test_whoami_for_each_kind_of_token(self):
        cli = self.cli
        self.assertEqual(cli("whoami"), "user-1 (User One)'s token\nscopes: read\nroots: downloads, store, snapshots\n")
        self.assertEqual(json.loads(cli("whoami", "--json")),
                         {"person": "user-1", "display": "User One", "kind": "person", "scopes": ["read"],
                          "roots": ["downloads", "store", "snapshots"]})
        self.as_token(make_token(self, "user-1", roots=[self.q("SELECT root_id FROM pinakes.roots "
                                                                  "WHERE label = 'downloads'")[0][0]], client="phone"))
        self.assertEqual(json.loads(cli("whoami", "--json"))["roots"], ["downloads"])
        self.as_token(make_kind_token(self, "user-1", group="household", client="kitchen"))
        self.assertEqual(cli("whoami").splitlines()[0], "the group household, as no one member")
        self.assertEqual(json.loads(cli("whoami", "--json"))["kind"], "group")
        self.as_token(make_kind_token(self, "user-1", scopes=("ops",), client="deploy"))
        self.assertEqual(cli("whoami"), "an ops token: no person, no root\nscopes: ops\n")

    def test_export_is_the_persons_own(self):
        cli = self.cli
        mine = json.loads(cli("export"))
        self.assertEqual(mine["person"], "user-1")
        self.assertEqual(sorted((f["root"], f["relpath"]) for f in mine["files"]),
                         [("downloads", "letter.txt"), ("snapshots", "2026-01-01_0140/" + self.GONE),
                          ("store", self.GONE), ("store", "people/user-1/taxes.txt")])
        self.assertNotIn("diary", json.dumps(mine))
        self.assertEqual(json.loads(cli("export", "files", "--json")).keys(), {"person", "exported", "files"})
        table = list(csv.DictReader(io.StringIO(cli("export", "files", "--csv"))))
        self.assertEqual(sorted(t["relpath"] for t in table), ["2026-01-01_0140/" + self.GONE, "letter.txt", self.GONE,
                                                               "people/user-1/taxes.txt"])
        self.assertEqual(cli("export", "--csv", code=1), "pinakes: a CSV is one part: pinakes export PART --csv")
        self.assertIn("part is one of", cli("export", "everything", code=1))
        # a token limited to a root: that root's only; a group's or an ops token: refused
        self.as_token(make_token(self, "user-1", roots=[self.q("SELECT root_id FROM pinakes.roots "
                                                                  "WHERE label = 'downloads'")[0][0]], client="phone"))
        self.assertEqual([f["relpath"] for f in json.loads(cli("export", "files"))["files"]], ["letter.txt"])
        self.as_token(make_kind_token(self, "user-1", group="household", client="kitchen"))
        self.assertEqual(cli("export", code=1), "pinakes: an export is a person's own records: use a person's token")
        self.as_token(make_kind_token(self, "user-1", scopes=("ops",), client="deploy"))
        self.assertEqual(cli("export", code=1), "pinakes: this token doesn't have the read scope")
        # and user-2's is hers
        self.as_token(make_token(self, "user-2", client="laptop-2"))
        self.assertEqual([f["relpath"] for f in json.loads(cli("export", "files"))["files"]], ["people/user-2/diary.txt"])

    def test_at_risk(self):
        cli = self.cli
        got = json.loads(cli("at-risk", "--json"))
        self.assertEqual(sorted(got), ["disks", "folders", "folders_shown", "folders_total", "hosts"])
        self.assertEqual({(h["host"], h["files"]) for h in got["hosts"]}, {("server-1", 1), ("laptop-1", 1), ("server-2", 1)})
        # the gone file's one backup copy is now its only copy: at risk with its disk
        self.assertEqual(sorted((f["root"], f["folder"], f["owner"]) for f in got["folders"]),
                         [("downloads", "", "User One"), ("snapshots", "2026-01-01_0140", "User One"),
                          ("store", "people", "User One")])
        self.assertNotIn("owner_id", json.dumps(got))
        text = cli("at-risk")
        self.assertTrue(text.startswith("lost with a disk (no copy on another disk of any machine):\n"), text)
        self.assertIn("lost with a machine", text)
        self.assertIn("3 B", text)                                     # "his", as a size to read
        # her diary is hers: not in his, and his not in hers
        self.as_token(make_token(self, "user-2", client="laptop-2"))
        got = json.loads(cli("at-risk", "--json"))
        self.assertEqual([(f["root"], f["owner"], f["files"]) for f in got["folders"]], [("store", "User Two", 1)])
        # a token limited to a root: only that root
        self.as_token(make_token(self, "user-1", roots=[self.q("SELECT root_id FROM pinakes.roots "
                                                                  "WHERE label = 'downloads'")[0][0]], client="phone"))
        self.assertEqual([h["host"] for h in json.loads(cli("at-risk", "--json"))["hosts"]], ["laptop-1"])
        # nothing at risk: said so (she has nothing in the downloads)
        self.as_token(make_token(self, "user-2", roots=[self.q("SELECT root_id FROM pinakes.roots "
                                                                  "WHERE label = 'downloads'")[0][0]], client="tv"))
        self.assertEqual(cli("at-risk"), "nothing at risk: every file you can see has a copy you can see on another "
                                         "disk\n")

    def test_growth_from_a_folder_and_given_one(self):
        cli = self.cli
        got = json.loads(cli("growth", "store:people", "--json"))
        self.assertEqual(sorted(got), ["cut", "rows"])
        self.assertFalse(got["cut"])
        self.assertEqual({(r["folder"], r["files_added"], r["files_gone"]) for r in got["rows"]}, {("user-1", 2, 1)})
        self.assertNotIn("owners", json.dumps(got))
        here = json.loads(cli("growth", "--json", "--weeks", "2", cwd=self.path("server-1", "store", "people/user-1")))
        self.assertEqual(sorted((r["folder"], r["files_added"]) for r in here["rows"]), [("", 1), ("cleanup", 1)])
        text = cli("growth", cwd=self.path("server-1", "store", "people/user-1"))
        self.assertTrue(text.startswith("growth per folder under store:people/user-1, per week, in the last 8 "
                                        "weeks:\n"), text)
        self.assertIn("(files directly in it)", text)
        self.assertEqual(cli("growth", "taxes.txt", cwd=self.path("server-1", "store", "people/user-1"), code=1),
                         "pinakes: pinakes growth needs a folder; taxes.txt is a file: `pinakes history` shows its "
                         "changes")
        # hers is not counted in his, and his not in hers
        self.as_token(make_token(self, "user-2", client="laptop-2"))
        self.assertEqual({r["folder"] for r in json.loads(cli("growth", "store:people", "--json"))["rows"]}, {"user-2"})

    def test_restores_and_where_they_are_held(self):
        cli = self.cli
        rows = json.loads(cli("restores", "--json"))["rows"]
        self.assertEqual([(r["root"], r["old_relpath"], r["backups"], r["back"]) for r in rows],
                         [("store", self.GONE, 1, False)])
        self.assertEqual(rows[0]["held_in"], [{"root": "snapshots", "snapshot": "2026-01-01",
                                              "path": "2026-01-01_0140/" + self.GONE}])
        text = cli("restores", "store:people/user-1")
        self.assertIn("store:" + self.GONE, text)
        self.assertIn("snapshots:2026-01-01_0140/" + self.GONE, text)        # a cell is cut at 60 characters
        self.assertEqual(cli("restores", "store:people/user-2"), "(none)\n")
        # back where it was: gone from the list unless --back is asked for
        self.write("server-1", "store", self.GONE, b"cleanup a")
        self.scan("server-1", "store")
        self.assertEqual(json.loads(cli("restores", "--json"))["rows"], [])
        self.assertEqual([r["back"] for r in json.loads(cli("restores", "--back", "--json"))["rows"]], [True])
        # not hers to see
        self.as_token(make_token(self, "user-2", client="laptop-2"))
        self.assertEqual(json.loads(cli("restores", "--back", "--json"))["rows"], [])

    def test_changes_tree_and_filters(self):
        cli = self.cli
        tree = json.loads(cli("changes", "store:", "--tree", "--json"))
        self.assertEqual(sorted(tree), ["cut", "rows"])
        by = {r["folder"]: r for r in tree["rows"]}
        self.assertEqual(sorted(by), ["", "people", "people/user-1", "people/user-1/cleanup"])
        self.assertEqual((by["people/user-1"]["new"], by["people/user-1"]["gone"]), (2, 1))
        self.assertNotIn("owners", json.dumps(tree))
        shallow = json.loads(cli("changes", "store:", "--tree", "--depth", "1", "--json"))
        self.assertEqual([r["folder"] for r in shallow["rows"]], ["", "people"])
        text = cli("changes", "--tree", cwd=self.path("server-1", "store", "people"))
        self.assertTrue(text.startswith("changes per folder under store:people in the last 7 days:\n"), text)
        self.assertIn("  user-1", text.replace("people/", ""))
        self.assertEqual(cli("changes", "--tree", "--host", "server-1", code=1),
                         "pinakes: pinakes changes --tree takes a folder, not --host")
        # the filters, on the list and on the tree
        gone = json.loads(cli("changes", "store:", "--what", "gone", "--json"))["rows"]
        self.assertEqual([(r["kind"], r["old_relpath"]) for r in gone], [("gone", self.GONE)])
        self.assertEqual(sorted(r["kind"] for r in json.loads(cli("changes", "store:", "--what", "gone", "--what",
                                                                   "new", "--json"))["rows"]), ["gone", "new", "new"])
        self.assertEqual(json.loads(cli("changes", "store:", "--what", "gone", "--review", "unreviewed",
                                        "--json"))["rows"], [])
        self.assertEqual(len(json.loads(cli("changes", "store:", "--what", "gone", "--review", "reviewed",
                                            "--json"))["rows"]), 1)
        self.assertEqual({r["folder"]: r["gone"] for r in json.loads(cli(
            "changes", "store:", "--tree", "--what", "gone", "--json"))["rows"]}["people/user-1/cleanup"], 1)
        self.assertIn("what is one of", cli("changes", "--what", "renamed", code=1))
        # her changes are not counted in his tree, and his not in hers
        self.as_token(make_token(self, "user-2", client="laptop-2"))
        self.assertEqual({r["folder"] for r in json.loads(cli("changes", "store:", "--tree", "--json"))["rows"]},
                         {"", "people", "people/user-2"})

    def test_access_is_the_persons_own(self):
        cli = self.cli
        cli("whoami")
        rows = json.loads(cli("access", "--json"))["rows"]
        self.assertEqual([(r["action"], r["detail"]["call"], r["mine"]) for r in rows[:2]],
                         [("api", "access", True), ("api", "whoami", True)])          # the newest first
        self.assertTrue(all(r["actor"] == "User One" for r in rows))
        text = cli("access").splitlines()
        self.assertEqual(text[0].split(), ["at", "actor", "action", "detail"])
        self.assertIn('"call": "access"', text[1])
        self.assertEqual(text[1].split()[2], "you")
        # hers has none of his calls
        self.as_token(make_token(self, "user-2", client="laptop-2"))
        hers = json.loads(cli("access", "--json"))["rows"]
        self.assertEqual([r["detail"]["call"] for r in hers if r["action"] == "api"], ["access"])
        self.assertTrue(all(r["mine"] and r["actor"] == "User Two" for r in hers), hers)
        # a group's or an ops token: refused
        self.as_token(make_kind_token(self, "user-1", group="household", client="kitchen"))
        self.assertEqual(cli("access", code=1), "pinakes: an access record is a person's own: use a person's token")
        self.as_token(make_kind_token(self, "user-1", scopes=("ops",), client="deploy"))
        self.assertEqual(cli("access", code=1), "pinakes: this token doesn't have the read scope")


@unittest.skipUnless(web is not None, "Flask not installed")
class TestCliPages(ServerCase):
    """Paged answers with counts (ROADMAP 61): every list call of the API answers one page by default, with the
    total; each paged command says "N of TOTAL" and takes --limit and --offset, its --json carrying the total."""

    def setUp(self):
        super().setUp()
        import jpegs
        self.scan("server-1", "store")      # empty: a root's first scan is not a change (ROADMAP 52), the next is
        for i in range(5):
            self.write("server-1", "store", "people/user-1/notes/note-%d.txt" % i, b"note %d" % i)
            self.write("server-1", "store", "people/user-1/copies/c-%d.txt" % i, b"the same")
            self.write("server-1", "store", "people/user-1/photos/IMG_%04d.JPG" % i,
                       jpegs.camera(make="Maker-1", when="2019:06:01 12:30:0%d" % i))
            self.write("server-1", "store", "people/user-2/notes/note-%d.txt" % i, b"hers %d" % i)
        self.write("server-1", "store", "people/user-1/edited.txt", b"v0")
        self.scan("server-1", "store")
        for v in range(1, 5):               # four more versions: five history rows
            self.write("server-1", "store", "people/user-1/edited.txt", b"v%d" % v, mtime=time.time() + v)
            self.scan("server-1", "store")
        self.cli = CliRun(self, "user-1")
        self.addCleanup(self.cli.close)

    # each command: its arguments, and how many rows user-1 sees
    COMMANDS = [("find", ["note-*"], 5), ("where", ["store:people/user-1/copies/c-0.txt"], 5),
                ("history", ["store:people/user-1/edited.txt"], 5), ("changes", ["store:people/user-1"], 20),
                ("only-here", ["store:people/user-1/notes"], 5), ("backed-up", ["store:people/user-1/photos"], 5),
                ("meta", ["exif.make=Maker-1"], 5)]

    def test_each_command_says_n_of_total_and_pages(self):
        cli = self.cli
        for cmd, args, total in self.COMMANDS:
            with self.subTest(cmd=cmd):
                whole = cli(cmd, *args).splitlines()
                self.assertEqual(whole[-1], "%d of %d" % (total, total))
                first = cli(cmd, *args, "--limit", "2").splitlines()
                self.assertEqual(first[-1], "2 of %d; the next: --offset 2" % total)
                self.assertEqual(len(first), len(whole) - (total - 2))                  # two rows, not all
                second = cli(cmd, *args, "--limit", "2", "--offset", "2").splitlines()
                self.assertEqual(second[-1], "3-4 of %d; the next: --offset 4" % total)
                last = cli(cmd, *args, "--limit", "2", "--offset", str(total - 1)).splitlines()
                self.assertEqual(last[-1], "%d-%d of %d" % (total, total, total))
                self.assertEqual(cli(cmd, *args, "--offset", str(total)).splitlines()[-1],
                                 "none of %d: --offset %d is past the end" % (total, total))
                got = json.loads(cli(cmd, *args, "--limit", "2", "--offset", "1", "--json"))
                self.assertEqual((sorted(got), got["total"], len(got["rows"]), got["limit"], got["offset"]),
                                 (["limit", "offset", "rows", "total"], total, 2, 2, 1))
                self.assertNotIn("total_rows", got["rows"][0])
                # the pages are the whole list, in order, with nothing twice
                pages = [r for o in range(0, total, 2)
                         for r in json.loads(cli(cmd, *args, "--limit", "2", "--offset", str(o), "--json"))["rows"]]
                self.assertEqual(pages, json.loads(cli(cmd, *args, "--json"))["rows"])

    def test_the_api_answers_one_page_by_default(self):
        with mock.patch.object(web, "API_PAGE", 3):
            got = json.loads(self.cli("find", "*.txt", "--json"))
        self.assertEqual((len(got["rows"]), got["total"], got["limit"], got["offset"]), (3, 11, 3, 0))
        got = json.loads(self.cli("find", "*.txt", "--limit", "999999", "--json"))   # at most API_MAX
        self.assertEqual((len(got["rows"]), got["total"], got["limit"]), (11, 11, web.API_MAX))
        # a page past the end still says the total
        got = json.loads(self.cli("find", "*.txt", "--offset", "50", "--json"))
        self.assertEqual((got["rows"], got["total"], got["offset"]), ([], 11, 50))

    def test_a_total_counts_only_what_the_person_sees(self):
        cli = self.cli
        cli.save(cli.home_token(), make_token(self, "user-2", client="laptop-2"))
        got = json.loads(cli("find", "note-*", "--limit", "1", "--json"))
        self.assertEqual((got["total"], [r["relpath"] for r in got["rows"]]), (5, ["people/user-2/notes/note-0.txt"]))
        self.assertEqual(json.loads(cli("changes", "store:", "--limit", "1", "--json"))["total"], 5)
        self.assertEqual(json.loads(cli("meta", "exif.make=Maker-1", "--json"))["total"], 0)
        self.assertEqual(cli("where", "store:people/user-1/copies/c-0.txt", code=1),
                         "pinakes: no file you can see there")

    def test_whole_lists_for_review_and_tag_page_through(self):
        """review and tag act on every row under a folder: they ask a page at a time until the last."""
        cli = self.cli
        cli.save(cli.home_token(), make_token(self, "user-1", ("read", "review", "tag"), client="laptop-3"))
        for i in range(5):
            os.remove(self.path("server-1", "store", "people/user-1/notes/note-%d.txt" % i))
        self.scan("server-1", "store")
        with mock.patch("pinakes.cli.BATCH", 2):
            self.assertIn("marked 5 of 5 as intended", cli("review", "intended", "store:people/user-1/notes", "--yes"))
            self.assertIn("tagged 5 of 5", cli("tag", "store:people/user-1/photos", "--add", "trip", "--yes"))

    def test_an_export_is_every_page(self):
        """The API answers a page of each part; pinakes export asks until the last and gives them all, once."""
        cli = self.cli
        whole = json.loads(cli("export"))
        self.assertEqual((len(whole["files"]), len(whole["history"])), (16, 20))        # pages of 4: several
        with mock.patch.object(web, "API_PAGE", 3):
            got = self.cli.app.test_client().get("/api/v1/export?part=files", headers={
                "Authorization": "Bearer " + make_token(self, "user-1", client="laptop-4")}).get_json()
        self.assertEqual((len(got["files"]), got["limit"], got["offset"]), (3, 3, 0))
        with mock.patch("pinakes.cli.EXPORT_BATCH", 4):
            paged = json.loads(cli("export"))
            table = list(csv.DictReader(io.StringIO(cli("export", "history", "--csv"))))
        self.assertEqual({k: v for k, v in paged.items() if k != "exported"},
                         {k: v for k, v in whole.items() if k != "exported"})
        self.assertEqual(sorted(paged), ["exported", "files", "history", "lineage", "metadata", "person", "reviews"])
        self.assertEqual([r["history_id"] for r in table], [str(r["history_id"]) for r in whole["history"]])

    def test_safe_to_delete_pages_its_files(self):
        cli = self.cli
        text = cli("safe-to-delete", "store:people/user-1/notes", "--limit", "2").splitlines()
        self.assertEqual(text[-1], "2 of 5; the next: --offset 2")
        got = json.loads(cli("safe-to-delete", "store:people/user-1/notes", "--limit", "2", "--json"))
        self.assertEqual((len(got["not_safe"]), got["total"], got["links_into"], got["links_into_total"]),
                         (2, 5, [], 0))
        # past the end of the list is not "safe"
        self.assertNotIn("safe:", cli("safe-to-delete", "store:people/user-1/notes", "--offset", "9"))


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

    def test_the_token_forms_suit_a_password_manager_and_answer_by_the_form(self):
        """ROADMAP 49: a password manager fills the text field before a password with the user name; each token form
        has its own for that, and the others say they aren't to be filled. Its message and token come back next to
        the form that sent them, and the form's action jumps there."""
        c = self.login("user-1")                                        # an operator: both forms
        page = c.get("/account").get_data(as_text=True)
        forms = re.findall(r'<form method="post" action="/account#([\w-]+)".*?</form>', page, re.S)
        self.assertEqual(forms, ["make-token", "make-ops-token"])
        for action in forms:
            form = re.search(r'<div id="%s">.*?<form [^>]*#%s".*?</form>' % (action, action), page, re.S).group(0)
            inputs = re.findall(r"<input [^>]*>", form)
            kinds = [re.search(r'autocomplete="([\w-]+)"', i).group(1) if "autocomplete" in i else None
                     for i in inputs if 'type="hidden"' not in i and 'type="checkbox"' not in i
                     and 'type="radio"' not in i]
            self.assertEqual(kinds, ["username", "off", "off", "current-password"], action)
            user = next(i for i in inputs if 'autocomplete="username"' in i)
            self.assertIn('value="user-1"', user)
            self.assertNotIn("name=", user)                             # never sent
        # a refused form: its message by it, not at the top
        tok = self.csrf(c, "/account")
        bad = c.post("/account", data={"csrf": tok, "action": "make-ops-token", "client": "deploy",
                                       "days": "user-1", "current": PASSWORDS["user-1"]}).get_data(as_text=True)
        said = "Expires after is a number of days, or empty for until revoked."
        self.assertEqual(bad.count(said), 1)
        self.assertLess(bad.index('<div id="make-ops-token">'), bad.index(said))
        self.assertLess(bad.index(said), bad.index('action="/account#make-ops-token"'))
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.tokens")[0][0], 0)
        # a made one: the message and token by the form that made it, for each form
        for action, extra in (("make-ops-token", {}), ("make-token", {"scope": ["read"], "roots": "all"})):
            made = c.post("/account", data=dict(extra, csrf=tok, action=action, client="c-" + action, days="",
                                                current=PASSWORDS["user-1"])).get_data(as_text=True)
            at = made.index('<div id="%s">' % action)
            self.assertLess(at, made.index("made for c-%s." % action))
            self.assertLess(at, made.index("Your new token:"))
            self.assertLess(made.index("Your new token:"), made.index('action="/account#%s"' % action))
            self.assertEqual(made.count("Your new token:"), 1)
        # other messages stay at the top
        top = c.post("/account", data={"csrf": tok, "action": "revoke-token", "token": "0"}).get_data(as_text=True)
        self.assertLess(top.index("No such token of yours to revoke."), top.index("<h2>Second factor</h2>"))

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
            self.assertEqual(row, (None, ["ops"], "ops", None))
            self.assertEqual(conn.execute("SELECT pinakes.current_person(), count(*) FROM pinakes.files")
                             .fetchone(), (None, 0))
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "no person set"):
                conn.execute("SELECT pinakes.mark_changes('{1}', 'intended')")


class TestGroupToken(ApiCase):
    """Group tokens (ROADMAP 38): a token that acts as a group and no member. The household owns store:household
    and reads store:people/user-2/for-household; user-3 is no member."""

    SERVER_EXTRA = """
[people.user-3]
display = "User Three"
roles = ["person"]
[[ownership.rule]]
root = "store"
folder = "household"
owner = "household"
[[ownership.enrollment]]
root = "store"
folder = "people/user-2/for-household"
group = "household"
as = "reader"
"""
    GONE = ("household/old.txt", "people/user-2/for-household/old.txt", "people/user-1/old.txt")

    def setUp(self):
        super().setUp()
        self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) VALUES (%s, %s)",
                          (self.pid("user-3"), auth.hash_password(PASSWORDS["user-3"])))
        for rel in ("household/budget.txt", "people/user-2/for-household/recipe.txt") + self.GONE:
            self.write("server-1", "store", rel, b"content of " + rel.encode())
        self.scan("server-1", "store")
        for rel in self.GONE:
            os.remove(self.path("server-1", "store", rel))
        self.scan("server-1", "store")

    def gone_ids(self):
        return dict(self.q("SELECT old_relpath, history_id FROM pinakes.history WHERE kind = 'gone'"))

    def test_it_sees_the_groups_files_and_no_members_own(self):
        grp = self.token("user-1", group="household")
        self.assertEqual(self.paths("find?q=*.txt", grp),
                         ["store:household/budget.txt", "store:people/user-2/for-household/recipe.txt"])
        self.assertEqual(self.get("whoami", grp)[1], {"person": None, "group": "household", "kind": "group",
                                                      "scopes": ["read"], "roots": ["store"]})
        self.assertEqual(self.get("where?loc=store:people/user-1/taxes.txt", grp)[0], 404)
        self.assertEqual(sorted(r["path"] for r in self.get("changes?days=7&what=gone", grp)[1]["rows"]),
                         ["household/old.txt", "people/user-2/for-household/old.txt"])
        # its maker's own token sees theirs and the group's: the two are never added up in one token
        self.assertIn("store:people/user-1/taxes.txt", self.paths("find?q=*.txt", self.token("user-1")))
        # the database: no person, the group's files only, and its roots held as a person's are
        with self.app_conn() as conn:
            row = conn.execute("SELECT * FROM pinakes.begin_token_call(%s, 'test')",
                               (hashlib.sha256(grp.encode()).digest(),)).fetchone()
            self.assertEqual(row, (None, ["read"], "group", "household"))
            self.assertEqual(conn.execute("SELECT pinakes.current_person(), pinakes.current_group(), "
                                          "pinakes.stepped_up()").fetchone(), (None, self.gid("household"), False))
            self.assertEqual(sorted(r[0] for r in conn.execute("SELECT relpath FROM pinakes.files")),
                             ["household/budget.txt", "household/old.txt", "people/user-2/for-household/old.txt",
                              "people/user-2/for-household/recipe.txt"])
            self.assertEqual(conn.execute("SELECT count(*) FROM pinakes.audit").fetchone()[0], 0)
        limited = self.token("user-1", group="household", roots=[self.root_id("downloads")])
        self.assertEqual(self.paths("find?q=*.txt", limited), [])

    def test_its_calls_are_on_every_members_record(self):
        grp = self.token("user-2", group="household", client="kitchen")
        self.get("find?q=budget*", grp)
        self.assertEqual(self.q("SELECT p.name, a.affects, a.detail->>'token', a.detail->>'group', a.detail->>'call' "
                                "FROM pinakes.audit a JOIN pinakes.people p ON p.person_id = a.actor "
                                "WHERE a.action = 'api'"),
                         [("user-2", [self.pid("user-1"), self.pid("user-2")], "kitchen", "household",
                           "find?q=budget*")])
        made = self.q("SELECT actor, affects, detail->>'group' FROM pinakes.audit WHERE action = 'token_made'")
        self.assertEqual(made, [(self.pid("user-2"), [self.pid("user-1"), self.pid("user-2")], "household")])
        page = self.login("user-1").get("/access").get_data(as_text=True)
        self.assertIn("kitchen", page)
        self.assertNotIn("kitchen", self.login("user-3").get("/access").get_data(as_text=True))

    def test_only_members_make_see_and_revoke_it(self):
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "only a member of the group makes its tokens"):
            self.token("user-3", group="household")
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "the ops scope alone, and no roots or group"):
            self.token("user-1", scopes=("ops",), group="household")
        # on the account page: a member chooses the group; a non-member has no choice, and a forged one is refused
        c = self.login("user-2")
        page = c.get("/account").get_data(as_text=True)
        self.assertIn('<option value="%d">the group household</option>' % self.gid("household"), page)
        page = c.post("/account", data={"csrf": self.csrf(c, "/account"), "action": "make-token", "client": "kitchen",
                                        "as": str(self.gid("household")), "scope": "read", "roots": "all",
                                        "days": "", "current": PASSWORDS["user-2"]}).get_data(as_text=True)
        self.assertIn("Group token made for kitchen.", page)
        secret = re.search(r'Your new token: <span class="mono">(pinakes_[\w-]+)</span>', page).group(1)
        self.assertEqual(self.get("whoami", secret)[1]["group"], "household")
        c3 = self.login("user-3")
        self.assertNotIn('name="as"', c3.get("/account").get_data(as_text=True))
        page = c3.post("/account", data={"csrf": self.csrf(c3, "/account"), "action": "make-token", "client": "x",
                                         "as": str(self.gid("household")), "scope": "read", "roots": "all",
                                         "days": "", "current": PASSWORDS["user-3"]}).get_data(as_text=True)
        self.assertIn("Not made: only a member of the group makes its tokens.", page)
        # every member sees it and may revoke it; no one else
        listed = self.login("user-1").get("/account").get_data(as_text=True)
        self.assertIn('<td>kitchen</td><td>group household <span class="muted">(by User Two)</span></td>', listed)
        self.assertNotIn("kitchen", c3.get("/account").get_data(as_text=True))
        tid = self.q("SELECT token_id FROM pinakes.tokens WHERE client = 'kitchen'")[0][0]
        page = c3.post("/account", data={"csrf": self.csrf(c3, "/account"), "action": "revoke-token",
                                         "token": str(tid)}).get_data(as_text=True)
        self.assertIn("No such token of yours to revoke.", page)
        self.assertEqual(self.get("whoami", secret)[0], 200)
        c1 = self.login("user-1")
        page = c1.post("/account", data={"csrf": self.csrf(c1, "/account"), "action": "revoke-token",
                                         "token": str(tid)}).get_data(as_text=True)
        self.assertIn("Token revoked.", page)
        self.assertEqual(self.get("whoami", secret)[0], 401)
        self.assertEqual(self.q("SELECT actor, affects, detail->>'group' FROM pinakes.audit "
                                "WHERE action = 'token_revoked'"),
                         [(self.pid("user-1"), [self.pid("user-1"), self.pid("user-2")], "household")])

    def test_a_former_members_token_stops_working(self):
        grp = self.token("user-2", group="household")
        self.assertEqual(self.get("whoami", grp)[0], 200)
        self.conn.execute("DELETE FROM pinakes.group_members WHERE person_id = %s", (self.pid("user-2"),))
        self.ing.refresh_acl_members()
        self.assertEqual(self.get("whoami", grp)[0], 401)
        self.assertEqual(self.get("find?q=*.txt", grp)[0], 401)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "only a member of the group makes its tokens"):
            self.token("user-2", group="household")
        with self.app_conn() as conn:                   # nor listed for them, nor theirs to revoke
            conn.execute("SELECT set_config('pinakes.person', %s, true)", (str(self.pid("user-2")),))
            self.assertEqual(conn.execute("SELECT count(*) FROM pinakes.my_tokens()").fetchone()[0], 0)
            tid = self.q("SELECT token_id FROM pinakes.tokens")[0][0]
            self.assertFalse(conn.execute("SELECT pinakes.revoke_token(%s)", (tid,)).fetchone()[0])
        # a member's token of the same group still works: the group didn't change, its maker did
        self.assertEqual(self.paths("find?q=budget*", self.token("user-1", group="household")),
                         ["store:household/budget.txt"])

    def test_its_marks_are_the_groups(self):
        ids = self.gone_ids()
        post = lambda secret: self.app.test_client().post(
            "/api/v1/review", json={"mark": "intended", "ids": sorted(ids.values())},
            headers={"Authorization": "Bearer " + secret})
        self.assertEqual(post(self.token("user-1", group="household")).status_code, 403)    # no review scope
        r = post(self.token("user-1", scopes=("read", "review"), group="household", client="tidy"))
        # its own folder only: not the one it reads, nor a member's own
        self.assertEqual(r.get_json(), {"asked": 3, "marked": 1})
        self.assertEqual(self.q("SELECT history_id, mark, marked_by, marked_by_group FROM pinakes.review_marks"),
                         [(ids["household/old.txt"], "intended", None, self.gid("household"))])
        self.assertEqual(self.q("SELECT actor, affects, detail - 'call' FROM pinakes.audit WHERE action = 'review'"),
                         [(self.pid("user-1"), [self.pid("user-1"), self.pid("user-2")],
                           {"mark": "intended", "changes": 1, "token": "tidy", "group": "household"})])
        # shown as the group's, to a member on the web and through the API
        page = self.login("user-2").get("/reports/changes?days=7").get_data(as_text=True)
        self.assertIn('<span class="tag">intended</span> <span class="muted">household,', page)
        rows = self.get("changes?days=7", self.token("user-2"))[1]["rows"]
        self.assertEqual({r["path"]: r["marked_by"] for r in rows if r["mark"]}, {"household/old.txt": "household"})
        # a member marking the same change later makes it theirs
        with self.app_conn() as conn:
            conn.execute("SELECT set_config('pinakes.person', %s, true)", (str(self.pid("user-2")),))
            self.assertEqual(conn.execute("SELECT pinakes.mark_changes(%s, 'restore')",
                                          ([ids["household/old.txt"]],)).fetchone()[0], 1)
        self.assertEqual(self.q("SELECT mark, marked_by, marked_by_group FROM pinakes.review_marks"),
                         [("restore", self.pid("user-2"), None)])

    def test_sensitive_metadata_where_the_group_owns(self):
        for rel in ("household/budget.txt", "people/user-2/for-household/recipe.txt"):
            self.conn.execute("INSERT INTO pinakes.metadata (content_id, schema, vals, source, sensitive) "
                              "SELECT content_id, 'exif', '{\"gps\": [0, 0]}', 'embedded', true FROM pinakes.files "
                              "WHERE relpath = %s", (rel,))
        grp = self.token("user-1", group="household")
        with self.app_conn() as conn:
            conn.execute("SELECT * FROM pinakes.begin_token_call(%s, 'test')", (hashlib.sha256(grp.encode()).digest(),))
            self.assertEqual([r[0] for r in conn.execute(
                "SELECT f.relpath FROM pinakes.metadata m JOIN pinakes.files f USING (content_id) WHERE m.sensitive")],
                ["household/budget.txt"])                    # the owner's, not the reader's

    def test_root_counts_are_each_callers_own(self):
        """ROADMAP 48: every root's counts in one grouped pass give what a count per root gives, for each kind of
        caller, hidden files shown and not; a root with none of the caller's files counts 0."""
        self.write("server-1", "store", "household/.notes.txt", b"hidden")
        self.write("server-1", "store", "people/user-1/.private/key.txt", b"hidden too")
        self.scan("server-1", "store")
        live = ("SELECT r.label, (SELECT count(*) FROM pinakes.present f WHERE f.root_id = r.root_id "
                "AND (%s OR NOT f.hidden)), (SELECT count(*) FROM pinakes.present f WHERE f.root_id = r.root_id "
                "AND f.hidden) FROM pinakes.roots r WHERE pinakes.token_roots() IS NULL "
                "OR r.root_id = ANY (pinakes.token_roots()) ORDER BY r.label")
        callers = {"user-1 signed in": ("user-1", None), "user-2 signed in": ("user-2", None),
                   "user-3 signed in": ("user-3", None),
                   "user-1's token": ("user-1", self.token("user-1")),
                   "the household's token": ("user-1", self.token("user-1", group="household", client="kitchen")),
                   "a token for downloads": ("user-1", self.token("user-1", roots=[self.root_id("downloads")],
                                                                    client="workstation-1"))}
        seen = {}
        for what, (name, secret) in callers.items():
            for hidden in (True, False):
                with self.app_conn() as c:
                    if secret:
                        c.execute("SELECT pinakes.begin_token_call(%s, 'test')",
                                  (hashlib.sha256(secret.encode()).digest(),))
                    else:
                        c.execute("SELECT set_config('pinakes.person', %s, false)", (str(self.pid(name)),))
                    got = [(r["label"], r["files"], r["hidden_files"]) for r in queries.roots(c, hidden=hidden)]
                    self.assertEqual(sorted(got), c.execute(live, (hidden,)).fetchall(), (what, hidden))
                    seen[what, hidden] = sorted(got)
        # the numbers themselves, so that the two forms can't agree by both being wrong
        # user-1: taxes, plan, the household's budget, recipe and .notes, their own .private/key; user-2: diary, plan
        # and the household's three
        self.assertEqual(seen["user-1 signed in", True], [("downloads", 2, 0), ("store", 6, 2)])
        self.assertEqual(seen["user-1 signed in", False], [("downloads", 2, 0), ("store", 4, 2)])
        self.assertEqual(seen["user-2 signed in", True], [("downloads", 0, 0), ("store", 5, 1)])
        self.assertEqual(seen["user-3 signed in", True], [("downloads", 0, 0), ("store", 0, 0)])
        self.assertEqual(seen["user-1's token", True], [("store", 6, 2)])
        self.assertEqual(seen["the household's token", False], [("store", 2, 1)])
        self.assertEqual(seen["a token for downloads", True], [("downloads", 2, 0)])

    def test_files_policy_upgrade_matches_the_schema(self):
        """files-policy.sql (ROADMAP 48) turns the policy with visible_acls() bare into schema.sql's, and the server
        asks for it until it has run."""
        policy = ("SELECT pg_get_expr(polqual, polrelid) FROM pg_policy "
                  "WHERE polrelid = 'pinakes.files'::regclass AND polname = 'files_visible'")
        with admin_conn(self.db) as c:
            fresh = c.execute(policy).fetchone()[0]
            self.assertEqual(schema_missing(c), [])
            c.execute("ALTER POLICY files_visible ON pinakes.files USING (acl_id = ANY (pinakes.visible_acls()) "
                      "AND ((SELECT pinakes.token_roots()) IS NULL "
                      "OR root_id = ANY ((SELECT pinakes.token_roots())::int[])))")
            self.assertNotEqual(c.execute(policy).fetchone()[0], fresh)
            self.assertEqual(schema_missing(c), ["files-policy.sql"])
            with open(os.path.join(UPGRADES, "files-policy.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(policy).fetchone()[0], fresh)
            self.assertEqual(schema_missing(c), [])

    def test_upgrade_fills_the_groups_of_each_acl(self):
        fresh = self.check_upgrade_matches_the_schema()
        self.assertEqual(len(fresh[-1]), 2, fresh[-1])                  # the household's two ACLs, by its key
        self.assertEqual(sorted(x.rsplit(":", 1)[1] for x in fresh[-1]), ["owner", "reader"])
