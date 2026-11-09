"""The web UI through Flask's test client, on a catalog built by real scans, under row-level security."""

import datetime
import os
import re
import time
import unittest

from tests.test_server import PGHOST, ServerCase, admin_conn, psycopg

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

    def test_file_linked_from_a_protected_root_says_so(self):
        his = self.file_id("people/user-1/taxes.txt")
        c, _ = self.login("user-1", "correct horse battery")
        self.assertNotIn("protected", c.get("/file/%d" % his).get_data(as_text=True))
        self.conn.execute("UPDATE pinakes.files SET protected_link = true WHERE file_id = %s", (his,))
        self.assertIn("protected: linked from a protected root", c.get("/file/%d" % his).get_data(as_text=True))

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

    def test_browse_sizes_over_a_kilobyte(self):
        self.write("server-1", "store", "people/user-1/big.bin", b"x" * 1500)   # a folder's size is a numeric sum
        self.scan("server-1", "store")
        c1, _ = self.login("user-1", "correct horse battery")
        r = c1.get("/browse/store/people")
        self.assertEqual(r.status_code, 200)
        self.assertIn("1.5 KB", r.get_data(as_text=True))

    def test_reports_and_headers(self):
        c1, _ = self.login("user-1", "correct horse battery")
        r = c1.get("/reports/safe-to-delete?loc=store:people/user-1/")
        self.assertIn("Not safe", r.get_data(as_text=True))          # no backups yet
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertIn("a location is ROOT:PATH", c1.get("/reports/only-here?loc=nocolon").get_data(as_text=True))
        for url in ("/reports/dupes", "/reports/changes", "/reports/backed-up?loc=store:", "/access", "/account"):
            self.assertEqual(c1.get(url).status_code, 200, url)

    def test_changes_tree_and_what_filter(self):
        """A clean-up: a folder emptied into another (moves, not new and gone), one file deleted, one added."""
        from pinakes import queries
        for i in range(3):
            self.write("server-1", "store", "people/user-1/inbox/old/f%d.txt" % i, b"keep %d" % i)
        self.write("server-1", "store", "people/user-1/inbox/junk.txt", b"junk")
        self.scan("server-1", "store")
        with admin_conn(self.db) as c:   # what was there before the clean-up was seen a month ago
            c.execute("UPDATE pinakes.history SET seen_on = seen_on - 30, seen_after = seen_after - 30")
        self.write("server-1", "store", "people/user-1/sorted/index.txt", b"index")  # before the delete: no inode reuse
        os.makedirs(self.path("server-1", "store", "people/user-1/sorted/2026"), exist_ok=True)
        for i in range(3):
            os.rename(self.path("server-1", "store", "people/user-1/inbox/old/f%d.txt" % i),
                      self.path("server-1", "store", "people/user-1/sorted/2026/f%d.txt" % i))
        os.remove(self.path("server-1", "store", "people/user-1/inbox/junk.txt"))
        self.scan("server-1", "store")
        with self.as_person("user-1", "s-tree") as c:
            tree = {(t["root"], t["folder"]): (t["new"], t["changed"], t["moved_in"], t["moved_out"], t["gone"])
                    for t in queries.change_tree(c, 7, "store:people/user-1/", 3)}
            u = "people/user-1"
            self.assertEqual(tree[("store", u + "/inbox")], (0, 0, 0, 3, 1))
            self.assertEqual(tree[("store", u + "/inbox/old")], (0, 0, 0, 3, 0))
            self.assertEqual(tree[("store", u + "/sorted")], (1, 0, 3, 0, 0))
            self.assertEqual(tree[("store", u + "/sorted/2026")], (0, 0, 3, 0, 0))
            self.assertEqual(tree[("store", u)][2:], (3, 3, 1))                    # moves inside: in and out
            self.assertNotIn(("store", "people"), tree)                            # above the folder asked for
            self.assertEqual(len(queries.change_tree(c, 7, "store:people/user-1/", 1)), 3)   # depth: u, inbox, sorted
            gone = {(t["folder"]): t for t in queries.change_tree(c, 7, "store:", 2, ["gone"])}
            self.assertEqual(gone["people/user-1"]["gone"], 1)
            self.assertEqual(gone["people/user-1"]["moved_out"], 0)
            self.assertEqual(sum(t["new"] for t in gone.values()), 0)
            moved = queries.changes(c, 7, kinds=["moved"], loc="store:" + u + "/inbox/")
            self.assertEqual(sorted(r["old_relpath"] for r in moved), [u + "/inbox/old/f%d.txt" % i for i in range(3)])
            self.assertEqual({r["kind"] for r in queries.changes(c, 7, kinds=["gone", "bogus"])}, {"gone"})
        c1, _ = self.login("user-1", "correct horse battery")
        page = c1.get("/reports/changes?what=gone&loc=store:people/").get_data(as_text=True)
        self.assertIn("junk.txt", page)
        self.assertNotIn("index.txt", page)
        self.assertIn('value="gone" checked', page)
        page = c1.get("/reports/changes?what=moved&what=moved_changed&loc=store:people/user-1/sorted/").get_data(
            as_text=True)
        self.assertIn("from people/user-1/inbox/old/f0.txt", page)
        self.assertIn('class="t1"', page)
        # user-2 sees none of it: neither the folders nor the counts
        c2, _ = self.login("user-2", "staple pony 12345")
        page = c2.get("/reports/changes?loc=store:people/user-1/").get_data(as_text=True)
        self.assertNotIn("sorted/", page)
        self.assertNotIn("inbox", page)
        for bad in ("days=x&depth=99", "loc=nocolon", "what=x%27"):
            self.assertEqual(c1.get("/reports/changes?" + bad).status_code, 200, bad)

    def test_totp_enrollment(self):
        c2, _ = self.login("user-2", "staple pony 12345")
        tok = self.csrf(c2, "/account")
        page = c2.post("/account", data={"csrf": tok, "action": "start-totp"}).get_data(as_text=True)
        secret = re.search(r'class="mono">([A-Z2-7]+)<', page).group(1)
        r = c2.post("/account", data={"csrf": tok, "action": "confirm-totp", "code": auth.totp(secret)})
        self.assertIn("Second factor saved", r.get_data(as_text=True))
        self.assertIn("A second factor is set up", c2.get("/account").get_data(as_text=True))

    def test_mark_by_row_in_bulk_and_restore(self):
        """Marking by row and in bulk, with the session's CSRF token; the restore page names the backup; a second
        person's marks of the owner's changes are skipped and said so."""
        from pinakes import queries
        u = "people/user-1/cleanup/"
        for n in ("a", "b", "c"):
            self.write("server-1", "store", u + n + ".txt", b"cleanup " + n.encode())
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-01_0140/" + u + "a.txt", b"cleanup a")
        self.scan("server-2", "snapshots")
        for n in ("a", "b", "c"):
            os.remove(self.path("server-1", "store", u + n + ".txt"))
        self.scan("server-1", "store")
        ids = {r[1]: r[0] for r in self.q("SELECT history_id, old_relpath FROM pinakes.history WHERE kind = 'gone'")}
        c1, _ = self.login("user-1", "correct horse battery")
        page = c1.get("/reports/changes?loc=store:" + u).get_data(as_text=True)
        self.assertIn('name="id" value="%d"' % ids[u + "a.txt"], page)
        self.assertIn("only in 1 backup copy", page)
        self.assertIn("Mark in bulk", page)
        tok = self.csrf(c1, "/reports/changes")
        self.assertEqual(c1.post("/reports/changes/mark", data={"mark": "restore", "id": ids[u + "a.txt"]}).status_code,
                         400)                                                 # no token
        self.assertEqual(c1.post("/reports/changes/mark", data={"csrf": tok, "mark": "keep"}).status_code, 400)
        r = c1.post("/reports/changes/mark", data={"csrf": tok, "mark": "restore", "id": ids[u + "a.txt"],
                                                   "loc": "store:" + u, "days": "7", "review": "unreviewed"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("marked=1", r.headers["Location"])
        self.assertIn("review=unreviewed", r.headers["Location"])
        page = c1.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("1 of 1 change(s) marked.", page)
        self.assertNotIn(u + "a.txt", page)                                  # reviewed now: filtered out
        restore = c1.get("/reports/restore").get_data(as_text=True)
        self.assertIn("snapshots · 2026-01-01: 2026-01-01_0140/" + u + "a.txt", restore)
        # in bulk: the rest, seen up to today; a mark already made stays
        r = c1.post("/reports/changes/mark", data={"csrf": tok, "mark": "intended", "scope": "all", "loc": "store:" + u,
                                                   "days": "7", "until": datetime.date.today().isoformat()})
        self.assertIn("marked=2", r.headers["Location"])
        marks = dict(self.q("SELECT h.old_relpath, m.mark FROM pinakes.review_marks m JOIN pinakes.history h "
                            "USING (history_id)"))
        self.assertEqual(marks, {u + "a.txt": "restore", u + "b.txt": "intended", u + "c.txt": "intended"})
        self.assertEqual(c1.post("/reports/changes/mark", data={"csrf": tok, "mark": "clear", "scope": "all",
                                                                "until": "2026-01-01"}).status_code, 400)
        self.assertEqual(c1.post("/reports/changes/mark", data={"csrf": tok, "mark": "intended", "scope": "all",
                                                                "until": "soon"}).status_code, 400)
        # user-2 can't mark them, and is told
        c2, _ = self.login("user-2", "staple pony 12345")
        tok2 = self.csrf(c2, "/reports/changes")
        r = c2.post("/reports/changes/mark", data={"csrf": tok2, "mark": "clear", "id": list(ids.values())})
        self.assertIn("marked=0", r.headers["Location"])
        self.assertIn("not yours to mark", c2.get(r.headers["Location"]).get_data(as_text=True))
        self.assertNotIn("cleanup", c2.get("/reports/restore").get_data(as_text=True))
        self.assertEqual(len(self.q("SELECT 1 FROM pinakes.review_marks")), 3)


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


@unittest.skipUnless(web is not None, "Flask not installed")
class TestPaging(ServerCase):
    def setUp(self):
        super().setUp()
        for i in range(120):
            self.write("server-1", "store", "people/user-1/many/f%03d.txt" % i, b"only here %d" % i)
        self.scan("server-1", "store")
        pid = self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-1'")[0][0]
        self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) VALUES (%s, %s)",
                          (pid, auth.hash_password("correct horse battery")))
        app = web.create_app(server_config.loads(TestWeb.SERVER_WEB),
                             connect=lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db))
        app.testing = True
        self.c = app.test_client()
        tok = re.search(r'name="csrf" value="([^"]+)"', self.c.get("/login").get_data(as_text=True)).group(1)
        self.c.post("/login", data={"csrf": tok, "name": "user-1", "password": "correct horse battery"})

    def rows_on(self, html):
        return len(re.findall(r'href="/file/\d+">(?:[^<]*/)?f\d{3}\.txt<', html))   # a name, or a path to it

    def test_browse_pages(self):
        p1 = self.c.get("/browse/store/people/user-1/many?per=50").get_data(as_text=True)
        self.assertEqual(self.rows_on(p1), 50)
        self.assertIn("1–50 of 120 entries", p1)
        self.assertIn("page 1 of 3", p1)
        self.assertIn('rel="next"', p1)
        p3 = self.c.get("/browse/store/people/user-1/many?per=50&page=3").get_data(as_text=True)
        self.assertEqual(self.rows_on(p3), 20)
        self.assertIn("101–120 of 120", p3)
        self.assertNotIn('rel="next"', p3)
        names = lambda h: re.findall(r'>(f\d{3})\.txt<', h)
        p2 = self.c.get("/browse/store/people/user-1/many?per=50&page=2").get_data(as_text=True)
        self.assertEqual(len(set(names(p1)) | set(names(p2)) | set(names(p3))), 120)   # no overlap, none missing

    def test_bad_page_arguments_fall_back(self):
        r = self.c.get("/browse/store/people/user-1/many?per=7&page=x")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.rows_on(r.get_data(as_text=True)), 100)      # the default size, page 1

    def test_find_and_report_totals(self):
        f = self.c.get("/find?q=f0&per=50").get_data(as_text=True)
        self.assertIn("of 100 files", f)                                   # f000-f099
        r = self.c.get("/reports/safe-to-delete?loc=store:people/user-1/many/&per=50").get_data(as_text=True)
        self.assertIn("These 120 file(s)", r)                              # the total, not the page
        self.assertEqual(self.rows_on(r), 50)
        self.assertIn("per=50", r)

    def test_page_links_keep_the_other_arguments(self):
        r = self.c.get("/reports/only-here?loc=store:people/user-1/many/&per=50").get_data(as_text=True)
        nxt = re.search(r'href="([^"]+)" rel="next"', r).group(1).replace("&amp;", "&")
        self.assertIn("loc=store%3Apeople%2Fuser-1%2Fmany%2F", nxt)
        self.assertIn("page=2", nxt)

    def test_cli_queries_are_unlimited(self):
        from pinakes import queries
        self.assertEqual(len(queries.find(self.conn, "f*.txt")), 120)
        self.assertEqual(queries.page_total(queries.find(self.conn, "f*.txt", 10, 0)), 120)


@unittest.skipUnless(web is not None, "Flask not installed")
class TestSorting(ServerCase):
    """Sorting in SQL: every whitelisted column of every paged list, both ways, across small pages; bad values; the
    web wiring; and a second person under row-level security."""

    MANY = "people/user-1/many/"
    PAGE = 2                        # the queries take any limit: small pages make several of every list
    CONSTANT = {("copies", "size"),                                    # one content, one size
                ("only-here", "where"), ("safe-to-delete", "where"),   # one folder: one root,
                ("only-here", "snapshot"), ("safe-to-delete", "snapshot")}  # and not a backup

    def setUp(self):
        super().setUp()
        t0 = int(time.time()) - 86400
        for i in range(16):         # sizes and times that tie (the tie-breaker matters); four duplicated contents
            self.write("server-1", "store", self.MANY + "f%02d.txt" % i, (b"c%d" % (i % 6)) * (1 + i % 4),
                       mtime=t0 + (i % 5) * 60)
        for i in range(5):
            self.write("server-1", "store", self.MANY + "copies/c%d.txt" % i, b"one content, five paths",
                       mtime=t0 + i * 60)
        self.write("server-1", "store", self.MANY + "sub-a/x.txt", b"c5c5", mtime=t0)
        self.write("server-1", "store", self.MANY + "sub-b/deeper/z.txt", b"deep", mtime=t0 + 30)
        for i in range(3):          # copies on the same disk outside the folder: 0, 1 and 2 of them
            self.write("server-1", "store", self.MANY + "kept/k%d.txt" % i, b"kept %d" % i, mtime=t0)
            for j in range(i):
                self.write("server-1", "store", "people/user-1/elsewhere/%d/k%d.txt" % (j, i), b"kept %d" % i,
                           mtime=t0)
        for i in range(40):         # enough for a second page of find in the web UI
            self.write("server-1", "store", "people/user-1/bulk/b%02d.txt" % i, b"bulk %d" % i, mtime=t0 + i)
        for i in range(6):          # user-2's own, one sharing a content with user-1
            self.write("server-1", "store", "people/user-2/d%02d.txt" % i, b"hers %d" % i if i else b"c0", mtime=t0)
        target = self.MANY + "target.txt"
        self.write("server-1", "store", target, b"version 1", mtime=t0)
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup", extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        for snap, n, version in (("2026-01-01_0100", 8, b"version 1"), ("2026-01-02_0100", 4, b"version 2")):
            if version == b"version 2":
                self.write("server-1", "store", target, version, mtime=t0 + 60)
                self.scan("server-1", "store")
            for i in range(n):
                self.write("server-2", "snapshots", "%s/%sf%02d.txt" % (snap, self.MANY, i),
                           (b"c%d" % (i % 6)) * (1 + i % 4), mtime=t0)
            self.write("server-2", "snapshots", "%s/%s" % (snap, target), version, mtime=t0)
            self.write("server-2", "snapshots", "%s/%scopies/c0.txt" % (snap, self.MANY), b"one content, five paths",
                       mtime=t0)
            self.scan("server-2", "snapshots")
        self.write("server-1", "store", target, b"version 3", mtime=t0 + 120)
        self.scan("server-1", "store")
        os.rename(self.path("server-1", "store", target), self.path("server-1", "store", self.MANY + "target-2.txt"))
        with open(self.path("server-1", "store", self.MANY + "target-2.txt"), "ab") as f:
            f.write(b" and 4")
        os.remove(self.path("server-1", "store", self.MANY + "f15.txt"))
        self.scan("server-1", "store")
        self.write("server-1", "store", self.MANY + "target-2.txt", b"version 5", mtime=t0 + 300)
        self.scan("server-1", "store")
        for i in range(3):          # another machine's changes (owned by the default owner, user-1)
            self.write("laptop-1", "downloads", "camera/img-%d.jpg" % i, b"photo %d" % i, mtime=t0)
        self.scan("laptop-1", "downloads")
        with admin_conn(self.db) as c:   # spread the scans over days, and an entry by someone else in the access log
            c.execute("UPDATE pinakes.history SET seen_on = seen_on - (history_id % 4)::int, "
                      "seen_after = seen_after - (history_id % 4)::int - 1")
            ids = dict(c.execute("SELECT name, person_id FROM pinakes.people").fetchall())
            c.execute("INSERT INTO pinakes.audit (actor, action, affects, at) VALUES (%s, 'rule_change', %s, "
                      "now() - interval '1 hour')", (ids["user-2"], [ids["user-1"]]))
        self.target = self.file("store", self.MANY + "target-2.txt")
        self.copied = self.file("store", self.MANY + "copies/c0.txt")
        with self.as_person("user-1", "s-audit") as c:
            c.execute("SELECT pinakes.begin_step_up('checking sorting', 15)")
            c.commit()
            for n in range(4):
                c.execute("SELECT pinakes.audit_view(%s, %s::jsonb)", ([ids["user-2"]], '{"page": "p%d"}' % n))
                c.commit()
        pid = ids["user-1"]
        for name, pw in (("user-1", "correct horse battery"), ("user-2", "staple pony 12345")):
            self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) VALUES (%s, %s)",
                              (ids[name], auth.hash_password(pw)))
        app = web.create_app(server_config.loads(TestWeb.SERVER_WEB),
                             connect=lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db))
        app.testing = True
        self.app = app

    def login(self, name, pw):
        c = self.app.test_client()
        tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
        c.post("/login", data={"csrf": tok, "name": name, "password": pw})
        return c

    # every paged list: (name, call(conn, limit, offset, **order), whitelist, the value each column sorts by)
    def lists(self):
        from pinakes import queries as Q
        loc = "store:" + self.MANY
        files = {"where": lambda r: (r["host"], r["root"]), "path": lambda r: r["relpath"],
                 "size": lambda r: r["size"], "modified": lambda r: r["mtime"], "snapshot": lambda r: r["snapshot"]}
        copies = dict(files, same_disk=lambda r: r["same_disk"])
        return [
            ("find", lambda c, *a, **o: Q.find(c, "*", *a, **o), Q.FILE_SORT, files),
            ("copies", lambda c, *a, **o: Q.where(c, self.copied, *a, **o), Q.FILE_SORT, files),
            ("only-here", lambda c, *a, **o: Q.only_here(c, loc, *a, **o), Q.COPY_SORT, copies),
            ("safe-to-delete", lambda c, *a, **o: Q.not_safe_to_delete(c, loc, *a, **o), Q.COPY_SORT, copies),
            ("backed-up", lambda c, *a, **o: Q.backed_up(c, loc, *a, **o), Q.BACKED_UP_SORT,
             {"file": lambda r: r["relpath"], "copies": lambda r: r["backup_copies"],
              "snapshots": lambda r: r["snapshots"], "newest": lambda r: r["newest"]}),
            ("dupes", lambda c, *a, **o: Q.dupes(c, *a, **o), Q.DUPES_SORT,
             {"copies": lambda r: r["copies"], "reclaimable": lambda r: r["reclaimable"],
              "where": lambda r: r["paths"]}),
            ("changes", lambda c, *a, **o: Q.changes(c, 7, None, *a, **o), Q.CHANGES_SORT,
             {"seen": lambda r: r["seen_on"], "where": lambda r: (r["host"], r["root"]),
              "what": lambda r: r["kind"], "path": lambda r: r["path"]}),
            ("history", lambda c, *a, **o: Q.history(c, self.target, *a, **o), Q.HISTORY_SORT,
             {"between": lambda r: r["seen_on"], "what": lambda r: r["kind"],
              "path": lambda r: r["new_relpath"] or r["old_relpath"], "evidence": lambda r: r["evidence"]}),
            ("versions", lambda c, *a, **o: Q.versions(c, self.target, *a, **o), Q.VERSIONS_SORT,
             {"sha256": lambda r: r["sha256"], "first_seen": lambda r: r["first_seen_on"],
              "backup": lambda r: r["backup_root"], "snapshot": lambda r: r["snapshot"]}),
            ("browse", lambda c, *a, **o: Q.listing(c, loc, *a, **o), Q.LISTING_SORT,
             {"name": lambda r: r["entry"], "files": lambda r: r["files"], "size": lambda r: r["size"],
              "newest": lambda r: r["newest"]}),
            ("access", lambda c, *a, **o: Q.audit_mine(c, *a, **o), Q.AUDIT_SORT,
             {"when": lambda r: r["at"], "who": lambda r: r["actor"], "what": lambda r: r["action"]}),
        ]

    def assert_sorted(self, conn, vals, desc, what):
        """Values in order, NULLs last; text compared in the database's own collation."""
        present = [v for v in vals if v is not None]
        self.assertEqual(vals[:len(present)], present, "%s: NULLs last" % what)
        texts = set()

        def collect(v):
            if isinstance(v, str):
                texts.add(v)
            elif isinstance(v, (tuple, list)):
                for x in v:
                    collect(x)
        for v in present:
            collect(v)
        rank = {t: i for i, (t,) in enumerate(conn.execute("SELECT t FROM unnest(%s::text[]) t ORDER BY t",
                                                           (sorted(texts),)).fetchall())}

        def key(v):
            if isinstance(v, str):
                return rank[v]
            if isinstance(v, (tuple, list)):
                return tuple(key(x) for x in v)
            return v
        keys = [key(v) for v in present]
        self.assertEqual(keys, sorted(keys, reverse=desc), what)

    def test_every_column_both_ways_across_pages(self):
        with self.as_person("user-1") as c:
            for name, call, sorts, value in self.lists():
                self.assertEqual(set(value), set(sorts), name)          # a column added to a whitelist gets tested
                default = call(c)
                self.assertGreater(len(default), 2 * self.PAGE, name)    # three pages at least
                for col in sorts:
                    if (name, col) not in self.CONSTANT:
                        vals = {repr(value[col](r)) for r in default}
                        self.assertGreater(len(vals), 1, "%s %s: the data doesn't vary" % (name, col))
                    for d in ("asc", "desc"):
                        with self.subTest(list=name, sort=col, dir=d):
                            whole = call(c, sort=col, direction=d)
                            pages, off = [], 0
                            while True:
                                page = call(c, self.PAGE, off, sort=col, direction=d)
                                if not page:
                                    break
                                pages += page
                                off += self.PAGE
                            self.assertEqual(pages, whole)               # pages neither overlap nor skip
                            self.assertEqual(sorted(map(repr, whole)), sorted(map(repr, default)))  # same rows
                            self.assert_sorted(c, [value[col](r) for r in whole], d == "desc", "%s %s" % (name, col))

    def test_bad_values_fall_back(self):
        with self.as_person("user-1") as c:
            for name, call, sorts, value in self.lists():
                default = call(c)
                col = next(iter(sorts))
                for bad in ("nonsense", "f.size; DROP TABLE pinakes.files", "", None, 3, ["size"]):
                    self.assertEqual(call(c, sort=bad, direction="desc"), default, (name, bad))
                self.assertEqual(call(c, sort=col, direction="sideways"), call(c, sort=col, direction="asc"), name)

    def test_second_person_sees_only_their_own_when_sorted(self):
        with self.as_person("user-2") as c2, self.as_person("user-1") as c1:
            for name, call, sorts, value in self.lists():
                default = call(c2)
                total = queries_total(default)
                for col in sorts:
                    for d in ("asc", "desc"):
                        rows = call(c2, sort=col, direction=d)
                        self.assertEqual(sorted(map(repr, rows)), sorted(map(repr, default)), (name, col, d))
                        self.assertEqual(queries_total(call(c2, 1, 0, sort=col, direction=d)), total)
            found = {r["relpath"] for r in call_find(c2)}
            self.assertTrue(found)
            self.assertFalse({p for p in found if p.startswith(self.MANY)})    # none of user-1's files
            dupes = call_dupes(c2)
            self.assertEqual(dupes, [])            # d00 matches a file of user-1's, which user-2 can't see
            self.assertTrue(call_dupes(c1))
        c = self.login("user-2", "staple pony 12345")
        for col in ("size", "path", "where"):
            page = c.get("/find?q=*&sort=%s&dir=desc&per=50" % col).get_data(as_text=True)
            self.assertNotIn(self.MANY, page)
            self.assertIn("people/user-2/d00.txt", page)
        self.assertEqual(c.get("/file/%d?copies_sort=size&history_sort=what" % self.copied).status_code, 404)

    def test_web_wiring(self):
        from pinakes import queries
        c = self.login("user-1", "correct horse battery")
        with self.as_person("user-1") as conn:
            for col in queries.FILE_SORT:
                for d in ("asc", "desc"):
                    want = [r["file_id"] for r in queries.find(conn, "*.txt", sort=col, direction=d)]
                    got = re.findall(r'href="/file/(\d+)"',
                                     c.get("/find?q=*.txt&per=500&sort=%s&dir=%s" % (col, d)).get_data(as_text=True))
                    self.assertEqual([int(x) for x in got], want, (col, d))
        page = c.get("/find?q=*.txt&per=50&sort=size&dir=asc").get_data(as_text=True)
        self.assertIn('aria-sort="ascending"', page)
        link = lambda html, label, word: re.search(r'<a href="([^"]+)" title="Sort by %s, %s"' % (label, word),
                                                   html).group(1).replace("&amp;", "&")
        self.assertIn('<span class="on" title="Size, ascending">▲</span>', page)   # the current one: marked
        self.assertIsNone(re.search(r'title="Sort by Size, ascending"', page))      # and not a link
        down = link(page, "Size", "descending")                            # the other way is one click
        self.assertIn("sort=size", down)
        self.assertIn("dir=desc", down)
        self.assertIn("dir=desc", link(page, "Path", "descending"))        # any column, either way, one click
        self.assertIn("dir=asc", link(page, "Path", "ascending"))
        nxt = re.search(r'href="([^"]+)" rel="next"', page).group(1).replace("&amp;", "&")
        self.assertIn("sort=size", nxt)                                    # the pager keeps the sort
        self.assertIn("dir=asc", nxt)
        self.assertIn("page=2", nxt)
        p2 = c.get("/find?q=*.txt&per=50&sort=size&dir=asc&page=2").get_data(as_text=True)
        path = link(p2, "Path", "descending")
        self.assertIn("page=1", path)                                      # a new sort starts at page 1
        self.assertIn("sort=path", path)
        # a bad sort is no sort: the default page, no column marked, and the links drop it
        plain = c.get("/find?q=*.txt&per=50").get_data(as_text=True)
        bad = c.get("/find?q=*.txt&per=50&sort=f.size%3B--&dir=up").get_data(as_text=True)
        self.assertEqual(re.findall(r'/file/\d+', bad), re.findall(r'/file/\d+', plain))
        self.assertNotIn("aria-sort", bad)
        self.assertNotIn("sort=f.size", bad)
        # each list on a file's page sorts on its own, and every page with a table answers sorted
        fp = c.get("/file/%d?copies_sort=size&copies_dir=desc&history_sort=what" % self.target).get_data(as_text=True)
        self.assertEqual(fp.count('aria-sort='), 2)
        loc = "loc=store:" + self.MANY
        page = "/reports/%s?loc=store:" + self.MANY + "&"
        for url, prefix, cols in (("/browse/store/%s?" % self.MANY, "", queries.LISTING_SORT),
                                  (page % "only-here", "", queries.COPY_SORT),
                                  (page % "safe-to-delete", "", queries.COPY_SORT),
                                  (page % "backed-up", "", queries.BACKED_UP_SORT),
                                  ("/reports/restore?", "", queries.RESTORE_SORT),
                                  ("/reports/dupes?", "", queries.DUPES_SORT),
                                  ("/reports/changes?", "", queries.CHANGES_SORT),
                                  ("/access?", "", queries.AUDIT_SORT),
                                  ("/file/%d?" % self.copied, "copies_", queries.FILE_SORT),
                                  ("/file/%d?" % self.target, "versions_", queries.VERSIONS_SORT),
                                  ("/file/%d?" % self.target, "history_", queries.HISTORY_SORT)):
            for col in cols:
                for d in ("asc", "desc"):
                    r = c.get("%s%ssort=%s&%sdir=%s" % (url, prefix, col, prefix, d))
                    self.assertEqual(r.status_code, 200, (url, col, d))
                    html = r.get_data(as_text=True)
                    self.assertEqual(html.count('aria-sort="%s"' % ("ascending" if d == "asc" else "descending")), 1,
                                     (url, col, d))


def queries_total(rows):
    from pinakes import queries
    return queries.page_total(rows)


def call_find(c):
    from pinakes import queries
    return queries.find(c, "*", sort="size", direction="desc")


def call_dupes(c):
    from pinakes import queries
    return queries.dupes(c, sort="where", direction="desc")


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


@unittest.skipUnless(web is not None, "Flask not installed")
class TestHealth(ServerCase):
    """4: /health for monitoring, without sign-in: the database, each host's newest batch and staleness, no names
    of roots, people or files."""

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.scan("server-1", "store")
        self.conn.execute("UPDATE pinakes.hosts SET expected_every = NULL WHERE name = 'server-2'")  # not tested here
        self.cfg = server_config.loads('[web]\nsecure_cookies = false\nsession_key = "test-key"\n')
        self.connect = lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db)

    def get(self, connect=None, app=None):
        app = app or web.create_app(self.cfg, connect=connect or self.connect)
        r = app.test_client().get("/health")
        return r.status_code, r.get_json(), r.get_data(as_text=True)

    def test_healthy(self):
        code, body, text = self.get()
        self.assertEqual((code, body["status"], body["database"]), (200, "ok", "ok"))
        hosts = {h["host"]: h for h in body["hosts"]}
        self.assertEqual(sorted(hosts), ["laptop-1", "server-1", "server-2"])
        self.assertIsNotNone(hosts["server-1"]["newest_batch"])
        self.assertEqual(hosts["server-1"]["expected_every_s"], 86400)
        self.assertFalse(any(h["stale"] for h in hosts.values()))      # laptop-1 is never stale: expected "never"
        for name in ("store", "taxes", "people", "user-1", "user-2"):
            self.assertNotIn(name, text)

    def test_stale_host(self):
        self.conn.execute("UPDATE pinakes.hosts SET last_scan = now() - interval '2 days' WHERE name = 'server-1'")
        code, body, _ = self.get()
        self.assertEqual((code, body["status"]), (503, "stale"))
        self.assertEqual([h["host"] for h in body["hosts"] if h["stale"]], ["server-1"])

    def test_host_never_reported_is_stale(self):
        self.conn.execute("UPDATE pinakes.hosts SET expected_every = interval '1 day' WHERE name = 'server-2'")
        code, body, _ = self.get()
        self.assertEqual(code, 503)
        self.assertEqual([(h["host"], h["newest_batch"]) for h in body["hosts"] if h["stale"]], [("server-2", None)])

    def test_database_down(self):
        def down():
            raise psycopg.OperationalError("connection refused")
        code, body, text = self.get(connect=down)
        self.assertEqual((code, body), (503, {"status": "down", "database": "unreachable", "hosts": []}))
        self.assertNotIn("refused", text)                                  # no error details

    def test_health_alone_on_its_own_listener(self):
        app = web.create_health_app(self.cfg, connect=self.connect)
        self.assertEqual(self.get(app=app)[0], 200)
        c = app.test_client()
        for path in ("/", "/login", "/find?q=taxes", "/browse/store/"):
            self.assertEqual(c.get(path).status_code, 404, path)


if __name__ == "__main__":
    unittest.main()
