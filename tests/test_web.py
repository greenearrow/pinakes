"""The web UI through Flask's test client, on a catalog built by real scans, under row-level security."""

import datetime
import os
import re
import time
import unittest

from pinakes import queries
from tests import jpegs
from tests.test_server import FAR_ZONES, PGHOST, ServerCase, admin_conn, in_time_zone, psycopg

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

    def test_hidden_files_left_out_of_browse_and_find_until_shown(self):
        self.write("server-1", "store", "people/user-1/.profile", b"profile")
        self.write("server-1", "store", "people/user-1/.cache-dir/thing.txt", b"thing")
        self.scan("server-1", "store")
        c, _ = self.login("user-1", "correct horse battery")
        folder = "/browse/store/people/user-1/"
        page = c.get(folder).get_data(as_text=True)
        self.assertNotIn(".profile", page)
        self.assertNotIn(".cache-dir", page)
        self.assertIn("taxes.txt", page)
        self.assertIn("2 hidden file(s) not shown.", page)
        self.assertNotIn("thing.txt", c.get("/find?q=thing").get_data(as_text=True))
        # the roots page counts the same way, and has the toggle
        def store_files(html):
            return int(re.search(r'>store</a>.*?<td class="num">(\d+)</td>', html, re.S).group(1))
        home = c.get("/").get_data(as_text=True)
        self.assertIn("2 hidden file(s) not shown.", home)
        left_out = store_files(home)
        # reports count them all the same: deleting a folder deletes its hidden files too
        self.assertIn(".profile", c.get("/reports/only-here?loc=store:people/user-1/").get_data(as_text=True))
        # shown, for this session
        tok = self.csrf(c, folder)
        self.assertEqual(c.post("/hidden-files", data={"show": "1", "next": folder}).status_code, 400)   # no token
        r = c.post("/hidden-files", data={"csrf": tok, "show": "1", "next": folder})
        self.assertEqual((r.status_code, r.headers["Location"]), (302, folder))
        page = c.get(folder).get_data(as_text=True)
        self.assertIn('.profile</a> <span class="tag">hidden</span>', page)
        self.assertIn('.cache-dir/</a>', page)
        self.assertIn("Hidden files are shown.", page)
        found = c.get("/find?q=thing").get_data(as_text=True)
        self.assertIn('people/user-1/.cache-dir/thing.txt</a> <span class="tag">hidden</span>', found)
        self.assertIn("Leave out hidden files", found)
        self.assertNotIn("hidden file(s) not shown", c.get("/browse/store/people/").get_data(as_text=True))
        home = c.get("/").get_data(as_text=True)
        self.assertEqual(store_files(home), left_out + 2)
        self.assertIn("Leave out hidden files", home)
        # and left out again; a next that isn't this site's goes home
        for bad in ("//example.net/x", "/\\example.net/x", "https://example.net/"):
            r = c.post("/hidden-files", data={"csrf": tok, "show": "0", "next": bad})
            self.assertEqual(r.headers["Location"], "/")
        self.assertNotIn(".profile", c.get(folder).get_data(as_text=True))
        # someone else's hidden files aren't counted for her
        c2, _ = self.login("user-2", "staple pony 12345")
        page = c2.get(folder).get_data(as_text=True)
        self.assertIn("shared-with-2", page)
        self.assertNotIn("hidden file(s) not shown", page)

    def test_file_linked_from_a_protected_root_says_so(self):
        his = self.file_id("people/user-1/taxes.txt")
        c, _ = self.login("user-1", "correct horse battery")
        self.assertNotIn("protected", c.get("/file/%d" % his).get_data(as_text=True))
        self.conn.execute("UPDATE pinakes.files SET protected_link = true WHERE file_id = %s", (his,))
        self.assertIn("protected: linked from a protected root", c.get("/file/%d" % his).get_data(as_text=True))

    def test_symlinks_on_safe_to_delete_and_their_page(self):
        os.makedirs(self.path("server-1", "store", "people/user-1/links"))
        os.symlink("../taxes.txt", self.path("server-1", "store", "people/user-1/links/to-taxes"))
        os.symlink("../nowhere.txt", self.path("server-1", "store", "people/user-1/links/dangling"))
        self.scan("server-1", "store")
        c, _ = self.login("user-1", "correct horse battery")
        page = c.get("/reports/safe-to-delete?loc=store:people/user-1/").get_data(as_text=True)
        self.assertNotIn("Links that would break", page)                  # both links are inside the folder
        self.assertNotIn("to-taxes", page)                                # and a link holds no data
        page = c.get("/reports/safe-to-delete?loc=store:people/user-1/taxes.txt").get_data(as_text=True)
        self.assertIn("1 symlink(s) you can see elsewhere lead into this folder", page)
        self.assertIn("store:people/user-1/links/to-taxes", page)
        link = c.get("/file/%d" % self.file_id("people/user-1/links/to-taxes")).get_data(as_text=True)
        self.assertIn('href="/file/%d">store:people/user-1/taxes.txt</a>' % self.file_id("people/user-1/taxes.txt"),
                      link)
        dangling = c.get("/file/%d" % self.file_id("people/user-1/links/dangling")).get_data(as_text=True)
        self.assertIn("dangling: its target is missing", dangling)

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

    def test_folder_copies_page_relations_paging_sort_and_row_level_security(self):
        """ROADMAP 50: the page for `pinakes folder-copies`: the three relations, another person's folders absent
        until a step-up (which the owner sees), sorted and paged like the other reports."""
        def put(who, folder, files):
            for name, data in files.items():
                self.write("server-1", "store", "people/%s/%s/%s" % (who, folder, name), data)
        photos = {"a.jpg": os.urandom(300), "b.jpg": os.urandom(300)}
        put("user-1", "trip", photos)
        put("user-1", "trip-same", photos)                                       # the same
        docs = {"d%d.txt" % i: os.urandom(100) for i in range(5)}
        put("user-1", "docs", docs)
        put("user-1", "docs-edit", dict(docs, **{"d2.txt": os.urandom(100)}))      # nearly: d2.txt edited
        put("user-1", "extra", dict(photos, **{"c.jpg": os.urandom(300)}))        # holds trip: trip is inside it
        theirs = {"h1.txt": os.urandom(400), "h2.txt": os.urandom(400)}
        put("user-2", "hers-1", theirs)
        put("user-2", "hers-2", theirs)
        for i in range(55):                                                      # enough pairs for a second page
            data = os.urandom(1000 + i)
            put("user-1", "many/p%02d" % i, {"f.bin": data})
            put("user-1", "many/p%02d-copy" % i, {"f.bin": data})
        self.scan("server-1", "store")
        c1, _ = self.login("user-1", "correct horse battery")
        url = "/reports/folder-copies?loc=store:people/user-1/"
        page = c1.get(url).get_data(as_text=True)
        self.assertIn("Folder copies", page)
        self.assertEqual(c1.get("/reports/folder-copies").status_code, 200)       # the form alone
        self.assertEqual(c1.get("/reports/folder-copies?loc=nocolon").status_code, 200)
        self.assertIn("a location is ROOT:PATH", c1.get("/reports/folder-copies?loc=nocolon").get_data(as_text=True))
        self.assertNotIn("people/user-2", page)                                  # another person's folders
        self.assertNotIn("hers-", page)

        def table(html):
            """(folder, relation, other) per row, folder and other as the path after people/user-1/."""
            return [(f, rel, o) for f, rel, o in re.findall(
                r'<tr><td><a href="[^"]*">store:people/user-1/([^<]*)</a></td><td>(\w+)</td>'
                r'<td><a href="[^"]*">store:people/user-1/([^<]*)</a></td>', html)]
        # the relations, on a page of a smaller folder
        small = {}
        for f, rel, o in table(c1.get(url + "&per=500").get_data(as_text=True)):
            small[(f, o)] = rel
        self.assertEqual(small[("trip", "trip-same")], "same")
        self.assertEqual(small[("trip", "extra")], "inside")
        self.assertEqual(small[("docs", "docs-edit")], "nearly")
        row = re.search(r'<tr><td><a [^>]*>store:people/user-1/docs</a></td>.*?</tr>',
                        c1.get(url + "&per=500").get_data(as_text=True), re.S).group(0)
        self.assertIn("d2.txt", row)                                              # the edited file is named
        self.assertIn('href="/browse/store/people/user-1/docs"', row)             # a folder links to its listing
        # paging: 58 or more rows over pages of 50, none twice, none missing
        first = table(c1.get(url + "&per=50&sort=where&dir=asc").get_data(as_text=True))
        second = table(c1.get(url + "&per=50&sort=where&dir=asc&page=2").get_data(as_text=True))
        everything = table(c1.get(url + "&per=500&sort=where&dir=asc").get_data(as_text=True))
        self.assertEqual(len(first), 50)
        self.assertEqual(first + second, everything)
        self.assertGreaterEqual(len(second), 8)
        self.assertEqual(len(set(everything)), len(everything))
        self.assertEqual([r[0] for r in everything], sorted(r[0] for r in everything))
        self.assertIn("1–50 of ", c1.get(url + "&per=50").get_data(as_text=True))
        desc = table(c1.get(url + "&per=500&sort=where&dir=desc").get_data(as_text=True))
        self.assertEqual([r[0] for r in desc], sorted((r[0] for r in desc), reverse=True))
        biggest = table(c1.get(url + "&per=50&sort=size&dir=desc").get_data(as_text=True))[0]
        self.assertEqual(biggest[0].split("/")[0], "many")                         # p54 holds the most bytes: 1054 B
        self.assertIn("p54", biggest[0] + biggest[2])
        smallest = table(c1.get(url + "&per=50&sort=size&dir=asc").get_data(as_text=True))[0]
        self.assertEqual(smallest[0], "docs")
        by_rel = [r[1] for r in table(c1.get(url + "&per=500&sort=relation&dir=asc").get_data(as_text=True))]
        self.assertEqual(by_rel, sorted(by_rel))
        for col in queries.FOLDER_COPIES_SORT:
            for d in ("asc", "desc"):
                html = c1.get(url + "&sort=%s&dir=%s" % (col, d)).get_data(as_text=True)
                self.assertEqual(html.count('aria-sort="%s"' % ("ascending" if d == "asc" else "descending")), 1)
        # another person's folders: none without a step-up, listed in one, which they see
        theirs_url = "/reports/folder-copies?loc=store:people/user-2/"
        self.assertNotIn("hers-1", c1.get(theirs_url).get_data(as_text=True))
        c2, _ = self.login("user-2", "staple pony 12345")
        mine = c2.get(theirs_url).get_data(as_text=True)
        self.assertIn("people/user-2/hers-1", mine)
        self.assertNotIn("people/user-1", c2.get("/reports/folder-copies?loc=store:people/").get_data(as_text=True))
        self.assertNotIn("report folder-copies", c2.get("/access").get_data(as_text=True))
        tok = self.csrf(c1, "/step-up")
        c1.post("/step-up", data={"csrf": tok, "reason": "checking the copies", "code": auth.totp(self.secret)})
        self.assertIn("people/user-2/hers-1", c1.get(theirs_url).get_data(as_text=True))
        self.assertIn("report folder-copies", c2.get("/access").get_data(as_text=True))

    def test_operator_page_totals_without_paths(self):
        c1, _ = self.login("user-1", "correct horse battery")              # an operator
        self.assertIn('href="/operator"', c1.get("/").get_data(as_text=True))
        r = c1.get("/operator")
        self.assertEqual(r.status_code, 200)
        page = r.get_data(as_text=True)
        self.assertRegex(page, r'<td>store</td><td>server-1</td><td>primary</td>\s*<td class="num">3</td>')
        self.assertIn("If a disk failed", page)
        for name in ("people", "diary", "taxes", "plan", "User Two"):          # no path, file or other person
            self.assertNotIn(name, page)
        c2, _ = self.login("user-2", "staple pony 12345")
        self.assertNotIn('href="/operator"', c2.get("/").get_data(as_text=True))
        self.assertEqual(c2.get("/operator").status_code, 403)

    def test_at_risk_shows_a_person_their_own_and_a_step_up_is_audited(self):
        c2, _ = self.login("user-2", "staple pony 12345")
        page = c2.get("/reports/at-risk").get_data(as_text=True)
        self.assertIn("User Two", page)                     # diary.txt, and plan.txt, shared with them
        self.assertIn("User One", page)
        self.assertRegex(page, r"<td class=\"num\">2</td><td class=\"num\">8 B</td>")   # diary and plan, 4 B each
        c1, _ = self.login("user-1", "correct horse battery")
        mine = c1.get("/reports/at-risk").get_data(as_text=True)
        self.assertNotIn("User Two", mine)
        tok = self.csrf(c1, "/step-up")
        c1.post("/step-up", data={"csrf": tok, "reason": "planning a disk swap", "code": auth.totp(self.secret)})
        self.assertIn("User Two", c1.get("/reports/at-risk").get_data(as_text=True))
        access = c2.get("/access").get_data(as_text=True)
        self.assertIn("report at-risk", access)

    def test_growth_by_folder_per_week_under_row_level_security(self):
        """ROADMAP 47: three dated scans after the first (which is the catalog starting, not growth)."""
        monday = queries.today() - datetime.timedelta(days=queries.today().weekday())
        two_ago, last = monday - datetime.timedelta(days=12), monday - datetime.timedelta(days=4)

        def dated(on):
            with admin_conn(self.db) as c:
                c.execute("UPDATE pinakes.history SET seen_on = %s WHERE history_id > %s", (on, mark))
        u1 = "people/user-1/"
        mark = self.q("SELECT max(history_id) FROM pinakes.history")[0][0]
        self.write("server-1", "store", u1 + "inbox/a.bin", b"a" * 100)
        self.write("server-1", "store", u1 + "inbox/b.bin", b"b" * 20)
        self.write("server-1", "store", "people/user-2/c.bin", b"c" * 50)
        self.scan("server-1", "store")
        dated(two_ago)
        mark = self.q("SELECT max(history_id) FROM pinakes.history")[0][0]
        self.write("server-1", "store", u1 + "taxes.txt", b"his, more")              # 3 B to 9 B: changed
        os.makedirs(self.path("server-1", "store", u1 + "sorted"))
        os.rename(self.path("server-1", "store", u1 + "inbox/a.bin"), self.path("server-1", "store", u1 + "sorted/a.bin"))
        os.remove(self.path("server-1", "store", u1 + "inbox/b.bin"))
        self.scan("server-1", "store")
        dated(last)
        self.write("server-1", "store", u1 + "sorted/d.bin", b"d" * 30)
        os.remove(self.path("server-1", "store", "people/user-2/c.bin"))
        self.scan("server-1", "store")                                               # this week, as seen
        self.assertIn("moved", self.history(self.file("store", u1 + "sorted/a.bin")))

        def weekly(c, weeks=8, loc=None):
            return {(r["folder"], r["week"]): (r["files_added"], r["files_gone"], r["bytes_added"], r["bytes_gone"])
                    for r in queries.growth(c, weeks, loc)}
        wk2, wk1 = monday - datetime.timedelta(days=14), monday - datetime.timedelta(days=7)
        with self.as_person("user-1", "s-growth-1") as c:
            self.assertEqual(weekly(c, loc="store:" + u1), {
                ("", wk1): (0, 0, 6, 0),                  # taxes.txt grew; the first scan's files aren't growth
                ("inbox", wk2): (2, 0, 120, 0),
                ("inbox", wk1): (0, 2, 0, 120),           # one moved out, one deleted
                ("sorted", wk1): (1, 0, 100, 0),          # moved in
                ("sorted", monday): (1, 0, 30, 0)})
            self.assertEqual(weekly(c), {                 # each root's top folders: user-2's c.bin not counted
                ("people", wk2): (2, 0, 120, 0), ("people", wk1): (0, 1, 6, 20), ("people", monday): (1, 0, 30, 0)})
            self.assertEqual(set(weekly(c, 2)), {("people", wk1), ("people", monday)})
            with self.assertRaises(ValueError):
                queries.growth(c, 8, "nocolon")
        with self.as_person("user-2", "s-growth-2") as c:
            self.assertEqual(weekly(c), {("people", wk2): (1, 0, 50, 0), ("people", monday): (0, 1, 0, 50)})
            self.assertEqual(weekly(c, loc="store:" + u1), {})
        # the page, and an administrator's step-up view of it audited for the owner
        c2, _ = self.login("user-2", "staple pony 12345")
        page = c2.get("/reports/growth?loc=store:people/").get_data(as_text=True)
        self.assertIn('store:people/user-2/</a>', page)
        self.assertNotIn("user-1/", page)
        c1, _ = self.login("user-1", "correct horse battery")
        page = c1.get("/reports/growth?loc=store:people/user-1/").get_data(as_text=True)
        self.assertIn('href="/reports/growth?loc=store:people/user-1/inbox/&amp;weeks=8"', page)
        self.assertIn("+100 B", page)                                                 # sorted/, moved in
        self.assertIn("−120 B", page)                                            # inbox/, emptied
        self.assertNotIn("report growth", c2.get("/access").get_data(as_text=True))
        tok = self.csrf(c1, "/step-up")
        c1.post("/step-up", data={"csrf": tok, "reason": "where the space went", "code": auth.totp(self.secret)})
        self.assertIn("store:people/user-2/", c1.get("/reports/growth?loc=store:people/").get_data(as_text=True))
        self.assertIn("report growth store:people/", c2.get("/access").get_data(as_text=True))

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

    def test_backed_up_report_says_how_many_have_a_backup(self):
        """Sorted unbacked first, page 1 can be all zeros: the line above it counts every file, not the page's."""
        from pinakes import queries
        self.agent("server-2", "snapshots", kind="backup", extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        with self.as_person("user-1") as c:
            (backed, *rest) = sorted(queries.backed_up(c, "store:people/user-1/"), key=lambda r: r["relpath"])
        with open(self.path("server-1", "store", backed["relpath"]), "rb") as f:
            self.write("server-2", "snapshots", "2026-01-01_0140/" + backed["relpath"], f.read())
        self.scan("server-2", "snapshots")
        n = len(rest) + 1
        self.assertGreater(n, 1)
        c1, _ = self.login("user-1", "correct horse battery")
        page = c1.get("/reports/backed-up?loc=store:people/user-1/").get_data(as_text=True)
        self.assertIn("<p>1 of %d file(s) have a backup; %d have none.</p>" % (n, n - 1), page)
        self.assertLess(page.index(rest[0]["relpath"]), page.index(backed["relpath"]))   # the unbacked first
        empty = c1.get("/reports/backed-up?loc=store:people/nobody/").get_data(as_text=True)
        self.assertNotIn("have a backup", empty)

    def test_a_roots_first_scan_is_not_a_change(self):
        """ROADMAP 52: every file a first scan records is new; the changes page leaves them out (a root added later
        too), keeps what is new in a later scan, and the file's own history still has it."""
        from pinakes import queries
        self.write("server-1", "store", "people/user-1/added.txt", b"added later")
        self.scan("server-1", "store")
        self.agent("laptop-1", "downloads", kind="drop")
        self.write("laptop-1", "downloads", "fetched.txt", b"fetched")
        self.scan("laptop-1", "downloads")
        with self.as_person("user-1", "s-first") as c:
            self.assertEqual(len(queries.find(c, "fetched.txt")), 1)                 # visible, so absent below by rule
            self.assertEqual([(r["root"], r["path"], r["kind"]) for r in queries.changes(c, 7)],
                             [("store", "people/user-1/added.txt", "new")])
            tree = {(t["root"], t["folder"]): t["new"] for t in queries.change_tree(c, 7, None, 3)}
            self.assertEqual(tree, {("store", ""): 1, ("store", "people"): 1, ("store", "people/user-1"): 1})
            self.assertEqual(queries.page_total(queries.changes(c, 7, None, 1, kinds=["new"])), 1)
            taxes = self.file("store", "people/user-1/taxes.txt")
            self.assertEqual([h["kind"] for h in queries.history(c, taxes)], ["new"])
        c1, _ = self.login("user-1", "correct horse battery")
        page = c1.get("/reports/changes").get_data(as_text=True)
        self.assertIn("added.txt", page)
        self.assertNotIn("taxes.txt", page)
        self.assertNotIn("fetched.txt", page)

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
        self.assertIn("first scan", page)
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

    def test_seen_up_to_defaults_to_the_utc_date(self):
        """The bulk form's "seen up to" is the catalog's (UTC) date, whatever the server's own zone."""
        self.write("server-1", "store", "people/user-1/a.txt", b"a")
        self.scan("server-1", "store")
        os.remove(self.path("server-1", "store", "people/user-1/a.txt"))     # a gone file: the bulk form shows
        self.scan("server-1", "store")
        c1, _ = self.login("user-1", "correct horse battery")
        for tz in FAR_ZONES:
            with self.subTest(tz=tz), in_time_zone(tz):
                page = c1.get("/reports/changes?loc=store:people/user-1/").get_data(as_text=True)
                utc = datetime.datetime.now(datetime.timezone.utc).date()
                self.assertIn('name="until" value="%s"' % utc.isoformat(), page)

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
                                                   "days": "7", "until": queries.today().isoformat()})
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


    def test_decide_a_relative_on_the_file_page(self):
        """Confirm, reject and clear a direct relative (ROADMAP 9), with the session's CSRF token; a reader of the
        file sees the link and its buttons, and is told nothing was decided."""
        t0 = time.time() - 86400
        a, b = "people/user-1/shared-with-2/x/notes.txt", "people/user-1/shared-with-2/y/notes.txt"
        self.write("server-1", "store", a, os.urandom(1000), mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", b, os.urandom(1010), mtime=t0 + 1)
        self.scan("server-1", "store")
        fa, fb = self.file_id(a), self.file_id(b)
        decision = lambda: self.q("SELECT decision FROM pinakes.lineage WHERE to_file_id = %s", (fb,))[0][0]
        c1, _ = self.login("user-1", "correct horse battery")
        page = c1.get("/file/%d" % fb).get_data(as_text=True)
        self.assertIn("Direct relatives", page)
        self.assertIn('name="other" value="%d"' % fa, page)
        self.assertIn('value="rejected">reject</button>', page)
        tok = self.csrf(c1, "/file/%d" % fb)
        url = "/file/%d/decide" % fb
        self.assertEqual(c1.post(url, data={"decision": "rejected", "other": fa}).status_code, 400)   # no token
        self.assertEqual(c1.post(url, data={"csrf": tok, "decision": "maybe", "other": fa}).status_code, 400)
        self.assertEqual(c1.post(url, data={"csrf": tok, "decision": "rejected", "other": "x"}).status_code, 400)
        r = c1.post(url, data={"csrf": tok, "decision": "rejected", "other": fa})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/file/%d?decided=1#relatives" % fb), r.headers["Location"])
        page = c1.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("Decided 1 link(s).", page)
        self.assertIn('<span class="tag">rejected</span> <span class="muted">User One', page)
        self.assertIn('value="clear">clear</button>', page)
        self.assertEqual(decision(), "rejected")
        # user-2 reads the folder: sees the link, can't decide it
        c2, _ = self.login("user-2", "staple pony 12345")
        tok2 = self.csrf(c2, "/file/%d" % fb)
        r = c2.post(url, data={"csrf": tok2, "decision": "clear", "other": fa})
        self.assertIn("Nothing decided", c2.get(r.headers["Location"]).get_data(as_text=True))
        self.assertEqual(decision(), "rejected")
        r = c1.post(url, data={"csrf": tok, "decision": "clear", "other": fa})
        self.assertEqual(decision(), None)
        r = c1.post("/file/%d/decide" % fa, data={"csrf": tok, "decision": "confirmed", "other": fb})  # either end
        self.assertIn("decided=1", r.headers["Location"])
        self.assertEqual(decision(), "confirmed")


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
        self.write("laptop-1", "downloads", "readme.txt", b"first scan", mtime=t0)   # a first scan is no change
        self.scan("laptop-1", "downloads")
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


@unittest.skipUnless(web is not None, "Flask not installed")
class TestMetadataPage(ServerCase):
    """Extracted metadata on a file's page and in find (ROADMAP 16): every field a person may see, the sensitive
    ones (GPS, people shown, places) only for the owners of a copy or an administrator in a step-up, audited."""

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/own.jpg", jpegs.camera(make="Maker-1"))
        self.write("server-1", "store", "people/user-1/shared-with-2/shared.jpg", jpegs.camera(make="Maker-2"))
        self.write("server-1", "store", "people/user-1/shared-with-2/tagged.jpg", jpegs.tagged())
        self.write("server-1", "store", "people/user-1/private-tagged.jpg", jpegs.tagged(jpegs.XMP_ELEMENTS))
        self.write("server-1", "store", "people/user-2/hers.jpg", jpegs.camera(make="Maker-4", when="2021:03:04 08:00:00"))
        self.write("server-1", "store", "people/user-2/notes.txt", b"no metadata")
        self.scan("server-1", "store")
        self.secret = auth.new_totp_secret()
        for name, pw, secret in (("user-1", "correct horse battery", self.secret), ("user-2", "staple pony 12345", None)):
            pid = self.q("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))[0][0]
            self.conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash, totp_secret) "
                              "VALUES (%s, %s, %s)", (pid, auth.hash_password(pw), secret))
        cfg = server_config.loads(TestWeb.SERVER_WEB)
        self.app = web.create_app(cfg, connect=lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db))
        self.app.testing = True

    def login(self, name, pw):
        c = self.app.test_client()
        tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
        c.post("/login", data={"csrf": tok, "name": name, "password": pw})
        return c

    def page(self, c, rel):
        r = c.get("/file/%d" % self.file("store", rel))
        self.assertEqual(r.status_code, 200)
        return r.get_data(as_text=True)

    def found(self, c, **args):
        page = c.get("/find", query_string=args).get_data(as_text=True)
        return sorted(set(re.findall(r'href="/file/\d+">(people/[^<]+)</a>', page)))

    def test_the_owner_sees_every_field_and_gps(self):
        c = self.login("user-1", "correct horse battery")
        page = self.page(c, "people/user-1/own.jpg")
        for text in ("EXIF", "Maker-1", "Model-1", "Lens-1 35mm", "2019-06-01T10:30:00Z", "640", "400",
                     "47.50000, -8.26000", "embedded", "v2"):
            self.assertIn(text, page)
        self.assertIn('title="where it was taken">gps</span> <span class="tag"', page)    # marked sensitive
        self.assertNotIn("are shown only to the owners", page)
        page = self.page(c, "people/user-1/shared-with-2/tagged.jpg")
        for text in ("XMP", "Title-1", "User One", "walk, lake", "City-1", "Country-1", "Place-1", "User Two",
                     "xmp.did:doc-1"):
            self.assertIn(text, page)

    def test_a_reader_sees_the_rest_not_the_sensitive_fields(self):
        c = self.login("user-2", "staple pony 12345")
        page = self.page(c, "people/user-1/shared-with-2/shared.jpg")
        for text in ("Maker-2", "Model-1", "2019-06-01T10:30:00Z"):
            self.assertIn(text, page)
        self.assertNotIn("47.50000", page)
        self.assertNotIn(">gps</span>", page)
        self.assertIn("Sensitive fields (", page)
        page = self.page(c, "people/user-1/shared-with-2/tagged.jpg")
        for text in ("Title-1", "User One", "walk, lake"):
            self.assertIn(text, page)
        for text in ("City-1", "Country-1", "Place-1", ">people</span>", ">location</span>"):
            self.assertNotIn(text, page)
        # the note is the same for a photo without GPS: it says nothing about whether this one has any
        page = self.page(c, "people/user-2/hers.jpg")
        self.assertIn("47.50000", page)                                    # her own
        self.assertNotIn("are shown only to the owners", page)
        self.assertIn("None recorded.", self.page(c, "people/user-2/notes.txt"))

    def test_what_each_extractor_made_of_it(self):
        # ROADMAP 44: on the page, by reason code; a reader of a photo whose only values are its GPS reads
        # "nothing found", as of a photo with none, and its owner "values found"
        self.write("server-1", "store", "people/user-1/cut.jpg", jpegs.camera()[:300])
        self.write("server-1", "store", "people/user-1/shared-with-2/where.jpg", jpegs.gps_only())
        self.write("server-1", "store", "people/user-1/shared-with-2/bare.jpg", jpegs.bare())
        self.scan("server-1", "store")
        c = self.login("user-1", "correct horse battery")
        self.assertIn("refused: the file ends early", self.page(c, "people/user-1/cut.jpg"))
        page = self.page(c, "people/user-1/shared-with-2/where.jpg")
        self.assertRegex(page, r"EXIF <span class=\"tag\">v2</span> values found")
        self.assertIn("47.50000", page)
        c = self.login("user-2", "staple pony 12345")
        reads = [re.search(r"Read by: .*?\.</p>", self.page(c, "people/user-1/shared-with-2/" + n)).group(0)
                 for n in ("where.jpg", "bare.jpg")]
        self.assertRegex(reads[0], r"EXIF <span class=\"tag\">v2</span> nothing found")
        self.assertEqual(reads[0], reads[1])                                # the same as a photo with none
        self.assertEqual(c.get("/file/%d" % self.file("store", "people/user-1/cut.jpg")).status_code, 404)

    def test_an_administrator_sees_them_only_in_a_step_up_and_the_owner_is_told(self):
        c = self.login("user-1", "correct horse battery")
        hers = self.file("store", "people/user-2/hers.jpg")
        self.assertEqual(c.get("/file/%d" % hers).status_code, 404)
        tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/step-up").get_data(as_text=True)).group(1)
        c.post("/step-up", data={"csrf": tok, "reason": "checking a photo", "code": auth.totp(self.secret)})
        self.assertIn("47.50000", c.get("/file/%d" % hers).get_data(as_text=True))
        access = self.login("user-2", "staple pony 12345").get("/access").get_data(as_text=True)
        self.assertIn("file %d, with sensitive metadata" % hers, access)

    def test_find_by_creator_and_date_under_row_level_security(self):
        c1 = self.login("user-1", "correct horse battery")
        c2 = self.login("user-2", "staple pony 12345")
        both = ["people/user-1/private-tagged.jpg", "people/user-1/shared-with-2/tagged.jpg"]
        self.assertEqual(self.found(c1, by="user one"), both)
        self.assertEqual(self.found(c2, by="user one"), ["people/user-1/shared-with-2/tagged.jpg"])
        self.assertEqual(self.found(c1, by="user one", q="private"), ["people/user-1/private-tagged.jpg"])
        self.assertEqual(self.found(c1, by="nobody"), [])
        self.assertEqual(self.found(c1, by="%"), [])                      # LIKE's wildcards are only text here
        # dated: EXIF's taken and XMP's created both map onto the common date
        self.assertEqual(self.found(c1, **{"from": "2019-06", "to": "2019-06-01"}),
                         ["people/user-1/own.jpg"] + both[:1] + ["people/user-1/shared-with-2/shared.jpg"] + both[1:])
        self.assertEqual(self.found(c1, **{"from": "2019-06-02"}), [])
        self.assertEqual(self.found(c2, **{"from": "2021"}), ["people/user-2/hers.jpg"])
        self.assertEqual(self.found(c1, **{"from": "2021"}), [])          # hers: not his to find
        self.assertEqual(self.found(c2, **{"to": "2019"}), ["people/user-1/shared-with-2/shared.jpg",
                                                            "people/user-1/shared-with-2/tagged.jpg"])
        page = c1.get("/find", query_string={"from": "June"}).get_data(as_text=True)
        self.assertIn("A date is a year", page)

    def test_a_sensitive_field_finds_nothing_for_a_reader(self):
        # a site mapping a sensitive field onto a common one: the search still goes through row-level security
        with self.as_person("user-2") as c:
            got = queries.find_by(c, creator="user two", mapped_creator=[("xmp", "people")])
            self.assertEqual(got, [])
        with self.as_person("user-1") as c:
            got = queries.find_by(c, creator="user two", mapped_creator=[("xmp", "people")])
            self.assertEqual(sorted(r["relpath"] for r in got), ["people/user-1/private-tagged.jpg",
                                                                 "people/user-1/shared-with-2/tagged.jpg"])

    def test_find_by_common_fields_uses_each_schemas_index(self):
        from pinakes import registry
        self.ing.enroll(registry.load())

        class Explain:          # find_by's own SQL, explained: rows() reads the plan's lines as its rows
            def __init__(self, c):
                self.c = c

            def execute(self, sql, args=()):
                return self.c.execute("EXPLAIN " + sql, args)

        # each schema's index serves its part of the search, when the table has only those (on a few rows the
        # planner would take any index that covers "schema = ...")
        pid = self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-1'")[0][0]
        others = {r[0] for r in self.q("SELECT indexname FROM pg_indexes WHERE schemaname = 'pinakes' AND "
                                       "tablename = 'metadata' AND indexname <> 'metadata_pkey'")}
        with admin_conn(self.db) as c:
            for kw, wanted, n in [({"creator": "user", "mapped_creator": [("dc", "creator"), ("xmp", "creator")]},
                                   {"md_dc_creator_trgm", "md_xmp_creator_trgm"}, 2),
                                  ({"dated": ("2019", "2020"), "mapped_date": [("exif", "taken"), ("xmp", "created")]},
                                   {"md_exif_taken_date", "md_xmp_created_date"}, 4)]:
                with c.transaction(force_rollback=True):
                    for other in others - wanted:
                        c.execute("DROP INDEX pinakes.%s" % other)
                    c.execute("SET LOCAL ROLE pinakes_app")
                    c.execute("SELECT set_config('pinakes.person', %s, true)", (str(pid),))
                    c.execute("SET LOCAL enable_seqscan = off")
                    plan = "\n".join(r["QUERY PLAN"] for r in queries.find_by(Explain(c), **kw))
                    for idx in wanted:
                        self.assertIn(idx, plan)
                    self.assertEqual(len(queries.find_by(c, **kw)), n)       # his tagged photos; his from 2019

    def test_only_registry_names_reach_the_sql(self):
        with self.as_person("user-1") as c:
            for bad in [("xmp", "x') OR true --"), ("Xmp", "creator")]:
                with self.assertRaises(ValueError):
                    queries.find_by(c, creator="a", mapped_creator=[bad])

    def test_markup_in_a_value_is_text(self):
        evil = jpegs.camera(make="<script>x</script>")
        self.write("server-1", "store", "people/user-1/evil.jpg", evil)
        self.scan("server-1", "store")
        page = self.page(self.login("user-1", "correct horse battery"), "people/user-1/evil.jpg")
        self.assertNotIn("<script>x", page)
        self.assertIn("&lt;script&gt;x", page)


class TestEnteringMetadata(TestMetadataPage):
    """Person-entered metadata and shared sensitive fields on a file's page (ROADMAP 16): a shared file shows its
    non-sensitive fields to the other person and hides the sensitive ones unless shared too."""

    def csrf(self, c, rel):
        return re.search(r'name="csrf" value="([^"]+)"', self.page(c, rel)).group(1)

    def post(self, c, rel, what, **data):
        fid = self.file("store", rel)
        return c.post("/file/%d/%s" % (fid, what), data=dict(data, csrf=self.csrf(c, rel)))

    def test_entered_fields_show_to_a_reader_and_the_sensitive_ones_only_once_shared(self):
        rel = "people/user-1/shared-with-2/shared.jpg"
        one, two = self.login("user-1", "correct horse battery"), self.login("user-2", "staple pony 12345")
        self.assertIn('<option value="xmp.people">people (sensitive)</option>', self.page(one, rel))
        r = self.post(one, rel, "metadata", field="dc.subject", value="walk, lake , ")
        self.assertEqual(r.status_code, 302)
        self.assertIn("entered=subject", r.headers["Location"])
        self.assertEqual(self.post(one, rel, "metadata", field="xmp.people", value="Person-7").status_code, 302)
        self.assertEqual(self.post(one, rel, "metadata", field="xmp.title", value="Title-7").status_code, 302)
        page = self.page(one, rel)
        for text in ("walk, lake", "Person-7", "Title-7", "person, User One"):
            self.assertIn(text, page)
        self.assertIn("Sensitive fields shared with", page)
        page = self.page(two, rel)
        for text in ("walk, lake", "Title-7", "Maker-2"):                    # the rest, entered and extracted
            self.assertIn(text, page)
        for text in ("Person-7", "47.50000", "Sensitive fields shared with", 'name="field"'):
            self.assertNotIn(text, page)                                     # no sensitive field, no forms: a reader
        self.assertIn("Sensitive fields (", page)
        pid = self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-2'")[0][0]
        r = self.post(one, rel, "share-sensitive", person=pid, do="share")
        self.assertEqual(r.status_code, 302)
        self.assertIn("stop sharing", self.page(one, rel))
        page = self.page(two, rel)
        for text in ("Person-7", "47.50000", ">gps</span>"):
            self.assertIn(text, page)
        self.assertNotIn("Sensitive fields (", page)
        other = self.page(two, "people/user-1/shared-with-2/tagged.jpg")    # another file of the same folder
        self.assertNotIn("City-1", other)
        access = two.get("/access").get_data(as_text=True)                   # she is told
        self.assertIn("sensitive share", access)
        self.assertIn("file: %d" % self.file("store", rel), access)
        self.post(one, rel, "share-sensitive", person=pid, do="stop")
        self.assertNotIn("Person-7", self.page(two, rel))
        self.assertEqual(self.post(one, rel, "metadata", field="xmp.people", remove="1").status_code, 302)
        self.assertNotIn("Person-7", self.page(one, rel))
        self.assertIn("Title-7", self.page(one, rel))                       # the rest of hers stays

    def test_refused(self):
        rel = "people/user-1/shared-with-2/shared.jpg"
        one, two = self.login("user-1", "correct horse battery"), self.login("user-2", "staple pony 12345")
        self.assertEqual(self.post(two, rel, "metadata", field="dc.title", value="x").status_code, 403)   # a reader
        pid = self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-2'")[0][0]
        self.assertEqual(self.post(two, rel, "share-sensitive", person=pid, do="share").status_code, 403)
        for field, value, why in (("dc.date", "June 2019", "a date is ISO 8601"),
                                  ("exif.gps", "47.5", "LAT, LON"),
                                  ("exif.gps", "95, 8", "not a point"),
                                  ("dc.title", "  ", "no value"),
                                  ("dc.title", "x" * 1001, "longer than 1000"),
                                  ("dc.nothing", "x", "not a field entered on this file")):
            r = self.post(one, rel, "metadata", field=field, value=value)
            self.assertEqual(r.status_code, 400, field)
            self.assertIn(why, r.get_data(as_text=True))
        r = self.post(two, "people/user-2/notes.txt", "metadata", field="exif.make", value="x")
        self.assertEqual(r.status_code, 400)                                # EXIF isn't a text file's
        self.assertIn('value="dc.title"', self.page(two, "people/user-2/notes.txt"))
        self.assertNotIn('value="exif.make"', self.page(two, "people/user-2/notes.txt"))
        self.assertEqual(self.post(one, "people/user-1/own.jpg", "share-sensitive", person=pid,
                                   do="share").status_code, 400)            # she doesn't read that one
        fid = self.file("store", rel)
        self.assertEqual(one.post("/file/%d/metadata" % fid, data={"field": "dc.title", "value": "x"}).status_code,
                         400)                                               # no CSRF token
        hers = self.file("store", "people/user-2/hers.jpg")
        self.assertEqual(one.post("/file/%d/metadata" % hers, data={"csrf": self.csrf(one, rel), "field": "dc.title",
                                                                    "value": "x"}).status_code, 404)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.metadata WHERE source = 'person'"), [(0,)])
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.sensitive_shares"), [(0,)])


class TestParseEntry(unittest.TestCase):
    """What a person types, as the registry stores it (web.parse_entry)."""

    def test_types(self):
        from pinakes import registry, web
        F = registry.Field
        self.assertEqual(web.parse_entry(F("t", "text"), "  Title  "), "Title")
        self.assertEqual(web.parse_entry(F("l", "list", of="text"), "a, b,, c "), ["a", "b", "c"])
        self.assertEqual(web.parse_entry(F("l", "list", of="number"), "1, 2.5"), [1, 2.5])
        self.assertEqual(web.parse_entry(F("n", "number"), "640"), 640)
        self.assertEqual(web.parse_entry(F("d", "duration"), "1:02:03"), 3723)
        self.assertEqual(web.parse_entry(F("d", "duration"), "90"), 90)
        self.assertEqual(web.parse_entry(F("p", "point"), "47.5, -8.26"), {"lat": 47.5, "lon": -8.26})
        self.assertEqual(web.parse_entry(F("w", "date"), "2019-06-01"), "2019-06-01")
        for field, text in ((F("n", "number"), "many"), (F("d", "duration"), "1:x"), (F("p", "point"), "north"),
                            (F("w", "date"), "June"), (F("t", "text"), ""), (F("r", "person"), "user-2")):
            with self.assertRaises(ValueError):
                web.parse_entry(field, text)


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

    def test_refused_and_numbering_went_back(self):
        """A host whose batch was refused since its newest one applied holds its batches: 503 "refused". When its
        agent's numbering last went back is shown, a reason never (it can name a root)."""
        code, body, _ = self.get()
        self.assertEqual({h["host"]: (h["refused"], h["seq_reset"]) for h in body["hosts"]},
                         {"laptop-1": (False, None), "server-1": (False, None), "server-2": (False, None)})
        self.ing._note_refused("server-1", "batch 1: the numbering went back", seq_reset=True)
        code, body, text = self.get()
        self.assertEqual((code, body["status"]), (503, "refused"))
        h = {h["host"]: h for h in body["hosts"]}["server-1"]
        self.assertTrue(h["refused"])
        self.assertIsNotNone(h["seq_reset"])
        self.assertNotIn("numbering", text)
        self.write("server-1", "store", "people/user-1/more.txt", b"more")
        self.scan("server-1", "store")                                  # a batch applied since: no longer held
        code, body, _ = self.get()
        self.assertEqual((code, body["status"]), (200, "ok"))
        self.assertIsNotNone({h["host"]: h for h in body["hosts"]}["server-1"]["seq_reset"])

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
