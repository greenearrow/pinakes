"""Ingester, matching, lineage and row-level security against a real PostgreSQL.

Needs PINAKES_TEST_PGHOST (a socket directory or host of a throwaway server where the user PINAKES_TEST_PGUSER,
default postgres, is a superuser) and psycopg. Each test class gets a fresh database. Skipped otherwise.
"""

import os
import shutil
import tempfile
import time
import unittest

try:
    import psycopg
except ImportError:
    psycopg = None

from pinakes import config, outbox, server_config
from pinakes.ingest import Ingester, Refused, apply_schema
from pinakes.scan import Scanner
from pinakes.state import State

PGHOST = os.environ.get("PINAKES_TEST_PGHOST")
PGUSER = os.environ.get("PINAKES_TEST_PGUSER", "postgres")

SERVER = """
[ownership]
default_owner = "user-1"
[[ownership.rule]]
root = "store"
folder = "people/user-2"
owner = "user-2"
[[ownership.enrollment]]
root = "store"
folder = "people/user-1/shared-with-2"
person = "user-2"
as = "reader"
[people.user-1]
display = "User One"
roles = ["person", "operator", "administrator"]
[people.user-2]
display = "User Two"
roles = ["person"]
[groups.household]
members = ["user-1", "user-2"]
[hosts.server-1]
roots = ["store"]
[hosts.server-2]
roots = ["snapshots"]
[hosts.laptop-1]
roots = ["downloads"]
expected_every = "never"
[lineage]
chunk_overlap = 0.6
"""


def admin_conn(db="postgres"):
    return psycopg.connect(host=PGHOST, user=PGUSER, dbname=db, autocommit=True)


@unittest.skipUnless(PGHOST and psycopg, "set PINAKES_TEST_PGHOST to a throwaway PostgreSQL")
class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = "pinakes_test_%s" % cls.__name__.lower()
        with admin_conn() as c:
            c.execute("DROP DATABASE IF EXISTS %s" % cls.db)
            c.execute("CREATE DATABASE %s" % cls.db)
            c.execute("DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pinakes_app') THEN "
                      "CREATE ROLE pinakes_app LOGIN; END IF; IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE "
                      "rolname = 'pinakes_ingest') THEN CREATE ROLE pinakes_ingest LOGIN BYPASSRLS; END IF; END$$")

    @classmethod
    def tearDownClass(cls):
        with admin_conn() as c:
            c.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % cls.db)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-srv-")
        with admin_conn(self.db) as c:
            c.execute("DROP SCHEMA IF EXISTS pinakes CASCADE")
            apply_schema(c)
        self.conn = psycopg.connect(host=PGHOST, user="pinakes_ingest", dbname=self.db, autocommit=True)
        self.scfg = server_config.loads(SERVER)
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        self.agents = {}

    def tearDown(self):
        for st, _, _ in self.agents.values():
            st.close()
        self.conn.close()
        shutil.rmtree(self.tmp)

    # an agent per (host, root) on a temporary tree ------------------------------------------------------------
    def agent(self, host, label, kind="primary", extra=""):
        key = (host, label)
        if key not in self.agents:
            base = os.path.join(self.tmp, host)
            top = os.path.join(base, label)
            os.makedirs(top, exist_ok=True)
            cfg = config.loads("""
[agent]
host = "%(h)s"
state = "%(b)s/state-%(l)s.sqlite"
outbox = "%(b)s/outbox"
[[root]]
label = "%(l)s"
path = "%(top)s"
kind = "%(k)s"
%(x)s
""" % {"h": host, "b": base, "l": label, "top": top, "k": kind, "x": extra})
            st = State(cfg.state)
            self.agents[key] = (st, cfg, top)
        return self.agents[key]

    def write(self, host, label, rel, data, mtime=None):
        _, _, top = self.agent(host, label)
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        if mtime is not None:
            os.utime(p, (mtime, mtime))
        return p

    def path(self, host, label, rel):
        return os.path.join(self.agent(host, label)[2], rel)

    def scan(self, host, label, **kw):
        st, cfg, _ = self.agent(host, label)
        Scanner(cfg, st).scan(cfg.roots[0], **kw)
        results = []
        for seq, p in outbox.pending(cfg.outbox):
            header, recs = outbox.read(p)
            results.append(self.ing.apply(header, recs, host))
            outbox.ack(cfg.outbox, seq)
        return results

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def file(self, label, relpath):
        return self.q("SELECT f.file_id FROM pinakes.files f JOIN pinakes.roots r USING (root_id) "
                      "WHERE r.label = %s AND f.relpath = %s AND f.gone_on IS NULL", (label, relpath))[0][0]

    def history(self, file_id):
        return [r[0] for r in self.q("SELECT kind FROM pinakes.history WHERE file_id = %s ORDER BY history_id",
                                     (file_id,))]

    def as_person(self, name, session="s1"):
        c = psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db)
        pid = self.q("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))[0][0]
        c.execute("SELECT set_config('pinakes.person', %s, false), set_config('pinakes.session', %s, false)",
                  (str(pid), session))
        c.commit()
        return c


class TestIngest(ServerCase):
    def test_new_changed_moved_gone(self):
        self.write("server-1", "store", "a.txt", b"alpha")
        self.write("server-1", "store", "b.txt", b"beta")
        self.write("server-1", "store", "c.txt", b"gamma")
        self.scan("server-1", "store")
        a, b, c = (self.file("store", p) for p in ("a.txt", "b.txt", "c.txt"))
        self.assertEqual(self.history(a), ["new"])
        time.sleep(0.01)
        self.write("server-1", "store", "a.txt", b"alpha 2")
        os.makedirs(self.path("server-1", "store", "moved"))
        os.rename(self.path("server-1", "store", "b.txt"), self.path("server-1", "store", "moved/b.txt"))
        os.remove(self.path("server-1", "store", "c.txt"))
        self.scan("server-1", "store")
        self.assertEqual(self.history(a), ["new", "changed"])
        self.assertEqual(self.file("store", "moved/b.txt"), b)       # the move kept b's file_id
        self.assertEqual(self.history(b), ["new", "moved"])
        self.assertEqual(self.history(c), ["new", "gone"])
        self.assertEqual(self.q("SELECT gone_on IS NOT NULL FROM pinakes.files WHERE file_id = %s", (c,))[0][0], True)

    def test_moved_and_changed_by_inode(self):
        p = self.write("server-1", "store", "draft.txt", b"x" * 5000)
        self.scan("server-1", "store")
        f = self.file("store", "draft.txt")
        os.rename(p, self.path("server-1", "store", "draft-renamed.txt"))
        with open(self.path("server-1", "store", "draft-renamed.txt"), "ab") as fh:
            fh.write(b"more")
        self.scan("server-1", "store")
        self.assertEqual(self.file("store", "draft-renamed.txt"), f)
        self.assertEqual(self.q("SELECT kind, confidence FROM pinakes.history WHERE file_id = %s ORDER BY history_id",
                                (f,))[-1], ("moved_changed", "strong"))

    def test_duplicate_batch_ignored_and_wrong_host_refused(self):
        self.write("server-1", "store", "a", b"a")
        st, cfg, _ = self.agent("server-1", "store")
        Scanner(cfg, st).scan(cfg.roots[0])
        (seq, p), = outbox.pending(cfg.outbox)
        header, recs = outbox.read(p)
        self.assertEqual(self.ing.apply(header, recs, "server-1"), "applied")
        self.assertEqual(self.ing.apply(header, recs, "server-1"), "duplicate")
        with self.assertRaises(Refused):
            self.ing.apply(header, recs, "laptop-1")                # the key's host must match the batch
        header2 = dict(header, root="downloads", seq=seq + 1)
        with self.assertRaises(Refused):
            self.ing.apply(header2, recs, "server-1")              # a root this host isn't enrolled for

    def test_owners_by_folder_and_backup_inherits(self):
        self.write("server-1", "store", "people/user-2/hers.txt", b"hers")
        self.write("server-1", "store", "people/user-1/mine.txt", b"mine")
        self.write("server-1", "store", "media/song.mp3", b"song")
        self.scan("server-1", "store")
        owners = dict(self.q("SELECT f.relpath, p.name FROM pinakes.files f JOIN pinakes.people p "
                             "ON p.person_id = f.owner_id"))
        self.assertEqual(owners["people/user-2/hers.txt"], "user-2")
        self.assertEqual(owners["people/user-1/mine.txt"], "user-1")
        self.assertEqual(owners["media/song.mp3"], "user-1")         # the default owner
        # a snapshot of the store on another host: each copy tied to its source and owned like it
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-02_0140/people/user-2/hers.txt", b"hers")
        self.scan("server-2", "snapshots")
        src = self.file("store", "people/user-2/hers.txt")
        row = self.q("SELECT backup_of, snapshot::text, p.name FROM pinakes.files f JOIN pinakes.people p "
                     "ON p.person_id = f.owner_id WHERE relpath = '2026-01-02_0140/people/user-2/hers.txt'")[0]
        self.assertEqual(row, (src, "2026-01-02", "user-2"))

    def test_rule_change_recomputes(self):
        self.write("server-1", "store", "projects/x.txt", b"x")
        self.scan("server-1", "store")
        root_id = self.q("SELECT root_id FROM pinakes.roots WHERE label = 'store'")[0][0]
        u2 = self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-2'")[0][0]
        self.q("INSERT INTO pinakes.owner_rules (root_id, folder, owner_person) VALUES (%s, 'projects', %s) "
               "RETURNING rule_id", (root_id, u2))
        self.assertEqual(self.ing.recompute_root(root_id), 1)
        self.assertEqual(self.q("SELECT owner_id FROM pinakes.files WHERE relpath = 'projects/x.txt'")[0][0], u2)


class TestLineage(ServerCase):
    def edges(self):
        return self.q("""SELECT fr.relpath, ft.relpath, l.kind, l.confidence FROM pinakes.lineage l
                         JOIN pinakes.files fr ON fr.file_id = l.from_file_id
                         JOIN pinakes.files ft ON ft.file_id = l.to_file_id ORDER BY 1, 2""")

    def test_copy_out_edit_copy_back(self):
        """A file taken to a laptop, edited there, and copied back over the original stays one line."""
        t0 = time.time() - 3600
        self.write("server-1", "store", "people/user-1/essay.odt", b"version 1", mtime=t0)
        self.scan("server-1", "store")
        # copied to the laptop (a plain copy: new mtime)
        self.write("laptop-1", "downloads", "essay.odt", b"version 1", mtime=t0 + 60)
        self.scan("laptop-1", "downloads")
        # edited there
        self.write("laptop-1", "downloads", "essay.odt", b"version 2", mtime=t0 + 600)
        self.scan("laptop-1", "downloads")
        # copied back over the original
        self.write("server-1", "store", "people/user-1/essay.odt", b"version 2", mtime=t0 + 900)
        self.scan("server-1", "store")
        self.assertEqual(self.edges(), [
            ("essay.odt", "people/user-1/essay.odt", "replaced_by", "certain"),
            ("people/user-1/essay.odt", "essay.odt", "copied_from", "certain"),
        ])

    def test_late_laptop_report_links_up(self):
        """The laptop reports after the copy came back: the direction comes from the files' times."""
        t0 = time.time() - 3600
        self.write("server-1", "store", "notes.txt", b"v1", mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", "notes.txt", b"v2", mtime=t0 + 900)   # came back from the laptop
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "notes.txt", b"v2", mtime=t0 + 600)  # where v2 was written
        self.scan("laptop-1", "downloads")
        self.assertIn(("notes.txt", "notes.txt", "replaced_by", "certain"), self.edges())
        src = self.q("""SELECT r.label FROM pinakes.lineage l JOIN pinakes.files f ON f.file_id = l.from_file_id
                        JOIN pinakes.roots r USING (root_id)""")[0][0]
        self.assertEqual(src, "downloads")

    def test_chunks_and_names(self):
        extra = 'chunks = { enabled = true, min_size = "1", average = "4KiB" }'
        self.agent("server-1", "store", extra=extra)
        self.agent("laptop-1", "downloads", extra=extra)
        base = os.urandom(200000)
        t0 = time.time() - 3600
        self.write("server-1", "store", "report.txt", base, mtime=t0)
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "report - new.txt", base[:100000] + b"EDIT" + base[100000:],
                   mtime=t0 + 60)
        self.write("laptop-1", "downloads", "Report (2) final.txt", b"entirely different text", mtime=t0 + 120)
        self.scan("laptop-1", "downloads")
        e = {(a, b): (k, c) for a, b, k, c in self.edges()}
        self.assertEqual(e[("report.txt", "report - new.txt")], ("derived_from", "likely"))
        # by name only: the most recent earlier file with the same name once markers are off
        self.assertEqual(e[("report - new.txt", "Report (2) final.txt")], ("derived_from", "possible"))


class TestRowLevelSecurity(ServerCase):
    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers")
        self.write("server-1", "store", "people/user-1/taxes.txt", b"his")
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.write("server-1", "store", "people/user-1/same.txt", b"same bytes")
        self.write("server-1", "store", "people/user-2/same-copy.txt", b"same bytes")
        self.scan("server-1", "store")

    def visible(self, c, table="pinakes.present"):
        return sorted(r[0] for r in c.execute("SELECT relpath FROM %s" % table).fetchall())

    def test_each_person_sees_their_own(self):
        with self.as_person("user-2") as c:
            self.assertEqual(self.visible(c), ["people/user-1/shared-with-2/plan.txt", "people/user-2/diary.txt",
                                               "people/user-2/same-copy.txt"])
            self.assertEqual(self.visible(c, "pinakes.files"), self.visible(c))  # the view adds nothing
        with self.as_person("user-1") as c:
            self.assertNotIn("people/user-2/diary.txt", self.visible(c))

    def test_copies_across_owners_not_shown_or_counted(self):
        with self.as_person("user-1") as c:
            n = c.execute("""SELECT count(*) FROM pinakes.present o WHERE o.content_id =
                             (SELECT content_id FROM pinakes.present WHERE relpath = 'people/user-1/same.txt')""").fetchone()[0]
            self.assertEqual(n, 1)
            self.assertEqual(c.execute("SELECT count(*) FROM pinakes.history h JOIN pinakes.files f USING (file_id)").fetchone()[0],
                             c.execute("SELECT count(*) FROM pinakes.history").fetchone()[0])

    def test_step_up(self):
        with self.as_person("user-1") as c:
            with self.assertRaises(psycopg.errors.RaiseException):
                c.execute("SELECT pinakes.begin_step_up('')")
            c.rollback()
            c.execute("SELECT pinakes.begin_step_up('checking a backup for user-2', 15)")
            c.commit()
            self.assertIn("people/user-2/diary.txt", self.visible(c))
            c.execute("SELECT pinakes.end_step_up()")
            c.commit()
            self.assertNotIn("people/user-2/diary.txt", self.visible(c))
        # another session of the same person doesn't share the step-up
        with self.as_person("user-1", session="s1") as c:
            c.execute("SELECT pinakes.begin_step_up('reason', 15)")
            c.commit()
        with self.as_person("user-1", session="s2") as c:
            self.assertNotIn("people/user-2/diary.txt", self.visible(c))
        # a person without the role can't step up
        with self.as_person("user-2") as c:
            with self.assertRaises(psycopg.errors.RaiseException):
                c.execute("SELECT pinakes.begin_step_up('curious', 15)")

    def test_audit_append_only_and_visible_to_affected(self):
        with self.as_person("user-1") as c:
            c.execute("SELECT pinakes.begin_step_up('a reason', 15)")
            u2 = c.execute("SELECT person_id FROM pinakes.people WHERE name = 'user-2'").fetchone()[0]
            c.execute("SELECT pinakes.audit_view(ARRAY[%s], '{\"folder\": \"people/user-2\"}')", (u2,))
            c.commit()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("DELETE FROM pinakes.audit")
            c.rollback()
        with self.as_person("user-2") as c:
            self.assertEqual([r[0] for r in c.execute("SELECT action FROM pinakes.audit")], ["view"])

    def test_past_versions_visible_only_to_their_owner(self):
        self.write("server-1", "store", "people/user-2/diary.txt", b"hers, edited")
        self.scan("server-1", "store")
        old = self.q("SELECT encode(sha256, 'hex') FROM pinakes.contents WHERE sha256 = sha256('hers')")[0][0]
        for person, sees in (("user-2", True), ("user-1", False)):
            with self.as_person(person) as c:
                n = c.execute("SELECT count(*) FROM pinakes.contents WHERE sha256 = decode(%s, 'hex')", (old,)).fetchone()[0]
                self.assertEqual(n, 1 if sees else 0, person)

    def test_app_cannot_write_or_read_acl_tables(self):
        with self.as_person("user-1") as c:
            for sql in ("INSERT INTO pinakes.people (name, display) VALUES ('x', 'x')",
                        "SELECT * FROM pinakes.acl_members", "SELECT roles FROM pinakes.people",
                        "UPDATE pinakes.files SET owner_id = NULL", "SELECT * FROM pinakes.step_ups"):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege, msg=sql):
                    c.execute(sql)
                c.rollback()

    def test_no_person_sees_nothing(self):
        c = psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db)
        try:
            self.assertEqual(c.execute("SELECT count(*) FROM pinakes.files").fetchone()[0], 0)
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
