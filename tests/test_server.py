"""Ingester, matching, lineage and row-level security against a real PostgreSQL.

Needs PINAKES_TEST_PGHOST (a socket directory or host of a throwaway server where the user PINAKES_TEST_PGUSER,
default postgres, is a superuser) and psycopg. Each test class gets a fresh database. Skipped otherwise.
"""

import contextlib
import datetime
import hashlib
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

try:
    import psycopg
except ImportError:
    psycopg = None

import pinakes
from pinakes import config, outbox, server_config
from pinakes.ingest import Ingester, Refused, apply_schema, main as ingest_main
from pinakes.scan import Scanner, check, check_verdict
from pinakes.state import State

PGHOST = os.environ.get("PINAKES_TEST_PGHOST")
UPGRADES = os.path.join(os.path.dirname(pinakes.__file__), "upgrades")   # as installed: a wheel must carry them
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

    def test_bad_name_and_far_time(self):
        far = self.write("server-1", "store", "far.txt", b"far")
        os.utime(far, ns=(10_000_000_000 * 10**9,) * 2)                  # the year 2286
        with open(os.path.join(os.fsencode(self.path("server-1", "store", "")), b"bad\xff.txt"), "wb") as f:
            f.write(b"bad")
        self.scan("server-1", "store")
        self.assertEqual(self.q("SELECT relpath FROM pinakes.scan_errors"), [("bad\\xff.txt",)])
        f = self.file("store", "far.txt")
        if os.stat(far).st_mtime_ns == 10_000_000_000 * 10**9:            # the filesystem kept it
            self.assertEqual(self.q("SELECT mtime FROM pinakes.files WHERE file_id = %s", (f,)), [(None,)])

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

    def test_backup_of_one_folder_with_prefix(self):
        self.write("server-1", "store", "games/world-1/level.dat", b"level")
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}", prefix = "games/world-1" }')
        self.write("server-2", "snapshots", "2026-02-03_0100/level.dat", b"level")
        self.scan("server-2", "snapshots")
        row = self.q("SELECT backup_of, snapshot::text FROM pinakes.files WHERE relpath = '2026-02-03_0100/level.dat'")[0]
        self.assertEqual(row, (self.file("store", "games/world-1/level.dat"), "2026-02-03"))

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
        # the two edges form a cycle between the two files: walks must stop, not loop
        from pinakes import queries
        store = self.file("store", "people/user-1/essay.odt")
        self.assertEqual(len(queries.lineage(self.conn, store, "up")), 1)
        self.assertEqual(len(queries.lineage(self.conn, store, "down")), 1)

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
        self.agent("laptop-1", "downloads", kind="drop", extra=extra)
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
        # by name and a drop root: the most recent earlier file with the same name once markers are off
        self.assertEqual(e[("report - new.txt", "Report (2) final.txt")], ("derived_from", "possible"))


class TestHardLinks(ServerCase):
    """Hard links are the same data on the same disk: one copy, however many paths."""

    def test_snapshots_are_one_copy_and_take_space_once(self):
        from pinakes import queries
        data = os.urandom(10000)
        self.write("server-1", "store", "people/user-1/photo.jpg", data)
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        first = self.write("server-2", "snapshots", "2026-01-01_0140/people/user-1/photo.jpg", data)
        os.makedirs(self.path("server-2", "snapshots", "2026-01-02_0140/people/user-1"))
        os.link(first, self.path("server-2", "snapshots", "2026-01-02_0140/people/user-1/photo.jpg"))
        self.scan("server-2", "snapshots")
        (row,) = queries.backed_up(self.conn, "store:people/user-1/")
        self.assertEqual((row["backup_copies"], row["snapshots"]), (1, 2))
        self.assertEqual(str(row["newest"]), "2026-01-02")
        sizes = {e["entry"]: e["size"] for e in queries.listing(self.conn, "snapshots:")}
        self.assertEqual(sizes, {"2026-01-01_0140": 10000, "2026-01-02_0140": 10000})

    def test_dupes_count_copies_not_links(self):
        from pinakes import queries
        data = os.urandom(5000)
        a = self.write("server-1", "store", "a.bin", data)
        os.link(a, self.path("server-1", "store", "a-link.bin"))          # a hard link: reclaims nothing
        self.scan("server-1", "store")
        self.assertEqual(queries.dupes(self.conn), [])
        self.write("server-1", "store", "a-copy.bin", data)               # a real second copy
        self.scan("server-1", "store")
        (d,) = queries.dupes(self.conn)
        self.assertEqual((d["copies"], d["paths_count"], d["reclaimable"]), (2, 3, 5000))
        f = self.file("store", "a.bin")
        same = {r["relpath"]: r["same_inode"] for r in queries.where(self.conn, f)}
        self.assertEqual(same, {"a.bin": True, "a-link.bin": True, "a-copy.bin": False})


class TestSameDisk(ServerCase):
    """Only-here and safe-to-delete count a copy only on another disk (another host, or another device on the same
    host); a copy on the same disk is shown apart, and a hard link is not a copy at all (ROADMAP 5)."""

    OLD = "people/user-1/old/"

    def setUp(self):
        super().setUp()
        put = lambda host, label, rel, name: self.write(host, label, rel, b"content of " + name.encode())
        for n in ("same", "link", "device", "backup", "drop", "alone"):
            put("server-1", "store", self.OLD + n + ".jpg", n)
        put("server-1", "store", "people/user-1/keep/same.jpg", "same")          # same host, same disk
        os.makedirs(self.path("server-1", "store", "people/user-1/links"))
        os.link(self.path("server-1", "store", self.OLD + "link.jpg"),        # the same inode: not a copy
                self.path("server-1", "store", "people/user-1/links/link.jpg"))
        put("server-1", "store", "people/user-1/usb/device.jpg", "device")      # made another device below
        self.scan("server-1", "store")
        self.conn.execute("UPDATE pinakes.files SET dev = dev + 1 WHERE relpath = 'people/user-1/usb/device.jpg'")
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        put("server-2", "snapshots", "2026-01-01_0140/" + self.OLD + "backup.jpg", "backup")   # another host
        self.scan("server-2", "snapshots")
        self.agent("laptop-1", "downloads", kind="drop")
        put("laptop-1", "downloads", "drop.jpg", "drop")                       # another host, but not kept
        self.scan("laptop-1", "downloads")

    def answers(self, conn, query):
        return {r["relpath"][len(self.OLD):]: r["same_disk"] for r in query(conn, "store:" + self.OLD)}

    def test_only_here_and_safe_to_delete(self):
        from pinakes import queries
        with self.as_person("user-1") as c:          # under row-level security, as the web UI and CLI run
            self.assertEqual(self.answers(c, queries.only_here), {"same.jpg": 1, "link.jpg": 0, "alone.jpg": 0})
            self.assertEqual(self.answers(c, queries.not_safe_to_delete),
                             {"same.jpg": 1, "link.jpg": 0, "alone.jpg": 0, "drop.jpg": 0})

    def test_unknown_device_is_the_same_disk(self):
        from pinakes import queries
        self.conn.execute("UPDATE pinakes.files SET dev = NULL WHERE relpath = 'people/user-1/usb/device.jpg'")
        self.assertEqual(self.answers(self.conn, queries.only_here)["device.jpg"], 1)

    def test_copies_inside_the_folder_do_not_count(self):
        from pinakes import queries
        self.assertEqual(self.answers(self.conn, queries.only_here)["same.jpg"], 1)
        rows = queries.only_here(self.conn, "store:people/user-1/")       # keep/ is inside now
        self.assertEqual({r["relpath"]: r["same_disk"] for r in rows if r["relpath"].endswith("same.jpg")},
                         {"people/user-1/old/same.jpg": 0, "people/user-1/keep/same.jpg": 0})


class TestReview(ServerCase):
    """Reviewing a clean-up (ROADMAP 32): gone files and moves marked intended or restore, by row or in bulk, under
    row-level security; marks written only through mark_changes()."""

    U = "people/user-1/"

    def setUp(self):
        super().setUp()
        for n in ("a", "b", "c", "moved"):
            self.write("server-1", "store", self.U + "cleanup/%s.txt" % n, b"content " + n.encode())
        self.write("server-1", "store", "people/user-1/shared-with-2/plan.txt", b"plan")
        self.write("server-1", "store", "people/user-2/hers.txt", b"hers")
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "b.txt", b"content b")          # b went to another disk first
        self.scan("laptop-1", "downloads")
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-01_0140/" + self.U + "cleanup/c.txt", b"content c")
        self.scan("server-2", "snapshots")
        for n in ("a", "b", "c"):
            os.remove(self.path("server-1", "store", self.U + "cleanup/%s.txt" % n))
        os.makedirs(self.path("server-1", "store", self.U + "kept"))
        os.rename(self.path("server-1", "store", self.U + "cleanup/moved.txt"),
                  self.path("server-1", "store", self.U + "kept/moved.txt"))
        os.remove(self.path("server-1", "store", "people/user-1/shared-with-2/plan.txt"))
        os.remove(self.path("server-1", "store", "people/user-2/hers.txt"))
        self.scan("server-1", "store")
        self.today = datetime.date.today()

    def unreviewed(self, c, loc="store:people/user-1/cleanup/"):
        from pinakes import queries
        return sorted(r["path"] for r in queries.changes(c, 7, loc=loc, review="unreviewed"))

    def test_bulk_intended_then_a_later_gone_is_unreviewed(self):
        from pinakes import queries
        with self.as_person("user-1") as c:
            self.assertEqual(self.unreviewed(c), [self.U + "cleanup/%s.txt" % n for n in "abc"]
                             + [self.U + "kept/moved.txt"])                  # a move counts at its source too
            (tree,) = [t for t in queries.change_tree(c, 7, "store:" + self.U, 1) if t["folder"] == self.U + "cleanup"]
            self.assertEqual(tree["unreviewed"], 4)
            ids = [r["history_id"] for r in queries.changes(c, 7, loc="store:" + self.U + "cleanup/",
                                                            review="unreviewed", until=self.today)]
            self.assertEqual(queries.mark_changes(c, ids, "intended"), 4)
            c.commit()
            self.assertEqual(self.unreviewed(c), [])
            (tree,) = [t for t in queries.change_tree(c, 7, "store:" + self.U, 1) if t["folder"] == self.U + "cleanup"]
            self.assertEqual(tree["unreviewed"], 0)
            reviewed = queries.changes(c, 7, loc="store:" + self.U + "cleanup/", review="reviewed")
            self.assertEqual({(r["mark"], r["marked_by"]) for r in reviewed}, {("intended", "User One")})
            # nothing after the date given is marked
            self.assertEqual(queries.changes(c, 7, loc="store:" + self.U, review="unreviewed",
                                             until=self.today - datetime.timedelta(days=1)), [])
        self.write("server-1", "store", self.U + "cleanup/d.txt", b"content d")
        self.scan("server-1", "store")
        os.remove(self.path("server-1", "store", self.U + "cleanup/d.txt"))
        self.scan("server-1", "store")
        with self.as_person("user-1") as c:
            self.assertEqual(self.unreviewed(c), [self.U + "cleanup/d.txt"])   # the gone; its "new" needs no review

    def test_a_disk_move_is_recognised_by_its_copy(self):
        from pinakes import queries
        with self.as_person("user-1") as c:
            gone = {r["path"].rsplit("/", 1)[1]: r for r in
                    queries.changes(c, 7, kinds=["gone"], loc="store:" + self.U + "cleanup/")}
            self.assertEqual((gone["b.txt"]["elsewhere"], gone["b.txt"]["elsewhere_at"]),
                             (1, "laptop-1 · downloads:b.txt"))
            self.assertEqual((gone["a.txt"]["elsewhere"], gone["a.txt"]["backups"]), (0, 0))   # may be lost
            self.assertEqual((gone["c.txt"]["elsewhere"], gone["c.txt"]["backups"]), (0, 1))   # in a backup only
            moved = [r["history_id"] for r in queries.changes(c, 7, loc="store:" + self.U, review="unreviewed",
                                                              until=self.today, elsewhere=True)]
            self.assertEqual(queries.mark_changes(c, moved, "intended"), 1)
            c.commit()
            self.assertEqual(self.unreviewed(c), [self.U + "cleanup/%s.txt" % n for n in "ac"]
                             + [self.U + "kept/moved.txt"])

    def test_restore_names_the_snapshot_and_clears_when_back(self):
        from pinakes import queries
        with self.as_person("user-1") as c:
            want = {r["path"]: r["history_id"] for r in queries.changes(c, 7, loc="store:" + self.U)}
            self.assertEqual(queries.mark_changes(c, [want[self.U + "cleanup/c.txt"], want[self.U + "cleanup/a.txt"],
                                                      want[self.U + "kept/moved.txt"]], "restore"), 3)
            c.commit()
            rs = {r["old_relpath"]: r for r in queries.restores(c)}
            self.assertEqual(set(rs), {self.U + "cleanup/%s.txt" % n for n in ("a", "c", "moved")})
            (held,) = rs[self.U + "cleanup/c.txt"]["held_in"]
            self.assertEqual((held["root"], held["snapshot"], held["path"]),
                             ("snapshots", "2026-01-01", "2026-01-01_0140/" + self.U + "cleanup/c.txt"))
            self.assertEqual(rs[self.U + "cleanup/a.txt"]["backups"], 0)              # nothing holds it
            self.assertEqual(rs[self.U + "cleanup/moved.txt"]["back"], False)        # its content is elsewhere
        self.write("server-1", "store", self.U + "restored/c.txt", b"content c")      # back, in another folder
        self.write("server-1", "store", self.U + "cleanup/moved.txt", b"content moved")   # back at its old path
        self.scan("server-1", "store")
        with self.as_person("user-1") as c:
            self.assertEqual([r["old_relpath"] for r in queries.restores(c)], [self.U + "cleanup/a.txt"])
            back = {r["old_relpath"]: r["back"] for r in queries.restores(c, back=True)}
            self.assertEqual(back, {self.U + "cleanup/a.txt": False, self.U + "cleanup/c.txt": True,
                                    self.U + "cleanup/moved.txt": True})
            self.assertEqual(len(queries.restores(c, "store:" + self.U + "kept/")), 0)   # a's folder isn't kept/

    def test_others_neither_see_nor_make_marks(self):
        from pinakes import queries
        with self.as_person("user-1") as c:
            ids = [r["history_id"] for r in queries.changes(c, 7)]
            mine = [r["history_id"] for r in queries.changes(c, 7, loc="store:" + self.U + "cleanup/")]
            queries.mark_changes(c, mine, "restore")
            c.commit()
        with self.as_person("user-2", "s2") as c:
            self.assertEqual(queries.changes(c, 7, loc="store:" + self.U + "cleanup/"), [])
            self.assertEqual(queries.restores(c), [])
            self.assertEqual(c.execute("SELECT count(*) FROM pinakes.review_marks").fetchone()[0], 0)
            self.assertEqual(queries.mark_changes(c, ids, "intended"), 0)       # not hers: skipped
            self.assertEqual(queries.mark_changes(c, mine, None), 0)            # nor can she clear them
            c.commit()
            shared = [r for r in queries.changes(c, 7, kinds=["gone"]) if r["path"].endswith("plan.txt")]
            self.assertEqual(len(shared), 1)                                     # she reads it, as an enrolled reader
            self.assertEqual(queries.mark_changes(c, [shared[0]["history_id"]], "intended"), 0)   # but can't mark
            (her,) = [r["history_id"] for r in queries.changes(c, 7, kinds=["gone"]) if r["path"].endswith("hers.txt")]
            self.assertEqual(queries.mark_changes(c, [her], "intended"), 1)      # her own
            c.commit()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("INSERT INTO pinakes.review_marks (history_id, mark, marked_by) VALUES (%s, 'intended', 1)",
                          (mine[0],))
            c.rollback()
        self.assertEqual({r[0] for r in self.q("SELECT mark FROM pinakes.review_marks WHERE history_id = ANY (%s)",
                                               (mine,))}, {"restore"})

    def test_an_administrator_marks_others_only_in_a_step_up_audited(self):
        from pinakes import queries
        (her,) = [r[0] for r in self.q("SELECT history_id FROM pinakes.history WHERE old_relpath = "
                                       "'people/user-2/hers.txt' AND kind = 'gone'")]
        (new,) = [r[0] for r in self.q("SELECT history_id FROM pinakes.history WHERE kind = 'new' LIMIT 1")]
        with self.as_person("user-1") as c:
            self.assertEqual(queries.mark_changes(c, [her], "intended"), 0)
            c.execute("SELECT pinakes.begin_step_up('reviewing the clean-up', 15)")
            c.commit()
            self.assertEqual(queries.mark_changes(c, [her, new], "intended"), 1)   # a new file is never marked
            c.commit()
            with self.assertRaises(psycopg.errors.RaiseException):
                c.execute("SELECT pinakes.mark_changes(%s, 'bogus')", ([her],))
            c.rollback()
        two = self.q("SELECT person_id FROM pinakes.people WHERE name = 'user-2'")[0][0]
        (audit,) = self.q("SELECT affects, detail FROM pinakes.audit WHERE action = 'review'")
        self.assertEqual(audit, ([two], {"mark": "intended", "changes": 1}))

    def test_upgrade_file_matches_the_schema(self):
        path = os.path.join(UPGRADES, "review-marks.sql")
        defs = ("SELECT pg_get_functiondef('pinakes.mark_changes(bigint[], text)'::regprocedure), "
                "(SELECT array_agg(pg_get_expr(polqual, polrelid)) FROM pg_policy "
                " WHERE polrelid = 'pinakes.review_marks'::regclass), "
                "(SELECT array_agg(grantee || ':' || privilege_type ORDER BY grantee, privilege_type) "
                " FROM information_schema.role_table_grants WHERE table_schema = 'pinakes' "
                " AND table_name = 'review_marks'), "
                "has_function_privilege('pinakes_app', 'pinakes.mark_changes(bigint[], text)', 'EXECUTE'), "
                "has_function_privilege('public', 'pinakes.mark_changes(bigint[], text)', 'EXECUTE')")
        with admin_conn(self.db) as c:
            fresh = c.execute(defs).fetchone()
            c.execute("DROP FUNCTION pinakes.mark_changes(bigint[], text); DROP TABLE pinakes.review_marks")
            with open(path) as f:
                c.execute(f.read())
            c.execute("RESET search_path")                  # the file sets its own; compare as before
            self.assertEqual(c.execute(defs).fetchone(), fresh)
        self.assertEqual(fresh[3:], (True, False))


class TestProtectedByInode(ServerCase):
    """A file under a protected root hard-linked into another root is protected at that path too (ROADMAP 6): the
    catalog keeps no archive listing for it, even one made before the link, and says so."""

    def setUp(self):
        super().setUp()
        self.scfg = server_config.loads(SERVER.replace('roots = ["store"]', 'roots = ["store", "writing"]', 1))
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        base = os.path.join(self.tmp, "server-1")
        self.store, self.writing = os.path.join(base, "store"), os.path.join(base, "writing")
        os.makedirs(self.store)
        os.makedirs(self.writing)
        self.cfg = config.loads("""
[agent]
host = "server-1"
state = "%(b)s/state.sqlite"
outbox = "%(b)s/outbox"
[[root]]
label = "store"
path = "%(b)s/store"
archives = true
[[root]]
label = "writing"
path = "%(b)s/writing"
protected = true
""" % {"b": base})
        self.st = State(self.cfg.state)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("chapter.txt", b"a chapter")
        self.zipped = buf.getvalue()
        self.put(self.writing, "people/user-1/draft.zip", self.zipped)
        self.put(self.store, "people/user-1/old.zip", self.zipped + b"old")

    def tearDown(self):
        self.st.close()
        super().tearDown()

    def put(self, top, rel, data):
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def run_scan(self, label):
        Scanner(self.cfg, self.st).scan(self.cfg.root(label))
        for seq, p in outbox.pending(self.cfg.outbox):
            header, recs = outbox.read(p)
            self.ing.apply(header, recs, "server-1")
            outbox.ack(self.cfg.outbox, seq)

    def listed(self, rel):
        return self.q("SELECT count(*) FROM pinakes.members m JOIN pinakes.files f "
                      "ON f.content_id = m.archive_content_id WHERE f.relpath = %s AND f.gone_on IS NULL", (rel,))[0][0]

    def flags(self):
        return dict(self.q("SELECT f.relpath, f.protected_link FROM pinakes.present f JOIN pinakes.roots r "
                           "USING (root_id) WHERE r.label = 'store'"))

    def test_linked_now_and_linked_later(self):
        os.makedirs(os.path.join(self.store, "people/user-1/copies"))
        os.link(os.path.join(self.writing, "people/user-1/draft.zip"),
                os.path.join(self.store, "people/user-1/copies/draft.zip"))
        os.link(os.path.join(self.store, "people/user-1/old.zip"), os.path.join(self.store, "people/user-1/old2.zip"))
        self.run_scan("writing")
        self.run_scan("store")
        self.assertEqual(self.flags(), {"people/user-1/copies/draft.zip": True, "people/user-1/old.zip": False,
                                        "people/user-1/old2.zip": False})
        self.assertEqual(self.listed("people/user-1/copies/draft.zip"), 0)
        self.assertEqual(self.listed("people/user-1/old.zip"), 1)     # listed: no protected path to it yet
        os.link(os.path.join(self.store, "people/user-1/old.zip"), os.path.join(self.writing, "people/user-1/old.zip"))
        self.run_scan("store")
        self.assertEqual(set(self.flags().values()), {True})
        self.assertEqual(self.listed("people/user-1/old.zip"), 0)     # the listing made before the link is gone
        os.rename(os.path.join(self.store, "people/user-1/copies/draft.zip"),
                  os.path.join(self.store, "people/user-1/draft.zip"))
        self.run_scan("store")                                         # a move keeps the flag
        self.assertTrue(self.flags()["people/user-1/draft.zip"])
        self.assertEqual(self.history(self.file("store", "people/user-1/draft.zip")), ["new", "moved"])

    def test_the_owner_sees_the_flag_under_row_level_security(self):
        from pinakes import queries
        os.link(os.path.join(self.writing, "people/user-1/draft.zip"),
                os.path.join(self.store, "people/user-1/draft.zip"))
        self.run_scan("writing")
        self.run_scan("store")
        fid = self.file("store", "people/user-1/draft.zip")
        with self.as_person("user-1") as c:
            f = queries.file_by_id(c, fid)
            self.assertEqual((f["protected_link"], f["root_protected"]), (True, False))
        with self.as_person("user-2") as c:
            self.assertIsNone(queries.file_by_id(c, fid))

    def test_upgrade_file_matches_the_schema_and_fills_in(self):
        os.link(os.path.join(self.writing, "people/user-1/draft.zip"),
                os.path.join(self.store, "people/user-1/draft.zip"))
        self.run_scan("writing")
        self.run_scan("store")
        draft = self.q("SELECT content_id FROM pinakes.files WHERE relpath = 'people/user-1/draft.zip' "
                       "AND root_id = (SELECT root_id FROM pinakes.roots WHERE label = 'store')")[0][0]
        # a catalog from before: no flag, and a listing kept for the linked file
        upgrade_files_match_the_schema(
            self, ["protected_link", "link_root", "link_relpath", "link_dangling"], ["files_link"],
            ["protected-links.sql", "symlink-targets.sql"],
            "INSERT INTO pinakes.members (archive_content_id, entry_path, size, content_id) "
            "VALUES (%d, 'chapter.txt', 9, %d)" % (draft, draft))
        self.assertEqual(self.flags(), {"people/user-1/draft.zip": True, "people/user-1/old.zip": False})
        self.assertEqual(self.listed("people/user-1/draft.zip"), 0)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files f JOIN pinakes.roots r USING (root_id) "
                                "WHERE r.protected AND f.protected_link")[0][0], 0)


class TestSymlinks(ServerCase):
    """Symlinks tied to their targets (ROADMAP 7): where each leads, dangling ones, moved ones matched by inode or by
    target, and safe-to-delete naming the links elsewhere that point into the folder, under row-level security."""

    OLD = "people/user-1/old/"

    def setUp(self):
        super().setUp()
        self.scfg = server_config.loads(SERVER.replace('roots = ["store"]', 'roots = ["store", "media"]', 1))
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        base = os.path.join(self.tmp, "server-1")
        self.store, self.media = os.path.join(base, "store"), os.path.join(base, "media")
        os.makedirs(self.media)
        self.cfg = config.loads("""
[agent]
host = "server-1"
state = "%(b)s/state.sqlite"
outbox = "%(b)s/outbox"
[[root]]
label = "store"
path = "%(b)s/store"
[[root]]
label = "media"
path = "%(b)s/media"
""" % {"b": base})
        self.st = State(self.cfg.state)
        for rel in (self.OLD + "a.txt", self.OLD + "sub/b.txt", "people/user-2/hers.txt"):
            self.put(self.store, rel, rel.encode())
        self.ln(self.store, "a.txt", self.OLD + "inside")                      # in the folder: goes with it
        self.ln(self.store, "../old/a.txt", "people/user-1/elsewhere/to-a")
        self.ln(self.store, "old", "people/user-1/to-the-folder")
        self.ln(self.store, "../user-1/old/sub/b.txt", "people/user-2/to-b")    # user-2's link to user-1's file
        self.ln(self.media, os.path.join(self.store, self.OLD, "a.txt"), "from-media")
        self.ln(self.store, "gone.txt", "people/user-1/dangling")
        self.scan_all()

    def tearDown(self):
        self.st.close()
        super().tearDown()

    def put(self, top, rel, data):
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    def ln(self, top, target, rel):
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        os.symlink(target, p)

    def scan_all(self):
        for label in ("store", "media"):
            Scanner(self.cfg, self.st).scan(self.cfg.root(label))
            for seq, p in outbox.pending(self.cfg.outbox):
                header, recs = outbox.read(p)
                self.ing.apply(header, recs, "server-1")
                outbox.ack(self.cfg.outbox, seq)

    def links(self):
        return {(r, p): (lr, lp, d) for r, p, lr, lp, d in self.q(
            "SELECT r.label, f.relpath, f.link_root, f.link_relpath, f.link_dangling FROM pinakes.present f "
            "JOIN pinakes.roots r USING (root_id) WHERE f.is_symlink")}

    def test_targets_and_dangling(self):
        links = self.links()
        self.assertEqual(links[("store", "people/user-1/elsewhere/to-a")], ("store", self.OLD + "a.txt", False))
        self.assertEqual(links[("media", "from-media")], ("store", self.OLD + "a.txt", False))
        self.assertEqual(links[("store", "people/user-1/dangling")], ("store", "people/user-1/gone.txt", True))
        self.put(self.store, "people/user-1/gone.txt", b"back")
        self.scan_all()
        self.assertFalse(self.links()[("store", "people/user-1/dangling")][2])

    def test_moved_links(self):
        os.makedirs(os.path.join(self.store, "people/user-1/moved"))
        os.rename(os.path.join(self.store, "people/user-1/elsewhere/to-a"),
                  os.path.join(self.store, "people/user-1/moved/to-a"))           # mv: the same inode
        self.ln(self.store, "../old", "people/user-1/moved/to-the-folder")      # made again elsewhere: same target
        os.unlink(os.path.join(self.store, "people/user-1/to-the-folder"))      # (after, so its inode isn't reused)
        self.scan_all()
        rows = dict(self.q("SELECT h.new_relpath, h.kind || ': ' || h.evidence FROM pinakes.history h "
                           "WHERE h.kind <> 'new'"))
        self.assertEqual(rows, {"people/user-1/moved/to-a": "moved: same inode, same target",
                                "people/user-1/moved/to-the-folder": "moved: same target and name"})

    def test_two_links_to_one_place_are_not_guessed(self):
        for name in ("one", "two"):
            self.ln(self.store, "../x/t.txt", "people/user-1/pair/%s" % name)
        self.scan_all()
        for name in ("three", "four"):  # made before the old ones go, so no inode is reused
            self.ln(self.store, "../x/t.txt", "people/user-1/pair2/%s" % name)
        shutil.rmtree(os.path.join(self.store, "people/user-1/pair"))
        self.scan_all()
        kinds = self.q("SELECT kind, count(*) FROM pinakes.history h JOIN pinakes.files f USING (file_id) "
                       "WHERE f.relpath LIKE 'people/user-1/pair%%' GROUP BY kind ORDER BY kind")
        self.assertEqual(kinds, [("gone", 2), ("new", 4)])

    def test_a_reused_inode_leading_elsewhere_is_no_move(self):
        from pinakes.ingest import _NewFiles
        gone = (1, "p/l", None, 5, 10, 20, None, None, None, True, "../x", "store", "x")
        elsewhere = (2, "q/l", None, 5, 10, 20, None, None, None, True, "../y", "store", "y")
        same_place = (3, "q/r/l", None, 5, 10, 20, None, None, None, True, "../../x", "store", "x")
        self.assertIsNone(self.ing._match_move(gone, _NewFiles([elsewhere], set())))
        self.assertEqual(self.ing._match_move(gone, _NewFiles([same_place], set()))[1:],
                         ("moved", "same inode, same target", "certain"))

    def test_safe_to_delete_names_the_links_into_the_folder(self):
        from pinakes import queries
        loc = "store:" + self.OLD
        with self.as_person("user-1") as c:
            self.assertEqual([r["relpath"] for r in queries.not_safe_to_delete(c, loc)],
                             [self.OLD + "a.txt", self.OLD + "sub/b.txt"])      # the link inside isn't data
            self.assertEqual({(r["root"], r["relpath"]) for r in queries.links_into(c, loc)},
                             {("store", "people/user-1/elsewhere/to-a"), ("store", "people/user-1/to-the-folder"),
                              ("media", "from-media")})                          # not user-2's, nor the one inside
        with self.as_person("user-2") as c:
            self.assertEqual([(r["root"], r["relpath"]) for r in queries.links_into(c, loc)],
                             [("store", "people/user-2/to-b")])
            mine = self.file("store", "people/user-2/to-b")
            f = queries.file_by_id(c, mine)
            self.assertEqual((f["link_root"], f["link_relpath"]), ("store", self.OLD + "sub/b.txt"))
            self.assertIsNone(f["link_file_id"])                                  # the target is user-1's
        with self.as_person("user-1") as c:
            f = queries.file_by_id(c, self.file("store", "people/user-1/elsewhere/to-a"))
            self.assertEqual(f["link_file_id"], self.file("store", self.OLD + "a.txt"))

    def test_cli_safe_to_delete(self):
        import json
        from pinakes import cli
        conf = os.path.join(self.tmp, "server.toml")
        with open(conf, "w") as f:
            f.write(SERVER + '[web]\ndsn = "host=%s user=pinakes_app dbname=%s"\n' % (PGHOST, self.db))
        loc = "store:" + self.OLD

        def run(*extra):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["--config", conf, "--as", "user-1", *extra, "safe-to-delete", loc]), 0)
            return out.getvalue()

        text = run()
        self.assertIn(self.OLD + "a.txt", text)
        self.assertNotIn(self.OLD + "inside", text)
        self.assertIn("3 symlink(s) elsewhere lead into %s and would be left dangling:" % loc, text)
        self.assertIn("media:from-media", text)
        got = json.loads(run("--json"))
        self.assertEqual([r["relpath"] for r in got["not_safe"]], [self.OLD + "a.txt", self.OLD + "sub/b.txt"])
        self.assertEqual(len(got["links_into"]), 3)

    def test_upgrade_file_matches_the_schema(self):
        upgrade_files_match_the_schema(self, ["link_root", "link_relpath", "link_dangling"], ["files_link"],
                                       ["symlink-targets.sql"])


def upgrade_files_match_the_schema(case, columns, indexes, files, before=""):
    """Make case's catalog one from before: drop these columns of files (and these indexes), run `before`, then
    the upgrade files in order; the files table, the present view and its grants must come out as schema.sql
    makes them."""
    defs = ("SELECT (SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || "
            "        coalesce(column_default, '') ORDER BY ordinal_position) FROM information_schema.columns "
            "        WHERE table_schema = 'pinakes' AND table_name = 'files'), "
            "(SELECT array_agg(column_name::text ORDER BY ordinal_position) FROM information_schema.columns "
            " WHERE table_schema = 'pinakes' AND table_name = 'present'), "
            "pg_get_viewdef('pinakes.present'::regclass), "
            "(SELECT reloptions FROM pg_class WHERE oid = 'pinakes.present'::regclass), "
            "(SELECT array_agg(grantee || ':' || privilege_type ORDER BY grantee, privilege_type) "
            " FROM information_schema.role_table_grants WHERE table_schema = 'pinakes' AND table_name = 'present'), "
            "(SELECT array_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE schemaname = 'pinakes' "
            " AND tablename = 'files')")
    upgrades = UPGRADES
    with admin_conn(case.db) as c:
        fresh = c.execute(defs).fetchone()
        grants = c.execute("SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                           "WHERE table_schema = 'pinakes' AND table_name = 'present'").fetchall()
        c.execute("DROP VIEW pinakes.present")
        for index in indexes:
            c.execute("DROP INDEX pinakes.%s" % index)
        c.execute("ALTER TABLE pinakes.files %s" % ", ".join("DROP COLUMN %s" % col for col in columns))
        c.execute("CREATE VIEW pinakes.present WITH (security_invoker = true) AS "
                  "SELECT * FROM pinakes.files WHERE gone_on IS NULL")
        for grantee, priv in grants:
            c.execute("GRANT %s ON pinakes.present TO %s" % (priv, grantee))
        if before:
            c.execute(before)
        for name in files:
            with open(os.path.join(upgrades, name)) as f:
                c.execute(f.read())
            c.execute("RESET search_path")              # each file sets its own; compare as before
        case.assertEqual(c.execute(defs).fetchone(), fresh)


class TestBackupRoots(ServerCase):
    """A backup root records what holds a copy now (ROADMAP 28): hard-linked snapshots rotating through it send only
    the new snapshot's paths, and leave no gone rows or history of their own."""

    KEEP = 3

    def snap(self, k):
        return "2026-01-%02d_0140" % k

    def scan_records(self, host, label):
        """Scan, apply, and return the records sent (all batches)."""
        st, cfg, _ = self.agent(host, label)
        Scanner(cfg, st).scan(cfg.roots[0])
        sent = []
        for seq, p in outbox.pending(cfg.outbox):
            header, recs = outbox.read(p)
            self.assertEqual(self.ing.apply(header, recs, host), "applied")
            outbox.ack(cfg.outbox, seq)
            sent += recs
        return sent

    def test_rotating_hard_linked_snapshots(self):
        from pinakes import queries
        names = ["people/user-1/a.txt", "people/user-1/b.txt", "people/user-1/c.txt"]
        data = {n: os.urandom(3000) for n in names}
        for n in names:
            self.write("server-1", "store", n, data[n])
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup", extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        b = names[1]
        for k in range(1, 11):
            if k == 6:  # b changes at the source; the next snapshot holds the new version, the rest stays linked
                data[b] = os.urandom(3500)
                self.write("server-1", "store", b, data[b])
                self.scan("server-1", "store")
            for n in names:
                if k == 1 or (k == 6 and n == b):
                    self.write("server-2", "snapshots", "%s/%s" % (self.snap(k), n), data[n])
                else:
                    os.makedirs(os.path.dirname(self.path("server-2", "snapshots", "%s/%s" % (self.snap(k), n))),
                                exist_ok=True)
                    os.link(self.path("server-2", "snapshots", "%s/%s" % (self.snap(k - 1), n)),
                            self.path("server-2", "snapshots", "%s/%s" % (self.snap(k), n)))
            if k > self.KEEP:
                shutil.rmtree(self.path("server-2", "snapshots", self.snap(k - self.KEEP)))
            recs = self.scan_records("server-2", "snapshots")
            files = sorted(r["path"] for r in recs if r["t"] == "file")
            gone = sorted(r["path"] for r in recs if r["t"] == "gone")
            self.assertEqual(files, sorted("%s/%s" % (self.snap(k), n) for n in names), "snapshot %d" % k)
            self.assertEqual(gone, sorted("%s/%s" % (self.snap(k - self.KEEP), n) for n in names)
                             if k > self.KEEP else [], "snapshot %d" % k)
        backup = "SELECT f.file_id FROM pinakes.files f JOIN pinakes.roots r USING (root_id) WHERE r.label = 'snapshots'"
        self.assertEqual(self.q("SELECT count(*), count(gone_on) FROM pinakes.files WHERE file_id IN (%s)" % backup),
                         [(self.KEEP * len(names), 0)])
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.history WHERE file_id IN (%s)" % backup), [(0,)])
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.lineage WHERE from_file_id IN (%s) OR to_file_id IN (%s)"
                                % (backup, backup)), [(0,)])
        # the source files still answer: every one held by the three snapshots kept, as one physical copy
        rows = {r["relpath"]: r for r in queries.backed_up(self.conn, "store:people/user-1/")}
        for n in names:
            self.assertEqual((rows[n]["backup_copies"], rows[n]["snapshots"], str(rows[n]["newest"])),
                             (1, self.KEEP, "2026-01-10"), n)
        v = queries.versions(self.conn, self.file("store", b))
        old_sha, new_sha = (hashlib.sha256(d).hexdigest() for d in (b"", data[b]))
        self.assertEqual(len({r["sha256"] for r in v}), 2)                       # both versions of b
        held = sorted(str(r["snapshot"]) for r in v if r["sha256"] == new_sha)
        self.assertEqual(held, ["2026-01-08", "2026-01-09", "2026-01-10"])       # the new one in the kept snapshots
        self.assertEqual([r["backup_root"] for r in v if r["sha256"] != new_sha], [None])  # the old one: pruned

    def test_tidy_clears_what_older_releases_left(self):
        """A catalog built before ROADMAP 28: a backup root with gone rows and history rows. tidy removes them."""
        self.write("server-1", "store", "a.txt", b"alpha")
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup", extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-01_0140/a.txt", b"alpha")
        self.write("server-2", "snapshots", "2026-01-02_0140/a.txt", b"alpha")
        self.scan("server-2", "snapshots")
        kept, pruned = self.file("snapshots", "2026-01-02_0140/a.txt"), self.file("snapshots", "2026-01-01_0140/a.txt")
        # what the older release wrote: history for every backup path, a pruned snapshot kept as a gone row
        self.q("INSERT INTO pinakes.history (file_id, kind, new_relpath, seen_on) SELECT file_id, 'new', relpath, "
               "current_date FROM pinakes.files WHERE file_id IN (%s, %s) RETURNING 1", (kept, pruned))
        self.q("UPDATE pinakes.files SET gone_on = current_date WHERE file_id = %s RETURNING 1", (pruned,))
        src = self.file("store", "a.txt")
        src_history = self.history(src)
        with self.conn.transaction():
            n = self.ing.tidy(datetime.date.today())
        self.assertEqual((n["backup history rows"], n["backup gone rows"]), (2, 1))
        self.assertEqual(self.q("SELECT file_id FROM pinakes.files f JOIN pinakes.roots r USING (root_id) "
                                "WHERE r.label = 'snapshots'"), [(kept,)])
        self.assertEqual(self.history(kept), [])
        self.assertEqual(self.history(src), src_history)                          # a primary root's history stays
        with self.conn.transaction():
            n = self.ing.tidy(datetime.date.today())                            # a second run finds nothing
        self.assertEqual(set(n.values()), {0})


class TestNameLineage(ServerCase):
    """A similar name links two files only with a second signal (ROADMAP 29)."""

    def edges(self):
        return sorted(self.q("""SELECT fr.relpath, ft.relpath, l.evidence FROM pinakes.lineage l
                                JOIN pinakes.files fr ON fr.file_id = l.from_file_id
                                JOIN pinakes.files ft ON ft.file_id = l.to_file_id"""))

    def test_generic_names_in_unrelated_folders_link_nothing(self):
        t0 = time.time() - 86400
        generic = {"projects/alpha/README.md": 400, "projects/beta/README.md": 900,
                   "imports/2024-01-01/IMG_0001.JPG": 20000, "imports/2024-02-01/IMG_0001.JPG": 26000,
                   "games/world-1/level.dat": 1500, "games/world-2/level.dat": 1800}
        for i, (rel, size) in enumerate(sorted(generic.items())):
            self.write("server-1", "store", rel, os.urandom(size), mtime=t0 + i)
        self.scan("server-1", "store")
        # and the same names arriving later, on another machine
        self.write("laptop-1", "downloads", "gamma/README.md", os.urandom(2000), mtime=t0 + 100)
        self.write("laptop-1", "downloads", "card/IMG_0001.JPG", os.urandom(31000), mtime=t0 + 100)
        self.scan("laptop-1", "downloads")
        self.assertEqual(self.edges(), [])

    def test_copy_out_and_back_still_links(self):
        t0 = time.time() - 86400
        self.write("server-1", "store", "people/user-1/Thesis/chapter.odt", os.urandom(5000), mtime=t0)
        self.write("server-1", "store", "people/user-1/notes.txt", os.urandom(1000), mtime=t0)
        self.write("server-1", "store", "people/user-1/plan.odt", os.urandom(4000), mtime=t0)
        self.scan("server-1", "store")
        os.remove(self.path("server-1", "store", "people/user-1/plan.odt"))      # taken to the laptop: gone here
        self.scan("server-1", "store")
        # on the laptop (a primary root), each edited: other sizes, other contents
        self.write("laptop-1", "downloads", "work/Thesis/chapter edited.odt", os.urandom(2000), mtime=t0 + 600)
        self.write("laptop-1", "downloads", "work/notes - Copy.txt", os.urandom(1010), mtime=t0 + 600)
        self.write("laptop-1", "downloads", "work/plan v2.odt", os.urandom(9000), mtime=t0 + 600)
        self.scan("laptop-1", "downloads")
        self.assertEqual(self.edges(), [
            ("people/user-1/Thesis/chapter.odt", "work/Thesis/chapter edited.odt", "similar name, same folder name"),
            ("people/user-1/notes.txt", "work/notes - Copy.txt", "similar name, similar size"),
            ("people/user-1/plan.odt", "work/plan v2.odt", "similar name, the other changed or went then"),
        ])

    def test_structural_folder_names_link_nothing(self):
        """A folder name many folders have (a game's region/, a package's data/) is structure, not a sign; and a
        minus sign keeps region coordinates apart."""
        t0 = time.time() - 86400
        for i in range(6):
            self.write("server-1", "store", "pkg-%d/data/index.dat" % i, os.urandom(1000 + 400 * i), mtime=t0 + i)
        self.write("server-1", "store", "worlds/a/region/r.-1.1.mca", os.urandom(3000), mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", "worlds/b/region/r.1.1.mca", os.urandom(6000), mtime=t0 + 10)
        self.write("server-1", "store", "pkg-6/data/index.dat", os.urandom(9000), mtime=t0 + 10)
        self.scan("server-1", "store")
        self.assertEqual(self.edges(), [])
        # the rare folder name still links: two folders have region/ here
        self.write("server-1", "store", "worlds/b/region/r.-1.1.mca", os.urandom(6000), mtime=t0 + 20)
        self.scan("server-1", "store")
        self.assertEqual(self.edges(), [("worlds/a/region/r.-1.1.mca", "worlds/b/region/r.-1.1.mca",
                                         "similar name, same folder name")])

    def test_similar_size_needs_a_rare_name(self):
        """A fixed name in every package (DESCRIPTION, a .meta file) has namesakes of similar size by the dozen."""
        t0 = time.time() - 86400
        for i in range(6):
            self.write("server-1", "store", "lib/pkg-%d/DESCRIPTION" % i, os.urandom(1000 + i), mtime=t0 + i)
        self.scan("server-1", "store")
        self.write("server-1", "store", "lib/pkg-6/DESCRIPTION", os.urandom(1003), mtime=t0 + 10)
        self.write("server-1", "store", "photos/2024/IMG_0420.JPG", os.urandom(20000), mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", "photos/best of/IMG_0420.JPG", os.urandom(20100), mtime=t0 + 10)
        self.scan("server-1", "store")
        self.assertEqual(self.edges(), [("photos/2024/IMG_0420.JPG", "photos/best of/IMG_0420.JPG",
                                         "similar name, similar size")])

    def test_tidy_rekeys_and_drops_what_the_new_rules_reject(self):
        """Edges from 286c409: one between region files whose keys lost the sign, one in a structural folder."""
        t0 = time.time() - 86400
        for i in range(6):
            self.write("server-1", "store", "pkg-%d/data/index.dat" % i, os.urandom(1000 + 400 * i), mtime=t0 + i)
        self.write("server-1", "store", "worlds/a/region/r.-1.1.mca", os.urandom(3000), mtime=t0)
        self.write("server-1", "store", "worlds/b/region/r.1.1.mca", os.urandom(6000), mtime=t0 + 10)
        self.scan("server-1", "store")
        self.assertEqual(self.edges(), [])
        neg, pos = self.file("store", "worlds/a/region/r.-1.1.mca"), self.file("store", "worlds/b/region/r.1.1.mca")
        self.q("UPDATE pinakes.files SET name_key = 'r 1 1' WHERE file_id = %s RETURNING 1", (neg,))  # the old key
        for frm, to in [(neg, pos), (self.file("store", "pkg-0/data/index.dat"),
                                     self.file("store", "pkg-1/data/index.dat"))]:
            self.q("INSERT INTO pinakes.lineage (from_file_id, to_file_id, kind, evidence, confidence) "
                   "VALUES (%s, %s, 'derived_from', 'similar name, same folder name', 'possible') RETURNING 1",
                   (frm, to))
        with self.conn.transaction():
            n = self.ing.tidy(datetime.date.today())
        self.assertEqual((n["name keys updated"], n["name edges removed"], n["name edges kept"]), (1, 2, 0))
        self.assertEqual(self.q("SELECT name_key FROM pinakes.files WHERE file_id = %s", (neg,)), [("r -1 1",)])
        self.assertEqual(self.edges(), [])
        with self.conn.transaction():
            self.assertEqual(set(self.ing.tidy(datetime.date.today()).values()), {0})

    def test_tidy_redoes_name_edges(self):
        """Edges by name alone from an older release: the unrelated ones go, a decided one stays."""
        t0 = time.time() - 86400
        self.write("server-1", "store", "a/README.md", os.urandom(400), mtime=t0)
        self.write("server-1", "store", "b/README.md", os.urandom(900), mtime=t0 + 1)
        self.write("server-1", "store", "c/level.dat", os.urandom(1500), mtime=t0)
        self.write("server-1", "store", "d/level.dat", os.urandom(1800), mtime=t0 + 1)
        self.write("server-1", "store", "x/notes.txt", os.urandom(1000), mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", "y/notes.txt", os.urandom(1010), mtime=t0 + 1)
        self.scan("server-1", "store")
        self.assertEqual(self.edges(), [("x/notes.txt", "y/notes.txt", "similar name, similar size")])
        self.q("DELETE FROM pinakes.lineage RETURNING 1")
        old = [("a/README.md", "b/README.md", None), ("c/level.dat", "d/level.dat", "confirmed"),
               ("x/notes.txt", "y/notes.txt", None)]
        for frm, to, decision in old:  # as the older release wrote them
            self.q("INSERT INTO pinakes.lineage (from_file_id, to_file_id, kind, evidence, confidence, decision) "
                   "VALUES (%s, %s, 'derived_from', 'similar name', 'possible', %s) RETURNING 1",
                   (self.file("store", frm), self.file("store", to), decision))
        with self.conn.transaction():
            n = self.ing.tidy(datetime.date.today())
        self.assertEqual((n["name edges kept"], n["name edges removed"], n["name edges to another source"]), (1, 1, 0))
        self.assertEqual(self.edges(), [("c/level.dat", "d/level.dat", "similar name"),        # decided: a person's
                                        ("x/notes.txt", "y/notes.txt", "similar name, similar size")])


class TestEmptyFiles(ServerCase):
    """Every empty file has the same hash: not a duplicate, and no line of descent."""

    def test_not_dupes_and_no_lineage(self):
        from pinakes import queries
        t0 = time.time() - 86400
        for i in range(5):
            self.write("server-1", "store", "world/entities/r.%d.0.mca" % i, b"", mtime=t0 + i)
        self.write("server-1", "store", "world/level.dat", b"x" * 100, mtime=t0)
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "copy/r.0.0.mca", b"", mtime=t0 + 60)
        self.write("laptop-1", "downloads", "copy/level.dat", b"x" * 100, mtime=t0 + 60)
        self.scan("laptop-1", "downloads")
        self.assertEqual([d["size"] for d in queries.dupes(self.conn)], [100])
        self.assertEqual(self.q("""SELECT ft.relpath, l.evidence FROM pinakes.lineage l
                                   JOIN pinakes.files ft ON ft.file_id = l.to_file_id"""),
                         [("copy/level.dat", "same sha256")])

    def test_tidy_removes_empty_file_edges(self):
        self.write("server-1", "store", "a/empty.txt", b"")
        self.write("server-1", "store", "b/empty.txt", b"")
        self.write("server-1", "store", "c/kept.txt", b"kept")
        self.write("server-1", "store", "d/kept.txt", b"kept")
        self.scan("server-1", "store")
        e1, e2 = self.file("store", "a/empty.txt"), self.file("store", "b/empty.txt")
        self.q("DELETE FROM pinakes.lineage RETURNING 1")
        self.q("INSERT INTO pinakes.lineage (from_file_id, to_file_id, kind, evidence, confidence) VALUES "
               "(%s, %s, 'copied_from', 'same sha256', 'certain'), (%s, %s, 'copied_from', 'same sha256', 'certain') "
               "RETURNING 1", (e1, e2, self.file("store", "c/kept.txt"), self.file("store", "d/kept.txt")))
        with self.conn.transaction():
            n = self.ing.tidy(datetime.date.today())
        self.assertEqual(n["empty-file edges"], 1)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.lineage"), [(1,)])


class TestLineageRounds(ServerCase):
    """Lineage worked out in rounds of many files gives the same catalog as one file at a time."""

    CHUNKS = 'chunks = { enabled = true, min_size = "1", average = "4KiB" }'
    NAMES = ["report.txt", "report (2).txt", "Report - Copy.txt", "notes.txt", "notes 2024-01-01.txt", "photo.jpg",
             "photo (1).jpg", "plan.odt", "plan final.odt", "data.bin"]

    def reset(self, lineage_round):
        for st, _, _ in self.agents.values():
            st.close()
        self.agents = {}
        shutil.rmtree(self.tmp)
        self.tmp = tempfile.mkdtemp(prefix="pinakes-srv-")
        with admin_conn(self.db) as c:
            c.execute("DROP SCHEMA IF EXISTS pinakes CASCADE")
            apply_schema(c)
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        self.ing.lineage_round = lineage_round

    def scenario(self, lineage_round):
        self.reset(lineage_round)
        rnd = random.Random(7)
        base = [rnd.randbytes(30000) for _ in range(4)]
        pool = base + [b"small %d" % i for i in range(4)]

        def content():  # a copy of a pooled content, an edited copy of a big one (shared chunks), or its own
            r = rnd.random()
            if r < 0.4:
                return rnd.choice(pool)
            if r < 0.7:
                b, k = rnd.choice(base), rnd.randrange(1000, 29000)
                return b[:k] + rnd.randbytes(8) + b[k:]
            return rnd.randbytes(rnd.randrange(10, 200))
        t0 = 1700000000
        self.agent("server-1", "store", extra=self.CHUNKS)
        self.agent("laptop-1", "downloads", kind="drop", extra=self.CHUNKS)  # a drop root: names count there
        for i in range(40):  # mtimes from a few values: ties between copies are common (cp -p)
            self.write("server-1", "store", "d%d/%s" % (i % 7, self.NAMES[i % len(self.NAMES)]) if i < 10 else
                       "d%d/%d-%s" % (i % 7, i, rnd.choice(self.NAMES)), content(), mtime=t0 + 60 * rnd.randint(0, 5))
        # the oldest copy has two names on one inode: each name finds the copies without a source, and only the
        # first one worked out may become their source (what a round must remember between its files)
        old = self.write("server-1", "store", "links/old.bin", b"linked original", mtime=t0 - 600)
        os.link(old, self.path("server-1", "store", "links/old-link.bin"))
        for i in range(2):
            self.write("server-1", "store", "links/copy-%d.bin" % i, b"linked original", mtime=t0 + 60 * i)
        for i in range(3):  # hard links: the same data, not a copy
            os.link(self.path("server-1", "store", "d%d/%s" % (i, self.NAMES[i])),
                    self.path("server-1", "store", "d%d/link-%d.bin" % (i, i)))
        self.scan("server-1", "store")
        for i in range(15):
            self.write("laptop-1", "downloads", "%d-%s" % (i, rnd.choice(self.NAMES)), content(),
                       mtime=t0 + 60 * rnd.randint(-3, 8))
        self.scan("laptop-1", "downloads")
        # a person rejects one edge; then the store changes: edits, moves, new copies
        self.q("""UPDATE pinakes.lineage SET decision = 'rejected' WHERE (from_file_id, to_file_id, kind) =
                  (SELECT from_file_id, to_file_id, kind FROM pinakes.lineage l
                   JOIN pinakes.files f ON f.file_id = l.to_file_id ORDER BY f.relpath, l.kind LIMIT 1)
                  RETURNING 1""")
        for i in range(5):
            self.write("server-1", "store", "d%d/%s" % (i, self.NAMES[i]), content(), mtime=t0 + 900 + i)
        os.makedirs(self.path("server-1", "store", "moved"))
        for i in range(5, 8):
            os.rename(self.path("server-1", "store", "d%d/%s" % (i % 7, self.NAMES[i])),
                      self.path("server-1", "store", "moved/%s" % self.NAMES[i]))
        for i in range(5):
            self.write("server-1", "store", "new/%d-%s" % (i, rnd.choice(self.NAMES)), content(),
                       mtime=t0 + 60 * rnd.randint(-2, 12))
        self.scan("server-1", "store")
        edges = self.q("""SELECT rf.label, fr.relpath, rt.label, ft.relpath, l.kind, l.evidence, l.confidence, l.decision
                          FROM pinakes.lineage l
                          JOIN pinakes.files fr ON fr.file_id = l.from_file_id JOIN pinakes.roots rf ON rf.root_id = fr.root_id
                          JOIN pinakes.files ft ON ft.file_id = l.to_file_id JOIN pinakes.roots rt ON rt.root_id = ft.root_id
                          ORDER BY 1, 2, 3, 4, 5""")
        history = self.q("""SELECT r.label, f.relpath, h.kind, h.evidence FROM pinakes.history h
                            JOIN pinakes.files f USING (file_id) JOIN pinakes.roots r USING (root_id) ORDER BY 1, 2, 3""")
        return edges, history

    def test_rounds_match_one_at_a_time(self):
        one_edges, one_history = self.scenario(1)
        kinds = {e[5] for e in one_edges}
        # the scenario exercises every kind of evidence and a rejected edge
        self.assertTrue("same sha256" in kinds and any(k.startswith("chunks") for k in kinds)
                        and any(k.startswith("similar name, ") for k in kinds), kinds)
        self.assertIn("rejected", {e[7] for e in one_edges})
        for n in (3, 2000):
            edges, history = self.scenario(n)
            self.assertEqual(edges, one_edges, "rounds of %d" % n)
            self.assertEqual(history, one_history, "rounds of %d" % n)


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


class TestCheckAgainstCatalog(ServerCase):
    """30: the agent's check and the catalog's totals agree on a root, every owner's files counted."""

    def test_check_matches_totals(self):
        self.write("server-1", "store", "people/user-1/a.txt", b"aaaa")
        self.write("server-1", "store", "people/user-2/b.txt", b"bbbbbb")       # another owner's: counted too
        self.write("server-1", "store", "shared/c.txt", b"c")
        self.scan("server-1", "store")
        st, cfg, _ = self.agent("server-1", "store")
        c = check(cfg.roots[0], st)
        self.assertEqual(self.ing.totals(), [("server-1", "store", c["files"], c["bytes"], 0)])
        self.assertEqual((c["files"], c["bytes"]), (3, 11))
        self.assertEqual(check_verdict(c), "the disk matches the last scan")
        # the command prints the same totals, and no names
        path = os.path.join(self.tmp, "server.toml")
        with open(path, "w") as f:
            f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s"\n%s' % (PGHOST, self.db, SERVER))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ingest_main(["--config", path, "totals"]), 0)
        self.assertEqual(out.getvalue(), "server-1 store: 3 files 11 bytes\n")


class TestDurations(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(server_config.seconds("90s"), 90)
        self.assertEqual(server_config.seconds("1h"), 3600)
        self.assertIsNone(server_config.seconds("never"))
        for bad in ("0s", "1 hour", "-5m"):
            with self.assertRaises(config.ConfigError):
                server_config.seconds(bad)
        self.assertEqual(server_config.loads("").max_batch_time, 3600)


class TestIngesterStops(ServerCase):
    """31: a forced ingester whose agent gave up stops, and its batch is rolled back, not left holding locks."""

    def setUp(self):
        super().setUp()
        for i in range(20):
            self.write("server-1", "store", "docs/note-%02d.txt" % i, b"note %d" % i)
        st, cfg, _ = self.agent("server-1", "store")
        Scanner(cfg, st).scan(cfg.roots[0])
        [(_, path)] = outbox.pending(cfg.outbox)
        with open(path, "rb") as f:
            self.batch = f.read()

    def ingester(self, extra=""):
        cfg = os.path.join(self.tmp, "server.toml")
        with open(cfg, "w") as f:
            f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s"\n%s\n%s'
                    % (PGHOST, self.db, extra, SERVER))
        env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(pinakes.__file__)))  # the one in use
        p = subprocess.Popen([sys.executable, "-m", "pinakes.ingest", "--config", cfg, "--host", "server-1"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        p.stdin.write(self.batch)
        p.stdin.close()
        p.stdin = None                           # sent; communicate() has nothing more to write
        return p

    def blocker(self):
        """Hold the history table so the batch, mid-transaction (its files written), waits on a lock."""
        c = psycopg.connect(host=PGHOST, user=PGUSER, dbname=self.db)
        c.execute("LOCK TABLE pinakes.history IN SHARE MODE")
        return c

    def others(self):
        """The ingester's backends other than this test's own connection, and what each is waiting on."""
        return self.q("SELECT state, wait_event_type FROM pg_stat_activity WHERE datname = %s "
                      "AND usename = 'pinakes_ingest' AND pid <> pg_backend_pid()", (self.db,))

    def wait_for(self, cond, what, timeout=20):
        end = time.monotonic() + timeout
        while not cond():
            if time.monotonic() > end:
                self.fail("timed out waiting for " + what)
            time.sleep(0.1)

    def assertRolledBack(self):
        self.wait_for(lambda: not self.others(), "the ingester's backend to go")
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 0)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.roots")[0][0], 0)
        self.assertEqual(self.q("SELECT coalesce(max(last_seq), 0) FROM pinakes.hosts")[0][0], 0)

    def stuck(self, p):
        self.wait_for(lambda: ("active", "Lock") in self.others() or p.poll() is not None, "the batch to block")
        if p.poll() is not None:
            self.fail("the ingester ended before blocking: %s" % p.stderr.read().decode())

    def test_sender_hangs_up(self):
        b = self.blocker()
        try:
            p = self.ingester()
            self.stuck(p)
            t0 = time.monotonic()
            p.stdout.close()                     # the agent's ssh went away
            self.assertEqual(p.wait(timeout=15), 3)
            self.assertLess(time.monotonic() - t0, 5)
            self.assertIn(b"hung up", p.stderr.read())
            p.stderr.close()
        finally:
            b.rollback()
            b.close()
        self.assertRolledBack()
        # nothing was left half-done: the same batch, sent again, applies and is acknowledged
        p = self.ingester()
        out, err = p.communicate(timeout=60)
        self.assertEqual((p.returncode, out), (0, b"ack 1\n"), err)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 20)

    def test_batch_past_its_time(self):
        b = self.blocker()
        try:
            p = self.ingester('[ingest]\nmax_batch_time = "2s"\n')
            self.stuck(p)
            out, err = p.communicate(timeout=15)         # stdout stays open: only the cap stops it
            self.assertEqual((p.returncode, out), (3, b""), err)
            self.assertIn(b"max_batch_time", err)
        finally:
            b.rollback()
            b.close()
        self.assertRolledBack()


if __name__ == "__main__":
    unittest.main()
