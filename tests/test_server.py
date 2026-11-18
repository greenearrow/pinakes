"""Ingester, matching, lineage and row-level security against a real PostgreSQL.

Needs PINAKES_TEST_PGHOST (a socket directory or host of a throwaway server where the user PINAKES_TEST_PGUSER,
default postgres, is a superuser) and psycopg. Each test class gets a fresh database. Skipped otherwise.
"""

import argparse
import contextlib
import datetime
import hashlib
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import zipfile

try:
    import psycopg
except ImportError:
    psycopg = None

import pinakes
from pinakes import compat, config, outbox, queries, registry, server_config
import jpegs
from pinakes.ingest import Incompatible, Ingester, Refused, apply_schema, main as ingest_main, schema_missing
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


@contextlib.contextmanager
def in_time_zone(tz):
    """This process's local time zone set to tz (the server's, as the web and CLI would see it)."""
    old = os.environ.get("TZ")
    os.environ["TZ"] = tz
    time.tzset()
    try:
        yield
    finally:
        if old is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old
        time.tzset()


# 26 hours apart: at any moment the local date in one of them differs from the UTC date
FAR_ZONES = ("Etc/GMT+12", "Etc/GMT-14")


def admin_conn(db="postgres"):
    return psycopg.connect(host=PGHOST, user=PGUSER, dbname=db, autocommit=True)


@unittest.skipUnless(PGHOST and psycopg, "set PINAKES_TEST_PGHOST to a throwaway PostgreSQL")
class ServerCase(unittest.TestCase):
    server_toml = SERVER
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
        self.scfg = server_config.loads(self.server_toml)
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

    def test_cli_backups_from_inside_a_folder(self):
        import json
        from tests.test_api import CliRun
        data = os.urandom(10000)
        self.write("server-1", "store", "people/user-1/docs/photo.jpg", data)
        self.write("server-1", "store", "people/user-1/docs/lonely.txt", b"only one copy")
        self.write("server-1", "store", "people/user-2/theirs.txt", b"not user-1's")
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup",
                   extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-01_0140/people/user-1/docs/photo.jpg", data)
        self.scan("server-2", "snapshots")
        cli = CliRun(self, "user-1")
        self.addCleanup(cli.close)

        def run(*args, cwd=None, code=0):
            return cli("backups", "--host", "server-1", *args, cwd=cwd, code=code)

        docs = self.path("server-1", "store", "people/user-1/docs")
        text = run(cwd=docs)                                        # from inside the folder, no argument
        self.assertIn("store:people/user-1/docs: 2 file(s) you can see, 1 with no backup", text)
        self.assertLess(text.index("lonely.txt"), text.index("photo.jpg"))      # the least backed up first
        got = json.loads(run("--json", docs))                       # or given the folder
        self.assertEqual(got["folder"], "store:people/user-1/docs")
        self.assertEqual({r["relpath"]: r["backup_copies"] for r in got["shown"]},
                         {"people/user-1/docs/lonely.txt": 0, "people/user-1/docs/photo.jpg": 1})
        # the whole root; and user-2's file is not user-1's to see
        whole = run(cwd=self.path("server-1", "store", ""))
        self.assertIn("store: 2 file(s) you can see", whole)
        self.assertNotIn("theirs.txt", whole)
        # refusals: outside any root, and inside a backup root
        self.assertIn("is not inside a root", run(self.tmp, code=1))
        snapshots = self.path("server-2", "snapshots", "")
        self.assertIn("itself a backup root", cli("backups", "--host", "server-2", snapshots, code=1))

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
        self.today = queries.today()

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

    def test_today_is_the_catalogs_utc_date_in_any_local_zone(self):
        """Seen-on dates are UTC dates; "the last 7 days, seen up to today" must mean the same anywhere. With the
        server's local date, a server west of UTC marked nothing in bulk in its evenings (the window's end was the
        day before the scan's date)."""
        for tz in FAR_ZONES:
            with self.subTest(tz=tz), in_time_zone(tz), self.as_person("user-1") as c:
                self.assertEqual(queries.today(), datetime.datetime.now(datetime.timezone.utc).date())
                ids = [r["history_id"] for r in queries.changes(c, 7, loc="store:" + self.U + "cleanup/",
                                                                review="unreviewed", until=queries.today())]
                self.assertEqual(len(ids), 4, tz)
                (tree,) = [t for t in queries.change_tree(c, 1, "store:" + self.U, 1)
                           if t["folder"] == self.U + "cleanup"]
                self.assertEqual(tree["unreviewed"], 4, tz)              # a 1-day window still holds today's scan
                c.rollback()

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
            # and mark_changes() as api-tokens.sql replaces it (a token's scope and roots, ROADMAP 37)
            with open(os.path.join(UPGRADES, "api-tokens.sql")) as f:
                tokens = f.read()
            start = tokens.index("CREATE OR REPLACE FUNCTION mark_changes")
            c.execute("SET search_path = pinakes; " + tokens[start:tokens.index("END $$;", start) + len("END $$;")])
            # and as scrub.sql replaces it (what the scrub finds is reviewed too, ROADMAP 41)
            with open(os.path.join(UPGRADES, "scrub.sql")) as f:
                scrub = f.read()
            start = scrub.index("CREATE OR REPLACE FUNCTION mark_changes")
            c.execute("SET search_path = pinakes; " + scrub[start:scrub.index("END $$;", start) + len("END $$;")])
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
            self, ["protected_link", "link_root", "link_relpath", "link_dangling", "hidden"], ["files_link"],
            ["protected-links.sql", "symlink-targets.sql", "hidden-files.sql"],
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
        from tests.test_api import CliRun
        cli = CliRun(self, "user-1")
        self.addCleanup(cli.close)
        loc = "store:" + self.OLD

        def run(*extra):
            return cli(*extra, "safe-to-delete", loc)

        text = run()
        self.assertIn(self.OLD + "a.txt", text)
        self.assertNotIn(self.OLD + "inside", text)
        self.assertIn("3 symlink(s) elsewhere lead into %s and would be left dangling:" % loc, text)
        self.assertIn("media:from-media", text)
        got = json.loads(run("--json"))
        self.assertEqual([r["relpath"] for r in got["not_safe"]], [self.OLD + "a.txt", self.OLD + "sub/b.txt"])
        self.assertEqual(len(got["links_into"]), 3)

    def test_upgrade_file_matches_the_schema(self):
        upgrade_files_match_the_schema(self, ["link_root", "link_relpath", "link_dangling", "hidden"], ["files_link"],
                                       ["symlink-targets.sql", "hidden-files.sql"])


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
        # from before the scrub and checksum manifests too, which add the last columns of files (upgrades/scrub.sql,
        # then manifests.sql, run last)
        columns = list(columns) + ["unreadable_on", "unreadable_error", "manifest_verdict", "manifest_file_id",
                                   "manifest_on", "manifest_counts"]
        files = list(files) + ["scrub.sql", "manifests.sql"]
        c.execute("ALTER TABLE pinakes.roots DROP COLUMN scrub_on, DROP COLUMN scrub_since, DROP COLUMN scrub_days, "
                  "DROP COLUMN scrub_oldest, DROP COLUMN scrub_never")
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


class TestCheckIn(ServerCase):
    """Check-in and the protocol of each batch: hello records an agent and answers this server's release; a batch
    from an agent outside the range is refused, and the refusal kept; one that declares nothing counts as 0."""

    def checkin(self, host="server-1"):
        cols = ("at", "release", "protocol", "min_server_protocol", "locked", "batch_at", "batch_release",
                "batch_protocol", "refused_at", "refused")
        r = self.q("SELECT %s FROM pinakes.checkins c JOIN pinakes.hosts h USING (host_id) WHERE h.name = %%s"
                   % ", ".join("c." + c for c in cols), (host,))
        return dict(zip(cols, r[0])) if r else None

    def test_hello_records_and_answers(self):
        answer = self.ing.hello("server-1", {"release": 11, "protocol": 1, "min_server_protocol": 0})
        self.assertEqual(answer, {"release": compat.RELEASE, "protocol": compat.PROTOCOL,
                                  "min_agent_protocol": compat.MIN_AGENT_PROTOCOL, "schema_applied": True,
                                  "upgrades_missing": [], "last_seq": 0, "last_header_sha256": None})
        c = self.checkin()
        self.assertEqual((c["release"], c["protocol"], c["min_server_protocol"], c["locked"]), (11, 1, 0, None))
        self.assertIsNotNone(c["at"])
        with self.assertRaises(Refused):
            self.ing.hello("server-9", {})
        self.ing.hello("laptop-1", {"protocol": "x", "release": -3})   # malformed: protocol 0, no release
        c = self.checkin("laptop-1")
        self.assertEqual((c["release"], c["protocol"]), (None, 0))

    def test_hello_from_an_agent_behind_is_recorded_as_locked(self):
        with unittest.mock.patch.multiple(compat, PROTOCOL=3, MIN_AGENT_PROTOCOL=2):
            self.assertEqual(self.ing.hello("server-1", {"protocol": 1})["min_agent_protocol"], 2)
        self.assertEqual(self.checkin()["locked"], "agent must update: the server (protocol 3) accepts agents of "
                                                   "protocol 2 or later; the agent is at 1")

    def pending(self, host="server-1"):
        st, cfg, _ = self.agent(host, "store")
        return [outbox.read(p) for _, p in outbox.pending(cfg.outbox)]

    def test_an_agent_behind_is_refused_and_says_why(self):
        self.write("server-1", "store", "a.txt", b"a")
        st, cfg, _ = self.agent("server-1", "store")
        Scanner(cfg, st).scan(cfg.roots[0])                              # an agent of this protocol
        (header, recs), = self.pending()
        p = compat.PROTOCOL
        with unittest.mock.patch.multiple(compat, PROTOCOL=p + 2, MIN_AGENT_PROTOCOL=p + 1):
            with self.assertRaises(Incompatible) as e:
                self.ing.apply(header, recs, "server-1")
            self.assertEqual(str(e.exception), "batch 1: the server (protocol %d) accepts agents of protocol %d or "
                                               "later; the agent is at %d; the agent must update" % (p + 2, p + 1, p))
            # through the forced command: refused on stderr, to the agent, and to the system log
            path = os.path.join(self.tmp, "server.toml")
            with open(path, "w") as f:
                f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s"\n%s' % (PGHOST, self.db, SERVER))
            (_, batch), = outbox.pending(cfg.outbox)
            with open(batch, "rb") as f:
                stdin = io.TextIOWrapper(io.BytesIO(f.read()))
            err = io.StringIO()
            # in this process the watchdog would outlive the call, and exit the tests once stdout closes
            dog = unittest.mock.patch("pinakes.ingest.Watchdog", **{"return_value.batch.return_value":
                                                                     contextlib.nullcontext()})
            with unittest.mock.patch("sys.stdin", stdin), unittest.mock.patch("pinakes.ingest._syslog") as log, \
                    dog, tempfile.TemporaryFile("w") as out, contextlib.redirect_stderr(err), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(ingest_main(["--config", path, "--host", "server-1"]), 1)
        self.assertEqual(err.getvalue(), "refused: %s\n" % e.exception)
        log.assert_called_once_with("host server-1: refused %s" % e.exception)
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 0)      # nothing applied
        self.assertEqual(self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0], 0)
        c = self.checkin()
        self.assertEqual(c["refused"], str(e.exception))
        self.assertIsNotNone(c["refused_at"])
        self.assertEqual(self.ing.apply(header, recs, "server-1"), "applied")     # the server it was made for

    def test_an_agent_too_far_ahead_is_refused(self):
        self.write("server-1", "store", "a.txt", b"a")
        st, cfg, _ = self.agent("server-1", "store")
        ahead = compat.PROTOCOL + 2
        with unittest.mock.patch.multiple(compat, PROTOCOL=ahead, MIN_SERVER_PROTOCOL=ahead - 1):
            Scanner(cfg, st).scan(cfg.roots[0])
        (header, recs), = self.pending()
        with self.assertRaises(Incompatible) as e:
            self.ing.apply(header, recs, "server-1")
        self.assertIn("the agent (protocol %d) needs a server of protocol %d or later; the server is at %d; the server "
                      "must update" % (ahead, ahead - 1, compat.PROTOCOL), str(e.exception))

    def test_ahead_but_compatible_and_before_check_in_are_applied(self):
        self.write("server-1", "store", "a.txt", b"a")
        st, cfg, _ = self.agent("server-1", "store")
        with unittest.mock.patch.multiple(compat, RELEASE=12, PROTOCOL=compat.PROTOCOL + 1):
            Scanner(cfg, st).scan(cfg.roots[0])
        (header, recs), = self.pending()
        self.assertEqual(self.ing.apply(header, recs, "server-1"), "applied")
        c = self.checkin()
        self.assertEqual((c["batch_release"], c["batch_protocol"], c["at"]), (12, compat.PROTOCOL + 1, None))
        outbox.ack(cfg.outbox, header["seq"])
        # an agent from before check-in: no release or protocol in its header
        self.write("server-1", "store", "b.txt", b"b")
        Scanner(cfg, st).scan(cfg.roots[0])
        (header, recs), = self.pending()
        for k in ("release", "protocol", "min_server_protocol"):
            del header[k]
        with unittest.mock.patch.multiple(compat, PROTOCOL=2, MIN_AGENT_PROTOCOL=0):
            self.assertEqual(self.ing.apply(header, recs, "server-1"), "applied")
        c = self.checkin()
        self.assertEqual((c["batch_release"], c["batch_protocol"]), (None, 0))
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.present")[0][0], 2)

    def test_upgrade_file_matches_the_schema(self):
        defs = ("SELECT (SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || "
                "        coalesce(column_default, '') ORDER BY ordinal_position) FROM information_schema.columns "
                "        WHERE table_schema = 'pinakes' AND table_name = 'checkins'), "
                "(SELECT array_agg(grantee || ':' || privilege_type ORDER BY grantee, privilege_type) "
                " FROM information_schema.role_table_grants WHERE table_schema = 'pinakes' "
                " AND table_name = 'checkins'), "
                "(SELECT array_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint "
                " WHERE conrelid = 'pinakes.checkins'::regclass)")
        self.assertEqual(schema_missing(self.conn), [])
        with admin_conn(self.db) as c:
            fresh = c.execute(defs).fetchone()
            c.execute("DROP TABLE pinakes.checkins")
            self.assertEqual(schema_missing(self.conn), ["checkins.sql", "takeovers.sql"])
            self.assertFalse(self.ing.hello("server-1", {"protocol": 1})["schema_applied"])
            for u in ("checkins.sql", "takeovers.sql"):         # its columns of other tables are there: no change
                with open(os.path.join(UPGRADES, u)) as f:
                    c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(defs).fetchone(), fresh)
            self.assertEqual(schema_missing(self.conn), [])
            c.execute("ALTER TABLE pinakes.files DROP COLUMN hidden CASCADE")
            self.assertEqual(schema_missing(self.conn), ["hidden-files.sql"])
            c.execute("DROP SCHEMA pinakes CASCADE")
            self.assertEqual(schema_missing(self.conn), ["schema.sql"])

    def test_through_the_forced_key_locked_until_the_upgrade_then_reported(self):
        """The real route: a stand-in ssh runs pinakes-ingest --host as an agent's forced key would, with what was
        asked for in SSH_ORIGINAL_COMMAND. The catalog lacks checkins.sql: the agent locks; once it runs, the next
        run sends what was held, and pinakes releases shows it."""
        from pinakes import agent
        conf = os.path.join(self.tmp, "server.toml")
        with open(conf, "w") as f:
            f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s"\n%s[web]\ndsn = "host=%s '
                    'user=pinakes_app dbname=%s"\n' % (PGHOST, self.db, SERVER, PGHOST, self.db))
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "ssh"), "w") as f:
            f.write("#!%s\nimport os, subprocess, sys\nos.environ['SSH_ORIGINAL_COMMAND'] = sys.argv[-1]\n"
                    "sys.exit(subprocess.call([sys.executable, '-m', 'pinakes.ingest', '--config', %r, '--host', "
                    "'server-1']))\n" % (sys.executable, conf))
        os.chmod(os.path.join(bindir, "ssh"), 0o755)
        env = {"PATH": bindir + os.pathsep + os.environ.get("PATH", ""),
               "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(pinakes.__file__)))}
        st, cfg, _ = self.agent("server-1", "store")
        cfg.transport = {"kind": "ssh", "target": "pinakes@server-1", "timeout": 60}
        self.write("server-1", "store", "a.txt", b"a")

        def run():
            err = io.StringIO()
            with unittest.mock.patch.dict(os.environ, env), \
                    unittest.mock.patch.object(agent, "on_ac_power", return_value=True), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = agent.cmd_run(cfg, argparse.Namespace(root=None))
            return rc, err.getvalue()

        with admin_conn(self.db) as c:
            c.execute("DROP TABLE pinakes.checkins")
        rc, err = run()
        self.assertEqual(rc, 4)
        self.assertIn("pinakes-agent: locked: agent release %d protocol %d, server release %d protocol %d: the "
                      "server must update (its catalog lacks checkins.sql, takeovers.sql)"
                      % ((compat.RELEASE, compat.PROTOCOL) * 2),
                      err)
        self.assertEqual(len(outbox.pending(cfg.outbox)), 2)                # the scan's and its scrub's, held
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 0)
        with admin_conn(self.db) as c:
            for u in ("checkins.sql", "takeovers.sql"):
                with open(os.path.join(UPGRADES, u)) as f:
                    c.execute(f.read())
        self.write("server-1", "store", "b.txt", b"b")
        rc, err = run()
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(outbox.pending(cfg.outbox), [])
        self.assertEqual(self.q("SELECT relpath FROM pinakes.present ORDER BY 1"), [("a.txt",), ("b.txt",)])
        c = self.checkin()
        self.assertEqual((c["release"], c["protocol"], c["locked"], c["batch_protocol"]),
                         (compat.RELEASE, compat.PROTOCOL, None, compat.PROTOCOL))
        # the deploy's report: pinakes releases, through the API, with an ops token (an operator's: user-1)
        from tests.test_api import CliRun, make_token
        ops = CliRun(self)
        self.addCleanup(ops.close)
        ops.save(ops.home_token(), make_token(self, "user-1", scopes=("ops",), client="deploy"))
        lines = ops("releases", cwd=self.tmp).splitlines()
        self.assertEqual(lines[0], "server: release %d, protocol %d, accepts agents of protocol %d or later; schema "
                                   "applied" % (compat.RELEASE, compat.PROTOCOL, compat.MIN_AGENT_PROTOCOL))
        self.assertEqual(lines[1].split(), ["host", "checked_in", "release", "protocol", "min_server", "state",
                                            "newest_batch", "batch_protocol"])
        rows = {l.split()[0]: l for l in lines[2:]}
        self.assertEqual(sorted(rows), ["laptop-1", "server-1", "server-2"])
        self.assertIn("sending", rows["server-1"])
        self.assertIn("never heard from", rows["server-2"])
        got = json.loads(ops("releases", "--json", cwd=self.tmp))
        self.assertTrue(got["server"]["schema_applied"])
        self.assertEqual([a["host"] for a in got["agents"] if a["locked"] is None and a["checked_in"]], ["server-1"])
        # nothing that names a file or person; and the old flag says where it went
        self.assertEqual(ops("roots", cwd=self.tmp, code=1), "pinakes: this token doesn't have the read scope")
        self.assertEqual(ops("--versions", cwd=self.tmp, code=1),
                         "pinakes: --versions is now `pinakes releases`, through the API with an ops token (made by "
                         "an operator on the account page)")


class TestTakeover(ServerCase):
    """A new machine takes over a host: its agent starts from a new state (batches and scans numbered from 1), and
    its roots hold only some of what the old machine's did. The server refuses numbers that went back rather than
    swallow them, check-in has the agent follow, a complete full scan retires what it didn't send, and retire-root
    clears a root the host no longer reports."""

    def other_agent(self, host, label, tree):
        """A second agent of host on root label (a new machine: its own state and outbox) over the folder tree."""
        base = os.path.join(self.tmp, "new-" + host)
        cfg = config.loads('[agent]\nhost = "%s"\nstate = "%s/state.sqlite"\noutbox = "%s/outbox"\n'
                           '[[root]]\nlabel = "%s"\npath = "%s"\n' % (host, base, base, label, tree))
        os.makedirs(base, exist_ok=True)
        st = State(cfg.state)
        self.addCleanup(st.close)
        return st, cfg

    def send(self, cfg, host="server-1"):
        out = []
        for seq, p in outbox.pending(cfg.outbox):
            header, recs = outbox.read(p)
            out.append(self.ing.apply(header, recs, host))
            outbox.ack(cfg.outbox, seq)
        return out

    def checkin(self):
        return self.q("SELECT c.refused, c.seq_reset, c.seq_reset_at IS NOT NULL FROM pinakes.checkins c "
                      "JOIN pinakes.hosts h USING (host_id) WHERE h.name = 'server-1'")[0]

    def old_machine(self, n=5):
        for i in range(n):
            self.write("server-1", "store", "home/f%03d.txt" % i, b"file %d" % i)
        for _ in range(3):
            self.write("server-1", "store", "home/later.txt", b"%f" % time.time())
            self.scan("server-1", "store")
        return self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0]

    def present(self):
        return [r[0] for r in self.q("SELECT relpath FROM pinakes.present ORDER BY 1")]

    def test_a_number_that_went_back_is_refused_not_swallowed(self):
        last = self.old_machine()
        self.assertEqual(last, 3)
        tree = os.path.join(self.tmp, "new-tree")
        os.makedirs(tree)
        with open(os.path.join(tree, "new.txt"), "wb") as f:
            f.write(b"new")
        st, cfg = self.other_agent("server-1", "store", tree)
        Scanner(cfg, st).scan(cfg.roots[0])
        (seq, p), = outbox.pending(cfg.outbox)
        header, recs = outbox.read(p)
        self.assertEqual(seq, 1)
        with self.assertRaises(Refused) as e:
            self.ing.apply(header, recs, "server-1")
        self.assertIn("batch 1: this host's batches are applied up to 3, and 1 was another batch: the agent's "
                      "numbering went back", str(e.exception))
        self.assertNotIn("new.txt", self.present())                     # nothing applied
        refused, reset, at = self.checkin()
        self.assertEqual((refused, reset, at), (str(e.exception), str(e.exception), True))
        # the same batch sent again (its ack lost) is still a duplicate, whatever its number
        st0, cfg0, _ = self.agent("server-1", "store")
        self.write("server-1", "store", "home/again.txt", b"again")
        Scanner(cfg0, st0).scan(cfg0.roots[0])
        (s0, p0), = outbox.pending(cfg0.outbox)
        h0, r0 = outbox.read(p0)
        self.assertEqual(self.ing.apply(h0, r0, "server-1"), "applied")
        self.assertEqual(self.ing.apply(h0, r0, "server-1"), "duplicate")
        outbox.ack(cfg0.outbox, s0)
        # hello tells the new agent where the host is; it follows, and its batch is applied
        answer = self.ing.hello("server-1", {"protocol": compat.PROTOCOL, "next_seq": 1})
        self.assertEqual(answer["last_seq"], 4)
        self.assertEqual(answer["last_header_sha256"], outbox.header_digest(h0).hex())
        self.assertIn("the agent's next batch was 1, this host's batches are applied up to 4", self.checkin()[1])
        self.conn.execute("UPDATE pinakes.checkins SET seq_reset = NULL")
        self.ing.hello("server-1", {"next_seq": 4, "next_header_sha256": answer["last_header_sha256"]})
        self.assertIsNone(self.checkin()[1])                            # its last batch sent again: no reset
        self.ing.hello("server-1", {"next_seq": 4, "next_header_sha256": "00"})
        self.assertIn("next batch was 4", self.checkin()[1])           # another batch of that number: a reset
        from pinakes import agent
        self.assertIn("1 waiting batch(es) renumbered 1-1 to 5-5", agent.follow(cfg, 4, answer["last_header_sha256"]))
        self.assertEqual(self.send(cfg), ["applied"])
        self.assertIn("new.txt", self.present())
        from tests.test_api import CliRun, make_token
        ops = CliRun(self)
        self.addCleanup(ops.close)
        ops.save(ops.home_token(), make_token(self, "user-1", scopes=("ops",), client="deploy"))
        out = ops("releases", cwd=self.tmp)
        self.assertIn("server-1: numbering went back ", out)
        self.assertIn(": the agent's next batch was 4, this host's batches are applied up to 4: it was told to "
                      "continue after 4", out)                                # the last check-in above
        row = [l for l in out.splitlines() if l.startswith("server-1 ")][0]
        self.assertIn("sending", row)                                   # applied since its refusal

    def test_a_batch_from_before_headers_were_kept(self):
        """ingested rows from before the upgrade have no header digest: only the last number is a duplicate."""
        self.old_machine()
        self.conn.execute("UPDATE pinakes.ingested SET header_sha256 = NULL")
        st, cfg, _ = self.agent("server-1", "store")
        hdr = {"t": "batch", "format": 2, "host": "server-1", "root": "store", "scan": 99, "complete": False,
               "started": "2026-01-01T00:00:00Z", "root_def": {"path": "/mnt/store"}, "protocol": compat.PROTOCOL}
        self.assertEqual(self.ing.apply(dict(hdr, seq=3), [], "server-1"), "duplicate")
        with self.assertRaises(Refused):
            self.ing.apply(dict(hdr, seq=2), [], "server-1")

    def takeover(self, keep, **scan):
        """The old machine's root, then a new machine with only `keep` of its files (and one of its own), scanning
        it with scan_kw; returns what the ingester said."""
        self.old_machine(n=keep[1])
        tree = os.path.join(self.tmp, "new-tree")
        for i in range(keep[0]):
            p = os.path.join(tree, "home/f%03d.txt" % i)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(b"file %d" % i)
        with open(os.path.join(tree, "home/mine.txt"), "wb") as f:
            f.write(b"the new machine's")
        st, cfg = self.other_agent("server-1", "store", tree)
        from pinakes import agent
        agent.follow(cfg, self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0])
        Scanner(cfg, st).scan(cfg.roots[0], **scan)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(set(self.send(cfg)), {"applied"})
        return err.getvalue(), tree

    def test_a_full_scan_retires_what_it_didnt_send(self):
        said, _ = self.takeover((3, 5), full=True)
        self.assertEqual(self.present(), ["home/f000.txt", "home/f001.txt", "home/f002.txt", "home/mine.txt"])
        self.assertIn("full scan 1: 3 file(s) present here that it didn't send are gone", said)
        gone = self.q("SELECT f.relpath FROM pinakes.files f JOIN pinakes.history h USING (file_id) "
                      "WHERE h.kind = 'gone' ORDER BY 1")
        self.assertEqual(gone, [("home/f003.txt",), ("home/f004.txt",), ("home/later.txt",)])
        self.assertEqual(self.q("SELECT completed, started_at IS NOT NULL FROM pinakes.scans s JOIN pinakes.roots r "
                                "USING (root_id) WHERE r.label = 'store' AND s.scan = 1"), [(True, True)])

    def test_a_scan_not_full_retires_nothing(self):
        said, _ = self.takeover((3, 5))
        self.assertEqual(len(self.present()), 7)
        self.assertNotIn("gone", said)

    def test_most_of_a_root_needs_accept_gone(self):
        said, tree = self.takeover((10, 150), full=True)
        self.assertEqual(len(self.present()), 152)
        self.assertIn("full scan 1 didn't send 141 of the 152 files present here; that is most of the root, so none "
                      "is retired. If they are really gone (another machine's, before this one took over), run "
                      "scan --full --accept-gone", said)
        st, cfg = self.other_agent("server-1", "store", tree)
        Scanner(cfg, st).scan(cfg.roots[0], full=True, accept_gone=True)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.send(cfg)
        self.assertEqual(len(self.present()), 11)
        self.assertIn("full scan 2: 141 file(s)", err.getvalue())

    @unittest.skipIf(os.geteuid() == 0, "root reads every folder")
    def test_nothing_under_a_folder_it_couldnt_read(self):
        self.old_machine()
        for rel in ("home/f000.txt", "locked/kept.txt"):
            self.write("server-1", "store", rel, b"x" + rel.encode())
        self.scan("server-1", "store")
        tree = os.path.join(self.tmp, "new-tree")
        os.makedirs(os.path.join(tree, "locked"))
        os.chmod(os.path.join(tree, "locked"), 0)
        st, cfg = self.other_agent("server-1", "store", tree)
        from pinakes import agent
        agent.follow(cfg, self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0])
        try:
            Scanner(cfg, st).scan(cfg.roots[0], full=True, accept_gone=True)
        finally:
            os.chmod(os.path.join(tree, "locked"), 0o755)
        with contextlib.redirect_stderr(io.StringIO()):
            self.send(cfg)
        self.assertEqual(self.present(), ["locked/kept.txt"])

    def test_retire_root(self):
        self.old_machine()
        conf = os.path.join(self.tmp, "server.toml")
        with open(conf, "w") as f:
            f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s"\n%s' % (PGHOST, self.db, SERVER))
        for args, line in ((["--dry-run"], "root store: 6 file(s) would go"), ([], "root store: 6 file(s) gone")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(ingest_main(["--config", conf, "retire-root", "store"] + args), 0)
            self.assertEqual(out.getvalue().strip(), line)
        self.assertEqual(self.present(), [])
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.history WHERE kind = 'gone'")[0][0], 6)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(ingest_main(["--config", conf, "retire-root", "nowhere"]), 1)
        self.assertEqual(err.getvalue(), "no root 'nowhere'\n")

    def test_upgrade_file_matches_the_schema(self):
        cols = ("SELECT array_agg(table_name || '.' || column_name || ':' || data_type || ':' || is_nullable || ':' "
                "|| coalesce(column_default, '') ORDER BY table_name, ordinal_position) "
                "FROM information_schema.columns "
                "WHERE table_schema = 'pinakes' AND table_name IN ('scans', 'ingested', 'checkins')")
        with admin_conn(self.db) as c:
            fresh = c.execute(cols).fetchone()
            for t, col in (("scans", "began_at"), ("scans", "started_at"), ("ingested", "header_sha256"),
                           ("checkins", "seq_reset_at"), ("checkins", "seq_reset")):
                c.execute("ALTER TABLE pinakes.%s DROP COLUMN %s" % (t, col))
            self.assertEqual(schema_missing(self.conn), ["takeovers.sql"])
            with open(os.path.join(UPGRADES, "takeovers.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(cols).fetchone(), fresh)
            self.assertEqual(schema_missing(self.conn), [])


class TestUnreportedRoots(ServerCase):
    """A machine replaced under the same name, with fewer roots (ROADMAP 46): every batch names the agent's roots, a
    root its host's batches leave out is reported (its files would otherwise count as copies), naming it again or
    retiring it clears that, and the report names no root where a root may not be named."""
    server_toml = SERVER.replace('roots = ["store"]', 'roots = ["store", "media"]').replace(
        'roots = ["snapshots"]', 'roots = ["snapshots"]\nexpected_every = "never"')     # only server-1 reports here

    def machine(self, name, labels):
        """An agent of server-1 with these roots (one config, as a real machine has), on trees of its own."""
        base = os.path.join(self.tmp, name)
        text = '[agent]\nhost = "server-1"\nstate = "%s/state.sqlite"\noutbox = "%s/outbox"\n' % (base, base)
        for label in labels:
            top = os.path.join(base, label)
            os.makedirs(top)
            with open(os.path.join(top, "%s-%s.txt" % (name, label)), "wb") as f:
                f.write(b"%s %s" % (name.encode(), label.encode()))
            text += '[[root]]\nlabel = "%s"\npath = "%s"\n' % (label, top)
        cfg = config.loads(text)
        st = State(cfg.state)
        self.addCleanup(st.close)
        return st, cfg

    def run_scan(self, st, cfg, edit=None, **kw):
        for root in cfg.roots:
            Scanner(cfg, st).scan(root, **kw)
        for seq, p in outbox.pending(cfg.outbox):
            header, recs = outbox.read(p)
            if edit:
                edit(header)
            with contextlib.redirect_stderr(io.StringIO()):
                self.ing.apply(header, recs, "server-1")
            outbox.ack(cfg.outbox, seq)

    def report(self):
        from pinakes import web
        code, body = web.health_report(lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db))
        h = {x["host"]: x for x in body["hosts"]}["server-1"]
        app = psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db)
        try:
            versions = {a["host"]: a for a in queries.agent_versions(app)}["server-1"]
        finally:
            app.close()
        self.assertNotIn("media", json.dumps(body))                     # /health: host names and counts only
        self.assertNotIn("media", json.dumps(versions, default=str))    # pinakes releases: the same
        return code, body["status"], h["roots_unreported"], versions["roots_unreported"]

    def totals(self, dsn_extra=""):
        conf = os.path.join(self.tmp, "server.toml")
        with open(conf, "w") as f:
            f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s%s"\n%s'
                    % (PGHOST, self.db, dsn_extra, self.server_toml))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ingest_main(["--config", conf, "totals"]), 0)
        return conf, out.getvalue()

    def test_a_machine_replaced_with_fewer_roots(self):
        old = self.machine("old", ["store", "media"])
        self.run_scan(*old)
        self.assertEqual(self.report(), (200, "ok", 0, 0))
        # the new machine has only store; its full scan retires the old machine's files there
        st, cfg = self.machine("new", ["store"])
        from pinakes import agent
        agent.follow(cfg, self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0])
        self.run_scan(st, cfg, full=True, accept_gone=True)
        self.assertEqual(self.report(), (503, "roots unreported", 1, 1))
        # media's file still counts: that is the wrong answer the report is for
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files f JOIN pinakes.roots r USING (root_id) "
                                "WHERE r.label = 'media' AND f.gone_on IS NULL")[0][0], 1)
        conf, out = self.totals()
        self.assertIn("server-1 media: 1 files 9 bytes; NOT REPORTED by server-1 since %s: if it has no such root "
                      "any more (a machine replaced, a root dropped), its files still count as copies until "
                      "pinakes-ingest retire-root media" % queries.today(), out)
        self.assertNotIn("store: 1 files 9 bytes; NOT", out)
        since = self.q("SELECT unreported_since FROM pinakes.roots WHERE label = 'media'")[0][0]
        # a batch from before release 6 names no roots: nothing changes; a later one keeps the first date
        self.run_scan(st, cfg, edit=lambda h: h.pop("roots"))
        self.run_scan(st, cfg)
        self.assertEqual(self.q("SELECT unreported_since FROM pinakes.roots WHERE label = 'media'")[0][0], since)
        # a batch that names it again clears it (the disk was back)
        self.run_scan(st, cfg, edit=lambda h: h.update(roots=["store", "media"]))
        self.assertEqual(self.report(), (200, "ok", 0, 0))
        self.run_scan(st, cfg)
        self.assertEqual(self.report()[1:], ("roots unreported", 1, 1))
        # retiring it ends it, and its file is gone
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ingest_main(["--config", conf, "retire-root", "media"]), 0)
        self.assertEqual(out.getvalue(), "root media: 1 file(s) gone\n")
        self.assertEqual(self.report(), (200, "ok", 0, 0))
        self.run_scan(st, cfg)                                          # still not named: still retired
        self.assertEqual(self.report(), (200, "ok", 0, 0))
        self.assertNotIn("NOT REPORTED", self.totals()[1])

    def test_totals_dates_are_utc_whatever_the_session_time_zone(self):
        # 02:00 UTC on the 2nd is still the 1st in New York: totals says the UTC date, as queries.today() does
        self.run_scan(*self.machine("old", ["store", "media"]))
        st, cfg = self.machine("new", ["store"])
        from pinakes import agent
        agent.follow(cfg, self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0])
        self.run_scan(st, cfg)
        self.conn.execute("UPDATE pinakes.roots SET unreported_since = '2026-01-02 02:00+00' WHERE label = 'media'")
        _, out = self.totals(" options='-c timezone=America/New_York'")
        self.assertIn("NOT REPORTED by server-1 since 2026-01-02:", out)

    def test_a_dry_run_retires_nothing(self):
        self.run_scan(*self.machine("old", ["store", "media"]))
        st, cfg = self.machine("new", ["store"])
        from pinakes import agent
        agent.follow(cfg, self.q("SELECT last_seq FROM pinakes.hosts WHERE name = 'server-1'")[0][0])
        self.run_scan(st, cfg)
        conf, _ = self.totals()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ingest_main(["--config", conf, "retire-root", "media", "--dry-run"]), 0)
        self.assertEqual(self.report()[1:], ("roots unreported", 1, 1))

    def test_a_roots_list_that_leaves_out_its_own_root_is_refused(self):
        st, cfg = self.machine("old", ["store", "media"])
        Scanner(cfg, st).scan(cfg.roots[0])
        (seq, p), = outbox.pending(cfg.outbox)
        header, recs = outbox.read(p)
        for bad in (["media"], "store", [1, "store"]):
            with self.assertRaises(Refused) as e:
                self.ing.apply(dict(header, roots=bad), recs, "server-1")
            self.assertEqual(str(e.exception), "roots must be the labels of every root the agent has, this batch's "
                                               "among them")
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 0)

    def test_upgrade_file_matches_the_schema(self):
        cols = ("SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' "
                "|| coalesce(column_default, '') ORDER BY ordinal_position) FROM information_schema.columns "
                "WHERE table_schema = 'pinakes' AND table_name = 'roots'")
        with admin_conn(self.db) as c:
            fresh = c.execute(cols).fetchone()
            c.execute("ALTER TABLE pinakes.roots DROP COLUMN unreported_since, DROP COLUMN retired_on")
            self.assertEqual(schema_missing(self.conn), ["unreported-roots.sql"])
            with open(os.path.join(UPGRADES, "unreported-roots.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(cols).fetchone(), fresh)
            self.assertEqual(schema_missing(self.conn), [])


class TestHiddenFiles(ServerCase):
    """Hidden files in the catalog: as the agent says (a dot in the path, Samba's hidden attribute), a dot-name also
    from an agent that doesn't say, following a file that moves."""

    def hidden(self):
        return {r[0]: r[1] for r in self.q("SELECT relpath, hidden FROM pinakes.present ORDER BY relpath")}

    def test_from_the_scan_and_through_a_move(self):
        self.write("server-1", "store", "people/user-1/plain.txt", b"plain")
        self.write("server-1", "store", "people/user-1/.config/app.toml", b"config")
        self.scan("server-1", "store")
        self.assertEqual(self.hidden(), {"people/user-1/.config/app.toml": True, "people/user-1/plain.txt": False})
        fid = self.file("store", "people/user-1/plain.txt")
        os.makedirs(self.path("server-1", "store", "people/user-1/.trash"))
        os.rename(self.path("server-1", "store", "people/user-1/plain.txt"),
                  self.path("server-1", "store", "people/user-1/.trash/plain.txt"))
        self.scan("server-1", "store")
        self.assertEqual(self.file("store", "people/user-1/.trash/plain.txt"), fid)        # the same file, moved
        self.assertTrue(self.hidden()["people/user-1/.trash/plain.txt"])

    def test_what_a_record_says_and_a_dot_without_it(self):
        header = {"t": "batch", "format": 2, "host": "server-1", "root": "store", "scan": 1, "seq": 1,
                  "started": "2024-01-01T00:00:00Z", "root_def": {"path": "/mnt/store", "kind": "primary"}}
        recs = [{"t": "file", "path": p, "size": 1, "mtime_ns": 1700000000000000000, "ctime_ns": 1700000000000000000,
                 "dev": 1, "ino": i, "nlink": 1, "uid": 1000, "sha256": hashlib.sha256(p.encode()).hexdigest(), **kw}
                for i, (p, kw) in enumerate([("a.txt", {}), ("by-attribute.txt", {"hidden": True}),
                                             (".from-an-older-agent", {})], 1)]
        self.assertEqual(self.ing.apply(header, recs, "server-1"), "applied")
        self.assertEqual(self.hidden(), {".from-an-older-agent": True, "a.txt": False, "by-attribute.txt": True})

    def test_upgrade_file_matches_the_schema_and_fills_in(self):
        self.write("server-1", "store", "people/user-1/plain.txt", b"plain")
        self.write("server-1", "store", "people/user-1/.config/app.toml", b"config")
        self.write("server-1", "store", ".hidden-at-the-top", b"top")
        self.scan("server-1", "store")
        upgrade_files_match_the_schema(self, ["hidden"], [], ["hidden-files.sql"])
        self.assertEqual(self.hidden(), {".hidden-at-the-top": True, "people/user-1/.config/app.toml": True,
                                         "people/user-1/plain.txt": False})


class TestOwnerByUid(ServerCase):
    """ROADMAP 2: owner = "uid" in a rule gives a folder's files to whoever the host's uid_map names for each file."""
    server_toml = SERVER.replace('[hosts.server-1]\nroots = ["store"]\n',
                                 '[hosts.server-1]\nroots = ["store"]\nuid_map = { 1000 = "user-1", 1001 = "user-2" }\n'
                                 ).replace('[[ownership.enrollment]]', '''[[ownership.rule]]
root = "store"
folder = "home"
owner = "uid"
[[ownership.rule]]
root = "store"
folder = "home/shared"
owner = "household"
[[ownership.enrollment]]''', 1)

    def send(self, files, seq):
        header = {"t": "batch", "format": 2, "host": "server-1", "root": "store", "scan": seq, "seq": seq,
                  "started": "2024-01-01T00:00:00Z", "root_def": {"path": "/mnt/store", "kind": "primary"}}
        recs = [{"t": "file", "path": p, "size": 1, "mtime_ns": 1700000000000000000, "ctime_ns": 1700000000000000000,
                 "dev": 1, "ino": i, "nlink": 1, "uid": uid, "sha256": hashlib.sha256(p.encode()).hexdigest()}
                for i, (p, uid) in enumerate(files, 1)]
        self.assertEqual(self.ing.apply(header, recs, "server-1"), "applied")

    def owners(self):
        return dict(self.q("SELECT f.relpath, p.name FROM pinakes.files f JOIN pinakes.people p "
                           "ON p.person_id = f.owner_id"))

    FILES = [("home/a.txt", 1000), ("home/b.txt", 1001), ("home/c.txt", 4242), ("home/shared/d.txt", 1001),
             ("elsewhere/e.txt", 1001)]

    def test_two_uids_two_people_by_the_map(self):
        self.send(self.FILES, 1)
        # c: a uid the map doesn't name falls to the default owner; d: a more specific folder rule outranks the
        # uid rule (its owner is a group, so no person owns it); e: no rule claims it
        self.assertEqual(self.owners(), {"home/a.txt": "user-1", "home/b.txt": "user-2", "home/c.txt": "user-1",
                                         "elsewhere/e.txt": "user-1"})
        self.assertEqual(self.q("SELECT owner_id FROM pinakes.files WHERE relpath = 'home/shared/d.txt'"), [(None,)])
        with self.as_person("user-2") as c:
            seen = {r[0] for r in c.execute("SELECT relpath FROM pinakes.files")}
        self.assertEqual(seen, {"home/b.txt", "home/shared/d.txt"})
        with self.as_person("user-1") as c:
            seen = {r[0] for r in c.execute("SELECT relpath FROM pinakes.files")}
        self.assertEqual(seen, {"home/a.txt", "home/c.txt", "home/shared/d.txt", "elsewhere/e.txt"})

    def test_a_chown_moves_the_file_and_a_recompute_agrees(self):
        self.send(self.FILES, 1)
        self.send([("home/a.txt", 1001)], 2)
        self.assertEqual(self.owners()["home/a.txt"], "user-2")
        before = self.q("SELECT file_id, acl_id FROM pinakes.files ORDER BY file_id")
        root_id = self.q("SELECT root_id FROM pinakes.roots WHERE label = 'store'")[0][0]
        self.assertEqual(self.ing.recompute_root(root_id), 0)
        self.assertEqual(self.q("SELECT file_id, acl_id FROM pinakes.files ORDER BY file_id"), before)

    def test_the_rules_are_seeded_and_a_map_change_needs_a_recompute(self):
        self.send(self.FILES, 1)                                      # the root's first batch seeds its rules
        self.assertEqual(self.q("SELECT folder, by_uid, owner_person, owner_group IS NOT NULL FROM pinakes.owner_rules "
                                "ORDER BY folder"),
                         [("home", True, None, False), ("home/shared", False, None, True),
                          ("people/user-2", False, self.q("SELECT person_id FROM pinakes.people WHERE "
                                                          "name = 'user-2'")[0][0], False)])
        self.scfg.hosts["server-1"]["uid_map"][4242] = "user-2"
        root_id = self.q("SELECT root_id FROM pinakes.roots WHERE label = 'store'")[0][0]
        self.assertEqual(self.ing.recompute_root(root_id), 1)
        self.assertEqual(self.owners()["home/c.txt"], "user-2")

    def test_the_config_refuses_a_uid_rule_with_no_map(self):
        with self.assertRaisesRegex(server_config.ConfigError, "needs a uid_map"):
            server_config.loads(SERVER.replace('[[ownership.enrollment]]', '''[[ownership.rule]]
root = "store"
folder = "home"
owner = "uid"
[[ownership.enrollment]]''', 1))
        with self.assertRaisesRegex(server_config.ConfigError, "not a person or group"):
            server_config.loads(self.server_toml.replace('1001 = "user-2"', '1001 = "nobody"'))

    def test_upgrade_file_matches_the_schema(self):
        defs = ("SELECT array_agg(column_name::text || ':' || data_type || ':' || is_nullable || ':' || "
                "coalesce(column_default, '') ORDER BY column_name) FROM information_schema.columns "
                "WHERE table_schema = 'pinakes' AND table_name = 'owner_rules'")      # an upgrade adds at the end
        cons = ("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'pinakes.owner_rules'::regclass "
                "AND contype = 'c'")
        with admin_conn(self.db) as c:
            fresh = (c.execute(defs).fetchone(), c.execute(cons).fetchall())
            c.execute("ALTER TABLE pinakes.owner_rules DROP COLUMN by_uid CASCADE")
            c.execute("ALTER TABLE pinakes.owner_rules ADD CONSTRAINT owner_rules_check "
                      "CHECK ((owner_person IS NULL) <> (owner_group IS NULL))")
            with open(os.path.join(UPGRADES, "owner-by-uid.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual((c.execute(defs).fetchone(), c.execute(cons).fetchall()), fresh)


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
            n = self.ing.tidy(queries.today())
        self.assertEqual((n["backup history rows"], n["backup gone rows"]), (2, 1))
        self.assertEqual(self.q("SELECT file_id FROM pinakes.files f JOIN pinakes.roots r USING (root_id) "
                                "WHERE r.label = 'snapshots'"), [(kept,)])
        self.assertEqual(self.history(kept), [])
        self.assertEqual(self.history(src), src_history)                          # a primary root's history stays
        with self.conn.transaction():
            n = self.ing.tidy(queries.today())                            # a second run finds nothing
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
            n = self.ing.tidy(queries.today())
        self.assertEqual((n["name keys updated"], n["name edges removed"], n["name edges kept"]), (1, 2, 0))
        self.assertEqual(self.q("SELECT name_key FROM pinakes.files WHERE file_id = %s", (neg,)), [("r -1 1",)])
        self.assertEqual(self.edges(), [])
        with self.conn.transaction():
            self.assertEqual(set(self.ing.tidy(queries.today()).values()), {0})

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
            n = self.ing.tidy(queries.today())
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
            n = self.ing.tidy(queries.today())
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
        self.assertEqual(self.ing.totals(), [("server-1", "store", c["files"], c["bytes"], 0, None)])
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


class TestSchemaRegistry(ServerCase):
    """The schema registry (ROADMAP 12): setup makes an index for every indexed field of every enrolled schema, the
    project's and the site's, and drops the ones no schema wants any more; a bad schema stops setup with a message
    and changes nothing; the function that makes them takes names, never SQL, and only the ingester may run it."""

    def setUp(self):
        super().setUp()
        self.site = os.path.join(self.tmp, "schemas")
        os.makedirs(self.site)
        self.write_schema("photo", PHOTO_SCHEMA)
        self.cfg_path = os.path.join(self.tmp, "server.toml")
        with open(self.cfg_path, "w") as f:
            f.write('[database]\ndsn = "host=%s user=pinakes_ingest dbname=%s"\n[metadata]\nschemas = "%s"\n%s'
                    % (PGHOST, self.db, self.site, SERVER))

    def write_schema(self, name, text):
        with open(os.path.join(self.site, name + ".toml"), "w") as f:
            f.write(text)

    def setup_cmd(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ingest_main(["--config", self.cfg_path, "setup"])
        return rc, out.getvalue(), err.getvalue()

    def md_indexes(self):
        return {r[0] for r in self.q("SELECT indexname FROM pg_indexes WHERE schemaname = 'pinakes' "
                                     "AND tablename = 'metadata' AND indexname LIKE 'md\\_%%'")}

    def wanted(self, site=True):
        reg = registry.load(self.site if site else None)
        return {registry.index_name(*i) for i in reg.indexes()}

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def test_setup_makes_every_enrolled_fields_index(self):
        rc, out, _ = self.setup_cmd()
        self.assertEqual(rc, 0)
        self.assertIn("schemas dc 1, exif 2, xmp 2, photo 1; 29 metadata indexes, 29 made, 0 dropped", out)
        self.assertEqual(self.md_indexes(), self.wanted())
        self.assertEqual(len(self.wanted()), 29)
        self.assertEqual(self.setup_cmd()[1].splitlines()[-1],
                         "schemas dc 1, exif 2, xmp 2, photo 1; 29 metadata indexes, 0 made, 0 dropped")
        # the indexes are partial, per schema: another schema's rows with the same field name don't reach them
        defs = dict(self.q("SELECT indexname, indexdef FROM pg_indexes WHERE indexname LIKE 'md\\_%%'"))
        self.assertIn("WHERE (schema = 'photo'::text)", defs["md_photo_iso_num"])
        self.assertIn("gin_trgm_ops", defs["md_dc_title_trgm"])
        self.assertIn("USING gist", defs["md_photo_place_geo"])

    def test_the_indexes_take_values_of_their_types_and_serve_searches(self):
        self.setup_cmd()
        cid = self.q("INSERT INTO pinakes.contents (sha256, size) VALUES ('\\x01', 1) RETURNING content_id")[0][0]
        self.q("INSERT INTO pinakes.metadata (content_id, schema, vals, source) VALUES (%s, 'photo', %s, 'embedded'),"
               " (%s, 'dc', %s, 'embedded') RETURNING metadata_id",
               (cid, json.dumps({"photographer": "User One", "taken": "2019-05-04T13:20:00Z",
                                 "place": {"lat": 47.5, "lon": 8.5}, "iso": 200, "length": 1.5, "shown": [1, 2],
                                 "album": 7, "document_id": "uuid:1"}),
                cid, json.dumps({"title": "A walk", "creator": ["User One"], "subject": ["walk"],
                                 "date": "2019-05-04"})))
        # each search uses its index, when it is the table's only one (on two rows the planner would pick any index
        # that covers "schema = ...": every md_* one does)
        others = {r[0] for r in self.q("SELECT indexname FROM pg_indexes WHERE schemaname = 'pinakes' AND "
                                       "tablename = 'metadata' AND indexname <> 'metadata_pkey'")}
        with admin_conn(self.db) as c:
            for where, idx in [
                    ("schema = 'photo' AND (vals ->> 'iso')::numeric > 100", "md_photo_iso_num"),
                    ("schema = 'photo' AND point((vals -> 'place' ->> 'lon')::float8, "
                     "(vals -> 'place' ->> 'lat')::float8) <@ box '((8,47),(9,48))'", "md_photo_place_geo"),
                    ("schema = 'dc' AND vals ->> 'title' ILIKE '%walk%'", "md_dc_title_trgm"),
                    ("schema = 'dc' AND vals ->> 'date' >= '2019'", "md_dc_date_date"),
                    ("schema = 'dc' AND vals -> 'subject' ? 'walk'", "md_dc_subject_list")]:
                with c.transaction(force_rollback=True):
                    for other in others - {idx}:
                        c.execute("DROP INDEX pinakes.%s" % other)
                    c.execute("SET LOCAL enable_seqscan = off")
                    sql = "SELECT metadata_id FROM pinakes.metadata WHERE " + where
                    plan = "\n".join(r[0] for r in c.execute("EXPLAIN " + sql))
                    self.assertIn(idx, plan, where)
                    self.assertEqual(len(c.execute(sql).fetchall()), 1, where)

    def test_indexes_no_schema_wants_are_dropped(self):
        self.setup_cmd()
        self.write_schema("photo", PHOTO_SCHEMA.replace('type = "number"\nindex = "range"', 'type = "number"'))
        rc, out, _ = self.setup_cmd()
        self.assertEqual(rc, 0)
        self.assertIn("28 metadata indexes, 0 made, 1 dropped", out)
        self.assertNotIn("md_photo_iso_num", self.md_indexes())
        os.remove(os.path.join(self.site, "photo.toml"))
        self.setup_cmd()
        self.assertEqual(self.md_indexes(), self.wanted(site=False))
        self.assertEqual(self.q("SELECT count(*) FROM pg_indexes WHERE indexname IN "
                                "('metadata_content', 'metadata_file', 'metadata_vals')")[0][0], 3)

    def test_a_bad_schema_stops_setup_and_changes_nothing(self):
        self.setup_cmd()
        before = self.md_indexes()
        self.conn.execute("UPDATE pinakes.people SET display = 'before' WHERE name = 'user-2'")
        self.write_schema("photo", PHOTO_SCHEMA.replace('index = "spatial"', 'index = "trigram"'))
        self.write_schema("extra", 'name = "extra"\nversion = 1\nmime = ["*/*"]\n[fields.x]\ntype = "text"\n'
                                   'index = "exact"\n')
        rc, out, err = self.setup_cmd()
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("schema refused: %s: field place: index 'trigram' doesn't apply to point (use spatial)"
                      % os.path.join(self.site, "photo.toml"), err)
        self.assertEqual(self.md_indexes(), before)
        self.assertEqual(self.q("SELECT display FROM pinakes.people WHERE name = 'user-2'")[0][0], "before")

    def test_the_function_takes_names_not_sql(self):
        for bad in ([["dc", "x')); DROP TABLE pinakes.files; --", "eq"]], [["dc; DROP", "x", "eq"]],
                    [["dc", "x", "eq; DROP"]], [["dc", "x"]], {"dc": "x"}, [["dc", "Title", "eq"]]):
            with self.subTest(bad=bad):
                with self.assertRaises(psycopg.errors.RaiseException):
                    self.conn.execute("SELECT pinakes.enroll_metadata_indexes(%s::jsonb)", (json.dumps(bad),))
        self.assertIsNotNone(self.q("SELECT to_regclass('pinakes.files')")[0][0])
        self.assertEqual(self.md_indexes(), set())

    def test_only_the_ingester_may_enroll(self):
        with admin_conn(self.db) as c:
            self.assertEqual(c.execute(
                "SELECT has_function_privilege('pinakes_app', 'pinakes.enroll_metadata_indexes(jsonb)', 'EXECUTE'), "
                "has_function_privilege('public', 'pinakes.enroll_metadata_indexes(jsonb)', 'EXECUTE'), "
                "has_function_privilege('pinakes_ingest', 'pinakes.enroll_metadata_indexes(jsonb)', 'EXECUTE')"
            ).fetchone(), (False, False, True))
        with psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db, autocommit=True) as app:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                app.execute("SELECT pinakes.enroll_metadata_indexes('[]')")
        # nor may the ingester make an index on its own: only through the function
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.conn.execute("CREATE INDEX md_dc_x_eq ON pinakes.metadata ((vals ->> 'x'))")

    def test_upgrade_file_matches_the_schema(self):
        sig = "'pinakes.enroll_metadata_indexes(jsonb)'::regprocedure"
        defs = ("SELECT pg_get_functiondef(%s), has_function_privilege('pinakes_ingest', %s, 'EXECUTE'), "
                "has_function_privilege('pinakes_app', %s, 'EXECUTE'), has_function_privilege('public', %s, "
                "'EXECUTE')" % (sig, sig, sig, sig))
        with admin_conn(self.db) as c:
            fresh = c.execute(defs).fetchone()
            c.execute("DROP FUNCTION pinakes.enroll_metadata_indexes(jsonb)")
            with open(os.path.join(UPGRADES, "metadata-indexes.sql")) as f:
                c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(defs).fetchone(), fresh)
        self.assertEqual(fresh[1:], (True, False, False))
        self.assertEqual(self.setup_cmd()[0], 0)


PHOTO_SCHEMA = """
name = "photo"
version = 1
mime = ["image/*"]
[common]
creator = "photographer"
date = "taken"
[fields.photographer]
type = "text"
index = "trigram"
[fields.taken]
type = "date"
index = "range"
[fields.place]
type = "point"
index = "spatial"
sensitive = true
[fields.iso]
type = "number"
index = "range"
[fields.shown]
type = "list"
of = "person"
index = "exact"
sensitive = true
[fields.album]
type = "file"
index = "exact"
[fields.note]
type = "text"
"""


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


class TestExtracted(ServerCase):
    """Extracted metadata in batches (ROADMAP 13): kept on the content, checked against the registry, refused from
    protected roots and links."""

    def metadata(self):
        return self.q("SELECT c.sha256, m.schema, m.vals, m.source, m.version, h.name, m.sensitive "
                      "FROM pinakes.metadata m "
                      "JOIN pinakes.contents c USING (content_id) LEFT JOIN pinakes.hosts h ON h.host_id = m.sent_by "
                      "ORDER BY m.metadata_id")

    def batch(self, records, protected=False, seq=1, fmt=2, host="server-1", root="store"):
        header = {"t": "batch", "format": fmt, "host": host, "root": root, "scan": seq, "seq": seq,
                  "started": "2024-01-01T00:00:00Z",
                  "root_def": {"path": "/mnt/store", "kind": "primary", "protected": protected}}
        return self.ing.apply(header, records, host)

    def rec(self, path, meta=None, **kw):
        r = {"t": "file", "path": path, "size": 10, "mtime_ns": 1700000000000000000, "ctime_ns": 1700000000000000000,
             "dev": 1, "ino": 1, "nlink": 1, "uid": 1000, "sha256": hashlib.sha256(path.encode()).hexdigest()}
        if meta is not None:
            r["meta"] = meta
        r.update(kw)
        return r

    def test_a_photo_and_its_copy_elsewhere_one_row(self):
        from pinakes import queries
        photo = jpegs.camera()
        self.write("server-1", "store", "people/user-1/IMG_0001.JPG", photo)
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "IMG_0001 (1).jpg", photo)
        self.scan("laptop-1", "downloads")
        rows = self.metadata()
        self.assertEqual(len(rows), 2)                          # one content: its fields, and its GPS apart
        digest = hashlib.sha256(photo).hexdigest()
        self.assertEqual([(r[0].hex(), r[1], r[2], r[3], r[4], r[5], r[6]) for r in rows],
                         [(digest, "exif", jpegs.EXPECTED, "embedded", 2, "server-1", False),
                          (digest, "exif", {"gps": jpegs.GPS}, "embedded", 2, "server-1", True)])
        found = queries.meta(self.conn, "exif", "make", "Maker-1")
        self.assertEqual(sorted(r["relpath"] for r in found), ["IMG_0001 (1).jpg", "people/user-1/IMG_0001.JPG"])

    def test_xmp_people_and_places_apart_and_found_by_its_id(self):
        from pinakes import queries
        self.write("server-1", "store", "people/user-1/IMG_0003.JPG", jpegs.tagged())
        self.scan("server-1", "store")
        rows = {(r[1], r[6]): r[2] for r in self.metadata()}
        self.assertEqual(set(rows), {("exif", False), ("xmp", False), ("xmp", True)})
        self.assertEqual(rows[("xmp", False)], jpegs.XMP_EXPECTED)
        self.assertEqual(rows[("xmp", True)], jpegs.XMP_SENSITIVE)
        found = queries.meta(self.conn, "xmp", "document_id", "xmp.did:doc-1")
        self.assertEqual([r["relpath"] for r in found], ["people/user-1/IMG_0003.JPG"])
        with self.as_person("user-2") as c:
            self.assertEqual(queries.meta(c, "xmp", "document_id", "xmp.did:doc-1"), [])   # not hers to see

    def test_seen_only_by_who_can_see_a_copy(self):
        self.write("server-1", "store", "people/user-1/IMG_0001.JPG", jpegs.camera())
        self.write("server-1", "store", "people/user-2/IMG_0002.JPG", jpegs.camera(make="Maker-2"))
        self.scan("server-1", "store")
        for person, makes in (("user-1", ["Maker-1"]), ("user-2", ["Maker-2"])):
            with self.as_person(person) as c:
                got = [r[0] for r in c.execute("SELECT vals ->> 'make' FROM pinakes.metadata WHERE NOT sensitive "
                                               "ORDER BY 1")]
            self.assertEqual(got, makes, person)

    def test_refused_from_a_protected_root_or_link(self):
        meta = {"exif": {"v": 1, "vals": {"make": "Maker-1"}}}
        with self.assertRaisesRegex(Refused, "metadata from a protected root"):
            self.batch([self.rec("a.jpg", meta)], protected=True)
        with self.assertRaisesRegex(Refused, "metadata from a protected link"):
            self.batch([self.rec("b.jpg", meta, protected_link=True)])
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 0)   # nothing of either applied
        self.assertEqual(self.metadata(), [])

    def test_a_link_into_a_protected_root_takes_what_was_known(self):
        meta = {"exif": {"v": 1, "vals": {"make": "Maker-1"}}}
        self.batch([self.rec("a.jpg", meta)])
        self.assertEqual(len(self.metadata()), 1)
        self.batch([self.rec("a.jpg", nlink=2, protected_link=True)], seq=2)
        self.assertEqual(self.metadata(), [])

    def test_what_the_registry_doesnt_allow_is_left_out(self):
        recs = [self.rec("unknown.jpg", {"nosuch": {"v": 1, "vals": {"x": 1}}}),
                self.rec("no-extractor.jpg", {"dc": {"v": 1, "vals": {"title": "t"}}}),
                self.rec("newer.jpg", {"exif": {"v": 9, "vals": {"make": "m"}}}),
                self.rec("field.jpg", {"exif": {"v": 1, "vals": {"make": "m", "owner": "user-2"}}}),
                self.rec("type.jpg", {"exif": {"v": 1, "vals": {"iso": "400"}}}),
                self.rec("shape.jpg", {"exif": {"v": 1, "vals": {}, "extra": 1}}),
                self.rec("failed.jpg", {"exif": {"v": 1, "error": "BadExif: not a JPEG"}}),
                self.rec("gps.jpg", {"exif": {"v": 1, "vals": {"make": "m", "gps": {"lat": 1.0, "lon": 2.0}}}})]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.batch(recs), "applied")
        self.assertEqual([d[0] for d in self.ing.dropped],
                         ["unknown.jpg", "no-extractor.jpg", "newer.jpg", "field.jpg", "type.jpg", "shape.jpg"])
        self.assertIn("metadata left out for 6 file(s)", err.getvalue())
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files")[0][0], 8)   # the files themselves are in
        rows = self.metadata()
        self.assertEqual([(r[2], r[4], r[6]) for r in rows], [({"make": "m"}, 1, False),
                                                              ({"gps": {"lat": 1.0, "lon": 2.0}}, 1, True)])
        with self.assertRaisesRegex(Refused, "meta is not a table"):
            self.batch([self.rec("x.jpg", ["exif"])], seq=2)

    def test_a_newer_version_replaces_the_same_does_not(self):
        self.ing.registry["exif"].version = 2
        self.batch([self.rec("a.jpg", {"exif": {"v": 2, "vals": {"make": "new"}}})])
        self.batch([self.rec("a.jpg", {"exif": {"v": 1, "vals": {"make": "old"}}}, mtime_ns=1)], seq=2)
        self.assertEqual([r[2] for r in self.metadata()], [{"make": "new"}])
        self.batch([self.rec("a.jpg", {"exif": {"v": 2, "vals": {"make": "other"}}}, mtime_ns=2)], seq=3)
        self.assertEqual([r[2] for r in self.metadata()], [{"make": "new"}])     # the same version: kept
        self.ing.registry["exif"].version = 3
        self.batch([self.rec("a.jpg", {"exif": {"v": 3, "vals": {"make": "newer"}}}, mtime_ns=3)], seq=4)
        self.assertEqual([r[2] for r in self.metadata()], [{"make": "newer"}])

    def test_formats(self):
        self.assertEqual(self.batch([self.rec("a.txt")], fmt=1), "applied")
        with self.assertRaisesRegex(Refused, "not a batch of format 1 or 2"):
            self.batch([self.rec("b.txt")], seq=2, fmt=3)

    def test_upgrade_files_match_the_schema(self):
        defs = ("SELECT (SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || "
                "        coalesce(column_default, '') ORDER BY ordinal_position) FROM information_schema.columns "
                "        WHERE table_schema = 'pinakes' AND table_name = 'metadata'), "
                "(SELECT array_agg(pg_get_constraintdef(oid) ORDER BY 1) FROM pg_constraint "
                " WHERE conrelid = 'pinakes.metadata'::regclass), "
                "(SELECT array_agg(policyname || ':' || cmd || ':' || qual ORDER BY policyname) FROM pg_policies "
                " WHERE schemaname = 'pinakes' AND tablename = 'metadata'), "
                "(SELECT pg_get_functiondef('pinakes.sensitive_visible'::regproc)), "
                "(SELECT array_agg(grantee || ':' || privilege_type ORDER BY grantee) "
                " FROM information_schema.routine_privileges WHERE routine_schema = 'pinakes' "
                " AND routine_name = 'sensitive_visible')")
        with admin_conn(self.db) as c:
            fresh = c.execute(defs).fetchone()
            c.execute("DROP POLICY metadata_visible ON pinakes.metadata")
            c.execute("CREATE POLICY metadata_visible ON pinakes.metadata FOR SELECT USING ("
                      "(file_id IS NOT NULL AND EXISTS (SELECT 1 FROM pinakes.files f "
                      "WHERE f.file_id = metadata.file_id))"
                      " OR (content_id IS NOT NULL AND EXISTS (SELECT 1 FROM pinakes.files f "
                      "WHERE f.content_id = metadata.content_id)))")
            c.execute("DROP FUNCTION pinakes.sensitive_visible(bigint, bigint)")
            c.execute("ALTER TABLE pinakes.metadata DROP COLUMN version, DROP COLUMN sent_by, DROP COLUMN sensitive")
            for name in ("metadata-extracted.sql", "metadata-sensitive.sql"):
                with open(os.path.join(UPGRADES, name)) as f:
                    c.execute(f.read())
                c.execute("RESET search_path")
            # api-tokens.sql, later in the order, replaces sensitive_visible() for group tokens (ROADMAP 38)
            with open(os.path.join(UPGRADES, "api-tokens.sql")) as f:
                later = re.search(r"^CREATE OR REPLACE FUNCTION sensitive_visible\(.*?^\$\$;$", f.read(), re.M | re.S)
            c.execute("SET search_path = pinakes")
            c.execute(later.group(0))
            c.execute("RESET search_path")
            self.assertEqual(c.execute(defs).fetchone(), fresh)


class TestSensitive(ServerCase):
    """Sensitive metadata (ROADMAP 16, its first part): GPS, people shown and places, kept in rows of their own that
    only the owners and co-owners of a copy see, or an administrator in a step-up. Readers of a shared folder see the
    rest of a file's metadata, not these."""

    def setUp(self):
        super().setUp()
        self.scfg = server_config.loads(SERVER + """
[[ownership.enrollment]]
root = "store"
folder = "people/user-1/co-owned"
person = "user-2"
as = "co-owner"
""")
        self.ing = Ingester(self.conn, self.scfg)
        self.ing.seed()
        self.write("server-1", "store", "people/user-1/own.jpg", jpegs.camera(make="Maker-1"))
        self.write("server-1", "store", "people/user-1/shared-with-2/shared.jpg", jpegs.camera(make="Maker-2"))
        self.write("server-1", "store", "people/user-1/co-owned/co.jpg", jpegs.camera(make="Maker-3"))
        self.write("server-1", "store", "people/user-2/hers.jpg", jpegs.camera(make="Maker-4"))
        self.write("server-1", "store", "people/user-1/shared-with-2/tagged.jpg", jpegs.tagged())
        self.scan("server-1", "store")

    def where(self, c, field="gps"):
        """The makes of the photos whose sensitive `field` this connection sees."""
        return sorted(r[0] for r in c.execute(
            "SELECT e.vals ->> 'make' FROM pinakes.metadata s JOIN pinakes.metadata e "
            "ON e.content_id = s.content_id AND e.schema = 'exif' AND NOT e.sensitive "
            "WHERE s.sensitive AND s.vals ? %s", (field,)))

    def test_owners_and_co_owners_only(self):
        with self.as_person("user-1") as c:
            self.assertEqual(self.where(c), ["Maker-1", "Maker-2", "Maker-3"])   # all hers; tagged.jpg has no GPS
            self.assertEqual(self.where(c, "people"), ["Maker-1"])            # tagged.jpg's people shown
        with self.as_person("user-2") as c:
            self.assertEqual(self.where(c), ["Maker-3", "Maker-4"])          # co-owner and owner, not as a reader
            shared = sorted(r[0] for r in c.execute("SELECT vals ->> 'make' FROM pinakes.metadata WHERE NOT sensitive "
                                                    "AND schema = 'exif'"))
            self.assertEqual(shared, ["Maker-1", "Maker-2", "Maker-3", "Maker-4"])   # the rest she sees as a reader
            self.assertEqual(self.where(c, "people"), [])                     # nor the people shown in tagged.jpg
            keywords = c.execute("SELECT vals -> 'keywords' FROM pinakes.metadata WHERE schema = 'xmp' "
                                 "AND NOT sensitive").fetchall()
            self.assertEqual(keywords, [(["walk", "lake"],)])

    def test_a_copy_of_her_own_shows_her_its_gps(self):
        self.write("server-1", "store", "people/user-2/copy.jpg", jpegs.camera(make="Maker-1"))
        self.scan("server-1", "store")
        with self.as_person("user-2") as c:
            self.assertEqual(self.where(c), ["Maker-1", "Maker-3", "Maker-4"])   # she holds those bytes herself

    def test_an_administrator_only_in_a_step_up(self):
        with self.as_person("user-1", session="s9") as c:
            self.assertNotIn("Maker-4", self.where(c))
            c.execute("SELECT pinakes.begin_step_up('checking a photo', 5)")
            self.assertIn("Maker-4", self.where(c))
            c.rollback()

    def test_a_search_by_place_returns_only_what_the_person_owns(self):
        box = ("SELECT e.vals ->> 'make' FROM pinakes.metadata s JOIN pinakes.metadata e "
               "ON e.content_id = s.content_id AND e.schema = 'exif' AND NOT e.sensitive "
               "WHERE s.schema = 'exif' AND point((s.vals -> 'gps' ->> 'lon')::float8, "
               "(s.vals -> 'gps' ->> 'lat')::float8) <@ box '((-9,47),(-8,48))' ORDER BY 1")
        with self.as_person("user-2") as c:
            self.assertEqual([r[0] for r in c.execute(box)], ["Maker-3", "Maker-4"])

    def test_the_web_role_cant_read_around_the_policy(self):
        with self.as_person("user-2") as c:
            for sql in ("SELECT count(*) FROM pinakes.metadata WHERE sensitive",):
                self.assertEqual(c.execute(sql).fetchone()[0], 2)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("UPDATE pinakes.metadata SET sensitive = false")
            c.rollback()


if __name__ == "__main__":
    unittest.main()


class _OneFilesystem:
    """Every path on one filesystem of the test's own id: the scrub's view of the disks, with no real mount table."""

    def of(self, path, dev=None):
        from pinakes.scrub import Filesystem
        return Filesystem("uuid:test-fs", "/mnt/test", "ext4", "/dev/test")


class TestScrub(ServerCase):
    """The scrub's findings in the catalog (ROADMAP 41, DESIGN.md "Scrub"): a mismatch is a change of its own kind and
    gives the file its new content, so it stops counting as a copy of the old; an unreadable file is no copy until it
    reads again; both are reviewed; a backup root keeps no history of them; the root's summary reaches /health."""

    U = "people/user-1/"

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", self.U + "a.txt", b"alpha" * 20)
        self.write("server-1", "store", self.U + "b.txt", b"beta" * 20)
        self.write("server-1", "store", "people/user-2/hers.txt", b"hers" * 20)
        self.scan("server-1", "store")
        self.agent("server-2", "snapshots", kind="backup", extra='mirrors = { root = "store", layout = "*/{relpath}" }')
        self.write("server-2", "snapshots", "2026-01-01_0140/" + self.U + "a.txt", b"alpha" * 20)
        self.write("server-2", "snapshots", "2026-01-01_0140/" + self.U + "b.txt", b"beta" * 20)
        self.scan("server-2", "snapshots")
        for key in self.agents:
            with open(self.agents[key][1].scrub, "w") as f:
                f.write('[[filesystem]]\nid = "uuid:test-fs"\ndays = 1\n')
        self.failing = set()

    def corrupt(self, host, label, rel):
        p = self.path(host, label, rel)
        st = os.stat(p)
        with open(p, "r+b") as f:
            f.write(b"X")
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))

    def scrub(self, host, label, days_later=0):
        from pinakes.scan import hash_file
        from pinakes.scrub import Scrubber
        st, cfg, _ = self.agent(host, label)

        def read(path, params=None):
            if path in self.failing:
                raise OSError(5, "Input/output error")
            return hash_file(path, params)
        Scrubber(cfg, st, _OneFilesystem(), now=lambda: time.time() + 60 + days_later * 86400, read=read).run()
        out = []
        for seq, p in outbox.pending(cfg.outbox):
            header, recs = outbox.read(p)
            out.append(self.ing.apply(header, recs, host))
            outbox.ack(cfg.outbox, seq)
        return out

    def not_safe(self, conn=None):
        return sorted(r["relpath"] for r in queries.not_safe_to_delete(conn or self.conn, "store:" + self.U))

    def test_a_mismatch_in_a_kept_file_is_its_own_change_with_the_old_content_in_the_backup(self):
        a = self.file("store", self.U + "a.txt")
        old = self.q("SELECT content_id FROM pinakes.files WHERE file_id = %s", (a,))[0][0]
        self.corrupt("server-1", "store", self.U + "a.txt")
        self.scan("server-1", "store")                                 # only its ctime: not a change
        self.assertEqual(self.history(a), ["new"])
        self.assertEqual(self.scrub("server-1", "store"), ["applied"])
        self.assertEqual(self.history(a), ["new", "mismatch"])
        row = self.q("SELECT old_content_id, new_content_id, old_mtime = new_mtime, seen_after, seen_on, evidence, "
                     "confidence FROM pinakes.history WHERE file_id = %s AND kind = 'mismatch'", (a,))[0]
        new = self.q("SELECT content_id FROM pinakes.files WHERE file_id = %s", (a,))[0][0]
        self.assertEqual(row[:3], (old, new, True))
        self.assertNotEqual(old, new)
        self.assertEqual((row[3], row[4]), (queries.today(), queries.today()))   # verified by today's scan
        self.assertEqual(row[5:], ("scrub: another hash, size and mtime unchanged", "certain"))
        self.assertEqual(self.not_safe(), [self.U + "a.txt"])           # its backup holds the old content now
        with self.as_person("user-1") as c:
            ch = queries.changes(c, kinds=["mismatch"])
            self.assertEqual([(r["path"], r["reviewable"]) for r in ch], [(self.U + "a.txt", True)])
            self.assertEqual(queries.mark_changes(c, [ch[0]["history_id"]], "restore"), 1)
            c.commit()
            (r,) = queries.restores(c)
            self.assertEqual((r["kind"], r["backups"], r["back"]), ("mismatch", 1, False))
            self.assertEqual(r["held_in"][0]["path"], "2026-01-01_0140/" + self.U + "a.txt")
            tree = {t["folder"]: t["scrub"] for t in queries.change_tree(c, loc="store:" + self.U)}
            self.assertEqual(tree["people/user-1"], 1)
        with self.as_person("user-2") as c:                             # not hers: not seen
            self.assertEqual(queries.changes(c, kinds=["mismatch"]), [])

    def test_a_mismatch_in_a_backup_copy_ends_it_as_a_copy_without_history(self):
        self.assertEqual(self.not_safe(), [])
        snap = "2026-01-01_0140/" + self.U + "b.txt"
        self.corrupt("server-2", "snapshots", snap)
        self.scrub("server-2", "snapshots")
        self.assertEqual(self.not_safe(), [self.U + "b.txt"])           # its only other copy is wrong now
        self.assertEqual(self.history(self.file("snapshots", snap)), [])

    def test_an_unreadable_copy_is_no_copy_until_it_reads(self):
        snap = "2026-01-01_0140/" + self.U + "a.txt"
        self.failing.add(self.path("server-2", "snapshots", snap))
        self.scrub("server-2", "snapshots")
        f = self.file("snapshots", snap)
        self.assertEqual(self.q("SELECT unreadable_on, unreadable_error FROM pinakes.files WHERE file_id = %s",
                                (f,)), [(queries.today(), "EIO")])
        self.assertEqual(self.not_safe(), [self.U + "a.txt"])
        self.assertEqual(self.history(f), [])                           # a backup root: no history
        with self.as_person("user-1") as c:
            self.assertEqual([r["backup_copies"] for r in queries.backed_up(c, "store:" + self.U + "a.txt")], [0])
        self.failing.clear()
        self.scrub("server-2", "snapshots", days_later=1)
        self.assertEqual(self.q("SELECT unreadable_on FROM pinakes.files WHERE file_id = %s", (f,)), [(None,)])
        self.assertEqual(self.not_safe(), [])

    def test_an_unreadable_kept_file_is_reviewed_and_its_restore_not_back_while_unreadable(self):
        a = self.file("store", self.U + "a.txt")
        self.failing.add(self.path("server-1", "store", self.U + "a.txt"))
        self.scrub("server-1", "store")
        self.scrub("server-1", "store", days_later=1)                  # still failing: one change, not two
        self.assertEqual(self.history(a), ["new", "unreadable"])
        with self.as_person("user-1") as c:
            ch = queries.changes(c, review="unreviewed")
            self.assertEqual([(r["kind"], r["path"]) for r in ch], [("unreadable", self.U + "a.txt")])
            queries.mark_changes(c, [ch[0]["history_id"]], "restore")
            c.commit()
            self.assertEqual([r["back"] for r in queries.restores(c, back=True)], [False])
        self.failing.clear()
        self.scrub("server-1", "store", days_later=2)
        with self.as_person("user-1") as c:
            self.assertEqual([r["back"] for r in queries.restores(c, back=True)], [True])
        # a later rewrite (a scan seeing new content) clears a mark too
        self.failing.add(self.path("server-1", "store", self.U + "b.txt"))
        self.scrub("server-1", "store", days_later=3)
        self.write("server-1", "store", self.U + "b.txt", b"rewritten")
        self.scan("server-1", "store")
        self.assertEqual(self.q("SELECT unreadable_on FROM pinakes.files WHERE relpath = %s", (self.U + "b.txt",)),
                         [(None,)])

    def test_a_reader_cannot_mark_what_the_scrub_found(self):
        self.corrupt("server-1", "store", self.U + "a.txt")
        self.scrub("server-1", "store")
        hid = self.q("SELECT history_id FROM pinakes.history WHERE kind = 'mismatch'")[0][0]
        with self.as_person("user-2") as c:
            self.assertEqual(queries.mark_changes(c, [hid], "intended"), 0)

    def test_the_summary_and_health(self):
        from pinakes import web
        self.scrub("server-1", "store")
        self.assertEqual(self.q("SELECT scrub_on, scrub_since, scrub_days, scrub_oldest, scrub_never "
                                "FROM pinakes.roots WHERE label = 'store'"),
                         [(queries.today(), queries.today(), 1, queries.today(), 0)])
        connect = lambda: psycopg.connect(host=PGHOST, user="pinakes_app", dbname=self.db)  # noqa: E731
        for tz in FAR_ZONES:            # the session's own date a day off UTC's either way: still today's scrub
            code, body = web.health_report(lambda: psycopg.connect(
                host=PGHOST, user="pinakes_app", dbname=self.db, options="-c timezone=%s" % tz))
            self.assertEqual((code, body["status"]), (200, "ok"), tz)
            self.conn.execute("UPDATE pinakes.roots SET scrub_on = scrub_on - 1 WHERE label = 'store'")
            code, body = web.health_report(lambda: psycopg.connect(
                host=PGHOST, user="pinakes_app", dbname=self.db, options="-c timezone=%s" % tz))
            self.assertEqual(body["status"], "ok", tz)                  # a day late: still within a pass + 1
            self.conn.execute("UPDATE pinakes.roots SET scrub_on = scrub_on + 1 WHERE label = 'store'")
        code, body = web.health_report(connect)
        h = {x["host"]: x for x in body["hosts"]}
        self.assertEqual((h["server-1"]["scrub_oldest"], h["server-1"]["scrub_behind"]),
                         (queries.today().isoformat(), False))
        self.assertIsNone(h["server-2"]["scrub_oldest"])                # not scrubbed: nothing said
        self.conn.execute("UPDATE pinakes.roots SET scrub_on = scrub_on - 2 WHERE label = 'store'")   # stopped
        code, body = web.health_report(connect)
        self.assertEqual((code, body["status"]), (503, "scrub behind"))
        self.assertNotIn("store", json.dumps(body))                     # host names only
        self.conn.execute("UPDATE pinakes.roots SET scrub_never = 3, scrub_since = scrub_on - 3, scrub_on = scrub_on "
                          "+ 2 WHERE label = 'store'")                              # a first pass overdue
        self.assertTrue({x["host"]: x for x in web.health_report(connect)[1]["hosts"]}["server-1"]["scrub_behind"])
        self.conn.execute("UPDATE pinakes.roots SET scrub_days = 0 WHERE label = 'store'")          # turned off
        self.assertEqual(web.health_report(connect)[1]["status"], "ok")

    def test_records_in_the_wrong_kind_of_batch_are_refused(self):
        st, cfg, _ = self.agent("server-1", "store")
        header = {"t": "batch", "format": 2, "host": "server-1", "root": "store", "seq": 50, "protocol": 2,
                  "root_def": {"path": cfg.roots[0].path, "kind": "primary"}}
        with self.assertRaisesRegex(Refused, "a file record in a scrub batch"):
            self.ing.apply(dict(header, scrub={"on": "2026-11-16", "days": 1, "oldest": None, "never": 0}),
                           [{"t": "file", "path": "x"}], "server-1")
        with self.assertRaisesRegex(Refused, "a mismatch record outside a scrub batch"):
            self.ing.apply(dict(header, scan=99, started="2026-11-16T00:00:00.000000Z"),
                           [{"t": "mismatch", "path": "x"}], "server-1")
        with self.assertRaisesRegex(Refused, "a scrub header needs its date"):
            self.ing.apply(dict(header, scrub={"days": 1}), [], "server-1")
        a = self.file("store", self.U + "a.txt")
        with self.assertRaisesRegex(Refused, "a mismatch without its hash"):    # not a file emptied of its content
            self.ing.apply(dict(header, scrub={"on": "2026-11-16", "days": 1, "oldest": None, "never": 0}),
                           [{"t": "mismatch", "path": self.U + "a.txt", "sha256": None}], "server-1")
        self.assertIsNotNone(self.q("SELECT content_id FROM pinakes.files WHERE file_id = %s", (a,))[0][0])

    def test_a_record_for_a_file_since_changed_is_left_alone(self):
        a = self.file("store", self.U + "a.txt")
        self.corrupt("server-1", "store", self.U + "a.txt")
        st, cfg, _ = self.agent("server-1", "store")
        from pinakes.scrub import Scrubber
        Scrubber(cfg, st, _OneFilesystem(), now=lambda: time.time() + 60).run()   # written, not yet sent
        self.write("server-1", "store", self.U + "a.txt", b"edited, a new mtime")
        os.utime(self.path("server-1", "store", self.U + "a.txt"), (time.time() + 5,) * 2)
        Scanner(cfg, st).scan(cfg.roots[0])
        for seq, p in outbox.pending(cfg.outbox):                    # the scrub's batch, then the scan's
            header, recs = outbox.read(p)
            self.ing.apply(header, recs, "server-1")
            outbox.ack(cfg.outbox, seq)
        self.assertEqual(self.history(a), ["new", "mismatch", "changed"])   # each as it came, the scan's last
        p = self.path("server-1", "store", self.U + "a.txt")
        st2 = os.stat(p)
        bad = {"t": "mismatch", "path": self.U + "a.txt", "size": st2.st_size, "mtime_ns": st2.st_mtime_ns - 1,
               "ino": st2.st_ino, "dev": st2.st_dev, "sha256": "00" * 32, "verified": None, "chunk_params": None}
        self.ing.apply({"t": "batch", "format": 2, "host": "server-1", "root": "store", "seq": 900, "protocol": 2,
                        "root_def": {"path": cfg.roots[0].path, "kind": "primary"},
                        "scrub": {"on": queries.today().isoformat(), "days": 1, "oldest": None, "never": 0}},
                       [bad], "server-1")                              # an older state than the catalog's
        self.assertEqual(self.history(a), ["new", "mismatch", "changed"])

    def test_upgrade_file_matches_the_schema(self):
        defs = ("SELECT (SELECT array_agg(column_name || ':' || data_type || ':' || is_nullable || ':' || "
                "        coalesce(column_default, '') ORDER BY ordinal_position) FROM information_schema.columns "
                "        WHERE table_schema = 'pinakes' AND table_name = 'roots'), "
                "(SELECT array_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint "
                " WHERE conrelid = 'pinakes.history'::regclass), "
                "pg_get_functiondef('pinakes.mark_changes(bigint[], text)'::regprocedure), "
                "has_function_privilege('pinakes_app', 'pinakes.mark_changes(bigint[], text)', 'EXECUTE')")
        with admin_conn(self.db) as c:
            fresh = c.execute(defs).fetchone()
            c.execute("ALTER TABLE pinakes.history DROP CONSTRAINT history_kind_check, ADD CONSTRAINT "
                      "history_kind_check CHECK (kind IN ('new', 'changed', 'moved', 'moved_changed', 'gone'))")
            c.execute("ALTER TABLE pinakes.roots DROP COLUMN scrub_on, DROP COLUMN scrub_since, DROP COLUMN "
                      "scrub_days, DROP COLUMN scrub_oldest, DROP COLUMN scrub_never, "
                      "DROP COLUMN unreported_since, DROP COLUMN retired_on")               # a later upgrade's too
            c.execute("ALTER TABLE pinakes.files DROP COLUMN unreadable_on CASCADE, DROP COLUMN unreadable_error")
            c.execute("CREATE OR REPLACE VIEW pinakes.present WITH (security_invoker = true) AS "
                      "SELECT * FROM pinakes.files WHERE gone_on IS NULL")
            self.assertNotEqual(c.execute(defs).fetchone()[:2], fresh[:2])
            for name in ("scrub.sql", "unreported-roots.sql"):
                with open(os.path.join(UPGRADES, name)) as f:
                    c.execute(f.read())
            c.execute("RESET search_path")
            self.assertEqual(c.execute(defs).fetchone(), fresh)
        self.assertTrue(fresh[3])


class TestManifests(ServerCase):
    """ROADMAP 19: checksum manifests in the catalog. A wrong line is reported and a right one confirmed, on the
    files, under the files policy; the catalog's hashes stay the agent's own."""

    def sums(self, rel, lines):
        self.write("server-1", "store", rel, "".join("%s  %s\n" % (hashlib.sha256(d).hexdigest(), n)
                                                     for d, n in lines).encode())

    def verdicts(self):
        return {r[0]: (r[1], r[2]) for r in self.q(
            "SELECT f.relpath, f.manifest_verdict, m.relpath FROM pinakes.present f "
            "LEFT JOIN pinakes.files m ON m.file_id = f.manifest_file_id WHERE f.manifest_verdict IS NOT NULL")}

    def setUp(self):
        super().setUp()
        self.write("server-1", "store", "people/user-1/iso/right.iso", b"right")
        self.write("server-1", "store", "people/user-1/iso/changed.iso", b"changed since")
        self.sums("people/user-1/iso/SHA256SUMS", [(b"right", "right.iso"), (b"as written", "changed.iso"),
                                                   (b"lost", "lost.iso")])
        self.assertEqual(set(self.scan("server-1", "store")), {"applied"})

    def test_a_wrong_line_is_reported_and_a_right_one_confirmed(self):
        m = "people/user-1/iso/SHA256SUMS"
        self.assertEqual(self.verdicts(), {"people/user-1/iso/right.iso": ("confirmed", m),
                                           "people/user-1/iso/changed.iso": ("wrong", m)})
        counts = self.q("SELECT manifest_counts FROM pinakes.present WHERE relpath = %s", (m,))[0][0]
        self.assertEqual(counts, {"lines": 3, "confirmed": 1, "wrong": 1, "missing": 1, "unchecked": 0, "bad": 0,
                                  "outside": 0})
        sha = self.q("SELECT encode(c.sha256, 'hex') FROM pinakes.present f JOIN pinakes.contents c "
                     "USING (content_id) WHERE f.relpath = 'people/user-1/iso/changed.iso'")[0][0]
        self.assertEqual(sha, hashlib.sha256(b"changed since").hexdigest())          # never the manifest's
        with self.as_person("user-1") as c:
            rows = queries.manifests(c, "store:people/user-1")
            self.assertEqual(sorted((r["relpath"], r["problem"], r["manifest_relpath"], r["missing"]) for r in rows),
                             [("people/user-1/iso/SHA256SUMS", "missing", m, 1),
                              ("people/user-1/iso/changed.iso", "wrong", m, None)])
            self.assertEqual(len(queries.manifests(c)), 2)
            f = queries.file_by_id(c, self.file("store", "people/user-1/iso/right.iso"))
            self.assertEqual((f["manifest_verdict"], f["manifest_relpath"]), ("confirmed", m))
        with self.as_person("user-2") as c:                             # not theirs: nothing of it
            self.assertEqual(queries.manifests(c), [])

    def test_fixed_moved_and_gone(self):
        self.write("server-1", "store", "people/user-1/iso/changed.iso", b"as written")
        self.scan("server-1", "store")
        self.assertEqual({p: v[0] for p, v in self.verdicts().items()},
                         {"people/user-1/iso/right.iso": "confirmed", "people/user-1/iso/changed.iso": "confirmed"})
        os.rename(self.path("server-1", "store", "people/user-1/iso"), self.path("server-1", "store",
                                                                                "people/user-1/isos"))
        self.scan("server-1", "store")                                  # moved together: verdicts follow
        self.assertEqual(self.verdicts(), {
            "people/user-1/isos/right.iso": ("confirmed", "people/user-1/isos/SHA256SUMS"),
            "people/user-1/isos/changed.iso": ("confirmed", "people/user-1/isos/SHA256SUMS")})
        os.remove(self.path("server-1", "store", "people/user-1/isos/SHA256SUMS"))
        self.scan("server-1", "store")
        self.assertEqual(self.verdicts(), {})

    def test_refused_from_a_protected_root_or_outside_a_complete_batch(self):
        st, cfg, _ = self.agent("server-1", "store")
        header = {"t": "batch", "format": 2, "host": "server-1", "root": "store", "scan": 99,
                  "started": "2026-11-17T00:00:00.000000Z",
                  "root_def": {"path": cfg.roots[0].path, "kind": "primary", "protected": False, "mirrors": None},
                  "seq": 1000, "roots": ["store"]}
        hint = {"t": "hint", "path": "people/user-1/iso/right.iso", "verdict": "confirmed",
                "manifest": "people/user-1/iso/SHA256SUMS"}
        with self.assertRaisesRegex(Refused, "incomplete"):
            self.ing.apply(header, [hint], "server-1")
        with self.assertRaisesRegex(Refused, "confirmed, wrong or null"):
            self.ing.apply(dict(header, complete=True), [dict(hint, verdict="trusted")], "server-1")
        with self.assertRaisesRegex(Refused, "protected root"):
            self.ing.apply(dict(header, complete=True, root_def=dict(header["root_def"], protected=True)),
                           [hint], "server-1")

    def test_upgrade_file_matches_the_schema(self):
        upgrade_files_match_the_schema(self, [], [], [])
