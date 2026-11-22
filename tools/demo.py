#!/usr/bin/env python3
"""Build a small demo catalog from generated trees, for trying the CLI and the web UI.

  tools/demo.py --pghost SOCKET_DIR_OR_HOST [--pguser postgres] [--db pinakes_demo]

Needs a throwaway PostgreSQL where --pguser is a superuser. Creates the roles if missing, (re)creates the database,
scans generated trees on six pretend machines with real agents, ingests the batches, and sets the demo people's
passwords to `demo password 1` to `demo password 4` (placeholders: never use this on a real catalog).

A household: user-1 (operator and administrator, with a second factor so a step-up works end to end: its codes are
`auth.totp(DEMO_TOTP)`), user-2, user-3 (with a laptop of their own, laptop-2, whose last scan is days old) and
user-4 (a few files on a shared workstation-1, beside user-1's birthday-plans they mustn't find); the group
`household` (all four) owns the shared photos and papers. Photos are generated JPEGs with EXIF and GPS. To walk:
a hash-matched move and gone photos with a snapshot copy under store:shared/photos, an unreviewed gone folder
(store:media/music/album), a file only on laptop-2, and GPS that user-1 sees on their trip photos and user-2, a
reader there, doesn't.
"""

import argparse
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg  # noqa: E402

from pinakes import auth, config, outbox, server_config  # noqa: E402
from pinakes.ingest import Ingester, apply_schema  # noqa: E402
from pinakes.scan import Scanner  # noqa: E402
from pinakes.state import State  # noqa: E402
from tests import jpegs  # noqa: E402

DEMO_TOTP = "DEMOTOTPDEMOTOTPDEMOTOTPDEMOTOTP"     # user-1's second factor: a placeholder, like the passwords

SERVER = """
[ownership]
default_owner = "user-1"
[[ownership.rule]]
root = "store"
folder = "people/user-2"
owner = "user-2"
[[ownership.rule]]
root = "store"
folder = "shared"
owner = "household"
[[ownership.rule]]
root = "downloads-2"
folder = ""
owner = "user-3"
[[ownership.rule]]
root = "shared-home"
folder = "user-4"
owner = "user-4"
[[ownership.enrollment]]
root = "store"
folder = "people/user-1/trip-photos"
person = "user-2"
as = "reader"
[people.user-1]
display = "User One"
roles = ["person", "operator", "administrator"]
[people.user-2]
display = "User Two"
roles = ["person"]
[people.user-3]
display = "User Three"
roles = ["person"]
[people.user-4]
display = "User Four"
roles = ["person"]
[groups.household]
members = ["user-1", "user-2", "user-3", "user-4"]
[hosts.server-1]
roots = ["store"]
[hosts.server-2]
roots = ["snapshots"]
[hosts.laptop-1]
roots = ["downloads"]
expected_every = "never"
[hosts.laptop-2]
roots = ["downloads-2"]
expected_every = "1d"
[hosts.workstation-1]
roots = ["shared-home"]
expected_every = "1d"
"""

PEOPLE = ("user-1", "user-2", "user-3", "user-4")


def photo(n, gps=True):
    """A generated JPEG with EXIF (GPS too), distinct per n: no real photo."""
    return jpegs.camera(gps=gps, when="2026:07:%02d 10:%02d:00" % (1 + n % 28, n % 60))


def build(pghost, pguser, db):
    """(Re)create database db on pghost and build the demo catalog in it; the summary line."""
    with psycopg.connect(host=pghost, user=pguser, dbname="postgres", autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % db)
        c.execute("CREATE DATABASE %s" % db)
        c.execute("DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pinakes_app') THEN "
                  "CREATE ROLE pinakes_app LOGIN; END IF; IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE "
                  "rolname = 'pinakes_ingest') THEN CREATE ROLE pinakes_ingest LOGIN BYPASSRLS; END IF; END$$")
    with psycopg.connect(host=pghost, user=pguser, dbname=db, autocommit=True) as c:
        apply_schema(c)
    conn = psycopg.connect(host=pghost, user="pinakes_ingest", dbname=db, autocommit=True)
    ing = Ingester(conn, server_config.loads(SERVER))
    ing.seed()
    tmp = tempfile.mkdtemp(prefix="pinakes-demo-")
    try:
        t0 = time.time() - 30 * 86400
        machines = {}

        def tree(host, label, kind="primary", extra=""):
            top = os.path.join(tmp, host, label)
            os.makedirs(top, exist_ok=True)
            cfg = config.loads('[agent]\nhost="%s"\nstate="%s/%s.sqlite"\noutbox="%s/outbox-%s"\n'
                               '[[root]]\nlabel="%s"\npath="%s"\nkind="%s"\n%s'
                               % (host, tmp, label, tmp, label, label, top, kind, extra))
            machines[label] = (host, top, cfg, State(cfg.state))

        def put(label, rel, data, days_ago):
            _, top, _, _ = machines[label]
            p = os.path.join(top, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
            t = time.time() - days_ago * 86400
            os.utime(p, (t, t))

        def scan(label):
            host, _, cfg, st = machines[label]
            Scanner(cfg, st).scan(cfg.roots[0])
            for seq, path in outbox.pending(cfg.outbox):
                header, recs = outbox.read(path)
                ing.apply(header, recs, host)
                outbox.ack(cfg.outbox, seq)

        chunks = 'chunks = { enabled = true, min_size = "1", average = "4KiB" }'
        tree("server-1", "store", extra=chunks)
        tree("server-2", "snapshots", "backup", 'mirrors = { root = "store", layout = "*/{relpath}" }')
        tree("laptop-1", "downloads", "drop", chunks)
        tree("laptop-2", "downloads-2")
        tree("workstation-1", "shared-home")
        essay = os.urandom(60000)
        put("store", "people/user-1/writing/essay.odt", essay, 30)
        put("store", "people/user-1/finance/budget-2026.ods", b"budget numbers", 20)
        photos = [photo(i) for i in range(4)]
        for i, data in enumerate(photos):
            put("store", "people/user-1/trip-photos/IMG_%04d.JPG" % i, data, 25)
        put("store", "people/user-2/recipes/bread.txt", b"flour, water, salt", 15)
        put("store", "media/music/album/01 track.flac", os.urandom(8000), 60)
        put("store", "media/music/album/02 track.flac", os.urandom(8000), 60)
        # the household's: beach photos (some to be moved into a dated folder, some to go) and scanned papers
        beach = {n: photo(n) for n in range(2001, 2007)}
        for n, data in beach.items():
            put("store", "shared/photos/beach/IMG_%d.JPG" % n, data, 40)
        put("store", "shared/papers/scan-001.pdf", os.urandom(5000), 50)
        put("store", "shared/papers/scan-002.pdf", os.urandom(5000), 50)
        scan("store")
        put("snapshots", "2026-01-10_0140/people/user-1/writing/essay.odt", essay, 30)
        put("snapshots", "2026-01-10_0140/people/user-2/recipes/bread.txt", b"flour, water, salt", 15)
        put("snapshots", "2026-01-10_0140/people/user-1/trip-photos/IMG_0001.JPG", photos[1], 25)
        for n in (2005, 2006):
            put("snapshots", "2026-01-10_0140/shared/photos/beach/IMG_%d.JPG" % n, beach[n], 40)
        scan("snapshots")
        # the essay goes to the laptop, gets worked on, and comes back; photos are dropped there too
        put("downloads", "essay.odt", essay, 5)
        put("downloads", "camera-import/IMG_0100.JPG", os.urandom(3000), 3)
        put("downloads", "camera-import/IMG_0001.JPG", b"", 3)
        put("downloads", "trip/IMG_0003.JPG", photos[3], 3)          # moved off the server by hand, below
        scan("downloads")
        # user-3's laptop: a school project with no copy anywhere else
        put("downloads-2", "school/project.odt", os.urandom(20000), 6)
        put("downloads-2", "music/mix.ogg", os.urandom(9000), 8)
        scan("downloads-2")
        # the shared workstation: user-4's few files, and user-1's plans they mustn't find
        put("shared-home", "user-4/drawings/cat.png", os.urandom(4000), 10)
        put("shared-home", "user-4/homework.txt", b"three times seven", 2)
        put("shared-home", "user-1/birthday-plans/gift-list.txt", b"a kite", 4)
        scan("shared-home")
        edited = essay[:30000] + b"a new paragraph" + essay[30000:]
        put("downloads", "essay.odt", edited, 2)
        put("downloads", "essay - new.odt", edited + b" and more", 1)
        scan("downloads")
        put("store", "people/user-1/writing/essay.odt", edited, 1)
        os.makedirs(os.path.join(machines["store"][1], "people/user-1/archive"), exist_ok=True)
        os.rename(os.path.join(machines["store"][1], "people/user-1/finance/budget-2026.ods"),
                  os.path.join(machines["store"][1], "people/user-1/archive/budget-2026.ods"))
        # a clean-up to review (ROADMAP 32): one photo gone with a backup, one moved to the laptop, one with no copy
        store = machines["store"][1]
        for i in (1, 2, 3):
            os.remove(os.path.join(store, "people/user-1/trip-photos/IMG_%04d.JPG" % i))
        # the beach: three moved into a dated folder (a move by hash), two gone (each with a snapshot copy)
        os.makedirs(os.path.join(store, "shared/photos/beach/2026-07"))
        for n in (2001, 2002, 2003):
            os.rename(os.path.join(store, "shared/photos/beach/IMG_%d.JPG" % n),
                      os.path.join(store, "shared/photos/beach/2026-07/IMG_%d.JPG" % n))
        for n in (2005, 2006):
            os.remove(os.path.join(store, "shared/photos/beach/IMG_%d.JPG" % n))
        # a folder gone, left unreviewed: to mark with `pinakes review intended`, then see in `edits` and `undo`
        shutil.rmtree(os.path.join(store, "media/music/album"))
        scan("store")
        # laptop-2 is off most of the time: its last complete scan was days ago
        conn.execute("UPDATE pinakes.hosts SET last_scan = now() - interval '4 days' WHERE name = 'laptop-2'")
        for i, name in enumerate(PEOPLE, 1):
            conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash, totp_secret) SELECT person_id, "
                         "%s, %s FROM pinakes.people WHERE name = %s",
                         (auth.hash_password("demo password %d" % i), DEMO_TOTP if name == "user-1" else None, name))
        n = conn.execute("SELECT count(*) FROM pinakes.files").fetchone()[0]
        e = conn.execute("SELECT count(*) FROM pinakes.lineage").fetchone()[0]
        p = conn.execute("SELECT count(*) FROM pinakes.people").fetchone()[0]
        gr = conn.execute("SELECT count(*) FROM pinakes.groups").fetchone()[0]
        return ("demo catalog %s: %d files, %d lineage edges; %d people (%s), %d group (household); user-1's "
                "second factor is DEMO_TOTP in tools/demo.py" % (db, n, e, p, ", ".join(PEOPLE), gr))
    finally:
        for _, _, _, st in machines.values():
            st.close()
        shutil.rmtree(tmp)
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pghost", required=True)
    ap.add_argument("--pguser", default="postgres")
    ap.add_argument("--db", default="pinakes_demo")
    a = ap.parse_args()
    print(build(a.pghost, a.pguser, a.db))


if __name__ == "__main__":
    main()
