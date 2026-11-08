#!/usr/bin/env python3
"""Build a small demo catalog from generated trees, for trying the CLI and the web UI.

  tools/demo.py --pghost SOCKET_DIR_OR_HOST [--pguser postgres] [--db pinakes_demo]

Needs a throwaway PostgreSQL where --pguser is a superuser. Creates the roles if missing, (re)creates the database,
scans generated trees on three pretend machines with real agents, ingests the batches, and sets the demo people's
passwords to `demo password 1` and `demo password 2` (placeholders: never use this on a real catalog).
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

SERVER = """
[ownership]
default_owner = "user-1"
[[ownership.rule]]
root = "store"
folder = "people/user-2"
owner = "user-2"
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
[hosts.server-1]
roots = ["store"]
[hosts.server-2]
roots = ["snapshots"]
[hosts.laptop-1]
roots = ["downloads"]
expected_every = "never"
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pghost", required=True)
    ap.add_argument("--pguser", default="postgres")
    ap.add_argument("--db", default="pinakes_demo")
    a = ap.parse_args()
    with psycopg.connect(host=a.pghost, user=a.pguser, dbname="postgres", autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % a.db)
        c.execute("CREATE DATABASE %s" % a.db)
        c.execute("DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pinakes_app') THEN "
                  "CREATE ROLE pinakes_app LOGIN; END IF; IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE "
                  "rolname = 'pinakes_ingest') THEN CREATE ROLE pinakes_ingest LOGIN BYPASSRLS; END IF; END$$")
    with psycopg.connect(host=a.pghost, user=a.pguser, dbname=a.db, autocommit=True) as c:
        apply_schema(c)
    conn = psycopg.connect(host=a.pghost, user="pinakes_ingest", dbname=a.db, autocommit=True)
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
        essay = os.urandom(60000)
        put("store", "people/user-1/writing/essay.odt", essay, 30)
        put("store", "people/user-1/finance/budget-2026.ods", b"budget numbers", 20)
        photos = [os.urandom(3000) for _ in range(4)]
        for i, data in enumerate(photos):
            put("store", "people/user-1/trip-photos/IMG_%04d.JPG" % i, data, 25)
        put("store", "people/user-2/recipes/bread.txt", b"flour, water, salt", 15)
        put("store", "media/music/album/01 track.flac", os.urandom(8000), 60)
        scan("store")
        put("snapshots", "2026-01-10_0140/people/user-1/writing/essay.odt", essay, 30)
        put("snapshots", "2026-01-10_0140/people/user-2/recipes/bread.txt", b"flour, water, salt", 15)
        put("snapshots", "2026-01-10_0140/people/user-1/trip-photos/IMG_0001.JPG", photos[1], 25)
        scan("snapshots")
        # the essay goes to the laptop, gets worked on, and comes back; photos are dropped there too
        put("downloads", "essay.odt", essay, 5)
        put("downloads", "camera-import/IMG_0100.JPG", os.urandom(3000), 3)
        put("downloads", "camera-import/IMG_0001.JPG", b"", 3)
        put("downloads", "trip/IMG_0003.JPG", photos[3], 3)          # moved off the server by hand, below
        scan("downloads")
        edited = essay[:30000] + b"a new paragraph" + essay[30000:]
        put("downloads", "essay.odt", edited, 2)
        put("downloads", "essay - new.odt", edited + b" and more", 1)
        scan("downloads")
        put("store", "people/user-1/writing/essay.odt", edited, 1)
        os.makedirs(os.path.join(machines["store"][1], "people/user-1/archive"), exist_ok=True)
        os.rename(os.path.join(machines["store"][1], "people/user-1/finance/budget-2026.ods"),
                  os.path.join(machines["store"][1], "people/user-1/archive/budget-2026.ods"))
        # a clean-up to review (ROADMAP 32): one photo gone with a backup, one moved to the laptop, one with no copy
        for i in (1, 2, 3):
            os.remove(os.path.join(machines["store"][1], "people/user-1/trip-photos/IMG_%04d.JPG" % i))
        scan("store")
        for name, pw in (("user-1", "demo password 1"), ("user-2", "demo password 2")):
            conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) SELECT person_id, %s "
                         "FROM pinakes.people WHERE name = %s", (auth.hash_password(pw), name))
        n = conn.execute("SELECT count(*) FROM pinakes.files").fetchone()[0]
        e = conn.execute("SELECT count(*) FROM pinakes.lineage").fetchone()[0]
        print("demo catalog %s: %d files, %d lineage edges; people user-1 and user-2" % (a.db, n, e))
    finally:
        for _, _, _, st in machines.values():
            st.close()
        shutil.rmtree(tmp)
        conn.close()


if __name__ == "__main__":
    main()
