"""pinakes: query the catalog from a shell, as one person, under the same row-level security as the web UI.

  pinakes [--config FILE] --as NAME find NAME-OR-GLOB
  pinakes ... where ROOT:PATH          every copy and backup of the file at that path
  pinakes ... only-here ROOT:PATH      files under PATH with no copy anywhere else
  pinakes ... safe-to-delete ROOT:PATH files under PATH with no kept copy elsewhere (none: safe)
  pinakes ... backed-up ROOT:PATH
  pinakes ... dupes
  pinakes ... history ROOT:PATH
  pinakes ... versions ROOT:PATH
  pinakes ... lineage ROOT:PATH [--down]
  pinakes ... changes [--days N] [--host NAME]
  pinakes ... meta SCHEMA.FIELD=VALUE
  pinakes ... stale
  Add --json for JSON. The CLI never steps up: it shows only what NAME may see.
"""

import argparse
import datetime
import json
import os
import sys

import psycopg

from . import queries
from .server_config import load as load_server_config


def _connect(cfg):
    web = cfg.web
    kw = {"conninfo": web.get("dsn", "")}
    pw = web.get("password_file")
    if pw and os.path.exists(pw):
        with open(pw) as f:
            kw["password"] = f.read().strip()
    return psycopg.connect(**kw)


def _default(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    if isinstance(o, datetime.timedelta):
        return str(o)
    if isinstance(o, (bytes, memoryview)):
        return bytes(o).hex()
    return str(o)


def _print(rows, as_json, cols=None):
    if as_json:
        print(json.dumps(rows, default=_default, indent=1))
        return
    if not rows:
        print("(none)")
        return
    cols = cols or [c for c in rows[0] if c not in ("file_id", "content_id")]
    widths = {c: min(60, max(len(c), *(len(_cell(r.get(c))) for r in rows))) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(_cell(r.get(c))[:60].ljust(widths[c]) for c in cols))


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, datetime.datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return str(v)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes", description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--config", default=os.environ.get("PINAKES_CONFIG", "/etc/pinakes/server.toml"))
    ap.add_argument("--as", dest="person", required=True, help="the person whose view to use")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("cmd")
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--down", action="store_true")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--host")
    a = ap.parse_args(argv)
    cfg = load_server_config(a.config)
    with _connect(cfg) as conn:
        pid = conn.execute("SELECT person_id FROM pinakes.people WHERE name = %s", (a.person,)).fetchone()
        if not pid:
            sys.exit("pinakes: no person %r" % a.person)
        conn.execute("SELECT set_config('pinakes.person', %s, false), set_config('pinakes.session', 'cli', false)",
                     (str(pid[0]),))

        def need(what="ROOT:PATH"):
            if not a.arg:
                sys.exit("pinakes %s needs %s" % (a.cmd, what))
            return a.arg

        def target():
            f = queries.file_at(conn, need())
            if not f:
                sys.exit("pinakes: no file you can see at %s" % a.arg)
            return f["file_id"]

        try:
            if a.cmd == "find":
                rows = queries.find(conn, need("a name or glob"))
            elif a.cmd == "where":
                rows = queries.where(conn, target())
            elif a.cmd == "only-here":
                rows = queries.only_here(conn, need())
            elif a.cmd == "safe-to-delete":
                rows = queries.not_safe_to_delete(conn, need())
                if not rows and not a.json:
                    print("safe: every file under %s has a kept copy elsewhere" % a.arg)
                    return 0
            elif a.cmd == "backed-up":
                rows = queries.backed_up(conn, need())
            elif a.cmd == "dupes":
                rows = queries.dupes(conn)
            elif a.cmd == "history":
                rows = queries.history(conn, target())
            elif a.cmd == "versions":
                rows = queries.versions(conn, target())
            elif a.cmd == "lineage":
                rows = queries.lineage(conn, target(), "down" if a.down else "up")
            elif a.cmd == "changes":
                rows = queries.changes(conn, a.days, a.host)
            elif a.cmd == "meta":
                spec = need("SCHEMA.FIELD=VALUE")
                key, value = spec.split("=", 1)
                schema, field = key.split(".", 1)
                rows = queries.meta(conn, schema, field, value)
            elif a.cmd == "stale":
                rows = queries.stale(conn)
            else:
                ap.error("unknown command %r" % a.cmd)
        except ValueError as e:
            sys.exit("pinakes: %s" % e)
        _print(rows, a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
