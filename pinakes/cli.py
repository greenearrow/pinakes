"""pinakes: query the catalog from a shell, as one person, under the same row-level security as the web UI.

  pinakes [--config FILE] --as NAME find NAME-OR-GLOB
  pinakes ... where ROOT:PATH          every copy and backup of the file at that path
  pinakes ... only-here ROOT:PATH      files under PATH with no copy on another disk
  pinakes ... safe-to-delete ROOT:PATH files under PATH with no kept copy on another disk (none: safe), and the
                                     symlinks elsewhere that lead into it
  pinakes ... backed-up ROOT:PATH
  pinakes ... dupes
  pinakes ... history ROOT:PATH
  pinakes ... versions ROOT:PATH
  pinakes ... lineage ROOT:PATH [--down]
  pinakes ... changes [--days N] [--host NAME]
  pinakes ... meta SCHEMA.FIELD=VALUE
  pinakes ... stale
  pinakes ... roots                    every root you can see: host, kind, files, last complete scan
  pinakes --backups [FOLDER]           from inside a scanned folder (or FOLDER): where its files are backed up,
                                     the least-backed-up first. The folder's root is found from this machine's
                                     name (--host, or [agent] host in agent.toml, else its hostname).
  --as defaults to $PINAKES_PERSON, then your login name.
  Add --json for JSON. The CLI never steps up: it shows only what NAME may see.
"""

import argparse
import datetime
import getpass
import json
import os
import socket
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


def _this_host(given):
    """This machine's name in the catalog: --host, else [agent] host of the agent config here, else its hostname."""
    if given:
        return given
    from . import config as agent_config
    for path in (os.environ.get("PINAKES_AGENT_CONFIG"), os.path.expanduser("~/.config/pinakes/agent.toml"),
                 "/etc/pinakes/agent.toml"):
        if path and os.path.exists(path):
            try:
                return agent_config.load(path).host
            except (OSError, ValueError):
                pass
    return socket.gethostname().split(".")[0]


def here(conn, host, folder):
    """ROOT:PATH of a local folder: the deepest root this host reports that holds it. Raises ValueError if none."""
    real = os.path.realpath(folder)
    best = None
    for r in queries.roots_of_host(conn, host):
        base = os.path.realpath(r["path"])
        if real == base or real.startswith(base.rstrip("/") + "/"):
            if best is None or len(base) > len(best[0]):
                best = (base, r)
    if not best:
        raise ValueError("%s is not inside a root that %s reports; `pinakes roots` lists them" % (real, host))
    base, r = best
    rel = os.path.relpath(real, base)
    return r, "" if rel == "." else rel.replace(os.sep, "/")


SHOW = 50


def backups_here(conn, host, folder, as_json):
    root, rel = here(conn, host, folder)
    loc = "%s:%s" % (root["label"], rel)
    if root["kind"] == "backup":
        raise ValueError("%s is itself a backup root; run this in the folder the backup is of" % loc)
    rows = queries.backed_up(conn, loc, SHOW, 0, sort="copies", direction="asc")
    total = rows[0]["total_rows"] if rows else 0
    if as_json:
        print(json.dumps({"folder": loc, "files": total, "shown": rows}, default=_default, indent=1))
        return
    unbacked = conn.execute("""SELECT count(*) FROM (SELECT 1 FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                               LEFT JOIN pinakes.present b ON b.backup_of = f.file_id AND b.content_id = f.content_id
                               WHERE r.label = %s AND f.relpath LIKE %s GROUP BY f.file_id
                               HAVING count(b.file_id) = 0) x""", (root["label"], queries._prefix(rel))).fetchone()[0]
    print("%s%s %d file(s) you can see, %d with no backup" % (loc, ":" if rel else "", total, unbacked))
    if rows:
        _print(rows, False, ["relpath", "backup_copies", "snapshots", "newest"])
        if total > len(rows):
            print("... and %d more (fewest backups first)" % (total - len(rows)))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes", description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--config", default=os.environ.get("PINAKES_CONFIG", "/etc/pinakes/server.toml"))
    ap.add_argument("--as", dest="person", default=os.environ.get("PINAKES_PERSON") or getpass.getuser(),
                    help="the person whose view to use (default: $PINAKES_PERSON, then your login name)")
    ap.add_argument("--backups", action="store_true", help="where the files of this folder are backed up")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("cmd", nargs="?")
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--down", action="store_true")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--host")
    a = ap.parse_args(argv)
    if a.backups:
        if a.arg or (a.cmd and not os.path.isdir(a.cmd)):
            ap.error("--backups takes one folder, or none for the current one")
    elif not a.cmd:
        ap.error("a command is needed (or --backups)")
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
            if a.backups:
                backups_here(conn, _this_host(a.host), a.cmd or ".", a.json)
                return 0
            if a.cmd == "find":
                rows = queries.find(conn, need("a name or glob"))
            elif a.cmd == "where":
                rows = queries.where(conn, target())
            elif a.cmd == "only-here":
                rows = queries.only_here(conn, need())
            elif a.cmd == "safe-to-delete":
                rows = queries.not_safe_to_delete(conn, need())
                links = queries.links_into(conn, a.arg)
                if a.json:
                    print(json.dumps({"not_safe": rows, "links_into": links}, default=_default, indent=1))
                    return 0
                if not rows:
                    print("safe: every file under %s has a kept copy on another disk" % a.arg)
                else:
                    _print(rows, False)
                if links:
                    print("\n%d symlink(s) elsewhere lead into %s and would be left dangling:" % (len(links), a.arg))
                    _print([{"link": "%s:%s" % (l["root"], l["relpath"]), "target": l["link_target"]}
                            for l in links], False)
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
            elif a.cmd == "roots":
                rows = queries.roots(conn)
            else:
                ap.error("unknown command %r" % a.cmd)
        except ValueError as e:
            sys.exit("pinakes: %s" % e)
        _print(rows, a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
