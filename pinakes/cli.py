"""pinakes: ask the catalog from a shell on any machine, through its API, as the person whose token it holds.

  pinakes                              inside a scanned folder: its files, backups, copies and changes in numbers
  pinakes find NAME-OR-GLOB
  pinakes where FILE                   every copy and backup of the file
  pinakes only-here [PATH]             files under the folder (or the file) with no copy on another disk
  pinakes safe-to-delete [PATH]        files under it with no kept copy on another disk (none: safe), and the
                                       symlinks elsewhere that lead into it
  pinakes backed-up [PATH]
  pinakes dupes
  pinakes history FILE
  pinakes versions FILE
  pinakes lineage FILE [--down]
  pinakes changes [FOLDER] [--days N] [--host NAME]   no folder, outside every root: everything you can see
  pinakes meta SCHEMA.FIELD=VALUE
  pinakes stale
  pinakes roots                        every root you can see: host, kind, files, last complete scan
  pinakes backups [FOLDER]             where the folder's files are backed up, the least-backed-up first
  pinakes --versions [--config FILE]   on the catalog server only: this server's release and protocol, whether its
                                       schema is applied, and each agent's last check-in (release, protocol, locked
                                       or not, newest batch, refusals, the last time its batch numbering went back).
                                       It reads server.toml and the database and needs no person or token.
  Add --json for JSON.

FILE, FOLDER and PATH are a path here (none: the current folder) or ROOT:PATH; a path that exists here is taken
as one.
A path here is found among the roots this machine reports, by its name in the catalog: --host (except for
changes, where it filters), else [client] host, else [agent] host in agent.toml, else its hostname.

The catalog's address is [client] url in ~/.config/pinakes/client.toml (or $PINAKES_CLIENT_CONFIG, or
/etc/pinakes/client.toml), or --url; https, or http to this machine only; [client] ca_file for a site's own CA.
The token is the first of: a .pinakes-token file in the current folder or one above it, ~/.config/pinakes/token.
Make one on the web UI's account page; a token file must be yours and readable by you alone (chmod 600). The CLI
shows only what that person may see, and never steps up.
"""

import argparse
import datetime
import json
import os
import socket
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

from . import compat
from .config import tomllib

CLIENT_CONFIGS = ("~/.config/pinakes/client.toml", "/etc/pinakes/client.toml")
HOME_TOKEN = "~/.config/pinakes/token"
FOLDER_TOKEN = ".pinakes-token"
LOCAL = ("localhost", "127.0.0.1", "::1")
SHOW = 50
TIMEOUT = 60


class Failed(Exception):
    """Something the person must fix or know: printed as `pinakes: ...`, exit 1."""


class NotInRoot(Failed):
    """A local path outside every root this machine reports."""


# where to ask, and as whom ---------------------------------------------------------------------------------------
def client_config(path=None):
    """[client] of the first client config found (url, ca_file, host), or {}."""
    paths = [path] if path else [os.environ.get("PINAKES_CLIENT_CONFIG")] + list(CLIENT_CONFIGS)
    for p in paths:
        if p and os.path.exists(os.path.expanduser(p)):
            with open(os.path.expanduser(p), "rb") as f:
                try:
                    return tomllib.load(f).get("client", {})
                except ValueError as e:
                    raise Failed("%s: %s" % (p, e))
    return {}


def token_files(start=None):
    """Where a token may be, in the order tried: .pinakes-token in the folder and each folder above it, then the
    home token."""
    d = os.path.abspath(start or os.getcwd())
    while True:
        yield os.path.join(d, FOLDER_TOKEN)
        up = os.path.dirname(d)
        if up == d:
            break
        d = up
    yield os.path.expanduser(HOME_TOKEN)


def find_token(start=None):
    """(the token, its file): the first token file there is. One that isn't a plain file of this user's, readable
    by them alone, is refused, not skipped: a token anyone else can read is no longer only theirs."""
    for path in token_files(start):
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        except OSError as e:
            raise Failed("%s: %s" % (path, e.strerror))
        if not stat.S_ISREG(st.st_mode):
            raise Failed("%s is not a file" % path)
        if st.st_uid != os.getuid():
            raise Failed("%s is not yours: a token file must belong to you" % path)
        if st.st_mode & 0o077:
            raise Failed("%s can be read by others: chmod 600 it, and revoke the token if anyone could have copied "
                         "it" % path)
        with open(path) as f:
            token = f.readline().strip()
        if not token:
            raise Failed("%s is empty" % path)
        return token, path
    raise Failed("no token: make one on the account page of the web UI and save it as %s (chmod 600), or as "
                 "%s in a folder above this one" % (HOME_TOKEN, FOLDER_TOKEN))


class Api:
    """The catalog's API, at its url, with a token."""

    def __init__(self, url, token, ca_file=None):
        u = urllib.parse.urlsplit(url or "")
        if u.scheme not in ("https", "http") or not u.hostname:
            raise Failed("no catalog address: set [client] url in %s, or give --url" % CLIENT_CONFIGS[0])
        if u.scheme == "http" and u.hostname not in LOCAL:
            raise Failed("%s: the token would cross the network unencrypted; use https" % url)
        self.base = url.rstrip("/") + "/api/v1/"
        self.token = token
        self.context = ssl.create_default_context(cafile=ca_file) if u.scheme == "https" else None

    def get(self, call, **args):
        q = urllib.parse.urlencode({k: v for k, v in args.items() if v is not None and v is not False})
        req = urllib.request.Request(self.base + call + ("?" + q if q else ""),
                                     headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self.context) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            try:
                msg = json.load(e).get("error") or e.reason
            except ValueError:
                msg = e.reason
            if e.code == 401:
                msg += "; the token may be revoked or expired: make a new one on the account page"
            raise Failed(msg)
        except urllib.error.URLError as e:
            raise Failed("can't reach the catalog at %s: %s" % (self.base, e.reason))
        except (OSError, ValueError) as e:
            raise Failed("the catalog at %s answered badly: %s" % (self.base, e))


# printing --------------------------------------------------------------------------------------------------------
def _print(rows, as_json, cols=None):
    if as_json:
        print(json.dumps(rows, indent=1))
        return
    if not rows:
        print("(none)")
        return
    cols = cols or [c for c in rows[0] if c not in ("file_id", "content_id", "total_rows")]
    widths = {c: min(60, max(len(c), *(len(_cell(r.get(c))) for r in rows))) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(_cell(r.get(c))[:60].ljust(widths[c]) for c in cols))


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, datetime.datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, str) and len(v) >= 19 and v[10] == "T":
        try:                                    # a time from the API (ISO 8601): in this machine's time zone
            return datetime.datetime.fromisoformat(v).astimezone().strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return v
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return str(v)


# a folder here -----------------------------------------------------------------------------------------------------
def _this_host(given, cfg):
    """This machine's name in the catalog: --host, else [client] host, else [agent] host of the agent config here,
    else its hostname."""
    if given:
        return given
    if cfg.get("host"):
        return cfg["host"]
    from . import config as agent_config
    for path in (os.environ.get("PINAKES_AGENT_CONFIG"), os.path.expanduser("~/.config/pinakes/agent.toml"),
                 "/etc/pinakes/agent.toml"):
        if path and os.path.exists(path):
            try:
                return agent_config.load(path).host
            except (OSError, ValueError):
                pass
    return socket.gethostname().split(".")[0]


def here(api, host, local):
    """(root, path in it) of a local folder or file: the deepest root this host reports that holds it. A file's own
    name is kept as it is (a symlink is itself, not its target); its folders are resolved. NotInRoot if none."""
    if os.path.isdir(local) and not os.path.islink(local):
        real = os.path.realpath(local)
    else:
        real = os.path.join(os.path.realpath(os.path.dirname(os.path.abspath(local))), os.path.basename(local))
    best = None
    for r in api.get("host-roots", host=host)["rows"]:
        base = os.path.realpath(r["path"])
        if real == base or real.startswith(base.rstrip("/") + "/"):
            if best is None or len(base) > len(best[0]):
                best = (base, r)
    if not best:
        raise NotInRoot("%s is not inside a root that %s reports; `pinakes roots` lists them" % (real, host))
    base, r = best
    rel = os.path.relpath(real, base)
    return r, "" if rel == "." else rel.replace(os.sep, "/")


def backups_here(api, host, folder, as_json):
    root, rel = here(api, host, folder)
    loc = "%s:%s" % (root["label"], rel)
    if root["kind"] == "backup":
        raise Failed("%s is itself a backup root; run this in the folder the backup is of" % loc)
    got = api.get("backups", loc=loc, show=SHOW)
    if as_json:
        print(json.dumps({"folder": got["folder"], "files": got["files"], "shown": got["shown"]}, indent=1))
        return
    print("%s%s %d file(s) you can see, %d with no backup" % (loc, ":" if rel else "", got["files"], got["unbacked"]))
    if got["shown"]:
        _print(got["shown"], False, ["relpath", "backup_copies", "snapshots", "newest"])
        if got["files"] > len(got["shown"]):
            print("... and %d more (fewest backups first)" % (got["files"] - len(got["shown"])))


# the server's own report -----------------------------------------------------------------------------------------
def versions(config, as_json):
    """On the catalog server, from server.toml and the database: no person, no token (ROADMAP 39 moves it to the
    API with an ops token)."""
    import psycopg
    from . import queries
    from .ingest import schema_missing
    from .server_config import load as load_server_config
    web = load_server_config(config).web
    kw = {"conninfo": web.get("dsn", "")}
    pw = web.get("password_file")
    if pw and os.path.exists(pw):
        with open(pw) as f:
            kw["password"] = f.read().strip()
    with psycopg.connect(**kw) as conn:
        # hosts, check-ins and batch times only (no row-level security, nothing about a person or file)
        missing = schema_missing(conn)
        agents = queries.agent_versions(conn) if "checkins.sql" not in missing and "schema.sql" not in missing else []
    server = {"release": compat.RELEASE, "protocol": compat.PROTOCOL, "min_agent_protocol": compat.MIN_AGENT_PROTOCOL,
              "schema_applied": not missing, "upgrades_missing": missing}
    if as_json:
        print(json.dumps({"server": server, "agents": agents}, default=queries.json_default, indent=1))
        return
    print("server: release %d, protocol %d, accepts agents of protocol %d or later; schema %s" % (
        compat.RELEASE, compat.PROTOCOL, compat.MIN_AGENT_PROTOCOL,
        "applied" if not missing else "lacks " + ", ".join(missing)))
    for a in agents:
        if a["checked_in"] is None:
            a["state"] = "no check-in" if a["newest_batch"] else "never heard from"
        else:
            a["state"] = "LOCKED" if a["locked"] else "sending"
        if a["refused_at"] and (a["newest_batch"] is None or a["refused_at"] > a["newest_batch"]):
            a["state"] = "REFUSED"                  # its batches are held: the reason is below
    _print(agents, False, ["host", "checked_in", "release", "protocol", "min_server", "state", "newest_batch",
                           "batch_protocol"])
    for a in agents:
        if a["locked"]:
            print("%s: locked at its last check-in: %s" % (a["host"], a["locked"]))
        if a["refused"]:
            print("%s: last refused %s: %s" % (a["host"], _cell(a["refused_at"]), a["refused"]))
        if a["seq_reset"]:
            print("%s: numbering went back %s: %s" % (a["host"], _cell(a["seq_reset_at"]), a["seq_reset"]))


# commands ----------------------------------------------------------------------------------------------------------
FILE = ("where", "history", "versions", "lineage")                  # take one file
FOLDER = ("only-here", "safe-to-delete", "backed-up")               # take a folder, or a file for itself
COMMANDS = ("find",) + FILE + FOLDER + ("dupes", "changes", "meta", "stale", "roots", "backups")


def location(api, cmd, given, host, want):
    """ROOT:PATH for a command's argument. A path that exists here, or none (the current folder), is found among
    the roots this machine (host) reports; anything else is taken as ROOT:PATH. want is "file", "folder" or
    "any"."""
    if given is None or os.path.lexists(given):
        path = given or "."
        is_folder = os.path.isdir(path) and not os.path.islink(path)
        if want == "file" and is_folder:
            raise Failed("pinakes %s needs a file; %s is a folder" % (cmd, path))
        if want == "folder" and not is_folder:
            raise Failed("pinakes %s needs a folder; %s is a file: `pinakes history` shows its changes" % (cmd, path))
        root, rel = here(api, host, path)
        return "%s:%s" % (root["label"], rel)
    if ":" not in given:
        raise Failed("%s is neither a path here nor ROOT:PATH" % given)
    return given


def count(got):
    return got["rows"][0]["total_rows"] if got["rows"] else 0


def summary(api, cfg, days=7, host=None):
    """Bare `pinakes` inside a root: the current folder in a few numbers."""
    root, rel = here(api, _this_host(host, cfg), ".")
    loc = "%s:%s" % (root["label"], rel)
    b = api.get("backups", loc=loc, show=1)
    line = "%s: %d file(s) you can see" % (loc, b["files"])
    if root["kind"] != "backup":
        line += ", %d with no backup, %d with no copy on another disk" % (
            b["unbacked"], count(api.get("only-here", loc=loc, limit=1)))
    print(line + ", %d change(s) in the last %d days" % (count(api.get("changes", loc=loc, days=days, limit=1)), days))
    print("(pinakes --help for the commands)")


def run(api, a, cfg):
    def need(what):
        if not a.arg:
            raise Failed("pinakes %s needs %s" % (a.cmd, what))
        return a.arg

    def loc(want):
        return location(api, a.cmd, a.arg, _this_host(a.host, cfg), want)

    if a.cmd == "backups":
        if a.arg and not os.path.isdir(a.arg):
            raise Failed("%s is not a folder here" % a.arg)
        backups_here(api, _this_host(a.host, cfg), a.arg or ".", a.json)
        return
    if a.cmd == "safe-to-delete":
        where = loc("any")
        got = api.get("safe-to-delete", loc=where)
        if a.json:
            print(json.dumps(got, indent=1))
            return
        if not got["not_safe"]:
            print("safe: every file under %s has a kept copy on another disk" % where)
        else:
            _print(got["not_safe"], False)
        links = got["links_into"]
        if links:
            print("\n%d symlink(s) elsewhere lead into %s and would be left dangling:" % (len(links), where))
            _print([{"link": "%s:%s" % (l["root"], l["relpath"]), "target": l["link_target"]} for l in links], False)
        return
    if a.cmd == "find":
        got = api.get("find", q=need("a name or glob"))
    elif a.cmd in FILE:
        got = api.get(a.cmd, loc=loc("file"), down=1 if a.cmd == "lineage" and a.down else None)
    elif a.cmd in FOLDER:
        got = api.get(a.cmd, loc=loc("any"))
    elif a.cmd == "changes":
        # --host is a filter here, not this machine's name; no folder outside every root: everything
        try:
            where = location(api, a.cmd, a.arg, _this_host(None, cfg), "folder")
        except NotInRoot:
            if a.arg:
                raise
            where = None
        got = api.get("changes", days=a.days, host=a.host, loc=where)
        if not a.json:
            print("changes %s in the last %d days%s:" % ("under " + where if where else "everywhere you can see",
                                                         a.days, ", on " + a.host if a.host else ""))
    elif a.cmd == "meta":
        key, eq, value = need("SCHEMA.FIELD=VALUE").partition("=")
        if not eq:
            raise Failed("pinakes meta needs SCHEMA.FIELD=VALUE")
        got = api.get("meta", field=key, value=value)
    else:                                                               # dupes, stale, roots
        got = api.get(a.cmd)
    _print(got["rows"], a.json)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes", description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("cmd", nargs="?", metavar="COMMAND", choices=COMMANDS)
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--down", action="store_true", help="lineage: what came from the file, not where it came from")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--host", help="changes: only this host's; backups: this machine's name in the catalog")
    ap.add_argument("--url", help="the catalog's address (default: [client] url)")
    ap.add_argument("--versions", action="store_true", help="on the catalog server: releases and protocols of the "
                                                           "server and each agent")
    ap.add_argument("--config", default=os.environ.get("PINAKES_CONFIG", "/etc/pinakes/server.toml"),
                    help="--versions: the server's config")
    a = ap.parse_intermixed_args(argv)          # options before or after the command and its argument
    try:
        if a.versions:
            if a.cmd:
                ap.error("--versions takes no command")
            versions(a.config, a.json)
            return 0
        cfg = client_config()
        if not a.cmd:
            try:
                summary(Api(a.url or cfg.get("url"), find_token()[0], cfg.get("ca_file")), cfg, a.days, a.host)
            except Failed as e:                 # outside a root, or not set up yet: how to use it, and why
                ap.print_usage()
                sys.exit("pinakes: %s" % e)
            return 0
        token, _ = find_token()
        run(Api(a.url or cfg.get("url"), token, cfg.get("ca_file")), a, cfg)
    except Failed as e:
        sys.exit("pinakes: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
