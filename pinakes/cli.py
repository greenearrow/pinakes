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
  pinakes changes [PATH] [--days N] [--host NAME]   no path, outside every root: everything you can see
  pinakes review intended|restore [PATH] [--days N] [--yes]   mark the unreviewed gone files and moves under PATH
                                       (or of that file) reviewed, as on the web's Changes page: shown, then marked
                                       once you say yes. Only your own or co-owned; the token needs the review scope
  pinakes meta SCHEMA.FIELD=VALUE
  pinakes stale
  pinakes roots                        every root you can see: host, kind, files, last complete scan
  pinakes backups [FOLDER]             where the folder's files are backed up, the least-backed-up first
  pinakes releases                     this server's release and protocol, whether its schema is applied, and each
                                       agent's last check-in (release, protocol, locked or not, newest batch,
                                       refusals, the last time its batch numbering went back). It needs an ops
                                       token, which an operator makes on the account page, and sees nothing else
                                       but `stale`; on the catalog server, [client] url can be http://127.0.0.1.
  Add --json for JSON, --as NAME to ask as another person (their password and second factor, or a token of theirs,
  at a hidden prompt; the command then sees only what they may see).

FILE, FOLDER and PATH are a path here (none: the current folder) or ROOT:PATH; a path that exists here is taken
as one.
A path here is found among the roots this machine reports, by its name in the catalog: --host (except for
changes, where it filters), else [client] host, else [agent] host in agent.toml, else its hostname.

The catalog's address is [client] url in ~/.config/pinakes/client.toml (or $PINAKES_CLIENT_CONFIG, or
/etc/pinakes/client.toml), or --url; https, or http to this machine only; [client] ca_file for a site's own CA.
The token is the first of: a .pinakes-token file in the current folder or one above it, ~/.config/pinakes/token.
Make one on the web UI's account page; a token file must be yours and readable by you alone (chmod 600). The CLI
shows only what that person (or, with a group token, that group) may see, and never steps up.
"""

import argparse
import datetime
import getpass
import json
import os
import socket
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

from .config import tomllib

CLIENT_CONFIGS = ("~/.config/pinakes/client.toml", "/etc/pinakes/client.toml")
HOME_TOKEN = "~/.config/pinakes/token"
FOLDER_TOKEN = ".pinakes-token"
TOKEN_PREFIX = "pinakes_"               # what the web UI's tokens begin with (web.TOKEN_PREFIX)
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
        q = urllib.parse.urlencode({k: v for k, v in args.items() if v is not None and v is not False}, doseq=True)
        return self._ask(urllib.request.Request(self.base + call + ("?" + q if q else ""), headers=self._headers()))

    def post(self, call, body=None):
        return self._ask(urllib.request.Request(self.base + call, data=json.dumps(body or {}).encode(), method="POST",
                                                headers=dict(self._headers(), **{"Content-Type": "application/json"})))

    def _headers(self):
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        return h

    def _ask(self, req):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self.context) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            try:
                msg = json.load(e).get("error") or e.reason
            except ValueError:
                msg = e.reason
            if e.code == 401 and self.token:
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


# the server's own report ----------------------------------------------------------------------------------------
def releases(api, as_json):
    """pinakes releases: the server's release, protocol and schema, and each agent's last check-in, through the API
    with an ops token (ROADMAP 39; before it, pinakes --versions read the database on the server)."""
    got = api.get("releases")
    server, agents = got["server"], got["agents"]
    if as_json:
        print(json.dumps(got, indent=1))
        return
    print("server: release %d, protocol %d, accepts agents of protocol %d or later; schema %s" % (
        server["release"], server["protocol"], server["min_agent_protocol"],
        "applied" if server["schema_applied"] else "lacks " + ", ".join(server["upgrades_missing"])))
    for a in agents:
        if a["checked_in"] is None:
            a["state"] = "no check-in" if a["newest_batch"] else "never heard from"
        else:
            a["state"] = "LOCKED" if a["locked"] else "sending"
        if a["refused_at"] and (a["newest_batch"] is None or _when(a["refused_at"]) > _when(a["newest_batch"])):
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


def _when(iso):
    return datetime.datetime.fromisoformat(iso)


# commands ----------------------------------------------------------------------------------------------------------
FILE = ("where", "history", "versions", "lineage")                  # take one file
FOLDER = ("only-here", "safe-to-delete", "backed-up")               # take a folder, or a file for itself
COMMANDS = ("find",) + FILE + FOLDER + ("dupes", "changes", "meta", "stale", "roots", "backups", "review",
                                         "releases")
MARKS = ("intended", "restore")
REVIEWABLE = ("gone", "moved", "moved_changed", "mismatch", "unreadable")   # what a review marks (queries.REVIEWABLE)


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

    if a.cmd == "review":
        review(api, a, cfg)
        return
    if a.cmd == "releases":
        releases(api, a.json)
        return
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
            where = location(api, a.cmd, a.arg, _this_host(None, cfg), "any")
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


def review(api, a, cfg):
    """pinakes review intended|restore [PATH]: the unreviewed gone files, moves and scrub findings under PATH (or of
    that file) in the last --days, shown, then marked once confirmed (or with --yes). The catalog marks only what the
    person owns or co-owns, in the token's roots and with its review scope, and says how many."""
    if a.arg not in MARKS:
        raise Failed("pinakes review needs intended or restore, then a path (none: the current folder)")
    where = location(api, "review", a.path, _this_host(a.host, cfg), "any")
    rows = api.get("changes", loc=where, days=a.days, review="unreviewed", what=list(REVIEWABLE))["rows"]
    if not rows:
        print("nothing to review under %s in the last %d days" % (where, a.days))
        return
    if not a.json:
        print("%d unreviewed change(s) (gone, moved, or found by the scrub) under %s in the last %d days:"
              % (len(rows), where, a.days))
        _print(rows, False, ["seen_on", "root", "path", "old_relpath", "kind"])
    if not a.yes:
        if not sys.stdin.isatty():
            raise Failed("not marked: add --yes to mark them without being asked")
        if input("Mark these %d as %s? [y/N] " % (len(rows), a.arg)).strip().lower() not in ("y", "yes"):
            print("not marked")
            return
    got = api.post("review", {"mark": a.arg, "ids": [r["history_id"] for r in rows]})
    if a.json:
        print(json.dumps(dict(got, changes=rows), indent=1))
        return
    print("marked %d of %d as %s" % (got["marked"], got["asked"], a.arg))
    if got["marked"] < got["asked"]:
        print("the rest are not yours or co-owned to mark (readers can't), or outside this token's roots")


def open_api(a, cfg):
    """(the API, whether it is a --as session to end). Without --as, the token found here. With --as NAME, only
    what NAME's secret opens, asked for at a hidden prompt and never written down: a token of theirs, checked to be
    theirs, or their password (and second factor) for a session of minutes. The caller's own token isn't read: the
    command sees exactly NAME's view, never the two added up."""
    url, ca = a.url or cfg.get("url"), cfg.get("ca_file")
    if not a.person:
        return Api(url, find_token()[0], ca), False
    Api(url, None, ca)                          # the address checked before a secret is asked for
    secret = getpass.getpass("%s's password, or a token of theirs: " % a.person).strip()
    if secret.startswith(TOKEN_PREFIX):
        api = Api(url, secret, ca)
        if api.get("whoami")["person"] != a.person:
            raise Failed("that token is not %s's" % a.person)
        return api, False
    code = getpass.getpass("%s's second-factor code (empty if they have none): " % a.person).strip()
    got = Api(url, None, ca).post("session", {"name": a.person, "password": secret, "code": code})
    return Api(url, got["token"], ca), True


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes", description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("cmd", nargs="?", metavar="COMMAND", choices=COMMANDS)
    ap.add_argument("arg", nargs="?")
    ap.add_argument("path", nargs="?", help=argparse.SUPPRESS)          # review MARK PATH
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--down", action="store_true", help="lineage: what came from the file, not where it came from")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--host", help="changes: only this host's; backups: this machine's name in the catalog")
    ap.add_argument("--yes", action="store_true", help="review: mark without asking")
    ap.add_argument("--url", help="the catalog's address (default: [client] url)")
    ap.add_argument("--as", dest="person", metavar="NAME",
                    help="as this person: asks for their password (and second factor) or a token of theirs")
    ap.add_argument("--versions", action="store_true", help=argparse.SUPPRESS)      # before ROADMAP 39
    ap.add_argument("--config", help=argparse.SUPPRESS)
    a = ap.parse_intermixed_args(argv)          # options before or after the command and its argument
    if a.path and a.cmd != "review":
        ap.error("pinakes %s takes one argument" % a.cmd)
    try:
        if a.versions:
            raise Failed("--versions is now `pinakes releases`, through the API with an ops token (made by an "
                         "operator on the account page)")
        cfg = client_config()
        try:
            api, session = open_api(a, cfg)
        except Failed:
            if a.cmd:
                raise
            ap.print_usage()                    # bare pinakes, not set up yet: how to use it, and why
            raise
        try:
            if a.cmd:
                run(api, a, cfg)
            else:
                try:
                    summary(api, cfg, a.days, a.host)
                except NotInRoot:               # outside a root: how to use it, and why
                    ap.print_usage()
                    raise
        finally:
            if session:
                try:
                    api.post("session/end")
                except Failed:
                    pass                        # it ends by itself in minutes
    except Failed as e:
        sys.exit("pinakes: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
