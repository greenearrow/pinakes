"""pinakes: ask the catalog from a shell on any machine, through its API, as the person whose token it holds.

  pinakes                              inside a scanned folder: its files, backups, copies and changes in numbers
  pinakes find NAME-OR-GLOB
  pinakes where FILE                   every copy and backup of the file
  pinakes only-here [PATH]             files under the folder (or the file) with no copy on another disk
  pinakes safe-to-delete [PATH]        files under it with no kept copy on another disk (none: safe), and the
                                       symlinks elsewhere that lead into it
  pinakes backed-up [PATH]
  pinakes dupes
  pinakes folder-copies [FOLDER]       folders under it that are copies of another folder (the same files at the
                                       same paths, all held by a bigger one, or the same bar a few edited files,
                                       named), biggest first
  pinakes manifests [PATH]             what SHA256SUMS files say that the agents' hashes don't bear out: files listed
                                       with another hash, and lists naming files not there (no path, outside every
                                       root: everywhere you can see)
  pinakes history FILE
  pinakes versions FILE
  pinakes lineage FILE [--down]
  pinakes relatives FILE [--confirm|--reject|--clear OTHER]   the file's direct relatives both ways, rejected ones
                                       too; with an option, decides the link between FILE and OTHER (a path here or
                                       ROOT:PATH): a rejected pair is never suggested again. Only where the later
                                       file is your own or co-owned; the token needs the review scope
  pinakes changes [PATH] [--days N] [--host NAME] [--what KIND] [--review reviewed|unreviewed]
                                       no path, outside every root: everything you can see. --what (again for
                                       more) keeps only those kinds of change; --tree [--depth N] counts them per
                                       folder instead, from PATH down N levels (3)
  pinakes review intended|restore [PATH] [--days N] [--yes]   mark the unreviewed gone files and moves under PATH
                                       (or of that file) reviewed, as on the web's Changes page: shown, then marked
                                       once you say yes. Only your own or co-owned; the token needs the review scope
  pinakes tag [PATH] [--add TAG] [--remove TAG] [--note TEXT] [--yes]   your tags (again for more) and note on
                                       the file, or on every file under the folder: shown, then changed once you say
                                       yes (a file: at once). Without an option: the tags and notes there. Only where
                                       you own, co-own or annotate; the token needs the tag scope. --note "" removes it
  pinakes edits [--token CLIENT]       your own writes in the last --days (7), the newest first: review marks,
                                       lineage decisions, tags, notes and other metadata, on the web and by each of
                                       your tokens (--token: that one's, by its name), and your groups'; each with
                                       how many values it changed, the first, and what undid it
  pinakes undo EDIT...                 put back the values before those edits (numbers as edits lists them), the
                                       newest first; an edit whose value changed since is refused, naming the later
                                       one. An undo is an edit too. The token needs the scope the edit needed
  pinakes restores [PATH] [--back]     the changes marked restore and the backup copies holding their content;
                                       --back: also those whose content is back where it was
  pinakes growth [FOLDER] [--weeks N]  per folder under FOLDER (none, outside every root: each root's top
                                       folders) and week, the files and bytes that came and went (8 weeks)
  pinakes at-risk                      what losing a disk or a machine would cost you: your files with no copy
                                       on another disk, per disk, per host and by top folder
  pinakes meta SCHEMA.FIELD=VALUE
  pinakes stale
  pinakes roots                        every root you can see: host, kind, files, last complete scan
  pinakes backups [FOLDER]             where the folder's files are backed up, the least-backed-up first
  pinakes whoami                       whose token this is, its kind, scopes and the roots it may see
  pinakes access                       your access record: who saw your records, and the calls made with your
                                       tokens, the newest first (a person's token only)
  pinakes export [PART] [--csv]        your own records, as JSON (every part, or one) or as CSV (one part: files,
                                       history, reviews, metadata or lineage), on standard output
  pinakes releases                     this server's release and protocol, whether its schema is applied, and each
                                       agent's last check-in (release, protocol, locked or not, newest batch,
                                       refusals, the last time its batch numbering went back). It needs an ops
                                       token, which an operator makes on the account page, and sees nothing else
                                       but `stale`; on the catalog server, [client] url can be http://127.0.0.1.
  A list (find, where, history, versions, only-here, safe-to-delete, backed-up, folder-copies, dupes, changes,
  manifests, meta, restores, access, edits) is one page: 100 rows, or --limit N (at most 10000), from --offset N; under it,
  "N of TOTAL" and the next page's --offset.
  Add --json for JSON (a list: {"rows", "total", "limit", "offset"}), --as NAME to ask as another person (their
  password and second factor, or a token of theirs, at a hidden prompt; the command then sees only what they may see).

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
import csv
import datetime
import getpass
import io
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
BATCH = 1000            # rows a command that needs a whole list asks the API for at a time
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

    def get(self, call, raw=False, **args):
        """The answer as JSON; with raw, as text (a CSV)."""
        q = urllib.parse.urlencode({k: v for k, v in args.items() if v is not None and v is not False}, doseq=True)
        return self._ask(urllib.request.Request(self.base + call + ("?" + q if q else ""), headers=self._headers()),
                         raw)

    def post(self, call, body=None):
        return self._ask(urllib.request.Request(self.base + call, data=json.dumps(body or {}).encode(), method="POST",
                                                headers=dict(self._headers(), **{"Content-Type": "application/json"})))

    def _headers(self):
        h = {"Accept": "application/json"}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        return h

    def _ask(self, req, raw=False):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self.context) as r:
                return r.read().decode("utf-8") if raw else json.load(r)
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
        if a.get("roots_unreported"):
            print("%s: %d root(s) its batches no longer name; their files still count as copies. On the server, "
                  "pinakes-ingest totals names them, and retire-root LABEL retires one it no longer has"
                  % (a["host"], a["roots_unreported"]))


def _when(iso):
    return datetime.datetime.fromisoformat(iso)


def size(n):
    """Bytes for a person to read: 1.5 GB, 320.0 KB, 12 B."""
    n = float(n or 0)
    if abs(n) < 1000:
        return "%d B" % n
    for unit in ("KB", "MB", "GB", "TB", "PB"):
        n /= 1000
        if abs(n) < 1000 or unit == "PB":
            return "%.1f %s" % (n, unit)


def sized(rows, *keys):
    return [dict(r, **{k: size(r[k]) for k in keys}) for r in rows]


def whoami(api, as_json):
    got = api.get("whoami")
    if as_json:
        print(json.dumps(got, indent=1))
        return
    who = {"person": "%s (%s)" % (got.get("person"), got.get("display")) if got.get("display") else got.get("person"),
           "group": "the group %s, as no one member" % got.get("group"),
           "ops": "an ops token: no person, no root"}[got["kind"]]
    print("%s's token" % who if got["kind"] == "person" else who)
    print("scopes: %s" % ", ".join(got["scopes"]))
    if got["kind"] != "ops":
        print("roots: %s" % (", ".join(got["roots"]) or "none"))


def at_risk(api, as_json):
    """pinakes at-risk: the web's at-risk report (ROADMAP 42, 55)."""
    got = api.get("at-risk")
    if as_json:
        print(json.dumps(got, indent=1))
        return
    if not got["hosts"]:
        print("nothing at risk: every file you can see has a copy you can see on another disk")
        return
    print("lost with a disk (no copy on another disk of any machine):")
    _print(sized(got["disks"], "bytes"), False, ["host", "dev", "roots", "files", "bytes"])
    print("\nlost with a machine (no copy on another machine):")
    _print(sized(got["hosts"], "bytes"), False, ["host", "roots", "files", "bytes"])
    print("\nby top folder, the largest first:")
    _print(sized(got["folders"], "bytes"), False, ["host", "dev", "root", "folder", "owner", "files", "bytes"])
    if got["folders_total"] > len(got["folders"]):
        print("... and %d more folder(s)" % (got["folders_total"] - len(got["folders"])))


def restores(rows):
    """The restore report's rows for reading: where each content is held, as ROOT:PATH (snapshot)."""
    return [{"seen_on": r["seen_on"], "kind": r["kind"], "path": "%s:%s" % (r["root"], r["old_relpath"] or r["new_relpath"]),
             "marked_by": r["marked_by"], "back": "yes" if r["back"] else "", "backups": r["backups"],
             "held_in": ", ".join("%s:%s%s" % (h["root"], h["path"], " (%s)" % h["snapshot"] if h["snapshot"] else "")
                                  for h in r["held_in"] or [])} for r in rows]


EXPORT_BATCH = 10000    # rows of each part an export asks for at a time (the API's most)


def export(api, a):
    """pinakes export [PART] [--csv]: the person's own records (ROADMAP 45, 54), every page of them (ROADMAP 61: the
    API answers a page of each part), as one JSON or one CSV."""
    if a.csv:
        if not a.arg:
            raise Failed("a CSV is one part: pinakes export PART --csv")
        offset = 0
        while True:
            page = api.get("export", raw=True, part=a.arg, format="csv", limit=EXPORT_BATCH, offset=offset)
            n = len(list(csv.reader(io.StringIO(page)))) - 1                  # rows, the header aside
            sys.stdout.write(page if not offset else page.split("\n", 1)[1])
            offset += n
            if n < EXPORT_BATCH:
                return
    got, offset = None, 0
    while True:
        page = api.get("export", part=a.arg, limit=EXPORT_BATCH, offset=offset)
        parts = [k for k, v in page.items() if isinstance(v, list)]
        if got is None:
            got = {k: v for k, v in page.items() if k not in ("limit", "offset")}
        else:
            for k in parts:
                got[k] += page[k]
        offset += EXPORT_BATCH
        if all(len(page[k]) < EXPORT_BATCH for k in parts):
            break
    print(json.dumps(got, indent=1))


# commands ----------------------------------------------------------------------------------------------------------
FILE = ("where", "history", "versions", "lineage")                  # take one file
FOLDER = ("only-here", "safe-to-delete", "backed-up", "folder-copies")   # take a folder, or a file for itself
COMMANDS = ("find",) + FILE + FOLDER + ("dupes", "changes", "meta", "stale", "roots", "backups", "review",
                                         "releases", "manifests", "whoami", "access", "export", "at-risk", "growth",
                                         "restores", "relatives", "tag", "edits", "undo")
PAGED = ("find", "where", "history", "versions", "only-here", "backed-up", "folder-copies", "dupes", "changes",
         "manifests", "meta", "restores", "access", "edits")    # lists the API answers a page of, with the total (61)
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
    """A list's total: the API's (ROADMAP 61), else, from a server before it, the window count in its rows."""
    if got.get("total") is not None:
        return got["total"]
    return got["rows"][0]["total_rows"] if got["rows"] else 0


def page_line(got):
    """"N of TOTAL" under a page of a list (ROADMAP 61), and how to ask for the next; None without a total (a server
    before it) or for an empty list."""
    n, total, offset = len(got["rows"]), got.get("total"), got.get("offset") or 0
    if total is None or not total:
        return None
    if not n:
        return "none of %d: --offset %d is past the end" % (total, offset)
    line = "%s of %d" % ("%d-%d" % (offset + 1, offset + n) if offset else n, total)
    return line + ("; the next: --offset %d" % (offset + n) if offset + n < total else "")


def every(api, call, **args):
    """Every row of a list call, a page of BATCH at a time (the API answers one page by default)."""
    rows, offset = [], 0
    while True:
        got = api.get(call, limit=BATCH, offset=offset, **args)["rows"]
        rows += got
        offset += len(got)
        if len(got) < BATCH:
            return rows


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

    def loc_or_everywhere(want):
        """The argument's ROOT:PATH; none given, outside every root: None (everything the person can see)."""
        try:
            return loc(want)
        except NotInRoot:
            if a.arg:
                raise
            return None

    if a.cmd in ("whoami", "at-risk", "export"):
        {"whoami": lambda: whoami(api, a.json), "at-risk": lambda: at_risk(api, a.json),
         "export": lambda: export(api, a)}[a.cmd]()
        return

    if a.cmd == "review":
        review(api, a, cfg)
        return
    if a.cmd == "undo":
        undo(api, a)
        return
    if a.cmd == "relatives":
        relatives(api, a, cfg)
        return
    if a.cmd == "tag":
        tag(api, a, cfg)
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
        got = api.get("safe-to-delete", loc=where, limit=a.limit, offset=a.offset)
        if a.json:
            print(json.dumps(got, indent=1))
            return
        not_safe = {"rows": got["not_safe"], "total": got.get("total"), "offset": got.get("offset")}
        if not count(not_safe):
            print("safe: every file under %s has a kept copy on another disk" % where)
        else:
            _print(got["not_safe"], False)
            _page_line(not_safe)
        links = got["links_into"]
        if links:
            n = got.get("links_into_total", len(links))
            print("\n%d symlink(s) elsewhere lead into %s and would be left dangling%s:" % (
                n, where, " (the first %d)" % len(links) if n > len(links) else ""))
            _print([{"link": "%s:%s" % (l["root"], l["relpath"]), "target": l["link_target"]} for l in links], False)
        return
    page = {"limit": a.limit, "offset": a.offset} if a.cmd in PAGED else {}
    if a.cmd == "find":
        got = api.get("find", q=need("a name or glob"), **page)
    elif a.cmd in FILE:
        got = api.get(a.cmd, loc=loc("file"), down=1 if a.cmd == "lineage" and a.down else None, **page)
    elif a.cmd in FOLDER:
        got = api.get(a.cmd, loc=loc("any"), **page)
    elif a.cmd == "changes":
        # --host is a filter here, not this machine's name; no folder outside every root: everything
        try:
            where = location(api, a.cmd, a.arg, _this_host(None, cfg), "any")
        except NotInRoot:
            if a.arg:
                raise
            where = None
        filters = {"days": a.days, "loc": where, "what": a.what, "review": a.review}
        if a.tree:
            if a.host:
                raise Failed("pinakes changes --tree takes a folder, not --host")
            got = api.get("change-tree", depth=a.depth, **filters)
            if a.json:
                print(json.dumps(got, indent=1))
                return
            print("changes per folder %s in the last %d days:" % ("under " + where if where else
                                                                  "everywhere you can see", a.days))
            if got["cut"]:
                print("(cut at %d folders: give a folder or a smaller --depth)" % len(got["rows"]))
            got["rows"] = [dict(r, folder="  " * r["level"] + (r["folder"] or "(top)")) for r in got["rows"]]
            _print(got["rows"], False, ["host", "root", "folder", "new", "changed", "moved_in", "moved_out",
                                        "gone", "scrub", "unreviewed"])
            return
        else:
            got = api.get("changes", host=a.host, **dict(filters, **page))
            if not a.json:
                print("changes %s in the last %d days%s:" % ("under " + where if where else "everywhere you can see",
                                                             a.days, ", on " + a.host if a.host else ""))
    elif a.cmd == "growth":
        where = loc_or_everywhere("folder")
        got = api.get("growth", loc=where, weeks=a.weeks)
        if a.json:
            print(json.dumps(got, indent=1))
            return
        print("growth per folder %s, per week, in the last %d weeks:" % (
            "under " + where if where else "at the top of each root", a.weeks))
        if got["cut"]:
            print("(cut at %d rows: give a folder or fewer --weeks)" % len(got["rows"]))
        got["rows"] = [dict(r, folder=r["folder"] or "(files directly in it)")
                       for r in sized(got["rows"], "bytes_added", "bytes_gone")]
    elif a.cmd == "restores":
        got = api.get("restores", loc=loc_or_everywhere("any"), back=1 if a.back else None, **page)
        if not a.json:
            got["rows"] = restores(got["rows"])
    elif a.cmd == "access":
        got = api.get("access", **page)
        if not a.json:
            got["rows"] = [dict(r, actor="you" if r["mine"] else r["actor"],
                                detail=json.dumps(r["detail"], sort_keys=True) if r["detail"] else "")
                           for r in got["rows"]]
            _print(got["rows"], False, ["at", "actor", "action", "detail"])
            _page_line(got)
            return
    elif a.cmd == "edits":
        got = api.get("edits", days=a.days, token=a.token, **page)
        if not a.json:
            print("your edits in the last %d days%s:" % (a.days, ", by the token " + a.token if a.token else ""))
            got["rows"] = edit_rows(got["rows"])
            _print(got["rows"], False, ["edit", "at", "by", "action", "changes", "first", "change", "undone"])
            _page_line(got)
            return
    elif a.cmd == "manifests":
        where = loc_or_everywhere("any")
        got = api.get("manifests", loc=where, **page)
        if not a.json:
            print("checksum manifests %s: %s" % ("under " + where if where else "everywhere you can see",
                                                 "%d problem(s)" % count(got) if got["rows"] else "nothing wrong"))
            got["rows"] = [{"what": "another hash" if r["problem"] == "wrong" else "%d not there" % r["missing"],
                            "path": "%s:%s" % (r["root"], r["relpath"]),
                            "manifest": r["manifest_relpath"] if r["problem"] == "wrong" else ""}
                           for r in got["rows"]]
    elif a.cmd == "meta":
        key, eq, value = need("SCHEMA.FIELD=VALUE").partition("=")
        if not eq:
            raise Failed("pinakes meta needs SCHEMA.FIELD=VALUE")
        got = api.get("meta", field=key, value=value, **page)
    else:                                                               # dupes, stale, roots
        got = api.get(a.cmd, **page)
    if a.json and a.cmd in PAGED:
        print(json.dumps(got, indent=1))                                # the rows, and the total
        return
    _print(got["rows"], a.json)
    if a.cmd in PAGED:
        _page_line(got)


def edit_rows(rows):
    """The edits list for reading (ROADMAP 62): who and by what, the first value changed, before and after."""
    out = []
    for r in rows:
        who = "you" if r["mine"] else r["person"] or ""
        if r["group"]:
            who = "%s for %s" % (who, r["group"]) if who else r["group"]
        what = r["action"] if not r["undoes"] else "undo %d (%s)" % (r["undoes"], r["action"])
        first = "%s:%s" % (r["root"], r["relpath"])
        if r["kind"]:                                   # the later file, and the name it came from (--json: both)
            first += " (from %s)" % r["other_relpath"].rsplit("/", 1)[-1]
        out.append({"edit": r["edit"], "at": r["at"], "by": "%s, %s" % (who, r["token"] or "on the web"),
                    "action": what, "changes": r["changes"], "first": first,
                    "change": "%s -> %s" % (_value(r, r["before"]), _value(r, r["after"])),
                    "undone": "by %d" % r["undone_by"] if r["undone_by"] else ""})
    return out


def _value(r, v):
    """One value an edit changed, short: a mark, a decision, or the fields entered (sensitive ones with the rest)."""
    if v is None:
        return "none"
    if r["action"] == "review":
        return v["mark"]
    if r["action"] == "lineage":
        return v["decision"]
    vals = dict(v.get("plain") or {}, **(v.get("hidden") or {}))
    return "; ".join("%s %s" % (k, _cell(vals[k])) for k in sorted(vals)) or "none"


def undo(api, a):
    """pinakes undo EDIT...: the values before those edits put back, each edit whole or refused (ROADMAP 62)."""
    ids = []
    for x in [a.arg] + (a.more or []):
        try:
            ids.append(int(x))
        except (TypeError, ValueError):
            raise Failed("pinakes undo needs edit numbers, as pinakes edits lists them%s" % (
                "; %s is not one" % x if x else ""))
    got = api.post("undo", {"edits": ids})
    if a.json:
        print(json.dumps(got, indent=1))
    else:
        for r in got["undone"]:
            print("undid edit %d: %d value(s) put back, as edit %d" % (r["edit"], r["changes"], r["undone_by"]))
        for r in got["refused"]:
            print("edit %d not undone: %s" % (r["edit"], r["message"]))
    if got["refused"]:
        raise Failed("%d of %d edit(s) not undone" % (len(got["refused"]), got["asked"]))


def _page_line(got):
    line = page_line(got)
    if line:
        print(line)


def review(api, a, cfg):
    """pinakes review intended|restore [PATH]: the unreviewed gone files, moves and scrub findings under PATH (or of
    that file) in the last --days, shown, then marked once confirmed (or with --yes). The catalog marks only what the
    person owns or co-owns, in the token's roots and with its review scope, and says how many."""
    if a.arg not in MARKS:
        raise Failed("pinakes review needs intended or restore, then a path (none: the current folder)")
    where = location(api, "review", a.path, _this_host(a.host, cfg), "any")
    rows = every(api, "changes", loc=where, days=a.days, review="unreviewed", what=list(REVIEWABLE))
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


ENTERS = ("owner", "co-owner", "annotator")      # who may tag a file (web.ENTERS)
TAG_BATCH = 1000                                 # files one POST tag names (web.TAG_BATCH)


def tag(api, a, cfg):
    """pinakes tag [PATH] [--add TAG] [--remove TAG] [--note TEXT]: the person's own tags and note (their dc.subject
    and dc.description, ROADMAP 37) on the file, or on each file under the folder, shown and then changed by their
    ids once confirmed (a file named alone: at once; --yes: without asking). Without an option, the tags and notes
    there. The catalog changes only what the person owns, co-owns or annotates, in the token's roots, with its tag
    scope, and says how many."""
    where = location(api, "tag", a.arg, _this_host(a.host, cfg), "any")
    rows = every(api, "tags", loc=where)
    changing = bool(a.add or a.remove or a.note is not None)
    if not changing:
        if a.json:
            print(json.dumps({"rows": rows}, indent=1))
            return
        if not rows:
            print("no file you can see under %s" % where)
            return
        print("tags and notes on %d file(s) under %s:" % (len(rows), where))
        _print(_tag_rows(rows[:SHOW]), False, ["path", "role", "tags", "note", "others"])
        if len(rows) > SHOW:
            print("... and %d more (--json for every one)" % (len(rows) - SHOW))
        return
    mine = [r for r in rows if r["role"] in ENTERS]
    if not mine:
        print("nothing to tag under %s: no file you own, co-own or annotate%s" % (
            where, " (%d you only read)" % len(rows) if rows else ""))
        return
    what = "; ".join(x for x in ("add " + ", ".join(a.add) if a.add else "",
                                 "remove " + ", ".join(a.remove) if a.remove else "",
                                 ("note " + json.dumps(a.note) if a.note else "remove the note")
                                 if a.note is not None else "") if x)
    one = len(rows) == 1 and rows[0]["relpath"] == where.split(":", 1)[1]        # a file, named alone
    if not a.json:
        print("%d file(s) under %s to tag (%s)%s:" % (len(mine), where, what,
                                                      ", %d you only read left alone" % (len(rows) - len(mine))
                                                      if len(rows) > len(mine) else ""))
        _print(_tag_rows(mine[:SHOW]), False, ["path", "tags", "note"])
        if len(mine) > SHOW:
            print("... and %d more" % (len(mine) - SHOW))
    if not a.yes and not one:
        if not sys.stdin.isatty():
            raise Failed("not tagged: add --yes to tag them without being asked")
        if input("Tag these %d? [y/N] " % len(mine)).strip().lower() not in ("y", "yes"):
            print("not tagged")
            return
    body = {"add": a.add or [], "remove": a.remove or []}
    if a.note is not None:
        body["note"] = a.note
    asked = tagged = 0
    for i in range(0, len(mine), TAG_BATCH):
        got = api.post("tag", dict(body, ids=[r["file_id"] for r in mine[i:i + TAG_BATCH]]))
        asked, tagged = asked + got["asked"], tagged + got["tagged"]
    if a.json:
        print(json.dumps({"asked": asked, "tagged": tagged, "files": mine}, indent=1))
        return
    print("tagged %d of %d" % (tagged, asked))
    if tagged < asked:
        print("the rest are no longer yours to tag, or outside this token's roots")


def _tag_rows(rows):
    return [{"path": "%s:%s" % (r["root"], r["relpath"]), "role": r["role"] or "", "tags": r["tags"] or [],
             "note": r["note"] or "",
             "others": "; ".join("%s: %s" % (o["by"], ", ".join(x for x in (", ".join(o["tags"] or []),
                                                                         o["note"] or "") if x))
                                 for o in r["others"])} for r in rows]


def relatives(api, a, cfg):
    """pinakes relatives FILE [--confirm|--reject|--clear OTHER]: the file's direct relatives; with an option, the
    link between FILE and OTHER decided first (ROADMAP 9). The catalog decides only what the person may, and says how
    many links it decided."""
    host = _this_host(a.host, cfg)
    where = location(api, "relatives", a.arg, host, "file")
    picked = [(d, o) for d, o in (("confirmed", a.confirm), ("rejected", a.reject), (None, a.clear)) if o]
    if len(picked) > 1:
        raise Failed("pinakes relatives takes one of --confirm, --reject and --clear")
    got = {}
    if picked:
        decision, other = picked[0]
        got = api.post("decide", {"files": [where, location(api, "relatives", other, host, "file")],
                                  "decision": decision})
    listed = api.get("relatives", loc=where)
    if a.json:
        print(json.dumps(dict(listed, **got), indent=1))
        return
    if picked:
        print("%s %d link(s)" % (decision or "cleared", got["decided"]) if got["decided"] else
              "nothing decided: no link between the two that isn't by the same content, or the later file isn't "
              "yours or co-owned, or it's outside this token's roots")
    print("direct relatives of %s:" % where)
    _print([{"way": "came from" if r["direction"] == "up" else "went on to", "how": r["how"],
             "file": "%s:%s" % (r["root"], r["relpath"]), "evidence": r["evidence"], "confidence": r["confidence"],
             "decision": r["decision"] or ""} for r in listed["rows"]], False)


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
    ap.add_argument("more", nargs="*", help=argparse.SUPPRESS)          # review MARK PATH, undo EDIT...
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--down", action="store_true", help="lineage: what came from the file, not where it came from")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--host", help="changes: only this host's; backups: this machine's name in the catalog")
    ap.add_argument("--yes", action="store_true", help="review, tag: mark or tag without asking")
    ap.add_argument("--add", action="append", metavar="TAG", help="tag: add this tag (again for more)")
    ap.add_argument("--remove", action="append", metavar="TAG", help="tag: remove this tag (again for more)")
    ap.add_argument("--note", metavar="TEXT", help='tag: your note on each file ("" removes it)')
    ap.add_argument("--confirm", metavar="OTHER", help="relatives: confirm the link between FILE and OTHER")
    ap.add_argument("--reject", metavar="OTHER", help="relatives: reject it (never suggested again)")
    ap.add_argument("--clear", metavar="OTHER", help="relatives: clear the decision on it")
    ap.add_argument("--what", action="append", metavar="KIND",
                    help="changes: only this kind (new, changed, moved, moved_changed, gone, mismatch, unreadable)")
    ap.add_argument("--review", choices=("reviewed", "unreviewed"), help="changes: only the reviewed or unreviewed")
    ap.add_argument("--tree", action="store_true", help="changes: per folder, from PATH down --depth levels")
    ap.add_argument("--depth", type=int, default=3, help="changes --tree: how many levels (3)")
    ap.add_argument("--weeks", type=int, default=8, help="growth: how many weeks, this one counted (8)")
    ap.add_argument("--back", action="store_true", help="restores: also those whose content is back")
    ap.add_argument("--csv", action="store_true", help="export: one part, as CSV")
    ap.add_argument("--token", metavar="CLIENT", help="edits: only those made by this token (its name)")
    ap.add_argument("--limit", type=int, metavar="N", help="a list: show N rows (the API's page: 100; at most 10000)")
    ap.add_argument("--offset", type=int, metavar="N", help="a list: from the row after the first N (0)")
    ap.add_argument("--url", help="the catalog's address (default: [client] url)")
    ap.add_argument("--as", dest="person", metavar="NAME",
                    help="as this person: asks for their password (and second factor) or a token of theirs")
    ap.add_argument("--versions", action="store_true", help=argparse.SUPPRESS)      # before ROADMAP 39
    ap.add_argument("--config", help=argparse.SUPPRESS)
    a = ap.parse_intermixed_args(argv)          # options before or after the command and its argument
    if a.more and a.cmd != "undo" and (a.cmd != "review" or len(a.more) > 1):
        ap.error("pinakes %s takes one argument" % a.cmd)
    a.path = a.more[0] if a.more and a.cmd == "review" else None
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
