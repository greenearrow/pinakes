"""The scrub (DESIGN.md "Scrub"): read every file again over a period, per filesystem, and check its hash.

A file is hashed again by a scan only when its size, mtime or inode changes, so bytes that change under an unchanged
mtime (a disk returning wrong data, a program that puts the mtime back) would never be noticed. The scrub re-reads
the least recently verified files of each filesystem under the agent's roots, up to that filesystem's share for the
run, and reports a hash that differs (`mismatch`) or a read that fails (`unreadable`), never as an edit.

The share is set per filesystem in the scrub file, which the agent writes itself (`[agent] scrub`, by default
scrub.toml beside agent.toml): one block per filesystem, `days` for a full pass (default 30; 0, off, the default for
network filesystems). The agent appends filesystems it finds later and never rewrites a block, so a number the person
set stays. Standard library only, like the rest of the agent.
"""

import collections
import datetime
import errno
import json
import os
import re
import time

from . import chunker, fsinfo
from .config import ConfigError
from .outbox import BatchWriter
from .scan import hash_file

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the distribution's python3-tomli
    import tomli as tomllib

DEFAULT_DAYS = 30
MAX_DAYS = 3650
CATCH_UP_DAYS = 7                 # a run reads at most this many nights' share: a machine off for a month catches up
                                  # over a few runs, not in one
DAY = 86400.0
PAGE = 2000                       # inodes fetched from the state at a time
NETWORK = frozenset(("nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "sshfs", "9p", "ceph", "glusterfs",
                     "fuse.glusterfs", "afs", "davfs", "fuse.rclone"))
MOUNTINFO = "/proc/self/mountinfo"
BY_UUID = "/dev/disk/by-uuid"

FILE_HEADER = """\
# Written by pinakes-agent from the filesystems under its roots. Edit the numbers; the agent never changes them,
# and adds a block at the end when it finds a new filesystem (DESIGN.md "Scrub").
# days: read every file of this filesystem again and check its hash, a full pass every this many days
# (30: about 3.3 % of its bytes a night). 0: off.
"""

Filesystem = collections.namedtuple("Filesystem", "id mount fstype source")
Mount = collections.namedtuple("Mount", "majmin mount fstype source")


class Interrupted(Exception):
    """Raised by a test hook to simulate a crash or shutdown mid-scrub."""


# filesystems ---------------------------------------------------------------------------------------------------

def _unescape(s):
    """A mountinfo field: space, tab, newline and backslash come as octal escapes."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def mounts(mountinfo=MOUNTINFO):
    out = []
    with open(mountinfo) as f:
        for line in f:
            fields = line.split()
            try:
                sep = fields.index("-", 6)
                out.append(Mount(fields[2], _unescape(fields[4]), fields[sep + 1], _unescape(fields[sep + 2])))
            except (ValueError, IndexError):
                continue
    return out


class Filesystems:
    """Which filesystem a path is on, by an id that survives a reboot: the filesystem's UUID where it has one (the
    mount's source device, matched to a link in /dev/disk/by-uuid), else `source:` and the mount source (a ZFS
    dataset, an NFS export). The device number alone can change across a reboot (a USB or md device): it is the id
    only when the mount table doesn't list the device, as `dev:MAJ:MIN`."""

    def __init__(self, mountinfo=MOUNTINFO, by_uuid=BY_UUID):
        self.mountinfo = mountinfo
        self.by_uuid = by_uuid
        self._mounts = None
        self._uuids = None

    def _uuid(self, source):
        if self._uuids is None:
            self._uuids = {}
            try:
                for name in sorted(os.listdir(self.by_uuid)):
                    self._uuids.setdefault(os.path.realpath(os.path.join(self.by_uuid, name)), name)
            except OSError:
                pass
        return self._uuids.get(os.path.realpath(source))

    def of(self, path, dev=None):
        """The Filesystem holding path (dev: its st_dev, if known)."""
        real = os.path.realpath(path)
        if dev is None:
            dev = os.stat(path).st_dev
        if self._mounts is None:
            try:
                self._mounts = mounts(self.mountinfo)
            except OSError:
                self._mounts = []
        majmin = "%d:%d" % (os.major(dev), os.minor(dev))
        best = None
        for m in self._mounts:           # the last of the longest: a later mount on the same point hides an earlier
            top = m.mount.rstrip("/")
            if m.majmin == majmin and (real == m.mount or real.startswith(top + "/")):
                if best is None or len(m.mount) >= len(best.mount):
                    best = m
        if best is None:
            fs = Filesystem("dev:" + majmin, "?", "?", "?")
        else:
            uuid = self._uuid(best.source) if best.source.startswith("/") else None
            fs = Filesystem("uuid:" + uuid if uuid else "source:" + best.source, best.mount, best.fstype,
                            best.source)
        return fs


def default_days(fs):
    return 0 if fs.fstype in NETWORK else DEFAULT_DAYS


# the scrub file ------------------------------------------------------------------------------------------------

def load_file(path):
    """{filesystem id: days} from the scrub file, in its order; {} if it doesn't exist. Raises ConfigError, naming the
    file, for anything else wrong in it."""
    try:
        with open(path, "rb") as f:
            d = tomllib.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError("%s: %s" % (path, e))
    extra = set(d) - {"filesystem"}
    if extra:
        raise ConfigError("%s: unknown key(s) %s: the file holds [[filesystem]] blocks only"
                          % (path, ", ".join(sorted(extra))))
    out = {}
    blocks = d.get("filesystem", [])
    if not isinstance(blocks, list):
        raise ConfigError("%s: filesystem must be [[filesystem]] blocks" % path)
    for i, b in enumerate(blocks, 1):
        where = "%s: [[filesystem]] %d" % (path, i)
        bad = set(b) - {"id", "days"}
        if bad:
            raise ConfigError("%s: unknown key(s) %s" % (where, ", ".join(sorted(bad))))
        fid, days = b.get("id"), b.get("days")
        if not isinstance(fid, str) or not fid:
            raise ConfigError("%s: id must be a filesystem id (as the agent wrote it)" % where)
        if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= MAX_DAYS:
            raise ConfigError("%s (%s): days must be a whole number from 0 (off) to %d" % (where, fid, MAX_DAYS))
        if fid in out:
            raise ConfigError("%s: %s is listed twice" % (where, fid))
        out[fid] = days
    return out


def _comment(text):
    return re.sub(r"[\x00-\x1f\x7f]", "?", text)


def _block(fs, roots):
    return "\n[[filesystem]]\nid = %s   # %s\ndays = %d\n" % (
        json.dumps(fs.id), _comment("%s, %s; root%s %s" % (fs.mount, fs.fstype, "s" if len(roots) > 1 else "",
                                                           ", ".join(roots))), default_days(fs))


def ensure_file(path, found):
    """Make the scrub file list every filesystem in found ([(Filesystem, [root labels])]): created if missing,
    blocks appended for those it lacks, nothing else touched. Returns (the filesystems added, None) or (those it
    would have added, why it couldn't write)."""
    have = load_file(path)
    new = [(fs, roots) for fs, roots in found if fs.id not in have]
    if not new and os.path.exists(path):
        return [], None
    text = "".join(_block(fs, roots) for fs, roots in new)
    try:
        if not os.path.exists(path):
            tmp = "%s.%d.tmp" % (path, os.getpid())
            with open(tmp, "w") as f:
                f.write(FILE_HEADER + text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        else:
            with open(path, "a") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
    except OSError as e:
        return [fs for fs, _ in new], "%s: %s" % (path, e.strerror or e)
    back = load_file(path)                       # read back: every filesystem is there with its number
    missing = [fs.id for fs, _ in new if fs.id not in back]
    if missing:
        return [fs for fs, _ in new], "%s: written, but %s not read back" % (path, ", ".join(missing))
    return [fs for fs, _ in new], None


# the run -------------------------------------------------------------------------------------------------------

def _date(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d") if t else None


def _error_name(e):
    return errno.errorcode.get(e.errno, type(e).__name__) if e.errno else type(e).__name__


class Scrubber:
    """One scrub run over this agent's filesystems (run()), or what it would do (status())."""

    PROGRESS_EVERY = 60

    def __init__(self, cfg, state, filesystems=None, progress=None, hook=None, now=time.time, read=hash_file):
        self.cfg = cfg
        self.state = state
        self.fss = filesystems or Filesystems()
        self.progress = progress
        self.hook = hook              # tests: called with (root label, relpath) before each read; may raise
        self.now = now
        self.read = read              # (path, chunk params) -> (sha256 hex, chunks)
        self.notes = []               # lines for the person: filesystems added to the file, skipped, ...

    def _roots(self):
        return {r.label: r for r in self.cfg.roots}

    def plan(self):
        """{filesystem id: {"fs", "roots": [labels], "keys": [(root, dev)]}} for every filesystem under the roots:
        each root's own, and each other device its hashed files were recorded on (a root that crosses mounts)."""
        roots = self._roots()
        groups = {}

        def add(fs, label, dev):
            g = groups.setdefault(fs.id, {"fs": fs, "roots": [], "keys": []})
            if label not in g["roots"]:
                g["roots"].append(label)
            if dev is not None and (label, dev) not in g["keys"]:
                g["keys"].append((label, dev))

        for r in self.cfg.roots:
            try:
                st = os.stat(r.path)
            except OSError:
                continue
            add(self.fss.of(r.path, st.st_dev), r.label, None)
        for row in self.state.db.execute(
                "SELECT root, dev, min(relpath) AS relpath FROM files WHERE t = 'file' AND sha256 IS NOT NULL "
                "GROUP BY root, dev ORDER BY root, dev").fetchall():
            r = roots.get(row["root"])
            if r is None or row["dev"] is None:
                continue
            path = os.path.join(r.path, row["relpath"])
            try:
                fs = self.fss.of(path, row["dev"])
            except OSError:
                continue
            add(fs, r.label, row["dev"])
        return groups

    @staticmethod
    def _where(keys):
        return "(" + " OR ".join("(root = ? AND dev = ?)" for _ in keys) + ")", [x for k in keys for x in k]

    def _bytes(self, keys):
        if not keys:
            return 0
        w, args = self._where(keys)
        return self.state.db.execute(
            "SELECT coalesce(sum(size), 0) FROM (SELECT max(size) AS size FROM files WHERE t = 'file' "
            "AND sha256 IS NOT NULL AND %s GROUP BY dev, ino)" % w, args).fetchone()[0]

    def _ages(self, label):
        """(oldest verified time, files never verified) of a root's hashed files."""
        r = self.state.db.execute("SELECT min(verified), count(*) - count(verified) FROM files "
                                  "WHERE root = ? AND t = 'file' AND sha256 IS NOT NULL", (label,)).fetchone()
        return r[0], r[1]

    def _file_and_days(self, groups):
        """{filesystem id: days}, the scrub file made to list every filesystem first."""
        path = self.cfg.scrub
        found = [(g["fs"], g["roots"]) for g in groups.values() if not g["fs"].id.startswith("dev:")]
        added, why = ensure_file(path, found)
        for fs in added:
            if why is None:
                self.notes.append("scrub: %s (%s) added to %s with days = %d" % (fs.id, fs.mount, path,
                                                                                 default_days(fs)))
        if why:
            self.notes.append("scrub: can't write the scrub file (%s); using the default for %s" % (
                why, ", ".join(fs.id for fs in added) or "nothing new"))
        days = load_file(path)
        return {fid: days.get(fid, default_days(g["fs"])) for fid, g in groups.items()}

    def status(self):
        """Per filesystem: what the scrub does there, and what its last run found."""
        groups = self.plan()
        days = self._file_and_days(groups)
        out = []
        for fid, g in sorted(groups.items(), key=lambda kv: kv[1]["fs"].mount):
            total = self._bytes(g["keys"])
            ages = [self._ages(label) for label in g["roots"]]
            oldest = min((a[0] for a in ages if a[0] is not None), default=None)
            last = json.loads(self.state.get_meta("scrub_stats:" + fid) or "null")
            out.append({"id": fid, "mount": g["fs"].mount, "fstype": g["fs"].fstype, "roots": g["roots"],
                        "days": days[fid], "bytes": total,
                        "per_night": total // days[fid] if days[fid] else 0, "oldest": _date(oldest),
                        "never": sum(a[1] for a in ages), "last": last})
        return out

    def run(self, max_minutes=None, only_roots=None):
        """Scrub every filesystem whose `days` is above 0 and none of whose roots has a scan unfinished. Writes one
        batch per root scrubbed (its summary, and its mismatches and read errors). Returns a summary per filesystem.
        Each file confirmed is committed as it goes; what is to be sent is kept with the batches, in one transaction
        with them, so a crash before they are written finds the same thing again next run."""
        start = self.now()
        deadline = start + max_minutes * 60 if max_minutes else None
        groups = self.plan()
        days = self._file_and_days(groups)
        roots = self._roots()
        results = []
        out = {}                      # root label -> records to send
        updates = []                  # (sql, args) applied with the batches
        stats = {}                    # filesystem id -> its run's numbers, kept with the batches
        ran_roots = {}                # root label -> days of its filesystem
        for fid, g in sorted(groups.items()):
            d = days[fid]
            res = {"id": fid, "mount": g["fs"].mount, "days": d, "files": 0, "bytes": 0, "mismatches": 0,
                   "unreadable": 0, "skipped": None}
            results.append(res)
            if only_roots is not None and not set(only_roots) & set(g["roots"]):
                results.pop()
                continue
            if d == 0:
                res["skipped"] = "off"
                continue
            open_ = self.state.db.execute(
                "SELECT count(*) FROM scans WHERE finished IS NULL AND root IN (%s)" % ",".join("?" * len(g["roots"])),
                g["roots"]).fetchone()[0]
            if open_:
                res["skipped"] = "a scan of a root on it is unfinished"
                continue
            if deadline is not None and self.now() >= deadline:
                res["skipped"] = "out of time"
                continue
            total = self._bytes(g["keys"])
            last = self.state.get_meta("scrub_last:" + fid)
            elapsed = DAY if last is None else min(max(start - float(last), 0.0), CATCH_UP_DAYS * DAY)
            res["budget"] = budget = total * elapsed / (d * DAY)
            self._scrub_fs(g, budget, start, deadline, roots, res, out, updates)
            stats[fid] = dict(res, at=start)
            for label in g["roots"]:
                ran_roots[label] = d
        self._write(ran_roots, out, updates, stats, start)
        return results

    def _scrub_fs(self, g, budget, start, deadline, roots, res, out, updates):
        if not g["keys"]:
            return
        w, wargs = self._where(g["keys"])
        last_key = (-2.0, -1, -1)
        last_report = time.monotonic()
        while res["bytes"] < budget:
            page = self.state.db.execute(
                "SELECT dev, ino, min(coalesce(verified, -1.0)) AS v FROM files WHERE t = 'file' "
                "AND sha256 IS NOT NULL AND %s GROUP BY dev, ino HAVING v < ? AND (v > ? OR (v = ? AND (dev > ? "
                "OR (dev = ? AND ino > ?)))) ORDER BY v, dev, ino LIMIT ?" % w,
                wargs + [start, last_key[0], last_key[0], last_key[1], last_key[1], last_key[2], PAGE]).fetchall()
            if not page:
                return
            for p in page:
                last_key = (p["v"], p["dev"], p["ino"])
                if res["bytes"] >= budget or (deadline is not None and self.now() >= deadline):
                    return
                if self.progress and time.monotonic() - last_report >= self.PROGRESS_EVERY:
                    last_report = time.monotonic()
                    self.progress("scrub %s: %d files, %d of %d bytes" % (g["fs"].mount, res["files"], res["bytes"],
                                                                          int(budget)))
                self._inode(p["dev"], p["ino"], w, wargs, start, roots, res, out, updates)

    def _inode(self, dev, ino, w, wargs, start, roots, res, out, updates):
        rows = [r for r in self.state.db.execute(
            "SELECT root, relpath, size, mtime_ns, dev, ino, sha256, chunk_params, verified, scrub_error FROM files "
            "WHERE dev = ? AND ino = ? AND t = 'file' AND sha256 IS NOT NULL AND %s ORDER BY root, relpath" % w,
            [dev, ino] + wargs).fetchall() if r["root"] in roots]
        here = None
        for r in rows:                # the first path that is still this file, unchanged since the scan
            path = os.path.join(roots[r["root"]].path, r["relpath"])
            try:
                fi = fsinfo.info(path)
            except OSError:
                continue
            if (fi.size, fi.mtime_ns, fi.dev, fi.ino) == (r["size"], r["mtime_ns"], r["dev"], r["ino"]):
                here = (r, path, fi)
                break
        if here is None:
            return                    # changed or gone since the scan: the next scan handles it
        r, path, fi = here
        rows = [x for x in rows if x["sha256"] == r["sha256"]]
        if self.hook:
            self.hook(r["root"], r["relpath"])
        res["files"] += 1
        res["bytes"] += fi.size
        try:
            digest, _ = self.read(path, None)
        except FileNotFoundError:
            return
        except OSError as e:
            err = _error_name(e)
            res["unreadable"] += 1
            for x in rows:            # verified stays: the next run tries it first
                if x["scrub_error"] != err:
                    out.setdefault(x["root"], []).append({"t": "unreadable", "path": x["relpath"], "error": err})
                    updates.append(("UPDATE files SET scrub_error = ? WHERE root = ? AND relpath = ?",
                                    (err, x["root"], x["relpath"])))
            return
        try:
            after = fsinfo.info(path)
        except OSError:
            return
        if (after.size, after.mtime_ns, after.ino) != (fi.size, fi.mtime_ns, fi.ino):
            return                    # changed while read: the next scan sees it
        now = self.now()
        if digest == r["sha256"]:
            for x in rows:
                if x["scrub_error"] is not None:
                    out.setdefault(x["root"], []).append({"t": "readable", "path": x["relpath"]})
                    updates.append(("UPDATE files SET scrub_error = NULL, verified = ? WHERE root = ? AND relpath = ?",
                                    (now, x["root"], x["relpath"])))
                else:
                    self.state.db.execute("UPDATE files SET verified = ? WHERE root = ? AND relpath = ?",
                                          (now, x["root"], x["relpath"]))
            return
        res["mismatches"] += 1
        chunked = {}
        for x in rows:
            root = roots[x["root"]]
            rec = {"t": "mismatch", "path": x["relpath"], "size": fi.size, "mtime_ns": fi.mtime_ns, "dev": fi.dev,
                   "ino": fi.ino, "sha256": digest, "verified": _date(x["verified"]), "chunk_params": None}
            if x["chunk_params"] and root.wants_chunks(fi.size):
                params = chunker.Params(root.chunk_average)
                if params.ident() not in chunked:
                    try:
                        d2, chunks = self.read(path, params)
                    except OSError:
                        d2, chunks = None, None
                    chunked[params.ident()] = chunks if d2 == digest else None
                if chunked[params.ident()] is not None:
                    rec.update(chunk_params=params.ident(), chunks=chunked[params.ident()])
            out.setdefault(x["root"], []).append(rec)
            # the new content's metadata is extracted by the next scan (meta_v cleared)
            updates.append(("UPDATE files SET sha256 = ?, chunk_params = ?, verified = ?, scrub_error = NULL, "
                            "meta_v = NULL WHERE root = ? AND relpath = ?",
                            (digest, rec["chunk_params"], now, x["root"], x["relpath"])))

    def _header(self, root, summary):
        return {"host": self.cfg.host, "root": root.label,
                "started": datetime.datetime.fromtimestamp(summary.pop("_at"), datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "root_def": {"path": root.path, "kind": root.kind, "protected": root.protected,
                             "mirrors": root.mirrors},
                "scrub": summary}

    def _write(self, ran_roots, out, updates, stats, start):
        """The batches, one per root scrubbed, written with the state changes they report, in one transaction."""
        if not ran_roots:
            return
        roots = self._roots()
        seqs = {label: self.state.reserve_seq() for label in sorted(ran_roots)}
        self.state.begin()
        try:
            for sql, args in updates:
                self.state.db.execute(sql, args)
            for label in sorted(ran_roots):
                recs = out.get(label, [])
                oldest, never = self._ages(label)
                summary = {"on": _date(start), "days": ran_roots[label], "oldest": _date(oldest), "never": never,
                           "mismatches": sum(1 for x in recs if x["t"] == "mismatch"),
                           "unreadable": sum(1 for x in recs if x["t"] == "unreadable"), "_at": start}
                w = BatchWriter(self.cfg.outbox, self._header(roots[label], summary))
                for rec in recs:
                    w.add(rec)
                w.write(seqs[label], False)
            for fid, s in stats.items():
                self.state.set_meta("scrub_last:" + fid, repr(start))
                self.state.set_meta("scrub_stats:" + fid, json.dumps(
                    {k: s[k] for k in ("at", "files", "bytes", "mismatches", "unreadable")}))
            self.state.commit()
        except BaseException:
            self.state.rollback()
            raise
