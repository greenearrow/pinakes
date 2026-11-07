"""Scanning one root: walk it, compare with the local state, hash what changed, write batches.

Read-only on the tree: files are opened O_RDONLY (with O_NOATIME where permitted, O_NOFOLLOW always), nothing is
written inside the root, symlinks are recorded but never followed.
"""

import hashlib
import os
import stat
import tarfile
import time
import zipfile

from . import chunker, fsinfo
from .outbox import BatchWriter

READ_BLOCK = 1024 * 1024
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


class Interrupted(Exception):
    """Raised by a test hook to simulate a crash or shutdown mid-scan."""


class TooManyGone(Exception):
    """The walk found most of the root missing: a mount that didn't come up, or a mass deletion. Nothing is
    reported gone until a person confirms (accept_gone=True). cause says which it looks like: "not-mounted" (the
    root is on another filesystem than the one its files were recorded on) or "deleted" (the same filesystem)."""

    def __init__(self, message, cause):
        super().__init__(message)
        self.cause = cause


class MountChanged(TooManyGone):
    """The root's filesystem changed during the walk (unmounted or remounted mid-scan). Nothing from the end of
    this scan can be trusted, so nothing is reported gone, whatever accept_gone says; the next run resumes."""

    def __init__(self, message):
        super().__init__(message, "unmounted-during-scan")


def _root_dev(top):
    return os.stat(top).st_dev


def _open_readonly(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    if noatime:
        try:
            return os.open(path, flags | noatime)
        except PermissionError:
            pass  # O_NOATIME needs ownership of the file; fall back
    return os.open(path, flags)


def hash_file(path, chunk_params=None, counter=None):
    """SHA-256 of the file and, if chunk_params, its chunks; one read pass."""
    if counter is not None:
        counter["hashed"] = counter.get("hashed", 0) + 1
    fd = _open_readonly(path)
    h = hashlib.sha256()
    ch = chunker.Chunker(chunk_params) if chunk_params else None
    with os.fdopen(fd, "rb", buffering=0) as f:
        while True:
            block = f.read(READ_BLOCK)
            if not block:
                break
            h.update(block)
            if ch:
                ch.update(block)
    return h.hexdigest(), (ch.finish() if ch else None)


def _sha_stream(f):
    h = hashlib.sha256()
    size = 0
    for block in iter(lambda: f.read(READ_BLOCK), b""):
        h.update(block)
        size += len(block)
    return h.hexdigest(), size


def list_members(path):
    """[(entry path, size, sha256)] of a zip or tar file's regular members, or raises."""
    out = []
    lower = path.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                with z.open(info) as f:
                    digest, size = _sha_stream(f)
                out.append([info.filename, size, digest])
    else:
        with tarfile.open(path) as t:
            for m in t:
                if not m.isreg():
                    continue
                f = t.extractfile(m)
                digest, size = _sha_stream(f)
                out.append([m.name, size, digest])
    return out


class MountPoint(OSError):
    """A folder that is another filesystem's mount point: not crossed (like restic --one-file-system)."""


class BadName(OSError):
    """A name that isn't valid UTF-8: the catalog can't hold it, so it is reported (as the bytes, escaped), not
    catalogued, and a folder so named is not entered. Renaming it catalogues it at the next scan."""


def _printable(rel):
    """rel with any undecodable bytes as \\xNN escapes (for an error report only: it can collide with a real name)."""
    return os.fsencode(rel).decode("utf-8", "backslashreplace")


def _dev_of(entry):
    return entry.stat(follow_symlinks=False).st_dev


def _walk(top, exclude, root_dev=None):
    """(relpath, abspath, error) for every non-directory under top, sorted, excluded paths pruned. With root_dev,
    a folder on another filesystem is not entered: it comes back once, with a MountPoint error. A name that isn't
    valid UTF-8 comes back once, printable, with a BadName error."""
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        abs_dir = os.path.join(top, rel_dir) if rel_dir else top
        try:
            with os.scandir(abs_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as e:
            yield rel_dir, abs_dir, e
            continue
        subdirs = []
        for e in entries:
            rel = rel_dir + "/" + e.name if rel_dir else e.name
            if exclude and exclude(rel):
                continue
            try:
                e.name.encode("utf-8")
            except UnicodeEncodeError:
                yield _printable(rel), e.path, BadName("name is not valid UTF-8: rename it to catalog it")
                continue
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir and root_dev is not None:
                try:
                    dev = _dev_of(e)
                except OSError:
                    dev = root_dev
                if dev != root_dev:
                    yield rel, e.path, MountPoint("mount point of another filesystem: not crossed")
                    continue
            if is_dir:
                subdirs.append(rel)
            else:
                yield rel, e.path, None
        stack.extend(reversed(subdirs))  # depth first, in name order


class Scanner:
    PROGRESS_EVERY = 60  # seconds between progress lines (to stdout: the journal under systemd)

    def __init__(self, cfg, state, hook=None, progress=None):
        self.cfg = cfg
        self.state = state
        self.hook = hook          # tests: called with (relpath) before each file; may raise Interrupted
        self.counter = {}
        self.progress = progress  # callable(str), e.g. print; None: quiet

    def _header(self, root, scan_id, started):
        return {"host": self.cfg.host, "root": root.label, "scan": scan_id,
                "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                "root_def": {"path": root.path, "kind": root.kind, "protected": root.protected,
                             "mirrors": root.mirrors}}

    def _record(self, root, relpath, abspath, prev, seen_inodes):
        """The record to send for one path, and the state row to keep; (None, None) if unchanged."""
        try:
            fi = fsinfo.info(abspath)
        except FileNotFoundError:
            return "vanished", None
        rec = {"t": "file", "path": relpath, "size": fi.size, "mtime_ns": fi.mtime_ns, "ctime_ns": fi.ctime_ns,
               "btime_ns": fi.btime_ns, "dev": fi.dev, "ino": fi.ino, "nlink": fi.nlink, "uid": fi.uid}
        if stat.S_ISLNK(fi.mode):
            rec["t"] = "symlink"
            try:
                rec["target"] = os.readlink(abspath)
            except OSError:
                rec["target"] = None
        elif not stat.S_ISREG(fi.mode):
            return None, None  # sockets, fifos, devices: not files
        cparams = (chunker.Params(root.chunk_average) if rec["t"] == "file" and root.wants_chunks(fi.size)
                   else None)
        rec["chunk_params"] = cparams.ident() if cparams else None

        same_meta = (prev is not None and prev["size"] == fi.size and prev["mtime_ns"] == fi.mtime_ns
                     and prev["dev"] == fi.dev and prev["ino"] == fi.ino)
        if same_meta and prev["chunk_params"] == rec["chunk_params"]:
            if prev["ctime_ns"] == fi.ctime_ns and prev["nlink"] == fi.nlink and prev["uid"] == fi.uid:
                return None, None  # unchanged: nothing to send
            rec["sha256"] = prev["sha256"]  # metadata only (permissions, links): no rehash
            return rec, rec

        if rec["t"] == "symlink" or root.hash == "none":
            rec["sha256"] = None
            return rec, rec

        key = (fi.dev, fi.ino, fi.size, fi.mtime_ns)
        known = seen_inodes.get(key)
        if known is None and fi.nlink > 1:
            row = self.state.by_inode(fi.dev, fi.ino, fi.size, fi.mtime_ns)
            if row is not None and row["chunk_params"] == rec["chunk_params"]:
                known = (row["sha256"], None, True)
        if known is not None:
            rec["sha256"] = known[0]  # another link to an inode already hashed; chunks belong to the content,
            return rec, rec           # which the ingester already has from the first link

        try:
            digest, chunks = hash_file(abspath, cparams, self.counter)
        except FileNotFoundError:
            return "vanished", None
        except OSError as e:
            return {"t": "error", "path": relpath, "error": "%s: %s" % (type(e).__name__, e)}, None
        after = fsinfo.info(abspath)
        if (after.size, after.mtime_ns, after.ino) != (fi.size, fi.mtime_ns, fi.ino):
            # changed while being read: report it unhashed; the next scan hashes it
            rec["sha256"] = None
            rec["unstable"] = True
            return rec, None
        rec["sha256"] = digest
        if chunks is not None:
            rec["chunks"] = chunks
        if (root.archives and not root.protected
                and relpath.lower().endswith(ARCHIVE_SUFFIXES)):
            try:
                rec["members"] = list_members(abspath)
            except Exception as e:  # corrupt, encrypted, or not really an archive
                rec["members_error"] = "%s: %s" % (type(e).__name__, e)
        if fi.nlink > 1:
            seen_inodes[key] = (digest, chunks, False)
        return rec, rec

    GONE_GUARD_FRACTION = 0.5
    GONE_GUARD_MIN = 100

    def scan(self, root, full=False, accept_gone=False):
        """Scan one root. Returns a summary dict. full=True also resends every unchanged file's record."""
        top = root.path
        if not os.path.isdir(top):
            raise FileNotFoundError("root %s: %s is not a directory" % (root.label, top))
        scan_id, started, resumed = self.state.open_scan(root.label)
        summary = {"root": root.label, "scan": scan_id, "resumed": resumed, "sent": 0, "gone": 0,
                   "errors": 0, "batches": 0}
        seen_inodes = {}
        unreadable = []   # directories that couldn't be listed: what's under them is not reported gone
        writer = None

        def flush(complete):
            nonlocal writer
            if writer is None:
                return
            seq = writer.seq
            writer.write(seq, complete)
            self.state.commit()
            summary["batches"] += 1
            writer = None

        def ensure_writer():
            nonlocal writer
            if writer is None:
                seq = self.state.reserve_seq()
                writer = BatchWriter(self.cfg.outbox, self._header(root, scan_id, started))
                writer.seq = seq
                self.state.begin()
            return writer

        seen = 0
        last_report = time.monotonic()
        try:
            start_dev = _root_dev(top)
            root_dev = None if root.cross_mounts else start_dev
            for relpath, abspath, err in _walk(top, root.exclude, root_dev):
                seen += 1
                if self.progress and time.monotonic() - last_report >= self.PROGRESS_EVERY:
                    last_report = time.monotonic()
                    self.progress("%s: %d paths walked, %d sent, %d hashed, at %s"
                                  % (root.label, seen, summary["sent"], self.counter.get("hashed", 0), relpath))
                if err is not None:
                    if not isinstance(err, BadName):  # nothing under a bad name was ever catalogued
                        unreadable.append(relpath)
                    w = ensure_writer()
                    w.add({"t": "error", "path": relpath or ".", "error": "%s: %s" % (type(err).__name__, err)})
                    summary["errors"] += 1
                    continue
                if self.hook:
                    self.hook(relpath)
                prev = self.state.get(root.label, relpath)
                if prev is not None and prev["seen_scan"] == scan_id:
                    continue  # already handled before an interruption
                rec, keep = self._record(root, relpath, abspath, prev, seen_inodes)
                if rec == "vanished":
                    continue  # gone between listing and reading; the end of the scan reports it if so
                if rec is None and full and prev is not None:
                    rec = {k: prev[k] for k in ("size", "mtime_ns", "ctime_ns", "btime_ns", "dev", "ino",
                                                "nlink", "uid", "sha256", "chunk_params")}
                    rec.update(t="file", path=relpath, resend=True)
                w = ensure_writer()
                if rec is None:
                    self.state.mark_seen(root.label, relpath, scan_id)
                else:
                    w.add(rec)
                    if rec["t"] == "error":
                        summary["errors"] += 1
                        if prev is not None:
                            self.state.mark_seen(root.label, relpath, scan_id)
                    elif keep is not None:
                        self.state.put(root.label, relpath, keep, scan_id)
                        summary["sent"] += 1
                    else:  # unstable: keep the old row, marked seen, so it isn't reported gone
                        summary["sent"] += 1
                        if prev is not None:
                            self.state.mark_seen(root.label, relpath, scan_id)
                if len(w) >= self.cfg.batch_records:
                    flush(False)
            # the walk completed. If the root's filesystem changed under it, what was missed is not gone.
            try:
                end_dev = _root_dev(top)
            except OSError:
                end_dev = None
            if end_dev != start_dev:
                raise MountChanged("root %s: %s changed filesystem during the scan (unmounted or remounted?); "
                                   "nothing reported gone. Rerun when it is mounted." % (root.label, top))
            # everything not seen in this scan is gone, except under unreadable folders
            w = ensure_writer()
            unseen = self.state.unseen(root.label, scan_id)
            gone = [p for p in unseen
                    if not any(d == "" or p == d or p.startswith(d + "/") for d in unreadable)]
            total = self.state.db.execute("SELECT count(*) FROM files WHERE root = ?", (root.label,)).fetchone()[0]
            if (not accept_gone and len(gone) >= self.GONE_GUARD_MIN
                    and len(gone) > self.GONE_GUARD_FRACTION * total):
                recorded = self.state.db.execute(
                    "SELECT dev FROM files WHERE root = ? GROUP BY dev ORDER BY count(*) DESC LIMIT 1",
                    (root.label,)).fetchone()
                if recorded is not None and recorded[0] != start_dev:
                    raise TooManyGone("root %s: %d of %d files are missing, and %s is on another filesystem than "
                                      "they were recorded on: not mounted? Mount it and rerun; --accept-gone only "
                                      "if this is real." % (root.label, len(gone), total, top), "not-mounted")
                raise TooManyGone("root %s: %d of %d files are missing on the same filesystem as before: deleted? "
                                  "Rerun with --accept-gone if this is real." % (root.label, len(gone), total),
                                  "deleted")
            gone_set = set(gone)
            for relpath in unseen:
                if relpath in gone_set:
                    continue
                self.state.mark_seen(root.label, relpath, scan_id)
            for relpath in gone:
                w.add({"t": "gone", "path": relpath})
                self.state.delete(root.label, relpath)
                summary["gone"] += 1
            self.state.finish_scan(scan_id)
            flush(True)
        except BaseException:
            self.state.rollback()  # the unwritten batch's records are found again on the next run
            raise
        return summary
