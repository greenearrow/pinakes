"""Scanning one root: walk it, compare with the local state, hash what changed, write batches.

Read-only on the tree: files are opened O_RDONLY (with O_NOATIME where permitted, O_NOFOLLOW always), nothing is
written inside the root, symlinks are recorded but never followed into: a symlink's target is looked up (lstat, no
reading) only inside this agent's own roots, to say which root and path it leads to and whether it is there.
"""

import hashlib
import json
import os
import stat
import tarfile
import time
import zipfile

from . import chunker, extract, fsinfo, hidden, registry
from .outbox import BatchWriter

READ_BLOCK = 1024 * 1024
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


def _flag(v):
    """A stored true/false/unknown (SQLite keeps 1, 0 or NULL) as True, False or None."""
    return None if v is None else bool(v)


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


def check(root, state):
    """Count a root as a scan sees it, with this process's rights: files (regular and symlinks) and bytes, how many
    of them changed since the last complete scan started, errors by kind, and the agent's state for the root.

    For comparing the catalog with the disk (`pinakes-agent check`, then `pinakes-ingest totals` on the server).
    The walk is the scan's own (exclusions, one filesystem, sockets and devices skipped), so a difference is a
    change since the scan, missing rights (the errors) or a bug. No file names come out; nothing is sent
    and the state is only read.
    """
    since = state.db.execute("SELECT max(started) FROM scans WHERE root = ? AND finished IS NOT NULL",
                             (root.label,)).fetchone()[0]
    unfinished = state.db.execute("SELECT count(*) FROM scans WHERE root = ? AND finished IS NULL",
                                  (root.label,)).fetchone()[0] > 0
    n = size = changed = changed_bytes = 0
    errors = {}
    top_dev = _root_dev(root.path)
    for _, abspath, err in _walk(root.path, root.exclude, None if root.cross_mounts else top_dev):
        if err is not None:
            kind = type(err).__name__
            errors[kind] = errors.get(kind, 0) + 1
            continue
        try:
            st = os.lstat(abspath)
        except FileNotFoundError:
            continue
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
            continue
        n += 1
        size += st.st_size
        if since is None or max(st.st_mtime, st.st_ctime) >= since:
            changed += 1
            changed_bytes += st.st_size
    kept = state.db.execute("SELECT count(*), coalesce(sum(size), 0) FROM files WHERE root = ?",
                            (root.label,)).fetchone()
    return {"root": root.label, "files": n, "bytes": size, "since": since, "unfinished": unfinished,
            "changed": changed, "changed_bytes": changed_bytes, "errors": errors,
            "state_files": kept[0], "state_bytes": kept[1]}


def check_verdict(c):
    """One line on what a check's numbers mean."""
    if c["since"] is None:
        return "no complete scan yet"
    if c["unfinished"]:
        return "a scan is unfinished: the state is part old, part new; check again after it completes"
    if (c["files"], c["bytes"]) == (c["state_files"], c["state_bytes"]):
        return "the disk matches the last scan"
    if c["changed"]:
        return "differs from the last scan; %d file(s) changed since it started" % c["changed"]
    if c["errors"]:
        return "differs from the last scan, with errors: missing rights?"
    return "differs from the last scan with nothing changed since: a bug, please report it"


class Scanner:
    PROGRESS_EVERY = 60  # seconds between progress lines (to stdout: the journal under systemd)

    def __init__(self, cfg, state, hook=None, progress=None, extractors=None):
        self.cfg = cfg
        self.state = state
        # the project's schemas' extractors; those missing a dependency are off (self.extractors.off says why)
        self.extractors = extractors if extractors is not None else extract.Extractors(registry.load())
        self.hook = hook          # tests: called with (relpath) before each file; may raise Interrupted
        self.counter = {}
        self.progress = progress  # callable(str), e.g. print; None: quiet
        self._protected = None
        self._root_devs = {}

    def _header(self, root, scan_id, started):
        return {"host": self.cfg.host, "root": root.label, "scan": scan_id,
                "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                "root_def": {"path": root.path, "kind": root.kind, "protected": root.protected,
                             "mirrors": root.mirrors}}

    def _root_holding(self, path):
        """The root of this agent whose folder holds path (the innermost, for nested roots), and path's relpath in
        it ('' for the root's own folder); (None, None) outside every root."""
        best = None
        for r in self.cfg.roots:
            top = r.path.rstrip("/")
            if (path == r.path or path.startswith(top + "/")) and (best is None or len(r.path) > len(best.path)):
                best = r
        if best is None:
            return None, None
        return best, path[len(best.path.rstrip("/")):].lstrip("/")

    def _root_dev(self, r):
        if r.label not in self._root_devs:
            try:
                self._root_devs[r.label] = _root_dev(r.path)
            except OSError:
                self._root_devs[r.label] = None
        return self._root_devs[r.label]

    LINK_HOPS = 40  # as the kernel's limit on symlinks in one lookup

    def resolve_link(self, abspath, target):
        """Where a symlink leads: (root label, relpath, dangling). Followed like the kernel would, one name at a
        time, but looked up (lstat) only inside this agent's roots, on the root's own filesystem unless it crosses
        mounts: anything else is never touched, so a link to a hung network mount can't stall the scan. Outside
        every root: (None, None, None). Inside one: dangling is True when the target is missing (or a loop), False
        when it is there, None when it can't be told (no rights, a mount not crossed)."""
        if not target:
            return None, None, None
        todo = list(reversed(target.split("/")))
        cur = "/" if target.startswith("/") else os.path.dirname(abspath)
        hops = 0

        def at(path, dangling):
            r, rel = self._root_holding(os.path.normpath(path))
            return (r.label, rel, dangling) if r else (None, None, None)

        while todo:
            name = todo.pop()
            if name in ("", "."):
                continue
            if name == "..":
                cur = os.path.dirname(cur)
                continue
            nxt = os.path.join(cur, name)
            r, rel = self._root_holding(nxt)
            if r is None or rel == "":
                if r is None and not any(p.path.startswith(nxt.rstrip("/") + "/") for p in self.cfg.roots):
                    return None, None, None   # leaves every root, and isn't on the way to one: not looked at
                cur = nxt                     # a root's folder or a folder above one: taken as configured
                continue
            rest = os.path.join(nxt, *reversed(todo)) if todo else nxt
            try:
                st = os.lstat(nxt)
            except (FileNotFoundError, NotADirectoryError):
                return at(rest, True)
            except OSError:
                return at(rest, None)
            if not r.cross_mounts and st.st_dev != self._root_dev(r):
                return at(rest, None)         # a mount inside the root, which scans don't cross either
            if stat.S_ISLNK(st.st_mode):
                hops += 1
                if hops > self.LINK_HOPS:
                    return at(rest, True)     # a loop: nothing is there
                try:
                    t = os.readlink(nxt)
                except OSError:
                    return at(rest, None)
                todo.extend(reversed(t.split("/")))
                if t.startswith("/"):
                    cur = "/"
                continue
            cur = nxt
        return at(cur, False)

    def _protecting_root(self, root, fi):
        """The protected root holding another link to this file's inode, or None. A file in a protected root is
        protected by its root; a file with one link has no other path."""
        if root.protected or fi.nlink < 2 or not stat.S_ISREG(fi.mode):
            return None
        if self._protected is None:
            self._protected = self._protected_inodes(root)
        inodes, uncertain = self._protected
        return inodes.get((fi.dev, fi.ino)) or uncertain.get(fi.dev)

    def _protected_inodes(self, root):
        """Every inode with more than one link under this agent's protected roots, walked afresh once per scan (a
        link can be made at any time), excludes ignored: an excluded file is still under the root. A folder there
        that can't be listed hides what it holds, so every file with more than one link on its filesystem counts
        as protected. Returns ({(dev, ino): protected root}, {dev: protected root})."""
        inodes, uncertain = {}, {}
        for p in self.cfg.roots:
            if not p.protected or p is root or not os.path.isdir(p.path):
                continue
            try:
                start = _root_dev(p.path)
            except OSError:
                continue
            for rel, path, err in _walk(p.path, None, None if p.cross_mounts else start):
                if isinstance(err, MountPoint):
                    continue
                try:
                    st = os.lstat(path)
                except FileNotFoundError:
                    continue
                except OSError:
                    uncertain.setdefault(start, p)
                    continue
                if err is not None:
                    uncertain.setdefault(st.st_dev, p)
                elif stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    inodes.setdefault((st.st_dev, st.st_ino), p)
        return inodes, uncertain

    def _wanted(self, root, relpath, t, protected_link, sha256):
        """{schema: version} to extract from this file: none on a protected root or a protected link, none for a
        symlink or a file not hashed (there is no content to attach them to)."""
        if root.protected or protected_link or t != "file" or not sha256:
            return {}
        return self.extractors.wanted(root.metadata, relpath)

    def _from_state(self, prev, relpath):
        """A file's record rebuilt from its state row, as last sent."""
        rec = {k: prev[k] for k in ("size", "mtime_ns", "ctime_ns", "btime_ns", "dev", "ino", "nlink", "uid",
                                    "sha256", "chunk_params")}
        rec.update(t="file", path=relpath)
        if prev["protected_link"]:
            rec["protected_link"] = True
        if prev["hidden"]:
            rec["hidden"] = True
        if prev["t"] == "symlink":
            rec.update(t="symlink", target=prev["target"], link_root=prev["link_root"],
                       link_path=prev["link_path"], dangling=_flag(prev["dangling"]))
        return rec

    def _record(self, root, relpath, abspath, prev, seen_inodes, full=False):
        """The record to send for one path, and the state row to keep; (None, None) if unchanged. With extracted
        metadata (METADATA.md) when the schemas' versions differ from what was extracted last, or with full (the
        server lost what it had)."""
        rec, keep = self._record_file(root, relpath, abspath, prev, seen_inodes)
        if rec == "unchanged":
            wanted = self._wanted(root, relpath, prev["t"], prev["protected_link"], prev["sha256"])
            want = json.dumps(wanted, sort_keys=True) if wanted else None
            if prev["meta_v"] == want and not (full and wanted):
                return None, None
            rec = keep = self._from_state(prev, relpath)   # only the metadata is new
        elif rec is None or rec == "vanished" or keep is None or rec["t"] == "error":
            return rec, keep
        else:
            wanted = self._wanted(root, relpath, rec["t"], rec.get("protected_link"), rec.get("sha256"))
            want = json.dumps(wanted, sort_keys=True) if wanted else None
        keep = dict(keep, meta_v=want)
        if not wanted:
            return rec, keep
        if not full and ((prev is not None and prev["sha256"] == rec["sha256"] and prev["meta_v"] == want)
                         or self.state.extracted(rec["sha256"], want)):
            return rec, keep             # this content's metadata, at these versions, is already sent
        meta = self.extractors.run(abspath, wanted)
        self.counter["extracted"] = self.counter.get("extracted", 0) + 1
        try:
            after = fsinfo.info(abspath)
        except FileNotFoundError:
            return "vanished", None
        if (after.size, after.mtime_ns, after.ino) != (rec["size"], rec["mtime_ns"], rec["ino"]):
            return rec, dict(keep, meta_v=None)   # changed since it was hashed: the next scan reads it again
        rec["meta"] = meta
        return rec, keep

    def _record_file(self, root, relpath, abspath, prev, seen_inodes):
        """The record to send for one path, and the state row to keep; (None, None) for what isn't a file,
        ("unchanged", None) if nothing changed."""
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
            rec["link_root"], rec["link_path"], rec["dangling"] = self.resolve_link(abspath, rec["target"])
        elif not stat.S_ISREG(fi.mode):
            return None, None  # sockets, fifos, devices: not files
        prot = self._protecting_root(root, fi)
        if prot is not None:
            rec["protected_link"] = True  # another link to this inode is under a protected root: protected here too
        hid = self.hidden(relpath, abspath)
        if hid:
            rec["hidden"] = True          # by a dot in its path, or Samba's hidden attribute on it or a folder above
        cparams = (chunker.Params(root.chunk_average)
                   if rec["t"] == "file" and root.wants_chunks(fi.size) and (prot is None or prot.wants_chunks(fi.size))
                   else None)
        rec["chunk_params"] = cparams.ident() if cparams else None

        same_meta = (prev is not None and prev["size"] == fi.size and prev["mtime_ns"] == fi.mtime_ns
                     and prev["dev"] == fi.dev and prev["ino"] == fi.ino)
        if same_meta and prev["chunk_params"] == rec["chunk_params"]:
            if (prev["uid"] == fi.uid and bool(prev["protected_link"]) == (prot is not None)
                    and bool(prev["hidden"]) == hid
                    and (rec["t"] != "symlink" or (prev["t"], prev["target"], prev["link_root"], prev["link_path"],
                                                   _flag(prev["dangling"]))
                         == ("symlink", rec["target"], rec["link_root"], rec["link_path"], rec["dangling"]))
                    and (root.kind == "backup" or (prev["ctime_ns"] == fi.ctime_ns and prev["nlink"] == fi.nlink))):
                # unchanged: nothing to send. In a backup root a new hard-linked snapshot changes every shared
                # inode's link count and ctime; that says nothing about the copy, so it isn't sent
                return "unchanged", None
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
        if (root.archives and not root.protected and prot is None
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
        unknown = sorted(set(root.metadata or ()) - self.extractors.known)
        if unknown:
            from .config import ConfigError
            raise ConfigError("root %s: metadata names %s: no schema with an extractor (there are: %s)"
                              % (root.label, ", ".join(unknown), ", ".join(sorted(self.extractors.known))))
        if not os.path.isdir(top):
            raise FileNotFoundError("root %s: %s is not a directory" % (root.label, top))
        scan_id, started, resumed = self.state.open_scan(root.label)
        summary = {"root": root.label, "scan": scan_id, "resumed": resumed, "sent": 0, "gone": 0,
                   "errors": 0, "batches": 0}
        self._protected = None  # walked when first needed: see _protecting_root
        self.hidden = hidden.Hidden(top)   # each folder's hidden attribute read once in this scan
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
                rec, keep = self._record(root, relpath, abspath, prev, seen_inodes, full)
                if rec == "vanished":
                    continue  # gone between listing and reading; the end of the scan reports it if so
                if rec is None and full and prev is not None:
                    rec = self._from_state(prev, relpath)
                    rec["resend"] = True
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
