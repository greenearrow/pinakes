"""Agent tests on generated trees in a temporary directory. Standard library only: python3 -m unittest."""

import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import zipfile

from pinakes import agent, chunker, config, fsinfo, globs, hidden, manifests, names, outbox, transport
from pinakes.scan import Interrupted, MountChanged, Scanner, TooManyGone, check, check_verdict
from pinakes.state import State


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Tree(unittest.TestCase):
    """A root with files, an agent config and state in a temporary directory."""

    root_extra = ""
    root_kind = "primary"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-test-")
        self.top = os.path.join(self.tmp, "root")
        os.makedirs(self.top)
        self.cfg = config.loads("""
[agent]
host = "test-1"
state = "%(t)s/state.sqlite"
outbox = "%(t)s/outbox"
[transport]
kind = "directory"
path = "%(t)s/inbox"
[[root]]
label = "r"
path = "%(top)s"
kind = "%(kind)s"
exclude = ["**/cache", "**/*.part"]
%(extra)s
""" % {"t": self.tmp, "top": self.top, "extra": self.root_extra, "kind": self.root_kind})
        self.state = State(self.cfg.state)
        self.scanner = Scanner(self.cfg, self.state)

    def tearDown(self):
        self.state.close()
        shutil.rmtree(self.tmp)

    def write(self, rel, data):
        p = os.path.join(self.top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def scan(self, **kw):
        return self.scanner.scan(self.cfg.roots[0], **kw)

    def drain(self):
        """Records of every waiting batch, then acknowledge them."""
        recs = []
        for seq, path in outbox.pending(self.cfg.outbox):
            header, r = outbox.read(path)
            self.assertEqual(header["seq"], seq)
            recs.extend(r)
            outbox.ack(self.cfg.outbox, seq)
        return recs

    def by_path(self, recs):
        return {r["path"]: r for r in recs}


class TestFsinfo(unittest.TestCase):
    def test_statx_matches_lstat(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"x")
            f.flush()
            fi = fsinfo.info(f.name)
            st = os.lstat(f.name)
            self.assertEqual((fi.size, fi.mtime_ns, fi.ctime_ns, fi.ino, fi.dev, fi.nlink),
                             (st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino, st.st_dev, st.st_nlink))
            self.assertTrue(fsinfo.has_statx())
            out = subprocess.run(["stat", "-c", "%W", f.name], stdout=subprocess.PIPE).stdout.decode().strip()
            if out not in ("0", "-"):  # the filesystem records birth time
                self.assertEqual(fi.btime_ns // 1_000_000_000, int(out))

    def test_symlink_not_followed(self):
        d = tempfile.mkdtemp()
        try:
            os.symlink("/nonexistent-target", os.path.join(d, "l"))
            fi = fsinfo.info(os.path.join(d, "l"))
            self.assertTrue(os.path.stat.S_ISLNK(fi.mode) if hasattr(os.path, "stat") else True)
        finally:
            shutil.rmtree(d)


class TestGlobs(unittest.TestCase):
    def test_patterns(self):
        m = globs.Matcher(["**/cache", "**/*.part", "people/user-2/**", "top.txt"])
        for p in ("cache", "a/b/cache", "x.part", "a/x.part", "people/user-2/a", "people/user-2/a/b", "top.txt"):
            self.assertTrue(m(p), p)
        for p in ("cachex", "a/cache/x", "x.parts", "people/user-22/a", "people/user-2", "a/top.txt"):
            self.assertFalse(m(p), p)


class TestNames(unittest.TestCase):
    def test_markers_off_signs_kept(self):
        p = names.load_patterns()
        key = lambda n: names.normalize(n, p)
        self.assertEqual(key("Report - Copy (2).txt"), key("report.txt"))
        self.assertEqual(key("plan v2.odt"), key("plan.odt"))
        # a minus sign before a number is part of the name (a game's region coordinates): not a separator
        self.assertNotEqual(key("r.-1.1.mca"), key("r.1.1.mca"))
        self.assertNotEqual(key("r.8.-2.mca"), key("r.8.2.mca"))
        self.assertEqual(key("r.-1.1.mca"), ("r -1 1", ".mca"))
        self.assertEqual(key("report-2.txt"), key("report 2.txt"))   # a hyphen inside a word is still a separator
        # an AppleDouble sidecar is not the file it describes
        self.assertNotEqual(key("._photo.jpg"), key("photo.jpg"))
        self.assertEqual(key("._photo (2).jpg"), key("._photo.jpg"))


class TestChunker(unittest.TestCase):
    def test_deterministic_and_local(self):
        rnd = io.BytesIO()
        h = b"seed"
        while rnd.tell() < 3 * 1024 * 1024:
            h = hashlib.sha256(h).digest()
            rnd.write(h)  # non-repeating: periodic data has almost no cut points
        data = rnd.getvalue()
        p = chunker.Params(64 * 1024)
        a = chunker.chunk_bytes(data, p)
        # the same result whatever block sizes the data arrives in
        c = chunker.Chunker(p)
        for i in range(0, len(data), 77777):
            c.update(data[i:i + 77777])
        self.assertEqual(a, c.finish())
        self.assertEqual(sum(n for _, n, _ in a), len(data))
        for _, n, _ in a[:-1]:
            self.assertTrue(p.minimum <= n <= p.maximum)
        # an insertion in the middle changes only the chunks around it
        edited = data[:1_500_000] + b"inserted text" + data[1_500_000:]
        b = chunker.chunk_bytes(edited, p)
        shared = len({d for _, _, d in a} & {d for _, _, d in b})
        self.assertGreaterEqual(shared, len(a) - 3)


class TestScan(Tree):
    def test_first_scan_and_unchanged(self):
        self.write("a.txt", b"alpha")
        self.write("sub/b.txt", b"beta")
        self.write("cache", b"excluded")
        self.write("sub/cache/c.txt", b"excluded dir")
        self.write("dl.part", b"excluded")
        s = self.scan()
        recs = self.by_path(self.drain())
        self.assertEqual(set(recs), {"a.txt", "sub/b.txt"})
        self.assertEqual(recs["a.txt"]["sha256"], sha(b"alpha"))
        self.assertEqual(s["gone"], 0)
        self.scan()
        self.assertEqual(self.drain(), [])  # nothing changed: nothing sent

    def test_change_metadata_gone_rename(self):
        self.write("a.txt", b"alpha")
        p = self.write("b.txt", b"beta")
        self.write("c.txt", b"gamma")
        self.scan()
        self.drain()
        time.sleep(0.01)
        self.write("a.txt", b"alpha 2")                              # content change
        os.chmod(p, 0o600)                                          # metadata only
        ino = os.lstat(os.path.join(self.top, "c.txt")).st_ino
        os.rename(os.path.join(self.top, "c.txt"), os.path.join(self.top, "d.txt"))  # rename
        self.scanner.counter.clear()
        self.scan()
        recs = self.drain()
        by = {(r["t"], r["path"]): r for r in recs}
        self.assertEqual(by[("file", "a.txt")]["sha256"], sha(b"alpha 2"))
        self.assertEqual(by[("file", "b.txt")]["sha256"], sha(b"beta"))
        self.assertIn(("gone", "c.txt"), by)
        self.assertEqual(by[("file", "d.txt")]["ino"], ino)          # the ingester matches the move by inode
        # hashed: a.txt (changed) and d.txt (new path); b.txt was only re-read for metadata
        self.assertEqual(self.scanner.counter["hashed"], 2)

    def test_hard_links_hashed_once(self):
        p = self.write("snap1/f.bin", b"x" * 100000)
        os.makedirs(os.path.join(self.top, "snap2"))
        os.link(p, os.path.join(self.top, "snap2/f.bin"))
        self.scan()
        recs = self.by_path(self.drain())
        self.assertEqual(recs["snap1/f.bin"]["sha256"], recs["snap2/f.bin"]["sha256"])
        self.assertEqual(self.scanner.counter["hashed"], 1)
        # a new snapshot linking to a known inode is not hashed again either
        os.makedirs(os.path.join(self.top, "snap3"))
        os.link(p, os.path.join(self.top, "snap3/f.bin"))
        self.scanner.counter.clear()
        self.scan()
        recs = self.by_path(self.drain())
        self.assertIn("snap3/f.bin", recs)
        self.assertEqual(self.scanner.counter.get("hashed", 0), 0)

    def test_interrupted_scan_resumes(self):
        for i in range(10):
            self.write("f%02d" % i, b"%d" % i)
        self.cfg.batch_records = 3
        self.scan()
        self.drain()
        os.remove(os.path.join(self.top, "f09"))
        for i in range(10, 20):
            self.write("f%02d" % i, b"%d" % i)

        calls = []

        def crash_at_f15(rel):
            calls.append(rel)
            if rel == "f15":
                raise Interrupted()
        self.scanner.hook = crash_at_f15
        with self.assertRaises(Interrupted):
            self.scan()
        partial = self.drain()
        self.assertFalse(any(r["t"] == "gone" for r in partial))      # no gone reports from an unfinished walk
        self.scanner.hook = None
        s = self.scan()
        self.assertTrue(s["resumed"])
        recs = partial + self.drain()
        files = {r["path"] for r in recs if r["t"] == "file"}
        self.assertEqual(files, {"f%02d" % i for i in range(10, 20)})  # each new file reported, none lost
        self.assertEqual([r["path"] for r in recs if r["t"] == "gone"], ["f09"])

    def test_crash_between_batch_and_commit_resends(self):
        self.write("a", b"a")
        self.write("b", b"b")
        real_commit = self.state.commit
        self.state.commit = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):
            self.scan()
        self.state.commit = real_commit
        first = self.drain()                         # the batch file made it to disk
        self.scan()
        again = self.drain()                         # state was not committed, so the records come again
        self.assertEqual({r["path"] for r in first if r["t"] == "file"}, {"a", "b"})
        self.assertEqual({r["path"] for r in again if r["t"] == "file"}, {"a", "b"})
        seqs = [h for h in (first, again)]
        self.assertTrue(seqs)

    def test_sequence_numbers_increase_with_gaps_allowed(self):
        self.write("a", b"a")
        self.scan()
        seqs1 = [s for s, _ in outbox.pending(self.cfg.outbox)]
        self.write("b", b"b")
        self.scan()
        seqs2 = [s for s, _ in outbox.pending(self.cfg.outbox)]
        self.assertTrue(seqs2[-1] > seqs1[-1])

    def test_unreadable_folder_not_reported_gone(self):
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        self.write("locked/x", b"x")
        self.write("open/y", b"y")
        self.scan()
        self.drain()
        os.chmod(os.path.join(self.top, "locked"), 0)
        try:
            self.scan()
            recs = self.drain()
        finally:
            os.chmod(os.path.join(self.top, "locked"), 0o755)
        self.assertFalse(any(r["t"] == "gone" for r in recs))
        self.assertTrue(any(r["t"] == "error" and r["path"] == "locked" for r in recs))

    def test_name_not_utf8_reported_not_fatal(self):
        top = os.fsencode(self.top)
        self.write("ok.txt", b"ok")
        self.write("dir\\xfe", b"a real name with a backslash")   # what the bad folder's report looks like
        with open(os.path.join(top, b"bad\xff.txt"), "wb") as f:
            f.write(b"bad")
        os.makedirs(os.path.join(top, b"dir\xfe"))
        with open(os.path.join(top, b"dir\xfe", b"inner.txt"), "wb") as f:
            f.write(b"inner")
        self.scan()
        recs = self.drain()
        self.assertEqual({r["path"] for r in recs if r["t"] == "file"}, {"ok.txt", "dir\\xfe"})
        errors = {r["path"]: r["error"] for r in recs if r["t"] == "error"}
        self.assertEqual(set(errors), {"bad\\xff.txt", "dir\\xfe"})
        self.assertIn("not valid UTF-8", errors["bad\\xff.txt"])
        # a bad name shields nothing from being reported gone, even a real file its report collides with
        os.remove(os.path.join(self.top, "dir\\xfe"))
        self.scan()
        self.assertIn(("gone", "dir\\xfe"), {(r["t"], r["path"]) for r in self.drain()})
        # renamed, it is catalogued
        os.rename(os.path.join(top, b"bad\xff.txt"), os.path.join(top, b"good.txt"))
        self.scan()
        self.assertIn("good.txt", {r["path"] for r in self.drain() if r["t"] == "file"})

    def test_time_out_of_range_is_unknown(self):
        p = self.write("far.txt", b"far")
        far = 10_000_000_000 * 10**9                               # the year 2286: past what an int64 of ns holds
        os.utime(p, ns=(far, far))
        if os.stat(p).st_mtime_ns != far:
            self.skipTest("this filesystem can't store a time that far off")
        self.assertIsNone(fsinfo.info(p).mtime_ns)
        self.scan()
        rec = self.by_path(self.drain())["far.txt"]
        self.assertIsNone(rec["mtime_ns"])
        self.assertEqual(rec["sha256"], sha(b"far"))
        self.scan()
        self.assertNotIn("far.txt", self.by_path(self.drain()))      # unchanged: not resent, not rehashed

    def test_mount_points_not_crossed(self):
        self.write("own/a", b"a")
        self.write("other-fs/secret", b"plaintext")
        self.write("other-fs/deeper/b", b"b")
        import pinakes.scan as scanmod
        real = scanmod._dev_of
        root_dev = os.stat(self.top).st_dev
        scanmod._dev_of = lambda e: root_dev + 1 if e.name == "other-fs" else real(e)
        try:
            self.scan()
        finally:
            scanmod._dev_of = real
        recs = self.drain()
        paths = {r["path"] for r in recs if r["t"] == "file"}
        self.assertEqual(paths, {"own/a"})
        self.assertTrue(any(r["t"] == "error" and r["path"] == "other-fs" and "mount point" in r["error"]
                            for r in recs))

    def test_mount_point_appearing_hides_nothing_as_gone(self):
        self.write("media/x", b"x")
        self.scan()
        self.drain()
        import pinakes.scan as scanmod
        real = scanmod._dev_of
        root_dev = os.stat(self.top).st_dev
        scanmod._dev_of = lambda e: root_dev + 1 if e.name == "media" else real(e)
        try:
            self.scan()
        finally:
            scanmod._dev_of = real
        self.assertFalse(any(r["t"] == "gone" for r in self.drain()))

    def test_mass_gone_guard(self):
        for i in range(150):
            self.write("f%03d" % i, b"%d" % i)
        self.scan()
        self.drain()
        for i in range(120):
            os.remove(os.path.join(self.top, "f%03d" % i))
        with self.assertRaises(TooManyGone) as cm:
            self.scan()
        self.assertEqual(cm.exception.cause, "deleted")
        self.assertFalse(any(r["t"] == "gone" for r in self.drain()))
        self.scan(accept_gone=True)
        self.assertEqual(sum(r["t"] == "gone" for r in self.drain()), 120)

    def unmount(self):
        """Stand-in for an unmount: the tree moves aside, an empty folder is left at the mount point, and the
        root reports another device (a real unmount needs root)."""
        import pinakes.scan as scanmod
        os.rename(self.top, self.top + ".mounted")
        os.makedirs(self.top)
        real_dev = os.stat(self.top + ".mounted").st_dev
        scanmod._root_dev = lambda top: real_dev + 1

    def remount(self):
        import pinakes.scan as scanmod
        shutil.rmtree(self.top)
        os.rename(self.top + ".mounted", self.top)
        scanmod._root_dev = self.real_root_dev

    def keep_root_dev(self):
        import pinakes.scan as scanmod
        self.real_root_dev = scanmod._root_dev
        self.addCleanup(setattr, scanmod, "_root_dev", scanmod._root_dev)

    def test_mass_gone_guard_not_mounted(self):
        self.keep_root_dev()
        for i in range(150):
            self.write("d/f%03d" % i, b"%d" % i)
        self.scan()
        self.drain()
        self.unmount()
        with self.assertRaises(TooManyGone) as cm:
            self.scan()
        self.assertEqual(cm.exception.cause, "not-mounted")
        self.assertNotIsInstance(cm.exception, MountChanged)
        self.assertIn("not mounted", str(cm.exception))
        self.assertFalse(any(r["t"] == "gone" for r in self.drain()))
        self.remount()
        self.scan()
        self.assertFalse(any(r["t"] == "gone" for r in self.drain()))

    def test_unmounted_during_scan(self):
        # 40 files in one folder, unmounted after the 10th: the other 30 vanish, below the mass-gone threshold,
        # so only the device check stops them being reported gone. accept_gone does not override it.
        self.keep_root_dev()
        for i in range(40):
            self.write("d/f%03d" % i, b"%d" % i)
        self.scan()
        self.drain()
        for accept in (False, True):
            self.write("d/f000", b"changed %d" % accept)  # something to send before the unmount
            calls = []

            def hook(relpath):
                calls.append(relpath)
                if len(calls) == 10:
                    self.unmount()
            scanner = Scanner(self.cfg, self.state, hook=hook)
            with self.assertRaises(MountChanged) as cm:
                scanner.scan(self.cfg.roots[0], accept_gone=accept)
            self.assertEqual(cm.exception.cause, "unmounted-during-scan")
            self.assertFalse(any(r["t"] == "gone" for r in self.drain()))
            self.remount()
        self.scan()  # resumes with the mount back: nothing gone
        recs = self.drain()
        self.assertFalse(any(r["t"] == "gone" for r in recs))
        self.assertEqual(len(list(self.state.all_files("r"))), 40)

    def test_device_unchanged_small_loss_still_reported(self):
        self.keep_root_dev()
        for i in range(40):
            self.write("d/f%03d" % i, b"%d" % i)
        self.scan()
        self.drain()
        for i in range(30):
            os.remove(os.path.join(self.top, "d/f%03d" % i))
        self.scan()
        self.assertEqual(sum(r["t"] == "gone" for r in self.drain()), 30)

    def test_changed_while_reading(self):
        p = self.write("growing", b"start")
        import pinakes.scan as scanmod
        real = scanmod.hash_file

        def hash_then_append(path, *a, **kw):
            result = real(path, *a, **kw)
            with open(path, "ab") as f:
                f.write(b" more")
            return result
        scanmod.hash_file = hash_then_append
        try:
            self.scan()
        finally:
            scanmod.hash_file = real
        rec = self.by_path(self.drain())["growing"]
        self.assertTrue(rec["unstable"])
        self.assertIsNone(rec["sha256"])
        self.scan()
        rec = self.by_path(self.drain())["growing"]
        self.assertEqual(rec["sha256"], sha(b"start more"))

    def test_tree_untouched(self):
        self.write("a", b"a")
        self.write("d/b", b"b")
        before = {}
        for dp, dn, fn in os.walk(self.top):
            for n in dn + fn:
                st = os.lstat(os.path.join(dp, n))
                before[os.path.join(dp, n)] = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode)
        self.scan()
        after = {}
        for dp, dn, fn in os.walk(self.top):
            for n in dn + fn:
                st = os.lstat(os.path.join(dp, n))
                after[os.path.join(dp, n)] = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode)
        self.assertEqual(before, after)

    def test_symlink_recorded_not_followed(self):
        self.write("real/x", b"x")
        os.symlink("real", os.path.join(self.top, "link"))
        self.scan()
        recs = self.by_path(self.drain())
        self.assertEqual(recs["link"]["t"], "symlink")
        self.assertEqual(recs["link"]["target"], "real")
        self.assertNotIn("link/x", recs)

    def test_progress_lines(self):
        for i in range(5):
            self.write("f%d" % i, b"x")
        lines = []
        self.scanner.progress = lines.append
        self.scanner.PROGRESS_EVERY = 0
        self.scan()
        self.assertEqual(len(lines), 5)
        self.assertIn("r: 5 paths walked", lines[-1])

    def test_full_resend(self):
        self.write("a", b"a")
        self.scan()
        self.drain()
        self.scan(full=True)
        recs = self.drain()
        self.assertEqual([r["path"] for r in recs if r.get("resend")], ["a"])


# user.DOSATTRIB values as Samba writes them: ndr_pack(xattr.DOSATTRIB) from Samba 4.19.5's own Python bindings
# (python3-samba), versions 1 to 5 and the 0xFFFF compat form; versions 1 to 3 begin with the attributes in hex
SAMBA_DOSATTRIB = [
    ("v1 hidden archive", "3078323200000100010000002200000000000000", 0x22),
    ("v2 hidden", "3078320002000200000000000200000000000000", 0x2),
    ("v3 hidden archive", "3078323200000300030000000100000022000000", 0x22),
    ("v4 archive", "0000040004000000010000002000000000000000", 0x20),
    ("v4 hidden archive", "0000040004000000010000002200000000000000", 0x22),
    ("v5 hidden archive", "0000050005000000010000002200000000000000", 0x22),
    ("v5 archive", "0000050005000000010000002000000000000000", 0x20),
    ("0xFFFF hidden", "30783200", 0x2),
]
SAMBA_V5_NOT_VALID = "0000050005000000000000000200000000000000"   # attrib 0x2, valid_flags without ATTRIB


def _can_xattr(directory):
    p = os.path.join(directory, ".probe")
    open(p, "w").close()
    try:
        os.setxattr(p, hidden.XATTR, b"0x20\0")
        return True
    except (AttributeError, OSError):
        return False
    finally:
        os.remove(p)


class TestHidden(Tree):
    """Hidden files: a dot in the path, or Samba's hidden attribute on the file or a folder above it."""

    def hide(self, rel, blob=bytes.fromhex(SAMBA_DOSATTRIB[5][1])):
        os.setxattr(os.path.join(self.top, rel), hidden.XATTR, blob, follow_symlinks=False)

    def need_xattr(self):
        if not _can_xattr(self.tmp):
            self.skipTest("no user extended attributes on this filesystem")

    def test_samba_values(self):
        for what, blob, attrib in SAMBA_DOSATTRIB:
            self.assertEqual(hidden.dos_attrib(bytes.fromhex(blob)), attrib, what)
        self.assertIsNone(hidden.dos_attrib(bytes.fromhex(SAMBA_V5_NOT_VALID)))   # not to be trusted
        for junk in (b"", b"\0", b"0xZZ\0", b"\0\0\x05\0\x04\0", b"\0\0\x09\0\x09\0\0\0" + bytes(8), b"text\0"):
            self.assertIsNone(hidden.dos_attrib(junk), junk)

    def test_by_name(self):
        self.write("plain.txt", b"a")
        self.write(".dotfile", b"b")
        self.write("photos/.thumbs/t.jpg", b"c")
        self.write("photos/a.jpg", b"d")
        self.scan()
        got = {r["path"]: r.get("hidden", False) for r in self.drain() if r["t"] == "file"}
        self.assertEqual(got, {"plain.txt": False, ".dotfile": True, "photos/.thumbs/t.jpg": True,
                               "photos/a.jpg": False})

    def test_by_samba_attribute_on_a_file_or_a_folder_above(self):
        self.need_xattr()
        self.write("a.txt", b"a")
        self.write("b.txt", b"b")
        self.write("private/deep/c.txt", b"c")
        self.write("open/d.txt", b"d")
        self.hide("a.txt")
        self.hide("private")
        self.hide("open", bytes.fromhex(SAMBA_DOSATTRIB[6][1]))      # the archive bit alone: not hidden
        self.scan()
        got = {r["path"]: r.get("hidden", False) for r in self.drain() if r["t"] == "file"}
        self.assertEqual(got, {"a.txt": True, "b.txt": False, "private/deep/c.txt": True, "open/d.txt": False})

    def test_a_change_of_attribute_alone_is_sent_without_rehashing(self):
        self.need_xattr()
        self.write("a.txt", b"a")
        self.write("b.txt", b"b")
        self.scan()
        self.drain()
        self.hide("a.txt")
        self.scan()
        recs = [r for r in self.drain() if r["t"] == "file"]
        self.assertEqual([(r["path"], r.get("hidden")) for r in recs], [("a.txt", True)])   # b.txt: unchanged
        self.assertEqual(self.scanner.counter.get("hashed"), 2)                            # the first scan's only
        self.hide("a.txt", bytes.fromhex(SAMBA_DOSATTRIB[6][1]))
        self.scan()
        self.assertEqual([(r["path"], r.get("hidden")) for r in self.drain() if r["t"] == "file"], [("a.txt", None)])
        self.scan()
        self.assertEqual([r for r in self.drain() if r["t"] == "file"], [])

    def test_state_from_before_hidden_files(self):
        self.write("plain.txt", b"a")
        self.write(".dotfile", b"b")
        self.scan()
        self.drain()
        self.state.close()
        db = sqlite3.connect(self.cfg.state)
        db.execute("ALTER TABLE files DROP COLUMN hidden")
        db.commit()
        db.close()
        self.state = State(self.cfg.state)
        self.scanner = Scanner(self.cfg, self.state)
        self.scan()
        self.assertEqual([(r["path"], r.get("hidden")) for r in self.drain() if r["t"] == "file"],
                         [(".dotfile", True)])                                # sent once more; plain.txt isn't


class TestBackupRoot(Tree):
    """A new hard-linked snapshot changes the link count and ctime of every inode it shares (ROADMAP 28)."""

    root_kind = "backup"
    root_extra = 'mirrors = { root = "store", layout = "*/{relpath}" }'

    def test_new_snapshot_sends_only_its_own_paths(self):
        p = self.write("2026-01-01/f.bin", b"x" * 1000)
        self.scan()
        self.drain()
        os.makedirs(os.path.join(self.top, "2026-01-02"))
        os.link(p, os.path.join(self.top, "2026-01-02/f.bin"))
        self.scan()
        self.assertEqual([(r["t"], r["path"]) for r in self.drain()], [("file", "2026-01-02/f.bin")])
        shutil.rmtree(os.path.join(self.top, "2026-01-01"))                 # pruned: its path goes
        self.scan()
        self.assertEqual([(r["t"], r["path"]) for r in self.drain()], [("gone", "2026-01-01/f.bin")])

    def test_primary_root_still_sends_link_changes(self):
        self.cfg.roots[0].kind = "primary"
        p = self.write("a/f.bin", b"x" * 1000)
        self.scan()
        self.drain()
        os.link(p, os.path.join(self.top, "a/g.bin"))
        self.scan()
        self.assertEqual(sorted(r["path"] for r in self.drain()), ["a/f.bin", "a/g.bin"])


class TestArchivesAndChunks(Tree):
    root_extra = 'archives = true\nchunks = { enabled = true, min_size = "1", average = "4KiB" }'

    def test_zip_members_and_chunks(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("one.txt", b"one")
            z.writestr("dir/two.txt", b"two")
        self.write("pack.zip", buf.getvalue())
        self.write("doc.txt", os.urandom(50000))
        self.scan()
        recs = self.by_path(self.drain())
        self.assertEqual(sorted(m[0] for m in recs["pack.zip"]["members"]), ["dir/two.txt", "one.txt"])
        self.assertEqual({m[0]: m[2] for m in recs["pack.zip"]["members"]}["one.txt"], sha(b"one"))
        self.assertTrue(recs["doc.txt"]["chunks"])
        self.assertEqual(sum(n for _, n, _ in recs["doc.txt"]["chunks"]), 50000)

    def test_corrupt_archive_is_an_error_not_a_crash(self):
        self.write("bad.zip", b"not a zip")
        self.scan()
        rec = self.by_path(self.drain())["bad.zip"]
        self.assertIn("members_error", rec)
        self.assertEqual(rec["sha256"], sha(b"not a zip"))


class TestProtected(Tree):
    root_extra = 'protected = true\nchunks = { enabled = true, min_size = "1", average = "4KiB" }'

    def test_protected_hashes_and_chunks_only(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("inner.txt", b"inner")
        self.write("draft.zip", buf.getvalue())
        self.scan()
        rec = self.by_path(self.drain())["draft.zip"]
        self.assertNotIn("members", rec)
        self.assertTrue(rec["chunks"])
        self.assertEqual(rec["sha256"], sha(buf.getvalue()))

    def test_protected_refuses_archives(self):
        with self.assertRaises(config.ConfigError):
            config.loads('[agent]\nhost="h"\nstate="s"\noutbox="o"\n[[root]]\nlabel="w"\npath="/x"\n'
                         'protected=true\narchives=true\n')


class TestProtectedByInode(unittest.TestCase):
    """A file under a protected root hard-linked into another root is protected at every path (ROADMAP 6): no
    archive listing there, and chunks only if the protected root makes them."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-test-")
        self.store = os.path.join(self.tmp, "store")
        self.writing = os.path.join(self.tmp, "writing")
        os.makedirs(self.store)
        os.makedirs(self.writing)
        self.state = None
        self.configure()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("chapter.txt", os.urandom(20000))
        self.zipped = buf.getvalue()
        self.put(self.writing, "draft.zip", self.zipped)
        self.put(self.store, "own.zip", self.zipped[:-1] + b"x")  # not linked: listed as before

    def configure(self, writing_chunks="false", store_kind="primary", writing_extra=""):
        if self.state:
            self.state.close()
        mirrors = '\nmirrors = { root = "elsewhere", layout = "{relpath}" }' if store_kind == "backup" else ""
        self.cfg = config.loads("""
[agent]
host = "test-1"
state = "%(t)s/state.sqlite"
outbox = "%(t)s/outbox"
[transport]
kind = "directory"
path = "%(t)s/inbox"
[[root]]
label = "store"
path = "%(store)s"
kind = "%(kind)s"
archives = true
chunks = { enabled = true, min_size = "1", average = "4KiB" }%(mirrors)s
[[root]]
label = "writing"
path = "%(writing)s"
protected = true
exclude = ["**/private"]
chunks = { enabled = %(wc)s, min_size = "1", average = "4KiB" }
%(wx)s
""" % {"t": self.tmp, "store": self.store, "writing": self.writing, "wc": writing_chunks, "kind": store_kind,
       "mirrors": mirrors, "wx": writing_extra})
        self.state = State(self.cfg.state)

    def tearDown(self):
        self.state.close()
        for d, subdirs, _ in os.walk(self.tmp):
            for sub in subdirs:
                os.chmod(os.path.join(d, sub), 0o755)
        shutil.rmtree(self.tmp)

    def put(self, top, rel, data):
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def link(self, rel, to):
        os.makedirs(os.path.dirname(os.path.join(self.store, to)), exist_ok=True)
        os.link(os.path.join(self.writing, rel), os.path.join(self.store, to))

    def scan_store(self):
        Scanner(self.cfg, self.state).scan(self.cfg.root("store"))
        recs = []
        for seq, path in outbox.pending(self.cfg.outbox):
            recs.extend(outbox.read(path)[1])
            outbox.ack(self.cfg.outbox, seq)
        return {r["path"]: r for r in recs if r["t"] == "file"}

    def test_linked_file_has_no_listing_and_no_chunks(self):
        self.link("draft.zip", "copies/draft.zip")
        recs = self.scan_store()
        linked, own = recs["copies/draft.zip"], recs["own.zip"]
        self.assertTrue(linked["protected_link"])
        self.assertEqual(linked["sha256"], sha(self.zipped))       # hashes, as on the protected root itself
        for key in ("members", "members_error", "chunks", "metadata"):
            self.assertNotIn(key, linked)
        self.assertIsNone(linked["chunk_params"])                  # the protected root makes no chunks
        self.assertNotIn("protected_link", own)
        self.assertTrue(own["members"])
        self.assertTrue(own["chunks"])

    def test_chunks_when_the_protected_root_makes_them(self):
        self.configure(writing_chunks="true")
        self.link("draft.zip", "copies/draft.zip")
        linked = self.scan_store()["copies/draft.zip"]
        self.assertTrue(linked["protected_link"])
        self.assertTrue(linked["chunks"])
        self.assertNotIn("members", linked)

    def test_excluded_file_is_still_under_the_root(self):
        self.put(self.writing, "private/notes.zip", self.zipped + b"2")
        self.link("private/notes.zip", "notes.zip")
        self.assertTrue(self.scan_store()["notes.zip"]["protected_link"])

    def test_link_made_or_removed_later_is_sent_again(self):
        for kind in ("primary", "backup"):  # a backup root sends no link-count change, but this one it does
            with self.subTest(kind=kind):
                self.configure(store_kind=kind)
                self.put(self.store, "pair/a.zip", self.zipped + kind.encode())
                os.link(os.path.join(self.store, "pair/a.zip"), os.path.join(self.store, "pair/b.zip"))
                first = self.scan_store()
                self.assertTrue(first["pair/a.zip"]["members"])
                self.assertNotIn("protected_link", first["pair/a.zip"])
                os.link(os.path.join(self.store, "pair/a.zip"), os.path.join(self.writing, "a-%s.zip" % kind))
                again = self.scan_store()
                self.assertEqual(set(again) & {"pair/a.zip", "pair/b.zip"}, {"pair/a.zip", "pair/b.zip"})
                self.assertTrue(again["pair/a.zip"]["protected_link"])
                self.assertNotIn("members", again["pair/b.zip"])
                self.assertEqual(self.scan_store(), {})              # settled: nothing more to send
                os.unlink(os.path.join(self.writing, "a-%s.zip" % kind))
                after = self.scan_store()
                self.assertNotIn("protected_link", after["pair/a.zip"])
                shutil.rmtree(os.path.join(self.store, "pair"))
                self.scan_store()

    @unittest.skipIf(os.geteuid() == 0, "root lists every folder")
    def test_unlistable_folder_protects_every_linked_file_on_its_disk(self):
        self.put(self.store, "x.zip", self.zipped + b"x")
        os.link(os.path.join(self.store, "x.zip"), os.path.join(self.store, "y.zip"))
        self.put(self.writing, "locked/inner.txt", b"inner")
        os.chmod(os.path.join(self.writing, "locked"), 0)
        recs = self.scan_store()
        self.assertTrue(recs["x.zip"]["protected_link"])           # can't tell: treated as protected
        self.assertNotIn("protected_link", recs["own.zip"])        # one link: no other path to it

    def test_no_walk_without_a_linked_file(self):
        walked = []
        sc = Scanner(self.cfg, self.state)
        sc._protected_inodes = lambda root: walked.append(root) or ({}, {})
        sc.scan(self.cfg.root("store"))
        self.assertEqual(walked, [])

    def test_state_from_before_gains_the_column(self):
        self.state.close()
        path = os.path.join(self.tmp, "old.sqlite")
        db = sqlite3.connect(path)
        db.executescript(SCHEMA_BEFORE_PROTECTED_LINK)
        db.execute("INSERT INTO files (root, relpath, size, seen_scan) VALUES ('store', 'a', 1, 1)")
        db.commit()
        db.close()
        self.state = State(path)
        self.assertIsNone(self.state.get("store", "a")["protected_link"])


SCHEMA_BEFORE_PROTECTED_LINK = """
CREATE TABLE files (
    root TEXT NOT NULL, relpath TEXT NOT NULL,
    size INTEGER, mtime_ns INTEGER, ctime_ns INTEGER, btime_ns INTEGER,
    dev INTEGER, ino INTEGER, nlink INTEGER, uid INTEGER,
    sha256 TEXT, chunk_params TEXT, seen_scan INTEGER,
    PRIMARY KEY (root, relpath));
"""


class TestSymlinkTargets(unittest.TestCase):
    """A symlink's target, followed only inside the agent's roots (ROADMAP 7): which root and path it leads to, and
    whether anything is there."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-test-")
        self.a, self.b, self.out = (os.path.join(self.tmp, d) for d in ("a", "b", "outside"))
        for d in (self.a, self.b, self.out):
            os.makedirs(d)
        self.cfg = config.loads("""
[agent]
host = "test-1"
state = "%(t)s/state.sqlite"
outbox = "%(t)s/outbox"
[transport]
kind = "directory"
path = "%(t)s/inbox"
[[root]]
label = "a"
path = "%(a)s"
[[root]]
label = "b"
path = "%(b)s"
""" % {"t": self.tmp, "a": self.a, "b": self.b})
        self.state = State(self.cfg.state)
        self.put(self.a, "x.txt")
        self.put(self.a, "deep/x.txt")
        self.put(self.a, "deep/sub/f.txt")
        self.put(self.b, "y.txt")
        self.put(self.out, "z.txt")

    def tearDown(self):
        self.state.close()
        shutil.rmtree(self.tmp)

    def put(self, top, rel, data=b"data"):
        p = os.path.join(top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    def ln(self, target, rel):
        p = os.path.join(self.a, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        os.symlink(target, p)

    def scan(self, **kw):
        Scanner(self.cfg, self.state).scan(self.cfg.root("a"), **kw)
        recs = []
        for seq, path in outbox.pending(self.cfg.outbox):
            recs.extend(outbox.read(path)[1])
            outbox.ack(self.cfg.outbox, seq)
        return {r["path"]: (r["link_root"], r["link_path"], r["dangling"]) for r in recs if r["t"] == "symlink"}

    def test_where_each_link_leads(self):
        self.maxDiff = None
        self.ln("../x.txt", "docs/inside")
        self.ln(os.path.join(self.b, "y.txt"), "other-root")
        self.ln("missing.txt", "dangling")
        self.ln(os.path.join(self.out, "z.txt"), "outside")
        self.ln("deep/sub", "dirlink")
        self.ln("dirlink/f.txt", "through-a-folder-link")
        self.ln("dirlink/../x.txt", "dotdot-after-a-link")      # .. after a link: the link's parent, as the kernel
        self.ln("loop-2", "loop-1")
        self.ln("loop-1", "loop-2")
        self.ln(self.b, "the-other-root")
        self.ln("x.txt/nothing", "under-a-file")
        self.assertEqual(self.scan(), {
            "docs/inside": ("a", "x.txt", False),
            "other-root": ("b", "y.txt", False),
            "dangling": ("a", "missing.txt", True),
            "outside": (None, None, None),
            "dirlink": ("a", "deep/sub", False),
            "through-a-folder-link": ("a", "deep/sub/f.txt", False),
            "dotdot-after-a-link": ("a", "deep/x.txt", False),
            "loop-1": ("a", "loop-2", True),                    # a loop: dangling
            "loop-2": ("a", "loop-1", True),
            "the-other-root": ("b", "", False),
            "under-a-file": ("a", "x.txt/nothing", True),
        })

    def test_nothing_outside_the_roots_is_looked_up(self):
        self.ln(os.path.join(self.out, "z.txt"), "outside")
        self.ln(os.path.join(self.out, "../a/x.txt"), "back-in-by-name")   # leaves the roots: not followed
        looked = []
        real = os.lstat

        def lstat(path, *args, **kw):
            looked.append(os.fspath(path))
            return real(path, *args, **kw)

        with unittest.mock.patch("os.lstat", lstat):
            recs = self.scan()
        self.assertEqual(recs["outside"], (None, None, None))
        self.assertEqual(recs["back-in-by-name"], (None, None, None))
        self.assertEqual([p for p in looked if p.startswith(self.out)], [])

    def test_target_appearing_or_going_sends_the_link_again(self):
        self.ln("later.txt", "link")
        self.assertEqual(self.scan(), {"link": ("a", "later.txt", True)})
        self.assertEqual(self.scan(), {})
        self.put(self.a, "later.txt")
        self.assertEqual(self.scan(), {"link": ("a", "later.txt", False)})
        os.unlink(os.path.join(self.a, "later.txt"))
        self.assertEqual(self.scan(), {"link": ("a", "later.txt", True)})

    def test_full_resend_keeps_a_symlink_a_symlink(self):
        self.ln("x.txt", "link")
        self.scan()
        Scanner(self.cfg, self.state).scan(self.cfg.root("a"), full=True)
        recs = [r for seq, path in outbox.pending(self.cfg.outbox) for r in outbox.read(path)[1]]
        (link,) = [r for r in recs if r.get("path") == "link"]
        self.assertEqual((link["t"], link["target"], link["link_root"], link["link_path"], link["dangling"]),
                         ("symlink", "x.txt", "a", "x.txt", False))


class TestConfig(unittest.TestCase):
    def test_example_config_loads(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cfg = config.load(os.path.join(here, "config.example.toml"))
        self.assertEqual([r.label for r in cfg.roots], ["store", "store-writing", "store-snapshots", "downloads"])
        w = cfg.root("store-writing")
        self.assertTrue(w.protected and w.chunks and not w.archives)

    def test_sizes(self):
        self.assertEqual(config.parse_size("64KiB"), 65536)
        self.assertEqual(config.parse_size("2GiB"), 2 * 1024 ** 3)
        self.assertEqual(config.parse_size("1.5MB"), 1_500_000)
        self.assertEqual(config.parse_size(10), 10)


class TestBatchFormat(Tree):
    def test_header_and_gzip(self):
        self.write("a", b"a")
        self.scan()
        (seq, path), = outbox.pending(self.cfg.outbox)
        with gzip.open(path, "rt") as f:
            header = json.loads(f.readline())
        self.assertEqual((header["t"], header["host"], header["root"], header["seq"], header["complete"]),
                         ("batch", "test-1", "r", seq, True))


class TestCheck(Tree):
    """30: the check counts a root as a scan sees it, beside the last scan, and names no file."""

    def setUp(self):
        super().setUp()
        self.write("docs/a.txt", b"aaaa")
        self.write("docs/b.txt", b"bb")
        self.write("docs/cache/skipped", b"excluded")
        self.write("docs/c.part", b"excluded too")
        os.symlink("a.txt", os.path.join(self.top, "docs/link"))
        os.mkfifo(os.path.join(self.top, "docs/fifo"))

    def check(self):
        return check(self.cfg.roots[0], self.state)

    def test_before_any_scan(self):
        c = self.check()
        self.assertIsNone(c["since"])
        self.assertEqual(check_verdict(c), "no complete scan yet")

    def test_matches_the_scan(self):
        self.scan()
        c = self.check()
        link = os.lstat(os.path.join(self.top, "docs/link")).st_size
        self.assertEqual((c["files"], c["bytes"]), (3, 6 + link))     # two files and the link; no fifo, no excluded
        self.assertEqual((c["state_files"], c["state_bytes"]), (c["files"], c["bytes"]))
        self.assertEqual((c["changed"], c["errors"]), (0, {}))
        self.assertEqual(check_verdict(c), "the disk matches the last scan")

    def test_changed_since_the_scan(self):
        self.scan()
        self.write("docs/new.txt", b"new")
        with open(os.path.join(self.top, "docs/b.txt"), "ab") as f:
            f.write(b"grown")
        c = self.check()
        self.assertEqual((c["files"] - c["state_files"], c["bytes"] - c["state_bytes"]), (1, 8))
        self.assertEqual((c["changed"], c["changed_bytes"]), (2, 10))
        self.assertIn("2 file(s) changed since", check_verdict(c))

    @unittest.skipIf(os.geteuid() == 0, "root reads every folder")
    def test_missing_rights(self):
        self.write("private/p.txt", b"p")
        self.scan()
        d = os.path.join(self.top, "private")
        os.chmod(d, 0)
        try:
            c = self.check()
        finally:
            os.chmod(d, 0o755)
        self.assertEqual(c["errors"], {"PermissionError": 1})
        self.assertEqual(c["files"], c["state_files"] - 1)
        self.assertEqual(check_verdict(c), "differs from the last scan, with errors: missing rights?")

    def test_a_file_the_scan_missed(self):
        self.scan()
        self.state.db.execute("DELETE FROM files WHERE relpath = 'docs/a.txt'")    # as if the scan had missed it
        self.assertIn("a bug", check_verdict(self.check()))

    def test_command_names_no_file(self):
        self.scan()
        path = os.path.join(self.tmp, "agent.toml")
        with open(path, "w") as f:
            f.write('[agent]\nhost = "test-1"\nstate = "%s"\noutbox = "%s"\n[[root]]\nlabel = "r"\npath = "%s"\n'
                    'exclude = ["**/cache", "**/*.part"]\n' % (self.cfg.state, self.cfg.outbox, self.top))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(agent.main(["--config", path, "check"]), 0)
        line = out.getvalue()
        self.assertIn("r: disk 3 files", line)
        self.assertIn("the disk matches the last scan", line)
        for name in ("docs", "a.txt", "b.txt", "link", self.top):
            self.assertNotIn(name, line)


class TestSshTransport(Tree):
    """What the ingester says on stderr about a batch it applied (metadata left out, progress) reaches the agent's
    journal, not only when a batch is refused. A stand-in ssh on PATH plays the forced ingest command."""

    FAKE = r"""#!%(py)s
import gzip, json, os, sys
lines = gzip.decompress(sys.stdin.buffer.read()).decode().splitlines()
seq = json.loads(lines[0])["seq"]
said = os.environ.get("FAKE_SAID", "")
if said:
    sys.stderr.write(said.replace("SEQ", str(seq)) + "\n")
if os.environ.get("FAKE_REFUSE"):
    sys.exit(3)
print("ack %%d" %% seq)
"""

    def setUp(self):
        super().setUp()
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "ssh"), "w") as f:
            f.write(self.FAKE % {"py": sys.executable})
        os.chmod(os.path.join(bindir, "ssh"), 0o755)
        self.cfg.transport = {"kind": "ssh", "target": "pinakes@server-1", "timeout": 30}
        env = {"PATH": bindir + os.pathsep + os.environ.get("PATH", "")}
        patcher = unittest.mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def send(self, said="", refuse=False):
        heard = []
        with unittest.mock.patch.dict(os.environ, {"FAKE_SAID": said, "FAKE_REFUSE": "1" if refuse else ""}):
            sent, err = transport.send_pending(self.cfg, say=heard.append)
        return sent, err, heard

    def test_what_the_ingester_said_is_passed_on(self):
        self.write("a.txt", b"a")
        self.scan()
        warning = "pinakes-ingest: host test-1 batch SEQ: metadata left out for 1 file(s), first: a.jpg exif: x"
        sent, err, heard = self.send(warning)
        self.assertEqual((sent, err), (1, None))
        self.assertEqual(heard, ["batch 1: ingest said: " + warning.replace("SEQ", "1")])
        self.assertEqual(outbox.pending(self.cfg.outbox), [])

    def test_nothing_said_nothing_logged_and_a_long_message_keeps_its_end(self):
        self.write("a.txt", b"a")
        self.scan()
        self.assertEqual(self.send()[2], [])
        self.write("b.txt", b"b")
        self.scan()
        long = "\n".join("progress line %d" % i for i in range(2000)) + "\nthe summary"
        heard = self.send(long)[2]
        self.assertEqual(heard[-1], "batch 2: ingest said: the summary")
        self.assertLessEqual(sum(len(h) for h in heard), transport.SAID_MAX + len(heard) * 30)
        self.assertTrue(all(h.startswith("batch 2: ingest said: progress line ") for h in heard[:-1]))

    def test_a_refused_batch_still_says_why_and_stays(self):
        self.write("a.txt", b"a")
        self.scan()
        sent, err, heard = self.send("refused: unknown root", refuse=True)
        self.assertEqual((sent, heard), (0, []))
        self.assertIn("refused: unknown root", err)
        self.assertEqual(len(outbox.pending(self.cfg.outbox)), 1)


class TestCheckIn(Tree):
    """Check-in before sending (pinakes-agent run): locked while the server is incompatible, scanning on and batches
    held, one line naming both sides, exit 4; unlocked by the next run once the server is in range. A stand-in ssh
    plays the server: FAKE_SERVER is its hello answer (JSON), "before" for an ingester from before check-in (it
    reads a hello as a batch and refuses it), or "down" (ssh fails to connect)."""

    FAKE = r"""#!%(py)s
import gzip, json, os, sys
mode = os.environ["FAKE_SERVER"]
if mode == "down":
    sys.stderr.write("ssh: connect to host server-1 port 22: No route to host\n")
    sys.exit(255)
data = sys.stdin.buffer.read()
log = open(os.environ["FAKE_LOG"], "a")
if sys.argv[-1] == "hello" and mode != "before":
    log.write(json.dumps({"hello": json.loads(data)}) + "\n")
    print(mode)
    sys.exit(0)
try:
    lines = gzip.decompress(data).decode().splitlines()
except OSError:
    sys.stderr.write("refused: not gzip\n")
    sys.exit(1)
header = json.loads(lines[0])
log.write(json.dumps({"batch": header}) + "\n")
print("ack %%d" %% header["seq"])
"""

    def setUp(self):
        super().setUp()
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "ssh"), "w") as f:
            f.write(self.FAKE % {"py": sys.executable})
        os.chmod(os.path.join(bindir, "ssh"), 0o755)
        self.cfg.transport = {"kind": "ssh", "target": "pinakes@server-1", "timeout": 30}
        self.log = os.path.join(self.tmp, "server.log")
        for p in (unittest.mock.patch.dict(os.environ, {"PATH": bindir + os.pathsep + os.environ.get("PATH", ""),
                                                        "FAKE_LOG": self.log}),
                  unittest.mock.patch.object(agent, "on_ac_power", return_value=True)):
            p.start()
            self.addCleanup(p.stop)

    def server(self, protocol, min_agent=0, release=2, schema_applied=True, missing=(), **more):
        return json.dumps(dict({"release": release, "protocol": protocol, "min_agent_protocol": min_agent,
                                "schema_applied": schema_applied, "upgrades_missing": list(missing)}, **more))

    def run_agent(self, server, **compat_now):
        """One `pinakes-agent run` against that server, with pinakes/compat.py's values as given: (exit, stderr
        lines, what the server got)."""
        err = io.StringIO()
        with contextlib.ExitStack() as stack:
            for k, v in compat_now.items():
                stack.enter_context(unittest.mock.patch.object(agent.compat, k, v))
            stack.enter_context(unittest.mock.patch.dict(os.environ, {"FAKE_SERVER": server}))
            stack.enter_context(contextlib.redirect_stderr(err))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            open(self.log, "w").close()
            rc = agent.cmd_run(self.cfg, argparse.Namespace(root=None))
        with open(self.log) as f:
            got = [json.loads(l) for l in f]
        return rc, err.getvalue().splitlines(), got

    def batches(self, got):
        return [g["batch"] for g in got if "batch" in g]

    def test_too_far_ahead_locks_and_unlocks_when_the_server_catches_up(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent(self.server(1), PROTOCOL=3, MIN_SERVER_PROTOCOL=2, RELEASE=13)
        self.assertEqual(rc, 4)
        self.assertEqual(self.batches(got), [])                         # nothing sent
        self.assertEqual(got[0]["hello"], {"release": 13, "protocol": 3, "min_server_protocol": 2, "next_seq": 1})
        self.assertEqual(len(err), 1)
        self.assertEqual(err[0], "pinakes-agent: locked: agent release 13 protocol 3, server release 2 protocol 1: "
                                 "the server must update (the agent (protocol 3) needs a server of protocol 2 or "
                                 "later; the server is at 1); scanning goes on, 1 batch(es) held, nothing sent until "
                                 "then")
        self.write("b.txt", b"b")                                       # still scanning, still holding
        rc, err, got = self.run_agent(self.server(1), PROTOCOL=3, MIN_SERVER_PROTOCOL=2, RELEASE=13)
        self.assertEqual((rc, self.batches(got), len(outbox.pending(self.cfg.outbox))), (4, [], 2))
        self.assertIn("2 batch(es) held", err[0])
        st = State(self.cfg.state)
        self.assertEqual(st.db.execute("SELECT count(*) FROM files").fetchone()[0], 2)   # state saved locally
        st.close()
        rc, err, got = self.run_agent(self.server(2), PROTOCOL=3, MIN_SERVER_PROTOCOL=2, RELEASE=13)  # updated
        self.assertEqual((rc, err), (0, []))
        self.assertEqual([b["seq"] for b in self.batches(got)], [1, 2, 3])  # the two held, in order, then this run's
        self.assertEqual(outbox.pending(self.cfg.outbox), [])

    def test_ahead_but_compatible_sends(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent(self.server(1), PROTOCOL=2, MIN_SERVER_PROTOCOL=1, RELEASE=12)
        self.assertEqual((rc, err), (0, []))
        (b,), = [self.batches(got)]
        self.assertEqual((b["release"], b["protocol"], b["min_server_protocol"]), (12, 2, 1))

    def test_behind_locks(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent(self.server(3, min_agent=2, release=14), PROTOCOL=1)
        self.assertEqual((rc, self.batches(got)), (4, []))
        self.assertIn("server release 14 protocol 3: the agent must update (the server (protocol 3) accepts agents "
                      "of protocol 2 or later; the agent is at 1)", err[0])

    def test_a_server_without_its_upgrade_locks(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent(self.server(1, schema_applied=False, missing=["checkins.sql"]))
        self.assertEqual((rc, self.batches(got)), (4, []))
        self.assertIn("the server must update (its catalog lacks checkins.sql)", err[0])

    def test_a_server_from_before_check_in(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent("before", MIN_SERVER_PROTOCOL=1)  # this agent needs check-in: locked
        self.assertEqual((rc, self.batches(got)), (4, []))
        self.assertIn("server from before check-in protocol 0: the server must update", err[0])
        rc, err, got = self.run_agent("before", MIN_SERVER_PROTOCOL=0)  # this one doesn't: it sends
        self.assertEqual((rc, err, len(self.batches(got))), (0, [], 2))  # the one held, and this run's

    def test_unreachable_holds_and_retries_as_before(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent("down")
        self.assertEqual(rc, 1)                                         # as a failed send always was
        self.assertEqual(len(outbox.pending(self.cfg.outbox)), 1)
        self.assertFalse(any("locked" in e for e in err))
        self.assertIn("No route to host", err[0])
        rc, err, got = self.run_agent(self.server(1))
        self.assertEqual((rc, len(self.batches(got))), (0, 2))         # the one held, and this run's

    def test_send_alone_checks_in_too(self):
        self.write("a.txt", b"a")
        self.scan()
        with unittest.mock.patch.dict(os.environ, {"FAKE_SERVER": self.server(1, min_agent=5)}), \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.cmd_send(self.cfg, argparse.Namespace()), 4)
        self.assertEqual(len(outbox.pending(self.cfg.outbox)), 1)

    def test_a_new_state_follows_the_servers_numbering(self):
        """A new machine taking over a host starts its batches at 1; the server has applied up to 87. Check-in
        answers that, and the agent renumbers what it holds and goes on after it, saying so once."""
        self.write("a.txt", b"a")
        self.scan()
        self.write("b.txt", b"b")
        self.scan()                                                     # 1 and 2 waiting
        rc, err, got = self.run_agent(self.server(2, last_seq=87, last_header_sha256=None))
        self.assertEqual(got[0]["hello"]["next_seq"], 1)
        self.assertEqual(rc, 0)
        self.assertEqual([b["seq"] for b in self.batches(got)], [88, 89, 90])  # the two held, then this run's
        self.assertEqual(err, ["pinakes-agent: the server has applied this host's batches up to 87 and this agent's "
                               "numbering was behind it (a new or restored state): 2 waiting batch(es) renumbered "
                               "1-2 to 88-89; it continues after 87"])
        rc, err, got = self.run_agent(self.server(2, last_seq=90))     # in step: nothing to say
        self.assertEqual((rc, err, got[0]["hello"]["next_seq"]), (0, [], 91))

    def test_the_last_batch_sent_again_keeps_its_number(self):
        """The first waiting batch is the server's last, its acknowledgement lost: the same header. It is sent as it
        is (the server acknowledges it as a duplicate); only what follows it would move, and it already does."""
        self.write("a.txt", b"a")
        self.scan()
        (seq, path), = outbox.pending(self.cfg.outbox)
        digest = outbox.header_digest(outbox.read(path)[0]).hex()
        rc, err, got = self.run_agent(self.server(2, last_seq=seq, last_header_sha256=digest))
        self.assertEqual(got[0]["hello"]["next_header_sha256"], digest)
        self.assertEqual((rc, err), (0, []))
        self.assertEqual([b["seq"] for b in self.batches(got)], [1, 2])
        # another batch of that number is not the same: it moves
        self.write("b.txt", b"b")
        self.scan()
        (seq, path), = outbox.pending(self.cfg.outbox)
        rc, err, got = self.run_agent(self.server(2, last_seq=seq, last_header_sha256=digest))
        self.assertEqual([b["seq"] for b in self.batches(got)], [seq + 1, seq + 2])
        self.assertIn("1 waiting batch(es) renumbered 3-3 to 4-4", err[0])

    def test_the_scrub_waits_for_a_server_of_protocol_3(self):
        """Release 6's agent scrubs after its scans, but sends scrub batches only to a server that takes them: one
        of protocol 2 (release 5) gets the scan's batch alone, one of 3 the scan's and the scrub's."""
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent(self.server(2))
        self.assertEqual((rc, err), (0, []))
        self.assertEqual([("scan" in b, "scrub" in b) for b in self.batches(got)], [(True, False)])
        self.write("b.txt", b"b")
        rc, err, got = self.run_agent(self.server(3))
        self.assertEqual((rc, err), (0, []))
        self.assertEqual([("scan" in b, "scrub" in b) for b in self.batches(got)], [(True, False), (False, True)])

    def test_a_server_before_protocol_2_answers_no_number(self):
        self.write("a.txt", b"a")
        rc, err, got = self.run_agent(self.server(1))
        self.assertEqual((rc, err, [b["seq"] for b in self.batches(got)]), (0, [], [1]))

    def test_renumber_by_hand(self):
        self.write("a.txt", b"a")
        self.scan()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(agent.cmd_renumber(self.cfg, argparse.Namespace(after=40)), 0)
            self.assertEqual(agent.cmd_renumber(self.cfg, argparse.Namespace(after=40)), 0)
        self.assertEqual(out.getvalue().splitlines()[1], "nothing to do: the next batch is already after 40")
        (seq, path), = outbox.pending(self.cfg.outbox)
        header, recs = outbox.read(path)
        self.assertEqual((seq, header["seq"], [r["path"] for r in recs]), (41, 41, ["a.txt"]))
        self.write("b.txt", b"b")
        self.scan()
        self.assertEqual([s for s, _ in outbox.pending(self.cfg.outbox)], [41, 42])

    def test_the_directory_transport_needs_no_check_in(self):
        self.cfg.transport = {"kind": "directory", "path": os.path.join(self.tmp, "inbox")}
        self.assertEqual(agent.check_in(self.cfg), ("ok", None))


class TestFullScanHeader(Tree):
    """A scan full from start to end says so in its complete batch (and whether gone is accepted): the server then
    retires what it didn't send. One resumed without --full, or never full, says nothing."""

    def complete_header(self):
        headers = [outbox.read(p)[0] for _, p in outbox.pending(self.cfg.outbox)]
        for _, p in outbox.pending(self.cfg.outbox):
            os.remove(p)
        (h,) = [h for h in headers if h["complete"]]
        return {k: h.get(k) for k in ("full", "accept_gone")}

    def test_full_and_not(self):
        for i in range(5):
            self.write("f%d.txt" % i, b"%d" % i)
        self.scan()
        self.assertEqual(self.complete_header(), {"full": None, "accept_gone": None})
        self.scan(full=True)
        self.assertEqual(self.complete_header(), {"full": True, "accept_gone": False})
        self.scan(full=True, accept_gone=True)
        self.assertEqual(self.complete_header(), {"full": True, "accept_gone": True})

    def test_resumed_without_full_is_not_full(self):
        self.cfg.batch_records = 1
        for i in range(5):
            self.write("f%d.txt" % i, b"%d" % i)
        self.scan()
        self.complete_header()

        def stop(rel):
            if rel == "f3.txt":
                raise Interrupted()
        for resumed_full, want in ((False, None), (True, True)):
            self.scanner.hook = stop
            with self.assertRaises(Interrupted):
                self.scan(full=True)
            self.scanner.hook = None
            self.scan(full=resumed_full)
            self.assertEqual(self.complete_header()["full"], want)


if __name__ == "__main__":
    unittest.main()


class TestManifests(Tree):
    """ROADMAP 19: checksum manifests (SHA256SUMS) as hints, checked against the scan's own hashes, never trusted."""

    def hints(self, recs):
        return {r["path"]: (r["verdict"], r.get("manifest")) for r in recs if r["t"] == "hint"}

    def counts(self, recs):
        return {r["path"]: {k: v for k, v in r.items() if k not in ("t", "path")} for r in recs if r["t"] == "manifest"}

    def sums(self, rel, lines):
        return self.write(rel, "".join("%s  %s\n" % (h, n) for h, n in lines).encode())

    def test_a_wrong_line_is_reported_and_a_right_one_confirmed(self):
        self.write("iso/right.iso", b"right")
        self.write("iso/changed.iso", b"changed since")
        self.sums("iso/SHA256SUMS", [(sha(b"right"), "right.iso"), (sha(b"as written"), "changed.iso")])
        s = self.scan()
        batches = []
        for seq, path in outbox.pending(self.cfg.outbox):
            header, recs = outbox.read(path)
            batches.append((header.get("complete"), recs))
            outbox.ack(self.cfg.outbox, seq)
        recs = batches[-1][1]
        self.assertTrue(batches[-1][0])                                 # in the complete batch
        self.assertEqual(self.hints(recs), {"iso/right.iso": ("confirmed", "iso/SHA256SUMS"),
                                            "iso/changed.iso": ("wrong", "iso/SHA256SUMS")})
        self.assertEqual(self.counts(recs)["iso/SHA256SUMS"], {"lines": 2, "confirmed": 1, "wrong": 1, "missing": 0,
                                                               "unchecked": 0, "bad": 0, "outside": 0})
        self.assertEqual(s["manifests"], {"manifests": 1, "wrong": 1, "missing": 0})
        # the catalog's hash is the agent's own: the manifest's never replaces it
        files = {r["path"]: r["sha256"] for _, rs in batches for r in rs if r["t"] == "file"}
        self.assertEqual(files["iso/changed.iso"], sha(b"changed since"))
        self.assertEqual([r for r in self.drain() if r["t"] in ("hint", "manifest")], [])   # unchanged: not again
        self.scan()
        self.assertEqual([r for r in self.drain() if r["t"] in ("hint", "manifest")], [])

    def test_formats(self):
        lines, bad, outside = manifests.parse(
            ("# made by hand\r\n\n%s  a b.txt\r\n%s *./bin.dat\nSHA256 (sub/c.txt) = %s\n"
             "\\%s  back\\\\slash\\nline\nnot a line\n%s  /etc/x\n%s  ../../up\n%s  ../dir/d\n"
             % (sha(b"a"), sha(b"b"), sha(b"c").upper(), sha(b"e"), sha(b"f"), sha(b"g"), sha(b"d"))).encode()
            + b"\xff\xfe  bad\n", "dir/SHA256SUMS")
        self.assertEqual(lines, [("dir/a b.txt", sha(b"a")), ("dir/bin.dat", sha(b"b")), ("dir/sub/c.txt", sha(b"c")),
                                 ("dir/back\\slash\nline", sha(b"e")), ("dir/d", sha(b"d"))])
        self.assertEqual((bad, outside), (2, 2))
        for name in ("SHA256SUMS", "x/sha256sums.txt", "a.iso.sha256", "A.ISO.SHA256"):
            self.assertTrue(manifests.is_manifest(name), name)
        for name in (".sha256", "SHA256SUMS.asc", "sha1sums", "x.sha256.bak"):
            self.assertFalse(manifests.is_manifest(name), name)

    def test_changes_follow_the_tree(self):
        self.write("a.txt", b"a")
        self.write("b.txt", b"b")
        self.sums("SHA256SUMS", [(sha(b"a"), "a.txt"), (sha(b"old b"), "b.txt"), (sha(b"c"), "c.txt")])
        self.scan()
        recs = self.drain()
        self.assertEqual(self.counts(recs)["SHA256SUMS"]["missing"], 1)
        self.write("b.txt", b"old b")                                   # put back as listed
        os.remove(os.path.join(self.top, "a.txt"))                      # a listed file goes
        self.scan()
        recs = self.drain()
        self.assertEqual(self.hints(recs), {"b.txt": ("confirmed", "SHA256SUMS"), "a.txt": (None, None)})
        self.assertEqual(self.counts(recs)["SHA256SUMS"], {"lines": 3, "confirmed": 1, "wrong": 0, "missing": 2,
                                                           "unchecked": 0, "bad": 0, "outside": 0})
        os.remove(os.path.join(self.top, "SHA256SUMS"))                 # the manifest goes: its verdicts with it
        self.scan()
        recs = self.drain()
        self.assertEqual(self.hints(recs), {"b.txt": (None, None)})
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM manifest_lines").fetchone()[0], 0)

    def test_wrong_outranks_confirmed_and_a_full_scan_sends_again(self):
        self.write("a.txt", b"a")
        self.sums("SHA256SUMS", [(sha(b"a"), "a.txt")])
        self.sums("a.txt.sha256", [(sha(b"not a"), "a.txt")])
        self.scan()
        self.assertEqual(self.hints(self.drain()), {"a.txt": ("wrong", "a.txt.sha256")})
        self.scan(full=True)
        recs = self.drain()
        self.assertEqual(self.hints(recs), {"a.txt": ("wrong", "a.txt.sha256")})
        self.assertEqual(set(self.counts(recs)), {"SHA256SUMS", "a.txt.sha256"})

    def test_read_only_when_new_and_as_hashed(self):
        self.write("a.txt", b"a")
        self.sums("SHA256SUMS", [(sha(b"a"), "a.txt")])
        reads = []
        real = manifests._read

        def counting(path):
            reads.append(path)
            return real(path)
        with unittest.mock.patch.object(manifests, "_read", counting):
            self.scan()
            self.scan()
        self.assertEqual(len(reads), 1)                                 # read once while its content is the same
        self.drain()
        self.sums("SHA256SUMS", [(sha(b"other"), "a.txt")])
        with unittest.mock.patch.object(manifests, "_read", lambda p: b"not what was hashed"):
            self.scan()                                                 # changed after hashing: not believed
        self.assertEqual([r for r in self.drain() if r["t"] in ("hint", "manifest")], [])
        self.scan()
        self.assertEqual(self.hints(self.drain()), {"a.txt": ("wrong", "SHA256SUMS")})

    def test_a_symlink_or_unhashed_file_is_unchecked(self):
        self.write("a.txt", b"a")
        os.symlink("a.txt", os.path.join(self.top, "link"))
        self.sums("SHA256SUMS", [(sha(b"a"), "link")])
        self.scan()
        recs = self.drain()
        self.assertEqual(self.hints(recs), {})
        self.assertEqual(self.counts(recs)["SHA256SUMS"]["unchecked"], 1)

    def test_off_and_waiting(self):
        self.write("a.txt", b"a")
        self.sums("SHA256SUMS", [(sha(b"a"), "a.txt")])
        self.cfg.transport = {"kind": "ssh"}
        self.state.set_meta("server_protocol", "3")                     # release 6: no manifest records
        s = self.scan()
        self.assertIn("protocol 4", s["manifests_wait"])
        self.assertEqual([r for r in self.drain() if r["t"] in ("hint", "manifest")], [])
        self.state.set_meta("server_protocol", "4")
        self.scan()
        self.assertEqual(self.hints(self.drain()), {"a.txt": ("confirmed", "SHA256SUMS")})
        self.cfg.roots[0].manifests = False                             # turned off: what was sent is taken back
        self.scan()
        recs = self.drain()
        self.assertEqual(self.hints(recs), {"a.txt": (None, None)})
        self.assertEqual(self.counts(recs), {"SHA256SUMS": {}})

    def test_config(self):
        base = '[agent]\nhost = "h"\nstate = "/s"\noutbox = "/o"\n[[root]]\nlabel = "r"\npath = "/mnt/store"\n'
        self.assertTrue(config.loads(base).roots[0].manifests)
        self.assertFalse(config.loads(base + "manifests = false\n").roots[0].manifests)
        self.assertFalse(config.loads(base + "protected = true\n").roots[0].manifests)
        self.assertFalse(config.loads(base + 'hash = "none"\n').roots[0].manifests)
        for extra in ("protected = true\nmanifests = true\n", 'hash = "none"\nmanifests = true\n',
                      'manifests = "yes"\n'):
            with self.assertRaises(config.ConfigError):
                config.loads(base + extra)


class TestManifestsProtected(Tree):
    root_extra = "protected = true"

    def test_never_read_on_a_protected_root(self):
        self.write("a.txt", b"a")
        self.write("SHA256SUMS", ("%s  a.txt\n" % sha(b"a")).encode())
        with unittest.mock.patch.object(manifests, "_read", side_effect=AssertionError("read")):
            self.scan()
        self.assertEqual([r for r in self.drain() if r["t"] in ("hint", "manifest")], [])
