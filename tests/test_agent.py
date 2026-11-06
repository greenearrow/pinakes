"""Agent tests on generated trees in a temporary directory. Standard library only: python3 -m unittest."""

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import zipfile

from pinakes import chunker, config, fsinfo, globs, outbox
from pinakes.scan import Interrupted, MountChanged, Scanner, TooManyGone
from pinakes.state import State


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Tree(unittest.TestCase):
    """A root with files, an agent config and state in a temporary directory."""

    root_extra = ""

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
kind = "primary"
exclude = ["**/cache", "**/*.part"]
%(extra)s
""" % {"t": self.tmp, "top": self.top, "extra": self.root_extra})
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


if __name__ == "__main__":
    unittest.main()
