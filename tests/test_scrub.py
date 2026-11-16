"""The scrub (ROADMAP 41, DESIGN.md "Scrub") on generated trees in a temporary directory. Standard library only.

The filesystem a root is on is found through a mount table and a /dev/disk/by-uuid folder made by the test, so the
ids are the test's own and no real device is named.
"""

import argparse
import contextlib
import errno
import io
import json
import os
import shutil
import tempfile
import time
import unittest
import unittest.mock

from pinakes import agent, compat, config, outbox, scrub
from pinakes.scan import Scanner, hash_file
from pinakes.state import State

UUID = "0f0e0d0c-0b0a-4908-8706-050403020100"
DAY = 86400.0


class ScrubTree(unittest.TestCase):
    """A root on a filesystem the test describes, an agent config, state and scrub file in a temporary directory."""

    root_extra = ""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pinakes-scrub-")
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
%(extra)s
""" % {"t": self.tmp, "top": self.top, "extra": self.root_extra})
        self.state = State(self.cfg.state)
        self.scanner = Scanner(self.cfg, self.state)
        # the mount table and by-uuid folder: the tree's own device, mounted at the temporary folder, from a
        # stand-in device file whose uuid link is the test's
        dev = os.stat(self.top).st_dev
        self.devfile = os.path.join(self.tmp, "dev-1")
        open(self.devfile, "w").close()
        self.by_uuid = os.path.join(self.tmp, "by-uuid")
        os.makedirs(self.by_uuid)
        os.symlink(self.devfile, os.path.join(self.by_uuid, UUID))
        self.mountinfo = os.path.join(self.tmp, "mountinfo")
        self.mount_table("36 25 %d:%d / %s rw,relatime - ext4 %s rw\n"
                         % (os.major(dev), os.minor(dev), self.tmp, self.devfile))
        self.fsid = "uuid:" + UUID
        self.reads = []
        self.fail = {}                               # path -> errno: reading it fails so
        self.clock = time.time() + 60                # the scrub's clock: after the scans, which use the real one

    def tearDown(self):
        self.state.close()
        shutil.rmtree(self.tmp)

    def mount_table(self, text):
        with open(self.mountinfo, "w") as f:
            f.write(text)

    def write(self, rel, data):
        p = os.path.join(self.top, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def corrupt(self, rel, at=0):
        """Change one byte of a file and put its mtime back, as a disk returning other bytes would look."""
        p = os.path.join(self.top, rel)
        st = os.stat(p)
        with open(p, "r+b") as f:
            f.seek(at)
            b = f.read(1)
            f.seek(at)
            f.write(bytes([b[0] ^ 0xFF]))
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))

    def scan(self, **kw):
        s = self.scanner.scan(self.cfg.roots[0], **kw)
        self.drain()
        return s

    def read(self, path, params=None):
        self.reads.append(os.path.relpath(path, self.top))
        if path in self.fail:
            raise OSError(self.fail[path], os.strerror(self.fail[path]))
        return hash_file(path, params)

    def scrubber(self, hook=None):
        return scrub.Scrubber(self.cfg, self.state, scrub.Filesystems(self.mountinfo, self.by_uuid), hook=hook,
                              now=lambda: self.clock, read=self.read)

    def set_days(self, days):
        with open(self.cfg.scrub, "w") as f:
            f.write('[[filesystem]]\nid = "%s"\ndays = %d\n' % (self.fsid, days))

    def run_scrub(self, hook=None, **kw):
        """One scrub run: (its results, the batches it wrote as (header, records))."""
        res = self.scrubber(hook).run(**kw)
        return res, self.drain()

    def drain(self):
        got = []
        for seq, path in outbox.pending(self.cfg.outbox):
            got.append(outbox.read(path))
            outbox.ack(self.cfg.outbox, seq)
        return got

    def verified(self, rel):
        return self.state.db.execute("SELECT verified FROM files WHERE relpath = ?", (rel,)).fetchone()[0]


class TestFilesystems(ScrubTree):
    def test_by_uuid_through_the_source_device(self):
        fs = scrub.Filesystems(self.mountinfo, self.by_uuid).of(self.top)
        self.assertEqual(fs, scrub.Filesystem(self.fsid, self.tmp, "ext4", self.devfile))
        self.assertEqual(scrub.default_days(fs), 30)

    def test_a_device_link_resolved_on_both_sides(self):
        """/dev/disk/by-uuid links lead to ../../sdX and the mount table may name /dev/mapper/NAME: compared by where
        they lead, not by name."""
        alias = os.path.join(self.tmp, "alias")
        os.symlink(self.devfile, alias)
        dev = os.stat(self.top).st_dev
        self.mount_table("36 25 %d:%d / %s rw - xfs %s rw\n" % (os.major(dev), os.minor(dev), self.tmp, alias))
        self.assertEqual(scrub.Filesystems(self.mountinfo, self.by_uuid).of(self.top).id, self.fsid)

    def test_no_uuid_the_mount_source_and_a_network_filesystem_is_off(self):
        dev = os.stat(self.top).st_dev
        self.mount_table("36 25 %d:%d / %s rw - nfs4 server-2:/export/media rw\n"
                         % (os.major(dev), os.minor(dev), self.tmp))
        fs = scrub.Filesystems(self.mountinfo, self.by_uuid).of(self.top)
        self.assertEqual((fs.id, fs.fstype, scrub.default_days(fs)), ("source:server-2:/export/media", "nfs4", 0))

    def test_the_innermost_mount_and_escaped_names(self):
        inner = os.path.join(self.tmp, "a b")
        os.makedirs(inner)
        dev = os.stat(self.top).st_dev
        mm = "%d:%d" % (os.major(dev), os.minor(dev))
        self.mount_table("36 25 %s / / rw - ext4 /dev/other rw\n37 36 %s / %s rw - zfs pool/data rw\n"
                         % (mm, mm, inner.replace(" ", "\\040")))
        fs = scrub.Filesystems(self.mountinfo, self.by_uuid).of(inner)
        self.assertEqual((fs.id, fs.mount), ("source:pool/data", inner))

    def test_a_device_not_in_the_table_by_its_number(self):
        self.mount_table("")
        dev = os.stat(self.top).st_dev
        self.assertEqual(scrub.Filesystems(self.mountinfo, self.by_uuid).of(self.top).id,
                         "dev:%d:%d" % (os.major(dev), os.minor(dev)))


class TestScrubFile(ScrubTree):
    def test_written_with_the_defaults_then_appended_never_rewritten(self):
        self.write("a.txt", b"alpha")
        self.scan()
        sc = self.scrubber()
        sc.run()
        with open(self.cfg.scrub) as f:
            text = f.read()
        self.assertTrue(text.startswith(scrub.FILE_HEADER))
        self.assertEqual(scrub.load_file(self.cfg.scrub), {self.fsid: 30})
        self.assertIn("# %s, ext4; root r" % self.tmp, text)
        self.assertEqual(sc.notes, ["scrub: %s (%s) added to %s with days = 30" % (self.fsid, self.tmp,
                                                                                    self.cfg.scrub)])
        # the person changes the number and adds a comment; a second filesystem appears (another root, elsewhere)
        with open(self.cfg.scrub, "w") as f:
            f.write(text.replace("days = 30", "days = 14  # the old disk") + "# mine\n")
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        dev = os.stat(self.top).st_dev
        with open(self.mountinfo, "a") as f:
            f.write("37 25 %d:%d / %s rw - nfs4 server-2:/export rw\n" % (os.major(dev), os.minor(dev), other))
        self.cfg.roots.append(config.Root({"label": "net", "path": other}))
        sc = self.scrubber()
        sc.run()
        with open(self.cfg.scrub) as f:
            after = f.read()
        self.assertTrue(after.startswith(text.replace("days = 30", "days = 14  # the old disk") + "# mine\n"))
        self.assertEqual(scrub.load_file(self.cfg.scrub), {self.fsid: 14, "source:server-2:/export": 0})
        sc = self.scrubber()
        sc.run()
        with open(self.cfg.scrub) as f:
            self.assertEqual(f.read(), after)                                   # nothing new: untouched
        self.assertEqual(sc.notes, [])

    def test_a_wrong_number_is_refused_naming_the_file(self):
        for bad in ("days = -1", "days = 9999", 'days = "30"', "days = true", "dayz = 3"):
            with open(self.cfg.scrub, "w") as f:
                f.write('[[filesystem]]\nid = "uuid:x"\n%s\n' % bad)
            with self.assertRaisesRegex(config.ConfigError, "^%s" % self.cfg.scrub):
                scrub.load_file(self.cfg.scrub)
        with open(self.cfg.scrub, "w") as f:
            f.write('[[filesystem]]\nid = "uuid:x"\ndays = 1\n[[filesystem]]\nid = "uuid:x"\ndays = 2\n')
        with self.assertRaisesRegex(config.ConfigError, "listed twice"):
            scrub.load_file(self.cfg.scrub)

    @unittest.skipIf(os.geteuid() == 0, "root writes anywhere")
    def test_unwritable_uses_the_default_and_says_so(self):
        self.write("a.txt", b"alpha")
        self.scan()
        self.cfg.scrub = os.path.join(self.tmp, "ro", "scrub.toml")
        os.makedirs(os.path.dirname(self.cfg.scrub))
        os.chmod(os.path.dirname(self.cfg.scrub), 0o555)
        try:
            sc = self.scrubber()
            res = sc.run()
        finally:
            os.chmod(os.path.dirname(self.cfg.scrub), 0o755)
        self.assertEqual(res[0]["days"], 30)
        self.assertEqual(len(sc.notes), 1)
        self.assertIn("can't write the scrub file", sc.notes[0])
        self.assertIn(self.fsid, sc.notes[0])

    def test_the_default_path_is_beside_agent_toml(self):
        p = os.path.join(self.tmp, "agent.toml")
        with open(p, "w") as f:
            f.write('[agent]\nhost = "h"\nstate = "/var/lib/pinakes/state.sqlite"\noutbox = "/var/lib/pinakes/o"\n')
        self.assertEqual(config.load(p).scrub, os.path.join(self.tmp, "scrub.toml"))
        with open(p, "a") as f:
            f.write('scrub = "/etc/pinakes/elsewhere.toml"\nscrub_max_minutes = 30\n')
        c = config.load(p)
        self.assertEqual((c.scrub, c.scrub_max_minutes), ("/etc/pinakes/elsewhere.toml", 30))


class TestScrub(ScrubTree):
    def test_a_flipped_byte_under_the_same_mtime_is_a_mismatch_not_an_edit(self):
        self.write("a.txt", b"alpha" * 100)
        self.write("b.txt", b"beta" * 100)
        self.scan()
        self.set_days(1)                                     # a full pass a night: everything is read
        before = self.verified("a.txt")
        self.assertIsNotNone(before)                         # hashed by the scan: verified then
        self.clock += DAY
        self.corrupt("a.txt")
        self.assertEqual(self.scan()["sent"], 1)             # the scan sees only the ctime: no rehash, no change
        res, got = self.run_scrub()
        self.assertEqual((res[0]["mismatches"], res[0]["unreadable"], res[0]["files"]), (1, 0, 2))
        (header, recs), = got
        self.assertEqual(header["scrub"]["mismatches"], 1)
        self.assertNotIn("scan", header)
        (rec,), = [recs]
        with open(os.path.join(self.top, "a.txt"), "rb") as f:
            now_sha = hash_file(f.name)[0]
        st = os.stat(os.path.join(self.top, "a.txt"))
        self.assertEqual(rec, {"t": "mismatch", "path": "a.txt", "size": 500, "mtime_ns": st.st_mtime_ns,
                               "dev": st.st_dev, "ino": st.st_ino, "sha256": now_sha,
                               "verified": scrub._date(before), "chunk_params": None})
        row = self.state.db.execute("SELECT sha256, verified, meta_v FROM files WHERE relpath = 'a.txt'").fetchone()
        self.assertEqual((row[0], row[1], row[2]), (now_sha, self.clock, None))
        self.clock += DAY
        res, got = self.run_scrub()                          # found once: the next run finds it right
        self.assertEqual((res[0]["mismatches"], got[0][1]), (0, []))

    def test_an_edit_that_moves_the_mtime_is_left_to_the_scan(self):
        p = self.write("a.txt", b"alpha")
        self.scan()
        self.set_days(1)
        with open(p, "ab") as f:
            f.write(b" more")
        os.utime(p, ns=(os.stat(p).st_atime_ns, os.stat(p).st_mtime_ns + 10**9))
        res, got = self.run_scrub()
        self.assertEqual((res[0]["files"], res[0]["mismatches"], got[0][1]), (0, 0, []))   # not read, not sent
        self.assertEqual(self.reads, [])

    def test_a_read_error_is_sent_once_and_its_clearing_too(self):
        p = self.write("a.txt", b"alpha")
        self.scan()
        self.set_days(1)
        v = self.verified("a.txt")
        self.fail[p] = errno.EIO
        res, got = self.run_scrub()
        self.assertEqual(res[0]["unreadable"], 1)
        self.assertEqual(got[0][1], [{"t": "unreadable", "path": "a.txt", "error": "EIO"}])
        self.assertEqual(got[0][0]["scrub"]["unreadable"], 1)
        self.assertEqual(self.verified("a.txt"), v)                         # not verified: first again next time
        self.clock += DAY
        res, got = self.run_scrub()
        self.assertEqual((res[0]["unreadable"], got[0][1]), (1, []))        # still failing: not sent again
        del self.fail[p]
        self.clock += DAY
        res, got = self.run_scrub()
        self.assertEqual(got[0][1], [{"t": "readable", "path": "a.txt"}])
        self.assertEqual(self.verified("a.txt"), self.clock)

    def test_days_zero_reads_nothing(self):
        self.write("a.txt", b"alpha")
        self.scan()
        self.set_days(0)
        res, got = self.run_scrub()
        self.assertEqual((res[0]["skipped"], self.reads, got), ("off", [], []))

    def test_the_budget_and_the_catch_up_cap(self):
        for i in range(20):
            self.write("f%02d" % i, bytes([i]) * 1000)
        self.scan()
        self.set_days(10)                                  # 20 000 bytes over 10 days: 2000 a night
        res, _ = self.run_scrub()                          # a first run counts as one night
        self.assertEqual((res[0]["budget"], res[0]["files"]), (2000.0, 2))
        self.clock += 30 * DAY                             # off for a month: at most seven nights' share
        res, _ = self.run_scrub()
        self.assertEqual((res[0]["budget"], res[0]["files"]), (14000.0, 14))
        self.clock += 2 * DAY
        res, _ = self.run_scrub()
        self.assertEqual(res[0]["files"], 4)               # the rest, then those checked longest ago
        self.assertEqual(len(set(self.reads)), 20)         # every file once before any twice

    def test_max_minutes_ends_the_run(self):
        for i in range(5):
            self.write("f%d" % i, bytes([i]) * 100)
        self.scan()
        self.set_days(1)

        def tick(root, rel):
            self.clock += 25                               # each file takes 25 seconds
        res, _ = self.run_scrub(hook=tick, max_minutes=1)
        self.assertEqual(res[0]["files"], 3)               # 0, 25, 50 seconds in; the fourth would start at 75

    def test_a_hard_linked_inode_is_read_once(self):
        p = self.write("a.txt", b"alpha" * 10)
        os.link(p, os.path.join(self.top, "b.txt"))
        self.scan()
        self.set_days(1)
        self.corrupt("a.txt")
        res, got = self.run_scrub()
        self.assertEqual((self.reads, res[0]["files"], res[0]["bytes"]), (["a.txt"], 1, 50))
        self.assertEqual(sorted(r["path"] for r in got[0][1]), ["a.txt", "b.txt"])   # both paths' records
        self.assertEqual(self.verified("a.txt"), self.verified("b.txt"))

    def test_interrupted_it_resumes_where_it_stopped(self):
        for i in range(6):
            self.write("f%d" % i, bytes([i]) * 100)
        self.scan()
        self.set_days(1)
        self.corrupt("f0")

        def stop_at_third(root, rel):
            if len(self.reads) == 2:
                raise scrub.Interrupted()
        with self.assertRaises(scrub.Interrupted):
            self.run_scrub(hook=stop_at_third)
        self.assertEqual(outbox.pending(self.cfg.outbox), [])          # nothing written
        first = list(self.reads)
        confirmed = [r for r in first if self.verified(r) == self.clock]
        self.assertEqual(len(confirmed), 1)                             # f0's mismatch wasn't kept: found again
        self.reads.clear()
        self.clock += DAY
        res, got = self.run_scrub()
        self.assertEqual(res[0]["files"], 6)                            # a full pass: the five not confirmed
        self.assertEqual(self.reads[-1], confirmed[0])                  # first, the one confirmed last
        self.assertEqual([r["path"] for r in got[0][1]], ["f0"])

    def test_after_a_complete_scan_only(self):
        self.write("a.txt", b"alpha")
        self.scan()
        self.set_days(1)
        self.state.open_scan("r")                                       # one unfinished
        res, got = self.run_scrub()
        self.assertEqual((res[0]["skipped"], self.reads, got), ("a scan of a root on it is unfinished", [], []))

    def test_a_metadata_change_keeps_when_it_was_verified(self):
        p = self.write("a.txt", b"alpha")
        self.scan()
        v = self.verified("a.txt")
        os.chmod(p, 0o600)                                              # ctime only
        self.clock += DAY
        self.scan()
        self.assertEqual(self.verified("a.txt"), v)
        with open(p, "ab") as f:                                        # rewritten: read now
            f.write(b"!")
        self.scan()
        self.assertGreater(self.verified("a.txt"), v)

    def test_the_summary_and_the_fields_declared(self):
        self.write("a.txt", b"alpha" * 10)
        self.write("b.txt", b"beta" * 10)
        self.scan()
        self.set_days(2)
        self.state.db.execute("UPDATE files SET verified = NULL WHERE relpath = 'b.txt'")
        self.corrupt("a.txt")
        res, got = self.run_scrub()
        (header, recs), = got
        self.assertEqual(self.reads, ["b.txt", "a.txt"])                # never checked first
        self.assertEqual(header["scrub"], {"on": scrub._date(self.clock), "days": 2, "oldest": scrub._date(
            self.state.db.execute("SELECT min(verified) FROM files").fetchone()[0]), "never": 0,
            "mismatches": 1, "unreadable": 0})
        self.assertEqual(set(header) - set(compat.BATCH_FIELDS["header"]), set())
        self.assertEqual(set(header["scrub"]) - set(compat.BATCH_FIELDS["scrub"]), set())
        for r in recs:
            self.assertEqual(set(r) - set(compat.BATCH_FIELDS[r["t"]]), set())


class TestScrubChunked(ScrubTree):
    root_extra = 'chunks = { enabled = true, min_size = "1KiB" }'

    def test_a_mismatch_carries_the_new_chunks(self):
        self.write("big.bin", os.urandom(100_000))
        self.scan()
        self.set_days(1)
        self.corrupt("big.bin", at=50_000)
        _, got = self.run_scrub()
        (rec,), = [got[0][1]]
        self.assertTrue(rec["chunk_params"])
        self.assertEqual(sum(c[1] for c in rec["chunks"]), 100_000)


class TestScrubProtected(ScrubTree):
    root_extra = "protected = true"

    def test_a_protected_root_is_scrubbed_hashes_only(self):
        self.write("a.txt", b"alpha")
        self.scan()
        self.set_days(1)
        self.corrupt("a.txt")
        _, got = self.run_scrub()
        self.assertEqual([r["t"] for r in got[0][1]], ["mismatch"])
        self.assertNotIn("meta", got[0][1][0])
        self.assertTrue(got[0][0]["root_def"]["protected"])


class TestAgentCommand(ScrubTree):
    def test_waits_for_a_server_that_takes_it(self):
        self.write("a.txt", b"alpha")
        self.scan()
        self.cfg.transport = {"kind": "ssh", "target": "pinakes@server-1", "timeout": 30}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            agent.run_scrub(self.cfg, self.state)
        self.assertEqual(out.getvalue(), "scrub: not run: the server hasn't checked in yet; the scrub waits for one "
                                         "of protocol 2 or later\n")
        self.state.set_meta("server_protocol", "1")
        self.assertIsNotNone(agent.scrub_waits(self.cfg, self.state))
        self.state.set_meta("server_protocol", "2")
        self.assertIsNone(agent.scrub_waits(self.cfg, self.state))
        self.cfg.transport = {"kind": "directory", "path": os.path.join(self.tmp, "inbox")}
        self.state.set_meta("server_protocol", "0")
        self.assertIsNone(agent.scrub_waits(self.cfg, self.state))       # an agent on the server itself

    def test_status(self):
        self.write("a.txt", b"alpha" * 10)
        self.scan()
        self.set_days(10)
        made = scrub.Filesystems
        with unittest.mock.patch.object(scrub, "Filesystems", lambda: made(self.mountinfo, self.by_uuid)), \
                contextlib.redirect_stdout(io.StringIO()):
            agent.cmd_scrub(self.cfg, argparse.Namespace(what=None))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                agent.cmd_scrub(self.cfg, argparse.Namespace(what="status"))
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "scrub file: %s" % self.cfg.scrub)
        self.assertRegex(lines[1], r"^%s \(%s, ext4; root r\): days 10, 0.0 GB, 0.0 GB a night; oldest check "
                                   r"\d{4}-\d\d-\d\d, 0 file\(s\) never checked; last run .*: 1 files, 0.0 GB, "
                                   r"0 mismatch\(es\), 0 unreadable$" % (self.tmp, self.fsid))


if __name__ == "__main__":
    unittest.main()
