"""Completing a scan that lost many paths: the same moves as matching each gone file against every new one, and
fast at the size of a big reorganisation (tens of thousands of gone and new files). Needs PostgreSQL as
test_server.py does."""

import hashlib
import os
import random
import shutil
import tempfile
import time
import unittest

from pinakes import BATCH_FORMAT
from pinakes.ingest import Ingester, apply_schema
from tests.test_server import ServerCase, admin_conn


class _OldIngester(Ingester):
    """Move matching as release 7aa2e7a did it: every gone file against every new one. The reference."""

    def _complete_tracked(self, ctx, gone_paths):
        root_id, scan, on, after = ctx["root"]["root_id"], ctx["scan"], ctx["on"], ctx["after"]
        fields = "file_id, relpath, content_id, size, dev, ino, mtime, ctime, btime"
        new = {}
        if gone_paths:
            new = {r[0]: r for r in self.q("SELECT %s FROM pinakes.files WHERE root_id = %%s AND pending_scan = %%s "
                                           "AND gone_on IS NULL ORDER BY file_id" % fields, (root_id, scan)).fetchall()}
        touched = []
        for path in gone_paths:
            g = self.one("SELECT %s FROM pinakes.files WHERE root_id = %%s AND relpath = %%s AND gone_on IS NULL"
                         % fields, (root_id, path))
            if g is None:
                continue
            match = self._old_match_move(g, new)
            if match:
                n, kind, evidence, confidence = match
                del new[n[0]]
                self._merge_move(g, n, kind, evidence, confidence, after, on)
                if kind == "moved_changed":
                    touched.append(g[0])
            else:
                self.q("UPDATE pinakes.files SET gone_on = %s, pending_scan = NULL WHERE file_id = %s", (on, g[0]))
                self.q("INSERT INTO pinakes.history (file_id, kind, old_relpath, old_content_id, old_mtime, old_ctime, "
                       "old_btime, seen_after, seen_on) VALUES (%s, 'gone', %s, %s, %s, %s, %s, %s, %s)",
                       (g[0], g[1], g[2], g[6], g[7], g[8], after, on))
        pending = "FROM pinakes.files WHERE root_id = %s AND pending_scan = %s AND gone_on IS NULL"
        touched += [r[0] for r in self.q("SELECT file_id %s ORDER BY file_id" % pending, (root_id, scan)).fetchall()]
        self.q("INSERT INTO pinakes.history (file_id, kind, new_relpath, new_content_id, new_mtime, new_ctime, "
               "new_btime, seen_after, seen_on) SELECT file_id, 'new', relpath, content_id, mtime, ctime, btime, %%s, "
               "%%s %s ORDER BY file_id" % pending, (after, on, root_id, scan))
        touched += [r[0] for r in self.q("SELECT file_id FROM pinakes.files WHERE root_id = %s AND changed_scan = %s",
                                         (root_id, scan)).fetchall()]
        self.q("UPDATE pinakes.files SET pending_scan = NULL, changed_scan = NULL "
               "WHERE root_id = %s AND (pending_scan = %s OR changed_scan = %s)", (root_id, scan, scan))
        self.lineage_many(list(dict.fromkeys(touched)), on)

    def _old_match_move(self, g, new):
        _, gpath, gcontent, gsize, gdev, gino = g[:6]
        gname = gpath.rsplit("/", 1)[-1]
        if gcontent is not None:
            same = [n for n in new.values() if n[2] == gcontent]
            if same:
                same.sort(key=lambda n: (n[1].rsplit("/", 1)[-1] != gname, n[1]))
                return same[0], "moved", "same sha256", "certain"
        if gdev is not None:
            for n in new.values():
                if n[4] == gdev and n[5] == gino and n[3] is not None and gsize is not None and (
                        abs(n[3] - gsize) <= max(4096, 0.5 * max(gsize, 1))):
                    return n, "moved_changed", "same inode, similar size", "strong"
        if gcontent is not None:
            best = None
            for n in new.values():
                if n[2] is None:
                    continue
                r = self.one("""SELECT coalesce(sum(ca.len), 0),
                                       (SELECT sum(len) FROM pinakes.content_chunks WHERE content_id = %s)
                                FROM pinakes.content_chunks ca WHERE ca.content_id = %s AND ca.digest IN
                                     (SELECT digest FROM pinakes.content_chunks WHERE content_id = %s)""",
                             (gcontent, gcontent, n[2]))
                ov = (r[0] / r[1]) if r and r[1] else 0.0
                if ov >= self.cfg.chunk_overlap and (best is None or ov > best[1]):
                    best = (n, ov)
            if best:
                return best[0], "moved_changed", "chunks %.0f%% shared" % (100 * best[1]), "likely"
        return None


class TestMovesSameAsBefore(ServerCase):
    CHUNKS = 'chunks = { enabled = true, min_size = "1", average = "4KiB" }'

    def scenario(self, cls):
        self.reset()
        self.ing = cls(self.conn, self.scfg)
        self.ing.seed()
        self.ing.progress_every = 7  # the progress lines run too
        rnd = random.Random(11)
        big = [rnd.randbytes(30000) for _ in range(3)]
        t0 = 1700000000
        self.agent("server-1", "store", extra=self.CHUNKS)
        names = ["a.txt", "b.txt", "c.bin", "same.txt"]
        for i in range(60):
            r = i % 6
            if r == 0:
                data = b"copy %d" % (i % 4)  # several copies of a few contents, some with the same name
            elif r == 1:
                data = big[i % 3][:1000 * (i % 20)] + rnd.randbytes(5) + big[i % 3][1000 * (i % 20):]
            elif r == 2:
                data = b""  # empty files: one content, many paths
            else:
                data = rnd.randbytes(rnd.randrange(10, 3000))
            self.write("server-1", "store", "d%d/%d-%s" % (i % 5, i // 5, names[i % 4]) if i % 3 else
                       "d%d/%s" % (i % 5, names[i % 4]), data, mtime=t0 + i)
        self.scan("server-1", "store")
        top = self.agent("server-1", "store")[2]
        files = sorted(os.path.relpath(os.path.join(d, f), top) for d, _, fs in os.walk(top) for f in fs)
        rnd.shuffle(files)
        os.makedirs(os.path.join(top, "moved"))
        for k, rel in enumerate(files):
            src = os.path.join(top, rel)
            dst = "moved/" + ("%d-%s" % (k, os.path.basename(rel)) if k % 2 else rel.replace("/", "-"))
            if k % 5 == 0:
                os.remove(src)  # gone for good
            elif k % 5 == 1:
                with open(src, "ab") as f:  # edited in place, then moved: the same inode
                    f.write(b"edit")
                os.rename(src, os.path.join(top, dst))
            elif k % 5 == 2:
                with open(src, "rb") as f:  # edited, then saved as a new file elsewhere: shared chunks
                    data = f.read()
                os.remove(src)
                self.write("server-1", "store", dst, data[:len(data) // 2] + b"x" + data[len(data) // 2:])
            else:
                os.rename(src, os.path.join(top, dst))  # moved as it is
        for i in range(4):  # new copies of contents that also moved: the same-name preference decides
            self.write("server-1", "store", "extra/%d-same.txt" % i, b"copy %d" % i, mtime=t0 + 500)
        self.scan("server-1", "store")
        history = self.q("""SELECT f.relpath, h.kind, h.old_relpath, h.new_relpath, h.evidence, h.confidence
                            FROM pinakes.history h JOIN pinakes.files f USING (file_id) ORDER BY 1, 2, 3, 4""")
        catalog = self.q("SELECT relpath, gone_on IS NULL, content_id FROM pinakes.files ORDER BY 1, 2, 3")
        edges = self.q("""SELECT fr.relpath, ft.relpath, l.kind, l.evidence FROM pinakes.lineage l
                          JOIN pinakes.files fr ON fr.file_id = l.from_file_id
                          JOIN pinakes.files ft ON ft.file_id = l.to_file_id ORDER BY 1, 2, 3""")
        return history, catalog, edges

    def reset(self):
        for st, _, _ in self.agents.values():
            st.close()
        self.agents = {}
        shutil.rmtree(self.tmp)
        self.tmp = tempfile.mkdtemp(prefix="pinakes-srv-")
        with admin_conn(self.db) as c:
            c.execute("DROP SCHEMA IF EXISTS pinakes CASCADE")
            apply_schema(c)

    def test_same_history_catalog_and_lineage(self):
        old = self.scenario(_OldIngester)
        new = self.scenario(Ingester)
        kinds = {(h[1], h[4]) for h in old[0]}
        for k in [("moved", "same sha256"), ("moved_changed", "same inode, similar size"), ("gone", None),
                  ("new", None)]:
            self.assertIn(k, kinds)
        self.assertTrue(any(e and e.startswith("chunks") for _, e in kinds), kinds)
        self.assertEqual(new[0], old[0])
        self.assertEqual(new[1], old[1])
        self.assertEqual(new[2], old[2])


class TestMovesAtScale(ServerCase):
    """Like the reorganisation that timed out: ~40k files gone outside the roots, ~37k new; a few moves."""

    GONE, NEW, MOVED = 40000, 37000, 500
    LIMIT = 60  # seconds for the completing batch (about 5 here); the agent waits 600 by default

    def batch(self, seq, scan, records, complete=False):
        header = {"t": "batch", "format": BATCH_FORMAT, "host": "server-1", "root": "store", "scan": scan, "seq": seq,
                  "started": "2024-0%d-01T00:00:00Z" % scan,
                  "root_def": {"path": "/mnt/store", "kind": "primary"}}
        if complete:
            header["complete"] = True
        return self.ing.apply(header, records, "server-1")

    def test_completing_is_fast(self):
        def rec(path, i, ino):
            return {"t": "file", "path": path, "size": 100 + i % 50, "mtime_ns": 1700000000000000000 + i,
                    "ctime_ns": 1700000000000000000 + i, "dev": 1, "ino": ino, "nlink": 1, "uid": 1000,
                    "sha256": hashlib.sha256(b"%d" % i).hexdigest()}
        old = [rec("old/%d/f%d.txt" % (i % 100, i), i, i) for i in range(self.GONE)]
        seq = 0
        for k in range(0, len(old), 5000):
            seq += 1
            self.assertEqual(self.batch(seq, 1, old[k:k + 5000], complete=k + 5000 >= len(old)), "applied")
        # scan 2: MOVED of the old files at new paths (same content), the rest new contents; every old path gone
        new = [rec("new/%d/m%d.txt" % (i % 100, i), i, i) for i in range(self.MOVED)]
        new += [rec("new/%d/n%d.txt" % (i % 100, i), self.GONE + i, self.GONE + i) for i in range(self.NEW - self.MOVED)]
        for k in range(0, len(new), 5000):
            seq += 1
            self.batch(seq, 2, new[k:k + 5000])
        seq += 1
        t = time.monotonic()
        self.assertEqual(self.batch(seq, 2, [{"t": "gone", "path": r["path"]} for r in old], complete=True), "applied")
        took = time.monotonic() - t
        print("\n%d gone, %d new: completing took %.1f s" % (self.GONE, self.NEW, took))
        self.assertLess(took, self.LIMIT)
        counts = dict(self.q("SELECT kind, count(*) FROM pinakes.history WHERE seen_on = '2024-02-01' GROUP BY kind"))
        self.assertEqual(counts, {"moved": self.MOVED, "gone": self.GONE - self.MOVED, "new": self.NEW - self.MOVED})
        self.assertEqual(self.q("SELECT count(*) FROM pinakes.files WHERE gone_on IS NULL")[0][0], self.NEW)


if __name__ == "__main__":
    unittest.main()
