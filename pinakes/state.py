"""The agent's local state (SQLite): what it last saw of every file, and its scans."""

import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    root TEXT NOT NULL, relpath TEXT NOT NULL,
    size INTEGER, mtime_ns INTEGER, ctime_ns INTEGER, btime_ns INTEGER,
    dev INTEGER, ino INTEGER, nlink INTEGER, uid INTEGER,
    sha256 TEXT, chunk_params TEXT, seen_scan INTEGER,
    PRIMARY KEY (root, relpath));
CREATE INDEX IF NOT EXISTS files_inode ON files (dev, ino);
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY, root TEXT NOT NULL, started REAL NOT NULL, finished REAL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

COLUMNS = ("size", "mtime_ns", "ctime_ns", "btime_ns", "dev", "ino", "nlink", "uid", "sha256", "chunk_params",
           "protected_link", "t", "target", "link_root", "link_path", "dangling", "meta_v", "hidden")


class State:
    def __init__(self, path):
        self.db = sqlite3.connect(path, isolation_level=None)  # transactions managed explicitly
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        have = [r["name"] for r in self.db.execute("PRAGMA table_info(files)")]
        # state from an older release: a file whose new fields aren't empty gets sent again by the next scan
        for col, typ in (("protected_link", "INTEGER"), ("t", "TEXT"), ("target", "TEXT"), ("link_root", "TEXT"),
                         ("link_path", "TEXT"), ("dangling", "INTEGER"), ("meta_v", "TEXT"), ("hidden", "INTEGER")):
            if col not in have:
                self.db.execute("ALTER TABLE files ADD COLUMN %s %s" % (col, typ))
        # full: the scan resent every file from its start (scan --full each time it ran), so the server may retire
        # what it didn't send; a scan from before this was kept counts as not full
        if "full" not in [r["name"] for r in self.db.execute("PRAGMA table_info(scans)")]:
            self.db.execute("ALTER TABLE scans ADD COLUMN full INTEGER")
        # meta_v: the schemas and versions extracted for the file ({"exif": 1} as JSON), NULL for none; a state from
        # before extraction has none, so the next scan extracts. By content: another copy here already sent it
        self.db.execute("CREATE INDEX IF NOT EXISTS files_content ON files (sha256)")
        # t: a row saved before the agent kept a file's type (27650a5) has none, and extraction asks for a regular
        # file, so it was never read. A row with a hash was a regular file then (a symlink got none); one without is
        # an old symlink, resent anyway as its type now differs, or a file not hashed, which nothing is read from.
        # Once: every row written since has its type
        if self.db.execute("SELECT 1 FROM meta WHERE key = 'types_filled'").fetchone() is None:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("UPDATE files SET t = 'file' WHERE t IS NULL AND sha256 IS NOT NULL")
            self.db.execute("INSERT INTO meta (key, value) VALUES ('types_filled', '1')")
            self.db.execute("COMMIT")

    def close(self):
        self.db.close()

    # transactions: one per batch, committed after the batch file is safely written
    def begin(self):
        self.db.execute("BEGIN IMMEDIATE")

    def commit(self):
        self.db.execute("COMMIT")

    def rollback(self):
        if self.db.in_transaction:
            self.db.execute("ROLLBACK")

    def reserve_seq(self):
        """Reserve the next batch sequence number, committed at once (outside any batch transaction).

        A crash after reserving leaves a gap, never a reused number: the ingester applies batches in increasing
        order and ignores a number it has already seen, so a reused number could lose a batch; a gap loses nothing.
        """
        assert not self.db.in_transaction
        row = self.db.execute("SELECT value FROM meta WHERE key = 'next_seq'").fetchone()
        seq = int(row["value"]) if row else 1
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('next_seq', ?)", (str(seq + 1),))
        return seq

    def next_seq(self):
        """The number the next batch will have."""
        row = self.db.execute("SELECT value FROM meta WHERE key = 'next_seq'").fetchone()
        return int(row["value"]) if row else 1

    def set_next_seq(self, seq):
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('next_seq', ?)", (str(seq),))

    def open_scan(self, root, full=False):
        """The unfinished scan of this root to resume, or a new one. A scan is full only if every run of it was."""
        row = self.db.execute("SELECT scan_id, started FROM scans WHERE root = ? AND finished IS NULL "
                              "ORDER BY scan_id DESC LIMIT 1", (root,)).fetchone()
        if row:
            if not full:
                self.db.execute("UPDATE scans SET full = 0 WHERE scan_id = ?", (row["scan_id"],))
            return row["scan_id"], row["started"], True
        now = time.time()
        cur = self.db.execute("INSERT INTO scans (root, started, full) VALUES (?, ?, ?)", (root, now, int(full)))
        return cur.lastrowid, now, False

    def scan_full(self, scan_id):
        return bool(self.db.execute("SELECT full FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()["full"])

    def finish_scan(self, scan_id):
        self.db.execute("UPDATE scans SET finished = ? WHERE scan_id = ?", (time.time(), scan_id))

    def get(self, root, relpath):
        return self.db.execute("SELECT * FROM files WHERE root = ? AND relpath = ?", (root, relpath)).fetchone()

    def by_inode(self, dev, ino, size, mtime_ns):
        """A hashed record of the same inode, unchanged in size and mtime (another link to it)."""
        return self.db.execute(
            "SELECT * FROM files WHERE dev = ? AND ino = ? AND size = ? AND mtime_ns = ? AND sha256 IS NOT NULL "
            "LIMIT 1", (dev, ino, size, mtime_ns)).fetchone()

    def extracted(self, sha256, meta_v):
        """Whether another path here has this content with these schemas extracted, so already sent."""
        return self.db.execute("SELECT 1 FROM files WHERE sha256 = ? AND meta_v = ? LIMIT 1",
                               (sha256, meta_v)).fetchone() is not None

    def put(self, root, relpath, rec, scan_id):
        self.db.execute(
            "INSERT OR REPLACE INTO files (root, relpath, %s, seen_scan) VALUES (?, ?, %s, ?)"
            % (", ".join(COLUMNS), ", ".join("?" * len(COLUMNS))),
            (root, relpath) + tuple(rec.get(c) for c in COLUMNS) + (scan_id,))

    def mark_seen(self, root, relpath, scan_id):
        self.db.execute("UPDATE files SET seen_scan = ? WHERE root = ? AND relpath = ?", (scan_id, root, relpath))

    def unseen(self, root, scan_id):
        return [r["relpath"] for r in self.db.execute(
            "SELECT relpath FROM files WHERE root = ? AND seen_scan IS NOT ? ORDER BY relpath", (root, scan_id))]

    def delete(self, root, relpath):
        self.db.execute("DELETE FROM files WHERE root = ? AND relpath = ?", (root, relpath))

    def all_files(self, root):
        return self.db.execute("SELECT * FROM files WHERE root = ? ORDER BY relpath", (root,))
