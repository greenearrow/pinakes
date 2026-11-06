"""Every SQL block in QUERIES.md runs, as a person under row-level security, on a catalog built by real scans."""

import os
import re
import time
import unittest

from tests.test_server import ServerCase, psycopg

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sql_blocks():
    with open(os.path.join(HERE, "QUERIES.md")) as f:
        text = f.read()
    blocks = re.findall(r"```sql\n(.*?)```", text, re.S)
    out = []
    for b in blocks:
        if "CREATE VIEW" in b or b.lstrip().startswith("hosts"):
            continue  # the schema sketch, not a query
        name = re.search(r"-- pinakes (\S+)", b)
        out.append((name.group(1) if name else "?", b))
    return out


class TestQueries(ServerCase):
    def setUp(self):
        super().setUp()
        t0 = time.time() - 7200
        self.write("server-1", "store", "people/user-1/notes.odt", b"notes v1", mtime=t0)
        self.write("server-1", "store", "people/user-1/budget-2026.ods", b"budget", mtime=t0)
        self.scan("server-1", "store")
        self.write("server-1", "store", "people/user-1/notes.odt", b"notes v2", mtime=t0 + 60)
        self.scan("server-1", "store")
        self.write("laptop-1", "downloads", "report.pdf", b"report", mtime=t0)
        self.write("laptop-1", "downloads", "camera/IMG_0001.JPG", b"photo", mtime=t0)
        self.write("laptop-1", "downloads", "old-phone/a.jpg", b"notes v2", mtime=t0 + 120)
        self.scan("laptop-1", "downloads")

    def test_every_query_runs(self):
        blocks = sql_blocks()
        self.assertGreaterEqual(len(blocks), 12)
        with self.as_person("user-1") as c:
            c.execute("SET search_path = pinakes, public")
            c.commit()
            for name, sql in blocks:
                with self.subTest(query=name):
                    try:
                        rows = c.execute(sql).fetchall()
                    finally:
                        c.rollback()
                    self.assertIsInstance(rows, list)

    def test_some_answers(self):
        q = dict(sql_blocks())
        with self.as_person("user-1") as c:
            c.execute("SET search_path = pinakes, public")
            c.commit()
            find = c.execute(q["find"]).fetchall()
            self.assertEqual([r[2] for r in find], ["people/user-1/budget-2026.ods"])
            only = c.execute(q["only-here"]).fetchall()
            self.assertEqual([r[0] for r in only], ["camera/IMG_0001.JPG"])
            unsafe = c.execute(q["safe-to-delete"]).fetchall()
            self.assertEqual(unsafe, [])            # old-phone/a.jpg has a copy in the store
            hist = c.execute(q["history"]).fetchall()
            self.assertEqual([r[2] for r in hist], ["new", "changed"])
            versions = c.execute(q["versions"]).fetchall()
            self.assertEqual(len({r[0] for r in versions}), 2)
            stale = c.execute(q["stale"]).fetchall()
            # server-2 is expected daily and has never reported; the laptop is never stale; server-1 just scanned
            self.assertEqual([r[0] for r in stale], ["server-2"])


if __name__ == "__main__":
    unittest.main()
