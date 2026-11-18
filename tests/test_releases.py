"""The release manifest (RELEASES.toml), pinakes/compat.py and tools/latest-release. Standard library only.

The protocol guard: the batch fields, the agent's state and the catalog's schema are fingerprinted, and the newest
release records the fingerprint of its protocol. Changing any of them without raising compat.PROTOCOL fails here.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

import pinakes
from pinakes import BATCH_FORMAT, BATCH_FORMATS, compat, config, outbox
from pinakes.config import tomllib
from pinakes.scan import Scanner
from pinakes.state import State

import jpegs

HERE = os.path.dirname(os.path.abspath(__file__))
TOP = os.path.dirname(HERE)
MANIFEST = os.path.join(TOP, "RELEASES.toml")
PACKAGE = os.path.dirname(os.path.abspath(pinakes.__file__))   # as installed: a wheel's own copy
UPGRADES = os.path.join(PACKAGE, "upgrades")
ROLES = ("server", "agent", "cli")
FIELDS = {"id": int, "affects": list, "protocol": int, "min_agent_protocol": int, "min_server_protocol": int,
          "upgrade_sql": list, "note": str, "fingerprint": dict}
REQUIRED = ("id", "affects", "protocol", "min_agent_protocol", "min_server_protocol", "upgrade_sql")


def load_manifest(path=MANIFEST):
    with open(path, "rb") as f:
        return tomllib.load(f)


def validate(manifest, upgrade_files):
    """Every problem with a manifest, as messages; [] if none."""
    errs = []
    rels = manifest.get("release")
    if set(manifest) != {"release"} or not isinstance(rels, list) or not rels:
        return ["the manifest is [[release]] entries and nothing else"]
    named = {}
    for i, r in enumerate(rels, 1):
        where = "release %s" % r.get("id", "#%d" % i)
        for k in REQUIRED:
            if k not in r:
                errs.append("%s: no %s" % (where, k))
        for k, v in r.items():
            if k not in FIELDS:
                errs.append("%s: unknown field %s" % (where, k))
            elif not isinstance(v, FIELDS[k]) or isinstance(v, bool):
                errs.append("%s: %s must be a %s" % (where, k, FIELDS[k].__name__))
        if errs:
            continue
        if r["id"] != i:
            errs.append("%s: ids go 1, 2, 3, ...; expected %d" % (where, i))
        if not r["affects"] or len(set(r["affects"])) != len(r["affects"]) or set(r["affects"]) - set(ROLES):
            errs.append("%s: affects must name one or more of %s, once each" % (where, ", ".join(ROLES)))
        if min(r["protocol"], r["min_agent_protocol"], r["min_server_protocol"]) < 0:
            errs.append("%s: protocols are 0 or more" % where)
        if r["min_agent_protocol"] > r["protocol"] or r["min_server_protocol"] > r["protocol"]:
            errs.append("%s: a release can't need a protocol above its own" % where)
        if i > 1 and r["protocol"] < rels[i - 2].get("protocol", 0):
            errs.append("%s: protocol went down" % where)
        if r["protocol"] >= 1 and set(r.get("fingerprint", {})) != {"batch", "state", "schema"}:
            errs.append("%s: from protocol 1 a release has fingerprint = {batch, state, schema}" % where)
        for u in r["upgrade_sql"]:
            if u not in upgrade_files:
                errs.append("%s: upgrade_sql %s is not in pinakes/upgrades" % (where, u))
            if u in named:
                errs.append("%s: upgrade_sql %s is already release %d's" % (where, u, named[u]))
            named[u] = r["id"]
        if r["upgrade_sql"] and "server" not in r["affects"]:
            errs.append("%s: an upgrade_sql is the server's" % where)
    for u in sorted(set(upgrade_files) - set(named)):
        errs.append("pinakes/upgrades/%s belongs to no release" % u)
    return errs


def _sql(text):
    return " ".join(re.sub(r"--[^\n]*", "", text).split())


def _h(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def fingerprints():
    """What compat.PROTOCOL stands for, now: the batch fields, the state's tables, the schema and its upgrades."""
    batch = {"format": BATCH_FORMAT, "formats": list(BATCH_FORMATS),
             "fields": {k: sorted(v) for k, v in compat.BATCH_FIELDS.items()}}
    tmp = tempfile.mkdtemp(prefix="pinakes-fp-")
    try:
        st = State(os.path.join(tmp, "state.sqlite"))
        tables = sorted([r[0], r[1], " ".join((r[2] or "").split())]
                        for r in st.db.execute("SELECT type, name, sql FROM sqlite_master"))
        meta = sorted(r[0] for r in st.db.execute("SELECT key FROM meta"))
        st.close()
    finally:
        shutil.rmtree(tmp)
    with open(os.path.join(PACKAGE, "schema.sql")) as f:
        schema = [_sql(f.read())]
    for name in sorted(os.listdir(UPGRADES)):
        with open(os.path.join(UPGRADES, name)) as f:
            schema.append([name, _sql(f.read())])
    schema.append(sorted(compat.UPGRADE_PROBES.items()))
    return {"batch": _h(batch), "state": _h({"tables": tables, "meta": meta}), "schema": _h(schema)}


def upgrade_files():
    return sorted(n for n in os.listdir(UPGRADES) if n.endswith(".sql"))


@unittest.skipUnless(os.path.exists(MANIFEST), "no RELEASES.toml beside tests/")
class TestManifest(unittest.TestCase):
    def setUp(self):
        self.m = load_manifest()
        self.rels = self.m["release"]

    def test_valid(self):
        self.assertEqual(validate(self.m, upgrade_files()), [])

    def test_the_code_is_the_newest_release(self):
        r = self.rels[-1]
        self.assertEqual((compat.RELEASE, compat.PROTOCOL, compat.MIN_AGENT_PROTOCOL, compat.MIN_SERVER_PROTOCOL),
                         (r["id"], r["protocol"], r["min_agent_protocol"], r["min_server_protocol"]),
                         "pinakes/compat.py and the newest release in RELEASES.toml must agree")

    def test_the_protocol_is_raised_with_its_formats(self):
        now = fingerprints()
        same = [r for r in self.rels if r["protocol"] == compat.PROTOCOL and "fingerprint" in r]
        for r in same:
            self.assertEqual(r["fingerprint"], now,
                             "the batch fields, the agent's state or the schema changed since release %d, at protocol "
                             "%d. If that release is cut (git tag release-%d), raise compat.PROTOCOL and add the next "
                             "release with fingerprint = %s; if not yet, put that in its entry"
                             % (r["id"], r["protocol"], r["id"], json.dumps(now).replace(":", " =")))
        self.assertTrue(same or compat.PROTOCOL == 0, "no release records protocol %d's fingerprint" % compat.PROTOCOL)

    def test_the_validator_catches(self):
        ok = {"release": [{"id": 1, "affects": ["agent"], "protocol": 0, "min_agent_protocol": 0,
                           "min_server_protocol": 0, "upgrade_sql": []}]}
        self.assertEqual(validate(ok, []), [])
        fp = {"batch": "a", "state": "b", "schema": "c"}
        cases = [
            ({"id": 2}, "ids go"),
            ({"affects": []}, "affects must"),
            ({"affects": ["web"]}, "affects must"),
            ({"affects": ["agent", "agent"]}, "affects must"),
            ({"protocol": "1"}, "protocol must be a int"),
            ({"protocol": True}, "protocol must be a int"),
            ({"min_agent_protocol": 1}, "above its own"),
            ({"protocol": 1}, "fingerprint"),
            ({"upgrade_sql": ["nope.sql"]}, "not in pinakes/upgrades"),
            ({"colour": "red"}, "unknown field"),
            ({"protocol": 1, "fingerprint": fp, "upgrade_sql": ["x.sql"]}, "the server's"),
        ]
        for change, msg in cases:
            r = dict(ok["release"][0], **change)
            errs = validate({"release": [r]}, ["x.sql"])
            self.assertTrue(any(msg in e for e in errs), (change, errs))
        r = dict(ok["release"][0])
        del r["upgrade_sql"]
        self.assertIn("release 1: no upgrade_sql", validate({"release": [r]}, []))
        down = [dict(ok["release"][0], protocol=1, fingerprint=fp), dict(ok["release"][0], id=2)]
        self.assertTrue(any("went down" in e for e in validate({"release": down}, [])))
        twice = [dict(ok["release"][0], affects=["server"], upgrade_sql=["x.sql"]),
                 dict(ok["release"][0], id=2, affects=["server"], upgrade_sql=["x.sql"])]
        self.assertTrue(any("already release 1's" in e for e in validate({"release": twice}, ["x.sql"])))
        self.assertIn("pinakes/upgrades/y.sql belongs to no release", validate(ok, ["y.sql"]))
        self.assertTrue(validate({"releases": []}, []))


class TestCompat(unittest.TestCase):
    def test_every_upgrade_has_a_probe(self):
        self.assertEqual(sorted(compat.UPGRADE_PROBES), upgrade_files())

    def test_verdict(self):
        self.assertIsNone(compat.verdict(1, 0, 1, 0))
        self.assertIsNone(compat.verdict(2, 1, 1, 0))                   # agent ahead, compatible
        self.assertEqual(compat.verdict(3, 2, 1, 0)[0], "server")       # agent too far ahead
        self.assertEqual(compat.verdict(1, 0, 3, 2)[0], "agent")        # agent behind
        self.assertIsNone(compat.verdict(0, 0, 1, 0))                   # an agent before check-in

    def test_as_int(self):
        self.assertEqual([compat.as_int(v) for v in (3, "3", None, True, -1, 1 << 40, 2.0)], [3, 0, 0, 0, 0, 0, 0])
        self.assertIsNone(compat.as_int("x", None))


class TestBatchFields(unittest.TestCase):
    """What a scan writes stays inside compat.BATCH_FIELDS: a new field fails here, so it is declared, and declaring
    it changes the fingerprint, so the protocol is raised."""

    def test_a_scan_writes_only_declared_fields(self):
        tmp = tempfile.mkdtemp(prefix="pinakes-fields-")
        self.addCleanup(shutil.rmtree, tmp)
        top = os.path.join(tmp, "root")
        os.makedirs(os.path.join(top, "docs"))
        cfg = config.loads("""
[agent]
host = "test-1"
state = "%(t)s/state.sqlite"
outbox = "%(t)s/outbox"
[[root]]
label = "r"
path = "%(top)s"
archives = true
chunks = { enabled = true, min_size = "1KiB" }
""" % {"t": tmp, "top": top})
        files = {"docs/a.txt": b"alpha", ".hidden": b"h", "photo.jpg": jpegs.jpeg(jpegs.camera()),
                 "big.bin": os.urandom(300_000),
                 "docs/SHA256SUMS": ("%s  a.txt\n" % hashlib.sha256(b"alpha").hexdigest()).encode()}
        for rel, data in files.items():
            with open(os.path.join(top, rel), "wb") as f:
                f.write(data)
        with zipfile.ZipFile(os.path.join(top, "a.zip"), "w") as z:
            z.writestr("inside.txt", "inside")
        os.symlink("docs/a.txt", os.path.join(top, "link"))
        os.symlink("nowhere", os.path.join(top, "dangling"))
        with open(os.path.join(os.fsencode(top), b"bad\xff.txt"), "wb") as f:
            f.write(b"bad")
        st = State(cfg.state)
        self.addCleanup(st.close)
        sc = Scanner(cfg, st)
        sc.scan(cfg.roots[0])
        os.remove(os.path.join(top, "docs/a.txt"))
        sc.scan(cfg.roots[0])
        sc.scan(cfg.roots[0], full=True)
        seen = {}
        for _, path in outbox.pending(cfg.outbox):
            header, recs = outbox.read(path)
            seen.setdefault("header", set()).update(header)
            seen.setdefault("root_def", set()).update(header["root_def"])
            for r in recs:
                seen.setdefault("file" if r["t"] == "symlink" else r["t"], set()).update(r)
        self.assertEqual(set(seen), {"header", "root_def", "file", "error", "gone", "hint", "manifest"})
        for kind, keys in seen.items():
            self.assertEqual(keys - set(compat.BATCH_FIELDS[kind]), set(), "%s fields not in compat.BATCH_FIELDS"
                             % kind)
        for k in ("meta", "members", "chunks", "hidden", "target", "dangling", "resend"):
            self.assertIn(k, seen["file"])                              # the tree reached them
        self.assertEqual({k: header[k] for k in ("release", "protocol", "min_server_protocol")},
                         {"release": compat.RELEASE, "protocol": compat.PROTOCOL,
                          "min_server_protocol": compat.MIN_SERVER_PROTOCOL})


TOOL = os.path.join(TOP, "tools", "latest-release")


@unittest.skipUnless(os.path.exists(TOOL) and shutil.which("git"), "needs tools/latest-release and git")
class TestLatestRelease(unittest.TestCase):
    """tools/latest-release ROLE: the newest release that affects ROLE and is cut (tagged)."""

    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="pinakes-rel-")
        self.addCleanup(shutil.rmtree, self.repo)
        entries = [(1, '["server", "agent"]', '["a.sql"]'), (2, '["server"]', "[]"), (3, '["agent"]', "[]"),
                   (4, '["server"]', '["b.sql"]')]
        with open(os.path.join(self.repo, "RELEASES.toml"), "w") as f:
            for i, affects, up in entries:
                f.write("[[release]]\nid = %d\naffects = %s\nprotocol = 0\nmin_agent_protocol = 0\n"
                        "min_server_protocol = 0\nupgrade_sql = %s\n\n" % (i, affects, up))
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.net", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.net")
        for cmd in (["init", "-q"], ["add", "RELEASES.toml"], ["commit", "-q", "-m", "r"],
                    ["tag", "release-1"], ["tag", "release-2"], ["tag", "release-3"]):   # 4: not cut yet
            subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-C", self.repo] + cmd,
                           check=True, env=env, stdout=subprocess.DEVNULL)

    def run_tool(self, *args):
        return subprocess.run([sys.executable, TOOL, "--manifest", os.path.join(self.repo, "RELEASES.toml"), *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_by_role_and_cut_only(self):
        self.assertEqual(self.run_tool("agent").stdout, "release-3\n")
        p = self.run_tool("server")
        self.assertEqual(p.stdout, "release-2\n")
        self.assertIn("release 4 is not cut yet", p.stderr)
        self.assertNotEqual(self.run_tool("cli").returncode, 0)        # none affects it
        info = json.loads(self.run_tool("server", "--json").stdout)
        self.assertEqual((info["id"], info["tag"], len(info["commit"])), (2, "release-2", 40))
        self.assertEqual(self.run_tool("--upgrades-after", "0").stdout, "a.sql\n")   # b.sql is release 4's: uncut
        self.assertNotEqual(self.run_tool("web").returncode, 0)


if __name__ == "__main__":
    unittest.main()
