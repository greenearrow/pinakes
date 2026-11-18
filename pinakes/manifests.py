"""Checksum manifests (ROADMAP 19, DESIGN.md "Checksum manifests"): SHA256SUMS files as hints, never trusted.

A manifest someone wrote (`sha256sum * > SHA256SUMS`, a download's checksum file) says what each file it lists held
then. At the end of a scan the agent reads every manifest in the root whose content it hasn't read before, and checks
each line against its own hash of the listed file, as the scan has it: a line is confirmed, wrong (the file there now
has another hash), missing (no file at that path), or unchecked (no hash of its own to compare: a symlink, a file
being written, a mount not crossed). Nothing in a manifest is taken as a file's hash: the catalog's hashes stay the
agent's own.

Sent with the scan's complete batch: per listed file, its verdict (`hint`: wrong beats confirmed when two manifests
list it) and the manifest that gave it, only when it changes; per manifest, its counts (`manifest`). A protected root
or a protected link has no manifest read (its content is never read for meaning), nor a root with hash = "none" or
manifests = false. Standard library only, like the rest of the agent.
"""

import hashlib
import json
import os
import posixpath
import re

PROTOCOL = 4                      # the oldest server that takes hint and manifest records
MAX_BYTES = 64 * 1024 * 1024      # a larger "manifest" is not read: counted as one bad line
NAMES = ("sha256sums", "sha256sums.txt")
SUFFIX = ".sha256"
COUNTS = ("lines", "confirmed", "wrong", "missing", "unchecked", "bad", "outside")

_GNU = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)\Z")
_BSD = re.compile(r"SHA256 ?\((.+)\) ?= ?([0-9a-fA-F]{64})\Z")


def is_manifest(relpath):
    name = relpath.rsplit("/", 1)[-1].lower()
    return name in NAMES or (name.endswith(SUFFIX) and len(name) > len(SUFFIX))


def _unescape(name):
    """sha256sum's escaping of a line that starts with a backslash: \\\\ and \\n (and \\r)."""
    out, i = [], 0
    while i < len(name):
        c = name[i]
        if c == "\\" and i + 1 < len(name) and name[i + 1] in "\\nr":
            out.append({"\\": "\\", "n": "\n", "r": "\r"}[name[i + 1]])
            i += 2
            continue
        if c == "\\":
            return None
        out.append(c)
        i += 1
    return "".join(out)


def parse(data, manifest_relpath):
    """The lines of a manifest's bytes: ([(listed relpath, sha256)], bad, outside). A listed name is relative to the
    manifest's folder; one that leaves the root (absolute, or above it) is outside, never looked up. Blank lines and
    # comments are not lines."""
    folder = posixpath.dirname(manifest_relpath)
    lines, bad, outside = [], 0, 0
    for raw in data.split(b"\n"):
        raw = raw.rstrip(b"\r")
        if not raw.strip() or raw.lstrip().startswith(b"#"):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            bad += 1
            continue
        escaped = text.startswith("\\")
        if escaped:
            text = text[1:]
        m = _GNU.match(text)
        if m:
            digest, name = m.group(1), m.group(2)
        else:
            m = _BSD.match(text)
            if not m:
                bad += 1
                continue
            name, digest = m.group(1), m.group(2)
        if escaped:
            name = _unescape(name)
            if name is None:
                bad += 1
                continue
        if name.startswith("/"):
            outside += 1
            continue
        rel = posixpath.normpath(posixpath.join(folder, name))
        if rel == ".." or rel.startswith("../") or rel == ".":
            outside += 1
            continue
        lines.append((rel, digest.lower()))
    return lines, bad, outside


def _read(abspath):
    from .scan import _open_readonly       # scan imports this module
    fd = _open_readonly(abspath)
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_BYTES + 1)
    return data


def waits(cfg, state):
    """Why manifests can't be sent to this agent's server yet, or None (as the scrub's: agent.scrub_waits)."""
    if cfg.transport["kind"] != "ssh":
        return None
    p = state.get_meta("server_protocol")
    if p is not None and int(p) >= PROTOCOL:
        return None
    return ("the server %s; manifests wait for one of protocol %d or later"
            % ("hasn't checked in yet" if p is None else "is at protocol %s" % p, PROTOCOL))


def check(root, state, scan_id, unreadable, full=False):
    """Check the root's manifests at the end of a scan, inside the scan's open state transaction. Returns (records
    to send in the complete batch, {"manifests": n, "wrong": n, "missing": n})."""
    db = state.db
    label = root.label
    wanted = {}
    if root.manifests and not root.protected and root.hash != "none":
        for r in db.execute(
                "SELECT relpath, sha256 FROM files WHERE root = ? AND seen_scan = ? AND t = 'file' "
                "AND sha256 IS NOT NULL AND NOT coalesce(protected_link, 0) "
                "AND (relpath LIKE '%sha256sums' OR relpath LIKE '%sha256sums.txt' OR relpath LIKE '%.sha256')",
                (label, scan_id)):
            if is_manifest(r["relpath"]):
                wanted[r["relpath"]] = r["sha256"]
    have = {r["relpath"]: r for r in db.execute("SELECT * FROM manifests WHERE root = ?", (label,))}
    records = []
    for relpath, r in have.items():
        if relpath not in wanted:
            db.execute("DELETE FROM manifests WHERE root = ? AND relpath = ?", (label, relpath))
            db.execute("DELETE FROM manifest_lines WHERE root = ? AND manifest = ?", (label, relpath))
            if r["sent"] is not None and not root.protected:
                records.append({"t": "manifest", "path": relpath})   # no longer checked: its counts go
    for relpath, sha in sorted(wanted.items()):
        if relpath in have and have[relpath]["sha256"] == sha:
            continue
        try:
            data = _read(os.path.join(root.path, relpath))
        except OSError:
            continue                  # read again by the next scan; what it said before stands meanwhile
        if len(data) > MAX_BYTES:
            lines, bad, outside = [], 1, 0
        elif hashlib.sha256(data).hexdigest() != sha:
            continue                  # changed since it was hashed: the next scan hashes and reads it again
        else:
            lines, bad, outside = parse(data, relpath)
        db.execute("DELETE FROM manifest_lines WHERE root = ? AND manifest = ?", (label, relpath))
        db.executemany("INSERT INTO manifest_lines (root, manifest, listed, sha256) VALUES (?, ?, ?, ?)",
                       [(label, relpath, listed, digest) for listed, digest in lines])
        db.execute("INSERT INTO manifests (root, relpath, sha256, bad, outside, sent) VALUES (?, ?, ?, ?, ?, ?) "
                   "ON CONFLICT (root, relpath) DO UPDATE SET sha256 = excluded.sha256, bad = excluded.bad, "
                   "outside = excluded.outside",
                   (label, relpath, sha, bad, outside, have[relpath]["sent"] if relpath in have else None))

    counts = {}
    for r in db.execute("SELECT relpath, bad, outside FROM manifests WHERE root = ?", (label,)):
        counts[r["relpath"]] = dict.fromkeys(COUNTS, 0) | {"bad": r["bad"], "outside": r["outside"]}
    verdicts = {}                     # listed relpath: (verdict, manifest)
    for r in db.execute(
            "SELECT l.manifest, l.listed, l.sha256 AS want, f.sha256 AS have, f.seen_scan, f.t FROM manifest_lines l "
            "LEFT JOIN files f ON f.root = l.root AND f.relpath = l.listed WHERE l.root = ? "
            "ORDER BY l.listed, l.manifest", (label,)):
        c = counts[r["manifest"]]
        c["lines"] += 1
        if r["t"] is None or r["seen_scan"] != scan_id:
            under = any(d == "" or r["listed"] == d or r["listed"].startswith(d + "/") for d in unreadable)
            c["unchecked" if under else "missing"] += 1
            continue
        if r["have"] is None or r["t"] != "file":
            c["unchecked"] += 1
            continue
        v = "confirmed" if r["have"] == r["want"] else "wrong"
        c[v] += 1
        old = verdicts.get(r["listed"])
        if old is None or (v == "wrong" and old[0] != "wrong"):
            verdicts[r["listed"]] = (v, r["manifest"])

    sent = {r["relpath"]: (r["verdict"], r["manifest"])
            for r in db.execute("SELECT relpath, verdict, manifest FROM hints WHERE root = ?", (label,))}
    for listed, (v, m) in sorted(verdicts.items()):
        if full or sent.get(listed) != (v, m):
            records.append({"t": "hint", "path": listed, "verdict": v, "manifest": m})
            db.execute("INSERT OR REPLACE INTO hints (root, relpath, verdict, manifest) VALUES (?, ?, ?, ?)",
                       (label, listed, v, m))
    for listed in sorted(set(sent) - set(verdicts)):
        records.append({"t": "hint", "path": listed, "verdict": None})
        db.execute("DELETE FROM hints WHERE root = ? AND relpath = ?", (label, listed))
    for relpath, c in sorted(counts.items()):
        text = json.dumps(c, sort_keys=True)
        prev = db.execute("SELECT sent FROM manifests WHERE root = ? AND relpath = ?", (label, relpath)).fetchone()
        if full or prev["sent"] != text:
            records.append(dict({"t": "manifest", "path": relpath}, **c))
            db.execute("UPDATE manifests SET sent = ? WHERE root = ? AND relpath = ?", (text, label, relpath))
    return records, {"manifests": len(counts), "wrong": sum(c["wrong"] for c in counts.values()),
                     "missing": sum(c["missing"] for c in counts.values())}
