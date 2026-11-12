"""pinakes-ingest: apply agents' batches to the catalog.

  pinakes-ingest --config server.toml --host NAME     one batch on stdin (the forced command of an agent's key)
  pinakes-ingest --config server.toml inbox DIR       every batch file waiting in DIR (the directory transport)
  pinakes-ingest --config server.toml setup           seed people, hosts and settings, and enroll the metadata
                                                      schemas' indexes (the schema must exist)
  pinakes-ingest --config server.toml passwd NAME     set a person's password at a hidden prompt (first sign-in)
  pinakes-ingest --config server.toml recompute ROOT  reassign a root's files after its rules or enrollments change
  pinakes-ingest --config server.toml tidy [--dry-run] clear backup roots' history and gone rows, and redo name
                                                      lineage by the current rules (after an upgrade)
  pinakes-ingest --config server.toml totals          files and bytes per root, every owner's (no names): to compare
                                                      with pinakes-agent check
  pinakes-ingest --config server.toml --host NAME hello   an agent's check-in: its release and protocol as JSON on
                                                      stdin; answers this server's, and whether the schema is
                                                      applied, as JSON. Through the forced key, `ssh ... hello`
                                                      reaches it (sshd's SSH_ORIGINAL_COMMAND); nothing else does.

Each batch is applied in one transaction. A host's batches apply in increasing sequence order; a number already
applied is acknowledged and ignored. Moves, changes, copies and lineage are worked out here, when a scan completes.

A batch is stopped and rolled back, and the ingester exits 3, when the agent that sent it hangs up (its stdout
closes) or when it runs past [ingest] max_batch_time: an agent that gave up must not leave a transaction holding
locks that the next batch and setup wait behind.

A batch from an agent whose protocol this server doesn't work with (pinakes/compat.py) is refused, with the reason,
to the agent and to the system log; a batch that declares no protocol (an agent before check-in) counts as 0.
"""

import argparse
import datetime
import gzip
import io
import json
import os
import select
import sys
import threading
import time

import psycopg

from . import BATCH_FORMATS, compat, extract, hidden, names, queries, registry
from .config import ConfigError
from .server_config import load as load_server_config

SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


class Refused(Exception):
    """The batch is not acceptable (unknown host or root, bad format). Nothing is applied."""


class Incompatible(Refused):
    """The batch comes from an agent whose protocol this server doesn't work with."""


def _ts(ns):
    if ns is None:
        return None
    return datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc)


def _under(relpath, folder):
    return folder == "" or relpath == folder or relpath.startswith(folder + "/")


# The file a file t most likely descends from by its name: the same name once copy markers, dates and versions are
# off (names.normalize), another content, not empty, not in a backup root, and a second signal:
# - sizes within name_size_within of each other, if few files have the name (k.few: name_size_namesakes or fewer
#   present outside backup roots; a fixed name in every software package, a camera's counter, is not a sign);
# - the same parent folder name, if few folders have it (t.rare_folder: name_folder_max or fewer; region/ or data/
#   is structure, not a sign);
# - the other changed, moved or went within name_window_days of t appearing;
# - a drop root on either side.
# The most recent earlier one wins. Used for t in unnest(...) with a.appeared, and parameters (size share, days,
# days, namesakes, namesakes + 1).
# Where a file "appeared" is min(seen_on + 0) over its history: a bare min(seen_on) lets PostgreSQL read the
# history_seen index from the oldest day, filtering by file, which costs the whole history for a new file.
NAME_CANDIDATE = """
    SELECT s.file_id, 'similar name, ' || s.why AS evidence FROM (
        SELECT o.file_id, o.mtime, CASE
            WHEN k.few AND t.size > 0 AND o.size > 0 AND abs(o.size - t.size) <= %s * greatest(o.size, t.size)
                THEN 'similar size'
            WHEN t.rare_folder
                 AND lower(substring(o.relpath from '([^/]+)/[^/]+$')) = lower(substring(t.relpath from '([^/]+)/[^/]+$'))
                THEN 'same folder name'
            WHEN r.kind = 'drop' OR t.kind = 'drop' THEN 'drop root'
            WHEN EXISTS (SELECT 1 FROM pinakes.history oh WHERE oh.file_id = o.file_id
                           AND oh.kind IN ('changed', 'moved', 'moved_changed', 'gone')
                           AND oh.seen_on BETWEEN a.appeared - %s::int AND a.appeared + %s::int)
                THEN 'the other changed or went then'
            END AS why
        FROM (SELECT count(*) <= %s AS few FROM (SELECT 1 FROM pinakes.files x JOIN pinakes.roots xr USING (root_id)
                                                 WHERE x.name_key = t.key AND x.ext = t.ext AND x.gone_on IS NULL
                                                   AND xr.kind <> 'backup' LIMIT %s) c) k
        CROSS JOIN pinakes.files o JOIN pinakes.roots r USING (root_id)
        WHERE o.name_key = t.key AND o.ext = t.ext AND o.file_id <> t.fid
          AND r.kind <> 'backup' AND o.content_id IS DISTINCT FROM t.content AND o.size > 0) s
    WHERE s.why IS NOT NULL
    ORDER BY (s.mtime <= t.mtime) DESC, s.mtime DESC NULLS LAST, s.file_id LIMIT 1"""


class _LineageState:
    """What one pass of lineage knows. Files and history don't change during a pass, so what was read of them is
    kept for the whole pass; edges do, so what is known of them is read again from the table each round."""

    def __init__(self):
        self.holders = {}            # content_id -> [(file_id, content_id, mtime, first_seen, host_id, dev, ino)]
        self.how_loaded = set()
        self.how = {}                # (file_id, content_id) -> latest history kind that brought it
        self.rare_folders = None     # folder names few folders have (RARE_FOLDERS), read when first needed
        self.new_round()

    def new_round(self):
        self.loaded = set()          # file ids whose incoming edges are in keys / has_source
        self.keys = set()            # (from, to, kind) present in the table or queued
        self.has_source = set()      # files with an edge in that isn't rejected
        self.has_copy_source = set()  # ... of evidence 'same sha256'
        self.queue = []              # edges to write at the end of the round


# Folder names held by at most name_folder_max folders (distinct root and parent path) of present files outside
# backup roots, lowercased: one statement, once a pass. A snapshot repeats every folder name, so backups don't count.
RARE_FOLDERS = """
    SELECT lower(substring(f.relpath from '([^/]+)/[^/]+$')) FROM pinakes.files f JOIN pinakes.roots r USING (root_id)
    WHERE r.kind <> 'backup' AND f.gone_on IS NULL AND f.relpath LIKE '%%/%%'
    GROUP BY 1 HAVING count(DISTINCT (f.root_id, regexp_replace(f.relpath, '/[^/]+$', ''))) <= %s"""


def _folder_name(relpath):
    """The parent folder's name, lowercased as SQL's lower() would for the names that matter; None at the top."""
    parts = relpath.rsplit("/", 2)
    return parts[-2].lower() if len(parts) > 1 else None


def _other_inode(h, host_id, dev, ino):
    """SQL's NOT (host = host AND dev = dev AND ino = ino): true only if one of them is known to differ."""
    eqs = [h[4] == host_id, None if h[5] is None or dev is None else h[5] == dev,
           None if h[6] is None or ino is None else h[6] == ino]
    return False in eqs


def link_key(r):
    """What a symlink row (of _complete_tracked's fields) leads to, for matching a moved one: the root and path of
    its target, or an absolute target outside the roots as written; None for a relative one outside them (it reads
    differently from another folder) and for anything not a symlink."""
    if not r[9]:
        return None
    if r[11] is not None:
        return ("in", r[11], r[12])
    if r[10] and r[10].startswith("/"):
        return ("text", r[10])
    return None


class _NewFiles:
    """A completing scan's new files (rows of file_id, relpath, content_id, size, dev, ino, ...), indexed for
    matching moves: by content (and name), by inode, and those whose content has chunks. Taking one removes it from
    every index; a taken row still in a list is skipped (and dropped) when met."""

    def __init__(self, rows, chunked):
        self.left = {r[0]: r for r in rows}
        self.chunked = chunked
        self._by_content, self._by_name, self._by_inode, self._with_chunks = {}, {}, {}, []
        self._by_link = {}
        for r in sorted(rows, key=lambda r: r[1], reverse=True):  # by path, the first at the end (pop)
            if r[2] is not None:
                self._by_content.setdefault(r[2], []).append(r)
                self._by_name.setdefault((r[2], r[1].rsplit("/", 1)[-1]), []).append(r)
        for r in rows:  # in file_id order
            self._by_inode.setdefault((r[4], r[5]), []).append(r)
            if link_key(r):
                self._by_link.setdefault(link_key(r), []).append(r)
            if r[2] in chunked:
                self._with_chunks.append(r)

    def take(self, r):
        del self.left[r[0]]

    def _first(self, rows):
        while rows and rows[-1][0] not in self.left:
            rows.pop()
        return rows[-1] if rows else None

    def same_content(self, content, name):
        return self._first(self._by_name.get((content, name), [])) or self._first(self._by_content.get(content, []))

    def same_inode(self, dev, ino):
        return [r for r in self._by_inode.get((dev, ino), ()) if r[0] in self.left]

    def same_link(self, key, name):
        """A new symlink leading where a gone one did: the one of the same name, or else the only one."""
        cands = [r for r in self._by_link.get(key, ()) if r[0] in self.left]
        named = [r for r in cands if r[1].rsplit("/", 1)[-1] == name]
        if named:
            return named[0], True
        return (cands[0], False) if len(cands) == 1 else (None, False)

    def with_chunks(self):
        self._with_chunks = [r for r in self._with_chunks if r[0] in self.left]
        return self._with_chunks


class Ingester:
    def __init__(self, conn, cfg):
        self.conn = conn
        self.cfg = cfg
        self.patterns = names.load_patterns(cfg.name_patterns_file)
        self.registry = registry.load(getattr(cfg, "schemas_dir", None))   # what a batch's metadata is checked by
        self.dropped = []   # the last batch's metadata left out: (path, schema, why)
        self._acl_cache = {}
        # files worked out per round of lineage: a few queries per round, not per file (1 gives the per-file order)
        self.lineage_round = 2000
        self.progress_every = 5000  # gone paths between progress lines on stderr while a scan completes

    # helpers ---------------------------------------------------------------------------------------------------
    def q(self, sql, args=()):
        return self.conn.execute(sql, args)

    def one(self, sql, args=()):
        return self.q(sql, args).fetchone()

    def _principal(self, name):
        """('p', id) for a person, ('g', id) for a group."""
        r = self.one("SELECT person_id FROM pinakes.people WHERE name = %s", (name,))
        if r:
            return ("p", r[0])
        r = self.one("SELECT group_id FROM pinakes.groups WHERE name = %s", (name,))
        if r:
            return ("g", r[0])
        raise Refused("unknown person or group %r" % name)

    # ownership -------------------------------------------------------------------------------------------------
    def acl_for(self, root_id, relpath):
        """(acl_id, owner person or None) for a path, from the owner rules and enrollments of its root."""
        rules = self.q("SELECT folder, owner_person, owner_group FROM pinakes.owner_rules WHERE root_id = %s",
                       (root_id,)).fetchall()
        best = None
        for folder, op, og in rules:
            if _under(relpath, folder) and (best is None or len(folder) > len(best[0])):
                best = (folder, op, og)
        if best:
            owner = ("p", best[1]) if best[1] else ("g", best[2])
        else:
            d = self.one("SELECT value FROM pinakes.settings WHERE key = 'default_owner'")
            if not d:
                raise Refused("no default owner set (run setup)")
            owner = self._principal(d[0])
        enr = sorted({(role, "p" if pid else "g", pid or gid)
                      for folder, pid, gid, role in self.q(
                          "SELECT folder, person_id, group_id, role FROM pinakes.enrollments WHERE root_id = %s",
                          (root_id,)).fetchall()
                      if _under(relpath, folder)})
        key = "o:%s%d|" % owner + "|".join("%s:%s%d" % e for e in enr)
        if key in self._acl_cache:
            return self._acl_cache[key], (owner[1] if owner[0] == "p" else None)
        r = self.one("SELECT acl_id FROM pinakes.acls WHERE acl_key = %s", (key,))
        if r:
            acl_id = r[0]
        else:
            acl_id = self.one("INSERT INTO pinakes.acls (acl_key, owner_person, owner_group) VALUES (%s, %s, %s) "
                              "RETURNING acl_id", (key, owner[1] if owner[0] == "p" else None,
                                                   owner[1] if owner[0] == "g" else None))[0]
            self._expand_acl(acl_id, owner, enr)
        self._acl_cache[key] = acl_id
        return acl_id, (owner[1] if owner[0] == "p" else None)

    def _people_of(self, kind, ident):
        if kind == "p":
            return [ident]
        return [r[0] for r in self.q("SELECT person_id FROM pinakes.group_members WHERE group_id = %s", (ident,))]

    def _expand_acl(self, acl_id, owner, enr):
        rank = {"owner": 3, "co-owner": 2, "annotator": 1, "reader": 0}
        members = {}
        for pid in self._people_of(*owner):
            members[pid] = "owner"
        for role, kind, ident in enr:
            for pid in self._people_of(kind, ident):
                if pid not in members or rank[role] > rank[members[pid]]:
                    members[pid] = role
        self.q("DELETE FROM pinakes.acl_members WHERE acl_id = %s", (acl_id,))
        for pid, role in members.items():
            self.q("INSERT INTO pinakes.acl_members (acl_id, person_id, role) VALUES (%s, %s, %s)",
                   (acl_id, pid, role))

    def refresh_acl_members(self):
        """Re-expand every ACL (after a group's membership changes)."""
        for acl_id, key in self.q("SELECT acl_id, acl_key FROM pinakes.acls").fetchall():
            parts = key.split("|")
            o = parts[0][2:]
            owner = (o[0], int(o[1:]))
            enr = []
            for e in parts[1:]:
                if e:
                    role, who = e.split(":")
                    enr.append((role, who[0], int(who[1:])))
            self._expand_acl(acl_id, owner, enr)

    def recompute_root(self, root_id):
        """Reassign every file of a root after its rules or enrollments change; returns how many changed."""
        n = 0
        self._acl_cache.clear()
        for file_id, relpath, acl in self.q("SELECT file_id, relpath, acl_id FROM pinakes.files WHERE root_id = %s "
                                            "AND backup_of IS NULL", (root_id,)).fetchall():
            new_acl, owner = self.acl_for(root_id, relpath)
            if new_acl != acl:
                self.q("UPDATE pinakes.files SET acl_id = %s, owner_id = %s WHERE file_id = %s",
                       (new_acl, owner, file_id))
                n += 1
        # backup copies follow their source
        self.q("UPDATE pinakes.files b SET acl_id = s.acl_id, owner_id = s.owner_id FROM pinakes.files s "
               "WHERE b.backup_of = s.file_id AND s.root_id = %s AND b.acl_id <> s.acl_id", (root_id,))
        return n

    # roots -----------------------------------------------------------------------------------------------------
    def _root(self, host_id, host, header):
        label = header["root"]
        if not self.cfg.host_allows(host, label):
            raise Refused("host %s may not report root %s" % (host, label))
        d = header.get("root_def") or {}
        r = self.one("SELECT root_id, host_id, kind FROM pinakes.roots WHERE label = %s", (label,))
        if r and r[1] != host_id:
            raise Refused("root %s belongs to another host" % label)
        mirrors = d.get("mirrors") or {}
        if r:
            self.q("UPDATE pinakes.roots SET path = %s, kind = %s, protected = %s, mirrors_layout = %s, "
                   "mirrors_prefix = %s WHERE root_id = %s",
                   (d.get("path", ""), d.get("kind", r[2]), bool(d.get("protected")), mirrors.get("layout"),
                    (mirrors.get("prefix") or "").strip("/") or None, r[0]))
            root_id = r[0]
            new = False
        else:
            root_id = self.one(
                "INSERT INTO pinakes.roots (host_id, label, path, kind, protected, mirrors_layout, mirrors_prefix) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING root_id",
                (host_id, label, d.get("path", ""), d.get("kind", "primary"), bool(d.get("protected")),
                 mirrors.get("layout"), (mirrors.get("prefix") or "").strip("/") or None))[0]
            new = True
        if mirrors.get("root"):
            m = self.one("SELECT root_id FROM pinakes.roots WHERE label = %s", (mirrors["root"],))
            if m:
                self.q("UPDATE pinakes.roots SET mirrors_root_id = %s WHERE root_id = %s", (m[0], root_id))
        if new:
            self._seed_root(root_id, label)
        return root_id

    def _seed_root(self, root_id, label):
        """Owner rules and enrollments from the config, for a root seen for the first time."""
        for r in self.cfg.rules:
            if r["root"] == label:
                k, i = self._principal(r["owner"])
                self.q("INSERT INTO pinakes.owner_rules (root_id, folder, owner_person, owner_group) "
                       "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                       (root_id, r["folder"].strip("/"), i if k == "p" else None, i if k == "g" else None))
        for e in self.cfg.enrollments:
            if e["root"] == label:
                k, i = self._principal(e.get("person") or e.get("group"))
                self.q("INSERT INTO pinakes.enrollments (root_id, folder, person_id, group_id, role) "
                       "VALUES (%s, %s, %s, %s, %s)",
                       (root_id, e["folder"].strip("/"), i if k == "p" else None, i if k == "g" else None, e["as"]))

    # contents --------------------------------------------------------------------------------------------------
    def content(self, sha256_hex, size, chunks=None, chunk_params=None):
        if not sha256_hex:
            return None
        digest = bytes.fromhex(sha256_hex)
        r = self.one("SELECT content_id, chunk_params FROM pinakes.contents WHERE sha256 = %s", (digest,))
        if r:
            content_id = r[0]
            have_chunks = r[1] is not None
        else:
            content_id = self.one("INSERT INTO pinakes.contents (sha256, size) VALUES (%s, %s) RETURNING content_id",
                                  (digest, size))[0]
            have_chunks = False
        if chunks and not have_chunks:
            with self.conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO pinakes.content_chunks (content_id, ord, off, len, digest) VALUES (%s, %s, %s, %s, %s)",
                    [(content_id, i, off, n, bytes.fromhex(d)) for i, (off, n, d) in enumerate(chunks)])
            self.q("UPDATE pinakes.contents SET chunk_params = %s WHERE content_id = %s", (chunk_params, content_id))
        return content_id

    def _members(self, archive_id, members):
        if self.one("SELECT 1 FROM pinakes.members WHERE archive_content_id = %s LIMIT 1", (archive_id,)):
            return
        for entry, size, digest in members:
            cid = self.content(digest, size)
            self.q("INSERT INTO pinakes.members (archive_content_id, entry_path, size, content_id) "
                   "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", (archive_id, entry, size, cid))

    # backups ---------------------------------------------------------------------------------------------------
    def _meta(self, ctx, content_id, relpath, meta):
        """A file record's extracted metadata (format 2), kept on its content. Only a schema of the registry with an
        extractor, at most the catalog's version of it, with values of its own fields and types (extract.check_vals);
        anything else is left out and reported, not applied. The schema's sensitive fields go in a row of their own,
        which only the owners of a copy see (sensitive_visible()). Values replace a
        content's only when of a newer version: the same bytes give the same values, so a copy elsewhere rewrites
        nothing, and a later agent can't overwrite what is known."""
        if not isinstance(meta, dict):
            raise Refused("%s: meta is not a table" % relpath)
        for name, e in meta.items():
            s = self.registry.schemas.get(name)
            why = None
            if s is None or s.extractor is None:
                why = "no schema with an extractor"
            elif not isinstance(e, dict) or not set(e) <= {"v", "vals", "error"}:
                why = "not {v, vals} or {v, error}"
            elif isinstance(e.get("v"), bool) or not isinstance(e.get("v"), int) or not 1 <= e["v"] <= s.version:
                why = "version %r; the catalog has %d" % (e.get("v"), s.version)
            if why is None and "vals" in e:
                vals, problems = extract.check_vals(s, e["vals"])
                why = "; ".join(problems) or None
            if why:
                self.dropped.append((relpath, name, why))
                continue
            if "vals" not in e or not vals:
                continue                            # the extractor failed or found nothing: what is known stays
            old = self.one("SELECT max(version) FROM pinakes.metadata WHERE content_id = %s AND schema = %s "
                           "AND source = 'embedded'", (content_id, name))[0]
            if old is not None and old >= e["v"]:
                continue
            self.q("DELETE FROM pinakes.metadata WHERE content_id = %s AND schema = %s AND source = 'embedded'",
                   (content_id, name))
            for sensitive in (False, True):
                part = {k: v for k, v in vals.items() if s.fields[k].sensitive == sensitive}
                if part:
                    self.q("INSERT INTO pinakes.metadata (content_id, schema, vals, source, version, sent_by, "
                           "sensitive) VALUES (%s, %s, %s, 'embedded', %s, %s, %s)",
                           (content_id, name, json.dumps(part, sort_keys=True), e["v"], ctx["host_id"], sensitive))

    def _backup_source(self, root, relpath):
        """(source root_id, source relpath, snapshot date) of a path in a backup root, by its layout."""
        layout = root["mirrors_layout"] or "{relpath}"
        if not root["mirrors_root_id"]:
            return None
        lparts = layout.split("/")
        rparts = relpath.split("/")
        if lparts[-1] != "{relpath}" or len(rparts) < len(lparts):
            return None
        prefix = rparts[: len(lparts) - 1]
        snapshot = None
        for seg in prefix:
            try:
                snapshot = datetime.date.fromisoformat(seg[:10])
            except ValueError:
                pass
        rest = "/".join(rparts[len(lparts) - 1:])
        if root.get("mirrors_prefix"):
            rest = root["mirrors_prefix"] + "/" + rest
        return root["mirrors_root_id"], rest, snapshot

    def totals(self):
        """(host, root, files, bytes, pending) per root: present files, every owner's. Pending counts files new in
        an unfinished scan, so it should be 0 when comparing with the agent's check."""
        return self.conn.execute(
            "SELECT h.name, r.label, count(f.file_id), coalesce(sum(f.size), 0), count(f.pending_scan) "
            "FROM pinakes.roots r JOIN pinakes.hosts h USING (host_id) "
            "LEFT JOIN pinakes.files f ON f.root_id = r.root_id AND f.gone_on IS NULL "
            "GROUP BY 1, 2 ORDER BY 1, 2").fetchall()

    # applying a batch ------------------------------------------------------------------------------------------
    def apply(self, header, records, host):
        if header.get("t") != "batch" or header.get("format") not in BATCH_FORMATS:
            raise Refused("not a batch of format %s" % " or ".join(map(str, BATCH_FORMATS)))
        self.dropped = []
        if header.get("host") != host:
            raise Refused("batch says host %r, key is for %r" % (header.get("host"), host))
        if host not in self.cfg.hosts:
            raise Refused("unknown host %r" % host)
        seq = int(header["seq"])
        protocol = compat.as_int(header.get("protocol"))
        v = compat.verdict(protocol, compat.as_int(header.get("min_server_protocol")), compat.PROTOCOL,
                           compat.MIN_AGENT_PROTOCOL)
        if v:
            why = "batch %d: %s; the %s must update" % (seq, v[1], v[0])
            self._note_refused(host, why)
            raise Incompatible(why)
        with self.conn.transaction():
            h = self.one("SELECT host_id, last_seq FROM pinakes.hosts WHERE name = %s FOR UPDATE", (host,))
            if h is None:
                host_id = self.one("INSERT INTO pinakes.hosts (name, expected_every) VALUES (%s, %s) "
                                   "RETURNING host_id", (host, self.cfg.hosts[host]["expected_every"]))[0]
                last_seq = 0
            else:
                host_id, last_seq = h
            if seq <= last_seq:
                return "duplicate"
            root_id = self._root(host_id, host, header)
            root = self.one("SELECT root_id, kind, protected, mirrors_root_id, mirrors_layout, last_complete_on, "
                            "mirrors_prefix FROM pinakes.roots WHERE root_id = %s", (root_id,))
            root = dict(zip(("root_id", "kind", "protected", "mirrors_root_id", "mirrors_layout",
                             "last_complete_on", "mirrors_prefix"), root))
            scan = int(header["scan"])
            started_on = datetime.date.fromisoformat(header["started"][:10])
            self.q("INSERT INTO pinakes.scans (root_id, scan, started_on) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                   (root_id, scan, started_on))
            ctx = {"root": root, "scan": scan, "on": started_on, "after": root["last_complete_on"],
                   "uid_map": self.cfg.hosts[host]["uid_map"], "host_id": host_id}
            gone = []
            for rec in records:
                t = rec.get("t")
                if t in ("file", "symlink"):
                    self._file(ctx, rec)
                elif t == "gone":
                    gone.append(rec["path"])
                elif t == "error":
                    self.q("INSERT INTO pinakes.scan_errors (root_id, relpath, error, seen_on) VALUES (%s, %s, %s, %s) "
                           "ON CONFLICT (root_id, relpath) DO UPDATE SET error = EXCLUDED.error, "
                           "seen_on = EXCLUDED.seen_on", (root_id, rec["path"], rec["error"], started_on))
            if header.get("complete"):
                self._complete(ctx, gone, host_id)
            elif gone:
                raise Refused("gone records in an incomplete scan")
            self.q("INSERT INTO pinakes.ingested (host_id, seq, records) VALUES (%s, %s, %s)",
                   (host_id, seq, len(records)))
            self.q("UPDATE pinakes.hosts SET last_seq = %s WHERE host_id = %s", (seq, host_id))
            self.q("INSERT INTO pinakes.checkins (host_id, batch_at, batch_release, batch_protocol) "
                   "VALUES (%s, now(), %s, %s) ON CONFLICT (host_id) DO UPDATE SET batch_at = EXCLUDED.batch_at, "
                   "batch_release = EXCLUDED.batch_release, batch_protocol = EXCLUDED.batch_protocol",
                   (host_id, compat.as_int(header.get("release"), None), protocol))
        if self.dropped:
            sys.stderr.write("pinakes-ingest: host %s batch %d: metadata left out for %d file(s), first: %s %s: %s\n"
                             % ((host, seq, len(self.dropped)) + self.dropped[0]))
        return "applied"

    # check-in ------------------------------------------------------------------------------------------------
    def hello(self, host, req):
        """An agent's check-in: record what it runs, answer what this server runs. req is what the agent sent (a
        dict; anything missing or malformed counts as 0)."""
        if host not in self.cfg.hosts:
            raise Refused("unknown host %r" % host)
        release = compat.as_int(req.get("release"), None)
        protocol = compat.as_int(req.get("protocol"))
        min_server = compat.as_int(req.get("min_server_protocol"))
        missing = schema_missing(self.conn)
        v = compat.verdict(protocol, min_server, compat.PROTOCOL, compat.MIN_AGENT_PROTOCOL)
        if not missing:
            with self.conn.transaction():
                self.q("INSERT INTO pinakes.hosts (name, expected_every) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING",
                       (host, self.cfg.hosts[host]["expected_every"]))
                self.q("INSERT INTO pinakes.checkins (host_id, at, release, protocol, min_server_protocol, locked) "
                       "SELECT host_id, now(), %s, %s, %s, %s FROM pinakes.hosts WHERE name = %s "
                       "ON CONFLICT (host_id) DO UPDATE SET at = EXCLUDED.at, release = EXCLUDED.release, "
                       "protocol = EXCLUDED.protocol, min_server_protocol = EXCLUDED.min_server_protocol, "
                       "locked = EXCLUDED.locked",
                       (release, protocol, min_server, "%s must update: %s" % v if v else None, host))
        return {"release": compat.RELEASE, "protocol": compat.PROTOCOL,
                "min_agent_protocol": compat.MIN_AGENT_PROTOCOL, "schema_applied": not missing,
                "upgrades_missing": missing}

    def _note_refused(self, host, why):
        """Keep the last refusal for its protocol where pinakes --versions shows it (if the catalog has the table)."""
        try:
            with self.conn.transaction():
                self.q("INSERT INTO pinakes.checkins (host_id, refused_at, refused) "
                       "SELECT host_id, now(), %s FROM pinakes.hosts WHERE name = %s ON CONFLICT (host_id) "
                       "DO UPDATE SET refused_at = EXCLUDED.refused_at, refused = EXCLUDED.refused", (why, host))
        except psycopg.errors.UndefinedTable:
            pass

    def _file(self, ctx, rec):
        root = ctx["root"]
        relpath = rec["path"]
        name = relpath.rsplit("/", 1)[-1]
        content_id = self.content(rec.get("sha256"), rec.get("size") or 0, rec.get("chunks"), rec.get("chunk_params"))
        if rec.get("meta") is not None and (root["protected"] or rec.get("protected_link")):
            # the agent never extracts there (METADATA.md): one that says it did is refused, not trusted
            raise Refused("%s: metadata from a protected %s" % (relpath, "root" if root["protected"] else "link"))
        if rec.get("protected_link") and content_id:
            # another link to this inode is under a protected root: nothing readable is kept from it, even a
            # listing or metadata got before the link was
            self.q("DELETE FROM pinakes.members WHERE archive_content_id = %s", (content_id,))
            self.q("DELETE FROM pinakes.metadata WHERE content_id = %s AND source IN ('embedded', 'derived')",
                   (content_id,))
        elif rec.get("members") and content_id and not root["protected"]:
            self._members(content_id, rec["members"])
        if rec.get("meta") is not None and content_id:
            self._meta(ctx, content_id, relpath, rec["meta"])
        key, ext = names.normalize(name, self.patterns)
        cols = {"name": name, "content_id": content_id, "size": rec.get("size"),
                "mtime": _ts(rec.get("mtime_ns")), "ctime": _ts(rec.get("ctime_ns")), "btime": _ts(rec.get("btime_ns")),
                "mtime_ns": rec.get("mtime_ns"), "ctime_ns": rec.get("ctime_ns"), "btime_ns": rec.get("btime_ns"),
                "dev": rec.get("dev"), "ino": rec.get("ino"), "nlink": rec.get("nlink"), "uid": rec.get("uid"),
                "is_symlink": rec.get("t") == "symlink", "link_target": rec.get("target"),
                "unstable": bool(rec.get("unstable")), "name_key": key, "ext": ext,
                "protected_link": bool(rec.get("protected_link")), "link_root": rec.get("link_root"),
                "link_relpath": rec.get("link_path"), "link_dangling": rec.get("dangling"),
                # an agent from before hidden files doesn't say; a dot in the path is known here anyway
                "hidden": bool(rec.get("hidden")) or hidden.by_name(relpath)}
        ex = self.one("SELECT file_id, content_id, mtime, ctime, btime FROM pinakes.files "
                      "WHERE root_id = %s AND relpath = %s AND gone_on IS NULL", (root["root_id"], relpath))
        if ex:
            file_id, old_content, old_m, old_c, old_b = ex
            if content_id is None and rec.get("unstable"):
                cols["content_id"] = old_content  # keep the last known content until it settles
            sets = ", ".join("%s = %%(%s)s" % (k, k) for k in cols)
            self.q("UPDATE pinakes.files SET %s, last_seen = now() WHERE file_id = %%(file_id)s" % sets,
                   dict(cols, file_id=file_id))
            if (content_id is not None and old_content is not None and content_id != old_content
                    and root["kind"] != "backup"):  # a backup root keeps no history of its own
                self.q("INSERT INTO pinakes.history (file_id, kind, old_relpath, new_relpath, old_content_id, "
                       "new_content_id, old_mtime, new_mtime, old_ctime, new_ctime, old_btime, new_btime, "
                       "seen_after, seen_on) VALUES (%s, 'changed', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                       (file_id, relpath, relpath, old_content, content_id, old_m, cols["mtime"], old_c, cols["ctime"],
                        old_b, cols["btime"], ctx["after"], ctx["on"]))
                self.q("UPDATE pinakes.files SET changed_scan = %s WHERE file_id = %s", (ctx["scan"], file_id))
            return
        backup_of = snapshot = None
        acl_root, acl_path = root["root_id"], relpath
        if root["kind"] == "backup":
            src = self._backup_source(root, relpath)
            if src:
                acl_root, acl_path, snapshot = src
                s = self.one("SELECT file_id, acl_id, owner_id FROM pinakes.files WHERE root_id = %s AND relpath = %s "
                             "AND gone_on IS NULL", (acl_root, acl_path))
                if s:
                    backup_of = s[0]
        if backup_of:
            acl_id, owner = self.one("SELECT acl_id, owner_id FROM pinakes.files WHERE file_id = %s", (backup_of,))
        else:
            acl_id, owner = self.acl_for(acl_root, acl_path)
        cols.update(root_id=root["root_id"], relpath=relpath, acl_id=acl_id, owner_id=owner, backup_of=backup_of,
                    snapshot=snapshot, pending_scan=ctx["scan"])
        self.q("INSERT INTO pinakes.files (%s) VALUES (%s)" % (", ".join(cols), ", ".join("%%(%s)s" % k for k in cols)),
               cols)

    # completing a scan: moves, gone, new, lineage --------------------------------------------------------------
    def _complete(self, ctx, gone_paths, host_id):
        root_id, scan, on, after = ctx["root"]["root_id"], ctx["scan"], ctx["on"], ctx["after"]
        if ctx["root"]["kind"] == "backup":
            self._complete_backup(ctx, gone_paths)
        else:
            self._complete_tracked(ctx, gone_paths)
        self.q("UPDATE pinakes.scans SET completed = true WHERE root_id = %s AND scan = %s", (root_id, scan))
        self.q("UPDATE pinakes.roots SET last_complete_on = %s WHERE root_id = %s", (on, root_id))
        self.q("UPDATE pinakes.hosts SET last_scan = now() WHERE host_id = %s", (host_id,))
        self.q("DELETE FROM pinakes.scan_errors WHERE root_id = %s AND seen_on < %s", (root_id, on))

    def _complete_backup(self, ctx, gone_paths):
        """A backup root records what holds a copy now, not its own history: a gone path's row goes, nothing is
        matched as a move (a pruned snapshot is not a move into the new one), and no history rows are written."""
        root_id, scan = ctx["root"]["root_id"], ctx["scan"]
        if gone_paths:
            self.q("DELETE FROM pinakes.files WHERE root_id = %s AND relpath = ANY(%s)", (root_id, gone_paths))
        self.q("UPDATE pinakes.files SET pending_scan = NULL, changed_scan = NULL "
               "WHERE root_id = %s AND (pending_scan = %s OR changed_scan = %s)", (root_id, scan, scan))

    def _complete_tracked(self, ctx, gone_paths):
        root_id, scan, on, after = ctx["root"]["root_id"], ctx["scan"], ctx["on"], ctx["after"]
        fields = ("file_id, relpath, content_id, size, dev, ino, mtime, ctime, btime, "
                  "is_symlink, link_target, link_root, link_relpath")
        touched = []
        if gone_paths:  # only a scan that lost paths needs the new files in hand, to match moves
            rows = self.q("SELECT %s FROM pinakes.files WHERE root_id = %%s AND pending_scan = %%s "
                          "AND gone_on IS NULL ORDER BY file_id" % fields, (root_id, scan)).fetchall()
            paths = list(dict.fromkeys(gone_paths))  # a repeated record is already gone the second time
            present = {r[1]: r for r in self.q("SELECT %s FROM pinakes.files WHERE root_id = %%s AND relpath = ANY(%%s) "
                                               "AND gone_on IS NULL" % fields, (root_id, paths)).fetchall()}
            chunked = {r[0] for r in self.q(  # contents, new or gone, that have chunks
                "SELECT c.content_id FROM pinakes.contents c WHERE c.content_id = ANY(%s) AND EXISTS "
                "(SELECT 1 FROM pinakes.content_chunks k WHERE k.content_id = c.content_id)",
                (list({r[2] for r in rows + list(present.values()) if r[2] is not None}),)).fetchall()}
            new = _NewFiles(rows, chunked)
            gone_ids = []
            for i, path in enumerate(paths, 1):
                g = present.get(path)
                if g is not None:
                    match = self._match_move(g, new)
                    if match:
                        n, kind, evidence, confidence = match
                        new.take(n)
                        self._merge_move(g, n, kind, evidence, confidence, after, on)
                        if kind == "moved_changed":
                            touched.append(g[0])
                    else:
                        gone_ids.append(g[0])
                if i % self.progress_every == 0 or (i == len(paths) > self.progress_every):
                    print("pinakes-ingest: scan %d: %d/%d gone path(s) matched or marked gone"
                          % (scan, i, len(paths)), file=sys.stderr, flush=True)
            if gone_ids:  # in the order of the gone records, as one at a time would write them
                self.q("INSERT INTO pinakes.history (file_id, kind, old_relpath, old_content_id, old_mtime, old_ctime, "
                       "old_btime, seen_after, seen_on) SELECT f.file_id, 'gone', f.relpath, f.content_id, f.mtime, "
                       "f.ctime, f.btime, %s, %s FROM unnest(%s::bigint[]) WITH ORDINALITY AS t(file_id, ord) "
                       "JOIN pinakes.files f USING (file_id) ORDER BY t.ord", (after, on, gone_ids))
                self.q("UPDATE pinakes.files SET gone_on = %s, pending_scan = NULL WHERE file_id = ANY(%s)",
                       (on, gone_ids))
        # what is still pending after the moves is new in this scan: one statement however many (a first scan: all)
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

    def _match_move(self, g, new):
        """The new file g most likely became: same content, same inode, or shared chunks. `new` is a _NewFiles;
        each step looks only at the files that could match, so a gone file with no match costs next to nothing."""
        _, gpath, gcontent, gsize, gdev, gino = g[:6]
        gname = gpath.rsplit("/", 1)[-1]
        if g[9]:  # a symlink: no content. The same inode leading to the same place, or a new link that does; a
            # symlink is small, so a freed inode is soon another link's, and an inode alone says little
            key = link_key(g)
            if gdev is not None:
                for n in new.same_inode(gdev, gino):
                    if n[9] and (n[10] == g[10] or (key is not None and link_key(n) == key)):
                        return n, "moved", "same inode, same target", "certain"
            if key:
                n, named = new.same_link(key, gname)
                if n:
                    return n, "moved", "same target" + (" and name" if named else ""), "strong" if named else "likely"
            return None
        if gcontent is not None:
            n = new.same_content(gcontent, gname)  # the same name first, then by path
            if n:
                return n, "moved", "same sha256", "certain"
        if gdev is not None:
            for n in new.same_inode(gdev, gino):
                if n[3] is not None and gsize is not None and abs(n[3] - gsize) <= max(4096, 0.5 * max(gsize, 1)):
                    return n, "moved_changed", "same inode, similar size", "strong"
        if gcontent is not None and gcontent in new.chunked:  # no chunks of its own: nothing can share them
            cands = new.with_chunks()
            if cands:
                ovs = self.chunk_overlaps(gcontent, list({n[2] for n in cands}))
                best = None
                for n in cands:
                    ov = ovs.get(n[2], 0.0)
                    if ov and ov >= self.cfg.chunk_overlap and (best is None or ov > best[1]):
                        best = (n, ov)
                if best:
                    return best[0], "moved_changed", "chunks %.0f%% shared" % (100 * best[1]), "likely"
        return None

    def chunk_overlaps(self, a, others):
        """Share of a's bytes found in each other content's chunks (by chunk digest): {content_id: share}, one
        query for them all; a content sharing nothing is left out."""
        total = self.one("SELECT sum(len) FROM pinakes.content_chunks WHERE content_id = %s", (a,))[0]
        if not total:
            return {}
        return {b: s / total for b, s in self.q(
            """SELECT b.content_id, sum(ca.len) FROM unnest(%s::bigint[]) AS b(content_id)
               JOIN pinakes.content_chunks ca ON ca.content_id = %s AND ca.digest IN
                    (SELECT digest FROM pinakes.content_chunks WHERE content_id = b.content_id)
               GROUP BY b.content_id""", (others, a)).fetchall()}

    def _merge_move(self, g, n, kind, evidence, confidence, after, on):
        """g's file_id lives on at n's path, with n's attributes; n's row goes."""
        cols = ("relpath, name, content_id, size, mtime, ctime, btime, mtime_ns, ctime_ns, btime_ns, dev, ino, nlink, "
                "uid, is_symlink, link_target, unstable, name_key, ext, acl_id, owner_id, backup_of, snapshot, "
                "protected_link, link_root, link_relpath, link_dangling, hidden")
        row = self.one("SELECT %s FROM pinakes.files WHERE file_id = %%s" % cols, (n[0],))
        self.q("DELETE FROM pinakes.files WHERE file_id = %s", (n[0],))
        sets = ", ".join("%s = %%s" % c.strip() for c in cols.split(","))
        self.q("UPDATE pinakes.files SET %s, last_seen = now(), pending_scan = NULL WHERE file_id = %%s" % sets,
               tuple(row) + (g[0],))
        self.q("INSERT INTO pinakes.history (file_id, kind, old_relpath, new_relpath, old_content_id, new_content_id, "
               "old_mtime, new_mtime, old_ctime, new_ctime, old_btime, new_btime, seen_after, seen_on, evidence, "
               "confidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
               (g[0], kind, g[1], n[1], g[2], n[2], g[6], n[6], g[7], n[7], g[8], n[8], after, on, evidence,
                confidence))

    # lineage ---------------------------------------------------------------------------------------------------
    def lineage_for(self, file_id, on):
        self.lineage_many([file_id], on)

    def lineage_many(self, file_ids, on):
        """Lines of descent for these files, in this order, as if one at a time.

        Each round of `lineage_round` files costs a handful of queries; the edges a round finds are written at its end.
        What a later file depends on (which files already have a source) is kept here meanwhile, so the result is
        the same as working the files out one by one: a round of 1 is the per-file order exactly, reading every edge
        back from the table. Chunk sharing, rare, is still asked per file.
        """
        st = _LineageState()
        for i in range(0, len(file_ids), self.lineage_round):
            self._lineage_round(file_ids[i:i + self.lineage_round], on, st)

    def _lineage_round(self, ids, on, st):
        st.new_round()
        rows = self.q("""SELECT f.file_id, f.content_id, f.mtime, f.dev, f.ino, r.host_id, f.name_key, f.ext,
                                f.size, f.relpath, r.kind
                         FROM pinakes.files f JOIN pinakes.roots r USING (root_id)
                         WHERE f.file_id = ANY(%s) AND f.content_id IS NOT NULL
                           AND f.size > 0""", (ids,)).fetchall()  # an empty file descends from nothing
        by_id = {r[0]: r for r in rows}
        if not by_id:
            return
        contents = list({r[1] for r in rows})
        # holders of each content, earliest first (the files table doesn't change while lineage is worked out)
        missing = [c for c in contents if c not in st.holders]
        if missing:
            far = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
            for c in missing:
                st.holders[c] = []
            for h in self.q("""SELECT o.file_id, o.content_id, o.mtime, o.first_seen, r.host_id, o.dev, o.ino
                               FROM pinakes.files o JOIN pinakes.roots r USING (root_id)
                               WHERE o.content_id = ANY(%s) AND r.kind <> 'backup'""", (missing,)).fetchall():
                st.holders[h[1]].append(h)
            for c in missing:
                st.holders[c].sort(key=lambda h: (h[2] or far, h[3], h[0]))
        # incoming edges and history of these files and of every holder of their contents (each loaded once a pass)
        near = list(by_id) + [h[0] for c in contents for h in st.holders[c]]
        self._load_lineage(near, st)
        self._load_how(near, st)
        changed = {r[0] for r in self.q("SELECT DISTINCT file_id FROM pinakes.history WHERE file_id = ANY(%s) "
                                        "AND kind <> 'new'", (list(by_id),)).fetchall()}
        chunked = {r[0] for r in self.q("SELECT c.content_id FROM pinakes.contents c WHERE c.content_id = ANY(%s) "
                                        "AND EXISTS (SELECT 1 FROM pinakes.content_chunks k "
                                        "WHERE k.content_id = c.content_id)", (contents,)).fetchall()}
        named = [r for r in rows if r[6]]
        by_name = {}
        if named:
            by_name = {fid: (src, evidence) for fid, src, evidence in self.q(
                """SELECT t.fid, n.file_id, n.evidence
                   FROM unnest(%s::bigint[], %s::text[], %s::text[], %s::bigint[], %s::timestamptz[], %s::bigint[],
                               %s::text[], %s::text[], %s::boolean[])
                        AS t(fid, key, ext, content, mtime, size, relpath, kind, rare_folder)
                   CROSS JOIN LATERAL (SELECT coalesce(min(h.seen_on + 0), %s::date) AS appeared FROM pinakes.history h
                                       WHERE h.file_id = t.fid) a
                   CROSS JOIN LATERAL (""" + NAME_CANDIDATE + """) n""",
                ([r[0] for r in named], [r[6] for r in named], [r[7] for r in named], [r[1] for r in named],
                 [r[2] for r in named], [r[8] for r in named], [r[9] for r in named], [r[10] for r in named],
                 self._rare(st, [r[9] for r in named]), on,
                 *self._name_params())).fetchall()}
        for file_id in ids:
            f = by_id.get(file_id)
            if f is not None:
                self._lineage_one(f, on, st, changed, chunked, by_name)
        if st.queue:
            with self.conn.cursor() as cur:
                cur.executemany("INSERT INTO pinakes.lineage (from_file_id, to_file_id, kind, evidence, confidence, "
                                "found_on) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING", st.queue)
            st.queue = []

    def _load_lineage(self, ids, st):
        ids = [i for i in ids if i not in st.loaded]
        if not ids:
            return
        st.loaded.update(ids)
        for frm, to, kind, evidence, decision in self.q(
                "SELECT from_file_id, to_file_id, kind, evidence, decision FROM pinakes.lineage "
                "WHERE to_file_id = ANY(%s)", (ids,)).fetchall():
            st.keys.add((frm, to, kind))
            if decision != "rejected":
                st.has_source.add(to)
                if evidence == "same sha256":
                    st.has_copy_source.add(to)

    def _load_how(self, ids, st):
        ids = [i for i in ids if i not in st.how_loaded]
        if not ids:
            return
        st.how_loaded.update(ids)
        for file_id, content_id, kind in self.q(
                "SELECT DISTINCT ON (file_id, new_content_id) file_id, new_content_id, kind FROM pinakes.history "
                "WHERE file_id = ANY(%s) AND new_content_id IS NOT NULL "
                "ORDER BY file_id, new_content_id, history_id DESC", (ids,)).fetchall():
            st.how[(file_id, content_id)] = kind

    def _how_got(self, st, file_id, content_id):
        """'replaced_by' if the file came to hold this content by a change, else 'copied_from'."""
        return "replaced_by" if st.how.get((file_id, content_id)) in ("changed", "moved_changed") else "copied_from"

    def _edge(self, st, src, dst, kind, evidence, confidence, on):
        if src == dst or (src, dst, kind) in st.keys:
            return  # the table already has it, perhaps rejected: as ON CONFLICT DO NOTHING would leave it
        st.keys.add((src, dst, kind))
        st.has_source.add(dst)
        if evidence == "same sha256":
            st.has_copy_source.add(dst)
        st.queue.append((src, dst, kind, evidence, confidence, on))

    def _lineage_one(self, f, on, st, changed, chunked, by_name):
        file_id, content, mtime, dev, ino, host_id, name_key, ext = f[:8]
        # 1. identical content elsewhere (not a backup copy, not another link to the same inode)
        others = [h for h in st.holders.get(content, ()) if h[0] != file_id and _other_inode(h, host_id, dev, ino)]
        if others:
            earliest = others[0]
            if mtime is not None and earliest[2] is not None and mtime < earliest[2]:
                # this file had it first: it is the source of the copies that have no source yet
                ids = [o[0] for o in others]
                self._load_lineage(ids, st)
                self._load_how(ids, st)
                for o in others:
                    if o[0] not in st.has_copy_source:
                        self._edge(st, file_id, o[0], self._how_got(st, o[0], content), "same sha256", "certain", on)
            else:
                self._edge(st, earliest[0], file_id, self._how_got(st, file_id, content), "same sha256", "certain",
                           on)
            return
        # weaker evidence only for a file with no line of descent yet (a changed file keeps its own)
        if file_id in st.has_source or file_id in changed:
            return
        # 2. shared chunks with another content
        if content in chunked:
            best = self.one("""SELECT cb.content_id, sum(ca.len)::float / (SELECT sum(len) FROM pinakes.content_chunks
                                                                            WHERE content_id = %s) AS share
                               FROM pinakes.content_chunks ca JOIN pinakes.content_chunks cb
                                 ON cb.digest = ca.digest AND cb.content_id <> ca.content_id
                               WHERE ca.content_id = %s GROUP BY cb.content_id ORDER BY share DESC LIMIT 1""",
                            (content, content))
            if best and best[1] and best[1] >= self.cfg.chunk_overlap:
                src = self.one("""SELECT o.file_id FROM pinakes.files o JOIN pinakes.roots r USING (root_id)
                                  WHERE o.content_id = %s AND r.kind <> 'backup' AND o.file_id <> %s
                                  ORDER BY (o.mtime <= %s) DESC, o.mtime DESC NULLS LAST LIMIT 1""",
                               (best[0], file_id, mtime))
                if src:
                    self._edge(st, src[0], file_id, "derived_from", "chunks %.0f%% shared" % (100 * best[1]),
                               "likely", on)
                    return
        # 3. the same name once copy markers, dates and versions are taken off
        #    and a second signal (NAME_CANDIDATE): a name alone links unrelated files (camera names, README)
        if name_key and by_name.get(file_id):
            src, evidence = by_name[file_id]
            self._edge(st, src, file_id, "derived_from", evidence, "possible", on)

    def _name_params(self):
        """NAME_CANDIDATE's parameters, in order."""
        c = self.cfg
        return (c.name_size_within, c.name_window_days, c.name_window_days, c.name_size_namesakes,
                c.name_size_namesakes + 1)

    def _rare(self, st, relpaths):
        if st.rare_folders is None:
            st.rare_folders = {r[0] for r in self.q(RARE_FOLDERS, (self.cfg.name_folder_max,))}
        return [_folder_name(p) in st.rare_folders for p in relpaths]

    # tidying what older releases left ---------------------------------------------------------------------------
    def tidy(self, on):
        """Bring a catalog built by an older release in line with the current rules; returns counts. Backup roots:
        their history rows, gone rows and any lineage edges go. Undecided edges to or from an empty file go (it
        descends from nothing). Name keys are recomputed by the current patterns. Name lineage: every undecided edge
        by name is worked out again by NAME_CANDIDATE (the same source kept, another taken, or none). Decided edges
        stay. Run it again after an upgrade; a second run changes nothing."""
        n = {}
        backup = "SELECT f.file_id FROM pinakes.files f JOIN pinakes.roots r USING (root_id) WHERE r.kind = 'backup'"
        n["backup history rows"] = self.q("DELETE FROM pinakes.history WHERE file_id IN (%s)" % backup).rowcount
        n["backup lineage edges"] = self.q("DELETE FROM pinakes.lineage WHERE from_file_id IN (%s) OR to_file_id IN "
                                           "(%s)" % (backup, backup)).rowcount
        n["empty-file edges"] = self.q(
            "DELETE FROM pinakes.lineage l WHERE decision IS NULL AND (EXISTS (SELECT 1 FROM pinakes.files f "
            "WHERE f.file_id = l.to_file_id AND f.size = 0) OR EXISTS (SELECT 1 FROM pinakes.files f "
            "WHERE f.file_id = l.from_file_id AND f.size = 0))").rowcount
        n["backup gone rows"] = self.q("DELETE FROM pinakes.files WHERE gone_on IS NOT NULL AND root_id IN "
                                       "(SELECT root_id FROM pinakes.roots WHERE kind = 'backup')").rowcount
        # name keys by the current patterns (a release may change normalize): every file, read in a server cursor
        rekey = []
        with self.conn.cursor(name="pinakes_tidy_names") as cur:
            cur.execute("SELECT file_id, name, name_key, ext FROM pinakes.files")
            for fid, name, key, ext in cur:
                k, e = names.normalize(name, self.patterns)
                if (k, e) != (key, ext):
                    rekey.append((k, e, fid))
        with self.conn.cursor() as cur:
            cur.executemany("UPDATE pinakes.files SET name_key = %s, ext = %s WHERE file_id = %s", rekey)
        n["name keys updated"] = len(rekey)
        edges = self.q("SELECT from_file_id, to_file_id FROM pinakes.lineage WHERE evidence LIKE 'similar name%%' "
                       "AND decision IS NULL ORDER BY to_file_id").fetchall()
        old = {}
        for frm, to in edges:
            old.setdefault(to, []).append(frm)
        kept = moved = dropped = 0
        ids = list(old)
        st = _LineageState()
        for i in range(0, len(ids), self.lineage_round):
            part = ids[i:i + self.lineage_round]
            paths = dict(self.q("SELECT file_id, relpath FROM pinakes.files WHERE file_id = ANY(%s)", (part,)).fetchall())
            part = [fid for fid in part if fid in paths]
            new = {fid: (src, ev) for fid, src, ev in self.q(
                """SELECT t.fid, n.file_id, n.evidence
                   FROM (SELECT f.file_id AS fid, f.name_key AS key, f.ext, f.content_id AS content, f.mtime, f.size,
                                f.relpath, r.kind, x.rare_folder
                         FROM unnest(%s::bigint[], %s::boolean[]) AS x(fid, rare_folder)
                         JOIN pinakes.files f ON f.file_id = x.fid JOIN pinakes.roots r USING (root_id)) t
                   CROSS JOIN LATERAL (SELECT coalesce(min(h.seen_on + 0), %s::date) AS appeared FROM pinakes.history h
                                       WHERE h.file_id = t.fid) a
                   CROSS JOIN LATERAL (""" + NAME_CANDIDATE + """) n""",
                (part, self._rare(st, [paths[f] for f in part]), on) + self._name_params()).fetchall()}
            for to in part:
                src, ev = new.get(to, (None, None))
                for frm in old[to]:
                    if frm == src:
                        self.q("UPDATE pinakes.lineage SET evidence = %s WHERE from_file_id = %s AND to_file_id = %s "
                               "AND kind = 'derived_from'", (ev, frm, to))
                        kept += 1
                    else:
                        self.q("DELETE FROM pinakes.lineage WHERE from_file_id = %s AND to_file_id = %s "
                               "AND evidence LIKE 'similar name%%' AND decision IS NULL", (frm, to))
                if src is not None and src not in old[to]:
                    self.q("INSERT INTO pinakes.lineage (from_file_id, to_file_id, kind, evidence, confidence, found_on) "
                           "VALUES (%s, %s, 'derived_from', %s, 'possible', %s) ON CONFLICT DO NOTHING",
                           (src, to, ev, on))
                    moved += 1
                elif src is None:
                    dropped += 1
        n["name edges kept"], n["name edges to another source"], n["name edges removed"] = kept, moved, dropped
        return n

    # setup -----------------------------------------------------------------------------------------------------
    def enroll(self, reg):
        """Every indexed field of the registry's schemas gets its index; md_* indexes nothing wants are dropped."""
        return self.one("SELECT pinakes.enroll_metadata_indexes(%s::jsonb)",
                        (json.dumps([list(i) for i in reg.indexes()]),))[0]

    def seed(self):
        with self.conn.transaction():
            for name, p in self.cfg.people.items():
                self.q("INSERT INTO pinakes.people (name, display, roles) VALUES (%s, %s, %s) "
                       "ON CONFLICT (name) DO UPDATE SET display = EXCLUDED.display, roles = EXCLUDED.roles",
                       (name, p.get("display", name), p.get("roles", ["person"])))
            for gname, members in self.cfg.groups.items():
                gid = self.one("INSERT INTO pinakes.groups (name) VALUES (%s) ON CONFLICT (name) DO UPDATE "
                               "SET name = EXCLUDED.name RETURNING group_id", (gname,))[0]
                self.q("DELETE FROM pinakes.group_members WHERE group_id = %s", (gid,))
                for m in members:
                    self.q("INSERT INTO pinakes.group_members (group_id, person_id) "
                           "SELECT %s, person_id FROM pinakes.people WHERE name = %s", (gid, m))
            for name, h in self.cfg.hosts.items():
                self.q("INSERT INTO pinakes.hosts (name, expected_every) VALUES (%s, %s) ON CONFLICT (name) DO UPDATE "
                       "SET expected_every = EXCLUDED.expected_every", (name, h["expected_every"]))
            if self.cfg.default_owner:
                self.q("INSERT INTO pinakes.settings (key, value) VALUES ('default_owner', %s) "
                       "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (self.cfg.default_owner,))
            self.refresh_acl_members()


def schema_exists(conn):
    return conn.execute("SELECT to_regclass('pinakes.files') IS NOT NULL").fetchone()[0]


def schema_missing(conn):
    """What this release needs of the catalog that isn't there: ["schema.sql"] for no schema at all, else the
    upgrades/*.sql not yet run (compat.UPGRADE_PROBES), in order. Empty: the schema is applied."""
    if not schema_exists(conn):
        return ["schema.sql"]
    names_ = list(compat.UPGRADE_PROBES)
    row = conn.execute("SELECT %s" % ", ".join("(%s)" % compat.UPGRADE_PROBES[n] for n in names_)).fetchone()
    return [n for n, ok in zip(names_, row) if not ok]


def _syslog(message):
    """To the server's own log as well: what the forced command writes on stderr goes only to the agent."""
    try:
        import syslog
        syslog.openlog("pinakes-ingest", 0, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_WARNING, message)
    except (ImportError, OSError):
        pass


def apply_schema(conn):
    with open(SCHEMA_FILE) as f:
        sql = f.read()
    with conn.transaction():
        conn.execute(sql)


def read_batch(stream):
    data = stream.read()
    try:
        data = gzip.decompress(data)
    except OSError:
        raise Refused("not gzip")
    lines = [json.loads(l) for l in io.StringIO(data.decode()) if l.strip()]
    if not lines:
        raise Refused("empty batch")
    return lines[0], lines[1:]


class Watchdog:
    """Stops a batch whose sender hung up or that runs too long: cancels the running statement and exits.

    Exiting closes the database connection, and PostgreSQL rolls back the open transaction, whether a statement was
    running (cancelled) or not (idle in transaction). The batch is left as if never sent; the agent sends it again.
    """

    EXIT = 3

    def __init__(self, conn, hangup_fd=None, limit=None, exit=os._exit):
        self.conn, self.fd, self.limit, self._exit = conn, hangup_fd, limit, exit
        self.end = None
        self.stopping = threading.Event()
        self.poll = select.poll()
        if hangup_fd is not None:
            # a pipe's write end reports POLLERR when its reader closes; a socket reports POLLHUP or POLLRDHUP
            self.poll.register(hangup_fd, select.POLLERR | select.POLLHUP | getattr(select, "POLLRDHUP", 0))
        if hangup_fd is not None or limit:
            threading.Thread(target=self._run, name="pinakes-watchdog", daemon=True).start()

    def batch(self):
        """Time one batch against the limit: `with watchdog.batch(): ...`."""
        dog = self

        class _Batch:
            def __enter__(self):
                if dog.limit:
                    dog.end = time.monotonic() + dog.limit

            def __exit__(self, *exc):
                dog.end = None
                if dog.stopping.is_set():
                    # the batch failed because it was cancelled: leave the exit, and its message, to the watchdog
                    time.sleep(10)
                    dog._exit(dog.EXIT)

        return _Batch()

    def _run(self):
        while True:
            if self.fd is not None and self.poll.poll(1000):
                return self._stop("the sender hung up")
            if self.fd is None:
                time.sleep(1)
            end = self.end
            if end is not None and time.monotonic() >= end:
                return self._stop("the batch ran past max_batch_time (%ds)" % self.limit)

    def _stop(self, why):
        self.stopping.set()
        try:
            os.write(2, ("pinakes-ingest: %s; stopping, the batch is rolled back\n" % why).encode())
        except OSError:
            pass                                    # stderr went with the sender
        try:
            self.conn.cancel_safe(timeout=5)
        except Exception:
            pass                                    # closing the connection rolls back all the same
        self._exit(self.EXIT)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes-ingest", description=__doc__.split("\n")[0])
    ap.add_argument("--config", required=True)
    ap.add_argument("--host", help="the host whose key this is (set by the forced command)")
    ap.add_argument("cmd", nargs="?", choices=("setup", "inbox", "passwd", "recompute", "tidy", "totals", "hello"))
    ap.add_argument("dir", nargs="?")
    ap.add_argument("--dry-run", action="store_true", help="tidy: count what would change, change nothing")
    args = ap.parse_args(argv)
    if args.cmd is None and args.host and os.environ.get("SSH_ORIGINAL_COMMAND", "").strip() == "hello":
        args.cmd = "hello"                          # an agent's `ssh ... hello` through its forced key
    cfg = load_server_config(args.config)
    if args.cmd == "setup":
        try:
            reg = registry.load(cfg.schemas_dir)       # a bad schema stops setup before it changes anything
        except ConfigError as e:
            print("schema refused: %s" % e, file=sys.stderr)
            return 1
    with psycopg.connect(**cfg.connect_kwargs(), autocommit=True) as conn:
        if args.cmd == "setup":
            if not schema_exists(conn):
                # the schema belongs to the owner role, which can't log in: a superuser applies it once
                print("no schema yet. Apply it as its owner, then run setup again:\n"
                      "  psql -d pinakes -c 'SET ROLE pinakes_owner' -f - < %s\n"
                      "(on a server in Docker: sudo docker exec -i -u postgres CONTAINER psql ...)" % SCHEMA_FILE,
                      file=sys.stderr)
                return 2
            ing = Ingester(conn, cfg)
            ing.seed()
            print("seeded people, groups, hosts and settings")
            r = ing.enroll(reg)
            print("schemas %s; %d metadata indexes, %d made, %d dropped" % (
                ", ".join("%s %d" % (sc.name, sc.version) for sc in reg), len(r["wanted"]), len(r["created"]),
                len(r["dropped"])))
            return 0
        ing = Ingester(conn, cfg)
        if args.cmd == "hello":
            if not args.host:
                ap.error("--host is required for hello")
            try:
                req = json.loads(sys.stdin.buffer.read(4096) or b"{}")
            except ValueError:
                req = {}
            try:
                print(json.dumps(ing.hello(args.host, req if isinstance(req, dict) else {}), sort_keys=True))
            except Refused as e:
                print("refused: %s" % e, file=sys.stderr)
                return 1
            return 0
        if args.cmd in ("inbox", None):
            dog = Watchdog(conn, hangup_fd=None if args.cmd else sys.stdout.fileno(), limit=cfg.max_batch_time)
        if args.cmd == "passwd":
            import getpass
            from . import auth
            pid = conn.execute("SELECT person_id FROM pinakes.people WHERE name = %s", (args.dir,)).fetchone()
            if not pid:
                print("no person %r (add them to server.toml and run setup)" % args.dir, file=sys.stderr)
                return 1
            pw = getpass.getpass("New password for %s (12+ characters): " % args.dir)
            if len(pw) < 12 or pw != getpass.getpass("Again: "):
                print("too short, or the two didn't match; nothing changed", file=sys.stderr)
                return 1
            conn.execute("INSERT INTO pinakes.credentials (person_id, password_hash) VALUES (%s, %s) "
                         "ON CONFLICT (person_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated = now()",
                         (pid[0], auth.hash_password(pw)))
            print("password set for %s" % args.dir)
            return 0
        if args.cmd == "recompute":
            r = conn.execute("SELECT root_id FROM pinakes.roots WHERE label = %s", (args.dir,)).fetchone()
            if not r:
                print("no root %r" % args.dir, file=sys.stderr)
                return 1
            with conn.transaction():
                print("%d file(s) reassigned" % ing.recompute_root(r[0]))
            return 0
        if args.cmd == "totals":
            for host, label, n, size, pending in ing.totals():
                print("%s %s: %d files %d bytes%s" % (host, label, n, size,
                                                      "; %d pending (a scan is unfinished)" % pending if pending else ""))
            return 0
        if args.cmd == "tidy":
            with conn.transaction():
                for k, v in ing.tidy(queries.today()).items():
                    print("%s: %d" % (k, v))
                if args.dry_run:
                    print("dry run: nothing changed")
                    raise psycopg.Rollback()
            return 0
        if args.cmd == "inbox":
            rc = 0
            for name in sorted(os.listdir(args.dir)):
                if not name.endswith(".jsonl.gz"):
                    continue
                path = os.path.join(args.dir, name)
                with open(path, "rb") as f:
                    header, records = read_batch(f)
                try:
                    with dog.batch():
                        result = ing.apply(header, records, header.get("host"))
                except Refused as e:
                    print("%s: refused: %s" % (name, e), file=sys.stderr)
                    if isinstance(e, Incompatible):
                        _syslog("host %s: refused %s" % (header.get("host"), e))
                    rc = 1
                    continue
                os.remove(path)
                print("%s: %s" % (name, result))
            return rc
        if not args.host:
            ap.error("--host is required for a batch on stdin")
        try:
            header, records = read_batch(sys.stdin.buffer)
            with dog.batch():
                ing.apply(header, records, args.host)
        except Refused as e:
            print("refused: %s" % e, file=sys.stderr)
            if isinstance(e, Incompatible):
                _syslog("host %s: refused %s" % (args.host, e))
            return 1
        print("ack %d" % int(header["seq"]))
        return 0


if __name__ == "__main__":
    sys.exit(main())
