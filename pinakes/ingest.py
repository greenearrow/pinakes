"""pinakes-ingest: apply agents' batches to the catalog.

  pinakes-ingest --config server.toml --host NAME     one batch on stdin (the forced command of an agent's key)
  pinakes-ingest --config server.toml inbox DIR       every batch file waiting in DIR (the directory transport)
  pinakes-ingest --config server.toml setup           create the schema if needed and seed people, hosts, settings

Each batch is applied in one transaction. A host's batches apply in increasing sequence order; a number already
applied is acknowledged and ignored. Moves, changes, copies and lineage are worked out here, when a scan completes.
"""

import argparse
import datetime
import gzip
import io
import json
import os
import sys

import psycopg

from . import BATCH_FORMAT, names
from .server_config import load as load_server_config

SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


class Refused(Exception):
    """The batch is not acceptable (unknown host or root, bad format). Nothing is applied."""


def _ts(ns):
    if ns is None:
        return None
    return datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc)


def _under(relpath, folder):
    return folder == "" or relpath == folder or relpath.startswith(folder + "/")


class Ingester:
    def __init__(self, conn, cfg):
        self.conn = conn
        self.cfg = cfg
        self.patterns = names.load_patterns(cfg.name_patterns_file)
        self._acl_cache = {}

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
            self.q("UPDATE pinakes.roots SET path = %s, kind = %s, protected = %s, mirrors_layout = %s "
                   "WHERE root_id = %s", (d.get("path", ""), d.get("kind", r[2]), bool(d.get("protected")),
                                          mirrors.get("layout"), r[0]))
            root_id = r[0]
            new = False
        else:
            root_id = self.one(
                "INSERT INTO pinakes.roots (host_id, label, path, kind, protected, mirrors_layout) "
                "VALUES (%s, %s, %s, %s, %s, %s) RETURNING root_id",
                (host_id, label, d.get("path", ""), d.get("kind", "primary"), bool(d.get("protected")),
                 mirrors.get("layout")))[0]
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
        return root["mirrors_root_id"], "/".join(rparts[len(lparts) - 1:]), snapshot

    # applying a batch ------------------------------------------------------------------------------------------
    def apply(self, header, records, host):
        if header.get("t") != "batch" or header.get("format") != BATCH_FORMAT:
            raise Refused("not a batch of format %d" % BATCH_FORMAT)
        if header.get("host") != host:
            raise Refused("batch says host %r, key is for %r" % (header.get("host"), host))
        if host not in self.cfg.hosts:
            raise Refused("unknown host %r" % host)
        seq = int(header["seq"])
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
            root = self.one("SELECT root_id, kind, protected, mirrors_root_id, mirrors_layout, last_complete_on "
                            "FROM pinakes.roots WHERE root_id = %s", (root_id,))
            root = dict(zip(("root_id", "kind", "protected", "mirrors_root_id", "mirrors_layout",
                             "last_complete_on"), root))
            scan = int(header["scan"])
            started_on = datetime.date.fromisoformat(header["started"][:10])
            self.q("INSERT INTO pinakes.scans (root_id, scan, started_on) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                   (root_id, scan, started_on))
            ctx = {"root": root, "scan": scan, "on": started_on, "after": root["last_complete_on"],
                   "uid_map": self.cfg.hosts[host]["uid_map"]}
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
        return "applied"

    def _file(self, ctx, rec):
        root = ctx["root"]
        relpath = rec["path"]
        name = relpath.rsplit("/", 1)[-1]
        content_id = self.content(rec.get("sha256"), rec.get("size") or 0, rec.get("chunks"), rec.get("chunk_params"))
        if rec.get("members") and content_id and not root["protected"]:
            self._members(content_id, rec["members"])
        key, ext = names.normalize(name, self.patterns)
        cols = {"name": name, "content_id": content_id, "size": rec.get("size"),
                "mtime": _ts(rec.get("mtime_ns")), "ctime": _ts(rec.get("ctime_ns")), "btime": _ts(rec.get("btime_ns")),
                "mtime_ns": rec.get("mtime_ns"), "ctime_ns": rec.get("ctime_ns"), "btime_ns": rec.get("btime_ns"),
                "dev": rec.get("dev"), "ino": rec.get("ino"), "nlink": rec.get("nlink"), "uid": rec.get("uid"),
                "is_symlink": rec.get("t") == "symlink", "link_target": rec.get("target"),
                "unstable": bool(rec.get("unstable")), "name_key": key, "ext": ext}
        ex = self.one("SELECT file_id, content_id, mtime, ctime, btime FROM pinakes.files "
                      "WHERE root_id = %s AND relpath = %s AND gone_on IS NULL", (root["root_id"], relpath))
        if ex:
            file_id, old_content, old_m, old_c, old_b = ex
            if content_id is None and rec.get("unstable"):
                cols["content_id"] = old_content  # keep the last known content until it settles
            sets = ", ".join("%s = %%(%s)s" % (k, k) for k in cols)
            self.q("UPDATE pinakes.files SET %s, last_seen = now() WHERE file_id = %%(file_id)s" % sets,
                   dict(cols, file_id=file_id))
            if content_id is not None and old_content is not None and content_id != old_content:
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
        fields = "file_id, relpath, content_id, size, dev, ino, mtime, ctime, btime"
        new = {r[0]: r for r in self.q("SELECT %s FROM pinakes.files WHERE root_id = %%s AND pending_scan = %%s "
                                       "AND gone_on IS NULL" % fields, (root_id, scan)).fetchall()}
        touched = []
        for path in gone_paths:
            g = self.one("SELECT %s FROM pinakes.files WHERE root_id = %%s AND relpath = %%s AND gone_on IS NULL"
                         % fields, (root_id, path))
            if g is None:
                continue  # already gone (a repeated record)
            match = self._match_move(g, new)
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
        for n in new.values():
            self.q("INSERT INTO pinakes.history (file_id, kind, new_relpath, new_content_id, new_mtime, new_ctime, "
                   "new_btime, seen_after, seen_on) VALUES (%s, 'new', %s, %s, %s, %s, %s, %s, %s)",
                   (n[0], n[1], n[2], n[6], n[7], n[8], after, on))
            touched.append(n[0])
        touched += [r[0] for r in self.q("SELECT file_id FROM pinakes.files WHERE root_id = %s AND changed_scan = %s",
                                         (root_id, scan)).fetchall()]
        self.q("UPDATE pinakes.files SET pending_scan = NULL, changed_scan = NULL "
               "WHERE root_id = %s AND (pending_scan = %s OR changed_scan = %s)", (root_id, scan, scan))
        if ctx["root"]["kind"] != "backup":
            for file_id in dict.fromkeys(touched):
                self.lineage_for(file_id, on)
        self.q("UPDATE pinakes.scans SET completed = true WHERE root_id = %s AND scan = %s", (root_id, scan))
        self.q("UPDATE pinakes.roots SET last_complete_on = %s WHERE root_id = %s", (on, root_id))
        self.q("UPDATE pinakes.hosts SET last_scan = now() WHERE host_id = %s", (host_id,))
        self.q("DELETE FROM pinakes.scan_errors WHERE root_id = %s AND seen_on < %s", (root_id, on))

    def _match_move(self, g, new):
        """The new file g most likely became: same content, same inode, or shared chunks."""
        _, gpath, gcontent, gsize, gdev, gino = g[:6]
        gname = gpath.rsplit("/", 1)[-1]
        if gcontent is not None:
            same = [n for n in new.values() if n[2] == gcontent]
            if same:
                same.sort(key=lambda n: (n[1].rsplit("/", 1)[-1] != gname, n[1]))  # prefer the same name
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
                ov = self.chunk_overlap(gcontent, n[2])
                if ov >= self.cfg.chunk_overlap and (best is None or ov > best[1]):
                    best = (n, ov)
            if best:
                return best[0], "moved_changed", "chunks %.0f%% shared" % (100 * best[1]), "likely"
        return None

    def chunk_overlap(self, a, b):
        """Share of a's bytes found in b's chunks (by chunk digest)."""
        r = self.one("""SELECT coalesce(sum(ca.len), 0), (SELECT sum(len) FROM pinakes.content_chunks WHERE content_id = %s)
                        FROM pinakes.content_chunks ca
                        WHERE ca.content_id = %s AND ca.digest IN
                              (SELECT digest FROM pinakes.content_chunks WHERE content_id = %s)""", (a, a, b))
        return (r[0] / r[1]) if r and r[1] else 0.0

    def _merge_move(self, g, n, kind, evidence, confidence, after, on):
        """g's file_id lives on at n's path, with n's attributes; n's row goes."""
        cols = ("relpath, name, content_id, size, mtime, ctime, btime, mtime_ns, ctime_ns, btime_ns, dev, ino, nlink, "
                "uid, is_symlink, link_target, unstable, name_key, ext, acl_id, owner_id, backup_of, snapshot")
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
    def _edge(self, src, dst, kind, evidence, confidence, on):
        if src == dst:
            return
        self.q("INSERT INTO pinakes.lineage (from_file_id, to_file_id, kind, evidence, confidence, found_on) "
               "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING", (src, dst, kind, evidence, confidence, on))

    def _how_got(self, file_id, content_id):
        """'replaced_by' if the file came to hold this content by a change, else 'copied_from'."""
        r = self.one("SELECT kind FROM pinakes.history WHERE file_id = %s AND new_content_id = %s "
                     "ORDER BY history_id DESC LIMIT 1", (file_id, content_id))
        return "replaced_by" if r and r[0] in ("changed", "moved_changed") else "copied_from"

    def lineage_for(self, file_id, on):
        f = self.one("""SELECT f.file_id, f.content_id, f.mtime, f.dev, f.ino, r.host_id, f.name_key, f.ext, r.protected
                        FROM pinakes.files f JOIN pinakes.roots r USING (root_id) WHERE f.file_id = %s""", (file_id,))
        if f is None or f[1] is None:
            return
        _, content, mtime, dev, ino, host_id, name_key, ext, _protected = f
        # 1. identical content elsewhere (not a backup copy, not another link to the same inode)
        others = self.q("""SELECT o.file_id, o.mtime, o.first_seen FROM pinakes.files o JOIN pinakes.roots r USING (root_id)
                           WHERE o.content_id = %s AND o.file_id <> %s AND r.kind <> 'backup'
                             AND NOT (r.host_id = %s AND o.dev = %s AND o.ino = %s)""",
                        (content, file_id, host_id, dev, ino)).fetchall()
        if others:
            far = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
            earliest = min(others, key=lambda o: (o[1] or far, o[2]))
            if mtime is not None and earliest[1] is not None and mtime < earliest[1]:
                # this file had it first: it is the source of the copies that have no source yet
                for o in others:
                    if not self.one("SELECT 1 FROM pinakes.lineage WHERE to_file_id = %s AND evidence = 'same sha256' "
                                    "AND decision IS DISTINCT FROM 'rejected'", (o[0],)):
                        self._edge(file_id, o[0], self._how_got(o[0], content), "same sha256", "certain", on)
            else:
                self._edge(earliest[0], file_id, self._how_got(file_id, content), "same sha256", "certain", on)
            return
        # weaker evidence only for a file with no line of descent yet (a changed file keeps its own)
        if self.one("SELECT 1 FROM pinakes.lineage WHERE to_file_id = %s AND decision IS DISTINCT FROM 'rejected'",
                    (file_id,)) or self.one("SELECT 1 FROM pinakes.history WHERE file_id = %s AND kind <> 'new'",
                                            (file_id,)):
            return
        # 2. shared chunks with another content
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
                self._edge(src[0], file_id, "derived_from", "chunks %.0f%% shared" % (100 * best[1]), "likely", on)
                return
        # 3. the same name once copy markers, dates and versions are taken off
        if name_key:
            src = self.one("""SELECT o.file_id FROM pinakes.files o JOIN pinakes.roots r USING (root_id)
                              WHERE o.name_key = %s AND o.ext = %s AND o.file_id <> %s AND r.kind <> 'backup'
                                AND o.content_id IS DISTINCT FROM %s
                              ORDER BY (o.mtime <= %s) DESC, o.mtime DESC NULLS LAST LIMIT 1""",
                           (name_key, ext, file_id, content, mtime))
            if src:
                self._edge(src[0], file_id, "derived_from", "similar name", "possible", on)

    # setup -----------------------------------------------------------------------------------------------------
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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pinakes-ingest", description=__doc__.split("\n")[0])
    ap.add_argument("--config", required=True)
    ap.add_argument("--host", help="the host whose key this is (set by the forced command)")
    ap.add_argument("cmd", nargs="?", choices=("setup", "inbox"))
    ap.add_argument("dir", nargs="?")
    args = ap.parse_args(argv)
    cfg = load_server_config(args.config)
    with psycopg.connect(**cfg.connect_kwargs(), autocommit=True) as conn:
        if args.cmd == "setup":
            if not schema_exists(conn):
                apply_schema(conn)
                print("schema created")
            Ingester(conn, cfg).seed()
            print("seeded people, groups, hosts and settings")
            return 0
        ing = Ingester(conn, cfg)
        if args.cmd == "inbox":
            rc = 0
            for name in sorted(os.listdir(args.dir)):
                if not name.endswith(".jsonl.gz"):
                    continue
                path = os.path.join(args.dir, name)
                with open(path, "rb") as f:
                    header, records = read_batch(f)
                try:
                    result = ing.apply(header, records, header.get("host"))
                except Refused as e:
                    print("%s: refused: %s" % (name, e), file=sys.stderr)
                    rc = 1
                    continue
                os.remove(path)
                print("%s: %s" % (name, result))
            return rc
        if not args.host:
            ap.error("--host is required for a batch on stdin")
        try:
            header, records = read_batch(sys.stdin.buffer)
            ing.apply(header, records, args.host)
        except Refused as e:
            print("refused: %s" % e, file=sys.stderr)
            return 1
        print("ack %d" % int(header["seq"]))
        return 0


if __name__ == "__main__":
    sys.exit(main())
