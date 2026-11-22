"""The catalog's queries (QUERIES.md), parameterized. Every function runs as whoever the connection is set to:
row-level security decides what comes back. A location is ROOT:PATH, where ROOT is a root's label."""

import datetime
import json
import re

FILE_COLS = ("f.file_id, h.name AS host, r.label AS root, r.kind, f.relpath, f.size, f.mtime, f.snapshot, f.gone_on, "
             "f.hidden, f.unreadable_on, f.unreadable_error")


def today():
    """Today's date in UTC: the catalog's dates (a scan's seen_on, from the agent's UTC start time) are UTC dates,
    so a window or a cutoff from the server's local date would be a day off for part of every day."""
    return datetime.datetime.now(datetime.timezone.utc).date()


def split_location(loc):
    if ":" not in loc:
        raise ValueError("a location is ROOT:PATH, e.g. store:people/user-1/")
    root, path = loc.split(":", 1)
    return root, path.strip("/") if path.endswith("/") else path


def _prefix(path):
    """LIKE pattern for a folder (empty: the whole root), with LIKE's wildcards escaped."""
    esc = path.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return (esc + "/%") if esc else "%"


def rows(conn, sql, args=()):
    cur = conn.execute(sql, args)
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _like(text, wildcards=False):
    """ILIKE pattern for a substring, LIKE's own wildcards escaped; with `wildcards`, * and ? work as wildcards, and
    a pattern with none matches anywhere in the text."""
    like = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    if wildcards and ("*" in text or "?" in text):      # the text's own, not an escaped % or _ of LIKE's
        return like.replace("*", "%").replace("?", "_")
    return "%" + like + "%"


# Paging: a paged query selects TOTAL among its columns (the number of rows the whole query has, counted after any
# grouping) and ends with PAGE (limit and offset; a limit of None is no limit). page_total() reads the total back.
TOTAL = "count(*) OVER () AS total_rows"
PAGE = " LIMIT %s OFFSET %s"


def page_total(result):
    """The whole query's row count, from a page of it (0 for an empty page)."""
    return result[0]["total_rows"] if result else 0


# Sorting: each paged query has a whitelist, a column name the web UI may ask for mapped to the SQL it sorts by.
# order() builds the ORDER BY from the whitelist only: a name that isn't in it, or isn't a string, gets the query's
# default order, never interpolated text. The default order follows the chosen column and ends in a unique key, so
# rows that tie keep one order and pages neither overlap nor skip.
FILE_SORT = {"where": ("h.name", "r.label"), "path": ("f.relpath",), "size": ("f.size",), "modified": ("f.mtime",),
             "snapshot": ("f.snapshot",)}
LISTING_SORT = {"name": ("entry",), "files": ("files",), "size": ("size",), "newest": ("newest",)}
BACKED_UP_SORT = {"file": ("f.relpath",), "copies": ("backup_copies",), "snapshots": ("snapshots",),
                  "newest": ("newest",)}
DUPES_SORT = {"copies": ("copies",), "reclaimable": ("reclaimable",), "where": ("paths",)}
CHANGES_SORT = {"seen": ("hi.seen_on",), "where": ("h.name", "r.label"), "what": ("hi.kind",), "path": ("path",)}
CHANGES_PAGE_SORT = {"seen": ("p.seen_on",), "where": ("p.host", "p.root"), "what": ("p.kind",), "path": ("p.path",)}
HISTORY_SORT = {"between": ("h.seen_on",), "what": ("h.kind",),
                "path": ("coalesce(h.new_relpath, h.old_relpath)",), "evidence": ("h.evidence",)}
VERSIONS_SORT = {"sha256": ("c.sha256",), "first_seen": ("v.first_seen_on",), "backup": ("r.label",),
                 "snapshot": ("b.snapshot",)}
AUDIT_SORT = {"when": ("a.at",), "who": ("p.display",), "what": ("a.action",)}


def order(sorts, sort, direction, default):
    """ORDER BY the whitelisted column `sort` ("asc" or "desc"; anything else is "asc"), then `default`."""
    cols = sorts.get(sort) if isinstance(sort, str) else None
    if not cols:
        return " ORDER BY " + default
    d = "DESC" if direction == "desc" else "ASC"
    return " ORDER BY " + ", ".join("%s %s NULLS LAST" % (c, d) for c in cols) + ", " + default


# A list that holds copies (ROADMAP 68): `backups` None is the rows as they come (the web's pages, for now); "fold"
# lists the primary and drop rows first, each with `backups`, the backup copies of its content in the answer, and a
# content found only in backup roots once, as its newest snapshot (`backups`: the others); "all" lists every copy,
# the primary and drop rows first, each with the same count. Counted over the whole answer under row-level security,
# so a count is of the copies the person can see. A file without content (not hashed yet) is a content of its own.
# Each row of a folded answer has total_rows (the rows listed) and folded_rows (the backup copies left out of them).
# A placeholder (ROADMAP 69) is folded by file, not by content: its other holders aren't copies of it, while its own
# backups (backup_of) are.
BACKUPS = (None, "fold", "all")
_FOLD_COLS = ("in_backup", "in_others", "in_backups", "rank_in", "pos", "all_rows")
_PLACEHOLDER = "EXISTS (SELECT 1 FROM pinakes.placeholders pp WHERE pp.content_id = %s.content_id)"
_FOLD_KEY = ("CASE WHEN " + _PLACEHOLDER % "f" + " THEN -coalesce(f.backup_of, f.file_id) "
             "ELSE coalesce(f.content_id, -f.file_id) END")


def copies(conn, cols, body, args, ordering, backups, limit, offset):
    """SELECT cols (FILE_COLS first) body ORDER BY ordering, a page of it, folded as `backups` says (above)."""
    if backups not in BACKUPS:
        raise ValueError("backups is fold or all")
    if backups is None:
        return rows(conn, "SELECT %s, %s %s ORDER BY %s" % (cols, TOTAL, body, ordering) + PAGE,
                    args + (limit, offset))
    keep = "true" if backups == "all" else "NOT x.in_backup OR (x.in_others = 0 AND x.rank_in = 1)"
    got = rows(conn, """SELECT x.*, count(*) OVER () AS total_rows, x.all_rows - count(*) OVER () AS folded_rows
                        FROM (SELECT %s, r.kind = 'backup' AS in_backup,
                                     count(*) FILTER (WHERE r.kind <> 'backup')
                                         OVER (PARTITION BY %s) AS in_others,
                                     count(*) FILTER (WHERE r.kind = 'backup')
                                         OVER (PARTITION BY %s) AS in_backups,
                                     row_number() OVER (PARTITION BY %s,
                                                                     r.kind = 'backup'
                                                        ORDER BY f.snapshot DESC NULLS LAST, r.label, f.relpath,
                                                                 f.file_id) AS rank_in,
                                     row_number() OVER (ORDER BY %s) AS pos, count(*) OVER () AS all_rows
                              %s) x
                        WHERE %s ORDER BY x.in_backup, x.pos""" % (cols, _FOLD_KEY, _FOLD_KEY, _FOLD_KEY,
                                                                    ordering, body, keep) + PAGE,
               args + (limit, offset))
    for r in got:
        r["backups"] = r["in_backups"] - r["in_backup"]
        for k in _FOLD_COLS:
            del r[k]
    return got


def folded(result):
    """How many backup copies a folded answer left out of its rows (0 for an empty page)."""
    return result[0].get("folded_rows", 0) if result else 0


def _order_by(sorts, sort, direction, default):
    return order(sorts, sort, direction, default)[len(" ORDER BY "):]


PLACEHOLDERS = (True, False, "only")


def _placeholders_cond(placeholders):
    """A filter on files f by placeholders (ROADMAP 69): True every file, False none of a placeholder's, "only"
    only those."""
    if placeholders not in PLACEHOLDERS:
        raise ValueError("placeholders is shown, hidden or only")
    return {True: "", False: " AND NOT " + _PLACEHOLDER % "f", "only": " AND " + _PLACEHOLDER % "f"}[placeholders]


def find(conn, pattern, limit=None, offset=0, sort=None, direction="asc", backups=None, placeholders=True):
    """Files by name or glob. `placeholders` False leaves out the files of placeholders, "only" lists only them."""
    like = _like(pattern, wildcards=True)
    return copies(conn, FILE_COLS, """FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                                      JOIN pinakes.hosts h USING (host_id) WHERE f.name ILIKE %s"""
                  + _placeholders_cond(placeholders), (like,),
                  _order_by(FILE_SORT, sort, direction, "f.name, h.name, f.file_id"), backups, limit, offset)


def file_at(conn, loc):
    root, path = split_location(loc)
    r = rows(conn, """SELECT %s, f.content_id FROM pinakes.files f JOIN pinakes.roots r USING (root_id)
                      JOIN pinakes.hosts h USING (host_id) WHERE r.label = %%s AND f.relpath = %%s
                      ORDER BY f.gone_on NULLS FIRST, f.file_id DESC LIMIT 1""" % FILE_COLS, (root, path))
    return r[0] if r else None


def file_by_id(conn, file_id):
    r = rows(conn, """SELECT %s, f.content_id, encode(c.sha256, 'hex') AS sha256, f.ctime, f.btime, f.first_seen,
                             f.last_seen, f.backup_of, p.display AS owner, r.protected AS root_protected,
                             f.protected_link, f.is_symlink, f.link_target, f.link_root, f.link_relpath,
                             f.link_dangling,
                             (SELECT t.file_id FROM pinakes.present t JOIN pinakes.roots tr USING (root_id)
                              WHERE f.is_symlink AND tr.label = f.link_root AND t.relpath = f.link_relpath
                              LIMIT 1) AS link_file_id,
                             f.manifest_verdict, f.manifest_on, f.manifest_counts,
                             (SELECT m.file_id FROM pinakes.present m WHERE m.file_id = f.manifest_file_id)
                                 AS manifest_file_id,
                             (SELECT m.relpath FROM pinakes.present m WHERE m.file_id = f.manifest_file_id)
                                 AS manifest_relpath
                      FROM pinakes.files f JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                      LEFT JOIN pinakes.contents c ON c.content_id = f.content_id
                      LEFT JOIN pinakes.people p ON p.person_id = f.owner_id
                      WHERE f.file_id = %%s""" % FILE_COLS, (file_id,))
    return r[0] if r else None


def where(conn, file_id, limit=None, offset=0, sort=None, direction="asc", backups=None):
    """Every copy; same_inode marks hard links of this very file (the same data on the same disk, not a copy). Of a
    placeholder (ROADMAP 69), only the file, its hard links and its own backups: the other files holding the same
    default bytes aren't copies of it."""
    return copies(conn, FILE_COLS + ", (r.host_id = tr.host_id AND f.dev = t.dev AND f.ino = t.ino) AS same_inode",
                  """FROM pinakes.files t JOIN pinakes.roots tr ON tr.root_id = t.root_id
                     JOIN pinakes.present f ON f.content_id = t.content_id
                     JOIN pinakes.roots r ON r.root_id = f.root_id JOIN pinakes.hosts h ON h.host_id = r.host_id
                     WHERE t.file_id = %s AND (NOT """ + _PLACEHOLDER % "t" + """ OR f.file_id = t.file_id
                                               OR f.backup_of = t.file_id
                                               OR coalesce(r.host_id = tr.host_id AND f.dev = t.dev
                                                           AND f.ino = t.ino, false))""", (file_id,),
                  _order_by(FILE_SORT, sort, direction, "r.kind, h.name, f.relpath, f.file_id"), backups, limit, offset)


# Copies of a file f (in root r) outside a folder, counted physically: distinct (host, device, inode), never f's own
# inode (a hard link of f is the same data, not a copy). A copy is on another disk when its host differs, or its
# device does on the same host; a device the catalog doesn't know counts as the same disk. A copy the scrub couldn't
# read (unreadable_on) is no copy until it reads again (DESIGN.md "Scrub"). Of a placeholder (ROADMAP 69), only f's
# own backups (backup_of) count: the other files holding the same default bytes aren't copies. %%s: the folder's
# pattern.
_COPIES = """CROSS JOIN LATERAL (
        SELECT count(DISTINCT (ro.host_id, o.dev, o.ino))
                   FILTER (WHERE NOT coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS same_disk,
               count(DISTINCT (ro.host_id, o.dev, o.ino))
                   FILTER (WHERE coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS other_disk
        FROM pinakes.present o JOIN pinakes.roots ro ON ro.root_id = o.root_id
        WHERE o.content_id = f.content_id AND o.unreadable_on IS NULL
          AND NOT (o.root_id = f.root_id AND o.relpath LIKE %%s)
          AND NOT coalesce(ro.host_id = r.host_id AND o.dev = f.dev AND o.ino = f.ino, false)
          AND (o.backup_of = f.file_id OR NOT """ + _PLACEHOLDER % "f" + """) %s) s"""
COPY_SORT = dict(FILE_SORT, same_disk=("s.same_disk",))


def _no_copy_on_another_disk(conn, loc, kinds, limit, offset, sort, direction):
    root, path = split_location(loc)
    pre = _prefix(path)
    # the folder's files, or the file itself: a file given would otherwise have nothing under it, which reads as safe
    return rows(conn, """SELECT %s, s.same_disk, %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) %s
                         WHERE r.label = %%s AND (f.relpath LIKE %%s OR f.relpath = %%s) AND s.other_disk = 0
                           AND NOT f.is_symlink"""
                % (FILE_COLS, TOTAL, _COPIES % ("AND ro.kind IN ('primary', 'backup')" if kinds else ""))
                + order(COPY_SORT, sort, direction, "f.relpath, f.file_id") + PAGE,
                (pre, root, pre, path, limit, offset))


def only_here(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """The files under loc with no copy on another disk. same_disk: their copies outside loc on the same disk, which
    die with it (0: no copy anywhere else)."""
    return _no_copy_on_another_disk(conn, loc, False, limit, offset, sort, direction)


def not_safe_to_delete(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """The files under loc with no copy in a primary or backup root on another disk. Empty: safe. same_disk: their
    kept copies outside loc on the same disk, which don't make them safe."""
    return _no_copy_on_another_disk(conn, loc, True, limit, offset, sort, direction)


def links_into(conn, loc, limit=None, offset=0):
    """Symlinks outside loc that lead into it, or to it: deleting the folder would leave them dangling. Only those
    the person can see (row-level security); only links whose agent also scans loc's root (same host)."""
    root, path = split_location(loc)
    pre = _prefix(path)
    return rows(conn, """SELECT %s, f.link_target, f.link_relpath, %s FROM pinakes.present f
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         WHERE f.is_symlink AND f.link_root = %%s AND (f.link_relpath LIKE %%s OR f.link_relpath = %%s)
                           AND NOT (r.label = %%s AND f.relpath LIKE %%s)
                         ORDER BY r.label, f.relpath, f.file_id""" % (FILE_COLS, TOTAL) + PAGE,
                (root, pre, path, root, pre, limit, offset))


def backed_up(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """Per file: physical backup copies (distinct host, device and inode: hard-linked snapshots are one copy), the
    snapshots that hold the current version, and the newest of them. `with_backup`: how many of all the files (not
    only the page's) have at least one copy, since the page is sorted unbacked first."""
    root, path = split_location(loc)
    return rows(conn, """SELECT f.file_id, f.relpath,
                                count(DISTINCT (br.host_id, b.dev, b.ino)) FILTER (WHERE b.file_id IS NOT NULL)
                                    AS backup_copies,
                                count(b.file_id) AS snapshots, max(b.snapshot) AS newest,
                                sum((count(b.file_id) > 0)::int) OVER () AS with_backup, """ + TOTAL + """
                         FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         LEFT JOIN pinakes.present b ON b.backup_of = f.file_id AND b.content_id = f.content_id
                                                     AND b.unreadable_on IS NULL
                         LEFT JOIN pinakes.roots br ON br.root_id = b.root_id
                         WHERE r.label = %s AND (f.relpath LIKE %s OR f.relpath = %s)
                         GROUP BY f.file_id, f.relpath"""
                + order(BACKED_UP_SORT, sort, direction, "backup_copies, f.relpath, f.file_id") + PAGE,
                (root, _prefix(path), path, limit, offset))


MANIFEST_SORT = {"where": ("x.host", "x.root"), "path": ("x.relpath",), "what": ("x.problem",),
                 "checked": ("x.checked_on",)}


def manifests(conn, loc=None, limit=None, offset=0, sort=None, direction="asc"):
    """What checksum manifests found (DESIGN.md "Checksum manifests"), under a folder or everywhere: each present file
    a manifest lists with another hash than the agent's (problem 'wrong', with the manifest if visible), and each
    manifest listing files that aren't there (problem 'missing', with how many). Rows are files under the files
    policy: a manifest's counts are seen by whoever sees the manifest."""
    root, path = split_location(loc) if loc else (None, "")
    return rows(conn, """SELECT x.*, """ + TOTAL + """ FROM (
                             SELECT """ + FILE_COLS + """, 'wrong' AS problem, f.manifest_on AS checked_on,
                                    m.file_id AS manifest_id, m.relpath AS manifest_relpath, NULL::int AS missing
                             FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                             JOIN pinakes.hosts h USING (host_id)
                             LEFT JOIN pinakes.present m ON m.file_id = f.manifest_file_id
                             WHERE f.manifest_verdict = 'wrong'
                               AND (%s::text IS NULL OR (r.label = %s AND (f.relpath LIKE %s OR f.relpath = %s)))
                             UNION ALL
                             SELECT """ + FILE_COLS + """, 'missing', f.last_seen::date, f.file_id, f.relpath,
                                    (f.manifest_counts->>'missing')::int
                             FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                             JOIN pinakes.hosts h USING (host_id)
                             WHERE (f.manifest_counts->>'missing')::int > 0
                               AND (%s::text IS NULL OR (r.label = %s AND (f.relpath LIKE %s OR f.relpath = %s)))
                         ) x"""
                + order(MANIFEST_SORT, sort, direction, "x.host, x.root, x.relpath, x.problem, x.file_id") + PAGE,
                (root, root, _prefix(path), path) * 2 + (limit, offset))


def dupes(conn, limit=None, offset=0, sort=None, direction="asc"):
    """The same content stored more than once. copies counts physical copies (host, device, inode): hard links share
    their storage, so they are paths, not copies, and reclaim nothing. Empty files are not duplicates: they all have
    the same hash, take no space and reclaim nothing. Nor are placeholders (ROADMAP 69): an app's default bytes."""
    return rows(conn, """SELECT encode(c.sha256, 'hex') AS sha256, c.size,
                                count(DISTINCT (r.host_id, f.dev, f.ino)) AS copies, count(*) AS paths_count,
                                c.size * (count(DISTINCT (r.host_id, f.dev, f.ino)) - 1) AS reclaimable,
                                array_agg(r.label || ':' || f.relpath ORDER BY r.label, f.relpath) AS paths,
                                """ + TOTAL + """
                         FROM pinakes.present f JOIN pinakes.contents c USING (content_id)
                         JOIN pinakes.roots r USING (root_id)
                         WHERE r.kind <> 'backup' AND c.size > 0
                           AND NOT EXISTS (SELECT 1 FROM pinakes.placeholders pp WHERE pp.content_id = c.content_id)
                         GROUP BY c.content_id
                         HAVING count(DISTINCT (r.host_id, f.dev, f.ino)) > 1"""
                + order(DUPES_SORT, sort, direction, "reclaimable DESC, c.content_id") + PAGE, (limit, offset))


FOLDER_COPIES_SORT = {"size": ("bytes",), "files": ("files",), "where": ("folder",), "relation": ("relation",)}
NEAR_PERCENT = 10      # "nearly the same": every file of the folder is in the other, at most this share (min. 1) edited

# A folder is the set of its files' (path inside it, content): the whole subtree, empty files, placeholders (ROADMAP
# 69) and symlinks left out (they all hash alike or hold no data), backup roots too (a backup copying a folder is its
# job). Only what the scope asks about is built (ROADMAP 61: building every folder's entries of the catalog took 5.7 s
# for a folder of 2,000 files among 500,000): the entries of the scope's folders (es), the entries of every file
# holding one of their contents (ec, where another folder holding them is found), and each candidate other folder's
# files looked up by path (by index). An entry is a file in one of its ancestor folders, the root's own folder ('')
# included.
_ENTRIES = """SELECT x.root_id, d.dir, substr(x.relpath, CASE WHEN d.dir = '' THEN 1 ELSE length(d.dir) + 2 END) AS rel,
                     x.content_id, x.size
              FROM %s x CROSS JOIN LATERAL (
                  SELECT '' AS dir
                  UNION ALL SELECT left(x.relpath, i - 1) FROM generate_series(1, length(x.relpath)) i
                  WHERE substr(x.relpath, i, 1) = '/') d"""
_FOLDER_COPIES = """
WITH sf AS (SELECT f.root_id, f.relpath, f.content_id, c.size
            FROM pinakes.present f JOIN pinakes.roots r USING (root_id) JOIN pinakes.contents c USING (content_id)
            WHERE r.label = %(root)s AND r.kind <> 'backup' AND c.size > 0 AND NOT f.is_symlink
              AND NOT """ + _PLACEHOLDER % "c" + """
              AND (%(path)s = '' OR f.relpath ~>=~ %(lo)s AND f.relpath ~<~ %(hi)s)),
es AS (SELECT * FROM (""" + _ENTRIES % "sf" + """) e
       WHERE %(path)s = '' OR e.dir = %(path)s OR left(e.dir, length(%(path)s) + 1) = %(path)s || '/'),
ns AS (SELECT root_id, dir, count(*) AS n FROM es GROUP BY root_id, dir),
ef AS (SELECT f.root_id, f.relpath, f.content_id, k.size
       FROM (SELECT DISTINCT content_id, size FROM sf) k JOIN pinakes.present f USING (content_id)
       JOIN pinakes.roots r USING (root_id) WHERE r.kind <> 'backup' AND NOT f.is_symlink),
ec AS (""" + _ENTRIES % "ef" + """),
held AS (SELECT rel, content_id, count(*) AS h FROM ec GROUP BY rel, content_id),
-- a folder's rarest entries are where to look for what holds them: a folder that is the same, or inside another, holds
-- all of them; one with k files edited holds at least one of its k + 1 rarest
anchors AS (SELECT * FROM (SELECT e.root_id, e.dir, e.rel, e.content_id, m.n,
                                  row_number() OVER (PARTITION BY e.root_id, e.dir ORDER BY held.h, e.rel) AS rk
                           FROM es e JOIN ns m USING (root_id, dir) JOIN held USING (rel, content_id)) x
            WHERE rk <= greatest(1, x.n * %(near)s / 100) + 1),
cand AS (SELECT DISTINCT a.root_id AS ra, a.dir AS da, b.root_id AS rb, b.dir AS db
         FROM anchors a JOIN ec b ON b.rel = a.rel AND b.content_id = a.content_id
         WHERE NOT (a.root_id = b.root_id AND (a.dir = b.dir OR a.dir = '' OR b.dir = ''
                    OR left(b.dir, length(a.dir) + 1) = a.dir || '/' OR left(a.dir, length(b.dir) + 1) = b.dir || '/'))),
-- The other folders' files, by the relpath index. Each path is made first (MATERIALIZED) and compared as a value:
-- under row-level security only a leakproof comparison is used as an index condition, and || is not leakproof.
-- A folder's files: db/ up to db0 ('0' follows '/'); its root's all, for '' (a count of its own: in an OR, the range
-- would not be an index condition either).
od AS MATERIALIZED (SELECT DISTINCT rb, db, db || '/' AS lo, db || '0' AS hi FROM cand),
nc AS MATERIALIZED (
    SELECT o.rb, o.db, (SELECT count(*) FROM pinakes.present f JOIN pinakes.contents oc USING (content_id)
                        WHERE o.db <> '' AND f.root_id = o.rb AND f.relpath ~>=~ o.lo AND f.relpath ~<~ o.hi
                          AND NOT f.is_symlink AND oc.size > 0 AND NOT """ + _PLACEHOLDER % "oc" + """)
                     + (SELECT count(*) FROM pinakes.present f JOIN pinakes.contents oc USING (content_id)
                        WHERE o.db = '' AND f.root_id = o.rb AND NOT f.is_symlink AND oc.size > 0
                          AND NOT """ + _PLACEHOLDER % "oc" + """) AS n
    FROM od o),
-- each entry of the folder against the file at the same path in the other: the same content, another, or none
pe AS MATERIALIZED (SELECT c.ra, c.da, c.rb, c.db, ea.rel, ea.content_id, ea.size,
                           CASE WHEN c.db = '' THEN ea.rel ELSE c.db || '/' || ea.rel END AS opath
                    FROM cand c JOIN es ea ON ea.root_id = c.ra AND ea.dir = c.da),
pairs AS (SELECT pe.ra, pe.da, pe.rb, pe.db, count(*) FILTER (WHERE o.content_id = pe.content_id) AS shared,
                 array_agg(pe.rel ORDER BY pe.rel) FILTER (WHERE o.content_id <> pe.content_id) AS differing,
                 sum(pe.size) AS bytes
          FROM pe LEFT JOIN LATERAL (SELECT f.content_id FROM pinakes.present f
                                     JOIN pinakes.contents oc USING (content_id)
                                     WHERE f.root_id = pe.rb AND f.relpath = pe.opath AND NOT f.is_symlink
                                       AND oc.size > 0 AND NOT """ + _PLACEHOLDER % "oc" + """) o ON true
          GROUP BY pe.ra, pe.da, pe.rb, pe.db),
res AS (SELECT p.ra, p.da, p.rb, p.db, p.bytes, na.n AS files, nb.n AS other_files, p.shared, p.differing,
               CASE WHEN p.shared = na.n AND na.n = nb.n THEN 'same'
                    WHEN p.shared = na.n THEN 'inside'
                    WHEN p.shared + cardinality(p.differing) = na.n
                         AND cardinality(p.differing) <= greatest(1, na.n * %(near)s / 100) THEN 'nearly'
               END AS relation
        FROM pairs p JOIN ns na ON na.root_id = p.ra AND na.dir = p.da JOIN nc nb ON nb.rb = p.rb AND nb.db = p.db),
kept AS (SELECT p.* FROM res p
         WHERE p.relation IS NOT NULL
           -- two folders in scope that are the same are one row, not two
           AND NOT (p.relation = 'same' AND (p.ra, p.da) > (p.rb, p.db)
                    AND EXISTS (SELECT 1 FROM ns m WHERE m.root_id = p.rb AND m.dir = p.db))
           -- a subfolder of a folder already shown with the same relation to the same other side is nothing new
           AND NOT EXISTS (SELECT 1 FROM res q WHERE q.relation = p.relation AND q.ra = p.ra AND q.rb = p.rb
                           AND p.da = CASE WHEN q.da = '' THEN '' ELSE q.da || '/' END || regexp_replace(p.da, '^.*/', '')
                           AND p.db = CASE WHEN q.db = '' THEN '' ELSE q.db || '/' END || regexp_replace(p.db, '^.*/', '')))
SELECT ra.label || ':' || k.da AS folder, rb.label || ':' || k.db AS other, k.relation, k.files, k.other_files,
       k.files - k.shared - coalesce(cardinality(k.differing), 0) AS only_in_folder,
       k.other_files - k.shared - coalesce(cardinality(k.differing), 0) AS only_in_other,
       coalesce(k.differing, '{}') AS differing, k.bytes, """ + TOTAL + """
FROM kept k JOIN pinakes.roots ra ON ra.root_id = k.ra JOIN pinakes.roots rb ON rb.root_id = k.rb"""


def folder_copies(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """Folders under loc (a root or a folder, ROOT:PATH) that are copies of another folder, anywhere you can see: the
    same files at the same paths inside ('same'), all of them held by a bigger folder ('inside'), or all held with a
    few edited, listed in `differing` ('nearly': at most NEAR_PERCENT of the files, at least one). A subfolder
    whose parent is shown with the same relation to the same other folder is left out; folders of only empty files
    are ignored. Biggest first. Counts are of the files you can see. The work grows with the scope, not the catalog: a
    folder of 2,000 files among 500,000 takes a tenth of a second, the whole root seconds; on a very large root, ask
    for a smaller folder."""
    root, path = split_location(loc)
    return rows(conn, _FOLDER_COPIES + order(FOLDER_COPIES_SORT, sort, direction, "k.bytes DESC, folder, other")
                + " LIMIT %(limit)s OFFSET %(offset)s",
                {"root": root, "path": path, "lo": path + "/", "hi": path + "0", "near": NEAR_PERCENT, "limit": limit,
                 "offset": offset})


def folder_owners(conn, locs):
    """Owner person ids of the files under these folders (ROOT:PATH), for the step-up audit of a page that names
    folders. Only files the person can see (row-level security)."""
    pairs = [split_location(loc) for loc in locs]
    if not pairs:
        return []
    return [r[0] for r in conn.execute(
        """SELECT DISTINCT f.owner_id FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
           JOIN unnest(%s::text[], %s::text[]) AS w(label, path)
             ON r.label = w.label AND (w.path = '' OR left(f.relpath, length(w.path) + 1) = w.path || '/')
           WHERE f.owner_id IS NOT NULL""",
        ([p[0] for p in pairs], [p[1] for p in pairs])).fetchall()]


def history(conn, file_id, limit=None, offset=0, sort=None, direction="asc"):
    return rows(conn, """SELECT h.seen_after, h.seen_on, h.kind, h.old_relpath, h.new_relpath,
                                encode(oc.sha256, 'hex') AS old_sha256, encode(nc.sha256, 'hex') AS new_sha256,
                                h.old_mtime, h.new_mtime, h.evidence, h.confidence, """ + TOTAL + """
                         FROM pinakes.history h
                         LEFT JOIN pinakes.contents oc ON oc.content_id = h.old_content_id
                         LEFT JOIN pinakes.contents nc ON nc.content_id = h.new_content_id
                         WHERE h.file_id = %s"""
                + order(HISTORY_SORT, sort, direction, "h.seen_on, h.history_id") + PAGE, (file_id, limit, offset))


KINDS = ("new", "changed", "moved", "moved_changed", "gone", "mismatch", "unreadable")


def _kinds(kinds):
    """The history kinds asked for, whitelisted; None (no filter) when none are."""
    k = [x for x in (kinds or ()) if x in KINDS]
    return k or None


REVIEWABLE = ("gone", "moved", "moved_changed", "mismatch", "unreadable")   # the kinds a review marks (ROADMAP 32,
                                                                            # 41)
REVIEWS = ("unreviewed", "reviewed")


def _review(review):
    return review if review in REVIEWS else None


# The review filter on history hi with its mark m: unreviewed is a reviewable change with no mark.
_REVIEW_WHERE = """(%%s::text IS NULL OR (%%s = 'reviewed' AND m.history_id IS NOT NULL)
                     OR (%%s = 'unreviewed' AND m.history_id IS NULL
                         AND hi.kind IN (%s)))""" % ", ".join("'%s'" % k for k in REVIEWABLE)


# A root's first scan records every file as new (seen_after NULL): the catalog starting, not a change. Left out of the
# changes page, as growth() leaves it out; a file's own history (history()) still shows it. Without this, a window
# holding a first scan reads every file in the root (ROADMAP 52: 30 s to 7 s, generated 2M files).
_NOT_FIRST = "NOT (hi.kind = 'new' AND hi.seen_after IS NULL)"


def changes(conn, days=7, host=None, limit=None, offset=0, sort=None, direction="asc", kinds=None, loc=None,
            review=None, until=None, elsewhere=False):
    """History in the last `days` (and up to `until`, a date), optionally only some kinds, only what touched a folder
    or a file (ROOT:PATH; a move counts at both ends), only unreviewed or reviewed changes, and only gone files whose
    last content is still in another root you can see, not a backup (`elsewhere`). Each row has its review mark, and for
    a gone file the copies of its last content you can see: `elsewhere` (primary and drop roots, one shown in
    `elsewhere_at`) and `backups`. A root's first scan is not a change: its new files are left out (_NOT_FIRST)."""
    since = today() - datetime.timedelta(days=days)
    root, pre, path = (None, None, None)
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
    rv = _review(review)
    # The page first, then the copies for its rows only. The total counts every matching row, so with the copy lookup
    # inside, it ran for every gone file in the window: 193 k rows, cancelled at 300 s on a 3.4 M-file catalog. No sort
    # reads the copies; `elsewhere` filters by EXISTS, which stops at the first copy.
    return rows(conn, """SELECT p.seen_on, p.host, p.root, p.path, p.old_relpath, p.kind, p.file_id, p.history_id,
                                p.reviewable, p.mark, p.marked_at, coalesce(mp.display, mg.name) AS marked_by,
                                c.elsewhere, c.elsewhere_at, c.backups, p.total_rows
                         FROM (SELECT hi.seen_on, h.name AS host, r.label AS root,
                                      coalesce(hi.new_relpath, hi.old_relpath) AS path, hi.old_relpath, hi.kind,
                                      hi.file_id, hi.history_id, hi.old_content_id,
                                      hi.kind IN ('gone', 'moved', 'moved_changed', 'mismatch', 'unreadable') AS reviewable,
                                      m.mark, m.marked_at, m.marked_by, m.marked_by_group, """ + TOTAL + """
                               FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                               JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                               LEFT JOIN pinakes.review_marks m ON m.history_id = hi.history_id
                               WHERE hi.seen_on >= %s AND (%s::date IS NULL OR hi.seen_on <= %s)
                                 AND """ + _NOT_FIRST + """
                                 AND (%s::text IS NULL OR h.name = %s)
                                 AND (%s::text[] IS NULL OR hi.kind = ANY (%s::text[]))
                                 AND (%s::text IS NULL OR r.label = %s AND (hi.new_relpath LIKE %s OR hi.old_relpath LIKE %s
                                                                             OR hi.new_relpath = %s OR hi.old_relpath = %s))
                                 AND """ + _REVIEW_WHERE + """
                                 AND (NOT %s OR hi.kind = 'gone' AND EXISTS (
                                          SELECT 1 FROM pinakes.present o JOIN pinakes.roots ro ON ro.root_id = o.root_id
                                          WHERE o.content_id = hi.old_content_id AND o.unreadable_on IS NULL
                                            AND ro.kind <> 'backup'))"""
                + order(CHANGES_SORT, sort, direction, "hi.seen_on DESC, path, hi.history_id") + PAGE + """) p
                         LEFT JOIN pinakes.people mp ON mp.person_id = p.marked_by
                         LEFT JOIN pinakes.groups mg ON mg.group_id = p.marked_by_group
                         LEFT JOIN LATERAL (
                             SELECT count(*) FILTER (WHERE ro.kind <> 'backup') AS elsewhere,
                                    min(oh.name || ' · ' || ro.label || ':' || o.relpath)
                                        FILTER (WHERE ro.kind <> 'backup') AS elsewhere_at,
                                    count(DISTINCT (ro.host_id, o.dev, o.ino)) FILTER (WHERE ro.kind = 'backup')
                                        AS backups
                             FROM pinakes.present o JOIN pinakes.roots ro ON ro.root_id = o.root_id
                             JOIN pinakes.hosts oh ON oh.host_id = ro.host_id
                             WHERE p.kind = 'gone' AND o.content_id = p.old_content_id
                               AND o.unreadable_on IS NULL) c ON true"""
                + order(CHANGES_PAGE_SORT, sort, direction, "p.seen_on DESC, p.path, p.history_id"),
                (since, until, until, host, host, _kinds(kinds), _kinds(kinds), root, root, pre, pre, path, path,
                 rv, rv, rv,
                 bool(elsewhere), limit, offset))


def mark_changes(conn, history_ids, mark):
    """Mark changes 'intended' or 'restore' (None clears). The database decides who may: changes the person may not
    mark are skipped. Returns how many were marked."""
    if mark not in ("intended", "restore", None):
        raise ValueError("a mark is intended or restore")
    return conn.execute("SELECT pinakes.mark_changes(%s::bigint[], %s)", (list(history_ids), mark)).fetchone()[0]


RESTORE_SORT = {"marked": ("m.marked_at",), "where": ("h.name", "r.label"), "path": ("hi.old_relpath",),
                "backups": ("b.backups",)}


def restores(conn, loc=None, back=False, limit=None, offset=0, sort=None, direction="asc"):
    """Changes marked 'restore', and where their last content is: the backup copies holding it (the newest few in
    `held_in`, each root, snapshot and path), or none. A restore is `back`, and leaves the list unless `back` is
    asked for, once that content is present again in the file's root (a moved file: at its old path). Pinakes
    points at the copy; it never restores it."""
    root, pre = (None, None)
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
    return rows(conn, """SELECT hi.history_id, hi.file_id, hi.kind, hi.seen_on, h.name AS host, r.label AS root,
                                hi.old_relpath, hi.new_relpath, m.marked_at, coalesce(mp.display, mg.name) AS marked_by,
                                encode(ct.sha256, 'hex') AS sha256, b.backups, b.held_in, k.back, """ + TOTAL + """
                         FROM pinakes.review_marks m JOIN pinakes.history hi USING (history_id)
                         JOIN pinakes.files f ON f.file_id = hi.file_id
                         JOIN pinakes.roots r ON r.root_id = f.root_id JOIN pinakes.hosts h ON h.host_id = r.host_id
                         LEFT JOIN pinakes.people mp ON mp.person_id = m.marked_by
                         LEFT JOIN pinakes.groups mg ON mg.group_id = m.marked_by_group
                         LEFT JOIN pinakes.contents ct ON ct.content_id = hi.old_content_id
                         CROSS JOIN LATERAL (
                             SELECT EXISTS (SELECT 1 FROM pinakes.present o
                                            WHERE o.root_id = f.root_id AND o.content_id = hi.old_content_id
                                              AND o.unreadable_on IS NULL
                                              AND (hi.kind = 'gone' OR o.relpath = hi.old_relpath)) AS back) k
                         CROSS JOIN LATERAL (
                             SELECT count(*) AS backups,
                                    (array_agg(jsonb_build_object('root', x.label, 'snapshot', x.snapshot,
                                                                  'path', x.relpath)
                                               ORDER BY x.snapshot DESC NULLS LAST, x.label, x.relpath))[1:5]
                                        AS held_in
                             FROM (SELECT DISTINCT ON (bh.host_id, bo.dev, bo.ino) br.label, bo.snapshot, bo.relpath
                                   FROM pinakes.present bo JOIN pinakes.roots br ON br.root_id = bo.root_id
                                   JOIN pinakes.hosts bh ON bh.host_id = br.host_id
                                   WHERE br.kind = 'backup' AND bo.content_id = hi.old_content_id
                                     AND bo.unreadable_on IS NULL
                                   ORDER BY bh.host_id, bo.dev, bo.ino, bo.snapshot DESC NULLS LAST) x) b
                         WHERE m.mark = 'restore' AND (%s OR NOT k.back)
                           AND (%s::text IS NULL OR r.label = %s AND (hi.old_relpath LIKE %s OR hi.new_relpath LIKE %s))"""
                + order(RESTORE_SORT, sort, direction, "m.marked_at DESC, hi.history_id") + PAGE,
                (bool(back), root, root, pre, pre, limit, offset))


TREE_LIMIT = 2000


def change_tree(conn, days=7, loc=None, depth=3, kinds=None, review=None):
    """Per folder, what happened under it in the last `days`: files new, changed, moved in (destination), moved out
    (source) and gone. A tracked move counts at both ends, never as new and gone; a move inside a folder counts
    there as both in and out. From the folder `loc` (ROOT:PATH; None: every root) down `depth` levels, in tree order.
    `scrub` counts what the scrub found (a mismatch or an unreadable file). `unreviewed` counts the gone files, moves
    and scrub findings under it with no review mark (a move once), and `review` filters
    as in changes(). `owners` is the owners of the files counted, for the step-up audit. A root's first scan is
    left out, as in changes(). At most TREE_LIMIT rows."""
    since = today() - datetime.timedelta(days=days)
    root, pre, base = None, "%", 0
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
        base = len([p for p in path.split("/") if p])
    return rows(conn, """WITH ev AS (
                             SELECT h.name AS host, r.label AS root, f.owner_id, x.role, hi.history_id,
                                    (m.history_id IS NULL AND hi.kind IN ('gone', 'moved', 'moved_changed',
                                                                          'mismatch', 'unreadable')) AS unreviewed,
                                    string_to_array(x.path, '/') AS parts
                             FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                             JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                             LEFT JOIN pinakes.review_marks m ON m.history_id = hi.history_id
                             CROSS JOIN LATERAL (VALUES
                                 (CASE WHEN hi.kind IN ('moved', 'moved_changed') THEN hi.new_relpath END, 'in'),
                                 (CASE WHEN hi.kind IN ('moved', 'moved_changed') THEN hi.old_relpath END, 'out'),
                                 (CASE WHEN hi.kind = 'new' THEN hi.new_relpath END, 'new'),
                                 (CASE WHEN hi.kind = 'changed' THEN hi.new_relpath END, 'changed'),
                                 (CASE WHEN hi.kind = 'gone' THEN hi.old_relpath END, 'gone'),
                                 (CASE WHEN hi.kind IN ('mismatch', 'unreadable') THEN hi.new_relpath END, 'scrub'))
                                 AS x (path, role)
                             WHERE hi.seen_on >= %s AND x.path IS NOT NULL AND x.path LIKE %s
                               AND """ + _NOT_FIRST + """
                               AND (%s::text IS NULL OR r.label = %s)
                               AND (%s::text[] IS NULL OR hi.kind = ANY (%s::text[]))
                               AND """ + _REVIEW_WHERE + """),
                         t AS (
                             SELECT host, root, owner_id, role, history_id, unreviewed, parts[1:i] AS folder
                             FROM ev, generate_series(%s, least(array_length(parts, 1) - 1, %s)) AS i)
                         SELECT host, root, array_to_string(folder, '/') AS folder,
                                coalesce(array_length(folder, 1), 0) AS level,
                                count(*) FILTER (WHERE role = 'new') AS new,
                                count(*) FILTER (WHERE role = 'changed') AS changed,
                                count(*) FILTER (WHERE role = 'in') AS moved_in,
                                count(*) FILTER (WHERE role = 'out') AS moved_out,
                                count(*) FILTER (WHERE role = 'gone') AS gone,
                                count(*) FILTER (WHERE role = 'scrub') AS scrub,
                                count(DISTINCT history_id) FILTER (WHERE unreviewed) AS unreviewed,
                                array_agg(DISTINCT owner_id) FILTER (WHERE owner_id IS NOT NULL) AS owners
                         FROM t GROUP BY host, root, folder ORDER BY host, root, folder LIMIT %s""",
                (since, pre, root, root, _kinds(kinds), _kinds(kinds), _review(review), _review(review),
                 _review(review), base, base + depth, TREE_LIMIT + 1))


GROWTH_LIMIT = 2000


def growth(conn, weeks=8, loc=None):
    """Growth by folder over time (ROADMAP 47): per root and folder one level under `loc` (ROOT:PATH; None: each
    root's top folders), per week (from its Monday, UTC dates), the files and bytes that came and went, from history,
    in the last `weeks` weeks counting this one. Per change, what it did to a folder: a new file adds, a gone one takes
    away, a change of content adds or takes away the difference in size, a move between folders takes from one and adds
    to the other (a move inside one, nothing). `folder` '' is files directly under `loc`. A root's first scan is the
    catalog starting, not growth: left out. A file's size counts once per path (a hard link again). `owners` is the
    owners of the files counted, for the step-up audit. At most GROWTH_LIMIT rows, in tree order and by week."""
    since = today() - datetime.timedelta(days=today().weekday() + 7 * (max(weeks, 1) - 1))
    root, pre, base = None, "%", 0
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
        base = len([p for p in path.split("/") if p])
    return rows(conn, """WITH ev AS (
                             SELECT hi.history_id, h.name AS host, r.label AS root, f.owner_id,
                                    date_trunc('week', hi.seen_on)::date AS week, x.path, x.files, x.bytes
                             FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                             JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                             LEFT JOIN pinakes.contents oc ON oc.content_id = hi.old_content_id
                             LEFT JOIN pinakes.contents nc ON nc.content_id = hi.new_content_id
                             CROSS JOIN LATERAL (VALUES
                                 (CASE WHEN hi.kind <> 'new' THEN coalesce(hi.old_relpath, hi.new_relpath) END,
                                  -1, -coalesce(oc.size, 0)),
                                 (CASE WHEN hi.kind <> 'gone' THEN coalesce(hi.new_relpath, hi.old_relpath) END,
                                  1, coalesce(nc.size, 0))) AS x (path, files, bytes)
                             WHERE hi.seen_on >= %s AND hi.kind <> 'unreadable'
                               AND NOT (hi.kind = 'new' AND hi.seen_after IS NULL)
                               AND x.path IS NOT NULL AND x.path LIKE %s AND (%s::text IS NULL OR r.label = %s)),
                         net AS (
                             SELECT history_id, host, root, owner_id, week,
                                    CASE WHEN array_length(string_to_array(path, '/'), 1) > %s + 1
                                         THEN (string_to_array(path, '/'))[%s + 1] ELSE '' END AS folder,
                                    sum(files) AS files, sum(bytes) AS bytes
                             FROM ev GROUP BY 1, 2, 3, 4, 5, 6)
                         SELECT host, root, folder, week,
                                count(*) FILTER (WHERE files > 0) AS files_added,
                                count(*) FILTER (WHERE files < 0) AS files_gone,
                                coalesce(sum(bytes) FILTER (WHERE bytes > 0), 0) AS bytes_added,
                                coalesce(-sum(bytes) FILTER (WHERE bytes < 0), 0) AS bytes_gone,
                                array_agg(DISTINCT owner_id) FILTER (WHERE owner_id IS NOT NULL) AS owners
                         FROM net WHERE files <> 0 OR bytes <> 0
                         GROUP BY host, root, folder, week ORDER BY host, root, folder, week LIMIT %s""",
                (since, pre, root, root, base, base, GROWTH_LIMIT + 1))


def versions(conn, file_id, limit=None, offset=0, sort=None, direction="asc"):
    return rows(conn, """WITH v AS (SELECT new_content_id AS content_id, min(seen_on) AS first_seen_on
                                    FROM pinakes.history WHERE file_id = %s AND new_content_id IS NOT NULL
                                    GROUP BY new_content_id)
                         SELECT encode(c.sha256, 'hex') AS sha256, v.first_seen_on, r.label AS backup_root,
                                b.snapshot, b.relpath AS backup_path, """ + TOTAL + """
                         FROM v JOIN pinakes.contents c USING (content_id)
                         LEFT JOIN (pinakes.present b JOIN pinakes.roots r ON r.root_id = b.root_id
                                    AND r.kind = 'backup') ON b.content_id = v.content_id"""
                + order(VERSIONS_SORT, sort, direction, "v.first_seen_on, b.snapshot, v.content_id, b.file_id")
                + PAGE, (file_id, limit, offset))


# A lineage edge by the hash into or out of a placeholder (ROADMAP 69) is left out of every answer while the content is
# one: the same default bytes aren't a copy. The table keeps it, so that an unmark brings it back.
_SHOWN_EDGE = """NOT (l.evidence = 'same sha256' AND EXISTS (
                     SELECT 1 FROM pinakes.files pf JOIN pinakes.placeholders pp ON pp.content_id = pf.content_id
                     WHERE pf.file_id IN (l.from_file_id, l.to_file_id)))"""


def lineage(conn, file_id, direction="up", depth=50):
    """Ancestors (up) or descendants (down). Lineage is between files, and a file keeps its id through versions,
    so a copy out and back makes a cycle: the walk carries the files it has visited and never revisits one."""
    if direction == "up":
        join, nxt = "l.to_file_id = w.file_id", "l.from_file_id"
    else:
        join, nxt = "l.from_file_id = w.file_id", "l.to_file_id"
    return rows(conn, """WITH RECURSIVE w (file_id, depth, how, evidence, confidence, decision, seen) AS (
                             SELECT %%s::bigint, 0, NULL::text, NULL::text, NULL::text, NULL::text, ARRAY[%%s::bigint]
                           UNION ALL
                             SELECT %s, w.depth + 1, l.kind, l.evidence, l.confidence, l.decision, w.seen || %s
                             FROM pinakes.lineage l JOIN w ON %s
                             WHERE l.decision IS DISTINCT FROM 'rejected' AND NOT %s = ANY (w.seen)
                               AND w.depth < %%s AND %s)
                         SELECT w.depth, w.how, w.evidence, w.confidence, w.decision, %s
                         FROM w JOIN pinakes.files f USING (file_id) JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) WHERE w.depth > 0
                         ORDER BY w.depth, h.name""" % (nxt, nxt, join, nxt, _SHOWN_EDGE, FILE_COLS),
                (file_id, file_id, depth))


DECISIONS = ("confirmed", "rejected")


def relatives(conn, file_id):
    """A file's direct relatives, both ways, rejected ones too (a walk leaves those out): one row per edge, with its
    ends (from_file_id, to_file_id), so a person can confirm, reject or clear it (ROADMAP 9). Certain edges (the same
    content) are listed but can't be decided: the hash decides them. An edge by a placeholder's hash isn't listed
    (ROADMAP 69)."""
    return rows(conn, """SELECT CASE WHEN l.to_file_id = %%s THEN 'up' ELSE 'down' END AS direction,
                                l.from_file_id, l.to_file_id, l.kind AS how, l.evidence, l.confidence, l.decision,
                                l.decided_at, p.display AS decided_by, %s
                         FROM pinakes.lineage l
                         JOIN pinakes.files f ON f.file_id = CASE WHEN l.to_file_id = %%s THEN l.from_file_id
                                                                  ELSE l.to_file_id END
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         LEFT JOIN pinakes.people p ON p.person_id = l.decided_by
                         WHERE %%s IN (l.from_file_id, l.to_file_id) AND %s
                         ORDER BY direction DESC, l.decision NULLS FIRST, h.name, f.relpath, l.kind"""
                % (FILE_COLS, _SHOWN_EDGE),
                (file_id, file_id, file_id))


def decide_lineage(conn, a, b, decision):
    """Confirm or reject (None clears) every edge between files a and b, either way but the certain ones. The
    database decides who may: edges the person may not decide are skipped. Returns how many were decided."""
    if decision not in DECISIONS + (None,):
        raise ValueError("a decision is confirmed or rejected")
    return conn.execute("SELECT pinakes.decide_lineage(%s, %s, %s)", (a, b, decision)).fetchone()[0]


PLACEHOLDER_SORT = {"names": ("x.names",), "holders": ("x.holders",), "folders": ("x.folders",), "size": ("c.size",)}


def placeholders(conn, min_names, max_size, marked=False, like=None, within=0.2, limit=None, offset=0, sort=None,
                 direction="desc"):
    """Placeholder candidates (ROADMAP 69): contents of at most max_size bytes held under at least min_names names (a
    name and its extension, compared as lineage compares names) by present files outside backup roots, not yet
    placeholders, the most names first. `marked`: instead, every content that is one, by a person's mark or a site
    rule, whatever its size. `like` (a file id): instead, that file's likely siblings, the candidates whose every
    holder has its extension and whose size is within `within` of its size (the same default written by another
    version of an app). Counted under row-level security: holders, names and folders of the files the person sees.
    Each row has an example file (outside backups) to name the content by."""
    names = "count(DISTINCT (coalesce(f.name_key, f.name), f.ext))"
    where, having, after, args = [], "", ["p.content_id IS NULL"], []
    if marked:
        where.append(_PLACEHOLDER % "f")
        after = ["p.content_id IS NOT NULL"]
    else:
        where.append("f.size <= %s")
        args.append(max_size)
        having = "HAVING %s >= %%s" % names
    if like is not None:
        got = rows(conn, "SELECT f.content_id, f.size, coalesce(f.ext, '') AS ext FROM pinakes.files f "
                         "WHERE f.file_id = %s AND f.content_id IS NOT NULL", (like,))
        if not got:
            return []
        me = got[0]
        after += ["x.content_id <> %s", "x.exts = ARRAY[%s]::text[]", "c.size BETWEEN %s AND %s"]
        lo, hi = int(me["size"] * (1 - within)), int(me["size"] * (1 + within) + 0.999999)
        tail = [me["content_id"], me["ext"], lo, hi]
    else:
        tail = []
    sql = """SELECT x.content_id, encode(c.sha256, 'hex') AS sha256, c.size, x.exts, x.holders, x.names, x.folders,
                    x.example_id AS file_id, er.label AS root, ef.relpath,
                    CASE WHEN p.content_id IS NULL THEN NULL WHEN p.rule IS NULL THEN 'marked'
                         ELSE 'rule ' || p.rule END AS placeholder, """ + TOTAL + """
             FROM (SELECT f.content_id, array_agg(DISTINCT coalesce(f.ext, '') ORDER BY coalesce(f.ext, '')) AS exts,
                          count(*) AS holders, """ + names + """ AS names,
                          count(DISTINCT (f.root_id, CASE WHEN strpos(f.relpath, '/') > 0
                                                          THEN regexp_replace(f.relpath, '/[^/]+$', '') ELSE ''
                                                     END)) AS folders,
                          min(f.file_id) AS example_id
                   FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                   WHERE r.kind <> 'backup' AND f.size > 0 AND f.content_id IS NOT NULL AND NOT f.is_symlink
                     AND """ + " AND ".join(where) + """
                   GROUP BY f.content_id """ + having + """) x
             JOIN pinakes.contents c USING (content_id) LEFT JOIN pinakes.placeholders p USING (content_id)
             JOIN pinakes.files ef ON ef.file_id = x.example_id JOIN pinakes.roots er ON er.root_id = ef.root_id
             WHERE """ + " AND ".join(after)
    return rows(conn, sql + order(PLACEHOLDER_SORT, sort, direction, "x.names DESC, x.holders DESC, c.content_id")
                + PAGE, tuple(args) + (() if marked else (min_names,)) + tuple(tail) + (limit, offset))


def mark_placeholder(conn, file_id, mark):
    """Mark (True) or unmark (False) the file's content a placeholder (ROADMAP 69). The database decides who may (the
    owner or a co-owner of every file holding it, or an administrator in a step-up) and skips the rest; returns 1 if
    the mark changed, else 0."""
    if not isinstance(mark, bool):
        raise ValueError("a placeholder is marked (true) or unmarked (false)")
    return conn.execute("SELECT pinakes.mark_placeholder(%s, %s)", (file_id, mark)).fetchone()[0]


def placeholder_of(conn, file_id):
    """How the file's content is a placeholder: 'marked', 'rule NAME', or None."""
    r = conn.execute("""SELECT CASE WHEN p.rule IS NULL THEN 'marked' ELSE 'rule ' || p.rule END
                        FROM pinakes.files f JOIN pinakes.placeholders p USING (content_id) WHERE f.file_id = %s""",
                     (file_id,)).fetchone()
    return r[0] if r else None


def meta(conn, schema, field, value, limit=None, offset=0, sensitive=None, backups=None):
    """The files whose content has metadata `schema` with `field` equal to `value` (as text). `sensitive`: whether the
    field is one of its schema's sensitive fields (registry.Field.sensitive), whose values are kept in a row of their
    own; None (not known) looks in both. Knowing it is what makes the query fast (ROADMAP 61): the test of the column
    runs before the row-level policy, which otherwise asks sensitive_visible() of every sensitive row of the schema."""
    return copies(conn, FILE_COLS + ", m.vals",
                  """FROM pinakes.metadata m JOIN pinakes.present f ON f.content_id = m.content_id
                     JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                     WHERE m.schema = %s AND (%s::boolean IS NULL OR m.sensitive = %s) AND m.vals ->> %s = %s""",
                  (schema, sensitive, sensitive, field, value), "f.relpath, f.file_id", backups, limit, offset)


# A person's export of their own records (ROADMAP 45): the files they own (files.owner_id; shared, co-owned and a
# group's files are their owners' exports) and what the catalog holds about them, in parts. A query, not a dump: it
# runs as the person under row-level security like any other, so a token's roots limit it and sensitive metadata
# comes only where sensitive_visible() allows. Every part ends in a unique key, so pages neither overlap nor skip.
_MINE = """WITH mine AS (SELECT f.* FROM pinakes.files f WHERE f.owner_id = pinakes.current_person())"""
EXPORT = {
    "files": _MINE + """
        SELECT f.file_id, h.name AS host, r.label AS root, r.kind AS root_kind, f.relpath, f.name, f.size,
               encode(c.sha256, 'hex') AS sha256, c.mime, f.mtime, f.ctime, f.btime, f.first_seen, f.last_seen,
               f.gone_on, f.hidden, f.is_symlink, f.link_target, f.backup_of, f.snapshot, f.unreadable_on,
               f.unreadable_error, f.manifest_verdict, f.manifest_on
        FROM mine f JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
        LEFT JOIN pinakes.contents c ON c.content_id = f.content_id
        ORDER BY f.file_id""",
    "history": _MINE + """
        SELECT hi.history_id, hi.file_id, hi.kind, hi.seen_after, hi.seen_on, hi.old_relpath, hi.new_relpath,
               encode(oc.sha256, 'hex') AS old_sha256, encode(nc.sha256, 'hex') AS new_sha256,
               hi.old_mtime, hi.new_mtime, hi.evidence, hi.confidence
        FROM mine f JOIN pinakes.history hi USING (file_id)
        LEFT JOIN pinakes.contents oc ON oc.content_id = hi.old_content_id
        LEFT JOIN pinakes.contents nc ON nc.content_id = hi.new_content_id
        ORDER BY hi.history_id""",
    "reviews": _MINE + """
        SELECT m.history_id, hi.file_id, hi.kind, m.mark, m.marked_at, p.name AS marked_by, g.name AS marked_by_group
        FROM mine f JOIN pinakes.history hi USING (file_id) JOIN pinakes.review_marks m USING (history_id)
        LEFT JOIN pinakes.people p ON p.person_id = m.marked_by
        LEFT JOIN pinakes.groups g ON g.group_id = m.marked_by_group
        ORDER BY m.history_id""",
    # a content's metadata is true of every copy: one row per file of theirs that holds it
    "metadata": _MINE + """
        SELECT x.file_id, m.metadata_id, CASE WHEN m.file_id IS NULL THEN 'content' ELSE 'file' END AS of,
               m.schema, m.vals, m.source, m.version, m.at, m.sensitive, p.name AS author
        FROM (SELECT f.file_id, m.metadata_id FROM mine f JOIN pinakes.metadata m ON m.content_id = f.content_id
              UNION ALL
              SELECT f.file_id, m.metadata_id FROM mine f JOIN pinakes.metadata m ON m.file_id = f.file_id) x
        JOIN pinakes.metadata m USING (metadata_id) LEFT JOIN pinakes.people p ON p.person_id = m.author
        ORDER BY x.file_id, m.metadata_id""",
    # lineage with either end theirs (row-level security shows a link only when both ends are visible)
    "lineage": _MINE + """
        SELECT l.from_file_id, rf.label AS from_root, ff.relpath AS from_relpath, l.to_file_id, rt.label AS to_root,
               ft.relpath AS to_relpath, l.kind, l.evidence, l.confidence, l.found_on, l.decision
        FROM pinakes.lineage l
        JOIN pinakes.files ff ON ff.file_id = l.from_file_id JOIN pinakes.roots rf ON rf.root_id = ff.root_id
        JOIN pinakes.files ft ON ft.file_id = l.to_file_id JOIN pinakes.roots rt ON rt.root_id = ft.root_id
        WHERE l.from_file_id IN (SELECT file_id FROM mine) OR l.to_file_id IN (SELECT file_id FROM mine)
        ORDER BY l.from_file_id, l.to_file_id, l.kind""",
}


def export(conn, part, limit=None, offset=0):
    """One part of the current person's export (EXPORT's keys), a page of it: its column names and its rows."""
    if part not in EXPORT:
        raise ValueError("part is one of %s" % ", ".join(EXPORT))
    cur = conn.execute(EXPORT[part] + PAGE, (limit, offset))
    cols = [d.name for d in cur.description]
    return cols, [dict(zip(cols, r)) for r in cur.fetchall()]


def file_metadata(conn, file_id, content_id):
    """The metadata the person may see on a file: its content's (extracted, true of every copy) and the file's own
    (entered by people). Sensitive rows come back only where row-level security lets them (sensitive_visible())."""
    return rows(conn, """SELECT m.schema, m.vals, m.source, m.version, m.at, m.sensitive, p.display AS author
                         FROM pinakes.metadata m LEFT JOIN pinakes.people p ON p.person_id = m.author
                         WHERE m.file_id = %s OR m.content_id = %s
                         ORDER BY m.schema, m.sensitive, m.source, m.metadata_id""", (file_id, content_id))


def file_extractions(conn, content_id):
    """What each extractor made of a file's content (ROADMAP 44), as the person sees it (extraction_outcomes: where
    the values found are all sensitive and hidden from them, "nothing")."""
    if not content_id:
        return []
    return rows(conn, """SELECT schema, outcome, reason, version, at FROM pinakes.extraction_outcomes
                         WHERE content_id = %s ORDER BY schema""", (content_id,))


def sensitive_visible(conn, file_id, content_id):
    return conn.execute("SELECT pinakes.sensitive_visible(%s, %s)", (content_id, file_id)).fetchone()[0]


# Person-entered metadata and shared sensitive fields (ROADMAP 16): written only through the database's functions,
# which decide who may (the owner, a co-owner or an annotator enters; the owner or a co-owner shares).
def my_file_role(conn, file_id):
    """The person's role on the file (owner, co-owner, reader, annotator), or None."""
    return conn.execute("SELECT pinakes.my_file_role(%s)", (file_id,)).fetchone()[0]


def my_entered(conn, file_id, schema):
    """The values of one schema the person entered on a file, its sensitive fields with the rest."""
    vals = {}
    for (v,) in conn.execute("""SELECT vals FROM pinakes.metadata WHERE file_id = %s AND schema = %s
                                AND source = 'person' AND author = pinakes.current_person()
                                ORDER BY sensitive""", (file_id, schema)).fetchall():
        vals.update(v)
    return vals


def set_file_metadata(conn, file_id, schema, vals):
    """Replace the person's values of `schema` (a registry.Schema) on a file with `vals`, already checked
    (extract.check_vals): the sensitive fields go in a row of their own."""
    plain = {k: v for k, v in vals.items() if not schema.fields[k].sensitive}
    hidden = {k: v for k, v in vals.items() if schema.fields[k].sensitive}
    conn.execute("SELECT pinakes.set_file_metadata(%s, %s, %s::jsonb, %s::jsonb)",
                 (file_id, schema.name, json.dumps(plain), json.dumps(hidden)))


def tags(conn, loc, limit=None, offset=0):
    """The files under loc (or that file) the person can see, symlinks aside, each with the person's role on it, their
    own tags and note (their dc.subject and dc.description, ROADMAP 37) and the others' they can see (`others`: by,
    tags, note)."""
    root, path = split_location(loc)
    return rows(conn, """SELECT f.file_id, r.label AS root, f.relpath, pinakes.my_file_role(f.file_id) AS role,
                                mine.vals->'subject' AS tags, mine.vals->>'description' AS note,
                                (SELECT coalesce(jsonb_agg(jsonb_build_object('by', p.display,
                                                                              'tags', o.vals->'subject',
                                                                              'note', o.vals->'description')
                                                           ORDER BY p.display, o.metadata_id), '[]')
                                 FROM pinakes.metadata o JOIN pinakes.people p ON p.person_id = o.author
                                 WHERE o.file_id = f.file_id AND o.schema = 'dc' AND o.source = 'person'
                                   AND NOT o.sensitive AND o.author IS DISTINCT FROM pinakes.current_person()
                                   AND (o.vals ? 'subject' OR o.vals ? 'description')) AS others, """ + TOTAL + """
                         FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         LEFT JOIN pinakes.metadata mine ON mine.file_id = f.file_id AND mine.schema = 'dc'
                              AND mine.source = 'person' AND NOT mine.sensitive
                              AND mine.author = pinakes.current_person()
                         WHERE r.label = %s AND (f.relpath LIKE %s OR f.relpath = %s) AND NOT f.is_symlink
                         ORDER BY f.relpath, f.file_id""" + PAGE, (root, _prefix(path), path, limit, offset))


def sensitive_sharing(conn, file_id):
    """For the file's owner or a co-owner: its readers and annotators, and whether its sensitive fields are shared
    with each. Nobody else gets a row."""
    return rows(conn, "SELECT * FROM pinakes.sensitive_sharing(%s)", (file_id,))


def share_sensitive(conn, file_id, person_id, give):
    """Share the file's sensitive fields with a reader or annotator of it (give False: stop). Whether it changed."""
    return conn.execute("SELECT pinakes.share_sensitive(%s, %s, %s)", (file_id, person_id, give)).fetchone()[0]


_FIELD = re.compile(r"[a-z][a-z0-9_]{0,29}\Z")
_DAY = re.compile(r"(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?\Z")


def date_bounds(text):
    """(first, after) for a date as precise as given (2019, 2019-06, 2019-06-01), as ISO 8601 text: a stored date in
    it is >= first and < after, since text order is time order. ValueError for anything else."""
    m = _DAY.match(text)
    if not m:
        raise ValueError("a date is YYYY, YYYY-MM or YYYY-MM-DD")
    y, mo, d = int(m.group(1)), m.group(2), m.group(3)
    if d:
        day = datetime.date(y, int(mo), int(d))
        return day.isoformat(), (day + datetime.timedelta(days=1)).isoformat()
    if mo:
        datetime.date(y, int(mo), 1)                                # a month out of range raises
        return "%04d-%s" % (y, mo), "%04d-%02d" % ((y + 1, 1) if mo == "12" else (y, int(mo) + 1))
    return "%04d" % y, "%04d" % (y + 1)


def _common_cond(mapping, test):
    """One condition on metadata over every schema mapping a common field: (schema, field) pairs from the registry.
    `test` has {v} for the value's expression. The names are the registry's own, checked again here, and written as
    literals so that each matches its partial index (md_SCHEMA_FIELD_KIND, WHERE schema = 'SCHEMA'); values stay
    parameters."""
    parts = []
    for schema, field in mapping:
        if not (_FIELD.match(schema) and _FIELD.match(field)):
            raise ValueError("not a schema and field: %r" % ((schema, field),))
        parts.append("(m.schema = '%s' AND %s)" % (schema, test.format(v="(m.vals ->> '%s')" % field)))
    return "(" + " OR ".join(parts) + ")" if parts else "false"


def find_by(conn, name=None, creator=None, mapped_creator=(), dated=None, mapped_date=(), limit=None, offset=0,
            sort=None, direction="asc", hidden=True, backups=None, placeholders=True):
    """Files by name, by common fields, or both: `creator`, a substring, over every (schema, field) in
    `mapped_creator`; `dated`, (first, after) with either None for no bound, over every one in `mapped_date`
    (from date_bounds(): "from a day" is its first, "to a day" the next one's). Metadata on a file's content or on
    the file itself counts. Row-level security decides which metadata is searched, so a sensitive field the person
    may not see finds nothing. Without `hidden`, no hidden file. `backups` as copies() takes it, `placeholders` as
    find() does."""
    where, args = [], []
    if name:
        where.append("f.name ILIKE %s")
        args.append(_like(name, wildcards=True))
    first, after = dated or (None, None)
    on_date = [t for t, b in (("{v} >= %s", first), ("{v} < %s", after)) if b]
    for mapping, cond, vals in ((mapped_creator, "{v} ILIKE %s", [_like(creator)] if creator else None),
                                (mapped_date, "(" + " AND ".join(on_date) + ")",
                                 [b for b in (first, after) if b] if on_date else None)):
        if vals is None:
            continue
        c = _common_cond(mapping, cond)
        where.append("(f.content_id IN (SELECT m.content_id FROM pinakes.metadata m WHERE m.content_id IS NOT NULL "
                     "AND %s) OR f.file_id IN (SELECT m.file_id FROM pinakes.metadata m WHERE m.file_id IS NOT NULL "
                     "AND %s))" % (c, c))
        args += vals * len(mapping) * 2
    if not where:
        return []
    if not hidden:
        where.append("NOT f.hidden")
    return copies(conn, FILE_COLS, """FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                                      JOIN pinakes.hosts h USING (host_id) WHERE """ + " AND ".join(where)
                  + _placeholders_cond(placeholders),
                  tuple(args), _order_by(FILE_SORT, sort, direction, "f.name, h.name, f.file_id"), backups, limit,
                  offset)


def stale(conn):
    return rows(conn, """SELECT name, last_scan, expected_every FROM pinakes.hosts
                         WHERE expected_every IS NOT NULL AND (last_scan IS NULL OR last_scan < now() - expected_every)
                         ORDER BY last_scan NULLS FIRST""")


# A root's scrub is behind (DESIGN.md "Scrub") when its last run is older than a full pass, or a file still there
# was last checked more than two full passes ago (or never, two passes after the scrub began). Off (days 0) or not
# reported: never behind. Its dates are UTC dates, as the agent sends them (today()), so today is UTC's too.
_UTC_TODAY = "(now() AT TIME ZONE 'UTC')::date"
_SCRUB_BEHIND = """(r.scrub_days > 0 AND (r.scrub_on < %(d)s - r.scrub_days
                    OR r.scrub_oldest < %(d)s - 2 * r.scrub_days
                    OR (r.scrub_never > 0 AND r.scrub_since < %(d)s - 2 * r.scrub_days)))""" % {"d": _UTC_TODAY}


# A root its host's batches stopped naming (ROADMAP 46), not retired since: its files still count as copies.
_UNREPORTED = "r.unreported_since IS NOT NULL AND r.retired_on IS NULL"


def health(conn):
    """Per host: its newest batch, its last complete scan, how often it should report, whether it is stale, whether
    its batches are being refused (a refusal since its newest batch applied: for its protocol or its sequence), when
    its agent's numbering last went back, its scrub: the oldest check of a file on any of its roots (before a
    full pass, the day the scrub began there) and whether the scrub is behind, and how many of its roots its batches
    stopped naming (ROADMAP 46). Host names, counts, dates and times only: no root, person or file."""
    return rows(conn, """SELECT x.*, (x.refused_at IS NOT NULL AND (x.newest_batch IS NULL
                                      OR x.refused_at > x.newest_batch)) AS refused
                         FROM (SELECT h.name AS host, (SELECT max(i.at) FROM pinakes.ingested i
                                                      WHERE i.host_id = h.host_id) AS newest_batch,
                                      h.last_scan, h.expected_every,
                                      (h.expected_every IS NOT NULL AND (h.last_scan IS NULL
                                       OR h.last_scan < now() - h.expected_every)) AS stale,
                                      c.refused_at, c.seq_reset_at, s.scrub_oldest, coalesce(s.scrub_behind, false)
                                          AS scrub_behind, s.roots_unreported
                               FROM pinakes.hosts h LEFT JOIN pinakes.checkins c USING (host_id)
                               LEFT JOIN LATERAL (
                                   SELECT min(CASE WHEN r.scrub_never > 0 THEN r.scrub_since ELSE r.scrub_oldest END)
                                              FILTER (WHERE r.scrub_days > 0) AS scrub_oldest,
                                          bool_or(""" + _SCRUB_BEHIND + """) AS scrub_behind,
                                          count(*) FILTER (WHERE """ + _UNREPORTED + """) AS roots_unreported
                                   FROM pinakes.roots r WHERE r.host_id = h.host_id) s ON true) x
                         ORDER BY x.host""")


def agent_versions(conn):
    """Per host: its last check-in (release, protocol, the oldest server it works with, whether it is locked), its
    newest batch and the protocol that batch declared (0: none, an agent before check-in), its last batch refused
    (for its protocol or its sequence), when its numbering last went back and what was done, and how many of its
    roots its batches stopped naming (ROADMAP 46). Host names, numbers and times only: no root, person or file."""
    return rows(conn, """SELECT h.name AS host, c.at AS checked_in, c.release, c.protocol,
                                c.min_server_protocol AS min_server, c.locked,
                                (SELECT max(i.at) FROM pinakes.ingested i WHERE i.host_id = h.host_id) AS newest_batch,
                                c.batch_release, c.batch_protocol, c.refused_at, c.refused, c.seq_reset_at, c.seq_reset,
                                (SELECT count(*) FROM pinakes.roots r WHERE r.host_id = h.host_id AND """ + _UNREPORTED
                      + """) AS roots_unreported
                         FROM pinakes.hosts h LEFT JOIN pinakes.checkins c USING (host_id) ORDER BY h.name""")


# What a disk's loss would cost (ROADMAP 42), from pinakes.at_risk(): the files with no copy on another host, and of
# them those with none on another device of their host either. Each inode once (hard links take their space once).
_AT_RISK_INODES = """WITH i AS (SELECT a.host_id, a.dev, min(a.root_id) AS root_id, max(a.size) AS size,
                                   bool_or(a.disk_only) AS disk_only
                            FROM pinakes.at_risk() a GROUP BY a.host_id, a.dev, coalesce(a.ino, -a.file_id))"""
AT_RISK_FOLDERS = 200       # the largest folders listed; the rest counted


def at_risk(conn):
    """What losing a disk, or a whole machine, would cost the person: of the files they can see, those with no copy
    they can see on another disk (another host, or another device of the host). `disks`: per device of a host (dev
    None: not known), files and bytes lost with it and the roots they are in; `hosts`: the same if the machine were
    lost; `folders`: per disk, root, top folder ('' for files at the root's top) and owner, the largest first (at
    most AT_RISK_FOLDERS of them, `folders_total` all); `owners`: the owner ids shown, for the step-up audit."""
    disks = rows(conn, _AT_RISK_INODES + """
                       SELECT h.name AS host, i.dev, array_agg(DISTINCT r.label ORDER BY r.label) AS roots,
                              count(*) AS files, coalesce(sum(i.size), 0) AS bytes
                       FROM i JOIN pinakes.roots r ON r.root_id = i.root_id
                       JOIN pinakes.hosts h ON h.host_id = i.host_id
                       WHERE i.disk_only GROUP BY h.name, i.dev ORDER BY bytes DESC, h.name, i.dev NULLS LAST""")
    hosts = rows(conn, _AT_RISK_INODES + """
                       SELECT h.name AS host, array_agg(DISTINCT r.label ORDER BY r.label) AS roots,
                              count(*) AS files, coalesce(sum(i.size), 0) AS bytes
                       FROM i JOIN pinakes.roots r ON r.root_id = i.root_id
                       JOIN pinakes.hosts h ON h.host_id = i.host_id
                       GROUP BY h.name ORDER BY bytes DESC, h.name""")
    folders = rows(conn, """SELECT h.name AS host, x.dev, r.label AS root, x.folder, x.owner_id, p.display AS owner,
                                   count(*) AS files, coalesce(sum(x.size), 0) AS bytes, """ + TOTAL + """
                            FROM (SELECT a.host_id, a.dev, a.root_id, a.owner_id,
                                         CASE WHEN strpos(a.relpath, '/') > 0 THEN split_part(a.relpath, '/', 1)
                                              ELSE '' END AS folder, max(a.size) AS size
                                  FROM pinakes.at_risk() a WHERE a.disk_only
                                  GROUP BY 1, 2, 3, 4, 5, coalesce(a.ino, -a.file_id)) x
                            JOIN pinakes.roots r ON r.root_id = x.root_id JOIN pinakes.hosts h ON h.host_id = x.host_id
                            LEFT JOIN pinakes.people p ON p.person_id = x.owner_id
                            GROUP BY h.name, x.dev, r.label, x.folder, x.owner_id, p.display
                            ORDER BY bytes DESC, h.name, x.dev NULLS LAST, r.label, x.folder, x.owner_id NULLS LAST"""
                   + PAGE, (AT_RISK_FOLDERS, 0))
    return {"disks": disks, "hosts": hosts, "folders": folders, "folders_total": page_total(folders),
            "owners": sorted({f["owner_id"] for f in folders if f["owner_id"] is not None})}


def operator_roots(conn):
    """The operator page (ROADMAP 10): every root's files, bytes, scan, scrub, reporting state and scan errors, as
    counts and dates (pinakes.operator_roots(): an operator signed in on the web only)."""
    return rows(conn, "SELECT * FROM pinakes.operator_roots()")


def operator_at_risk(conn):
    """What a disk's loss would cost, as every person's totals per disk and per host, without names (ROADMAP 42)."""
    out = rows(conn, "SELECT * FROM pinakes.operator_at_risk()")
    return {"disks": [r for r in out if r["scope"] == "disk"], "hosts": [r for r in out if r["scope"] == "host"]}


def roots(conn, hidden=True):
    """Every root with the files the person can see in it (under a token, only the roots it may see); without
    `hidden`, not counting the hidden ones, which `hidden_files` still counts. Every root's counts come from one
    grouped pass over the files the person can see: two counts per root read them once per count (ROADMAP 48)."""
    return rows(conn, """SELECT r.label, h.name AS host, r.kind, r.protected, r.last_complete_on,
                                coalesce(c.files, 0) AS files, coalesce(c.hidden_files, 0) AS hidden_files
                         FROM pinakes.roots r JOIN pinakes.hosts h USING (host_id)
                         LEFT JOIN (SELECT f.root_id, count(*) FILTER (WHERE %s OR NOT f.hidden) AS files,
                                           count(*) FILTER (WHERE f.hidden) AS hidden_files
                                    FROM pinakes.present f GROUP BY f.root_id) c USING (root_id)
                         WHERE pinakes.token_roots() IS NULL OR r.root_id = ANY (pinakes.token_roots())
                         ORDER BY h.name, r.label""", (hidden,))


def root_choices(conn):
    """Every root, for choosing the ones a token may see: id, label, host, whether protected."""
    return rows(conn, """SELECT r.root_id, r.label, h.name AS host, r.protected
                         FROM pinakes.roots r JOIN pinakes.hosts h USING (host_id) ORDER BY h.name, r.label""")


def roots_of_host(conn, host):
    """The roots a host reports (label, path on that host, kind), for finding which one a local folder is in (under
    a token, only the roots it may see)."""
    return rows(conn, """SELECT r.label, r.path, r.kind FROM pinakes.roots r JOIN pinakes.hosts h USING (host_id)
                         WHERE h.name = %s
                           AND (pinakes.token_roots() IS NULL OR r.root_id = ANY (pinakes.token_roots()))""", (host,))


def unbacked(conn, loc):
    """How many present files under ROOT:PATH that the person can see have no backup copy holding their content."""
    root, path = split_location(loc)
    return conn.execute("""SELECT count(*) FROM (SELECT 1 FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                           LEFT JOIN pinakes.present b ON b.backup_of = f.file_id AND b.content_id = f.content_id
                           WHERE r.label = %s AND (f.relpath LIKE %s OR f.relpath = %s) GROUP BY f.file_id
                           HAVING count(b.file_id) = 0) x""", (root, _prefix(path), path)).fetchone()[0]


def listing(conn, loc, limit=None, offset=0, sort=None, direction="asc", hidden=True, placeholders=True):
    """The folders and files directly in a folder that the person can see; without `hidden`, none of the hidden
    files (a folder whose files are all hidden doesn't show). An entry is hidden when all its files are. Without
    `placeholders`, none of a placeholder's files (ROADMAP 69), the same way."""
    root, path = split_location(loc)
    pre = _prefix(path)
    depth = path.count("/") + 1 if path else 0
    # size counts each inode once: hard links (a snapshot tree) take their space once on the disk
    return rows(conn, """WITH e AS (
                             SELECT split_part(f.relpath, '/', %s + 1) AS entry,
                                    array_length(string_to_array(f.relpath, '/'), 1) > %s + 1 AS deeper,
                                    f.file_id, f.size, f.mtime, f.dev, f.ino, f.hidden
                             FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                             WHERE r.label = %s AND f.relpath LIKE %s""" + ("" if hidden else " AND NOT f.hidden")
                + _placeholders_cond(bool(placeholders)) + """)
                         SELECT entry, bool_or(deeper) AS is_folder, count(*) AS files,
                                (SELECT sum(s.size) FROM (SELECT DISTINCT ON (x.dev, x.ino) x.size FROM e x
                                                          WHERE x.entry = e.entry) s) AS size,
                                max(mtime) AS newest, min(file_id) FILTER (WHERE NOT deeper) AS file_id,
                                bool_and(hidden) AS hidden, """ + TOTAL + """
                         FROM e GROUP BY entry"""
                + order(LISTING_SORT, sort, direction, "2 DESC, 1") + PAGE, (depth, depth, root, pre, limit, offset))


def placeholders_in(conn, loc, hidden=True):
    """How many files of placeholders the person can see in a folder, at any depth (without `hidden`, of those not
    hidden): what a listing without them leaves out."""
    root, path = split_location(loc)
    return conn.execute("SELECT count(*) FROM pinakes.present f JOIN pinakes.roots r USING (root_id) "
                        "WHERE r.label = %s AND f.relpath LIKE %s" + ("" if hidden else " AND NOT f.hidden")
                        + _placeholders_cond("only"), (root, _prefix(path))).fetchone()[0]


def hidden_in(conn, loc):
    """How many hidden files the person can see in a folder, at any depth."""
    root, path = split_location(loc)
    return conn.execute("SELECT count(*) FROM pinakes.present f JOIN pinakes.roots r USING (root_id) "
                        "WHERE r.label = %s AND f.relpath LIKE %s AND f.hidden", (root, _prefix(path))).fetchone()[0]


def audit_mine(conn, limit=None, offset=0, sort=None, direction="asc"):
    """Audit entries that concern the current person or were made by them (row-level security picks them)."""
    return rows(conn, """SELECT a.at, a.action, p.display AS actor, a.detail,
                                a.actor = pinakes.current_person() AS mine, """ + TOTAL + """
                         FROM pinakes.audit a LEFT JOIN pinakes.people p ON p.person_id = a.actor"""
                + order(AUDIT_SORT, sort, direction, "a.at DESC, a.audit_id DESC") + PAGE, (limit, offset))


# The catalog's own writes (ROADMAP 62): review marks, lineage decisions and person-entered metadata, each write call
# an edit, kept with the values before. Written only by the database's functions; row-level security shows a person
# their own and their groups', and of each only the values on files they still see.
def edits(conn, days=7, client=None, limit=None, offset=0):
    """The person's edits of the last `days`, the newest first: their own (on the web and by each of their tokens;
    `client`: by that token only, by its name) and their groups'. Each with how many values it changed that they can
    still see, the first of those (its file, and an edge's other end), the edit it undoes and the one that undid it."""
    return rows(conn, """SELECT e.edit_id AS edit, e.at, e.action, p.display AS person, g.name AS "group",
                                e.person_id = pinakes.current_person() AS mine, e.client AS token, e.undoes,
                                (SELECT min(u.edit_id) FROM pinakes.edits u WHERE u.undoes = e.edit_id) AS undone_by,
                                i.changes, r.label AS root, f.relpath, ro.label AS other_root,
                                fo.relpath AS other_relpath, fi.kind, fi.schema, fi.before, fi.after, """ + TOTAL + """
                         FROM pinakes.edits e
                         LEFT JOIN pinakes.people p ON p.person_id = e.person_id
                         LEFT JOIN pinakes.groups g ON g.group_id = e.group_id
                         CROSS JOIN LATERAL (SELECT count(*) AS changes, min(it.item_id) AS first
                                             FROM pinakes.edit_items it WHERE it.edit_id = e.edit_id) i
                         JOIN pinakes.edit_items fi ON fi.item_id = i.first
                         JOIN pinakes.files f ON f.file_id = fi.file_id JOIN pinakes.roots r ON r.root_id = f.root_id
                         LEFT JOIN pinakes.files fo ON fo.file_id = fi.other_file_id
                         LEFT JOIN pinakes.roots ro ON ro.root_id = fo.root_id
                         WHERE e.at > now() - make_interval(days => %s) AND (%s::text IS NULL OR e.client = %s)
                         ORDER BY e.edit_id DESC""" + PAGE, (days, client, client, limit, offset))


UNDO_LIMIT = 1000           # edits one undo names


def undo_edits(conn, ids):
    """Undo the person's edits (the database decides what they may, edit by edit, the newest first): one row per
    edit asked, the undo's own edit and how many values it put back, or why not, in words for a person (`message`)
    with the file it concerns (ROOT:PATH, if they still see it) and the later edit that changed it since."""
    out = []
    for r in rows(conn, "SELECT * FROM pinakes.undo_edits(%s::bigint[])", (list(ids),)):
        if not r["refused"]:
            out.append({"edit": r["edit"], "undone_by": r["undone_by"], "changes": r["changes"]})
            continue
        f = file_by_id(conn, r["refused_file"]) if r["refused_file"] else None
        where = "%s:%s" % (f["root"], f["relpath"]) if f else None
        action = conn.execute("SELECT action FROM pinakes.edits WHERE edit_id = %s", (r["edit"],)).fetchone()
        message = {
            "not_yours": "no edit %d of yours" % r["edit"],
            "no_scope": "this token doesn't have the %s scope" % ("tag" if action and action[0] == "metadata"
                                                                  else "review"),
            "gone": "the link to %s is no longer in the catalog" % (where or "a file"),
            "not_now": "%s is no longer yours to change, or outside this token's roots" % (where or "a file it changed"),
        }.get(r["refused"])
        if r["refused"] == "changed":
            message = "%s changed since" % (where or "a value it wrote")
            later = rows(conn, """SELECT e.at, e.person_id = pinakes.current_person() AS mine, p.display AS person,
                                         g.name AS "group", e.client AS token
                                  FROM pinakes.edits e LEFT JOIN pinakes.people p ON p.person_id = e.person_id
                                  LEFT JOIN pinakes.groups g ON g.group_id = e.group_id
                                  WHERE e.edit_id = %s""", (r["later"],)) if r["later"] else []
            if later:
                message += ", by edit %d (%s, %s)" % (r["later"], later[0]["at"].astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                                                      edit_by(later[0]))
            elif r["later"]:
                message += ", by another person's edit %d" % r["later"]
            else:
                message += ", not by an edit"
        out.append({"edit": r["edit"], "refused": r["refused"], "message": message, "file": where,
                    "later": r["later"]})
    return out


def edit_by(e):
    """Who made an edit, for a person reading it: you, or the group, by token or on the web."""
    who = "you" if e["mine"] else e["person"] or ""
    if e["group"]:
        who = "%s for %s" % (who, e["group"]) if who else "group " + e["group"]
    return "%s, %s" % (who, "token " + e["token"] if e["token"] else "on the web")


def owners_of(conn, file_ids):
    """Owner person ids of these files (for the step-up audit)."""
    if not file_ids:
        return []
    return [r[0] for r in conn.execute("SELECT DISTINCT owner_id FROM pinakes.files WHERE file_id = ANY (%s) "
                                       "AND owner_id IS NOT NULL", (list(file_ids),)).fetchall()]


def json_default(o):
    """For json.dumps of query rows: dates and times as ISO 8601, intervals as text, hashes as hex."""
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    if isinstance(o, datetime.timedelta):
        return str(o)
    if isinstance(o, (bytes, memoryview)):
        return bytes(o).hex()
    return str(o)
