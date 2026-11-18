"""The catalog's queries (QUERIES.md), parameterized. Every function runs as whoever the connection is set to:
row-level security decides what comes back. A location is ROOT:PATH, where ROOT is a root's label."""

import datetime
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
    if wildcards:
        like = like.replace("*", "%").replace("?", "_")
        return like if "%" in like or "_" in like else "%" + like + "%"
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


def find(conn, pattern, limit=None, offset=0, sort=None, direction="asc"):
    like = _like(pattern, wildcards=True)
    return rows(conn, """SELECT %s, %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) WHERE f.name ILIKE %%s""" % (FILE_COLS, TOTAL)
                + order(FILE_SORT, sort, direction, "f.name, h.name, f.file_id") + PAGE, (like, limit, offset))


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


def where(conn, file_id, limit=None, offset=0, sort=None, direction="asc"):
    """Every copy; same_inode marks hard links of this very file (the same data on the same disk, not a copy)."""
    return rows(conn, """SELECT %s, (r.host_id = tr.host_id AND f.dev = t.dev AND f.ino = t.ino) AS same_inode, %s
                         FROM pinakes.files t JOIN pinakes.roots tr ON tr.root_id = t.root_id
                         JOIN pinakes.present f ON f.content_id = t.content_id
                         JOIN pinakes.roots r ON r.root_id = f.root_id JOIN pinakes.hosts h ON h.host_id = r.host_id
                         WHERE t.file_id = %%s""" % (FILE_COLS, TOTAL)
                + order(FILE_SORT, sort, direction, "r.kind, h.name, f.relpath, f.file_id") + PAGE,
                (file_id, limit, offset))


# Copies of a file f (in root r) outside a folder, counted physically: distinct (host, device, inode), never f's own
# inode (a hard link of f is the same data, not a copy). A copy is on another disk when its host differs, or its
# device does on the same host; a device the catalog doesn't know counts as the same disk. A copy the scrub couldn't
# read (unreadable_on) is no copy until it reads again (DESIGN.md "Scrub"). %%s: the folder's pattern.
_COPIES = """CROSS JOIN LATERAL (
        SELECT count(DISTINCT (ro.host_id, o.dev, o.ino))
                   FILTER (WHERE NOT coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS same_disk,
               count(DISTINCT (ro.host_id, o.dev, o.ino))
                   FILTER (WHERE coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS other_disk
        FROM pinakes.present o JOIN pinakes.roots ro ON ro.root_id = o.root_id
        WHERE o.content_id = f.content_id AND o.unreadable_on IS NULL
          AND NOT (o.root_id = f.root_id AND o.relpath LIKE %%s)
          AND NOT coalesce(ro.host_id = r.host_id AND o.dev = f.dev AND o.ino = f.ino, false) %s) s"""
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
    snapshots that hold the current version, and the newest of them."""
    root, path = split_location(loc)
    return rows(conn, """SELECT f.file_id, f.relpath,
                                count(DISTINCT (br.host_id, b.dev, b.ino)) FILTER (WHERE b.file_id IS NOT NULL)
                                    AS backup_copies,
                                count(b.file_id) AS snapshots, max(b.snapshot) AS newest, """ + TOTAL + """
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
    the same hash, take no space and reclaim nothing."""
    return rows(conn, """SELECT encode(c.sha256, 'hex') AS sha256, c.size,
                                count(DISTINCT (r.host_id, f.dev, f.ino)) AS copies, count(*) AS paths_count,
                                c.size * (count(DISTINCT (r.host_id, f.dev, f.ino)) - 1) AS reclaimable,
                                array_agg(r.label || ':' || f.relpath ORDER BY r.label, f.relpath) AS paths,
                                """ + TOTAL + """
                         FROM pinakes.present f JOIN pinakes.contents c USING (content_id)
                         JOIN pinakes.roots r USING (root_id)
                         WHERE r.kind <> 'backup' AND c.size > 0 GROUP BY c.content_id
                         HAVING count(DISTINCT (r.host_id, f.dev, f.ino)) > 1"""
                + order(DUPES_SORT, sort, direction, "reclaimable DESC, c.content_id") + PAGE, (limit, offset))


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


def changes(conn, days=7, host=None, limit=None, offset=0, sort=None, direction="asc", kinds=None, loc=None,
            review=None, until=None, elsewhere=False):
    """History in the last `days` (and up to `until`, a date), optionally only some kinds, only what touched a folder
    or a file (ROOT:PATH; a move counts at both ends), only unreviewed or reviewed changes, and only gone files whose
    last content is still in another root you can see, not a backup (`elsewhere`). Each row has its review mark, and for
    a gone file the copies of its last content you can see: `elsewhere` (primary and drop roots, one shown in
    `elsewhere_at`) and `backups`."""
    since = today() - datetime.timedelta(days=days)
    root, pre, path = (None, None, None)
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
    rv = _review(review)
    return rows(conn, """SELECT hi.seen_on, h.name AS host, r.label AS root,
                                coalesce(hi.new_relpath, hi.old_relpath) AS path, hi.old_relpath, hi.kind,
                                hi.file_id, hi.history_id, hi.kind IN ('gone', 'moved', 'moved_changed', 'mismatch', 'unreadable') AS reviewable,
                                m.mark, m.marked_at, coalesce(mp.display, mg.name) AS marked_by,
                                c.elsewhere, c.elsewhere_at, c.backups, """ + TOTAL + """
                         FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         LEFT JOIN pinakes.review_marks m ON m.history_id = hi.history_id
                         LEFT JOIN pinakes.people mp ON mp.person_id = m.marked_by
                         LEFT JOIN pinakes.groups mg ON mg.group_id = m.marked_by_group
                         LEFT JOIN LATERAL (
                             SELECT count(*) FILTER (WHERE ro.kind <> 'backup') AS elsewhere,
                                    min(oh.name || ' · ' || ro.label || ':' || o.relpath)
                                        FILTER (WHERE ro.kind <> 'backup') AS elsewhere_at,
                                    count(DISTINCT (ro.host_id, o.dev, o.ino)) FILTER (WHERE ro.kind = 'backup')
                                        AS backups
                             FROM pinakes.present o JOIN pinakes.roots ro ON ro.root_id = o.root_id
                             JOIN pinakes.hosts oh ON oh.host_id = ro.host_id
                             WHERE hi.kind = 'gone' AND o.content_id = hi.old_content_id
                               AND o.unreadable_on IS NULL) c ON true
                         WHERE hi.seen_on >= %s AND (%s::date IS NULL OR hi.seen_on <= %s)
                           AND (%s::text IS NULL OR h.name = %s)
                           AND (%s::text[] IS NULL OR hi.kind = ANY (%s::text[]))
                           AND (%s::text IS NULL OR r.label = %s AND (hi.new_relpath LIKE %s OR hi.old_relpath LIKE %s
                                                                       OR hi.new_relpath = %s OR hi.old_relpath = %s))
                           AND """ + _REVIEW_WHERE + """
                           AND (NOT %s OR hi.kind = 'gone' AND c.elsewhere > 0)"""
                + order(CHANGES_SORT, sort, direction, "hi.seen_on DESC, path, hi.history_id") + PAGE,
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
    as in changes(). `owners` is the owners of the files counted, for the step-up audit. At most TREE_LIMIT rows."""
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
                               AND w.depth < %%s)
                         SELECT w.depth, w.how, w.evidence, w.confidence, w.decision, %s
                         FROM w JOIN pinakes.files f USING (file_id) JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) WHERE w.depth > 0
                         ORDER BY w.depth, h.name""" % (nxt, nxt, join, nxt, FILE_COLS), (file_id, file_id, depth))


def meta(conn, schema, field, value, limit=None, offset=0):
    return rows(conn, """SELECT %s, m.vals, %s FROM pinakes.metadata m JOIN pinakes.present f ON f.content_id = m.content_id
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         WHERE m.schema = %%s AND m.vals ->> %%s = %%s ORDER BY f.relpath, f.file_id""" % (FILE_COLS, TOTAL)
                + PAGE, (schema, field, value, limit, offset))


def file_metadata(conn, file_id, content_id):
    """The metadata the person may see on a file: its content's (extracted, true of every copy) and the file's own
    (entered by people). Sensitive rows come back only where row-level security lets them (sensitive_visible())."""
    return rows(conn, """SELECT m.schema, m.vals, m.source, m.version, m.at, m.sensitive, p.display AS author
                         FROM pinakes.metadata m LEFT JOIN pinakes.people p ON p.person_id = m.author
                         WHERE m.file_id = %s OR m.content_id = %s
                         ORDER BY m.schema, m.sensitive, m.source, m.metadata_id""", (file_id, content_id))


def sensitive_visible(conn, file_id, content_id):
    return conn.execute("SELECT pinakes.sensitive_visible(%s, %s)", (content_id, file_id)).fetchone()[0]


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
            sort=None, direction="asc", hidden=True):
    """Files by name, by common fields, or both: `creator`, a substring, over every (schema, field) in
    `mapped_creator`; `dated`, (first, after) with either None for no bound, over every one in `mapped_date`
    (from date_bounds(): "from a day" is its first, "to a day" the next one's). Metadata on a file's content or on
    the file itself counts. Row-level security decides which metadata is searched, so a sensitive field the person
    may not see finds nothing. Without `hidden`, no hidden file."""
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
    return rows(conn, """SELECT %s, %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) WHERE %s""" % (FILE_COLS, TOTAL, " AND ".join(where))
                + order(FILE_SORT, sort, direction, "f.name, h.name, f.file_id") + PAGE, args + [limit, offset])


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


def listing(conn, loc, limit=None, offset=0, sort=None, direction="asc", hidden=True):
    """The folders and files directly in a folder that the person can see; without `hidden`, none of the hidden
    files (a folder whose files are all hidden doesn't show). An entry is hidden when all its files are."""
    root, path = split_location(loc)
    pre = _prefix(path)
    depth = path.count("/") + 1 if path else 0
    # size counts each inode once: hard links (a snapshot tree) take their space once on the disk
    return rows(conn, """WITH e AS (
                             SELECT split_part(f.relpath, '/', %s + 1) AS entry,
                                    array_length(string_to_array(f.relpath, '/'), 1) > %s + 1 AS deeper,
                                    f.file_id, f.size, f.mtime, f.dev, f.ino, f.hidden
                             FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                             WHERE r.label = %s AND f.relpath LIKE %s""" + ("" if hidden else " AND NOT f.hidden") + """)
                         SELECT entry, bool_or(deeper) AS is_folder, count(*) AS files,
                                (SELECT sum(s.size) FROM (SELECT DISTINCT ON (x.dev, x.ino) x.size FROM e x
                                                          WHERE x.entry = e.entry) s) AS size,
                                max(mtime) AS newest, min(file_id) FILTER (WHERE NOT deeper) AS file_id,
                                bool_and(hidden) AS hidden, """ + TOTAL + """
                         FROM e GROUP BY entry"""
                + order(LISTING_SORT, sort, direction, "2 DESC, 1") + PAGE, (depth, depth, root, pre, limit, offset))


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
