"""The catalog's queries (QUERIES.md), parameterized. Every function runs as whoever the connection is set to:
row-level security decides what comes back. A location is ROOT:PATH, where ROOT is a root's label."""

import datetime

FILE_COLS = "f.file_id, h.name AS host, r.label AS root, r.kind, f.relpath, f.size, f.mtime, f.snapshot, f.gone_on"


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
    like = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")
    if "%" not in like and "_" not in like:
        like = "%" + like + "%"
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
                             f.last_seen, f.backup_of, p.display AS owner
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
# device does on the same host; a device the catalog doesn't know counts as the same disk. %%s: the folder's pattern.
_COPIES = """CROSS JOIN LATERAL (
        SELECT count(DISTINCT (ro.host_id, o.dev, o.ino))
                   FILTER (WHERE NOT coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS same_disk,
               count(DISTINCT (ro.host_id, o.dev, o.ino))
                   FILTER (WHERE coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS other_disk
        FROM pinakes.present o JOIN pinakes.roots ro ON ro.root_id = o.root_id
        WHERE o.content_id = f.content_id AND NOT (o.root_id = f.root_id AND o.relpath LIKE %%s)
          AND NOT coalesce(ro.host_id = r.host_id AND o.dev = f.dev AND o.ino = f.ino, false) %s) s"""
COPY_SORT = dict(FILE_SORT, same_disk=("s.same_disk",))


def _no_copy_on_another_disk(conn, loc, kinds, limit, offset, sort, direction):
    root, path = split_location(loc)
    pre = _prefix(path)
    return rows(conn, """SELECT %s, s.same_disk, %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) %s
                         WHERE r.label = %%s AND f.relpath LIKE %%s AND s.other_disk = 0"""
                % (FILE_COLS, TOTAL, _COPIES % ("AND ro.kind IN ('primary', 'backup')" if kinds else ""))
                + order(COPY_SORT, sort, direction, "f.relpath, f.file_id") + PAGE, (pre, root, pre, limit, offset))


def only_here(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """The files under loc with no copy on another disk. same_disk: their copies outside loc on the same disk, which
    die with it (0: no copy anywhere else)."""
    return _no_copy_on_another_disk(conn, loc, False, limit, offset, sort, direction)


def not_safe_to_delete(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """The files under loc with no copy in a primary or backup root on another disk. Empty: safe. same_disk: their
    kept copies outside loc on the same disk, which don't make them safe."""
    return _no_copy_on_another_disk(conn, loc, True, limit, offset, sort, direction)


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
                         LEFT JOIN pinakes.roots br ON br.root_id = b.root_id
                         WHERE r.label = %s AND f.relpath LIKE %s
                         GROUP BY f.file_id, f.relpath"""
                + order(BACKED_UP_SORT, sort, direction, "backup_copies, f.relpath, f.file_id") + PAGE,
                (root, _prefix(path), limit, offset))


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


KINDS = ("new", "changed", "moved", "moved_changed", "gone")


def _kinds(kinds):
    """The history kinds asked for, whitelisted; None (no filter) when none are."""
    k = [x for x in (kinds or ()) if x in KINDS]
    return k or None


def changes(conn, days=7, host=None, limit=None, offset=0, sort=None, direction="asc", kinds=None, loc=None):
    """History in the last `days`, optionally only some kinds and only what touched a folder (ROOT:PATH; a move
    counts at both ends)."""
    since = datetime.date.today() - datetime.timedelta(days=days)
    root, pre = (None, None)
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
    return rows(conn, """SELECT hi.seen_on, h.name AS host, r.label AS root,
                                coalesce(hi.new_relpath, hi.old_relpath) AS path, hi.old_relpath, hi.kind,
                                hi.file_id, """ + TOTAL + """
                         FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         WHERE hi.seen_on >= %s AND (%s::text IS NULL OR h.name = %s)
                           AND (%s::text[] IS NULL OR hi.kind = ANY (%s::text[]))
                           AND (%s::text IS NULL OR r.label = %s AND (hi.new_relpath LIKE %s OR hi.old_relpath LIKE %s))"""
                + order(CHANGES_SORT, sort, direction, "hi.seen_on DESC, path, hi.history_id") + PAGE,
                (since, host, host, _kinds(kinds), _kinds(kinds), root, root, pre, pre, limit, offset))


TREE_LIMIT = 2000


def change_tree(conn, days=7, loc=None, depth=3, kinds=None):
    """Per folder, what happened under it in the last `days`: files new, changed, moved in (destination), moved out
    (source) and gone. A tracked move counts at both ends, never as new and gone; a move inside a folder counts
    there as both in and out. From the folder `loc` (ROOT:PATH; None: every root) down `depth` levels, in tree order.
    `owners` is the owners of the files counted, for the step-up audit. At most TREE_LIMIT rows."""
    since = datetime.date.today() - datetime.timedelta(days=days)
    root, pre, base = None, "%", 0
    if loc:
        root, path = split_location(loc)
        pre = _prefix(path)
        base = len([p for p in path.split("/") if p])
    return rows(conn, """WITH ev AS (
                             SELECT h.name AS host, r.label AS root, f.owner_id, x.role,
                                    string_to_array(x.path, '/') AS parts
                             FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                             JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                             CROSS JOIN LATERAL (VALUES
                                 (CASE WHEN hi.kind IN ('moved', 'moved_changed') THEN hi.new_relpath END, 'in'),
                                 (CASE WHEN hi.kind IN ('moved', 'moved_changed') THEN hi.old_relpath END, 'out'),
                                 (CASE WHEN hi.kind = 'new' THEN hi.new_relpath END, 'new'),
                                 (CASE WHEN hi.kind = 'changed' THEN hi.new_relpath END, 'changed'),
                                 (CASE WHEN hi.kind = 'gone' THEN hi.old_relpath END, 'gone')) AS x (path, role)
                             WHERE hi.seen_on >= %s AND x.path IS NOT NULL AND x.path LIKE %s
                               AND (%s::text IS NULL OR r.label = %s)
                               AND (%s::text[] IS NULL OR hi.kind = ANY (%s::text[]))),
                         t AS (
                             SELECT host, root, owner_id, role, parts[1:i] AS folder
                             FROM ev, generate_series(%s, least(array_length(parts, 1) - 1, %s)) AS i)
                         SELECT host, root, array_to_string(folder, '/') AS folder,
                                coalesce(array_length(folder, 1), 0) AS level,
                                count(*) FILTER (WHERE role = 'new') AS new,
                                count(*) FILTER (WHERE role = 'changed') AS changed,
                                count(*) FILTER (WHERE role = 'in') AS moved_in,
                                count(*) FILTER (WHERE role = 'out') AS moved_out,
                                count(*) FILTER (WHERE role = 'gone') AS gone,
                                array_agg(DISTINCT owner_id) FILTER (WHERE owner_id IS NOT NULL) AS owners
                         FROM t GROUP BY host, root, folder ORDER BY host, root, folder LIMIT %s""",
                (since, pre, root, root, _kinds(kinds), _kinds(kinds), base, base + depth, TREE_LIMIT + 1))


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


def stale(conn):
    return rows(conn, """SELECT name, last_scan, expected_every FROM pinakes.hosts
                         WHERE expected_every IS NOT NULL AND (last_scan IS NULL OR last_scan < now() - expected_every)
                         ORDER BY last_scan NULLS FIRST""")


def health(conn):
    """Per host: its newest batch, its last complete scan, how often it should report, and whether it is stale.
    Host names and times only: no root, person or file."""
    return rows(conn, """SELECT h.name AS host, (SELECT max(i.at) FROM pinakes.ingested i WHERE i.host_id = h.host_id)
                                AS newest_batch, h.last_scan, h.expected_every,
                                (h.expected_every IS NOT NULL AND (h.last_scan IS NULL
                                 OR h.last_scan < now() - h.expected_every)) AS stale
                         FROM pinakes.hosts h ORDER BY h.name""")


def roots(conn):
    return rows(conn, """SELECT r.label, h.name AS host, r.kind, r.protected, r.last_complete_on,
                                (SELECT count(*) FROM pinakes.present f WHERE f.root_id = r.root_id) AS files
                         FROM pinakes.roots r JOIN pinakes.hosts h USING (host_id) ORDER BY h.name, r.label""")


def listing(conn, loc, limit=None, offset=0, sort=None, direction="asc"):
    """The folders and files directly in a folder that the person can see."""
    root, path = split_location(loc)
    pre = _prefix(path)
    depth = path.count("/") + 1 if path else 0
    # size counts each inode once: hard links (a snapshot tree) take their space once on the disk
    return rows(conn, """WITH e AS (
                             SELECT split_part(f.relpath, '/', %s + 1) AS entry,
                                    array_length(string_to_array(f.relpath, '/'), 1) > %s + 1 AS deeper,
                                    f.file_id, f.size, f.mtime, f.dev, f.ino
                             FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                             WHERE r.label = %s AND f.relpath LIKE %s)
                         SELECT entry, bool_or(deeper) AS is_folder, count(*) AS files,
                                (SELECT sum(s.size) FROM (SELECT DISTINCT ON (x.dev, x.ino) x.size FROM e x
                                                          WHERE x.entry = e.entry) s) AS size,
                                max(mtime) AS newest, min(file_id) FILTER (WHERE NOT deeper) AS file_id, """ + TOTAL + """
                         FROM e GROUP BY entry"""
                + order(LISTING_SORT, sort, direction, "2 DESC, 1") + PAGE, (depth, depth, root, pre, limit, offset))


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
