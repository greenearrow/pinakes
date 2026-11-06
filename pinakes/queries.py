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


def find(conn, pattern, limit=200):
    like = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")
    if "%" not in like and "_" not in like:
        like = "%" + like + "%"
    return rows(conn, """SELECT %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id) WHERE f.name ILIKE %%s
                         ORDER BY f.name, h.name LIMIT %%s""" % FILE_COLS, (like, limit))


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


def where(conn, file_id):
    return rows(conn, """SELECT %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id)
                         WHERE f.content_id = (SELECT content_id FROM pinakes.files WHERE file_id = %%s)
                         ORDER BY r.kind, h.name, f.relpath""" % FILE_COLS, (file_id,))


def only_here(conn, loc):
    root, path = split_location(loc)
    pre = _prefix(path)
    return rows(conn, """SELECT %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id)
                         WHERE r.label = %%s AND f.relpath LIKE %%s
                           AND NOT EXISTS (SELECT 1 FROM pinakes.present o WHERE o.content_id = f.content_id
                                           AND NOT (o.root_id = f.root_id AND o.relpath LIKE %%s))
                         ORDER BY f.relpath""" % FILE_COLS, (root, pre, pre))


def not_safe_to_delete(conn, loc):
    """The files under loc with no copy in a primary or backup root outside it. Empty: safe."""
    root, path = split_location(loc)
    pre = _prefix(path)
    return rows(conn, """SELECT %s FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         JOIN pinakes.hosts h USING (host_id)
                         WHERE r.label = %%s AND f.relpath LIKE %%s
                           AND NOT EXISTS (SELECT 1 FROM pinakes.present o JOIN pinakes.roots ro
                                             ON ro.root_id = o.root_id
                                           WHERE o.content_id = f.content_id AND ro.kind IN ('primary', 'backup')
                                             AND NOT (o.root_id = f.root_id AND o.relpath LIKE %%s))
                         ORDER BY f.relpath""" % FILE_COLS, (root, pre, pre))


def backed_up(conn, loc):
    root, path = split_location(loc)
    return rows(conn, """SELECT f.file_id, f.relpath, count(b.file_id) AS backup_copies, max(b.snapshot) AS newest
                         FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         LEFT JOIN pinakes.present b ON b.backup_of = f.file_id AND b.content_id = f.content_id
                         WHERE r.label = %s AND f.relpath LIKE %s
                         GROUP BY f.file_id, f.relpath ORDER BY backup_copies, f.relpath""", (root, _prefix(path)))


def dupes(conn, limit=50):
    return rows(conn, """SELECT encode(c.sha256, 'hex') AS sha256, c.size, count(*) AS copies,
                                c.size * (count(*) - 1) AS reclaimable,
                                array_agg(r.label || ':' || f.relpath ORDER BY r.label, f.relpath) AS paths
                         FROM pinakes.present f JOIN pinakes.contents c USING (content_id)
                         JOIN pinakes.roots r USING (root_id)
                         WHERE r.kind <> 'backup' GROUP BY c.content_id HAVING count(*) > 1
                         ORDER BY reclaimable DESC LIMIT %s""", (limit,))


def history(conn, file_id):
    return rows(conn, """SELECT h.seen_after, h.seen_on, h.kind, h.old_relpath, h.new_relpath,
                                encode(oc.sha256, 'hex') AS old_sha256, encode(nc.sha256, 'hex') AS new_sha256,
                                h.old_mtime, h.new_mtime, h.evidence, h.confidence
                         FROM pinakes.history h
                         LEFT JOIN pinakes.contents oc ON oc.content_id = h.old_content_id
                         LEFT JOIN pinakes.contents nc ON nc.content_id = h.new_content_id
                         WHERE h.file_id = %s ORDER BY h.seen_on, h.history_id""", (file_id,))


def changes(conn, days=7, host=None, limit=500):
    since = datetime.date.today() - datetime.timedelta(days=days)
    return rows(conn, """SELECT hi.seen_on, h.name AS host, r.label AS root,
                                coalesce(hi.new_relpath, hi.old_relpath) AS path, hi.kind, hi.file_id
                         FROM pinakes.history hi JOIN pinakes.files f USING (file_id)
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         WHERE hi.seen_on >= %s AND (%s::text IS NULL OR h.name = %s)
                         ORDER BY hi.seen_on DESC, path LIMIT %s""", (since, host, host, limit))


def versions(conn, file_id):
    return rows(conn, """WITH v AS (SELECT new_content_id AS content_id, min(seen_on) AS first_seen_on
                                    FROM pinakes.history WHERE file_id = %s AND new_content_id IS NOT NULL
                                    GROUP BY new_content_id)
                         SELECT encode(c.sha256, 'hex') AS sha256, v.first_seen_on, r.label AS backup_root,
                                b.snapshot, b.relpath AS backup_path
                         FROM v JOIN pinakes.contents c USING (content_id)
                         LEFT JOIN (pinakes.present b JOIN pinakes.roots r ON r.root_id = b.root_id
                                    AND r.kind = 'backup') ON b.content_id = v.content_id
                         ORDER BY v.first_seen_on, b.snapshot""", (file_id,))


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


def meta(conn, schema, field, value, limit=200):
    return rows(conn, """SELECT %s, m.vals FROM pinakes.metadata m JOIN pinakes.present f ON f.content_id = m.content_id
                         JOIN pinakes.roots r USING (root_id) JOIN pinakes.hosts h USING (host_id)
                         WHERE m.schema = %%s AND m.vals ->> %%s = %%s ORDER BY f.relpath LIMIT %%s""" % FILE_COLS,
                (schema, field, value, limit))


def stale(conn):
    return rows(conn, """SELECT name, last_scan, expected_every FROM pinakes.hosts
                         WHERE expected_every IS NOT NULL AND (last_scan IS NULL OR last_scan < now() - expected_every)
                         ORDER BY last_scan NULLS FIRST""")


def roots(conn):
    return rows(conn, """SELECT r.label, h.name AS host, r.kind, r.protected, r.last_complete_on,
                                (SELECT count(*) FROM pinakes.present f WHERE f.root_id = r.root_id) AS files
                         FROM pinakes.roots r JOIN pinakes.hosts h USING (host_id) ORDER BY h.name, r.label""")


def listing(conn, loc, limit=1000):
    """The folders and files directly in a folder that the person can see."""
    root, path = split_location(loc)
    pre = _prefix(path)
    depth = path.count("/") + 1 if path else 0
    return rows(conn, """SELECT split_part(f.relpath, '/', %s + 1) AS entry,
                                bool_or(array_length(string_to_array(f.relpath, '/'), 1) > %s + 1) AS is_folder,
                                count(*) AS files, sum(f.size) AS size, max(f.mtime) AS newest,
                                min(f.file_id) FILTER (WHERE array_length(string_to_array(f.relpath, '/'), 1) = %s + 1)
                                    AS file_id
                         FROM pinakes.present f JOIN pinakes.roots r USING (root_id)
                         WHERE r.label = %s AND f.relpath LIKE %s
                         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT %s""", (depth, depth, depth, root, pre, limit))


def owners_of(conn, file_ids):
    """Owner person ids of these files (for the step-up audit)."""
    if not file_ids:
        return []
    return [r[0] for r in conn.execute("SELECT DISTINCT owner_id FROM pinakes.files WHERE file_id = ANY (%s) "
                                       "AND owner_id IS NOT NULL", (list(file_ids),)).fetchall()]
