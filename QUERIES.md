# Queries in SQL

Every `pinakes` command (DESIGN.md "Queries") is one SQL statement over the catalog, shown here as the CLI runs it.
They run as the signed-in person, so row-level security (SECURITY.md) already limits them to what that person may
see: no owner filters appear below.

Status: every block below runs in `tests/test_queries.py`, as a person under row-level security, on a catalog built by
real scans (PostgreSQL 16). The sketch matches `pinakes/schema.sql` for the columns used; the schema has more.

## The schema, as these queries assume it

The tables of DESIGN.md "What is recorded", with the columns these queries use:

```sql
hosts    (host_id, name, last_scan timestamptz, expected_every interval)   -- expected_every NULL: never stale
-- files also carry dev and ino: rows with the same host, dev and ino are hard links, one physical copy
roots    (root_id, host_id, label text UNIQUE, path, kind text)             -- kind: primary | drop | backup
contents (content_id, sha256 bytea UNIQUE, size bigint, mime text)
files    (file_id, root_id, relpath text, name text,                        -- name: last part of relpath
          content_id, size bigint, mtime, ctime, btime timestamptz,
          owner_id, first_seen, last_seen timestamptz, gone_on date,       -- gone_on NULL while present
          backup_of bigint, snapshot date,                                  -- backup copies: source file, snapshot date
          is_symlink boolean, link_target text,                            -- a symlink: its target as written, and
          link_root text, link_relpath text, link_dangling boolean)        -- where it leads in its agent's roots
history  (history_id, file_id, kind text,                                   -- new | changed | moved | moved_changed | gone
          old_relpath, new_relpath, old_content_id, new_content_id,
          seen_after date, seen_on date, evidence text, confidence text)   -- the window: last scan before, scan that saw it
lineage  (from_file_id, to_file_id, kind text,                              -- copied_from | replaced_by | derived_from
          evidence text, confidence text, decision text)                   -- decision: NULL | confirmed | rejected
metadata (content_id, file_id, schema text, vals jsonb, source text)        -- one of content_id, file_id is set

CREATE VIEW present AS SELECT * FROM files WHERE gone_on IS NULL;
```

`files` keeps a row for every file ever seen, so history and lineage still resolve after a file is gone; `present`
is what exists now. Root labels are unique across the site, so a root's label names its host too. Examples use the
placeholder roots of `config.example.toml`.

## find NAME-OR-GLOB

```sql
-- pinakes find '*budget*'
SELECT h.name AS host, r.label AS root, f.relpath, f.size, f.mtime::date AS modified
FROM present f
JOIN roots r USING (root_id)
JOIN hosts h USING (host_id)
WHERE f.name ILIKE '%budget%'            -- a trigram index on name serves this
ORDER BY f.name, h.name;
```

## where PATH|SHA256

```sql
-- pinakes where downloads:report.pdf
SELECT h.name AS host, r.label AS root, r.kind, f.relpath, f.snapshot, f.last_seen::date AS seen
FROM present f
JOIN roots r USING (root_id)
JOIN hosts h USING (host_id)
WHERE f.content_id = (SELECT f0.content_id
                      FROM present f0 JOIN roots r0 USING (root_id)
                      WHERE r0.label = 'downloads' AND f0.relpath = 'report.pdf')
ORDER BY r.kind, h.name, f.relpath;

-- pinakes where <sha256>: the same, with
--   WHERE f.content_id = (SELECT content_id FROM contents WHERE sha256 = decode('<sha256>', 'hex'))
```

## only-here HOST:PATH

Files with no copy on another disk. A copy is on another disk when it is on another host, or on another device of
the same host (a device the catalog doesn't know counts as the same disk). Copies are counted physically, as
distinct (host, device, inode), and a hard link of the file itself is not a copy. `same_disk` counts the copies
outside the folder on the file's own disk, which die with it; 0 means no copy anywhere else.

```sql
-- pinakes only-here downloads:camera/
SELECT f.relpath, f.size, s.same_disk
FROM present f
JOIN roots r USING (root_id)
CROSS JOIN LATERAL (
      SELECT count(DISTINCT (ro.host_id, o.dev, o.ino))
                 FILTER (WHERE NOT coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS same_disk,
             count(DISTINCT (ro.host_id, o.dev, o.ino))
                 FILTER (WHERE coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS other_disk
      FROM present o JOIN roots ro ON ro.root_id = o.root_id
      WHERE o.content_id = f.content_id
        AND NOT (o.root_id = f.root_id AND o.relpath LIKE 'camera/%')   -- copies inside the folder don't count
        AND NOT coalesce(ro.host_id = r.host_id AND o.dev = f.dev AND o.ino = f.ino, false)) s  -- nor hard links
WHERE r.label = 'downloads' AND f.relpath LIKE 'camera/%' AND s.other_disk = 0
  AND NOT f.is_symlink                                                  -- a symlink holds no data
ORDER BY f.relpath;
```

## safe-to-delete HOST:PATH

Lists the files that are **not** safe: no copy in a primary or backup root outside the folder on another disk, with
`same_disk` as above (kept copies on the same disk, which don't make a file safe). No rows means safe.

```sql
-- pinakes safe-to-delete downloads:old-phone/
SELECT f.relpath, f.size, s.same_disk
FROM present f
JOIN roots r USING (root_id)
CROSS JOIN LATERAL (
      SELECT count(DISTINCT (ro.host_id, o.dev, o.ino))
                 FILTER (WHERE NOT coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS same_disk,
             count(DISTINCT (ro.host_id, o.dev, o.ino))
                 FILTER (WHERE coalesce(ro.host_id <> r.host_id OR o.dev <> f.dev, false)) AS other_disk
      FROM present o JOIN roots ro ON ro.root_id = o.root_id
      WHERE o.content_id = f.content_id
        AND ro.kind IN ('primary', 'backup')
        AND NOT (o.root_id = f.root_id AND o.relpath LIKE 'old-phone/%')
        AND NOT coalesce(ro.host_id = r.host_id AND o.dev = f.dev AND o.ino = f.ino, false)) s
WHERE r.label = 'downloads' AND f.relpath LIKE 'old-phone/%' AND s.other_disk = 0
  AND NOT f.is_symlink
ORDER BY f.relpath;
```

A symlink in the folder holds no data, so it is never what makes a folder unsafe. Links elsewhere that point into
the folder would be left dangling; the CLI and the web UI list them beside the answer:

```sql
-- symlinks outside downloads:old-phone/ that lead into it (or to it)
SELECT r.label, f.relpath, f.link_target, f.link_relpath
FROM present f
JOIN roots r USING (root_id)
WHERE f.is_symlink AND f.link_root = 'downloads'
  AND (f.link_relpath LIKE 'old-phone/%' OR f.link_relpath = 'old-phone')
  AND NOT (r.label = 'downloads' AND f.relpath LIKE 'old-phone/%')
ORDER BY r.label, f.relpath;
```

## backed-up HOST:PATH

Backup copies are counted physically: distinct (host, device, inode). Snapshot backups made with hard links hold one
copy of an unchanged file however many snapshots list it, so a file in 22 such snapshots has one backup copy, not 22.

```sql
-- pinakes backed-up store:people/user-1/
SELECT f.relpath,
       count(DISTINCT (br.host_id, b.dev, b.ino)) FILTER (WHERE b.file_id IS NOT NULL) AS backup_copies,
       count(b.file_id) AS snapshots,                -- snapshots holding the current version
       max(b.snapshot)  AS newest_snapshot
FROM present f
JOIN roots r USING (root_id)
LEFT JOIN present b ON b.backup_of = f.file_id AND b.content_id = f.content_id
LEFT JOIN roots br ON br.root_id = b.root_id
WHERE r.label = 'store' AND f.relpath LIKE 'people/user-1/%'
GROUP BY f.file_id, f.relpath
ORDER BY backup_copies, f.relpath;                 -- unprotected files first
```

## dupes [HOST:PATH]

Hard links share their storage, so they are paths, not copies, and reclaim nothing: copies are distinct (host,
device, inode). Empty files all have the same hash and take no space: they are not duplicates.

```sql
-- pinakes dupes
SELECT encode(c.sha256, 'hex') AS sha256, c.size,
       count(DISTINCT (r.host_id, f.dev, f.ino))                AS copies,
       count(*)                                                 AS paths,
       c.size * (count(DISTINCT (r.host_id, f.dev, f.ino)) - 1) AS reclaimable,
       array_agg(r.label || ':' || f.relpath ORDER BY r.label, f.relpath) AS where_
FROM present f
JOIN contents c USING (content_id)
JOIN roots r USING (root_id)
WHERE r.kind <> 'backup'                           -- backups are meant to be copies
  AND c.size > 0                                   -- every empty file has the same hash
GROUP BY c.content_id
HAVING count(DISTINCT (r.host_id, f.dev, f.ino)) > 1
ORDER BY reclaimable DESC
LIMIT 50;
```

## history HOST:PATH

```sql
-- pinakes history store:people/user-1/notes.odt
SELECT hi.seen_after, hi.seen_on, hi.kind, hi.old_relpath, hi.new_relpath,
       encode(oc.sha256, 'hex') AS old_sha256, encode(nc.sha256, 'hex') AS new_sha256,
       hi.evidence, hi.confidence
FROM files f
JOIN roots r USING (root_id)
JOIN history hi USING (file_id)
LEFT JOIN contents oc ON oc.content_id = hi.old_content_id
LEFT JOIN contents nc ON nc.content_id = hi.new_content_id
WHERE r.label = 'store' AND f.relpath = 'people/user-1/notes.odt'
ORDER BY hi.seen_on, hi.history_id;
```

## changes --since DATE [--host]

```sql
-- pinakes changes --since 7d --host server-1
SELECT hi.seen_on, r.label AS root, coalesce(hi.new_relpath, hi.old_relpath) AS path, hi.kind
FROM history hi
JOIN files f USING (file_id)
JOIN roots r USING (root_id)
JOIN hosts h USING (host_id)
WHERE hi.seen_on >= current_date - 7
  AND h.name = 'server-1'
ORDER BY hi.seen_on, path;
```

## changes by folder (web UI)

For a clean-up: per folder, what happened under it in the last N days, from a chosen folder down a few levels.
A tracked move counts as moved in at its destination and moved out at its source, never as new and gone; a move
within a folder counts there as both. Moves are matched within a root only. The changes page filters by kind (What)
and by folder too; `queries.change_tree` and `queries.changes(kinds=, loc=)`.

```sql
-- each history row gives one or two (path, role): new, changed, gone, or a move's in (new path) and out (old path);
-- each role counts at every folder above its path
SELECT folder, count(*) FILTER (WHERE role = 'in') AS moved_in, count(*) FILTER (WHERE role = 'out') AS moved_out
FROM (SELECT x.role, (string_to_array(x.path, '/'))[1:i] AS folder
      FROM history hi
      CROSS JOIN LATERAL (VALUES (hi.new_relpath, 'in'), (hi.old_relpath, 'out')) x (path, role),
           generate_series(0, array_length(string_to_array(x.path, '/'), 1) - 1) i
      WHERE hi.kind IN ('moved', 'moved_changed') AND hi.seen_on >= current_date - 7) t
GROUP BY folder ORDER BY folder;
```

## versions HOST:PATH

Each version the catalog has seen at that file, and which backup copies hold it: the "which backup do I restore
from" question.

```sql
-- pinakes versions store:people/user-1/notes.odt
WITH target AS (
    SELECT f.file_id FROM files f JOIN roots r USING (root_id)
    WHERE r.label = 'store' AND f.relpath = 'people/user-1/notes.odt'
), versions AS (
    SELECT hi.new_content_id AS content_id, min(hi.seen_on) AS first_seen_on, max(hi.seen_on) AS last_change_on
    FROM history hi JOIN target USING (file_id)
    WHERE hi.new_content_id IS NOT NULL
    GROUP BY hi.new_content_id
)
SELECT encode(c.sha256, 'hex') AS sha256, v.first_seen_on,
       r.label AS backup_root, b.snapshot, b.relpath AS backup_path
FROM versions v
JOIN contents c USING (content_id)
LEFT JOIN (present b JOIN roots r ON r.root_id = b.root_id AND r.kind = 'backup')
       ON b.content_id = v.content_id
ORDER BY v.first_seen_on, b.snapshot;
```

## lineage HOST:PATH

Ancestors, following edges backwards; descendants are the same query with the join reversed. Lineage links files,
and a file keeps its id through its versions, so a copy taken out and brought back makes a cycle: the walk carries
the files it has visited (`seen`) and never revisits one.

```sql
-- pinakes lineage store:people/user-1/notes.odt
WITH RECURSIVE up (file_id, depth, how, confidence, decision, seen) AS (
    SELECT f.file_id, 0, NULL::text, NULL::text, NULL::text, ARRAY[f.file_id]
    FROM files f JOIN roots r USING (root_id)
    WHERE r.label = 'store' AND f.relpath = 'people/user-1/notes.odt'
  UNION ALL
    SELECT l.from_file_id, up.depth + 1, l.kind, l.confidence, l.decision, up.seen || l.from_file_id
    FROM lineage l JOIN up ON l.to_file_id = up.file_id
    WHERE l.decision IS DISTINCT FROM 'rejected'
      AND NOT l.from_file_id = ANY (up.seen)        -- no file twice: copies out and back form cycles
)
SELECT up.depth, h.name AS host, r.label AS root, f.relpath, up.how, up.confidence, up.decision, f.gone_on
FROM up
JOIN files f USING (file_id)
JOIN roots r USING (root_id)
JOIN hosts h USING (host_id)
WHERE up.depth > 0
ORDER BY up.depth, h.name;
```

## meta SCHEMA.FIELD=VALUE

```sql
-- pinakes meta exif.model='Camera-1'
SELECT r.label AS root, f.relpath, m.vals ->> 'date_taken' AS taken
FROM metadata m
JOIN present f ON f.content_id = m.content_id
JOIN roots r USING (root_id)
WHERE m.schema = 'exif'
  AND m.vals ->> 'model' = 'Camera-1'               -- an expression index per indexed field serves this
ORDER BY taken;
```

## stale

```sql
-- pinakes stale
SELECT name, last_scan::date AS last_scan, expected_every
FROM hosts
WHERE expected_every IS NOT NULL
  AND (last_scan IS NULL OR last_scan < now() - expected_every)
ORDER BY last_scan NULLS FIRST;
```
