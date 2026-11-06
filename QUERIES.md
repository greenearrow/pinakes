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
roots    (root_id, host_id, label text UNIQUE, path, kind text)             -- kind: primary | drop | backup
contents (content_id, sha256 bytea UNIQUE, size bigint, mime text)
files    (file_id, root_id, relpath text, name text,                        -- name: last part of relpath
          content_id, size bigint, mtime, ctime, btime timestamptz,
          owner_id, first_seen, last_seen timestamptz, gone_on date,       -- gone_on NULL while present
          backup_of bigint, snapshot date)                                  -- backup copies: source file, snapshot date
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

```sql
-- pinakes only-here downloads:camera/
SELECT f.relpath, f.size
FROM present f
JOIN roots r USING (root_id)
WHERE r.label = 'downloads' AND f.relpath LIKE 'camera/%'
  AND NOT EXISTS (
        SELECT 1 FROM present o
        WHERE o.content_id = f.content_id
          AND NOT (o.root_id = f.root_id AND o.relpath LIKE 'camera/%'))   -- copies inside the folder don't count
ORDER BY f.relpath;
```

## safe-to-delete HOST:PATH

Lists the files that are **not** safe: no copy in a primary or backup root outside the folder. No rows means safe.

```sql
-- pinakes safe-to-delete downloads:old-phone/
SELECT f.relpath, f.size
FROM present f
JOIN roots r USING (root_id)
WHERE r.label = 'downloads' AND f.relpath LIKE 'old-phone/%'
  AND NOT EXISTS (
        SELECT 1 FROM present o
        JOIN roots ro ON ro.root_id = o.root_id
        WHERE o.content_id = f.content_id
          AND ro.kind IN ('primary', 'backup')
          AND NOT (o.root_id = f.root_id AND o.relpath LIKE 'old-phone/%'))
ORDER BY f.relpath;
```

## backed-up HOST:PATH

```sql
-- pinakes backed-up store:people/user-1/
SELECT f.relpath,
       count(b.file_id) AS backup_copies,          -- copies of the current version
       max(b.snapshot)  AS newest_snapshot
FROM present f
JOIN roots r USING (root_id)
LEFT JOIN present b ON b.backup_of = f.file_id AND b.content_id = f.content_id
WHERE r.label = 'store' AND f.relpath LIKE 'people/user-1/%'
GROUP BY f.file_id, f.relpath
ORDER BY backup_copies, f.relpath;                 -- unprotected files first
```

## dupes [HOST:PATH]

```sql
-- pinakes dupes
SELECT encode(c.sha256, 'hex') AS sha256, c.size,
       count(*)                AS copies,
       c.size * (count(*) - 1) AS reclaimable,
       array_agg(r.label || ':' || f.relpath ORDER BY r.label, f.relpath) AS paths
FROM present f
JOIN contents c USING (content_id)
JOIN roots r USING (root_id)
WHERE r.kind <> 'backup'                           -- backups are meant to be copies
GROUP BY c.content_id
HAVING count(*) > 1
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

Ancestors, following edges backwards; descendants are the same query with the join reversed.

```sql
-- pinakes lineage store:people/user-1/notes.odt
WITH RECURSIVE up (file_id, depth, kind, confidence, decision) AS (
    SELECT f.file_id, 0, NULL::text, NULL::text, NULL::text
    FROM files f JOIN roots r USING (root_id)
    WHERE r.label = 'store' AND f.relpath = 'people/user-1/notes.odt'
  UNION
    SELECT l.from_file_id, up.depth + 1, l.kind, l.confidence, l.decision
    FROM lineage l JOIN up ON l.to_file_id = up.file_id
    WHERE l.decision IS DISTINCT FROM 'rejected'
      AND up.depth < 50                             -- a bound, in case of a cycle
)
SELECT up.depth, h.name AS host, r.label AS root, f.relpath, up.kind, up.confidence, up.decision,
       f.gone_on
FROM up
JOIN files f USING (file_id)
JOIN roots r USING (root_id)
JOIN hosts h USING (host_id)
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
