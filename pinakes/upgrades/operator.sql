-- Upgrade a catalog built before the operator page (ROADMAP 10) and what a disk's loss would cost (ROADMAP 42);
-- release 8. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f operator.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- What a disk's loss would cost (ROADMAP 42): every present file but a symlink with no readable copy on another
-- host, and whether it has none on another device of its own host either (disk_only: lost with its disk, not only
-- with its machine). Copies are counted as only-here counts them (queries._COPIES): a hard link is no copy, a file
-- the scrub couldn't read is none until it reads again, a copy in any root counts, and a device the catalog doesn't
-- know (dev NULL) is never another disk. Row-level security applies to the caller: a person counts only the copies
-- they can see, so their answer errs toward "at risk", never away from it.
CREATE FUNCTION at_risk()
RETURNS TABLE (file_id bigint, root_id int, host_id int, dev bigint, ino bigint, size bigint, relpath text,
               owner_id int, disk_only boolean)
LANGUAGE sql STABLE SET search_path = pinakes AS $$
    WITH c AS (
        SELECT f.content_id, min(r.host_id) AS min_host, max(r.host_id) AS max_host,
               min(f.dev) AS min_dev, max(f.dev) AS max_dev
        FROM present f JOIN roots r ON r.root_id = f.root_id
        WHERE f.content_id IS NOT NULL AND f.unreadable_on IS NULL AND NOT f.is_symlink
        GROUP BY f.content_id)
    SELECT f.file_id, f.root_id, r.host_id, f.dev, f.ino, f.size, f.relpath, f.owner_id,
           (f.dev IS NULL OR c.min_dev IS NULL OR (c.min_dev = f.dev AND c.max_dev = f.dev)) AS disk_only
    FROM present f JOIN roots r ON r.root_id = f.root_id LEFT JOIN c ON c.content_id = f.content_id
    WHERE NOT f.is_symlink AND (c.min_host IS NULL OR (c.min_host = r.host_id AND c.max_host = r.host_id))
$$;

-- The operator's functions refuse anyone but an operator signed in on the web: never a token, not even an ops one.
CREATE FUNCTION require_operator() RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
BEGIN
    IF current_token() IS NOT NULL OR NOT has_role('operator') THEN
        RAISE EXCEPTION 'only an operator, signed in on the web, sees every root''s totals';
    END IF;
END $$;

-- The operator page (ROADMAP 10): per root, every person's present files and their bytes (an inode once: hard links
-- take their space once), its last complete scan, the oldest check of its scrub, whether its host stopped reporting
-- it or it was retired, and how many scan errors it has and the newest. Counts, sizes and dates: never a path, a
-- file's name, a person or metadata (SECURITY.md "People and roles").
CREATE FUNCTION operator_roots()
RETURNS TABLE (host text, root text, kind text, protected boolean, files bigint, bytes numeric,
               last_complete_on date, scrub_oldest date, unreported_since timestamptz, retired_on date,
               errors bigint, newest_error date)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
#variable_conflict use_column
BEGIN
    PERFORM require_operator();
    RETURN QUERY
    SELECT h.name, r.label, r.kind, r.protected, coalesce(n.files, 0)::bigint, coalesce(n.bytes, 0)::numeric,
           r.last_complete_on, CASE WHEN r.scrub_never > 0 THEN r.scrub_since ELSE r.scrub_oldest END,
           r.unreported_since, r.retired_on, coalesce(e.errors, 0)::bigint, e.newest
    FROM roots r JOIN hosts h ON h.host_id = r.host_id
    LEFT JOIN (SELECT i.root_id, sum(i.links) AS files, sum(i.size) AS bytes
               FROM (SELECT f.root_id, count(*) AS links, max(f.size) AS size FROM files f WHERE f.gone_on IS NULL
                     GROUP BY f.root_id, f.dev, coalesce(f.ino, -f.file_id)) i
               GROUP BY i.root_id) n ON n.root_id = r.root_id
    LEFT JOIN (SELECT s.root_id, count(*) AS errors, max(s.seen_on) AS newest FROM scan_errors s
               GROUP BY s.root_id) e ON e.root_id = r.root_id
    ORDER BY h.name, r.label;
END $$;

-- What a disk's loss would cost, for the operator page (ROADMAP 42): every person's files that at_risk() finds, as
-- totals. scope 'disk': per device of a host (dev NULL: files whose device the catalog doesn't know), the files
-- lost with that disk; scope 'host': per host, the files lost with the machine. The roots are those the files are
-- in. Files and bytes count an inode once. Never a path, a folder, a person or a file's name.
CREATE FUNCTION operator_at_risk()
RETURNS TABLE (scope text, host text, dev bigint, roots text[], files bigint, bytes numeric)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
#variable_conflict use_column
BEGIN
    PERFORM require_operator();
    RETURN QUERY
    WITH i AS (SELECT a.host_id, a.dev, min(a.root_id) AS root_id, max(a.size) AS size, bool_or(a.disk_only) AS d
               FROM at_risk() a GROUP BY a.host_id, a.dev, coalesce(a.ino, -a.file_id))
    SELECT x.scope, h.name, x.dev, x.roots, x.files, x.bytes
    FROM (SELECT 'disk'::text AS scope, i.host_id, i.dev, array_agg(DISTINCT r.label ORDER BY r.label) AS roots,
                 count(*) AS files, coalesce(sum(i.size), 0)::numeric AS bytes
          FROM i JOIN roots r ON r.root_id = i.root_id WHERE i.d GROUP BY i.host_id, i.dev
          UNION ALL
          SELECT 'host', i.host_id, NULL, array_agg(DISTINCT r.label ORDER BY r.label), count(*),
                 coalesce(sum(i.size), 0)::numeric
          FROM i JOIN roots r ON r.root_id = i.root_id GROUP BY i.host_id) x
    JOIN hosts h ON h.host_id = x.host_id
    ORDER BY x.scope, x.bytes DESC, h.name, x.dev NULLS LAST;
END $$;

REVOKE ALL ON FUNCTION at_risk(), require_operator(), operator_roots(), operator_at_risk() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION at_risk(), operator_roots(), operator_at_risk() TO pinakes_app;
GRANT EXECUTE ON FUNCTION at_risk(), require_operator(), operator_roots(), operator_at_risk() TO pinakes_ingest;
