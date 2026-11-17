-- Upgrade a catalog whose files policy calls visible_acls() bare (ROADMAP 48; release 6), after scrub.sql. Run once
-- as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f files-policy.sql
-- A new catalog gets the same from schema.sql; tests/test_api.py checks the two agree.

SET search_path = pinakes;

-- The same rule, with visible_acls() wrapped in (SELECT ...) as token_roots() already was, so it is evaluated once
-- per query: bare, a large catalog's plan can call it per row.
ALTER POLICY files_visible ON files USING (acl_id = ANY ((SELECT visible_acls())::int[])
    AND ((SELECT token_roots()) IS NULL OR root_id = ANY ((SELECT token_roots())::int[])));
