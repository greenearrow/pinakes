-- Upgrade a catalog built before roots a host stopped reporting were noticed (ROADMAP 46; release 6), after
-- owner-by-uid.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f unreported-roots.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

ALTER TABLE roots ADD COLUMN unreported_since timestamptz;
ALTER TABLE roots ADD COLUMN retired_on date;
