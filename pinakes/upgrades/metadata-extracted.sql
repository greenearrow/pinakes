-- Upgrade a catalog built before ROADMAP 13 (extracted metadata). Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f metadata-extracted.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

ALTER TABLE metadata
    ADD COLUMN version int,                                     -- the schema's version it was extracted by
    ADD COLUMN sent_by int REFERENCES hosts ON DELETE SET NULL; -- the agent that sent it (not host_id: queries
                                                                -- join hosts USING (host_id))
