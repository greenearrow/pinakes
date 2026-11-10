-- Upgrade a catalog built before hidden files, after symlink-targets.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f hidden-files.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- A file is hidden by a dot at the start of its name or of a folder's above it, or by the hidden attribute that
-- Samba keeps for Windows clients (user.DOSATTRIB), which the agent reads.
ALTER TABLE files ADD COLUMN hidden boolean NOT NULL DEFAULT false;
CREATE OR REPLACE VIEW present WITH (security_invoker = true) AS SELECT * FROM files WHERE gone_on IS NULL;

-- What the catalog already knows: the dot-names. The agents' next scans send the attribute, as their records now
-- differ from what they last sent for hidden files.
UPDATE files SET hidden = true WHERE relpath ~ '(^|/)\.';
