-- Upgrade a catalog built before ROADMAP 7 (symlinks tied to their targets), after protected-links.sql. Run once as
-- the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f symlink-targets.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- Where a symlink leads, when that is in a root of its agent, and whether its target is there. The agents' next
-- scans fill these in: a symlink's record differs from what they kept, so it is sent again.
ALTER TABLE files ADD COLUMN link_root text, ADD COLUMN link_relpath text, ADD COLUMN link_dangling boolean;
CREATE OR REPLACE VIEW present WITH (security_invoker = true) AS SELECT * FROM files WHERE gone_on IS NULL;
CREATE INDEX files_link ON files (link_root, link_relpath text_pattern_ops) WHERE is_symlink;
