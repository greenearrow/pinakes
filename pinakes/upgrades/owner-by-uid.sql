-- Upgrade a catalog built before owner rules by uid (ROADMAP 2; release 6), after files-policy.sql. Run once as the
-- schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f owner-by-uid.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- a rule that gives a folder's files to whoever their uid maps to on the root's host
ALTER TABLE owner_rules ADD COLUMN by_uid boolean NOT NULL DEFAULT false;
ALTER TABLE owner_rules DROP CONSTRAINT owner_rules_check;
ALTER TABLE owner_rules ADD CONSTRAINT owner_rules_check CHECK (CASE WHEN by_uid THEN owner_person IS NULL
    AND owner_group IS NULL ELSE (owner_person IS NULL) <> (owner_group IS NULL) END);
