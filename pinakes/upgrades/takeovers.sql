-- Upgrade a catalog built before release 5 (sequence resets, takeovers), after checkins.sql. Run once as the schema's
-- owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f takeovers.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree. A column already there is
-- left as it is (IF NOT EXISTS).

SET search_path = pinakes;

-- when a scan's first batch was applied (unknown, NULL, for scans before this upgrade): a complete full scan retires
-- its root's files last seen before then; and when the agent started it: a new agent state numbers its scans from 1
-- again, and this tells them apart
ALTER TABLE scans ADD COLUMN IF NOT EXISTS began_at timestamptz;
ALTER TABLE scans ALTER COLUMN began_at SET DEFAULT now();
ALTER TABLE scans ADD COLUMN IF NOT EXISTS started_at timestamptz;

-- each batch's header digest: the same batch sent again is a duplicate; another batch of a number already applied
-- is a sequence that went back (a new or restored agent state), refused
ALTER TABLE ingested ADD COLUMN IF NOT EXISTS header_sha256 bytea;

-- the last time a host's agent numbering went back, and what was done
ALTER TABLE checkins ADD COLUMN IF NOT EXISTS seq_reset_at timestamptz;
ALTER TABLE checkins ADD COLUMN IF NOT EXISTS seq_reset text;
