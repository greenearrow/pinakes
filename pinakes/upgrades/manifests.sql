-- Upgrade a catalog built before checksum manifests (ROADMAP 19, DESIGN.md "Checksum manifests"; release 7), after
-- unreported-roots.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f manifests.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- what a SHA256SUMS listing a file says of the agent's hash, the manifest that said it and when; on a manifest, its
-- lines' counts. Under the files policy, as every column of a file is
ALTER TABLE files ADD COLUMN manifest_verdict text CHECK (manifest_verdict IN ('confirmed', 'wrong')),
                  ADD COLUMN manifest_file_id bigint REFERENCES files ON DELETE SET NULL,
                  ADD COLUMN manifest_on date,
                  ADD COLUMN manifest_counts jsonb;
CREATE INDEX files_manifest ON files (manifest_file_id) WHERE manifest_file_id IS NOT NULL;
CREATE OR REPLACE VIEW present WITH (security_invoker = true) AS SELECT * FROM files WHERE gone_on IS NULL;
