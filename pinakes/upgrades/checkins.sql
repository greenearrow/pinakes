-- Upgrade a catalog built before check-in (release 11), after hidden-files.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f checkins.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- each agent's last check-in (pinakes-ingest hello) and the protocol of its last batch: which release and protocol
-- it runs, and whether it holds its batches for want of a compatible server (pinakes --versions)
CREATE TABLE checkins (
    host_id     int PRIMARY KEY REFERENCES hosts ON DELETE CASCADE,
    at          timestamptz,                                -- the last hello; NULL: none (an agent before check-in)
    release     int,
    protocol    int,
    min_server_protocol int,
    locked      text,                                       -- NULL: compatible; else which side must update, and why
    batch_at    timestamptz,                                -- the last batch applied, and what its header declared
    batch_release int,
    batch_protocol int,                                     -- 0: none declared (an agent before check-in)
    refused_at  timestamptz,                                -- the last batch refused for its protocol, and why
    refused     text
);

GRANT SELECT ON checkins TO pinakes_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON checkins TO pinakes_ingest;
