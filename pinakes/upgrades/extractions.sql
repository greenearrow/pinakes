-- Upgrade a catalog built before extraction outcomes (ROADMAP 44, METADATA.md "Extraction"; release 7), after
-- manifests.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f extractions.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- What each extractor made of a content (ROADMAP 44), as the latest agent of protocol 4 to read it said: values
-- found, nothing found, refused (a reason code: extract.REFUSALS) or skipped there (extract.SKIPS); never an error's
-- text. As the metadata, the content's, true of every copy. Found values that are all sensitive fields are kept as a
-- second row, sensitive, with the first saying nothing: whoever may not see them reads "nothing", as they would of
-- a content without any (extraction_outcomes picks the row each person sees).
CREATE TABLE extractions (
    content_id  bigint NOT NULL REFERENCES contents ON DELETE CASCADE,
    schema      text NOT NULL,
    sensitive   boolean NOT NULL DEFAULT false,
    outcome     text NOT NULL CHECK (outcome IN ('found', 'nothing', 'refused', 'skipped')),
    reason      text,
    version     int NOT NULL,                            -- the schema's version the agent ran (or would have)
    sent_by     int REFERENCES hosts ON DELETE SET NULL,
    at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (content_id, schema, sensitive),
    CHECK (CASE outcome
           WHEN 'refused' THEN reason IN ('truncated', 'wrong_type', 'malformed', 'bad_values', 'unreadable', 'failed')
           WHEN 'skipped' THEN reason IN ('dependency', 'broken')
           ELSE reason IS NULL END),
    CHECK (NOT sensitive OR outcome = 'found')
);

-- Each content's outcome per schema as the current person sees it: the sensitive row where they may see it, else the
-- other (row-level security on extractions decides which they see).
CREATE VIEW extraction_outcomes WITH (security_invoker = true) AS
    SELECT DISTINCT ON (content_id, schema) content_id, schema, outcome, reason, version, at
    FROM extractions ORDER BY content_id, schema, sensitive DESC;

ALTER TABLE extractions ENABLE ROW LEVEL SECURITY;
CREATE POLICY extractions_visible ON extractions FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.content_id = extractions.content_id)
    AND (NOT sensitive OR sensitive_visible(content_id, NULL)));

GRANT SELECT ON extractions, extraction_outcomes TO pinakes_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON extractions, extraction_outcomes TO pinakes_ingest;   -- as schema.sql's
