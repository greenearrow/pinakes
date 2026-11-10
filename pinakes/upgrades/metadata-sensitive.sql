-- Upgrade a catalog built before sensitive metadata was kept (ROADMAP 16, its first part), after
-- metadata-extracted.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f metadata-sensitive.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

ALTER TABLE metadata
    ADD COLUMN sensitive boolean NOT NULL DEFAULT false;  -- the schema's sensitive fields, apart: owners only

-- Whether the current person may see sensitive metadata (GPS, people shown, places: METADATA.md) on a content or
-- a file: as the owner or a co-owner of a file with that content (or of that file), or as an administrator in a
-- step-up. Readers and annotators of a shared folder see a file's other metadata, not these.
CREATE FUNCTION sensitive_visible(content bigint, file bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT stepped_up() OR EXISTS (
        SELECT 1 FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
        WHERE (f.content_id = content OR f.file_id = file)
          AND am.person_id = current_person() AND am.role IN ('owner', 'co-owner'))
$$;
REVOKE ALL ON FUNCTION sensitive_visible(bigint, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sensitive_visible(bigint, bigint) TO pinakes_app, pinakes_ingest;

DROP POLICY metadata_visible ON metadata;
CREATE POLICY metadata_visible ON metadata FOR SELECT USING (
    ((file_id IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.file_id = metadata.file_id))
     OR (content_id IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.content_id = metadata.content_id)))
    AND (NOT sensitive OR sensitive_visible(content_id, file_id)));
