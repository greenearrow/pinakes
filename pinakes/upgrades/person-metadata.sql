-- Upgrade a catalog built before person-entered metadata and shared sensitive fields (ROADMAP 16); release 10,
-- after api-tokens.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f person-metadata.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- A file's sensitive fields shared by its owner or a co-owner with one of its readers or annotators (ROADMAP 16):
-- they see the file's sensitive metadata, and its content's, as the owners do. Written only through
-- share_sensitive(); read only through sensitive_sharing(). A share counts only while its person still reads the file.
CREATE TABLE sensitive_shares (
    file_id     bigint REFERENCES files ON DELETE CASCADE,
    person_id   int REFERENCES people ON DELETE CASCADE,
    shared_by   int REFERENCES people,
    shared_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, person_id)
);
CREATE INDEX sensitive_shares_person ON sensitive_shares (person_id);
ALTER TABLE sensitive_shares ENABLE ROW LEVEL SECURITY;   -- no policy: the application reads it through functions

-- Whether the current person may see sensitive metadata (GPS, people shown, places: METADATA.md) on a content or
-- a file: as the owner or a co-owner of a file with that content (or of that file), as a reader or annotator whom
-- such a file's owner shared its sensitive fields with (sensitive_shares, ROADMAP 16), or as an administrator in a
-- step-up; under a group token, where the group is the owner or a co-owner (ROADMAP 38). Other readers and
-- annotators of a shared folder see a file's other metadata, not these.
CREATE OR REPLACE FUNCTION sensitive_visible(content bigint, file bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT stepped_up() OR EXISTS (
        SELECT 1 FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
        WHERE (f.content_id = content OR f.file_id = file)
          AND am.person_id = current_person() AND am.role IN ('owner', 'co-owner'))
    OR EXISTS (
        SELECT 1 FROM files f JOIN acl_groups ag ON ag.acl_id = f.acl_id
        WHERE (f.content_id = content OR f.file_id = file)
          AND ag.group_id = current_group() AND ag.role IN ('owner', 'co-owner'))
    OR EXISTS (
        SELECT 1 FROM sensitive_shares s JOIN files f ON f.file_id = s.file_id
        JOIN acl_members am ON am.acl_id = f.acl_id AND am.person_id = s.person_id
        WHERE (f.content_id = content OR f.file_id = file) AND s.person_id = current_person())
$$;

-- The current person's role on a file (owner, co-owner, reader, annotator), or NULL: none, a group token, or a file
-- outside the token's roots. A step-up gives no role.
CREATE FUNCTION my_file_role(fid bigint) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT am.role FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
    WHERE f.file_id = fid AND am.person_id = current_person() AND current_group() IS NULL
      AND (token_roots() IS NULL OR f.root_id = ANY (token_roots()))
$$;

-- Enter metadata on a file (ROADMAP 16): the current person's values of one schema replace what they entered on it
-- before, the schema's sensitive fields (`hidden`) in a row of their own as extracted ones are; empty objects remove
-- them. The values are the file's own, so they follow it through moves, and belong to their author: nobody else
-- changes them. Only the owner, a co-owner or an annotator enters, on the web (never under a token: `pinakes tag`
-- is ROADMAP 37), and a step-up gives no right to. The application checks the values against the registry
-- (extract.check_vals); this checks who, the schema's name and the size. Entering on another person's file is
-- audited for its owners and co-owners.
CREATE FUNCTION set_file_metadata(fid bigint, sch text, plain jsonb, hidden jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    mine text := my_file_role(fid);
    affected int[];
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'metadata is entered on the web, not with a token'; END IF;
    IF mine IS NULL OR mine NOT IN ('owner', 'co-owner', 'annotator') THEN
        RAISE EXCEPTION 'only the owner, a co-owner or an annotator of a file enters its metadata';
    END IF;
    IF sch IS NULL OR sch !~ '^[a-z][a-z0-9]{0,19}$' THEN RAISE EXCEPTION 'not a schema''s name'; END IF;
    IF jsonb_typeof(plain) IS DISTINCT FROM 'object' OR jsonb_typeof(hidden) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'values are an object';
    END IF;
    IF octet_length(plain::text) + octet_length(hidden::text) > 32768 THEN
        RAISE EXCEPTION 'values over 32768 bytes';
    END IF;
    DELETE FROM metadata m WHERE m.file_id = fid AND m.schema = sch AND m.source = 'person' AND m.author = me;
    INSERT INTO metadata (file_id, schema, vals, source, author, sensitive)
    SELECT fid, sch, x.v, 'person', me, x.s FROM (VALUES (plain, false), (hidden, true)) x (v, s) WHERE x.v <> '{}';
    SELECT array_agg(DISTINCT am.person_id ORDER BY am.person_id) INTO affected
    FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
    WHERE f.file_id = fid AND am.person_id <> me AND am.role IN ('owner', 'co-owner');
    IF affected IS NOT NULL THEN
        INSERT INTO audit (actor, action, affects, detail)
        VALUES (me, 'metadata', affected, jsonb_build_object('file', fid, 'schema', sch));
    END IF;
END $$;

-- Who a file's sensitive fields may be shared with, for its owner or a co-owner only (else no rows): its readers and
-- annotators, and whether they have them now.
CREATE FUNCTION sensitive_sharing(fid bigint)
RETURNS TABLE (person_id int, display text, role text, shared boolean, shared_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT am.person_id, p.display, am.role, s.file_id IS NOT NULL, s.shared_at
    FROM files f JOIN acl_members am ON am.acl_id = f.acl_id JOIN people p ON p.person_id = am.person_id
    LEFT JOIN sensitive_shares s ON s.file_id = f.file_id AND s.person_id = am.person_id
    WHERE f.file_id = fid AND am.role IN ('reader', 'annotator') AND my_file_role(fid) IN ('owner', 'co-owner')
    ORDER BY p.display, am.person_id
$$;

-- Share a file's sensitive fields with one of its readers or annotators, or stop (ROADMAP 16): by its owner or a
-- co-owner, on the web; never an administrator for someone else, never under a token. It shares only what that
-- person already sees the file for: never the file. Audited for the file's other owners and co-owners and for the
-- person. Returns whether anything changed.
CREATE FUNCTION share_sensitive(fid bigint, who int, give boolean) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    mine text := my_file_role(fid);
    n int;
    affected int[];
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'sensitive fields are shared on the web, not with a token'; END IF;
    IF mine IS NULL OR mine NOT IN ('owner', 'co-owner') THEN
        RAISE EXCEPTION 'only the owner or a co-owner of a file shares its sensitive fields';
    END IF;
    IF give IS NULL THEN RAISE EXCEPTION 'share or stop sharing'; END IF;
    IF give THEN
        IF NOT EXISTS (SELECT 1 FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
                       WHERE f.file_id = fid AND am.person_id = who AND am.role IN ('reader', 'annotator')) THEN
            RAISE EXCEPTION 'sensitive fields are shared only with a reader or annotator of the file';
        END IF;
        INSERT INTO sensitive_shares (file_id, person_id, shared_by) VALUES (fid, who, me) ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM sensitive_shares s WHERE s.file_id = fid AND s.person_id = who;
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n > 0 THEN
        SELECT array_agg(DISTINCT x ORDER BY x) INTO affected FROM (
            SELECT am.person_id AS x FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
            WHERE f.file_id = fid AND am.person_id <> me AND am.role IN ('owner', 'co-owner')
            UNION SELECT who) y;
        INSERT INTO audit (actor, action, affects, detail)
        VALUES (me, 'sensitive_share', affected,
                jsonb_build_object('file', fid, 'person', (SELECT display FROM people WHERE person_id = who),
                                   'shared', give));
    END IF;
    RETURN n > 0;
END $$;

DROP POLICY metadata_visible ON metadata;
CREATE POLICY metadata_visible ON metadata FOR SELECT USING (
    ((file_id IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.file_id = metadata.file_id))
     OR (content_id IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.content_id = metadata.content_id)))
    AND (NOT sensitive OR author = current_person() OR sensitive_visible(content_id, file_id)));

REVOKE ALL ON FUNCTION my_file_role(bigint), set_file_metadata(bigint, text, jsonb, jsonb), sensitive_sharing(bigint),
                       share_sensitive(bigint, int, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION my_file_role(bigint), set_file_metadata(bigint, text, jsonb, jsonb), sensitive_sharing(bigint),
                          share_sensitive(bigint, int, boolean) TO pinakes_app, pinakes_ingest;
GRANT SELECT, INSERT, UPDATE, DELETE ON sensitive_shares TO pinakes_ingest;
