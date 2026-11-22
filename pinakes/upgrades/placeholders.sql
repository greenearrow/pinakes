-- Upgrade a catalog built before placeholders (ROADMAP 69); release 14. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f placeholders.sql
-- then `pinakes-ingest tidy`, which applies the site's [[placeholders.rule]] to every content.
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- Placeholders (ROADMAP 69): contents that are an app's default bytes (the same minimal sidecar beside every photo,
-- an object a game writes with nothing stored in it), so the files holding them aren't copies of one another. A
-- person's mark (marked_by, through mark_placeholder()) or a site rule's ([[placeholders.rule]] in server.toml,
-- written by the ingester: rule). A placeholder gets no lineage edge by its hash, and the ones made before are left
-- out of every answer while it is one (kept, so that an unmark brings them back); its other holders are no copy for
-- only-here, safe-to-delete, folding or duplicates, though a backup of the file itself still is.
CREATE TABLE placeholders (
    content_id  bigint PRIMARY KEY REFERENCES contents ON DELETE CASCADE,
    rule        text,                                       -- the site rule that matched; NULL: a person's mark
    marked_by   int REFERENCES people,
    marked_at   timestamptz NOT NULL DEFAULT now()
);

-- Mark a file's content a placeholder (ROADMAP 69), or with what false unmark it. A mark changes what every holder of
-- those bytes is told (its copies and its lineage), so only a person who owns or co-owns every present file holding
-- them may, or an administrator in a step-up, which is audited for those files' owners and co-owners. The file
-- must be visible and present. Under a token, only with its review scope, and only when every holder is in its
-- roots; never under a group token. A content a site rule matched is the rule's: neither marked nor unmarked here.
-- Returns 1 if the mark changed, else 0.
CREATE FUNCTION mark_placeholder(f bigint, what boolean) RETURNS int
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    up boolean := stepped_up();
    tr int[] := token_roots();
    c bigint;
    all_mine boolean;
    outside boolean;
    holders int;
    theirs int[];
    n int;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_group() IS NOT NULL THEN RAISE EXCEPTION 'a group token doesn''t mark placeholders'; END IF;
    IF current_token() IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM tokens t WHERE t.token_id = current_token() AND 'review' = ANY (t.scopes)) THEN
        RAISE EXCEPTION 'this token doesn''t have the review scope';
    END IF;
    IF what IS NULL THEN RAISE EXCEPTION 'a placeholder is marked (true) or unmarked (false)'; END IF;
    SELECT x.content_id INTO c FROM files x
    WHERE x.file_id = f AND x.gone_on IS NULL AND x.content_id IS NOT NULL AND x.size > 0
      AND x.acl_id = ANY (visible_acls()) AND (tr IS NULL OR x.root_id = ANY (tr));
    IF c IS NULL THEN RETURN 0; END IF;
    SELECT bool_and(EXISTS (SELECT 1 FROM acl_members am WHERE am.acl_id = h.acl_id AND am.person_id = me
                                                           AND am.role IN ('owner', 'co-owner'))),
           bool_or(tr IS NOT NULL AND NOT h.root_id = ANY (tr)), count(*)
    INTO all_mine, outside, holders FROM files h WHERE h.content_id = c AND h.gone_on IS NULL;
    IF outside OR NOT (all_mine OR up) THEN RETURN 0; END IF;
    IF what THEN
        INSERT INTO placeholders (content_id, marked_by) VALUES (c, me) ON CONFLICT (content_id) DO NOTHING;
    ELSE
        DELETE FROM placeholders p WHERE p.content_id = c AND p.rule IS NULL;
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n > 0 AND NOT all_mine THEN
        SELECT array_agg(DISTINCT am.person_id ORDER BY am.person_id) INTO theirs
        FROM files h JOIN acl_members am ON am.acl_id = h.acl_id AND am.role IN ('owner', 'co-owner')
        WHERE h.content_id = c AND h.gone_on IS NULL AND am.person_id <> me;
        IF theirs IS NOT NULL THEN
            INSERT INTO audit (actor, action, affects, detail)
            VALUES (me, 'placeholder', theirs, jsonb_build_object('placeholder', what, 'files', holders));
        END IF;
    END IF;
    RETURN n;
END $$;

ALTER TABLE placeholders ENABLE ROW LEVEL SECURITY;    -- seen by whoever sees a file holding the content
CREATE POLICY placeholders_visible ON placeholders FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.content_id = placeholders.content_id));

REVOKE ALL ON placeholders FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_placeholder(bigint, boolean) FROM PUBLIC;
GRANT SELECT ON placeholders TO pinakes_app;              -- written only through mark_placeholder() (ROADMAP 69)
GRANT EXECUTE ON FUNCTION mark_placeholder(bigint, boolean) TO pinakes_app, pinakes_ingest;
GRANT SELECT, INSERT, UPDATE, DELETE ON placeholders TO pinakes_ingest;
