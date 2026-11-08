-- Upgrade a catalog built before ROADMAP 32 (reviewing changes). Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f review-marks.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- A review of a change (ROADMAP 32): a gone file or a move, marked intended, or to restore. Written only through
-- mark_changes(); a later change is a new history row, unreviewed.
CREATE TABLE review_marks (
    history_id  bigint PRIMARY KEY REFERENCES history ON DELETE CASCADE,
    mark        text NOT NULL CHECK (mark IN ('intended', 'restore')),
    marked_by   int NOT NULL REFERENCES people,
    marked_at   timestamptz NOT NULL DEFAULT now()
);

-- Mark changes reviewed: 'intended', 'restore', or NULL to clear. Only gone files and moves, only by the file's
-- owner or a co-owner, or by an administrator in a step-up, which is audited for the owners. Changes the person
-- may not mark are skipped; returns how many were marked or cleared.
CREATE FUNCTION mark_changes(ids bigint[], what text) RETURNS int
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    up boolean := stepped_up();
    ok bigint[];
    theirs int[];
    others int;
    n int;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF what IS NOT NULL AND what NOT IN ('intended', 'restore') THEN
        RAISE EXCEPTION 'a mark is intended or restore';
    END IF;
    WITH t AS (
        SELECT hi.history_id, f.acl_id,
               EXISTS (SELECT 1 FROM acl_members am WHERE am.acl_id = f.acl_id AND am.person_id = me
                                                      AND am.role IN ('owner', 'co-owner')) AS mine
        FROM history hi JOIN files f USING (file_id)
        WHERE hi.history_id = ANY (ids) AND hi.kind IN ('gone', 'moved', 'moved_changed'))
    SELECT array_agg(history_id) FILTER (WHERE mine OR up), array_agg(DISTINCT acl_id) FILTER (WHERE NOT mine AND up),
           count(*) FILTER (WHERE NOT mine AND up)
    INTO ok, theirs, others FROM t;
    IF what IS NULL THEN
        DELETE FROM review_marks WHERE history_id = ANY (ok);
    ELSE
        INSERT INTO review_marks (history_id, mark, marked_by) SELECT unnest(ok), what, me
        ON CONFLICT (history_id) DO UPDATE SET mark = EXCLUDED.mark, marked_by = EXCLUDED.marked_by, marked_at = now();
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF others > 0 THEN
        INSERT INTO audit (actor, action, affects, detail)
        SELECT me, 'review', coalesce(array_agg(DISTINCT am.person_id), '{}'),
               jsonb_build_object('mark', coalesce(what, 'cleared'), 'changes', others)
        FROM acl_members am WHERE am.acl_id = ANY (theirs) AND am.person_id <> me AND am.role IN ('owner', 'co-owner');
    END IF;
    RETURN n;
END $$;

ALTER TABLE review_marks ENABLE ROW LEVEL SECURITY;
CREATE POLICY review_marks_visible ON review_marks FOR SELECT USING (
    EXISTS (SELECT 1 FROM history h WHERE h.history_id = review_marks.history_id));

REVOKE ALL ON review_marks FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_changes(bigint[], text) FROM PUBLIC;
GRANT SELECT ON review_marks TO pinakes_app;
GRANT EXECUTE ON FUNCTION mark_changes(bigint[], text) TO pinakes_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON review_marks TO pinakes_ingest;
GRANT EXECUTE ON FUNCTION mark_changes(bigint[], text) TO pinakes_ingest;
