-- Upgrade a catalog built before the scrub (ROADMAP 41, DESIGN.md "Scrub"), after api-tokens.sql. Run once as the
-- schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f scrub.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- the agent's last scrub batch per root: counts and dates only
ALTER TABLE roots ADD COLUMN scrub_on date, ADD COLUMN scrub_since date, ADD COLUMN scrub_days int,
                  ADD COLUMN scrub_oldest date, ADD COLUMN scrub_never bigint;

-- a file the scrub couldn't read: not a copy until it reads again
ALTER TABLE files ADD COLUMN unreadable_on date, ADD COLUMN unreadable_error text;
CREATE OR REPLACE VIEW present WITH (security_invoker = true) AS SELECT * FROM files WHERE gone_on IS NULL;

-- two kinds of change the scrub finds, reviewed like gone files and moves
ALTER TABLE history DROP CONSTRAINT history_kind_check;
ALTER TABLE history ADD CONSTRAINT history_kind_check CHECK (kind IN ('new', 'changed', 'moved', 'moved_changed',
                                                                      'gone', 'mismatch', 'unreadable'));

-- Mark changes reviewed: 'intended', 'restore', or NULL to clear. Only gone files, moves, and what the scrub found
-- (a mismatch or an unreadable file), only by the file's
-- owner or a co-owner, or by an administrator in a step-up, which is audited for the owners; under a token (ROADMAP
-- 37), only with its `review` scope and only in the roots it may see. Under a group token (ROADMAP 38), only where
-- the group is the owner or a co-owner: the mark is the group's, audited for its members with the token. Changes
-- the person may not mark are skipped; returns how many were marked or cleared.
CREATE OR REPLACE FUNCTION mark_changes(ids bigint[], what text) RETURNS int
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    grp int := current_group();
    up boolean := stepped_up();
    ok bigint[];
    theirs int[];
    others int;
    n int;
BEGIN
    IF me IS NULL AND grp IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM tokens t WHERE t.token_id = current_token() AND 'review' = ANY (t.scopes)) THEN
        RAISE EXCEPTION 'this token doesn''t have the review scope';
    END IF;
    IF what IS NOT NULL AND what NOT IN ('intended', 'restore') THEN
        RAISE EXCEPTION 'a mark is intended or restore';
    END IF;
    WITH t AS (
        SELECT hi.history_id, f.acl_id,
               CASE WHEN grp IS NOT NULL
                    THEN EXISTS (SELECT 1 FROM acl_groups ag WHERE ag.acl_id = f.acl_id AND ag.group_id = grp
                                                              AND ag.role IN ('owner', 'co-owner'))
                    ELSE EXISTS (SELECT 1 FROM acl_members am WHERE am.acl_id = f.acl_id AND am.person_id = me
                                                               AND am.role IN ('owner', 'co-owner')) END AS mine
        FROM history hi JOIN files f USING (file_id)
        WHERE hi.history_id = ANY (ids) AND hi.kind IN ('gone', 'moved', 'moved_changed', 'mismatch', 'unreadable')
          AND (token_roots() IS NULL OR f.root_id = ANY (token_roots())))
    SELECT array_agg(history_id) FILTER (WHERE mine OR up), array_agg(DISTINCT acl_id) FILTER (WHERE NOT mine AND up),
           count(*) FILTER (WHERE NOT mine AND up)
    INTO ok, theirs, others FROM t;
    IF what IS NULL THEN
        DELETE FROM review_marks WHERE history_id = ANY (ok);
    ELSE
        INSERT INTO review_marks (history_id, mark, marked_by, marked_by_group) SELECT unnest(ok), what, me, grp
        ON CONFLICT (history_id) DO UPDATE SET mark = EXCLUDED.mark, marked_by = EXCLUDED.marked_by,
                                               marked_by_group = EXCLUDED.marked_by_group, marked_at = now();
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF others > 0 THEN
        INSERT INTO audit (actor, action, affects, detail)
        SELECT me, 'review', coalesce(array_agg(DISTINCT am.person_id), '{}'),
               jsonb_build_object('mark', coalesce(what, 'cleared'), 'changes', others)
        FROM acl_members am WHERE am.acl_id = ANY (theirs) AND am.person_id <> me AND am.role IN ('owner', 'co-owner');
    END IF;
    IF grp IS NOT NULL AND n > 0 THEN
        INSERT INTO audit (actor, action, affects, detail)
        SELECT t.person_id, 'review',
               (SELECT coalesce(array_agg(m.person_id ORDER BY m.person_id), '{}') FROM group_members m
                WHERE m.group_id = grp),
               jsonb_build_object('mark', coalesce(what, 'cleared'), 'changes', n, 'token', t.client,
                                  'group', (SELECT g.name FROM groups g WHERE g.group_id = grp))
        FROM tokens t WHERE t.token_id = current_token();
    END IF;
    RETURN n;
END $$;
