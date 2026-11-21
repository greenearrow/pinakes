-- Upgrade a catalog built before the history of its own writes (ROADMAP 62); release 10, after lineage-decisions.sql
-- and person-metadata.sql. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f edits.sql
-- A new catalog gets the same from schema.sql; tests/test_api.py checks the two agree. Writes made before it have
-- no history: only those after it are listed and undone.

SET search_path = pinakes;

-- The catalog's own writes (ROADMAP 62): every review mark, lineage decision and person-entered metadata written,
-- with who wrote it, by which token or on the web, when, and each value before and after. One edit is one write
-- call (the functions' writes of one kind in one transaction); its items are the values it changed, nothing for a
-- value written again unchanged. Written only by mark_changes(), decide_lineage(), set_file_metadata() and
-- undo_edits(), and never changed after: an undo is an edit of its own, naming the one it undoes. An edit is its
-- person's, or under a group token its group's (an undo of a group's edit is the group's too, by the member who
-- undid it). The items keep no foreign key to what they name, so that nothing removes them; an item of a file no
-- longer seen is simply not shown.
CREATE TABLE edits (
    edit_id     bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    xact        bigint NOT NULL DEFAULT txid_current(),     -- the transaction: one edit per call and kind
    person_id   int REFERENCES people,                      -- who; NULL: a group token
    group_id    int REFERENCES groups,                      -- a group token's group, or the group whose edit it undoes
    token_id    int,                                        -- the token it was made by; NULL: on the web
    client      text,                                       -- that token's name then
    action      text NOT NULL CHECK (action IN ('review', 'lineage', 'metadata')),
    undoes      bigint REFERENCES edits,
    CHECK (person_id IS NOT NULL OR group_id IS NOT NULL),
    CHECK ((token_id IS NULL) = (client IS NULL))
);
CREATE INDEX edits_xact ON edits (xact);
CREATE INDEX edits_person ON edits (person_id, edit_id);
CREATE INDEX edits_group ON edits (group_id, edit_id) WHERE group_id IS NOT NULL;
CREATE INDEX edits_undoes ON edits (undoes) WHERE undoes IS NOT NULL;
-- What an edit changed: a review mark (history_id), a lineage edge (other_file_id to file_id, of kind) or one
-- person's values of a schema on a file (schema; the edit's person is their author). file_id is the file whose
-- rights decide (a change's file, an edge's later file, the file entered on). before and after: the value, as
-- review_value(), lineage_value() and metadata_value() give it; NULL is none.
CREATE TABLE edit_items (
    item_id     bigserial PRIMARY KEY,
    edit_id     bigint NOT NULL REFERENCES edits,
    file_id     bigint NOT NULL,
    other_file_id bigint,
    history_id  bigint,
    kind        text,
    schema      text,
    before      jsonb,
    after       jsonb,
    CHECK (num_nonnulls(history_id, kind, schema) = 1),
    CHECK ((kind IS NULL) = (other_file_id IS NULL))
);
CREATE INDEX edit_items_edit ON edit_items (edit_id);
CREATE INDEX edit_items_history ON edit_items (history_id) WHERE history_id IS NOT NULL;
CREATE INDEX edit_items_edge ON edit_items (file_id, other_file_id, kind) WHERE kind IS NOT NULL;
CREATE INDEX edit_items_metadata ON edit_items (file_id, schema) WHERE schema IS NOT NULL;

-- The catalog's own writes (ROADMAP 62), as an edit keeps them: a change's review mark, an edge's decision, and one
-- person's values of a schema on a file (plain and sensitive apart); NULL is none (and, for an edge, no edge too).
-- same_value() compares two without the time they were written.
CREATE FUNCTION review_value(hid bigint) RETURNS jsonb LANGUAGE sql STABLE SET search_path = pinakes AS $$
    SELECT jsonb_build_object('mark', m.mark, 'marked_by', m.marked_by, 'marked_by_group', m.marked_by_group,
                              'marked_at', m.marked_at)
    FROM review_marks m WHERE m.history_id = hid
$$;

CREATE FUNCTION lineage_value(f bigint, t bigint, k text) RETURNS jsonb LANGUAGE sql STABLE SET search_path = pinakes
AS $$
    SELECT jsonb_build_object('decision', l.decision, 'decided_by', l.decided_by, 'decided_at', l.decided_at)
    FROM lineage l WHERE l.from_file_id = f AND l.to_file_id = t AND l.kind = k AND l.decision IS NOT NULL
$$;

CREATE FUNCTION metadata_value(fid bigint, sch text, who int) RETURNS jsonb LANGUAGE sql STABLE
SET search_path = pinakes AS $$
    SELECT CASE WHEN count(*) > 0 THEN jsonb_build_object(
               'plain', coalesce((array_agg(m.vals ORDER BY m.metadata_id DESC) FILTER (WHERE NOT m.sensitive))[1], '{}'),
               'hidden', coalesce((array_agg(m.vals ORDER BY m.metadata_id DESC) FILTER (WHERE m.sensitive))[1], '{}'))
           END
    FROM metadata m WHERE m.file_id = fid AND m.schema = sch AND m.source = 'person' AND m.author = who
$$;

CREATE FUNCTION same_value(a jsonb, b jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pinakes AS $$
    SELECT (a - 'marked_at' - 'decided_at') IS NOT DISTINCT FROM (b - 'marked_at' - 'decided_at')
$$;

-- The edit a write belongs to: this transaction's of its kind by the same person, group and token, made with its
-- first value changed.
CREATE FUNCTION edit_now(what text) RETURNS bigint LANGUAGE plpgsql VOLATILE SET search_path = pinakes AS $$
DECLARE
    id bigint;
BEGIN
    SELECT e.edit_id INTO id FROM edits e
    WHERE e.xact = txid_current() AND e.action = what AND e.undoes IS NULL
      AND e.person_id IS NOT DISTINCT FROM current_person() AND e.group_id IS NOT DISTINCT FROM current_group()
      AND e.token_id IS NOT DISTINCT FROM current_token();
    IF id IS NULL THEN
        INSERT INTO edits (person_id, group_id, token_id, client, action)
        VALUES (current_person(), current_group(), current_token(),
                (SELECT t.client FROM tokens t WHERE t.token_id = current_token()), what)
        RETURNING edit_id INTO id;
    END IF;
    RETURN id;
END $$;

-- Whether an edit (by its person and group) is the current person's to see and undo: their own, made on the web or
-- by any of their tokens, outside a group token; a group's, under that group's token or for a member of it.
CREATE FUNCTION my_edit(p int, grp int) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT coalesce(CASE WHEN grp IS NULL THEN p = current_person() AND current_group() IS NULL
                         ELSE grp = current_group() OR EXISTS (SELECT 1 FROM group_members m
                                                               WHERE m.group_id = grp
                                                                 AND m.person_id = current_person()) END, false)
$$;

-- Mark changes reviewed: 'intended', 'restore', or NULL to clear. Only gone files, moves, and what the scrub found
-- (a mismatch or an unreadable file), only by the file's
-- owner or a co-owner, or by an administrator in a step-up, which is audited for the owners; under a token (ROADMAP
-- 37), only with its `review` scope and only in the roots it may see. Under a group token (ROADMAP 38), only where
-- the group is the owner or a co-owner: the mark is the group's, audited for its members with the token. Changes
-- the person may not mark are skipped; returns how many were marked or cleared. Each mark changed is kept, with
-- the one before, as one edit (ROADMAP 62).
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
    olds jsonb[];
    cx bigint[];
    cb jsonb[];
    ca jsonb[];
    eid bigint;
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
    olds := ARRAY(SELECT review_value(u.x) FROM unnest(ok) WITH ORDINALITY u (x, i) ORDER BY u.i);
    IF what IS NULL THEN
        DELETE FROM review_marks WHERE history_id = ANY (ok);
    ELSE
        INSERT INTO review_marks (history_id, mark, marked_by, marked_by_group) SELECT unnest(ok), what, me, grp
        ON CONFLICT (history_id) DO UPDATE SET mark = EXCLUDED.mark, marked_by = EXCLUDED.marked_by,
                                               marked_by_group = EXCLUDED.marked_by_group, marked_at = now();
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    SELECT array_agg(c.x), array_agg(c.v), array_agg(c.nv) INTO cx, cb, ca
    FROM (SELECT u.x, u.v, review_value(u.x) AS nv FROM unnest(ok, olds) u (x, v)) c WHERE NOT same_value(c.v, c.nv);
    IF cx IS NOT NULL THEN
        eid := edit_now('review');
        INSERT INTO edit_items (edit_id, file_id, history_id, before, after)
        SELECT eid, hi.file_id, u.x, u.v, u.nv FROM unnest(cx, cb, ca) u (x, v, nv) JOIN history hi ON hi.history_id = u.x;
    END IF;
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

-- Decide whether two files are relatives (ROADMAP 9): 'confirmed', 'rejected', or NULL to clear the decision. It
-- applies to every edge between the two, either way round, except one of the same content (certain: the hash
-- decides). A decision outranks every heuristic: a confirmed edge survives tidy, and the ingester never suggests a
-- rejected pair again. Only the owner or a co-owner of an edge's descendant (its to_file) decides it, and only when
-- both ends are visible to them; an administrator in a step-up decides others'. Under a token, only with its review
-- scope and in its roots; never under a group token. A decision that touches another person's file (either end) is
-- audited for its owners and co-owners. Returns how many edges were decided or cleared. Each decision changed is
-- kept, with the one before, as one edit (ROADMAP 62).
CREATE OR REPLACE FUNCTION decide_lineage(a bigint, b bigint, what text) RETURNS int
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    up boolean := stepped_up();
    seen int[] := visible_acls();
    tr int[] := token_roots();
    n int;
    acls int[];
    affected int[];
    cf bigint[];
    ct bigint[];
    ck text[];
    cb jsonb[];
    ca jsonb[];
    eid bigint;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_group() IS NOT NULL THEN RAISE EXCEPTION 'a group token doesn''t decide lineage'; END IF;
    IF current_token() IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM tokens t WHERE t.token_id = current_token() AND 'review' = ANY (t.scopes)) THEN
        RAISE EXCEPTION 'this token doesn''t have the review scope';
    END IF;
    IF what IS NOT NULL AND what NOT IN ('confirmed', 'rejected') THEN
        RAISE EXCEPTION 'a decision is confirmed or rejected';
    END IF;
    WITH e AS (
        SELECT l.from_file_id, l.to_file_id, l.kind, ff.acl_id AS from_acl, ft.acl_id AS to_acl,
               lineage_value(l.from_file_id, l.to_file_id, l.kind) AS was
        FROM lineage l JOIN files ff ON ff.file_id = l.from_file_id JOIN files ft ON ft.file_id = l.to_file_id
        WHERE ((l.from_file_id = a AND l.to_file_id = b) OR (l.from_file_id = b AND l.to_file_id = a))
          AND l.confidence <> 'certain'
          AND ff.acl_id = ANY (seen) AND ft.acl_id = ANY (seen)
          AND (tr IS NULL OR (ff.root_id = ANY (tr) AND ft.root_id = ANY (tr)))
          AND (up OR EXISTS (SELECT 1 FROM acl_members am WHERE am.acl_id = ft.acl_id AND am.person_id = me
                                                         AND am.role IN ('owner', 'co-owner')))),
    d AS (
        UPDATE lineage l SET decision = what, decided_by = CASE WHEN what IS NULL THEN NULL ELSE me END,
                             decided_at = CASE WHEN what IS NULL THEN NULL ELSE now() END
        FROM e WHERE l.from_file_id = e.from_file_id AND l.to_file_id = e.to_file_id AND l.kind = e.kind
        RETURNING e.from_acl, e.to_acl, l.from_file_id, l.to_file_id, l.kind, e.was,
                  CASE WHEN l.decision IS NOT NULL      -- as lineage_value(), of the edge as updated
                       THEN jsonb_build_object('decision', l.decision, 'decided_by', l.decided_by,
                                               'decided_at', l.decided_at) END AS became)
    SELECT count(*), array_agg(d.from_acl) || array_agg(d.to_acl),
           array_agg(d.from_file_id) FILTER (WHERE NOT same_value(d.was, d.became)),
           array_agg(d.to_file_id) FILTER (WHERE NOT same_value(d.was, d.became)),
           array_agg(d.kind) FILTER (WHERE NOT same_value(d.was, d.became)),
           array_agg(d.was) FILTER (WHERE NOT same_value(d.was, d.became)),
           array_agg(d.became) FILTER (WHERE NOT same_value(d.was, d.became))
    INTO n, acls, cf, ct, ck, cb, ca FROM d;
    IF cf IS NOT NULL THEN
        eid := edit_now('lineage');
        INSERT INTO edit_items (edit_id, file_id, other_file_id, kind, before, after)
        SELECT eid, u.t, u.f, u.k, u.was, u.became FROM unnest(cf, ct, ck, cb, ca) u (f, t, k, was, became);
    END IF;
    SELECT array_agg(DISTINCT am.person_id ORDER BY am.person_id) INTO affected
    FROM acl_members am WHERE am.acl_id = ANY (acls) AND am.person_id <> me AND am.role IN ('owner', 'co-owner');
    IF n > 0 AND affected IS NOT NULL THEN
        INSERT INTO audit (actor, action, affects, detail)
        VALUES (me, 'lineage', affected, jsonb_build_object('decision', coalesce(what, 'cleared'), 'edges', n));
    END IF;
    RETURN n;
END $$;

-- Enter metadata on a file (ROADMAP 16): the current person's values of one schema replace what they entered on it
-- before, the schema's sensitive fields (`hidden`) in a row of their own as extracted ones are; empty objects remove
-- them. The values are the file's own, so they follow it through moves, and belong to their author: nobody else
-- changes them. Only the owner, a co-owner or an annotator enters: on the web, or under a person's token with its
-- `tag` scope and in its roots (`pinakes tag`, ROADMAP 37), never a group token; a step-up gives no right to.
-- The application checks the values against the registry (extract.check_vals); this checks who, the schema's name
-- and the size. Entering on another person's file is audited for its owners and co-owners. A change is kept, with
-- the values before, as an edit (ROADMAP 62).
CREATE OR REPLACE FUNCTION set_file_metadata(fid bigint, sch text, plain jsonb, hidden jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    mine text := my_file_role(fid);
    affected int[];
    was jsonb;
    now_is jsonb;
BEGIN
    IF current_group() IS NOT NULL THEN RAISE EXCEPTION 'a group token doesn''t enter metadata'; END IF;
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM tokens t WHERE t.token_id = current_token() AND 'tag' = ANY (t.scopes)) THEN
        RAISE EXCEPTION 'this token doesn''t have the tag scope';
    END IF;
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
    was := metadata_value(fid, sch, me);
    DELETE FROM metadata m WHERE m.file_id = fid AND m.schema = sch AND m.source = 'person' AND m.author = me;
    INSERT INTO metadata (file_id, schema, vals, source, author, sensitive)
    SELECT fid, sch, x.v, 'person', me, x.s FROM (VALUES (plain, false), (hidden, true)) x (v, s) WHERE x.v <> '{}';
    now_is := metadata_value(fid, sch, me);
    IF was IS DISTINCT FROM now_is THEN
        INSERT INTO edit_items (edit_id, file_id, schema, before, after)
        VALUES (edit_now('metadata'), fid, sch, was, now_is);
    END IF;
    SELECT array_agg(DISTINCT am.person_id ORDER BY am.person_id) INTO affected
    FROM files f JOIN acl_members am ON am.acl_id = f.acl_id
    WHERE f.file_id = fid AND am.person_id <> me AND am.role IN ('owner', 'co-owner');
    IF affected IS NOT NULL THEN
        INSERT INTO audit (actor, action, affects, detail)
        VALUES (me, 'metadata', affected, jsonb_build_object('file', fid, 'schema', sch));
    END IF;
END $$;

-- Undo edits (ROADMAP 62): put back each value an edit changed as it was before, newest edit first, each edit whole
-- or not at all. Only the person's own edits (or their group's, as my_edit() has it), and only what they may write
-- now, by the same rules as the write itself: a review mark where they own or co-own the change's file (or the
-- group does, under its token) or in a step-up; a lineage decision as decide_lineage() allows; their own values of
-- a schema where they own, co-own or annotate the file; under a token, with the scope of its kind (review, or tag
-- for metadata) and in its roots. An edit is refused if a value it wrote has changed since: `later` names the
-- newest later edit of that value, if any. The undo is an edit of its own, which can be undone in turn, and is
-- audited for the other owners and co-owners its decisions and values touch (a mark's: where the person marked as
-- no owner, in a step-up), and for the group's members. One row per edit asked: the undo's edit and how many values
-- it put back, or why not (not_yours: no edit of theirs; no_scope: not the token's; changed; gone: the edge is no
-- longer in the catalog; not_now: they may no longer write it) and the file.
CREATE FUNCTION undo_edits(ids bigint[])
RETURNS TABLE (edit bigint, undone_by bigint, changes int, refused text, refused_file bigint, later bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    grp int := current_group();
    up boolean := stepped_up();
    seen int[] := visible_acls();
    tr int[] := token_roots();
    x bigint;
    ed edits;
    it edit_items;
    cur jsonb;
    why text;
    bad bigint;
    newer bigint;
    eid bigint;
    n int;
    affected int[];
BEGIN
    IF me IS NULL AND grp IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    FOR x IN SELECT DISTINCT u.id FROM unnest(ids) u (id) WHERE u.id IS NOT NULL ORDER BY u.id DESC LOOP
        why := NULL; bad := NULL; newer := NULL;
        SELECT * INTO ed FROM edits e WHERE e.edit_id = x AND my_edit(e.person_id, e.group_id);
        IF NOT FOUND THEN
            why := 'not_yours';
        ELSIF current_token() IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM tokens t WHERE t.token_id = current_token()
                AND CASE WHEN ed.action = 'metadata' THEN 'tag' ELSE 'review' END = ANY (t.scopes)) THEN
            why := 'no_scope';
        ELSIF grp IS NOT NULL AND ed.action <> 'review' THEN
            why := 'not_now';
        END IF;
        IF why IS NULL THEN
            FOR it IN SELECT * FROM edit_items i WHERE i.edit_id = x ORDER BY i.item_id LOOP
                IF it.history_id IS NOT NULL THEN                       -- as mark_changes()
                    IF NOT EXISTS (
                            SELECT 1 FROM history hi JOIN files f ON f.file_id = hi.file_id
                            WHERE hi.history_id = it.history_id
                              AND hi.kind IN ('gone', 'moved', 'moved_changed', 'mismatch', 'unreadable')
                              AND (tr IS NULL OR f.root_id = ANY (tr))
                              AND (up OR CASE WHEN grp IS NOT NULL
                                   THEN EXISTS (SELECT 1 FROM acl_groups ag WHERE ag.acl_id = f.acl_id
                                                AND ag.group_id = grp AND ag.role IN ('owner', 'co-owner'))
                                   ELSE EXISTS (SELECT 1 FROM acl_members am WHERE am.acl_id = f.acl_id
                                                AND am.person_id = me AND am.role IN ('owner', 'co-owner')) END)) THEN
                        why := 'not_now';
                    ELSIF NOT same_value(review_value(it.history_id), it.after) THEN
                        why := 'changed';
                        SELECT max(i.edit_id) INTO newer FROM edit_items i
                        WHERE i.history_id = it.history_id AND i.edit_id > x;
                    END IF;
                ELSIF it.kind IS NOT NULL THEN                          -- as decide_lineage()
                    IF NOT EXISTS (SELECT 1 FROM lineage l WHERE l.from_file_id = it.other_file_id
                                   AND l.to_file_id = it.file_id AND l.kind = it.kind) THEN
                        why := 'gone';
                    ELSIF NOT EXISTS (
                            SELECT 1 FROM lineage l JOIN files ff ON ff.file_id = l.from_file_id
                            JOIN files ft ON ft.file_id = l.to_file_id
                            WHERE l.from_file_id = it.other_file_id AND l.to_file_id = it.file_id AND l.kind = it.kind
                              AND l.confidence <> 'certain' AND ff.acl_id = ANY (seen) AND ft.acl_id = ANY (seen)
                              AND (tr IS NULL OR (ff.root_id = ANY (tr) AND ft.root_id = ANY (tr)))
                              AND (up OR EXISTS (SELECT 1 FROM acl_members am WHERE am.acl_id = ft.acl_id
                                                 AND am.person_id = me AND am.role IN ('owner', 'co-owner')))) THEN
                        why := 'not_now';
                    ELSIF NOT same_value(lineage_value(it.other_file_id, it.file_id, it.kind), it.after) THEN
                        why := 'changed';
                        SELECT max(i.edit_id) INTO newer FROM edit_items i
                        WHERE i.file_id = it.file_id AND i.other_file_id = it.other_file_id AND i.kind = it.kind
                          AND i.edit_id > x;
                    END IF;
                ELSE                                                    -- as set_file_metadata()
                    IF me IS DISTINCT FROM ed.person_id
                       OR coalesce(my_file_role(it.file_id), '') NOT IN ('owner', 'co-owner', 'annotator') THEN
                        why := 'not_now';
                    ELSIF NOT same_value(metadata_value(it.file_id, it.schema, me), it.after) THEN
                        why := 'changed';
                        SELECT max(i.edit_id) INTO newer FROM edit_items i JOIN edits e ON e.edit_id = i.edit_id
                        WHERE i.file_id = it.file_id AND i.schema = it.schema AND e.person_id = me
                          AND i.edit_id > x;
                    END IF;
                END IF;
                IF why IS NOT NULL THEN
                    bad := it.file_id;
                    EXIT;
                END IF;
            END LOOP;
        END IF;
        IF why IS NOT NULL THEN
            RETURN QUERY SELECT x, NULL::bigint, 0, why, bad, newer;
            CONTINUE;
        END IF;
        INSERT INTO edits (person_id, group_id, token_id, client, action, undoes)
        VALUES (me, coalesce(grp, ed.group_id), current_token(),
                (SELECT t.client FROM tokens t WHERE t.token_id = current_token()), ed.action, x)
        RETURNING edits.edit_id INTO eid;
        n := 0;
        FOR it IN SELECT * FROM edit_items i WHERE i.edit_id = x ORDER BY i.item_id LOOP
            IF it.history_id IS NOT NULL THEN
                cur := review_value(it.history_id);
                IF it.before IS NULL THEN
                    DELETE FROM review_marks m WHERE m.history_id = it.history_id;
                ELSE
                    INSERT INTO review_marks (history_id, mark, marked_by, marked_by_group, marked_at)
                    VALUES (it.history_id, it.before ->> 'mark', (it.before ->> 'marked_by')::int,
                            (it.before ->> 'marked_by_group')::int, (it.before ->> 'marked_at')::timestamptz)
                    ON CONFLICT (history_id) DO UPDATE SET mark = EXCLUDED.mark, marked_by = EXCLUDED.marked_by,
                        marked_by_group = EXCLUDED.marked_by_group, marked_at = EXCLUDED.marked_at;
                END IF;
                INSERT INTO edit_items (edit_id, file_id, history_id, before, after)
                VALUES (eid, it.file_id, it.history_id, cur, review_value(it.history_id));
            ELSIF it.kind IS NOT NULL THEN
                cur := lineage_value(it.other_file_id, it.file_id, it.kind);
                UPDATE lineage l SET decision = it.before ->> 'decision', decided_by = (it.before ->> 'decided_by')::int,
                                     decided_at = (it.before ->> 'decided_at')::timestamptz
                WHERE l.from_file_id = it.other_file_id AND l.to_file_id = it.file_id AND l.kind = it.kind;
                INSERT INTO edit_items (edit_id, file_id, other_file_id, kind, before, after)
                VALUES (eid, it.file_id, it.other_file_id, it.kind, cur,
                        lineage_value(it.other_file_id, it.file_id, it.kind));
            ELSE
                cur := metadata_value(it.file_id, it.schema, me);
                DELETE FROM metadata m WHERE m.file_id = it.file_id AND m.schema = it.schema AND m.source = 'person'
                                         AND m.author = me;
                INSERT INTO metadata (file_id, schema, vals, source, author, sensitive)
                SELECT it.file_id, it.schema, v.vals, 'person', me, v.s
                FROM (VALUES (it.before -> 'plain', false), (it.before -> 'hidden', true)) v (vals, s)
                WHERE v.vals IS NOT NULL AND v.vals <> '{}';
                INSERT INTO edit_items (edit_id, file_id, schema, before, after)
                VALUES (eid, it.file_id, it.schema, cur, metadata_value(it.file_id, it.schema, me));
            END IF;
            n := n + 1;
        END LOOP;
        SELECT array_agg(DISTINCT y.p ORDER BY y.p) INTO affected FROM (
            SELECT am.person_id AS p FROM edit_items i JOIN files f ON f.file_id IN (i.file_id, i.other_file_id)
            JOIN acl_members am ON am.acl_id = f.acl_id AND am.role IN ('owner', 'co-owner')
            WHERE i.edit_id = eid AND am.person_id IS DISTINCT FROM me
              AND (ed.action <> 'review' OR NOT EXISTS (SELECT 1 FROM acl_members mm WHERE mm.acl_id = f.acl_id
                                                        AND mm.person_id = me AND mm.role IN ('owner', 'co-owner')))
            UNION
            SELECT m.person_id FROM group_members m WHERE m.group_id = coalesce(grp, ed.group_id)) y;
        IF affected IS NOT NULL THEN
            INSERT INTO audit (actor, action, affects, detail)
            SELECT coalesce(me, t.person_id), 'undo', affected,
                   jsonb_build_object('edit', x, 'undone_by', eid, 'action', ed.action, 'changes', n)
                   || CASE WHEN t.client IS NULL THEN '{}' ELSE jsonb_build_object('token', t.client) END
                   || CASE WHEN coalesce(grp, ed.group_id) IS NULL THEN '{}'
                           ELSE jsonb_build_object('group', (SELECT g.name FROM groups g
                                                             WHERE g.group_id = coalesce(grp, ed.group_id))) END
            FROM (SELECT 1) one LEFT JOIN tokens t ON t.token_id = current_token();
        END IF;
        RETURN QUERY SELECT x, eid, n, NULL::text, NULL::bigint, NULL::bigint;
    END LOOP;
END $$;

-- the catalog's own writes (ROADMAP 62): a person's own and their groups', and of those an item only while its files
-- are visible (under a token, in its roots)
ALTER TABLE edits ENABLE ROW LEVEL SECURITY;
CREATE POLICY edits_mine ON edits FOR SELECT USING (my_edit(person_id, group_id));
ALTER TABLE edit_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY edit_items_visible ON edit_items FOR SELECT USING (
    EXISTS (SELECT 1 FROM edits e WHERE e.edit_id = edit_items.edit_id)
    AND EXISTS (SELECT 1 FROM files f WHERE f.file_id = edit_items.file_id)
    AND (other_file_id IS NULL OR EXISTS (SELECT 1 FROM files f WHERE f.file_id = edit_items.other_file_id)));

REVOKE ALL ON edits, edit_items FROM PUBLIC;
GRANT SELECT ON edits, edit_items TO pinakes_app;           -- written only through the functions that write (62)
GRANT SELECT, INSERT ON edits, edit_items TO pinakes_ingest;
GRANT USAGE ON SEQUENCE edits_edit_id_seq, edit_items_item_id_seq TO pinakes_ingest;
REVOKE ALL ON FUNCTION review_value(bigint), lineage_value(bigint, bigint, text), metadata_value(bigint, text, int),
                       same_value(jsonb, jsonb), edit_now(text), my_edit(int, int), undo_edits(bigint[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION review_value(bigint), lineage_value(bigint, bigint, text), metadata_value(bigint, text, int),
                       same_value(jsonb, jsonb), edit_now(text), my_edit(int, int), undo_edits(bigint[]) TO pinakes_ingest;
GRANT EXECUTE ON FUNCTION my_edit(int, int), undo_edits(bigint[]) TO pinakes_app;
