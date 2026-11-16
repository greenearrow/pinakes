-- Upgrade a catalog built before ROADMAP 34 (API tokens: person, ops and group tokens, 34 to 39). Run once as the
-- schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f api-tokens.sql
-- A new catalog gets the same from schema.sql; tests/test_web.py checks the two agree.

SET search_path = pinakes;

-- API tokens (ROADMAP 34): one per person per client, made and revoked by the person in the web UI. Only the
-- secret's SHA-256 is kept. The application reads and writes these only through the functions below. An ops token
-- (ROADMAP 39) is an operator's, and acts as no person: hosts, check-ins, releases and staleness only. A group token
-- (ROADMAP 38) acts as its group and no member; person_id is the member who made it, and it works only while they
-- are still one.
CREATE TABLE tokens (
    token_id    serial PRIMARY KEY,
    person_id   int NOT NULL REFERENCES people ON DELETE CASCADE,
    client      text NOT NULL,                              -- the person's name for it: a machine, a script
    secret_sha256 bytea UNIQUE NOT NULL,
    kind        text NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'ops', 'group')),
    group_id    int REFERENCES groups ON DELETE CASCADE,    -- a group token's group
    scopes      text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ '{read,review,tag,ops}'),
    roots       int[],                                      -- NULL: every root but the protected ones
    created     timestamptz NOT NULL DEFAULT now(),
    expires     timestamptz,                                -- NULL: until revoked
    revoked     timestamptz,
    last_used   timestamptz,
    cli_session boolean NOT NULL DEFAULT false,             -- pinakes --as: minutes long, ended by its command
    CHECK ((kind = 'ops') = (scopes = '{ops}')),            -- an ops token has the ops scope, and only it does
    CHECK (kind <> 'ops' OR roots IS NULL),
    CHECK ((kind = 'group') = (group_id IS NOT NULL)),
    CHECK (kind = 'person' OR NOT cli_session)
);

-- The groups named by an ACL, as the owner or enrolled, with the group's own role: what a group token sees (ROADMAP
-- 38). Written by the ingester with acl_members; membership changes don't touch it.
CREATE TABLE acl_groups (
    acl_id      int REFERENCES acls ON DELETE CASCADE,
    group_id    int REFERENCES groups ON DELETE CASCADE,
    role        text NOT NULL CHECK (role IN ('owner', 'co-owner', 'reader', 'annotator')),
    PRIMARY KEY (acl_id, group_id)
);
CREATE INDEX acl_groups_group ON acl_groups (group_id);
INSERT INTO acl_groups (acl_id, group_id, role)       -- from each ACL's key: o:g1|co-owner:g2|reader:p3
SELECT acl_id, g, (array_agg(role ORDER BY array_position('{owner,co-owner,annotator,reader}'::text[], role)))[1]
FROM (SELECT a.acl_id, (m)[2]::int AS g, CASE WHEN (m)[1] = 'o' THEN 'owner' ELSE (m)[1] END AS role
      FROM acls a, regexp_matches(a.acl_key, '(?:^|\|)(o|co-owner|reader|annotator):g([0-9]+)', 'g') AS m) k
WHERE g IN (SELECT group_id FROM groups)
GROUP BY acl_id, g;

ALTER TABLE review_marks ALTER COLUMN marked_by DROP NOT NULL,
    ADD COLUMN marked_by_group int REFERENCES groups,
    ADD CHECK ((marked_by IS NULL) <> (marked_by_group IS NULL));

-- The token this transaction acts by (set only by begin_token_call), or NULL: a web session or the CLI.
CREATE FUNCTION current_token() RETURNS int LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('pinakes.token', true), '')::int
$$;

-- The group a group token acts as (ROADMAP 38), or NULL: a person's token, an ops token, a web session or the CLI.
CREATE FUNCTION current_group() RETURNS int LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT group_id FROM tokens WHERE token_id = current_token() AND kind = 'group'
$$;

-- An open step-up for this person and web session, for an administrator.
CREATE OR REPLACE FUNCTION stepped_up() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT EXISTS (
        SELECT 1 FROM step_ups s JOIN people p USING (person_id)
        WHERE s.person_id = current_person()
          AND s.session = current_setting('pinakes.session', true)
          AND s.expires > now()
          AND 'administrator' = ANY (p.roles)
          AND current_token() IS NULL)                          -- a token never steps up
$$;

-- Open a step-up. The application checks the second factor before calling this; the database checks the role,
-- sets the expiry and writes the audit entry.
CREATE OR REPLACE FUNCTION begin_step_up(reason text, minutes int DEFAULT 15) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    sess text := current_setting('pinakes.session', true);
    until timestamptz := now() + make_interval(mins => least(greatest(minutes, 1), 60));
BEGIN
    IF me IS NULL OR sess IS NULL OR sess = '' THEN RAISE EXCEPTION 'no person or session set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token never steps up'; END IF;
    IF NOT EXISTS (SELECT 1 FROM people WHERE person_id = me AND 'administrator' = ANY (roles)) THEN
        RAISE EXCEPTION 'not an administrator';
    END IF;
    IF coalesce(btrim(reason), '') = '' THEN RAISE EXCEPTION 'a reason is required'; END IF;
    INSERT INTO step_ups (person_id, session, reason, expires) VALUES (me, sess, reason, until);
    INSERT INTO audit (actor, action, detail) VALUES (me, 'step_up', jsonb_build_object('reason', reason, 'until', until));
    RETURN until;
END $$;

-- The roots a token's call may see: those it was limited to, else every root but the protected ones. NULL when no
-- token is in use (a web session or the CLI: every root).
CREATE FUNCTION token_roots() RETURNS int[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT CASE WHEN current_token() IS NULL THEN NULL ELSE coalesce((
        SELECT array_agg(r.root_id ORDER BY r.root_id)
        FROM tokens t JOIN roots r ON (t.roots IS NULL AND NOT r.protected) OR r.root_id = ANY (t.roots)
        WHERE t.token_id = current_token()), '{}') END
$$;

-- An API call by token: if the secret's hash names a token neither revoked nor expired, act as its person for this
-- transaction, record the call (the person sees it on their access page) and return the person, the scopes, the
-- token's kind and its group; else no row. A token's session is never a web session's, and stepped_up() is false
-- under a token. An ops token acts as no person (its person is NULL): row-level security shows it no file, and the
-- call is its maker's record. A group token acts as its group and no person, only while its maker is still a member;
-- its calls are recorded for the group's members.
CREATE FUNCTION begin_token_call(secret bytea, call text)
RETURNS TABLE (person_id int, scopes text[], kind text, group_name text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    t tokens;
    gname text;
BEGIN
    SELECT * INTO t FROM tokens tk
    WHERE tk.secret_sha256 = secret AND tk.revoked IS NULL AND (tk.expires IS NULL OR tk.expires > now())
      AND (tk.kind <> 'group' OR EXISTS (SELECT 1 FROM group_members m
                                         WHERE m.group_id = tk.group_id AND m.person_id = tk.person_id));
    IF NOT FOUND THEN RETURN; END IF;
    SELECT g.name INTO gname FROM groups g WHERE g.group_id = t.group_id;
    PERFORM set_config('pinakes.person', CASE WHEN t.kind = 'person' THEN t.person_id::text ELSE '' END, true),
            set_config('pinakes.session', 'token:' || t.token_id, true),
            set_config('pinakes.token', t.token_id::text, true);
    UPDATE tokens tk SET last_used = now() WHERE tk.token_id = t.token_id;
    INSERT INTO audit (actor, action, affects, detail)
    VALUES (t.person_id, 'api',
            CASE WHEN gname IS NULL THEN '{}'
                 ELSE (SELECT array_agg(m.person_id ORDER BY m.person_id) FROM group_members m
                       WHERE m.group_id = t.group_id) END,
            jsonb_build_object('token', t.client, 'call', left(call, 500))
            || CASE WHEN gname IS NULL THEN '{}' ELSE jsonb_build_object('group', gname) END);
    RETURN QUERY SELECT CASE WHEN t.kind = 'person' THEN t.person_id END, t.scopes, t.kind, gname;
END $$;

-- A new token for the current person, from a web session (a token can't make one). The application makes the secret
-- and passes its SHA-256; `limit_roots` NULL is every root but the protected ones, else exactly those roots (a
-- protected one only if listed); `days` NULL: until revoked. Scopes {ops} alone make an ops token, for an
-- operator only, with no root list. `for_group` makes a group token instead, by a member of that group only
-- (ROADMAP 38), audited for every member. Audited for the person; returns the token's id.
CREATE FUNCTION make_token(client text, secret bytea, scopes text[], limit_roots int[], days int,
                           for_group int DEFAULT NULL) RETURNS int
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    id int;
    ops boolean := 'ops' = ANY (scopes);
    until timestamptz := CASE WHEN days IS NULL THEN NULL ELSE now() + make_interval(days => greatest(days, 1)) END;
    gname text;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token can''t make tokens'; END IF;
    IF coalesce(btrim(client), '') = '' THEN RAISE EXCEPTION 'name the client'; END IF;
    IF ops AND (scopes <> '{ops}' OR limit_roots IS NOT NULL OR for_group IS NOT NULL) THEN
        RAISE EXCEPTION 'an ops token has the ops scope alone, and no roots or group';
    END IF;
    IF ops AND NOT has_role('operator') THEN RAISE EXCEPTION 'only an operator makes ops tokens'; END IF;
    IF for_group IS NOT NULL THEN
        SELECT g.name INTO gname FROM groups g JOIN group_members m USING (group_id)
        WHERE g.group_id = for_group AND m.person_id = me;
        IF gname IS NULL THEN RAISE EXCEPTION 'only a member of the group makes its tokens'; END IF;
    END IF;
    IF limit_roots IS NOT NULL AND (cardinality(limit_roots) = 0
       OR EXISTS (SELECT unnest(limit_roots) EXCEPT SELECT root_id FROM roots)) THEN
        RAISE EXCEPTION 'not a root list';
    END IF;
    INSERT INTO tokens (person_id, kind, group_id, client, secret_sha256, scopes, roots, expires)
    VALUES (me, CASE WHEN ops THEN 'ops' WHEN for_group IS NOT NULL THEN 'group' ELSE 'person' END, for_group,
            btrim(client), secret, scopes, limit_roots, until)
    RETURNING token_id INTO id;
    INSERT INTO audit (actor, action, affects, detail)
    VALUES (me, 'token_made',
            CASE WHEN for_group IS NULL THEN ARRAY[me]
                 ELSE (SELECT array_agg(m.person_id ORDER BY m.person_id) FROM group_members m
                       WHERE m.group_id = for_group) END,
            jsonb_build_object(
        'client', btrim(client), 'scopes', scopes, 'until', until,
        'roots', CASE WHEN ops THEN to_jsonb('none: an ops token'::text)
                      WHEN limit_roots IS NULL THEN to_jsonb('every root but the protected ones'::text)
                      ELSE (SELECT to_jsonb(array_agg(label ORDER BY label)) FROM roots
                            WHERE root_id = ANY (limit_roots))
                 END)
            || CASE WHEN gname IS NULL THEN '{}' ELSE jsonb_build_object('group', gname) END);
    RETURN id;
END $$;

-- The current person's tokens, and the tokens of the groups they are a member of (whoever made them), without
-- their secrets' hashes.
CREATE FUNCTION my_tokens() RETURNS TABLE (token_id int, kind text, client text, scopes text[], roots text[],
                                           created timestamptz, expires timestamptz, revoked timestamptz,
                                           last_used timestamptz, group_name text, made_by text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT t.token_id, t.kind, t.client, t.scopes,
           CASE WHEN t.roots IS NULL THEN NULL
                ELSE (SELECT array_agg(r.label ORDER BY r.label) FROM roots r WHERE r.root_id = ANY (t.roots)) END,
           t.created, t.expires, t.revoked, t.last_used, g.name, p.display
    FROM tokens t JOIN people p ON p.person_id = t.person_id LEFT JOIN groups g ON g.group_id = t.group_id
    WHERE NOT t.cli_session
      AND (t.kind <> 'group' AND t.person_id = current_person()
           OR t.kind = 'group' AND EXISTS (SELECT 1 FROM group_members m
                                           WHERE m.group_id = t.group_id AND m.person_id = current_person()))
    ORDER BY t.revoked NULLS FIRST, t.created DESC
$$;

-- Revoke one of the current person's own tokens, or a token of a group they are a member of, from a web session;
-- audited (a group's for every member). False if it isn't theirs or is already revoked.
CREATE FUNCTION revoke_token(id int) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    name text;
    grp int;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token can''t revoke tokens'; END IF;
    UPDATE tokens t SET revoked = now()
    WHERE t.token_id = id AND t.revoked IS NULL
      AND (t.kind <> 'group' AND t.person_id = me
           OR t.kind = 'group' AND EXISTS (SELECT 1 FROM group_members m
                                           WHERE m.group_id = t.group_id AND m.person_id = me))
    RETURNING t.client, t.group_id INTO name, grp;
    IF name IS NULL THEN RETURN false; END IF;
    INSERT INTO audit (actor, action, affects, detail)
    VALUES (me, 'token_revoked',
            CASE WHEN grp IS NULL THEN ARRAY[me]
                 ELSE (SELECT array_agg(m.person_id ORDER BY m.person_id) FROM group_members m
                       WHERE m.group_id = grp) END,
            jsonb_build_object('client', name)
            || CASE WHEN grp IS NULL THEN '{}'
                    ELSE jsonb_build_object('group', (SELECT g.name FROM groups g WHERE g.group_id = grp)) END);
    RETURN true;
END $$;

-- pinakes --as NAME (ROADMAP 36): once the application has checked NAME's password (and second factor, if they have
-- one) and set them as the current person, a token for that one command: `read` only, every root but the protected
-- ones, minutes long, not listed among their tokens. Audited for the person as a sign-in from the CLI.
CREATE FUNCTION begin_cli_session(secret bytea, minutes int, addr text) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    until timestamptz := now() + make_interval(mins => least(greatest(minutes, 1), 60));
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token can''t sign in'; END IF;
    INSERT INTO tokens (person_id, client, secret_sha256, scopes, expires, cli_session)
    VALUES (me, 'pinakes --as', secret, '{read}', until, true);
    INSERT INTO audit (actor, action, affects, detail)
    VALUES (me, 'cli_sign_in', ARRAY[me], jsonb_build_object('from', left(addr, 100), 'until', until));
    RETURN until;
END $$;

-- The end of a pinakes --as command: the session token this call acts by is revoked.
CREATE FUNCTION end_cli_session() RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
    UPDATE tokens SET revoked = now() WHERE token_id = current_token() AND cli_session AND revoked IS NULL
    RETURNING true
$$;

-- Mark changes reviewed: 'intended', 'restore', or NULL to clear. Only gone files and moves, only by the file's
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
        WHERE hi.history_id = ANY (ids) AND hi.kind IN ('gone', 'moved', 'moved_changed')
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

-- The ACLs whose files the current person may see: their own, enrolled and shared; all of them in a step-up. Under a
-- group token, the group's: those it owns or is enrolled in, never a member's own (ROADMAP 38).
CREATE OR REPLACE FUNCTION visible_acls() RETURNS int[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT CASE WHEN stepped_up() THEN (SELECT coalesce(array_agg(acl_id), '{}') FROM acls)
                WHEN current_group() IS NOT NULL
                    THEN (SELECT coalesce(array_agg(acl_id), '{}') FROM acl_groups WHERE group_id = current_group())
                ELSE (SELECT coalesce(array_agg(acl_id), '{}') FROM acl_members WHERE person_id = current_person())
           END
$$;

-- The groups the current person is a member of: those they may make group tokens for.
CREATE FUNCTION my_groups() RETURNS TABLE (group_id int, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT g.group_id, g.name FROM groups g JOIN group_members m USING (group_id)
    WHERE m.person_id = current_person() ORDER BY g.name
$$;

-- Whether the current person may see sensitive metadata (GPS, people shown, places: METADATA.md) on a content or
-- a file: as the owner or a co-owner of a file with that content (or of that file), or as an administrator in a
-- step-up; under a group token, where the group is the owner or a co-owner (ROADMAP 38). Readers and annotators of
-- a shared folder see a file's other metadata, not these.
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
$$;

DROP POLICY files_visible ON files;
-- under a token, only the roots it may see (ROADMAP 34); token_roots() is evaluated once per query
CREATE POLICY files_visible ON files FOR SELECT USING (acl_id = ANY (visible_acls())
    AND ((SELECT token_roots()) IS NULL OR root_id = ANY ((SELECT token_roots())::int[])));

GRANT EXECUTE ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                          make_token(text, bytea, text[], int[], int, int), my_tokens(), revoke_token(int),
                          begin_cli_session(bytea, int, text), end_cli_session(), current_group(), my_groups()
                          TO pinakes_app;
REVOKE ALL ON tokens, acl_groups FROM PUBLIC;
REVOKE ALL ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                       make_token(text, bytea, text[], int[], int, int), my_tokens(), revoke_token(int),
                       begin_cli_session(bytea, int, text), end_cli_session(), current_group(), my_groups()
                       FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON tokens, acl_groups TO pinakes_ingest;
GRANT USAGE ON SEQUENCE tokens_token_id_seq TO pinakes_ingest;
GRANT EXECUTE ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                          make_token(text, bytea, text[], int[], int, int), my_tokens(), revoke_token(int),
                          begin_cli_session(bytea, int, text), end_cli_session(), current_group(), my_groups()
                          TO pinakes_ingest;
