-- Upgrade a catalog built before ROADMAP 34 (API tokens). Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f api-tokens.sql
-- A new catalog gets the same from schema.sql; tests/test_web.py checks the two agree.

SET search_path = pinakes;

-- API tokens (ROADMAP 34): one per person per client, made and revoked by the person in the web UI. Only the
-- secret's SHA-256 is kept. The application reads and writes these only through the functions below.
CREATE TABLE tokens (
    token_id    serial PRIMARY KEY,
    person_id   int NOT NULL REFERENCES people ON DELETE CASCADE,
    client      text NOT NULL,                              -- the person's name for it: a machine, a script
    secret_sha256 bytea UNIQUE NOT NULL,
    scopes      text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ '{read,review,tag}'),
    roots       int[],                                      -- NULL: every root but the protected ones
    created     timestamptz NOT NULL DEFAULT now(),
    expires     timestamptz,                                -- NULL: until revoked
    revoked     timestamptz,
    last_used   timestamptz
);

-- The token this transaction acts by (set only by begin_token_call), or NULL: a web session or the CLI.
CREATE FUNCTION current_token() RETURNS int LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('pinakes.token', true), '')::int
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
-- transaction, record the call (the person sees it on their access page) and return the person and the scopes;
-- else no row. A token's session is never a web session's, and stepped_up() is false under a token.
CREATE FUNCTION begin_token_call(secret bytea, call text) RETURNS TABLE (person_id int, scopes text[])
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    t tokens;
BEGIN
    SELECT * INTO t FROM tokens tk
    WHERE tk.secret_sha256 = secret AND tk.revoked IS NULL AND (tk.expires IS NULL OR tk.expires > now());
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('pinakes.person', t.person_id::text, true),
            set_config('pinakes.session', 'token:' || t.token_id, true),
            set_config('pinakes.token', t.token_id::text, true);
    UPDATE tokens tk SET last_used = now() WHERE tk.token_id = t.token_id;
    INSERT INTO audit (actor, action, detail)
    VALUES (t.person_id, 'api', jsonb_build_object('token', t.client, 'call', left(call, 500)));
    RETURN QUERY SELECT t.person_id, t.scopes;
END $$;

-- A new token for the current person, from a web session (a token can't make one). The application makes the secret
-- and passes its SHA-256; `limit_roots` NULL is every root but the protected ones, else exactly those roots (a
-- protected one only if listed); `days` NULL: until revoked. Audited for the person; returns the token's id.
CREATE FUNCTION make_token(client text, secret bytea, scopes text[], limit_roots int[], days int) RETURNS int
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    id int;
    until timestamptz := CASE WHEN days IS NULL THEN NULL ELSE now() + make_interval(days => greatest(days, 1)) END;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token can''t make tokens'; END IF;
    IF coalesce(btrim(client), '') = '' THEN RAISE EXCEPTION 'name the client'; END IF;
    IF limit_roots IS NOT NULL AND (cardinality(limit_roots) = 0
       OR EXISTS (SELECT unnest(limit_roots) EXCEPT SELECT root_id FROM roots)) THEN
        RAISE EXCEPTION 'not a root list';
    END IF;
    INSERT INTO tokens (person_id, client, secret_sha256, scopes, roots, expires)
    VALUES (me, btrim(client), secret, scopes, limit_roots, until) RETURNING token_id INTO id;
    INSERT INTO audit (actor, action, affects, detail)
    VALUES (me, 'token_made', ARRAY[me], jsonb_build_object(
        'client', btrim(client), 'scopes', scopes, 'until', until,
        'roots', CASE WHEN limit_roots IS NULL THEN to_jsonb('every root but the protected ones'::text)
                      ELSE (SELECT to_jsonb(array_agg(label ORDER BY label)) FROM roots WHERE root_id = ANY (limit_roots))
                 END));
    RETURN id;
END $$;

-- The current person's tokens, without their secrets' hashes.
CREATE FUNCTION my_tokens() RETURNS TABLE (token_id int, client text, scopes text[], roots text[], created timestamptz,
                                           expires timestamptz, revoked timestamptz, last_used timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT t.token_id, t.client, t.scopes,
           CASE WHEN t.roots IS NULL THEN NULL
                ELSE (SELECT array_agg(r.label ORDER BY r.label) FROM roots r WHERE r.root_id = ANY (t.roots)) END,
           t.created, t.expires, t.revoked, t.last_used
    FROM tokens t WHERE t.person_id = current_person() ORDER BY t.revoked NULLS FIRST, t.created DESC
$$;

-- Revoke one of the current person's own tokens, from a web session; audited. False if it isn't theirs or is
-- already revoked.
CREATE FUNCTION revoke_token(id int) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    name text;
BEGIN
    IF me IS NULL THEN RAISE EXCEPTION 'no person set'; END IF;
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token can''t revoke tokens'; END IF;
    UPDATE tokens SET revoked = now() WHERE token_id = id AND person_id = me AND revoked IS NULL
    RETURNING client INTO name;
    IF name IS NULL THEN RETURN false; END IF;
    INSERT INTO audit (actor, action, affects, detail)
    VALUES (me, 'token_revoked', ARRAY[me], jsonb_build_object('client', name));
    RETURN true;
END $$;

DROP POLICY files_visible ON files;
-- under a token, only the roots it may see (ROADMAP 34); token_roots() is evaluated once per query
CREATE POLICY files_visible ON files FOR SELECT USING (acl_id = ANY (visible_acls())
    AND ((SELECT token_roots()) IS NULL OR root_id = ANY ((SELECT token_roots())::int[])));

GRANT EXECUTE ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                          make_token(text, bytea, text[], int[], int), my_tokens(), revoke_token(int) TO pinakes_app;
REVOKE ALL ON tokens FROM PUBLIC;
REVOKE ALL ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                       make_token(text, bytea, text[], int[], int), my_tokens(), revoke_token(int) FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON tokens TO pinakes_ingest;
GRANT USAGE ON SEQUENCE tokens_token_id_seq TO pinakes_ingest;
GRANT EXECUTE ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                          make_token(text, bytea, text[], int[], int), my_tokens(), revoke_token(int) TO pinakes_ingest;
