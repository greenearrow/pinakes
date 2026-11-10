-- pinakes schema: PostgreSQL 15+. Applied by `pinakes-ingest setup` as the schema owner.
-- Roles, created once by a superuser (setup does it when it can):
--   pinakes_ingest  LOGIN BYPASSRLS  the ingester: writes everything
--   pinakes_app     LOGIN            web UI, CLI, MCP: row-level security applies; sets the person per transaction

CREATE SCHEMA IF NOT EXISTS pinakes;
SET search_path = pinakes;
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;   -- the database is pinakes' own

-- people and access -------------------------------------------------------------------------------------------

CREATE TABLE people (
    person_id   serial PRIMARY KEY,
    name        text UNIQUE NOT NULL,
    display     text NOT NULL,
    roles       text[] NOT NULL DEFAULT '{person}'          -- person, operator, administrator
);
CREATE TABLE groups (
    group_id    serial PRIMARY KEY,
    name        text UNIQUE NOT NULL
);
CREATE TABLE group_members (
    group_id    int REFERENCES groups ON DELETE CASCADE,
    person_id   int REFERENCES people ON DELETE CASCADE,
    PRIMARY KEY (group_id, person_id)
);

-- An ACL is one combination of owner and enrollments; files point at one. acl_members is it expanded to people.
CREATE TABLE acls (
    acl_id      serial PRIMARY KEY,
    acl_key     text UNIQUE NOT NULL,                       -- canonical description, e.g. "o:p1|r:p2|c:g1"
    owner_person int REFERENCES people,
    owner_group int REFERENCES groups
);
CREATE TABLE acl_members (
    acl_id      int REFERENCES acls ON DELETE CASCADE,
    person_id   int REFERENCES people ON DELETE CASCADE,
    role        text NOT NULL CHECK (role IN ('owner', 'co-owner', 'reader', 'annotator')),
    PRIMARY KEY (acl_id, person_id)
);

-- step-up sessions: an administrator sees everything only while one is open for their web session
CREATE TABLE step_ups (
    step_up_id  serial PRIMARY KEY,
    person_id   int NOT NULL REFERENCES people,
    session     text NOT NULL,
    reason      text NOT NULL,
    started     timestamptz NOT NULL DEFAULT now(),
    expires     timestamptz NOT NULL
);
CREATE TABLE audit (
    audit_id    bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       int REFERENCES people,
    action      text NOT NULL,                              -- step_up, view, rule_change, enroll, operation, ...
    affects     int[] NOT NULL DEFAULT '{}',                -- people whose records it concerns
    detail      jsonb NOT NULL DEFAULT '{}'
);

-- sign-in: the application reads these only through the functions below
CREATE TABLE credentials (
    person_id   int PRIMARY KEY REFERENCES people ON DELETE CASCADE,
    password_hash text,                                     -- scrypt$N$r$p$salt$hash
    totp_secret text,                                       -- base32; NULL until the person enrolls a second factor
    updated     timestamptz NOT NULL DEFAULT now()
);

-- hosts, roots, scans -----------------------------------------------------------------------------------------

CREATE TABLE hosts (
    host_id     serial PRIMARY KEY,
    name        text UNIQUE NOT NULL,
    last_seq    bigint NOT NULL DEFAULT 0,
    last_scan   timestamptz,
    expected_every interval                                 -- NULL: never reported stale
);
CREATE TABLE roots (
    root_id     serial PRIMARY KEY,
    host_id     int NOT NULL REFERENCES hosts,
    label       text UNIQUE NOT NULL,
    path        text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('primary', 'drop', 'backup')),
    protected   boolean NOT NULL DEFAULT false,
    mirrors_root_id int REFERENCES roots,
    mirrors_layout text,
    mirrors_prefix text,                                    -- where in the source root the copied tree sits
    last_complete_on date
);
CREATE TABLE scans (
    root_id     int REFERENCES roots,
    scan        bigint NOT NULL,
    started_on  date NOT NULL,
    completed   boolean NOT NULL DEFAULT false,
    PRIMARY KEY (root_id, scan)
);
CREATE TABLE ingested (
    host_id     int REFERENCES hosts,
    seq         bigint NOT NULL,
    at          timestamptz NOT NULL DEFAULT now(),
    records     int NOT NULL,
    PRIMARY KEY (host_id, seq)
);
CREATE TABLE scan_errors (
    root_id     int REFERENCES roots,
    relpath     text NOT NULL,
    error       text NOT NULL,
    seen_on     date NOT NULL,
    PRIMARY KEY (root_id, relpath)
);

-- ownership rules and enrollments, per folder (relpath prefix; '' is the whole root) --------------------------

CREATE TABLE settings (key text PRIMARY KEY, value text NOT NULL);   -- default_owner, chunk_overlap
CREATE TABLE owner_rules (
    rule_id     serial PRIMARY KEY,
    root_id     int NOT NULL REFERENCES roots ON DELETE CASCADE,
    folder      text NOT NULL,
    owner_person int REFERENCES people,
    owner_group int REFERENCES groups,
    created_by  int REFERENCES people,
    created     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (root_id, folder),
    CHECK ((owner_person IS NULL) <> (owner_group IS NULL))
);
CREATE TABLE enrollments (
    enrollment_id serial PRIMARY KEY,
    root_id     int NOT NULL REFERENCES roots ON DELETE CASCADE,
    folder      text NOT NULL,
    person_id   int REFERENCES people,
    group_id    int REFERENCES groups,
    role        text NOT NULL CHECK (role IN ('co-owner', 'reader', 'annotator')),
    created_by  int REFERENCES people,
    created     timestamptz NOT NULL DEFAULT now(),
    CHECK ((person_id IS NULL) <> (group_id IS NULL))
);

-- what was seen -----------------------------------------------------------------------------------------------

CREATE TABLE contents (
    content_id  bigserial PRIMARY KEY,
    sha256      bytea UNIQUE NOT NULL,
    size        bigint NOT NULL,
    mime        text,
    chunk_params text                                       -- set when its chunks are stored
);
CREATE TABLE content_chunks (
    content_id  bigint REFERENCES contents ON DELETE CASCADE,
    ord         int NOT NULL,
    off         bigint NOT NULL,
    len         int NOT NULL,
    digest      bytea NOT NULL,
    PRIMARY KEY (content_id, ord)
);
CREATE INDEX content_chunks_digest ON content_chunks (digest);

CREATE TABLE files (
    file_id     bigserial PRIMARY KEY,
    root_id     int NOT NULL REFERENCES roots,
    relpath     text NOT NULL,
    name        text NOT NULL,
    content_id  bigint REFERENCES contents,
    size        bigint,
    mtime       timestamptz, ctime timestamptz, btime timestamptz,
    mtime_ns    bigint, ctime_ns bigint, btime_ns bigint,
    dev         bigint, ino bigint, nlink int, uid int,
    is_symlink  boolean NOT NULL DEFAULT false,
    link_target text,
    unstable    boolean NOT NULL DEFAULT false,
    owner_id    int REFERENCES people,                      -- the owning person (NULL when a group owns it)
    acl_id      int NOT NULL REFERENCES acls,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    gone_on     date,
    backup_of   bigint REFERENCES files,
    snapshot    date,
    pending_scan bigint,                                    -- new in this unfinished scan: move matching pending
    changed_scan bigint,                                    -- changed in this unfinished scan: lineage pending
    name_key    text,                                       -- the name normalized for lineage (names.toml)
    ext         text,
    protected_link boolean NOT NULL DEFAULT false,          -- another link to its inode is under a protected root
    link_root   text,                                       -- a symlink's target, when in a root of its agent: the
    link_relpath text,                                      -- root's label and the path in it ('' for the root)
    link_dangling boolean                                   -- its target is missing; NULL: not known
);
CREATE UNIQUE INDEX files_present_path ON files (root_id, relpath) WHERE gone_on IS NULL;
CREATE INDEX files_content ON files (content_id);
CREATE INDEX files_inode ON files (dev, ino);
CREATE INDEX files_acl ON files (acl_id);
CREATE INDEX files_backup_of ON files (backup_of);
CREATE INDEX files_name_trgm ON files USING gin (name public.gin_trgm_ops);
CREATE INDEX files_relpath ON files (root_id, relpath text_pattern_ops);
CREATE INDEX files_name_key ON files (name_key, ext);
CREATE INDEX files_link ON files (link_root, link_relpath text_pattern_ops) WHERE is_symlink;
-- security_invoker: without it a view reads its table as the view's owner, and row-level security wouldn't apply
CREATE VIEW present WITH (security_invoker = true) AS SELECT * FROM files WHERE gone_on IS NULL;

CREATE TABLE members (
    archive_content_id bigint REFERENCES contents ON DELETE CASCADE,
    entry_path  text NOT NULL,
    size        bigint NOT NULL,
    content_id  bigint NOT NULL REFERENCES contents,
    PRIMARY KEY (archive_content_id, entry_path)
);
CREATE INDEX members_content ON members (content_id);

CREATE TABLE history (
    history_id  bigserial PRIMARY KEY,
    file_id     bigint NOT NULL REFERENCES files ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('new', 'changed', 'moved', 'moved_changed', 'gone')),
    old_relpath text, new_relpath text,
    old_content_id bigint REFERENCES contents, new_content_id bigint REFERENCES contents,
    old_mtime timestamptz, new_mtime timestamptz,
    old_ctime timestamptz, new_ctime timestamptz,
    old_btime timestamptz, new_btime timestamptz,
    seen_after  date,                                       -- the last completed scan before (NULL: first scan)
    seen_on     date NOT NULL,                              -- the scan that saw it
    evidence    text,
    confidence  text CHECK (confidence IN ('certain', 'strong', 'likely', 'possible'))
);
CREATE INDEX history_file ON history (file_id);
CREATE INDEX history_seen ON history (seen_on);
CREATE INDEX history_old_content ON history (old_content_id);
CREATE INDEX history_new_content ON history (new_content_id);

CREATE TABLE lineage (
    from_file_id bigint REFERENCES files ON DELETE CASCADE,
    to_file_id  bigint REFERENCES files ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('copied_from', 'replaced_by', 'derived_from')),
    evidence    text NOT NULL,
    confidence  text NOT NULL CHECK (confidence IN ('certain', 'strong', 'likely', 'possible')),
    found_on    date NOT NULL DEFAULT current_date,
    decision    text CHECK (decision IN ('confirmed', 'rejected')),
    decided_by  int REFERENCES people,
    PRIMARY KEY (from_file_id, to_file_id, kind),
    CHECK (from_file_id <> to_file_id)
);
CREATE INDEX lineage_to ON lineage (to_file_id);

CREATE TABLE metadata (
    metadata_id bigserial PRIMARY KEY,
    content_id  bigint REFERENCES contents ON DELETE CASCADE,
    file_id     bigint REFERENCES files ON DELETE CASCADE,
    schema      text NOT NULL,
    vals        jsonb NOT NULL,
    source      text NOT NULL CHECK (source IN ('person', 'sidecar', 'embedded', 'derived')),
    author      int REFERENCES people,
    at          timestamptz NOT NULL DEFAULT now(),
    version     int,                                     -- the schema's version it was extracted by (ROADMAP 13)
    sent_by     int REFERENCES hosts ON DELETE SET NULL, -- the agent that sent it, so a revoked one's can be found
    sensitive   boolean NOT NULL DEFAULT false,          -- the schema's sensitive fields, apart: owners only (ROADMAP 16)
    CHECK ((content_id IS NULL) <> (file_id IS NULL))
);
CREATE INDEX metadata_content ON metadata (content_id, schema);
CREATE INDEX metadata_file ON metadata (file_id, schema);
CREATE INDEX metadata_vals ON metadata USING gin (vals jsonb_path_ops);

-- A review of a change (ROADMAP 32): a gone file or a move, marked intended, or to restore. Written only through
-- mark_changes(); a later change is a new history row, unreviewed.
CREATE TABLE review_marks (
    history_id  bigint PRIMARY KEY REFERENCES history ON DELETE CASCADE,
    mark        text NOT NULL CHECK (mark IN ('intended', 'restore')),
    marked_by   int NOT NULL REFERENCES people,
    marked_at   timestamptz NOT NULL DEFAULT now()
);

-- who is asking -----------------------------------------------------------------------------------------------

CREATE FUNCTION current_person() RETURNS int LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('pinakes.person', true), '')::int
$$;

CREATE FUNCTION has_role(r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT EXISTS (SELECT 1 FROM people WHERE person_id = current_person() AND r = ANY (roles))
$$;

-- An open step-up for this person and web session, for an administrator.
CREATE FUNCTION stepped_up() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT EXISTS (
        SELECT 1 FROM step_ups s JOIN people p USING (person_id)
        WHERE s.person_id = current_person()
          AND s.session = current_setting('pinakes.session', true)
          AND s.expires > now()
          AND 'administrator' = ANY (p.roles))
$$;

-- The ACLs whose files the current person may see: their own, enrolled and shared; all of them in a step-up.
CREATE FUNCTION visible_acls() RETURNS int[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT CASE WHEN stepped_up() THEN (SELECT coalesce(array_agg(acl_id), '{}') FROM acls)
                ELSE (SELECT coalesce(array_agg(acl_id), '{}') FROM acl_members WHERE person_id = current_person())
           END
$$;

-- Open a step-up. The application checks the second factor before calling this; the database checks the role,
-- sets the expiry and writes the audit entry.
CREATE FUNCTION begin_step_up(reason text, minutes int DEFAULT 15) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    me int := current_person();
    sess text := current_setting('pinakes.session', true);
    until timestamptz := now() + make_interval(mins => least(greatest(minutes, 1), 60));
BEGIN
    IF me IS NULL OR sess IS NULL OR sess = '' THEN RAISE EXCEPTION 'no person or session set'; END IF;
    IF NOT EXISTS (SELECT 1 FROM people WHERE person_id = me AND 'administrator' = ANY (roles)) THEN
        RAISE EXCEPTION 'not an administrator';
    END IF;
    IF coalesce(btrim(reason), '') = '' THEN RAISE EXCEPTION 'a reason is required'; END IF;
    INSERT INTO step_ups (person_id, session, reason, expires) VALUES (me, sess, reason, until);
    INSERT INTO audit (actor, action, detail) VALUES (me, 'step_up', jsonb_build_object('reason', reason, 'until', until));
    RETURN until;
END $$;

CREATE FUNCTION end_step_up() RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
    UPDATE step_ups SET expires = now()
    WHERE person_id = current_person() AND session = current_setting('pinakes.session', true) AND expires > now()
$$;

-- What an administrator viewed in a step-up: called by the application, summarized by folder.
CREATE FUNCTION audit_view(affects int[], detail jsonb) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
    INSERT INTO audit (actor, action, affects, detail)
    SELECT current_person(), 'view', affects, detail WHERE stepped_up()
$$;

-- The password hash of a person by name, to check a sign-in (the application verifies it).
CREATE FUNCTION login_material(person_name text) RETURNS TABLE (person_id int, password_hash text, has_totp boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT p.person_id, c.password_hash, c.totp_secret IS NOT NULL
    FROM people p LEFT JOIN credentials c USING (person_id) WHERE p.name = person_name
$$;

-- The current person's own second-factor secret, to check a code before a step-up.
CREATE FUNCTION my_totp_secret() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT totp_secret FROM credentials WHERE person_id = current_person()
$$;

CREATE FUNCTION set_my_password(hash text) RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pinakes AS $$
    INSERT INTO credentials (person_id, password_hash) VALUES (current_person(), hash)
    ON CONFLICT (person_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated = now()
$$;

CREATE FUNCTION set_my_totp(secret text) RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pinakes AS $$
    INSERT INTO credentials (person_id, totp_secret) VALUES (current_person(), secret)
    ON CONFLICT (person_id) DO UPDATE SET totp_secret = EXCLUDED.totp_secret, updated = now()
$$;

CREATE FUNCTION my_roles() RETURNS text[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT roles FROM people WHERE person_id = current_person()
$$;

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

-- The metadata schema registry's indexes (ROADMAP 12, METADATA.md "Storage and speed"): one partial index on
-- metadata per indexed field, made from `wanted`, an array of [schema, field, kind] from pinakes/registry.py. Makes
-- the missing ones and drops the md_* indexes nothing wants; returns their names. The schema owner's, so that the
-- ingester (which owns no table) can keep them in step at setup: it may name a schema and a field, never SQL.
CREATE FUNCTION enroll_metadata_indexes(wanted jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pinakes AS $$
DECLARE
    w jsonb;
    s text;
    f text;
    k text;
    idx text;
    how text;
    names text[] := '{}';
    made text[] := '{}';
    gone text[] := '{}';
BEGIN
    IF jsonb_typeof(wanted) <> 'array' THEN RAISE EXCEPTION 'wanted is an array of [schema, field, kind]'; END IF;
    FOR w IN SELECT jsonb_array_elements(wanted) LOOP
        s := w ->> 0; f := w ->> 1; k := w ->> 2;
        IF jsonb_typeof(w) <> 'array' OR jsonb_array_length(w) <> 3 OR s !~ '^[a-z][a-z0-9]{0,19}$'
           OR f !~ '^[a-z][a-z0-9_]{0,29}$' THEN
            RAISE EXCEPTION 'not a schema and field: %', w;
        END IF;
        how := CASE k
            WHEN 'eq'   THEN format('btree ((vals ->> %L))', f)
            WHEN 'date' THEN format('btree ((vals ->> %L))', f)          -- ISO 8601 text: text order is time order
            WHEN 'trgm' THEN format('gin ((vals ->> %L) public.gin_trgm_ops)', f)
            WHEN 'num'  THEN format('btree (((vals ->> %L)::numeric))', f)
            WHEN 'ref'  THEN format('btree (((vals ->> %L)::bigint))', f)
            WHEN 'list' THEN format('gin ((vals -> %L))', f)
            WHEN 'geo'  THEN format('gist (point((vals -> %L ->> ''lon'')::float8, (vals -> %L ->> ''lat'')::float8))',
                                    f, f)
        END;
        IF how IS NULL THEN RAISE EXCEPTION 'not an index kind: %', k; END IF;
        idx := format('md_%s_%s_%s', s, f, k);
        names := names || idx;
        IF to_regclass(format('pinakes.%I', idx)) IS NULL THEN
            EXECUTE format('CREATE INDEX %I ON metadata USING %s WHERE schema = %L', idx, how, s);
            made := made || idx;
        END IF;
    END LOOP;
    FOR idx IN SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
               WHERE i.indrelid = 'pinakes.metadata'::regclass AND c.relname LIKE 'md\_%' AND c.relname <> ALL (names)
               ORDER BY c.relname LOOP
        EXECUTE format('DROP INDEX %I', idx);
        gone := gone || idx;
    END LOOP;
    RETURN jsonb_build_object('created', to_jsonb(made), 'dropped', to_jsonb(gone), 'wanted', to_jsonb(names));
END $$;

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

-- row-level security ------------------------------------------------------------------------------------------

ALTER TABLE files ENABLE ROW LEVEL SECURITY;
CREATE POLICY files_visible ON files FOR SELECT USING (acl_id = ANY (visible_acls()));

ALTER TABLE contents ENABLE ROW LEVEL SECURITY;
-- a content is visible through a file that holds it now, an archive member, or the history of a visible file
-- (a past version nobody holds any more is still the owner's to see)
CREATE POLICY contents_visible ON contents FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.content_id = contents.content_id)
    OR EXISTS (SELECT 1 FROM members m WHERE m.content_id = contents.content_id)
    OR EXISTS (SELECT 1 FROM history h WHERE h.old_content_id = contents.content_id)
    OR EXISTS (SELECT 1 FROM history h WHERE h.new_content_id = contents.content_id));

ALTER TABLE content_chunks ENABLE ROW LEVEL SECURITY;
CREATE POLICY chunks_visible ON content_chunks FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.content_id = content_chunks.content_id));

ALTER TABLE members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_visible ON members FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.content_id = members.archive_content_id));

ALTER TABLE history ENABLE ROW LEVEL SECURITY;
CREATE POLICY history_visible ON history FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.file_id = history.file_id));

ALTER TABLE lineage ENABLE ROW LEVEL SECURITY;
CREATE POLICY lineage_visible ON lineage FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.file_id = lineage.from_file_id)
    AND EXISTS (SELECT 1 FROM files f WHERE f.file_id = lineage.to_file_id));

ALTER TABLE metadata ENABLE ROW LEVEL SECURITY;
CREATE POLICY metadata_visible ON metadata FOR SELECT USING (
    ((file_id IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.file_id = metadata.file_id))
     OR (content_id IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.content_id = metadata.content_id)))
    AND (NOT sensitive OR sensitive_visible(content_id, file_id)));

ALTER TABLE review_marks ENABLE ROW LEVEL SECURITY;
CREATE POLICY review_marks_visible ON review_marks FOR SELECT USING (
    EXISTS (SELECT 1 FROM history h WHERE h.history_id = review_marks.history_id));

ALTER TABLE scan_errors ENABLE ROW LEVEL SECURITY;
CREATE POLICY scan_errors_operators ON scan_errors FOR SELECT USING (stepped_up() OR has_role('operator'));

-- the audit log: a person sees what concerns them or what they did; append-only for everyone
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_visible ON audit FOR SELECT USING (
    actor = current_person() OR current_person() = ANY (affects) OR stepped_up());

-- grants ------------------------------------------------------------------------------------------------------

REVOKE ALL ON ALL TABLES IN SCHEMA pinakes FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pinakes FROM PUBLIC;
GRANT USAGE ON SCHEMA pinakes TO pinakes_app, pinakes_ingest;

GRANT SELECT ON files, present, contents, content_chunks, members, history, lineage, metadata, hosts, roots,
               scans, audit, scan_errors TO pinakes_app;
GRANT SELECT ON ingested TO pinakes_app;                 -- when each host's batches came in: for /health
GRANT SELECT (person_id, name, display) ON people TO pinakes_app;
GRANT SELECT ON groups TO pinakes_app;
GRANT EXECUTE ON FUNCTION current_person(), has_role(text), stepped_up(), visible_acls(), begin_step_up(text, int),
                          end_step_up(), audit_view(int[], jsonb), login_material(text), my_totp_secret(),
                          set_my_password(text), set_my_totp(text), my_roles() TO pinakes_app;
GRANT SELECT ON review_marks TO pinakes_app;              -- written only through mark_changes()
GRANT EXECUTE ON FUNCTION mark_changes(bigint[], text) TO pinakes_app;
GRANT EXECUTE ON FUNCTION sensitive_visible(bigint, bigint) TO pinakes_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA pinakes TO pinakes_ingest;
REVOKE UPDATE, DELETE ON audit FROM pinakes_ingest;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA pinakes TO pinakes_ingest;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pinakes TO pinakes_ingest;
