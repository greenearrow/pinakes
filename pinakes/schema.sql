-- pinakes schema: PostgreSQL 15+. Applied by `pinakes-ingest setup` as the schema owner.
-- Roles, created once by a superuser (setup does it when it can):
--   pinakes_ingest  LOGIN BYPASSRLS  the ingester: writes everything
--   pinakes_app     LOGIN            web UI, CLI, MCP: row-level security applies; sets the person per transaction
--                                    (or, for the API, begin_token_call() sets it from a token)

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
-- The groups named by an ACL, as the owner or enrolled, with the group's own role: what a group token sees (ROADMAP
-- 38). Written by the ingester with acl_members; membership changes don't touch it.
CREATE TABLE acl_groups (
    acl_id      int REFERENCES acls ON DELETE CASCADE,
    group_id    int REFERENCES groups ON DELETE CASCADE,
    role        text NOT NULL CHECK (role IN ('owner', 'co-owner', 'reader', 'annotator')),
    PRIMARY KEY (acl_id, group_id)
);
CREATE INDEX acl_groups_group ON acl_groups (group_id);

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
    last_complete_on date,
    -- the scrub (DESIGN.md "Scrub"), as the agent's last scrub batch for the root said; counts and dates only
    scrub_on    date,                                       -- its last scrub run
    scrub_since date,                                       -- its first: before a full pass, files never checked
    scrub_days  int,                                        -- a full pass every this many days
    scrub_oldest date,                                      -- the oldest check of a file still there
    scrub_never bigint,                                     -- files never checked yet
    -- a root its host stopped reporting (ROADMAP 46): every batch names its agent's roots, and one that leaves this
    -- root out marks it; naming it again clears the mark, retire-root ends it
    unreported_since timestamptz,                           -- the first batch since then that left it out
    retired_on  date                                        -- pinakes-ingest retire-root (its files gone that day)
);
CREATE TABLE scans (
    root_id     int REFERENCES roots,
    scan        bigint NOT NULL,
    started_on  date NOT NULL,
    completed   boolean NOT NULL DEFAULT false,
    began_at    timestamptz DEFAULT now(),                  -- its first batch applied: a full scan retires what it
                                                            -- didn't send, files last seen before then
    started_at  timestamptz,                                -- when the agent started it: a new agent state numbers
                                                            -- its scans from 1 again, and this tells them apart
    PRIMARY KEY (root_id, scan)
);
CREATE TABLE ingested (
    host_id     int REFERENCES hosts,
    seq         bigint NOT NULL,
    at          timestamptz NOT NULL DEFAULT now(),
    records     int NOT NULL,
    header_sha256 bytea,                                    -- of the batch's header (outbox.header_digest): a batch
                                                            -- sent again is a duplicate, another of that number is not
    PRIMARY KEY (host_id, seq)
);
-- each agent's last check-in (pinakes-ingest hello) and the protocol of its last batch: which release and protocol
-- it runs, and whether it holds its batches for want of a compatible server (pinakes --versions)
CREATE TABLE checkins (
    host_id     int PRIMARY KEY REFERENCES hosts ON DELETE CASCADE,
    at          timestamptz,                                -- the last hello; NULL: none (an agent before check-in)
    release     int,
    protocol    int,
    min_server_protocol int,
    locked      text,                                       -- NULL: compatible; else which side must update, and why
    batch_at    timestamptz,                                -- the last batch applied, and what its header declared
    batch_release int,
    batch_protocol int,                                     -- 0: none declared (an agent before check-in)
    refused_at  timestamptz,                                -- the last batch refused (protocol or sequence), and why
    refused     text,
    seq_reset_at timestamptz,                               -- the last time the agent's numbering went back (a new
    seq_reset   text                                        -- or restored state), and what was done
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
    by_uid      boolean NOT NULL DEFAULT false,             -- owner = the person the file's uid maps to (the host's uid_map)
    created_by  int REFERENCES people,
    created     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (root_id, folder),
    CONSTRAINT owner_rules_check CHECK (CASE WHEN by_uid THEN owner_person IS NULL AND owner_group IS NULL
                                             ELSE (owner_person IS NULL) <> (owner_group IS NULL) END)
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
    link_dangling boolean,                                  -- its target is missing; NULL: not known
    hidden      boolean NOT NULL DEFAULT false,             -- a dot in its path, or the hidden attribute (Samba)
    unreadable_on date,                                     -- the scrub couldn't read it (DESIGN.md "Scrub"): not a
    unreadable_error text,                                  -- copy until it reads again; the error's name (EIO)
    -- checksum manifests (DESIGN.md "Checksum manifests"): what a SHA256SUMS listing this file says of the agent's
    -- hash, the manifest that said it (wrong over confirmed) and when; on a manifest, its lines' counts
    manifest_verdict text CHECK (manifest_verdict IN ('confirmed', 'wrong')),
    manifest_file_id bigint REFERENCES files ON DELETE SET NULL,
    manifest_on date,
    manifest_counts jsonb
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
CREATE INDEX files_manifest ON files (manifest_file_id) WHERE manifest_file_id IS NOT NULL;
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
    -- mismatch and unreadable: found by the scrub (DESIGN.md "Scrub"), the content changed under an unchanged
    -- size and mtime, or couldn't be read
    kind        text NOT NULL CHECK (kind IN ('new', 'changed', 'moved', 'moved_changed', 'gone', 'mismatch',
                                              'unreadable')),
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
    decided_at  timestamptz,                                -- written only through decide_lineage() (ROADMAP 9)
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

-- A review of a change (ROADMAP 32): a gone file, a move, or what the scrub found (ROADMAP 41), marked intended, or
-- to restore. Written only through mark_changes(); a later change is a new history row, unreviewed. A group token's
-- mark is the group's (ROADMAP 38).
CREATE TABLE review_marks (
    history_id  bigint PRIMARY KEY REFERENCES history ON DELETE CASCADE,
    mark        text NOT NULL CHECK (mark IN ('intended', 'restore')),
    marked_by   int REFERENCES people,
    marked_at   timestamptz NOT NULL DEFAULT now(),
    marked_by_group int REFERENCES groups,
    CHECK ((marked_by IS NULL) <> (marked_by_group IS NULL))
);

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

-- who is asking -----------------------------------------------------------------------------------------------

CREATE FUNCTION current_person() RETURNS int LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('pinakes.person', true), '')::int
$$;

-- The token this transaction acts by (set only by begin_token_call), or NULL: a web session or the CLI.
CREATE FUNCTION current_token() RETURNS int LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('pinakes.token', true), '')::int
$$;

-- The group a group token acts as (ROADMAP 38), or NULL: a person's token, an ops token, a web session or the CLI.
CREATE FUNCTION current_group() RETURNS int LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT group_id FROM tokens WHERE token_id = current_token() AND kind = 'group'
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
          AND 'administrator' = ANY (p.roles)
          AND current_token() IS NULL)                          -- a token never steps up
$$;

-- The ACLs whose files the current person may see: their own, enrolled and shared; all of them in a step-up. Under a
-- group token, the group's: those it owns or is enrolled in, never a member's own (ROADMAP 38).
CREATE FUNCTION visible_acls() RETURNS int[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT CASE WHEN stepped_up() THEN (SELECT coalesce(array_agg(acl_id), '{}') FROM acls)
                WHEN current_group() IS NOT NULL
                    THEN (SELECT coalesce(array_agg(acl_id), '{}') FROM acl_groups WHERE group_id = current_group())
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
    IF current_token() IS NOT NULL THEN RAISE EXCEPTION 'a token never steps up'; END IF;
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

-- The groups the current person is a member of: those they may make group tokens for.
CREATE FUNCTION my_groups() RETURNS TABLE (group_id int, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
    SELECT g.group_id, g.name FROM groups g JOIN group_members m USING (group_id)
    WHERE m.person_id = current_person() ORDER BY g.name
$$;

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
CREATE FUNCTION mark_changes(ids bigint[], what text) RETURNS int
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
CREATE FUNCTION decide_lineage(a bigint, b bigint, what text) RETURNS int
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
-- a file: as the owner or a co-owner of a file with that content (or of that file), as a reader or annotator whom
-- such a file's owner shared its sensitive fields with (sensitive_shares, ROADMAP 16), or as an administrator in a
-- step-up; under a group token, where the group is the owner or a co-owner (ROADMAP 38). Other readers and
-- annotators of a shared folder see a file's other metadata, not these.
CREATE FUNCTION sensitive_visible(content bigint, file bigint) RETURNS boolean
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
-- changes them. Only the owner, a co-owner or an annotator enters: on the web, or under a person's token with its
-- `tag` scope and in its roots (`pinakes tag`, ROADMAP 37), never a group token; a step-up gives no right to.
-- The application checks the values against the registry (extract.check_vals); this checks who, the schema's name
-- and the size. Entering on another person's file is audited for its owners and co-owners. A change is kept, with
-- the values before, as an edit (ROADMAP 62).
CREATE FUNCTION set_file_metadata(fid bigint, sch text, plain jsonb, hidden jsonb) RETURNS void
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

-- Each content's outcome per schema as the current person sees it: the sensitive row where they may see it, else the
-- other (row-level security on extractions decides which they see).
CREATE VIEW extraction_outcomes WITH (security_invoker = true) AS
    SELECT DISTINCT ON (content_id, schema) content_id, schema, outcome, reason, version, at
    FROM extractions ORDER BY content_id, schema, sensitive DESC;

-- What a disk's loss would cost (ROADMAP 42): every present file but a symlink with no readable copy on another
-- host, and whether it has none on another device of its own host either (disk_only: lost with its disk, not only
-- with its machine). Copies are counted as only-here counts them (queries._COPIES): a hard link is no copy, a file
-- the scrub couldn't read is none until it reads again, a copy in any root counts, and a device the catalog doesn't
-- know (dev NULL) is never another disk. Row-level security applies to the caller: a person counts only the copies
-- they can see, so their answer errs toward "at risk", never away from it.
CREATE FUNCTION at_risk()
RETURNS TABLE (file_id bigint, root_id int, host_id int, dev bigint, ino bigint, size bigint, relpath text,
               owner_id int, disk_only boolean)
LANGUAGE sql STABLE SET search_path = pinakes AS $$
    WITH c AS (
        SELECT f.content_id, min(r.host_id) AS min_host, max(r.host_id) AS max_host,
               min(f.dev) AS min_dev, max(f.dev) AS max_dev
        FROM present f JOIN roots r ON r.root_id = f.root_id
        WHERE f.content_id IS NOT NULL AND f.unreadable_on IS NULL AND NOT f.is_symlink
        GROUP BY f.content_id)
    SELECT f.file_id, f.root_id, r.host_id, f.dev, f.ino, f.size, f.relpath, f.owner_id,
           (f.dev IS NULL OR c.min_dev IS NULL OR (c.min_dev = f.dev AND c.max_dev = f.dev)) AS disk_only
    FROM present f JOIN roots r ON r.root_id = f.root_id LEFT JOIN c ON c.content_id = f.content_id
    WHERE NOT f.is_symlink AND (c.min_host IS NULL OR (c.min_host = r.host_id AND c.max_host = r.host_id))
$$;

-- The operator's functions refuse anyone but an operator signed in on the web: never a token, not even an ops one.
CREATE FUNCTION require_operator() RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
BEGIN
    IF current_token() IS NOT NULL OR NOT has_role('operator') THEN
        RAISE EXCEPTION 'only an operator, signed in on the web, sees every root''s totals';
    END IF;
END $$;

-- The operator page (ROADMAP 10): per root, every person's present files and their bytes (an inode once: hard links
-- take their space once), its last complete scan, the oldest check of its scrub, whether its host stopped reporting
-- it or it was retired, and how many scan errors it has and the newest. Counts, sizes and dates: never a path, a
-- file's name, a person or metadata (SECURITY.md "People and roles").
CREATE FUNCTION operator_roots()
RETURNS TABLE (host text, root text, kind text, protected boolean, files bigint, bytes numeric,
               last_complete_on date, scrub_oldest date, unreported_since timestamptz, retired_on date,
               errors bigint, newest_error date)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
#variable_conflict use_column
BEGIN
    PERFORM require_operator();
    RETURN QUERY
    SELECT h.name, r.label, r.kind, r.protected, coalesce(n.files, 0)::bigint, coalesce(n.bytes, 0)::numeric,
           r.last_complete_on, CASE WHEN r.scrub_never > 0 THEN r.scrub_since ELSE r.scrub_oldest END,
           r.unreported_since, r.retired_on, coalesce(e.errors, 0)::bigint, e.newest
    FROM roots r JOIN hosts h ON h.host_id = r.host_id
    LEFT JOIN (SELECT i.root_id, sum(i.links) AS files, sum(i.size) AS bytes
               FROM (SELECT f.root_id, count(*) AS links, max(f.size) AS size FROM files f WHERE f.gone_on IS NULL
                     GROUP BY f.root_id, f.dev, coalesce(f.ino, -f.file_id)) i
               GROUP BY i.root_id) n ON n.root_id = r.root_id
    LEFT JOIN (SELECT s.root_id, count(*) AS errors, max(s.seen_on) AS newest FROM scan_errors s
               GROUP BY s.root_id) e ON e.root_id = r.root_id
    ORDER BY h.name, r.label;
END $$;

-- What a disk's loss would cost, for the operator page (ROADMAP 42): every person's files that at_risk() finds, as
-- totals. scope 'disk': per device of a host (dev NULL: files whose device the catalog doesn't know), the files
-- lost with that disk; scope 'host': per host, the files lost with the machine. The roots are those the files are
-- in. Files and bytes count an inode once. Never a path, a folder, a person or a file's name.
CREATE FUNCTION operator_at_risk()
RETURNS TABLE (scope text, host text, dev bigint, roots text[], files bigint, bytes numeric)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pinakes AS $$
#variable_conflict use_column
BEGIN
    PERFORM require_operator();
    RETURN QUERY
    WITH i AS (SELECT a.host_id, a.dev, min(a.root_id) AS root_id, max(a.size) AS size, bool_or(a.disk_only) AS d
               FROM at_risk() a GROUP BY a.host_id, a.dev, coalesce(a.ino, -a.file_id))
    SELECT x.scope, h.name, x.dev, x.roots, x.files, x.bytes
    FROM (SELECT 'disk'::text AS scope, i.host_id, i.dev, array_agg(DISTINCT r.label ORDER BY r.label) AS roots,
                 count(*) AS files, coalesce(sum(i.size), 0)::numeric AS bytes
          FROM i JOIN roots r ON r.root_id = i.root_id WHERE i.d GROUP BY i.host_id, i.dev
          UNION ALL
          SELECT 'host', i.host_id, NULL, array_agg(DISTINCT r.label ORDER BY r.label), count(*),
                 coalesce(sum(i.size), 0)::numeric
          FROM i JOIN roots r ON r.root_id = i.root_id GROUP BY i.host_id) x
    JOIN hosts h ON h.host_id = x.host_id
    ORDER BY x.scope, x.bytes DESC, h.name, x.dev NULLS LAST;
END $$;

-- row-level security ------------------------------------------------------------------------------------------

ALTER TABLE files ENABLE ROW LEVEL SECURITY;
-- under a token, only the roots it may see (ROADMAP 34). Both functions are wrapped in (SELECT ...) to be evaluated
-- once per query: bare, a large catalog's plan can call visible_acls() per row (ROADMAP 48: 79 s to 12.6 s, 10M files)
CREATE POLICY files_visible ON files FOR SELECT USING (acl_id = ANY ((SELECT visible_acls())::int[])
    AND ((SELECT token_roots()) IS NULL OR root_id = ANY ((SELECT token_roots())::int[])));

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
    AND (NOT sensitive OR author = current_person() OR sensitive_visible(content_id, file_id)));

ALTER TABLE sensitive_shares ENABLE ROW LEVEL SECURITY;   -- no policy: the application reads it through functions

ALTER TABLE extractions ENABLE ROW LEVEL SECURITY;
CREATE POLICY extractions_visible ON extractions FOR SELECT USING (
    EXISTS (SELECT 1 FROM files f WHERE f.content_id = extractions.content_id)
    AND (NOT sensitive OR sensitive_visible(content_id, NULL)));

ALTER TABLE review_marks ENABLE ROW LEVEL SECURITY;
CREATE POLICY review_marks_visible ON review_marks FOR SELECT USING (
    EXISTS (SELECT 1 FROM history h WHERE h.history_id = review_marks.history_id));

-- the catalog's own writes (ROADMAP 62): a person's own and their groups', and of those an item only while its files
-- are visible (under a token, in its roots)
ALTER TABLE edits ENABLE ROW LEVEL SECURITY;
CREATE POLICY edits_mine ON edits FOR SELECT USING (my_edit(person_id, group_id));
ALTER TABLE edit_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY edit_items_visible ON edit_items FOR SELECT USING (
    EXISTS (SELECT 1 FROM edits e WHERE e.edit_id = edit_items.edit_id)
    AND EXISTS (SELECT 1 FROM files f WHERE f.file_id = edit_items.file_id)
    AND (other_file_id IS NULL OR EXISTS (SELECT 1 FROM files f WHERE f.file_id = edit_items.other_file_id)));

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
GRANT SELECT ON checkins TO pinakes_app;                 -- releases and protocols: pinakes --versions
GRANT SELECT (person_id, name, display) ON people TO pinakes_app;
GRANT SELECT ON groups TO pinakes_app;
GRANT EXECUTE ON FUNCTION current_person(), has_role(text), stepped_up(), visible_acls(), begin_step_up(text, int),
                          end_step_up(), audit_view(int[], jsonb), login_material(text), my_totp_secret(),
                          set_my_password(text), set_my_totp(text), my_roles() TO pinakes_app;
GRANT SELECT ON extractions, extraction_outcomes TO pinakes_app;   -- under row-level security (ROADMAP 44)
GRANT SELECT ON review_marks TO pinakes_app;              -- written only through mark_changes()
GRANT EXECUTE ON FUNCTION mark_changes(bigint[], text) TO pinakes_app;
GRANT EXECUTE ON FUNCTION decide_lineage(bigint, bigint, text) TO pinakes_app;   -- ROADMAP 9
GRANT EXECUTE ON FUNCTION sensitive_visible(bigint, bigint) TO pinakes_app;
GRANT EXECUTE ON FUNCTION my_file_role(bigint), set_file_metadata(bigint, text, jsonb, jsonb),
                          sensitive_sharing(bigint), share_sensitive(bigint, int, boolean) TO pinakes_app;   -- 16
GRANT EXECUTE ON FUNCTION at_risk(), operator_roots(), operator_at_risk() TO pinakes_app;   -- ROADMAP 10, 42
GRANT EXECUTE ON FUNCTION current_token(), token_roots(), begin_token_call(bytea, text),
                          make_token(text, bytea, text[], int[], int, int), my_tokens(), revoke_token(int),
                          begin_cli_session(bytea, int, text), end_cli_session(), current_group(), my_groups()
                          TO pinakes_app;
GRANT SELECT ON edits, edit_items TO pinakes_app;           -- written only through the functions that write (62)
GRANT EXECUTE ON FUNCTION my_edit(int, int), undo_edits(bigint[]) TO pinakes_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA pinakes TO pinakes_ingest;
REVOKE UPDATE, DELETE ON audit, edits, edit_items FROM pinakes_ingest;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA pinakes TO pinakes_ingest;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pinakes TO pinakes_ingest;
