-- Upgrade a catalog built before lineage decisions (ROADMAP 9); release 10. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f lineage-decisions.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

ALTER TABLE lineage ADD COLUMN decided_at timestamptz;     -- written only through decide_lineage() (ROADMAP 9)

-- Decide whether two files are relatives (ROADMAP 9): 'confirmed', 'rejected', or NULL to clear the decision. It
-- applies to every edge between the two, either way round, except one of the same content (certain: the hash
-- decides). A decision outranks every heuristic: a confirmed edge survives tidy, and the ingester never suggests a
-- rejected pair again. Only the owner or a co-owner of an edge's descendant (its to_file) decides it, and only when
-- both ends are visible to them; an administrator in a step-up decides others'. Under a token, only with its review
-- scope and in its roots; never under a group token. A decision that touches another person's file (either end) is
-- audited for its owners and co-owners. Returns how many edges were decided or cleared.
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
        SELECT l.from_file_id, l.to_file_id, l.kind, ff.acl_id AS from_acl, ft.acl_id AS to_acl
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
        RETURNING e.from_acl, e.to_acl)
    SELECT count(*), array_agg(d.from_acl) || array_agg(d.to_acl) INTO n, acls FROM d;
    SELECT array_agg(DISTINCT am.person_id ORDER BY am.person_id) INTO affected
    FROM acl_members am WHERE am.acl_id = ANY (acls) AND am.person_id <> me AND am.role IN ('owner', 'co-owner');
    IF n > 0 AND affected IS NOT NULL THEN
        INSERT INTO audit (actor, action, affects, detail)
        VALUES (me, 'lineage', affected, jsonb_build_object('decision', coalesce(what, 'cleared'), 'edges', n));
    END IF;
    RETURN n;
END $$;

REVOKE ALL ON FUNCTION decide_lineage(bigint, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION decide_lineage(bigint, bigint, text) TO pinakes_app, pinakes_ingest;
