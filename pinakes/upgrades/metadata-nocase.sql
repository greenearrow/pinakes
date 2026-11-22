-- Upgrade a catalog built before ROADMAP 70 (text matched without case); release 14. Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f metadata-nocase.sql
-- then `pinakes-ingest setup`, which makes an md_SCHEMA_FIELD_ci index for each exact-indexed text field and drops
-- the md_SCHEMA_FIELD_eq ones no identity field wants. It replaces enroll_metadata_indexes() (metadata-indexes.sql,
-- release 1), which gains the `ci` kind: lower(btrim(value)), what `pinakes meta SCHEMA.FIELD=VALUE` matches on a
-- text field. A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

CREATE OR REPLACE FUNCTION enroll_metadata_indexes(wanted jsonb) RETURNS jsonb
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
            WHEN 'ci'   THEN format('btree ((lower(btrim(vals ->> %L))))', f)    -- text without case (ROADMAP 70)
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
