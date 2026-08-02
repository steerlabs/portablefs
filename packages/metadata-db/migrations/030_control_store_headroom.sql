-- 030_control_store_headroom: readiness that can actually fail.
--
-- INCIDENT THIS EXISTS FOR: the control-store Postgres filled its disk and
-- every lease write failed, yet both readiness probes stayed green and the
-- deploy gate (railway healthcheckPath=/readyz) declared the release healthy.
-- Both probes were READ-ONLY:
--   * pfm lineage:  SELECT to_regproc('pfm.manager_renew') IS NOT NULL
--   * metadata:     SELECT count(*) FROM public.portablefs_migrations ...
-- An out-of-disk primary answers BOTH perfectly. Catalog reads take no row
-- lock, allocate no tuple, extend no relation, and write no WAL, so a
-- read-only probe can never distinguish "the control store is serving" from
-- "the control store cannot accept another byte". That distinction IS
-- readiness for a control plane whose only job is durable transitions.
--
-- This migration adds the two primitives a read-only probe cannot provide.
--
-- (1) DURABLE WRITE PROBE. pfm.control_write_probe() performs the SAME class
--     of operation a lease write performs: the same SECURITY DEFINER
--     boundary, the same pfm.require_durable_primary() admission, a real
--     heap tuple version, a real WAL record, and a real synchronous commit.
--     It is not a proxy for write capability — it IS a write. When it
--     returns, this control store accepted a durable transition moments ago;
--     when the disk is full it fails with the same 53100 / PANIC-adjacent
--     failure that broke the lease writes, because it is the same path.
--     Bounded: exactly ONE row per ring slot, updated in place forever. The
--     ring (pfm.control_write_probe_slots slots) exists so N manager
--     replicas do not serialize every readiness check on one row lock — a
--     lock convoy on a healthy store must never read as an outage.
--
-- (2) USAGE ACCOUNTING. Core PostgreSQL exposes no free-space primitive, so
--     honest headroom cannot be measured from inside the database. What CAN
--     be measured exactly is CONSUMPTION: pfm.control_store_usage() reports
--     total database bytes plus per-plane bytes (journal, manager control,
--     history) so an operator watches the curve that filled the disk twice
--     instead of discovering it at 100%. Callers compare it against a
--     deployment-configured capacity budget; the database never guesses one.
--
-- The public-schema twin (public.portablefs_control_write_probes) serves the
-- volume-api, which runs as the migration/owner principal and therefore
-- writes it directly rather than through a SECURITY DEFINER function.

-- ── volume-api write probe (public schema, owner principal) ─────────────────

-- WHY THE FILLER COLUMN. A one-word UPDATE can be satisfied by a HOT update
-- inside the row's existing page: no relation extension, so on a cluster
-- whose DATA volume is full (but whose WAL volume is not) it could still
-- succeed while a growing table's insert fails with 53100. A ~4 KiB
-- incompressible payload stored PLAIN means each new row version needs a
-- page with 4 KiB free; with fillfactor 100 the old page has none, so the
-- update must take a free page from the FSM or EXTEND the relation. On a
-- full disk that extension is exactly the "could not extend file ... No
-- space left on device" the failing lease writes hit. The probe therefore
-- exercises the same failure, not a weaker cousin of it.
CREATE TABLE public.portablefs_control_write_probes (
  probe_key    TEXT PRIMARY KEY,
  probe_seq    BIGINT NOT NULL,
  probed_at_ms BIGINT NOT NULL,
  filler       BYTEA NOT NULL
) WITH (fillfactor = 100);
ALTER TABLE public.portablefs_control_write_probes ALTER COLUMN filler SET STORAGE PLAIN;

COMMENT ON TABLE public.portablefs_control_write_probes IS
  'Readiness write probe target. Bounded to one row per ring slot; rows are updated in place and never accumulate.';

-- ── pfm write probe + usage accounting (manager principal) ──────────────────

SET LOCAL ROLE portablefs_manager_owner;

CREATE TABLE pfm.control_write_probes (
  probe_key    TEXT PRIMARY KEY,
  probe_seq    BIGINT NOT NULL,
  probed_at_ms BIGINT NOT NULL,
  filler       BYTEA NOT NULL
) WITH (fillfactor = 100);
ALTER TABLE pfm.control_write_probes ALTER COLUMN filler SET STORAGE PLAIN;

-- The bounded slot count. A caller picks one slot per process; the table can
-- therefore never exceed this many rows no matter how many managers, how
-- many restarts, or how long the deployment runs.
CREATE FUNCTION pfm.control_write_probe_slots() RETURNS INT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT 16 $$;

-- 4096 incompressible bytes (256 md5 digests of independent random values,
-- hex-decoded). Deliberately VOLATILE: a probe that wrote the same bytes
-- twice could be optimized into a no-op update and would stop proving
-- anything.
CREATE FUNCTION pfm.control_write_probe_filler() RETURNS BYTEA
LANGUAGE sql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT decode(string_agg(md5(random()::TEXT || g::TEXT), ''), 'hex')
    FROM generate_series(1, 256) g
$$;

-- The durable write probe. p_slot is reduced into the bounded ring, so a
-- hostile or buggy caller cannot grow the table.
--
-- Ordering matches every other pfm mutation: durability admission first, then
-- the clock sample, then the single write. lock_timeout is transaction-local
-- and small: a probe that cannot take the row lock promptly must report
-- unready rather than queue behind a stuck writer for the caller's whole
-- deadline.
CREATE FUNCTION pfm.control_write_probe(p_slot INT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_slot INT := abs(COALESCE(p_slot, 0)) % pfm.control_write_probe_slots();
  v_key  TEXT := 'readyz:' || v_slot::TEXT;
  v_now  BIGINT;
  v_seq  BIGINT;
BEGIN
  -- The probe must be exactly as admissible as a lease write; a store that
  -- would refuse a lease write is NOT ready, and PF015 says so by name.
  PERFORM pfm.require_durable_primary();
  SET LOCAL lock_timeout = '1500ms';
  SET LOCAL synchronous_commit = 'on';
  v_now := pfm.now_ms();
  -- 4 KiB of INCOMPRESSIBLE bytes: a compressible filler would be squeezed
  -- back down and the page would stop being the constraint. Fresh every
  -- probe so the new row version can never be a no-op.
  INSERT INTO pfm.control_write_probes AS p (probe_key, probe_seq, probed_at_ms, filler)
  VALUES (v_key, 1, v_now, pfm.control_write_probe_filler())
  ON CONFLICT (probe_key) DO UPDATE
    SET probe_seq = p.probe_seq + 1,
        probed_at_ms = EXCLUDED.probed_at_ms,
        filler = EXCLUDED.filler
  RETURNING probe_seq INTO v_seq;
  RETURN jsonb_build_object(
    'ok', TRUE,
    'slot', v_slot,
    'probeSeq', v_seq::TEXT,
    'dbTimeMs', v_now::TEXT
  );
END;
$$;

-- Control-store consumption. Every value is an exact measurement; nothing is
-- inferred and no capacity is assumed. Sizes are canonical decimal strings
-- (they are BIGINT bytes and routinely exceed the JS safe integer once a
-- deployment is large enough to care).
CREATE FUNCTION pfm.control_store_usage() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_database BIGINT;
  v_planes   JSONB := '{}'::JSONB;
BEGIN
  v_database := pg_catalog.pg_database_size(current_database());
  SELECT COALESCE(
           jsonb_object_agg(plane, total::TEXT),
           '{}'::JSONB)
    INTO v_planes
    FROM (
      SELECT n.nspname AS plane,
             SUM(pg_catalog.pg_total_relation_size(c.oid))::BIGINT AS total
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname IN ('pfj', 'pfm', 'pfh', 'public')
         AND c.relkind IN ('r', 'm', 'p')
       GROUP BY n.nspname
    ) s;
  RETURN jsonb_build_object(
    'databaseBytes', v_database::TEXT,
    'planeBytes', v_planes,
    'dbTimeMs', pfm.now_ms()::TEXT
  );
END;
$$;

RESET ROLE;

-- ── Privileges ──────────────────────────────────────────────────────────────

REVOKE ALL ON FUNCTION
  pfm.control_write_probe_slots(),
  pfm.control_write_probe_filler(),
  pfm.control_write_probe(INT),
  pfm.control_store_usage()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  pfm.control_write_probe_slots(),
  pfm.control_write_probe(INT),
  pfm.control_store_usage()
TO portablefs_manager;

-- ── Postconditions ──────────────────────────────────────────────────────────

DO $post$
DECLARE
  v_rec RECORD;
BEGIN
  IF to_regclass('public.portablefs_control_write_probes') IS NULL THEN
    RAISE EXCEPTION '030 postcondition: the public write probe table is absent';
  END IF;
  IF to_regclass('pfm.control_write_probes') IS NULL THEN
    RAISE EXCEPTION '030 postcondition: the pfm write probe table is absent';
  END IF;
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, p.proconfig AS config,
           pg_get_userbyid(p.proowner) AS owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'pfm'
       AND p.proname IN ('control_write_probe', 'control_store_usage',
                         'control_write_probe_slots', 'control_write_probe_filler')
  LOOP
    IF v_rec.owner <> 'portablefs_manager_owner'
       OR array_to_string(v_rec.config, ',') NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '030 postcondition: pfm.% owner/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '030 postcondition: PUBLIC can execute pfm.%', v_rec.proname;
    END IF;
  END LOOP;
  -- The probe is a WRITE. A regression that turns it back into a catalog
  -- read is exactly the incident this migration exists for, so assert the
  -- mutation is still in the body.
  IF position('INSERT INTO pfm.control_write_probes' IN pg_get_functiondef(
       to_regprocedure('pfm.control_write_probe(int)'))) = 0
     OR position('require_durable_primary' IN pg_get_functiondef(
       to_regprocedure('pfm.control_write_probe(int)'))) = 0 THEN
    RAISE EXCEPTION '030 postcondition: the write probe no longer writes under durability admission';
  END IF;
  IF NOT has_function_privilege(
       'portablefs_manager', 'pfm.control_write_probe(int)', 'EXECUTE') THEN
    RAISE EXCEPTION '030 postcondition: the manager role cannot execute the write probe';
  END IF;
  -- Lineage: 031 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '031%') THEN
    RAISE EXCEPTION '030 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
