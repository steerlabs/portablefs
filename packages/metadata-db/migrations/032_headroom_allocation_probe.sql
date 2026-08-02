-- 032_headroom_allocation_probe: readiness that proves an ALLOCATION.
--
-- WHAT 030 GOT WRONG. 030 replaced a read-only readiness probe with a
-- durable WRITE probe: a fixed ring of 16 rows, each updated in place with a
-- fresh 4 KiB incompressible PLAIN filler on a fillfactor-100 page. Its own
-- header concedes the hole: such an update "must take a free page from the
-- FSM or EXTEND the relation". Only the second arm proves headroom, and
-- after the very first vacuum the first arm is the one that runs forever.
--
--   Measured on postgres:18, probe ring in a 64 MiB tablespace filled to
--   100% (WAL on a separate, writable volume):
--     * 400 fixed-ring probes grew the relation to 400 pages;
--     * VACUUM turned the dead versions into FSM-reusable pages;
--     * 40 further probes on the FULL tablespace ALL SUCCEEDED and the
--       relation grew by exactly 0 bytes — no allocation whatsoever;
--     * a journal-class INSERT in the same tablespace, in the same session,
--       failed 53100 "could not extend file ... No space left on device".
--   /readyz was green while the control store could not accept a byte. That
--   is the SAME class of lie the 030 incident shipped, one layer down.
--
-- The one-time full-tablespace test that blessed 030 only proved a state in
-- which the probe relation happened to have no reusable page. Repeated
-- fixed-ring operation destroys that premise: it is a steady state of
-- non-HOT updates, dead tuples and vacuum, i.e. a machine for MANUFACTURING
-- reusable pages.
--
-- WHAT PROVES HEADROOM. Exactly one thing: an allocation that CANNOT be
-- satisfied from space the relation already holds. This migration adds a
-- probe relation with three properties that make every probe extend it:
--
--   1. INSERT-ONLY. It is never UPDATEd and never DELETEd, so it never has a
--      dead tuple, so vacuum can never free one byte of it and the FSM can
--      never be handed a reusable page. (This is why autovacuum needs no
--      fighting and anti-wraparound vacuum is harmless: there is nothing to
--      reclaim.)
--   2. A TUPLE LARGER THAN THE LARGEST HOLE. The filler is 6000
--      incompressible bytes stored PLAIN, so a row occupies ~6 KiB of an
--      8 KiB page and NO page that already holds one can ever take another.
--      Every insert therefore extends the relation by at least one page.
--   3. A SELF-CHECK, not a belief. The probe measures pg_relation_size()
--      before and after and RAISES 53100 if the file did not grow. A future
--      change that shrinks the filler, drops the insert-only discipline, or
--      re-introduces FSM reuse turns into a loud readiness failure instead
--      of a silent regression to 030's behaviour.
--
-- BOUNDING IT HONESTLY. An append-only probe must be capped, and a cap means
-- releasing space, and released space could be re-consumed by later probes —
-- which is precisely the recycling the fix exists to eliminate. The reset is
-- therefore built so that it CANNOT hand the probe free space:
--
--     TRUNCATE (the old file is only unlinked at COMMIT)
--     then refill FLOOR pages IN THE SAME TRANSACTION
--
-- While the refill runs, the old CAP pages are still on disk, so the refill
-- must allocate FLOOR pages of GENUINELY free filesystem space or fail. On a
-- full volume the reset fails, the transaction rolls back, the old file
-- survives, and readiness goes red — it can never truncate its way to a
-- green answer. The only masking window this design has is bounded by CAP
-- (1 MiB): a shortfall smaller than the probe's own footprint. 030's window
-- was unbounded in both bytes and time.
--
-- COST PER READINESS CALL. One ~6 KiB heap insert, one page extension, one
-- WAL record, two pg_relation_size() stats — plus, once every (CAP-FLOOR)
-- probes (~120), one TRUNCATE and a 64 KiB refill. Callers keep the round 16
-- single-flight + TTL cache, so this is per readiness CACHE MISS, not per
-- HTTP request.
--
-- WHAT IS KEPT. The 030 ring UPDATE stays, inside the new probe, as what the
-- audit says it may honestly be: a transaction / WAL / row-lock health check
-- under the same pfm.require_durable_primary() admission. It no longer
-- pretends to assert headroom. The new functions are separately named so a
-- binary from this build FAILS CLOSED against a store that lacks them
-- (the manager's lineage predicate and the metadata lineage check both name
-- them) instead of silently getting the weaker probe.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='031_journal_reclamation'
  ) THEN
    RAISE EXCEPTION '032 preflight: the 031 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '033%') THEN
    RAISE EXCEPTION '032 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('public.portablefs_control_write_probes') IS NULL
     OR to_regclass('pfm.control_write_probes') IS NULL
     OR to_regprocedure('pfm.control_write_probe(int)') IS NULL THEN
    RAISE EXCEPTION '032 preflight: the 030 write-probe surface is missing';
  END IF;
  IF to_regclass('public.portablefs_control_headroom_probes') IS NOT NULL THEN
    RAISE EXCEPTION '032 preflight: the headroom probe relation already exists';
  END IF;
END;
$preflight$;

-- ── volume-api arm (public schema, owner principal) ─────────────────────────

-- INSERT-ONLY by contract. No primary key and no index at all: an index
-- would be a second relation with its own free-space behaviour, and nothing
-- ever reads this table by key. The rows are evidence that an allocation
-- happened, not data.
CREATE TABLE public.portablefs_control_headroom_probes (
  probed_at_ms BIGINT NOT NULL,
  probe_key    TEXT   NOT NULL,
  filler       BYTEA  NOT NULL
) WITH (fillfactor = 100, autovacuum_enabled = false);
ALTER TABLE public.portablefs_control_headroom_probes
  ALTER COLUMN filler SET STORAGE PLAIN;

COMMENT ON TABLE public.portablefs_control_headroom_probes IS
  'Readiness ALLOCATION proof. Insert-only (never updated, never deleted, so vacuum can never hand its pages back to the FSM); one ~6 KiB PLAIN row per 8 KiB page, so every probe must extend the relation. Bounded by a TRUNCATE+refill reset whose refill is allocated before the old file is released.';

-- ── manager arm (pfm, manager principal) ────────────────────────────────────

SET LOCAL ROLE portablefs_manager_owner;

CREATE TABLE pfm.control_headroom_probes (
  probed_at_ms BIGINT NOT NULL,
  probe_key    TEXT   NOT NULL,
  filler       BYTEA  NOT NULL
) WITH (fillfactor = 100, autovacuum_enabled = false);
ALTER TABLE pfm.control_headroom_probes ALTER COLUMN filler SET STORAGE PLAIN;

-- The three constants of the design, as functions so drift is impossible
-- between the two arms and so a reader can find them by name.
--
-- 6000 bytes: comfortably more than half of an 8 KiB page's ~8160 usable
-- bytes, so two rows can never share a page and no partially-filled page can
-- ever accept another row. Stored PLAIN, so no TOAST and no compression can
-- shrink it back under the threshold.
CREATE FUNCTION pfm.control_headroom_probe_bytes() RETURNS INT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT 6000 $$;

-- 128 pages = 1 MiB. The relation's ceiling, and therefore the exact upper
-- bound on how much free space a reset can ever hand back.
CREATE FUNCTION pfm.control_headroom_probe_cap_pages() RETURNS INT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT 128 $$;

-- 8 pages = 64 KiB. What a reset must allocate from genuinely free space,
-- while the old file it is replacing is still on disk.
CREATE FUNCTION pfm.control_headroom_probe_floor_pages() RETURNS INT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT 8 $$;

-- Incompressible filler. VOLATILE and re-derived per row: identical bytes
-- could be optimized away and would stop proving anything.
CREATE FUNCTION pfm.control_headroom_filler() RETURNS BYTEA
LANGUAGE sql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT decode(string_agg(md5(random()::TEXT || g::TEXT), ''), 'hex')
    FROM generate_series(1, 375) g
$$;

-- The headroom probe. Two proofs, one transaction, one round trip:
--
--   (1) TRANSACTION / WAL / ROW-LOCK health — the 030 ring update, under the
--       same pfm.require_durable_primary() admission a lease write takes.
--       This is all a fixed-row update was ever entitled to assert.
--   (2) ALLOCATION HEADROOM — an insert that provably extends the relation,
--       verified by measuring the file.
--
-- Fail-closed everywhere: a missing durability quorum, a lock it cannot take
-- promptly, an ENOSPC on the extension, or an extension that did not happen
-- all raise, and readiness has nothing to report but "not writable".
CREATE FUNCTION pfm.control_headroom_probe(p_slot INT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_slot   INT := abs(COALESCE(p_slot, 0)) % pfm.control_write_probe_slots();
  v_key    TEXT := 'readyz:' || v_slot::TEXT;
  v_cap    BIGINT := pfm.control_headroom_probe_cap_pages()::BIGINT * 8192;
  v_floor  INT := pfm.control_headroom_probe_floor_pages();
  v_now    BIGINT;
  v_seq    BIGINT;
  v_before BIGINT;
  v_after  BIGINT;
  v_reset  BOOLEAN := FALSE;
BEGIN
  PERFORM pfm.require_durable_primary();
  SET LOCAL lock_timeout = '1500ms';
  SET LOCAL synchronous_commit = 'on';
  v_now := pfm.now_ms();

  -- (1) the 030 durable-transition probe, unchanged in kind.
  INSERT INTO pfm.control_write_probes AS p (probe_key, probe_seq, probed_at_ms, filler)
  VALUES (v_key, 1, v_now, pfm.control_write_probe_filler())
  ON CONFLICT (probe_key) DO UPDATE
    SET probe_seq = p.probe_seq + 1,
        probed_at_ms = EXCLUDED.probed_at_ms,
        filler = EXCLUDED.filler
  RETURNING probe_seq INTO v_seq;

  -- (2) the allocation proof.
  v_before := pg_catalog.pg_relation_size('pfm.control_headroom_probes');
  IF v_before >= v_cap THEN
    -- Bounded reset. TRUNCATE only marks the old relfilenode for unlink AT
    -- COMMIT, so the refill below competes with it for space: on a full
    -- volume the refill raises 53100, this transaction rolls back, and the
    -- probe can never truncate its way to a green answer.
    BEGIN
      TRUNCATE pfm.control_headroom_probes;
      v_reset := TRUE;
    EXCEPTION WHEN lock_not_available THEN
      -- Another replica is resetting right now. Do NOT report an outage for
      -- a lock convoy on a healthy store: skip the reset and let the plain
      -- extension below still prove headroom. The cap is soft by exactly
      -- this much and is re-attempted on the next probe; the hard ceiling
      -- below is what stays unforgiving.
      IF v_before >= v_cap * 16 THEN
        RAISE EXCEPTION
          'readiness headroom probe cannot reset its relation (% bytes, hard ceiling %)',
          v_before, v_cap * 16 USING ERRCODE = '55P03';
      END IF;
    END;
  END IF;

  IF v_reset THEN
    INSERT INTO pfm.control_headroom_probes (probed_at_ms, probe_key, filler)
      SELECT v_now, v_key, pfm.control_headroom_filler()
        FROM generate_series(1, v_floor);
    v_after := pg_catalog.pg_relation_size('pfm.control_headroom_probes');
    IF v_after < v_floor::BIGINT * 8192 THEN
      RAISE EXCEPTION
        'readiness headroom probe refill allocated % bytes, expected at least %',
        v_after, v_floor::BIGINT * 8192 USING ERRCODE = '53100';
    END IF;
  ELSE
    INSERT INTO pfm.control_headroom_probes (probed_at_ms, probe_key, filler)
    VALUES (v_now, v_key, pfm.control_headroom_filler());
    v_after := pg_catalog.pg_relation_size('pfm.control_headroom_probes');
    IF v_after <= v_before THEN
      -- The relation did not grow: this probe was satisfied from space the
      -- relation already held, which is the 030 defect exactly. It proves
      -- nothing about headroom, so it must not be reported as readiness.
      RAISE EXCEPTION
        'readiness headroom probe did not extend its relation (% bytes before and after)',
        v_before USING ERRCODE = '53100';
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'ok', TRUE,
    'slot', v_slot,
    'probeSeq', v_seq::TEXT,
    -- Bytes this probe took from the filesystem and did not already hold.
    'allocatedBytes', GREATEST(v_after - CASE WHEN v_reset THEN 0 ELSE v_before END, 0)::TEXT,
    'probeRelationBytes', v_after::TEXT,
    'reset', v_reset,
    'dbTimeMs', v_now::TEXT
  );
END;
$$;

RESET ROLE;

-- The public twin for the volume-api, which runs as the migration/owner
-- principal (so SECURITY INVOKER, and TRUNCATE is its own table's).
-- Byte-for-byte the same proof; the manager's durability admission is a pfm
-- boundary and has no public-schema equivalent.
CREATE FUNCTION public.portablefs_control_headroom_probe(p_slot INT) RETURNS JSONB
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_slot   INT := abs(COALESCE(p_slot, 0)) % 16;
  v_key    TEXT := 'readyz:' || v_slot::TEXT;
  v_cap    BIGINT := 128::BIGINT * 8192;
  v_floor  INT := 8;
  v_now    BIGINT := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_seq    BIGINT;
  v_before BIGINT;
  v_after  BIGINT;
  v_reset  BOOLEAN := FALSE;
  v_filler BYTEA;
BEGIN
  SET LOCAL lock_timeout = '1500ms';
  SET LOCAL synchronous_commit = 'on';

  -- (1) transaction / WAL / row-lock health: the 030 ring update.
  INSERT INTO public.portablefs_control_write_probes AS p
    (probe_key, probe_seq, probed_at_ms, filler)
  VALUES (v_key, 1, v_now,
          (SELECT decode(string_agg(md5(random()::TEXT || g::TEXT), ''), 'hex')
             FROM generate_series(1, 256) g))
  ON CONFLICT (probe_key) DO UPDATE
    SET probe_seq = p.probe_seq + 1,
        probed_at_ms = EXCLUDED.probed_at_ms,
        filler = EXCLUDED.filler
  RETURNING probe_seq INTO v_seq;

  -- (2) allocation headroom.
  v_before := pg_catalog.pg_relation_size('public.portablefs_control_headroom_probes');
  IF v_before >= v_cap THEN
    BEGIN
      TRUNCATE public.portablefs_control_headroom_probes;
      v_reset := TRUE;
    EXCEPTION WHEN lock_not_available THEN
      IF v_before >= v_cap * 16 THEN
        RAISE EXCEPTION
          'readiness headroom probe cannot reset its relation (% bytes, hard ceiling %)',
          v_before, v_cap * 16 USING ERRCODE = '55P03';
      END IF;
    END;
  END IF;

  IF v_reset THEN
    INSERT INTO public.portablefs_control_headroom_probes (probed_at_ms, probe_key, filler)
      SELECT v_now, v_key,
             (SELECT decode(string_agg(md5(random()::TEXT || g::TEXT || s::TEXT), ''), 'hex')
                FROM generate_series(1, 375) g)
        FROM generate_series(1, v_floor) s;
    v_after := pg_catalog.pg_relation_size('public.portablefs_control_headroom_probes');
    IF v_after < v_floor::BIGINT * 8192 THEN
      RAISE EXCEPTION
        'readiness headroom probe refill allocated % bytes, expected at least %',
        v_after, v_floor::BIGINT * 8192 USING ERRCODE = '53100';
    END IF;
  ELSE
    SELECT decode(string_agg(md5(random()::TEXT || g::TEXT), ''), 'hex') INTO v_filler
      FROM generate_series(1, 375) g;
    INSERT INTO public.portablefs_control_headroom_probes (probed_at_ms, probe_key, filler)
    VALUES (v_now, v_key, v_filler);
    v_after := pg_catalog.pg_relation_size('public.portablefs_control_headroom_probes');
    IF v_after <= v_before THEN
      RAISE EXCEPTION
        'readiness headroom probe did not extend its relation (% bytes before and after)',
        v_before USING ERRCODE = '53100';
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'ok', TRUE,
    'slot', v_slot,
    'probeSeq', v_seq::TEXT,
    'allocatedBytes', GREATEST(v_after - CASE WHEN v_reset THEN 0 ELSE v_before END, 0)::TEXT,
    'probeRelationBytes', v_after::TEXT,
    'reset', v_reset,
    'dbTimeMs', v_now::TEXT
  );
END;
$$;

-- ── Privileges ──────────────────────────────────────────────────────────────

REVOKE ALL ON FUNCTION
  pfm.control_headroom_probe_bytes(),
  pfm.control_headroom_probe_cap_pages(),
  pfm.control_headroom_probe_floor_pages(),
  pfm.control_headroom_filler(),
  pfm.control_headroom_probe(INT)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.portablefs_control_headroom_probe(INT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION pfm.control_headroom_probe(INT) TO portablefs_manager;

-- ── Postconditions ──────────────────────────────────────────────────────────

DO $post$
DECLARE
  v_rec RECORD;
  v_def TEXT;
  v_size BIGINT;
BEGIN
  IF to_regclass('public.portablefs_control_headroom_probes') IS NULL
     OR to_regclass('pfm.control_headroom_probes') IS NULL THEN
    RAISE EXCEPTION '032 postcondition: a headroom probe relation is absent';
  END IF;

  -- INSERT-ONLY is the property that keeps the FSM empty. Assert it the only
  -- way SQL can: no UPDATE and no DELETE against the probe relation may
  -- appear in either probe body.
  FOR v_rec IN
    SELECT 'pfm.control_headroom_probe(int)' AS sig,
           'pfm.control_headroom_probes' AS rel
    UNION ALL
    SELECT 'public.portablefs_control_headroom_probe(int)',
           'public.portablefs_control_headroom_probes'
  LOOP
    v_def := pg_get_functiondef(to_regprocedure(v_rec.sig));
    IF position('UPDATE ' || v_rec.rel IN v_def) > 0
       OR position('DELETE FROM ' || v_rec.rel IN v_def) > 0 THEN
      RAISE EXCEPTION
        '032 postcondition: % updates or deletes its probe relation; dead tuples would restore FSM reuse',
        v_rec.sig;
    END IF;
    IF position('pg_relation_size' IN v_def) = 0 THEN
      RAISE EXCEPTION
        '032 postcondition: % no longer measures the allocation it claims to prove', v_rec.sig;
    END IF;
    IF position('did not extend its relation' IN v_def) = 0 THEN
      RAISE EXCEPTION
        '032 postcondition: % lost the fail-closed extension self-check', v_rec.sig;
    END IF;
  END LOOP;

  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, p.proconfig AS config,
           pg_get_userbyid(p.proowner) AS owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'pfm'
       AND p.proname IN ('control_headroom_probe', 'control_headroom_filler',
                         'control_headroom_probe_bytes',
                         'control_headroom_probe_cap_pages',
                         'control_headroom_probe_floor_pages')
  LOOP
    IF v_rec.owner <> 'portablefs_manager_owner'
       OR array_to_string(v_rec.config, ',') NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '032 postcondition: pfm.% owner/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '032 postcondition: PUBLIC can execute pfm.%', v_rec.proname;
    END IF;
  END LOOP;

  IF has_function_privilege(
       'public', 'public.portablefs_control_headroom_probe(int)', 'EXECUTE') THEN
    RAISE EXCEPTION '032 postcondition: PUBLIC can execute the volume-api headroom probe';
  END IF;
  IF NOT has_function_privilege(
       'portablefs_manager', 'pfm.control_headroom_probe(int)', 'EXECUTE') THEN
    RAISE EXCEPTION '032 postcondition: the manager role cannot execute the headroom probe';
  END IF;

  -- The durability admission a lease write takes must still gate the probe.
  IF position('require_durable_primary' IN pg_get_functiondef(
       to_regprocedure('pfm.control_headroom_probe(int)'))) = 0 THEN
    RAISE EXCEPTION '032 postcondition: the headroom probe dropped durability admission';
  END IF;

  -- The row must be too big to share a page. Anything at or below half of a
  -- page would let two rows co-exist and the extension guarantee would go.
  IF pfm.control_headroom_probe_bytes() <= 4096 THEN
    RAISE EXCEPTION
      '032 postcondition: the probe filler (% bytes) is small enough for two rows per page',
      pfm.control_headroom_probe_bytes();
  END IF;
  IF pfm.control_headroom_probe_floor_pages() >= pfm.control_headroom_probe_cap_pages() THEN
    RAISE EXCEPTION '032 postcondition: the reset floor is not below the cap';
  END IF;
  -- The declared size and the bytes actually produced must be the same
  -- number, or the guarantee above is asserted about the wrong thing.
  IF length(pfm.control_headroom_filler()) <> pfm.control_headroom_probe_bytes() THEN
    RAISE EXCEPTION
      '032 postcondition: the filler produces % bytes, not the declared %',
      length(pfm.control_headroom_filler()), pfm.control_headroom_probe_bytes();
  END IF;

  -- END-TO-END: two consecutive probes must each grow the relation. This runs
  -- at migration time, so a store that cannot allocate two pages never
  -- records a 032 receipt.
  PERFORM public.portablefs_control_headroom_probe(0);
  v_size := pg_catalog.pg_relation_size('public.portablefs_control_headroom_probes');
  PERFORM public.portablefs_control_headroom_probe(0);
  IF pg_catalog.pg_relation_size('public.portablefs_control_headroom_probes') <= v_size THEN
    RAISE EXCEPTION
      '032 postcondition: a second probe did not extend the relation (% bytes)', v_size;
  END IF;

  -- Lineage: 033 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '033%') THEN
    RAISE EXCEPTION '032 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
