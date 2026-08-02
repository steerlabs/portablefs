-- 031_journal_reclamation: journal records that can actually be released.
--
-- INCIDENT THIS EXISTS FOR: this deployment filled its production control
-- store TWICE (5 GB, then 20 GB) purely with test-branch journal data, and
-- both times the only cure was manual SQL. The reason is exact and provable:
--
--   * pfj.journal_records rows are NEVER physically deleted. Adoption
--     (pfj.history_adopt_base, 013) advances base_seq and subtracts the
--     backlog counters in O(1) — a LOGICAL trim. The BYTEA payloads below
--     the base stay in the table forever.
--   * pfj.journal_physical_trim (009) is the only DELETE against that table
--     in the entire repository. It has no GRANT, no caller in TS or Go, and
--     for pfj3 generations it is structurally blocked by the freeze trigger
--     ("trim stays fail-closed in 013"). physical_trimmed_seq is therefore
--     always 0 in production.
--   * `portablefs rm <volume>` -> DELETE /v1/volumes/:id sets
--     volumes.retired_at and runs pfh.volume_retire_cleanup. 021 says so in
--     its own header: "this migration deletes nothing". A retired volume's
--     journal survives it completely.
--   * 028's retention policy governs history OBJECTS in the blob store. It
--     has no effect on Postgres journal rows.
--
-- 013 froze pfj3 trim deliberately, and named its preconditions: "until
-- recovery anchors, restore verification, serving pins, and the signed drill
-- policy prove safety end to end." Those landed: 028 gave retention its
-- rooted set and serving pins, and 029 made EVERY ready cut materialize a
-- verified recovery anchor (013's own CHECK already forces
-- state='ready' => recovery_anchor_id IS NOT NULL). So this migration
-- unfreezes trim the way 013 unfroze the base advance: not with a setting,
-- but with an edge whose safety is proven by ROWS.
--
-- THE HORIZON. pfj.journal_reclaim_horizon() is the ONLY seq below which
-- records may be deleted, and it is the minimum of every reader that can
-- still exist:
--   1. the generation's logical base (base_seq) — nothing at or above it is
--      reclaimable, ever;
--   2. the source boundary of every non-terminal cut of this generation — a
--      pending/materializing fold starts at its own source_base_seq, which
--      can predate the current base if an adoption raced ahead;
--   3. for pfj3, a READY cut of this generation carrying a recovery anchor
--      at or beyond the horizon. Without that anchor the records below the
--      horizon are the only copy and deleting them would be data loss, so
--      the horizon collapses to the existing physical_trimmed_seq and
--      nothing is reclaimed. This is 013's precondition, enforced as a row.
-- A generation of a RETIRED volume is exempt from (3): the operator asked
-- for the volume to be gone, and the whole journal goes with it.
--
-- WHAT THIS MIGRATION DELETES: nothing at migration time. It installs the
-- capability, the safety proof, and the accounting. Reclamation happens in
-- bounded batches driven by the volume-api maintenance loop.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='030_control_store_headroom'
  ) THEN
    RAISE EXCEPTION '031 preflight: the 030 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '032%') THEN
    RAISE EXCEPTION '031 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfj.journal_generations') IS NULL
     OR to_regclass('pfj.journal_records') IS NULL
     OR to_regclass('pfh.history_cuts') IS NULL THEN
    RAISE EXCEPTION '031 preflight: a required 009/013 table is missing';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='volumes' AND column_name='retired_at'
  ) THEN
    RAISE EXCEPTION '031 preflight: the 021 volumes.retired_at column is missing';
  END IF;
  IF to_regprocedure('pfj.journal_reclaim(text,int)') IS NOT NULL THEN
    RAISE EXCEPTION '031 preflight: pfj.journal_reclaim already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: cross-schema reads the horizon proof needs ══════════════════

-- The journal owner must be able to see (a) whether a volume is retired and
-- (b) the exact cut rows that authorize a horizon. Both are narrow
-- column-level grants: no other public or pfh state crosses the boundary.
GRANT USAGE ON SCHEMA public TO portablefs_journal_owner;
GRANT SELECT (id, tenant_id, retired_at) ON public.volumes TO portablefs_journal_owner;
-- The candidate list names the branch so the maintenance loop can drive the
-- SAME deterministic recovery-cut path it already drives for backlog.
GRANT SELECT (id, name) ON public.branches TO portablefs_journal_owner;

SET LOCAL ROLE portablefs_history_owner;
GRANT USAGE ON SCHEMA pfh TO portablefs_journal_owner;
GRANT SELECT (id, generation_id, state, source_base_seq, cut_seq_exclusive,
              recovery_anchor_id)
  ON pfh.history_cuts TO portablefs_journal_owner;
RESET ROLE;

-- ═══ SECTION B: pfj (journal owner) — horizon, reclaim, retire, accounting ══

SET LOCAL ROLE portablefs_journal_owner;

-- journal_reclaim_horizon: the provably-safe exclusive floor. Returns the
-- CURRENT physical_trimmed_seq when nothing is reclaimable, so callers can
-- treat "no progress" and "not safe" identically.
CREATE FUNCTION pfj.journal_reclaim_horizon(p_generation_id TEXT) RETURNS BIGINT
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_horizon BIGINT;
  v_anchor_seq BIGINT;
  v_volume_retired BOOLEAN;
  v_terminal BOOLEAN;
BEGIN
  SELECT * INTO g FROM pfj.journal_generations WHERE id = p_generation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found', p_generation_id USING ERRCODE = 'PF007';
  END IF;

  SELECT v.retired_at IS NOT NULL INTO v_volume_retired
    FROM public.volumes v WHERE v.id = g.volume_id;
  v_volume_retired := COALESCE(v_volume_retired, FALSE);
  v_terminal := g.status IN ('retired', 'abandoned');

  -- (1) Never at or above the logical base. A terminal generation's base has
  -- already been driven to its tip by journal_retire_for_volume, so this one
  -- bound covers both cases without a second rule.
  v_horizon := g.base_seq;

  -- (2) Never below any non-terminal cut's read window.
  SELECT LEAST(v_horizon, COALESCE(MIN(c.source_base_seq), v_horizon))
    INTO v_horizon
    FROM pfh.history_cuts c
   WHERE c.generation_id = g.id
     AND c.state IN ('pending', 'materializing');

  -- (3) pfj3 needs a materialized recovery anchor covering what we delete.
  -- 013 froze trim for exactly this reason; the proof is a row, not a flag.
  -- A terminal generation of a RETIRED volume is exempt: the operator asked
  -- for the data to go away, so there is nothing left to recover it for.
  --
  -- PLAN SHAPE MATTERS HERE, and it is not obvious.
  --
  -- source_kind is pinned so this rides the existing 026 partial index
  -- history_cuts_ready_chain (generation_id, cut_seq_exclusive DESC)
  -- WHERE state='ready' AND source_kind='managed_journal'. The predicate is
  -- semantically free — 013 CHECKs (source_kind='managed_journal') =
  -- (generation_id IS NOT NULL), so every cut naming a generation has it.
  --
  -- The anchor is fetched as a MAX and compared in plpgsql rather than
  -- written as EXISTS(... cut_seq_exclusive >= v_horizon). That looks like a
  -- pointless rewrite and is not: with the horizon inside the predicate, the
  -- only variable is a PARAMETER in an inequality, and after five calls
  -- plpgsql promotes the statement to a GENERIC plan, where the planner
  -- cannot estimate that inequality and falls back to a sequential scan of
  -- the whole cut table. Measured on a 60k-cut fixture: 20 horizon calls
  -- produced 15 sequential scans over 900,045 tuples. Single-shot EXPLAIN
  -- never shows it, because the first five calls still get custom plans.
  -- As a MAX, the only parameter left is a generation_id EQUALITY, which a
  -- generic plan resolves against the index every time.
  IF g.record_codec = 'pfj3' AND NOT (v_terminal AND v_volume_retired) THEN
    SELECT MAX(c.cut_seq_exclusive) INTO v_anchor_seq
      FROM pfh.history_cuts c
     WHERE c.generation_id = g.id
       AND c.state = 'ready'
       AND c.source_kind = 'managed_journal'
       AND c.recovery_anchor_id IS NOT NULL;
    IF v_anchor_seq IS NULL OR v_anchor_seq < v_horizon THEN
      RETURN g.physical_trimmed_seq;
    END IF;
  END IF;

  RETURN GREATEST(v_horizon, g.physical_trimmed_seq);
END;
$$;

-- journal_reclaim: bounded physical deletion below the proven horizon.
-- Deliberately takes NO generation row lock (appends never wait on
-- reclamation); progress is recorded with a conditional update that only
-- moves physical_trimmed_seq forward. Every call is retryable and does a
-- bounded amount of work, so a 20 GB backlog drains as a stream of small
-- transactions instead of one unbounded DELETE that would itself need the
-- disk space it is trying to release.
CREATE FUNCTION pfj.journal_reclaim(
  p_generation_id TEXT,
  p_max_rows INT DEFAULT 512
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_max_rows, 512), 1), 4096);
  v_horizon BIGINT;
  v_deleted BIGINT;
  v_bytes BIGINT;
  v_new_floor BIGINT;
BEGIN
  PERFORM pfj.require_txn_settings();
  v_horizon := pfj.journal_reclaim_horizon(p_generation_id);
  WITH doomed AS (
    SELECT r.seq FROM pfj.journal_records r
      WHERE r.generation_id = p_generation_id AND r.seq < v_horizon
      ORDER BY r.seq
      LIMIT v_limit
  ), gone AS (
    DELETE FROM pfj.journal_records r
      USING doomed d
      WHERE r.generation_id = p_generation_id AND r.seq = d.seq
      RETURNING r.seq, r.payload_bytes
  )
  SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0), COALESCE(MAX(seq) + 1, 0)
    INTO v_deleted, v_bytes, v_new_floor FROM gone;
  IF v_deleted > 0 THEN
    UPDATE pfj.journal_generations
       SET physical_trimmed_seq = GREATEST(physical_trimmed_seq, v_new_floor),
           updated_at = pfj.now_ms()
     WHERE id = p_generation_id AND physical_trimmed_seq < v_new_floor;
  END IF;
  RETURN jsonb_build_object(
    'generationId', p_generation_id,
    'deletedRecords', v_deleted::TEXT,
    'deletedBytes', v_bytes::TEXT,
    'horizonSeq', v_horizon::TEXT,
    -- More work remains below the horizon: the caller re-enters instead of
    -- letting one transaction grow without bound.
    'more', v_deleted >= v_limit);
END;
$$;

-- journal_retire_for_volume: the reclamation half of `portablefs rm`.
-- Retiring a volume used to leave every journal record it ever wrote in the
-- control store forever. This drives the volume's generations terminal AND
-- moves each base to its own tip, which is what makes the WHOLE journal fall
-- below the reclaim horizon. It refuses unless the volume is actually
-- retired, so it can never be aimed at a live volume.
CREATE FUNCTION pfj.journal_retire_for_volume(
  p_tenant TEXT, p_volume TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_retired TIMESTAMPTZ;
  v_found BOOLEAN;
  v_now BIGINT;
  v_retired_count BIGINT := 0;
  v_reclaimable BIGINT := 0;
BEGIN
  PERFORM pfj.require_txn_settings();
  SELECT v.retired_at, TRUE INTO v_retired, v_found
    FROM public.volumes v WHERE v.id = p_volume AND v.tenant_id = p_tenant;
  IF NOT COALESCE(v_found, FALSE) THEN
    RAISE EXCEPTION 'volume % not found in tenant %', p_volume, p_tenant
      USING ERRCODE = 'PF007';
  END IF;
  IF v_retired IS NULL THEN
    RAISE EXCEPTION 'volume % is not retired; journal retirement is not defined for a live volume', p_volume
      USING ERRCODE = 'PF008';
  END IF;
  v_now := pfj.now_ms();
  WITH moved AS (
    UPDATE pfj.journal_generations g
       SET status = 'retired',
           capability_hash = NULL,
           base_seq = g.next_seq,
           base_digest = g.tip_digest,
           backlog_bytes = 0,
           backlog_records = 0,
           updated_at = v_now
     WHERE g.volume_id = p_volume
       AND g.tenant_id = p_tenant
       AND g.status NOT IN ('retired', 'abandoned')
    RETURNING g.id)
  SELECT COUNT(*) INTO v_retired_count FROM moved;
  SELECT COUNT(*) INTO v_reclaimable
    FROM pfj.journal_records r
    JOIN pfj.journal_generations g ON g.id = r.generation_id
   WHERE g.volume_id = p_volume AND g.tenant_id = p_tenant;
  RETURN jsonb_build_object(
    'volumeId', p_volume,
    'generationsRetired', v_retired_count::TEXT,
    'reclaimableRecords', v_reclaimable::TEXT);
END;
$$;

-- journal_reclaim_candidates: the bounded work list, largest waste first.
--
-- `suspendedPastRetention` is the second half of the requirement a backlog
-- threshold alone cannot meet: a branch that was suspended and abandoned
-- never crosses a percent-of-quota threshold, so it was never cut, never
-- adopted, and never reclaimable. Flagging it lets the maintenance loop cut
-- and adopt it on AGE rather than on size, after which its records fall
-- below the horizon like any other.
-- COST DISCIPLINE. This runs on EVERY maintenance cycle, so it must never
-- read the table it exists to bound. An earlier revision counted the
-- reclaimable rows (COUNT(*) + SUM(payload_bytes) per generation) and
-- measured, on a 320k-record fixture, a Parallel Seq Scan over the whole
-- journal: 133 ms and 19,487 buffers PER CALL, growing without limit as the
-- backlog grows. A GC scan whose cost scales with the garbage is the same
-- bug in a new place.
--
-- The reclaimable count is therefore taken from the generation row itself:
-- (horizon - physical_trimmed_seq) is the span of seqs eligible for
-- deletion, and journal seqs are dense, so it is exact in the normal case
-- and an upper bound after a partial trim leaves gaps. The only journal
-- touch is an EXISTS that stops at the first matching row, so a generation
-- whose span is non-empty but whose rows are already gone drops off the list
-- instead of being offered forever. Exact byte accounting belongs to
-- pfj.journal_storage_usage(), which is operator-triggered, not per-cycle.
CREATE FUNCTION pfj.journal_reclaim_candidates(
  p_limit INT DEFAULT 32,
  p_retention_ms BIGINT DEFAULT 604800000
) RETURNS JSONB
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit, 32), 1), 256);
  v_retention BIGINT := GREATEST(COALESCE(p_retention_ms, 604800000), 0);
  v_now BIGINT := pfj.now_ms();
BEGIN
  RETURN COALESCE((
    SELECT jsonb_agg(entry ORDER BY rank_span DESC)
      FROM (
        SELECT jsonb_build_object(
                 'generationId', g.id,
                 'tenantId', g.tenant_id,
                 'volumeId', g.volume_id,
                 'branchId', g.branch_id,
                 'branchName', b.name,
                 'status', g.status,
                 'recordCodec', g.record_codec,
                 'baseSeq', g.base_seq::TEXT,
                 'nextSeq', g.next_seq::TEXT,
                 'horizonSeq', h.seq::TEXT,
                 'reclaimableRecords', GREATEST(h.seq - g.physical_trimmed_seq, 0)::TEXT,
                 'suspendedPastRetention', aged.flag
               ) AS entry,
               GREATEST(h.seq - g.physical_trimmed_seq, 0) AS rank_span
          FROM pfj.journal_generations g
          JOIN public.branches b ON b.id = g.branch_id
          CROSS JOIN LATERAL (SELECT pfj.journal_reclaim_horizon(g.id) AS seq) h
          CROSS JOIN LATERAL (
            SELECT (g.status = 'suspended' AND v_now - g.updated_at > v_retention) AS flag
          ) aged
         -- Two kinds of work: rows that can be deleted NOW, and generations
         -- a backlog-percent threshold can never reach — suspended, idle
         -- past retention, and still holding an un-cut tail. The second kind
         -- is exactly how abandoned test branches accumulated forever.
         WHERE (h.seq > g.physical_trimmed_seq
                AND EXISTS (SELECT 1 FROM pfj.journal_records r
                             WHERE r.generation_id = g.id AND r.seq < h.seq))
            OR (aged.flag AND g.next_seq > g.base_seq)
         ORDER BY rank_span DESC
         LIMIT v_limit
      ) ranked
  ), '[]'::JSONB);
END;
$$;

-- journal_storage_usage: the operator-visible accounting that did not exist.
--
-- BYTES ARE MEASURED AT THE RELATION, NOT SUMMED OVER ROWS.
-- pg_total_relation_size is O(1) and is also the more honest number: it
-- includes indexes, TOAST and dead-tuple bloat, which is what actually
-- consumes the disk. Summing payload_bytes would report a smaller figure at
-- the cost of a full sequential scan (measured: 63 ms / 38,543 buffers on a
-- 320k-record fixture, unbounded thereafter) — an accounting call that gets
-- slower exactly as the problem it reports gets worse.
--
-- Record counts come from the generation rows' seq spans (dense in the
-- normal case, an upper bound after a partial trim leaves gaps), so this
-- whole function reads only pfj.journal_generations plus catalog size.
CREATE FUNCTION pfj.journal_storage_usage() RETURNS JSONB
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_records BIGINT;
  v_reclaimable_records BIGINT;
  v_generations BIGINT;
  v_retired BIGINT;
BEGIN
  SELECT COUNT(*),
         COUNT(*) FILTER (WHERE status IN ('retired', 'abandoned')),
         COALESCE(SUM(GREATEST(next_seq - physical_trimmed_seq, 0)), 0),
         COALESCE(SUM(GREATEST(
           pfj.journal_reclaim_horizon(id) - physical_trimmed_seq, 0)), 0)
    INTO v_generations, v_retired, v_records, v_reclaimable_records
    FROM pfj.journal_generations;
  RETURN jsonb_build_object(
    'generations', v_generations::TEXT,
    'terminalGenerations', v_retired::TEXT,
    'records', v_records::TEXT,
    'reclaimableRecords', v_reclaimable_records::TEXT,
    'tableBytes', pg_catalog.pg_total_relation_size('pfj.journal_records')::TEXT,
    'dbTimeMs', pfj.now_ms()::TEXT);
END;
$$;

-- ═══ SECTION C: the freeze trigger gains exactly two proven edges ═══════════
--
-- Byte-for-byte the 013 revision, plus:
--   (A) a physical_trimmed_seq ADVANCE bounded by journal_reclaim_horizon();
--   (B) the terminal retirement of a RETIRED volume's generation, which
--       drives base_seq to next_seq so the whole journal falls below the
--       horizon.
-- Both are performed by the journal owner and authorized by ROWS (the cut
-- rows behind the horizon; volumes.retired_at) — never by a setting.
CREATE OR REPLACE FUNCTION pfj.journal_generations_freeze() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_terminal_retirement BOOLEAN;
BEGIN
  -- 031_journal_reclamation revision of the 013 freeze.
  IF NEW.record_codec IS DISTINCT FROM OLD.record_codec
     OR NEW.control_codec IS DISTINCT FROM OLD.control_codec THEN
    RAISE EXCEPTION
      'journal generation codecs are immutable; conversion is retire + new generation'
      USING ERRCODE='PF005';
  END IF;
  IF OLD.ha_policy_hash IS NOT NULL
     AND NEW.ha_policy_hash IS DISTINCT FROM OLD.ha_policy_hash THEN
    RAISE EXCEPTION 'journal generation HA policy binding is immutable'
      USING ERRCODE='PF001';
  END IF;
  IF NEW.control_db_floor_ms < OLD.control_db_floor_ms THEN
    RAISE EXCEPTION 'journal control floor can never regress' USING ERRCODE='PF010';
  END IF;

  -- (B) Terminal retirement of a RETIRED volume's generation. Recognized
  -- before the codec-specific rules because it is the one edge that must
  -- move base_seq WITHOUT an adoption proof: there is no cut to adopt, the
  -- volume is gone, and the base moves to the generation's own tip.
  v_terminal_retirement :=
    current_user = 'portablefs_journal_owner'
    AND NEW.status = 'retired'
    AND OLD.status NOT IN ('retired', 'abandoned')
    AND NEW.next_seq = OLD.next_seq
    AND NEW.base_seq = OLD.next_seq
    AND NEW.base_digest = OLD.tip_digest
    AND NEW.backlog_bytes = 0
    AND NEW.backlog_records = 0
    AND NEW.physical_trimmed_seq = OLD.physical_trimmed_seq
    AND EXISTS (SELECT 1 FROM public.volumes v
                 WHERE v.id = OLD.volume_id AND v.retired_at IS NOT NULL);

  -- Reclamation NEVER regresses the floor, for any codec.
  IF NEW.physical_trimmed_seq < OLD.physical_trimmed_seq THEN
    RAISE EXCEPTION 'journal physical trim floor can never regress' USING ERRCODE='PF010';
  END IF;
  -- (A) A physical_trimmed_seq advance must stay inside the proven horizon,
  -- whatever the codec. The horizon is computed from the pre-update row and
  -- from cut rows, so a caller cannot widen it by asserting anything.
  IF NEW.physical_trimmed_seq > OLD.physical_trimmed_seq THEN
    IF current_user <> 'portablefs_journal_owner'
       OR NEW.physical_trimmed_seq > pfj.journal_reclaim_horizon(OLD.id) THEN
      RAISE EXCEPTION
        'journal physical trim beyond the proven reclamation horizon'
        USING ERRCODE='PF011';
    END IF;
  END IF;

  IF OLD.record_codec='pfj3' AND NOT v_terminal_retirement THEN
    -- physical_trimmed_seq is no longer frozen (it is bounded above by the
    -- horizon check). The legacy cut fields stay frozen for pfj3.
    IF NEW.cut_operation_id IS DISTINCT FROM OLD.cut_operation_id
       OR NEW.cut_status IS DISTINCT FROM OLD.cut_status THEN
      RAISE EXCEPTION
        'legacy cut/rotate is not defined for a PFJ3 generation'
        USING ERRCODE='PF005';
    END IF;
    IF NEW.base_seq IS DISTINCT FROM OLD.base_seq
       OR NEW.base_digest IS DISTINCT FROM OLD.base_digest
       OR NEW.base_commit_id IS DISTINCT FROM OLD.base_commit_id THEN
      -- The ONLY admitted base advance: performed by the journal owner
      -- (inside pfj.history_adopt_base) AND matched by exactly one
      -- 'applying' adoption proof row for this generation and this exact
      -- old/new tuple INCLUDING the backlog subtraction. Rows, not
      -- settings, authorize.
      IF current_user <> 'portablefs_journal_owner'
         OR NEW.base_seq IS NULL OR NEW.base_seq < OLD.base_seq
         OR NOT EXISTS (
           SELECT 1 FROM pfh.adoptions a
           WHERE a.generation_id = OLD.id
             AND a.state = 'applying'
             AND a.old_base_seq = OLD.base_seq
             AND a.old_base_digest = OLD.base_digest
             AND a.new_base_seq = NEW.base_seq
             AND a.new_base_digest = NEW.base_digest
             AND a.new_base_commit_id = NEW.base_commit_id
             AND OLD.backlog_bytes - NEW.backlog_bytes = a.subtract_backlog_bytes
             AND OLD.backlog_records - NEW.backlog_records = a.subtract_backlog_records) THEN
        RAISE EXCEPTION
          'PFJ3 base advance requires an exact applying adoption proof row'
          USING ERRCODE='PF011';
      END IF;
    ELSIF NEW.backlog_bytes < OLD.backlog_bytes
       OR NEW.backlog_records < OLD.backlog_records THEN
      -- Backlog only shrinks through an adoption base advance.
      RAISE EXCEPTION 'PFJ3 backlog regression without a base advance'
        USING ERRCODE='PF010';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION pfj.journal_generations_freeze() FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION D: grants ══════════════════════════════════════════════════════

REVOKE ALL ON FUNCTION
  pfj.journal_reclaim_horizon(TEXT),
  pfj.journal_reclaim(TEXT, INT),
  pfj.journal_retire_for_volume(TEXT, TEXT),
  pfj.journal_reclaim_candidates(INT, BIGINT),
  pfj.journal_storage_usage()
FROM PUBLIC;

-- Metadata/caller surface (the volume-api repository's admin DSN role), the
-- exact 013/017/022 grant pattern. The restricted authority and worker roles
-- gain NOTHING: reclamation is a maintenance-plane capability.
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfj.journal_reclaim(TEXT, INT),
    pfj.journal_retire_for_volume(TEXT, TEXT),
    pfj.journal_reclaim_candidates(INT, BIGINT),
    pfj.journal_storage_usage()
    TO %I', CURRENT_USER);
END
$$;

-- ═══ SECTION E: postconditions ══════════════════════════════════════════════

DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, p.prosecdef, p.proconfig AS config,
           pg_get_userbyid(p.proowner) AS owner
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'pfj'
       AND p.proname IN ('journal_reclaim', 'journal_reclaim_horizon',
                         'journal_retire_for_volume', 'journal_reclaim_candidates',
                         'journal_storage_usage')
  LOOP
    IF v_rec.owner <> 'portablefs_journal_owner' THEN
      RAISE EXCEPTION '031 postcondition: pfj.% is not owned by the journal owner', v_rec.proname;
    END IF;
    IF NOT v_rec.prosecdef THEN
      RAISE EXCEPTION '031 postcondition: pfj.% must be SECURITY DEFINER', v_rec.proname;
    END IF;
    IF array_to_string(v_rec.config, ',') NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '031 postcondition: pfj.% has no pinned search_path', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '031 postcondition: PUBLIC can execute pfj.%', v_rec.proname;
    END IF;
  END LOOP;

  -- The restricted roles gained NOTHING.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfj'
      AND p.proname IN ('journal_reclaim', 'journal_retire_for_volume',
                        'journal_reclaim_candidates', 'journal_storage_usage')
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_worker'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '031 postcondition: a restricted role can execute journal reclamation';
  END IF;

  -- The freeze trigger still exists, still guards, and now carries the two
  -- proven edges. A regression that drops the horizon bound would re-open
  -- unbounded deletion, so assert the bound by name.
  IF position('journal_reclaim_horizon' IN pg_get_functiondef(
       to_regprocedure('pfj.journal_generations_freeze()'))) = 0 THEN
    RAISE EXCEPTION '031 postcondition: the freeze trigger no longer bounds trim by the horizon';
  END IF;
  IF position('applying adoption proof row' IN pg_get_functiondef(
       to_regprocedure('pfj.journal_generations_freeze()'))) = 0 THEN
    RAISE EXCEPTION '031 postcondition: the freeze trigger lost the 013 adoption proof edge';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger t
     WHERE t.tgrelid = 'pfj.journal_generations'::regclass
       AND NOT t.tgisinternal
       AND t.tgfoid = to_regprocedure('pfj.journal_generations_freeze()')::oid) THEN
    RAISE EXCEPTION '031 postcondition: the freeze trigger is not installed';
  END IF;

  -- The horizon proof needs its two cross-schema reads; without them every
  -- reclaim would fail closed at runtime instead of at migration time.
  IF NOT has_column_privilege('portablefs_journal_owner', 'public.volumes', 'retired_at', 'SELECT')
     OR NOT has_column_privilege(
       'portablefs_journal_owner', 'pfh.history_cuts', 'source_base_seq', 'SELECT') THEN
    RAISE EXCEPTION '031 postcondition: the journal owner cannot read the horizon proof';
  END IF;

  -- Lineage: 032 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '032%') THEN
    RAISE EXCEPTION '031 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
