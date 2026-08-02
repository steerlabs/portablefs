-- 035_recovery_cut_lifecycle: name the generations whose recovery cut died.
--
-- INCIDENT THIS EXISTS FOR: production volume-api logged, every 60 seconds,
-- for days,
--
--   "recovery cut hcut_f6c19bfeb58148138c86d3ea54ea0eb5 for generation
--    jgen_c6c2ed9f537c42a884edbffe2bfdddcc is failed; adoption is blocked
--    until an operator intervenes"
--
-- with cycle telemetry {cutsFailed: 1}. That line names a cut and a
-- generation and nothing else: no tenant, no volume, no branch, no failure
-- reason, no age, and no remedy. An operator who wanted the list of affected
-- volumes had no query to run — pfj.journal_generations and the terminal
-- rows of pfh.history_cuts are owner-private, and every existing projection
-- (017's backlog scan, 031's reclaim candidates) is deliberately blind to
-- cut STATE. The maintenance loop could see one such generation per cycle,
-- only if that generation also happened to cross a backlog threshold.
--
-- The actual failure was recorded on the cut row the whole time:
--   {"kind":"corrupt","message":"historycut: source corruption: journal page
--    at seq 0 is empty below the cut 32"}
-- The generation's 32 append receipts all survive in
-- pfj.journal_append_receipts while pfj.journal_records holds zero rows for
-- it. Neither bounded DELETE path in this lineage can produce that state:
-- pfj.journal_physical_trim (009) and pfj.journal_reclaim (031) both delete
-- only below base_seq / the proven horizon, both were looking at base_seq=0,
-- and the freeze trigger RAISEs rather than silently dropping a floor
-- advance. The rows went out of band — 031's own header records that this
-- control store was cured "manually" twice — and physical_trimmed_seq could
-- not have recorded it either, because 009 CHECKs physical_trimmed_seq <=
-- base_seq. Whatever removed them, the consequence is structural: the cut's
-- captured range has no bytes, so EVERY re-cut of that range fails the same
-- way. It is permanently, not transiently, failed.
--
-- WHAT THIS MIGRATION ADDS: one bounded projection that answers "which live
-- generations have terminal history work and nothing live in flight", with
-- the identity, the failure classification and the age an operator (and the
-- maintenance loop's per-cycle telemetry) needs to act. It changes NO
-- behavior, deletes nothing, and grants no restricted role anything.
--
-- WHAT THIS MIGRATION DOES NOT CHANGE, deliberately: the reclamation
-- horizon. pfj.journal_reclaim_horizon (031) already clamps only on cuts in
-- ('pending','materializing') — a cut that might still materialize keeps its
-- read window pinned — and a 'failed'/'canceled' cut is already excluded,
-- because it can never produce the anchor that would make its window
-- meaningful. A terminally failed cut therefore does NOT hold reclamation
-- hostage. What pins such a generation's journal is the ABSENCE of an
-- adoption (base_seq never advances, so the horizon stays at base_seq), and
-- releasing that is an operator decision about data, not an accounting fix:
-- see docs/history.md, "A recovery cut that cannot be re-cut".
--
-- SECURITY MODEL (extends 009/013/017/031): the projection is owned by
-- portablefs_journal_owner, SECURITY DEFINER with a pinned search_path,
-- loses PUBLIC EXECUTE, and is EXECUTE-granted to the migration user (the
-- volume-api repository's admin DSN role) only. The authority, worker and
-- auditor roles gain nothing.

-- LINEAGE NOTE. This migration was authored as 034 and renumbered: a parallel
-- round took 034 (034_liveness_lock_isolation) for the journal-plane lock-mode
-- fix — pfj.require_writer, pfm.require_manager, pfm.verify_authority_binding,
-- pfm.manager_renew. Nothing here touches any object 034 replaces, and this
-- file depends only on 033, so the preflight asks for the 033 receipt and the
-- two apply in either order; the ordered lineage in postgres.ts places 034
-- first, which is what production will actually do.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='033_retirement_transition'
  ) THEN
    RAISE EXCEPTION '035 preflight: the 033 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '036%') THEN
    RAISE EXCEPTION '035 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfj.journal_generations') IS NULL
     OR to_regclass('pfh.history_cuts') IS NULL THEN
    RAISE EXCEPTION '035 preflight: a required 009/013 table is missing';
  END IF;
  IF to_regprocedure('pfj.stuck_recovery_generations(int)') IS NOT NULL THEN
    RAISE EXCEPTION '035 preflight: pfj.stuck_recovery_generations already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: the terminal-cut index and the columns the survey reads ═════

SET LOCAL ROLE portablefs_history_owner;

-- 013's history_cuts_by_generation is PARTIAL on ('pending','materializing')
-- — exactly the rows this survey is NOT looking for. Without an index the
-- survey degrades into a sequential scan of every cut ever taken, on every
-- maintenance cycle, growing with the cut table. Give the terminal rows
-- their own exact partial index, keyed the way the survey reads them:
-- newest boundary first, newest revision first, per generation.
CREATE INDEX history_cuts_terminal_by_generation
  ON pfh.history_cuts (generation_id, cut_seq_exclusive DESC, dedup_revision DESC)
  WHERE state IN ('failed','canceled') AND source_kind='managed_journal';

-- Narrow column-level grants, in the 031 style: the journal owner already
-- reads (id, generation_id, state, source_base_seq, cut_seq_exclusive,
-- recovery_anchor_id) for the horizon proof. The survey additionally needs
-- the label, the revision counter, the attempt budget, the recorded failure
-- and the timestamps. No other pfh state crosses the boundary.
GRANT SELECT (kind, dedup_revision, attempt_count, last_error,
              created_db_ms, updated_db_ms)
  ON pfh.history_cuts TO portablefs_journal_owner;

RESET ROLE;

-- ═══ SECTION B: the survey ══════════════════════════════════════════════════

SET LOCAL ROLE portablefs_journal_owner;

-- Live PFJ3 generations whose history work is TERMINAL and whose journal is
-- therefore not advancing: at least one failed/canceled cut would have moved
-- the base past its current value, and nothing pending/materializing/ready
-- is in flight to do it instead. Oldest stuck first, bounded.
--
-- "Would have moved the base" is expressed as cut_seq_exclusive > g.base_seq
-- rather than source_base_seq = g.base_seq on purpose: 026 chained cuts base
-- a capture on a prior ready cut, so a cut's source_base_seq legitimately
-- sits ABOVE the generation base, and an adoption that raced ahead can leave
-- it below. The boundary it would have installed is the fact that matters.
--
-- Generations of a RETIRED volume are excluded: 022 cancels their cuts by
-- design, so every one of them would report as stuck forever, and 033's
-- retirement drain — not an operator — owns their release.
--
-- PLAN SHAPE. The only parameter is p_limit, and it appears only in LIMIT:
-- there is no parameter inside an inequality, so the generic plan plpgsql
-- promotes this to after five calls is the same plan as the first custom
-- one. (031's horizon documents the trap this avoids: a horizon parameter
-- inside `cut_seq_exclusive >= $1` estimated so badly under a generic plan
-- that it seq-scanned the whole cut table, and a single EXPLAIN never showed
-- it because the first five calls still got custom plans.) Every cut lookup
-- here is a generation_id EQUALITY against the 035 partial index.
--
-- COST DISCIPLINE, in 031's words: a scan whose cost scales with the thing
-- it exists to report is the same bug in a new place. This runs on EVERY
-- maintenance cycle, so it is driven FROM the terminal-cut partial index —
-- a set that is small precisely because dead cuts are rare — and not from
-- pfj.journal_generations. An earlier revision drove it from the generation
-- table with a LATERAL per row and measured, on a 400-generation / 20,000-cut
-- fixture, 6,714 shared buffers per call, growing with the number of live
-- generations whether or not any of them were stuck.
CREATE FUNCTION pfj.stuck_recovery_generations(p_limit INT DEFAULT 32)
RETURNS SETOF JSONB
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit, 32), 1), 256);
  v_now BIGINT := pfj.now_ms();
BEGIN
  RETURN QUERY
    -- MATERIALIZED is load-bearing, not decoration. Standalone, this DISTINCT
    -- is a 4-buffer index-only scan of the 035 partial index. Inlined, the
    -- planner flattens it into the join tree, loses the index-only path, and
    -- measured a 1,872-buffer bitmap scan of the whole cut table on the same
    -- 20,000-cut fixture. Pinning the driver keeps the cost proportional to
    -- the DEAD cuts, which is the only set that should matter here.
    WITH dead AS MATERIALIZED (
      SELECT DISTINCT c.generation_id
        FROM pfh.history_cuts c
       WHERE c.source_kind = 'managed_journal'
         AND c.state IN ('failed','canceled')
    )
    SELECT jsonb_build_object(
             'tenantId', g.tenant_id,
             'volumeId', g.volume_id,
             'branchId', g.branch_id,
             'branchName', b.name,
             'generationId', g.id,
             'status', g.status,
             'baseSeq', g.base_seq::TEXT,
             'nextSeq', g.next_seq::TEXT,
             'backlogBytes', g.backlog_bytes::TEXT,
             'backlogRecords', g.backlog_records::TEXT,
             'cutId', newest.id,
             'cutState', newest.state,
             'cutKind', newest.kind,
             'cutSeqExclusive', newest.cut_seq_exclusive::TEXT,
             'dedupRevision', newest.dedup_revision::TEXT,
             'attemptCount', newest.attempt_count,
             -- The classification the loop's retry policy reads. 'corrupt'
             -- is definite source damage: re-cutting the same range folds
             -- the same absent bytes and fails identically. A dead letter is
             -- FLATTENED onto the error that exhausted the attempt budget —
             -- 'dead_letter' alone says only that 013's counter ran out, and
             -- sixteen transient failures are still a transient story.
             'failureKind', CASE
               WHEN newest.state = 'canceled' THEN 'canceled'
               WHEN newest.last_error->>'kind' = 'dead_letter'
                 THEN 'dead_letter/' ||
                      COALESCE(newest.last_error->'lastError'->>'kind', 'unknown')
               ELSE COALESCE(newest.last_error->>'kind', 'unknown')
             END,
             'failureMessage', left(COALESCE(
               CASE WHEN newest.last_error->>'kind' = 'dead_letter'
                 THEN newest.last_error->'lastError'->>'message'
                 ELSE newest.last_error->>'message' END,
               newest.last_error->>'message', ''), 200),
             'firstFailedDbMs', span.first_failed::TEXT,
             'lastFailedDbMs', newest.updated_db_ms::TEXT,
             'stuckAgeMs', GREATEST(v_now - span.first_failed, 0)::TEXT,
             'terminalCuts', span.terminal_cuts::TEXT,
             'dbTimeMs', v_now::TEXT)
      -- The driver: generations that HAVE a terminal cut, read straight off
      -- the 035 partial index. Live generations with no dead cut — the
      -- overwhelming majority — are never touched.
      FROM dead
      JOIN pfj.journal_generations g ON g.id = dead.generation_id
      JOIN public.branches b ON b.id = g.branch_id
      JOIN public.volumes v ON v.id = g.volume_id AND v.tenant_id = g.tenant_id
      -- The newest terminal boundary this generation failed to install.
      CROSS JOIN LATERAL (
        SELECT c.id, c.state, c.kind, c.cut_seq_exclusive, c.dedup_revision,
               c.attempt_count, c.last_error, c.updated_db_ms
          FROM pfh.history_cuts c
         WHERE c.generation_id = g.id
           AND c.source_kind = 'managed_journal'
           AND c.state IN ('failed','canceled')
           AND c.cut_seq_exclusive > g.base_seq
         ORDER BY c.cut_seq_exclusive DESC, c.dedup_revision DESC, c.id DESC
         LIMIT 1
      ) newest
      CROSS JOIN LATERAL (
        SELECT MIN(c.updated_db_ms) AS first_failed, COUNT(*) AS terminal_cuts
          FROM pfh.history_cuts c
         WHERE c.generation_id = g.id
           AND c.source_kind = 'managed_journal'
           AND c.state IN ('failed','canceled')
           AND c.cut_seq_exclusive > g.base_seq
      ) span
     WHERE g.record_codec = 'pfj3'
       AND g.status IN ('active','suspended')
       AND v.retired_at IS NULL
       -- Nothing live is in flight for a boundary past the base: if there
       -- is, this generation is progressing and is not an operator's
       -- problem.
       --
       -- SPLIT ON PURPOSE, one EXISTS per existing index. As a single
       -- state IN ('pending','materializing','ready') there is no index that
       -- covers all three, and the planner turned it into a Hash Right Anti
       -- Join over a SEQUENTIAL SCAN of the cut table: 3,632 buffers on a
       -- 20,000-cut fixture, growing with every cut ever taken. Split, each
       -- arm is an exact partial index that 013 and 026 already installed —
       -- history_cuts_by_generation (generation_id) WHERE state IN
       -- ('pending','materializing'), and history_cuts_ready_chain
       -- (generation_id, cut_seq_exclusive DESC) WHERE state='ready'.
       AND NOT EXISTS (
         SELECT 1 FROM pfh.history_cuts live
          WHERE live.generation_id = g.id
            AND live.state IN ('pending','materializing')
            AND live.cut_seq_exclusive > g.base_seq)
       AND NOT EXISTS (
         SELECT 1 FROM pfh.history_cuts live
          WHERE live.generation_id = g.id
            AND live.state = 'ready'
            AND live.source_kind = 'managed_journal'
            AND live.cut_seq_exclusive > g.base_seq)
     ORDER BY span.first_failed ASC, g.id
     LIMIT v_limit;
END;
$$;
REVOKE ALL ON FUNCTION pfj.stuck_recovery_generations(INT) FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION C: grants ══════════════════════════════════════════════════════

REVOKE ALL ON FUNCTION pfj.stuck_recovery_generations(INT) FROM PUBLIC;

-- Metadata/caller surface only (the volume-api repository's admin DSN role),
-- the exact 013/017/022/031 grant pattern.
DO $$
BEGIN
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION pfj.stuck_recovery_generations(INT) TO %I',
    CURRENT_USER);
END
$$;

-- ═══ SECTION D: postconditions ══════════════════════════════════════════════

DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  SELECT p.oid AS fnoid, p.prosecdef, p.proconfig AS config,
         pg_get_userbyid(p.proowner) AS owner
    INTO v_rec
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pfj' AND p.proname = 'stuck_recovery_generations';
  IF NOT FOUND THEN
    RAISE EXCEPTION '035 postcondition: pfj.stuck_recovery_generations is missing';
  END IF;
  IF v_rec.owner <> 'portablefs_journal_owner' THEN
    RAISE EXCEPTION '035 postcondition: the survey is not owned by the journal owner';
  END IF;
  IF NOT v_rec.prosecdef THEN
    RAISE EXCEPTION '035 postcondition: the survey must be SECURITY DEFINER';
  END IF;
  IF array_to_string(v_rec.config, ',') NOT LIKE '%search_path%' THEN
    RAISE EXCEPTION '035 postcondition: the survey has no pinned search_path';
  END IF;
  IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
    RAISE EXCEPTION '035 postcondition: PUBLIC can execute the survey';
  END IF;

  -- The restricted roles gained NOTHING.
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
   WHERE n.nspname='pfj' AND p.proname='stuck_recovery_generations'
     AND acl.grantee IN (
       'portablefs_authority'::regrole,
       'portablefs_history_worker'::regrole)
     AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '035 postcondition: a restricted role can execute the survey';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class WHERE relname='history_cuts_terminal_by_generation'
      AND relkind='i') THEN
    RAISE EXCEPTION '035 postcondition: the terminal-cut index is missing';
  END IF;

  -- The horizon proof is UNCHANGED and still clamps only on cuts that might
  -- still materialize. A regression that widened it to terminal cuts would
  -- pin a failed generation's journal forever — the exact hostage this
  -- migration's header argues must never happen.
  IF position('''pending'', ''materializing''' IN pg_get_functiondef(
       to_regprocedure('pfj.journal_reclaim_horizon(text)'))) = 0 THEN
    RAISE EXCEPTION '035 postcondition: the reclaim horizon no longer clamps on non-terminal cuts only';
  END IF;
END;
$post$;
