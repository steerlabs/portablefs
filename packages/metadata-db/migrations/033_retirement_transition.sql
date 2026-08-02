-- 033_retirement_transition: retirement that actually releases the journal.
--
-- 031 gave `portablefs rm` a reclamation half (pfj.journal_retire_for_volume)
-- and the DELETE route calls it. Two things make that call a wish rather than
-- a transition:
--
-- (a) NO DURABLE SCHEDULE. server.ts wraps the call in try/catch, LOGS the
--     failure, and returns the retirement receipt anyway. Nothing is written
--     down. The maintenance loop only reclaims below EXISTING horizons — it
--     calls pfj.journal_reclaim_candidates and pfj.journal_reclaim, and never
--     pfj.journal_retire_for_volume — and a live generation's horizon is its
--     own base_seq, so a generation that never got retired offers ZERO
--     reclaimable records and never appears as a candidate. Without a client
--     replay of the DELETE, an active generation keeps its whole tail
--     forever: exactly the accumulation that filled this control store twice.
--
-- (b) NO COMMON SERIALIZATION. pfh.volume_retire_cleanup (022) and
--     pfj.journal_retire_for_volume (031) are separate transactions, and
--     pfh.cut_create (029) never looked at volumes.retired_at. So:
--
--       T1 cut_create   ── captures head, still sees a LIVE volume ──┐
--       T2 retire flip  ── volumes.retired_at set, committed         │
--       T2 cleanup      ── cancels the cuts it can SEE (not T1's)    │
--       T1 commit       ── a PENDING cut now exists on the generation┘
--       T2 journal_retire_for_volume ── base_seq := next_seq
--
--     journal_reclaim_horizon then clamps to that pending cut's
--     source_base_seq (rule 2) for as long as the cut stays non-terminal,
--     and nothing will ever cancel it: 022's cleanup already ran, the
--     maintenance loop only creates cuts, and the volume is gone so no
--     client will. The horizon is pinned at the retirement boundary
--     indefinitely.
--
-- THE TRANSITION THIS INSTALLS.
--
--   1. public.portablefs_volume_retire() performs the 021 conditional flip
--      AND enqueues a durable retirement task IN THE SAME TRANSACTION. The
--      receipt and the obligation are one commit: there is no state where a
--      caller holds a receipt and the fleet has no record of the work. A
--      replay (already-retired volume) re-asserts the task row, so a crash
--      between an old flip and this migration heals on the next DELETE.
--
--   2. public.portablefs_volume_retire_finish() performs cleanup AND journal
--      retirement in ONE transaction, under ONE lock order: every branch
--      advisory lock of the volume first (pfj.volume_branch_locks, the same
--      keys and the same sorted acquisition pfj.history_head_capture uses),
--      then the pfh row work, then the pfj row work. The T1/T2 interleaving
--      above cannot occur: whoever holds the branch lock runs to completion
--      first, and the other side then sees the committed result.
--
--   3. pfh.cut_create() REFUSES a retired volume, transactionally, AFTER the
--      branch advisory lock is held. That is what makes the serialization
--      total rather than merely likely: a cut_create that wins the lock race
--      creates a cut the finish pass will cancel; one that loses it sees
--      retired_at and refuses with PF001.
--
--   4. pfh.cut_cancel() joins the same lock order (branch advisory lock at
--      position 0, before its pfh row lock), so cancellation cannot
--      interleave with creation or retirement either.
--
--   5. The task queue is drained by the volume-api maintenance loop with
--      bounded attempts and backoff. A journal-release failure therefore
--      costs the caller NOTHING — the round 16 property is kept, and the
--      durable enqueue, not best-effort inline work, is the mechanism.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF007 not found, PF008 invalid
-- argument, PF011 precondition failure, PF001 state refusal).

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='032_headroom_allocation_probe'
  ) THEN
    RAISE EXCEPTION '033 preflight: the 032 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '034%') THEN
    RAISE EXCEPTION '033 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfh.volume_retire_cleanup(text,text)') IS NULL
     OR to_regprocedure('pfj.journal_retire_for_volume(text,text)') IS NULL
     OR to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb,text)') IS NULL
     OR to_regprocedure('pfh.cut_cancel(text,text,text,text)') IS NULL THEN
    RAISE EXCEPTION '033 preflight: the 022/029/031 retirement surface is incomplete';
  END IF;
  IF to_regclass('public.portablefs_volume_retirement_tasks') IS NOT NULL THEN
    RAISE EXCEPTION '033 preflight: the retirement task queue already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: the durable obligation ══════════════════════════════════════

-- One row per volume, ever. The queue cannot grow beyond the number of
-- retired volumes, and a completed row is kept as the receipt that the
-- transition ran (and when).
CREATE TABLE public.portablefs_volume_retirement_tasks (
  volume_id       TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  enqueued_at_ms  BIGINT NOT NULL,
  next_attempt_ms BIGINT NOT NULL,
  attempts        INT NOT NULL DEFAULT 0,
  completed_at_ms BIGINT,
  last_error      TEXT
);

-- The only scan the drain performs: due, incomplete, oldest first. A partial
-- index so the queue's cost is proportional to OUTSTANDING work, never to
-- the number of volumes ever retired.
CREATE INDEX portablefs_volume_retirement_tasks_due
  ON public.portablefs_volume_retirement_tasks (next_attempt_ms, volume_id)
  WHERE completed_at_ms IS NULL;

COMMENT ON TABLE public.portablefs_volume_retirement_tasks IS
  'Durable obligation to run the volume retirement transition (cut cleanup + journal retirement). Enqueued in the SAME transaction as the 021 retirement flip, so a receipt can never exist without the scheduled work.';

-- ═══ SECTION B: the common lock order ═══════════════════════════════════════

-- The journal owner already reads (id, name) of public.branches for 031's
-- candidate list; the whole-volume lock enumeration needs the two scoping
-- columns as well. Column-level, like every other cross-schema read.
GRANT SELECT (tenant_id, volume_id) ON public.branches TO portablefs_journal_owner;

SET LOCAL ROLE portablefs_journal_owner;

-- One branch advisory lock, in the canonical key space, exposed to the
-- history owner exactly the way pfj.history_head_capture already is. This is
-- what lets pfh.cut_cancel join the lock order without widening the pfj
-- boundary to the generic scope_locks/branch_lock_key primitives.
CREATE FUNCTION pfj.branch_scope_lock(
  p_tenant TEXT, p_volume TEXT, p_branch_name TEXT
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_tenant IS NULL OR p_volume IS NULL OR p_branch_name IS NULL THEN
    RETURN;
  END IF;
  PERFORM pfj.scope_locks(ARRAY[pfj.branch_lock_key(p_tenant, p_volume, p_branch_name)]);
END;
$$;

-- Every branch advisory lock of one volume, acquired in the SAME sorted
-- order pfj.scope_locks imposes everywhere else. Taking them all at once,
-- sorted, is what lets a whole-volume transition share a lock order with
-- per-branch callers that take exactly one: a single-lock holder can never
-- close a cycle against an acquirer that only ever waits upward.
--
-- The branch set is enumerated with a PLAIN read, deliberately. A row lock
-- here would be taken BEFORE the advisory locks and would therefore invert
-- the order pfj.history_head_capture uses (advisory lock, then branches FOR
-- UPDATE) — a deadlock built to prevent one. The set is stable without it:
-- this function only ever runs after volumes.retired_at is committed, and
-- every branch-creating route resolves ownership through the same resolver
-- that treats a retired volume as absent.
CREATE FUNCTION pfj.volume_branch_locks(p_tenant TEXT, p_volume TEXT) RETURNS INT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_keys TEXT[];
BEGIN
  SELECT COALESCE(array_agg(pfj.branch_lock_key(p_tenant, p_volume, b.name)), ARRAY[]::TEXT[])
    INTO v_keys
    FROM public.branches b
   WHERE b.tenant_id = p_tenant AND b.volume_id = p_volume;
  IF array_length(v_keys, 1) IS NULL THEN
    RETURN 0;
  END IF;
  PERFORM pfj.scope_locks(v_keys);
  RETURN array_length(v_keys, 1);
END;
$$;

-- pfj -> pfh boundary: the history owner gains exactly ONE new capability,
-- the branch scope lock, mirroring its existing history_head_capture grant.
REVOKE ALL ON FUNCTION pfj.branch_scope_lock(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pfj.branch_scope_lock(TEXT, TEXT, TEXT)
  TO portablefs_history_owner;

RESET ROLE;

-- ═══ SECTION C: cut creation and cancellation join the lock order ═══════════

SET LOCAL ROLE portablefs_history_owner;

-- 033 revision of the 029 cut creation: byte-for-byte the 029 body plus the
-- retired-volume refusal, placed immediately AFTER pfj.history_head_capture
-- so the check is made while this transaction holds the branch advisory lock
-- and therefore sees whatever a committed retirement wrote.
CREATE OR REPLACE FUNCTION pfh.cut_create(
  p_tenant TEXT, p_volume TEXT, p_branch_name TEXT,
  p_kind TEXT, p_operation_id TEXT, p_fingerprint TEXT,
  p_materializer_version TEXT, p_target_ids JSONB, p_user_label TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_policy pfh.history_policies;
  v_capture JSONB;
  v_now BIGINT;
  v_op JSONB;
  v_cut pfh.history_cuts;
  v_chain RECORD;
  v_dedup_key TEXT;
  v_revision BIGINT;
  v_id TEXT;
  v_source_kind TEXT;
  v_retired TIMESTAMPTZ;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_kind NOT IN ('user','recovery','conversion_final') THEN
    RAISE EXCEPTION 'cut kind % is unknown', p_kind USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.require_sha256(p_fingerprint, 'cut fingerprint');
  IF p_materializer_version IS NULL
     OR length(p_materializer_version) NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'materializer version is required (<=64 chars)' USING ERRCODE='PF008';
  END IF;
  IF p_user_label IS NOT NULL AND length(p_user_label) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'cut user label must be 1..256 chars' USING ERRCODE='PF008';
  END IF;
  v_policy := pfh.require_history_policy();
  v_op := pfh.resource_operation_begin(
    p_tenant, 'history-cut', p_operation_id, 'cut-create', p_fingerprint,
    COALESCE(p_target_ids, '{}'::jsonb));
  IF (v_op->>'replayed')::BOOLEAN THEN
    -- Exact replay: the recorded pending/terminal outcome (or its tombstone).
    RETURN v_op;
  END IF;

  -- Exact head capture under the append lock order (journal owner primitive).
  v_capture := pfj.history_head_capture(p_tenant, p_volume, p_branch_name);

  -- 033: a RETIRED volume takes no new cuts. This read happens while the
  -- branch advisory lock taken by history_head_capture is held, so it is
  -- ordered against public.portablefs_volume_retire_finish(), which holds
  -- every branch lock of the volume for the whole cleanup+journal-retirement
  -- transition. Without this, a cut created in the gap between cleanup and
  -- journal retirement pins the reclamation horizon forever: 022's cleanup
  -- has already run, the maintenance loop never cancels, and the volume is
  -- gone, so nothing would ever settle the cut.
  SELECT v.retired_at INTO v_retired
    FROM public.volumes v WHERE v.id=p_volume AND v.tenant_id=p_tenant;
  IF v_retired IS NOT NULL THEN
    RAISE EXCEPTION 'volume % is retired; history cuts are not defined for it', p_volume
      USING ERRCODE='PF001';
  END IF;

  v_source_kind := v_capture->>'sourceKind';
  IF v_source_kind = 'legacy_manifest' AND p_kind <> 'conversion_final' THEN
    RAISE EXCEPTION 'legacy_manifest branches only take conversion_final cuts'
      USING ERRCODE='PF001';
  END IF;
  IF p_kind = 'conversion_final'
     AND v_source_kind = 'managed_journal'
     AND COALESCE(v_capture->>'recordCodec','pfr1') <> 'pfr1' THEN
    RAISE EXCEPTION 'conversion_final cuts capture pfr1/legacy sources only'
      USING ERRCODE='PF005';
  END IF;

  -- Chained cuts (026): base on the branch's newest ready cut of this
  -- generation when one sits strictly below the captured head.
  IF v_source_kind = 'managed_journal' AND p_kind <> 'conversion_final' THEN
    SELECT hc.result_commit_id, hc.cut_seq_exclusive, hc.cut_digest
      INTO v_chain
      FROM pfh.history_cuts hc
      WHERE hc.generation_id = v_capture->>'generationId'
        AND hc.source_kind = 'managed_journal'
        AND hc.state = 'ready'
        AND hc.result_commit_id IS NOT NULL
        AND hc.record_codec IS NOT DISTINCT FROM v_capture->>'recordCodec'
        AND hc.cut_seq_exclusive >= (v_capture->>'baseSeq')::BIGINT
        AND hc.cut_seq_exclusive < (v_capture->>'cutSeqExclusive')::BIGINT
      ORDER BY hc.cut_seq_exclusive DESC, hc.ready_db_ms DESC, hc.id DESC
      LIMIT 1;
    IF FOUND THEN
      v_capture := v_capture || jsonb_build_object(
        'baseCommitId', v_chain.result_commit_id,
        'baseSeq', v_chain.cut_seq_exclusive::TEXT,
        'baseDigest', v_chain.cut_digest);
    END IF;
  END IF;

  -- The branch's durable inode namespace exists from the first cut onward.
  PERFORM pfh.inode_namespace_issue(
    p_tenant, p_volume, v_capture->>'branchId',
    CASE WHEN p_kind='conversion_final' THEN 'conversion' ELSE 'branch' END);

  v_now := pfh.now_ms();
  v_dedup_key := CASE v_source_kind
    WHEN 'managed_journal' THEN
      'g'||E'\x01'||(v_capture->>'generationId')||E'\x01'||(v_capture->>'cutSeqExclusive')
    ELSE
      'h'||E'\x01'||(v_capture->>'branchId')||E'\x01'||(v_capture->>'headCommitId')
  END;

  -- Kind-agnostic convergence between user and recovery: cuts at the same
  -- exact boundary are the same materialization regardless of the label
  -- that requested them. Live rows win over terminal ones.
  SELECT * INTO v_cut FROM pfh.history_cuts
    WHERE dedup_key=v_dedup_key
      AND (kind=p_kind
           OR (p_kind IN ('user','recovery') AND kind IN ('user','recovery')))
    ORDER BY (state NOT IN ('failed','canceled')) DESC,
             dedup_revision DESC, created_db_ms DESC, id DESC
    LIMIT 1
    FOR UPDATE;
  IF FOUND AND v_cut.state NOT IN ('failed','canceled') THEN
    -- Concurrent identical captures converge onto the live cut row. THIS
    -- operation settles now: its outcome is the existing cut (usable or
    -- progressing under its own original operation). A labeled request
    -- converging onto an unlabeled row adopts the label (first wins).
    IF p_user_label IS NOT NULL AND v_cut.user_label IS NULL THEN
      UPDATE pfh.history_cuts SET user_label=p_user_label, updated_db_ms=v_now
      WHERE id=v_cut.id;
    END IF;
    PERFORM pfh.resource_operation_finish(
      p_tenant, 'history-cut', p_operation_id, 'succeeded',
      jsonb_build_object('cutId', v_cut.id, 'state', v_cut.state, 'deduplicated', TRUE));
    RETURN pfh.cut_status(p_tenant, v_cut.id);
  END IF;
  -- A fresh revision after definite failure: the revision counter spans
  -- the converged kind set (revisions stay unique per kind either way).
  SELECT COALESCE(MAX(dedup_revision),0)+1 INTO v_revision
    FROM pfh.history_cuts
    WHERE dedup_key=v_dedup_key
      AND (kind=p_kind
           OR (p_kind IN ('user','recovery') AND kind IN ('user','recovery')));

  v_id := pfh.new_id('hcut');
  INSERT INTO pfh.history_cuts (
    id, tenant_id, volume_id, branch_id, branch_name, kind, source_kind,
    generation_id, journal_epoch, record_codec, control_codec,
    source_base_commit_id, source_base_seq, source_base_digest,
    cut_seq_exclusive, cut_digest, cut_backlog_bytes, cut_backlog_records,
    source_head_commit_id,
    materializer_version, replication_policy, dedup_key, dedup_revision,
    request_fingerprint, op_tenant_id, op_domain, op_operation_id,
    state, user_label, created_db_ms, updated_db_ms)
  VALUES (
    v_id, p_tenant, p_volume, v_capture->>'branchId', p_branch_name, p_kind,
    v_source_kind,
    v_capture->>'generationId',
    (v_capture->>'journalEpoch')::BIGINT,
    v_capture->>'recordCodec', v_capture->>'controlCodec',
    v_capture->>'baseCommitId',
    (v_capture->>'baseSeq')::BIGINT,
    v_capture->>'baseDigest',
    (v_capture->>'cutSeqExclusive')::BIGINT,
    v_capture->>'cutDigest',
    (v_capture->>'backlogBytes')::BIGINT,
    (v_capture->>'backlogRecords')::BIGINT,
    v_capture->>'headCommitId',
    p_materializer_version,
    jsonb_build_object(
      'v','1',
      'requiredFailureDomains', v_policy.policy->'requiredFailureDomains',
      'policyEpoch', v_policy.policy_epoch::TEXT),
    v_dedup_key, v_revision, p_fingerprint,
    p_tenant, 'history-cut', p_operation_id,
    'pending', p_user_label, v_now, v_now);

  -- Record the preallocated target on the still-pending operation.
  UPDATE pfh.resource_operations SET
    target_ids = target_ids || jsonb_build_object('cutId', v_id),
    updated_db_ms = v_now
  WHERE tenant_id=p_tenant AND domain='history-cut' AND operation_id=p_operation_id;
  RETURN pfh.cut_status(p_tenant, v_id);
END;
$$;

-- 033 revision of the 013 cancel: the exact 013 body with the branch
-- advisory lock taken at position 0, before the pfh row lock, so
-- cancellation shares the lock order of creation and retirement.
CREATE OR REPLACE FUNCTION pfh.cut_cancel(
  p_tenant TEXT, p_cut_id TEXT, p_operation_id TEXT, p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
  v_op JSONB;
  v_scope RECORD;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'cancel fingerprint');
  v_op := pfh.resource_operation_begin(
    p_tenant, 'history-cut', p_operation_id, 'cut-cancel', p_fingerprint,
    jsonb_build_object('cutId', p_cut_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  -- 033: join the common lock order. The scope is read WITHOUT a row lock
  -- first (the cut's volume/branch are immutable), the advisory lock is
  -- taken, and only then is the cut row locked.
  SELECT hc.volume_id, hc.branch_name INTO v_scope
    FROM pfh.history_cuts hc WHERE hc.id=p_cut_id AND hc.tenant_id=p_tenant;
  IF FOUND AND v_scope.branch_name IS NOT NULL THEN
    PERFORM pfj.branch_scope_lock(p_tenant, v_scope.volume_id, v_scope.branch_name);
  END IF;
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF c.state NOT IN ('pending','materializing') THEN
    RAISE EXCEPTION 'cut % is % and cannot be canceled', p_cut_id, c.state
      USING ERRCODE='PF002';
  END IF;
  IF EXISTS (SELECT 1 FROM pfh.cut_consumers
             WHERE cut_id=p_cut_id AND released_db_ms IS NULL
               AND consumer_kind IN ('conversion','adoption')) THEN
    RAISE EXCEPTION 'cut % is pinned by a conversion/adoption consumer', p_cut_id
      USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.history_cuts SET
    state='canceled', lease_expires_db_ms=NULL, updated_db_ms=v_now
  WHERE id=p_cut_id;
  -- Settle BOTH operations: the original create settles 'canceled', this
  -- cancel operation settles 'succeeded' (cut row already locked above).
  PERFORM pfh.resource_operation_finish(
    c.op_tenant_id, c.op_domain, c.op_operation_id, 'canceled',
    jsonb_build_object('cutId', p_cut_id, 'state', 'canceled'));
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'history-cut', p_operation_id, 'succeeded',
    jsonb_build_object('cutId', p_cut_id, 'state', 'canceled'));
  RETURN jsonb_build_object('cutId', p_cut_id, 'state', 'canceled', 'replayed', FALSE);
END;
$$;

RESET ROLE;

-- ═══ SECTION D: the receipt and the transition ══════════════════════════════

-- The 021 flip, plus the durable obligation, in ONE transaction.
--
-- Returns NULL for an unknown or foreign volume (the caller keeps its
-- non-enumerating 404). For a volume that is already retired it returns the
-- stored receipt AND re-asserts the task row, so a receipt minted before
-- this migration — or one whose enqueue was lost to a crash — acquires its
-- obligation on the next replay instead of never.
CREATE FUNCTION public.portablefs_volume_retire(
  p_tenant TEXT, p_volume TEXT, p_now_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_retired TIMESTAMPTZ;
  v_flipped BOOLEAN := FALSE;
  v_now BIGINT := COALESCE(p_now_ms, (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT);
BEGIN
  UPDATE public.volumes
     SET retired_at = to_timestamp(v_now::double precision / 1000.0)
   WHERE id = p_volume AND tenant_id = p_tenant AND retired_at IS NULL
  RETURNING retired_at INTO v_retired;
  IF FOUND THEN
    v_flipped := TRUE;
  ELSE
    SELECT v.retired_at INTO v_retired
      FROM public.volumes v
     WHERE v.id = p_volume AND v.tenant_id = p_tenant AND v.retired_at IS NOT NULL;
    IF NOT FOUND THEN
      -- Unknown, foreign, or (impossibly) live-after-a-lost-race: the caller
      -- serves all three as the same non-enumerating answer.
      RETURN NULL;
    END IF;
  END IF;

  -- The obligation is part of the receipt's transaction, not a follow-up.
  INSERT INTO public.portablefs_volume_retirement_tasks AS t
    (volume_id, tenant_id, enqueued_at_ms, next_attempt_ms, attempts)
  VALUES (p_volume, p_tenant, v_now, v_now, 0)
  ON CONFLICT (volume_id) DO UPDATE
    -- A replay of a still-incomplete task pulls its next attempt forward:
    -- the client asking again is the best evidence the work is wanted now.
    SET next_attempt_ms = LEAST(t.next_attempt_ms, v_now)
    WHERE t.completed_at_ms IS NULL;

  RETURN jsonb_build_object(
    'volumeId', p_volume,
    'retiredAtMs', (EXTRACT(EPOCH FROM v_retired) * 1000)::BIGINT::TEXT,
    'flipped', v_flipped);
END;
$$;

-- The whole retirement transition, atomically.
--
-- Order is the point:
--   0. every branch advisory lock of the volume (sorted) — the SAME keys
--      pfh.cut_create/pfh.cut_cancel take through pfj.history_head_capture;
--   1. the 021 receipt must already exist (a live volume is refused, PF011);
--   2. pfh.volume_retire_cleanup — pins released, conversions voided,
--      non-terminal cuts canceled;
--   3. pfj.journal_retire_for_volume — generations terminal, base driven to
--      tip, so the WHOLE journal falls below the reclamation horizon;
--   4. the task is marked complete.
-- 2 and 3 are now one transaction, so no cut can be created between them and
-- no cut created before them can survive them.
CREATE FUNCTION public.portablefs_volume_retire_finish(
  p_tenant TEXT, p_volume TEXT, p_now_ms BIGINT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_retired TIMESTAMPTZ;
  v_found BOOLEAN;
  v_now BIGINT := COALESCE(p_now_ms, (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT);
  v_branches INT;
  v_cleanup JSONB;
  v_journal JSONB;
BEGIN
  IF p_tenant IS NULL OR p_volume IS NULL THEN
    RAISE EXCEPTION 'retirement transition requires tenant and volume ids'
      USING ERRCODE='PF008';
  END IF;
  v_branches := pfj.volume_branch_locks(p_tenant, p_volume);
  SELECT v.retired_at, TRUE INTO v_retired, v_found
    FROM public.volumes v WHERE v.id=p_volume AND v.tenant_id=p_tenant;
  IF NOT COALESCE(v_found, FALSE) THEN
    RAISE EXCEPTION 'volume % not found', p_volume USING ERRCODE='PF007';
  END IF;
  IF v_retired IS NULL THEN
    RAISE EXCEPTION 'volume % is not retired; the retirement receipt is the precondition',
      p_volume USING ERRCODE='PF011';
  END IF;

  v_cleanup := pfh.volume_retire_cleanup(p_tenant, p_volume);
  v_journal := pfj.journal_retire_for_volume(p_tenant, p_volume);

  UPDATE public.portablefs_volume_retirement_tasks
     SET completed_at_ms = v_now,
         attempts = attempts + 1,
         last_error = NULL
   WHERE volume_id = p_volume AND tenant_id = p_tenant;

  RETURN jsonb_build_object(
    'volumeId', p_volume,
    'branchesLocked', v_branches::TEXT,
    'cleanup', v_cleanup,
    'journal', v_journal,
    'completedAtMs', v_now::TEXT);
END;
$$;

-- The drain's claim step. SKIP LOCKED so N replicas share the queue without
-- stampeding one row, and the attempt/backoff bump happens in the CLAIM
-- transaction, so a claimer that then crashes still yields a retry.
CREATE FUNCTION public.portablefs_volume_retirement_tasks_claim(
  p_limit INT DEFAULT 8,
  p_now_ms BIGINT DEFAULT NULL,
  p_backoff_ms BIGINT DEFAULT 60000
) RETURNS JSONB
LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit, 8), 1), 64);
  v_now BIGINT := COALESCE(p_now_ms, (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT);
  v_backoff BIGINT := LEAST(GREATEST(COALESCE(p_backoff_ms, 60000), 1000), 3600000);
  v_out JSONB;
BEGIN
  -- A data-modifying CTE must be the top level of its statement, so the
  -- aggregation lands in a variable rather than inside a scalar subquery.
  WITH due AS (
    SELECT t.volume_id
      FROM public.portablefs_volume_retirement_tasks t
     WHERE t.completed_at_ms IS NULL
       AND t.next_attempt_ms <= v_now
     ORDER BY t.next_attempt_ms, t.volume_id
     LIMIT v_limit
     FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE public.portablefs_volume_retirement_tasks t
       SET attempts = t.attempts + 1,
           -- Linear-in-attempts, hard-capped: a permanently failing task
           -- retries forever but never faster than the backoff ceiling.
           next_attempt_ms = v_now + LEAST(v_backoff * (t.attempts + 1), 3600000)
      FROM due
     WHERE t.volume_id = due.volume_id
    RETURNING t.volume_id, t.tenant_id, t.attempts
  )
  SELECT jsonb_agg(jsonb_build_object(
           'volumeId', volume_id,
           'tenantId', tenant_id,
           'attempts', attempts::TEXT) ORDER BY volume_id)
    INTO v_out
    FROM claimed;
  RETURN COALESCE(v_out, '[]'::JSONB);
END;
$$;

-- Records why an attempt failed. The retry itself is already scheduled by
-- the claim, so this is observability, not control flow — and it must be
-- callable in a FRESH transaction after the failed one rolled back.
CREATE FUNCTION public.portablefs_volume_retirement_task_defer(
  p_tenant TEXT, p_volume TEXT, p_error TEXT
) RETURNS VOID
LANGUAGE sql VOLATILE
SET search_path = pg_catalog, public, pg_temp
AS $$
  UPDATE public.portablefs_volume_retirement_tasks
     SET last_error = left(COALESCE(p_error, 'unknown error'), 500)
   WHERE volume_id = p_volume AND tenant_id = p_tenant AND completed_at_ms IS NULL;
$$;

-- ═══ SECTION E: grants ══════════════════════════════════════════════════════

REVOKE ALL ON FUNCTION
  public.portablefs_volume_retire(TEXT, TEXT, BIGINT),
  public.portablefs_volume_retire_finish(TEXT, TEXT, BIGINT),
  public.portablefs_volume_retirement_tasks_claim(INT, BIGINT, BIGINT),
  public.portablefs_volume_retirement_task_defer(TEXT, TEXT, TEXT)
FROM PUBLIC;
REVOKE ALL ON FUNCTION pfj.volume_branch_locks(TEXT, TEXT) FROM PUBLIC;

-- The maintenance-plane caller (the volume-api repository's admin DSN role),
-- the exact 013/017/022/031 grant pattern. The restricted authority and
-- worker roles gain NOTHING.
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION pfj.volume_branch_locks(TEXT, TEXT) TO %I',
                 CURRENT_USER);
END
$$;

-- ═══ SECTION F: postconditions ══════════════════════════════════════════════

DO $post$
DECLARE
  v_def TEXT;
  v_count BIGINT;
BEGIN
  IF to_regclass('public.portablefs_volume_retirement_tasks') IS NULL THEN
    RAISE EXCEPTION '033 postcondition: the retirement task queue is absent';
  END IF;
  IF to_regprocedure('public.portablefs_volume_retire(text,text,bigint)') IS NULL
     OR to_regprocedure('public.portablefs_volume_retire_finish(text,text,bigint)') IS NULL
     OR to_regprocedure('public.portablefs_volume_retirement_tasks_claim(int,bigint,bigint)') IS NULL
     OR to_regprocedure('public.portablefs_volume_retirement_task_defer(text,text,text)') IS NULL
     OR to_regprocedure('pfj.volume_branch_locks(text,text)') IS NULL THEN
    RAISE EXCEPTION '033 postcondition: the retirement transition surface is incomplete';
  END IF;

  -- The receipt and the obligation are ONE transaction. A regression that
  -- splits them re-opens (a) exactly.
  v_def := pg_get_functiondef(to_regprocedure('public.portablefs_volume_retire(text,text,bigint)'));
  IF position('portablefs_volume_retirement_tasks' IN v_def) = 0
     OR position('UPDATE public.volumes' IN v_def) = 0 THEN
    RAISE EXCEPTION '033 postcondition: the retirement flip no longer enqueues its obligation';
  END IF;

  -- Cleanup and journal retirement are ONE transaction, under the branch
  -- lock order. A regression that drops either re-opens (b).
  v_def := pg_get_functiondef(
    to_regprocedure('public.portablefs_volume_retire_finish(text,text,bigint)'));
  IF position('pfj.volume_branch_locks' IN v_def) = 0
     OR position('pfh.volume_retire_cleanup' IN v_def) = 0
     OR position('pfj.journal_retire_for_volume' IN v_def) = 0 THEN
    RAISE EXCEPTION '033 postcondition: the retirement transition is no longer atomic under one lock order';
  END IF;

  -- cut_create refuses a retired volume, and does so AFTER the branch lock.
  v_def := pg_get_functiondef(
    to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb,text)'));
  IF position('history cuts are not defined for it' IN v_def) = 0 THEN
    RAISE EXCEPTION '033 postcondition: cut_create no longer refuses a retired volume';
  END IF;
  IF position('pfj.history_head_capture' IN v_def) = 0
     OR position('pfj.history_head_capture' IN v_def)
        > position('history cuts are not defined for it' IN v_def) THEN
    RAISE EXCEPTION '033 postcondition: the retired check must follow the branch lock capture';
  END IF;

  -- cut_cancel joined the lock order.
  v_def := pg_get_functiondef(to_regprocedure('pfh.cut_cancel(text,text,text,text)'));
  IF position('pfj.branch_scope_lock' IN v_def) = 0 THEN
    RAISE EXCEPTION '033 postcondition: cut_cancel is outside the common lock order';
  END IF;

  -- The restricted roles gained NOTHING.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
   WHERE ((n.nspname='pfj' AND p.proname='volume_branch_locks')
          OR (n.nspname='public' AND p.proname LIKE 'portablefs_volume_retire%'))
     AND acl.grantee IN (
       'portablefs_authority'::regrole,
       'portablefs_history_worker'::regrole)
     AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '033 postcondition: a restricted role can drive volume retirement';
  END IF;

  -- The due-work index must exist: the drain runs every maintenance cycle and
  -- must cost outstanding work, not history.
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
     WHERE schemaname='public' AND indexname='portablefs_volume_retirement_tasks_due') THEN
    RAISE EXCEPTION '033 postcondition: the due-task index is absent';
  END IF;

  -- Lineage: 034 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '034%') THEN
    RAISE EXCEPTION '033 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
