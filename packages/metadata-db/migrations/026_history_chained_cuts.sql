-- 026_history_chained_cuts: capture bases on the newest ready cut.
--
-- A managed-journal cut used to fold from the generation's ADOPTION-PINNED
-- base: the base only advanced at adoption, so every cut re-folded (and,
-- before 024, re-uploaded) the branch's whole backlog since the last
-- adoption — O(journal backlog) work per cut, growing until the next
-- adoption. This migration makes pfh.cut_create's capture select the
-- branch's newest READY managed cut of the same generation as the frozen
-- source base whenever one exists strictly below the captured head:
--
--   * The chained base is the ready cut's (result commit, cutSeqExclusive,
--     cutDigest) — the exact chain-digest boundary the reducer verifies
--     continuity from, so the fold covers only the tail since the last
--     ready cut. cut_status projects the base commit as baseMode
--     'adopted' (same branch) with its verified recovery anchor; the
--     reducer already loads, binds, and re-verifies adopted anchors —
--     it needs no changes, and no MaterializerVersion bump: the frozen
--     tuple is a DIFFERENT tuple, not changed bytes for an existing one.
--   * Dedup semantics are unchanged: one live cut per
--     (generationId, cutSeqExclusive) and kind, converged FOR UPDATE.
--   * Adoption cadence is unchanged (journal trimming stays adoption's
--     job). pfh.cut_adopt now reads the OLD base tuple for its proof row
--     from the GENERATION (pfj.journal_generations), not from the cut —
--     a chained cut's source base is a ready-cut boundary, not the
--     adoption-pinned base the freeze trigger and pfj.history_adopt_base
--     verify. The captured cumulative backlog counters stay
--     adoption-relative, so the O(1) subtraction is untouched.
--   * pfh.object_is_root grows the one clause chaining structurally
--     needs: the closures of a ready cut whose commit is the SOURCE BASE
--     of a live (pending/materializing) cut are roots while that fold is
--     in flight. Today every in-flight base is also the generation base
--     (already a root); with chaining it usually is not.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF001 stale/fenced, PF002
-- conflict, PF005 codec, PF007 not found, PF008 invalid argument, PF011
-- proof missing).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='025_history_write_quorum'
  ) THEN
    RAISE EXCEPTION '026 preflight: 025_history_write_quorum receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '027%'
  ) THEN
    RAISE EXCEPTION '026 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb,text)') IS NULL
     OR to_regprocedure('pfh.cut_adopt(text,text,text,text,text,text)') IS NULL
     OR to_regprocedure('pfh.object_is_root(text,text,text)') IS NULL THEN
    RAISE EXCEPTION '026 preflight: the 013/019 cut surface is incomplete';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — chained capture ═════════════════════════
SET LOCAL ROLE portablefs_history_owner;

-- The chain-base selection scans ready cuts per generation on every
-- capture; give it an exact partial index.
CREATE INDEX history_cuts_ready_chain
  ON pfh.history_cuts (generation_id, cut_seq_exclusive DESC)
  WHERE state='ready' AND source_kind='managed_journal';

-- 026 revision of the 019 labeled cut creation: the exact 019 body plus
-- the chained-base selection between head capture and dedup. Everything
-- else — capture under the append lock order, the pending-until-usable
-- outer operation, dedup convergence, the preallocated target id, the
-- label — is byte-identical in behaviour.
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

  -- Chained cuts: base on the branch's newest ready cut of this generation
  -- when one sits strictly below the captured head, instead of the
  -- adoption-pinned base — the fold then covers only the tail since that
  -- cut. Strictly below: an idle boundary either converges on the dedup
  -- key or re-folds from the previous boundary; a zero-record fold is
  -- never created. Same generation and codec only — the chain digest is a
  -- pure function of the generation's records, so continuity from the
  -- ready cut's (cutSeqExclusive, cutDigest) is exactly what the reducer
  -- verifies. The conversion pipeline (conversion_final) drains whole
  -- legacy generations and never chains.
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

  SELECT * INTO v_cut FROM pfh.history_cuts
    WHERE dedup_key=v_dedup_key AND kind=p_kind
    ORDER BY dedup_revision DESC LIMIT 1
    FOR UPDATE;
  IF FOUND AND v_cut.state NOT IN ('failed','canceled') THEN
    -- Concurrent identical captures converge onto the live cut row. THIS
    -- operation settles now: its outcome is the existing cut (usable or
    -- progressing under its own original operation).
    PERFORM pfh.resource_operation_finish(
      p_tenant, 'history-cut', p_operation_id, 'succeeded',
      jsonb_build_object('cutId', v_cut.id, 'state', v_cut.state, 'deduplicated', TRUE));
    RETURN pfh.cut_status(p_tenant, v_cut.id);
  END IF;
  v_revision := COALESCE(v_cut.dedup_revision, 0) + 1;

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

-- 026 revision of the 013 adoption: the proof row's OLD base tuple reads
-- from the GENERATION (the tuple pfj.history_adopt_base and the freeze
-- trigger verify), because a chained cut's own source base is a ready-cut
-- boundary, not the adoption-pinned base. The read is optimistic — a
-- concurrent adoption between it and the journal primitive surfaces as
-- the primitive's typed PF002 refusal, exactly like today's stale-base
-- race. Everything else is byte-identical in behaviour.
CREATE OR REPLACE FUNCTION pfh.cut_adopt(
  p_tenant TEXT, p_cut_id TEXT, p_anchor_id TEXT,
  p_operation_id TEXT, p_fingerprint TEXT, p_serving_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  ra pfh.recovery_anchors;
  v_gen RECORD;
  v_op JSONB;
  v_now BIGINT;
  v_id TEXT;
  v_advance JSONB;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'adoption fingerprint');
  -- Capability gate: adoption is blocked until the operator/manager proves
  -- the serving fleet can open PFT2 bases (the managed child advertises
  -- pft2-base in its bootstrap features; the manager forwards this token).
  IF p_serving_capability IS DISTINCT FROM 'pft2-base-v1' THEN
    RAISE EXCEPTION 'adoption requires the pft2-base-v1 serving capability proof'
      USING ERRCODE='PF011';
  END IF;
  v_op := pfh.resource_operation_begin(
    p_tenant, 'adoption', p_operation_id, 'cut-adopt', p_fingerprint,
    jsonb_build_object('cutId', p_cut_id, 'anchorId', p_anchor_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  -- Plain read: 'ready' is stable (cancel refuses non-pending states) and the
  -- freeze trigger re-verifies the exact tuple under the generation lock, so
  -- no pfh row lock is held before the branch advisory lock (lock order).
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF c.state <> 'ready' OR c.result_commit_id IS NULL THEN
    RAISE EXCEPTION 'cut % is not ready', p_cut_id USING ERRCODE='PF011';
  END IF;
  IF c.kind <> 'recovery' OR c.source_kind <> 'managed_journal'
     OR c.record_codec <> 'pfj3' THEN
    RAISE EXCEPTION 'adoption requires a ready recovery cut of a pfj3 managed journal'
      USING ERRCODE='PF011';
  END IF;
  SELECT * INTO ra FROM pfh.recovery_anchors
    WHERE id=p_anchor_id AND tenant_id=p_tenant;
  IF NOT FOUND OR ra.cut_id <> p_cut_id THEN
    -- The matching-boundary rule: the anchor must be THE anchor of this cut.
    RAISE EXCEPTION 'anchor % does not bound cut %', p_anchor_id, p_cut_id
      USING ERRCODE='PF011';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pfh.history_cuts older
    WHERE older.generation_id=c.generation_id
      AND older.state IN ('pending','materializing')
      AND older.cut_seq_exclusive < c.cut_seq_exclusive) THEN
    RAISE EXCEPTION 'an older pending cut still pins the prefix' USING ERRCODE='PF011';
  END IF;
  -- The old base the adoption replaces is the GENERATION's current base
  -- (what a still-serving child holds), never the cut's chained source.
  SELECT g.base_seq, g.base_digest, g.base_commit_id INTO v_gen
    FROM pfj.journal_generations g WHERE g.id=c.generation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'generation % of cut % is gone', c.generation_id, p_cut_id
      USING ERRCODE='PF007';
  END IF;
  IF c.cut_seq_exclusive < v_gen.base_seq THEN
    RAISE EXCEPTION 'cut % boundary % is behind the adopted base %',
      p_cut_id, c.cut_seq_exclusive, v_gen.base_seq USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  v_id := pfh.new_id('hadopt');
  INSERT INTO pfh.adoptions (
    id, cut_id, anchor_id, generation_id, tenant_id, op_operation_id,
    old_base_seq, old_base_digest, old_base_commit_id,
    new_base_seq, new_base_digest, new_base_commit_id,
    subtract_backlog_bytes, subtract_backlog_records,
    state, created_db_ms)
  VALUES (
    v_id, p_cut_id, p_anchor_id, c.generation_id, p_tenant, p_operation_id,
    v_gen.base_seq, v_gen.base_digest, v_gen.base_commit_id,
    c.cut_seq_exclusive, c.cut_digest, c.result_commit_id,
    c.cut_backlog_bytes, c.cut_backlog_records,
    'applying', v_now);
  -- Journal-owner primitive: branch advisory -> generation row; verifies the
  -- exact old base, advances it, and subtracts the captured backlog; the
  -- replaced freeze trigger re-verifies against the 'applying' row inserted
  -- above (same transaction). Returns the pinned runtime facts.
  v_advance := pfj.history_adopt_base(v_id);
  UPDATE pfh.adoptions SET state='applied', applied_db_ms=pfh.now_ms() WHERE id=v_id;
  PERFORM pfh.consumer_attach(p_tenant, p_cut_id, 'adoption', v_id);
  INSERT INTO pfh.serving_base_pins (
    adoption_id, cut_id, anchor_id, tenant_id, generation_id, writer_fence,
    manager_epoch, authority_runtime_id, authority_runtime_seq,
    old_base_commit_id, old_base_root_digest, old_anchor_id, created_db_ms)
  SELECT v_id, p_cut_id, p_anchor_id, p_tenant, c.generation_id,
         COALESCE((v_advance->>'writerFence')::BIGINT, 0),
         (v_advance->>'managerEpoch')::BIGINT,
         v_advance->>'authorityRuntimeId',
         (v_advance->>'authorityRuntimeSeq')::BIGINT,
         v_gen.base_commit_id,
         bp.root_digest, ba.id, v_now
  FROM (SELECT 1) one
  LEFT JOIN pfh.pft2_commits bp ON bp.commit_id=v_gen.base_commit_id
  LEFT JOIN pfh.recovery_anchors ba ON ba.commit_id=v_gen.base_commit_id;
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'adoption', p_operation_id, 'succeeded',
    jsonb_build_object('adoptionId', v_id, 'cutId', p_cut_id,
                       'anchorId', p_anchor_id,
                       'newBaseCommitId', c.result_commit_id));
  RETURN jsonb_build_object(
    'adoptionId', v_id, 'cutId', p_cut_id, 'anchorId', p_anchor_id,
    'state', 'applied',
    'newBaseSeq', c.cut_seq_exclusive::TEXT, 'newBaseDigest', c.cut_digest,
    'newBaseCommitId', c.result_commit_id,
    'writerFence', COALESCE(v_advance->>'writerFence','0'),
    'managerEpoch', v_advance->>'managerEpoch',
    'authorityRuntimeId', v_advance->>'authorityRuntimeId',
    'authorityRuntimeSeq', v_advance->>'authorityRuntimeSeq');
END;
$$;

-- 026 revision of the 013 root predicate: identical clauses plus the one
-- chaining structurally requires — a ready cut whose commit is the source
-- base of a live (pending/materializing) cut roots its closures while
-- that fold is in flight. (Until now every in-flight base was also the
-- generation base and rooted through that clause.)
CREATE OR REPLACE FUNCTION pfh.object_is_root(p_tenant TEXT, p_kind TEXT, p_digest TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  -- 026_history_chained_cuts revision.
  RETURN EXISTS (
    SELECT 1 FROM pfh.upload_intents ui
    JOIN pfh.history_cuts hc ON hc.id=ui.cut_id
    WHERE ui.tenant_id=p_tenant AND ui.kind=p_kind AND ui.digest=p_digest
      AND hc.state IN ('pending','materializing'))
  OR EXISTS (
    SELECT 1 FROM pfh.cut_objects co
    JOIN pfh.history_cuts hc ON hc.id=co.cut_id
    WHERE co.tenant_id=p_tenant AND co.kind=p_kind AND co.digest=p_digest
      AND hc.state='ready'
      AND (EXISTS (SELECT 1 FROM pfh.cut_consumers cc
                   WHERE cc.cut_id=hc.id AND cc.released_db_ms IS NULL)
        OR EXISTS (SELECT 1 FROM pfh.serving_base_pins sp
                   WHERE sp.cut_id=hc.id AND sp.released_db_ms IS NULL)
        OR EXISTS (SELECT 1 FROM pfh.serving_base_pins sp
                   JOIN pfh.pft2_commits oldp ON oldp.commit_id=sp.old_base_commit_id
                   WHERE oldp.cut_id=hc.id AND sp.released_db_ms IS NULL)
        OR EXISTS (SELECT 1 FROM pfh.pft2_commits pc
                   JOIN pfh.history_cuts child
                     ON child.source_base_commit_id=pc.commit_id
                   WHERE pc.cut_id=hc.id
                     AND child.state IN ('pending','materializing'))
        OR EXISTS (SELECT 1 FROM pfh.pft2_commits pc
                   JOIN public.commits cm ON cm.id=pc.commit_id
                   WHERE pc.cut_id=hc.id
                     AND (EXISTS (SELECT 1 FROM public.branches b
                                  WHERE b.head_commit_id=cm.id)
                       OR EXISTS (SELECT 1 FROM public.snapshots s
                                  WHERE s.commit_id=cm.id)
                       OR EXISTS (SELECT 1 FROM public.commits child
                                  WHERE child.parent_commit_id=cm.id)
                       OR EXISTS (SELECT 1 FROM pfj.journal_generations jg
                                  WHERE jg.base_commit_id=cm.id
                                    AND jg.status IN ('active','suspended','retiring'))))));
END;
$$;

RESET ROLE;

-- ═══ SECTION B: postconditions ════════════════════════════════════════════════
-- No grant changes: every replaced function keeps its grants through
-- CREATE OR REPLACE, and the chain index is owner-internal.
DO $post$
DECLARE
  v_rec RECORD;
BEGIN
  IF to_regclass('pfh.history_cuts_ready_chain') IS NULL THEN
    RAISE EXCEPTION '026 postcondition: the ready-chain index is missing';
  END IF;
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, pg_get_userbyid(p.proowner) AS owner,
           p.prosecdef,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh'
      AND ((p.proname='cut_create' AND p.pronargs=9)
        OR p.proname='cut_adopt'
        OR p.proname='object_is_root')
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner'
       OR v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '026 postcondition: pfh.% owner/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '026 postcondition: PUBLIC can execute pfh.%', v_rec.proname;
    END IF;
  END LOOP;
  -- The replaced bodies actually landed.
  IF position('Chained cuts' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb,text)'))) = 0 THEN
    RAISE EXCEPTION '026 postcondition: cut_create does not select chained bases';
  END IF;
  IF position('journal_generations g WHERE g.id=c.generation_id' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_adopt(text,text,text,text,text,text)'))) = 0 THEN
    RAISE EXCEPTION '026 postcondition: cut_adopt does not read the generation base';
  END IF;
  IF position('child.source_base_commit_id=pc.commit_id' IN pg_get_functiondef(
       to_regprocedure('pfh.object_is_root(text,text,text)'))) = 0 THEN
    RAISE EXCEPTION '026 postcondition: object_is_root misses the in-flight-base clause';
  END IF;
  -- Lineage: 027 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '027%') THEN
    RAISE EXCEPTION '026 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
