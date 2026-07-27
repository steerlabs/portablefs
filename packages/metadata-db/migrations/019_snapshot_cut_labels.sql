-- 019_snapshot_cut_labels: the user snapshot label on journal-era cuts.
--
-- A cut-backed snapshot (`portablefs snapshot --name x` on a journal-served
-- branch) previously embedded the name only in the request's canonical JSON,
-- whose sha256 fingerprint is all the database retains — so every cut
-- projection and listing answered name-less. The label is a USER fact of the
-- snapshot record, so it lives on the cut row itself and rides every read.
--
-- What this migration does, exactly:
--   1. pfh.history_cuts gains the nullable bounded user_label column
--      (1..256 chars, the exact snapshot-name wire bounds). Additive; no
--      stored row changes meaning — pre-019 cuts stay NULL ("unnamed").
--   2. pfh.cut_create grows a 9th p_user_label parameter (a new signature —
--      the 013 eight-argument signature cannot carry it). The 013 signature
--      is REPLACED as a delegator to the new one with a NULL label, so a
--      not-yet-redeployed caller keeps working mid-rollout; the label rides
--      the INSERT only — the dedup convergence arm answers the EXISTING live
--      cut unchanged (first capture's label wins; the journal position, not
--      the label, is the cut's identity).
--   3. pfh.cut_status is replaced forward (same signature; every existing
--      key byte-identical) with the one additive userLabel key
--      (jsonb_strip_nulls drops it for unnamed cuts).
--
-- Fork/branch-from-cut label semantics are deliberately untouched: fork
-- consumers name their own cut.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF008 invalid argument).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='018_managed_volume_fork'
  ) THEN
    RAISE EXCEPTION '019 preflight: 018_managed_volume_fork receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '020%'
  ) THEN
    RAISE EXCEPTION '019 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfh.history_cuts') IS NULL
     OR to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb)') IS NULL
     OR to_regprocedure('pfh.cut_status(text,text)') IS NULL THEN
    RAISE EXCEPTION '019 preflight: the 013 cut surface is incomplete';
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='pfh' AND table_name='history_cuts' AND column_name='user_label'
  ) THEN
    RAISE EXCEPTION '019 preflight: pfh.history_cuts.user_label already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — label column + labeled cut creation ═════
SET LOCAL ROLE portablefs_history_owner;

ALTER TABLE pfh.history_cuts
  ADD COLUMN user_label TEXT
    CONSTRAINT history_cuts_user_label_bounds
    CHECK (user_label IS NULL OR length(user_label) BETWEEN 1 AND 256);

-- The labeled cut creation: the exact 013 body plus the validated label on
-- the INSERT. Everything else — capture under the append lock order, the
-- pending-until-usable outer operation, dedup convergence, the preallocated
-- target id — is byte-identical in behaviour. On dedup convergence the
-- EXISTING live cut answers unchanged: the label is a record fact of the
-- capture that created the row, never a second identity axis.
CREATE FUNCTION pfh.cut_create(
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
REVOKE ALL ON FUNCTION
  pfh.cut_create(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB,TEXT)
FROM PUBLIC;

-- The 013 signature stays callable as a label-free delegator: a volume-api
-- replica still running pre-019 code calls it mid-rollout (migrations apply
-- at service startup, so old and new callers overlap). It carries no DEFAULT
-- on the new signature — an eight-argument call must resolve to exactly one
-- candidate, never an ambiguity error.
CREATE OR REPLACE FUNCTION pfh.cut_create(
  p_tenant TEXT, p_volume TEXT, p_branch_name TEXT,
  p_kind TEXT, p_operation_id TEXT, p_fingerprint TEXT,
  p_materializer_version TEXT, p_target_ids JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  RETURN pfh.cut_create(
    p_tenant, p_volume, p_branch_name, p_kind, p_operation_id,
    p_fingerprint, p_materializer_version, p_target_ids, NULL::TEXT);
END;
$$;

-- 019 forward replacement of the 018 cut-status projection: identical
-- signature, rows, and keys, plus the one additive userLabel key (stripped
-- for unnamed cuts).
CREATE OR REPLACE FUNCTION pfh.cut_status(p_tenant TEXT, p_cut_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  p pfh.pft2_commits;
  ra pfh.recovery_anchors;
  ns pfh.inode_namespaces;
  v_base JSONB;
BEGIN
  SELECT * INTO c FROM pfh.history_cuts WHERE id=p_cut_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF c.result_commit_id IS NOT NULL THEN
    SELECT * INTO p FROM pfh.pft2_commits WHERE cut_id=c.id;
    SELECT * INTO ra FROM pfh.recovery_anchors WHERE cut_id=c.id;
  END IF;
  SELECT * INTO ns FROM pfh.inode_namespaces WHERE branch_id=c.branch_id;
  IF c.source_base_commit_id IS NOT NULL OR c.source_head_commit_id IS NOT NULL THEN
    -- The worker's base view: commit kind plus, for a pft2 base, its exact
    -- normalized provenance, recovery anchor, and branch-relative base mode
    -- (the worker holds no table privileges). Cross-volume fork destination
    -- bases carry their provenance-table root facts and are always 'fork'.
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'commitId', cm.id,
        'commitKind', cm.commit_kind,
        'baseMode', CASE
          WHEN cm.commit_kind='manifest_v1' THEN 'conversion'
          WHEN fk.commit_id IS NOT NULL THEN 'fork'
          WHEN cm.commit_kind='pft2' AND bcut.branch_id IS NULL THEN NULL
          WHEN bcut.branch_id=c.branch_id THEN 'adopted'
          ELSE 'fork' END,
        'treeHash', cm.tree_hash,
        'rootDigest', COALESCE(bp.root_digest, fk.root_digest),
        'rootSize', CASE WHEN COALESCE(bp.root_size, fk.root_size) IS NULL THEN NULL
                         ELSE COALESCE(bp.root_size, fk.root_size)::TEXT END,
        'maxInoSeen', CASE WHEN COALESCE(bp.max_ino_seen, fk.max_ino_seen) IS NULL THEN NULL
                           ELSE COALESCE(bp.max_ino_seen, fk.max_ino_seen)::TEXT END,
        'anchorId', ba.id,
        'recoveryRootDigest', ba.recovery_root_digest,
        'recoveryRootSize', CASE WHEN ba.recovery_root_size IS NULL THEN NULL
                                 ELSE ba.recovery_root_size::TEXT END,
        'controlRootDigest', ba.control_root_digest,
        'orphanIndexDigest', ba.orphan_index_digest,
        'inodeNamespace', CASE WHEN ba.inode_namespace IS NULL THEN NULL
                               ELSE ba.inode_namespace::TEXT END,
        'nextLocal', CASE WHEN ba.next_local IS NULL THEN NULL ELSE ba.next_local::TEXT END,
        'anchorMaxInoSeen', CASE WHEN ba.max_ino_seen IS NULL THEN NULL
                                 ELSE ba.max_ino_seen::TEXT END))
      INTO v_base
      FROM public.commits cm
      LEFT JOIN pfh.pft2_commits bp ON bp.commit_id=cm.id
      LEFT JOIN pfh.pft2_fork_commits fk ON fk.commit_id=cm.id
      LEFT JOIN pfh.recovery_anchors ba ON ba.commit_id=cm.id
      LEFT JOIN pfh.history_cuts bcut ON bcut.id=bp.cut_id
      WHERE cm.id=COALESCE(c.source_base_commit_id, c.source_head_commit_id);
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'baseCommit', v_base,
    'cutId', c.id, 'tenantId', c.tenant_id, 'volumeId', c.volume_id,
    'branchId', c.branch_id, 'branchName', c.branch_name,
    'kind', c.kind, 'sourceKind', c.source_kind,
    'userLabel', c.user_label,
    'generationId', c.generation_id,
    'journalEpoch', CASE WHEN c.journal_epoch IS NULL THEN NULL ELSE c.journal_epoch::TEXT END,
    'recordCodec', c.record_codec, 'controlCodec', c.control_codec,
    'sourceBaseCommitId', c.source_base_commit_id,
    'sourceBaseSeq', CASE WHEN c.source_base_seq IS NULL THEN NULL ELSE c.source_base_seq::TEXT END,
    'sourceBaseDigest', c.source_base_digest,
    'cutSeqExclusive', CASE WHEN c.cut_seq_exclusive IS NULL THEN NULL ELSE c.cut_seq_exclusive::TEXT END,
    'cutDigest', c.cut_digest,
    'cutBacklogBytes', CASE WHEN c.cut_backlog_bytes IS NULL THEN NULL ELSE c.cut_backlog_bytes::TEXT END,
    'cutBacklogRecords', CASE WHEN c.cut_backlog_records IS NULL THEN NULL ELSE c.cut_backlog_records::TEXT END,
    'sourceHeadCommitId', c.source_head_commit_id,
    'materializerVersion', c.materializer_version,
    'replicationPolicy', c.replication_policy,
    'dedupRevision', c.dedup_revision::TEXT,
    'state', c.state,
    'claimEpoch', c.claim_epoch::TEXT,
    'attemptCount', c.attempt_count,
    'nextAttemptDbMs', c.next_attempt_db_ms::TEXT,
    'progress', c.progress,
    'lastError', c.last_error,
    'resultCommitId', c.result_commit_id,
    'recoveryAnchorId', c.recovery_anchor_id,
    'operationId', c.op_operation_id,
    'inodeNamespace', CASE WHEN ns.namespace IS NULL THEN NULL ELSE ns.namespace::TEXT END,
    'namespaceNextLocal', CASE WHEN ns.namespace IS NULL THEN NULL ELSE ns.next_local::TEXT END,
    'namespaceMaxInoSeen', CASE WHEN ns.namespace IS NULL THEN NULL ELSE ns.max_ino_seen::TEXT END,
    'result', CASE WHEN p.commit_id IS NULL THEN NULL ELSE jsonb_strip_nulls(jsonb_build_object(
      'commitId', p.commit_id,
      'rootDigest', p.root_digest, 'rootSize', p.root_size::TEXT,
      'maxInoSeen', p.max_ino_seen::TEXT,
      'objectCount', p.object_count::TEXT,
      'objectBytes', p.object_bytes::TEXT,
      'anchorId', ra.id,
      'recoveryRootDigest', ra.recovery_root_digest,
      'recoveryRootSize', ra.recovery_root_size::TEXT,
      'controlRootDigest', ra.control_root_digest,
      'orphanIndexDigest', ra.orphan_index_digest,
      'inodeNamespace', ra.inode_namespace::TEXT,
      'nextLocal', ra.next_local::TEXT,
      'anchorObjectCount', ra.object_count::TEXT,
      'anchorObjectBytes', ra.object_bytes::TEXT)) END,
    'createdDbMs', c.created_db_ms::TEXT,
    'updatedDbMs', c.updated_db_ms::TEXT,
    'readyDbMs', CASE WHEN c.ready_db_ms IS NULL THEN NULL ELSE c.ready_db_ms::TEXT END));
END;
$$;

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

-- Metadata/caller surface (the volume-api repository's admin DSN role), the
-- exact 013 grant pattern. The replaced 8-argument delegator keeps its 013
-- grant through CREATE OR REPLACE.
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfh.cut_create(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB,TEXT)
    TO %I', CURRENT_USER);
END
$$;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  -- The label column exists with its bounds check.
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='pfh' AND table_name='history_cuts' AND column_name='user_label'
  ) THEN
    RAISE EXCEPTION '019 postcondition: pfh.history_cuts.user_label is missing';
  END IF;
  IF COALESCE((SELECT pg_get_constraintdef(oid) FROM pg_constraint
      WHERE conrelid='pfh.history_cuts'::regclass
        AND conname='history_cuts_user_label_bounds'),'') NOT LIKE '%256%' THEN
    RAISE EXCEPTION '019 postcondition: the user_label bounds check is missing';
  END IF;
  -- The new/replaced functions: owner, definer, pinned search_path, no PUBLIC.
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, p.pronargs, pg_get_userbyid(p.proowner) AS owner,
           p.prosecdef,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh' AND p.proname IN ('cut_create','cut_status')
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner' OR NOT v_rec.prosecdef
       OR v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '019 postcondition: pfh.% owner/definer/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '019 postcondition: PUBLIC can execute pfh.%', v_rec.proname;
    END IF;
  END LOOP;
  -- Both cut_create signatures exist; the 013 one delegates label-free.
  IF to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb,text)') IS NULL THEN
    RAISE EXCEPTION '019 postcondition: the labeled cut_create signature is missing';
  END IF;
  IF position('NULL::TEXT' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb)'))) = 0 THEN
    RAISE EXCEPTION '019 postcondition: the 013 cut_create signature does not delegate';
  END IF;
  -- The labeled INSERT and the label projection actually landed (a stale
  -- body silently surviving the replace would drop every name again).
  IF position('user_label' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_create(text,text,text,text,text,text,text,jsonb,text)'))) = 0 THEN
    RAISE EXCEPTION '019 postcondition: cut_create does not persist user_label';
  END IF;
  IF position('userLabel' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_status(text,text)'))) = 0 THEN
    RAISE EXCEPTION '019 postcondition: cut_status does not project userLabel';
  END IF;
  -- The restricted roles gained NOTHING here (DIRECT grants).
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='cut_create' AND p.pronargs=9
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_worker'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '019 postcondition: a restricted role can execute the labeled cut_create';
  END IF;
  -- Lineage: 020 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '020%') THEN
    RAISE EXCEPTION '019 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
