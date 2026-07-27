-- 014_history_serving: tenant-scoped exact base proof and degraded-copy
-- scheduling for the production PFT2 serving path, plus the base-mode
-- provenance the HistoryCut worker needs to fold a cut safely.
--
-- This migration is deliberately additive. The frozen 013 migration FILE is
-- untouched; the one 013 function this migration replaces (pfh.cut_status)
-- is replaced forward, with the same signature, ACL, and every existing
-- JSON key byte-identical — it only ADDS the database-proven 'baseMode' key
-- to the baseCommit object. Normal filesystem writes still go only through
-- the live PFJ3/PFC2 journal; these functions are read/recovery surfaces
-- used after a writer has already claimed and durability-checked its exact
-- generation.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations
    WHERE id='013_managed_history'
  ) THEN
    RAISE EXCEPTION '014 preflight: 013_managed_history receipt is missing; checked lineage must be gap-free';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations
    WHERE id LIKE '015%' OR id LIKE '016%'
  ) THEN
    RAISE EXCEPTION '014 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfh.pft2_commits') IS NULL
     OR to_regclass('pfh.object_copies') IS NULL
     OR to_regclass('pfh.inode_namespaces') IS NULL
     OR to_regclass('pfj.journal_generations') IS NULL THEN
    RAISE EXCEPTION '014 preflight: history/journal serving facts are incomplete';
  END IF;
END;
$preflight$;

SET LOCAL ROLE portablefs_history_owner;

-- Proves one authority's EXACT journal base in one MVCC snapshot. Callers
-- present every fact returned by the already-claimed journal. This function
-- never guesses a commit family from absence: manifest_v1 and pft2 are
-- positive, tenant-scoped outcomes, while an unavailable/mismatched proof is
-- NULL or a typed PF0xx failure.
--
-- PFT2 has three structurally distinct origins:
--   * fork: a new seq-0 generation whose branch was durably created from this
--     exact ready cut (active cut-consumer row); controls intentionally start
--     empty, no recovery anchor is projected, and the proof instead carries
--     the NEW branch's DB-issued never-reused inode allocator namespace
--     (managed branch/fork creation issues the pfh.inode_namespaces row) —
--     the reused
--     source root holds namespaced inodes far beyond the flat 2^32 cap, so a
--     fork without its fresh namespace could never allocate;
--   * conversion: a new seq-0 PFJ3 generation after a durably converted final
--     cut; the anchor seeds allocator/recovery facts;
--   * adopted: an applied adoption row binds this exact generation, commit,
--     cut sequence, cut digest and matching recovery anchor.
-- Missing recovery data is never interpreted as fork evidence, and a missing
-- fork namespace row fails the proof rather than degrading it.
CREATE FUNCTION pfh.serving_base_prove(
  p_tenant TEXT,
  p_commit_id TEXT,
  p_generation_id TEXT,
  p_base_seq BIGINT,
  p_base_digest TEXT,
  p_record_codec TEXT,
  p_control_codec TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  cm public.commits;
  pc pfh.pft2_commits;
  hc pfh.history_cuts;
  ra pfh.recovery_anchors;
  ad pfh.adoptions;
  cv pfh.conversions;
  ns pfh.inode_namespaces;
  v_mode TEXT;
  v_zero_digest CONSTANT TEXT := repeat('0',64);
BEGIN
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 512
     OR p_commit_id IS NULL OR length(p_commit_id) NOT BETWEEN 1 AND 256
     OR p_generation_id IS NULL OR length(p_generation_id) NOT BETWEEN 1 AND 256
     OR p_base_seq IS NULL OR p_base_seq < 0
     OR p_base_digest IS NULL OR p_base_digest !~ '^[0-9a-f]{64}$'
     OR NOT ((p_record_codec='pfr1' AND p_control_codec='pfc1')
          OR (p_record_codec='pfj3' AND p_control_codec='pfc2')) THEN
    RAISE EXCEPTION 'serving base proof arguments are invalid' USING ERRCODE='PF008';
  END IF;

  -- Tenant is part of the lookup so another tenant's generation is
  -- indistinguishable from an unknown id to this caller.
  SELECT * INTO g FROM pfj.journal_generations
    WHERE id=p_generation_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF g.status <> 'active'
     OR g.base_commit_id IS DISTINCT FROM p_commit_id
     OR g.base_seq IS DISTINCT FROM p_base_seq
     OR g.base_digest IS DISTINCT FROM p_base_digest
     OR g.record_codec IS DISTINCT FROM p_record_codec
     OR g.control_codec IS DISTINCT FROM p_control_codec THEN
    RAISE EXCEPTION 'journal base tuple no longer matches the claimed generation'
      USING ERRCODE='PF002';
  END IF;

  SELECT c.* INTO cm
    FROM public.commits c
    JOIN public.volumes v ON v.id=c.volume_id
    WHERE c.id=p_commit_id AND c.volume_id=g.volume_id AND v.tenant_id=p_tenant;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  IF cm.commit_kind='manifest_v1' THEN
    RETURN jsonb_build_object(
      'v','1','kind','manifest_v1','tenantId',p_tenant,
      'commitId',cm.id,'volumeId',g.volume_id,'branchId',g.branch_id,
      'generationId',g.id,'baseSeq',g.base_seq::TEXT,
      'baseDigest',g.base_digest,'recordCodec',g.record_codec,
      'controlCodec',g.control_codec);
  END IF;
  IF cm.commit_kind<>'pft2' THEN
    RAISE EXCEPTION 'base commit has an unknown commit family' USING ERRCODE='PF005';
  END IF;
  IF g.record_codec<>'pfj3' OR g.control_codec<>'pfc2' THEN
    RAISE EXCEPTION 'PFT2 bases require a PFJ3/PFC2 generation' USING ERRCODE='PF005';
  END IF;

  SELECT * INTO pc FROM pfh.pft2_commits
    WHERE commit_id=cm.id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PFT2 commit provenance is missing' USING ERRCODE='PF011';
  END IF;
  SELECT * INTO hc FROM pfh.history_cuts
    WHERE id=pc.cut_id AND tenant_id=p_tenant AND volume_id=g.volume_id
      AND result_commit_id=cm.id AND state='ready';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PFT2 commit is not backed by one ready tenant cut'
      USING ERRCODE='PF011';
  END IF;
  IF pc.root_size NOT BETWEEN 12 AND 262144
     OR pc.max_ino_seen NOT BETWEEN 1 AND 9223372036854775807::BIGINT THEN
    RAISE EXCEPTION 'PFT2 root provenance exceeds the frozen format bounds'
      USING ERRCODE='PF004';
  END IF;

  -- A fork is proven positively by the managed branch-from-cut consumer;
  -- seq/digest must still be the fresh generation origin.
  IF g.base_seq=0 AND g.base_digest=v_zero_digest AND EXISTS (
    SELECT 1 FROM pfh.cut_consumers cc
    WHERE cc.cut_id=pc.cut_id AND cc.tenant_id=p_tenant
      AND cc.consumer_kind='branch' AND cc.consumer_id=g.branch_id
      AND cc.released_db_ms IS NULL
  ) THEN
    v_mode := 'fork';
  ELSE
    SELECT * INTO cv FROM pfh.conversions c
      WHERE c.tenant_id=p_tenant AND c.volume_id=g.volume_id
        AND c.branch_id=g.branch_id AND c.final_cut_id=pc.cut_id
        AND c.state='converted';
    IF FOUND THEN
      IF g.base_seq<>0 OR g.base_digest<>v_zero_digest THEN
        RAISE EXCEPTION 'converted generation no longer has its proven seq-0 base'
          USING ERRCODE='PF002';
      END IF;
      v_mode := 'conversion';
    ELSE
      SELECT * INTO ad FROM pfh.adoptions a
        WHERE a.tenant_id=p_tenant AND a.generation_id=g.id
          AND a.cut_id=pc.cut_id AND a.new_base_commit_id=cm.id
          AND a.new_base_seq=g.base_seq AND a.new_base_digest=g.base_digest
          AND a.state='applied';
      IF NOT FOUND
         OR hc.generation_id IS DISTINCT FROM g.id
         OR hc.record_codec IS DISTINCT FROM 'pfj3'
         OR hc.control_codec IS DISTINCT FROM 'pfc2'
         OR hc.cut_seq_exclusive IS DISTINCT FROM g.base_seq
         OR hc.cut_digest IS DISTINCT FROM g.base_digest THEN
        RAISE EXCEPTION 'PFT2 base has no exact applied-adoption proof'
          USING ERRCODE='PF011';
      END IF;
      v_mode := 'adopted';
    END IF;
  END IF;

  IF v_mode='fork' THEN
    -- The fork's writability hinges on the NEW branch's own allocator row
    -- (issued at managed branch/fork creation): canonical
    -- decimal namespace + nextLocal + the branch allocator high-water. The
    -- SOURCE branch's allocator is never copied — namespaces are global,
    -- monotone, and never reused, so the fresh row can never collide with
    -- any inode id already inside the reused root.
    SELECT * INTO ns FROM pfh.inode_namespaces
      WHERE branch_id=g.branch_id AND tenant_id=p_tenant AND volume_id=g.volume_id;
    IF NOT FOUND
       OR ns.namespace NOT BETWEEN 1 AND 2147483647
       OR ns.next_local NOT BETWEEN 1 AND 4294967296
       OR ns.max_ino_seen NOT BETWEEN 1 AND 9223372036854775807::BIGINT THEN
      RAISE EXCEPTION 'fork base is missing its issued branch inode namespace'
        USING ERRCODE='PF011';
    END IF;
    RETURN jsonb_build_object(
      'v','1','kind','pft2','baseMode',v_mode,'tenantId',p_tenant,
      'commitId',cm.id,'volumeId',g.volume_id,'branchId',g.branch_id,
      'generationId',g.id,'baseSeq',g.base_seq::TEXT,
      'baseDigest',g.base_digest,'recordCodec',g.record_codec,
      'controlCodec',g.control_codec,
      'root',jsonb_build_object(
        'digest',pc.root_digest,'size',pc.root_size::TEXT,
        'maxInoSeen',pc.max_ino_seen::TEXT),
      'allocator',jsonb_build_object(
        'inodeNamespace',ns.namespace::TEXT,
        'nextLocal',ns.next_local::TEXT,
        'maxInoSeen',ns.max_ino_seen::TEXT));
  END IF;

  SELECT * INTO ra FROM pfh.recovery_anchors
    WHERE id=hc.recovery_anchor_id AND cut_id=pc.cut_id
      AND commit_id=cm.id AND tenant_id=p_tenant;
  IF NOT FOUND
     OR ra.recovery_root_size NOT BETWEEN 12 AND 262144
     OR ra.control_root_digest IS NULL
     OR ra.control_root_size NOT BETWEEN 12 AND 262144
     OR ra.inode_namespace NOT BETWEEN 1 AND 2147483647
     OR ra.next_local NOT BETWEEN 1 AND 4294967296
     OR ra.max_ino_seen NOT BETWEEN 1 AND 9223372036854775807::BIGINT THEN
    RAISE EXCEPTION 'live PFT2 base is missing bounded recovery/control provenance'
      USING ERRCODE='PF011';
  END IF;
  IF v_mode='adopted'
     AND (ra.id IS DISTINCT FROM ad.anchor_id
          OR ra.as_of_seq IS DISTINCT FROM g.base_seq) THEN
    RAISE EXCEPTION 'adopted PFT2 anchor does not match the exact base sequence'
      USING ERRCODE='PF011';
  END IF;

  RETURN jsonb_build_object(
    'v','1','kind','pft2','baseMode',v_mode,'tenantId',p_tenant,
    'commitId',cm.id,'volumeId',g.volume_id,'branchId',g.branch_id,
    'generationId',g.id,'baseSeq',g.base_seq::TEXT,
    'baseDigest',g.base_digest,'recordCodec',g.record_codec,
    'controlCodec',g.control_codec,
    'root',jsonb_build_object(
      'digest',pc.root_digest,'size',pc.root_size::TEXT,
      'maxInoSeen',pc.max_ino_seen::TEXT),
    'anchor',jsonb_strip_nulls(jsonb_build_object(
      'anchorId',ra.id,'asOfSeq',ra.as_of_seq::TEXT,
      'recoveryRootDigest',ra.recovery_root_digest,
      'recoveryRootSize',ra.recovery_root_size::TEXT,
      'controlRootDigest',ra.control_root_digest,
      'controlRootSize',ra.control_root_size::TEXT,
      'orphanIndexDigest',ra.orphan_index_digest,
      'orphanIndexSize',CASE WHEN ra.orphan_index_size IS NULL THEN NULL
                             ELSE ra.orphan_index_size::TEXT END,
      'inodeNamespace',ra.inode_namespace::TEXT,
      'nextLocal',ra.next_local::TEXT,
      'maxInoSeen',ra.max_ino_seen::TEXT)));
END;
$$;

-- Forward replacement of the 013 cut-status projection: identical signature,
-- rows, and keys, plus ONE new key — baseCommit.baseMode — proving how this
-- cut's base relates to the cut's own branch:
--   * 'conversion' — a manifest_v1 legacy base (imported, never anchored);
--   * 'adopted'    — a pft2 commit produced by a cut of the SAME branch:
--                    its recovery anchor (controls, orphans, allocator)
--                    binds exactly;
--   * 'fork'       — a pft2 commit produced by ANOTHER branch's cut: the
--                    worker imports only the immutable user root and must
--                    never read the source anchor, orphan namespace, or
--                    allocator (the cut's own branch allocates in its own
--                    never-reused namespace).
-- A pft2 base whose producing cut cannot be traced projects NO baseMode and
-- the worker fails the cut closed rather than guessing.
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
    -- (the worker holds no table privileges).
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'commitId', cm.id,
        'commitKind', cm.commit_kind,
        'baseMode', CASE
          WHEN cm.commit_kind='manifest_v1' THEN 'conversion'
          WHEN cm.commit_kind='pft2' AND bcut.branch_id IS NULL THEN NULL
          WHEN bcut.branch_id=c.branch_id THEN 'adopted'
          ELSE 'fork' END,
        'treeHash', cm.tree_hash,
        'rootDigest', bp.root_digest,
        'rootSize', CASE WHEN bp.root_size IS NULL THEN NULL ELSE bp.root_size::TEXT END,
        'maxInoSeen', CASE WHEN bp.max_ino_seen IS NULL THEN NULL ELSE bp.max_ino_seen::TEXT END,
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
      LEFT JOIN pfh.recovery_anchors ba ON ba.commit_id=cm.id
      LEFT JOIN pfh.history_cuts bcut ON bcut.id=bp.cut_id
      WHERE cm.id=COALESCE(c.source_base_commit_id, c.source_head_commit_id);
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'baseCommit', v_base,
    'cutId', c.id, 'tenantId', c.tenant_id, 'volumeId', c.volume_id,
    'branchId', c.branch_id, 'branchName', c.branch_name,
    'kind', c.kind, 'sourceKind', c.source_kind,
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

-- A serving read that has itself observed a missing/corrupt/unreachable
-- recorded copy asks the ordinary scrub loop to revisit it. This does not
-- quarantine, repair, overwrite, or delete inline; it only advances the
-- existing durable schedule for the exact current incarnation/domain.
CREATE FUNCTION pfh.serving_copy_degraded(
  p_tenant TEXT,
  p_digest TEXT,
  p_incarnation BIGINT,
  p_failure_domain TEXT,
  p_reason TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_updated BIGINT;
BEGIN
  PERFORM pfh.require_object_identity(p_tenant,'pft2',p_digest);
  IF p_incarnation IS NULL OR p_incarnation<1
     OR p_failure_domain IS NULL OR length(p_failure_domain) NOT BETWEEN 1 AND 128
     OR p_reason NOT IN ('missing','corrupt','unreachable') THEN
    RAISE EXCEPTION 'serving degraded-copy arguments are invalid' USING ERRCODE='PF008';
  END IF;
  UPDATE pfh.object_copies oc SET next_verify_db_ms=0
    FROM pfh.objects o
    WHERE o.tenant_id=p_tenant AND o.kind='pft2' AND o.digest=p_digest
      AND o.state='live' AND o.incarnation=p_incarnation
      AND oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
      AND oc.incarnation=o.incarnation AND oc.failure_domain=p_failure_domain
      AND oc.state='present';
  GET DIAGNOSTICS v_updated=ROW_COUNT;
  RETURN v_updated=1;
END;
$$;

RESET ROLE;

DO $grant$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfh.serving_base_prove(TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT),
    pfh.serving_copy_degraded(TEXT,TEXT,BIGINT,TEXT,TEXT)
    TO %I',CURRENT_USER);
END;
$grant$;

REVOKE ALL ON FUNCTION
  pfh.serving_base_prove(TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT),
  pfh.serving_copy_degraded(TEXT,TEXT,BIGINT,TEXT,TEXT)
FROM PUBLIC;

DO $postcondition$
DECLARE v_proc RECORD;
BEGIN
  FOR v_proc IN
    SELECT p.oid,p.prosecdef,r.rolname AS owner,p.proconfig
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_roles r ON r.oid=p.proowner
    WHERE n.nspname='pfh'
      AND p.proname IN ('serving_base_prove','serving_copy_degraded','cut_status')
  LOOP
    IF v_proc.owner<>'portablefs_history_owner' OR NOT v_proc.prosecdef
       OR v_proc.proconfig IS NULL
       OR NOT ('search_path=pg_catalog, pg_temp'=ANY(v_proc.proconfig)) THEN
      RAISE EXCEPTION '014 postcondition: serving function owner/definer/search_path drift';
    END IF;
    IF has_function_privilege('public',v_proc.oid,'EXECUTE') THEN
      RAISE EXCEPTION '014 postcondition: PUBLIC can execute a serving function';
    END IF;
  END LOOP;
  IF to_regprocedure('pfh.serving_base_prove(text,text,text,bigint,text,text,text)') IS NULL
     OR to_regprocedure('pfh.serving_copy_degraded(text,text,bigint,text,text)') IS NULL THEN
    RAISE EXCEPTION '014 postcondition: serving functions are missing';
  END IF;
  -- The replaced cut-status projection must actually carry the base-mode
  -- provenance (a stale 013 body silently surviving the replace would make
  -- the worker fail every pft2-base cut closed).
  IF position('baseMode' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_status(text,text)'))) = 0 THEN
    RAISE EXCEPTION '014 postcondition: cut_status does not project baseMode';
  END IF;
END;
$postcondition$;
