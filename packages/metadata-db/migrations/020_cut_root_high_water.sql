-- 020_cut_root_high_water: record the USER root object's own allocation
-- high-water on the cut's pft2 commit provenance, distinct from the branch
-- allocator watermark.
--
-- pfh.cut_mark_ready received ONE p_max_ino_seen — the branch ALLOCATOR
-- watermark (max of the fold engine's high-water and the base root's) — and
-- wrote it into BOTH provenance arms: pfh.pft2_commits.max_ino_seen (the
-- USER commit arm, served as the attach proof's `maxInoSeen`) and
-- pfh.recovery_anchors.max_ino_seen (the internal anchor arm). The attach
-- verifier (workfs) binds the proof's root high-water BYTE-EXACTLY against
-- the hashed ROOT object's own recorded MaxInoSeen, so whenever the fold
-- burned identities that did not survive into the tree (deletes, reaped
-- orphans — any git workflow), the allocator watermark sat ABOVE the ROOT's
-- recorded value and every later cut-base attach (branch-from-cut, fork,
-- adoption re-base) failed closed with "proven root high-water N does not
-- equal the hashed ROOT's N-1".
--
-- What this migration does, exactly:
--   1. pfh.cut_mark_ready grows an 18th p_root_max_ino_seen parameter (a new
--      signature — the 013 seventeen-argument signature cannot carry it):
--      the USER root object's own recorded high-water, validated to sit in
--      1..p_max_ino_seen. It lands ONLY in pfh.pft2_commits.max_ino_seen;
--      the recovery anchor and the namespace watermark keep the allocator
--      value. A NULL falls back to p_max_ino_seen (the pre-020 behaviour).
--   2. The 013 signature is REPLACED as a delegator to the new one with a
--      NULL root value, so a not-yet-redeployed worker keeps publishing
--      mid-rollout (with the old, sometimes-skewed semantics — no worse
--      than before).
--   3. Stored rows are untouched: a pre-020 pft2_commits row may carry the
--      allocator watermark. The attach verifier tolerates proven >= hashed
--      (never below), so those rows stay attachable; exact rows are exact.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF008 invalid argument, PF010
-- closure proof failure, PF011 replication proof failure).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='019_snapshot_cut_labels'
  ) THEN
    RAISE EXCEPTION '020 preflight: 019_snapshot_cut_labels receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '021%'
  ) THEN
    RAISE EXCEPTION '020 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION '020 preflight: the 013 cut_mark_ready surface is incomplete';
  END IF;
  IF to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)') IS NOT NULL THEN
    RAISE EXCEPTION '020 preflight: the 18-argument cut_mark_ready already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — dual-watermark ready publication ════════
SET LOCAL ROLE portablefs_history_owner;

-- The dual-watermark publication: the exact 013 body (as forward-carried by
-- the checked lineage) plus the validated p_root_max_ino_seen landing on the
-- USER commit arm. Everything else — closure proofs, replication coverage,
-- namespace watermark advance, atomic ready + operation settle — is
-- byte-identical in behaviour.
CREATE FUNCTION pfh.cut_mark_ready(
  p_cut_id TEXT, p_claim_epoch BIGINT,
  p_root_digest TEXT, p_root_size BIGINT,
  p_recovery_root_digest TEXT, p_recovery_root_size BIGINT,
  p_control_root_digest TEXT, p_control_root_size BIGINT,
  p_orphan_index_digest TEXT, p_orphan_index_size BIGINT,
  p_inode_namespace BIGINT, p_next_local BIGINT, p_max_ino_seen BIGINT,
  p_user_object_count BIGINT, p_user_object_bytes BIGINT,
  p_recovery_object_count BIGINT, p_recovery_object_bytes BIGINT,
  p_root_max_ino_seen BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  ns pfh.inode_namespaces;
  v_now BIGINT;
  v_required BIGINT;
  v_missing BIGINT;
  v_user_closure BIGINT;
  v_recovery_closure BIGINT;
  v_commit_id TEXT;
  v_anchor_id TEXT;
  v_freshness BIGINT;
  v_policy pfh.history_policies;
  v_root_max BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, TRUE);
  PERFORM pfh.require_sha256(p_root_digest, 'pft2 root digest');
  PERFORM pfh.require_sha256(p_recovery_root_digest, 'recovery root digest');
  IF p_root_size IS NULL OR p_root_size <= 0
     OR p_recovery_root_size IS NULL OR p_recovery_root_size <= 0 THEN
    RAISE EXCEPTION 'root sizes are required' USING ERRCODE='PF008';
  END IF;
  IF (p_control_root_digest IS NULL) <> (p_control_root_size IS NULL)
     OR (p_orphan_index_digest IS NULL) <> (p_orphan_index_size IS NULL) THEN
    RAISE EXCEPTION 'control/orphan roots require digest and size together'
      USING ERRCODE='PF008';
  END IF;
  IF p_next_local IS NULL OR p_next_local NOT BETWEEN 1 AND 4294967296
     OR p_max_ino_seen IS NULL OR p_max_ino_seen < 1
     OR p_user_object_count IS NULL OR p_user_object_count < 1
     OR p_user_object_bytes IS NULL OR p_user_object_bytes < 0
     OR p_recovery_object_count IS NULL OR p_recovery_object_count < 1
     OR p_recovery_object_bytes IS NULL OR p_recovery_object_bytes < 0 THEN
    RAISE EXCEPTION 'allocator watermarks and object totals are required'
      USING ERRCODE='PF008';
  END IF;
  -- The USER root's own high-water can never exceed the allocator watermark
  -- (every id in the tree was allocated); NULL is the delegator fallback.
  IF p_root_max_ino_seen IS NOT NULL
     AND p_root_max_ino_seen NOT BETWEEN 1 AND p_max_ino_seen THEN
    RAISE EXCEPTION 'root high-water must sit in 1..the allocator watermark'
      USING ERRCODE='PF008';
  END IF;
  v_root_max := COALESCE(p_root_max_ino_seen, p_max_ino_seen);
  v_policy := pfh.require_history_policy();
  v_freshness := (v_policy.policy->>'maxLastVerifiedAgeMs')::BIGINT;
  v_now := pfh.now_ms();

  SELECT COUNT(*) INTO v_user_closure
    FROM pfh.cut_objects WHERE cut_id=p_cut_id AND closure='user';
  SELECT COUNT(*) INTO v_recovery_closure
    FROM pfh.cut_objects WHERE cut_id=p_cut_id AND closure='recovery';
  IF v_user_closure <> p_user_object_count
     OR v_recovery_closure <> p_recovery_object_count THEN
    RAISE EXCEPTION 'closures hold %/% objects, worker reported %/%',
      v_user_closure, v_recovery_closure, p_user_object_count, p_recovery_object_count
      USING ERRCODE='PF010';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      WHERE co.cut_id=p_cut_id AND co.closure='user'
        AND co.digest='sha256:'||p_root_digest)
     OR NOT EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      WHERE co.cut_id=p_cut_id AND co.closure='recovery'
        AND co.digest='sha256:'||p_recovery_root_digest) THEN
    RAISE EXCEPTION 'closures must contain their own roots' USING ERRCODE='PF010';
  END IF;
  -- The internal arm never leaks into the user closure: the recovery root,
  -- control root and orphan index are structurally recovery-only.
  IF EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      WHERE co.cut_id=p_cut_id AND co.closure='user'
        AND co.digest IN (
          'sha256:'||p_recovery_root_digest,
          'sha256:'||COALESCE(p_control_root_digest,repeat('0',64)),
          'sha256:'||COALESCE(p_orphan_index_digest,repeat('0',64)))) THEN
    RAISE EXCEPTION 'user closure reaches internal recovery objects' USING ERRCODE='PF010';
  END IF;

  SELECT COUNT(*) INTO v_required
    FROM jsonb_array_elements_text(c.replication_policy->'requiredFailureDomains');
  -- Every closure object (both closures): registered under THIS tenant,
  -- live (not quarantined/deleting), and covered by a fresh verified copy in
  -- EVERY required failure domain at its CURRENT incarnation.
  SELECT COUNT(*) INTO v_missing
  FROM (SELECT DISTINCT co.tenant_id, co.kind, co.digest
        FROM pfh.cut_objects co WHERE co.cut_id=p_cut_id) refs
  LEFT JOIN pfh.objects o
    ON o.tenant_id=refs.tenant_id AND o.kind=refs.kind AND o.digest=refs.digest
  WHERE o.digest IS NULL
     OR o.state <> 'live'
     OR v_required > (
        SELECT COUNT(*) FROM pfh.object_copies oc
        WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
          AND oc.incarnation=o.incarnation
          AND oc.state='present'
          AND oc.last_verified_db_ms >= v_now - v_freshness
          AND oc.failure_domain IN (
            SELECT d.v FROM jsonb_array_elements_text(
              c.replication_policy->'requiredFailureDomains') d(v)));
  IF v_missing > 0 THEN
    RAISE EXCEPTION 'cut % has % objects without fresh verified copies in every required domain',
      p_cut_id, v_missing USING ERRCODE='PF011';
  END IF;

  -- Branch allocator watermarks advance monotonically (trigger re-checks).
  SELECT * INTO ns FROM pfh.inode_namespaces WHERE namespace=p_inode_namespace FOR UPDATE;
  IF NOT FOUND OR ns.branch_id <> c.branch_id THEN
    RAISE EXCEPTION 'inode namespace % does not belong to branch %',
      p_inode_namespace, c.branch_id USING ERRCODE='PF011';
  END IF;
  UPDATE pfh.inode_namespaces SET
    next_local=GREATEST(next_local, p_next_local),
    max_ino_seen=GREATEST(max_ino_seen, p_max_ino_seen),
    updated_db_ms=v_now
  WHERE namespace=p_inode_namespace;

  v_commit_id := pfh.new_id('cpft2');
  v_anchor_id := pfh.new_id('hanch');
  INSERT INTO public.commits (
    id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,
    manifest_base_commit_id, manifest_diff, materialized_manifest,
    mutation_count, byte_count, created_at, commit_kind)
  VALUES (
    v_commit_id, c.volume_id, c.branch_id,
    COALESCE(c.source_base_commit_id, c.source_head_commit_id),
    'pft2:'||p_root_digest, NULL, NULL, NULL, FALSE,
    0, p_user_object_bytes, v_now, 'pft2');
  INSERT INTO pfh.pft2_commits (
    commit_id, cut_id, tenant_id, root_digest, root_size, max_ino_seen,
    object_count, object_bytes, created_db_ms)
  VALUES (
    v_commit_id, p_cut_id, c.tenant_id, p_root_digest, p_root_size,
    v_root_max, p_user_object_count, p_user_object_bytes, v_now);
  INSERT INTO pfh.recovery_anchors (
    id, cut_id, commit_id, tenant_id, as_of_seq,
    recovery_root_digest, recovery_root_size,
    control_root_digest, control_root_size,
    orphan_index_digest, orphan_index_size,
    inode_namespace, next_local, max_ino_seen,
    object_count, object_bytes, created_db_ms)
  VALUES (
    v_anchor_id, p_cut_id, v_commit_id, c.tenant_id,
    COALESCE(c.cut_seq_exclusive, 0),
    p_recovery_root_digest, p_recovery_root_size,
    p_control_root_digest, p_control_root_size,
    p_orphan_index_digest, p_orphan_index_size,
    p_inode_namespace, p_next_local, p_max_ino_seen,
    p_recovery_object_count, p_recovery_object_bytes, v_now);

  UPDATE pfh.history_cuts SET
    state='ready', result_commit_id=v_commit_id, recovery_anchor_id=v_anchor_id,
    lease_expires_db_ms=NULL, last_error=NULL, updated_db_ms=v_now, ready_db_ms=v_now
  WHERE id=p_cut_id;

  -- The outer operation settles 'succeeded' now that the target is USABLE
  -- (cut row locked first, then the operation row).
  PERFORM pfh.resource_operation_finish(
    c.op_tenant_id, c.op_domain, c.op_operation_id, 'succeeded',
    jsonb_build_object('cutId', p_cut_id, 'state', 'ready',
                       'commitId', v_commit_id, 'anchorId', v_anchor_id));
  RETURN pfh.cut_status(c.tenant_id, p_cut_id);
END;
$$;
REVOKE ALL ON FUNCTION
  pfh.cut_mark_ready(TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT)
FROM PUBLIC;

-- The 013 signature delegates with a NULL root value (allocator fallback),
-- keeping a not-yet-redeployed worker publishing mid-rollout. Its 013 grant
-- to portablefs_history_worker survives CREATE OR REPLACE.
CREATE OR REPLACE FUNCTION pfh.cut_mark_ready(
  p_cut_id TEXT, p_claim_epoch BIGINT,
  p_root_digest TEXT, p_root_size BIGINT,
  p_recovery_root_digest TEXT, p_recovery_root_size BIGINT,
  p_control_root_digest TEXT, p_control_root_size BIGINT,
  p_orphan_index_digest TEXT, p_orphan_index_size BIGINT,
  p_inode_namespace BIGINT, p_next_local BIGINT, p_max_ino_seen BIGINT,
  p_user_object_count BIGINT, p_user_object_bytes BIGINT,
  p_recovery_object_count BIGINT, p_recovery_object_bytes BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  RETURN pfh.cut_mark_ready(
    p_cut_id, p_claim_epoch,
    p_root_digest, p_root_size,
    p_recovery_root_digest, p_recovery_root_size,
    p_control_root_digest, p_control_root_size,
    p_orphan_index_digest, p_orphan_index_size,
    p_inode_namespace, p_next_local, p_max_ino_seen,
    p_user_object_count, p_user_object_bytes,
    p_recovery_object_count, p_recovery_object_bytes,
    NULL::BIGINT);
END;
$$;

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

-- Worker surface: the 18-argument publication joins the claim-fenced set.
GRANT EXECUTE ON FUNCTION
  pfh.cut_mark_ready(TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT)
TO portablefs_history_worker;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  -- Both signatures exist.
  IF to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION '020 postcondition: the 18-argument cut_mark_ready is missing';
  END IF;
  IF to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION '020 postcondition: the 013 cut_mark_ready signature is missing';
  END IF;
  -- Owner, definer, pinned search_path, no PUBLIC — on every signature.
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, p.pronargs, pg_get_userbyid(p.proowner) AS owner,
           p.prosecdef,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh' AND p.proname='cut_mark_ready'
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner' OR NOT v_rec.prosecdef
       OR v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '020 postcondition: pfh.cut_mark_ready(%) owner/definer/path drift', v_rec.pronargs;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '020 postcondition: PUBLIC can execute pfh.cut_mark_ready(%)', v_rec.pronargs;
    END IF;
  END LOOP;
  -- The 17-argument signature delegates.
  IF position('NULL::BIGINT' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)'))) = 0 THEN
    RAISE EXCEPTION '020 postcondition: the 013 cut_mark_ready signature does not delegate';
  END IF;
  -- The 18-argument body actually lands the root value on the user arm (a
  -- stale body silently surviving would reintroduce the skew).
  IF position('v_root_max' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)'))) = 0 THEN
    RAISE EXCEPTION '020 postcondition: cut_mark_ready does not persist the root high-water';
  END IF;
  -- The worker role holds the DIRECT grant on the 18-argument signature; the
  -- other restricted roles gained nothing.
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='cut_mark_ready' AND p.pronargs=18
      AND acl.grantee='portablefs_history_worker'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 1 THEN
    RAISE EXCEPTION '020 postcondition: the worker grant on the 18-argument cut_mark_ready is missing';
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='cut_mark_ready'
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '020 postcondition: a restricted role can execute cut_mark_ready';
  END IF;
  -- Lineage: 021 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '021%') THEN
    RAISE EXCEPTION '020 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
