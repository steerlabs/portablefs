-- 025_history_write_quorum: batched copy receipts and W-of-N readiness.
--
-- Upload receipts were one database round trip per object per failure
-- domain, and readiness demanded a fresh verified copy in EVERY policy
-- domain — so one slow or dark domain blocked every cut even when enough
-- independent verified copies existed. This migration installs the
-- storage policy the worker's parallel-domain upload path drives:
--
--   * pfh.object_copy_receipt_batch(cutId, epoch, receipts[1..4096]) —
--     one transaction recording many verified copies. Each element passes
--     through the EXACT single-receipt path (intent binding, incarnation
--     fence, policy-domain membership, size agreement), so the batch adds
--     no new trust surface, only fewer round trips.
--   * Write quorum W = LEAST(2, N) over the N policy domains (N=1 ⇒ W=1):
--     pfh.object_copy_receipt flips an object 'live' at W present copies,
--     and pfh.cut_mark_ready publishes when every closure object holds W
--     verified copies in required domains. Copies the quorum did not need
--     are healed asynchronously by the ordinary repair loop (which already
--     targets every policy domain). With the production floor of exactly
--     two domains, W = N = 2: an outage in either still blocks readiness —
--     the quorum only relaxes deployments with three or more domains.
--   * Freshness at publish is required only of objects THIS cut produced
--     (rows with a pfh.upload_intents row for the cut — receipted moments
--     earlier with read-after-write proof). Reused closure rows (added by
--     the O(delta) base-closure copy of a later migration; until then
--     every row carries an intent and behavior is unchanged) must be
--     present and live at the current incarnation; their re-verification
--     cadence belongs to the scrub loop, not to every publish.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF004 bounds, PF008 invalid
-- argument, PF010 closure proof failure, PF011 replication proof failure).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='024_history_locate_batch'
  ) THEN
    RAISE EXCEPTION '025 preflight: 024_history_locate_batch receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '026%'
  ) THEN
    RAISE EXCEPTION '025 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfh.object_copy_receipt(text,bigint,text,bigint,text,text,bigint)') IS NULL
     OR to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION '025 preflight: the 013/020 receipt surface is incomplete';
  END IF;
  IF to_regprocedure('pfh.object_copy_receipt_batch(text,bigint,jsonb)') IS NOT NULL THEN
    RAISE EXCEPTION '025 preflight: pfh.object_copy_receipt_batch already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — quorum receipts + publication ═══════════
SET LOCAL ROLE portablefs_history_owner;

-- The write quorum: two independently verified copies whenever the policy
-- names at least two domains, one for explicit single-domain self-host
-- postures. A constant of the design, not a knob.
CREATE FUNCTION pfh.write_quorum(p_required BIGINT) RETURNS BIGINT
LANGUAGE sql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$ SELECT LEAST(2, GREATEST(p_required, 0)) $$;
REVOKE ALL ON FUNCTION pfh.write_quorum(BIGINT) FROM PUBLIC;

-- 025 revision of the 013 single-copy receipt: byte-identical validation
-- and receipt row, but the object flips 'live' at the WRITE QUORUM instead
-- of full policy coverage (repair heals the remainder asynchronously).
CREATE OR REPLACE FUNCTION pfh.object_copy_receipt(
  p_cut_id TEXT, p_claim_epoch BIGINT,
  p_digest TEXT, p_incarnation BIGINT,
  p_failure_domain TEXT, p_storage_key TEXT, p_size BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  o pfh.objects;
  v_intent pfh.upload_intents;
  v_now BIGINT;
  v_required BIGINT;
  v_present BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  PERFORM pfh.require_object_identity(c.tenant_id, 'pft2', p_digest);
  IF p_incarnation IS NULL OR p_incarnation < 1
     OR p_failure_domain IS NULL OR length(p_failure_domain) NOT BETWEEN 1 AND 128
     OR p_storage_key IS NULL OR length(p_storage_key) NOT BETWEEN 1 AND 1024
     OR p_size IS NULL OR p_size < 0 THEN
    RAISE EXCEPTION 'copy receipt requires incarnation, domain, storage key, size'
      USING ERRCODE='PF008';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(c.replication_policy->'requiredFailureDomains') d(v)
    WHERE d.v = p_failure_domain) THEN
    RAISE EXCEPTION 'failure domain % is not in the cut replication policy',
      p_failure_domain USING ERRCODE='PF008';
  END IF;
  SELECT * INTO v_intent FROM pfh.upload_intents
    WHERE cut_id=p_cut_id AND digest=p_digest;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'copy receipt for % without an upload intent', p_digest
      USING ERRCODE='PF011';
  END IF;
  IF v_intent.incarnation <> p_incarnation THEN
    RAISE EXCEPTION 'copy receipt incarnation % contradicts the intent (%)',
      p_incarnation, v_intent.incarnation USING ERRCODE='PF002';
  END IF;
  PERFORM pfh.scope_locks(ARRAY['pfh-object:'||c.tenant_id||E'\x01'||'pft2'||E'\x01'||p_digest]);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=p_digest FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'object % is not registered', p_digest USING ERRCODE='PF007';
  END IF;
  IF o.size <> p_size THEN
    RAISE EXCEPTION 'object % copy size % contradicts registered size %',
      p_digest, p_size, o.size USING ERRCODE='PF002';
  END IF;
  IF o.incarnation <> p_incarnation OR o.state IN ('deleting','tombstoned') THEN
    -- A stale upload (superseded incarnation, or a sweep won the race) can
    -- never heal or receipt into the current identity: re-intend first.
    RAISE EXCEPTION 'object % incarnation % is superseded (current %, state %)',
      p_digest, p_incarnation, o.incarnation, o.state USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  INSERT INTO pfh.object_copies (
    tenant_id, kind, digest, incarnation, failure_domain, storage_key, size,
    state, first_verified_db_ms, last_verified_db_ms)
  VALUES (c.tenant_id, 'pft2', p_digest, p_incarnation, p_failure_domain,
          p_storage_key, p_size, 'present', v_now, v_now)
  ON CONFLICT (tenant_id, kind, digest, incarnation, failure_domain) DO UPDATE
    SET storage_key=EXCLUDED.storage_key, size=EXCLUDED.size, state='present',
        last_verified_db_ms=EXCLUDED.last_verified_db_ms, verify_attempts=0,
        next_verify_db_ms=0, verify_claim_worker_id=NULL,
        verify_claim_expires_db_ms=NULL, absence_receipt=NULL;
  SELECT COUNT(*) INTO v_required
    FROM jsonb_array_elements_text(c.replication_policy->'requiredFailureDomains');
  SELECT COUNT(*) INTO v_present FROM pfh.object_copies oc
    WHERE oc.tenant_id=c.tenant_id AND oc.kind='pft2' AND oc.digest=p_digest
      AND oc.incarnation=o.incarnation AND oc.state='present'
      AND oc.failure_domain IN (
        SELECT d.v FROM jsonb_array_elements_text(
          c.replication_policy->'requiredFailureDomains') d(v));
  IF v_present >= pfh.write_quorum(v_required) AND o.state IN ('intended','reclaiming') THEN
    UPDATE pfh.objects SET state='live', updated_db_ms=v_now
    WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=p_digest;
  END IF;
  RETURN jsonb_build_object(
    'digest', p_digest, 'incarnation', o.incarnation::TEXT,
    'presentDomains', v_present, 'requiredDomains', v_required);
END;
$$;

-- Many verified copies, one transaction. Every element flows through the
-- single-receipt function above — identical fencing, validation, and
-- quorum bookkeeping — so a batch is exactly N receipts minus N-1 round
-- trips.
CREATE FUNCTION pfh.object_copy_receipt_batch(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_receipts JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_count INT;
  e JSONB;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF p_receipts IS NULL OR jsonb_typeof(p_receipts) <> 'array' THEN
    RAISE EXCEPTION 'copy receipts must be an array' USING ERRCODE='PF008';
  END IF;
  SELECT COUNT(*) INTO v_count FROM jsonb_array_elements(p_receipts);
  IF v_count NOT BETWEEN 1 AND 4096 THEN
    RAISE EXCEPTION 'copy receipt batches are bounded to 1..4096 entries'
      USING ERRCODE='PF004';
  END IF;
  FOR e IN SELECT * FROM jsonb_array_elements(p_receipts) LOOP
    PERFORM pfh.object_copy_receipt(
      p_cut_id, p_claim_epoch,
      e->>'digest', (e->>'incarnation')::BIGINT,
      e->>'failureDomain', e->>'storageKey', (e->>'size')::BIGINT);
  END LOOP;
  RETURN jsonb_build_object('recorded', v_count);
END;
$$;
REVOKE ALL ON FUNCTION pfh.object_copy_receipt_batch(TEXT,BIGINT,JSONB) FROM PUBLIC;

-- 025 revision of the 020 publication: readiness is W-of-N per closure
-- object, and the per-publish freshness window applies only to objects
-- this cut produced (rows with an upload intent). Everything else — dual
-- closure counting, root membership, internal-root disjointness, the
-- monotone allocator advance, the atomic commit+anchor+ready+settle — is
-- byte-identical in behaviour.
CREATE OR REPLACE FUNCTION pfh.cut_mark_ready(
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
  v_quorum BIGINT;
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
  v_quorum := pfh.write_quorum(v_required);
  -- Every closure object (both closures): registered under THIS tenant,
  -- live (not quarantined/deleting), and covered by W-of-N verified copies
  -- in required domains at its CURRENT incarnation. Objects this cut
  -- produced (upload-intent rows) must be FRESH within the policy window —
  -- they were receipted with read-after-write proof moments ago; reused
  -- closure rows count on presence, with scrub owning their freshness.
  SELECT COUNT(*) INTO v_missing
  FROM (SELECT DISTINCT co.tenant_id, co.kind, co.digest
        FROM pfh.cut_objects co WHERE co.cut_id=p_cut_id) refs
  LEFT JOIN pfh.objects o
    ON o.tenant_id=refs.tenant_id AND o.kind=refs.kind AND o.digest=refs.digest
  WHERE o.digest IS NULL
     OR o.state <> 'live'
     OR v_quorum > (
        SELECT COUNT(*) FROM pfh.object_copies oc
        WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
          AND oc.incarnation=o.incarnation
          AND oc.state='present'
          AND (oc.last_verified_db_ms >= v_now - v_freshness
               OR NOT EXISTS (
                 SELECT 1 FROM pfh.upload_intents ui
                 WHERE ui.cut_id=p_cut_id AND ui.digest=o.digest))
          AND oc.failure_domain IN (
            SELECT d.v FROM jsonb_array_elements_text(
              c.replication_policy->'requiredFailureDomains') d(v)));
  IF v_missing > 0 THEN
    RAISE EXCEPTION 'cut % has % objects below the verified write quorum',
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
    id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,
    manifest_base_commit_id, manifest_diff, materialized_manifest,
    mutation_count, byte_count, created_at, commit_kind)
  VALUES (
    v_commit_id, c.tenant_id, c.volume_id, c.branch_id,
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

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

-- Worker surface: the batched receipt joins the claim-fenced set. The
-- replaced single receipt and 18-argument publication keep their existing
-- grants through CREATE OR REPLACE.
GRANT EXECUTE ON FUNCTION pfh.object_copy_receipt_batch(TEXT,BIGINT,JSONB)
TO portablefs_history_worker;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, pg_get_userbyid(p.proowner) AS owner,
           p.prosecdef,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh'
      AND p.proname IN ('object_copy_receipt_batch','write_quorum')
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner'
       OR v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '025 postcondition: pfh.% owner/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '025 postcondition: PUBLIC can execute pfh.%', v_rec.proname;
    END IF;
  END LOOP;
  -- The quorum actually landed in both replaced bodies (a stale body
  -- silently surviving the replace would keep full-coverage readiness).
  IF position('write_quorum' IN pg_get_functiondef(
       to_regprocedure('pfh.object_copy_receipt(text,bigint,text,bigint,text,text,bigint)'))) = 0 THEN
    RAISE EXCEPTION '025 postcondition: object_copy_receipt does not apply the write quorum';
  END IF;
  IF position('write_quorum' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)'))) = 0
     OR position('upload_intents' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)'))) = 0 THEN
    RAISE EXCEPTION '025 postcondition: cut_mark_ready does not apply quorum + intent-gated freshness';
  END IF;
  -- Exactly the worker holds the DIRECT grant on the batch receipt.
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='object_copy_receipt_batch'
      AND acl.grantee='portablefs_history_worker'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 1 THEN
    RAISE EXCEPTION '025 postcondition: the worker grant on object_copy_receipt_batch is missing';
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname IN ('object_copy_receipt_batch','write_quorum')
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '025 postcondition: a restricted role can execute a 025 function';
  END IF;
  -- Lineage: 026 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '026%') THEN
    RAISE EXCEPTION '025 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
