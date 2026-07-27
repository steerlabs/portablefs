-- 018_managed_volume_fork: one atomic PostgreSQL cross-volume fork of a
-- ready journal-era (PFT2) history cut into a NEW managed volume. Ordinary
-- PFJ3/PFC2 filesystem writes remain completely unchanged and never enter
-- this migration; the destination's first writer claims its seq-0 generation
-- later through the ordinary pfj.journal_claim_v3 path.
--
-- The model (zero-copy fork):
--   A ready cut's single canonical PFT2 user root is IMMUTABLE and
--   content-addressed. A cross-volume fork therefore duplicates no objects:
--   it creates a new volume whose default branch is born managed_journal
--   with a fork-point pft2 commit carrying the EXACT copied user-root
--   identity (tree hash from the copied root digest, lineage to the source
--   result commit, copied byte count, ZERO recovery facts), issues the
--   destination branch its own fresh never-reused inode namespace, and pins
--   the shared history objects by attaching an ACTIVE 'fork' cut consumer
--   bound to the destination branch — the durable GC root of the source cut
--   for this fork (the 013 sweep marks ready cuts held by unreleased
--   consumers as roots). Writability comes from the destination branch's
--   own DB-issued allocator; the source allocator, RecoveryRoot, controls,
--   and orphans are never copied — a cross-volume fork starts with default
--   PFC2 state exactly like a same-volume branch fork.
--
-- What this migration does, exactly:
--   1. pfh.pft2_fork_commits: the separate IMMUTABLE positive fork-provenance
--      table keyed by destination commit/branch, linking the exact source cut
--      + source result commit + destination volume/branch + copied root
--      facts. It deliberately does NOT insert another pfh.pft2_commits row:
--      frozen 013/014 functions select pft2_commits by cut_id and assume the
--      single canonical cut result. A SECURITY DEFINER history-owner
--      installer re-proves every fact in the same transaction before the row
--      exists.
--   2. pfh.volume_fork_from_cut: the one atomic fork operation — exact-once
--      through the permanent pfh.resource_operations ledger under the new
--      'volume-fork' domain (deterministic operationId + request
--      fingerprint; an identical retry replays the recorded response, a
--      changed payload is a PF009 conflict). In ONE transaction it
--      authenticates the same-tenant READY source cut and its single
--      canonical pfh.pft2_commits user root; creates the destination
--      public.volumes row, the destination fork-point public.commits row,
--      and the managed_journal destination branch (also the default branch);
--      issues a fresh never-reused pfh.inode_namespaces row; attaches the
--      ACTIVE 'fork' cut consumer; installs the positive provenance row via
--      the installer's independent re-proof; settles the receipt. No
--      drain/freeze/checkpoint, no writer generation and no ownership lease
--      are created here. DB time only.
--   3. pfh.serving_base_prove is replaced forward (same signature; the
--      quiesced 014 behaviour is byte-identical for every existing case)
--      with ONE additive branch: a generation whose pft2 base commit is a
--      registered pfh.pft2_fork_commits destination proves as baseMode
--      'fork' — the immutable copied user root plus the DESTINATION
--      branch's own DB-issued allocator namespace, and deliberately NO
--      RecoveryRoot/control/orphan facts. It fails closed
--      (PF011/PF002/PF004) on a foreign generation binding, a non-origin
--      base tuple, a released/missing fork consumer, a missing destination
--      namespace row, or root-provenance drift against the destination
--      commit. Without this branch a fork destination's first authority
--      could never prove its base and the destination volume would be
--      permanently unservable.
--   4. pfh.cut_status is replaced forward (same signature; every existing
--      key byte-identical) so the baseCommit view recognizes a fork
--      destination base POSITIVELY from pfh.pft2_fork_commits: baseMode
--      'fork' with the provenance-table root facts. Without this, the fork
--      destination's own NEXT cut would project no baseMode (its base
--      commit has no pfh.pft2_commits row) and the worker would fail it
--      closed.
--
-- Deviations from the root lineage's 016_managed_volume_fork (documented
-- per the porting contract; the pfh object names/signatures are preserved):
--   * The root's pfc managed-control plane (protocol_artifacts registry,
--      pfc.operations, operation_apply dispatch, managed_volumes,
--      projections, tenant_lifecycle gates) does not exist in this lineage.
--      The atomic fork body that lived in the root's
--      pfc.operation_apply(managed_volume_fork) arm is expressed here as
--      pfh.volume_fork_from_cut, and exact-once receipts ride the 013
--      pfh.resource_operations ledger ('volume-fork' domain) instead of
--      pfc.operations. There is no pfc.managed_volumes row and no volume
--      projection to emit.
--   * Receipt semantics: the root settles REJECTED receipts for refused
--      forks; the 013 pfh ledger discipline instead rolls a refused fork
--      back entirely (no receipt row survives), so a retry with the same
--      operationId can succeed once the source becomes ready. Applied forks
--      settle 'succeeded' and replay exactly-once either way.
--   * The root's expectedStateRevision CAS rides its projection ledger; the
--      OSS destination CAS is "the destination volume id must not exist"
--      (PF002), which the root also enforces.
--   * The root's managed_volume_retire releases 'branch'/'fork' consumers at
--      volume retirement; this lineage has no volume-retirement plane, so
--      fork consumers stay held for the destination's lifetime — identical
--      to the existing 'branch' consumers attached by branch-from-cut
--      (fail-closed: the shared objects stay GC roots).
--   * The root grants its control-owner role EXECUTE on the installer and
--      SELECT on cut provenance; this lineage has no control owner. The
--      installer is callable only by the history owner (the orchestrator
--      runs as it); the metadata caller role receives EXECUTE on
--      pfh.volume_fork_from_cut only, following the 013 caller-surface
--      pattern.
--   * The history owner gains INSERT on public.volumes/public.branches and
--      UPDATE (default_branch_id) on public.volumes — the narrow public
--      write surface the fork needs. The root granted its control owner the
--      equivalent surface in its control-plane migration. The 012 branch
--      guard fires on UPDATE only, so a branch INSERTed born
--      managed_journal remains the one admitted journal birth.
--   * pfh.cut_status fork recognition is folded in here: the root shipped
--      that correction in a later migration (its rehome/import migration)
--      together with import-commit provenance this lineage does not have;
--      only the fork arm is ported.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF001 stale/fenced, PF002
-- conflict, PF004 bounds, PF008 invalid argument, PF009 replay mismatch,
-- PF010 accounting corruption, PF011 proof missing).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='017_history_maintenance'
  ) THEN
    RAISE EXCEPTION '018 preflight: 017_history_maintenance receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '019%'
  ) THEN
    RAISE EXCEPTION '018 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfh.history_cuts') IS NULL
     OR to_regclass('pfh.pft2_commits') IS NULL
     OR to_regclass('pfh.cut_consumers') IS NULL
     OR to_regclass('pfh.inode_namespaces') IS NULL
     OR to_regclass('pfh.recovery_anchors') IS NULL
     OR to_regclass('pfh.objects') IS NULL
     OR to_regclass('pfh.resource_operations') IS NULL THEN
    RAISE EXCEPTION '018 preflight: the 013 history schema is incomplete';
  END IF;
  IF to_regprocedure('pfh.serving_base_prove(text,text,text,bigint,text,text,text)') IS NULL THEN
    RAISE EXCEPTION '018 preflight: the 014 serving proof is missing';
  END IF;
  IF to_regclass('pfh.pft2_fork_commits') IS NOT NULL THEN
    RAISE EXCEPTION '018 preflight: pfh.pft2_fork_commits already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: public grants (migration/table owner) ═════════════════════════

-- The narrow public write surface the atomic fork needs (see the header
-- deviation note): volume birth, branch birth (born managed_journal; the
-- UPDATE-only branch guard is untouched), and the default-branch pointer.
-- 013 already granted SELECT/REFERENCES on these tables plus INSERT on
-- public.commits (the ready-publication insert this migration reuses for the
-- fork-point commit).
GRANT INSERT ON TABLE public.volumes, public.branches TO portablefs_history_owner;
GRANT UPDATE (default_branch_id) ON public.volumes TO portablefs_history_owner;

-- ═══ SECTION B: pfh (history owner) — fork provenance + atomic fork ═══════════
SET LOCAL ROLE portablefs_history_owner;

-- The USER arm of a cross-volume fork destination: one immutable row keyed by
-- the destination fork-point commit (and uniquely by the destination branch),
-- binding the exact source cut, the source cut's single canonical result
-- commit, the destination volume/branch, and the copied root facts. It holds
-- deliberately ZERO recovery facts: a fork starts with empty controls and no
-- RecoveryRoot/control/orphan state, and its writability comes from the
-- destination branch's own fresh pfh.inode_namespaces row.
CREATE TABLE pfh.pft2_fork_commits (
  commit_id TEXT PRIMARY KEY REFERENCES public.commits(id),
  branch_id TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
  volume_id TEXT NOT NULL,
  source_cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  source_commit_id TEXT NOT NULL REFERENCES public.commits(id),
  root_digest TEXT NOT NULL CHECK (root_digest ~ '^[0-9a-f]{64}$'),
  root_size BIGINT NOT NULL CHECK (root_size > 0),
  max_ino_seen BIGINT NOT NULL CHECK (max_ino_seen >= 1),
  object_count BIGINT NOT NULL CHECK (object_count >= 1),
  object_bytes BIGINT NOT NULL CHECK (object_bytes >= 0),
  created_db_ms BIGINT NOT NULL
);
CREATE INDEX pft2_fork_commits_by_cut ON pfh.pft2_fork_commits (source_cut_id);

CREATE FUNCTION pfh.pft2_fork_commits_freeze() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'pft2 fork provenance rows are immutable' USING ERRCODE='PF001';
END;
$$;
REVOKE ALL ON FUNCTION pfh.pft2_fork_commits_freeze() FROM PUBLIC;
CREATE TRIGGER pft2_fork_commits_freeze
  BEFORE UPDATE OR DELETE ON pfh.pft2_fork_commits
  FOR EACH ROW EXECUTE FUNCTION pfh.pft2_fork_commits_freeze();

-- The ONLY writer of pfh.pft2_fork_commits. Runs as the history owner and
-- re-proves, inside the caller's transaction and before the row exists:
--   * the same-tenant READY source cut whose result commit is the named
--     source commit;
--   * the exact canonical PFT2 provenance — EXACTLY ONE pfh.pft2_commits row
--     for the cut (frozen 013/014 functions select by cut_id and assume the
--     single canonical result even though that table has no unique
--     constraint), matching commit/tenant with root facts inside the frozen
--     format bounds, and a currently LIVE registered user-root object;
--   * the exact destination: tenant-owned volume, managed_journal branch
--     headed by the fork-point commit, and the commit's copied identity
--     (tree hash from the copied root digest, lineage to the source result
--     commit, copied byte count, pft2 family) with ZERO recovery facts and
--     no cut provenance of its own;
--   * the ACTIVE 'fork' cut consumer binding this exact cut to the
--     destination branch;
--   * the fresh DB-issued destination inode namespace row.
-- Callable only by the history owner (pfh.volume_fork_from_cut) — no other
-- role receives EXECUTE and nothing receives direct pfh table privileges.
CREATE FUNCTION pfh.pft2_fork_commit_install(
  p_tenant TEXT, p_source_cut_id TEXT, p_source_commit_id TEXT,
  p_dest_volume_id TEXT, p_dest_branch_id TEXT, p_dest_commit_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  pc pfh.pft2_commits;
  ns pfh.inode_namespaces;
  o pfh.objects;
  cm public.commits;
  b RECORD;
  v_tenant_owner TEXT;
  v_rows BIGINT;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_source_cut_id IS NULL OR length(p_source_cut_id) NOT BETWEEN 1 AND 256
     OR p_source_commit_id IS NULL OR length(p_source_commit_id) NOT BETWEEN 1 AND 256
     OR p_dest_volume_id IS NULL OR length(p_dest_volume_id) NOT BETWEEN 1 AND 256
     OR p_dest_branch_id IS NULL OR length(p_dest_branch_id) NOT BETWEEN 1 AND 256
     OR p_dest_commit_id IS NULL OR length(p_dest_commit_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'fork provenance arguments are invalid' USING ERRCODE='PF008';
  END IF;

  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_source_cut_id AND tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND OR c.state<>'ready'
     OR c.result_commit_id IS DISTINCT FROM p_source_commit_id THEN
    RAISE EXCEPTION 'fork source cut proof failed' USING ERRCODE='PF011';
  END IF;

  SELECT COUNT(*) INTO v_rows FROM pfh.pft2_commits WHERE cut_id=c.id;
  IF v_rows<>1 THEN
    RAISE EXCEPTION 'fork source cut % carries % pft2 provenance rows; exactly one canonical row is required',
      c.id, v_rows USING ERRCODE='PF010';
  END IF;
  SELECT * INTO pc FROM pfh.pft2_commits
    WHERE commit_id=p_source_commit_id AND cut_id=c.id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'fork source PFT2 provenance is missing' USING ERRCODE='PF011';
  END IF;
  IF pc.root_size NOT BETWEEN 12 AND 262144
     OR pc.max_ino_seen NOT BETWEEN 1 AND 9223372036854775807::BIGINT THEN
    RAISE EXCEPTION 'fork source root provenance exceeds the frozen format bounds'
      USING ERRCODE='PF004';
  END IF;
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=p_tenant AND kind='pft2' AND digest='sha256:'||pc.root_digest;
  IF NOT FOUND OR o.state<>'live' THEN
    RAISE EXCEPTION 'fork source user root object is not live' USING ERRCODE='PF011';
  END IF;

  SELECT v.tenant_id INTO v_tenant_owner FROM public.volumes v WHERE v.id=p_dest_volume_id;
  IF NOT FOUND OR v_tenant_owner IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION 'fork destination volume proof failed' USING ERRCODE='PF011';
  END IF;
  SELECT br.id, br.branch_mode, br.head_commit_id INTO b FROM public.branches br
    WHERE br.id=p_dest_branch_id AND br.volume_id=p_dest_volume_id;
  IF NOT FOUND OR b.branch_mode<>'managed_journal'
     OR b.head_commit_id IS DISTINCT FROM p_dest_commit_id THEN
    RAISE EXCEPTION 'fork destination branch proof failed' USING ERRCODE='PF011';
  END IF;
  SELECT * INTO cm FROM public.commits
    WHERE id=p_dest_commit_id AND volume_id=p_dest_volume_id;
  IF NOT FOUND OR cm.branch_id IS DISTINCT FROM p_dest_branch_id
     OR cm.commit_kind<>'pft2'
     OR cm.tree_hash IS DISTINCT FROM ('pft2:'||pc.root_digest)
     OR cm.parent_commit_id IS DISTINCT FROM p_source_commit_id
     OR cm.byte_count IS DISTINCT FROM pc.object_bytes THEN
    RAISE EXCEPTION 'fork destination commit proof failed' USING ERRCODE='PF011';
  END IF;
  IF EXISTS (SELECT 1 FROM pfh.pft2_commits x WHERE x.commit_id=p_dest_commit_id)
     OR EXISTS (SELECT 1 FROM pfh.recovery_anchors ra WHERE ra.commit_id=p_dest_commit_id) THEN
    RAISE EXCEPTION 'fork destination commit already carries cut or recovery provenance'
      USING ERRCODE='PF010';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pfh.cut_consumers cc
    WHERE cc.consumer_kind='fork' AND cc.consumer_id=p_dest_branch_id
      AND cc.cut_id=c.id AND cc.tenant_id=p_tenant AND cc.released_db_ms IS NULL) THEN
    RAISE EXCEPTION 'fork consumer binding proof failed' USING ERRCODE='PF011';
  END IF;

  SELECT * INTO ns FROM pfh.inode_namespaces WHERE branch_id=p_dest_branch_id;
  IF NOT FOUND OR ns.tenant_id<>p_tenant OR ns.volume_id<>p_dest_volume_id
     OR ns.purpose<>'branch'
     OR ns.namespace NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'fork destination inode namespace proof failed' USING ERRCODE='PF011';
  END IF;

  v_now := pfh.now_ms();
  INSERT INTO pfh.pft2_fork_commits (
    commit_id, branch_id, tenant_id, volume_id, source_cut_id, source_commit_id,
    root_digest, root_size, max_ino_seen, object_count, object_bytes, created_db_ms)
  VALUES (
    p_dest_commit_id, p_dest_branch_id, p_tenant, p_dest_volume_id, c.id, pc.commit_id,
    pc.root_digest, pc.root_size, pc.max_ino_seen, pc.object_count, pc.object_bytes, v_now);
  RETURN jsonb_build_object(
    'commitId', p_dest_commit_id, 'branchId', p_dest_branch_id,
    'volumeId', p_dest_volume_id, 'sourceCutId', c.id, 'sourceCommitId', pc.commit_id,
    'rootDigest', pc.root_digest, 'rootSize', pc.root_size::TEXT,
    'maxInoSeen', pc.max_ino_seen::TEXT,
    'objectCount', pc.object_count::TEXT, 'objectBytes', pc.object_bytes::TEXT,
    'inodeNamespace', ns.namespace::TEXT);
END;
$$;
REVOKE ALL ON FUNCTION
  pfh.pft2_fork_commit_install(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT)
FROM PUBLIC;

-- The permanent operation ledger gains the fork domain. Forward replacement
-- of the 013 key validator (same signature, same message shape, one more
-- admitted domain) plus the matching table CHECK. Everything already stored
-- is untouched.
DO $domains$
DECLARE v_constraint TEXT;
BEGIN
  SELECT conname INTO v_constraint
  FROM pg_catalog.pg_constraint
  WHERE conrelid='pfh.resource_operations'::regclass AND contype='c'
    AND pg_catalog.pg_get_constraintdef(oid) LIKE '%history-cut%';
  IF v_constraint IS NULL THEN
    RAISE EXCEPTION '018: the 013 resource_operations domain constraint is missing';
  END IF;
  EXECUTE format('ALTER TABLE pfh.resource_operations DROP CONSTRAINT %I', v_constraint);
END;
$domains$;
ALTER TABLE pfh.resource_operations
  ADD CONSTRAINT resource_operations_domain_check CHECK (
    domain IN ('history-cut','adoption','scrub','conversion','volume-fork'));

CREATE OR REPLACE FUNCTION pfh.require_operation_key(
  p_tenant TEXT, p_domain TEXT, p_operation_id TEXT
) RETURNS void
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_domain IS NULL
     OR p_domain NOT IN ('history-cut','adoption','scrub','conversion','volume-fork')
     OR p_operation_id IS NULL OR length(p_operation_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'operation identity requires tenant, known domain, and id (<=256 chars)'
      USING ERRCODE='PF008';
  END IF;
END;
$$;

-- The one atomic cross-volume fork operation (the OSS expression of the
-- root's managed_volume_fork arm; see the header). Exact-once: the
-- ('volume-fork', operationId) resource operation is begun and settled
-- 'succeeded' in this same transaction, so an identical retry replays the
-- recorded response and a concurrent identical call converges on one
-- execution through the ledger's advisory key lock. A REFUSED fork raises a
-- typed PF0xx error and rolls the whole transaction back — including the
-- ledger row — so nothing partial ever survives and a later retry with the
-- same operationId can succeed once the source is ready.
--
-- p_dest_volume_id may be NULL: a fresh id is minted inside the operation
-- and recorded on the receipt, so a replay answers the SAME minted id (the
-- request fingerprint deliberately excludes server-minted values).
CREATE FUNCTION pfh.volume_fork_from_cut(
  p_tenant TEXT, p_source_cut_id TEXT, p_dest_volume_id TEXT,
  p_branch_name TEXT, p_operation_id TEXT, p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_op JSONB;
  c pfh.history_cuts;
  pc pfh.pft2_commits;
  v_now BIGINT;
  v_volume TEXT;
  v_branch_id TEXT;
  v_commit_id TEXT;
  v_install JSONB;
  v_response JSONB;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_source_cut_id IS NULL OR length(p_source_cut_id) NOT BETWEEN 1 AND 256
     OR p_branch_name IS NULL OR length(p_branch_name) NOT BETWEEN 1 AND 128
     OR (p_dest_volume_id IS NOT NULL
         AND length(p_dest_volume_id) NOT BETWEEN 1 AND 256) THEN
    RAISE EXCEPTION 'fork arguments are invalid' USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.require_sha256(p_fingerprint, 'fork fingerprint');

  v_op := pfh.resource_operation_begin(
    p_tenant, 'volume-fork', p_operation_id, 'volume-fork', p_fingerprint,
    '{}'::jsonb);
  IF (v_op->>'replayed')::BOOLEAN THEN
    -- Only applied forks persist a ledger row (refusals roll back), so a
    -- replayed key answers the recorded success. A compacted response is a
    -- typed conflict, never a re-execution: the fork already happened.
    IF v_op->>'state'='succeeded' AND jsonb_typeof(v_op->'response')='object' THEN
      RETURN (v_op->'response')
        || jsonb_build_object('operationId', p_operation_id, 'replayed', TRUE);
    END IF;
    RAISE EXCEPTION 'fork operation % already settled (state %) but its response is unavailable%',
      p_operation_id, COALESCE(v_op->>'state','unknown'),
      CASE WHEN (v_op->>'responseCompacted')::BOOLEAN THEN ' (compacted)' ELSE '' END
      USING ERRCODE='PF002';
  END IF;

  -- Same-tenant READY immutable source. Missing, foreign-tenant, pending,
  -- materializing, failed and canceled sources all answer identically
  -- (non-enumerable).
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_source_cut_id AND tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND OR c.state<>'ready' OR c.result_commit_id IS NULL THEN
    RAISE EXCEPTION 'source cut % is not a ready cut of this tenant', p_source_cut_id
      USING ERRCODE='PF011';
  END IF;
  -- The cut's PFT2 user root (the installer re-proves this row is the
  -- SINGLE canonical provenance row before the fork becomes durable).
  SELECT * INTO pc FROM pfh.pft2_commits
    WHERE commit_id=c.result_commit_id AND cut_id=c.id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'source cut % has no canonical PFT2 user root', p_source_cut_id
      USING ERRCODE='PF011';
  END IF;
  v_volume := COALESCE(p_dest_volume_id, pfh.new_id('pvol'));
  -- Global destination volume id uniqueness: one uniform answer no matter
  -- which tenant owns the colliding id (a concurrent race past this check
  -- fails on the primary key and rolls back identically).
  IF EXISTS (SELECT 1 FROM public.volumes WHERE id=v_volume) THEN
    RAISE EXCEPTION 'volume % already exists', v_volume USING ERRCODE='PF002';
  END IF;

  v_now := pfh.now_ms();
  v_branch_id := pfh.new_id('pbr');
  v_commit_id := pfh.new_id('cpft2f');
  INSERT INTO public.volumes (id, tenant_id, metadata, created_at)
    VALUES (v_volume, p_tenant, '{}'::jsonb, v_now);
  -- Destination fork-point commit: the EXACT immutable user-root
  -- identity/counts, lineage to the source result commit, and no recovery
  -- facts (pft2 shape: no manifest of any form).
  INSERT INTO public.commits (
    id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,
    manifest_base_commit_id, manifest_diff, materialized_manifest,
    mutation_count, byte_count, created_at, commit_kind)
  VALUES (v_commit_id, v_volume, v_branch_id, c.result_commit_id,
    'pft2:'||pc.root_digest, NULL, NULL, NULL, FALSE,
    0, pc.object_bytes, v_now, 'pft2');
  INSERT INTO public.branches (
    id, volume_id, name, head_commit_id, created_at, updated_at, branch_mode)
  VALUES (v_branch_id, v_volume, p_branch_name, v_commit_id, v_now, v_now,
    'managed_journal');
  UPDATE public.volumes SET default_branch_id=v_branch_id WHERE id=v_volume;
  -- Fresh never-reused destination allocator namespace. The source branch's
  -- allocator is never copied.
  PERFORM pfh.inode_namespace_issue(p_tenant, v_volume, v_branch_id, 'branch');
  -- The ACTIVE fork consumer bound to the destination branch is THE durable
  -- GC root of the source cut for this fork.
  PERFORM pfh.consumer_attach(p_tenant, p_source_cut_id, 'fork', v_branch_id);
  -- History-owner installer: re-proves cut/canonical-provenance/destination/
  -- consumer/namespace inside this same transaction, then writes the
  -- immutable positive fork provenance row. Any failure rolls back every
  -- row above.
  v_install := pfh.pft2_fork_commit_install(
    p_tenant, p_source_cut_id, c.result_commit_id, v_volume, v_branch_id, v_commit_id);

  UPDATE pfh.resource_operations SET
    target_ids = target_ids || jsonb_build_object(
      'volumeId', v_volume, 'branchId', v_branch_id, 'commitId', v_commit_id),
    updated_db_ms = v_now
  WHERE tenant_id=p_tenant AND domain='volume-fork' AND operation_id=p_operation_id;

  v_response := jsonb_build_object(
    'volumeId', v_volume,
    'branchId', v_branch_id,
    'branchName', p_branch_name,
    'commitId', v_commit_id,
    'sourceCutId', c.id,
    'sourceCommitId', c.result_commit_id,
    'rootDigest', pc.root_digest,
    'rootSize', pc.root_size::TEXT,
    'maxInoSeen', pc.max_ino_seen::TEXT,
    'objectCount', pc.object_count::TEXT,
    'objectBytes', pc.object_bytes::TEXT,
    'inodeNamespace', v_install->>'inodeNamespace',
    'createdDbMs', v_now::TEXT);
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'volume-fork', p_operation_id, 'succeeded', v_response);
  RETURN v_response
    || jsonb_build_object('operationId', p_operation_id, 'replayed', FALSE);
END;
$$;
REVOKE ALL ON FUNCTION
  pfh.volume_fork_from_cut(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT)
FROM PUBLIC;

-- 018 forward replacement of the quiesced 014 serving proof: same signature,
-- byte-identical behaviour for every 014 case (manifest_v1, same-volume
-- branch fork, conversion, adopted), plus ONE additive branch for
-- cross-volume fork destinations. A destination generation's pft2 base
-- commit carries pfh.pft2_fork_commits provenance instead of a
-- pfh.pft2_commits row; the proof returns the immutable copied user root and
-- the DESTINATION branch's own DB-issued allocator, and deliberately NO
-- RecoveryRoot/control anchor — a cross-volume fork starts with default PFC2
-- controls and no orphans, exactly like a same-volume branch fork. Every
-- binding is fail closed: a foreign generation (wrong volume/branch), a
-- non-origin base tuple, a released or missing fork consumer (the cut's GC
-- root for this destination), a missing destination namespace row, or root
-- facts that no longer match the destination commit refuse the proof rather
-- than degrading it.
CREATE OR REPLACE FUNCTION pfh.serving_base_prove(
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
  fc pfh.pft2_fork_commits;
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

  -- 018 additive branch: a registered cross-volume fork destination. The
  -- immutable provenance row is POSITIVE evidence; its absence falls through
  -- to the exact 014 same-branch/fork/conversion/adoption logic below and is
  -- never guessed from missing pft2_commits provenance.
  SELECT * INTO fc FROM pfh.pft2_fork_commits
    WHERE commit_id=cm.id AND tenant_id=p_tenant;
  IF FOUND THEN
    IF fc.volume_id IS DISTINCT FROM g.volume_id
       OR fc.branch_id IS DISTINCT FROM g.branch_id THEN
      RAISE EXCEPTION 'fork destination provenance binds a different volume/branch'
        USING ERRCODE='PF011';
    END IF;
    IF g.base_seq<>0 OR g.base_digest<>v_zero_digest THEN
      RAISE EXCEPTION 'fork destination generation no longer has its fresh seq-0 origin'
        USING ERRCODE='PF002';
    END IF;
    IF cm.tree_hash IS DISTINCT FROM ('pft2:'||fc.root_digest) THEN
      RAISE EXCEPTION 'fork destination commit no longer matches its copied root provenance'
        USING ERRCODE='PF011';
    END IF;
    IF fc.root_size NOT BETWEEN 12 AND 262144
       OR fc.max_ino_seen NOT BETWEEN 1 AND 9223372036854775807::BIGINT THEN
      RAISE EXCEPTION 'fork destination root provenance exceeds the frozen format bounds'
        USING ERRCODE='PF004';
    END IF;
    -- The ACTIVE fork consumer is the durable GC root of the source cut for
    -- this destination; serving from a released root would race object
    -- reclamation.
    IF NOT EXISTS (
      SELECT 1 FROM pfh.cut_consumers cc
      WHERE cc.cut_id=fc.source_cut_id AND cc.tenant_id=p_tenant
        AND cc.consumer_kind='fork' AND cc.consumer_id=fc.branch_id
        AND cc.released_db_ms IS NULL
    ) THEN
      RAISE EXCEPTION 'fork destination is missing its active fork cut consumer'
        USING ERRCODE='PF011';
    END IF;
    SELECT * INTO ns FROM pfh.inode_namespaces
      WHERE branch_id=g.branch_id AND tenant_id=p_tenant AND volume_id=g.volume_id;
    IF NOT FOUND
       OR ns.namespace NOT BETWEEN 1 AND 2147483647
       OR ns.next_local NOT BETWEEN 1 AND 4294967296
       OR ns.max_ino_seen NOT BETWEEN 1 AND 9223372036854775807::BIGINT THEN
      RAISE EXCEPTION 'fork destination is missing its issued branch inode namespace'
        USING ERRCODE='PF011';
    END IF;
    RETURN jsonb_build_object(
      'v','1','kind','pft2','baseMode','fork','tenantId',p_tenant,
      'commitId',cm.id,'volumeId',g.volume_id,'branchId',g.branch_id,
      'generationId',g.id,'baseSeq',g.base_seq::TEXT,
      'baseDigest',g.base_digest,'recordCodec',g.record_codec,
      'controlCodec',g.control_codec,
      'root',jsonb_build_object(
        'digest',fc.root_digest,'size',fc.root_size::TEXT,
        'maxInoSeen',fc.max_ino_seen::TEXT),
      'allocator',jsonb_build_object(
        'inodeNamespace',ns.namespace::TEXT,
        'nextLocal',ns.next_local::TEXT,
        'maxInoSeen',ns.max_ino_seen::TEXT));
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

-- 018 forward replacement of the 014 cut-status projection: identical
-- signature, rows, and keys; the baseCommit view now recognizes fork
-- destination bases POSITIVELY from their provenance table. Before this, a
-- fork destination's own next cut projected NO baseMode (its base commit has
-- no pfh.pft2_commits row) and the worker failed it closed.
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

-- ═══ SECTION C: grants + postconditions ═══════════════════════════════════════

-- Metadata/caller surface (the volume-api repository's admin DSN role), the
-- exact 013 grant pattern. The installer is deliberately NOT granted: the
-- orchestrator (running as the history owner) is its only caller.
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfh.volume_fork_from_cut(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT)
    TO %I', CURRENT_USER);
END
$$;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  -- The provenance table exists, owned by the history owner, frozen, empty.
  IF (SELECT pg_get_userbyid(c.relowner) FROM pg_class c
      WHERE c.oid='pfh.pft2_fork_commits'::regclass) <> 'portablefs_history_owner' THEN
    RAISE EXCEPTION '018 postcondition: pft2_fork_commits owner drift';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='pft2_fork_commits_freeze'
                   AND tgrelid='pfh.pft2_fork_commits'::regclass) THEN
    RAISE EXCEPTION '018 postcondition: pft2_fork_commits freeze trigger is missing';
  END IF;
  SELECT COUNT(*) INTO v_count FROM pfh.pft2_fork_commits;
  IF v_count <> 0 THEN
    RAISE EXCEPTION '018 postcondition: fork provenance rows exist at install time';
  END IF;
  -- The new/replaced functions: owner, definer, pinned search_path.
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, pg_get_userbyid(p.proowner) AS owner,
           p.prosecdef,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh'
      AND p.proname IN ('pft2_fork_commit_install','volume_fork_from_cut',
                        'serving_base_prove','cut_status')
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner' OR NOT v_rec.prosecdef
       OR v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '018 postcondition: pfh.% owner/definer/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '018 postcondition: PUBLIC can execute pfh.%', v_rec.proname;
    END IF;
  END LOOP;
  -- The restricted roles gained NOTHING here (DIRECT grants).
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh'
      AND p.proname IN ('pft2_fork_commit_install','volume_fork_from_cut')
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_worker'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '018 postcondition: a restricted role can execute a fork function';
  END IF;
  -- The replaced serving proof actually recognizes fork-destination
  -- provenance (a stale 014 body silently surviving the replace would leave
  -- every fork destination permanently unservable), and cut_status projects
  -- fork bases.
  IF position('pft2_fork_commits' IN pg_get_functiondef(
       to_regprocedure('pfh.serving_base_prove(text,text,text,bigint,text,text,text)'))) = 0 THEN
    RAISE EXCEPTION '018 postcondition: the serving proof does not recognize fork-destination provenance';
  END IF;
  IF position('pft2_fork_commits' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_status(text,text)'))) = 0 THEN
    RAISE EXCEPTION '018 postcondition: cut_status does not recognize fork-destination bases';
  END IF;
  -- The ledger admits the fork domain (constraint and validator agree).
  IF COALESCE((SELECT pg_get_constraintdef(oid) FROM pg_constraint
      WHERE conrelid='pfh.resource_operations'::regclass
        AND conname='resource_operations_domain_check'),'')
      NOT LIKE '%volume-fork%' THEN
    RAISE EXCEPTION '018 postcondition: resource_operations domain constraint does not admit volume-fork';
  END IF;
  IF position('volume-fork' IN pg_get_functiondef(
       to_regprocedure('pfh.require_operation_key(text,text,text)'))) = 0 THEN
    RAISE EXCEPTION '018 postcondition: require_operation_key does not admit volume-fork';
  END IF;
  -- The narrow public write surface exists.
  IF NOT has_table_privilege('portablefs_history_owner','public.volumes','INSERT')
     OR NOT has_table_privilege('portablefs_history_owner','public.branches','INSERT')
     OR NOT has_column_privilege('portablefs_history_owner','public.volumes','default_branch_id','UPDATE') THEN
    RAISE EXCEPTION '018 postcondition: the history owner public fork write surface is missing';
  END IF;
  -- No PUBLIC/worker table grants leaked into pfh.
  SELECT COUNT(*) INTO v_count FROM information_schema.role_table_grants
    WHERE table_schema='pfh'
      AND grantee IN ('PUBLIC','portablefs_history_worker','portablefs_authority');
  IF v_count <> 0 THEN
    RAISE EXCEPTION '018 postcondition: restricted/public role has direct pfh table grants';
  END IF;
  -- Lineage: 019 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '019%') THEN
    RAISE EXCEPTION '018 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
