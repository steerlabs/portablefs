-- 028_history_retention: bounded history storage.
--
-- Until now storage was UNBOUNDED BY DESIGN: pfh.object_is_root kept a
-- ready cut's closure alive while its commit had ANY child commit — and
-- with chained cuts (026) every cut's commit becomes the parent of the
-- next, so every cut in the chain was a permanent GC root; adoption
-- consumers additionally accumulated one unreleased pin per adoption
-- forever. There was no delete path for any of it.
--
-- The retention policy, enforced structurally by the root predicate:
-- a ready cut's closure stays rooted iff the cut is
--   (a) pinned — an unreleased consumer (branch/fork/publish/conversion/
--       adoption/snapshot), an unreleased serving pin (either arm), the
--       source base of a live fold (026), or its commit is a branch head,
--       a public snapshot, or a LIVE generation base;
--   (b) named — user_label IS NOT NULL — on a live (unretired) volume; or
--   (c) recent — among the newest KEEP_READY_CUTS_PER_BRANCH = 8 ready
--       cuts of its branch, on a live volume.
-- The child-commit clause is REMOVED: in-flight folds are covered by the
-- 026 clause, the recent chain by (c), and fork lineage by the durable
-- ACTIVE 'fork' consumer 018 attaches. Everything that falls out of the
-- root set is collected by the EXISTING sweep (claims, absence proofs,
-- tombstones — unchanged).
--
-- Two release surfaces feed the policy:
--   * pfh.retention_release(limit) — the bounded maintenance entry point
--     the worker loop drives: releases adoption consumers whose adoption
--     is durably superseded (a strictly newer APPLIED adoption exists for
--     the same generation, or the generation is gone) and whose serving
--     pin is released. Everything else it leaves alone.
--   * pfh.snapshot_cut_release(tenant, volume, name) — named-snapshot
--     deletion for the caller surface: clears the label (and releases any
--     unreleased snapshot consumers) of the named ready cuts, so they age
--     out through (c) and the sweep collects them.
--
-- pfh.consumer_attach additionally refuses to attach a consumer to a
-- ready cut whose root object is already deleting/tombstoned: branching
-- or forking a retained-out cut must fail typed instead of serving holes.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF002 conflict, PF004 bounds,
-- PF007 not found, PF008 invalid argument, PF011 proof missing).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='027_history_delta_publish'
  ) THEN
    RAISE EXCEPTION '028 preflight: 027_history_delta_publish receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '029%'
  ) THEN
    RAISE EXCEPTION '028 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfh.object_is_root(text,text,text)') IS NULL
     OR to_regprocedure('pfh.consumer_attach(text,text,text,text)') IS NULL THEN
    RAISE EXCEPTION '028 preflight: the 013/026 root surface is incomplete';
  END IF;
  IF to_regprocedure('pfh.retention_release(int)') IS NOT NULL
     OR to_regprocedure('pfh.snapshot_cut_release(text,text,text)') IS NOT NULL THEN
    RAISE EXCEPTION '028 preflight: a 028 function already exists';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='volumes' AND column_name='retired_at'
  ) THEN
    RAISE EXCEPTION '028 preflight: the 021 volume retirement column is missing';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — retention-aware roots + releases ════════
SET LOCAL ROLE portablefs_history_owner;

-- The K-newest window scans ready cuts per branch on every root check.
CREATE INDEX history_cuts_ready_by_branch
  ON pfh.history_cuts (branch_id, ready_db_ms DESC, id DESC)
  WHERE state='ready';

-- 028 revision of the root predicate: retention IS the root set. The
-- newest-K constant is a property of the design, not a knob.
CREATE OR REPLACE FUNCTION pfh.object_is_root(p_tenant TEXT, p_kind TEXT, p_digest TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  KEEP_READY_CUTS_PER_BRANCH CONSTANT INT := 8;
BEGIN
  -- 028_history_retention revision.
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
                       OR EXISTS (SELECT 1 FROM pfj.journal_generations jg
                                  WHERE jg.base_commit_id=cm.id
                                    AND jg.status IN ('active','suspended','retiring'))))
        OR ((hc.user_label IS NOT NULL
             OR (SELECT COUNT(*) FROM pfh.history_cuts newer
                 WHERE newer.branch_id=hc.branch_id AND newer.state='ready'
                   AND (newer.ready_db_ms, newer.id) > (hc.ready_db_ms, hc.id))
                < KEEP_READY_CUTS_PER_BRANCH)
            AND EXISTS (SELECT 1 FROM public.volumes v
                        WHERE v.tenant_id=hc.tenant_id AND v.id=hc.volume_id
                          AND v.retired_at IS NULL))));
END;
$$;

-- The bounded maintenance entry point the worker loop drives: release
-- adoption consumers whose adoption is durably superseded. An adoption is
-- superseded when a strictly newer APPLIED adoption exists for the same
-- generation, or the generation is gone; its serving pin (the transition
-- window of the still-serving child) must already be released. Everything
-- else — snapshot/branch/fork/publish/conversion consumers — is owned by
-- its own lifecycle and never auto-released here.
CREATE FUNCTION pfh.retention_release(p_limit INT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,64),1),256);
  v_now BIGINT := pfh.now_ms();
  v_released BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  WITH superseded AS (
    SELECT cc.id
    FROM pfh.cut_consumers cc
    JOIN pfh.adoptions a ON a.id=cc.consumer_id
    WHERE cc.consumer_kind='adoption'
      AND cc.released_db_ms IS NULL
      AND a.state='applied'
      AND NOT EXISTS (
        SELECT 1 FROM pfh.serving_base_pins sp
        WHERE sp.adoption_id=a.id AND sp.released_db_ms IS NULL)
      AND (EXISTS (
             SELECT 1 FROM pfh.adoptions newer
             WHERE newer.generation_id=a.generation_id
               AND newer.state='applied'
               AND newer.new_base_seq > a.new_base_seq)
        OR NOT EXISTS (
             SELECT 1 FROM pfj.journal_generations g WHERE g.id=a.generation_id))
    ORDER BY a.applied_db_ms
    LIMIT v_limit
    FOR UPDATE OF cc SKIP LOCKED)
  UPDATE pfh.cut_consumers u SET released_db_ms=v_now
  FROM superseded WHERE u.id=superseded.id;
  GET DIAGNOSTICS v_released = ROW_COUNT;
  RETURN jsonb_build_object('adoptionConsumersReleased', v_released::TEXT);
END;
$$;
REVOKE ALL ON FUNCTION pfh.retention_release(INT) FROM PUBLIC;

-- Named-snapshot deletion: clear the label (and release any snapshot
-- consumers) of the named READY cuts of one volume. The cuts then age out
-- of the retention window and the ordinary sweep collects their objects;
-- a cut that is also adoption-pinned or a live generation base stays
-- rooted through those clauses exactly as long as they hold.
CREATE FUNCTION pfh.snapshot_cut_release(
  p_tenant TEXT, p_volume_id TEXT, p_name TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_now BIGINT := pfh.now_ms();
  v_ids TEXT[];
  v_consumers BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_volume_id IS NULL OR length(p_volume_id) NOT BETWEEN 1 AND 256
     OR p_name IS NULL OR length(p_name) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'snapshot release requires tenant, volume, and name (<=256 chars)'
      USING ERRCODE='PF008';
  END IF;
  SELECT array_agg(locked.id ORDER BY locked.id) INTO v_ids FROM (
    SELECT id FROM pfh.history_cuts
    WHERE tenant_id=p_tenant AND volume_id=p_volume_id
      AND user_label=p_name AND state='ready'
    ORDER BY id
    FOR UPDATE) locked;
  IF v_ids IS NULL THEN
    RAISE EXCEPTION 'volume % has no ready snapshot named %', p_volume_id, p_name
      USING ERRCODE='PF007';
  END IF;
  UPDATE pfh.history_cuts SET user_label=NULL, updated_db_ms=v_now
  WHERE id = ANY(v_ids);
  UPDATE pfh.cut_consumers SET released_db_ms=v_now
  WHERE cut_id = ANY(v_ids) AND consumer_kind='snapshot' AND released_db_ms IS NULL;
  GET DIAGNOSTICS v_consumers = ROW_COUNT;
  RETURN jsonb_build_object(
    'cutIds', to_jsonb(v_ids),
    'snapshotConsumersReleased', v_consumers);
END;
$$;
REVOKE ALL ON FUNCTION pfh.snapshot_cut_release(TEXT,TEXT,TEXT) FROM PUBLIC;

-- 028 revision of the 013 consumer attach: identical behaviour plus the
-- retained-out guard — a ready cut whose root object is already deleting
-- or tombstoned cannot take a new consumer (the history is gone or going;
-- resurrection is the sweep's decision, not an attach side effect).
CREATE OR REPLACE FUNCTION pfh.consumer_attach(
  p_tenant TEXT, p_cut_id TEXT, p_consumer_kind TEXT, p_consumer_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_root_state TEXT;
  v_now BIGINT;
  v_id TEXT;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_consumer_kind NOT IN ('snapshot','branch','fork','publish','adoption','conversion') THEN
    RAISE EXCEPTION 'consumer kind % is unknown', p_consumer_kind USING ERRCODE='PF008';
  END IF;
  IF p_consumer_id IS NULL OR length(p_consumer_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'consumer id is required (<=256 chars)' USING ERRCODE='PF008';
  END IF;
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF p_consumer_kind NOT IN ('conversion') AND c.state <> 'ready' THEN
    RAISE EXCEPTION 'cut % is % and cannot be consumed', p_cut_id, c.state
      USING ERRCODE='PF002';
  END IF;
  IF c.state = 'ready' THEN
    SELECT o.state INTO v_root_state
      FROM pfh.pft2_commits pc
      JOIN pfh.objects o
        ON o.tenant_id=c.tenant_id AND o.kind='pft2'
       AND o.digest='sha256:'||pc.root_digest
      WHERE pc.cut_id=c.id;
    IF FOUND AND v_root_state IN ('deleting','tombstoned') THEN
      RAISE EXCEPTION 'cut % history has been retained out (root object %)',
        p_cut_id, v_root_state USING ERRCODE='PF011';
    END IF;
  END IF;
  v_now := pfh.now_ms();
  v_id := pfh.new_id('hcon');
  INSERT INTO pfh.cut_consumers (id, cut_id, tenant_id, consumer_kind, consumer_id, created_db_ms)
  VALUES (v_id, p_cut_id, p_tenant, p_consumer_kind, p_consumer_id, v_now)
  ON CONFLICT (consumer_kind, consumer_id) DO NOTHING;
  RETURN jsonb_build_object('consumerId', p_consumer_id, 'cutId', p_cut_id,
                            'kind', p_consumer_kind);
END;
$$;

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

-- Worker surface: the retention pass joins the maintenance loops.
GRANT EXECUTE ON FUNCTION pfh.retention_release(INT)
TO portablefs_history_worker;

-- Caller surface: named-snapshot deletion (the volume-api's admin DSN role).
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfh.snapshot_cut_release(TEXT,TEXT,TEXT)
    TO %I', CURRENT_USER);
END
$$;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  IF to_regclass('pfh.history_cuts_ready_by_branch') IS NULL THEN
    RAISE EXCEPTION '028 postcondition: the ready-by-branch index is missing';
  END IF;
  FOR v_rec IN
    SELECT p.oid AS fnoid, p.proname, pg_get_userbyid(p.proowner) AS owner,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh'
      AND p.proname IN ('object_is_root','retention_release',
                        'snapshot_cut_release','consumer_attach')
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner'
       OR v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '028 postcondition: pfh.% owner/path drift', v_rec.proname;
    END IF;
    IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
      RAISE EXCEPTION '028 postcondition: PUBLIC can execute pfh.%', v_rec.proname;
    END IF;
  END LOOP;
  -- The retention predicate landed and the unbounded child-commit clause
  -- is gone.
  IF position('KEEP_READY_CUTS_PER_BRANCH' IN pg_get_functiondef(
       to_regprocedure('pfh.object_is_root(text,text,text)'))) = 0 THEN
    RAISE EXCEPTION '028 postcondition: object_is_root misses the retention window';
  END IF;
  IF position('child.parent_commit_id=cm.id' IN pg_get_functiondef(
       to_regprocedure('pfh.object_is_root(text,text,text)'))) > 0 THEN
    RAISE EXCEPTION '028 postcondition: object_is_root still roots every child-commit parent';
  END IF;
  IF position('retained out' IN pg_get_functiondef(
       to_regprocedure('pfh.consumer_attach(text,text,text,text)'))) = 0 THEN
    RAISE EXCEPTION '028 postcondition: consumer_attach misses the retained-out guard';
  END IF;
  -- Exactly the worker holds retention_release; the restricted roles
  -- gained nothing else.
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='retention_release'
      AND acl.grantee='portablefs_history_worker'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 1 THEN
    RAISE EXCEPTION '028 postcondition: the worker grant on retention_release is missing';
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh'
      AND p.proname IN ('retention_release','snapshot_cut_release')
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '028 postcondition: a restricted role can execute a 028 release';
  END IF;
  -- Lineage: 029 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '029%') THEN
    RAISE EXCEPTION '028 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
