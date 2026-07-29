-- 027_history_delta_publish: O(delta) closure registration.
--
-- Publication used to re-register (and, before 025, re-prove) the ENTIRE
-- reachable closure of every cut — one row per object per cut, walked and
-- shipped from the worker in 4,096-digest pages: O(tree) database work per
-- cut even when the fold changed three files. With chained cuts (026) the
-- base cut's closure rows already name every reused object, so the worker
-- now registers only the objects THIS run produced and asks the database
-- to copy the rest server-side:
--
--   pfh.cut_objects_add_from_base(cutId, claimEpoch)
--       copies the ADOPTED same-branch base cut's closure rows (both
--       closures) into this cut in one statement and returns the final
--       per-closure counts and byte totals for the publication.
--
-- The registered closure becomes a SUPERSET of the exact reachable set:
-- objects the fold deleted stay registered on the new cut (they were
-- reachable from its base). That is deliberate — the closure's job is GC
-- rootedness and serving authorization, both of which tolerate supersets;
-- storage stays bounded because retention (a later migration) releases
-- old cuts and the sweep collects whatever no retained closure names.
-- Freshness of reused rows already belongs to the scrub loop (025's
-- intent-gated publication proof).
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF011 proof missing).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='026_history_chained_cuts'
  ) THEN
    RAISE EXCEPTION '027 preflight: 026_history_chained_cuts receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '028%'
  ) THEN
    RAISE EXCEPTION '027 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfh.cut_objects') IS NULL THEN
    RAISE EXCEPTION '027 preflight: the 013 closure table is missing';
  END IF;
  IF to_regprocedure('pfh.cut_objects_add_from_base(text,bigint)') IS NOT NULL THEN
    RAISE EXCEPTION '027 preflight: pfh.cut_objects_add_from_base already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — base-closure copy ═══════════════════════
SET LOCAL ROLE portablefs_history_owner;

CREATE FUNCTION pfh.cut_objects_add_from_base(
  p_cut_id TEXT, p_claim_epoch BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_base RECORD;
  v_user_count BIGINT;
  v_user_bytes BIGINT;
  v_recovery_count BIGINT;
  v_recovery_bytes BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF c.source_base_commit_id IS NULL THEN
    RAISE EXCEPTION 'cut % has no base commit to copy closures from', p_cut_id
      USING ERRCODE='PF011';
  END IF;
  -- The base must be a READY same-branch cut's pft2 commit — exactly the
  -- provenance cut_status projects as baseMode 'adopted'. Fork and
  -- conversion bases never take this path: their closures are not the
  -- new branch's history.
  SELECT bp.cut_id AS base_cut_id, bcut.branch_id, bcut.state
    INTO v_base
    FROM pfh.pft2_commits bp
    JOIN pfh.history_cuts bcut ON bcut.id=bp.cut_id
    WHERE bp.commit_id=c.source_base_commit_id AND bp.tenant_id=c.tenant_id;
  IF NOT FOUND OR v_base.branch_id <> c.branch_id OR v_base.state <> 'ready' THEN
    RAISE EXCEPTION 'cut % base commit % is not an adopted same-branch ready cut',
      p_cut_id, c.source_base_commit_id USING ERRCODE='PF011';
  END IF;
  INSERT INTO pfh.cut_objects (cut_id, closure, tenant_id, kind, digest)
  SELECT p_cut_id, co.closure, co.tenant_id, co.kind, co.digest
  FROM pfh.cut_objects co
  WHERE co.cut_id=v_base.base_cut_id
  ON CONFLICT DO NOTHING;
  SELECT
    COUNT(*) FILTER (WHERE co.closure='user'),
    COALESCE(SUM(o.size) FILTER (WHERE co.closure='user'), 0),
    COUNT(*) FILTER (WHERE co.closure='recovery'),
    COALESCE(SUM(o.size) FILTER (WHERE co.closure='recovery'), 0)
    INTO v_user_count, v_user_bytes, v_recovery_count, v_recovery_bytes
    FROM pfh.cut_objects co
    LEFT JOIN pfh.objects o
      ON o.tenant_id=co.tenant_id AND o.kind=co.kind AND o.digest=co.digest
    WHERE co.cut_id=p_cut_id;
  RETURN jsonb_build_object(
    'baseCutId', v_base.base_cut_id,
    'userObjectCount', v_user_count::TEXT,
    'userObjectBytes', v_user_bytes::TEXT,
    'recoveryObjectCount', v_recovery_count::TEXT,
    'recoveryObjectBytes', v_recovery_bytes::TEXT);
END;
$$;
REVOKE ALL ON FUNCTION pfh.cut_objects_add_from_base(TEXT,BIGINT) FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

GRANT EXECUTE ON FUNCTION pfh.cut_objects_add_from_base(TEXT,BIGINT)
TO portablefs_history_worker;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  SELECT p.oid AS fnoid, pg_get_userbyid(p.proowner) AS owner, p.prosecdef,
         COALESCE(array_to_string(p.proconfig,';'),'') AS config
    INTO v_rec
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh' AND p.proname='cut_objects_add_from_base';
  IF NOT FOUND THEN
    RAISE EXCEPTION '027 postcondition: pfh.cut_objects_add_from_base is missing';
  END IF;
  IF v_rec.owner <> 'portablefs_history_owner' OR NOT v_rec.prosecdef
     OR v_rec.config NOT LIKE '%search_path%' THEN
    RAISE EXCEPTION '027 postcondition: cut_objects_add_from_base owner/definer/path drift';
  END IF;
  IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
    RAISE EXCEPTION '027 postcondition: PUBLIC can execute cut_objects_add_from_base';
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='cut_objects_add_from_base'
      AND acl.grantee='portablefs_history_worker'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 1 THEN
    RAISE EXCEPTION '027 postcondition: the worker grant on cut_objects_add_from_base is missing';
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='cut_objects_add_from_base'
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '027 postcondition: a restricted role can execute cut_objects_add_from_base';
  END IF;
  -- Lineage: 028 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '028%') THEN
    RAISE EXCEPTION '027 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
