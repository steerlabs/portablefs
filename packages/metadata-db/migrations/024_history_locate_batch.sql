-- 024_history_locate_batch: batched object location for convergent retries.
--
-- A retried cut attempt used to re-upload its ENTIRE object set: cutstore
-- Flush never consulted the copy receipts a previous attempt already
-- recorded, so a cut whose clean run needs more store I/O than one attempt
-- window could never converge against a throttling store (the 25-minute
-- incident class). The worker now batch-locates every intent batch BEFORE
-- uploading and skips objects that already hold fresh verified copies at
-- the bound incarnation in the required failure domains.
--
-- pfh.object_locate answers one digest per call — exactly the per-object
-- DB storm the convergent path must avoid. This migration adds the bounded
-- batched projection:
--
--   pfh.object_locate_batch(tenant, kind, digests[1..512])
--       one pfh.object_locate-shaped JSONB row per KNOWN digest (unknown /
--       tombstoned digests are simply absent from the result set), read in
--       one snapshot.
--
-- STABLE single-statement read: no locks beyond MVCC row reads, no
-- mutation, no advisory keys. Only the worker role gains EXECUTE — the
-- caller/serving surface keeps the single-digest pfh.object_locate.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF004 bounds, PF008 invalid
-- argument).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='023_tenant_scoped_volume_identity'
  ) THEN
    RAISE EXCEPTION '024 preflight: 023_tenant_scoped_volume_identity receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '025%'
  ) THEN
    RAISE EXCEPTION '024 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfh.objects') IS NULL
     OR to_regprocedure('pfh.object_locate(text,text,text)') IS NULL THEN
    RAISE EXCEPTION '024 preflight: the 013 object registry surface is incomplete';
  END IF;
  IF to_regprocedure('pfh.object_locate_batch(text,text,text[])') IS NOT NULL THEN
    RAISE EXCEPTION '024 preflight: pfh.object_locate_batch already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — batched location projection ═════════════
SET LOCAL ROLE portablefs_history_owner;

-- One pfh.object_locate row per known digest, in one snapshot. Same shape,
-- same rules: only 'present' copies of the CURRENT incarnation of a
-- non-tombstoned object are returned, exactly as receipts recorded them.
CREATE FUNCTION pfh.object_locate_batch(
  p_tenant TEXT, p_kind TEXT, p_digests TEXT[]
) RETURNS SETOF JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_count INT;
BEGIN
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_kind IS DISTINCT FROM 'pft2' THEN
    RAISE EXCEPTION 'object locate batch requires tenant and kind pft2'
      USING ERRCODE='PF008';
  END IF;
  v_count := COALESCE(array_length(p_digests,1),0);
  IF v_count NOT BETWEEN 1 AND 512 THEN
    RAISE EXCEPTION 'object locate batches are bounded to 1..512 digests'
      USING ERRCODE='PF004';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(p_digests) d(v) WHERE v !~ '^sha256:[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'object digests must be sha256 addresses' USING ERRCODE='PF008';
  END IF;
  RETURN QUERY
    SELECT jsonb_build_object(
      'tenantId', o.tenant_id, 'kind', o.kind, 'digest', o.digest,
      'size', o.size::TEXT, 'incarnation', o.incarnation::TEXT,
      'state', o.state,
      'copies', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'failureDomain', oc.failure_domain,
            'storageKey', oc.storage_key,
            'size', oc.size::TEXT,
            'lastVerifiedDbMs', oc.last_verified_db_ms::TEXT)
            ORDER BY oc.last_verified_db_ms DESC)
        FROM pfh.object_copies oc
        WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
          AND oc.incarnation=o.incarnation AND oc.state='present'), '[]'::jsonb))
    FROM pfh.objects o
    JOIN unnest(p_digests) d(v) ON d.v=o.digest
    WHERE o.tenant_id=p_tenant AND o.kind=p_kind
      AND o.state <> 'tombstoned';
END;
$$;
REVOKE ALL ON FUNCTION pfh.object_locate_batch(TEXT,TEXT,TEXT[]) FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

-- Worker surface only: the convergent Flush path is claim-driven worker
-- code; serving keeps the single-digest projection.
GRANT EXECUTE ON FUNCTION pfh.object_locate_batch(TEXT,TEXT,TEXT[])
TO portablefs_history_worker;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  SELECT p.oid AS fnoid, pg_get_userbyid(p.proowner) AS owner, p.prosecdef,
         p.provolatile,
         COALESCE(array_to_string(p.proconfig,';'),'') AS config
    INTO v_rec
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh' AND p.proname='object_locate_batch';
  IF NOT FOUND THEN
    RAISE EXCEPTION '024 postcondition: pfh.object_locate_batch is missing';
  END IF;
  IF v_rec.owner <> 'portablefs_history_owner' OR NOT v_rec.prosecdef
     OR v_rec.config NOT LIKE '%search_path%' OR v_rec.provolatile <> 's' THEN
    RAISE EXCEPTION '024 postcondition: object_locate_batch owner/definer/path/volatility drift';
  END IF;
  IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
    RAISE EXCEPTION '024 postcondition: PUBLIC can execute object_locate_batch';
  END IF;
  -- Exactly the worker holds the DIRECT grant; auditor/authority gained
  -- nothing.
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='object_locate_batch'
      AND acl.grantee='portablefs_history_worker'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 1 THEN
    RAISE EXCEPTION '024 postcondition: the worker grant on object_locate_batch is missing';
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='object_locate_batch'
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '024 postcondition: a restricted role can execute object_locate_batch';
  END IF;
  -- Lineage: 025 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '025%') THEN
    RAISE EXCEPTION '024 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
