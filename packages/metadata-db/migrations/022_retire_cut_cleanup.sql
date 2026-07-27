-- 022_retire_cut_cleanup: retirement cascades to the volume's history work.
--
-- Migration 021 made retirement a metadata fact (volumes.retired_at) that
-- fences every per-volume ROUTE, but the pfh history plane kept running for
-- a retired volume: a pending/materializing cut stayed claimable forever,
-- and pfh.cut_cancel refused it (PF002) whenever an unreleased
-- conversion/adoption consumer pinned it — the exact production shape of a
-- volume retired mid-activation, whose conversion_final cut then retried
-- with no reachable cancel path ("cut ... is pinned by a
-- conversion/adoption consumer").
--
-- This migration adds ONE idempotent SECURITY DEFINER cleanup operation the
-- volume-api calls AFTER the 021 retirement receipt is durable:
--
--   pfh.volume_retire_cleanup(p_tenant, p_volume) -> counts
--     1. releases the volume's unreleased 'conversion'/'adoption' cut
--        consumers (the pins that refuse cut_cancel; snapshot/branch/fork/
--        publish consumers are deliberately untouched — a fork consumer is
--        a LIVE destination volume's GC root),
--     2. voids the volume's non-terminal conversions (migrating/final_cut
--        -> failed, mirroring pfh.conversion_abort) with a typed
--        {kind:'volume_retired'} reason,
--     3. cancels the volume's non-terminal cuts (pending/materializing ->
--        canceled) with the same typed last_error — read distinctly from a
--        genuine materialization failure — and settles each cut's permanent
--        resource operation 'canceled' exactly like pfh.cut_cancel.
--
-- 'canceled' is terminal for the worker: pfh.cut_claim only ever claims
-- pending/materializing rows, and every claim-fenced worker call
-- (heartbeat/retry/fail/ready) refuses a canceled cut with PF001. A worker
-- holding a live claim at cleanup time simply loses its next fenced call.
--
-- Idempotent by construction: every statement narrows on non-terminal
-- state, so a replayed cleanup (crash between receipt and cleanup, hosted
-- control-plane retry) matches nothing and answers zero counts. The
-- function refuses a LIVE volume (PF011) — the retirement receipt is the
-- precondition, never an effect, of this cleanup — and answers PF007 for an
-- unknown/foreign volume (same non-enumerating shape as the caller surface).
--
-- Serving-base pins are deliberately NOT force-released here: an unexpired
-- authority may still serve lazy reads from the pinned old base. Retirement
-- stops lease renewal, so the existing fenced sweep
-- (pfh.serving_pins_unreleased -> pfh.serving_pin_release_fenced) releases
-- them as soon as the pinned runtime is provably superseded.
--
-- SECURITY MODEL (extends 013/017; same discipline): the function is owned
-- by portablefs_history_owner, carries a pinned search_path, loses PUBLIC
-- EXECUTE through the 013 owner-level default-privileges revoke (asserted
-- again below), and is EXECUTE-granted to the migration user (the
-- volume-api repository's admin DSN role) exactly like the 013 caller
-- surface. The authority, worker, and auditor roles gain nothing.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF007 not found, PF008 invalid
-- argument, PF011 precondition failure).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='021_volume_retirement'
  ) THEN
    RAISE EXCEPTION '022 preflight: 021_volume_retirement receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '023%'
  ) THEN
    RAISE EXCEPTION '022 preflight: a later migration receipt exists';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='volumes' AND column_name='retired_at'
  ) THEN
    RAISE EXCEPTION '022 preflight: the 021 volumes.retired_at receipt column is missing';
  END IF;
  IF to_regclass('pfh.history_cuts') IS NULL
     OR to_regclass('pfh.cut_consumers') IS NULL
     OR to_regclass('pfh.conversions') IS NULL
     OR to_regclass('pfh.resource_operations') IS NULL THEN
    RAISE EXCEPTION '022 preflight: a 013 history table is missing';
  END IF;
  IF to_regprocedure('pfh.volume_retire_cleanup(text,text)') IS NOT NULL THEN
    RAISE EXCEPTION '022 preflight: pfh.volume_retire_cleanup already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: pfh (history owner) — the retirement cascade ══════════════════
SET LOCAL ROLE portablefs_history_owner;

CREATE FUNCTION pfh.volume_retire_cleanup(
  p_tenant TEXT, p_volume TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_retired_at TIMESTAMPTZ;
  v_now BIGINT;
  v_err JSONB;
  c pfh.history_cuts;
  v_consumers BIGINT := 0;
  v_conversions BIGINT := 0;
  v_cuts BIGINT := 0;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_volume IS NULL OR length(p_volume) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'retirement cleanup requires tenant and volume ids (<=256 chars)'
      USING ERRCODE='PF008';
  END IF;
  SELECT v.retired_at INTO v_retired_at
    FROM public.volumes v WHERE v.id=p_volume AND v.tenant_id=p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'volume % not found', p_volume USING ERRCODE='PF007';
  END IF;
  IF v_retired_at IS NULL THEN
    -- The 021 receipt is the PRECONDITION of this cleanup, never its effect:
    -- refusing a live volume keeps the flip's atomic-conditional-UPDATE race
    -- the single source of retirement truth.
    RAISE EXCEPTION 'volume % is not retired; cleanup requires the retirement receipt',
      p_volume USING ERRCODE='PF011';
  END IF;
  v_now := pfh.now_ms();
  v_err := jsonb_build_object(
    'kind', 'volume_retired',
    'message', 'volume ' || p_volume || ' was retired; its pending history work was canceled');

  -- 1. Release the volume's conversion/adoption consumer pins — the rows
  -- whose unreleased presence makes cut_cancel refuse with PF002. Consumers
  -- of BOTH kinds only ever pin cuts of their own volume, so membership
  -- resolves through the pinned cut. Other consumer kinds are untouched.
  WITH released AS (
    UPDATE pfh.cut_consumers cc SET released_db_ms=v_now
    WHERE cc.released_db_ms IS NULL
      AND cc.tenant_id=p_tenant
      AND cc.consumer_kind IN ('conversion','adoption')
      AND EXISTS (
        SELECT 1 FROM pfh.history_cuts hc
        WHERE hc.id=cc.cut_id AND hc.tenant_id=p_tenant AND hc.volume_id=p_volume)
    RETURNING cc.id)
  SELECT COUNT(*) INTO v_consumers FROM released;

  -- 2. Void non-terminal conversions (the states conversion_abort admits).
  -- 'finalizing' is transaction-transient (conversion_finalize settles it to
  -- converted or rolls back in the same transaction), so it is unobservable
  -- here at rest; an in-flight finalize holds the row lock and this UPDATE
  -- re-evaluates after it settles.
  WITH voided AS (
    UPDATE pfh.conversions v SET
      state='failed', last_error=v_err, updated_db_ms=v_now
    WHERE v.tenant_id=p_tenant AND v.volume_id=p_volume
      AND v.state IN ('migrating','final_cut')
    RETURNING v.id)
  SELECT COUNT(*) INTO v_conversions FROM voided;

  -- 3. Cancel non-terminal cuts. Lock order matches cut_cancel/cut_fail:
  -- cut row first, then its permanent operation row. The typed last_error
  -- distinguishes retirement from a genuine materialization failure, and
  -- 'canceled' is unclaimable (cut_claim) and fenced (require_live_claim).
  FOR c IN
    SELECT * FROM pfh.history_cuts
    WHERE tenant_id=p_tenant AND volume_id=p_volume
      AND state IN ('pending','materializing')
    ORDER BY id
    FOR UPDATE
  LOOP
    UPDATE pfh.history_cuts SET
      state='canceled', lease_expires_db_ms=NULL, last_error=v_err,
      updated_db_ms=v_now
    WHERE id=c.id;
    -- Settle the cut's pending-until-usable create operation 'canceled'
    -- exactly like cut_cancel. A cut this function can cancel normally has a
    -- pending operation (cuts settle at ready/fail/cancel); the guard keeps
    -- a manually settled operation from aborting the whole cleanup.
    IF EXISTS (
      SELECT 1 FROM pfh.resource_operations o
      WHERE o.tenant_id=c.op_tenant_id AND o.domain=c.op_domain
        AND o.operation_id=c.op_operation_id AND o.state='pending') THEN
      PERFORM pfh.resource_operation_finish(
        c.op_tenant_id, c.op_domain, c.op_operation_id, 'canceled',
        jsonb_build_object('cutId', c.id, 'state', 'canceled', 'error', v_err));
    END IF;
    v_cuts := v_cuts + 1;
  END LOOP;

  RETURN jsonb_build_object(
    'volumeId', p_volume,
    'consumersReleased', v_consumers::INT,
    'conversionsVoided', v_conversions::INT,
    'cutsCanceled', v_cuts::INT);
END;
$$;
REVOKE ALL ON FUNCTION pfh.volume_retire_cleanup(TEXT,TEXT) FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION B: grants + postconditions ═══════════════════════════════════════

-- Metadata/caller surface (the volume-api repository's admin DSN role), the
-- exact 013/017 grant pattern.
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfh.volume_retire_cleanup(TEXT,TEXT)
    TO %I', CURRENT_USER);
END
$$;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  -- The cleanup exists, owned by the history owner, SECURITY DEFINER with a
  -- pinned search_path, and VOLATILE (it mutates cut/consumer/conversion
  -- rows and settles operations).
  SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner) AS owner,
         p.prosecdef, p.provolatile,
         COALESCE(array_to_string(p.proconfig,';'),'') AS config
    INTO v_rec
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh' AND p.proname='volume_retire_cleanup';
  IF NOT FOUND THEN
    RAISE EXCEPTION '022 postcondition: pfh.volume_retire_cleanup is missing';
  END IF;
  IF v_rec.owner <> 'portablefs_history_owner' THEN
    RAISE EXCEPTION '022 postcondition: pfh.volume_retire_cleanup is owned by %', v_rec.owner;
  END IF;
  IF NOT v_rec.prosecdef THEN
    RAISE EXCEPTION '022 postcondition: pfh.volume_retire_cleanup must be SECURITY DEFINER';
  END IF;
  IF v_rec.config NOT LIKE '%search_path%' THEN
    RAISE EXCEPTION '022 postcondition: pfh.volume_retire_cleanup has no pinned search_path';
  END IF;
  IF v_rec.provolatile <> 'v' THEN
    RAISE EXCEPTION '022 postcondition: pfh.volume_retire_cleanup must be VOLATILE';
  END IF;
  -- No PUBLIC execute (aclexplode over DIRECT ACL entries; the owner-level
  -- default-privileges revoke from 013 makes proacl non-NULL).
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    LEFT JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='volume_retire_cleanup'
      AND (p.proacl IS NULL OR (acl.grantee = 0 AND acl.privilege_type='EXECUTE'));
  IF v_count > 0 THEN
    RAISE EXCEPTION '022 postcondition: pfh.volume_retire_cleanup is PUBLIC-executable';
  END IF;
  -- The restricted roles gained NOTHING here.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh' AND p.proname='volume_retire_cleanup'
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_worker'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '022 postcondition: a restricted role can execute the retirement cleanup';
  END IF;
  -- Lineage: 023 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '023%') THEN
    RAISE EXCEPTION '022 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
