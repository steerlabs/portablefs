-- 036_history_worker_beat_convoy: the liveness beat stops queueing behind
-- the work.
--
-- INCIDENT THIS EXISTS FOR. During the append flood that killed every mount,
-- the lock sampler caught pfh.worker_beat, pfh.cut_claim, pfh.repair_claim and
-- pfh.sweep_claim blocked on each other for 1 to 4.5 SECONDS at a time — with
-- pfh.require_txn_settings pinning lock_timeout to 5s, that is one bad cycle
-- away from typed failures across the whole history plane. It reads like four
-- workers fighting over the same work item. It is not: every work-item claim
-- in this schema already distributes correctly (pfh.cut_claim and
-- pfh.sweep_claim take FOR UPDATE SKIP LOCKED on their targets, and
-- pfh.repair_claim uses a conditional lease upsert). The contention is
-- entirely on pfh.worker_heartbeats.
--
-- THE EXACT MECHANISM, reproduced against postgres:18 and confirmed in
-- production. The deployed history worker runs as ONE worker_id
-- ('railway-history-1') with FOUR heartbeat rows — gc, materializer, repair,
-- scrub. Every claim function opens by upserting ITS kind's row, so it holds
-- that row from its first statement until COMMIT, across the whole scan and
-- every advisory lock it takes afterwards (pfh.repair_claim was sampled live
-- in production with an 0.8s open transaction). pfh.worker_beat writes ALL
-- FOUR rows in one transaction. So the beat queues behind whichever claim is
-- running, while already holding the rows the OTHER claims need — and the
-- other claims queue behind the beat. Three functions, three different rows,
-- one serialized chain:
--
--     pfh.cut_claim  --blocked by-->  pfh.worker_beat  --blocked by-->  pfh.repair_claim
--
-- (pg_blocking_pids, measured; the beat took 913 ms and the cut claim 708 ms
-- against a single deliberately-slow repair claim.)
--
-- THE FIX. A heartbeat is a liveness assertion, not a mutual-exclusion
-- primitive: it must never wait. pfh.worker_touch writes the row only if it
-- can take it without queueing, via FOR UPDATE SKIP LOCKED, and reports
-- whether it did. Skipping loses nothing, and the reason is exact: the
-- heartbeat key is (worker_kind, worker_id), so the ONLY transaction that can
-- be holding that row is another in-flight transaction OF THE SAME WORKER FOR
-- THE SAME KIND — which is itself writing a fresh beat for it, and whose very
-- existence is the liveness this row exists to record. The write is also made
-- monotonic (GREATEST), so a skipped tick followed by a later one can never
-- move a beat backwards.
--
-- WHAT DOES NOT CHANGE. Every function body below is the DEPLOYED definition,
-- read back with pg_get_functiondef and patched at exactly one statement — the
-- heartbeat upsert — with an assertion that the pattern matched exactly once
-- and that no blocking upsert survived. No claim policy, no fencing, no
-- epoch, no lease TTL, and no work-item lock mode is touched. The work-item
-- locks were already right; only the liveness path was wrong.
--
-- NOT A DIFFERENT SCHEMA'S FIX. The parallel journal-plane change (034)
-- downgrades bulk validation reads to FOR KEY SHARE so they stop conflicting
-- with heartbeat UPDATEs. That shape does not apply here: nothing in pfh takes
-- a share lock on the heartbeat rows — they are written, not read for proof —
-- so the answer is not a weaker lock mode but not waiting at all.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='035_recovery_cut_lifecycle'
  ) THEN
    RAISE EXCEPTION '036 preflight: the 035 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '037%') THEN
    RAISE EXCEPTION '036 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfh.worker_heartbeats') IS NULL THEN
    RAISE EXCEPTION '036 preflight: the 013 worker heartbeat table is missing';
  END IF;
  IF to_regprocedure('pfh.worker_touch(text,text,bigint,jsonb)') IS NOT NULL THEN
    RAISE EXCEPTION '036 preflight: pfh.worker_touch already exists';
  END IF;
  -- Every body replaced below must exist exactly as 013 left it.
  IF to_regprocedure('pfh.cut_claim(text,integer,bigint)') IS NULL
     OR to_regprocedure('pfh.cut_heartbeat(text,bigint,text,bigint,jsonb)') IS NULL
     OR to_regprocedure('pfh.worker_beat(text,text[],jsonb)') IS NULL
     OR to_regprocedure('pfh.scrub_claim(text,integer)') IS NULL
     OR to_regprocedure('pfh.repair_claim(text,integer,bigint)') IS NULL
     OR to_regprocedure('pfh.sweep_claim(text,bigint,bigint)') IS NULL THEN
    RAISE EXCEPTION '036 preflight: a 013 worker function is missing';
  END IF;
END;
$preflight$;

SET LOCAL ROLE portablefs_history_owner;

-- ═══ SECTION A: the beat that cannot queue ══════════════════════════════════

-- Record a worker's liveness for one kind WITHOUT ever waiting on a lock.
--
-- Returns TRUE when the beat was written, FALSE when the row was already
-- locked and the write was skipped. FALSE is not a failure: see the header —
-- the holder is the same (kind, worker) and is beating for us. Callers that
-- care surface the count rather than retrying, because retrying would
-- reintroduce exactly the wait this removes.
--
-- THE INSERT ARM IS FOR A WORKER'S FIRST-EVER BEAT ONLY, and it is guarded by
-- an MVCC existence read rather than left to ON CONFLICT. This is not
-- defensive coding, it is the difference between fixing the bug and moving
-- it: ON CONFLICT arbitration against a row that a concurrent transaction has
-- UPDATED waits on that transaction's xid, so falling straight through from a
-- skipped SELECT into an INSERT would reintroduce the exact wait — measured,
-- it blocked for the full 5s lock_timeout. A plain EXISTS read never waits, so
-- "locked" and "absent" are told apart without one.
--
-- The only remaining wait is two transactions racing to create the SAME
-- worker's FIRST row, where the loser waits on a speculative insert. That
-- happens once per worker kind per deployment lifetime, at worker birth, with
-- nothing else in flight.
CREATE FUNCTION pfh.worker_touch(
  p_kind TEXT, p_worker_id TEXT, p_now BIGINT, p_facts JSONB
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_ctid TID;
BEGIN
  SELECT h.ctid INTO v_ctid
    FROM pfh.worker_heartbeats h
   WHERE h.worker_kind = p_kind AND h.worker_id = p_worker_id
   FOR UPDATE SKIP LOCKED;
  IF FOUND THEN
    -- GREATEST, not assignment: a beat that was skipped and lands later must
    -- never move a worker's liveness backwards.
    UPDATE pfh.worker_heartbeats
       SET last_beat_db_ms = GREATEST(last_beat_db_ms, p_now),
           facts = COALESCE(p_facts, facts)
     WHERE worker_kind = p_kind AND worker_id = p_worker_id;
    RETURN TRUE;
  END IF;
  IF EXISTS (SELECT 1 FROM pfh.worker_heartbeats h
              WHERE h.worker_kind = p_kind AND h.worker_id = p_worker_id) THEN
    -- Present but locked: the holder is this same (kind, worker) writing its
    -- own fresh beat, and its existence IS the liveness this row records.
    RETURN FALSE;
  END IF;
  INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
  VALUES (p_kind, p_worker_id, p_now, COALESCE(p_facts, '{}'::jsonb))
  ON CONFLICT (worker_kind, worker_id) DO NOTHING;
  RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION pfh.worker_touch(TEXT,TEXT,BIGINT,JSONB) FROM PUBLIC;

-- ═══ SECTION B: the deployed bodies, patched at one statement each ══════════

-- The materializer work claim. Its work-item distribution (FOR UPDATE
-- SKIP LOCKED over pfh.history_cuts) is unchanged and was never the problem.
CREATE OR REPLACE FUNCTION pfh.cut_claim(p_worker_id text, p_limit integer, p_lease_ttl_ms bigint)
 RETURNS SETOF jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,1),1),16);
  v_ttl BIGINT := LEAST(GREATEST(COALESCE(p_lease_ttl_ms,60000),5000),300000);
  v_now BIGINT;
  c pfh.history_cuts;
  v_dead JSONB;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_worker_id IS NULL OR length(p_worker_id) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'worker id is required (<=128 chars)' USING ERRCODE='PF008';
  END IF;
  v_now := pfh.now_ms();
  PERFORM pfh.worker_touch('materializer', p_worker_id, v_now, NULL);
  FOR c IN
    SELECT * FROM pfh.history_cuts
    WHERE state IN ('pending','materializing')
      AND next_attempt_db_ms <= v_now
      AND (state='pending' OR lease_expires_db_ms IS NULL OR lease_expires_db_ms < v_now)
    ORDER BY next_attempt_db_ms, created_db_ms
    LIMIT v_limit
    FOR UPDATE SKIP LOCKED
  LOOP
    IF c.attempt_count >= 16 THEN
      -- Dead-letter: permanent typed failure + atomic operation settlement.
      v_dead := jsonb_build_object(
        'kind','dead_letter',
        'message','cut exhausted its attempt budget',
        'attempts', c.attempt_count,
        'lastError', c.last_error);
      UPDATE pfh.history_cuts SET
        state='failed', lease_expires_db_ms=NULL, last_error=v_dead,
        updated_db_ms=v_now
      WHERE id=c.id;
      PERFORM pfh.resource_operation_finish(
        c.op_tenant_id, c.op_domain, c.op_operation_id, 'failed',
        jsonb_build_object('cutId', c.id, 'state', 'failed', 'error', v_dead));
      CONTINUE;
    END IF;
    UPDATE pfh.history_cuts SET
      state='materializing',
      claim_worker_id=p_worker_id,
      claim_epoch=claim_epoch+1,
      lease_expires_db_ms=v_now+v_ttl,
      attempt_count=attempt_count+1,
      updated_db_ms=v_now
    WHERE id=c.id;
    RETURN NEXT pfh.cut_status(c.tenant_id, c.id)
      || jsonb_build_object('claimEpoch',(c.claim_epoch+1)::TEXT,
                            'leaseExpiresDbMs',(v_now+v_ttl)::TEXT,
                            'dbTimeMs', v_now::TEXT);
  END LOOP;
END;
$function$
;


-- The in-flight lease renewal. It writes the materializer row DURING a
-- materialization, so before this it could hold that row against the next
-- cut_claim of the same worker as well.
CREATE OR REPLACE FUNCTION pfh.cut_heartbeat(p_cut_id text, p_claim_epoch bigint, p_worker_id text, p_lease_ttl_ms bigint, p_progress jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
  v_ttl BIGINT := LEAST(GREATEST(COALESCE(p_lease_ttl_ms,60000),5000),300000);
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, TRUE);
  IF p_progress IS NOT NULL AND pg_column_size(p_progress) > 16384 THEN
    RAISE EXCEPTION 'cut progress exceeds 16 KiB' USING ERRCODE='PF004';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.history_cuts SET
    lease_expires_db_ms=v_now+v_ttl,
    progress=COALESCE(p_progress, progress),
    updated_db_ms=v_now
  WHERE id=p_cut_id;
  PERFORM pfh.worker_touch('materializer', p_worker_id, v_now,
            jsonb_build_object('cut', p_cut_id, 'claimEpoch', p_claim_epoch::TEXT));
  RETURN jsonb_build_object(
    'cutId', p_cut_id, 'leaseExpiresDbMs', (v_now+v_ttl)::TEXT, 'dbTimeMs', v_now::TEXT);
END;
$function$
;


-- The liveness path itself, and the hub of the measured convoy: it is the
-- only caller that writes every kind's row in one transaction. It now
-- reports how many kinds it skipped instead of waiting for them.
CREATE OR REPLACE FUNCTION pfh.worker_beat(p_worker_id text, p_kinds text[], p_facts jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_kind TEXT;
  v_skipped INT := 0;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_worker_id IS NULL OR length(p_worker_id) NOT BETWEEN 1 AND 128
     OR p_kinds IS NULL OR array_length(p_kinds,1) IS NULL THEN
    RAISE EXCEPTION 'worker id and kinds are required' USING ERRCODE='PF008';
  END IF;
  IF p_facts IS NOT NULL AND pg_column_size(p_facts) > 8192 THEN
    RAISE EXCEPTION 'worker facts exceed 8 KiB' USING ERRCODE='PF004';
  END IF;
  FOREACH v_kind IN ARRAY p_kinds LOOP
    IF v_kind NOT IN ('materializer','scrub','repair','gc') THEN
      RAISE EXCEPTION 'worker kind % is unknown', v_kind USING ERRCODE='PF008';
    END IF;
    IF NOT pfh.worker_touch(v_kind, p_worker_id, v_now, COALESCE(p_facts,'{}'::jsonb)) THEN
      v_skipped := v_skipped + 1;
    END IF;
  END LOOP;
  RETURN jsonb_build_object('dbTimeMs', v_now::TEXT,
                            'skippedKinds', v_skipped);
END;
$function$
;


-- Copy verification claims.
CREATE OR REPLACE FUNCTION pfh.scrub_claim(p_worker_id text, p_limit integer)
 RETURNS TABLE(tenant_id text, kind text, digest text, incarnation bigint, failure_domain text, storage_key text, size bigint, last_verified_db_ms bigint, claim_epoch bigint, claim_expires_db_ms bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,64),1),512);
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_worker_id IS NULL OR length(p_worker_id) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'worker id is required' USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.worker_touch('scrub', p_worker_id, v_now, NULL);
  RETURN QUERY
    WITH due AS (
      SELECT oc.tenant_id, oc.kind, oc.digest, oc.incarnation, oc.failure_domain
      FROM pfh.object_copies oc
      JOIN pfh.objects o
        ON o.tenant_id=oc.tenant_id AND o.kind=oc.kind AND o.digest=oc.digest
       AND o.incarnation=oc.incarnation
      WHERE oc.state='present' AND oc.next_verify_db_ms <= v_now
        AND (oc.verify_claim_expires_db_ms IS NULL OR oc.verify_claim_expires_db_ms <= v_now)
        AND o.state IN ('live','quarantined','intended')
      ORDER BY oc.last_verified_db_ms
      LIMIT v_limit
      FOR UPDATE OF oc SKIP LOCKED)
    UPDATE pfh.object_copies u SET
      next_verify_db_ms=v_now+900000,
      verify_claim_worker_id=p_worker_id,
      verify_claim_epoch=verify_claim_epoch+1,
      verify_claim_expires_db_ms=v_now+900000
    FROM due
    WHERE u.tenant_id=due.tenant_id AND u.kind=due.kind AND u.digest=due.digest
      AND u.incarnation=due.incarnation AND u.failure_domain=due.failure_domain
    RETURNING u.tenant_id, u.kind, u.digest, u.incarnation, u.failure_domain,
              u.storage_key, u.size, u.last_verified_db_ms,
              u.verify_claim_epoch, u.verify_claim_expires_db_ms;
END;
$function$
;


-- The expensive one: it scans pfh.objects against every required failure
-- domain before it claims anything, and held the 'repair' row throughout.
CREATE OR REPLACE FUNCTION pfh.repair_claim(p_worker_id text, p_limit integer, p_lease_ttl_ms bigint)
 RETURNS SETOF jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,16),1),128);
  v_ttl BIGINT := LEAST(GREATEST(COALESCE(p_lease_ttl_ms,900000),15000),3600000);
  v_now BIGINT := pfh.now_ms();
  v_policy pfh.history_policies;
  r RECORD;
  v_sources JSONB;
  v_claim_epoch BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_worker_id IS NULL OR length(p_worker_id) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'worker id is required' USING ERRCODE='PF008';
  END IF;
  v_policy := pfh.require_history_policy();
  PERFORM pfh.worker_touch('repair', p_worker_id, v_now, NULL);
  FOR r IN
    SELECT o.tenant_id, o.kind, o.digest, o.incarnation, o.size, d.v AS missing_domain
    FROM pfh.objects o
    CROSS JOIN jsonb_array_elements_text(v_policy.policy->'requiredFailureDomains') d(v)
    WHERE o.state IN ('live','quarantined','intended')
      AND NOT EXISTS (
        SELECT 1 FROM pfh.object_copies oc
        WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
          AND oc.incarnation=o.incarnation AND oc.failure_domain=d.v
          AND oc.state='present' AND oc.verify_attempts=0)
      AND EXISTS (
        SELECT 1 FROM pfh.object_copies src
        WHERE src.tenant_id=o.tenant_id AND src.kind=o.kind AND src.digest=o.digest
          AND src.incarnation=o.incarnation AND src.failure_domain<>d.v
          AND src.state='present' AND src.verify_attempts=0)
      AND NOT EXISTS (
        SELECT 1 FROM pfh.repair_leases rl
        WHERE rl.tenant_id=o.tenant_id AND rl.kind=o.kind AND rl.digest=o.digest
          AND rl.incarnation=o.incarnation AND rl.failure_domain=d.v
          AND rl.expires_db_ms > v_now)
    ORDER BY o.updated_db_ms
    LIMIT v_limit
  LOOP
    PERFORM pfh.scope_locks(ARRAY['pfh-object:'||r.tenant_id||E'\x01'||r.kind||E'\x01'||r.digest]);
    INSERT INTO pfh.repair_leases (
      tenant_id, kind, digest, incarnation, failure_domain,
      worker_id, claim_epoch, expires_db_ms)
    VALUES (r.tenant_id, r.kind, r.digest, r.incarnation, r.missing_domain,
            p_worker_id, 1, v_now+v_ttl)
    ON CONFLICT (tenant_id, kind, digest, incarnation, failure_domain) DO UPDATE
      SET worker_id=EXCLUDED.worker_id,
          claim_epoch=pfh.repair_leases.claim_epoch+1,
          expires_db_ms=EXCLUDED.expires_db_ms
      WHERE pfh.repair_leases.expires_db_ms <= v_now
    RETURNING claim_epoch INTO v_claim_epoch;
    IF NOT FOUND THEN
      CONTINUE; -- another repairer holds a live lease
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'failureDomain', src.failure_domain,
        'storageKey', src.storage_key,
        'size', src.size::TEXT)), '[]'::jsonb)
      INTO v_sources
      FROM pfh.object_copies src
      WHERE src.tenant_id=r.tenant_id AND src.kind=r.kind AND src.digest=r.digest
        AND src.incarnation=r.incarnation AND src.failure_domain<>r.missing_domain
        AND src.state='present' AND src.verify_attempts=0;
    RETURN NEXT jsonb_build_object(
      'tenantId', r.tenant_id, 'kind', r.kind, 'digest', r.digest,
      'incarnation', r.incarnation::TEXT, 'size', r.size::TEXT,
      'missingDomain', r.missing_domain, 'sources', v_sources,
      'claimEpoch', v_claim_epoch::TEXT,
      'leaseExpiresDbMs', (v_now+v_ttl)::TEXT);
  END LOOP;
END;
$function$
;


-- The GC sweep claim.
CREATE OR REPLACE FUNCTION pfh.sweep_claim(p_worker_id text, p_min_age_ms bigint, p_lease_ttl_ms bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  o pfh.objects;
  v_now BIGINT := pfh.now_ms();
  v_age BIGINT := LEAST(GREATEST(COALESCE(p_min_age_ms,3600000),60000),2592000000);
  v_ttl BIGINT := LEAST(GREATEST(COALESCE(p_lease_ttl_ms,300000),15000),3600000);
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_worker_id IS NULL OR length(p_worker_id) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'worker id is required' USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.worker_touch('gc', p_worker_id, v_now, NULL);
  SELECT * INTO o FROM pfh.objects
    WHERE (state IN ('live','intended','reclaiming') AND updated_db_ms < v_now - v_age)
       OR (state = 'deleting' AND sweep_claim_expires_db_ms IS NOT NULL
           AND sweep_claim_expires_db_ms < v_now)
    ORDER BY (state = 'deleting') DESC, updated_db_ms
    LIMIT 1
    FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  -- Re-check under the row lock (reclaimed 'deleting' rows are already
  -- committed non-roots, but a resurrection may have raced).
  IF o.state <> 'deleting' AND pfh.object_is_root(o.tenant_id, o.kind, o.digest) THEN
    RETURN NULL;
  END IF;
  UPDATE pfh.objects SET
    state='deleting',
    reclaim_generation=reclaim_generation + CASE WHEN o.state='deleting' THEN 0 ELSE 1 END,
    sweep_worker_id=p_worker_id,
    sweep_claim_epoch=sweep_claim_epoch+1,
    sweep_claim_expires_db_ms=v_now+v_ttl,
    updated_db_ms=v_now
  WHERE tenant_id=o.tenant_id AND kind=o.kind AND digest=o.digest
  RETURNING * INTO o;
  UPDATE pfh.object_copies SET state='deleting'
  WHERE tenant_id=o.tenant_id AND kind=o.kind AND digest=o.digest
    AND incarnation=o.incarnation AND state='present';
  RETURN jsonb_build_object(
    'tenantId', o.tenant_id, 'kind', o.kind, 'digest', o.digest,
    'size', o.size::TEXT,
    'incarnation', o.incarnation::TEXT,
    'reclaimGeneration', o.reclaim_generation::TEXT,
    'claimEpoch', o.sweep_claim_epoch::TEXT,
    'leaseExpiresDbMs', o.sweep_claim_expires_db_ms::TEXT,
    'copies', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'failureDomain', oc.failure_domain, 'storageKey', oc.storage_key))
      FROM pfh.object_copies oc
      WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
        AND oc.incarnation=o.incarnation AND oc.state='deleting'), '[]'::jsonb));
END;
$function$
;

RESET ROLE;

-- ═══ SECTION C: postconditions ══════════════════════════════════════════════

DO $post$
DECLARE
  v_rec RECORD;
  v_def TEXT;
BEGIN
  SELECT p.oid AS fnoid, p.prosecdef, p.proconfig AS config,
         pg_get_userbyid(p.proowner) AS owner
    INTO v_rec
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname='pfh' AND p.proname='worker_touch';
  IF NOT FOUND THEN
    RAISE EXCEPTION '036 postcondition: pfh.worker_touch is missing';
  END IF;
  IF v_rec.owner <> 'portablefs_history_owner' THEN
    RAISE EXCEPTION '036 postcondition: pfh.worker_touch is not owned by the history owner';
  END IF;
  IF NOT v_rec.prosecdef THEN
    RAISE EXCEPTION '036 postcondition: pfh.worker_touch must be SECURITY DEFINER';
  END IF;
  IF array_to_string(v_rec.config, ',') NOT LIKE '%search_path%' THEN
    RAISE EXCEPTION '036 postcondition: pfh.worker_touch has no pinned search_path';
  END IF;
  IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
    RAISE EXCEPTION '036 postcondition: PUBLIC can execute pfh.worker_touch';
  END IF;
  IF position('SKIP LOCKED' IN pg_get_functiondef(v_rec.fnoid)) = 0 THEN
    RAISE EXCEPTION '036 postcondition: pfh.worker_touch can still queue on a locked row';
  END IF;

  -- THE INVARIANT THIS MIGRATION EXISTS FOR: after it, no function in pfh may
  -- write pfh.worker_heartbeats in a way that waits. A regression that
  -- reintroduces the upsert rebuilds the convoy exactly.
  FOR v_rec IN
    SELECT p.proname, p.oid AS fnoid
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname='pfh' AND p.prokind='f' AND p.proname <> 'worker_touch'
  LOOP
    v_def := pg_get_functiondef(v_rec.fnoid);
    IF position('INSERT INTO pfh.worker_heartbeats' IN v_def) > 0 THEN
      RAISE EXCEPTION
        '036 postcondition: pfh.% still writes worker_heartbeats directly; the beat can queue behind it',
        v_rec.proname;
    END IF;
  END LOOP;

  -- The work-item distribution the claims already had is UNCHANGED. If a
  -- rewrite ever dropped it, claims really would fight over work items, which
  -- is a different bug with a different fix.
  IF position('FOR UPDATE SKIP LOCKED' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_claim(text,integer,bigint)'))) = 0 THEN
    RAISE EXCEPTION '036 postcondition: cut_claim lost its SKIP LOCKED work distribution';
  END IF;
  IF position('FOR UPDATE SKIP LOCKED' IN pg_get_functiondef(
       to_regprocedure('pfh.sweep_claim(text,bigint,bigint)'))) = 0 THEN
    RAISE EXCEPTION '036 postcondition: sweep_claim lost its SKIP LOCKED work distribution';
  END IF;
  IF position('attempt_count >= 16' IN pg_get_functiondef(
       to_regprocedure('pfh.cut_claim(text,integer,bigint)'))) = 0 THEN
    RAISE EXCEPTION '036 postcondition: cut_claim lost its dead-letter budget';
  END IF;
END;
$post$;
