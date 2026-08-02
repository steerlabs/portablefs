-- 034_liveness_lock_isolation: liveness must not queue behind bulk data.
--
-- INCIDENT THIS EXISTS FOR (round 18b, reproduced live at fe994c0). A single
-- single-threaded 8 MiB-write flood into one mounted branch killed the mount
-- in ~231 s, every time. The client latched state=degraded credential=rejected
-- and appliedRateBps 0 forever. The proximate cause is the journal child
-- self-fencing:
--
--   16:43:01 lease renew failed (retrying; self-fence watchdog armed for 20s):
--            POST /v1/leases/lse_.../renew: http 500 VOLUME_INTERNAL
--   16:43:06 lease not renewed within 20s: fencing data plane and stepping down
--   16:43:06 writer lease lost (superseded, expired, or unrenewable)
--
-- and, in the same seconds, the manager:
--
--   epoch 39: claim renewal failed (1 consecutive):
--             canceling statement due to lock timeout
--
-- pg_stat_activity sampled at 1 Hz THROUGH that window named the blocker
-- exactly (blocked pid | wait | ms waited | blocking pid | query):
--
--   1841 | Lock/transactionid | 1286 | 1674 | SELECT * FROM leases WHERE id = $1 FOR UPDATE
--   1529 | Lock/transactionid | 1908 | 1674 | SELECT pfm.manager_renew($1,$2,$3,$4) AS r
--   1674 | LWLock/WALWrite    |  433 |    - | SELECT pfj.journal_append_v3(...)
--
-- ONE bulk append transaction (pid 1674, application_name
-- vcs-portablefs-cloud-3), sitting in its WAL fsync, was simultaneously
-- blocking BOTH liveness paths of the whole system. Waits climbed past the
-- 5 s lock_timeout, volume-api answered the renew 500, the child's 20 s
-- watchdog fired, the authority stepped down, and every access lease pointing
-- at it died -> ACCESS_LEASE_NOT_FOUND -> credential=rejected on the client.
--
-- WHY. pfj.journal_append_v3 validates its writer inside the SAME transaction
-- that writes up to 128 records / 16 MiB of payload under synchronous_commit=on:
--
--   pfj.require_writer          (009:621/626/629) FOR SHARE on public.branches,
--                                                 public.attach_sessions,
--                                                 public.leases
--   pfj.require_manager_binding (011:46)          FOR SHARE on public.branches
--   pfm.verify_authority_binding(010:1174)        FOR SHARE on the SINGLETON
--                                                 pfm.manager_claims row
--
-- Those share locks are taken BEFORE the payload writes and released only at
-- COMMIT. The two pure-liveness writers need conflicting modes on the very
-- same rows: volume-api's renewLease took `SELECT ... FOR UPDATE` on
-- public.leases, and pfm.manager_renew took `SELECT ... FOR UPDATE` on
-- pfm.manager_claims. So a heartbeat's lock queue IS the bulk write's commit
-- queue. Worse, pfm.manager_claims is a single fleet-global row: every append
-- of every authority, every access-lease call, and every child lease-facts
-- probe contend on it.
--
-- This is the FIFTH time this deployment has starved liveness behind bulk
-- work (Go pgx pool -> reserved liveness pool; Node claim heartbeat ->
-- dedicated worker thread + reserved connection; client session lease;
-- credential push). The previous four fixes isolated a POOL or an EVENT LOOP.
-- Neither helps here: the manager's heartbeat already owns a dedicated
-- worker thread and a dedicated pg Client, and it still lost -- because the
-- shared resource this time is a ROW LOCK QUEUE.
--
-- THE FIX, AND WHY IT DOES NOT WEAKEN FENCING. PostgreSQL's row-lock conflict
-- matrix has exactly one pair that does not conflict across the read/write
-- boundary:
--
--                    KEY SHARE  SHARE  NO KEY UPDATE  UPDATE
--   FOR KEY SHARE        -        -          -           X
--   FOR SHARE            -        -          X           X
--   FOR NO KEY UPDATE    -        X          X           X
--   FOR UPDATE           X        X          X           X
--
-- A plain UPDATE of a non-key column takes FOR NO KEY UPDATE. So:
--
--   * the bulk append path downgrades its VALIDATION lock on the two rows a
--     heartbeat writes -- and ONLY those two -- from FOR SHARE to FOR KEY
--     SHARE. It still pins the row against DELETE, against a key change, and
--     against any FOR UPDATE -- i.e. against every genuine fence transition
--     (lease release, session detach, successor claim, manager takeover,
--     manager release), all of which take FOR UPDATE. It also keeps the EPQ
--     "latest committed row version" semantics FOR SHARE gave, so validation
--     still reads through a concurrent renewal instead of an older snapshot.
--     The ONLY thing it stops conflicting with is a non-key UPDATE.
--     Because a non-key UPDATE is also how a lease RELEASE was written
--     (`UPDATE leases SET released_at = ...` in detach), the release now
--     takes FOR UPDATE on the lease rows first, in the same transaction, so
--     that a fence transition still says so with its lock instead of relying
--     on a lock it shares with a heartbeat. That is the paired TypeScript
--     change in packages/metadata-db/src/postgres.ts.
--   * the two pure-liveness writers stop taking FOR UPDATE. pfm.manager_renew
--     becomes ONE conditional UPDATE whose WHERE clause carries the identity
--     and live-at-database-time predicates the FOR UPDATE read used to check
--     (below); volume-api's renewLease becomes the same shape in TypeScript.
--     A renewal is a forward-only extension of expires_at -- it is not a
--     fence transition and never was -- so it has no business serializing
--     against data.
--
-- Net: liveness (FOR NO KEY UPDATE) and bulk validation (FOR KEY SHARE) are
-- provably non-conflicting, while fencing (FOR UPDATE) still conflicts with
-- both. The safety direction is untouched: a lease that genuinely cannot be
-- renewed still fails its predicates, still is not extended, and the child
-- still fences.
--
-- WHAT THIS MIGRATION DOES NOT CHANGE: the claim/takeover paths
-- (pfj.journal_claim_core, pfj.journal_claim, pfm.manager_claim,
-- pfm.manager_release) keep their FOR SHARE / FOR UPDATE modes. They are
-- fence transitions, they are rare, and serializing them against an in-flight
-- append is the correct behaviour.
--
-- ERROR SQLSTATES: unchanged (PF001 state refusal, PF008 invalid argument).

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='033_retirement_transition'
  ) THEN
    RAISE EXCEPTION '034 preflight: the 033 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '035%') THEN
    RAISE EXCEPTION '034 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfj.require_writer(pfj.journal_generations,bigint,text,text,bigint,text,text)') IS NULL
     OR to_regprocedure('pfj.require_manager_binding(pfj.journal_generations,bigint,bigint,text,text)') IS NULL
     OR to_regprocedure('pfm.require_manager(bigint,text,text)') IS NULL
     OR to_regprocedure('pfm.verify_authority_binding(text,text,text,bigint,bigint,text,text)') IS NULL
     OR to_regprocedure('pfm.manager_renew(bigint,text,text,bigint)') IS NULL THEN
    RAISE EXCEPTION '034 preflight: the 009/010/011 validation surface is incomplete';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: the pfj hot-path validation locks ═══════════════════════════
--
-- Rewritten the way 023 rewrote the checked lineage: pg_get_functiondef keeps
-- the complete, security-reviewed bodies byte-identical apart from the exact
-- asserted substring, so lineage drift ABORTS rather than installing a
-- partially-downgraded function.

-- SCOPE. ONLY the rows a heartbeat writes are downgraded. public.branches and
-- public.attach_sessions keep their FOR SHARE: nothing on a liveness path
-- writes them, so downgrading them would buy nothing and would silently let a
-- plain `UPDATE branches SET head_commit_id` or `UPDATE attach_sessions SET
-- status='detached'` stop serializing against an in-flight append. The blast
-- radius of this migration is exactly two rows: the writer's public.leases
-- row and the singleton pfm.manager_claims row.

SET LOCAL ROLE portablefs_journal_owner;
DO $pfj_locks$
DECLARE
  v_sigs TEXT[] := ARRAY[
    'pfj.require_writer(pfj.journal_generations,bigint,text,text,bigint,text,text)'
  ];
  v_olds TEXT[] := ARRAY[
    'FROM public.leases l WHERE l.id = g.lease_id FOR SHARE;'
  ];
  v_news TEXT[] := ARRAY[
    'FROM public.leases l WHERE l.id = g.lease_id FOR KEY SHARE;'
  ];
  v_oid REGPROCEDURE;
  v_def TEXT;
  v_next TEXT;
  i INTEGER;
BEGIN
  FOR i IN 1..array_length(v_sigs,1) LOOP
    v_oid := to_regprocedure(v_sigs[i]);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION '034 pfj rewrite: function % is missing', v_sigs[i];
    END IF;
    v_def := pg_get_functiondef(v_oid);
    v_next := replace(v_def, v_olds[i], v_news[i]);
    IF v_next = v_def THEN
      RAISE EXCEPTION '034 pfj rewrite: expected source not found in %', v_sigs[i];
    END IF;
    EXECUTE v_next;
  END LOOP;
END;
$pfj_locks$;
RESET ROLE;

-- ═══ SECTION B: the pfm claim-row validation locks ══════════════════════════
--
-- pfm.require_manager and pfm.verify_authority_binding both read the singleton
-- claim row to prove "the caller is bound to the live manager". Neither
-- writes it. Every append, every access-lease call, and every child
-- lease-facts probe goes through one of them, so this is the fleet-global
-- contention point on pfm.manager_claims.

SET LOCAL ROLE portablefs_manager_owner;
DO $pfm_locks$
DECLARE
  v_sigs TEXT[] := ARRAY[
    'pfm.require_manager(bigint,text,text)',
    'pfm.verify_authority_binding(text,text,text,bigint,bigint,text,text)'
  ];
  v_old CONSTANT TEXT :=
    'SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = ''manager'' FOR SHARE;';
  v_new CONSTANT TEXT :=
    'SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = ''manager'' FOR KEY SHARE;';
  v_oid REGPROCEDURE;
  v_def TEXT;
  v_next TEXT;
  i INTEGER;
BEGIN
  FOR i IN 1..array_length(v_sigs,1) LOOP
    v_oid := to_regprocedure(v_sigs[i]);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION '034 pfm rewrite: function % is missing', v_sigs[i];
    END IF;
    v_def := pg_get_functiondef(v_oid);
    v_next := replace(v_def, v_old, v_new);
    IF v_next = v_def THEN
      RAISE EXCEPTION '034 pfm rewrite: expected source not found in %', v_sigs[i];
    END IF;
    EXECUTE v_next;
  END LOOP;
END;
$pfm_locks$;
RESET ROLE;

-- ═══ SECTION C: the manager claim heartbeat, lock-free ══════════════════════
--
-- Replaces the `SELECT ... FOR UPDATE` + validate + `UPDATE` triple with ONE
-- conditional UPDATE. Every precondition the read used to enforce is now a
-- WHERE predicate, so zero matched rows means exactly what the old PF001
-- meant: superseded, expired, or identity mismatch. Under READ COMMITTED the
-- UPDATE re-evaluates its predicates against the LATEST committed row version
-- (EPQ), so a takeover that commits underneath it is seen and refused — the
-- same fail-closed outcome the FOR UPDATE read produced, without the lock.
--
-- THE CLOCK. The old function sampled pfm.now_ms() AFTER acquiring the row
-- lock, so `expires_at <= v_now` could not be evaluated against a stale
-- instant no matter how long the lock wait was. A single statement cannot
-- sample the clock after its own row wait, so the sample is taken immediately
-- before the UPDATE and the staleness is then BOUNDED and CHECKED: if more
-- than pfm.manager_renew_sample_bound_ms() elapsed between the sample and the
-- completed write, the function raises and the whole renewal — including the
-- extension — rolls back. That is the fail-closed direction: a renewal whose
-- liveness evidence went stale does not move the deadline, and the manager's
-- watchdog fences on schedule. With the KEY SHARE downgrade above, the only
-- thing that can make this statement wait at all is a genuine takeover or
-- release, which is exactly when refusing is correct.
--
-- expires_at moves with GREATEST, as before: a renewal is monotone and can
-- never shorten a claim.

SET LOCAL ROLE portablefs_manager_owner;

-- The bound on how stale the pre-write clock sample may be. Deliberately a
-- function, not a GUC or a literal, so the value is one reviewed place and
-- the tests can name it.
CREATE OR REPLACE FUNCTION pfm.manager_renew_sample_bound_ms() RETURNS BIGINT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT 250::BIGINT $$;

CREATE OR REPLACE FUNCTION pfm.manager_renew(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_ttl_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_settled BIGINT;
  c pfm.manager_claims;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_ttl_ms IS NULL OR p_ttl_ms < 1000 OR p_ttl_ms > 3600000 THEN
    RAISE EXCEPTION 'manager claim ttl must be 1s..1h' USING ERRCODE = 'PF008';
  END IF;
  IF p_manager_capability IS NULL
     OR length(p_manager_capability) NOT BETWEEN 32 AND 512 THEN
    RAISE EXCEPTION 'manager capability must be 32..512 characters'
      USING ERRCODE = 'PF008';
  END IF;
  IF p_manager_epoch IS NULL OR p_manager_runtime_id IS NULL THEN
    RAISE EXCEPTION 'manager identity (epoch, runtime id, capability) is required'
      USING ERRCODE = 'PF008';
  END IF;
  PERFORM pfm.require_durable_primary();
  v_now := pfm.now_ms();
  UPDATE pfm.manager_claims SET
    renewed_at = v_now, expires_at = GREATEST(expires_at, v_now + p_ttl_ms)
    WHERE singleton_key = 'manager'
      AND epoch = p_manager_epoch
      AND runtime_id = p_manager_runtime_id
      AND capability_hash
          = encode(sha256(convert_to(p_manager_capability, 'UTF8')), 'hex')
      AND expires_at > v_now
    RETURNING * INTO c;
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'manager renew rejected: claim superseded, expired, or identity mismatch'
      USING ERRCODE = 'PF001';
  END IF;
  v_settled := pfm.now_ms();
  IF v_settled - v_now > pfm.manager_renew_sample_bound_ms() THEN
    -- PF011 (proof missing), NOT PF001. PF001 is the manager's "the claim is
    -- provably gone" signal and makes it fence IMMEDIATELY
    -- (claim-heartbeat.ts EPOCH_SUPERSEDED_SQLSTATE -> onSuperseded). A stale
    -- clock sample proves nothing about the claim; it only means THIS
    -- renewal's evidence is not good enough to move the deadline. Raising
    -- rolls the extension back, the heartbeat records an ordinary failure,
    -- and the deadline watchdog continues on its existing schedule — which is
    -- the fail-closed direction without inventing a supersession.
    RAISE EXCEPTION 'manager renew liveness sample went stale (% ms > % ms bound)',
      v_settled - v_now, pfm.manager_renew_sample_bound_ms()
      USING ERRCODE = 'PF011';
  END IF;
  RETURN jsonb_build_object('dbTimeMs', v_now::TEXT, 'expiresAtDbMs', c.expires_at::TEXT);
END;
$$;

RESET ROLE;

-- ═══ SECTION D: postconditions ══════════════════════════════════════════════

DO $post$
DECLARE
  v_def TEXT;
BEGIN
  -- A1: the append path KEY SHAREs the writer's lease row (so a renewal's
  -- non-key UPDATE never queues behind it) and STILL takes the stronger FOR
  -- SHARE on the branch and attach-session rows (nothing on a liveness path
  -- writes those, so their serialization is untouched).
  v_def := pg_get_functiondef(to_regprocedure(
    'pfj.require_writer(pfj.journal_generations,bigint,text,text,bigint,text,text)'));
  IF position('FROM public.leases l WHERE l.id = g.lease_id FOR KEY SHARE;' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfj.require_writer does not KEY SHARE the lease row';
  END IF;
  IF position('WHERE b.id = g.branch_id AND b.volume_id = g.volume_id FOR SHARE;' IN v_def) = 0
     OR position('FROM public.attach_sessions s WHERE s.id = g.attach_session_id FOR SHARE;'
                 IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfj.require_writer lost the branch/session FOR SHARE locks';
  END IF;

  -- A2: neither pfm reader locks the singleton claim row in a mode that a
  -- non-key UPDATE conflicts with.
  v_def := pg_get_functiondef(to_regprocedure('pfm.require_manager(bigint,text,text)'));
  IF position('FOR SHARE' IN v_def) > 0 OR position('FOR KEY SHARE' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfm.require_manager did not downgrade';
  END IF;
  v_def := pg_get_functiondef(to_regprocedure(
    'pfm.verify_authority_binding(text,text,text,bigint,bigint,text,text)'));
  IF position('FROM pfm.manager_claims WHERE singleton_key = ''manager'' FOR KEY SHARE' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfm.verify_authority_binding did not downgrade the claim lock';
  END IF;

  -- A3: the heartbeat itself takes no explicit row lock at all.
  v_def := pg_get_functiondef(to_regprocedure('pfm.manager_renew(bigint,text,text,bigint)'));
  IF position('FOR UPDATE' IN v_def) > 0 OR position('FOR SHARE' IN v_def) > 0 THEN
    RAISE EXCEPTION '034 postcondition: pfm.manager_renew still takes an explicit row lock';
  END IF;
  IF position('GREATEST(expires_at, v_now + p_ttl_ms)' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfm.manager_renew lost its monotone extension';
  END IF;

  -- A4: the fence transitions kept their exclusive locks.
  v_def := pg_get_functiondef(to_regprocedure('pfm.manager_claim(text,text,text,bigint)'));
  IF position('WHERE singleton_key = ''manager'' FOR UPDATE' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfm.manager_claim lost its FOR UPDATE takeover lock';
  END IF;
  v_def := pg_get_functiondef(to_regprocedure('pfm.manager_release(bigint,text,text)'));
  IF position('WHERE singleton_key = ''manager'' FOR UPDATE' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: pfm.manager_release lost its FOR UPDATE lock';
  END IF;
  v_def := pg_get_functiondef(to_regprocedure(
    'pfj.journal_claim_core(text,text,text,text,text,text,bigint,text,text,text,bigint,bigint,text,text,bigint,bigint,text,text)'));
  IF position('FOR SHARE' IN v_def) = 0 THEN
    RAISE EXCEPTION '034 postcondition: the journal claim path lost its FOR SHARE fence serialization';
  END IF;

  -- Lineage: 035 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '035%') THEN
    RAISE EXCEPTION '034 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
