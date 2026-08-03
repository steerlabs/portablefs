-- 038_manager_renew_anchored_grant: a SLOW renewal must still be a renewal.
--
-- INCIDENT THIS EXISTS FOR (round 21c, live). One tenant's ordinary
-- single-threaded ~7 MiB/s write, plus one concurrent cut materialization,
-- made the fleet's singleton authority manager fence ITSELF — killing every
-- child and invalidating every access lease on the whole deployment:
--
--   21:10:58-21:57:18  manager renew liveness sample went stale
--                      (1007 / 1146 / 2123 / 3551 / 4174 ms > 250 ms bound)
--   21:57:25           [child] manager lease pipe fenced this child
--   21:57:27           manager epoch 41: the singleton claim's database-time
--                      deadline passed ... fencing this manager
--   21:57:27           manager epoch 41 fenced itself: claim-deadline-exceeded
--
-- Every mount then took "access credential REJECTED by a reachable authority"
-- -> EIO. It recurred on epoch 42 during a pure sequential read-back.
--
-- WHAT ACTUALLY HAPPENED. The message is 034's own PF011 guard, and it is
-- self-inflicted. 034 replaced the FOR UPDATE + validate + UPDATE triple with
-- ONE conditional UPDATE, which cannot sample the clock after its own row
-- wait, so it sampled BEFORE (v_now) and then rolled the whole renewal back
-- if more than a fixed 250 ms had elapsed by the time the write settled. So a
-- renewal that Postgres EXECUTED CORRECTLY — matched the singleton row, proved
-- the epoch/runtime/capability, extended expires_at — was thrown away because
-- the statement was slow. Three of those inside one 30 s TTL and expires_at
-- stops advancing; the manager's local deadline runs out and it fences. The
-- children fence 2 s earlier for the SAME reason: their own grounding probe
-- (pfj.authority_lease_facts) reads this very row, so a rolled-back renewal
-- stops the clock for every child on the deployment at once.
--
-- WHY THE STATEMENT WAS SLOW — MEASURED, NOT INFERRED (see
-- src/manager-renew-anchored-grant.integration.test.ts and the round report).
-- Against a real postgres constrained to one core / 32 MB shared_buffers /
-- 64 kB wal_buffers, under a bulk flood of 8 MiB payload commits at
-- synchronous_commit=on, with pg_stat_statements.track=all:
--
--   statement                                     calls  mean_ms  max_ms
--   INSERT INTO scratch_flood (payload)             845   168.92  418.79
--   SELECT ... pfm.manager_claims ... FOR KEY SHARE 909     0.58   73.31
--   UPDATE pfm.manager_claims SET renewed_at = ...  318     0.82   78.85
--   UPDATE scratch_control SET n = n + $1           280     0.51   64.53   <-- unrelated
--
-- The renewal's UPDATE (max 78.85 ms) is indistinguishable from a trivial
-- single-row UPDATE of an unrelated private table (max 64.53 ms). Running the
-- identical flood with the claim row REMOVED from the flood's transactions
-- changed the renewal's in-statement cost not at all (p90 5 ms vs 8 ms, max
-- 70 ms vs 69 ms). The renewal backend's sampled wait events across the
-- window were IO/WALSync, LWLock/WALWrite, IO/WALWrite, LWLock/WALInsert —
-- and ZERO Lock/transactionid, so 034's lock isolation is intact.
--
-- The cause is therefore NOT a lock queue, NOT the claim row, NOT the event
-- loop and NOT pool starvation (all four already fixed, rounds 16/18b/034).
-- It is generic WAL back-pressure: any statement that must insert a WAL
-- record waits behind — and sometimes performs — the flood's WAL writes. A
-- durable claim renewal MUST write WAL to the same Postgres the journal
-- saturates. That coupling cannot be isolated away. It can only be ABSORBED.
--
-- ══ THE FIX ═══════════════════════════════════════════════════════════════
--
-- Two changes, both about making a slow-but-successful renewal count.
--
-- 1. THE REPORTED DATABASE CLOCK IS THE POST-WRITE ONE. dbTimeMs was v_now,
--    sampled before the UPDATE. It is now v_settled, sampled after it. The
--    caller computes remaining = expiresAtDbMs - dbTimeMs and projects it
--    onto its own monotonic clock from an anchor taken BEFORE the call, so a
--    statement that cost T ms now yields a claim window shorter by exactly
--    T ms instead of yielding nothing at all. Slowness is charged against
--    the grant, which is honest and self-limiting, rather than discarded.
--    A 4174 ms renewal — the worst production observed — still delivers
--    25.8 s of a 30 s TTL. The manager never fences.
--
-- 2. THE FIXED 250 ms BOUND IS REPLACED BY THE EXACT UNSOUNDNESS TEST.
--    The bound existed because `expires_at > v_now` is evaluated against a
--    pre-wait sample, so a claim that expired DURING the statement could be
--    resurrected. 250 ms was never derived from anything: the quantity it
--    guards is the claim's own remaining lifetime (20-30 s at the default
--    TTL, and 1 s..1 h across the range this function accepts), so a fixed
--    millisecond constant is both far too small to survive an honest write
--    flood and unrelated to the property at stake. The precise condition
--    under which extending is unsound is:
--
--        the claim's PRE-EXISTING expiry had already passed when the write
--        settled
--
--    which is now checked directly against v_settled and the pre-update
--    expiry, with no constant and no tuning. It scales with the TTL by
--    construction and it fires exactly when — and only when — resurrection
--    would occur.
--
-- ══ WHY THIS DOES NOT WEAKEN FENCING ══════════════════════════════════════
--
-- A manager that genuinely cannot renew still fences, promptly and
-- definitely. Every path is unchanged or strictly stronger:
--
--   * SUPERSEDED. A takeover (pfm.manager_claim, FOR UPDATE) conflicts with
--     this UPDATE's FOR NO KEY UPDATE, so the two serialize. If the takeover
--     commits first, READ COMMITTED re-evaluates this UPDATE's predicates
--     against the LATEST committed row version (EvalPlanQual): epoch,
--     runtime_id and capability_hash no longer match, ROW_COUNT is 0, PF001,
--     and the manager fences IMMEDIATELY. If this renewal commits first the
--     takeover's FOR UPDATE re-reads the extended row and refuses. Exactly
--     one live manager, decided by the row lock — never by a clock.
--   * EXPIRED. `expires_at > v_now` still gates the UPDATE, and the new
--     post-write test additionally proves the PRE-EXISTING expiry had not
--     passed when the write settled. A renewal that outlives its own claim
--     raises PF001 and the extension rolls back, leaving the claim dead and a
--     successor free to take over at once. That is STRICTER than the 250 ms
--     bound was: the old guard raised PF011, which the manager treats as an
--     ordinary ambiguous failure, so a genuinely dead claim was reported as
--     merely unproven.
--   * UNREACHABLE / TIMED OUT / WEDGED. Unchanged: no response, no
--     extension, and the manager's local monotonic deadline — anchored
--     BEFORE the call, so it can never reach past the true database expiry —
--     runs out and fences on schedule.
--   * MONOTONICITY. expires_at still moves by GREATEST, so no renewal can
--     ever shorten a claim, and the grant is still v_now + ttl (the pre-write
--     instant), never v_settled + ttl. The window a slow renewal hands out is
--     therefore strictly SHORTER in real time than a fast one's, never longer.
--
-- The direction of every change is: a slow renewal gets LESS time, not more.
-- Nothing here can extend a claim past an instant the database vouched for.
--
-- ERROR SQLSTATES: PF001 (state refusal, now also covering the settled-past-
-- expiry case), PF008 (invalid argument). PF011 is no longer raised by
-- pfm.manager_renew.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='037_adoption_base_proof'
  ) THEN
    RAISE EXCEPTION '038 preflight: the 037 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '039%') THEN
    RAISE EXCEPTION '038 preflight: a later migration receipt exists';
  END IF;
  IF to_regprocedure('pfm.manager_renew(bigint,text,text,bigint)') IS NULL
     OR to_regprocedure('pfm.now_ms()') IS NULL
     OR to_regprocedure('pfm.require_durable_primary()') IS NULL THEN
    RAISE EXCEPTION '038 preflight: the 010/034 manager renewal surface is incomplete';
  END IF;
  -- The shape 038 replaces must be the one 034 installed. If some other
  -- migration already rewrote the renewal, abort rather than clobber it.
  IF position('pfm.manager_renew_sample_bound_ms()' IN pg_get_functiondef(
       to_regprocedure('pfm.manager_renew(bigint,text,text,bigint)'))) = 0 THEN
    RAISE EXCEPTION '038 preflight: pfm.manager_renew is not the 034 bounded-sample shape';
  END IF;
END;
$preflight$;

SET LOCAL ROLE portablefs_manager_owner;

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
  v_prior_expires_at BIGINT;
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

  -- The expiry this renewal extends FROM, read with NO row lock at all: this
  -- read must never be able to queue behind bulk validation, which is the
  -- whole point of 034. It is the quantity the post-write soundness test
  -- below compares against. A concurrent takeover can only make it larger
  -- (a takeover requires the old claim to be expired and grants a fresh
  -- window), and this manager is the only writer of its own claim, so the
  -- value read here is either exact or conservatively small — and small is
  -- the fail-closed direction.
  SELECT expires_at INTO v_prior_expires_at
    FROM pfm.manager_claims WHERE singleton_key = 'manager';

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

  -- THE EXACT SOUNDNESS TEST. `expires_at > v_now` was evaluated against a
  -- sample taken before the write, so the one thing it cannot see is a claim
  -- that expired WHILE the statement ran. That — and only that — would
  -- resurrect a dead claim, and a resurrected claim is read by every append
  -- (pfm.require_manager), every access-lease call
  -- (pfm.verify_authority_binding) and every child's grounding probe
  -- (pfj.authority_lease_facts). So it is checked directly, against the
  -- pre-existing expiry and the post-write clock, with no bound and no
  -- constant. PF001, not PF011: a claim whose own expiry has passed is
  -- provably dead, and the manager must fence on it immediately rather than
  -- treat it as an unproven attempt. Raising rolls the extension back, so the
  -- claim stays dead and a successor may take over at once.
  IF v_prior_expires_at IS NULL OR v_prior_expires_at <= v_settled THEN
    RAISE EXCEPTION
      'manager renew rejected: the claim expired at database time % while this renewal was in flight (settled %)',
      v_prior_expires_at, v_settled
      USING ERRCODE = 'PF001';
  END IF;

  -- dbTimeMs is the POST-WRITE clock. The caller's remaining window is
  -- expiresAtDbMs - dbTimeMs, so a renewal that cost T ms hands back T ms
  -- less rather than nothing. Combined with the caller anchoring on its own
  -- monotonic clock BEFORE the call, the projected local deadline can never
  -- reach past the true database expiry, however slow the statement was.
  RETURN jsonb_build_object('dbTimeMs', v_settled::TEXT, 'expiresAtDbMs', c.expires_at::TEXT);
END;
$$;

-- The 034 bound is no longer referenced by anything. It is dropped rather
-- than left behind at a new value: a fixed millisecond bound on how long this
-- statement may take is not a fencing criterion, and leaving the function in
-- place would invite one to be reintroduced.
DROP FUNCTION IF EXISTS pfm.manager_renew_sample_bound_ms();

RESET ROLE;

-- ═══ POSTCONDITIONS ═════════════════════════════════════════════════════════

DO $post$
DECLARE
  v_def TEXT;
BEGIN
  v_def := pg_get_functiondef(to_regprocedure('pfm.manager_renew(bigint,text,text,bigint)'));

  -- P1: no fixed staleness bound rolls a successful renewal back any more.
  IF position('manager_renew_sample_bound_ms' IN v_def) > 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_renew still consults a fixed sample bound';
  END IF;
  IF to_regprocedure('pfm.manager_renew_sample_bound_ms()') IS NOT NULL THEN
    RAISE EXCEPTION '038 postcondition: the fixed sample bound function still exists';
  END IF;

  -- P2: the reported database clock is the POST-WRITE sample, so a slow
  -- renewal is charged against its own grant.
  IF position('''dbTimeMs'', v_settled::TEXT' IN v_def) = 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_renew does not report the post-write clock';
  END IF;

  -- P3: the exact soundness test is present and fences (PF001) rather than
  -- reporting an unproven attempt.
  IF position('v_prior_expires_at <= v_settled' IN v_def) = 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_renew lost the settled-past-expiry test';
  END IF;

  -- P4: everything 034 established about the renewal is untouched — no
  -- explicit row lock, monotone extension, live-at-sample predicate.
  IF position('FOR UPDATE' IN v_def) > 0 OR position('FOR SHARE' IN v_def) > 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_renew took an explicit row lock';
  END IF;
  IF position('GREATEST(expires_at, v_now + p_ttl_ms)' IN v_def) = 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_renew lost its monotone extension';
  END IF;
  IF position('AND expires_at > v_now' IN v_def) = 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_renew lost its live-claim predicate';
  END IF;

  -- P5: the fence transitions still hold their exclusive locks, so takeover
  -- and renewal still serialize against each other.
  IF position('WHERE singleton_key = ''manager'' FOR UPDATE' IN
       pg_get_functiondef(to_regprocedure('pfm.manager_claim(text,text,text,bigint)'))) = 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_claim lost its FOR UPDATE takeover lock';
  END IF;
  IF position('WHERE singleton_key = ''manager'' FOR UPDATE' IN
       pg_get_functiondef(to_regprocedure('pfm.manager_release(bigint,text,text)'))) = 0 THEN
    RAISE EXCEPTION '038 postcondition: pfm.manager_release lost its FOR UPDATE lock';
  END IF;

  -- Lineage: 039 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '039%') THEN
    RAISE EXCEPTION '038 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
