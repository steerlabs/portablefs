-- 037_adoption_base_proof: the base advance carries the proof the schema
-- actually issues.
--
-- INCIDENT THIS EXISTS FOR. A history-cut adoption that lands while a writer
-- is attached KILLS that writer, deterministically. The child raises
-- "remotejournal: destructive advance refused without landed checkpoint cut
-- proof: append response advanced base commit without exact cut proof",
-- poisons its journal, fences the data plane, and takes the mount to EIO.
--
-- THE MECHANISM, and why it is a schema problem and not a client bug. The
-- child is right to refuse an unproven base advance: records below the base
-- become physically deletable (031's reclamation horizon), so a base commit
-- that moved without proof is a request to drop journal records on the word
-- of a response. The bug is WHICH proof it demanded. It demanded a LANDED or
-- FINALIZED legacy checkpoint cut — journal_generations.cut_operation_id /
-- cut_status / cut_watermark / cut_commit_id — at exactly the new base seq.
--
-- Those columns are FROZEN for a pfj3 generation. Migration 013 froze them
-- ('legacy cut/trim/rotate is not defined for a PFJ3 generation') and 031
-- re-froze them ('legacy cut/rotate is not defined for a PFJ3 generation'),
-- both PF005, on ANY write. In the same trigger both migrations name the one
-- edge that IS admitted: a base advance performed by the journal owner and
-- matched by exactly one pfh.adoptions row for this generation and this exact
-- old/new tuple INCLUDING the backlog subtraction. Rows, not settings,
-- authorize — and the row is an ADOPTION, never a legacy cut.
--
-- So pfj.generation_json emitted 'cut' = NULL for every pfj3 generation (its
-- CASE keys off cut_operation_id), every pfj3 append response carried
-- currentCut = null, and the child's check could not be satisfied by any
-- legitimate production flow. It was UNSATISFIABLE, not protective. Verified
-- against the live database: every generation that has ever adopted carries
-- base_seq > 0 with cut_operation_id IS NULL (8 applied adoptions, 8
-- generations, zero legacy cut rows among them).
--
-- The second-order damage is worse than the fence. The child assigns its
-- local base (l.baseSeq) only AFTER this check passes, so CompactedThrough()
-- never advanced either — every consumer of "how much of this journal is
-- already captured in the base" was pinned at the value it had at attach, for
-- the entire life of the writer.
--
-- THE FIX. Carry the modern proof and let the child validate THAT. This
-- migration adds pfj.adoption_proof_json(g): the pfh.adoptions row that
-- authorized the generation's CURRENT base tuple, joined to the
-- pfh.history_cuts row it adopted. It is exposed on generation_json (as
-- 'adoption'), on the quota preflight (as 'adoption'), and on a new
-- pfj.journal_append_v4 (as 'currentAdoption').
--
-- WHAT MAKES IT A PROOF, and not just a fact the server asserts. The child
-- checks the two rows against EACH OTHER and against what it already holds:
--
--   * the adoption names this generation, is landed, and does not reach back
--     behind the child's own base;
--   * the cut it cites is 'ready' — pfh.history_cuts' one terminal success
--     state, meaning the prefix was materialized, not merely scheduled;
--   * cut_seq_exclusive / cut_digest / result_commit_id equal EXACTLY the new
--     base seq / digest / commit id being installed.
--
-- cut_digest is the journal CHAIN DIGEST at the boundary, so that last clause
-- binds the materialized commit to the child's own byte history — the legacy
-- cut proof only ever pinned a watermark and a commit id. A response that
-- moved the base but cannot produce this row pair is still refused, exactly
-- as before.
--
-- WHY A NEW ENTRY POINT AND NOT A REPLACED ONE. pfj.journal_append_v3's
-- durable behaviour must not move: its response is written verbatim into
-- pfj.journal_append_receipts and replayed byte-identically for exactly-once
-- (PF009 and the receipt fingerprint are frozen). v4 is a thin wrapper that
-- calls v3 unchanged and overlays one key computed from rows the transaction
-- already holds locked. Nothing about the receipt, the fingerprint, the
-- operation identity, or the canonical JSON of the stored body changes. The
-- overlay is recomputed live on replay for the same reason every other
-- current* field already is.
--
-- COMPATIBILITY. Both directions fail closed, neither silently.
--   * OLD child + NEW schema: the child keeps calling v3, which is untouched
--     and keeps its grant. It behaves exactly as it does today (it will still
--     refuse an adoption) — no regression, no new failure.
--   * NEW child + OLD schema: v4 does not exist and the call raises
--     undefined_function. The child cannot mistake a missing proof for an
--     absent adoption. Upgrade schema before binary, as COMPATIBILITY.md
--     requires ("upgrade clients and authorities together").
--
-- WHAT THIS DOES NOT DO. It does not admit a base advance that has no
-- adoption row. 031's terminal-retirement edge (B) moves base_seq to next_seq
-- for a RETIRED volume with no adoption at all; that generation's writer is
-- already fenced by require_writer long before it could observe the move, and
-- a child that somehow did observe it still refuses. Fail-closed is the
-- correct answer there and it is preserved.

DO $preflight$
BEGIN
  IF to_regclass('pfh.adoptions') IS NULL
     OR to_regclass('pfh.history_cuts') IS NULL
     OR to_regclass('pfj.journal_generations') IS NULL THEN
    RAISE EXCEPTION '037 preflight: a required 009/013 table is missing';
  END IF;
  IF to_regprocedure('pfj.journal_append_v3(text,bigint,text,text,bigint,bigint,bigint,text,bigint,bytea[],text[],text)') IS NULL THEN
    RAISE EXCEPTION '037 preflight: pfj.journal_append_v3 is missing';
  END IF;
  IF to_regprocedure('pfj.adoption_proof_json(pfj.journal_generations)') IS NOT NULL THEN
    RAISE EXCEPTION '037 preflight: pfj.adoption_proof_json already exists';
  END IF;
  IF to_regprocedure('pfj.journal_append_v4(text,bigint,text,text,bigint,bigint,bigint,text,bigint,bytea[],text[],text)') IS NOT NULL THEN
    RAISE EXCEPTION '037 preflight: pfj.journal_append_v4 already exists';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: the proof projection ════════════════════════════════════════

SET LOCAL ROLE portablefs_journal_owner;

-- The adoption that authorized THIS generation's current base tuple, joined
-- to the cut it adopted. NULL when the base was never moved by an adoption
-- (a fresh generation still at its claim-time base, a legacy pfr1 generation
-- that uses the cut_* columns, or 031's terminal-retirement edge).
--
-- SECURITY INVOKER on purpose, exactly like pfj.generation_json: every caller
-- is already a SECURITY DEFINER pfj entry point running as this owner, and
-- 013 granted this owner SELECT on pfh.adoptions and pfh.history_cuts for
-- precisely this reason (its freeze trigger verifies the same rows). Adding a
-- definer surface here would hand a tenant-agnostic read of every adoption
-- row to whoever could reach the function.
--
-- The predicate is the generation's CURRENT tuple, not "the newest adoption":
-- a chain of adoptions may have landed, and the only row that can prove the
-- base a response is asking the child to install is the one that installed it.
--
-- Selection is total on the tuple (new_base_seq + new_base_digest +
-- new_base_commit_id) and 029's dedup_key already makes two cuts of the same
-- (generation, boundary) impossible, so at most one row can match; the ORDER
-- BY exists to keep the projection deterministic under any future relaxation
-- rather than to break a real tie.
--
-- 'applying' is accepted alongside 'applied' because the freeze trigger
-- itself authorizes on 'applying': the row is inserted, pfj.history_adopt_base
-- moves the base, and the row flips to 'applied' inside ONE transaction. Both
-- states mean the same thing to any reader outside it — the base has already
-- durably moved behind this row.
CREATE FUNCTION pfj.adoption_proof_json(g pfj.journal_generations) RETURNS JSONB
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT jsonb_build_object(
    'adoptionId', a.id,
    'generationId', a.generation_id,
    'cutId', a.cut_id,
    'anchorId', a.anchor_id,
    'operationId', a.op_operation_id,
    'state', a.state,
    'oldBaseSeq', a.old_base_seq::TEXT,
    'oldBaseDigest', a.old_base_digest,
    'newBaseSeq', a.new_base_seq::TEXT,
    'newBaseDigest', a.new_base_digest,
    'newBaseCommitId', a.new_base_commit_id,
    'subtractBacklogBytes', a.subtract_backlog_bytes::TEXT,
    'subtractBacklogRecords', a.subtract_backlog_records::TEXT,
    'cutState', c.state,
    'cutKind', c.kind,
    'cutSeqExclusive', c.cut_seq_exclusive::TEXT,
    'cutDigest', c.cut_digest,
    'cutResultCommitId', c.result_commit_id)
  FROM pfh.adoptions a
  JOIN pfh.history_cuts c ON c.id = a.cut_id
  WHERE a.generation_id = g.id
    AND a.state IN ('applied', 'applying')
    AND a.new_base_seq = g.base_seq
    AND a.new_base_digest = g.base_digest
    AND a.new_base_commit_id = g.base_commit_id
  ORDER BY a.created_db_ms DESC, a.id DESC
  LIMIT 1
$$;

REVOKE ALL ON FUNCTION pfj.adoption_proof_json(pfj.journal_generations) FROM PUBLIC;

-- ═══ SECTION B: the deployed bodies, patched at one key each ════════════════

-- pfj.generation_json, the 012 body read back with pg_get_functiondef, with
-- ONE key added next to 'cut'. Every generation-shaped response in pfj flows
-- through here, so the legacy trim/rotate/suspend lane (which validates the
-- same base transition) gains the proof at the same time as the append lane.
--
-- jsonb_strip_nulls keeps the key absent when there is no adoption, which is
-- the same absence the child already handles for 'cut'. Every field inside
-- the object is NOT NULL in its table, so strip_nulls cannot hollow out a
-- proof into a partially-populated one. (old_base_commit_id IS nullable and
-- is deliberately not carried: the child compares old_base_SEQ against its own
-- base, and a nullable field inside a proof is a field a forged proof can omit.)
CREATE OR REPLACE FUNCTION pfj.generation_json(g pfj.journal_generations)
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'generationId', g.id,
    'tenantId', g.tenant_id,
    'volumeId', g.volume_id,
    'branchId', g.branch_id,
    'branchName', (SELECT b.name FROM public.branches b WHERE b.id = g.branch_id),
    'branchMode', (SELECT b.branch_mode FROM public.branches b WHERE b.id = g.branch_id),
    'epoch', g.epoch::TEXT,
    'recordCodec', g.record_codec,
    'controlCodec', g.control_codec,
    'baseCommitId', g.base_commit_id,
    'baseSeq', g.base_seq::TEXT,
    'baseDigest', g.base_digest,
    'nextSeq', g.next_seq::TEXT,
    'tipDigest', g.tip_digest,
    'physicalTrimmedSeq', g.physical_trimmed_seq::TEXT,
    'status', g.status,
    'backlogBytes', g.backlog_bytes::TEXT,
    'backlogRecords', g.backlog_records::TEXT,
    'quotaBacklogBytes', g.quota_backlog_bytes::TEXT,
    'quotaBacklogRecords', g.quota_backlog_records::TEXT,
    'writerFence', g.writer_fence::TEXT,
    'attachSessionId', g.attach_session_id,
    'leaseId', g.lease_id,
    'holderId', g.holder_id,
    'authorityInstanceId', g.authority_instance_id,
    'managerEpoch', g.manager_epoch::TEXT,
    'authorityRuntimeSeq', g.authority_runtime_seq::TEXT,
    'authorityRuntimeId', g.authority_runtime_id,
    'controlDbFloorMs', g.control_db_floor_ms::TEXT,
    'haPolicyHash', g.ha_policy_hash,
    'appendReceiptFloorSeq', g.append_receipt_floor_seq::TEXT,
    'claimedAt', g.claimed_at::TEXT,
    'cut', CASE WHEN g.cut_operation_id IS NULL THEN NULL ELSE jsonb_strip_nulls(jsonb_build_object(
      'operationId', g.cut_operation_id,
      'epoch', g.epoch::TEXT,
      'status', g.cut_status,
      'watermark', g.cut_watermark::TEXT,
      'expectedHeadCommitId', g.cut_expected_head_commit_id,
      'treeHash', g.cut_tree_hash,
      'canonicalRequestHash', g.cut_request_hash,
      'auxiliaryBlobDigestsHash', g.cut_auxiliary_hash,
      'commitId', g.cut_commit_id
    )) END,
    'adoption', pfj.adoption_proof_json(g),
    'updatedAt', g.updated_at::TEXT
  ))
$function$;

-- pfj.journal_check_append_quota, the 011 body read back with
-- pg_get_functiondef, with ONE key added next to 'cut'. The zero-addition
-- quota preflight validates the same base transition as an append and
-- poisoned the writer identically when an adoption had landed since the last
-- call.
CREATE OR REPLACE FUNCTION pfj.journal_check_append_quota(p_generation_id text, p_epoch bigint, p_capability text, p_lease_id text, p_fencing_token bigint, p_record_codec text, p_control_codec text, p_manager_epoch bigint, p_authority_runtime_seq bigint, p_authority_runtime_id text, p_additional_bytes bigint, p_additional_records bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE g pfj.journal_generations;
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_additional_bytes IS NULL OR p_additional_bytes<0
     OR p_additional_records IS NULL OR p_additional_records<0 THEN
    RAISE EXCEPTION 'quota additions must be non-negative'
      USING ERRCODE='PF008';
  END IF;
  IF p_additional_bytes>16777216 OR p_additional_records>128 THEN
    RAISE EXCEPTION 'quota group exceeds append bounds' USING ERRCODE='PF004';
  END IF;
  SELECT * INTO g FROM pfj.journal_generations
    WHERE id=p_generation_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation not found' USING ERRCODE='PF007';
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    p_record_codec,p_control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  IF g.backlog_bytes>g.quota_backlog_bytes
     OR g.backlog_records>g.quota_backlog_records THEN
    RAISE EXCEPTION 'journal backlog accounting is corrupt'
      USING ERRCODE='PF010';
  END IF;
  IF p_additional_bytes>g.quota_backlog_bytes-g.backlog_bytes
     OR p_additional_records>g.quota_backlog_records-g.backlog_records THEN
    RAISE EXCEPTION 'journal backlog quota preflight exceeded'
      USING ERRCODE='PF003',
            DETAIL=jsonb_build_object(
              'backlogBytes',g.backlog_bytes::TEXT,
              'backlogRecords',g.backlog_records::TEXT,
              'quotaBacklogBytes',g.quota_backlog_bytes::TEXT,
              'quotaBacklogRecords',g.quota_backlog_records::TEXT,
              'additionalBytes',p_additional_bytes::TEXT,
              'additionalRecords',p_additional_records::TEXT)::TEXT;
  END IF;
  RETURN jsonb_build_object(
    'allowed',TRUE,'generationId',g.id,'epoch',g.epoch::TEXT,
    'branchName',(SELECT b.name FROM public.branches b WHERE b.id=g.branch_id),
    'baseCommitId',g.base_commit_id,'baseSeq',g.base_seq::TEXT,
    'baseDigest',g.base_digest,
    'physicalTrimmedSeq',g.physical_trimmed_seq::TEXT,
    'cut',pfj.generation_json(g)->'cut',
    'adoption',pfj.generation_json(g)->'adoption',
    'backlogBytes',g.backlog_bytes::TEXT,
    'backlogRecords',g.backlog_records::TEXT,
    'quotaBacklogBytes',g.quota_backlog_bytes::TEXT,
    'quotaBacklogRecords',g.quota_backlog_records::TEXT,
    'remainingBytes',
      (g.quota_backlog_bytes-g.backlog_bytes-p_additional_bytes)::TEXT,
    'remainingRecords',
      (g.quota_backlog_records-g.backlog_records-p_additional_records)::TEXT);
END;
$function$;

-- ═══ SECTION C: the proof-carrying append ═══════════════════════════════════

-- v4 = v3, plus the proof. Deliberately a WRAPPER and not a replacement:
--
--   * v3's stored receipt body must stay byte-identical. It is written into
--     pfj.journal_append_receipts inside v3 and replayed verbatim; a changed
--     body would make a replayed append differ from the original one it is
--     supposed to be indistinguishable from.
--   * every durable effect — record insert, backlog accounting, admission
--     fact consumption, control floor, receipt compaction, the whole lock
--     order — stays in exactly one place, unedited. There is no second
--     transcription of 340 lines to drift.
--
-- The generation is re-read after v3 returns, INSIDE the same transaction. v3
-- took pfj.lock_generation on that row, and a row lock is held to COMMIT, so
-- no concurrent adoption can move the base between v3's own read and this one:
-- the tuple the proof is computed against is exactly the tuple v3 reported.
CREATE FUNCTION pfj.journal_append_v4(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_first_seq BIGINT,
  p_payloads BYTEA[],
  p_record_hashes TEXT[],
  p_end_tip TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_response JSONB;
  g pfj.journal_generations;
BEGIN
  v_response := pfj.journal_append_v3(
    p_generation_id, p_epoch, p_capability, p_lease_id, p_fencing_token,
    p_manager_epoch, p_authority_runtime_seq, p_authority_runtime_id,
    p_first_seq, p_payloads, p_record_hashes, p_end_tip);
  SELECT * INTO g FROM pfj.journal_generations WHERE id=p_generation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'append lost its locked generation' USING ERRCODE='PF010';
  END IF;
  -- Defence in depth against a future edit to v3: the proof must describe the
  -- SAME base tuple v3 reported, or the response would carry a proof for a
  -- state the caller is not being asked to install.
  IF v_response->>'currentBaseSeq' IS DISTINCT FROM g.base_seq::TEXT
     OR v_response->>'currentBaseCommitId' IS DISTINCT FROM g.base_commit_id
     OR v_response->>'currentBaseDigest' IS DISTINCT FROM g.base_digest THEN
    RAISE EXCEPTION 'append base facts moved between the append and its proof'
      USING ERRCODE='PF010';
  END IF;
  RETURN v_response || jsonb_build_object(
    'currentAdoption', pfj.adoption_proof_json(g));
END;
$$;

REVOKE ALL ON FUNCTION pfj.journal_append_v4(
  TEXT,BIGINT,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,BIGINT,
  BYTEA[],TEXT[],TEXT) FROM PUBLIC;

-- The same least-authority surface v3 has. v3 KEEPS its grant: an older child
-- that has not been upgraded must keep working exactly as it does today
-- rather than lose its append path.
GRANT EXECUTE ON FUNCTION
  pfj.journal_append_v4(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,BIGINT,
    BYTEA[],TEXT[],TEXT)
TO portablefs_authority;

RESET ROLE;

-- ═══ SECTION D: postconditions ══════════════════════════════════════════════

DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
  v_def TEXT;
BEGIN
  -- The new entry point exists with the exact ownership/definer/search_path
  -- discipline 012's postcondition demands of every pfj entry point.
  SELECT p.oid AS fnoid, p.prosecdef,
         COALESCE(array_to_string(p.proconfig,';'),'') AS config,
         pg_get_userbyid(p.proowner) AS owner
    INTO v_rec
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname='pfj' AND p.proname='journal_append_v4';
  IF NOT FOUND THEN
    RAISE EXCEPTION '037 postcondition: pfj.journal_append_v4 is missing';
  END IF;
  IF v_rec.owner <> 'portablefs_journal_owner' THEN
    RAISE EXCEPTION '037 postcondition: pfj.journal_append_v4 is owned by %', v_rec.owner;
  END IF;
  IF NOT v_rec.prosecdef THEN
    RAISE EXCEPTION '037 postcondition: pfj.journal_append_v4 must be SECURITY DEFINER';
  END IF;
  IF v_rec.config NOT LIKE '%search_path%' THEN
    RAISE EXCEPTION '037 postcondition: pfj.journal_append_v4 has no pinned search_path';
  END IF;
  IF has_function_privilege('public', v_rec.fnoid, 'EXECUTE') THEN
    RAISE EXCEPTION '037 postcondition: PUBLIC can execute pfj.journal_append_v4';
  END IF;
  IF NOT has_function_privilege('portablefs_authority', v_rec.fnoid, 'EXECUTE') THEN
    RAISE EXCEPTION '037 postcondition: the authority cannot execute pfj.journal_append_v4';
  END IF;

  -- v3 is UNTOUCHED and still reachable. The compatibility posture depends on
  -- both halves: an old child keeps appending through v3, and v4 delegates to
  -- it rather than reimplementing it.
  IF to_regprocedure('pfj.journal_append_v3(text,bigint,text,text,bigint,bigint,bigint,text,bigint,bytea[],text[],text)') IS NULL THEN
    RAISE EXCEPTION '037 postcondition: pfj.journal_append_v3 disappeared';
  END IF;
  IF NOT has_function_privilege('portablefs_authority',
       'pfj.journal_append_v3(text,bigint,text,text,bigint,bigint,bigint,text,bigint,bytea[],text[],text)','EXECUTE') THEN
    RAISE EXCEPTION '037 postcondition: v3 lost the grant an un-upgraded child needs';
  END IF;
  v_def := pg_get_functiondef(to_regprocedure(
    'pfj.journal_append_v4(text,bigint,text,text,bigint,bigint,bigint,text,bigint,bytea[],text[],text)'));
  IF position('pfj.journal_append_v3' IN v_def) = 0 THEN
    RAISE EXCEPTION '037 postcondition: v4 no longer delegates to v3; the receipt body would fork';
  END IF;
  IF position('currentAdoption' IN v_def) = 0 THEN
    RAISE EXCEPTION '037 postcondition: v4 does not carry the adoption proof';
  END IF;

  -- The proof is reachable from every surface that validates a base
  -- transition: the generation snapshot (trim/rotate/suspend/claim lane) and
  -- the zero-addition quota preflight.
  IF position('adoption_proof_json' IN pg_get_functiondef(
       to_regprocedure('pfj.generation_json(pfj.journal_generations)'))) = 0 THEN
    RAISE EXCEPTION '037 postcondition: generation_json does not carry the adoption proof';
  END IF;
  IF position('adoption_proof_json' IN pg_get_functiondef(
       to_regprocedure('pfj.journal_check_append_quota(text,bigint,text,text,bigint,text,text,bigint,bigint,text,bigint,bigint)'))) = 0
     AND position('->''adoption''' IN pg_get_functiondef(
       to_regprocedure('pfj.journal_check_append_quota(text,bigint,text,text,bigint,text,text,bigint,bigint,text,bigint,bigint)'))) = 0 THEN
    RAISE EXCEPTION '037 postcondition: the quota preflight does not carry the adoption proof';
  END IF;

  -- THE INVARIANT THIS MIGRATION EXISTS FOR. Every generation whose base was
  -- moved by an adoption whose cut still exists must now be able to PRODUCE
  -- that proof. Before this migration the answer was structurally NULL for
  -- all of them, which is exactly what fenced every attached writer.
  SELECT count(*) INTO v_count
    FROM pfj.journal_generations g
   WHERE EXISTS (
           SELECT 1 FROM pfh.adoptions a
            JOIN pfh.history_cuts c ON c.id = a.cut_id
           WHERE a.generation_id = g.id
             AND a.state IN ('applied','applying')
             AND a.new_base_seq = g.base_seq
             AND a.new_base_digest = g.base_digest
             AND a.new_base_commit_id = g.base_commit_id)
     AND pfj.adoption_proof_json(g) IS NULL;
  IF v_count > 0 THEN
    RAISE EXCEPTION
      '037 postcondition: % adopted generations still cannot produce their proof', v_count;
  END IF;

  -- And the proof, where it exists, agrees with the base it is proving. A
  -- proof that disagreed with its own generation would be refused by the
  -- child anyway; catching it here names the schema as the source.
  SELECT count(*) INTO v_count
    FROM pfj.journal_generations g,
         LATERAL pfj.adoption_proof_json(g) AS proof
   WHERE proof IS NOT NULL
     AND (proof->>'newBaseSeq' IS DISTINCT FROM g.base_seq::TEXT
          OR proof->>'newBaseDigest' IS DISTINCT FROM g.base_digest
          OR proof->>'newBaseCommitId' IS DISTINCT FROM g.base_commit_id
          OR proof->>'cutSeqExclusive' IS DISTINCT FROM g.base_seq::TEXT
          OR proof->>'cutDigest' IS DISTINCT FROM g.base_digest
          OR proof->>'cutResultCommitId' IS DISTINCT FROM g.base_commit_id);
  IF v_count > 0 THEN
    RAISE EXCEPTION
      '037 postcondition: % generations carry a proof that contradicts their base', v_count;
  END IF;

  -- The legacy cut columns stay frozen for pfj3. This migration adds a proof
  -- shape; it does not reopen the one 013 and 031 closed.
  SELECT count(*) INTO v_count
    FROM pfj.journal_generations
   WHERE record_codec='pfj3' AND cut_operation_id IS NOT NULL;
  IF v_count > 0 THEN
    RAISE EXCEPTION
      '037 postcondition: % pfj3 generations carry a legacy cut', v_count;
  END IF;
END;
$post$;
