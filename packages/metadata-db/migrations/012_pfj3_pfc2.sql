-- 012_pfj3_pfc2: the PFJ3/PFC2 managed journal generation pair.
--
-- This migration admits the second (and final planned) immutable codec pair:
--   (record_codec='pfr1', control_codec='pfc1')  -- legacy managed pair
--   (record_codec='pfj3', control_codec='pfc2')  -- managed live data plane
--
-- One journal generation declares exactly one pair at creation and can NEVER
-- switch: codec columns are unconditionally immutable (no GUC, no owner
-- escape). Moving an existing writable branch onto PFJ3/PFC2 is the
-- exceptional retire + new-generation conversion owned by migration 013.
--
-- PFJ3 rows are whole journal entries ("PFJ3" magic): a fixed SQL-verifiable
-- preamble (outer LSN, admission-fact manifest count + SHA-256 digest +
-- ordered entries), then one optional canonical PFR1 tree intent plus ordered
-- canonical PFC2 controls, committed/hashed/chained/replayed as their exact
-- bytes in ONE synchronous fenced transaction. The append transaction parses
-- the preamble and validates + consumes (deletes) exactly the issued fact
-- rows it names — same scope, purpose, session, time — so a fact can never be
-- fabricated, omitted, reordered, stolen across sessions, or replayed.
-- Receipt replay of already-committed identical bytes is answered before any
-- fact validation and consumes nothing.
--
-- Branch storage modes (authoritative provisioning, never a caller/claim
-- choice): legacy_manifest | managed_journal | migrating | retiring | retired.
-- Managed branches are provisioned managed_journal by the metadata layer
-- BEFORE any attach; the v3 claim REQUIRES managed_journal and never changes
-- a mode. Pre-012 branches are backfilled deterministically from their live
-- generation state. Mode changes obey one explicit CAS transition matrix
-- enforced by trigger; the ONLY privileged actor is portablefs_journal_owner
-- (SECURITY DEFINER functions it owns — never a settable GUC).
--
-- Every mutating path takes ONE lock order: the sorted exclusive branch
-- advisory lock, then generation row, branch row, attach session, lease,
-- manager claim/runtime, live HA-policy evaluation, then the mutation. Reads
-- take the shared branch advisory lock and the same row order.
--
-- The canonical HA policy (exact eligible standby names, failure domains,
-- minimum synchronous count, remote_apply commit mode) is persisted here,
-- hash-bound to the PostgreSQL system identifier + database and stamped into
-- every PFJ3 generation at claim; every mutating PFJ3 operation re-evaluates
-- it after taking its locks. Topology or policy drift means no ACK.
--
-- The receipted (exact-compatibility) managed attach that these branch modes
-- gate stores its durable identity here as well: public.attach_receipts is
-- the permanent per-tenant operation-id tombstone written atomically with
-- the attach session/lease it names. It carries NO foreign keys on purpose —
-- retiring a volume/branch/session/commit must never erase the identity, so
-- a late replay answers committed-gone (410) instead of re-executing.
--
-- 013 and 014 remain absent. No HistoryCut, snapshot, drain, or
-- object-storage step joins ordinary writes.

-- ─── Preflight: migration lineage (fail closed, never repair silently) ───────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations
    WHERE id = '011_journal_hardening') THEN
    RAISE EXCEPTION '012 preflight: 011_journal_hardening receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations
    WHERE id LIKE '013%' OR id LIKE '014%') THEN
    RAISE EXCEPTION '012 preflight: a later migration receipt exists; 012 can never be applied after 013/014';
  END IF;
  IF to_regprocedure('pfm.verify_authority_binding(text,text,text,bigint,bigint,text,text)') IS NULL THEN
    RAISE EXCEPTION '012 preflight: pfm manager control plane (010/011) is not installed';
  END IF;
  IF to_regprocedure('pfj.journal_append(text,bigint,text,text,bigint,text,text,bigint,bigint,text,bigint,bytea[],text[],text)') IS NULL THEN
    RAISE EXCEPTION '012 preflight: pfj managed journal surface (011) is not installed';
  END IF;
END;
$preflight$;

-- Constraints added after the original 001/002 receipts shipped must live in
-- the current additive lineage. Validate existing rows first so an upgrade
-- never silently rewrites ambiguous lease/fence authority.
DO $legacy_counter_constraints$
BEGIN
  IF EXISTS (SELECT 1 FROM public.branches WHERE lease_counter < 0) THEN
    RAISE EXCEPTION '012 preflight: branches contains a negative lease_counter; repair the invalid legacy row explicitly'
      USING ERRCODE='PF008';
  END IF;
  IF EXISTS (SELECT 1 FROM public.leases WHERE fencing_token < 1) THEN
    RAISE EXCEPTION '012 preflight: leases contains a non-positive fencing_token; repair the invalid legacy row explicitly'
      USING ERRCODE='PF008';
  END IF;
  IF EXISTS (SELECT 1 FROM public.path_delegations WHERE fencing_token < 1) THEN
    RAISE EXCEPTION '012 preflight: path_delegations contains a non-positive fencing_token; repair the invalid legacy row explicitly'
      USING ERRCODE='PF008';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid='public.branches'::regclass
      AND conname='branches_lease_counter_nonnegative_check') THEN
    ALTER TABLE public.branches
      ADD CONSTRAINT branches_lease_counter_nonnegative_check
      CHECK (lease_counter >= 0);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid='public.leases'::regclass
      AND conname='leases_fencing_token_positive_check') THEN
    ALTER TABLE public.leases
      ADD CONSTRAINT leases_fencing_token_positive_check
      CHECK (fencing_token >= 1);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid='public.path_delegations'::regclass
      AND conname='path_delegations_fencing_token_positive_check') THEN
    ALTER TABLE public.path_delegations
      ADD CONSTRAINT path_delegations_fencing_token_positive_check
      CHECK (fencing_token >= 1);
  END IF;
END;
$legacy_counter_constraints$;

-- ═══ SECTION A: public.branches (runs as the migration/table owner) ══════════
-- The journal owner does NOT own public tables; every branches ALTER, trigger,
-- and backfill below runs as the actual migration user (the table owner).

ALTER TABLE public.branches
  ADD COLUMN branch_mode TEXT NOT NULL DEFAULT 'legacy_manifest'
  CONSTRAINT branches_branch_mode_check CHECK (
    branch_mode IN
      ('legacy_manifest','managed_journal','migrating','retiring','retired'));

-- Deterministic backfill from pre-012 journal state. Exactly one nonterminal
-- generation may exist per branch (009 enforces it with a partial unique
-- index); anything contradictory aborts the migration rather than guessing.
DO $backfill$
DECLARE
  v_row RECORD;
  v_mode TEXT;
BEGIN
  FOR v_row IN
    SELECT g.branch_id,
           COUNT(*) AS live_count,
           MIN(g.status) AS status,
           MIN(g.record_codec) AS record_codec,
           MIN(g.control_codec) AS control_codec
    FROM pfj.journal_generations g
    WHERE g.status IN ('active','suspended','retiring')
    GROUP BY g.branch_id
  LOOP
    IF v_row.live_count > 1 THEN
      RAISE EXCEPTION '012 backfill: branch % has % nonterminal journal generations; contradictory state aborts',
        v_row.branch_id, v_row.live_count;
    END IF;
    IF v_row.record_codec IS DISTINCT FROM 'pfr1'
       OR v_row.control_codec IS DISTINCT FROM 'pfc1' THEN
      RAISE EXCEPTION '012 backfill: branch % carries unexpected pre-012 codec pair %/%',
        v_row.branch_id, v_row.record_codec, v_row.control_codec;
    END IF;
    v_mode := CASE v_row.status
      WHEN 'active' THEN 'migrating'
      WHEN 'suspended' THEN 'migrating'
      WHEN 'retiring' THEN 'retiring'
    END;
    UPDATE public.branches SET branch_mode = v_mode WHERE id = v_row.branch_id;
  END LOOP;
END;
$backfill$;

-- Branch guard trigger: the explicit CAS transition matrix plus the managed
-- head guard. SECURITY INVOKER on purpose: current_user is the role whose
-- statement fired the trigger, so "inside an owner-only pfj SECURITY DEFINER
-- function" is exactly current_user = portablefs_journal_owner — a property
-- no caller can set, unlike a GUC. The generation-state prerequisites are
-- answered by an owner SECURITY DEFINER helper created in section B.
CREATE FUNCTION public.portablefs_branch_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_state TEXT;
BEGIN
  IF OLD.branch_mode = 'retired' THEN
    IF NEW.head_commit_id IS DISTINCT FROM OLD.head_commit_id
       OR NEW.branch_mode IS DISTINCT FROM OLD.branch_mode THEN
      RAISE EXCEPTION 'branch % is retired and frozen', OLD.id USING ERRCODE='PF001';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.branch_mode IS DISTINCT FROM OLD.branch_mode THEN
    IF NOT ((OLD.branch_mode = 'legacy_manifest' AND NEW.branch_mode = 'managed_journal')
         OR (OLD.branch_mode = 'legacy_manifest' AND NEW.branch_mode = 'migrating')
         OR (OLD.branch_mode = 'migrating'       AND NEW.branch_mode = 'managed_journal')
         OR (OLD.branch_mode = 'migrating'       AND NEW.branch_mode = 'legacy_manifest')
         OR (OLD.branch_mode = 'migrating'       AND NEW.branch_mode = 'retiring')
         OR (OLD.branch_mode = 'managed_journal' AND NEW.branch_mode = 'retiring')
         OR (OLD.branch_mode = 'retiring'        AND NEW.branch_mode = 'retired')) THEN
      RAISE EXCEPTION 'branch % mode transition % -> % is not in the transition matrix',
        OLD.id, OLD.branch_mode, NEW.branch_mode USING ERRCODE='PF001';
    END IF;
    v_state := pfj.branch_generation_state(OLD.id);
    -- Prerequisites: a mode may only claim what the journal state proves.
    IF NEW.branch_mode = 'managed_journal' AND OLD.branch_mode = 'legacy_manifest'
       AND v_state <> 'none' THEN
      RAISE EXCEPTION 'branch % cannot become managed_journal: a % journal generation exists (conversion is migration 013)',
        OLD.id, v_state USING ERRCODE='PF001';
    END IF;
    IF NEW.branch_mode = 'managed_journal' AND OLD.branch_mode = 'migrating'
       AND v_state NOT IN ('none') THEN
      RAISE EXCEPTION 'branch % cannot finish migrating: journal state is % (retire the legacy generation first)',
        OLD.id, v_state USING ERRCODE='PF001';
    END IF;
    IF NEW.branch_mode = 'legacy_manifest' AND OLD.branch_mode = 'migrating'
       AND v_state NOT IN ('none','legacy_active','legacy_suspended') THEN
      RAISE EXCEPTION 'branch % cannot abort migration: journal state is %',
        OLD.id, v_state USING ERRCODE='PF001';
    END IF;
    IF NEW.branch_mode = 'retired' AND v_state <> 'none' THEN
      RAISE EXCEPTION 'branch % cannot retire: a nonterminal journal generation remains (%)',
        OLD.id, v_state USING ERRCODE='PF001';
    END IF;
  END IF;
  -- Managed head guard: while the journal owns the branch, legacy manifest
  -- commits can never move its head. Exact head adoption (013+) runs inside
  -- owner-only SECURITY DEFINER functions, i.e. as portablefs_journal_owner.
  IF OLD.branch_mode IN ('managed_journal','migrating','retiring')
     AND NEW.head_commit_id IS DISTINCT FROM OLD.head_commit_id
     AND current_user <> 'portablefs_journal_owner' THEN
    RAISE EXCEPTION 'branch % is journal-managed (%); legacy manifest commits cannot move its head',
      OLD.id, OLD.branch_mode USING ERRCODE='PF001';
  END IF;
  RETURN NEW;
END;
$$;

-- ═══ SECTION B: pfj schema (journal owner) ═══════════════════════════════════
SET LOCAL ROLE portablefs_journal_owner;

-- branch_generation_state classifies one branch's nonterminal journal state
-- for the branch guard and the TS transition layer. Owner-executed SECURITY
-- DEFINER; EXECUTE is granted narrowly below.
CREATE FUNCTION pfj.branch_generation_state(p_branch_id TEXT) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_count BIGINT;
  g RECORD;
BEGIN
  SELECT COUNT(*) INTO v_count FROM pfj.journal_generations
    WHERE branch_id = p_branch_id AND status IN ('active','suspended','retiring');
  IF v_count = 0 THEN
    RETURN 'none';
  END IF;
  IF v_count > 1 THEN
    RAISE EXCEPTION 'branch % has % nonterminal journal generations', p_branch_id, v_count
      USING ERRCODE='PF010';
  END IF;
  SELECT record_codec, status INTO g FROM pfj.journal_generations
    WHERE branch_id = p_branch_id AND status IN ('active','suspended','retiring');
  RETURN CASE WHEN g.record_codec = 'pfj3' THEN 'pfj3_' ELSE 'legacy_' END || g.status;
END;
$$;

-- ─── immutable codec pairs ───────────────────────────────────────────────────

-- Drop the frozen single-codec CHECKs from 009 (names are system-assigned;
-- locate them by definition) and install the immutable pair constraint.
DO $$
DECLARE v_name TEXT;
BEGIN
  FOR v_name IN
    SELECT con.conname FROM pg_constraint con
    JOIN pg_class rel ON rel.oid=con.conrelid
    JOIN pg_namespace nsp ON nsp.oid=rel.relnamespace
    WHERE nsp.nspname='pfj' AND rel.relname='journal_generations'
      AND con.contype='c'
      AND (pg_get_constraintdef(con.oid) LIKE '%record_codec%'
        OR pg_get_constraintdef(con.oid) LIKE '%control_codec%')
  LOOP
    EXECUTE format(
      'ALTER TABLE pfj.journal_generations DROP CONSTRAINT %I',v_name);
  END LOOP;
END;
$$;

ALTER TABLE pfj.journal_generations
  ADD CONSTRAINT journal_generations_codec_pair_check CHECK (
    (record_codec='pfr1' AND control_codec='pfc1')
    OR (record_codec='pfj3' AND control_codec='pfc2'));

-- The PFC2 durable database-time floor: the maximum admission-fact time any
-- committed row of this generation carries. Appends advance it; issuance
-- binds it exactly.
ALTER TABLE pfj.journal_generations
  ADD COLUMN control_db_floor_ms BIGINT NOT NULL DEFAULT 0
  CONSTRAINT journal_generations_control_floor_check
    CHECK (control_db_floor_ms>=0);

-- The HA policy hash a PFJ3 generation was claimed under (drift = no ACK).
ALTER TABLE pfj.journal_generations
  ADD COLUMN ha_policy_hash TEXT
  CONSTRAINT journal_generations_ha_policy_hash_check
    CHECK (ha_policy_hash IS NULL OR ha_policy_hash ~ '^[0-9a-f]{64}$');

-- FK target so every record row is provably in its generation's codec.
ALTER TABLE pfj.journal_generations
  ADD CONSTRAINT journal_generations_id_codec_unique UNIQUE (id,record_codec);

-- Codec columns are UNCONDITIONALLY immutable, and a PFJ3 generation freezes
-- every legacy cut/trim/rotate/base surface until its own HistoryCut
-- machinery arrives with migration 013. There is deliberately NO escape
-- hatch of any kind.
CREATE FUNCTION pfj.journal_generations_freeze() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF NEW.record_codec IS DISTINCT FROM OLD.record_codec
     OR NEW.control_codec IS DISTINCT FROM OLD.control_codec THEN
    RAISE EXCEPTION
      'journal generation codecs are immutable; conversion is retire + new generation (migration 013)'
      USING ERRCODE='PF005';
  END IF;
  IF OLD.ha_policy_hash IS NOT NULL
     AND NEW.ha_policy_hash IS DISTINCT FROM OLD.ha_policy_hash THEN
    RAISE EXCEPTION 'journal generation HA policy binding is immutable'
      USING ERRCODE='PF001';
  END IF;
  IF NEW.control_db_floor_ms < OLD.control_db_floor_ms THEN
    RAISE EXCEPTION 'journal control floor can never regress' USING ERRCODE='PF010';
  END IF;
  IF OLD.record_codec='pfj3' THEN
    IF NEW.base_seq IS DISTINCT FROM OLD.base_seq
       OR NEW.base_digest IS DISTINCT FROM OLD.base_digest
       OR NEW.base_commit_id IS DISTINCT FROM OLD.base_commit_id
       OR NEW.physical_trimmed_seq IS DISTINCT FROM OLD.physical_trimmed_seq
       OR NEW.cut_operation_id IS DISTINCT FROM OLD.cut_operation_id
       OR NEW.cut_status IS DISTINCT FROM OLD.cut_status THEN
      RAISE EXCEPTION
        'legacy cut/trim/rotate is not defined for a PFJ3 generation (HistoryCut arrives with migration 013)'
        USING ERRCODE='PF005';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER journal_generations_freeze
  BEFORE UPDATE ON pfj.journal_generations
  FOR EACH ROW EXECUTE FUNCTION pfj.journal_generations_freeze();

-- New generations must agree with the authoritative branch mode: a pfr1 pair
-- may only be created on a legacy_manifest branch (a migrating branch RESUMES
-- its existing generation but never creates a new one), and a pfj3 pair only
-- on a provisioned managed_journal branch.
CREATE FUNCTION pfj.journal_generations_guard_branch_mode() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_mode TEXT;
BEGIN
  SELECT b.branch_mode INTO v_mode FROM public.branches b WHERE b.id=NEW.branch_id;
  IF v_mode IS NULL THEN
    RAISE EXCEPTION 'journal generation branch is gone' USING ERRCODE='PF007';
  END IF;
  IF NEW.record_codec='pfr1' AND v_mode<>'legacy_manifest' THEN
    RAISE EXCEPTION
      'branch mode is %; a new legacy pfr1/pfc1 generation is only created on legacy_manifest',
      v_mode USING ERRCODE='PF001';
  END IF;
  IF NEW.record_codec='pfj3' AND v_mode<>'managed_journal' THEN
    RAISE EXCEPTION
      'branch mode is %; a PFJ3/PFC2 generation requires authoritative managed_journal provisioning',
      v_mode USING ERRCODE='PF001';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER journal_generations_guard_branch_mode
  BEFORE INSERT ON pfj.journal_generations
  FOR EACH ROW EXECUTE FUNCTION pfj.journal_generations_guard_branch_mode();

-- ─── per-row codec identity + magic on journal records ──────────────────────

-- The DEFAULT stays 'pfr1' FOREVER: the 011 legacy append inserts without the
-- column and must keep working unchanged. The composite FK below is what
-- protects PFJ3 generations from mislabeled rows.
ALTER TABLE pfj.journal_records
  ADD COLUMN record_codec TEXT NOT NULL DEFAULT 'pfr1'
  CONSTRAINT journal_records_codec_check
    CHECK (record_codec IN ('pfr1','pfj3'));

-- Replace the PFR1-only magic CHECK with the codec-matched magic CHECK
-- (adding the constraint validates every retained pre-012 row: the backfill
-- proof that history is uniformly PFR1).
DO $$
DECLARE v_name TEXT;
BEGIN
  FOR v_name IN
    SELECT con.conname FROM pg_constraint con
    JOIN pg_class rel ON rel.oid=con.conrelid
    JOIN pg_namespace nsp ON nsp.oid=rel.relnamespace
    WHERE nsp.nspname='pfj' AND rel.relname='journal_records'
      AND con.contype='c'
      AND pg_get_constraintdef(con.oid) LIKE '%50465231%'
  LOOP
    EXECUTE format(
      'ALTER TABLE pfj.journal_records DROP CONSTRAINT %I',v_name);
  END LOOP;
END;
$$;

ALTER TABLE pfj.journal_records
  ADD CONSTRAINT journal_records_magic_check CHECK (
    (record_codec='pfr1'
      AND substring(payload FROM 1 FOR 4)='\x50465231'::BYTEA)
    OR (record_codec='pfj3'
      AND substring(payload FROM 1 FOR 4)='\x50464a33'::BYTEA));

ALTER TABLE pfj.journal_records
  ADD CONSTRAINT journal_records_generation_codec_fk
  FOREIGN KEY (generation_id,record_codec)
  REFERENCES pfj.journal_generations(id,record_codec)
  ON DELETE CASCADE;

-- ─── one lock order ──────────────────────────────────────────────────────────

-- Structured branch advisory locks. Mutations take the EXCLUSIVE lock; reads
-- take the SHARED lock; both precede every row lock. Keys are sorted before
-- acquisition (pfj.scope_locks already sorts; the shared variant mirrors it).
CREATE FUNCTION pfj.branch_lock_key(
  p_tenant_id TEXT, p_volume_id TEXT, p_branch_name TEXT
) RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
  SELECT jsonb_build_array('pfj-branch',p_tenant_id,p_volume_id,p_branch_name)::TEXT
$$;

CREATE FUNCTION pfj.scope_locks_shared(p_keys TEXT[]) RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_key BIGINT;
BEGIN
  FOR v_key IN
    SELECT DISTINCT hashtextextended(k,0)
    FROM unnest(p_keys) AS u(k) ORDER BY 1
  LOOP
    PERFORM pg_advisory_xact_lock_shared(v_key);
  END LOOP;
END;
$$;

-- branch_lock_for_generation resolves and takes the branch lock for a
-- generation-addressed mutation BEFORE the generation row lock.
CREATE FUNCTION pfj.branch_lock_for_generation(
  p_generation_id TEXT, p_exclusive BOOLEAN
) RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v RECORD;
BEGIN
  SELECT g.tenant_id, g.volume_id, b.name AS branch_name
    INTO v
    FROM pfj.journal_generations g
    JOIN public.branches b ON b.id=g.branch_id
    WHERE g.id=p_generation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found', p_generation_id USING ERRCODE='PF007';
  END IF;
  IF p_exclusive THEN
    PERFORM pfj.scope_locks(ARRAY[
      pfj.branch_lock_key(v.tenant_id,v.volume_id,v.branch_name)]);
  ELSE
    PERFORM pfj.scope_locks_shared(ARRAY[
      pfj.branch_lock_key(v.tenant_id,v.volume_id,v.branch_name)]);
  END IF;
END;
$$;

-- ─── canonical HA policy ─────────────────────────────────────────────────────

-- One policy row per (system identifier, database), in the ONE canonical
-- shape shared by the Go child (internal/hapolicy), the manager, and the ops
-- verification tooling:
--   { v:1, expectedSystemIdentifier, expectedDatabase,
--     minSynchronousCommit: on|remote_apply, minSyncStandbys,
--     standbyFailureDomains: { applicationName: domain, ... },
--     minDistinctFailureDomains }
-- The canonical BYTES are produced by the installer (deterministic JSON);
-- the database stores them verbatim, hashes exactly them, and parses a JSONB
-- copy for evaluation. policy_epoch is the monotone install counter the ops
-- audit reports as authorityPolicyEpoch.
CREATE TABLE pfj.ha_policies (
  system_identifier TEXT NOT NULL,
  database_name TEXT NOT NULL,
  policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 1),
  canonical_json TEXT NOT NULL CHECK (octet_length(canonical_json) BETWEEN 2 AND 8192),
  policy JSONB NOT NULL,
  policy_hash TEXT NOT NULL CHECK (policy_hash ~ '^[0-9a-f]{64}$'),
  installed_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (system_identifier, database_name)
);

-- ha_policy_shape_check validates the parsed canonical policy document.
CREATE FUNCTION pfj.ha_policy_shape_check(p JSONB) RETURNS void
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_names TEXT[];
  v_name TEXT;
  v_min_sync INT;
  v_min_domains INT;
BEGIN
  IF p IS NULL OR jsonb_typeof(p) <> 'object'
     OR (SELECT COUNT(*) FROM jsonb_object_keys(p)) <> 7
     OR p->>'v' IS DISTINCT FROM '1'
     OR COALESCE(length(p->>'expectedSystemIdentifier'),0) NOT BETWEEN 1 AND 64
     OR COALESCE(length(p->>'expectedDatabase'),0) NOT BETWEEN 1 AND 128
     OR p->>'minSynchronousCommit' NOT IN ('on','remote_apply')
     OR jsonb_typeof(p->'minSyncStandbys') <> 'number'
     OR (p->>'minSyncStandbys')::NUMERIC NOT BETWEEN 1 AND 16
     OR jsonb_typeof(p->'minDistinctFailureDomains') <> 'number'
     OR jsonb_typeof(p->'standbyFailureDomains') <> 'object' THEN
    RAISE EXCEPTION 'invalid HA policy shape' USING ERRCODE='PF008';
  END IF;
  v_min_sync := (p->>'minSyncStandbys')::INT;
  v_min_domains := (p->>'minDistinctFailureDomains')::INT;
  SELECT COALESCE(array_agg(k),'{}') INTO v_names
    FROM jsonb_object_keys(p->'standbyFailureDomains') AS u(k);
  IF array_length(v_names,1) IS NULL OR array_length(v_names,1) NOT BETWEEN 1 AND 16 THEN
    RAISE EXCEPTION 'HA policy standby mapping must contain 1..16 entries'
      USING ERRCODE='PF008';
  END IF;
  FOREACH v_name IN ARRAY v_names LOOP
    IF length(v_name) NOT BETWEEN 1 AND 63
       OR COALESCE(length(p->'standbyFailureDomains'->>v_name),0) NOT BETWEEN 1 AND 128 THEN
      RAISE EXCEPTION 'invalid HA policy standby entry' USING ERRCODE='PF008';
    END IF;
  END LOOP;
  IF v_min_domains < 1
     OR v_min_domains > (
       SELECT COUNT(DISTINCT p->'standbyFailureDomains'->>k)
       FROM jsonb_object_keys(p->'standbyFailureDomains') AS u(k)) THEN
    RAISE EXCEPTION 'HA policy domain minimum exceeds the mapped domains'
      USING ERRCODE='PF008';
  END IF;
END;
$$;

-- install_ha_policy is OWNER-ONLY (ops/manager provisioning path; no
-- authority grant). It takes the CANONICAL policy bytes, verifies the parsed
-- shape, pins expectedSystemIdentifier/expectedDatabase against live
-- evidence, hashes exactly the provided bytes, and bumps the monotone
-- policy epoch.
CREATE FUNCTION pfj.install_ha_policy(p_canonical_json TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_now BIGINT := pfj.now_ms();
  v_policy JSONB;
  v_system TEXT;
  v_hash TEXT;
  v_epoch BIGINT;
BEGIN
  IF p_canonical_json IS NULL
     OR octet_length(p_canonical_json) NOT BETWEEN 2 AND 8192 THEN
    RAISE EXCEPTION 'HA policy bytes are required (<= 8 KiB)' USING ERRCODE='PF008';
  END IF;
  v_policy := p_canonical_json::JSONB;
  PERFORM pfj.ha_policy_shape_check(v_policy);
  v_system := pfm.durability_evidence()->>'systemIdentifier';
  IF v_system IS NULL OR length(v_system)=0 THEN
    RAISE EXCEPTION 'HA policy: system identifier is unavailable; cannot bind a policy'
      USING ERRCODE='PF015';
  END IF;
  IF v_policy->>'expectedSystemIdentifier' IS DISTINCT FROM v_system
     OR v_policy->>'expectedDatabase' IS DISTINCT FROM current_database() THEN
    RAISE EXCEPTION 'HA policy names another cluster/database (policy %/%, live %/%)',
      v_policy->>'expectedSystemIdentifier', v_policy->>'expectedDatabase',
      v_system, current_database()
      USING ERRCODE='PF008';
  END IF;
  v_hash := encode(sha256(convert_to(p_canonical_json,'UTF8')),'hex');
  SELECT COALESCE(MAX(policy_epoch),0)+1 INTO v_epoch FROM pfj.ha_policies
    WHERE system_identifier=v_system AND database_name=current_database();
  INSERT INTO pfj.ha_policies(
    system_identifier,database_name,policy_epoch,canonical_json,policy,
    policy_hash,installed_at,updated_at)
  VALUES (v_system,current_database(),v_epoch,p_canonical_json,v_policy,
          v_hash,v_now,v_now)
  ON CONFLICT (system_identifier,database_name) DO UPDATE
    SET policy_epoch=EXCLUDED.policy_epoch,
        canonical_json=EXCLUDED.canonical_json,
        policy=EXCLUDED.policy,
        policy_hash=EXCLUDED.policy_hash,
        updated_at=EXCLUDED.updated_at;
  RETURN jsonb_build_object(
    'policyHash',v_hash,'policyEpoch',v_epoch::TEXT,'installedAt',v_now::TEXT);
END;
$$;

-- parse_synchronous_set decomposes synchronous_standby_names into the
-- configured set the ops audit reports: FIRST/ANY mode, required count, and
-- the sorted lowercased eligible application names. Unparseable or oversized
-- values fail closed (PF015): an unaccountable synchronous set is not
-- evidence.
CREATE FUNCTION pfj.parse_synchronous_set(p_names TEXT) RETURNS JSONB
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_raw TEXT := btrim(COALESCE(p_names,''));
  v_mode TEXT;
  v_count INT;
  v_list TEXT;
  v_names TEXT[];
  m TEXT[];
BEGIN
  IF v_raw = '' THEN
    RETURN jsonb_build_object(
      'mode','disabled','requiredCount',0,
      'eligibleApplicationNames',jsonb_build_array());
  END IF;
  m := regexp_match(v_raw,'^(?i)(FIRST|ANY)\s+([0-9]{1,2})\s*\((.*)\)$');
  IF m IS NOT NULL THEN
    v_mode := lower(m[1]);
    v_count := m[2]::INT;
    v_list := m[3];
  ELSE
    v_mode := 'first';
    v_count := 1;
    v_list := v_raw;
  END IF;
  SELECT COALESCE(array_agg(DISTINCT lower(pg_catalog.btrim(n, ' "')) ORDER BY lower(pg_catalog.btrim(n, ' "'))),'{}')
    INTO v_names
    FROM unnest(string_to_array(v_list,',')) AS u(n)
    WHERE pg_catalog.btrim(n) <> '';
  IF array_length(v_names,1) IS NULL OR array_length(v_names,1) > 16
     OR v_count < 1 OR v_count > array_length(v_names,1) THEN
    RAISE EXCEPTION 'synchronous standby set is not accountable (%s)', v_raw
      USING ERRCODE='PF015';
  END IF;
  RETURN jsonb_build_object(
    'mode',v_mode,'requiredCount',v_count,
    'eligibleApplicationNames',to_jsonb(v_names));
END;
$$;

-- ha_policy_verdict is the ONE evaluator every mutating path, readiness, and
-- the ops audit share. It never raises for a failing verdict — it reports —
-- and it evaluates the canonical policy fact by fact against the hardened
-- pfm.durability_evidence() reader: system identifier and database pins,
-- fsync/full_page_writes/primary/read-write, the commit-strength ratchet
-- (remote_apply satisfies on; on never satisfies remote_apply), the LIVE
-- sync/quorum streaming standbys matched against the attested name→domain
-- mapping, minimum count, and minimum distinct domains. The explicitly named
-- test bypass short-circuits to ok (hermetic tests only; production never
-- sets it).
CREATE FUNCTION pfj.ha_policy_verdict() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_policy pfj.ha_policies;
  v_ev JSONB;
  v_system TEXT;
  v_ok BOOLEAN := TRUE;
  v_matched INT := 0;
  v_domains TEXT[];
  v_name TEXT;
  v_standby JSONB;
  v_rank_observed INT;
  v_rank_required INT;
BEGIN
  v_ev := pfm.durability_evidence();
  v_system := v_ev->>'systemIdentifier';
  IF v_system IS NULL OR length(v_system)=0 THEN
    RETURN jsonb_build_object('installed',FALSE,'ok',FALSE,'evidence',v_ev);
  END IF;
  SELECT * INTO v_policy FROM pfj.ha_policies
    WHERE system_identifier=v_system AND database_name=current_database();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('installed',FALSE,'ok',FALSE,'evidence',v_ev);
  END IF;
  IF COALESCE((v_ev->>'testBypassActive')::BOOLEAN,FALSE) THEN
    RETURN jsonb_build_object(
      'installed',TRUE,'ok',TRUE,'bypass',TRUE,
      'policyHash',v_policy.policy_hash,
      'policyEpoch',v_policy.policy_epoch::TEXT,
      'canonicalJson',v_policy.canonical_json,
      'evidence',v_ev);
  END IF;
  IF v_policy.policy->>'expectedSystemIdentifier' IS DISTINCT FROM v_system
     OR v_policy.policy->>'expectedDatabase' IS DISTINCT FROM current_database() THEN
    v_ok := FALSE;
  END IF;
  v_rank_required := CASE v_policy.policy->>'minSynchronousCommit'
    WHEN 'on' THEN 1 WHEN 'remote_apply' THEN 2 ELSE 3 END;
  v_rank_observed := CASE v_ev->>'synchronousCommit'
    WHEN 'on' THEN 1 WHEN 'remote_apply' THEN 2 ELSE 0 END;
  IF v_ev->>'fsync' IS DISTINCT FROM 'on'
     OR v_ev->>'fullPageWrites' IS DISTINCT FROM 'on'
     OR COALESCE((v_ev->>'inRecovery')::BOOLEAN,TRUE)
     OR v_ev->>'transactionReadOnly' IS DISTINCT FROM 'off'
     OR v_rank_observed < v_rank_required
     OR btrim(COALESCE(v_ev->>'synchronousStandbyNames','')) = ''
     OR NOT COALESCE((v_ev->>'replicationVisible')::BOOLEAN,FALSE) THEN
    v_ok := FALSE;
  END IF;
  FOR v_name IN SELECT k FROM jsonb_object_keys(v_policy.policy->'standbyFailureDomains') AS u(k)
  LOOP
    FOR v_standby IN SELECT * FROM jsonb_array_elements(COALESCE(v_ev->'standbys','[]'::JSONB))
    LOOP
      IF lower(v_standby->>'applicationName') = lower(v_name)
         AND v_standby->>'state' = 'streaming'
         AND v_standby->>'syncState' IN ('sync','quorum') THEN
        v_matched := v_matched + 1;
        v_domains := array_append(
          v_domains, v_policy.policy->'standbyFailureDomains'->>v_name);
        EXIT;
      END IF;
    END LOOP;
  END LOOP;
  IF v_matched < (v_policy.policy->>'minSyncStandbys')::INT
     OR COALESCE((SELECT COUNT(DISTINCT d) FROM unnest(v_domains) AS u(d)),0)
        < (v_policy.policy->>'minDistinctFailureDomains')::INT THEN
    v_ok := FALSE;
  END IF;
  RETURN jsonb_build_object(
    'installed',TRUE,'ok',v_ok,
    'policyHash',v_policy.policy_hash,
    'policyEpoch',v_policy.policy_epoch::TEXT,
    'canonicalJson',v_policy.canonical_json,
    'matchedSyncStandbys',v_matched,
    'evidence',v_ev);
END;
$$;

-- evaluate_ha_policy is the raising form for admission paths: a missing
-- policy or a failing verdict is PF015 (no ACK).
CREATE FUNCTION pfj.evaluate_ha_policy() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v JSONB;
BEGIN
  v := pfj.ha_policy_verdict();
  IF NOT COALESCE((v->>'installed')::BOOLEAN,FALSE) THEN
    RAISE EXCEPTION 'no canonical HA policy is installed for this cluster/database'
      USING ERRCODE='PF015', DETAIL=COALESCE((v->'evidence')::TEXT,'{}');
  END IF;
  IF NOT COALESCE((v->>'ok')::BOOLEAN,FALSE) THEN
    RAISE EXCEPTION 'HA policy is not satisfied by live durability evidence'
      USING ERRCODE='PF015', DETAIL=COALESCE((v->'evidence')::TEXT,'{}');
  END IF;
  RETURN v;
END;
$$;

-- production_durability_audit is the owner-controlled read surface the ops
-- verification collector consumes: the SAME verdict the mutating paths and
-- readiness use, the persisted canonical policy (bytes + hash + epoch), and
-- the observed facts including the parsed configured synchronous set.
-- Bounded, SECURITY DEFINER, owner pfj, least ACL (ops/admin only — never
-- the authority role).
CREATE FUNCTION pfj.production_durability_audit() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v JSONB;
  v_ev JSONB;
BEGIN
  v := pfj.ha_policy_verdict();
  IF NOT COALESCE((v->>'installed')::BOOLEAN,FALSE) THEN
    RAISE EXCEPTION 'production durability audit requires an installed HA policy'
      USING ERRCODE='PF015';
  END IF;
  v_ev := v->'evidence';
  RETURN jsonb_build_object(
    'v',1,
    'ok',COALESCE((v->>'ok')::BOOLEAN,FALSE),
    'authorityPolicyEpoch',v->>'policyEpoch',
    'dbTimeMs',v_ev->>'dbTimeMs',
    'persistedPolicy',jsonb_build_object(
      'v',1,
      'canonicalSha256',v->>'policyHash',
      'canonicalJson',(v->>'canonicalJson')::JSONB),
    'observed',jsonb_build_object(
      'systemIdentifier',v_ev->'systemIdentifier',
      'database',v_ev->>'database',
      'fsync',v_ev->>'fsync',
      'fullPageWrites',v_ev->>'fullPageWrites',
      'synchronousCommit',v_ev->>'synchronousCommit',
      'synchronousStandbyNames',COALESCE(v_ev->>'synchronousStandbyNames',''),
      'inRecovery',COALESCE((v_ev->>'inRecovery')::BOOLEAN,TRUE),
      'transactionReadOnly',v_ev->>'transactionReadOnly',
      'replicationVisible',COALESCE((v_ev->>'replicationVisible')::BOOLEAN,FALSE),
      'ready',COALESCE((v_ev->>'ready')::BOOLEAN,FALSE),
      'testBypassActive',COALESCE((v_ev->>'testBypassActive')::BOOLEAN,FALSE),
      'configuredSynchronousSet',
        pfj.parse_synchronous_set(v_ev->>'synchronousStandbyNames'),
      'standbys',COALESCE(v_ev->'standbys','[]'::JSONB)));
END;
$$;

-- require_ha_policy evaluates the live policy AND pins the generation to the
-- exact policy hash it was claimed under: drift is a PF015, never an ACK.
CREATE FUNCTION pfj.require_ha_policy(g pfj.journal_generations) RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v JSONB;
BEGIN
  v := pfj.evaluate_ha_policy();
  IF g.record_codec='pfj3'
     AND (g.ha_policy_hash IS NULL
          OR g.ha_policy_hash IS DISTINCT FROM v->>'policyHash') THEN
    RAISE EXCEPTION 'HA policy drift: generation was claimed under % but the installed policy is %',
      COALESCE(g.ha_policy_hash,'<none>'), v->>'policyHash'
      USING ERRCODE='PF015';
  END IF;
END;
$$;

-- ─── capability-bound short-lived admission time facts ───────────────────────

-- purpose: 1=session-open 2=session-renew 3=session-expiry-decision (must
-- match the PFJ3 manifest purpose byte exactly).
CREATE TABLE pfj.admission_facts (
  fact_id BYTEA PRIMARY KEY
    CONSTRAINT admission_facts_id_shape_check CHECK (
      octet_length(fact_id)=16
      AND fact_id<>'\x00000000000000000000000000000000'::BYTEA),
  generation_id TEXT NOT NULL
    REFERENCES pfj.journal_generations(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  purpose SMALLINT NOT NULL CHECK (purpose BETWEEN 1 AND 3),
  session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 128),
  session_generation BIGINT NOT NULL CHECK (session_generation>=1),
  writer_capability_hash TEXT NOT NULL
    CHECK (writer_capability_hash ~ '^[0-9a-f]{64}$'),
  issued_db_ms BIGINT NOT NULL CHECK (issued_db_ms>0),
  expires_db_ms BIGINT NOT NULL CHECK (expires_db_ms>issued_db_ms),
  created_at BIGINT NOT NULL
);

CREATE INDEX admission_facts_generation_idx
  ON pfj.admission_facts(generation_id,expires_db_ms);

-- cleanup_expired_facts: bounded deletion of unused expired facts (an unused
-- fact is pure garbage once expired; consumption itself DELETES rows, so
-- everything left past expiry is unconsumed by construction).
CREATE FUNCTION pfj.cleanup_expired_facts(p_generation_id TEXT, p_now BIGINT)
RETURNS void
LANGUAGE sql
SET search_path=pg_catalog,pg_temp
AS $$
  DELETE FROM pfj.admission_facts f
  WHERE f.fact_id IN (
    SELECT f2.fact_id FROM pfj.admission_facts f2
    WHERE f2.generation_id=p_generation_id AND f2.expires_db_ms<=p_now
    LIMIT 64);
$$;

-- admission_fact_issue mints one fact for the EXACT writer under the same
-- proofs and lock order as an append. The issuer must present the durable
-- control floor EXACTLY; any other value fails closed (PF002) so a fact can
-- never be minted against superseded or speculative control state.
CREATE FUNCTION pfj.admission_fact_issue(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_purpose SMALLINT,
  p_session_id TEXT,
  p_session_generation BIGINT,
  p_prior_control_floor_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT;
  v_id BYTEA;
  v_ttl_ms CONSTANT BIGINT:=30000;
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_capability IS NULL OR length(p_capability) NOT BETWEEN 32 AND 512
     OR p_purpose IS NULL OR p_purpose NOT BETWEEN 1 AND 3
     OR p_session_id IS NULL OR length(p_session_id) NOT BETWEEN 1 AND 128
     OR p_session_generation IS NULL OR p_session_generation<1
     OR p_prior_control_floor_ms IS NULL OR p_prior_control_floor_ms<0 THEN
    RAISE EXCEPTION 'invalid admission fact arguments' USING ERRCODE='PF008';
  END IF;
  -- One lock order: branch advisory (exclusive: this call mutates), then the
  -- generation row, then require_writer's branch/session/lease rows, then the
  -- manager binding, then the HA policy, then the mutation.
  PERFORM pfj.branch_lock_for_generation(p_generation_id, TRUE);
  g:=pfj.lock_generation(p_generation_id);
  IF g.record_codec<>'pfj3' THEN
    RAISE EXCEPTION 'admission facts exist only for PFJ3/PFC2 generations'
      USING ERRCODE='PF005';
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    g.record_codec,g.control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  PERFORM pfj.require_ha_policy(g);
  IF p_prior_control_floor_ms IS DISTINCT FROM g.control_db_floor_ms THEN
    RAISE EXCEPTION 'issuer control floor does not equal the durable floor'
      USING ERRCODE='PF002',
            DETAIL=jsonb_build_object(
              'controlDbFloorMs',g.control_db_floor_ms::TEXT)::TEXT;
  END IF;
  v_now:=pfj.now_ms();
  IF v_now<g.control_db_floor_ms THEN
    RAISE EXCEPTION 'database time is behind the committed control floor'
      USING ERRCODE='PF010';
  END IF;
  v_id:=uuid_send(gen_random_uuid());
  INSERT INTO pfj.admission_facts(
    fact_id,generation_id,tenant_id,volume_id,branch_id,purpose,
    session_id,session_generation,writer_capability_hash,
    issued_db_ms,expires_db_ms,created_at)
  VALUES (
    v_id,g.id,g.tenant_id,g.volume_id,g.branch_id,p_purpose,
    p_session_id,p_session_generation,
    encode(sha256(convert_to(p_capability,'UTF8')),'hex'),
    v_now,v_now+v_ttl_ms,v_now);
  PERFORM pfj.cleanup_expired_facts(g.id,v_now);
  RETURN jsonb_build_object(
    'factId',encode(v_id,'hex'),
    'issuedDbMs',v_now::TEXT,
    'factExpiresDbMs',(v_now+v_ttl_ms)::TEXT,
    'controlDbFloorMs',g.control_db_floor_ms::TEXT);
END;
$$;

-- ─── PFJ3 preamble parsing (SQL side of the frozen envelope) ────────────────

-- parse_pfj3_manifest parses ONE payload's fixed preamble: magic, outer LSN
-- (must equal p_expected_lsn), fact count, manifest digest (recomputed over
-- the exact entry bytes), and each ordered entry. Everything is bounded
-- before any allocation-ish work: count<=128, session ids 1..128 bytes.
CREATE FUNCTION pfj.parse_pfj3_manifest(
  p_payload BYTEA,
  p_expected_lsn BIGINT
) RETURNS TABLE (
  entry_index INT,
  control_index INT,
  purpose SMALLINT,
  session_id TEXT,
  session_generation BIGINT,
  fact_id BYTEA,
  db_ms BIGINT
)
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_len INT := octet_length(p_payload);
  v_lsn NUMERIC := 0;
  v_count INT;
  v_digest BYTEA;
  v_entries BYTEA;
  v_off INT; -- 0-based offset
  v_id_len INT;
  v_gen NUMERIC;
  v_ms NUMERIC;
  i INT;
  j INT;
BEGIN
  IF v_len < 46 OR substring(p_payload FROM 1 FOR 4) <> '\x50464a33'::BYTEA THEN
    RAISE EXCEPTION 'payload is not a PFJ3 entry' USING ERRCODE='PF005';
  END IF;
  FOR j IN 4..11 LOOP
    v_lsn := v_lsn*256 + get_byte(p_payload,j);
  END LOOP;
  IF v_lsn > 9223372036854775807::NUMERIC OR v_lsn::BIGINT IS DISTINCT FROM p_expected_lsn THEN
    RAISE EXCEPTION 'PFJ3 preamble LSN % does not equal the row LSN %', v_lsn, p_expected_lsn
      USING ERRCODE='PF002';
  END IF;
  v_count := get_byte(p_payload,12)*256 + get_byte(p_payload,13);
  IF v_count > 128 THEN
    RAISE EXCEPTION 'PFJ3 manifest declares % facts (max 128)', v_count USING ERRCODE='PF004';
  END IF;
  v_digest := substring(p_payload FROM 15 FOR 32);
  v_off := 46;
  FOR i IN 0..v_count-1 LOOP
    IF v_len < v_off+4 THEN
      RAISE EXCEPTION 'PFJ3 manifest entry % is truncated', i USING ERRCODE='PF008';
    END IF;
    v_id_len := get_byte(p_payload,v_off+3);
    IF v_id_len < 1 OR v_id_len > 128 OR v_len < v_off+36+v_id_len THEN
      RAISE EXCEPTION 'PFJ3 manifest entry % has invalid shape', i USING ERRCODE='PF008';
    END IF;
    entry_index := i;
    control_index := get_byte(p_payload,v_off)*256 + get_byte(p_payload,v_off+1);
    purpose := get_byte(p_payload,v_off+2)::SMALLINT;
    IF purpose NOT BETWEEN 1 AND 3 THEN
      RAISE EXCEPTION 'PFJ3 manifest entry % purpose % is unknown', i, purpose
        USING ERRCODE='PF008';
    END IF;
    session_id := convert_from(substring(p_payload FROM v_off+5 FOR v_id_len),'UTF8');
    v_gen := 0;
    FOR j IN v_off+4+v_id_len..v_off+11+v_id_len LOOP
      v_gen := v_gen*256 + get_byte(p_payload,j);
    END LOOP;
    IF v_gen < 1 OR v_gen > 9223372036854775807::NUMERIC THEN
      RAISE EXCEPTION 'PFJ3 manifest entry % session generation is invalid', i
        USING ERRCODE='PF008';
    END IF;
    session_generation := v_gen::BIGINT;
    fact_id := substring(p_payload FROM v_off+13+v_id_len FOR 16);
    IF fact_id = '\x00000000000000000000000000000000'::BYTEA THEN
      RAISE EXCEPTION 'PFJ3 manifest entry % fact id is all-zero', i USING ERRCODE='PF008';
    END IF;
    v_ms := 0;
    FOR j IN v_off+28+v_id_len..v_off+35+v_id_len LOOP
      v_ms := v_ms*256 + get_byte(p_payload,j);
    END LOOP;
    IF v_ms < 1 OR v_ms > 253402300799999::NUMERIC THEN
      RAISE EXCEPTION 'PFJ3 manifest entry % database time is implausible', i
        USING ERRCODE='PF008';
    END IF;
    db_ms := v_ms::BIGINT;
    v_off := v_off + 36 + v_id_len;
    RETURN NEXT;
  END LOOP;
  v_entries := substring(p_payload FROM 47 FOR v_off-46);
  IF v_count = 0 THEN
    v_entries := ''::BYTEA;
  END IF;
  IF sha256('PFJ3-FACTS'::BYTEA || '\x00'::BYTEA
            || substring(p_payload FROM 13 FOR 2) || v_entries) <> v_digest THEN
    RAISE EXCEPTION 'PFJ3 manifest digest does not cover its entries' USING ERRCODE='PF002';
  END IF;
  RETURN;
END;
$$;

-- ─── PFJ3 append: entries + fact consumption in one fenced transaction ──────

CREATE FUNCTION pfj.journal_append_v3(
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
  g pfj.journal_generations;
  v_receipt pfj.journal_append_receipts;
  v_count INT;
  v_total_bytes BIGINT:=0;
  v_total_facts INT:=0;
  v_chain TEXT;
  v_hash TEXT;
  v_fingerprint TEXT;
  v_capability_hash TEXT;
  v_payload_facts JSONB;
  v_response JSONB;
  v_now BIGINT;
  v_seq BIGINT;
  v_rows BIGINT;
  v_floor BIGINT;
  v_running_floor BIGINT;
  v_fact pfj.admission_facts;
  m RECORD;
  i INT;
BEGIN
  PERFORM pfj.require_txn_settings();
  -- Explicit NULL/shape rejection before any comparison: SQL three-valued
  -- logic (`x <> NULL`) must never authorize anything.
  IF p_capability IS NULL OR length(p_capability) NOT BETWEEN 32 AND 512 THEN
    RAISE EXCEPTION 'append capability must be 32..512 characters'
      USING ERRCODE='PF008';
  END IF;
  IF p_payloads IS NULL OR array_ndims(p_payloads)<>1
     OR array_lower(p_payloads,1)<>1
     OR p_record_hashes IS NULL OR array_ndims(p_record_hashes)<>1
     OR array_lower(p_record_hashes,1)<>1 THEN
    RAISE EXCEPTION 'append arrays must be one-dimensional and 1-based'
      USING ERRCODE='PF008';
  END IF;
  v_count:=COALESCE(array_length(p_payloads,1),0);
  IF v_count NOT BETWEEN 1 AND 128
     OR COALESCE(array_length(p_record_hashes,1),0)<>v_count THEN
    RAISE EXCEPTION 'append group count is invalid' USING ERRCODE='PF004';
  END IF;
  IF p_first_seq IS NULL OR p_first_seq<0
     OR p_first_seq>9223372036854775807::BIGINT-v_count::BIGINT THEN
    RAISE EXCEPTION 'append sequence range is invalid' USING ERRCODE='PF004';
  END IF;
  IF p_end_tip IS NULL OR p_end_tip!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'append end tip is invalid' USING ERRCODE='PF008';
  END IF;
  FOR i IN 1..v_count LOOP
    IF p_payloads[i] IS NULL OR octet_length(p_payloads[i])<46 THEN
      RAISE EXCEPTION 'append payload is truncated' USING ERRCODE='PF008';
    END IF;
    IF octet_length(p_payloads[i])>8388608 THEN
      RAISE EXCEPTION 'append record exceeds 8 MiB' USING ERRCODE='PF004';
    END IF;
    IF substring(p_payloads[i] FROM 1 FOR 4)<>'\x50464a33'::BYTEA THEN
      RAISE EXCEPTION 'append record is not PFJ3' USING ERRCODE='PF005';
    END IF;
    IF p_record_hashes[i] IS NULL
       OR p_record_hashes[i]!~'^[0-9a-f]{64}$' THEN
      RAISE EXCEPTION 'append record hash is invalid' USING ERRCODE='PF008';
    END IF;
    v_total_bytes:=pfj.checked_add(
      v_total_bytes,octet_length(p_payloads[i])::BIGINT,'append byte count');
  END LOOP;
  IF v_total_bytes>16777216 THEN
    RAISE EXCEPTION 'append group exceeds 16 MiB' USING ERRCODE='PF004';
  END IF;
  SELECT jsonb_agg(jsonb_build_object(
      'length',octet_length(u.payload)::TEXT,
      'sha256',encode(sha256(u.payload),'hex')) ORDER BY u.ordinality)
    INTO v_payload_facts
    FROM unnest(p_payloads) WITH ORDINALITY AS u(payload,ordinality);
  v_fingerprint:=encode(sha256(convert_to(jsonb_build_array(
    'pfj-append-group-v3',p_generation_id,p_epoch::TEXT,p_lease_id,
    p_fencing_token::TEXT,'pfj3','pfc2',p_first_seq::TEXT,
    v_count::TEXT,v_payload_facts,to_jsonb(p_record_hashes),p_end_tip
  )::TEXT,'UTF8')),'hex');
  v_capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  -- One lock order: exclusive branch advisory, then the generation row.
  PERFORM pfj.branch_lock_for_generation(p_generation_id, TRUE);
  g:=pfj.lock_generation(p_generation_id);
  IF g.record_codec<>'pfj3' OR g.control_codec<>'pfc2' THEN
    RAISE EXCEPTION 'journal_append_v3 requires a PFJ3/PFC2 generation'
      USING ERRCODE='PF005';
  END IF;
  -- Exact durable receipt precedes live validation AND fact consumption: an
  -- ambiguous committed append replays identically even after its facts
  -- expired or were deleted — the original commit consumed them, and the
  -- replay is fact-free by construction.
  SELECT * INTO v_receipt FROM pfj.journal_append_receipts
    WHERE generation_id=p_generation_id AND first_seq=p_first_seq;
  IF FOUND THEN
    IF v_receipt.writer_capability_hash IS DISTINCT FROM v_capability_hash THEN
      RAISE EXCEPTION 'append receipt capability rejected'
        USING ERRCODE='PF001';
    END IF;
    IF v_receipt.record_count<>v_count
       OR v_receipt.request_fingerprint<>v_fingerprint THEN
      RAISE EXCEPTION 'append group content conflicts with durable receipt'
        USING ERRCODE='PF002';
    END IF;
    IF v_receipt.response IS NULL THEN
      RAISE EXCEPTION 'append receipt body was compacted'
        USING ERRCODE='PF014',
              DETAIL=jsonb_build_object(
                'generationId',g.id,
                'receiptFloorSeq',g.append_receipt_floor_seq::TEXT)::TEXT;
    END IF;
    RETURN v_receipt.response||jsonb_build_object(
      'replayed',TRUE,
      'currentBaseCommitId',g.base_commit_id,
      'currentBaseSeq',g.base_seq::TEXT,
      'currentBaseDigest',g.base_digest,
      'currentPhysicalTrimmedSeq',g.physical_trimmed_seq::TEXT,
      'currentBacklogBytes',g.backlog_bytes::TEXT,
      'currentBacklogRecords',g.backlog_records::TEXT,
      'currentQuotaBacklogBytes',g.quota_backlog_bytes::TEXT,
      'currentQuotaBacklogRecords',g.quota_backlog_records::TEXT,
      'currentControlDbFloorMs',g.control_db_floor_ms::TEXT,
      'currentCut',pfj.generation_json(g)->'cut');
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    'pfj3','pfc2');
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  PERFORM pfj.require_ha_policy(g);
  IF p_first_seq<g.append_receipt_floor_seq THEN
    RAISE EXCEPTION 'append receipt is below retained floor'
      USING ERRCODE='PF014',
            DETAIL=jsonb_build_object(
              'generationId',g.id,
              'receiptFloorSeq',g.append_receipt_floor_seq::TEXT)::TEXT;
  END IF;
  IF p_first_seq<g.next_seq THEN
    RAISE EXCEPTION 'append overlaps head without its exact receipt'
      USING ERRCODE='PF010',
            DETAIL=jsonb_build_object(
              'generationId',g.id,'nextSeq',g.next_seq::TEXT,
              'receiptFloorSeq',g.append_receipt_floor_seq::TEXT)::TEXT;
  END IF;
  IF p_first_seq>g.next_seq THEN
    RAISE EXCEPTION 'append has a gap' USING ERRCODE='PF006';
  END IF;
  -- Quota: the DATA quota plus the fixed hidden CONTROL RESERVE headroom
  -- (8 MiB / 8192 rows). The reserve exists so control-only rows — durable
  -- rejection outcomes (EDQUOT itself), session renew/terminal, lock
  -- releases, unpins, barriers — stay journalable at data-quota exhaustion:
  -- exactness and fencing are never unrecordable. The authority classifies
  -- row classes exactly (tree-bearing appends stop at the data quota
  -- client-side); this transactional check is defense in depth with the
  -- reserve included, and the accounting-corruption guard tolerates a
  -- backlog inside the reserve band.
  IF g.backlog_bytes>g.quota_backlog_bytes+8388608
     OR g.backlog_records>g.quota_backlog_records+8192 THEN
    RAISE EXCEPTION 'journal backlog accounting is corrupt'
      USING ERRCODE='PF010';
  END IF;
  IF v_total_bytes>(g.quota_backlog_bytes+8388608)-g.backlog_bytes
     OR v_count>(g.quota_backlog_records+8192)-g.backlog_records THEN
    RAISE EXCEPTION 'journal backlog quota exceeded'
      USING ERRCODE='PF003',
            DETAIL=jsonb_build_object(
              'backlogBytes',g.backlog_bytes::TEXT,
              'backlogRecords',g.backlog_records::TEXT,
              'quotaBacklogBytes',g.quota_backlog_bytes::TEXT,
              'quotaBacklogRecords',g.quota_backlog_records::TEXT,
              'controlReserveBytes','8388608',
              'controlReserveRecords','8192',
              'additionalBytes',v_total_bytes::TEXT,
              'additionalRecords',v_count::TEXT)::TEXT;
  END IF;
  -- Verify every caller hash and the complete chain before the durability
  -- probe and the mutation.
  v_chain:=g.tip_digest;
  FOR i IN 1..v_count LOOP
    v_hash:=pfj.chain_step(pfj.zero_digest(),p_payloads[i]);
    IF p_record_hashes[i]<>v_hash THEN
      RAISE EXCEPTION 'append record hash mismatch' USING ERRCODE='PF002';
    END IF;
    v_chain:=pfj.chain_step(v_chain,p_payloads[i]);
  END LOOP;
  IF v_chain<>p_end_tip THEN
    RAISE EXCEPTION 'append end tip mismatch' USING ERRCODE='PF002';
  END IF;
  PERFORM pfj.require_durable_primary();
  -- Lease/runtime/policy validity is sampled after the potentially slow probe.
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,'pfj3','pfc2');
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  PERFORM pfj.require_ha_policy(g);
  v_now:=pfj.now_ms();
  -- Validate and consume (DELETE) every fact the PFJ3 bytes themselves name,
  -- in exact manifest order across the group. Any omitted, extra, reordered,
  -- cross-session, wrong-purpose, expired, foreign, or reused fact fails the
  -- whole transaction; the bytes are the ONLY source of the fact list.
  v_running_floor:=g.control_db_floor_ms;
  FOR i IN 1..v_count LOOP
    v_seq:=p_first_seq+i-1;
    FOR m IN
      SELECT * FROM pfj.parse_pfj3_manifest(p_payloads[i],v_seq)
      ORDER BY entry_index
    LOOP
      v_total_facts:=v_total_facts+1;
      IF v_total_facts>128 THEN
        RAISE EXCEPTION 'append group consumes more than 128 admission facts'
          USING ERRCODE='PF004';
      END IF;
      DELETE FROM pfj.admission_facts f WHERE f.fact_id=m.fact_id
        RETURNING * INTO v_fact;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'admission fact is unknown, already consumed, or cleaned up'
          USING ERRCODE='PF001';
      END IF;
      IF v_fact.generation_id IS DISTINCT FROM g.id THEN
        RAISE EXCEPTION 'admission fact belongs to another generation scope'
          USING ERRCODE='PF001';
      END IF;
      IF v_fact.writer_capability_hash IS DISTINCT FROM v_capability_hash THEN
        RAISE EXCEPTION 'admission fact belongs to another capability'
          USING ERRCODE='PF001';
      END IF;
      IF v_fact.purpose IS DISTINCT FROM m.purpose THEN
        RAISE EXCEPTION 'admission fact purpose does not match the manifest'
          USING ERRCODE='PF002';
      END IF;
      IF v_fact.session_id IS DISTINCT FROM m.session_id
         OR v_fact.session_generation IS DISTINCT FROM m.session_generation THEN
        RAISE EXCEPTION 'admission fact subject session does not match the manifest'
          USING ERRCODE='PF002';
      END IF;
      IF v_fact.issued_db_ms IS DISTINCT FROM m.db_ms THEN
        RAISE EXCEPTION 'frozen fact time differs from the issued fact'
          USING ERRCODE='PF002';
      END IF;
      IF v_fact.expires_db_ms<=v_now THEN
        RAISE EXCEPTION 'admission fact expired unused' USING ERRCODE='PF001';
      END IF;
      IF v_fact.issued_db_ms>v_now THEN
        RAISE EXCEPTION 'admission fact is from the future' USING ERRCODE='PF010';
      END IF;
      IF v_fact.issued_db_ms<v_running_floor THEN
        RAISE EXCEPTION 'admission fact is behind the committed control floor'
          USING ERRCODE='PF002';
      END IF;
      IF v_fact.issued_db_ms>v_running_floor THEN
        v_running_floor:=v_fact.issued_db_ms;
      END IF;
    END LOOP;
  END LOOP;
  v_chain:=g.tip_digest;
  FOR i IN 1..v_count LOOP
    v_seq:=p_first_seq+i-1;
    v_hash:=pfj.chain_step(pfj.zero_digest(),p_payloads[i]);
    v_chain:=pfj.chain_step(v_chain,p_payloads[i]);
    INSERT INTO pfj.journal_records(
      generation_id,seq,payload,payload_bytes,record_hash,chain_digest,
      record_codec,created_at)
    VALUES (
      g.id,v_seq,p_payloads[i],octet_length(p_payloads[i]),
      v_hash,v_chain,'pfj3',v_now);
  END LOOP;
  UPDATE pfj.journal_generations SET
    next_seq=p_first_seq+v_count,tip_digest=p_end_tip,
    backlog_bytes=backlog_bytes+v_total_bytes,
    backlog_records=backlog_records+v_count,
    control_db_floor_ms=v_running_floor,
    updated_at=v_now
    WHERE id=g.id RETURNING * INTO g;
  GET DIAGNOSTICS v_rows=ROW_COUNT;
  IF v_rows<>1 THEN
    RAISE EXCEPTION 'append lost its locked generation' USING ERRCODE='PF010';
  END IF;
  PERFORM pfj.cleanup_expired_facts(g.id,v_now);
  v_response:=jsonb_build_object(
    'generationId',g.id,'epoch',g.epoch::TEXT,
    'nextSeq',g.next_seq::TEXT,'tipDigest',g.tip_digest,
    'backlogBytes',g.backlog_bytes::TEXT,
    'backlogRecords',g.backlog_records::TEXT,
    'appended',v_count::TEXT,'duplicated','0');
  INSERT INTO pfj.journal_append_receipts(
    generation_id,first_seq,record_count,request_fingerprint,
    writer_capability_hash,response,created_at)
  VALUES (
    g.id,p_first_seq,v_count,v_fingerprint,v_capability_hash,v_response,v_now);
  WITH compact AS (
    SELECT first_seq FROM pfj.journal_append_receipts
    WHERE generation_id=g.id AND response IS NOT NULL
    ORDER BY first_seq DESC OFFSET 1024 LIMIT 128
  )
  UPDATE pfj.journal_append_receipts r SET response=NULL
    FROM compact c
    WHERE r.generation_id=g.id AND r.first_seq=c.first_seq;
  SELECT COALESCE(MIN(first_seq),g.next_seq) INTO v_floor
    FROM pfj.journal_append_receipts
    WHERE generation_id=g.id AND response IS NOT NULL;
  UPDATE pfj.journal_generations SET
    append_receipt_floor_seq=GREATEST(append_receipt_floor_seq,v_floor)
    WHERE id=g.id RETURNING * INTO g;
  RETURN v_response||jsonb_build_object(
    'replayed',FALSE,
    'currentBaseCommitId',g.base_commit_id,
    'currentBaseSeq',g.base_seq::TEXT,
    'currentBaseDigest',g.base_digest,
    'currentPhysicalTrimmedSeq',g.physical_trimmed_seq::TEXT,
    'currentBacklogBytes',g.backlog_bytes::TEXT,
    'currentBacklogRecords',g.backlog_records::TEXT,
    'currentQuotaBacklogBytes',g.quota_backlog_bytes::TEXT,
    'currentQuotaBacklogRecords',g.quota_backlog_records::TEXT,
    'currentControlDbFloorMs',g.control_db_floor_ms::TEXT,
    'currentCut',pfj.generation_json(g)->'cut');
END;
$$;

-- ─── pair-aware claim core + fixed wrappers ──────────────────────────────────

-- Claim receipts learn their codec pair (older rows stay NULL and validate
-- through the legacy fingerprint fallback below).
ALTER TABLE pfj.journal_claim_receipts
  ADD COLUMN record_codec TEXT
  CONSTRAINT journal_claim_receipts_record_codec_check
    CHECK (record_codec IS NULL OR record_codec IN ('pfr1','pfj3'));
ALTER TABLE pfj.journal_claim_receipts
  ADD COLUMN control_codec TEXT
  CONSTRAINT journal_claim_receipts_control_codec_check
    CHECK (control_codec IS NULL OR control_codec IN ('pfc1','pfc2'));

-- journal_claim_core is OWNER-ONLY (never granted): one pair-aware claim
-- implementation behind both fixed public wrappers. It enforces the single
-- lock order, validates the requested codec pair against the live generation
-- BEFORE touching any writer/fence state (an N-1 legacy claim against a PFJ3
-- generation must never fence it), requires the branch mode that authorizes
-- the pair, inserts fresh generations directly with their final pair, binds
-- the pair into the receipt fingerprint and row, and stamps the HA policy
-- hash on PFJ3 generations.
CREATE FUNCTION pfj.journal_claim_core(
  p_operation_id TEXT,
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_attach_session_id TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_holder_id TEXT,
  p_authority_instance_id TEXT,
  p_capability TEXT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_expected_base_commit_id TEXT,
  p_quota_backlog_bytes BIGINT,
  p_quota_backlog_records BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_tenant TEXT;
  v_fingerprint TEXT;
  v_legacy_fingerprint TEXT;
  v_capability_hash TEXT;
  v_receipt pfj.journal_claim_receipts;
  v_receipt_found BOOLEAN;
  v_branch RECORD;
  v_session RECORD;
  v_lease RECORD;
  v_binding JSONB;
  v_generation_found BOOLEAN;
  g pfj.journal_generations;
  v_epoch BIGINT;
  v_created BOOLEAN:=FALSE;
  v_resumed BOOLEAN:=FALSE;
  v_response JSONB;
  v_count BIGINT;
  v_policy_hash TEXT;
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_operation_id IS NULL OR length(p_operation_id) NOT BETWEEN 1 AND 200
     OR p_tenant_id IS NULL OR length(p_tenant_id)=0
     OR p_volume_id IS NULL OR length(p_volume_id)=0
     OR p_branch_name IS NULL OR length(p_branch_name)=0
     OR p_attach_session_id IS NULL OR length(p_attach_session_id)=0
     OR p_lease_id IS NULL OR length(p_lease_id)=0
     OR p_fencing_token IS NULL OR p_fencing_token<1
     OR p_holder_id IS NULL OR length(p_holder_id)=0
     OR p_authority_instance_id IS NULL OR length(p_authority_instance_id)=0
     OR p_capability IS NULL OR length(p_capability) NOT BETWEEN 32 AND 512
     OR p_quota_backlog_bytes IS NOT NULL AND p_quota_backlog_bytes<=0
     OR p_quota_backlog_records IS NOT NULL AND p_quota_backlog_records<=0 THEN
    RAISE EXCEPTION 'invalid journal claim arguments' USING ERRCODE='PF008';
  END IF;
  IF NOT ((p_record_codec='pfr1' AND p_control_codec='pfc1')
       OR (p_record_codec='pfj3' AND p_control_codec='pfc2')) THEN
    RAISE EXCEPTION 'unknown journal codec pair %/%',p_record_codec,p_control_codec
      USING ERRCODE='PF005';
  END IF;
  v_capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  v_fingerprint:=encode(sha256(convert_to(jsonb_build_array(
    'portablefs-journal-claim-v6',p_tenant_id,p_volume_id,p_branch_name,
    p_attach_session_id,p_lease_id,p_fencing_token::TEXT,p_holder_id,
    p_authority_instance_id,v_capability_hash,p_manager_epoch::TEXT,
    p_authority_runtime_seq::TEXT,p_authority_runtime_id,
    p_expected_base_commit_id,p_quota_backlog_bytes::TEXT,
    p_quota_backlog_records::TEXT,p_record_codec,p_control_codec)::TEXT,'UTF8')),'hex');
  -- Pre-012 receipts were fingerprinted without the pair (v5). A legacy-pair
  -- retry of such an operation id must still replay identically.
  v_legacy_fingerprint:=encode(sha256(convert_to(jsonb_build_array(
    'portablefs-journal-claim-v5',p_tenant_id,p_volume_id,p_branch_name,
    p_attach_session_id,p_lease_id,p_fencing_token::TEXT,p_holder_id,
    p_authority_instance_id,v_capability_hash,p_manager_epoch::TEXT,
    p_authority_runtime_seq::TEXT,p_authority_runtime_id,
    p_expected_base_commit_id,p_quota_backlog_bytes::TEXT,
    p_quota_backlog_records::TEXT)::TEXT,'UTF8')),'hex');
  -- ONE lock order: sorted exclusive branch advisory lock (plus the claim
  -- receipt key), then volume, branch, receipt, generation, session, lease,
  -- manager claim/runtime, HA policy, mutation.
  PERFORM pfj.scope_locks(ARRAY[
    pfj.branch_lock_key(p_tenant_id,p_volume_id,p_branch_name),
    jsonb_build_array(
      'pfj-claim-receipt',p_tenant_id,p_volume_id,p_branch_name,p_operation_id)::TEXT]);
  SELECT v.tenant_id INTO v_tenant FROM public.volumes v
    WHERE v.id=p_volume_id FOR SHARE;
  IF NOT FOUND OR v_tenant<>p_tenant_id THEN
    RAISE EXCEPTION 'volume is not owned by tenant' USING ERRCODE='PF007';
  END IF;
  SELECT b.id,b.head_commit_id,b.branch_mode INTO v_branch FROM public.branches b
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='PF007';
  END IF;
  SELECT * INTO v_receipt FROM pfj.journal_claim_receipts
    WHERE tenant_id=p_tenant_id AND volume_id=p_volume_id
      AND branch_id=v_branch.id AND operation_id=p_operation_id;
  v_receipt_found:=FOUND;
  IF v_receipt_found THEN
    IF v_receipt.writer_capability_hash<>v_capability_hash THEN
      RAISE EXCEPTION 'claim receipt capability rejected' USING ERRCODE='PF001';
    END IF;
    IF v_receipt.record_codec IS NOT NULL
       AND (v_receipt.record_codec IS DISTINCT FROM p_record_codec
            OR v_receipt.control_codec IS DISTINCT FROM p_control_codec) THEN
      RAISE EXCEPTION 'claim operation replayed with a different codec pair'
        USING ERRCODE='PF009';
    END IF;
    IF v_receipt.request_fingerprint<>v_fingerprint
       AND NOT (v_receipt.record_codec IS NULL
                AND p_record_codec='pfr1'
                AND v_receipt.request_fingerprint=v_legacy_fingerprint) THEN
      RAISE EXCEPTION 'claim operation replayed with different content'
        USING ERRCODE='PF009';
    END IF;
    SELECT * INTO g FROM pfj.journal_generations
      WHERE id=v_receipt.generation_id FOR SHARE;
    IF FOUND AND g.status='active' AND g.writer_fence=v_receipt.writer_fence
       AND g.lease_id=p_lease_id AND g.capability_hash=v_capability_hash THEN
      PERFORM pfj.require_writer(
        g,g.epoch,p_capability,p_lease_id,p_fencing_token,
        g.record_codec,g.control_codec);
      PERFORM pfj.require_manager_binding(
        g,p_manager_epoch,p_authority_runtime_seq,
        p_authority_runtime_id,p_capability);
      RETURN pfj.generation_json(g)||jsonb_build_object(
        'operationId',p_operation_id,
        'created',v_receipt.response->'created',
        'resumed',v_receipt.response->'resumed',
        'branchMode',v_branch.branch_mode,
        'current',TRUE,'replayed',TRUE);
    END IF;
    RETURN v_receipt.response||jsonb_build_object(
      'current',FALSE,'replayed',TRUE,'status','fenced');
  END IF;

  SELECT * INTO g FROM pfj.journal_generations
    WHERE branch_id=v_branch.id
      AND status IN ('active','suspended','retiring')
    FOR UPDATE;
  v_generation_found:=FOUND;
  -- Codec-pair and branch-mode authorization come BEFORE any writer/fence
  -- mutation: a wrong-pair claim can never fence the live generation and a
  -- claim can never manufacture a mode.
  IF v_generation_found
     AND (g.record_codec IS DISTINCT FROM p_record_codec
          OR g.control_codec IS DISTINCT FROM p_control_codec) THEN
    RAISE EXCEPTION
      'branch journal generation speaks %/%; a %/% claim requires the exceptional conversion (migration 013)',
      g.record_codec,g.control_codec,p_record_codec,p_control_codec
      USING ERRCODE='PF005',
            DETAIL=jsonb_build_object('migrationRequired',TRUE,
              'generationId',g.id,
              'recordCodec',g.record_codec,
              'controlCodec',g.control_codec)::TEXT;
  END IF;
  IF p_record_codec='pfj3' AND v_branch.branch_mode<>'managed_journal' THEN
    RAISE EXCEPTION
      'branch mode is %; a PFJ3/PFC2 claim requires authoritative managed_journal provisioning',
      v_branch.branch_mode
      USING ERRCODE='PF001',
            DETAIL=jsonb_build_object('branchMode',v_branch.branch_mode)::TEXT;
  END IF;
  IF p_record_codec='pfr1' THEN
    IF v_branch.branch_mode NOT IN ('legacy_manifest','migrating') THEN
      RAISE EXCEPTION 'branch mode is %; legacy claims are not admitted',
        v_branch.branch_mode
        USING ERRCODE='PF001',
              DETAIL=jsonb_build_object('branchMode',v_branch.branch_mode)::TEXT;
    END IF;
    IF NOT v_generation_found AND v_branch.branch_mode='migrating' THEN
      RAISE EXCEPTION
        'branch is migrating; a legacy claim may resume its existing generation but never create a new one'
        USING ERRCODE='PF001';
    END IF;
  END IF;
  -- Row order continues: attach session, then public lease.
  SELECT s.id,s.status,s.mode,s.holder_id INTO v_session
    FROM public.attach_sessions s
    WHERE s.id=p_attach_session_id AND s.volume_id=p_volume_id
      AND s.branch_id=v_branch.id FOR SHARE;
  SELECT l.id,l.fencing_token,l.expires_at,l.released_at,
         l.exclusive,l.holder_id,l.attach_session_id INTO v_lease
    FROM public.leases l
    WHERE l.id=p_lease_id AND l.attach_session_id=p_attach_session_id
      AND l.branch_id=v_branch.id AND l.volume_id=p_volume_id FOR SHARE;
  -- Manager claim/runtime locks are always after the branch-scope rows.
  v_binding:=pfm.verify_authority_binding(
    't:'||p_tenant_id,p_volume_id,p_branch_name,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,p_capability);
  -- Live HA policy, after every lock, before any mutation. PFJ3 claims
  -- REQUIRE the canonical policy; the hash is stamped below, and a resumed
  -- generation refuses a drifted policy outright.
  IF p_record_codec='pfj3' THEN
    v_policy_hash:=pfj.evaluate_ha_policy()->>'policyHash';
    IF v_generation_found AND g.ha_policy_hash IS NOT NULL
       AND g.ha_policy_hash IS DISTINCT FROM v_policy_hash THEN
      RAISE EXCEPTION 'HA policy drift: generation was claimed under % but the installed policy is %',
        g.ha_policy_hash, v_policy_hash USING ERRCODE='PF015';
    END IF;
  ELSE
    PERFORM pfj.require_durable_primary();
  END IF;
  -- The durability/policy probe may outlive a manager deadline. Reverify the
  -- exact binding afterwards and use its post-lock database-time sample.
  v_binding:=pfm.verify_authority_binding(
    't:'||p_tenant_id,p_volume_id,p_branch_name,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,p_capability);
  v_now:=(v_binding->>'dbTimeMs')::BIGINT;
  IF v_session.id IS NULL OR v_session.status<>'attached'
     OR v_session.mode<>'write'
     OR v_session.holder_id IS DISTINCT FROM p_holder_id THEN
    RAISE EXCEPTION 'attach session is not this holder''s live writer'
      USING ERRCODE='PF001';
  END IF;
  IF v_lease.id IS NULL OR NOT v_lease.exclusive
     OR v_lease.released_at IS NOT NULL OR v_lease.expires_at<=v_now
     OR v_lease.fencing_token IS DISTINCT FROM p_fencing_token
     OR v_lease.holder_id IS DISTINCT FROM p_holder_id THEN
    RAISE EXCEPTION 'exclusive writer lease is not live'
      USING ERRCODE='PF001';
  END IF;
  IF NOT v_generation_found THEN
    IF p_expected_base_commit_id IS NOT NULL
       AND p_expected_base_commit_id<>v_branch.head_commit_id THEN
      RAISE EXCEPTION 'new journal base differs from expected head'
        USING ERRCODE='PF002';
    END IF;
    SELECT COALESCE(MAX(epoch),0) INTO v_epoch
      FROM pfj.journal_generations WHERE branch_id=v_branch.id;
    IF v_epoch=9223372036854775807::BIGINT THEN
      RAISE EXCEPTION 'journal generation epoch exhausted' USING ERRCODE='PF004';
    END IF;
    v_epoch:=v_epoch+1;
    -- Direct insert of the FINAL immutable pair: there is no transient row
    -- and no post-insert rewrite anywhere.
    INSERT INTO pfj.journal_generations(
      id,tenant_id,volume_id,branch_id,epoch,record_codec,control_codec,
      base_commit_id,base_seq,base_digest,next_seq,tip_digest,
      physical_trimmed_seq,status,backlog_bytes,backlog_records,
      quota_backlog_bytes,quota_backlog_records,writer_fence,
      attach_session_id,lease_id,holder_id,authority_instance_id,
      capability_hash,manager_epoch,authority_runtime_seq,
      authority_runtime_id,control_db_floor_ms,ha_policy_hash,
      claimed_at,created_at,updated_at)
    VALUES (
      'jgen_'||replace(gen_random_uuid()::TEXT,'-',''),
      p_tenant_id,p_volume_id,v_branch.id,v_epoch,p_record_codec,p_control_codec,
      v_branch.head_commit_id,0,pfj.zero_digest(),0,pfj.zero_digest(),
      0,'active',0,0,
      COALESCE(p_quota_backlog_bytes,4294967296),
      COALESCE(p_quota_backlog_records,1048576),
      p_fencing_token,p_attach_session_id,p_lease_id,p_holder_id,
      p_authority_instance_id,v_capability_hash,
      CASE WHEN COALESCE((v_binding->>'managed')::BOOLEAN,FALSE)
        THEN p_manager_epoch END,
      CASE WHEN COALESCE((v_binding->>'managed')::BOOLEAN,FALSE)
        THEN p_authority_runtime_seq END,
      CASE WHEN COALESCE((v_binding->>'managed')::BOOLEAN,FALSE)
        THEN p_authority_runtime_id END,
      0,v_policy_hash,
      v_now,v_now,v_now)
    RETURNING * INTO g;
    v_created:=TRUE;
  ELSE
    IF g.status='retiring' THEN
      RAISE EXCEPTION 'journal generation is retiring' USING ERRCODE='PF001';
    END IF;
    IF p_expected_base_commit_id IS NOT NULL
       AND p_expected_base_commit_id<>g.base_commit_id THEN
      RAISE EXCEPTION 'journal resume base conflict' USING ERRCODE='PF002';
    END IF;
    IF g.status='suspended' AND g.authority_runtime_seq IS NOT NULL
       AND (p_authority_runtime_seq IS NULL
            OR p_authority_runtime_seq<=g.authority_runtime_seq) THEN
      RAISE EXCEPTION 'suspended generation requires a newer runtime'
        USING ERRCODE='PF001';
    END IF;
    IF g.writer_fence IS NOT NULL AND p_fencing_token<g.writer_fence THEN
      RAISE EXCEPTION 'journal claim fence is stale' USING ERRCODE='PF001';
    END IF;
    IF g.writer_fence=p_fencing_token THEN
      IF g.lease_id IS DISTINCT FROM p_lease_id
         OR g.attach_session_id IS DISTINCT FROM p_attach_session_id
         OR g.capability_hash IS NOT NULL
            AND g.capability_hash IS DISTINCT FROM v_capability_hash THEN
        RAISE EXCEPTION 'journal fence belongs to another writer'
          USING ERRCODE='PF002';
      END IF;
      v_resumed:=g.status='suspended';
    ELSE
      v_resumed:=TRUE;
    END IF;
    UPDATE pfj.journal_generations SET
      status='active',writer_fence=p_fencing_token,
      attach_session_id=p_attach_session_id,lease_id=p_lease_id,
      holder_id=p_holder_id,authority_instance_id=p_authority_instance_id,
      capability_hash=v_capability_hash,
      manager_epoch=CASE
        WHEN COALESCE((v_binding->>'managed')::BOOLEAN,FALSE)
        THEN p_manager_epoch END,
      authority_runtime_seq=CASE
        WHEN COALESCE((v_binding->>'managed')::BOOLEAN,FALSE)
        THEN p_authority_runtime_seq END,
      authority_runtime_id=CASE
        WHEN COALESCE((v_binding->>'managed')::BOOLEAN,FALSE)
        THEN p_authority_runtime_id END,
      ha_policy_hash=COALESCE(g.ha_policy_hash,v_policy_hash),
      claimed_at=v_now,updated_at=v_now
      WHERE id=g.id RETURNING * INTO g;
    GET DIAGNOSTICS v_count=ROW_COUNT;
    IF v_count<>1 THEN
      RAISE EXCEPTION 'journal claim lost its generation' USING ERRCODE='PF010';
    END IF;
  END IF;
  v_response:=pfj.generation_json(g)||jsonb_build_object(
    'operationId',p_operation_id,'created',v_created,'resumed',v_resumed,
    'branchMode',v_branch.branch_mode);
  INSERT INTO pfj.journal_claim_receipts(
    tenant_id,volume_id,branch_id,operation_id,generation_id,
    request_fingerprint,writer_fence,writer_capability_hash,response,
    record_codec,control_codec,created_at)
  VALUES (
    p_tenant_id,p_volume_id,g.branch_id,p_operation_id,g.id,
    v_fingerprint,p_fencing_token,v_capability_hash,v_response,
    p_record_codec,p_control_codec,v_now);
  RETURN v_response||jsonb_build_object(
    'current',TRUE,'replayed',FALSE);
END;
$$;

-- Fixed public wrappers. journal_claim keeps its exact 011 signature and
-- semantics for the legacy pair (CREATE OR REPLACE preserves its grants);
-- journal_claim_v3 is the managed pair. Neither takes a codec argument:
-- the pair is the wrapper, never a caller choice.
CREATE OR REPLACE FUNCTION pfj.journal_claim(
  p_operation_id TEXT,
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_attach_session_id TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_holder_id TEXT,
  p_authority_instance_id TEXT,
  p_capability TEXT,
  p_manager_epoch BIGINT DEFAULT NULL,
  p_authority_runtime_seq BIGINT DEFAULT NULL,
  p_authority_runtime_id TEXT DEFAULT NULL,
  p_expected_base_commit_id TEXT DEFAULT NULL,
  p_quota_backlog_bytes BIGINT DEFAULT NULL,
  p_quota_backlog_records BIGINT DEFAULT NULL
) RETURNS JSONB
LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
  SELECT pfj.journal_claim_core(
    p_operation_id,p_tenant_id,p_volume_id,p_branch_name,
    p_attach_session_id,p_lease_id,p_fencing_token,p_holder_id,
    p_authority_instance_id,p_capability,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,
    p_expected_base_commit_id,p_quota_backlog_bytes,p_quota_backlog_records,
    'pfr1','pfc1')
$$;

CREATE FUNCTION pfj.journal_claim_v3(
  p_operation_id TEXT,
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_attach_session_id TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_holder_id TEXT,
  p_authority_instance_id TEXT,
  p_capability TEXT,
  p_manager_epoch BIGINT DEFAULT NULL,
  p_authority_runtime_seq BIGINT DEFAULT NULL,
  p_authority_runtime_id TEXT DEFAULT NULL,
  p_expected_base_commit_id TEXT DEFAULT NULL,
  p_quota_backlog_bytes BIGINT DEFAULT NULL,
  p_quota_backlog_records BIGINT DEFAULT NULL
) RETURNS JSONB
LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
  SELECT pfj.journal_claim_core(
    p_operation_id,p_tenant_id,p_volume_id,p_branch_name,
    p_attach_session_id,p_lease_id,p_fencing_token,p_holder_id,
    p_authority_instance_id,p_capability,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,
    p_expected_base_commit_id,p_quota_backlog_bytes,p_quota_backlog_records,
    'pfj3','pfc2')
$$;

-- ─── authoritative provisioning discovery ───────────────────────────────────

-- branch_provisioning answers the ONE question a starting authority may ask:
-- what did provisioning decide for this branch? The answer derives the
-- immutable codec pair from the live generation when one exists, otherwise
-- from the authoritative branch mode — never from the caller. Retiring and
-- retired branches refuse service. The child then runs the matching claim
-- wrapper and verifies the claim result against this answer; a config typo
-- has nothing to select.
CREATE FUNCTION pfj.branch_provisioning(
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_authority_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_tenant TEXT;
  v_branch RECORD;
  v_binding JSONB;
  g pfj.journal_generations;
  v_found BOOLEAN;
  v_record TEXT;
  v_control TEXT;
BEGIN
  -- Shared branch advisory lock first, then the same row order reads take.
  PERFORM pfj.scope_locks_shared(ARRAY[
    pfj.branch_lock_key(p_tenant_id,p_volume_id,p_branch_name)]);
  SELECT v.tenant_id INTO v_tenant FROM public.volumes v
    WHERE v.id=p_volume_id FOR SHARE;
  IF NOT FOUND OR v_tenant<>p_tenant_id THEN
    RAISE EXCEPTION 'volume is not owned by tenant' USING ERRCODE='PF007';
  END IF;
  SELECT b.id,b.branch_mode INTO v_branch FROM public.branches b
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='PF007';
  END IF;
  SELECT * INTO g FROM pfj.journal_generations
    WHERE branch_id=v_branch.id
      AND status IN ('active','suspended','retiring') FOR SHARE;
  v_found := FOUND;
  -- The manager/runtime binding proves WHO is asking (and yields db time).
  v_binding:=pfm.verify_authority_binding(
    't:'||p_tenant_id,p_volume_id,p_branch_name,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,p_authority_capability);
  IF NOT COALESCE((v_binding->>'managed')::BOOLEAN,FALSE) THEN
    RAISE EXCEPTION 'branch provisioning requires a managed authority binding'
      USING ERRCODE='PF001';
  END IF;
  IF v_branch.branch_mode IN ('retiring','retired') THEN
    RAISE EXCEPTION 'branch is % and refuses authority service',
      v_branch.branch_mode
      USING ERRCODE='PF001',
            DETAIL=jsonb_build_object('branchMode',v_branch.branch_mode)::TEXT;
  END IF;
  IF v_found THEN
    -- The live generation's immutable pair is the answer, and it must agree
    -- with the mode (the 012 postconditions and triggers keep it coherent).
    v_record := g.record_codec;
    v_control := g.control_codec;
  ELSIF v_branch.branch_mode = 'managed_journal' THEN
    v_record := 'pfj3'; v_control := 'pfc2';
  ELSIF v_branch.branch_mode = 'legacy_manifest' THEN
    v_record := 'pfr1'; v_control := 'pfc1';
  ELSE
    -- migrating with no nonterminal generation is contradictory state.
    RAISE EXCEPTION 'branch is migrating but has no journal generation to resume'
      USING ERRCODE='PF010';
  END IF;
  RETURN jsonb_build_object(
    'branchMode',v_branch.branch_mode,
    'recordCodec',v_record,
    'controlCodec',v_control,
    'generationId',CASE WHEN v_found THEN g.id END,
    'generationStatus',CASE WHEN v_found THEN g.status END,
    'dbTimeMs',v_binding->>'dbTimeMs');
END;
$$;

-- ─── codec-aware refresh/read/suspend/lifecycle ──────────────────────────────

-- generation_json now carries the canonical decimal control floor, the HA
-- policy binding, and the branch mode on every claim/replay/append/adopt
-- surface that embeds a generation snapshot.
CREATE OR REPLACE FUNCTION pfj.generation_json(g pfj.journal_generations) RETURNS JSONB
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
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
    'updatedAt', g.updated_at::TEXT
  ))
$$;

-- journal_check_append_quota, journal_read_page, journal_record_hashes,
-- journal_suspend_exact: identical contracts, now codec-aware and under the
-- single lock order (shared advisory for reads, exclusive for suspend).
-- CREATE OR REPLACE preserves the 011 grants.
CREATE OR REPLACE FUNCTION pfj.journal_read_page(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_from_seq BIGINT,
  p_max_records INT DEFAULT 256,
  p_max_bytes BIGINT DEFAULT 16777216
) RETURNS TABLE (seq BIGINT, payload BYTEA, record_hash TEXT, chain_digest TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_limit INT:=LEAST(GREATEST(COALESCE(p_max_records,256),1),256);
  v_budget BIGINT:=LEAST(GREATEST(COALESCE(p_max_bytes,16777216),1),16777216);
  v_emitted INT:=0;
  r RECORD;
BEGIN
  IF p_from_seq IS NULL OR p_from_seq<0 THEN
    RAISE EXCEPTION 'journal read start must be non-negative'
      USING ERRCODE='PF008';
  END IF;
  PERFORM pfj.branch_lock_for_generation(p_generation_id, FALSE);
  SELECT * INTO g FROM pfj.journal_generations
    WHERE id=p_generation_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found',p_generation_id
      USING ERRCODE='PF007';
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    g.record_codec,g.control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  IF p_from_seq<g.base_seq THEN
    RAISE EXCEPTION 'read below journal base' USING ERRCODE='PF008';
  END IF;
  FOR r IN
    SELECT jr.seq,jr.payload,jr.record_hash,jr.chain_digest,jr.payload_bytes
    FROM pfj.journal_records jr
    WHERE jr.generation_id=g.id
      AND jr.seq>=p_from_seq AND jr.seq<g.next_seq
    ORDER BY jr.seq LIMIT v_limit
  LOOP
    IF v_emitted>0 AND v_budget<r.payload_bytes THEN EXIT; END IF;
    v_budget:=v_budget-r.payload_bytes;
    v_emitted:=v_emitted+1;
    seq:=r.seq;
    payload:=r.payload;
    record_hash:=r.record_hash;
    chain_digest:=r.chain_digest;
    RETURN NEXT;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION pfj.journal_record_hashes(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_from_seq BIGINT,
  p_to_seq BIGINT
) RETURNS TABLE (seq BIGINT, record_hash TEXT, chain_digest TEXT, payload_bytes BIGINT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE g pfj.journal_generations;
BEGIN
  IF p_from_seq IS NULL OR p_to_seq IS NULL
     OR p_from_seq<0 OR p_to_seq<p_from_seq THEN
    RAISE EXCEPTION 'invalid record hash range' USING ERRCODE='PF008';
  END IF;
  IF p_to_seq-p_from_seq>4096 THEN
    RAISE EXCEPTION 'record hash range is bounded to 4096 rows'
      USING ERRCODE='PF004';
  END IF;
  PERFORM pfj.branch_lock_for_generation(p_generation_id, FALSE);
  SELECT * INTO g FROM pfj.journal_generations
    WHERE id=p_generation_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found',p_generation_id
      USING ERRCODE='PF007';
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    g.record_codec,g.control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  IF p_from_seq<g.base_seq OR p_to_seq>g.next_seq THEN
    RAISE EXCEPTION 'record hash range is outside the live journal suffix'
      USING ERRCODE='PF008';
  END IF;
  RETURN QUERY
    SELECT jr.seq,jr.record_hash,jr.chain_digest,jr.payload_bytes
    FROM pfj.journal_records jr
    WHERE jr.generation_id=g.id
      AND jr.seq>=p_from_seq AND jr.seq<p_to_seq
    ORDER BY jr.seq;
END;
$$;

CREATE OR REPLACE FUNCTION pfj.journal_suspend_exact(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_operation_id TEXT,
  p_fingerprint TEXT,
  p_expected_next_seq BIGINT,
  p_expected_tip_digest TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT;
  v_effective_fingerprint TEXT;
  v_capability_hash TEXT;
  v_receipt pfj.journal_op_receipts;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_operation_id IS NULL OR length(p_operation_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'suspend operation id required (<=256 chars)'
      USING ERRCODE='PF008';
  END IF;
  IF p_fingerprint IS NULL OR p_fingerprint!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'suspend fingerprint must be 64 hex chars'
      USING ERRCODE='PF008';
  END IF;
  IF p_expected_next_seq IS NULL OR p_expected_next_seq<0
     OR p_expected_tip_digest IS NULL
     OR p_expected_tip_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'suspend expected head is required' USING ERRCODE='PF008';
  END IF;
  IF p_capability IS NULL THEN
    RAISE EXCEPTION 'suspend capability is required' USING ERRCODE='PF008';
  END IF;
  v_capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  v_effective_fingerprint:=encode(sha256(convert_to(jsonb_build_array(
    'pfj-suspend-v2',p_fingerprint,p_expected_next_seq::TEXT,
    p_expected_tip_digest)::TEXT,'UTF8')),'hex');
  PERFORM pfj.branch_lock_for_generation(p_generation_id, TRUE);
  g:=pfj.lock_generation(p_generation_id);
  SELECT * INTO v_receipt FROM pfj.journal_op_receipts
    WHERE tenant_id=g.tenant_id AND volume_id=g.volume_id
      AND branch_id=g.branch_id AND domain='suspend'
      AND operation_id=p_operation_id;
  IF FOUND THEN
    IF v_receipt.writer_capability_hash IS DISTINCT FROM v_capability_hash THEN
      RAISE EXCEPTION 'suspend receipt capability rejected'
        USING ERRCODE='PF001';
    END IF;
    IF v_receipt.fingerprint<>v_effective_fingerprint
       OR v_receipt.expected_next_seq<>p_expected_next_seq
       OR v_receipt.expected_tip_digest<>p_expected_tip_digest THEN
      RAISE EXCEPTION 'suspend operation replayed with different content'
        USING ERRCODE='PF009';
    END IF;
    RETURN v_receipt.response||jsonb_build_object('replayed',TRUE);
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    p_record_codec,p_control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  IF g.next_seq<>p_expected_next_seq
     OR g.tip_digest<>p_expected_tip_digest THEN
    RAISE EXCEPTION 'suspend head changed (expected %/%, current %/%)',
      p_expected_next_seq,p_expected_tip_digest,g.next_seq,g.tip_digest
      USING ERRCODE='PF002';
  END IF;
  IF g.record_codec='pfj3' THEN
    PERFORM pfj.require_ha_policy(g);
  ELSE
    PERFORM pfj.require_durable_primary();
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    p_record_codec,p_control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  v_now:=pfj.now_ms();
  UPDATE pfj.journal_generations SET
    status='suspended',capability_hash=NULL,updated_at=v_now
    WHERE id=g.id RETURNING * INTO g;
  GET DIAGNOSTICS v_row_count=ROW_COUNT;
  IF v_row_count<>1 THEN
    RAISE EXCEPTION 'journal suspend lost its locked generation'
      USING ERRCODE='PF010';
  END IF;
  v_response:=jsonb_build_object(
    'operationId',p_operation_id,'status','suspended',
    'tenantId',g.tenant_id,'volumeId',g.volume_id,'branchId',g.branch_id,
    'generationId',g.id,'epoch',g.epoch::TEXT,
    'nextSeq',g.next_seq::TEXT,'tipDigest',g.tip_digest,
    'writerFence',g.writer_fence::TEXT,
    'managerEpoch',g.manager_epoch::TEXT,
    'authorityRuntimeSeq',g.authority_runtime_seq::TEXT,
    'authorityRuntimeId',g.authority_runtime_id,
    'controlDbFloorMs',g.control_db_floor_ms::TEXT,
    'suspendedAtDbMs',v_now::TEXT);
  INSERT INTO pfj.journal_op_receipts(
    tenant_id,volume_id,branch_id,domain,operation_id,fingerprint,
    expected_next_seq,expected_tip_digest,writer_capability_hash,
    response,created_at)
  VALUES (
    g.tenant_id,g.volume_id,g.branch_id,'suspend',p_operation_id,
    v_effective_fingerprint,p_expected_next_seq,p_expected_tip_digest,
    v_capability_hash,v_response,v_now);
  RETURN v_response||jsonb_build_object('replayed',FALSE);
END;
$$;

-- ─── branch mode transition primitive (owner-only SECURITY DEFINER) ─────────

-- branch_mode_transition is the ONE privileged mode CAS: exclusive branch
-- advisory lock, branch row lock, exact expected-mode compare-and-set. The
-- transition matrix and generation-state prerequisites are enforced by the
-- public.branches trigger; running as the journal owner is what authorizes
-- managed-mode-related head/mode changes there. EXECUTE is granted to the
-- migration/admin user below (the metadata layer drives provisioning and
-- lifecycle transitions); the authority role never receives it.
CREATE FUNCTION pfj.branch_mode_transition(
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_expected_mode TEXT,
  p_new_mode TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_tenant TEXT;
  v_branch RECORD;
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_expected_mode IS NULL OR p_new_mode IS NULL
     OR p_expected_mode NOT IN ('legacy_manifest','managed_journal','migrating','retiring','retired')
     OR p_new_mode NOT IN ('legacy_manifest','managed_journal','migrating','retiring','retired') THEN
    RAISE EXCEPTION 'invalid branch mode arguments' USING ERRCODE='PF008';
  END IF;
  PERFORM pfj.scope_locks(ARRAY[
    pfj.branch_lock_key(p_tenant_id,p_volume_id,p_branch_name)]);
  SELECT v.tenant_id INTO v_tenant FROM public.volumes v
    WHERE v.id=p_volume_id FOR SHARE;
  IF NOT FOUND OR v_tenant<>p_tenant_id THEN
    RAISE EXCEPTION 'volume is not owned by tenant' USING ERRCODE='PF007';
  END IF;
  SELECT b.id,b.branch_mode INTO v_branch FROM public.branches b
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='PF007';
  END IF;
  IF v_branch.branch_mode IS DISTINCT FROM p_expected_mode THEN
    RAISE EXCEPTION 'branch mode CAS expected % but found %',
      p_expected_mode,v_branch.branch_mode
      USING ERRCODE='PF002',
            DETAIL=jsonb_build_object('branchMode',v_branch.branch_mode)::TEXT;
  END IF;
  IF p_new_mode = p_expected_mode THEN
    RETURN jsonb_build_object('branchMode',v_branch.branch_mode,'changed',FALSE);
  END IF;
  UPDATE public.branches SET branch_mode=p_new_mode, updated_at=pfj.now_ms()
    WHERE id=v_branch.id;
  RETURN jsonb_build_object('branchMode',p_new_mode,'changed',TRUE);
END;
$$;

-- ─── ACL / default privileges ────────────────────────────────────────────────
-- The owner-level default privileges from 009 already strip PUBLIC EXECUTE
-- from every function above. Assert the end state and grant EXACTLY the
-- authority surface: claim_v3, append_v3, fact issue. The claim core, HA
-- policy install, branch transitions, helpers, and parser get NO authority
-- grant. journal_claim / read_page / record_hashes / suspend keep their 011
-- grants through CREATE OR REPLACE.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pfj FROM PUBLIC;
REVOKE ALL ON TABLE pfj.admission_facts, pfj.ha_policies FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  pfj.admission_fact_issue(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,SMALLINT,TEXT,BIGINT,BIGINT),
  pfj.journal_append_v3(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT,BIGINT,
    BYTEA[],TEXT[],TEXT),
  pfj.journal_claim_v3(
    TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT,
    BIGINT,BIGINT,TEXT,TEXT,BIGINT,BIGINT),
  pfj.branch_provisioning(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT)
TO portablefs_authority;

RESET ROLE;

-- ═══ SECTION C: grants that need the table owner / migration user ════════════
-- The branch guard trigger runs SECURITY INVOKER, so the metadata layer's own
-- role (the migration user) needs the generation-state helper; the metadata
-- layer also drives provisioning/lifecycle transitions through the owner-only
-- CAS primitive. Neither is ever granted to portablefs_authority.
GRANT EXECUTE ON FUNCTION pfj.branch_generation_state(TEXT) TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION pfj.branch_mode_transition(TEXT,TEXT,TEXT,TEXT,TEXT)
  TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION pfj.install_ha_policy(TEXT) TO CURRENT_USER;
GRANT EXECUTE ON FUNCTION pfj.production_durability_audit() TO CURRENT_USER;

CREATE TRIGGER portablefs_branch_guard
  BEFORE UPDATE ON public.branches
  FOR EACH ROW EXECUTE FUNCTION public.portablefs_branch_guard();

-- ─── Receipted attach identity (public schema, table owner) ──────────────────
-- The durable exact-once record of one receipted managed attach, keyed by
-- (tenant_id, operation_id) — the identity the repository resolves BEFORE
-- executing and writes atomically WITH the session/lease/delegation rows.
-- The stored outcome is the bounded canonical JSON of the original response
-- facts (session, branch, delegations — never the manifest, which is
-- re-projected from the retained base commit).
--
-- This row is a PERMANENT identity tombstone. Deliberately NO foreign keys:
-- a cascading edge to volumes/branches/attach_sessions/commits would erase
-- the identity exactly when its prerequisites are retired, silently turning
-- a committed operation's replay into a fresh re-execution. With the
-- receipt retained, that replay answers committed-gone (410) instead.
CREATE TABLE public.attach_receipts (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
  operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
  request_fingerprint TEXT NOT NULL
    CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  volume_id TEXT NOT NULL CHECK (length(volume_id) BETWEEN 1 AND 256),
  branch_id TEXT NOT NULL CHECK (length(branch_id) BETWEEN 1 AND 256),
  attach_session_id TEXT NOT NULL CHECK (length(attach_session_id) BETWEEN 1 AND 256),
  base_commit_id TEXT NOT NULL CHECK (length(base_commit_id) BETWEEN 1 AND 256),
  outcome JSONB NOT NULL CHECK (
    jsonb_typeof(outcome) = 'object' AND pg_column_size(outcome) <= 65536),
  created_at BIGINT NOT NULL CHECK (created_at >= 0),
  PRIMARY KEY (tenant_id, operation_id)
);

-- Private posture: only the table owner (the metadata layer's migration/admin
-- user) touches receipts. Neither capability role is granted anything.
REVOKE ALL ON TABLE public.attach_receipts FROM PUBLIC;

-- ─── Postconditions: fail the migration loudly if any invariant regressed ────
DO $post$
DECLARE
  v_count BIGINT;
  v_owner TEXT;
  v_rec RECORD;
BEGIN
  -- Codec pair constraint + immutability trigger + branch-mode guards exist.
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint con
    JOIN pg_class rel ON rel.oid=con.conrelid
    JOIN pg_namespace nsp ON nsp.oid=rel.relnamespace
    WHERE nsp.nspname='pfj' AND rel.relname='journal_generations'
      AND con.conname='journal_generations_codec_pair_check') THEN
    RAISE EXCEPTION '012 postcondition: codec pair constraint missing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='journal_generations_freeze')
     OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='journal_generations_guard_branch_mode')
     OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='portablefs_branch_guard') THEN
    RAISE EXCEPTION '012 postcondition: a guard trigger is missing';
  END IF;
  -- journal_records keeps DEFAULT pfr1 (the 011 legacy append depends on it).
  SELECT column_default INTO v_owner FROM information_schema.columns
    WHERE table_schema='pfj' AND table_name='journal_records'
      AND column_name='record_codec';
  IF v_owner IS NULL OR v_owner NOT LIKE '%pfr1%' THEN
    RAISE EXCEPTION '012 postcondition: journal_records.record_codec default pfr1 was lost';
  END IF;
  -- No mixed/malformed codec state anywhere.
  SELECT COUNT(*) INTO v_count FROM pfj.journal_records
    WHERE record_codec NOT IN ('pfr1','pfj3');
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: % records carry unknown codecs',v_count;
  END IF;
  SELECT COUNT(*) INTO v_count FROM pfj.journal_generations g
    WHERE NOT ((g.record_codec='pfr1' AND g.control_codec='pfc1')
      OR (g.record_codec='pfj3' AND g.control_codec='pfc2'));
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: % generations carry mixed codec pairs',v_count;
  END IF;
  -- Branch/live-generation classification is coherent.
  SELECT COUNT(*) INTO v_count
    FROM pfj.journal_generations g
    JOIN public.branches b ON b.id=g.branch_id
    WHERE g.status IN ('active','suspended','retiring')
      AND ((g.record_codec='pfj3' AND b.branch_mode<>'managed_journal')
        OR (g.record_codec='pfr1' AND b.branch_mode NOT IN
             ('legacy_manifest','migrating','retiring')));
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: % branches contradict their live generation codec',v_count;
  END IF;
  SELECT COUNT(*) INTO v_count FROM public.branches b
    WHERE b.branch_mode IN ('migrating','retiring')
      AND NOT EXISTS (
        SELECT 1 FROM pfj.journal_generations g
        WHERE g.branch_id=b.id AND g.status IN ('active','suspended','retiring'));
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: % migrating/retiring branches have no nonterminal generation',v_count;
  END IF;
  -- Exact function ownership + SECURITY DEFINER discipline + pinned
  -- search_path on every new pfj entry point. Public entry points are
  -- SECURITY DEFINER; the owner-only claim core and the manifest parser are
  -- deliberately NOT (they only ever run inside owner contexts).
  FOR v_rec IN
    SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfj' AND p.proname IN
      ('journal_claim_core','journal_claim','journal_claim_v3',
       'journal_append_v3','admission_fact_issue','install_ha_policy',
       'evaluate_ha_policy','ha_policy_verdict','production_durability_audit',
       'branch_provisioning','branch_mode_transition','branch_generation_state',
       'parse_pfj3_manifest','journal_read_page','journal_record_hashes',
       'journal_suspend_exact')
  LOOP
    IF v_rec.owner <> 'portablefs_journal_owner' THEN
      RAISE EXCEPTION '012 postcondition: pfj.% is owned by %',v_rec.proname,v_rec.owner;
    END IF;
    IF v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '012 postcondition: pfj.% has no pinned search_path',v_rec.proname;
    END IF;
    IF v_rec.proname IN ('journal_claim_core','parse_pfj3_manifest') THEN
      IF v_rec.prosecdef THEN
        RAISE EXCEPTION '012 postcondition: pfj.% must not be SECURITY DEFINER',v_rec.proname;
      END IF;
    ELSIF NOT v_rec.prosecdef THEN
      RAISE EXCEPTION '012 postcondition: pfj.% must be SECURITY DEFINER',v_rec.proname;
    END IF;
  END LOOP;
  -- Least ACL: the authority role must NOT execute the core, the policy
  -- installer, the mode CAS, the manifest parser, or the ops audit surface.
  IF has_function_privilege('portablefs_authority',
       'pfj.journal_claim_core(text,text,text,text,text,text,bigint,text,text,text,bigint,bigint,text,text,bigint,bigint,text,text)','EXECUTE')
     OR has_function_privilege('portablefs_authority',
       'pfj.install_ha_policy(text)','EXECUTE')
     OR has_function_privilege('portablefs_authority',
       'pfj.branch_mode_transition(text,text,text,text,text)','EXECUTE')
     OR has_function_privilege('portablefs_authority',
       'pfj.parse_pfj3_manifest(bytea,bigint)','EXECUTE')
     OR has_function_privilege('portablefs_authority',
       'pfj.production_durability_audit()','EXECUTE') THEN
    RAISE EXCEPTION '012 postcondition: authority role holds a privileged grant';
  END IF;
  IF NOT has_function_privilege('portablefs_authority',
       'pfj.journal_claim_v3(text,text,text,text,text,text,bigint,text,text,text,bigint,bigint,text,text,bigint,bigint)','EXECUTE')
     OR NOT has_function_privilege('portablefs_authority',
       'pfj.journal_append_v3(text,bigint,text,text,bigint,bigint,bigint,text,bigint,bytea[],text[],text)','EXECUTE')
     OR NOT has_function_privilege('portablefs_authority',
       'pfj.admission_fact_issue(text,bigint,text,text,bigint,bigint,bigint,text,smallint,text,bigint,bigint)','EXECUTE')
     OR NOT has_function_privilege('portablefs_authority',
       'pfj.branch_provisioning(text,text,text,bigint,bigint,text,text)','EXECUTE') THEN
    RAISE EXCEPTION '012 postcondition: authority surface grant is missing';
  END IF;
  -- The shared policy evaluator + ops audit exist and no admission fact
  -- predates their shape.
  IF to_regprocedure('pfj.evaluate_ha_policy()') IS NULL
     OR to_regprocedure('pfj.ha_policy_verdict()') IS NULL
     OR to_regprocedure('pfj.production_durability_audit()') IS NULL THEN
    RAISE EXCEPTION '012 postcondition: HA policy evaluator/audit missing';
  END IF;
  SELECT COUNT(*) INTO v_count FROM pfj.admission_facts;
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: admission facts existed before 012 completed';
  END IF;
  -- attach_receipts: exact identity key, permanently tombstone-safe (no
  -- foreign-key edge may erase it), and private (no PUBLIC or capability-role
  -- privilege).
  IF to_regclass('public.attach_receipts') IS NULL THEN
    RAISE EXCEPTION '012 postcondition: attach_receipts is missing';
  END IF;
  SELECT string_agg(a.attname, ',' ORDER BY k.ord) INTO v_owner
    FROM pg_constraint con
    JOIN LATERAL unnest(con.conkey) WITH ORDINALITY k(attnum, ord) ON TRUE
    JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
    WHERE con.conrelid = 'public.attach_receipts'::regclass AND con.contype = 'p';
  IF v_owner IS DISTINCT FROM 'tenant_id,operation_id' THEN
    RAISE EXCEPTION '012 postcondition: attach_receipts primary key is % (want tenant_id,operation_id)',
      COALESCE(v_owner,'missing');
  END IF;
  SELECT COUNT(*) INTO v_count FROM pg_constraint
    WHERE conrelid = 'public.attach_receipts'::regclass AND contype = 'f';
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: attach_receipts carries % foreign keys; the identity tombstone must never cascade away',
      v_count;
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM pg_class c,
         LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) acl
    WHERE c.oid = 'public.attach_receipts'::regclass AND acl.grantee = 0;
  IF v_count>0 THEN
    RAISE EXCEPTION '012 postcondition: PUBLIC retains privileges on attach_receipts';
  END IF;
  IF has_table_privilege('portablefs_authority',
       'public.attach_receipts','SELECT,INSERT,UPDATE,DELETE')
     OR has_table_privilege('portablefs_manager',
       'public.attach_receipts','SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION '012 postcondition: a capability role holds attach_receipts privileges';
  END IF;
  -- Lineage: 013/014 remain absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations
             WHERE id LIKE '013%' OR id LIKE '014%') THEN
    RAISE EXCEPTION '012 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
