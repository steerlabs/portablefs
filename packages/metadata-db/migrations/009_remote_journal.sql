-- Remote journal core (pfj): the durable, fenced home of a branch's live
-- mutation log and remote operation-state store. Checkpoints/history cuts are
-- separate lightweight history features, never the definition of persistence.
-- This migration is the fresh-create baseline: roles, schema, tables,
-- invariants, internal primitives, and the owner-only lifecycle primitives.
-- It deliberately installs NO authority-callable API. The managed serving
-- surface (claim/append/read/receipted suspend/opstate/durability evidence)
-- is created by 011_journal_hardening on top of the pfm control plane
-- (010_manager_control); the managed authority (vcs) reaches THAT surface
-- directly over a restricted PostgreSQL login using pgx. The volume-api never
-- proxies journal mutations and tenant tokens have no route to journal state
-- at all.
--
-- SECURITY MODEL
--   portablefs_journal_owner  NOLOGIN. Owns the pfj schema, its tables and
--                             every SECURITY DEFINER function. It can read
--                             (never write) the public metadata tables it
--                             validates against; its only "write" privilege
--                             there is UPDATE (id) — the minimum PostgreSQL
--                             demands for FOR SHARE row locks. Nothing logs
--                             in as it.
--   portablefs_authority      NOLOGIN capability role. Deployments create a
--                             LOGIN role per environment and GRANT
--                             portablefs_authority TO it. This migration
--                             gives it ONLY schema USAGE: no tables — not
--                             even SELECT — no internal helpers, and no
--                             functions. 011 grants exactly the approved
--                             managed API, so a compromised authority
--                             credential can never bypass fencing, forge
--                             chains, or read another tenant's journal rows
--                             except through the fenced functions.
--   (migration/admin user)    Whatever runs migrations (the volume-api's
--                             admin DSN). It must be able to CREATE ROLE the
--                             first time. It is deliberately DISTINCT from
--                             the authority login: the volume-api/admin
--                             credential is never handed to a vcs process.
--
-- All functions here:
--   - are owner-executed (or SECURITY DEFINER extension points) with a fixed,
--     safe search_path ending in pg_temp, and fully schema-qualify every
--     object they touch;
--   - validate at DATABASE time (clock_timestamp(), milliseconds) — a
--     caller's clock never participates in lease/fence validity;
--   - raise typed errors with 'PF0xx' SQLSTATEs so the Go client can classify
--     outcomes without parsing messages.
--
-- ERROR SQLSTATES (the shared pfj vocabulary; PF003/PF004/PF006/PF009/PF014/
-- PF015 are raised by the managed API that 011 installs over these tables)
--   PF001 stale/fenced        (lease dead, fence superseded, capability wrong)
--   PF002 conflict            (byte/chain/identity mismatch, cut conflict)
--   PF003 quota exceeded      (explicit DB backlog quota; typed, not poison)
--   PF004 bounds              (group/record/page shape exceeds hard bounds)
--   PF005 codec mismatch      (epoch codec identity does not match caller)
--   PF006 gap                 (append does not extend the head contiguously)
--   PF007 not found           (no such generation / no live generation)
--   PF008 invalid argument    (malformed input shape)
--   PF009 operation replay mismatch (operation id reused with different body)
--   PF010 accounting corruption (backlog underflow / missing rows or exact
--                              receipts — fails closed)
--   PF011 proof missing       (trim/retire without a landed cut / drained log)
--   PF014 receipt evicted     (retry below a retained receipt floor)
--   PF015 durability absent   (no proven durable synchronous primary)
--
-- BOUNDS (frozen production values; the Go client enforces the same numbers
-- BEFORE staging, these are the server-side backstop)
--   one record payload   <= 8 MiB   (a whole logical intent, PFR1 encoded)
--   one append group     <= 128 records and <= 16 MiB of payload
--   one replay page      <= 256 records and <= 16 MiB of payload
--
-- CODECS: this legacy generation permanently declares exactly the frozen
-- pair (pfr1,pfc1); no epoch ever mixes codecs. PFJ3/PFC2 is introduced only
-- by additive migration 012, which admits the new pair atomically. Legacy gob
-- WALs are local files; a live gob epoch never migrates
-- into this journal implicitly. Moving a legacy volume onto the remote
-- journal is an exceptional strong-drain operation: checkpoint to a verified
-- boundary so no live suffix remains, then the first claim starts a fresh
-- epoch from that commit.
--
-- DIGEST CHAIN (must match vcs/internal/wal ChainDigestBytes exactly):
--   step(prev, payload) = sha256(prev[32] || be64(len(payload)) || payload)
--   record_hash         = step(32 zero bytes, payload)
--   chain_digest[n]     = step(chain_digest[n-1] (or base_digest), payload[n])
-- Payloads are exact PFR1 bytes; the chain is recomputed server-side from the
-- exact raw bytes on every append and cross-checked against the caller.

-- ── Roles ────────────────────────────────────────────────────────────────────
-- Roles are cluster-wide; two databases on one cluster share them. Creation is
-- race-guarded (advisory locks are per-database, so a concurrent migration in
-- ANOTHER database can race this one).
DO $$
BEGIN
  BEGIN
    CREATE ROLE portablefs_journal_owner NOLOGIN;
  -- Concurrent CREATE ROLE in another database can surface either
  -- duplicate_object or the underlying pg_authid unique_violation depending
  -- on which backend wins the catalog insertion race.
  EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
  END;
  BEGIN
    CREATE ROLE portablefs_authority NOLOGIN;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
  END;
END
$$;

-- The migration user must be able to act as the owner role to create objects
-- under its ownership (PG16+ grants the creator ADMIN OPTION automatically;
-- older versions allow this GRANT for CREATEROLE/superusers).
GRANT portablefs_journal_owner TO CURRENT_USER;

-- The owner role validates journal facts against live metadata: read-only on
-- exactly the tables it cross-checks, REFERENCES for the FKs below. It never
-- writes public tables; UPDATE (id) on the identity-bearing rows exists ONLY
-- because PostgreSQL requires some UPDATE privilege to take the FOR SHARE row
-- locks that serialize release/detach/rename against journal validation.
GRANT USAGE ON SCHEMA public TO portablefs_journal_owner;
GRANT SELECT, REFERENCES ON TABLE
  public.tenants, public.volumes, public.branches, public.commits,
  public.attach_sessions, public.leases
TO portablefs_journal_owner;
GRANT UPDATE (id) ON public.volumes, public.branches,
  public.attach_sessions, public.leases TO portablefs_journal_owner;

-- The schema is created by the migration user (CREATE on the database), then
-- handed to the owner role; everything inside is created AS the owner. The
-- authority role gets USAGE only — every EXECUTE it will ever hold is an
-- explicit later grant.
CREATE SCHEMA pfj;
ALTER SCHEMA pfj OWNER TO portablefs_journal_owner;
REVOKE ALL ON SCHEMA pfj FROM PUBLIC;
GRANT USAGE ON SCHEMA pfj TO portablefs_authority;

SET LOCAL ROLE portablefs_journal_owner;

-- Functions otherwise default to PUBLIC EXECUTE at creation. Revoke that
-- default for everything this owner will ever create in pfj — including the
-- managed API a later migration installs — so no function is callable without
-- an explicit grant, not even in the window before a migration's closing
-- REVOKE. (Tables carry no default PUBLIC privileges.)
-- PostgreSQL's built-in PUBLIC EXECUTE default is global; a per-schema
-- REVOKE cannot reverse it. Revoke at the owner level so every future
-- owner-created function is private until explicitly granted.
ALTER DEFAULT PRIVILEGES FOR ROLE portablefs_journal_owner
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- ── Tables ───────────────────────────────────────────────────────────────────

-- One row per journal generation of a branch. A generation is the durable
-- fact that a live record suffix exists; at most one non-terminal generation
-- per branch. The branch writer lease's fencing token is the SINGLE monotonic
-- writer fence (writer_fence); epoch identifies the digest-chain epoch and the
-- codec pair, and never acts as a second lease clock.
--
-- base_commit_id/base_seq/base_digest anchor recovery: cold start loads
-- exactly base_commit_id and replays [base_seq, next_seq). Logical trims
-- advance the anchor only under proof (a landed checkpoint cut, or a
-- control-only rotation which by construction does not move the manifest
-- anchor). Physically deleted rows lag behind base_seq (physical_trimmed_seq
-- <= base_seq); physical deletion is a separately claimed bounded batch job
-- that never takes the head row lock.
--
-- manager_epoch/authority_runtime_seq/authority_runtime_id bind a managed
-- generation to the pfm control plane's live authority runtime: either all
-- three are NULL (a scope that has never been manager-controlled — dev/local
-- Postgres) or all three carry the live binding. The managed API installed in
-- 011 proves this binding inside every journal transaction; an unmanaged
-- scope must present explicitly NULL facts.
--
-- append_receipt_floor_seq is the exact-once floor for group append receipts:
-- receipts at or above it are retained verbatim, and a retry below it is a
-- typed PF014 eviction — never a blind re-execution.
CREATE TABLE pfj.journal_generations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES public.tenants(id),
  volume_id TEXT NOT NULL REFERENCES public.volumes(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES public.branches(id) ON DELETE CASCADE,
  epoch BIGINT NOT NULL CHECK (epoch >= 1),
  record_codec TEXT NOT NULL CHECK (record_codec = 'pfr1'),
  control_codec TEXT NOT NULL DEFAULT 'pfc1' CHECK (control_codec = 'pfc1'),
  base_commit_id TEXT NOT NULL REFERENCES public.commits(id),
  base_seq BIGINT NOT NULL CHECK (base_seq >= 0),
  base_digest TEXT NOT NULL CHECK (base_digest ~ '^[0-9a-f]{64}$'),
  next_seq BIGINT NOT NULL CHECK (next_seq >= 0),
  tip_digest TEXT NOT NULL CHECK (tip_digest ~ '^[0-9a-f]{64}$'),
  physical_trimmed_seq BIGINT NOT NULL DEFAULT 0 CHECK (physical_trimmed_seq >= 0),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'retiring', 'retired', 'abandoned')),
  -- Backlog accounting for [base_seq, next_seq). Maintained transactionally by
  -- append/trim; CHECKed non-negative so corruption fails closed, and quota
  -- comparisons read THESE columns so no API replica can apply a different
  -- quota. Underflow raises PF010.
  backlog_bytes BIGINT NOT NULL DEFAULT 0 CHECK (backlog_bytes >= 0),
  backlog_records BIGINT NOT NULL DEFAULT 0 CHECK (backlog_records >= 0),
  quota_backlog_bytes BIGINT NOT NULL CHECK (quota_backlog_bytes > 0),
  quota_backlog_records BIGINT NOT NULL CHECK (quota_backlog_records > 0),
  -- Writer binding (fencing facts). writer_fence == the bound lease's fencing
  -- token; claims only ever move it forward. capability_hash is the sha256 of
  -- the writer capability the authority generated at claim time; the raw
  -- capability is never stored, logged, or returned.
  writer_fence BIGINT,
  attach_session_id TEXT REFERENCES public.attach_sessions(id),
  lease_id TEXT REFERENCES public.leases(id),
  holder_id TEXT,
  authority_instance_id TEXT,
  capability_hash TEXT CHECK (capability_hash IS NULL OR capability_hash ~ '^[0-9a-f]{64}$'),
  -- Manager-plane binding (all-or-nothing, see table comment).
  manager_epoch BIGINT,
  authority_runtime_seq BIGINT,
  authority_runtime_id TEXT,
  append_receipt_floor_seq BIGINT NOT NULL DEFAULT 0 CHECK (append_receipt_floor_seq >= 0),
  claimed_at BIGINT,
  -- Checkpoint cut (mirrors vcs/internal/wal CheckpointCut, same lifecycle:
  -- prepared -> landed|aborted -> finalized; core fields immutable per
  -- operation, commit id sticky once landed).
  cut_operation_id TEXT,
  cut_status TEXT CHECK (cut_status IN ('prepared', 'landed', 'aborted', 'finalized')),
  cut_watermark BIGINT,
  cut_expected_head_commit_id TEXT,
  cut_tree_hash TEXT,
  cut_request_hash TEXT,
  cut_auxiliary_hash TEXT,
  cut_commit_id TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  CHECK (base_seq <= next_seq),
  CHECK (physical_trimmed_seq <= base_seq),
  CHECK ((cut_operation_id IS NULL) = (cut_status IS NULL)),
  CHECK (cut_operation_id IS NULL OR cut_watermark IS NOT NULL),
  CHECK (cut_status IS DISTINCT FROM 'landed' OR cut_commit_id IS NOT NULL),
  CHECK (cut_status IS DISTINCT FROM 'finalized' OR cut_commit_id IS NOT NULL),
  CONSTRAINT journal_generation_manager_binding_check CHECK (
    (manager_epoch IS NULL AND authority_runtime_seq IS NULL
      AND authority_runtime_id IS NULL)
    OR
    (manager_epoch >= 1 AND authority_runtime_seq >= 1
      AND authority_runtime_id IS NOT NULL AND length(authority_runtime_id) > 0)
  ),
  UNIQUE (branch_id, epoch)
);

CREATE UNIQUE INDEX journal_generations_live_by_branch
  ON pfj.journal_generations(branch_id)
  WHERE status IN ('active', 'suspended', 'retiring');

-- Exact PFR1 record payloads plus the digest chain over exactly those bytes.
-- payload_bytes is CHECK-bound to the true octet length so accounting can
-- never drift from storage, and every payload must carry the PFR1 magic.
CREATE TABLE pfj.journal_records (
  generation_id TEXT NOT NULL REFERENCES pfj.journal_generations(id) ON DELETE CASCADE,
  seq BIGINT NOT NULL CHECK (seq >= 0),
  payload BYTEA NOT NULL,
  payload_bytes BIGINT NOT NULL CHECK (payload_bytes = octet_length(payload)),
  record_hash TEXT NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
  chain_digest TEXT NOT NULL CHECK (chain_digest ~ '^[0-9a-f]{64}$'),
  created_at BIGINT NOT NULL,
  PRIMARY KEY (generation_id, seq),
  CHECK (octet_length(payload) BETWEEN 5 AND 8388608),
  CHECK (substring(payload from 1 for 4) = '\x50465231'::bytea)
);

-- Claim receipts: durable idempotency for journal claims, written in the SAME
-- transaction as the fencing update they describe. Keyed by scope — never by
-- generation — and PERMANENT: an operation id plus fingerprint is a lasting
-- tombstone that survives generation retirement and branch/volume deletion
-- (no FKs, deliberately). A lost-response retry resolves the receipt first;
-- it replays the stored response only while that claim is still current, and
-- returns an explicitly stale/fenced receipt after a takeover — never a
-- seemingly usable claim. writer_capability_hash authenticates the replayer
-- as the ORIGINAL claimant; a receipt is never served to a different
-- capability.
CREATE TABLE pfj.journal_claim_receipts (
  tenant_id TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  generation_id TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  writer_fence BIGINT NOT NULL,
  writer_capability_hash TEXT NOT NULL CHECK (writer_capability_hash ~ '^[0-9a-f]{64}$'),
  response JSONB NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, volume_id, branch_id, operation_id)
);

-- Scope-namespaced receipts for receipted journal lifecycle operations
-- (currently: exact suspension). Permanent retention; fingerprints never
-- disappear or resurrect. The expected head (next_seq/tip_digest) is part of
-- the receipt identity so a step-down is exact, and the original writer
-- capability hash authenticates any replay.
CREATE TABLE pfj.journal_op_receipts (
  tenant_id TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  domain TEXT NOT NULL CHECK (domain IN ('suspend')),
  operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  expected_next_seq BIGINT NOT NULL CHECK (expected_next_seq >= 0),
  expected_tip_digest TEXT NOT NULL CHECK (expected_tip_digest ~ '^[0-9a-f]{64}$'),
  writer_capability_hash TEXT NOT NULL CHECK (writer_capability_hash ~ '^[0-9a-f]{64}$'),
  response JSONB NOT NULL CHECK (octet_length(response::TEXT) <= 262144),
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, volume_id, branch_id, domain, operation_id)
);

-- Group append receipts: the exact-once record of one landed append group,
-- authenticated by the capability hash captured at the original append so an
-- UNKNOWN-outcome retry is answerable even after lease/runtime expiry.
-- Bounded per generation: the managed append prunes to the newest groups and
-- raises journal_generations.append_receipt_floor_seq in the same
-- transaction, so eviction is always a typed fact (PF014), never silence.
-- Receipts die with their generation (unlike the scope-keyed tombstones
-- above, they are meaningless without its chain).
CREATE TABLE pfj.journal_append_receipts (
  generation_id TEXT NOT NULL REFERENCES pfj.journal_generations(id) ON DELETE CASCADE,
  first_seq BIGINT NOT NULL CHECK (first_seq >= 0),
  record_count INT NOT NULL CHECK (record_count BETWEEN 1 AND 128),
  request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  writer_capability_hash TEXT NOT NULL
    CHECK (writer_capability_hash ~ '^[0-9a-f]{64}$'),
  -- Permanent identity/fingerprint tombstone; 011 bounds only the newest
  -- response bodies by setting older bodies to NULL.
  response JSONB CHECK (
    response IS NULL OR octet_length(response::TEXT) <= 262144),
  created_at BIGINT NOT NULL,
  PRIMARY KEY (generation_id, first_seq)
);

-- Remote operation state: the managed-production home of the SAME versioned
-- JSON contract the local file store (vcs/internal/opstate, version 2)
-- persists next to a dev WAL. The Go store logic (validation, non-forgetful
-- receipts, pruning, retention floors) runs client-side exactly as for the
-- file; this table provides the durable, fenced, compare-and-swap byte home so
-- a managed authority never creates a local opstate file. Copy-on-write: every
-- put replaces the whole document under a version check.
CREATE TABLE pfj.opstate (
  volume_id TEXT NOT NULL REFERENCES public.volumes(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES public.branches(id) ON DELETE CASCADE,
  doc JSONB NOT NULL,
  version BIGINT NOT NULL CHECK (version >= 1),
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (volume_id, branch_id),
  CHECK (octet_length(doc::text) <= 16777216)
);

-- ── Cross-object binding validation ─────────────────────────────────────────
-- FKs prove each referenced row exists but not that they describe the SAME
-- volume/branch/session chain. This trigger proves object identity coherence
-- on every generation write, so a claim can never bind a lease from another
-- branch or a session from another volume.
CREATE FUNCTION pfj.generation_binding_check() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_branch_volume TEXT;
  v_volume_tenant TEXT;
  v_commit_volume TEXT;
  v_sess RECORD;
  v_lease RECORD;
BEGIN
  SELECT b.volume_id INTO v_branch_volume FROM public.branches b WHERE b.id = NEW.branch_id;
  IF v_branch_volume IS DISTINCT FROM NEW.volume_id THEN
    RAISE EXCEPTION 'journal generation branch % does not belong to volume %', NEW.branch_id, NEW.volume_id
      USING ERRCODE = 'PF002';
  END IF;
  SELECT v.tenant_id INTO v_volume_tenant FROM public.volumes v WHERE v.id = NEW.volume_id;
  IF v_volume_tenant IS DISTINCT FROM NEW.tenant_id THEN
    RAISE EXCEPTION 'journal generation volume % does not belong to tenant %', NEW.volume_id, NEW.tenant_id
      USING ERRCODE = 'PF002';
  END IF;
  SELECT c.volume_id INTO v_commit_volume FROM public.commits c WHERE c.id = NEW.base_commit_id;
  IF v_commit_volume IS DISTINCT FROM NEW.volume_id THEN
    RAISE EXCEPTION 'journal base commit % does not belong to volume %', NEW.base_commit_id, NEW.volume_id
      USING ERRCODE = 'PF002';
  END IF;
  IF NEW.attach_session_id IS NOT NULL THEN
    SELECT s.volume_id, s.branch_id, s.mode INTO v_sess
      FROM public.attach_sessions s WHERE s.id = NEW.attach_session_id;
    IF v_sess.volume_id IS DISTINCT FROM NEW.volume_id
       OR v_sess.branch_id IS DISTINCT FROM NEW.branch_id
       OR v_sess.mode IS DISTINCT FROM 'write' THEN
      RAISE EXCEPTION 'journal attach session % does not match volume %/branch % (write)',
        NEW.attach_session_id, NEW.volume_id, NEW.branch_id USING ERRCODE = 'PF002';
    END IF;
  END IF;
  IF NEW.lease_id IS NOT NULL THEN
    SELECT l.volume_id, l.branch_id, l.attach_session_id, l.fencing_token INTO v_lease
      FROM public.leases l WHERE l.id = NEW.lease_id;
    IF v_lease.volume_id IS DISTINCT FROM NEW.volume_id
       OR v_lease.branch_id IS DISTINCT FROM NEW.branch_id
       OR v_lease.attach_session_id IS DISTINCT FROM NEW.attach_session_id
       OR v_lease.fencing_token IS DISTINCT FROM NEW.writer_fence THEN
      RAISE EXCEPTION 'journal lease % does not match its bound session/branch/fence', NEW.lease_id
        USING ERRCODE = 'PF002';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER journal_generation_binding
  BEFORE INSERT OR UPDATE ON pfj.journal_generations
  FOR EACH ROW EXECUTE FUNCTION pfj.generation_binding_check();

-- ── Internal helpers (owner-only; no EXECUTE grants, ever) ───────────────────

-- Database time in milliseconds. VOLATILE: it reads the wall clock and every
-- call inside one transaction must observe real elapsed time (fence checks
-- sample it AFTER lock waits, not before).
CREATE FUNCTION pfj.now_ms() RETURNS BIGINT
LANGUAGE sql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT $$;

-- One digest-chain step over exact payload bytes:
-- sha256(prev[32] || be64(len(payload)) || payload), hex in/out.
CREATE FUNCTION pfj.chain_step(prev_hex TEXT, payload BYTEA) RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT encode(
    sha256(decode(prev_hex, 'hex') || int8send(octet_length(payload)::int8) || payload),
    'hex')
$$;

CREATE FUNCTION pfj.zero_digest() RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT repeat('0', 64) $$;

-- Checked non-negative BIGINT addition for all journal counters/byte totals.
-- Overflow is a typed bound failure, never a wrapped accounting value.
CREATE FUNCTION pfj.checked_add(
  p_left BIGINT,p_right BIGINT,p_what TEXT
) RETURNS BIGINT
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF p_left IS NULL OR p_right IS NULL OR p_left<0 OR p_right<0
     OR p_left>9223372036854775807::BIGINT-p_right THEN
    RAISE EXCEPTION '% exceeds the non-negative BIGINT range',p_what
      USING ERRCODE='PF004';
  END IF;
  RETURN p_left+p_right;
END;
$$;

-- The chain digest at an LSN boundary: base_digest at base_seq, otherwise the
-- stored chain of the record just below the boundary. Rows below base_seq may
-- already be physically deleted, so callers only ask for boundaries in
-- [base_seq, next_seq].
CREATE FUNCTION pfj.digest_at(g pfj.journal_generations, boundary BIGINT) RETURNS TEXT
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v TEXT;
BEGIN
  IF boundary < g.base_seq OR boundary > g.next_seq THEN
    RAISE EXCEPTION 'digest boundary % outside [%, %]', boundary, g.base_seq, g.next_seq
      USING ERRCODE = 'PF008';
  END IF;
  IF boundary = g.base_seq THEN
    RETURN g.base_digest;
  END IF;
  SELECT r.chain_digest INTO v
    FROM pfj.journal_records r
    WHERE r.generation_id = g.id AND r.seq = boundary - 1;
  IF v IS NULL THEN
    RAISE EXCEPTION 'journal record % is missing below the head', boundary - 1
      USING ERRCODE = 'PF010';
  END IF;
  RETURN v;
END;
$$;

-- Locks and returns the generation head row (the append head lock; lock order
-- position 1, before any branch/session/lease row lock).
CREATE FUNCTION pfj.lock_generation(p_generation_id TEXT) RETURNS pfj.journal_generations
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
BEGIN
  SELECT * INTO g FROM pfj.journal_generations WHERE id = p_generation_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found', p_generation_id USING ERRCODE = 'PF007';
  END IF;
  RETURN g;
END;
$$;

-- Transaction-local durability/lock settings for every mutating function.
-- set_config(..., true) survives function exit until COMMIT, so the commit of
-- THIS transaction is synchronous regardless of connection defaults — and a
-- pre-existing remote_apply setting is never downgraded to plain 'on'.
-- (statement_timeout cannot take effect mid-statement, so the Go pool also
-- pins statement_timeout/lock_timeout as session defaults.)
CREATE FUNCTION pfj.require_txn_settings() RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_commit TEXT := current_setting('synchronous_commit');
BEGIN
  IF v_commit NOT IN ('on', 'remote_apply') THEN
    PERFORM set_config('synchronous_commit', 'on', TRUE);
  END IF;
  PERFORM set_config('lock_timeout', '5s', TRUE);
END;
$$;

-- The redacted generation snapshot returned to callers. The capability hash
-- is intentionally OMITTED — receipts never carry capability material — and
-- every BIGINT is serialized as a decimal string so no consumer ever routes
-- an epoch/seq/fence through a JavaScript number.
CREATE FUNCTION pfj.generation_json(g pfj.journal_generations) RETURNS JSONB
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'generationId', g.id,
    'tenantId', g.tenant_id,
    'volumeId', g.volume_id,
    'branchId', g.branch_id,
    'branchName', (SELECT b.name FROM public.branches b WHERE b.id = g.branch_id),
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

-- Proves the caller is the CURRENT fenced writer of a generation, with
-- exactly ONE capability presented. Mutating callers already hold the
-- generation FOR UPDATE (lock order position 1); this function then locks the
-- branch, attach session, and public lease rows FOR SHARE in that fixed
-- deterministic order, samples DB time only AFTER those waits, and validates
-- the exact writer identity. Release/detach/rename must therefore wait or win
-- before validation; they can never commit between validation and the journal
-- mutation.
CREATE FUNCTION pfj.require_writer(
  g pfj.journal_generations,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_branch RECORD;
  v_session RECORD;
  v_lease RECORD;
BEGIN
  IF g.status <> 'active' THEN
    RAISE EXCEPTION 'journal generation % is % (not active)', g.id, g.status
      USING ERRCODE = 'PF001';
  END IF;
  IF p_epoch IS DISTINCT FROM g.epoch THEN
    RAISE EXCEPTION 'journal epoch mismatch' USING ERRCODE = 'PF002';
  END IF;
  IF p_record_codec IS DISTINCT FROM g.record_codec
     OR p_control_codec IS DISTINCT FROM g.control_codec THEN
    RAISE EXCEPTION 'journal codec mismatch' USING ERRCODE = 'PF005';
  END IF;
  IF g.capability_hash IS NULL OR g.writer_fence IS NULL
     OR g.lease_id IS NULL OR g.attach_session_id IS NULL THEN
    RAISE EXCEPTION 'journal generation % has no bound writer', g.id
      USING ERRCODE = 'PF001';
  END IF;
  IF p_capability IS NULL
     OR encode(sha256(convert_to(p_capability, 'UTF8')), 'hex') <> g.capability_hash THEN
    RAISE EXCEPTION 'journal writer capability rejected' USING ERRCODE = 'PF001';
  END IF;
  IF p_lease_id IS DISTINCT FROM g.lease_id
     OR p_fencing_token IS DISTINCT FROM g.writer_fence THEN
    RAISE EXCEPTION 'journal writer fence is stale' USING ERRCODE = 'PF001';
  END IF;

  SELECT b.id, b.name INTO v_branch FROM public.branches b
    WHERE b.id = g.branch_id AND b.volume_id = g.volume_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal branch is gone' USING ERRCODE = 'PF007';
  END IF;
  SELECT s.id, s.status, s.mode, s.holder_id INTO v_session
    FROM public.attach_sessions s WHERE s.id = g.attach_session_id FOR SHARE;
  SELECT l.id, l.expires_at, l.released_at, l.fencing_token,
         l.attach_session_id, l.holder_id, l.exclusive INTO v_lease
    FROM public.leases l WHERE l.id = g.lease_id FOR SHARE;
  v_now := pfj.now_ms();
  IF v_session.id IS NULL OR v_session.status <> 'attached'
     OR v_session.mode <> 'write' OR v_session.holder_id IS DISTINCT FROM g.holder_id THEN
    RAISE EXCEPTION 'journal writer attach session is not live' USING ERRCODE = 'PF001';
  END IF;
  IF v_lease.id IS NULL OR NOT v_lease.exclusive
     OR v_lease.released_at IS NOT NULL OR v_lease.expires_at <= v_now
     OR v_lease.fencing_token IS DISTINCT FROM g.writer_fence
     OR v_lease.attach_session_id IS DISTINCT FROM g.attach_session_id
     OR v_lease.holder_id IS DISTINCT FROM g.holder_id THEN
    RAISE EXCEPTION 'journal writer lease is not live at database time'
      USING ERRCODE = 'PF001';
  END IF;
END;
$$;

-- ── Owner-only lifecycle primitives (no EXECUTE grants) ──────────────────────
-- Maintenance and history-boundary primitives, executable only through owner
-- membership (the admin/migration credential) and kept as extension points
-- for the future HistoryCut worker role. They are DELIBERATELY not part of
-- the authority surface 011 grants: no authority credential can snapshot a
-- branch unauthenticated, trim, rotate, adopt bases, physically delete, or
-- retire anything. None of this is the ordinary persistence path — ordinary
-- durability is the fenced append the managed API provides; a drain or
-- checkpoint cut is only ever an explicit, proven history boundary.

-- journal_head: the redacted head identity for a branch's live generation.
-- Owner-only diagnostic snapshot (it never includes capability material);
-- the authenticated equivalent for the managed authority is installed by
-- 011. Returns NULL when the branch has no live generation.
CREATE FUNCTION pfj.journal_head(
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_branch_id TEXT;
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
  v_lease_live BOOLEAN := FALSE;
BEGIN
  SELECT b.id INTO v_branch_id
    FROM public.branches b
    JOIN public.volumes v ON v.id = b.volume_id
    WHERE b.volume_id = p_volume_id AND b.name = p_branch_name AND v.tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'volume %/branch % not found for tenant', p_volume_id, p_branch_name
      USING ERRCODE = 'PF007';
  END IF;
  SELECT * INTO g FROM pfj.journal_generations
    WHERE branch_id = v_branch_id AND status IN ('active', 'suspended', 'retiring');
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF g.lease_id IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1 FROM public.leases l
      WHERE l.id = g.lease_id AND l.released_at IS NULL AND l.expires_at > v_now
        AND l.fencing_token = g.writer_fence) INTO v_lease_live;
  END IF;
  RETURN pfj.generation_json(g) || jsonb_build_object(
    'writerLeaseLive', v_lease_live, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- journal_prepare_cut / journal_resolve_cut / journal_finalize_cut: the
-- remote CheckpointCut lifecycle, mirroring vcs/internal/wal semantics:
-- prepared -> landed|aborted -> finalized, immutable core, sticky commit id,
-- no phase regression, a new operation only after the previous is terminal.
CREATE FUNCTION pfj.journal_prepare_cut(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT,
  p_operation_id TEXT,
  p_watermark BIGINT,
  p_expected_head_commit_id TEXT,
  p_tree_hash TEXT,
  p_request_hash TEXT,
  p_auxiliary_hash TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_operation_id IS NULL OR length(p_operation_id) = 0 THEN
    RAISE EXCEPTION 'cut operation id required' USING ERRCODE = 'PF008';
  END IF;
  g := pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(g, p_epoch, p_capability, p_lease_id, p_fencing_token,
                             p_record_codec, p_control_codec);
  IF p_watermark IS NULL OR p_watermark < g.base_seq OR p_watermark > g.next_seq THEN
    RAISE EXCEPTION 'cut watermark % outside [%, %]', p_watermark, g.base_seq, g.next_seq
      USING ERRCODE = 'PF002';
  END IF;
  IF g.cut_operation_id IS NOT NULL AND g.cut_operation_id <> p_operation_id
     AND g.cut_status NOT IN ('aborted', 'finalized') THEN
    RAISE EXCEPTION 'cut % conflicts with active cut %', p_operation_id, g.cut_operation_id
      USING ERRCODE = 'PF002';
  END IF;
  IF g.cut_operation_id = p_operation_id THEN
    -- Idempotent re-prepare: identical core only, never a phase regression.
    IF g.cut_watermark IS DISTINCT FROM p_watermark
       OR g.cut_expected_head_commit_id IS DISTINCT FROM p_expected_head_commit_id
       OR g.cut_tree_hash IS DISTINCT FROM p_tree_hash
       OR g.cut_request_hash IS DISTINCT FROM p_request_hash
       OR g.cut_auxiliary_hash IS DISTINCT FROM p_auxiliary_hash THEN
      RAISE EXCEPTION 'cut % content changed on retry', p_operation_id USING ERRCODE = 'PF002';
    END IF;
    RETURN pfj.generation_json(g) -> 'cut';
  END IF;
  UPDATE pfj.journal_generations SET
    cut_operation_id = p_operation_id,
    cut_status = 'prepared',
    cut_watermark = p_watermark,
    cut_expected_head_commit_id = p_expected_head_commit_id,
    cut_tree_hash = p_tree_hash,
    cut_request_hash = p_request_hash,
    cut_auxiliary_hash = p_auxiliary_hash,
    cut_commit_id = NULL,
    updated_at = v_now
  WHERE id = g.id
  RETURNING * INTO g;
  RETURN pfj.generation_json(g) -> 'cut';
END;
$$;

CREATE FUNCTION pfj.journal_resolve_cut(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT,
  p_operation_id TEXT,
  p_commit_id TEXT,
  p_landed BOOLEAN
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
  v_commit_volume TEXT;
BEGIN
  PERFORM pfj.require_txn_settings();
  g := pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(g, p_epoch, p_capability, p_lease_id, p_fencing_token,
                             p_record_codec, p_control_codec);
  IF g.cut_operation_id IS DISTINCT FROM p_operation_id THEN
    RAISE EXCEPTION 'cut % not found (current %)', p_operation_id, g.cut_operation_id
      USING ERRCODE = 'PF007';
  END IF;
  IF p_landed THEN
    IF p_commit_id IS NULL OR length(p_commit_id) = 0 THEN
      RAISE EXCEPTION 'landed cut requires a commit id' USING ERRCODE = 'PF008';
    END IF;
    -- The landed proof must name a real commit of THIS volume.
    SELECT c.volume_id INTO v_commit_volume FROM public.commits c WHERE c.id = p_commit_id;
    IF v_commit_volume IS DISTINCT FROM g.volume_id THEN
      RAISE EXCEPTION 'cut commit % is not a commit of volume %', p_commit_id, g.volume_id
        USING ERRCODE = 'PF002';
    END IF;
    IF g.cut_status IN ('landed', 'finalized') THEN
      IF g.cut_commit_id IS DISTINCT FROM p_commit_id THEN
        RAISE EXCEPTION 'cut % commit changed (durable %, caller %)',
          p_operation_id, g.cut_commit_id, p_commit_id USING ERRCODE = 'PF002';
      END IF;
      RETURN pfj.generation_json(g) -> 'cut';
    END IF;
    IF g.cut_status <> 'prepared' THEN
      RAISE EXCEPTION 'cut % cannot land from %', p_operation_id, g.cut_status USING ERRCODE = 'PF002';
    END IF;
    UPDATE pfj.journal_generations SET
      cut_status = 'landed', cut_commit_id = p_commit_id, updated_at = v_now
      WHERE id = g.id RETURNING * INTO g;
  ELSE
    IF g.cut_status = 'aborted' THEN
      RETURN pfj.generation_json(g) -> 'cut';
    END IF;
    IF g.cut_status <> 'prepared' THEN
      RAISE EXCEPTION 'cut % cannot abort from %', p_operation_id, g.cut_status USING ERRCODE = 'PF002';
    END IF;
    UPDATE pfj.journal_generations SET
      cut_status = 'aborted', cut_commit_id = NULL, updated_at = v_now
      WHERE id = g.id RETURNING * INTO g;
  END IF;
  RETURN pfj.generation_json(g) -> 'cut';
END;
$$;

CREATE FUNCTION pfj.journal_finalize_cut(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT,
  p_operation_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
BEGIN
  PERFORM pfj.require_txn_settings();
  g := pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(g, p_epoch, p_capability, p_lease_id, p_fencing_token,
                             p_record_codec, p_control_codec);
  IF g.cut_operation_id IS DISTINCT FROM p_operation_id THEN
    RAISE EXCEPTION 'cut % not found (current %)', p_operation_id, g.cut_operation_id
      USING ERRCODE = 'PF007';
  END IF;
  IF g.cut_status = 'finalized' THEN
    RETURN pfj.generation_json(g) -> 'cut';
  END IF;
  IF g.cut_status <> 'landed' THEN
    RAISE EXCEPTION 'cut % is not landed', p_operation_id USING ERRCODE = 'PF002';
  END IF;
  IF g.base_seq < g.cut_watermark THEN
    RAISE EXCEPTION 'cut % is not compacted (base %, watermark %)',
      p_operation_id, g.base_seq, g.cut_watermark USING ERRCODE = 'PF011';
  END IF;
  UPDATE pfj.journal_generations SET cut_status = 'finalized', updated_at = v_now
    WHERE id = g.id RETURNING * INTO g;
  RETURN pfj.generation_json(g) -> 'cut';
END;
$$;

-- journal_logical_trim: advance the verified recovery anchor. Proof is the
-- generation's OWN landed/finalized cut: through_seq must not exceed the cut
-- watermark, and the new base commit is exactly the cut's landed commit (a
-- same-volume commit id from anywhere else is NOT proof). Rows below the new
-- base stay for the physical trimmer; backlog accounting moves here, fails
-- closed on underflow (PF010).
CREATE FUNCTION pfj.journal_logical_trim(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT,
  p_through_seq BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
  v_trim_bytes BIGINT;
  v_trim_records BIGINT;
  v_new_base_digest TEXT;
BEGIN
  PERFORM pfj.require_txn_settings();
  g := pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(g, p_epoch, p_capability, p_lease_id, p_fencing_token,
                             p_record_codec, p_control_codec);
  IF p_through_seq <= g.base_seq THEN
    RETURN pfj.generation_json(g);
  END IF;
  IF p_through_seq > g.next_seq THEN
    RAISE EXCEPTION 'trim through % exceeds head %', p_through_seq, g.next_seq USING ERRCODE = 'PF008';
  END IF;
  IF g.cut_status IS NULL OR g.cut_status NOT IN ('landed', 'finalized')
     OR g.cut_commit_id IS NULL OR p_through_seq IS DISTINCT FROM g.cut_watermark THEN
    RAISE EXCEPTION 'trim through % is not the exact landed checkpoint cut %',
      p_through_seq, g.cut_watermark
      USING ERRCODE = 'PF011';
  END IF;
  v_new_base_digest := pfj.digest_at(g, p_through_seq);
  SELECT COALESCE(SUM(r.payload_bytes), 0), COUNT(*) INTO v_trim_bytes, v_trim_records
    FROM pfj.journal_records r
    WHERE r.generation_id = g.id AND r.seq >= g.base_seq AND r.seq < p_through_seq;
  IF v_trim_records <> p_through_seq - g.base_seq THEN
    RAISE EXCEPTION 'trim range [%, %) holds % rows; accounting failed closed',
      g.base_seq, p_through_seq, v_trim_records USING ERRCODE = 'PF010';
  END IF;
  IF v_trim_bytes > g.backlog_bytes OR v_trim_records > g.backlog_records THEN
    RAISE EXCEPTION 'trim would underflow backlog accounting' USING ERRCODE = 'PF010';
  END IF;
  UPDATE pfj.journal_generations SET
    base_seq = p_through_seq,
    base_digest = v_new_base_digest,
    base_commit_id = g.cut_commit_id,
    backlog_bytes = backlog_bytes - v_trim_bytes,
    backlog_records = backlog_records - v_trim_records,
    updated_at = v_now
  WHERE id = g.id RETURNING * INTO g;
  RETURN pfj.generation_json(g);
END;
$$;

-- journal_rotate_control: control-only maintenance rotation. The retained
-- sidecar snapshot record at p_sidecar_seq must be durable and strictly above
-- the watermark; the manifest anchor does NOT move (control records change no
-- user state — the fenced caller proves control-onlyness from the decoded
-- records before calling, exactly as the file WAL does). Refuses to cross a
-- prepared checkpoint cut. Atomic, so there is no prepared/finalized
-- maintenance state to recover remotely.
CREATE FUNCTION pfj.journal_rotate_control(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT,
  p_watermark BIGINT,
  p_sidecar_seq BIGINT,
  p_sidecar_hash TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
  v_sidecar RECORD;
  v_trim_bytes BIGINT;
  v_trim_records BIGINT;
  v_new_base_digest TEXT;
BEGIN
  PERFORM pfj.require_txn_settings();
  g := pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(g, p_epoch, p_capability, p_lease_id, p_fencing_token,
                             p_record_codec, p_control_codec);
  IF p_watermark <= g.base_seq THEN
    RETURN pfj.generation_json(g);
  END IF;
  IF p_watermark > p_sidecar_seq OR p_sidecar_seq >= g.next_seq THEN
    RAISE EXCEPTION 'rotation sidecar % is not retained above watermark %', p_sidecar_seq, p_watermark
      USING ERRCODE = 'PF002';
  END IF;
  IF g.cut_status = 'prepared' AND g.cut_watermark < p_watermark THEN
    RAISE EXCEPTION 'rotation through % crosses prepared checkpoint cut %', p_watermark, g.cut_watermark
      USING ERRCODE = 'PF002';
  END IF;
  SELECT r.record_hash INTO v_sidecar
    FROM pfj.journal_records r WHERE r.generation_id = g.id AND r.seq = p_sidecar_seq;
  IF NOT FOUND OR v_sidecar.record_hash IS DISTINCT FROM p_sidecar_hash THEN
    RAISE EXCEPTION 'rotation sidecar hash mismatch at %', p_sidecar_seq USING ERRCODE = 'PF002';
  END IF;
  v_new_base_digest := pfj.digest_at(g, p_watermark);
  SELECT COALESCE(SUM(r.payload_bytes), 0), COUNT(*) INTO v_trim_bytes, v_trim_records
    FROM pfj.journal_records r
    WHERE r.generation_id = g.id AND r.seq >= g.base_seq AND r.seq < p_watermark;
  IF v_trim_records <> p_watermark - g.base_seq THEN
    RAISE EXCEPTION 'rotation range [%, %) holds % rows; accounting failed closed',
      g.base_seq, p_watermark, v_trim_records USING ERRCODE = 'PF010';
  END IF;
  IF v_trim_bytes > g.backlog_bytes OR v_trim_records > g.backlog_records THEN
    RAISE EXCEPTION 'rotation would underflow backlog accounting' USING ERRCODE = 'PF010';
  END IF;
  UPDATE pfj.journal_generations SET
    base_seq = p_watermark,
    base_digest = v_new_base_digest,
    backlog_bytes = backlog_bytes - v_trim_bytes,
    backlog_records = backlog_records - v_trim_records,
    updated_at = v_now
  WHERE id = g.id RETURNING * INTO g;
  RETURN pfj.generation_json(g);
END;
$$;

-- journal_physical_trim: bounded physical deletion of rows already below the
-- logical base. Deliberately takes NO generation row lock (appends never wait
-- on GC); progress is recorded with a conditional update that only moves
-- physical_trimmed_seq forward.
CREATE FUNCTION pfj.journal_physical_trim(
  p_generation_id TEXT,
  p_max_rows INT DEFAULT 512
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_base BIGINT;
  v_limit INT := LEAST(GREATEST(COALESCE(p_max_rows, 512), 1), 4096);
  v_deleted BIGINT;
  v_new_floor BIGINT;
BEGIN
  PERFORM pfj.require_txn_settings();
  SELECT base_seq INTO v_base FROM pfj.journal_generations WHERE id = p_generation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found', p_generation_id USING ERRCODE = 'PF007';
  END IF;
  WITH doomed AS (
    SELECT r.seq FROM pfj.journal_records r
      WHERE r.generation_id = p_generation_id AND r.seq < v_base
      ORDER BY r.seq
      LIMIT v_limit
  ), gone AS (
    DELETE FROM pfj.journal_records r
      USING doomed d
      WHERE r.generation_id = p_generation_id AND r.seq = d.seq
      RETURNING r.seq
  )
  SELECT COUNT(*), COALESCE(MAX(seq) + 1, 0) INTO v_deleted, v_new_floor FROM gone;
  IF v_deleted > 0 THEN
    UPDATE pfj.journal_generations
      SET physical_trimmed_seq = GREATEST(physical_trimmed_seq, v_new_floor)
      WHERE id = p_generation_id AND physical_trimmed_seq < v_new_floor;
  END IF;
  RETURN jsonb_build_object('deleted', v_deleted, 'baseSeq', v_base);
END;
$$;

-- journal_retire: terminal retirement after a strong drain — every record
-- logically trimmed under cut proof (base == head) and no prepared cut in
-- flight. The next claim starts a NEW generation (fresh epoch/base). This is
-- also the exceptional legacy-migration boundary: a drained volume retires
-- its generation and the replacement epoch starts clean. (An ordinary writer
-- never drains to persist; it suspends through the receipted managed API and
-- resumes.)
CREATE FUNCTION pfj.journal_retire(
  p_generation_id TEXT,
  p_epoch BIGINT,
  p_capability TEXT,
  p_lease_id TEXT,
  p_fencing_token BIGINT,
  p_record_codec TEXT,
  p_control_codec TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT := pfj.now_ms();
BEGIN
  PERFORM pfj.require_txn_settings();
  g := pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(g, p_epoch, p_capability, p_lease_id, p_fencing_token,
                             p_record_codec, p_control_codec);
  IF g.base_seq <> g.next_seq THEN
    RAISE EXCEPTION 'retire requires a drained journal (base %, head %)', g.base_seq, g.next_seq
      USING ERRCODE = 'PF011';
  END IF;
  IF g.cut_status = 'prepared' THEN
    RAISE EXCEPTION 'retire refuses a prepared checkpoint cut' USING ERRCODE = 'PF011';
  END IF;
  UPDATE pfj.journal_generations SET
    status = 'retired',
    capability_hash = NULL,
    updated_at = v_now
  WHERE id = g.id RETURNING * INTO g;
  RETURN pfj.generation_json(g);
END;
$$;

-- ── Privileges ───────────────────────────────────────────────────────────────
-- The default-privileges revocation above already stripped PUBLIC EXECUTE
-- from everything created in this file; assert the end state explicitly all
-- the same. NOTHING is granted to portablefs_authority here — it holds schema
-- USAGE only until 011 grants the managed API surface. Table access stays
-- owner-only (SECURITY DEFINER functions are the only path).
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pfj FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pfj FROM PUBLIC;

RESET ROLE;
