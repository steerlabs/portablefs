-- Manager control plane (pfm): the remote truth the singleton PRODUCTION
-- authority manager runs against. No file ledger, no local WAL: the singleton
-- manager claim (a DB-time lease), per-scope authority runtime rows, access
-- lease rows, and operation receipts all live here.
--
-- SECURITY MODEL (mirrors pfj in 009_remote_journal.sql)
--   portablefs_manager_owner  NOLOGIN. Owns the pfm schema, tables, and every
--                             SECURITY DEFINER function. Nothing logs in as it.
--   portablefs_manager        NOLOGIN capability role. Deployments create a
--                             LOGIN role and GRANT portablefs_manager TO it.
--                             EXECUTE on exactly the pfm.* API functions and
--                             NO table access at all.
--   portablefs_journal_owner  Crosses into pfm through exactly four EXECUTE
--                             grants (binding verifier + durability guard
--                             functions). It has NO pfm table access.
--   (migration/admin user)    Runs migrations; distinct from the manager login
--                             and from the authority login.
--
-- LOCK ORDER: the global order documented in 009_remote_journal.sql. pfm
-- functions take (0) advisory locks first, then (6) the manager claim row,
-- then (7) the authority runtime row, then (8) access lease rows in
-- C-collated lease_id order, then (9) inserts. Durability admission (PF015)
-- and the linearizing clock sample happen after the LAST lock, immediately
-- before the first write.
--
-- ERROR SQLSTATES (shared vocabulary with pfj; see 009)
--   PF001 stale/fenced        (manager claim dead/superseded/capability wrong)
--   PF002 conflict            (CAS mismatch; content changed under an id)
--   PF004 bounds              (batch overflow; a BIGINT counter is exhausted)
--   PF007 not found
--   PF008 invalid argument
--   PF009 operation replay mismatch (operation id reused with different body)
--   PF010 accounting corruption (a locked row disappeared under a mutation)
--   PF012 lease not active    (DETAIL carries the exact effective facts JSON)
--   PF013 claim held          (live singleton claim owned by another runtime)
--   PF014 receipt evicted     (renew body below the retained floor; the
--                              operation completed once, never re-executes)
--   PF015 durability absent   (DETAIL carries fail-closed durability evidence)
--
-- TIME: every validity decision uses pfm.now_ms() (database clock_timestamp,
-- re-sampled after lock waits). The manager's host clock NEVER participates:
-- callers receive dbTimeMs and expiresAtDbMs and enforce their own monotonic
-- deadlines from those facts.
--
-- FINGERPRINTS: the caller never supplies a fingerprint. Every receipted
-- operation derives one canonical sha256 server-side over a versioned JSONB
-- array of (kind, all semantic request arguments). Authentication proofs
-- (manager epoch/runtime id/capability), the CANDIDATE lease id of
-- access_create, and the derived CAS expectedControlSeq of access_renew are
-- deliberately EXCLUDED from the fingerprint — they authenticate or gate
-- separately, so an exact retry replays even when only those inputs moved.
--
-- RECEIPTS: pfm.receipts is namespaced by (tenant_key, domain, operation_id)
-- and rows are permanent. High-frequency renew receipts live in their own
-- per-lease table: rows are permanent tombstones, response BODIES are
-- compacted beyond the newest 64 per lease (bounded, index-driven pages),
-- and a request below the retained floor answers PF014 — never silent
-- re-execution. Create/release/revoke/batch/sweep/lifecycle receipts keep
-- their bodies. All BIGINTs inside response JSON are canonical decimal
-- strings.

DO $$
BEGIN
  BEGIN
    CREATE ROLE portablefs_manager_owner NOLOGIN;
  -- Roles are cluster-wide while advisory migration locks are database-local;
  -- a simultaneous first install in another database can expose the catalog
  -- uniqueness race directly as unique_violation.
  EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
  END;
  BEGIN
    CREATE ROLE portablefs_manager NOLOGIN;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
  END;
END;
$$;

GRANT portablefs_manager_owner TO CURRENT_USER;

-- Durability evidence must be able to see pg_stat_replication sync states and
-- the cluster identity. These are explicit migration prerequisites: readiness
-- fails closed without them, so refuse the migration rather than install a
-- control plane that can never admit a mutation.
DO $$
BEGIN
  BEGIN
    GRANT pg_read_all_stats TO portablefs_manager_owner;
  EXCEPTION WHEN insufficient_privilege OR undefined_object THEN
    NULL;
  END;
  BEGIN
    GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO portablefs_manager_owner;
  EXCEPTION WHEN insufficient_privilege OR undefined_function THEN
    NULL;
  END;
END
$$;
DO $$
BEGIN
  IF NOT pg_has_role('portablefs_manager_owner', 'pg_read_all_stats', 'MEMBER') THEN
    RAISE EXCEPTION 'migration principal must be able to grant pg_read_all_stats to portablefs_manager_owner';
  END IF;
  IF NOT has_function_privilege(
      'portablefs_manager_owner', 'pg_catalog.pg_control_system()', 'EXECUTE') THEN
    RAISE EXCEPTION 'migration principal must be able to grant pg_control_system() to portablefs_manager_owner';
  END IF;
END
$$;

-- The owner verifies that a caller's tenant namespace really owns the volume
-- it names. It reads exactly these two columns and nothing else in public.
GRANT USAGE ON SCHEMA public TO portablefs_manager_owner;
GRANT SELECT (id, tenant_id) ON public.volumes TO portablefs_manager_owner;

CREATE SCHEMA pfm;
ALTER SCHEMA pfm OWNER TO portablefs_manager_owner;
REVOKE ALL ON SCHEMA pfm FROM PUBLIC;
GRANT USAGE ON SCHEMA pfm TO portablefs_manager;
GRANT USAGE ON SCHEMA pfm TO portablefs_journal_owner;

SET LOCAL ROLE portablefs_manager_owner;

-- Owner-scoped default privileges: future pfm objects are private from
-- PUBLIC by default (functions would otherwise default to PUBLIC EXECUTE).
-- The built-in PUBLIC EXECUTE default is global and cannot be reversed by a
-- per-schema REVOKE. Make every future owner-created function private until
-- it is explicitly granted.
ALTER DEFAULT PRIVILEGES FOR ROLE portablefs_manager_owner
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pfm REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA pfm REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- ── Tables ───────────────────────────────────────────────────────────────────

-- The singleton manager claim: ONE row, keyed by a fixed singleton key. epoch
-- is minted from pfm.manager_epoch_seq (monotonic across takeovers, opaque to
-- callers — always transported as a decimal string). runtime_id is the random
-- identity of the claiming process; capability_hash is sha256(capability) of
-- the unguessable capability that process minted BEFORE claiming. The claim
-- call sends only the hash (so the permanent receipt never contains the raw
-- secret); verification calls send the raw capability, which is hashed and
-- compared but never stored.
CREATE SEQUENCE pfm.manager_epoch_seq AS BIGINT START 1;

CREATE TABLE pfm.manager_claims (
  singleton_key TEXT PRIMARY KEY DEFAULT 'manager' CHECK (singleton_key = 'manager'),
  epoch BIGINT NOT NULL CHECK (epoch >= 1),
  runtime_id TEXT NOT NULL CHECK (length(runtime_id) BETWEEN 1 AND 128),
  claim_operation_id TEXT NOT NULL,
  capability_hash TEXT NOT NULL CHECK (capability_hash ~ '^[0-9a-f]{64}$'),
  claimed_at BIGINT NOT NULL,
  renewed_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  CHECK (renewed_at >= claimed_at),
  CHECK (expires_at > claimed_at)
);

-- One row per child VCS runtime of an authority scope. runtime_seq is the
-- MONOTONIC per-scope sequence; runtime_id is the RANDOM per-start identity.
-- authority_capability_hash is sha256 of the manager-issued capability handed
-- to exactly that child: pfm.verify_authority_binding (and through it every
-- pfj journal transaction) authenticates the child's raw capability against
-- it. At most one live runtime per scope; beginning a new runtime ends the
-- previous one in the same transaction.
CREATE TABLE pfm.authority_runtimes (
  tenant_key TEXT NOT NULL CHECK (length(tenant_key) BETWEEN 1 AND 256),
  volume_id TEXT NOT NULL CHECK (length(volume_id) BETWEEN 1 AND 256),
  branch_name TEXT NOT NULL CHECK (length(branch_name) BETWEEN 1 AND 256),
  runtime_seq BIGINT NOT NULL CHECK (runtime_seq >= 1),
  runtime_id TEXT NOT NULL CHECK (length(runtime_id) BETWEEN 1 AND 128),
  authority_instance_id TEXT NOT NULL,
  manager_epoch BIGINT NOT NULL,
  manager_runtime_id TEXT NOT NULL,
  authority_capability_hash TEXT NOT NULL CHECK (authority_capability_hash ~ '^[0-9a-f]{64}$'),
  state TEXT NOT NULL CHECK (state IN ('live', 'ended')),
  end_reason TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_key, volume_id, branch_name, runtime_seq),
  CHECK ((state = 'ended') = (end_reason IS NOT NULL))
);

-- ONE live runtime per (volume, branch) GLOBALLY — volume ids are primary
-- keys upstream, and pfm.require_scope_tenant pins each volume to exactly one
-- tenant namespace, so this is the physical truth: one manager, one child per
-- scope.
CREATE UNIQUE INDEX authority_runtimes_one_live
  ON pfm.authority_runtimes(volume_id, branch_name)
  WHERE state = 'live';

-- Access leases: the external data-plane leases (tunnel admission), scoped to
-- the manager epoch that minted their tokens. Counters are BIGINTs and cross
-- the wire as decimal strings. Rows are never deleted; terminal states are
-- explicit. renew_receipt_floor is the lowest renew expectedControlSeq whose
-- exact receipt BODY may still be retained (see pfm.access_renew_receipts).
CREATE TABLE pfm.access_leases (
  lease_id TEXT PRIMARY KEY CHECK (length(lease_id) BETWEEN 1 AND 200),
  tenant_key TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_name TEXT NOT NULL,
  consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 256),
  authority_instance_id TEXT NOT NULL,
  authority_runtime_seq BIGINT NOT NULL,
  authority_runtime_id TEXT NOT NULL,
  manager_epoch BIGINT NOT NULL,
  token_generation BIGINT NOT NULL CHECK (token_generation >= 1),
  control_seq BIGINT NOT NULL CHECK (control_seq >= 1),
  renew_receipt_floor BIGINT NOT NULL DEFAULT 1 CHECK (renew_receipt_floor >= 1),
  state TEXT NOT NULL CHECK (state IN ('active', 'released', 'expired', 'revoked')),
  end_reason TEXT CHECK (end_reason IS NULL OR end_reason IN (
    'released', 'expired', 'revoked', 'owner-revoked', 'authority-retired',
    'manager-epoch-superseded')),
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  ended_at BIGINT,
  updated_at BIGINT NOT NULL,
  CHECK ((state = 'active') = (ended_at IS NULL)),
  CHECK ((state = 'active') = (end_reason IS NULL))
);

CREATE INDEX access_leases_active_by_scope
  ON pfm.access_leases(tenant_key, volume_id, branch_name)
  WHERE state = 'active';
CREATE INDEX access_leases_active_by_epoch
  ON pfm.access_leases(manager_epoch)
  WHERE state = 'active';
-- The sweep pages active rows in C-collated lease_id order.
CREATE INDEX access_leases_active_sweep_order
  ON pfm.access_leases(lease_id COLLATE "C")
  WHERE state = 'active';

-- Permanently retained operation receipts, namespaced by tenant/domain/op so
-- the same operation id in two tenants (or two domains) can never collide or
-- leak. The fingerprint is derived SERVER-side (see header) and only ever
-- compared for equality. A NULL response is a compacted tombstone (PF014 on
-- replay); nothing in this repository compacts these domains today.
CREATE TABLE pfm.receipts (
  -- '' is the explicit GLOBAL namespace (manager claim, cross-tenant sweeps).
  tenant_key TEXT NOT NULL CHECK (length(tenant_key) <= 256),
  domain TEXT NOT NULL CHECK (domain IN (
    'manager-claim', 'authority-runtime-begin', 'authority-runtime-end',
    'access', 'access-batch', 'access-sweep', 'lifecycle')),
  operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  response JSONB CHECK (response IS NULL OR octet_length(response::text) <= 262144),
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_key, domain, operation_id)
);

-- High-frequency renew receipts, one row per accepted (or replayed) renew.
-- Rows are PERMANENT tombstones: the key, the canonical fingerprint, and the
-- gating expectedControlSeq are never deleted. Bodies beyond the newest 64
-- per lease are compacted to NULL in bounded index-driven pages by the
-- accepting renew itself; a compacted (or below-floor) retry is PF014.
CREATE TABLE pfm.access_renew_receipts (
  tenant_key TEXT NOT NULL CHECK (length(tenant_key) BETWEEN 1 AND 256),
  lease_id TEXT NOT NULL CHECK (length(lease_id) BETWEEN 1 AND 200),
  operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
  fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  expected_control_seq BIGINT NOT NULL CHECK (expected_control_seq >= 1),
  ttl_ms BIGINT NOT NULL CHECK (ttl_ms BETWEEN 1000 AND 86400000),
  rotate BOOLEAN NOT NULL,
  response JSONB CHECK (response IS NULL OR octet_length(response::text) <= 262144),
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_key, lease_id, operation_id)
);
CREATE INDEX access_renew_receipts_by_lease_seq
  ON pfm.access_renew_receipts(tenant_key, lease_id, expected_control_seq DESC);

-- ── Internal helpers (owner-only; no EXECUTE grants beyond those noted) ─────

-- clock_timestamp advances inside a transaction so deadlines can be
-- re-sampled after lock waits. VOLATILE is the truthful volatility.
CREATE FUNCTION pfm.now_ms() RETURNS BIGINT
LANGUAGE sql VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
$$;

-- Transaction-local settings for every mutating function. synchronous_commit
-- is only raised to the 'on' floor: remote_apply is strictly stronger and is
-- never downgraded; off/local/remote_write are raised to 'on'.
CREATE FUNCTION pfm.require_txn_settings() RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF current_setting('synchronous_commit') NOT IN ('on', 'remote_apply') THEN
    PERFORM set_config('synchronous_commit', 'on', true);
  END IF;
  PERFORM set_config('lock_timeout', '5s', true);
END;
$$;

-- The ONE canonical fingerprint construction: sha256 over the text form of a
-- versioned JSONB array. JSONB array text is injective for text/null parts
-- (strings are quoted and escaped), so no delimiter can smear two requests.
CREATE FUNCTION pfm.request_fingerprint(p_parts JSONB) RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT encode(sha256(convert_to(p_parts::TEXT, 'UTF8')), 'hex')
$$;

-- Structured advisory transaction lock keys (jsonb array text form: length
-- safe, no delimiter collisions). When a function ever takes more than one
-- advisory lock it must acquire them in ascending key order.
CREATE FUNCTION pfm.advisory_key(p_kind TEXT, p_parts TEXT[]) RETURNS BIGINT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT hashtextextended((jsonb_build_array(p_kind) || to_jsonb(p_parts))::TEXT, 0)
$$;

CREATE FUNCTION pfm.scope_lock(p_kind TEXT, p_parts TEXT[]) RETURNS void
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT pg_advisory_xact_lock(pfm.advisory_key(p_kind, p_parts))
$$;

-- Typed BIGINT increment guard: a counter at the BIGINT ceiling raises PF004
-- instead of wrapping or failing with an untyped overflow.
CREATE FUNCTION pfm.require_bigint_headroom(p_value BIGINT, p_what TEXT) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_value IS NULL OR p_value >= 9223372036854775807 THEN
    RAISE EXCEPTION '% counter is exhausted', p_what USING ERRCODE = 'PF004';
  END IF;
END;
$$;

-- Proves the one canonical pfm namespace against metadata ownership before
-- any receipt lookup or runtime mutation. Managed state is keyed exactly
-- t:<public.volumes.tenant_id>; aliases would permit split live-row sets.
CREATE FUNCTION pfm.require_scope_tenant(
  p_tenant_key TEXT,
  p_volume_id TEXT
) RETURNS TEXT
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_metadata_tenant TEXT;
BEGIN
  SELECT v.tenant_id INTO v_metadata_tenant
    FROM public.volumes v WHERE v.id = p_volume_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'volume % not found', p_volume_id USING ERRCODE = 'PF007';
  END IF;
  IF p_tenant_key IS DISTINCT FROM 't:' || v_metadata_tenant THEN
    RAISE EXCEPTION 'tenant namespace does not own volume %', p_volume_id
      USING ERRCODE = 'PF001';
  END IF;
  RETURN v_metadata_tenant;
END;
$$;

-- ── Durability admission ─────────────────────────────────────────────────────

-- The single test-only escape: a custom GUC that is effective ONLY when the
-- ORIGINAL login (session_user, never the SECURITY DEFINER current_user) is a
-- superuser. Production manager/authority logins can never bypass.
CREATE FUNCTION pfm.durability_bypass_active() RETURNS BOOLEAN
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT COALESCE(current_setting('portablefs.test_allow_unsafe_durability', TRUE), '') = 'on'
     AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_roles
       WHERE rolname = session_user AND rolsuper
     )
$$;

-- Cheap boolean hot-path guard: settings, primary/read-write state, and one
-- EXISTS over pg_stat_replication. No JSON is built here; the rich evidence
-- document is assembled only on failure and for explicit readiness reads.
CREATE FUNCTION pfm.durability_ready() RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  -- pg_stat* snapshots persist for a transaction; every admission decision
  -- must see a fresh replication sample after its contended locks.
  PERFORM pg_catalog.pg_stat_clear_snapshot();
  RETURN current_setting('fsync') = 'on'
     AND current_setting('full_page_writes') = 'on'
     AND NOT pg_catalog.pg_is_in_recovery()
     AND current_setting('transaction_read_only') = 'off'
     AND current_setting('synchronous_commit') IN ('on', 'remote_apply')
     AND btrim(COALESCE(current_setting('synchronous_standby_names', TRUE), '')) <> ''
     AND EXISTS (
       SELECT 1 FROM pg_catalog.pg_stat_replication
       WHERE state = 'streaming' AND sync_state IN ('sync', 'quorum')
     );
END
$$;

-- The rich, verifiable evidence document (readiness endpoints and PF015
-- DETAIL). Reports exactly what is visible plus the visibility verdict;
-- callers treat invisible evidence as ABSENT evidence.
CREATE FUNCTION pfm.durability_evidence() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_system_identifier TEXT;
  v_total INT := 0;
  v_streaming INT := 0;
  v_sync INT := 0;
  v_visible BOOLEAN := FALSE;
  v_standbys JSONB := '[]'::JSONB;
  v_sync_names TEXT := COALESCE(current_setting('synchronous_standby_names', TRUE), '');
  v_sync_commit TEXT := current_setting('synchronous_commit');
  v_ready BOOLEAN;
BEGIN
  PERFORM pg_catalog.pg_stat_clear_snapshot();
  BEGIN
    SELECT system_identifier::TEXT INTO v_system_identifier
      FROM pg_catalog.pg_control_system();
  EXCEPTION WHEN insufficient_privilege OR undefined_function THEN
    v_system_identifier := NULL;
  END;

  SELECT COUNT(*)::INT,
         COUNT(*) FILTER (WHERE state = 'streaming')::INT,
         COUNT(*) FILTER (
           WHERE state = 'streaming' AND sync_state IN ('sync', 'quorum'))::INT,
         COUNT(*) FILTER (WHERE state IS NOT NULL) > 0
    INTO v_total, v_streaming, v_sync, v_visible
    FROM pg_catalog.pg_stat_replication;
  IF v_total = 0 THEN
    v_visible := TRUE; -- an empty view is honestly visible: there ARE no standbys
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
           'applicationName', application_name,
           'state', state,
           'syncState', sync_state)) ORDER BY application_name), '[]'::JSONB)
    INTO v_standbys
    FROM (SELECT * FROM pg_catalog.pg_stat_replication LIMIT 16) s;

  v_ready := v_system_identifier IS NOT NULL
    AND current_setting('fsync') = 'on'
    AND current_setting('full_page_writes') = 'on'
    AND NOT pg_catalog.pg_is_in_recovery()
    AND current_setting('transaction_read_only') = 'off'
    AND v_sync_commit IN ('on', 'remote_apply')
    AND btrim(v_sync_names) <> ''
    AND v_visible
    AND v_sync >= 1;

  RETURN jsonb_build_object(
    'systemIdentifier', v_system_identifier,
    'database', current_database(),
    'serverVersion', current_setting('server_version'),
    'fsync', current_setting('fsync'),
    'fullPageWrites', current_setting('full_page_writes'),
    'synchronousCommit', v_sync_commit,
    'synchronousStandbyNames', v_sync_names,
    'inRecovery', pg_catalog.pg_is_in_recovery(),
    'transactionReadOnly', current_setting('transaction_read_only'),
    'walSenders', v_total,
    'streamingStandbys', v_streaming,
    'syncOrQuorumStandbys', v_sync,
    'replicationVisible', v_visible,
    'standbys', v_standbys,
    'ready', v_ready,
    'testBypassActive', pfm.durability_bypass_active(),
    'dbTimeMs', pfm.now_ms()::TEXT
  );
END;
$$;

-- The mutation admission guard: cheap boolean check on the hot path; the
-- rich evidence JSON is built only when admission FAILS (PF015 DETAIL).
CREATE FUNCTION pfm.require_durable_primary() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF pfm.durability_ready() OR pfm.durability_bypass_active() THEN
    RETURN;
  END IF;
  RAISE EXCEPTION 'durable synchronous primary evidence is absent'
    USING ERRCODE = 'PF015', DETAIL = pfm.durability_evidence()::TEXT;
END;
$$;

-- ── Manager/receipt/lease helpers ────────────────────────────────────────────

-- Proves the caller IS the live singleton manager. FOR SHARE (lock-order
-- position 6) serializes against a concurrent takeover/renew committing under
-- us; the deadline clock is sampled only AFTER the claim row is locked. A
-- function that takes later locks calls this again afterwards — re-acquiring
-- the held FOR SHARE is free and refreshes the deadline sample.
CREATE FUNCTION pfm.require_manager(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT
) RETURNS BIGINT -- pfm.now_ms() sampled after the claim lock
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  c pfm.manager_claims;
BEGIN
  IF p_manager_epoch IS NULL OR p_manager_runtime_id IS NULL OR p_manager_capability IS NULL THEN
    RAISE EXCEPTION 'manager identity (epoch, runtime id, capability) is required' USING ERRCODE = 'PF008';
  END IF;
  SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = 'manager' FOR SHARE;
  v_now := pfm.now_ms();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no manager claim exists' USING ERRCODE = 'PF001';
  END IF;
  IF c.epoch IS DISTINCT FROM p_manager_epoch
     OR c.runtime_id IS DISTINCT FROM p_manager_runtime_id THEN
    RAISE EXCEPTION 'manager claim is superseded (caller epoch %, live epoch %)',
      p_manager_epoch, c.epoch
      USING ERRCODE = 'PF001',
            DETAIL = jsonb_build_object('currentEpoch', c.epoch::TEXT)::TEXT;
  END IF;
  IF encode(sha256(convert_to(p_manager_capability, 'UTF8')), 'hex') <> c.capability_hash THEN
    RAISE EXCEPTION 'manager capability rejected' USING ERRCODE = 'PF001';
  END IF;
  IF c.expires_at <= v_now THEN
    RAISE EXCEPTION 'manager claim expired at database time (% <= %)', c.expires_at, v_now
      USING ERRCODE = 'PF001';
  END IF;
  RETURN v_now;
END;
$$;

-- Receipt claim-or-replay for pfm.receipts. Returns NULL when the operation
-- is NEW (caller executes and inserts the receipt in THIS transaction);
-- returns the stored response when replayed; raises PF009 on fingerprint
-- mismatch and PF014 when only the body was compacted.
CREATE FUNCTION pfm.receipt_claim(
  p_tenant_key TEXT,
  p_domain TEXT,
  p_operation_id TEXT,
  p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  r pfm.receipts;
BEGIN
  IF p_operation_id IS NULL OR length(p_operation_id) = 0 OR length(p_operation_id) > 256 THEN
    RAISE EXCEPTION 'operation id required (<=256 chars)' USING ERRCODE = 'PF008';
  END IF;
  SELECT * INTO r FROM pfm.receipts
    WHERE tenant_key = p_tenant_key AND domain = p_domain AND operation_id = p_operation_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF r.fingerprint <> p_fingerprint THEN
    RAISE EXCEPTION 'operation % replayed with different content in %/%',
      p_operation_id, p_tenant_key, p_domain USING ERRCODE = 'PF009';
  END IF;
  IF r.response IS NULL THEN
    RAISE EXCEPTION 'operation % receipt body was compacted', p_operation_id
      USING ERRCODE = 'PF014',
            DETAIL = jsonb_build_object('operationId', p_operation_id, 'domain', p_domain)::TEXT;
  END IF;
  RETURN r.response;
END;
$$;

CREATE FUNCTION pfm.receipt_put(
  p_tenant_key TEXT,
  p_domain TEXT,
  p_operation_id TEXT,
  p_fingerprint TEXT,
  p_response JSONB,
  p_now BIGINT
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  INSERT INTO pfm.receipts (tenant_key, domain, operation_id, fingerprint, response, created_at)
    VALUES (p_tenant_key, p_domain, p_operation_id, p_fingerprint, p_response, p_now);
END;
$$;

-- The exact bounded response facts of one access lease row. Every BIGINT is a
-- canonical decimal string.
CREATE FUNCTION pfm.lease_json(l pfm.access_leases) RETURNS JSONB
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'leaseId', l.lease_id,
    'tenantKey', l.tenant_key,
    'volumeId', l.volume_id,
    'branch', l.branch_name,
    'consumerId', l.consumer_id,
    'authorityInstanceId', l.authority_instance_id,
    'authorityRuntimeSeq', l.authority_runtime_seq::TEXT,
    'authorityRuntimeId', l.authority_runtime_id,
    'managerEpoch', l.manager_epoch::TEXT,
    'tokenGeneration', l.token_generation::TEXT,
    'controlSeq', l.control_seq::TEXT,
    'state', l.state,
    'endReason', l.end_reason,
    'expiresAt', l.expires_at::TEXT,
    'createdAtMs', l.created_at::TEXT,
    'endedAtMs', l.ended_at::TEXT
  ))
$$;

-- The EFFECTIVE state of a lease at database time: a stored-active row whose
-- manager epoch is superseded reads as revoked/manager-epoch-superseded, one
-- bound to an ended authority runtime reads as revoked/authority-retired, and
-- one past its DB-time expiry reads as expired/expired. This never writes: read
-- paths and refusal paths (which roll back anyway) use effective facts, and
-- only committing mutations (revoke/batch/sweep) persist terminal states.
CREATE FUNCTION pfm.effective_lease(l pfm.access_leases, p_current_epoch BIGINT, p_now BIGINT)
RETURNS pfm.access_leases
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF l.state <> 'active' THEN
    RETURN l;
  END IF;
  IF l.manager_epoch <> p_current_epoch THEN
    l.state := 'revoked';
    l.end_reason := 'manager-epoch-superseded';
    RETURN l;
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pfm.authority_runtimes r
      WHERE r.tenant_key=l.tenant_key
        AND r.volume_id=l.volume_id AND r.branch_name=l.branch_name
        AND r.runtime_seq=l.authority_runtime_seq
        AND r.runtime_id=l.authority_runtime_id
        AND r.authority_instance_id=l.authority_instance_id
        AND r.manager_epoch=l.manager_epoch AND r.state='live') THEN
    l.state := 'revoked';
    l.end_reason := 'authority-retired';
    RETURN l;
  END IF;
  IF l.expires_at <= p_now THEN
    l.state := 'expired';
    l.end_reason := 'expired';
  END IF;
  RETURN l;
END;
$$;

-- Locks one lease row (lock-order position 8).
CREATE FUNCTION pfm.lock_lease(p_lease_id TEXT) RETURNS pfm.access_leases
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  l pfm.access_leases;
BEGIN
  SELECT * INTO l FROM pfm.access_leases WHERE lease_id = p_lease_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'access lease % not found', p_lease_id USING ERRCODE = 'PF007';
  END IF;
  RETURN l;
END;
$$;

-- The dynamic current-facts projection of a receipted lease: the exact row as
-- it is NOW, with effective DB-time/epoch state. Kept separate from the
-- immutable receipted outcome so an old replay can never rewind live routing
-- state.
CREATE FUNCTION pfm.current_lease_facts(p_lease_id TEXT, p_current_epoch BIGINT, p_now BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  l pfm.access_leases;
BEGIN
  SELECT * INTO l FROM pfm.access_leases WHERE lease_id = p_lease_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'receipted access lease % is missing', p_lease_id USING ERRCODE = 'PF007';
  END IF;
  RETURN pfm.lease_json(pfm.effective_lease(l, p_current_epoch, p_now));
END;
$$;

-- ── Manager claim API ────────────────────────────────────────────────────────

CREATE FUNCTION pfm.db_time_ms() RETURNS BIGINT
LANGUAGE sql SECURITY DEFINER VOLATILE
SET search_path = pg_catalog, pg_temp
AS $$ SELECT pfm.now_ms() $$;

-- manager_claim: claim the singleton manager role, a DATABASE-TIME lease.
--
--   - No claim / expired claim: mint the NEXT monotonic epoch for this
--     runtime; the previous epoch is superseded from this commit.
--   - Live claim held by THIS runtime + SAME operation id: exact replay of
--     the recorded claim plus the row's CURRENT expiry facts (replay never
--     extends).
--   - Live claim held by THIS runtime + different operation id: PF002 (a
--     runtime claims exactly once; renewal is manager_renew).
--   - Live claim held by ANOTHER runtime: PF013 with the current expiry in
--     DETAIL — the caller waits for DB-time expiry, never spins the epoch.
--
-- The receipt (tenant '', domain 'manager-claim') is permanent: a takeover
-- NEVER erases the fact that an old claim operation happened; its replay
-- returns the stored response with current:false.
CREATE FUNCTION pfm.manager_claim(
  p_operation_id TEXT,
  p_runtime_id TEXT,
  p_capability_hash TEXT,
  p_ttl_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  c pfm.manager_claims;
  v_claim_found BOOLEAN;
  v_seq_last BIGINT;
  v_epoch BIGINT;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_runtime_id IS NULL OR length(p_runtime_id) = 0 OR length(p_runtime_id) > 128 THEN
    RAISE EXCEPTION 'manager runtime id required (<=128 chars)' USING ERRCODE = 'PF008';
  END IF;
  IF p_capability_hash IS NULL OR p_capability_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'manager capability hash must be 64 hex chars' USING ERRCODE = 'PF008';
  END IF;
  IF p_ttl_ms IS NULL OR p_ttl_ms < 1000 OR p_ttl_ms > 3600000 THEN
    RAISE EXCEPTION 'manager claim ttl must be 1s..1h' USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-manager-claim-v2', p_runtime_id, p_capability_hash, p_ttl_ms::TEXT));

  PERFORM pfm.scope_lock('manager-claim', ARRAY[]::TEXT[]);
  SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = 'manager' FOR UPDATE;
  v_claim_found := FOUND;
  v_now := pfm.now_ms();

  v_replay := pfm.receipt_claim('', 'manager-claim', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    IF v_claim_found AND c.claim_operation_id = p_operation_id
       AND c.runtime_id = p_runtime_id AND c.expires_at > v_now THEN
      -- Same live claim: replay plus the CURRENT expiry facts.
      RETURN v_replay || jsonb_build_object(
        'currentExpiresAtDbMs', c.expires_at::TEXT,
        'currentRenewedAtDbMs', c.renewed_at::TEXT,
        'dbTimeMs', v_now::TEXT, 'current', TRUE, 'replayed', TRUE);
    END IF;
    RETURN v_replay || jsonb_build_object(
      'dbTimeMs', v_now::TEXT, 'current', FALSE, 'replayed', TRUE);
  END IF;

  IF v_claim_found AND c.expires_at > v_now THEN
    IF c.runtime_id = p_runtime_id THEN
      RAISE EXCEPTION 'runtime % already holds the live claim under operation %',
        p_runtime_id, c.claim_operation_id USING ERRCODE = 'PF002';
    END IF;
    RAISE EXCEPTION 'manager claim is held until % (database time %)', c.expires_at, v_now
      USING ERRCODE = 'PF013',
            DETAIL = jsonb_build_object(
              'expiresAtDbMs', c.expires_at::TEXT, 'dbTimeMs', v_now::TEXT,
              'currentEpoch', c.epoch::TEXT)::TEXT;
  END IF;

  SELECT last_value INTO v_seq_last FROM pfm.manager_epoch_seq;
  PERFORM pfm.require_bigint_headroom(v_seq_last, 'manager epoch');
  PERFORM pfm.require_durable_primary();
  v_now := pfm.now_ms();
  v_epoch := nextval('pfm.manager_epoch_seq');
  IF v_claim_found THEN
    UPDATE pfm.manager_claims SET
      epoch = v_epoch, runtime_id = p_runtime_id, claim_operation_id = p_operation_id,
      capability_hash = p_capability_hash,
      claimed_at = v_now, renewed_at = v_now, expires_at = v_now + p_ttl_ms
      WHERE singleton_key = 'manager';
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    IF v_row_count <> 1 THEN
      RAISE EXCEPTION 'manager claim lost its locked row' USING ERRCODE = 'PF010';
    END IF;
  ELSE
    INSERT INTO pfm.manager_claims
      (singleton_key, epoch, runtime_id, claim_operation_id, capability_hash,
       claimed_at, renewed_at, expires_at)
      VALUES ('manager', v_epoch, p_runtime_id, p_operation_id, p_capability_hash,
              v_now, v_now, v_now + p_ttl_ms);
  END IF;

  v_response := jsonb_build_object(
    'managerEpoch', v_epoch::TEXT,
    'runtimeId', p_runtime_id,
    'operationId', p_operation_id,
    'claimedAtDbMs', v_now::TEXT,
    'expiresAtDbMs', (v_now + p_ttl_ms)::TEXT);
  PERFORM pfm.receipt_put('', 'manager-claim', p_operation_id, v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object(
    'dbTimeMs', v_now::TEXT, 'current', TRUE, 'replayed', FALSE);
END;
$$;

-- manager_renew: extend the live claim. A grant never shortens an already
-- longer expiry. A superseded or expired claim raises PF001 (the caller
-- tears down, never retries into a fresh epoch here).
CREATE FUNCTION pfm.manager_renew(
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
  c pfm.manager_claims;
  v_claim_found BOOLEAN;
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
  SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = 'manager' FOR UPDATE;
  v_claim_found := FOUND;
  PERFORM pfm.require_durable_primary();
  v_now := pfm.now_ms();
  IF NOT v_claim_found OR c.epoch IS DISTINCT FROM p_manager_epoch
     OR c.runtime_id IS DISTINCT FROM p_manager_runtime_id
     OR encode(sha256(convert_to(p_manager_capability, 'UTF8')), 'hex')
        IS DISTINCT FROM c.capability_hash
     OR c.expires_at <= v_now THEN
    RAISE EXCEPTION 'manager renew rejected: claim superseded, expired, or identity mismatch'
      USING ERRCODE = 'PF001';
  END IF;
  UPDATE pfm.manager_claims SET
    renewed_at = v_now, expires_at = GREATEST(expires_at, v_now + p_ttl_ms)
    WHERE singleton_key = 'manager' RETURNING * INTO c;
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'manager renew lost its locked claim row' USING ERRCODE = 'PF010';
  END IF;
  RETURN jsonb_build_object('dbTimeMs', v_now::TEXT, 'expiresAtDbMs', c.expires_at::TEXT);
END;
$$;

-- manager_release: best-effort clean shutdown — expires the claim NOW so a
-- successor need not wait out the TTL. Only the exact live claimant may
-- release; anything else is PF001 (harmless at shutdown).
CREATE FUNCTION pfm.manager_release(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  c pfm.manager_claims;
  v_claim_found BOOLEAN;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_manager_capability IS NULL
     OR length(p_manager_capability) NOT BETWEEN 32 AND 512 THEN
    RAISE EXCEPTION 'manager capability must be 32..512 characters'
      USING ERRCODE = 'PF008';
  END IF;
  SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = 'manager' FOR UPDATE;
  v_claim_found := FOUND;
  PERFORM pfm.require_durable_primary();
  v_now := pfm.now_ms();
  IF NOT v_claim_found OR c.epoch IS DISTINCT FROM p_manager_epoch
     OR c.runtime_id IS DISTINCT FROM p_manager_runtime_id
     OR encode(sha256(convert_to(p_manager_capability, 'UTF8')), 'hex')
        IS DISTINCT FROM c.capability_hash
     OR c.expires_at <= v_now THEN
    RAISE EXCEPTION 'manager release rejected: not the live claimant' USING ERRCODE = 'PF001';
  END IF;
  UPDATE pfm.manager_claims SET expires_at = v_now WHERE singleton_key = 'manager';
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'manager release lost its locked claim row' USING ERRCODE = 'PF010';
  END IF;
  RETURN jsonb_build_object('dbTimeMs', v_now::TEXT, 'released', TRUE);
END;
$$;

-- ── Authority runtime API (exactly receipted) ────────────────────────────────

-- authority_runtime_begin: mint the next monotonic runtime for a scope and
-- END any previous live runtime in the same transaction. Exactly receipted:
-- a lost-response retry replays the identical mint and NEVER supersedes the
-- runtime it minted. The manager-issued authority capability is registered
-- by hash; it is EXCLUDED from the request fingerprint and authenticated
-- separately on replay, and the raw value never reaches any receipt.
CREATE FUNCTION pfm.authority_runtime_begin(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_tenant_key TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_authority_instance_id TEXT,
  p_runtime_id TEXT,
  p_authority_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_capability_hash TEXT;
  v_replay JSONB;
  v_replay_runtime pfm.authority_runtimes;
  v_live pfm.authority_runtimes;
  v_max_seq BIGINT;
  v_response JSONB;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_tenant_key IS NULL OR length(p_tenant_key) = 0
     OR p_volume_id IS NULL OR length(p_volume_id) = 0
     OR p_branch_name IS NULL OR length(p_branch_name) = 0
     OR p_authority_instance_id IS NULL OR length(p_authority_instance_id) = 0
     OR p_runtime_id IS NULL OR length(p_runtime_id) = 0 THEN
    RAISE EXCEPTION 'authority runtime scope/identity arguments are required' USING ERRCODE = 'PF008';
  END IF;
  IF p_authority_capability IS NULL OR length(p_authority_capability) < 32
     OR length(p_authority_capability) > 512 THEN
    RAISE EXCEPTION 'authority capability must be 32..512 characters' USING ERRCODE = 'PF008';
  END IF;
  v_capability_hash := encode(sha256(convert_to(p_authority_capability, 'UTF8')), 'hex');
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-runtime-begin-v1', p_tenant_key, p_volume_id, p_branch_name,
    p_authority_instance_id, p_runtime_id));

  PERFORM pfm.require_scope_tenant(p_tenant_key, p_volume_id);
  PERFORM pfm.scope_lock('authority-runtime', ARRAY[p_tenant_key, p_volume_id, p_branch_name]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);

  v_replay := pfm.receipt_claim(p_tenant_key, 'authority-runtime-begin', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    SELECT * INTO v_replay_runtime FROM pfm.authority_runtimes r
      WHERE r.tenant_key = p_tenant_key AND r.volume_id = p_volume_id
        AND r.branch_name = p_branch_name
        AND r.runtime_seq = (v_replay ->> 'runtimeSeq')::BIGINT
        AND r.runtime_id = v_replay ->> 'runtimeId';
    IF NOT FOUND OR v_replay_runtime.authority_capability_hash <> v_capability_hash THEN
      RAISE EXCEPTION 'authority runtime receipt capability rejected' USING ERRCODE = 'PF001';
    END IF;
    RETURN v_replay || jsonb_build_object(
      'current', v_replay_runtime.state = 'live',
      'replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  -- Lock the live runtime row (position 7) before the final deadline/HA
  -- proof: the supersession UPDATE below cannot wait past the evidence
  -- sample.
  SELECT * INTO v_live FROM pfm.authority_runtimes
    WHERE tenant_key = p_tenant_key AND volume_id = p_volume_id
      AND branch_name = p_branch_name AND state = 'live'
    FOR UPDATE;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  SELECT COALESCE(MAX(runtime_seq), 0) INTO v_max_seq
    FROM pfm.authority_runtimes
    WHERE tenant_key = p_tenant_key AND volume_id = p_volume_id
      AND branch_name = p_branch_name;
  PERFORM pfm.require_bigint_headroom(v_max_seq, 'authority runtime sequence');
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);

  UPDATE pfm.authority_runtimes SET
    state = 'ended', end_reason = 'superseded', updated_at = v_now
    WHERE tenant_key = p_tenant_key AND volume_id = p_volume_id
      AND branch_name = p_branch_name AND state = 'live';
  INSERT INTO pfm.authority_runtimes
    (tenant_key, volume_id, branch_name, runtime_seq, runtime_id,
     authority_instance_id, manager_epoch, manager_runtime_id,
     authority_capability_hash, state, created_at, updated_at)
    VALUES (p_tenant_key, p_volume_id, p_branch_name, v_max_seq + 1, p_runtime_id,
            p_authority_instance_id, p_manager_epoch, p_manager_runtime_id,
            v_capability_hash, 'live', v_now, v_now);

  v_response := jsonb_build_object(
    'operationId', p_operation_id,
    'runtimeSeq', (v_max_seq + 1)::TEXT,
    'runtimeId', p_runtime_id,
    'authorityInstanceId', p_authority_instance_id,
    'managerEpoch', p_manager_epoch::TEXT,
    'beganAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put(p_tenant_key, 'authority-runtime-begin', p_operation_id,
                          v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object(
    'current', TRUE, 'replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- authority_runtime_end: terminally end one exact runtime (child exited,
-- evicted, or fenced). Exactly receipted; the end reason is part of the
-- fingerprint, so the same operation id with a different reason is PF009.
-- A replay after a NEWER begin returns the stored terminal facts and can
-- never touch the newer runtime (the receipt is keyed to the exact seq).
CREATE FUNCTION pfm.authority_runtime_end(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_tenant_key TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_runtime_seq BIGINT,
  p_runtime_id TEXT,
  p_end_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  r pfm.authority_runtimes;
  v_reason TEXT;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_end_reason IS NULL OR length(p_end_reason) = 0 THEN
    RAISE EXCEPTION 'authority runtime end reason is required' USING ERRCODE = 'PF008';
  END IF;
  IF p_runtime_seq IS NULL OR p_runtime_seq < 1 OR p_runtime_id IS NULL OR length(p_runtime_id) = 0 THEN
    RAISE EXCEPTION 'authority runtime end requires the exact runtime seq and id' USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-runtime-end-v1', p_tenant_key, p_volume_id, p_branch_name,
    p_runtime_seq::TEXT, p_runtime_id, p_end_reason));

  PERFORM pfm.require_scope_tenant(p_tenant_key, p_volume_id);
  PERFORM pfm.scope_lock('authority-runtime', ARRAY[p_tenant_key, p_volume_id, p_branch_name]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);

  v_replay := pfm.receipt_claim(p_tenant_key, 'authority-runtime-end', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN v_replay || jsonb_build_object('replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  SELECT * INTO r FROM pfm.authority_runtimes
    WHERE tenant_key = p_tenant_key AND volume_id = p_volume_id
      AND branch_name = p_branch_name AND runtime_seq = p_runtime_seq
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'authority runtime %/%/% seq % not found',
      p_tenant_key, p_volume_id, p_branch_name, p_runtime_seq USING ERRCODE = 'PF007';
  END IF;
  IF r.runtime_id IS DISTINCT FROM p_runtime_id THEN
    RAISE EXCEPTION 'authority runtime seq % has a different runtime id', p_runtime_seq
      USING ERRCODE = 'PF002';
  END IF;
  -- The runtime-row wait may cross the manager deadline or a failover.
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);
  IF r.state = 'live' THEN
    v_reason := p_end_reason;
    UPDATE pfm.authority_runtimes SET
      state = 'ended', end_reason = p_end_reason, updated_at = v_now
      WHERE tenant_key = p_tenant_key AND volume_id = p_volume_id
        AND branch_name = p_branch_name AND runtime_seq = p_runtime_seq;
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    IF v_row_count <> 1 THEN
      RAISE EXCEPTION 'authority runtime end lost its locked row' USING ERRCODE = 'PF010';
    END IF;
  ELSE
    v_reason := r.end_reason;
  END IF;

  v_response := jsonb_build_object(
    'operationId', p_operation_id,
    'runtimeSeq', p_runtime_seq::TEXT,
    'runtimeId', p_runtime_id,
    'ended', TRUE,
    'endReason', v_reason,
    'endedAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put(p_tenant_key, 'authority-runtime-end', p_operation_id,
                          v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object('replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- The NARROW pfj->pfm boundary: the only function the journal owner may
-- execute against manager state. It exposes no table and no mutation
-- primitive; it validates and FOR SHARE row-locks the exact live binding
-- (lock-order positions 6 and 7) and samples the clock only after both rows
-- are held.
--
-- Unmanaged scopes (no runtime row has EVER existed) are admitted ONLY under
-- the explicit superuser test escape, with all binding facts absent; every
-- production scope must present the complete manager epoch / runtime /
-- capability chain.
CREATE FUNCTION pfm.verify_authority_binding(
  p_tenant_key TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_authority_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_scoped BOOLEAN;
  c pfm.manager_claims;
  r pfm.authority_runtimes;
  v_claim_found BOOLEAN;
  v_runtime_found BOOLEAN;
BEGIN
  PERFORM pfm.require_txn_settings();
  PERFORM pfm.require_scope_tenant(p_tenant_key, p_volume_id);
  SELECT EXISTS (
    SELECT 1 FROM pfm.authority_runtimes ar
    WHERE ar.tenant_key = p_tenant_key AND ar.volume_id = p_volume_id
      AND ar.branch_name = p_branch_name
  ) INTO v_scoped;
  IF NOT v_scoped THEN
    IF NOT pfm.durability_bypass_active() THEN
      RAISE EXCEPTION 'production authority scope %/% has no managed runtime binding',
        p_volume_id, p_branch_name USING ERRCODE = 'PF001';
    END IF;
    -- The shared capability argument doubles as the local journal writer
    -- capability, so it may be present on this explicit superuser-only test
    -- path; manager/runtime binding facts must remain absent.
    IF p_manager_epoch IS NOT NULL OR p_authority_runtime_seq IS NOT NULL
       OR p_authority_runtime_id IS NOT NULL THEN
      RAISE EXCEPTION 'unmanaged scope %/% received manager binding facts',
        p_volume_id, p_branch_name USING ERRCODE = 'PF001';
    END IF;
    RETURN jsonb_build_object('managed', FALSE, 'dbTimeMs', pfm.now_ms()::TEXT);
  END IF;
  IF p_manager_epoch IS NULL OR p_authority_runtime_seq IS NULL
     OR p_authority_runtime_id IS NULL OR p_authority_capability IS NULL
     OR length(p_authority_capability) = 0 THEN
    RAISE EXCEPTION 'managed scope %/% requires complete authority binding facts',
      p_volume_id, p_branch_name USING ERRCODE = 'PF001';
  END IF;

  SELECT * INTO c FROM pfm.manager_claims WHERE singleton_key = 'manager' FOR SHARE;
  v_claim_found := FOUND;
  SELECT * INTO r FROM pfm.authority_runtimes ar
    WHERE ar.tenant_key = p_tenant_key AND ar.volume_id = p_volume_id
      AND ar.branch_name = p_branch_name AND ar.state = 'live'
    FOR SHARE;
  v_runtime_found := FOUND;
  -- Both contended rows are held. Only this post-lock clock sample is used
  -- for the claim deadline and the returned evidence.
  v_now := pfm.now_ms();
  IF NOT v_claim_found OR c.epoch IS DISTINCT FROM p_manager_epoch
     OR c.expires_at <= v_now THEN
    RAISE EXCEPTION 'manager epoch % is not the live manager claim', p_manager_epoch
      USING ERRCODE = 'PF001';
  END IF;
  IF NOT v_runtime_found
     OR r.runtime_seq IS DISTINCT FROM p_authority_runtime_seq
     OR r.runtime_id IS DISTINCT FROM p_authority_runtime_id
     OR r.manager_epoch IS DISTINCT FROM p_manager_epoch
     OR encode(sha256(convert_to(p_authority_capability, 'UTF8')), 'hex')
        <> r.authority_capability_hash THEN
    RAISE EXCEPTION 'authority runtime %/% is not the live runtime of %/%',
      p_authority_runtime_seq, p_authority_runtime_id, p_volume_id, p_branch_name
      USING ERRCODE = 'PF001';
  END IF;

  RETURN jsonb_build_object(
    'managed', TRUE,
    'current', TRUE,
    'tenantKey', r.tenant_key,
    'managerEpoch', p_manager_epoch::TEXT,
    'managerRuntimeId', c.runtime_id,
    'expiresAtDbMs', c.expires_at::TEXT,
    'authorityRuntimeSeq', p_authority_runtime_seq::TEXT,
    'authorityRuntimeId', p_authority_runtime_id,
    'authorityInstanceId', r.authority_instance_id,
    'dbTimeMs', v_now::TEXT);
END;
$$;

-- ── Access lease API ─────────────────────────────────────────────────────────

-- access_create: ONE transaction — receipt claim/replay, live-manager check,
-- live-runtime binding check, row insert, receipt persist. The CANDIDATE
-- lease id is excluded from the fingerprint: an exact retry replays the
-- originally minted lease id, never mints a second lease. The response is
-- the exact bounded fact set plus the dynamic currentFacts projection; the
-- manager re-derives the deterministic token from these facts (token bytes
-- never reach the database).
CREATE FUNCTION pfm.access_create(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_lease_id TEXT,
  p_tenant_key TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_consumer_id TEXT,
  p_authority_instance_id TEXT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_ttl_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  v_runtime pfm.authority_runtimes;
  l pfm.access_leases;
  v_response JSONB;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_ttl_ms IS NULL OR p_ttl_ms < 1000 OR p_ttl_ms > 86400000 THEN
    RAISE EXCEPTION 'access lease ttl must be 1s..24h' USING ERRCODE = 'PF008';
  END IF;
  IF p_lease_id IS NULL OR p_lease_id !~ '^(pfal|pfms)_[A-Za-z0-9_-]{1,120}$' THEN
    RAISE EXCEPTION 'access lease id must be pfal_/pfms_ prefixed' USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-access-create-v2', p_tenant_key, p_volume_id, p_branch_name,
    p_consumer_id, p_authority_instance_id, p_authority_runtime_seq::TEXT,
    p_authority_runtime_id, p_ttl_ms::TEXT));

  PERFORM pfm.require_scope_tenant(p_tenant_key, p_volume_id);
  PERFORM pfm.scope_lock('receipt', ARRAY[p_tenant_key, 'access', p_operation_id]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  v_replay := pfm.receipt_claim(p_tenant_key, 'access', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN v_replay || jsonb_build_object(
      'currentFacts', pfm.current_lease_facts(v_replay ->> 'leaseId', p_manager_epoch, v_now),
      'replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  -- The lease must bind the CURRENT live runtime of its scope: a lease can
  -- never be created against a dead or superseded child.
  SELECT * INTO v_runtime FROM pfm.authority_runtimes
    WHERE tenant_key = p_tenant_key AND volume_id = p_volume_id
      AND branch_name = p_branch_name AND state = 'live'
    FOR SHARE;
  IF NOT FOUND
     OR v_runtime.runtime_seq IS DISTINCT FROM p_authority_runtime_seq
     OR v_runtime.runtime_id IS DISTINCT FROM p_authority_runtime_id
     OR v_runtime.authority_instance_id IS DISTINCT FROM p_authority_instance_id
     OR v_runtime.manager_epoch IS DISTINCT FROM p_manager_epoch THEN
    RAISE EXCEPTION 'access lease does not bind the live authority runtime of %/%/%',
      p_tenant_key, p_volume_id, p_branch_name USING ERRCODE = 'PF001';
  END IF;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);

  BEGIN
    INSERT INTO pfm.access_leases
      (lease_id, tenant_key, volume_id, branch_name, consumer_id,
       authority_instance_id, authority_runtime_seq, authority_runtime_id,
       manager_epoch, token_generation, control_seq, state, expires_at,
       created_at, updated_at)
      VALUES (p_lease_id, p_tenant_key, p_volume_id, p_branch_name, p_consumer_id,
              p_authority_instance_id, p_authority_runtime_seq, p_authority_runtime_id,
              p_manager_epoch, 1, 1, 'active', v_now + p_ttl_ms, v_now, v_now)
      RETURNING * INTO l;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'access lease id % already exists', p_lease_id USING ERRCODE = 'PF002';
  END;

  v_response := pfm.lease_json(l) || jsonb_build_object(
    'kind', 'create', 'operationId', p_operation_id,
    'receiptFingerprint', v_fingerprint, 'mintedToken', TRUE,
    'completedAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put(p_tenant_key, 'access', p_operation_id, v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object(
    'currentFacts', pfm.lease_json(l), 'replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- access_renew: the ONLY receipt family with bounded bodies. expectedControlSeq
-- is REQUIRED but excluded from the fingerprint: on a receipt miss it gates
-- the retained floor (PF014 below it) and the exact CAS (PF002 on mismatch);
-- on a receipt hit the stored outcome replays regardless of the presented
-- CAS. A grant never shortens an already-longer expiry.
CREATE FUNCTION pfm.access_renew(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_tenant_key TEXT,
  p_lease_id TEXT,
  p_expected_control_seq BIGINT,
  p_ttl_ms BIGINT,
  p_rotate BOOLEAN
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_receipt pfm.access_renew_receipts;
  v_preview pfm.access_leases;
  v_runtime pfm.authority_runtimes;
  l pfm.access_leases;
  l_eff pfm.access_leases;
  v_new_floor BIGINT;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_operation_id IS NULL OR length(p_operation_id) = 0 OR length(p_operation_id) > 256 THEN
    RAISE EXCEPTION 'renew operation id required (<=256 chars)' USING ERRCODE = 'PF008';
  END IF;
  IF p_ttl_ms IS NULL OR p_ttl_ms < 1000 OR p_ttl_ms > 86400000 THEN
    RAISE EXCEPTION 'access lease ttl must be 1s..24h' USING ERRCODE = 'PF008';
  END IF;
  IF p_expected_control_seq IS NULL OR p_expected_control_seq < 1 THEN
    RAISE EXCEPTION 'renew expected control sequence is required' USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-access-renew-v2', p_tenant_key, p_lease_id, p_ttl_ms::TEXT,
    COALESCE(p_rotate, FALSE)::TEXT));

  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  -- Runtime binding fields on an access lease are immutable. A non-locking
  -- preview lets us preserve the global manager -> runtime -> lease lock order.
  SELECT * INTO v_preview FROM pfm.access_leases WHERE lease_id=p_lease_id;
  IF NOT FOUND OR v_preview.tenant_key <> p_tenant_key THEN
    -- Cross-tenant probing is indistinguishable from not-found.
    RAISE EXCEPTION 'access lease % not found', p_lease_id USING ERRCODE = 'PF007';
  END IF;

  -- An exact accepted renew remains replayable even after its child ends.
  SELECT * INTO v_receipt FROM pfm.access_renew_receipts
    WHERE tenant_key=p_tenant_key AND lease_id=p_lease_id
      AND operation_id=p_operation_id;
  IF FOUND THEN
    IF v_receipt.fingerprint<>v_fingerprint THEN
      RAISE EXCEPTION 'renew operation % replayed with different content',p_operation_id
        USING ERRCODE='PF009';
    END IF;
    IF v_receipt.response IS NULL THEN
      RAISE EXCEPTION 'renew receipt is older than the retained floor %',
        v_preview.renew_receipt_floor
        USING ERRCODE='PF014',DETAIL=jsonb_build_object(
          'leaseId',v_preview.lease_id,
          'receiptFloorControlSeq',v_preview.renew_receipt_floor::TEXT)::TEXT;
    END IF;
    RETURN v_receipt.response||jsonb_build_object(
      'currentFacts',pfm.lease_json(
        pfm.effective_lease(v_preview,p_manager_epoch,v_now)),
      'replayed',TRUE,'dbTimeMs',v_now::TEXT);
  END IF;

  SELECT * INTO v_runtime FROM pfm.authority_runtimes r
    WHERE r.tenant_key=v_preview.tenant_key
      AND r.volume_id=v_preview.volume_id
      AND r.branch_name=v_preview.branch_name
      AND r.runtime_seq=v_preview.authority_runtime_seq
    FOR SHARE;
  IF NOT FOUND OR v_runtime.state<>'live'
     OR v_runtime.runtime_id IS DISTINCT FROM v_preview.authority_runtime_id
     OR v_runtime.authority_instance_id IS DISTINCT FROM v_preview.authority_instance_id
     OR v_runtime.manager_epoch IS DISTINCT FROM p_manager_epoch THEN
    RAISE EXCEPTION 'access lease % authority runtime is not live',p_lease_id
      USING ERRCODE='PF012',DETAIL=pfm.lease_json(
        pfm.effective_lease(v_preview,p_manager_epoch,v_now))::TEXT;
  END IF;
  l := pfm.lock_lease(p_lease_id);
  -- The lease-row wait may cross the manager deadline; re-verify against the
  -- post-lock clock.
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);

  SELECT * INTO v_receipt FROM pfm.access_renew_receipts
    WHERE tenant_key = p_tenant_key AND lease_id = p_lease_id
      AND operation_id = p_operation_id;
  IF FOUND THEN
    IF v_receipt.fingerprint <> v_fingerprint THEN
      RAISE EXCEPTION 'renew operation % replayed with different content', p_operation_id
        USING ERRCODE = 'PF009';
    END IF;
    IF v_receipt.response IS NULL THEN
      RAISE EXCEPTION 'renew receipt is older than the retained floor %', l.renew_receipt_floor
        USING ERRCODE = 'PF014',
              DETAIL = jsonb_build_object(
                'leaseId', l.lease_id,
                'receiptFloorControlSeq', l.renew_receipt_floor::TEXT)::TEXT;
    END IF;
    RETURN v_receipt.response || jsonb_build_object(
      'currentFacts', pfm.lease_json(pfm.effective_lease(l, p_manager_epoch, v_now)),
      'replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;
  IF p_expected_control_seq < l.renew_receipt_floor THEN
    RAISE EXCEPTION 'renew receipt is older than the retained floor %', l.renew_receipt_floor
      USING ERRCODE = 'PF014',
            DETAIL = jsonb_build_object(
              'leaseId', l.lease_id,
              'receiptFloorControlSeq', l.renew_receipt_floor::TEXT)::TEXT;
  END IF;

  l_eff := pfm.effective_lease(l, p_manager_epoch, v_now);
  IF l_eff.state <> 'active' THEN
    RAISE EXCEPTION 'access lease % is %', p_lease_id, l_eff.state
      USING ERRCODE = 'PF012', DETAIL = pfm.lease_json(l_eff)::TEXT;
  END IF;
  IF l.control_seq <> p_expected_control_seq THEN
    RAISE EXCEPTION 'access lease % control seq is % (caller expected %)',
      p_lease_id, l.control_seq, p_expected_control_seq
      USING ERRCODE = 'PF002', DETAIL = pfm.lease_json(l_eff)::TEXT;
  END IF;
  PERFORM pfm.require_bigint_headroom(l.control_seq, 'access lease control sequence');
  IF COALESCE(p_rotate, FALSE) THEN
    PERFORM pfm.require_bigint_headroom(l.token_generation, 'access lease token generation');
  END IF;
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);

  UPDATE pfm.access_leases SET
    expires_at = GREATEST(expires_at, v_now + p_ttl_ms),
    control_seq = control_seq + 1,
    token_generation = token_generation + (CASE WHEN COALESCE(p_rotate, FALSE) THEN 1 ELSE 0 END),
    updated_at = v_now
    WHERE lease_id = p_lease_id RETURNING * INTO l;
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'access renew lost its locked lease row' USING ERRCODE = 'PF010';
  END IF;

  v_response := pfm.lease_json(l) || jsonb_build_object(
    'kind', 'renew', 'operationId', p_operation_id,
    'receiptFingerprint', v_fingerprint,
    'mintedToken', COALESCE(p_rotate, FALSE),
    'completedAtDbMs', v_now::TEXT);
  INSERT INTO pfm.access_renew_receipts
    (tenant_key, lease_id, operation_id, fingerprint, expected_control_seq,
     ttl_ms, rotate, response, created_at)
    VALUES (p_tenant_key, p_lease_id, p_operation_id, v_fingerprint,
            p_expected_control_seq, p_ttl_ms, COALESCE(p_rotate, FALSE), v_response, v_now);

  -- Advance the retained floor to keep the newest 64 bodies, compacting the
  -- bodies below it in one bounded index-driven page. Tombstone rows are
  -- never deleted.
  v_new_floor := GREATEST(l.renew_receipt_floor, p_expected_control_seq - 63);
  IF v_new_floor > l.renew_receipt_floor THEN
    UPDATE pfm.access_leases SET renew_receipt_floor = v_new_floor
      WHERE lease_id = p_lease_id;
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    IF v_row_count <> 1 THEN
      RAISE EXCEPTION 'access renew lost its locked lease row' USING ERRCODE = 'PF010';
    END IF;
    UPDATE pfm.access_renew_receipts r SET response = NULL
      WHERE (r.tenant_key, r.lease_id, r.operation_id) IN (
        SELECT tenant_key, lease_id, operation_id FROM pfm.access_renew_receipts
        WHERE tenant_key = p_tenant_key AND lease_id = p_lease_id
          AND expected_control_seq < v_new_floor AND response IS NOT NULL
        ORDER BY expected_control_seq
        LIMIT 64);
  END IF;

  RETURN v_response || jsonb_build_object(
    'currentFacts', pfm.lease_json(l), 'replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- access_release: holder-initiated end (token verified by the manager BEFORE
-- this call). Exact permanent receipt; the optional expectedControlSeq gates
-- the CAS only and is excluded from the fingerprint.
CREATE FUNCTION pfm.access_release(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_tenant_key TEXT,
  p_lease_id TEXT,
  p_expected_control_seq BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  l pfm.access_leases;
  l_eff pfm.access_leases;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_expected_control_seq IS NULL OR p_expected_control_seq<1 THEN
    RAISE EXCEPTION 'release expected control sequence is required'
      USING ERRCODE='PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-access-release-v2', p_tenant_key, p_lease_id));
  PERFORM pfm.scope_lock('receipt', ARRAY[p_tenant_key, 'access', p_operation_id]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  v_replay := pfm.receipt_claim(p_tenant_key, 'access', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN v_replay || jsonb_build_object(
      'currentFacts', pfm.current_lease_facts(v_replay ->> 'leaseId', p_manager_epoch, v_now),
      'replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  l := pfm.lock_lease(p_lease_id);
  IF l.tenant_key <> p_tenant_key THEN
    RAISE EXCEPTION 'access lease % not found', p_lease_id USING ERRCODE = 'PF007';
  END IF;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  l_eff := pfm.effective_lease(l, p_manager_epoch, v_now);
  IF l_eff.state <> 'active' THEN
    RAISE EXCEPTION 'access lease % is %', p_lease_id, l_eff.state
      USING ERRCODE = 'PF012', DETAIL = pfm.lease_json(l_eff)::TEXT;
  END IF;
  IF l.control_seq <> p_expected_control_seq THEN
    RAISE EXCEPTION 'access lease % control seq is % (caller expected %)',
      p_lease_id, l.control_seq, p_expected_control_seq
      USING ERRCODE = 'PF002', DETAIL = pfm.lease_json(l_eff)::TEXT;
  END IF;
  PERFORM pfm.require_bigint_headroom(l.control_seq, 'access lease control sequence');
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);

  UPDATE pfm.access_leases SET
    state = 'released', end_reason = 'released', ended_at = v_now,
    control_seq = control_seq + 1, updated_at = v_now
    WHERE lease_id = p_lease_id RETURNING * INTO l;
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> 1 THEN
    RAISE EXCEPTION 'access release lost its locked lease row' USING ERRCODE = 'PF010';
  END IF;

  v_response := pfm.lease_json(l) || jsonb_build_object(
    'kind', 'release', 'operationId', p_operation_id,
    'receiptFingerprint', v_fingerprint, 'mintedToken', FALSE,
    'completedAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put(p_tenant_key, 'access', p_operation_id, v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object(
    'currentFacts', pfm.lease_json(l), 'replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- access_revoke: manager/owner/authority-initiated end. This path COMMITS a
-- terminal state, so an effectively dead row (DB-time expiry or superseded
-- epoch) is durably settled with its EFFECTIVE reason, a live row is ended
-- with the caller's reason, and an already-terminal row replays its terminal
-- facts idempotently (teardown paths converge, never error).
CREATE FUNCTION pfm.access_revoke(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_tenant_key TEXT,
  p_lease_id TEXT,
  p_end_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  l pfm.access_leases;
  l_eff pfm.access_leases;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_end_reason IS NULL OR p_end_reason NOT IN
     ('revoked', 'owner-revoked', 'authority-retired', 'manager-epoch-superseded', 'expired') THEN
    RAISE EXCEPTION 'invalid access revoke reason %', p_end_reason USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-access-revoke-v2', p_tenant_key, p_lease_id, p_end_reason));
  PERFORM pfm.scope_lock('receipt', ARRAY[p_tenant_key, 'access', p_operation_id]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  v_replay := pfm.receipt_claim(p_tenant_key, 'access', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN v_replay || jsonb_build_object(
      'currentFacts', pfm.current_lease_facts(v_replay ->> 'leaseId', p_manager_epoch, v_now),
      'replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  l := pfm.lock_lease(p_lease_id);
  IF l.tenant_key <> p_tenant_key THEN
    RAISE EXCEPTION 'access lease % not found', p_lease_id USING ERRCODE = 'PF007';
  END IF;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  PERFORM pfm.require_bigint_headroom(l.control_seq, 'access lease control sequence');
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);
  IF l.state = 'active' THEN
    l_eff := pfm.effective_lease(l, p_manager_epoch, v_now);
    IF l_eff.state <> 'active' THEN
      -- Effectively dead: persist the effective terminal state, not the
      -- caller's reason.
      UPDATE pfm.access_leases SET
        state = l_eff.state, end_reason = l_eff.end_reason, ended_at = v_now,
        control_seq = control_seq + 1, updated_at = v_now
        WHERE lease_id = p_lease_id RETURNING * INTO l;
    ELSE
      UPDATE pfm.access_leases SET
        state = (CASE WHEN p_end_reason = 'expired' THEN 'expired' ELSE 'revoked' END),
        end_reason = p_end_reason, ended_at = v_now,
        control_seq = control_seq + 1, updated_at = v_now
        WHERE lease_id = p_lease_id RETURNING * INTO l;
    END IF;
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    IF v_row_count <> 1 THEN
      RAISE EXCEPTION 'access revoke lost its locked lease row' USING ERRCODE = 'PF010';
    END IF;
  END IF;

  v_response := pfm.lease_json(l) || jsonb_build_object(
    'kind', 'revoke', 'operationId', p_operation_id,
    'receiptFingerprint', v_fingerprint, 'mintedToken', FALSE,
    'completedAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put(p_tenant_key, 'access', p_operation_id, v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object(
    'currentFacts', pfm.lease_json(l), 'replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- access_end_batch: one receipted transaction ending EVERY matching active
-- lease — child exit (runtime seq), authority retirement (instance id), owner
-- revoke, or epoch supersession sweep (epochs below the live one). Rows are
-- locked in C-collated lease_id order (lock-order position 8); a match wider
-- than 1024 rows is a typed PF004 (narrow the scope). Effectively dead rows
-- are settled with their EFFECTIVE reason; live rows end with the caller's.
CREATE FUNCTION pfm.access_end_batch(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_tenant_key TEXT,        -- '' sweeps every tenant (manager-internal batch)
  p_volume_id TEXT,         -- NULL = any
  p_branch_name TEXT,       -- NULL = any
  p_consumer_id TEXT,       -- NULL = any
  p_authority_instance_id TEXT, -- NULL = any
  p_authority_runtime_seq BIGINT, -- NULL = any
  p_epochs_below BIGINT,    -- NULL = only the live epoch; else end epochs < this
  p_end_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  v_matched TEXT[];
  v_max_control BIGINT;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_end_reason IS NULL OR p_end_reason NOT IN
     ('revoked', 'owner-revoked', 'authority-retired', 'manager-epoch-superseded', 'expired') THEN
    RAISE EXCEPTION 'invalid access batch end reason %', p_end_reason USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-access-end-batch-v2', COALESCE(p_tenant_key, ''), p_volume_id,
    p_branch_name, p_consumer_id, p_authority_instance_id,
    p_authority_runtime_seq::TEXT, p_epochs_below::TEXT, p_end_reason));
  PERFORM pfm.scope_lock('receipt', ARRAY[COALESCE(p_tenant_key, ''), 'access-batch', p_operation_id]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  v_replay := pfm.receipt_claim(COALESCE(p_tenant_key, ''), 'access-batch', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN v_replay || jsonb_build_object('replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  SELECT COALESCE(array_agg(x.lease_id ORDER BY x.lease_id COLLATE "C"), ARRAY[]::TEXT[]),
         COALESCE(MAX(x.control_seq), 0)
    INTO v_matched, v_max_control
    FROM (
      SELECT l.lease_id, l.control_seq FROM pfm.access_leases l
      WHERE l.state = 'active'
        AND (COALESCE(p_tenant_key, '') = '' OR l.tenant_key = p_tenant_key)
        AND (p_volume_id IS NULL OR l.volume_id = p_volume_id)
        AND (p_branch_name IS NULL OR l.branch_name = p_branch_name)
        AND (p_consumer_id IS NULL OR l.consumer_id = p_consumer_id)
        AND (p_authority_instance_id IS NULL OR l.authority_instance_id = p_authority_instance_id)
        AND (p_authority_runtime_seq IS NULL OR l.authority_runtime_seq = p_authority_runtime_seq)
        AND (CASE WHEN p_epochs_below IS NULL THEN l.manager_epoch = p_manager_epoch
                  ELSE l.manager_epoch < p_epochs_below END)
      ORDER BY l.lease_id COLLATE "C"
      LIMIT 1025
      FOR UPDATE
    ) x;
  IF cardinality(v_matched) > 1024 THEN
    RAISE EXCEPTION 'access batch matches more than 1024 leases; narrow the scope'
      USING ERRCODE = 'PF004';
  END IF;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  PERFORM pfm.require_bigint_headroom(v_max_control, 'access lease control sequence');
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);

  UPDATE pfm.access_leases SET
    state = CASE WHEN manager_epoch <> p_manager_epoch THEN 'revoked'
                 WHEN expires_at <= v_now THEN 'expired'
                 WHEN p_end_reason = 'expired' THEN 'expired'
                 ELSE 'revoked' END,
    end_reason = CASE WHEN manager_epoch <> p_manager_epoch THEN 'manager-epoch-superseded'
                      WHEN expires_at <= v_now THEN 'expired'
                      ELSE p_end_reason END,
    ended_at = v_now, control_seq = control_seq + 1, updated_at = v_now
    WHERE lease_id = ANY(v_matched) AND state = 'active';
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> cardinality(v_matched) THEN
    RAISE EXCEPTION 'access batch locked % leases but updated %',
      cardinality(v_matched), v_row_count USING ERRCODE = 'PF010';
  END IF;

  v_response := jsonb_build_object(
    'kind', 'end-batch', 'operationId', p_operation_id,
    'endReason', p_end_reason,
    'endedLeaseIds', to_jsonb(v_matched),
    'receiptFingerprint', v_fingerprint,
    'completedAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put(COALESCE(p_tenant_key, ''), 'access-batch', p_operation_id,
                          v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object('replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- access_sweep_due: durably terminalize one bounded, stable, exact-receipted
-- page of rows that are DUE at database time — still stored 'active' but past
-- expiry, or minted under a superseded manager epoch. Old epoch => revoked/
-- manager-epoch-superseded; due current-epoch => expired/expired. Pages are
-- C-collated lease_id ranges: afterLeaseId is an exclusive cursor and the
-- page receipt replays exactly.
CREATE FUNCTION pfm.access_sweep_due(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_operation_id TEXT,
  p_after_lease_id TEXT,
  p_limit INT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_pick_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
  v_page_plus TEXT[];
  v_page TEXT[];
  v_has_more BOOLEAN;
  v_max_control BIGINT;
  v_response JSONB;
  v_row_count BIGINT;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 512 THEN
    RAISE EXCEPTION 'access sweep limit must be 1..512' USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-access-sweep-v1', p_after_lease_id, p_limit::TEXT));
  PERFORM pfm.scope_lock('receipt', ARRAY['', 'access-sweep', p_operation_id]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  v_replay := pfm.receipt_claim('', 'access-sweep', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN v_replay || jsonb_build_object('replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;

  -- A row due at selection time stays due at the later mutation time (both
  -- predicates are monotonic in database time under the held manager epoch).
  v_pick_now := v_now;
  SELECT COALESCE(array_agg(x.lease_id ORDER BY x.lease_id COLLATE "C"), ARRAY[]::TEXT[]),
         COALESCE(MAX(x.control_seq), 0)
    INTO v_page_plus, v_max_control
    FROM (
      SELECT l.lease_id, l.control_seq FROM pfm.access_leases l
      WHERE l.state = 'active'
        AND (l.manager_epoch < p_manager_epoch OR l.expires_at <= v_pick_now
          OR NOT EXISTS (
            SELECT 1 FROM pfm.authority_runtimes r
            WHERE r.tenant_key=l.tenant_key
              AND r.volume_id=l.volume_id AND r.branch_name=l.branch_name
              AND r.runtime_seq=l.authority_runtime_seq
              AND r.runtime_id=l.authority_runtime_id
              AND r.authority_instance_id=l.authority_instance_id
              AND r.manager_epoch=l.manager_epoch AND r.state='live'))
        AND (p_after_lease_id IS NULL OR l.lease_id COLLATE "C" > p_after_lease_id COLLATE "C")
      ORDER BY l.lease_id COLLATE "C"
      LIMIT p_limit + 1
      FOR UPDATE
    ) x;
  v_has_more := cardinality(v_page_plus) > p_limit;
  v_page := v_page_plus[1:p_limit];
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  PERFORM pfm.require_bigint_headroom(v_max_control, 'access lease control sequence');
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);

  UPDATE pfm.access_leases l SET
    state = CASE WHEN l.manager_epoch<>p_manager_epoch THEN 'revoked'
      WHEN NOT EXISTS (
        SELECT 1 FROM pfm.authority_runtimes r
        WHERE r.tenant_key=l.tenant_key
          AND r.volume_id=l.volume_id AND r.branch_name=l.branch_name
          AND r.runtime_seq=l.authority_runtime_seq
          AND r.runtime_id=l.authority_runtime_id
          AND r.authority_instance_id=l.authority_instance_id
          AND r.manager_epoch=l.manager_epoch AND r.state='live') THEN 'revoked'
      ELSE 'expired' END,
    end_reason = CASE WHEN l.manager_epoch<>p_manager_epoch
      THEN 'manager-epoch-superseded'
      WHEN NOT EXISTS (
        SELECT 1 FROM pfm.authority_runtimes r
        WHERE r.tenant_key=l.tenant_key
          AND r.volume_id=l.volume_id AND r.branch_name=l.branch_name
          AND r.runtime_seq=l.authority_runtime_seq
          AND r.runtime_id=l.authority_runtime_id
          AND r.authority_instance_id=l.authority_instance_id
          AND r.manager_epoch=l.manager_epoch AND r.state='live')
        THEN 'authority-retired'
      ELSE 'expired' END,
    ended_at = v_now, control_seq = control_seq + 1, updated_at = v_now
    WHERE lease_id = ANY(v_page) AND state = 'active';
  GET DIAGNOSTICS v_row_count = ROW_COUNT;
  IF v_row_count <> cardinality(v_page) THEN
    RAISE EXCEPTION 'access sweep locked % leases but updated %',
      cardinality(v_page), v_row_count USING ERRCODE = 'PF010';
  END IF;

  v_response := jsonb_build_object(
    'kind', 'access-sweep',
    'operationId', p_operation_id,
    'afterLeaseId', p_after_lease_id,
    'limit', p_limit::TEXT,
    'endedLeaseIds', to_jsonb(v_page),
    'nextCursor', CASE WHEN v_has_more THEN v_page[cardinality(v_page)] ELSE NULL END,
    'hasMore', v_has_more,
    'receiptFingerprint', v_fingerprint,
    'completedAtDbMs', v_now::TEXT);
  PERFORM pfm.receipt_put('', 'access-sweep', p_operation_id, v_fingerprint, v_response, v_now);
  RETURN v_response || jsonb_build_object('replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- access_get: one lease's EFFECTIVE current facts (DB-time/epoch semantics
-- applied read-only; durable settlement belongs to revoke/batch/sweep).
CREATE FUNCTION pfm.access_get(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_tenant_key TEXT,
  p_lease_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  l pfm.access_leases;
BEGIN
  IF p_tenant_key IS NULL OR length(p_tenant_key) = 0 THEN
    RAISE EXCEPTION 'tenant namespace is required' USING ERRCODE = 'PF008';
  END IF;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  SELECT * INTO l FROM pfm.access_leases WHERE lease_id = p_lease_id;
  IF NOT FOUND OR l.tenant_key IS DISTINCT FROM p_tenant_key THEN
    RETURN NULL;
  END IF;
  RETURN pfm.lease_json(pfm.effective_lease(l, p_manager_epoch, v_now))
    || jsonb_build_object('dbTimeMs', v_now::TEXT);
END;
$$;

-- access_list_active: every lease that is EFFECTIVELY active at database
-- time under the live epoch (stored-active rows that are due or superseded
-- are excluded here and terminalized by the sweep). Bounded by a hard LIMIT.
CREATE FUNCTION pfm.access_list_active(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_rows JSONB;
  v_count BIGINT;
BEGIN
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  -- Count and aggregate the same bounded snapshot (LIMIT+1 detects overflow).
  -- A stored-active lease whose bound runtime ended is effectively revoked
  -- and is excluded even if cleanup is still retrying.
  WITH bounded AS MATERIALIZED (
    SELECT l.* FROM pfm.access_leases l
    WHERE l.state='active' AND l.manager_epoch=p_manager_epoch
      AND l.expires_at>v_now
      AND EXISTS (
        SELECT 1 FROM pfm.authority_runtimes r
        WHERE r.tenant_key=l.tenant_key
          AND r.volume_id=l.volume_id AND r.branch_name=l.branch_name
          AND r.runtime_seq=l.authority_runtime_seq
          AND r.runtime_id=l.authority_runtime_id
          AND r.authority_instance_id=l.authority_instance_id
          AND r.manager_epoch=l.manager_epoch AND r.state='live')
    ORDER BY l.lease_id COLLATE "C"
    LIMIT 65537)
  SELECT COUNT(*),COALESCE(jsonb_agg(
      pfm.lease_json(l) ORDER BY l.lease_id COLLATE "C"),'[]'::JSONB)
    INTO v_count,v_rows FROM bounded l;
  IF v_count>65536 THEN
    RAISE EXCEPTION 'active access lease restore exceeds 65536 rows'
      USING ERRCODE='PF004';
  END IF;
  RETURN jsonb_build_object('leases', v_rows, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- ── Lifecycle receipts ───────────────────────────────────────────────────────

-- lifecycle_receipt_put: record one completed lifecycle operation (evict /
-- quiesce / teardown) response EXACTLY as answered. The fingerprint is
-- derived from the canonical response document itself: the same operation id
-- with different content is PF009 forever.
CREATE FUNCTION pfm.lifecycle_receipt_put(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_tenant_key TEXT,
  p_operation_id TEXT,
  p_response JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_fingerprint TEXT;
  v_replay JSONB;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_response IS NULL THEN
    RAISE EXCEPTION 'lifecycle receipt response required' USING ERRCODE = 'PF008';
  END IF;
  v_fingerprint := pfm.request_fingerprint(jsonb_build_array(
    'pfm-lifecycle-v1', p_tenant_key, p_operation_id, p_response::TEXT));
  PERFORM pfm.scope_lock('receipt', ARRAY[p_tenant_key, 'lifecycle', p_operation_id]);
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  v_replay := pfm.receipt_claim(p_tenant_key, 'lifecycle', p_operation_id, v_fingerprint);
  IF v_replay IS NOT NULL THEN
    RETURN jsonb_build_object('response', v_replay, 'replayed', TRUE, 'dbTimeMs', v_now::TEXT);
  END IF;
  PERFORM pfm.require_durable_primary();
  v_now := pfm.require_manager(
    p_manager_epoch,p_manager_runtime_id,p_manager_capability);
  PERFORM pfm.receipt_put(p_tenant_key, 'lifecycle', p_operation_id, v_fingerprint, p_response, v_now);
  RETURN jsonb_build_object('response', p_response, 'replayed', FALSE, 'dbTimeMs', v_now::TEXT);
END;
$$;

-- lifecycle_receipt_get: exact lookup. Returns NULL when unknown (lifecycle
-- receipts are permanent, so unknown MEANS the operation never durably
-- completed).
CREATE FUNCTION pfm.lifecycle_receipt_get(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_tenant_key TEXT,
  p_operation_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  r pfm.receipts;
BEGIN
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  SELECT * INTO r FROM pfm.receipts
    WHERE tenant_key = p_tenant_key AND domain = 'lifecycle' AND operation_id = p_operation_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object('response', r.response, 'fingerprint', r.fingerprint,
                            'dbTimeMs', v_now::TEXT);
END;
$$;

-- ── Privileges ───────────────────────────────────────────────────────────────
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pfm FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pfm FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pfm FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  pfm.db_time_ms(),
  pfm.manager_claim(TEXT, TEXT, TEXT, BIGINT),
  pfm.manager_renew(BIGINT, TEXT, TEXT, BIGINT),
  pfm.manager_release(BIGINT, TEXT, TEXT),
  pfm.authority_runtime_begin(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT),
  pfm.authority_runtime_end(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT),
  pfm.access_create(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, BIGINT),
  pfm.access_renew(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, BOOLEAN),
  pfm.access_release(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT),
  pfm.access_revoke(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT),
  pfm.access_end_batch(BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT),
  pfm.access_sweep_due(BIGINT, TEXT, TEXT, TEXT, TEXT, INT),
  pfm.access_get(BIGINT, TEXT, TEXT, TEXT, TEXT),
  pfm.access_list_active(BIGINT, TEXT, TEXT),
  pfm.lifecycle_receipt_put(BIGINT, TEXT, TEXT, TEXT, TEXT, JSONB),
  pfm.lifecycle_receipt_get(BIGINT, TEXT, TEXT, TEXT, TEXT)
TO portablefs_manager;

-- The journal owner's ENTIRE pfm surface: exact binding verification, the
-- fail-closed SECURITY DEFINER durability guard, and rich read-only evidence.
-- No table grants or lower-level durability predicates cross the boundary.
GRANT EXECUTE ON FUNCTION
  pfm.verify_authority_binding(TEXT, TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT),
  pfm.require_durable_primary(),
  pfm.durability_evidence()
TO portablefs_journal_owner;

RESET ROLE;
