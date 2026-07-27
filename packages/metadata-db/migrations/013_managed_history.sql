-- 013_managed_history: HistoryCuts, PFT2 commit provenance, tenant-scoped
-- replicated-object registry, legacy_manifest -> managed_journal conversion,
-- O(1) adoption with serving pins, scrub/repair and GC sweep authority.
--
-- A HistoryCut captures ONE exact immutable revision of a branch and
-- materializes it asynchronously into content-addressed PFT2 objects. Nothing
-- here ever joins the ordinary write path: acknowledged mutations are already
-- durable in the fenced PFJ3/PFC2 journal before any cut exists, capture is a
-- short transaction under the exact append lock order, and materialization is
-- the external history-worker process (direct pgx + direct object stores)
-- that can crash, retry, race, and resume without touching live truth.
-- Ordinary live writes never wait on cuts, checkpoints, drains, object
-- storage, or PostgreSQL WAL LSNs (which stay diagnostic-only).
--
-- OBJECT IDENTITY (new in this revision): a history object is identified by
-- (tenant_id, kind, digest) and stored under EXACT per-incarnation physical
-- keys. There is deliberately no global digest-only identity: tenant B can
-- never observe or inherit tenant A's rows or storage keys, and every read
-- locates a verified live copy by the RECORDED exact key (never by deriving
-- a digest path). Same-digest bytes uploaded after (or during) deletion get a
-- NEW incarnation and therefore a NEW physical key; retained tombstones make
-- delete/re-upload ABA-impossible at both the metadata and the storage layer.
--
-- SEPARATE ROOTS: every ready cut publishes TWO artifacts atomically:
--   * the USER pft2 commit (public.commits + pfh.pft2_commits): the user
--     filesystem root and its exact closure ('user'),
--   * the internal RECOVERY ANCHOR (pfh.recovery_anchors): RecoveryRoot,
--     PFC2 control root, parked-orphan index, inode allocator watermarks and
--     the recovery-only closure ('recovery').
-- The user surface never exposes anchors, sessions, locks, pins, orphans or
-- outcome state; adoption takes (cutId, anchorId) and verifies they bound the
-- SAME cut before advancing anything.
--
-- SECURITY MODEL (extends 009/012; same discipline)
--   portablefs_history_owner   NOLOGIN. Owns schema pfh, its tables and every
--                              SECURITY DEFINER function. Reads (never writes)
--                              the public metadata it validates against, plus
--                              INSERT on public.commits for the single
--                              ready-publication insert of a pft2 commit.
--   portablefs_history_worker  NOLOGIN capability role for the ONE Go
--                              history-worker DSN. EXECUTE on exactly the
--                              claim-fenced worker surface; no tables.
--   portablefs_history_auditor NOLOGIN read-only audit role: EXECUTE on the
--                              two pure zero-argument STABLE audit functions
--                              and nothing else.
--   portablefs_journal_owner   (from 009) additionally owns the four narrow
--                              journal-side primitives created here (exact
--                              head capture incl. cumulative backlog, bounded
--                              record reads, O(1) adoption base advance,
--                              conversion finalize). They are EXECUTE-granted
--                              to portablefs_history_owner only.
--
-- AUTHORIZATION IS STRUCTURAL. No GUC, sentinel, session variable, or
-- search_path trick anywhere: the replaced triggers authorize privileged
-- updates by (a) current_user being the owner of the SECURITY DEFINER
-- function that performed the UPDATE — a property no caller can set — AND
-- (b) a durable proof ROW (pfh.adoptions / pfh.conversions) whose exact
-- contents (including the O(1) backlog subtraction) match the attempted
-- change. Trim of a live PFJ3 prefix remains fail-closed in 013.
--
-- LOCK ORDER (canonical; identical to 012): sorted exclusive branch advisory
-- lock, then generation row, then branch row, then pfh rows; reads take the
-- shared branch advisory lock. pfh-only operations (claims, receipts,
-- objects) take sorted pfh advisory keys first, then pfh rows, and never
-- take a branch advisory lock afterwards except through the capture/adopt/
-- finalize primitives, which are always entered BEFORE any pfh row lock is
-- held on the rows they touch. Within one cut, the cut row lock precedes its
-- outer operation row lock everywhere (mark_ready, fail, cancel), so worker
-- settlement and caller cancellation can never deadlock. DB time
-- (pfh.now_ms) is sampled after the last contended lock. All external
-- BIGINTs serialize as canonical decimal TEXT.
--
-- PG16/17/18 NOTES (fixes for defects found on real PG17):
--   * TEXT literals never contain NUL: E'\x00' is a lexer error on every
--     supported major. PostgreSQL TEXT (and jsonb strings) structurally
--     cannot hold NUL bytes, so path NUL checks are unnecessary and absent.
--   * All crypto/uuid helpers are schema-qualified pg_catalog built-ins
--     (pg_catalog.sha256, pg_catalog.gen_random_uuid — PG13+ floor), safe
--     under the pinned search_path with no extension dependency.
--   * Role creation is race-guarded. The migration user's direct memberships
--     in the owner and worker roles are UNCONDITIONAL idempotent GRANTs (never
--     pg_has_role-guarded): a superuser migration user answers
--     pg_has_role(...,'MEMBER') implicitly with no pg_auth_members row, so a
--     guard would skip the GRANT and leave the direct edge the role-graph
--     audit requires absent. Re-granting an existing membership is a no-op, so
--     the bare GRANT is safe on rerun and on a second database on the cluster.
--   * ACL postconditions audit DIRECT grants via aclexplode (never
--     has_function_privilege, which is polluted by PUBLIC defaults on legacy
--     schemas) and assert zero PUBLIC EXECUTE anywhere in pfh.
--   * Legacy work paths use COLLATE "C" so ordinals, paging and parent
--     synthesis are byte-ordered identically on every locale/ICU build.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary from 008 (PF001 stale/fenced,
-- PF002 conflict, PF003 quota, PF004 bounds, PF005 codec, PF007 not found,
-- PF008 invalid argument, PF009 replay mismatch, PF010 accounting
-- corruption, PF011 proof missing, PF015 durability policy).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id='012_pfj3_pfc2') THEN
    RAISE EXCEPTION '013 preflight: 012_pfj3_pfc2 receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations
             WHERE id LIKE '014%' OR id LIKE '015%') THEN
    RAISE EXCEPTION '013 preflight: a later migration receipt exists; 013 can never be applied after 014/015';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='pfj' AND p.proname='journal_claim_v3')
     OR NOT EXISTS (
      SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='pfj' AND p.proname='branch_lock_key') THEN
    RAISE EXCEPTION '013 preflight: the 012 PFJ3 surface is not installed';
  END IF;
  IF to_regclass('public.commits') IS NULL OR to_regclass('pfj.journal_generations') IS NULL THEN
    RAISE EXCEPTION '013 preflight: base schema is missing';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: public schema changes (migration/table owner) ═════════════════

-- commit_kind discriminates the two immutable commit families. manifest_v1 is
-- the historical JSON manifest family (default FOREVER: every existing writer
-- inserts without the column). pft2 commits carry NO manifest of any shape;
-- their content is the content-addressed PFT2 root recorded in
-- pfh.pft2_commits. materialized_manifest keeps its 003 BOOLEAN shape: a pft2
-- commit is structurally (manifest NULL, diff NULL, base NULL,
-- materialized_manifest FALSE) — never JSON smuggled into a boolean column.
ALTER TABLE public.commits
  ADD COLUMN commit_kind TEXT NOT NULL DEFAULT 'manifest_v1'
  CONSTRAINT commits_commit_kind_check CHECK (commit_kind IN ('manifest_v1','pft2'));

ALTER TABLE public.commits
  ADD CONSTRAINT commits_pft2_shape_check CHECK (
    commit_kind <> 'pft2'
    OR (manifest IS NULL AND manifest_diff IS NULL
        AND manifest_base_commit_id IS NULL AND materialized_manifest = FALSE));

-- Corrected 012 ACL defect: 012's pfj.branch_mode_transition (SECURITY
-- DEFINER, owner portablefs_journal_owner) updates branches.branch_mode, but
-- 009 granted the journal owner UPDATE(id) only, so every owner-driven mode
-- CAS failed with a privilege error on a least-privilege DSN. 013 grants the
-- journal owner exactly UPDATE (branch_mode, head_commit_id, updated_at); the
-- SECURITY INVOKER branch guard still constrains every transition.
GRANT UPDATE (branch_mode, head_commit_id, updated_at)
  ON public.branches TO portablefs_journal_owner;

-- Replace the 012 branch guard: the matrix and prerequisites are unchanged
-- EXCEPT that entering managed_journal by UPDATE now additionally requires a
-- durable conversion proof row. 012 allowed legacy_manifest->managed_journal
-- whenever no journal generation existed, which would let a NONEMPTY legacy
-- branch adopt managed mode without ever converting its manifest history to
-- PFT2. 013 closes that structurally: the ONLY writer that can perform the
-- UPDATE is the journal owner inside pfj.history_conversion_finalize, and the
-- trigger independently re-verifies the pfh.conversions proof row. Branches
-- BORN managed (INSERT with branch_mode='managed_journal') are untouched:
-- this guard fires on UPDATE only, exactly as in 012.
CREATE OR REPLACE FUNCTION public.portablefs_branch_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_state TEXT;
BEGIN
  -- 013_managed_history revision of the 012 guard.
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
    IF NEW.branch_mode = 'managed_journal' THEN
      -- BOTH entry edges (from legacy_manifest and from migrating) require:
      -- no nonterminal generation remains AND the update was issued by the
      -- journal owner inside the conversion finalizer AND a durable
      -- conversion proof row in state 'finalizing' names this exact branch.
      IF v_state <> 'none' THEN
        RAISE EXCEPTION 'branch % cannot become managed_journal: a % journal generation exists',
          OLD.id, v_state USING ERRCODE='PF001';
      END IF;
      IF current_user <> 'portablefs_journal_owner'
         OR NOT EXISTS (
           SELECT 1 FROM pfh.conversions c
           WHERE c.branch_id = OLD.id AND c.state = 'finalizing') THEN
        RAISE EXCEPTION 'branch % cannot become managed_journal without a finalizing conversion proof (013)',
          OLD.id USING ERRCODE='PF011';
      END IF;
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
  IF OLD.branch_mode IN ('managed_journal','migrating','retiring')
     AND NEW.head_commit_id IS DISTINCT FROM OLD.head_commit_id
     AND current_user <> 'portablefs_journal_owner' THEN
    RAISE EXCEPTION 'branch % is journal-managed (%); legacy manifest commits cannot move its head',
      OLD.id, OLD.branch_mode USING ERRCODE='PF001';
  END IF;
  RETURN NEW;
END;
$$;
-- Trigger functions carry no caller surface; strip the PUBLIC default.
REVOKE ALL ON FUNCTION public.portablefs_branch_guard() FROM PUBLIC;

-- ─── Roles (race-guarded, idempotent, PG16+ membership rules) ────────────────
DO $$
BEGIN
  BEGIN
    CREATE ROLE portablefs_history_owner NOLOGIN;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
  END;
  BEGIN
    CREATE ROLE portablefs_history_worker NOLOGIN;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
  END;
  BEGIN
    CREATE ROLE portablefs_history_auditor NOLOGIN;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
  END;
  -- The migration user must hold an EXPLICIT pg_auth_members membership in the
  -- owner role: it SETs ROLE to the owner below, and the role-graph audit
  -- asserts this direct edge. pg_has_role is deliberately NOT used as a guard
  -- here — a superuser migration user satisfies pg_has_role(...,'MEMBER')
  -- IMPLICITLY, with no membership row, so a guard would skip the GRANT and
  -- leave the direct edge absent on exactly the clusters where it is easiest
  -- to miss. A bare GRANT is idempotent (re-granting an existing membership by
  -- the same grantor is a no-op), so it is safe on a partial-apply rerun and
  -- on a second database sharing this cluster's roles.
  EXECUTE format('GRANT portablefs_history_owner TO %I', CURRENT_USER);
END
$$;

-- The history owner reads exactly the public metadata it validates against,
-- and INSERTs exactly one thing: the pft2 commit row at ready publication.
GRANT USAGE ON SCHEMA public TO portablefs_history_owner;
GRANT SELECT, REFERENCES ON TABLE
  public.tenants, public.volumes, public.branches, public.commits,
  public.snapshots, public.blobs, public.blob_refs,
  public.commit_auxiliary_blob_refs, public.leases
TO portablefs_history_owner;
GRANT INSERT ON TABLE public.commits TO portablefs_history_owner;
GRANT USAGE ON SCHEMA pfj TO portablefs_history_owner;

CREATE SCHEMA pfh;
ALTER SCHEMA pfh OWNER TO portablefs_history_owner;
REVOKE ALL ON SCHEMA pfh FROM PUBLIC;
GRANT USAGE ON SCHEMA pfh TO portablefs_history_worker;
GRANT USAGE ON SCHEMA pfh TO portablefs_history_auditor;
GRANT USAGE ON SCHEMA pfh TO portablefs_journal_owner;

-- ═══ SECTION B: pfh schema (history owner) ════════════════════════════════════
SET LOCAL ROLE portablefs_history_owner;

-- Functions default to PUBLIC EXECUTE at creation; revoke that default for
-- everything this owner will ever create so every EXECUTE is an explicit
-- grant (default-deny).
ALTER DEFAULT PRIVILEGES FOR ROLE portablefs_history_owner
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION pfh.now_ms() RETURNS BIGINT
LANGUAGE sql VOLATILE
SET search_path=pg_catalog,pg_temp
AS $$ SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT $$;

CREATE FUNCTION pfh.require_txn_settings() RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_commit TEXT := current_setting('synchronous_commit');
BEGIN
  IF v_commit NOT IN ('on','remote_apply') THEN
    PERFORM set_config('synchronous_commit','on',TRUE);
  END IF;
  PERFORM set_config('lock_timeout','5s',TRUE);
END;
$$;

-- Sorted transaction advisory locks over pfh scope keys (mirrors
-- pfj.scope_locks; position 0 of the pfh-local lock order).
CREATE FUNCTION pfh.scope_locks(p_keys TEXT[]) RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_key BIGINT;
BEGIN
  FOR v_key IN
    SELECT DISTINCT pg_catalog.hashtextextended(k,0) FROM unnest(p_keys) AS u(k) ORDER BY 1
  LOOP
    PERFORM pg_advisory_xact_lock(v_key);
  END LOOP;
END;
$$;

-- pg_catalog.gen_random_uuid is built into PostgreSQL 13+ (the lineage
-- floor); no pgcrypto extension dependency.
CREATE FUNCTION pfh.new_id(p_prefix TEXT) RETURNS TEXT
LANGUAGE sql VOLATILE
SET search_path=pg_catalog,pg_temp
AS $$ SELECT p_prefix || '_' || replace(pg_catalog.gen_random_uuid()::TEXT, '-', '') $$;

CREATE FUNCTION pfh.require_sha256(p_value TEXT, p_what TEXT) RETURNS void
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF p_value IS NULL OR p_value !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION '% must be 64 lowercase hex chars', p_what USING ERRCODE='PF008';
  END IF;
END;
$$;

CREATE FUNCTION pfh.require_object_identity(
  p_tenant TEXT, p_kind TEXT, p_digest TEXT
) RETURNS void
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_kind IS DISTINCT FROM 'pft2'
     OR p_digest IS NULL OR p_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'object identity requires tenant, kind pft2, sha256 digest'
      USING ERRCODE='PF008';
  END IF;
END;
$$;

CREATE FUNCTION pfh.require_operation_key(
  p_tenant TEXT, p_domain TEXT, p_operation_id TEXT
) RETURNS void
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF p_tenant IS NULL OR length(p_tenant) NOT BETWEEN 1 AND 256
     OR p_domain IS NULL
     OR p_domain NOT IN ('history-cut','adoption','scrub','conversion')
     OR p_operation_id IS NULL OR length(p_operation_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'operation identity requires tenant, known domain, and id (<=256 chars)'
      USING ERRCODE='PF008';
  END IF;
END;
$$;

-- ─── Tables ───────────────────────────────────────────────────────────────────

-- General resource operations: the tenant-scoped exact-once ledger. Keys are
-- PERMANENT tombstones: response bodies may compact away, the keyed row with
-- its frozen fingerprint never does. Target ids are preallocated BEFORE any
-- side effect, the row stays 'pending' until the target is USABLE (a cut
-- settles at ready/fail/cancel, never at enqueue), and state_revision
-- increments on every transition so a caller can prove exactly which
-- settlement it observed.
CREATE TABLE pfh.resource_operations (
  tenant_id TEXT NOT NULL,
  domain TEXT NOT NULL CHECK (domain IN ('history-cut','adoption','scrub','conversion')),
  operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  target_ids JSONB NOT NULL CHECK (pg_column_size(target_ids) <= 4096),
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','succeeded','failed','canceled','unknown_manual')),
  state_revision BIGINT NOT NULL DEFAULT 1 CHECK (state_revision >= 1),
  response JSONB CHECK (response IS NULL OR pg_column_size(response) <= 65536),
  response_compacted_db_ms BIGINT,
  created_db_ms BIGINT NOT NULL,
  updated_db_ms BIGINT NOT NULL,
  completed_db_ms BIGINT,
  PRIMARY KEY (tenant_id, domain, operation_id)
);

-- One HistoryCut: the frozen linearization tuple (including the generation's
-- CUMULATIVE backlog counters at the cut boundary, so adoption subtracts in
-- O(1)) plus the five-state lifecycle. The dedup_key converges concurrent
-- identical captures onto one row; dedup_revision separates a fresh attempt
-- after a definite failed/canceled cut at the same key.
CREATE TABLE pfh.history_cuts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  branch_name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('user','recovery','conversion_final')),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('managed_journal','legacy_manifest')),
  generation_id TEXT,
  journal_epoch BIGINT,
  record_codec TEXT CHECK (record_codec IS NULL OR record_codec IN ('pfr1','pfj3')),
  control_codec TEXT CHECK (control_codec IS NULL OR control_codec IN ('pfc1','pfc2')),
  source_base_commit_id TEXT,
  source_base_seq BIGINT,
  source_base_digest TEXT,
  cut_seq_exclusive BIGINT,
  cut_digest TEXT,
  cut_backlog_bytes BIGINT,
  cut_backlog_records BIGINT,
  source_head_commit_id TEXT,
  materializer_version TEXT NOT NULL CHECK (length(materializer_version) BETWEEN 1 AND 64),
  replication_policy JSONB NOT NULL CHECK (pg_column_size(replication_policy) <= 2048),
  dedup_key TEXT NOT NULL,
  dedup_revision BIGINT NOT NULL DEFAULT 1 CHECK (dedup_revision >= 1),
  request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
  op_tenant_id TEXT NOT NULL,
  op_domain TEXT NOT NULL,
  op_operation_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','materializing','ready','failed','canceled')),
  claim_worker_id TEXT,
  claim_epoch BIGINT NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
  lease_expires_db_ms BIGINT,
  attempt_count INT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_db_ms BIGINT NOT NULL DEFAULT 0,
  progress JSONB CHECK (progress IS NULL OR pg_column_size(progress) <= 16384),
  last_error JSONB CHECK (last_error IS NULL OR pg_column_size(last_error) <= 8192),
  result_commit_id TEXT,
  recovery_anchor_id TEXT,
  created_db_ms BIGINT NOT NULL,
  updated_db_ms BIGINT NOT NULL,
  ready_db_ms BIGINT,
  UNIQUE (dedup_key, kind, dedup_revision),
  CHECK ((source_kind = 'managed_journal') = (generation_id IS NOT NULL)),
  CHECK (source_kind <> 'managed_journal'
         OR (journal_epoch IS NOT NULL AND record_codec IS NOT NULL
             AND control_codec IS NOT NULL AND source_base_seq IS NOT NULL
             AND source_base_digest IS NOT NULL AND cut_seq_exclusive IS NOT NULL
             AND cut_digest IS NOT NULL AND source_base_seq >= 0
             AND cut_seq_exclusive >= source_base_seq
             AND cut_backlog_bytes IS NOT NULL AND cut_backlog_bytes >= 0
             AND cut_backlog_records IS NOT NULL AND cut_backlog_records >= 0)),
  CHECK (source_kind <> 'legacy_manifest' OR source_head_commit_id IS NOT NULL),
  CHECK (state <> 'ready' OR (result_commit_id IS NOT NULL AND recovery_anchor_id IS NOT NULL))
);
CREATE INDEX history_cuts_claimable
  ON pfh.history_cuts (next_attempt_db_ms, created_db_ms)
  WHERE state IN ('pending','materializing');
CREATE INDEX history_cuts_by_branch ON pfh.history_cuts (branch_id, state);
CREATE INDEX history_cuts_by_generation ON pfh.history_cuts (generation_id)
  WHERE generation_id IS NOT NULL AND state IN ('pending','materializing');

-- Snapshots, forks, branches, publishes, adoptions hold ready cuts as roots.
CREATE TABLE pfh.cut_consumers (
  id TEXT PRIMARY KEY,
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  tenant_id TEXT NOT NULL,
  consumer_kind TEXT NOT NULL
    CHECK (consumer_kind IN ('snapshot','branch','fork','publish','adoption','conversion')),
  consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 256),
  created_db_ms BIGINT NOT NULL,
  released_db_ms BIGINT,
  UNIQUE (consumer_kind, consumer_id)
);
CREATE INDEX cut_consumers_by_cut ON pfh.cut_consumers (cut_id) WHERE released_db_ms IS NULL;

-- Never-reused 31-bit inode namespaces plus the branch's durable allocator
-- high-water. next_local and max_ino_seen are MONOTONE: max_ino_seen covers
-- every inode ever live on the branch, deleted and orphaned included.
CREATE SEQUENCE pfh.inode_namespace_seq
  AS BIGINT START 1 INCREMENT 1 MINVALUE 1 MAXVALUE 2147483647 NO CYCLE;

CREATE TABLE pfh.inode_namespaces (
  namespace BIGINT PRIMARY KEY CHECK (namespace BETWEEN 1 AND 2147483647),
  tenant_id TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('branch','conversion')),
  next_local BIGINT NOT NULL DEFAULT 1 CHECK (next_local BETWEEN 1 AND 4294967296),
  max_ino_seen BIGINT NOT NULL DEFAULT 1 CHECK (max_ino_seen >= 1),
  issued_db_ms BIGINT NOT NULL,
  updated_db_ms BIGINT NOT NULL,
  UNIQUE (branch_id)
);

CREATE FUNCTION pfh.inode_namespaces_monotone() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  IF NEW.namespace IS DISTINCT FROM OLD.namespace
     OR NEW.branch_id IS DISTINCT FROM OLD.branch_id THEN
    RAISE EXCEPTION 'inode namespace identity is immutable' USING ERRCODE='PF001';
  END IF;
  IF NEW.next_local < OLD.next_local OR NEW.max_ino_seen < OLD.max_ino_seen THEN
    RAISE EXCEPTION 'inode allocator high-water can never regress' USING ERRCODE='PF010';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER inode_namespaces_monotone
  BEFORE UPDATE ON pfh.inode_namespaces
  FOR EACH ROW EXECUTE FUNCTION pfh.inode_namespaces_monotone();

-- Immutable tenant-scoped content-addressed object registry. The logical
-- identity is (tenant, kind, digest); each incarnation of that identity is a
-- distinct set of physical copies under distinct EXACT storage keys.
-- Incarnations + reclaim generations + retained tombstones make
-- delete/re-upload ABA-safe. Quarantined objects fence publication and
-- adoption until scrub/repair proves bytes again. The sweep claim
-- (worker/epoch/DB-time lease) makes GC crash-reclaimable: an expired
-- 'deleting' claim is re-claimable, and a stale sweeper's completion is
-- fenced by claim_epoch + reclaim_generation.
CREATE TABLE pfh.objects (
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
  kind TEXT NOT NULL CHECK (kind IN ('pft2')),
  digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  size BIGINT NOT NULL CHECK (size >= 0),
  incarnation BIGINT NOT NULL DEFAULT 1 CHECK (incarnation >= 1),
  reclaim_generation BIGINT NOT NULL DEFAULT 0 CHECK (reclaim_generation >= 0),
  state TEXT NOT NULL DEFAULT 'intended'
    CHECK (state IN ('intended','live','quarantined','reclaiming','deleting','tombstoned')),
  sweep_worker_id TEXT,
  sweep_claim_epoch BIGINT NOT NULL DEFAULT 0 CHECK (sweep_claim_epoch >= 0),
  sweep_claim_expires_db_ms BIGINT,
  created_db_ms BIGINT NOT NULL,
  updated_db_ms BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, kind, digest)
);
CREATE INDEX objects_sweepable ON pfh.objects (updated_db_ms)
  WHERE state IN ('intended','live','reclaiming');
CREATE INDEX objects_deleting ON pfh.objects (sweep_claim_expires_db_ms)
  WHERE state = 'deleting';

CREATE TABLE pfh.object_copies (
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pft2')),
  digest TEXT NOT NULL,
  incarnation BIGINT NOT NULL CHECK (incarnation >= 1),
  failure_domain TEXT NOT NULL CHECK (length(failure_domain) BETWEEN 1 AND 128),
  storage_key TEXT NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 1024),
  size BIGINT NOT NULL CHECK (size >= 0),
  state TEXT NOT NULL DEFAULT 'present' CHECK (state IN ('present','deleting','absent')),
  first_verified_db_ms BIGINT NOT NULL,
  last_verified_db_ms BIGINT NOT NULL,
  verify_attempts INT NOT NULL DEFAULT 0 CHECK (verify_attempts >= 0),
  next_verify_db_ms BIGINT NOT NULL DEFAULT 0,
  verify_claim_worker_id TEXT
    CHECK (verify_claim_worker_id IS NULL OR length(verify_claim_worker_id) BETWEEN 1 AND 128),
  verify_claim_epoch BIGINT NOT NULL DEFAULT 0 CHECK (verify_claim_epoch >= 0),
  verify_claim_expires_db_ms BIGINT,
  absence_receipt JSONB CHECK (absence_receipt IS NULL OR pg_column_size(absence_receipt) <= 2048),
  CHECK ((verify_claim_worker_id IS NULL) = (verify_claim_expires_db_ms IS NULL)),
  PRIMARY KEY (tenant_id, kind, digest, incarnation, failure_domain),
  FOREIGN KEY (tenant_id, kind, digest) REFERENCES pfh.objects (tenant_id, kind, digest)
);
CREATE INDEX object_copies_scrub_due
  ON pfh.object_copies (next_verify_db_ms, last_verified_db_ms)
  WHERE state = 'present';

-- Upload intents are GC roots from BEFORE the first PUT and bind the exact
-- claim epoch AND incarnation the upload will publish under: a crash between
-- PUT and receipt reconciles by re-reading the exact per-incarnation key and
-- rehashing (the worker records a copy receipt only after that proof; a lost
-- PUT outcome can therefore never fabricate readiness, and an intent from a
-- superseded incarnation can never receipt into the current one).
CREATE TABLE pfh.upload_intents (
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pft2')),
  digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  size BIGINT NOT NULL CHECK (size >= 0),
  incarnation BIGINT NOT NULL CHECK (incarnation >= 1),
  claim_epoch BIGINT NOT NULL,
  created_db_ms BIGINT NOT NULL,
  PRIMARY KEY (cut_id, digest)
);

-- The exact object closures of a cut. 'user' is the reachable set of the
-- user filesystem root; 'recovery' is the reachable set of the RecoveryRoot
-- MINUS the user closure (strictly internal objects: recovery root, control
-- map, orphan index). Both are root set members once the cut is ready; user
-- APIs only ever serve 'user' members plus — to the tenant's own authority
-- restore path — the anchor objects it names by digest.
CREATE TABLE pfh.cut_objects (
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  closure TEXT NOT NULL CHECK (closure IN ('user','recovery')),
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pft2')),
  digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (cut_id, closure, digest)
);
CREATE INDEX cut_objects_by_object ON pfh.cut_objects (tenant_id, kind, digest);

-- USER arm of a ready cut: the pft2 commit's provenance. Deliberately holds
-- no recovery/control/orphan facts — those live on the anchor.
CREATE TABLE pfh.pft2_commits (
  commit_id TEXT PRIMARY KEY REFERENCES public.commits(id),
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  tenant_id TEXT NOT NULL,
  root_digest TEXT NOT NULL CHECK (root_digest ~ '^[0-9a-f]{64}$'),
  root_size BIGINT NOT NULL CHECK (root_size > 0),
  max_ino_seen BIGINT NOT NULL CHECK (max_ino_seen >= 1),
  object_count BIGINT NOT NULL CHECK (object_count >= 1),
  object_bytes BIGINT NOT NULL CHECK (object_bytes >= 0),
  created_db_ms BIGINT NOT NULL
);
CREATE INDEX pft2_commits_by_cut ON pfh.pft2_commits (cut_id);

-- RECOVERY arm of a ready cut: the internal anchor (RecoveryRoot, PFC2
-- control root, parked-orphan index, allocator watermarks, recovery-only
-- closure accounting). Never reachable from the user commit; adoption
-- installs it as the generation's internal base anchor.
CREATE TABLE pfh.recovery_anchors (
  id TEXT PRIMARY KEY,
  cut_id TEXT NOT NULL UNIQUE REFERENCES pfh.history_cuts(id),
  commit_id TEXT NOT NULL UNIQUE REFERENCES public.commits(id),
  tenant_id TEXT NOT NULL,
  as_of_seq BIGINT NOT NULL CHECK (as_of_seq >= 0),
  recovery_root_digest TEXT NOT NULL CHECK (recovery_root_digest ~ '^[0-9a-f]{64}$'),
  recovery_root_size BIGINT NOT NULL CHECK (recovery_root_size > 0),
  control_root_digest TEXT CHECK (control_root_digest IS NULL OR control_root_digest ~ '^[0-9a-f]{64}$'),
  control_root_size BIGINT CHECK ((control_root_digest IS NULL) = (control_root_size IS NULL)),
  orphan_index_digest TEXT CHECK (orphan_index_digest IS NULL OR orphan_index_digest ~ '^[0-9a-f]{64}$'),
  orphan_index_size BIGINT CHECK ((orphan_index_digest IS NULL) = (orphan_index_size IS NULL)),
  inode_namespace BIGINT NOT NULL CHECK (inode_namespace BETWEEN 1 AND 2147483647),
  next_local BIGINT NOT NULL CHECK (next_local BETWEEN 1 AND 4294967296),
  max_ino_seen BIGINT NOT NULL CHECK (max_ino_seen >= 1),
  object_count BIGINT NOT NULL CHECK (object_count >= 1),
  object_bytes BIGINT NOT NULL CHECK (object_bytes >= 0),
  created_db_ms BIGINT NOT NULL
);

-- Serving-base pins: an adoption may advance the durable base while a live
-- authority still serves lazy references from the old base. The pin binds
-- the EXACT old base commit (and, when the old base was itself a pft2
-- commit, its anchor) plus the generation identity facts at adoption time —
-- manager epoch, authority runtime id/seq, writer fence. Release happens
-- ONLY through (a) a verified base-swap acknowledgment presenting those
-- exact runtime facts, or (b) a fenced release proving the pinned runtime is
-- durably superseded (writer fence advanced / generation terminal / writer
-- lease released or expired at DB time). There is deliberately NO TTL and no
-- unauthenticated release-by-id.
CREATE TABLE pfh.serving_base_pins (
  adoption_id TEXT PRIMARY KEY,
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  anchor_id TEXT NOT NULL REFERENCES pfh.recovery_anchors(id),
  tenant_id TEXT NOT NULL,
  generation_id TEXT NOT NULL,
  writer_fence BIGINT NOT NULL CHECK (writer_fence >= 0),
  manager_epoch BIGINT,
  authority_runtime_id TEXT,
  authority_runtime_seq BIGINT,
  old_base_commit_id TEXT NOT NULL,
  old_base_root_digest TEXT CHECK (old_base_root_digest IS NULL OR old_base_root_digest ~ '^[0-9a-f]{64}$'),
  old_anchor_id TEXT REFERENCES pfh.recovery_anchors(id),
  acked_db_ms BIGINT,
  released_db_ms BIGINT,
  release_reason TEXT CHECK (release_reason IS NULL OR release_reason IN ('acked','fenced')),
  created_db_ms BIGINT NOT NULL
);
CREATE INDEX serving_pins_live ON pfh.serving_base_pins (generation_id)
  WHERE released_db_ms IS NULL;

-- Adoption proof rows: the freeze trigger verifies the attempted base
-- advance — INCLUDING the O(1) cumulative-backlog subtraction — against
-- exactly one 'applying' row. Rows are permanent receipts.
CREATE TABLE pfh.adoptions (
  id TEXT PRIMARY KEY,
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  anchor_id TEXT NOT NULL REFERENCES pfh.recovery_anchors(id),
  generation_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  op_operation_id TEXT NOT NULL,
  old_base_seq BIGINT NOT NULL CHECK (old_base_seq >= 0),
  old_base_digest TEXT NOT NULL,
  old_base_commit_id TEXT,
  new_base_seq BIGINT NOT NULL CHECK (new_base_seq >= 0),
  new_base_digest TEXT NOT NULL,
  new_base_commit_id TEXT NOT NULL,
  subtract_backlog_bytes BIGINT NOT NULL CHECK (subtract_backlog_bytes >= 0),
  subtract_backlog_records BIGINT NOT NULL CHECK (subtract_backlog_records >= 0),
  state TEXT NOT NULL DEFAULT 'applying'
    CHECK (state IN ('applying','applied','failed')),
  created_db_ms BIGINT NOT NULL,
  applied_db_ms BIGINT,
  CHECK (new_base_seq >= old_base_seq)
);
CREATE INDEX adoptions_by_generation ON pfh.adoptions (generation_id, state);

-- Conversion proof rows: legacy_manifest -> managed_journal is the ONLY
-- exceptional strong-drain workflow, and only because it is terminal for the
-- old PFR1/PFC1 generation. The branch guard verifies 'finalizing'. abort
-- and retry are explicit primitives; the issued conversion namespace is
-- permanent (monotone counters make retry collisions impossible).
CREATE TABLE pfh.conversions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  volume_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  branch_name TEXT NOT NULL,
  op_operation_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'migrating'
    CHECK (state IN ('migrating','final_cut','finalizing','converted','failed')),
  attempt INT NOT NULL DEFAULT 1 CHECK (attempt >= 1),
  old_generation_id TEXT,
  final_cut_id TEXT REFERENCES pfh.history_cuts(id),
  inode_namespace BIGINT REFERENCES pfh.inode_namespaces(namespace),
  head_commit_id_pin TEXT,
  last_error JSONB CHECK (last_error IS NULL OR pg_column_size(last_error) <= 8192),
  created_db_ms BIGINT NOT NULL,
  updated_db_ms BIGINT NOT NULL,
  converted_db_ms BIGINT,
  UNIQUE (branch_id)
);

-- Bounded normalized legacy manifest work set for one conversion cut: the
-- resolved final entry stream (full manifest + chronological diff chain,
-- depth <= 32), persisted so resolution, verification, ino assignment, and
-- import are individually resumable and deterministic. The path column is
-- COLLATE "C": every ordinal, page boundary and parent comparison is
-- byte-ordered identically on every server locale. comparable_key is a
-- DB-internal deterministic identity over the normalized columns (jsonb key
-- order); the Go worker recomputes the CANONICAL stableJson comparable key
-- from the typed columns for the tree-hash proof.
CREATE TABLE pfh.legacy_work_entries (
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  path TEXT COLLATE "C" NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
  ord BIGINT,
  kind TEXT NOT NULL CHECK (kind IN ('file','directory','symlink')),
  mode BIGINT NOT NULL CHECK (mode BETWEEN 0 AND 4294967295),
  uid BIGINT NOT NULL DEFAULT 0 CHECK (uid BETWEEN 0 AND 4294967295),
  gid BIGINT NOT NULL DEFAULT 0 CHECK (gid BETWEEN 0 AND 4294967295),
  size BIGINT NOT NULL DEFAULT 0 CHECK (size >= 0),
  mtime_ms BIGINT NOT NULL DEFAULT 0,
  ctime_ms BIGINT NOT NULL DEFAULT 0,
  atime_ms BIGINT NOT NULL DEFAULT 0,
  executable BOOLEAN NOT NULL DEFAULT FALSE,
  ino BIGINT NOT NULL DEFAULT 0 CHECK (ino >= 0),
  assigned_ino BIGINT CHECK (assigned_ino IS NULL OR assigned_ino >= 1),
  nlink INT NOT NULL DEFAULT 1 CHECK (nlink >= 1),
  link_target TEXT CHECK (link_target IS NULL OR length(link_target) <= 4096),
  blob_digest TEXT CHECK (blob_digest IS NULL OR blob_digest ~ '^sha256:[0-9a-f]{64}$'),
  blob_size BIGINT CHECK (blob_size IS NULL OR blob_size >= 0),
  compression TEXT NOT NULL DEFAULT 'none' CHECK (compression IN ('none','gzip')),
  packed BOOLEAN NOT NULL DEFAULT FALSE,
  chunks JSONB CHECK (chunks IS NULL OR pg_column_size(chunks) <= 1048576),
  comparable_key TEXT NOT NULL,
  PRIMARY KEY (cut_id, path)
);
CREATE UNIQUE INDEX legacy_work_entries_by_ord
  ON pfh.legacy_work_entries (cut_id, ord) WHERE ord IS NOT NULL;
CREATE INDEX legacy_work_entries_by_ino
  ON pfh.legacy_work_entries (cut_id, ino) WHERE ino > 0;

-- Step receipts + cursors for the conversion pipeline.
CREATE TABLE pfh.legacy_work_steps (
  cut_id TEXT NOT NULL REFERENCES pfh.history_cuts(id),
  step TEXT NOT NULL CHECK (step IN
    ('chain_prepared','entries_resolved','ords_assigned','inos_assigned',
     'tree_hash_verified','import')),
  state TEXT NOT NULL DEFAULT 'running' CHECK (state IN ('running','done')),
  cursor JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(cursor) <= 16384),
  updated_db_ms BIGINT NOT NULL,
  PRIMARY KEY (cut_id, step)
);

-- Repair destination leases (worker + DB-time). A crashed repairer's lease
-- simply expires; receipts are fenced by the object's current incarnation,
-- so a stale repairer can neither heal nor harm the current identity.
CREATE TABLE pfh.repair_leases (
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pft2')),
  digest TEXT NOT NULL,
  incarnation BIGINT NOT NULL CHECK (incarnation >= 1),
  failure_domain TEXT NOT NULL CHECK (length(failure_domain) BETWEEN 1 AND 128),
  worker_id TEXT NOT NULL CHECK (length(worker_id) BETWEEN 1 AND 128),
  claim_epoch BIGINT NOT NULL CHECK (claim_epoch >= 1),
  expires_db_ms BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, kind, digest, incarnation, failure_domain)
);

-- History-worker heartbeats (DB time only). The production freshness audit
-- refuses to promise anything without a fresh worker.
CREATE TABLE pfh.worker_heartbeats (
  worker_kind TEXT NOT NULL CHECK (worker_kind IN ('materializer','scrub','repair','gc')),
  worker_id TEXT NOT NULL CHECK (length(worker_id) BETWEEN 1 AND 128),
  last_beat_db_ms BIGINT NOT NULL,
  facts JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(facts) <= 8192),
  PRIMARY KEY (worker_kind, worker_id)
);

-- One frozen replication + freshness policy row. requiredFailureDomains is
-- the exact duplicate-free set every object copy must cover before a cut can
-- be ready; installation is an expected-epoch CAS with byte-identical
-- idempotent retry.
CREATE TABLE pfh.history_policies (
  singleton_key TEXT PRIMARY KEY DEFAULT 'history'
    CHECK (singleton_key = 'history'),
  policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 1),
  canonical_json TEXT NOT NULL CHECK (octet_length(canonical_json) BETWEEN 2 AND 4096),
  policy JSONB NOT NULL CHECK (pg_column_size(policy) <= 4096),
  installed_db_ms BIGINT NOT NULL
);

-- ─── Policy ──────────────────────────────────────────────────────────────────

CREATE FUNCTION pfh.history_policy_shape_check(p JSONB) RETURNS void
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_count INT;
  v_distinct INT;
BEGIN
  IF p IS NULL OR jsonb_typeof(p) <> 'object'
     OR (SELECT COUNT(*) FROM jsonb_object_keys(p)) <> 4
     OR p->>'v' IS DISTINCT FROM '1'
     OR jsonb_typeof(p->'requiredFailureDomains') <> 'array'
     OR jsonb_typeof(p->'maxLastVerifiedAgeMs') <> 'number'
     OR (p->>'maxLastVerifiedAgeMs')::NUMERIC NOT BETWEEN 60000 AND 2592000000
     OR jsonb_typeof(p->'maxWorkerHeartbeatAgeMs') <> 'number'
     OR (p->>'maxWorkerHeartbeatAgeMs')::NUMERIC NOT BETWEEN 5000 AND 86400000 THEN
    RAISE EXCEPTION 'invalid history policy shape' USING ERRCODE='PF008';
  END IF;
  SELECT COUNT(*), COUNT(DISTINCT d.v)
    INTO v_count, v_distinct
    FROM jsonb_array_elements_text(p->'requiredFailureDomains') d(v);
  IF v_count NOT BETWEEN 1 AND 8 OR v_count <> v_distinct THEN
    RAISE EXCEPTION 'history policy requires 1..8 distinct failure domains'
      USING ERRCODE='PF008';
  END IF;
  IF EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(p->'requiredFailureDomains') d(v)
      WHERE d.v !~ '^[A-Za-z0-9._-]{1,64}$') THEN
    RAISE EXCEPTION 'history policy failure domains must match [A-Za-z0-9._-]{1,64}'
      USING ERRCODE='PF008';
  END IF;
END;
$$;

-- Expected-epoch CAS: p_expected_epoch must equal the installed epoch (0 when
-- none). A retry of the SAME bytes against the SAME expected epoch that
-- already succeeded returns the installed row idempotently.
CREATE FUNCTION pfh.install_history_policy(
  p_canonical_json TEXT, p_expected_epoch BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_policy JSONB;
  v_row pfh.history_policies;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_canonical_json IS NULL OR octet_length(p_canonical_json) NOT BETWEEN 2 AND 4096 THEN
    RAISE EXCEPTION 'history policy bytes are required (<= 4 KiB)' USING ERRCODE='PF008';
  END IF;
  IF p_expected_epoch IS NULL OR p_expected_epoch < 0 THEN
    RAISE EXCEPTION 'expected policy epoch is required (0 for first install)'
      USING ERRCODE='PF008';
  END IF;
  v_policy := p_canonical_json::JSONB;
  PERFORM pfh.history_policy_shape_check(v_policy);
  PERFORM pfh.scope_locks(ARRAY['pfh-policy:history']);
  SELECT * INTO v_row FROM pfh.history_policies WHERE singleton_key='history' FOR UPDATE;
  IF NOT FOUND THEN
    IF p_expected_epoch <> 0 THEN
      RAISE EXCEPTION 'policy CAS expected epoch % but none is installed',
        p_expected_epoch USING ERRCODE='PF002';
    END IF;
    INSERT INTO pfh.history_policies (
      singleton_key, policy_epoch, canonical_json, policy, installed_db_ms)
    VALUES ('history', 1, p_canonical_json, v_policy, v_now);
    RETURN jsonb_build_object('policyEpoch','1','installedAt',v_now::TEXT,'replayed',FALSE);
  END IF;
  IF v_row.policy_epoch = p_expected_epoch + 1
     AND v_row.canonical_json = p_canonical_json THEN
    -- Lost-response retry of the exact install that already happened.
    RETURN jsonb_build_object(
      'policyEpoch', v_row.policy_epoch::TEXT,
      'installedAt', v_row.installed_db_ms::TEXT, 'replayed', TRUE);
  END IF;
  IF v_row.policy_epoch <> p_expected_epoch THEN
    RAISE EXCEPTION 'policy CAS expected epoch % but % is installed',
      p_expected_epoch, v_row.policy_epoch USING ERRCODE='PF002';
  END IF;
  UPDATE pfh.history_policies SET
    policy_epoch=p_expected_epoch+1, canonical_json=p_canonical_json,
    policy=v_policy, installed_db_ms=v_now
  WHERE singleton_key='history';
  RETURN jsonb_build_object(
    'policyEpoch',(p_expected_epoch+1)::TEXT,'installedAt',v_now::TEXT,'replayed',FALSE);
END;
$$;

CREATE FUNCTION pfh.require_history_policy() RETURNS pfh.history_policies
LANGUAGE plpgsql STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v pfh.history_policies;
BEGIN
  SELECT * INTO v FROM pfh.history_policies WHERE singleton_key='history';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'history policy is not installed' USING ERRCODE='PF015';
  END IF;
  RETURN v;
END;
$$;

-- ─── Resource operations (permanent, pending until usable) ──────────────────

CREATE FUNCTION pfh.resource_operation_begin(
  p_tenant TEXT, p_domain TEXT, p_operation_id TEXT,
  p_kind TEXT, p_fingerprint TEXT, p_target_ids JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.resource_operations;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_operation_key(p_tenant, p_domain, p_operation_id);
  PERFORM pfh.require_sha256(p_fingerprint, 'operation fingerprint');
  IF p_target_ids IS NULL OR jsonb_typeof(p_target_ids) <> 'object'
     OR pg_column_size(p_target_ids) > 4096 THEN
    RAISE EXCEPTION 'operation target ids must be a bounded object' USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.scope_locks(ARRAY['pfh-op:'||p_tenant||E'\x01'||p_domain||E'\x01'||p_operation_id]);
  SELECT * INTO v FROM pfh.resource_operations
    WHERE tenant_id=p_tenant AND domain=p_domain AND operation_id=p_operation_id;
  IF FOUND THEN
    IF v.request_fingerprint <> p_fingerprint OR v.kind <> p_kind THEN
      RAISE EXCEPTION 'operation % replayed with different content', p_operation_id
        USING ERRCODE='PF009';
    END IF;
    RETURN jsonb_build_object(
      'operationId', v.operation_id, 'state', v.state,
      'stateRevision', v.state_revision::TEXT, 'targetIds', v.target_ids,
      'response', v.response, 'replayed', TRUE,
      'responseCompacted', v.response_compacted_db_ms IS NOT NULL);
  END IF;
  v_now := pfh.now_ms();
  INSERT INTO pfh.resource_operations (
    tenant_id, domain, operation_id, kind, request_fingerprint, target_ids,
    state, created_db_ms, updated_db_ms)
  VALUES (p_tenant, p_domain, p_operation_id, p_kind, p_fingerprint,
          p_target_ids, 'pending', v_now, v_now);
  RETURN jsonb_build_object(
    'operationId', p_operation_id, 'state', 'pending', 'stateRevision', '1',
    'targetIds', p_target_ids, 'replayed', FALSE);
END;
$$;

-- Settlement: pending -> terminal exactly once; an identical terminal replay
-- is idempotent; a contradicting terminal is a conflict. Settlement is
-- always invoked while the caller already holds the target's row lock (cut
-- before op — one order everywhere).
CREATE FUNCTION pfh.resource_operation_finish(
  p_tenant TEXT, p_domain TEXT, p_operation_id TEXT,
  p_state TEXT, p_response JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.resource_operations;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_operation_key(p_tenant, p_domain, p_operation_id);
  IF p_state NOT IN ('succeeded','failed','canceled','unknown_manual') THEN
    RAISE EXCEPTION 'operation terminal state % is unknown', p_state USING ERRCODE='PF008';
  END IF;
  IF p_response IS NOT NULL AND pg_column_size(p_response) > 65536 THEN
    RAISE EXCEPTION 'operation response exceeds 64 KiB' USING ERRCODE='PF004';
  END IF;
  SELECT * INTO v FROM pfh.resource_operations
    WHERE tenant_id=p_tenant AND domain=p_domain AND operation_id=p_operation_id
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'operation % not found', p_operation_id USING ERRCODE='PF007';
  END IF;
  IF v.state <> 'pending' THEN
    IF v.state = p_state THEN
      RETURN jsonb_build_object('operationId', v.operation_id, 'state', v.state,
                                'stateRevision', v.state_revision::TEXT, 'replayed', TRUE);
    END IF;
    RAISE EXCEPTION 'operation % is already terminal (%)', p_operation_id, v.state
      USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.resource_operations
    SET state=p_state, response=p_response, state_revision=state_revision+1,
        updated_db_ms=v_now, completed_db_ms=v_now
    WHERE tenant_id=p_tenant AND domain=p_domain AND operation_id=p_operation_id;
  RETURN jsonb_build_object('operationId', p_operation_id, 'state', p_state,
                            'stateRevision', (v.state_revision+1)::TEXT, 'replayed', FALSE);
END;
$$;

CREATE FUNCTION pfh.resource_operation_get(
  p_tenant TEXT, p_domain TEXT, p_operation_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v pfh.resource_operations;
BEGIN
  PERFORM pfh.require_operation_key(p_tenant, p_domain, p_operation_id);
  SELECT * INTO v FROM pfh.resource_operations
    WHERE tenant_id=p_tenant AND domain=p_domain AND operation_id=p_operation_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'tenantId', v.tenant_id, 'domain', v.domain, 'operationId', v.operation_id,
    'kind', v.kind, 'state', v.state, 'stateRevision', v.state_revision::TEXT,
    'targetIds', v.target_ids, 'response', v.response,
    'responseCompacted', v.response_compacted_db_ms IS NOT NULL,
    'createdDbMs', v.created_db_ms::TEXT, 'updatedDbMs', v.updated_db_ms::TEXT,
    'completedDbMs', CASE WHEN v.completed_db_ms IS NULL THEN NULL ELSE v.completed_db_ms::TEXT END);
END;
$$;

-- Bounded retention: response bodies compact away after the caller-supplied
-- age; the keyed tombstone (fingerprint + state + revision) is permanent.
CREATE FUNCTION pfh.resource_operation_compact(
  p_before_db_ms BIGINT, p_limit INT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,256),1),4096);
  v_now BIGINT := pfh.now_ms();
  v_count BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  WITH victims AS (
    SELECT tenant_id, domain, operation_id FROM pfh.resource_operations
    WHERE state <> 'pending' AND response IS NOT NULL
      AND completed_db_ms IS NOT NULL AND completed_db_ms < p_before_db_ms
    ORDER BY completed_db_ms
    LIMIT v_limit
    FOR UPDATE SKIP LOCKED)
  UPDATE pfh.resource_operations o
    SET response=NULL, response_compacted_db_ms=v_now, updated_db_ms=v_now
    FROM victims v
    WHERE o.tenant_id=v.tenant_id AND o.domain=v.domain AND o.operation_id=v.operation_id;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

-- ─── Cut status (shared projection) ──────────────────────────────────────────

CREATE FUNCTION pfh.cut_status(p_tenant TEXT, p_cut_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  p pfh.pft2_commits;
  ra pfh.recovery_anchors;
  ns pfh.inode_namespaces;
  v_base JSONB;
BEGIN
  SELECT * INTO c FROM pfh.history_cuts WHERE id=p_cut_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF c.result_commit_id IS NOT NULL THEN
    SELECT * INTO p FROM pfh.pft2_commits WHERE cut_id=c.id;
    SELECT * INTO ra FROM pfh.recovery_anchors WHERE cut_id=c.id;
  END IF;
  SELECT * INTO ns FROM pfh.inode_namespaces WHERE branch_id=c.branch_id;
  IF c.source_base_commit_id IS NOT NULL OR c.source_head_commit_id IS NOT NULL THEN
    -- The worker's base view: commit kind plus, for a pft2 base, its exact
    -- normalized provenance and recovery anchor (the worker holds no table
    -- privileges).
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'commitId', cm.id,
        'commitKind', cm.commit_kind,
        'treeHash', cm.tree_hash,
        'rootDigest', bp.root_digest,
        'rootSize', CASE WHEN bp.root_size IS NULL THEN NULL ELSE bp.root_size::TEXT END,
        'maxInoSeen', CASE WHEN bp.max_ino_seen IS NULL THEN NULL ELSE bp.max_ino_seen::TEXT END,
        'anchorId', ba.id,
        'recoveryRootDigest', ba.recovery_root_digest,
        'recoveryRootSize', CASE WHEN ba.recovery_root_size IS NULL THEN NULL
                                 ELSE ba.recovery_root_size::TEXT END,
        'controlRootDigest', ba.control_root_digest,
        'orphanIndexDigest', ba.orphan_index_digest,
        'inodeNamespace', CASE WHEN ba.inode_namespace IS NULL THEN NULL
                               ELSE ba.inode_namespace::TEXT END,
        'nextLocal', CASE WHEN ba.next_local IS NULL THEN NULL ELSE ba.next_local::TEXT END,
        'anchorMaxInoSeen', CASE WHEN ba.max_ino_seen IS NULL THEN NULL
                                 ELSE ba.max_ino_seen::TEXT END))
      INTO v_base
      FROM public.commits cm
      LEFT JOIN pfh.pft2_commits bp ON bp.commit_id=cm.id
      LEFT JOIN pfh.recovery_anchors ba ON ba.commit_id=cm.id
      WHERE cm.id=COALESCE(c.source_base_commit_id, c.source_head_commit_id);
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'baseCommit', v_base,
    'cutId', c.id, 'tenantId', c.tenant_id, 'volumeId', c.volume_id,
    'branchId', c.branch_id, 'branchName', c.branch_name,
    'kind', c.kind, 'sourceKind', c.source_kind,
    'generationId', c.generation_id,
    'journalEpoch', CASE WHEN c.journal_epoch IS NULL THEN NULL ELSE c.journal_epoch::TEXT END,
    'recordCodec', c.record_codec, 'controlCodec', c.control_codec,
    'sourceBaseCommitId', c.source_base_commit_id,
    'sourceBaseSeq', CASE WHEN c.source_base_seq IS NULL THEN NULL ELSE c.source_base_seq::TEXT END,
    'sourceBaseDigest', c.source_base_digest,
    'cutSeqExclusive', CASE WHEN c.cut_seq_exclusive IS NULL THEN NULL ELSE c.cut_seq_exclusive::TEXT END,
    'cutDigest', c.cut_digest,
    'cutBacklogBytes', CASE WHEN c.cut_backlog_bytes IS NULL THEN NULL ELSE c.cut_backlog_bytes::TEXT END,
    'cutBacklogRecords', CASE WHEN c.cut_backlog_records IS NULL THEN NULL ELSE c.cut_backlog_records::TEXT END,
    'sourceHeadCommitId', c.source_head_commit_id,
    'materializerVersion', c.materializer_version,
    'replicationPolicy', c.replication_policy,
    'dedupRevision', c.dedup_revision::TEXT,
    'state', c.state,
    'claimEpoch', c.claim_epoch::TEXT,
    'attemptCount', c.attempt_count,
    'nextAttemptDbMs', c.next_attempt_db_ms::TEXT,
    'progress', c.progress,
    'lastError', c.last_error,
    'resultCommitId', c.result_commit_id,
    'recoveryAnchorId', c.recovery_anchor_id,
    'operationId', c.op_operation_id,
    'inodeNamespace', CASE WHEN ns.namespace IS NULL THEN NULL ELSE ns.namespace::TEXT END,
    'namespaceNextLocal', CASE WHEN ns.namespace IS NULL THEN NULL ELSE ns.next_local::TEXT END,
    'namespaceMaxInoSeen', CASE WHEN ns.namespace IS NULL THEN NULL ELSE ns.max_ino_seen::TEXT END,
    'result', CASE WHEN p.commit_id IS NULL THEN NULL ELSE jsonb_strip_nulls(jsonb_build_object(
      'commitId', p.commit_id,
      'rootDigest', p.root_digest, 'rootSize', p.root_size::TEXT,
      'maxInoSeen', p.max_ino_seen::TEXT,
      'objectCount', p.object_count::TEXT,
      'objectBytes', p.object_bytes::TEXT,
      'anchorId', ra.id,
      'recoveryRootDigest', ra.recovery_root_digest,
      'recoveryRootSize', ra.recovery_root_size::TEXT,
      'controlRootDigest', ra.control_root_digest,
      'orphanIndexDigest', ra.orphan_index_digest,
      'inodeNamespace', ra.inode_namespace::TEXT,
      'nextLocal', ra.next_local::TEXT,
      'anchorObjectCount', ra.object_count::TEXT,
      'anchorObjectBytes', ra.object_bytes::TEXT)) END,
    'createdDbMs', c.created_db_ms::TEXT,
    'updatedDbMs', c.updated_db_ms::TEXT,
    'readyDbMs', CASE WHEN c.ready_db_ms IS NULL THEN NULL ELSE c.ready_db_ms::TEXT END));
END;
$$;

-- ─── Inode namespaces ────────────────────────────────────────────────────────

CREATE FUNCTION pfh.inode_namespace_issue(
  p_tenant TEXT, p_volume TEXT, p_branch_id TEXT, p_purpose TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.inode_namespaces;
  v_ns BIGINT;
  v_now BIGINT;
  v_attempt INT := 0;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_purpose NOT IN ('branch','conversion') THEN
    RAISE EXCEPTION 'namespace purpose % is unknown', p_purpose USING ERRCODE='PF008';
  END IF;
  SELECT * INTO v FROM pfh.inode_namespaces WHERE branch_id=p_branch_id;
  IF FOUND THEN
    RETURN jsonb_build_object(
      'namespace', v.namespace::TEXT, 'nextLocal', v.next_local::TEXT,
      'maxInoSeen', v.max_ino_seen::TEXT, 'issued', FALSE);
  END IF;
  v_now := pfh.now_ms();
  LOOP
    v_attempt := v_attempt + 1;
    IF v_attempt > 8 THEN
      RAISE EXCEPTION 'inode namespace issuance did not converge' USING ERRCODE='PF010';
    END IF;
    v_ns := nextval('pfh.inode_namespace_seq');
    BEGIN
      INSERT INTO pfh.inode_namespaces (
        namespace, tenant_id, volume_id, branch_id, purpose,
        issued_db_ms, updated_db_ms)
      VALUES (v_ns, p_tenant, p_volume, p_branch_id, p_purpose, v_now, v_now);
      EXIT;
    EXCEPTION WHEN unique_violation THEN
      -- A concurrent issuer won the branch row; return the winner.
      SELECT * INTO v FROM pfh.inode_namespaces WHERE branch_id=p_branch_id;
      IF FOUND THEN
        RETURN jsonb_build_object(
          'namespace', v.namespace::TEXT, 'nextLocal', v.next_local::TEXT,
          'maxInoSeen', v.max_ino_seen::TEXT, 'issued', FALSE);
      END IF;
    END;
  END LOOP;
  RETURN jsonb_build_object(
    'namespace', v_ns::TEXT, 'nextLocal', '1', 'maxInoSeen', '1', 'issued', TRUE);
END;
$$;

-- ─── Cut creation (exact capture; outer operation stays pending) ─────────────

-- pfh.cut_create captures one exact revision. It calls the journal-owner
-- primitive pfj.history_head_capture, which takes the SAME exclusive branch
-- advisory lock + generation head row lock the append path takes, so a racing
-- append is wholly before or after this cut — and returns the generation's
-- cumulative backlog counters AT that boundary in the same snapshot. Locks
-- persist to transaction end. It never reads authority RAM or object
-- storage, and it never drains, suspends, or changes a branch mode.
--
-- The outer resource operation is created 'pending' and REMAINS pending
-- until the cut is usable: pfh.cut_mark_ready settles it 'succeeded',
-- pfh.cut_fail / dead-lettering settle it 'failed', pfh.cut_cancel settles
-- it 'canceled'. A lost response replays as the pending operation with its
-- preallocated cut id.
CREATE FUNCTION pfh.cut_create(
  p_tenant TEXT, p_volume TEXT, p_branch_name TEXT,
  p_kind TEXT, p_operation_id TEXT, p_fingerprint TEXT,
  p_materializer_version TEXT, p_target_ids JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_policy pfh.history_policies;
  v_capture JSONB;
  v_now BIGINT;
  v_op JSONB;
  v_cut pfh.history_cuts;
  v_dedup_key TEXT;
  v_revision BIGINT;
  v_id TEXT;
  v_source_kind TEXT;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_kind NOT IN ('user','recovery','conversion_final') THEN
    RAISE EXCEPTION 'cut kind % is unknown', p_kind USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.require_sha256(p_fingerprint, 'cut fingerprint');
  IF p_materializer_version IS NULL
     OR length(p_materializer_version) NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'materializer version is required (<=64 chars)' USING ERRCODE='PF008';
  END IF;
  v_policy := pfh.require_history_policy();
  v_op := pfh.resource_operation_begin(
    p_tenant, 'history-cut', p_operation_id, 'cut-create', p_fingerprint,
    COALESCE(p_target_ids, '{}'::jsonb));
  IF (v_op->>'replayed')::BOOLEAN THEN
    -- Exact replay: the recorded pending/terminal outcome (or its tombstone).
    RETURN v_op;
  END IF;

  -- Exact head capture under the append lock order (journal owner primitive).
  v_capture := pfj.history_head_capture(p_tenant, p_volume, p_branch_name);
  v_source_kind := v_capture->>'sourceKind';
  IF v_source_kind = 'legacy_manifest' AND p_kind <> 'conversion_final' THEN
    RAISE EXCEPTION 'legacy_manifest branches only take conversion_final cuts'
      USING ERRCODE='PF001';
  END IF;
  IF p_kind = 'conversion_final'
     AND v_source_kind = 'managed_journal'
     AND COALESCE(v_capture->>'recordCodec','pfr1') <> 'pfr1' THEN
    RAISE EXCEPTION 'conversion_final cuts capture pfr1/legacy sources only'
      USING ERRCODE='PF005';
  END IF;

  -- The branch's durable inode namespace exists from the first cut onward.
  PERFORM pfh.inode_namespace_issue(
    p_tenant, p_volume, v_capture->>'branchId',
    CASE WHEN p_kind='conversion_final' THEN 'conversion' ELSE 'branch' END);

  v_now := pfh.now_ms();
  v_dedup_key := CASE v_source_kind
    WHEN 'managed_journal' THEN
      'g'||E'\x01'||(v_capture->>'generationId')||E'\x01'||(v_capture->>'cutSeqExclusive')
    ELSE
      'h'||E'\x01'||(v_capture->>'branchId')||E'\x01'||(v_capture->>'headCommitId')
  END;

  SELECT * INTO v_cut FROM pfh.history_cuts
    WHERE dedup_key=v_dedup_key AND kind=p_kind
    ORDER BY dedup_revision DESC LIMIT 1
    FOR UPDATE;
  IF FOUND AND v_cut.state NOT IN ('failed','canceled') THEN
    -- Concurrent identical captures converge onto the live cut row. THIS
    -- operation settles now: its outcome is the existing cut (usable or
    -- progressing under its own original operation).
    PERFORM pfh.resource_operation_finish(
      p_tenant, 'history-cut', p_operation_id, 'succeeded',
      jsonb_build_object('cutId', v_cut.id, 'state', v_cut.state, 'deduplicated', TRUE));
    RETURN pfh.cut_status(p_tenant, v_cut.id);
  END IF;
  v_revision := COALESCE(v_cut.dedup_revision, 0) + 1;

  v_id := pfh.new_id('hcut');
  INSERT INTO pfh.history_cuts (
    id, tenant_id, volume_id, branch_id, branch_name, kind, source_kind,
    generation_id, journal_epoch, record_codec, control_codec,
    source_base_commit_id, source_base_seq, source_base_digest,
    cut_seq_exclusive, cut_digest, cut_backlog_bytes, cut_backlog_records,
    source_head_commit_id,
    materializer_version, replication_policy, dedup_key, dedup_revision,
    request_fingerprint, op_tenant_id, op_domain, op_operation_id,
    state, created_db_ms, updated_db_ms)
  VALUES (
    v_id, p_tenant, p_volume, v_capture->>'branchId', p_branch_name, p_kind,
    v_source_kind,
    v_capture->>'generationId',
    (v_capture->>'journalEpoch')::BIGINT,
    v_capture->>'recordCodec', v_capture->>'controlCodec',
    v_capture->>'baseCommitId',
    (v_capture->>'baseSeq')::BIGINT,
    v_capture->>'baseDigest',
    (v_capture->>'cutSeqExclusive')::BIGINT,
    v_capture->>'cutDigest',
    (v_capture->>'backlogBytes')::BIGINT,
    (v_capture->>'backlogRecords')::BIGINT,
    v_capture->>'headCommitId',
    p_materializer_version,
    jsonb_build_object(
      'v','1',
      'requiredFailureDomains', v_policy.policy->'requiredFailureDomains',
      'policyEpoch', v_policy.policy_epoch::TEXT),
    v_dedup_key, v_revision, p_fingerprint,
    p_tenant, 'history-cut', p_operation_id,
    'pending', v_now, v_now);

  -- Record the preallocated target on the still-pending operation.
  UPDATE pfh.resource_operations SET
    target_ids = target_ids || jsonb_build_object('cutId', v_id),
    updated_db_ms = v_now
  WHERE tenant_id=p_tenant AND domain='history-cut' AND operation_id=p_operation_id;
  RETURN pfh.cut_status(p_tenant, v_id);
END;
$$;

-- ─── Worker claim / lease / progress (DB-time fenced) ────────────────────────

CREATE FUNCTION pfh.require_live_claim(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_for_update BOOLEAN
) RETURNS pfh.history_cuts
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT := pfh.now_ms();
BEGIN
  IF p_for_update THEN
    SELECT * INTO c FROM pfh.history_cuts WHERE id=p_cut_id FOR UPDATE;
  ELSE
    SELECT * INTO c FROM pfh.history_cuts WHERE id=p_cut_id;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF c.state <> 'materializing' OR c.claim_epoch <> p_claim_epoch THEN
    RAISE EXCEPTION 'cut % claim epoch % is stale (state %, epoch %)',
      p_cut_id, p_claim_epoch, c.state, c.claim_epoch USING ERRCODE='PF001';
  END IF;
  IF c.lease_expires_db_ms IS NULL OR c.lease_expires_db_ms < v_now THEN
    RAISE EXCEPTION 'cut % worker lease expired at database time', p_cut_id
      USING ERRCODE='PF001';
  END IF;
  RETURN c;
END;
$$;

-- Claim with bounded retry and dead-lettering: a cut whose attempt budget is
-- exhausted is settled 'failed' (dead_letter) instead of being handed out
-- again; its outer operation settles atomically with it.
CREATE FUNCTION pfh.cut_claim(
  p_worker_id TEXT, p_limit INT, p_lease_ttl_ms BIGINT
) RETURNS SETOF JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
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
  INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
  VALUES ('materializer', p_worker_id, v_now, '{}'::jsonb)
  ON CONFLICT (worker_kind, worker_id) DO UPDATE
    SET last_beat_db_ms=EXCLUDED.last_beat_db_ms;
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
$$;

CREATE FUNCTION pfh.cut_heartbeat(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_worker_id TEXT,
  p_lease_ttl_ms BIGINT, p_progress JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
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
  INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
  VALUES ('materializer', p_worker_id, v_now,
          jsonb_build_object('cut', p_cut_id, 'claimEpoch', p_claim_epoch::TEXT))
  ON CONFLICT (worker_kind, worker_id) DO UPDATE
    SET last_beat_db_ms=EXCLUDED.last_beat_db_ms, facts=EXCLUDED.facts;
  RETURN jsonb_build_object(
    'cutId', p_cut_id, 'leaseExpiresDbMs', (v_now+v_ttl)::TEXT, 'dbTimeMs', v_now::TEXT);
END;
$$;

CREATE FUNCTION pfh.cut_retry(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_error JSONB, p_backoff_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
  v_backoff BIGINT := LEAST(GREATEST(COALESCE(p_backoff_ms,5000),1000),3600000);
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, TRUE);
  IF p_error IS NOT NULL AND pg_column_size(p_error) > 8192 THEN
    RAISE EXCEPTION 'cut error exceeds 8 KiB' USING ERRCODE='PF004';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.history_cuts SET
    state='pending',
    lease_expires_db_ms=NULL,
    next_attempt_db_ms=v_now+v_backoff,
    last_error=p_error,
    updated_db_ms=v_now
  WHERE id=p_cut_id;
  RETURN jsonb_build_object('cutId', p_cut_id, 'state', 'pending',
                            'nextAttemptDbMs', (v_now+v_backoff)::TEXT);
END;
$$;

-- Definite failure (canonical corruption of the source). The journal prefix
-- stays pinned for audit; nothing is ever released for trimming by a
-- failure. The outer operation settles 'failed' atomically (cut row locked
-- first, then the operation row — the one lock order).
CREATE FUNCTION pfh.cut_fail(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_error JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, TRUE);
  IF p_error IS NULL OR pg_column_size(p_error) > 8192 THEN
    RAISE EXCEPTION 'a definite failure requires a bounded error document'
      USING ERRCODE='PF008';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.history_cuts SET
    state='failed', lease_expires_db_ms=NULL, last_error=p_error, updated_db_ms=v_now
  WHERE id=p_cut_id;
  PERFORM pfh.resource_operation_finish(
    c.op_tenant_id, c.op_domain, c.op_operation_id, 'failed',
    jsonb_build_object('cutId', p_cut_id, 'state', 'failed', 'error', p_error));
  RETURN jsonb_build_object('cutId', p_cut_id, 'state', 'failed');
END;
$$;

CREATE FUNCTION pfh.cut_cancel(
  p_tenant TEXT, p_cut_id TEXT, p_operation_id TEXT, p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
  v_op JSONB;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'cancel fingerprint');
  v_op := pfh.resource_operation_begin(
    p_tenant, 'history-cut', p_operation_id, 'cut-cancel', p_fingerprint,
    jsonb_build_object('cutId', p_cut_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF c.state NOT IN ('pending','materializing') THEN
    RAISE EXCEPTION 'cut % is % and cannot be canceled', p_cut_id, c.state
      USING ERRCODE='PF002';
  END IF;
  IF EXISTS (SELECT 1 FROM pfh.cut_consumers
             WHERE cut_id=p_cut_id AND released_db_ms IS NULL
               AND consumer_kind IN ('conversion','adoption')) THEN
    RAISE EXCEPTION 'cut % is pinned by a conversion/adoption consumer', p_cut_id
      USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.history_cuts SET
    state='canceled', lease_expires_db_ms=NULL, updated_db_ms=v_now
  WHERE id=p_cut_id;
  -- Settle BOTH operations: the original create settles 'canceled', this
  -- cancel operation settles 'succeeded' (cut row already locked above).
  PERFORM pfh.resource_operation_finish(
    c.op_tenant_id, c.op_domain, c.op_operation_id, 'canceled',
    jsonb_build_object('cutId', p_cut_id, 'state', 'canceled'));
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'history-cut', p_operation_id, 'succeeded',
    jsonb_build_object('cutId', p_cut_id, 'state', 'canceled'));
  RETURN jsonb_build_object('cutId', p_cut_id, 'state', 'canceled', 'replayed', FALSE);
END;
$$;

-- Claim-fenced bounded journal reads, independent of live writer credentials.
CREATE FUNCTION pfh.cut_read_page(
  p_cut_id TEXT, p_claim_epoch BIGINT,
  p_from_seq BIGINT, p_max_records INT, p_max_bytes BIGINT
) RETURNS TABLE (seq BIGINT, payload BYTEA, record_hash TEXT, chain_digest TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE c pfh.history_cuts;
BEGIN
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF c.source_kind <> 'managed_journal' THEN
    RAISE EXCEPTION 'cut % has no journal source', p_cut_id USING ERRCODE='PF008';
  END IF;
  IF p_from_seq IS NULL OR p_from_seq < c.source_base_seq
     OR p_from_seq > c.cut_seq_exclusive THEN
    RAISE EXCEPTION 'cut read start is outside [%, %]',
      c.source_base_seq, c.cut_seq_exclusive USING ERRCODE='PF008';
  END IF;
  RETURN QUERY SELECT * FROM pfj.history_read_records(
    c.generation_id, p_from_seq, c.cut_seq_exclusive, p_max_records, p_max_bytes);
END;
$$;

-- ─── Objects, copies, intents (tenant/kind/digest/incarnation) ───────────────

-- Registers upload intents and binds the incarnation each upload will
-- publish under. Returns one row per object: the bound incarnation (bumped
-- when the identity is deleting/tombstoned — the ABA guard) so the worker
-- derives the exact per-incarnation storage key BEFORE the first PUT.
CREATE FUNCTION pfh.object_intend(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_objects JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
  v_count INT;
  e JSONB;
  v_digest TEXT;
  v_size BIGINT;
  o pfh.objects;
  v_out JSONB := '[]'::jsonb;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF p_objects IS NULL OR jsonb_typeof(p_objects) <> 'array' THEN
    RAISE EXCEPTION 'object intents must be an array' USING ERRCODE='PF008';
  END IF;
  SELECT COUNT(*) INTO v_count FROM jsonb_array_elements(p_objects);
  IF v_count NOT BETWEEN 1 AND 512 THEN
    RAISE EXCEPTION 'object intents are bounded to 1..512 per call' USING ERRCODE='PF004';
  END IF;
  v_now := pfh.now_ms();
  FOR e IN SELECT * FROM jsonb_array_elements(p_objects) LOOP
    v_digest := e->>'digest';
    v_size := (e->>'size')::BIGINT;
    PERFORM pfh.require_object_identity(c.tenant_id, 'pft2', v_digest);
    IF v_size IS NULL OR v_size < 0 THEN
      RAISE EXCEPTION 'object intent requires digest and size' USING ERRCODE='PF008';
    END IF;
    -- Sorted per-identity advisory keys serialize against GC claims.
    PERFORM pfh.scope_locks(ARRAY['pfh-object:'||c.tenant_id||E'\x01'||'pft2'||E'\x01'||v_digest]);
    SELECT * INTO o FROM pfh.objects
      WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=v_digest FOR UPDATE;
    IF FOUND THEN
      IF o.size <> v_size THEN
        RAISE EXCEPTION 'object % size conflict (% vs %)', v_digest, o.size, v_size
          USING ERRCODE='PF002';
      END IF;
      IF o.state IN ('deleting','tombstoned') THEN
        -- Re-upload after (or during) deletion begins a NEW incarnation with
        -- a NEW physical key; a sweep in flight observes the bump and
        -- resurrects instead of finalizing. Incarnation N's deletion can
        -- never touch incarnation N+1's copies.
        UPDATE pfh.objects SET
          incarnation=incarnation+1, state='intended',
          sweep_worker_id=NULL, sweep_claim_expires_db_ms=NULL,
          updated_db_ms=v_now
        WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=v_digest
        RETURNING * INTO o;
      ELSIF o.state = 'reclaiming' THEN
        UPDATE pfh.objects SET state='intended', updated_db_ms=v_now
        WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=v_digest
        RETURNING * INTO o;
      END IF;
    ELSE
      INSERT INTO pfh.objects (tenant_id, kind, digest, size, state, created_db_ms, updated_db_ms)
      VALUES (c.tenant_id, 'pft2', v_digest, v_size, 'intended', v_now, v_now)
      RETURNING * INTO o;
    END IF;
    INSERT INTO pfh.upload_intents (
      cut_id, tenant_id, kind, digest, size, incarnation, claim_epoch, created_db_ms)
    VALUES (p_cut_id, c.tenant_id, 'pft2', v_digest, v_size, o.incarnation,
            p_claim_epoch, v_now)
    ON CONFLICT (cut_id, digest) DO UPDATE
      SET incarnation=EXCLUDED.incarnation, claim_epoch=EXCLUDED.claim_epoch;
    v_out := v_out || jsonb_build_array(jsonb_build_object(
      'digest', v_digest, 'incarnation', o.incarnation::TEXT));
  END LOOP;
  RETURN v_out;
END;
$$;

-- Records one VERIFIED copy: the caller has already written the EXACT
-- per-incarnation key, read it back from that same key, matched the byte
-- count, and re-hashed the plaintext (read-after-write, or the lost-outcome
-- reconciliation path — identical proof either way). The receipt binds the
-- live claim, the intended incarnation, the failure domain, the exact
-- storage key, and the size.
CREATE FUNCTION pfh.object_copy_receipt(
  p_cut_id TEXT, p_claim_epoch BIGINT,
  p_digest TEXT, p_incarnation BIGINT,
  p_failure_domain TEXT, p_storage_key TEXT, p_size BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  o pfh.objects;
  v_intent pfh.upload_intents;
  v_now BIGINT;
  v_required BIGINT;
  v_present BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  PERFORM pfh.require_object_identity(c.tenant_id, 'pft2', p_digest);
  IF p_incarnation IS NULL OR p_incarnation < 1
     OR p_failure_domain IS NULL OR length(p_failure_domain) NOT BETWEEN 1 AND 128
     OR p_storage_key IS NULL OR length(p_storage_key) NOT BETWEEN 1 AND 1024
     OR p_size IS NULL OR p_size < 0 THEN
    RAISE EXCEPTION 'copy receipt requires incarnation, domain, storage key, size'
      USING ERRCODE='PF008';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(c.replication_policy->'requiredFailureDomains') d(v)
    WHERE d.v = p_failure_domain) THEN
    RAISE EXCEPTION 'failure domain % is not in the cut replication policy',
      p_failure_domain USING ERRCODE='PF008';
  END IF;
  SELECT * INTO v_intent FROM pfh.upload_intents
    WHERE cut_id=p_cut_id AND digest=p_digest;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'copy receipt for % without an upload intent', p_digest
      USING ERRCODE='PF011';
  END IF;
  IF v_intent.incarnation <> p_incarnation THEN
    RAISE EXCEPTION 'copy receipt incarnation % contradicts the intent (%)',
      p_incarnation, v_intent.incarnation USING ERRCODE='PF002';
  END IF;
  PERFORM pfh.scope_locks(ARRAY['pfh-object:'||c.tenant_id||E'\x01'||'pft2'||E'\x01'||p_digest]);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=p_digest FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'object % is not registered', p_digest USING ERRCODE='PF007';
  END IF;
  IF o.size <> p_size THEN
    RAISE EXCEPTION 'object % copy size % contradicts registered size %',
      p_digest, p_size, o.size USING ERRCODE='PF002';
  END IF;
  IF o.incarnation <> p_incarnation OR o.state IN ('deleting','tombstoned') THEN
    -- A stale upload (superseded incarnation, or a sweep won the race) can
    -- never heal or receipt into the current identity: re-intend first.
    RAISE EXCEPTION 'object % incarnation % is superseded (current %, state %)',
      p_digest, p_incarnation, o.incarnation, o.state USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  INSERT INTO pfh.object_copies (
    tenant_id, kind, digest, incarnation, failure_domain, storage_key, size,
    state, first_verified_db_ms, last_verified_db_ms)
  VALUES (c.tenant_id, 'pft2', p_digest, p_incarnation, p_failure_domain,
          p_storage_key, p_size, 'present', v_now, v_now)
  ON CONFLICT (tenant_id, kind, digest, incarnation, failure_domain) DO UPDATE
    SET storage_key=EXCLUDED.storage_key, size=EXCLUDED.size, state='present',
        last_verified_db_ms=EXCLUDED.last_verified_db_ms, verify_attempts=0,
        next_verify_db_ms=0, verify_claim_worker_id=NULL,
        verify_claim_expires_db_ms=NULL, absence_receipt=NULL;
  SELECT COUNT(*) INTO v_required
    FROM jsonb_array_elements_text(c.replication_policy->'requiredFailureDomains');
  SELECT COUNT(*) INTO v_present FROM pfh.object_copies oc
    WHERE oc.tenant_id=c.tenant_id AND oc.kind='pft2' AND oc.digest=p_digest
      AND oc.incarnation=o.incarnation AND oc.state='present'
      AND oc.failure_domain IN (
        SELECT d.v FROM jsonb_array_elements_text(
          c.replication_policy->'requiredFailureDomains') d(v));
  IF v_present >= v_required AND o.state IN ('intended','reclaiming') THEN
    UPDATE pfh.objects SET state='live', updated_db_ms=v_now
    WHERE tenant_id=c.tenant_id AND kind='pft2' AND digest=p_digest;
  END IF;
  RETURN jsonb_build_object(
    'digest', p_digest, 'incarnation', o.incarnation::TEXT,
    'presentDomains', v_present, 'requiredDomains', v_required);
END;
$$;

CREATE FUNCTION pfh.cut_objects_add(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_closure TEXT, p_digests TEXT[]
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_count INT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF p_closure NOT IN ('user','recovery') THEN
    RAISE EXCEPTION 'closure must be user or recovery' USING ERRCODE='PF008';
  END IF;
  v_count := COALESCE(array_length(p_digests,1),0);
  IF v_count NOT BETWEEN 1 AND 4096 THEN
    RAISE EXCEPTION 'cut object pages are bounded to 1..4096 digests' USING ERRCODE='PF004';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(p_digests) d(v) WHERE v !~ '^sha256:[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'cut object digests must be sha256 addresses' USING ERRCODE='PF008';
  END IF;
  INSERT INTO pfh.cut_objects (cut_id, closure, tenant_id, kind, digest)
  SELECT p_cut_id, p_closure, c.tenant_id, 'pft2', d.v FROM unnest(p_digests) d(v)
  ON CONFLICT DO NOTHING;
  RETURN v_count;
END;
$$;

-- Locates the verified live copies of one object by RECORDED exact keys.
-- Never derives a path: the response is exactly what receipts recorded.
-- Shared by the worker (base-object reads) and the volume-api serving path
-- (tenant-gated object streaming). Only 'present' copies of the CURRENT
-- incarnation of a non-tombstoned object are returned.
CREATE FUNCTION pfh.object_locate(
  p_tenant TEXT, p_kind TEXT, p_digest TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  o pfh.objects;
  v_copies JSONB;
BEGIN
  PERFORM pfh.require_object_identity(p_tenant, p_kind, p_digest);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
  IF NOT FOUND OR o.state IN ('tombstoned') THEN
    RETURN NULL;
  END IF;
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'failureDomain', oc.failure_domain,
      'storageKey', oc.storage_key,
      'size', oc.size::TEXT,
      'lastVerifiedDbMs', oc.last_verified_db_ms::TEXT)
      ORDER BY oc.last_verified_db_ms DESC), '[]'::jsonb)
    INTO v_copies
    FROM pfh.object_copies oc
    WHERE oc.tenant_id=p_tenant AND oc.kind=p_kind AND oc.digest=p_digest
      AND oc.incarnation=o.incarnation AND oc.state='present';
  RETURN jsonb_build_object(
    'tenantId', p_tenant, 'kind', p_kind, 'digest', p_digest,
    'size', o.size::TEXT, 'incarnation', o.incarnation::TEXT,
    'state', o.state, 'copies', v_copies);
END;
$$;

-- Locates one LEGACY blob (conversion input) by its recorded public.blobs
-- storage key. Legacy blobs are the pre-013 digest-addressed store; their
-- recorded storage_key is returned verbatim (the worker maps file:// and
-- bucket-key forms onto its configured stores).
CREATE FUNCTION pfh.legacy_blob_locate(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_digest TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_row RECORD;
BEGIN
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF p_digest IS NULL OR p_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'legacy blob digest must be a sha256 address' USING ERRCODE='PF008';
  END IF;
  SELECT b.digest, b.size, b.storage_key INTO v_row
    FROM public.blobs b WHERE b.digest=p_digest;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'digest', v_row.digest, 'size', v_row.size::TEXT,
    'storageKey', v_row.storage_key));
END;
$$;

-- ─── Ready publication (user commit + recovery anchor, atomic) ───────────────

-- Verifies the complete DUAL closure (every recorded object live with fresh
-- verified copies across every required failure domain, none quarantined),
-- advances the branch allocator watermarks monotonically, inserts the pft2
-- commit (user arm) AND the recovery anchor (internal arm), settles the
-- outer operation 'succeeded', and marks the cut ready — atomically, under
-- the current claim epoch. Chain/hash/PFR1/PFC2 verification happened in the
-- worker against the exact cut tuple; the tuple itself is frozen in this row.
CREATE FUNCTION pfh.cut_mark_ready(
  p_cut_id TEXT, p_claim_epoch BIGINT,
  p_root_digest TEXT, p_root_size BIGINT,
  p_recovery_root_digest TEXT, p_recovery_root_size BIGINT,
  p_control_root_digest TEXT, p_control_root_size BIGINT,
  p_orphan_index_digest TEXT, p_orphan_index_size BIGINT,
  p_inode_namespace BIGINT, p_next_local BIGINT, p_max_ino_seen BIGINT,
  p_user_object_count BIGINT, p_user_object_bytes BIGINT,
  p_recovery_object_count BIGINT, p_recovery_object_bytes BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  ns pfh.inode_namespaces;
  v_now BIGINT;
  v_required BIGINT;
  v_missing BIGINT;
  v_user_closure BIGINT;
  v_recovery_closure BIGINT;
  v_commit_id TEXT;
  v_anchor_id TEXT;
  v_freshness BIGINT;
  v_policy pfh.history_policies;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, TRUE);
  PERFORM pfh.require_sha256(p_root_digest, 'pft2 root digest');
  PERFORM pfh.require_sha256(p_recovery_root_digest, 'recovery root digest');
  IF p_root_size IS NULL OR p_root_size <= 0
     OR p_recovery_root_size IS NULL OR p_recovery_root_size <= 0 THEN
    RAISE EXCEPTION 'root sizes are required' USING ERRCODE='PF008';
  END IF;
  IF (p_control_root_digest IS NULL) <> (p_control_root_size IS NULL)
     OR (p_orphan_index_digest IS NULL) <> (p_orphan_index_size IS NULL) THEN
    RAISE EXCEPTION 'control/orphan roots require digest and size together'
      USING ERRCODE='PF008';
  END IF;
  IF p_next_local IS NULL OR p_next_local NOT BETWEEN 1 AND 4294967296
     OR p_max_ino_seen IS NULL OR p_max_ino_seen < 1
     OR p_user_object_count IS NULL OR p_user_object_count < 1
     OR p_user_object_bytes IS NULL OR p_user_object_bytes < 0
     OR p_recovery_object_count IS NULL OR p_recovery_object_count < 1
     OR p_recovery_object_bytes IS NULL OR p_recovery_object_bytes < 0 THEN
    RAISE EXCEPTION 'allocator watermarks and object totals are required'
      USING ERRCODE='PF008';
  END IF;
  v_policy := pfh.require_history_policy();
  v_freshness := (v_policy.policy->>'maxLastVerifiedAgeMs')::BIGINT;
  v_now := pfh.now_ms();

  SELECT COUNT(*) INTO v_user_closure
    FROM pfh.cut_objects WHERE cut_id=p_cut_id AND closure='user';
  SELECT COUNT(*) INTO v_recovery_closure
    FROM pfh.cut_objects WHERE cut_id=p_cut_id AND closure='recovery';
  IF v_user_closure <> p_user_object_count
     OR v_recovery_closure <> p_recovery_object_count THEN
    RAISE EXCEPTION 'closures hold %/% objects, worker reported %/%',
      v_user_closure, v_recovery_closure, p_user_object_count, p_recovery_object_count
      USING ERRCODE='PF010';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      WHERE co.cut_id=p_cut_id AND co.closure='user'
        AND co.digest='sha256:'||p_root_digest)
     OR NOT EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      WHERE co.cut_id=p_cut_id AND co.closure='recovery'
        AND co.digest='sha256:'||p_recovery_root_digest) THEN
    RAISE EXCEPTION 'closures must contain their own roots' USING ERRCODE='PF010';
  END IF;
  -- The internal arm never leaks into the user closure: the recovery root,
  -- control root and orphan index are structurally recovery-only.
  IF EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      WHERE co.cut_id=p_cut_id AND co.closure='user'
        AND co.digest IN (
          'sha256:'||p_recovery_root_digest,
          'sha256:'||COALESCE(p_control_root_digest,repeat('0',64)),
          'sha256:'||COALESCE(p_orphan_index_digest,repeat('0',64)))) THEN
    RAISE EXCEPTION 'user closure reaches internal recovery objects' USING ERRCODE='PF010';
  END IF;

  SELECT COUNT(*) INTO v_required
    FROM jsonb_array_elements_text(c.replication_policy->'requiredFailureDomains');
  -- Every closure object (both closures): registered under THIS tenant,
  -- live (not quarantined/deleting), and covered by a fresh verified copy in
  -- EVERY required failure domain at its CURRENT incarnation.
  SELECT COUNT(*) INTO v_missing
  FROM (SELECT DISTINCT co.tenant_id, co.kind, co.digest
        FROM pfh.cut_objects co WHERE co.cut_id=p_cut_id) refs
  LEFT JOIN pfh.objects o
    ON o.tenant_id=refs.tenant_id AND o.kind=refs.kind AND o.digest=refs.digest
  WHERE o.digest IS NULL
     OR o.state <> 'live'
     OR v_required > (
        SELECT COUNT(*) FROM pfh.object_copies oc
        WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
          AND oc.incarnation=o.incarnation
          AND oc.state='present'
          AND oc.last_verified_db_ms >= v_now - v_freshness
          AND oc.failure_domain IN (
            SELECT d.v FROM jsonb_array_elements_text(
              c.replication_policy->'requiredFailureDomains') d(v)));
  IF v_missing > 0 THEN
    RAISE EXCEPTION 'cut % has % objects without fresh verified copies in every required domain',
      p_cut_id, v_missing USING ERRCODE='PF011';
  END IF;

  -- Branch allocator watermarks advance monotonically (trigger re-checks).
  SELECT * INTO ns FROM pfh.inode_namespaces WHERE namespace=p_inode_namespace FOR UPDATE;
  IF NOT FOUND OR ns.branch_id <> c.branch_id THEN
    RAISE EXCEPTION 'inode namespace % does not belong to branch %',
      p_inode_namespace, c.branch_id USING ERRCODE='PF011';
  END IF;
  UPDATE pfh.inode_namespaces SET
    next_local=GREATEST(next_local, p_next_local),
    max_ino_seen=GREATEST(max_ino_seen, p_max_ino_seen),
    updated_db_ms=v_now
  WHERE namespace=p_inode_namespace;

  v_commit_id := pfh.new_id('cpft2');
  v_anchor_id := pfh.new_id('hanch');
  INSERT INTO public.commits (
    id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,
    manifest_base_commit_id, manifest_diff, materialized_manifest,
    mutation_count, byte_count, created_at, commit_kind)
  VALUES (
    v_commit_id, c.volume_id, c.branch_id,
    COALESCE(c.source_base_commit_id, c.source_head_commit_id),
    'pft2:'||p_root_digest, NULL, NULL, NULL, FALSE,
    0, p_user_object_bytes, v_now, 'pft2');
  INSERT INTO pfh.pft2_commits (
    commit_id, cut_id, tenant_id, root_digest, root_size, max_ino_seen,
    object_count, object_bytes, created_db_ms)
  VALUES (
    v_commit_id, p_cut_id, c.tenant_id, p_root_digest, p_root_size,
    p_max_ino_seen, p_user_object_count, p_user_object_bytes, v_now);
  INSERT INTO pfh.recovery_anchors (
    id, cut_id, commit_id, tenant_id, as_of_seq,
    recovery_root_digest, recovery_root_size,
    control_root_digest, control_root_size,
    orphan_index_digest, orphan_index_size,
    inode_namespace, next_local, max_ino_seen,
    object_count, object_bytes, created_db_ms)
  VALUES (
    v_anchor_id, p_cut_id, v_commit_id, c.tenant_id,
    COALESCE(c.cut_seq_exclusive, 0),
    p_recovery_root_digest, p_recovery_root_size,
    p_control_root_digest, p_control_root_size,
    p_orphan_index_digest, p_orphan_index_size,
    p_inode_namespace, p_next_local, p_max_ino_seen,
    p_recovery_object_count, p_recovery_object_bytes, v_now);

  UPDATE pfh.history_cuts SET
    state='ready', result_commit_id=v_commit_id, recovery_anchor_id=v_anchor_id,
    lease_expires_db_ms=NULL, last_error=NULL, updated_db_ms=v_now, ready_db_ms=v_now
  WHERE id=p_cut_id;

  -- The outer operation settles 'succeeded' now that the target is USABLE
  -- (cut row locked first, then the operation row).
  PERFORM pfh.resource_operation_finish(
    c.op_tenant_id, c.op_domain, c.op_operation_id, 'succeeded',
    jsonb_build_object('cutId', p_cut_id, 'state', 'ready',
                       'commitId', v_commit_id, 'anchorId', v_anchor_id));
  RETURN pfh.cut_status(c.tenant_id, p_cut_id);
END;
$$;

-- ─── Consumers ───────────────────────────────────────────────────────────────

CREATE FUNCTION pfh.consumer_attach(
  p_tenant TEXT, p_cut_id TEXT, p_consumer_kind TEXT, p_consumer_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT;
  v_id TEXT;
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_consumer_kind NOT IN ('snapshot','branch','fork','publish','adoption','conversion') THEN
    RAISE EXCEPTION 'consumer kind % is unknown', p_consumer_kind USING ERRCODE='PF008';
  END IF;
  IF p_consumer_id IS NULL OR length(p_consumer_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'consumer id is required (<=256 chars)' USING ERRCODE='PF008';
  END IF;
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF p_consumer_kind NOT IN ('conversion') AND c.state <> 'ready' THEN
    RAISE EXCEPTION 'cut % is % and cannot be consumed', p_cut_id, c.state
      USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  v_id := pfh.new_id('hcon');
  INSERT INTO pfh.cut_consumers (id, cut_id, tenant_id, consumer_kind, consumer_id, created_db_ms)
  VALUES (v_id, p_cut_id, p_tenant, p_consumer_kind, p_consumer_id, v_now)
  ON CONFLICT (consumer_kind, consumer_id) DO NOTHING;
  RETURN jsonb_build_object('consumerId', p_consumer_id, 'cutId', p_cut_id,
                            'kind', p_consumer_kind);
END;
$$;

CREATE FUNCTION pfh.consumer_release(
  p_tenant TEXT, p_consumer_kind TEXT, p_consumer_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.cut_consumers;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  SELECT * INTO v FROM pfh.cut_consumers
    WHERE consumer_kind=p_consumer_kind AND consumer_id=p_consumer_id
      AND tenant_id=p_tenant
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'consumer %/% not found', p_consumer_kind, p_consumer_id
      USING ERRCODE='PF007';
  END IF;
  IF v.released_db_ms IS NULL THEN
    UPDATE pfh.cut_consumers SET released_db_ms=v_now WHERE id=v.id;
  END IF;
  RETURN jsonb_build_object('consumerId', p_consumer_id, 'released', TRUE);
END;
$$;

-- ─── PFT2 provenance (caller/read surface) ───────────────────────────────────

-- Exact provenance of one pft2 commit for the serving/fork/branch paths: the
-- USER arm plus — for the tenant's own authority restore path — the anchor
-- summary. The anchor's internal object digests are content addresses, not
-- session/lock/pin/orphan/outcome state; no such state is projected here.
CREATE FUNCTION pfh.pft2_commit_provenance(
  p_tenant TEXT, p_commit_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  p pfh.pft2_commits;
  ra pfh.recovery_anchors;
BEGIN
  IF p_tenant IS NULL OR p_commit_id IS NULL THEN
    RAISE EXCEPTION 'tenant and commit id are required' USING ERRCODE='PF008';
  END IF;
  SELECT * INTO p FROM pfh.pft2_commits
    WHERE commit_id=p_commit_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT * INTO ra FROM pfh.recovery_anchors WHERE commit_id=p_commit_id;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'commitId', p.commit_id, 'cutId', p.cut_id, 'tenantId', p.tenant_id,
    'rootDigest', p.root_digest, 'rootSize', p.root_size::TEXT,
    'maxInoSeen', p.max_ino_seen::TEXT,
    'objectCount', p.object_count::TEXT, 'objectBytes', p.object_bytes::TEXT,
    'anchor', CASE WHEN ra.id IS NULL THEN NULL ELSE jsonb_strip_nulls(jsonb_build_object(
      'anchorId', ra.id,
      'asOfSeq', ra.as_of_seq::TEXT,
      'recoveryRootDigest', ra.recovery_root_digest,
      'recoveryRootSize', ra.recovery_root_size::TEXT,
      'controlRootDigest', ra.control_root_digest,
      'controlRootSize', CASE WHEN ra.control_root_size IS NULL THEN NULL
                              ELSE ra.control_root_size::TEXT END,
      'orphanIndexDigest', ra.orphan_index_digest,
      'orphanIndexSize', CASE WHEN ra.orphan_index_size IS NULL THEN NULL
                              ELSE ra.orphan_index_size::TEXT END,
      'inodeNamespace', ra.inode_namespace::TEXT,
      'nextLocal', ra.next_local::TEXT,
      'maxInoSeen', ra.max_ino_seen::TEXT)) END));
END;
$$;

-- ─── Legacy conversion pipeline (chain resolve / ords / inos / verify) ───────

-- The anchor commit of the legacy work set: the pinned head for a pure
-- legacy_manifest cut, otherwise the generation's frozen base commit — a pfr1
-- conversion drains onto the imported base, and a born-managed pfj3 branch
-- whose base commit is still manifest_v1 (a fork point of a legacy volume)
-- imports that base exactly once before replaying journal records. A pft2
-- base commit never has a legacy anchor (PF005): the reader opens its root.
CREATE FUNCTION pfh.legacy_anchor_commit(c pfh.history_cuts) RETURNS TEXT
LANGUAGE plpgsql STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_kind TEXT;
BEGIN
  IF c.source_kind = 'legacy_manifest' THEN
    RETURN c.source_head_commit_id;
  END IF;
  SELECT cm.commit_kind INTO v_kind FROM public.commits cm
    WHERE cm.id=c.source_base_commit_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % base commit % is missing', c.id, c.source_base_commit_id
      USING ERRCODE='PF007';
  END IF;
  IF v_kind <> 'manifest_v1' THEN
    RAISE EXCEPTION 'cut % base commit is % — no legacy manifest anchor',
      c.id, v_kind USING ERRCODE='PF005';
  END IF;
  RETURN c.source_base_commit_id;
END;
$$;

CREATE FUNCTION pfh.legacy_step_get(p_cut_id TEXT, p_step TEXT)
RETURNS pfh.legacy_work_steps
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v pfh.legacy_work_steps;
BEGIN
  SELECT * INTO v FROM pfh.legacy_work_steps
    WHERE cut_id=p_cut_id AND step=p_step FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO pfh.legacy_work_steps (cut_id, step, updated_db_ms)
    VALUES (p_cut_id, p_step, pfh.now_ms())
    RETURNING * INTO v;
  END IF;
  RETURN v;
END;
$$;

-- Resolves the commit chain of the cut's anchor: the newest ancestor carrying
-- a FULL manifest (manifest IS NOT NULL), then the chronological diff commits
-- above it, depth <= 32 (chain includes the full-manifest base).
CREATE FUNCTION pfh.legacy_chain_prepare(
  p_cut_id TEXT, p_claim_epoch BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_step pfh.legacy_work_steps;
  v_chain TEXT[] := '{}';
  v_id TEXT;
  v_depth INT := 0;
  r RECORD;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  v_step := pfh.legacy_step_get(p_cut_id, 'chain_prepared');
  IF v_step.state = 'done' THEN
    RETURN v_step.cursor;
  END IF;
  v_id := pfh.legacy_anchor_commit(c);
  LOOP
    v_depth := v_depth + 1;
    IF v_depth > 33 THEN
      RAISE EXCEPTION 'legacy diff chain exceeds depth 32' USING ERRCODE='PF004';
    END IF;
    SELECT cm.id, cm.manifest_base_commit_id,
           (cm.manifest IS NOT NULL) AS has_manifest,
           (cm.manifest_diff IS NOT NULL) AS has_diff,
           cm.commit_kind
      INTO r
      FROM public.commits cm WHERE cm.id=v_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'legacy chain commit % is missing', v_id USING ERRCODE='PF007';
    END IF;
    IF r.commit_kind <> 'manifest_v1' THEN
      RAISE EXCEPTION 'legacy chain reached a % commit', r.commit_kind USING ERRCODE='PF005';
    END IF;
    v_chain := array_prepend(v_id, v_chain);
    IF r.has_manifest THEN
      EXIT; -- full manifest base found (oldest element of the chain)
    END IF;
    IF NOT r.has_diff OR r.manifest_base_commit_id IS NULL THEN
      RAISE EXCEPTION 'legacy chain commit % has neither manifest nor diff', v_id
        USING ERRCODE='PF010';
    END IF;
    v_id := r.manifest_base_commit_id;
    IF v_id = ANY(v_chain) THEN
      RAISE EXCEPTION 'legacy diff chain contains a cycle at %', v_id USING ERRCODE='PF010';
    END IF;
  END LOOP;
  UPDATE pfh.legacy_work_steps SET
    state='done',
    cursor=jsonb_build_object('chain', to_jsonb(v_chain), 'depth', v_depth),
    updated_db_ms=pfh.now_ms()
  WHERE cut_id=p_cut_id AND step='chain_prepared';
  RETURN jsonb_build_object('chain', to_jsonb(v_chain), 'depth', v_depth);
END;
$$;

-- Normalizes one manifest entry into typed columns. TEXT (and jsonb strings)
-- structurally cannot contain NUL on PostgreSQL, so no NUL check exists.
CREATE FUNCTION pfh.legacy_entry_columns(e JSONB)
RETURNS TABLE (
  path TEXT, kind TEXT, mode BIGINT, uid BIGINT, gid BIGINT, size BIGINT,
  mtime_ms BIGINT, ctime_ms BIGINT, atime_ms BIGINT, executable BOOLEAN,
  ino BIGINT, link_target TEXT, blob_digest TEXT, blob_size BIGINT,
  compression TEXT, packed BOOLEAN, chunks JSONB, comparable_key TEXT)
LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_path TEXT := e->>'path';
  v_kind TEXT := e->>'kind';
  v_chunks JSONB := e->'chunks';
  v_blob JSONB := e->'blob';
  v_key JSONB;
BEGIN
  IF pg_column_size(e) > 1114112 THEN
    RAISE EXCEPTION 'legacy entry exceeds 1 MiB' USING ERRCODE='PF004';
  END IF;
  IF v_path IS NULL OR length(v_path) NOT BETWEEN 1 AND 4096
     OR v_path LIKE '/%' OR v_path LIKE '%//%' OR v_path LIKE '%/'
     OR EXISTS (SELECT 1 FROM unnest(string_to_array(v_path,'/')) s(v)
                WHERE s.v IN ('','.','..')) THEN
    RAISE EXCEPTION 'legacy entry path % is invalid', v_path USING ERRCODE='PF008';
  END IF;
  IF v_kind NOT IN ('file','directory','symlink') THEN
    RAISE EXCEPTION 'legacy entry kind % is unknown', v_kind USING ERRCODE='PF008';
  END IF;
  IF v_chunks IS NOT NULL AND jsonb_typeof(v_chunks) = 'array' THEN
    IF (SELECT COUNT(*) FROM jsonb_array_elements(v_chunks)) > 8192 THEN
      RAISE EXCEPTION 'legacy entry % has more than 8192 chunks', v_path
        USING ERRCODE='PF004';
    END IF;
  ELSE
    v_chunks := NULL;
  END IF;
  -- DB-internal deterministic identity over the normalized fields (jsonb key
  -- ordering; NOT the canonical stableJson tree-hash key — the Go worker
  -- recomputes that from the typed columns).
  v_key := jsonb_strip_nulls(jsonb_build_object(
    'blob', CASE WHEN v_blob IS NULL THEN NULL ELSE jsonb_build_object(
      'compression', COALESCE(v_blob->>'compression','none'),
      'digest', v_blob->>'digest',
      'packed', COALESCE((v_blob->>'packed')::BOOLEAN, FALSE),
      'size', v_blob->'size') END,
    'chunks', v_chunks,
    'executable', COALESCE((e->>'executable')::BOOLEAN, FALSE),
    'gid', CASE WHEN COALESCE((e->>'gid')::BIGINT,0) = 0 THEN NULL ELSE e->'gid' END,
    'kind', v_kind,
    'linkTarget', e->>'linkTarget',
    'mode', e->'mode',
    'path', v_path,
    'size', COALESCE(e->'size','0'::jsonb),
    'uid', CASE WHEN COALESCE((e->>'uid')::BIGINT,0) = 0 THEN NULL ELSE e->'uid' END));
  RETURN QUERY SELECT
    v_path, v_kind,
    COALESCE((e->>'mode')::BIGINT, 0),
    COALESCE((e->>'uid')::BIGINT, 0),
    COALESCE((e->>'gid')::BIGINT, 0),
    COALESCE(floor((e->>'size')::NUMERIC)::BIGINT, 0),
    COALESCE(floor((e->>'mtimeMs')::NUMERIC)::BIGINT, 0),
    COALESCE(floor((e->>'ctimeMs')::NUMERIC)::BIGINT, 0),
    COALESCE(floor((e->>'atimeMs')::NUMERIC)::BIGINT, 0),
    COALESCE((e->>'executable')::BOOLEAN, FALSE),
    COALESCE(floor((e->>'ino')::NUMERIC)::BIGINT, 0),
    e->>'linkTarget',
    v_blob->>'digest',
    (v_blob->>'size')::BIGINT,
    COALESCE(v_blob->>'compression','none'),
    COALESCE((v_blob->>'packed')::BOOLEAN, FALSE),
    v_chunks,
    v_key::TEXT;
END;
$$;

-- Applies one bounded page of the chain (full manifest inserts, then diff
-- removed/added/changed segments in chronological order), idempotently via
-- the persisted cursor. Returns {done, cursor}. Page arrays are read WITH
-- ORDINALITY so the resume offset is exact.
CREATE FUNCTION pfh.legacy_chain_apply_page(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_max_ops INT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_prepared pfh.legacy_work_steps;
  v_step pfh.legacy_work_steps;
  v_chain TEXT[];
  v_cursor JSONB;
  v_chain_index INT;
  v_phase TEXT;
  v_offset BIGINT;
  v_max INT := LEAST(GREATEST(COALESCE(p_max_ops,1000),1),5000);
  v_commit_id TEXT;
  v_source JSONB;
  v_applied INT := 0;
  v_total BIGINT;
  v_row RECORD;
  v_now BIGINT;
  v_entry_cap BIGINT := 5000000;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  SELECT * INTO v_prepared FROM pfh.legacy_work_steps
    WHERE cut_id=p_cut_id AND step='chain_prepared' AND state='done';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'legacy chain is not prepared for cut %', p_cut_id USING ERRCODE='PF011';
  END IF;
  SELECT array_agg(v ORDER BY t.ord) INTO v_chain
    FROM jsonb_array_elements_text(v_prepared.cursor->'chain') WITH ORDINALITY t(v, ord);
  v_step := pfh.legacy_step_get(p_cut_id, 'entries_resolved');
  IF v_step.state = 'done' THEN
    RETURN jsonb_build_object('done', TRUE, 'cursor', v_step.cursor);
  END IF;
  v_cursor := COALESCE(v_step.cursor, '{}'::jsonb);
  v_chain_index := COALESCE((v_cursor->>'chainIndex')::INT, 1);
  v_phase := COALESCE(v_cursor->>'phase', 'entries');
  v_offset := COALESCE((v_cursor->>'offset')::BIGINT, 0);
  v_now := pfh.now_ms();

  WHILE v_applied < v_max AND v_chain_index <= COALESCE(array_length(v_chain,1),0) LOOP
    v_commit_id := v_chain[v_chain_index];
    IF v_chain_index = 1 THEN
      -- Full manifest base.
      SELECT cm.manifest->'entries' INTO v_source
        FROM public.commits cm WHERE cm.id=v_commit_id;
      IF v_source IS NULL OR jsonb_typeof(v_source) <> 'array' THEN
        RAISE EXCEPTION 'legacy base commit % has no manifest entries', v_commit_id
          USING ERRCODE='PF010';
      END IF;
      v_phase := 'entries';
    ELSE
      IF v_phase = 'entries' THEN
        v_phase := 'removed';
      END IF;
      SELECT cm.manifest_diff->v_phase INTO v_source
        FROM public.commits cm WHERE cm.id=v_commit_id;
      IF v_source IS NULL OR jsonb_typeof(v_source) <> 'array' THEN
        v_source := '[]'::jsonb;
      END IF;
    END IF;

    FOR v_row IN
      SELECT elem.value AS entry, elem.ordinality AS ord
      FROM jsonb_array_elements(v_source) WITH ORDINALITY elem
      WHERE elem.ordinality > v_offset
      ORDER BY elem.ordinality
      LIMIT (v_max - v_applied)
    LOOP
      IF v_phase = 'removed' THEN
        DELETE FROM pfh.legacy_work_entries
          WHERE cut_id=p_cut_id AND path=(v_row.entry->>'path');
      ELSE
        INSERT INTO pfh.legacy_work_entries (
          cut_id, path, kind, mode, uid, gid, size, mtime_ms, ctime_ms,
          atime_ms, executable, ino, link_target, blob_digest, blob_size,
          compression, packed, chunks, comparable_key)
        SELECT p_cut_id, t.path, t.kind, t.mode, t.uid, t.gid, t.size,
               t.mtime_ms, t.ctime_ms, t.atime_ms, t.executable, t.ino,
               t.link_target, t.blob_digest, t.blob_size, t.compression,
               t.packed, t.chunks, t.comparable_key
        FROM pfh.legacy_entry_columns(v_row.entry) t
        ON CONFLICT (cut_id, path) DO UPDATE SET
          kind=EXCLUDED.kind, mode=EXCLUDED.mode, uid=EXCLUDED.uid,
          gid=EXCLUDED.gid, size=EXCLUDED.size, mtime_ms=EXCLUDED.mtime_ms,
          ctime_ms=EXCLUDED.ctime_ms, atime_ms=EXCLUDED.atime_ms,
          executable=EXCLUDED.executable, ino=EXCLUDED.ino,
          link_target=EXCLUDED.link_target, blob_digest=EXCLUDED.blob_digest,
          blob_size=EXCLUDED.blob_size, compression=EXCLUDED.compression,
          packed=EXCLUDED.packed, chunks=EXCLUDED.chunks,
          comparable_key=EXCLUDED.comparable_key,
          ord=NULL, assigned_ino=NULL, nlink=1;
      END IF;
      v_offset := v_row.ord;
      v_applied := v_applied + 1;
    END LOOP;

    IF v_offset >= COALESCE(jsonb_array_length(v_source),0) THEN
      v_offset := 0;
      IF v_chain_index = 1 THEN
        v_chain_index := v_chain_index + 1;
        v_phase := 'entries';
      ELSIF v_phase = 'removed' THEN
        v_phase := 'added';
      ELSIF v_phase = 'added' THEN
        v_phase := 'changed';
      ELSE
        v_chain_index := v_chain_index + 1;
        v_phase := 'entries';
      END IF;
    ELSE
      EXIT; -- page budget spent inside this array
    END IF;
  END LOOP;

  SELECT COUNT(*) INTO v_total FROM pfh.legacy_work_entries WHERE cut_id=p_cut_id;
  IF v_total > v_entry_cap THEN
    RAISE EXCEPTION 'legacy conversion exceeds % entries', v_entry_cap USING ERRCODE='PF004';
  END IF;

  v_cursor := jsonb_build_object(
    'chainIndex', v_chain_index, 'phase', v_phase, 'offset', v_offset,
    'entries', v_total);
  IF v_chain_index > COALESCE(array_length(v_chain,1),0) THEN
    UPDATE pfh.legacy_work_steps SET state='done', cursor=v_cursor, updated_db_ms=v_now
      WHERE cut_id=p_cut_id AND step='entries_resolved';
    RETURN jsonb_build_object('done', TRUE, 'cursor', v_cursor);
  END IF;
  UPDATE pfh.legacy_work_steps SET cursor=v_cursor, updated_db_ms=v_now
    WHERE cut_id=p_cut_id AND step='entries_resolved';
  RETURN jsonb_build_object('done', FALSE, 'cursor', v_cursor);
END;
$$;

-- Assigns dense byte-ordered (COLLATE "C" column) ordinals in bounded keyset
-- pages, after synthesizing missing ancestor directories.
CREATE FUNCTION pfh.legacy_assign_ords(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_page INT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_step pfh.legacy_work_steps;
  v_after TEXT;
  v_next BIGINT;
  v_page INT := LEAST(GREATEST(COALESCE(p_page,5000),1),20000);
  v_count BIGINT;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF NOT EXISTS (SELECT 1 FROM pfh.legacy_work_steps
                 WHERE cut_id=p_cut_id AND step='entries_resolved' AND state='done') THEN
    RAISE EXCEPTION 'entries are not resolved for cut %', p_cut_id USING ERRCODE='PF011';
  END IF;
  v_step := pfh.legacy_step_get(p_cut_id, 'ords_assigned');
  IF v_step.state = 'done' THEN
    RETURN jsonb_build_object('done', TRUE, 'cursor', v_step.cursor);
  END IF;
  v_now := pfh.now_ms();
  IF COALESCE((v_step.cursor->>'parentsSynthesized')::BOOLEAN, FALSE) IS DISTINCT FROM TRUE THEN
    -- Synthesize the missing ancestor directories deterministically (mode
    -- 0755, root ownership, ino 0 so namespace assignment covers them), and
    -- refuse a non-directory parent as definite corruption.
    WITH RECURSIVE need(path) AS (
      SELECT DISTINCT regexp_replace(e.path,'/[^/]*$','')
      FROM pfh.legacy_work_entries e
      WHERE e.cut_id=p_cut_id AND position('/' IN e.path) > 0
      UNION
      SELECT regexp_replace(n.path,'/[^/]*$','')
      FROM need n WHERE position('/' IN n.path) > 0)
    INSERT INTO pfh.legacy_work_entries (
      cut_id, path, kind, mode, comparable_key)
    SELECT p_cut_id, n.path, 'directory', 493, 'synthetic-parent'
    FROM need n
    WHERE length(n.path) > 0
      AND NOT EXISTS (SELECT 1 FROM pfh.legacy_work_entries x
                      WHERE x.cut_id=p_cut_id AND x.path=n.path)
    ON CONFLICT (cut_id, path) DO NOTHING;
    IF EXISTS (
      SELECT 1 FROM pfh.legacy_work_entries child
      JOIN pfh.legacy_work_entries parent
        ON parent.cut_id=child.cut_id
       AND parent.path=regexp_replace(child.path,'/[^/]*$','')
      WHERE child.cut_id=p_cut_id
        AND position('/' IN child.path) > 0
        AND parent.kind <> 'directory') THEN
      RAISE EXCEPTION 'legacy manifest has a non-directory parent path'
        USING ERRCODE='PF002';
    END IF;
    UPDATE pfh.legacy_work_steps SET
      cursor=jsonb_build_object('parentsSynthesized', TRUE, 'nextOrd', 0),
      updated_db_ms=v_now
      WHERE cut_id=p_cut_id AND step='ords_assigned';
    RETURN jsonb_build_object('done', FALSE,
      'cursor', jsonb_build_object('parentsSynthesized', TRUE, 'nextOrd', 0));
  END IF;
  v_after := v_step.cursor->>'afterPath';
  v_next := COALESCE((v_step.cursor->>'nextOrd')::BIGINT, 0);
  WITH page AS (
    SELECT e.path, row_number() OVER (ORDER BY e.path) - 1 + v_next AS rn
    FROM pfh.legacy_work_entries e
    WHERE e.cut_id=p_cut_id AND (v_after IS NULL OR e.path > v_after)
    ORDER BY e.path
    LIMIT v_page)
  UPDATE pfh.legacy_work_entries e SET ord=page.rn
  FROM page WHERE e.cut_id=p_cut_id AND e.path=page.path;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 0 THEN
    UPDATE pfh.legacy_work_steps SET state='done',
      cursor=jsonb_build_object('total', v_next), updated_db_ms=v_now
      WHERE cut_id=p_cut_id AND step='ords_assigned';
    RETURN jsonb_build_object('done', TRUE, 'cursor', jsonb_build_object('total', v_next));
  END IF;
  SELECT e.path INTO v_after FROM pfh.legacy_work_entries e
    WHERE e.cut_id=p_cut_id AND e.ord IS NOT NULL
    ORDER BY e.ord DESC LIMIT 1;
  UPDATE pfh.legacy_work_steps SET
    cursor=jsonb_build_object('parentsSynthesized', TRUE,
                              'afterPath', v_after, 'nextOrd', v_next+v_count),
    updated_db_ms=v_now
    WHERE cut_id=p_cut_id AND step='ords_assigned';
  RETURN jsonb_build_object('done', FALSE,
    'cursor', jsonb_build_object('afterPath', v_after, 'nextOrd', v_next+v_count));
END;
$$;

-- Validates hardlink aliases and assigns deterministic inode ids.
--   * repeated NONZERO ino: every alias must be a non-directory with an
--     identical identity minus path (kind/mode/uid/gid/size/content/link
--     target); nlink = alias count; any mismatch is corrupt (PF002).
--   * ino = 0 entries (and the synthesized parents) get deterministic ids
--     from the cut's namespace, in byte-ordered path order.
CREATE FUNCTION pfh.legacy_assign_inos(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_page INT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_namespace BIGINT;
  ns pfh.inode_namespaces;
  v_step pfh.legacy_work_steps;
  v_page INT := LEAST(GREATEST(COALESCE(p_page,5000),1),20000);
  v_bad BIGINT;
  v_count BIGINT;
  v_local BIGINT;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF NOT EXISTS (SELECT 1 FROM pfh.legacy_work_steps
                 WHERE cut_id=p_cut_id AND step='ords_assigned' AND state='done') THEN
    RAISE EXCEPTION 'ordinals are not assigned for cut %', p_cut_id USING ERRCODE='PF011';
  END IF;
  -- A conversion cut allocates from its conversion namespace; any other cut
  -- importing a manifest_v1 base (born-managed fork of a legacy volume)
  -- allocates from the branch's own namespace, issued at cut creation.
  SELECT cv.inode_namespace INTO v_namespace
    FROM pfh.conversions cv WHERE cv.final_cut_id=p_cut_id;
  IF NOT FOUND OR v_namespace IS NULL THEN
    SELECT xns.namespace INTO v_namespace
      FROM pfh.inode_namespaces xns WHERE xns.branch_id=c.branch_id;
    IF NOT FOUND OR v_namespace IS NULL THEN
      RAISE EXCEPTION 'cut % has no inode namespace', p_cut_id USING ERRCODE='PF011';
    END IF;
  END IF;
  v_step := pfh.legacy_step_get(p_cut_id, 'inos_assigned');
  IF v_step.state = 'done' THEN
    RETURN jsonb_build_object('done', TRUE, 'cursor', v_step.cursor);
  END IF;
  v_now := pfh.now_ms();

  IF COALESCE((v_step.cursor->>'aliasesChecked')::BOOLEAN, FALSE) IS DISTINCT FROM TRUE THEN
    -- One set-based pass: duplicate-ino groups must be same-identity
    -- non-directories (hardlink aliases).
    SELECT COUNT(*) INTO v_bad FROM (
      SELECT g.ino FROM pfh.legacy_work_entries g
      WHERE g.cut_id=p_cut_id AND g.ino > 0
      GROUP BY g.ino
      HAVING COUNT(*) > 1
         AND (BOOL_OR(g.kind = 'directory')
           OR COUNT(DISTINCT jsonb_build_object(
                'kind',g.kind,'mode',g.mode,'uid',g.uid,'gid',g.gid,'size',g.size,
                'blob',g.blob_digest,'chunks',COALESCE(g.chunks,'null'::jsonb),
                'link',COALESCE(g.link_target,''))::TEXT) > 1)) bad;
    IF v_bad > 0 THEN
      RAISE EXCEPTION 'legacy conversion found % corrupt hardlink alias groups', v_bad
        USING ERRCODE='PF002';
    END IF;
    -- Preserved legacy inode ids must not collide with the fresh namespace.
    IF EXISTS (SELECT 1 FROM pfh.legacy_work_entries g
               WHERE g.cut_id=p_cut_id AND g.ino > 0
                 AND (g.ino / 4294967296) = v_namespace) THEN
      RAISE EXCEPTION 'legacy inode ids collide with issued namespace %',
        v_namespace USING ERRCODE='PF010';
    END IF;
    UPDATE pfh.legacy_work_entries e SET
      assigned_ino = e.ino,
      nlink = g.link_count
    FROM (SELECT w.ino, COUNT(*)::INT AS link_count
          FROM pfh.legacy_work_entries w
          WHERE w.cut_id=p_cut_id AND w.ino > 0 GROUP BY w.ino) g
    WHERE e.cut_id=p_cut_id AND e.ino=g.ino AND e.ino > 0;
    UPDATE pfh.legacy_work_steps SET
      cursor=jsonb_build_object('aliasesChecked', TRUE),
      updated_db_ms=v_now
      WHERE cut_id=p_cut_id AND step='inos_assigned';
    RETURN jsonb_build_object('done', FALSE,
      'cursor', jsonb_build_object('aliasesChecked', TRUE));
  END IF;

  SELECT * INTO ns FROM pfh.inode_namespaces
    WHERE namespace=v_namespace FOR UPDATE;
  v_local := ns.next_local;
  WITH page AS (
    SELECT e.path, row_number() OVER (ORDER BY e.ord) - 1 + v_local AS local_counter
    FROM pfh.legacy_work_entries e
    WHERE e.cut_id=p_cut_id AND e.assigned_ino IS NULL
    ORDER BY e.ord
    LIMIT v_page)
  UPDATE pfh.legacy_work_entries e SET
    assigned_ino = (v_namespace * 4294967296) + page.local_counter
  FROM page WHERE e.cut_id=p_cut_id AND e.path=page.path;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 0 THEN
    UPDATE pfh.legacy_work_steps SET state='done',
      cursor=jsonb_build_object('aliasesChecked', TRUE, 'nextLocal', v_local::TEXT),
      updated_db_ms=v_now
      WHERE cut_id=p_cut_id AND step='inos_assigned';
    RETURN jsonb_build_object('done', TRUE,
      'cursor', jsonb_build_object('nextLocal', v_local::TEXT));
  END IF;
  IF v_local + v_count > 4294967295 THEN
    RAISE EXCEPTION 'conversion namespace local counter exhausted' USING ERRCODE='PF004';
  END IF;
  UPDATE pfh.inode_namespaces SET
    next_local=v_local+v_count, updated_db_ms=v_now
    WHERE namespace=v_namespace;
  RETURN jsonb_build_object('done', FALSE, 'assigned', v_count);
END;
$$;

-- The Go worker streams the final entries, recomputes the exact canonical
-- tree hash (portablefs-tree-root-v2 sharded algorithm over stableJson
-- comparable keys), and proves it here against the anchor commit. A mismatch
-- is a definite corruption.
CREATE FUNCTION pfh.legacy_tree_hash_verify(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_tree_hash TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_anchor TEXT;
  v_expected TEXT;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  v_anchor := pfh.legacy_anchor_commit(c);
  SELECT cm.tree_hash INTO v_expected FROM public.commits cm WHERE cm.id=v_anchor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'anchor commit % is missing', v_anchor USING ERRCODE='PF007';
  END IF;
  IF p_tree_hash IS NULL OR p_tree_hash <> v_expected THEN
    RAISE EXCEPTION 'legacy tree hash mismatch (resolved % vs pinned %)',
      COALESCE(p_tree_hash,'<null>'), v_expected USING ERRCODE='PF002';
  END IF;
  INSERT INTO pfh.legacy_work_steps (cut_id, step, state, cursor, updated_db_ms)
  VALUES (p_cut_id, 'tree_hash_verified', 'done',
          jsonb_build_object('treeHash', p_tree_hash), v_now)
  ON CONFLICT (cut_id, step) DO UPDATE
    SET state='done', cursor=EXCLUDED.cursor, updated_db_ms=v_now;
  RETURN jsonb_build_object('verified', TRUE, 'treeHash', p_tree_hash);
END;
$$;

-- Keyset stream of the finalized entries for the Go importer (byte order).
CREATE FUNCTION pfh.legacy_entries_page(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_after_ord BIGINT, p_limit INT
) RETURNS TABLE (
  ord BIGINT, path TEXT, kind TEXT, mode BIGINT, uid BIGINT, gid BIGINT,
  size BIGINT, mtime_ms BIGINT, ctime_ms BIGINT, atime_ms BIGINT,
  executable BOOLEAN, assigned_ino BIGINT, nlink INT, link_target TEXT,
  blob_digest TEXT, blob_size BIGINT, compression TEXT, packed BOOLEAN,
  chunks JSONB, comparable_key TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,1000),1),10000);
BEGIN
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  RETURN QUERY
    SELECT e.ord, e.path::TEXT, e.kind, e.mode, e.uid, e.gid, e.size, e.mtime_ms,
           e.ctime_ms, e.atime_ms, e.executable, e.assigned_ino, e.nlink,
           e.link_target, e.blob_digest, e.blob_size, e.compression, e.packed,
           e.chunks, e.comparable_key
    FROM pfh.legacy_work_entries e
    WHERE e.cut_id=p_cut_id AND e.ord IS NOT NULL
      AND e.ord > COALESCE(p_after_ord,-1)
    ORDER BY e.ord
    LIMIT v_limit;
END;
$$;

-- Bounded import progress (chunked editor commits store their work cursors).
CREATE FUNCTION pfh.legacy_import_cursor_put(
  p_cut_id TEXT, p_claim_epoch BIGINT, p_cursor JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  IF p_cursor IS NULL OR pg_column_size(p_cursor) > 16384 THEN
    RAISE EXCEPTION 'import cursor must be a bounded document' USING ERRCODE='PF004';
  END IF;
  INSERT INTO pfh.legacy_work_steps (cut_id, step, state, cursor, updated_db_ms)
  VALUES (p_cut_id, 'import', 'running', p_cursor, v_now)
  ON CONFLICT (cut_id, step) DO UPDATE
    SET cursor=EXCLUDED.cursor, updated_db_ms=v_now;
  RETURN jsonb_build_object('stored', TRUE);
END;
$$;

CREATE FUNCTION pfh.legacy_import_cursor_get(
  p_cut_id TEXT, p_claim_epoch BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  v pfh.legacy_work_steps;
BEGIN
  c := pfh.require_live_claim(p_cut_id, p_claim_epoch, FALSE);
  SELECT * INTO v FROM pfh.legacy_work_steps WHERE cut_id=p_cut_id AND step='import';
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN v.cursor;
END;
$$;

-- ─── Conversion lifecycle (begin / attach / finalize / abort / retry) ────────

CREATE FUNCTION pfh.conversion_status(p_tenant TEXT, p_conversion_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v pfh.conversions;
BEGIN
  SELECT * INTO v FROM pfh.conversions
    WHERE id=p_conversion_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'conversionId', v.id, 'tenantId', v.tenant_id, 'volumeId', v.volume_id,
    'branchId', v.branch_id, 'branchName', v.branch_name,
    'state', v.state, 'attempt', v.attempt,
    'oldGenerationId', v.old_generation_id,
    'finalCutId', v.final_cut_id,
    'inodeNamespace', CASE WHEN v.inode_namespace IS NULL THEN NULL
                           ELSE v.inode_namespace::TEXT END,
    'headCommitIdPin', v.head_commit_id_pin,
    'lastError', v.last_error,
    'createdDbMs', v.created_db_ms::TEXT, 'updatedDbMs', v.updated_db_ms::TEXT,
    'convertedDbMs', CASE WHEN v.converted_db_ms IS NULL THEN NULL
                          ELSE v.converted_db_ms::TEXT END));
END;
$$;

CREATE FUNCTION pfh.conversion_begin(
  p_tenant TEXT, p_volume TEXT, p_branch_name TEXT,
  p_operation_id TEXT, p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_op JSONB;
  v_branch RECORD;
  v_conv pfh.conversions;
  v_ns JSONB;
  v_now BIGINT;
  v_id TEXT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'conversion fingerprint');
  v_op := pfh.resource_operation_begin(
    p_tenant, 'conversion', p_operation_id, 'conversion-begin', p_fingerprint,
    '{}'::jsonb);
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  SELECT b.id, b.branch_mode, b.head_commit_id, v.tenant_id
    INTO v_branch
    FROM public.branches b JOIN public.volumes v ON v.id=b.volume_id
    WHERE b.volume_id=p_volume AND b.name=p_branch_name;
  IF NOT FOUND OR v_branch.tenant_id IS DISTINCT FROM p_tenant THEN
    RAISE EXCEPTION 'branch %/% not found', p_volume, p_branch_name USING ERRCODE='PF007';
  END IF;
  SELECT * INTO v_conv FROM pfh.conversions WHERE branch_id=v_branch.id;
  IF FOUND THEN
    IF v_conv.state = 'failed' THEN
      RAISE EXCEPTION 'branch % has a failed conversion; retry it explicitly (pfh.conversion_retry)',
        v_branch.id USING ERRCODE='PF002';
    END IF;
    PERFORM pfh.resource_operation_finish(
      p_tenant, 'conversion', p_operation_id, 'succeeded',
      jsonb_build_object('conversionId', v_conv.id, 'state', v_conv.state,
                         'deduplicated', TRUE));
    RETURN pfh.conversion_status(p_tenant, v_conv.id);
  END IF;
  IF v_branch.branch_mode NOT IN ('legacy_manifest','migrating') THEN
    RAISE EXCEPTION 'branch % mode % cannot begin a conversion',
      v_branch.id, v_branch.branch_mode USING ERRCODE='PF001';
  END IF;
  v_now := pfh.now_ms();
  v_id := pfh.new_id('hconv');
  v_ns := pfh.inode_namespace_issue(p_tenant, p_volume, v_branch.id, 'conversion');
  INSERT INTO pfh.conversions (
    id, tenant_id, volume_id, branch_id, branch_name, op_operation_id,
    state, inode_namespace, head_commit_id_pin, created_db_ms, updated_db_ms)
  VALUES (v_id, p_tenant, p_volume, v_branch.id, p_branch_name, p_operation_id,
          'migrating', (v_ns->>'namespace')::BIGINT, v_branch.head_commit_id,
          v_now, v_now);
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'conversion', p_operation_id, 'succeeded',
    jsonb_build_object('conversionId', v_id, 'state', 'migrating'));
  RETURN pfh.conversion_status(p_tenant, v_id);
END;
$$;

-- Records the conversion's final cut (created via pfh.cut_create with kind
-- 'conversion_final') and pins it as a conversion consumer.
CREATE FUNCTION pfh.conversion_attach_final_cut(
  p_tenant TEXT, p_conversion_id TEXT, p_cut_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.conversions;
  c pfh.history_cuts;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  SELECT * INTO v FROM pfh.conversions
    WHERE id=p_conversion_id AND tenant_id=p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'conversion % not found', p_conversion_id USING ERRCODE='PF007';
  END IF;
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant AND kind='conversion_final';
  IF NOT FOUND OR c.branch_id <> v.branch_id THEN
    RAISE EXCEPTION 'cut % is not a conversion_final cut of branch %',
      p_cut_id, v.branch_id USING ERRCODE='PF002';
  END IF;
  IF v.final_cut_id IS NOT NULL AND v.final_cut_id <> p_cut_id THEN
    RAISE EXCEPTION 'conversion % already pins cut %', p_conversion_id, v.final_cut_id
      USING ERRCODE='PF002';
  END IF;
  IF v.state NOT IN ('migrating','final_cut') THEN
    RAISE EXCEPTION 'conversion % is % and cannot attach a cut', p_conversion_id, v.state
      USING ERRCODE='PF002';
  END IF;
  UPDATE pfh.conversions SET
    final_cut_id=p_cut_id, state='final_cut',
    old_generation_id=c.generation_id, updated_db_ms=v_now
  WHERE id=p_conversion_id;
  PERFORM pfh.consumer_attach(p_tenant, p_cut_id, 'conversion', p_conversion_id);
  RETURN pfh.conversion_status(p_tenant, p_conversion_id);
END;
$$;

-- Finalize: verifies the ready cut, flips the proof row to 'finalizing', and
-- calls the journal-owner primitive that (in this SAME transaction, under the
-- exclusive branch lock) retires the drained generation, installs the pft2
-- head, and moves the branch to managed_journal. Crash anywhere before COMMIT
-- leaves the proof row 'final_cut' and everything else untouched. The next
-- PFJ3/PFC2 generation then starts at seq 0 with empty session/lock/checkout
-- state through the ordinary 012 claim path.
CREATE FUNCTION pfh.conversion_finalize(
  p_tenant TEXT, p_conversion_id TEXT, p_operation_id TEXT, p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.conversions;
  c pfh.history_cuts;
  v_op JSONB;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'finalize fingerprint');
  v_op := pfh.resource_operation_begin(
    p_tenant, 'conversion', p_operation_id, 'conversion-finalize', p_fingerprint,
    jsonb_build_object('conversionId', p_conversion_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  SELECT * INTO v FROM pfh.conversions
    WHERE id=p_conversion_id AND tenant_id=p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'conversion % not found', p_conversion_id USING ERRCODE='PF007';
  END IF;
  IF v.state = 'converted' THEN
    PERFORM pfh.resource_operation_finish(
      p_tenant, 'conversion', p_operation_id, 'succeeded',
      jsonb_build_object('conversionId', v.id, 'state', 'converted', 'replayed', TRUE));
    RETURN pfh.conversion_status(p_tenant, p_conversion_id);
  END IF;
  IF v.state NOT IN ('final_cut','finalizing') OR v.final_cut_id IS NULL THEN
    RAISE EXCEPTION 'conversion % is % and cannot finalize', p_conversion_id, v.state
      USING ERRCODE='PF011';
  END IF;
  SELECT * INTO c FROM pfh.history_cuts WHERE id=v.final_cut_id;
  IF c.state <> 'ready' OR c.result_commit_id IS NULL THEN
    RAISE EXCEPTION 'conversion final cut % is not ready', v.final_cut_id
      USING ERRCODE='PF011';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.conversions SET state='finalizing', updated_db_ms=v_now
    WHERE id=p_conversion_id;
  -- Journal-owner primitive: exclusive branch lock; verifies suspension,
  -- exact head equality, absent writer; retires the old generation; moves the
  -- branch mode + head (the replaced triggers re-verify this row).
  PERFORM pfj.history_conversion_finalize(p_conversion_id);
  UPDATE pfh.conversions SET state='converted', converted_db_ms=v_now,
    updated_db_ms=v_now WHERE id=p_conversion_id;
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'conversion', p_operation_id, 'succeeded',
    jsonb_build_object('conversionId', p_conversion_id, 'state', 'converted',
                       'commitId', c.result_commit_id));
  RETURN pfh.conversion_status(p_tenant, p_conversion_id);
END;
$$;

-- Abort: a migrating/final_cut conversion becomes 'failed' with a bounded
-- reason; its consumer pin releases so the final cut is cancelable. The
-- branch mode is untouched (the TS transition layer owns migrating ->
-- legacy_manifest aborts through the 012 matrix).
CREATE FUNCTION pfh.conversion_abort(
  p_tenant TEXT, p_conversion_id TEXT, p_operation_id TEXT,
  p_fingerprint TEXT, p_reason JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.conversions;
  v_op JSONB;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'abort fingerprint');
  IF p_reason IS NOT NULL AND pg_column_size(p_reason) > 8192 THEN
    RAISE EXCEPTION 'abort reason exceeds 8 KiB' USING ERRCODE='PF004';
  END IF;
  v_op := pfh.resource_operation_begin(
    p_tenant, 'conversion', p_operation_id, 'conversion-abort', p_fingerprint,
    jsonb_build_object('conversionId', p_conversion_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  SELECT * INTO v FROM pfh.conversions
    WHERE id=p_conversion_id AND tenant_id=p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'conversion % not found', p_conversion_id USING ERRCODE='PF007';
  END IF;
  IF v.state NOT IN ('migrating','final_cut') THEN
    RAISE EXCEPTION 'conversion % is % and cannot abort', p_conversion_id, v.state
      USING ERRCODE='PF002';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.conversions SET
    state='failed', last_error=COALESCE(p_reason, jsonb_build_object('kind','aborted')),
    updated_db_ms=v_now
  WHERE id=p_conversion_id;
  IF v.final_cut_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM pfh.cut_consumers
                 WHERE consumer_kind='conversion' AND consumer_id=p_conversion_id
                   AND tenant_id=p_tenant AND released_db_ms IS NULL) THEN
    PERFORM pfh.consumer_release(p_tenant, 'conversion', p_conversion_id);
  END IF;
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'conversion', p_operation_id, 'succeeded',
    jsonb_build_object('conversionId', p_conversion_id, 'state', 'failed'));
  RETURN pfh.conversion_status(p_tenant, p_conversion_id);
END;
$$;

-- Retry: a failed conversion resumes as a fresh 'migrating' attempt. The
-- permanent namespace is reused (monotone counters make ino collisions
-- structurally impossible); the head pin refreshes to the current branch
-- head.
CREATE FUNCTION pfh.conversion_retry(
  p_tenant TEXT, p_conversion_id TEXT, p_operation_id TEXT, p_fingerprint TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.conversions;
  v_branch RECORD;
  v_op JSONB;
  v_now BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'retry fingerprint');
  v_op := pfh.resource_operation_begin(
    p_tenant, 'conversion', p_operation_id, 'conversion-retry', p_fingerprint,
    jsonb_build_object('conversionId', p_conversion_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  SELECT * INTO v FROM pfh.conversions
    WHERE id=p_conversion_id AND tenant_id=p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'conversion % not found', p_conversion_id USING ERRCODE='PF007';
  END IF;
  IF v.state <> 'failed' THEN
    RAISE EXCEPTION 'conversion % is % and cannot retry', p_conversion_id, v.state
      USING ERRCODE='PF002';
  END IF;
  SELECT b.id, b.branch_mode, b.head_commit_id INTO v_branch
    FROM public.branches b WHERE b.id=v.branch_id;
  IF NOT FOUND OR v_branch.branch_mode NOT IN ('legacy_manifest','migrating') THEN
    RAISE EXCEPTION 'branch % mode % cannot retry a conversion',
      v.branch_id, v_branch.branch_mode USING ERRCODE='PF001';
  END IF;
  v_now := pfh.now_ms();
  UPDATE pfh.conversions SET
    state='migrating', attempt=attempt+1, final_cut_id=NULL,
    old_generation_id=NULL, head_commit_id_pin=v_branch.head_commit_id,
    last_error=NULL, updated_db_ms=v_now
  WHERE id=p_conversion_id;
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'conversion', p_operation_id, 'succeeded',
    jsonb_build_object('conversionId', p_conversion_id, 'state', 'migrating'));
  RETURN pfh.conversion_status(p_tenant, p_conversion_id);
END;
$$;

-- ─── Adoption (O(1) frozen-base advance under exact proof) ───────────────────

-- adopt(cutId, anchorId): both arms must bound the SAME cut. The journal
-- primitive advances the base tuple AND subtracts the captured cumulative
-- backlog in O(1) (verified by the freeze trigger against this proof row).
-- The serving pin binds the exact old base commit/root/anchor plus the
-- generation's manager epoch, authority runtime, and writer fence at
-- adoption time. Older ready cuts of the generation are rechecked: nothing
-- is ever synchronously deleted here — GC observes root-set changes later.
CREATE FUNCTION pfh.cut_adopt(
  p_tenant TEXT, p_cut_id TEXT, p_anchor_id TEXT,
  p_operation_id TEXT, p_fingerprint TEXT, p_serving_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  c pfh.history_cuts;
  ra pfh.recovery_anchors;
  v_op JSONB;
  v_now BIGINT;
  v_id TEXT;
  v_advance JSONB;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_sha256(p_fingerprint, 'adoption fingerprint');
  -- Capability gate: adoption is blocked until the operator/manager proves
  -- the serving fleet can open PFT2 bases (the managed child advertises
  -- pft2-base in its bootstrap features; the manager forwards this token).
  IF p_serving_capability IS DISTINCT FROM 'pft2-base-v1' THEN
    RAISE EXCEPTION 'adoption requires the pft2-base-v1 serving capability proof'
      USING ERRCODE='PF011';
  END IF;
  v_op := pfh.resource_operation_begin(
    p_tenant, 'adoption', p_operation_id, 'cut-adopt', p_fingerprint,
    jsonb_build_object('cutId', p_cut_id, 'anchorId', p_anchor_id));
  IF (v_op->>'replayed')::BOOLEAN THEN
    RETURN v_op;
  END IF;
  -- Plain read: 'ready' is stable (cancel refuses non-pending states) and the
  -- freeze trigger re-verifies the exact tuple under the generation lock, so
  -- no pfh row lock is held before the branch advisory lock (lock order).
  SELECT * INTO c FROM pfh.history_cuts
    WHERE id=p_cut_id AND tenant_id=p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cut % not found', p_cut_id USING ERRCODE='PF007';
  END IF;
  IF c.state <> 'ready' OR c.result_commit_id IS NULL THEN
    RAISE EXCEPTION 'cut % is not ready', p_cut_id USING ERRCODE='PF011';
  END IF;
  IF c.kind <> 'recovery' OR c.source_kind <> 'managed_journal'
     OR c.record_codec <> 'pfj3' THEN
    RAISE EXCEPTION 'adoption requires a ready recovery cut of a pfj3 managed journal'
      USING ERRCODE='PF011';
  END IF;
  SELECT * INTO ra FROM pfh.recovery_anchors
    WHERE id=p_anchor_id AND tenant_id=p_tenant;
  IF NOT FOUND OR ra.cut_id <> p_cut_id THEN
    -- The matching-boundary rule: the anchor must be THE anchor of this cut.
    RAISE EXCEPTION 'anchor % does not bound cut %', p_anchor_id, p_cut_id
      USING ERRCODE='PF011';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pfh.history_cuts older
    WHERE older.generation_id=c.generation_id
      AND older.state IN ('pending','materializing')
      AND older.cut_seq_exclusive < c.cut_seq_exclusive) THEN
    RAISE EXCEPTION 'an older pending cut still pins the prefix' USING ERRCODE='PF011';
  END IF;
  v_now := pfh.now_ms();
  v_id := pfh.new_id('hadopt');
  INSERT INTO pfh.adoptions (
    id, cut_id, anchor_id, generation_id, tenant_id, op_operation_id,
    old_base_seq, old_base_digest, old_base_commit_id,
    new_base_seq, new_base_digest, new_base_commit_id,
    subtract_backlog_bytes, subtract_backlog_records,
    state, created_db_ms)
  VALUES (
    v_id, p_cut_id, p_anchor_id, c.generation_id, p_tenant, p_operation_id,
    c.source_base_seq, c.source_base_digest, c.source_base_commit_id,
    c.cut_seq_exclusive, c.cut_digest, c.result_commit_id,
    c.cut_backlog_bytes, c.cut_backlog_records,
    'applying', v_now);
  -- Journal-owner primitive: branch advisory -> generation row; verifies the
  -- exact old base, advances it, and subtracts the captured backlog; the
  -- replaced freeze trigger re-verifies against the 'applying' row inserted
  -- above (same transaction). Returns the pinned runtime facts.
  v_advance := pfj.history_adopt_base(v_id);
  UPDATE pfh.adoptions SET state='applied', applied_db_ms=pfh.now_ms() WHERE id=v_id;
  PERFORM pfh.consumer_attach(p_tenant, p_cut_id, 'adoption', v_id);
  INSERT INTO pfh.serving_base_pins (
    adoption_id, cut_id, anchor_id, tenant_id, generation_id, writer_fence,
    manager_epoch, authority_runtime_id, authority_runtime_seq,
    old_base_commit_id, old_base_root_digest, old_anchor_id, created_db_ms)
  SELECT v_id, p_cut_id, p_anchor_id, p_tenant, c.generation_id,
         COALESCE((v_advance->>'writerFence')::BIGINT, 0),
         (v_advance->>'managerEpoch')::BIGINT,
         v_advance->>'authorityRuntimeId',
         (v_advance->>'authorityRuntimeSeq')::BIGINT,
         COALESCE(c.source_base_commit_id, c.source_head_commit_id),
         bp.root_digest, ba.id, v_now
  FROM (SELECT 1) one
  LEFT JOIN pfh.pft2_commits bp ON bp.commit_id=c.source_base_commit_id
  LEFT JOIN pfh.recovery_anchors ba ON ba.commit_id=c.source_base_commit_id;
  PERFORM pfh.resource_operation_finish(
    p_tenant, 'adoption', p_operation_id, 'succeeded',
    jsonb_build_object('adoptionId', v_id, 'cutId', p_cut_id,
                       'anchorId', p_anchor_id,
                       'newBaseCommitId', c.result_commit_id));
  RETURN jsonb_build_object(
    'adoptionId', v_id, 'cutId', p_cut_id, 'anchorId', p_anchor_id,
    'state', 'applied',
    'newBaseSeq', c.cut_seq_exclusive::TEXT, 'newBaseDigest', c.cut_digest,
    'newBaseCommitId', c.result_commit_id,
    'writerFence', COALESCE(v_advance->>'writerFence','0'),
    'managerEpoch', v_advance->>'managerEpoch',
    'authorityRuntimeId', v_advance->>'authorityRuntimeId',
    'authorityRuntimeSeq', v_advance->>'authorityRuntimeSeq');
END;
$$;

-- Verified base-swap acknowledgment: the EXACT pinned runtime (generation +
-- writer fence + runtime id when pinned) must present itself. There is no
-- unauthenticated release-by-id.
CREATE FUNCTION pfh.serving_pin_ack(
  p_adoption_id TEXT, p_generation_id TEXT, p_writer_fence BIGINT,
  p_authority_runtime_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.serving_base_pins;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  SELECT * INTO v FROM pfh.serving_base_pins WHERE adoption_id=p_adoption_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'serving pin % not found', p_adoption_id USING ERRCODE='PF007';
  END IF;
  IF v.generation_id IS DISTINCT FROM p_generation_id
     OR v.writer_fence IS DISTINCT FROM p_writer_fence
     OR (v.authority_runtime_id IS NOT NULL
         AND v.authority_runtime_id IS DISTINCT FROM p_authority_runtime_id) THEN
    RAISE EXCEPTION 'serving pin ack does not present the pinned runtime facts'
      USING ERRCODE='PF001';
  END IF;
  IF v.released_db_ms IS NULL THEN
    UPDATE pfh.serving_base_pins SET
      acked_db_ms=v_now, released_db_ms=v_now, release_reason='acked'
    WHERE adoption_id=p_adoption_id;
  END IF;
  RETURN jsonb_build_object('adoptionId', p_adoption_id, 'released', TRUE,
                            'reason', 'acked');
END;
$$;

-- Fenced release: provable durable supersession of the pinned runtime — the
-- generation's writer fence advanced past the pinned fence, the generation
-- is terminal, or the pinned writer lease is durably released/expired at DB
-- time. Never a TTL.
CREATE FUNCTION pfh.serving_pin_release_fenced(p_adoption_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v pfh.serving_base_pins;
  g RECORD;
  v_lease RECORD;
  v_superseded BOOLEAN := FALSE;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  SELECT * INTO v FROM pfh.serving_base_pins WHERE adoption_id=p_adoption_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'serving pin % not found', p_adoption_id USING ERRCODE='PF007';
  END IF;
  IF v.released_db_ms IS NOT NULL THEN
    RETURN jsonb_build_object('adoptionId', p_adoption_id, 'released', TRUE,
                              'reason', v.release_reason);
  END IF;
  SELECT gg.writer_fence, gg.status, gg.lease_id INTO g
    FROM pfj.journal_generations gg WHERE gg.id=v.generation_id;
  IF NOT FOUND THEN
    v_superseded := TRUE; -- the generation itself is gone: durably terminal
  ELSE
    IF g.writer_fence > v.writer_fence OR g.status IN ('retired') THEN
      v_superseded := TRUE;
    ELSIF g.lease_id IS NOT NULL THEN
      SELECT l.released_at, l.expires_at INTO v_lease
        FROM public.leases l WHERE l.id=g.lease_id;
      IF FOUND AND (v_lease.released_at IS NOT NULL OR v_lease.expires_at <= v_now) THEN
        v_superseded := TRUE;
      END IF;
    END IF;
  END IF;
  IF NOT v_superseded THEN
    RAISE EXCEPTION 'serving pin % runtime is not durably superseded', p_adoption_id
      USING ERRCODE='PF011';
  END IF;
  UPDATE pfh.serving_base_pins SET
    released_db_ms=v_now, release_reason='fenced'
  WHERE adoption_id=p_adoption_id;
  RETURN jsonb_build_object('adoptionId', p_adoption_id, 'released', TRUE,
                            'reason', 'fenced');
END;
$$;

-- ─── Scrub / repair (worker + DB-time leases; stale receipts fenced) ─────────

CREATE FUNCTION pfh.worker_beat(
  p_worker_id TEXT, p_kinds TEXT[], p_facts JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_kind TEXT;
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
    INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
    VALUES (v_kind, p_worker_id, v_now, COALESCE(p_facts,'{}'::jsonb))
    ON CONFLICT (worker_kind, worker_id) DO UPDATE
      SET last_beat_db_ms=EXCLUDED.last_beat_db_ms, facts=EXCLUDED.facts;
  END LOOP;
  RETURN jsonb_build_object('dbTimeMs', v_now::TEXT);
END;
$$;

-- Claims due copies for verification under worker + monotone epoch + DB-time
-- lease fencing. A crashed scrubber's claim expires and is reclaimable; its
-- late receipt cannot mutate the reclaimed copy.
CREATE FUNCTION pfh.scrub_claim(
  p_worker_id TEXT, p_limit INT
) RETURNS TABLE (
  tenant_id TEXT, kind TEXT, digest TEXT, incarnation BIGINT,
  failure_domain TEXT, storage_key TEXT, size BIGINT, last_verified_db_ms BIGINT,
  claim_epoch BIGINT, claim_expires_db_ms BIGINT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,64),1),512);
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_worker_id IS NULL OR length(p_worker_id) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'worker id is required' USING ERRCODE='PF008';
  END IF;
  INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
  VALUES ('scrub', p_worker_id, v_now, '{}'::jsonb)
  ON CONFLICT (worker_kind, worker_id) DO UPDATE
    SET last_beat_db_ms=EXCLUDED.last_beat_db_ms;
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
$$;

-- Records one scrub outcome. ok=TRUE requires the caller to have re-read the
-- EXACT recorded key, matched byte count, recomputed the sha256, and matched
-- the expected storage key. Corruption quarantines the OBJECT: publication,
-- adoption readiness, and restore audits refuse quarantined objects until a
-- verified repair receipt (or a passing scrub of every failed copy) lands. A
-- receipt for a superseded incarnation is a typed stale error and can never
-- heal or harm the current identity.
CREATE FUNCTION pfh.scrub_receipt(
  p_worker_id TEXT, p_tenant TEXT, p_kind TEXT, p_digest TEXT,
  p_incarnation BIGINT, p_failure_domain TEXT, p_claim_epoch BIGINT,
  p_ok BOOLEAN, p_size BIGINT, p_storage_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  oc pfh.object_copies;
  o pfh.objects;
  v_now BIGINT := pfh.now_ms();
  v_backoff BIGINT;
  v_success_interval BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_object_identity(p_tenant, p_kind, p_digest);
  PERFORM pfh.scope_locks(ARRAY['pfh-object:'||p_tenant||E'\x01'||p_kind||E'\x01'||p_digest]);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'object % not registered', p_digest USING ERRCODE='PF007';
  END IF;
  IF o.incarnation <> p_incarnation THEN
    RAISE EXCEPTION 'scrub receipt for superseded incarnation % (current %)',
      p_incarnation, o.incarnation USING ERRCODE='PF001';
  END IF;
  SELECT * INTO oc FROM pfh.object_copies
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
      AND incarnation=p_incarnation AND failure_domain=p_failure_domain
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'object copy %/%/% not found', p_digest, p_incarnation, p_failure_domain
      USING ERRCODE='PF007';
  END IF;
  IF oc.verify_claim_worker_id IS DISTINCT FROM p_worker_id
     OR oc.verify_claim_epoch <> p_claim_epoch
     OR oc.verify_claim_expires_db_ms IS NULL
     OR oc.verify_claim_expires_db_ms <= v_now THEN
    RAISE EXCEPTION 'scrub receipt claim is stale for %/%/%',
      p_digest, p_incarnation, p_failure_domain USING ERRCODE='PF001';
  END IF;
  IF p_ok THEN
    IF p_size IS DISTINCT FROM oc.size OR p_storage_key IS DISTINCT FROM oc.storage_key THEN
      RAISE EXCEPTION 'scrub facts contradict the recorded copy' USING ERRCODE='PF002';
    END IF;
    SELECT GREATEST(60000, LEAST(
      ((pfh.require_history_policy()).policy->>'maxLastVerifiedAgeMs')::BIGINT / 2,
      86400000)) INTO v_success_interval;
    UPDATE pfh.object_copies SET
      last_verified_db_ms=v_now, verify_attempts=0,
      next_verify_db_ms=v_now+v_success_interval,
      verify_claim_worker_id=NULL, verify_claim_expires_db_ms=NULL
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
      AND incarnation=p_incarnation AND failure_domain=p_failure_domain;
    IF o.state = 'quarantined'
       AND NOT EXISTS (
         SELECT 1 FROM pfh.object_copies q
         WHERE q.tenant_id=p_tenant AND q.kind=p_kind AND q.digest=p_digest
           AND q.incarnation=o.incarnation
           AND q.state='present' AND q.verify_attempts > 0
           AND q.failure_domain <> p_failure_domain) THEN
      UPDATE pfh.objects SET state='live', updated_db_ms=v_now
      WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
    END IF;
    RETURN jsonb_build_object('digest', p_digest, 'ok', TRUE);
  END IF;
  v_backoff := LEAST(60000 * (2 ^ LEAST(oc.verify_attempts, 10))::BIGINT, 86400000);
  UPDATE pfh.object_copies SET
    verify_attempts=verify_attempts+1, next_verify_db_ms=v_now+v_backoff,
    verify_claim_worker_id=NULL, verify_claim_expires_db_ms=NULL
  WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
    AND incarnation=p_incarnation AND failure_domain=p_failure_domain;
  IF oc.verify_attempts + 1 >= 3 AND o.state IN ('live','intended') THEN
    UPDATE pfh.objects SET state='quarantined', updated_db_ms=v_now
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
  END IF;
  RETURN jsonb_build_object('digest', p_digest, 'ok', FALSE,
                            'attempts', oc.verify_attempts+1);
END;
$$;

-- Claims repairable destinations: required failure domains whose copy of
-- the CURRENT incarnation of a live/quarantined/intended object is missing
-- or has failed verification — provided a verified source copy exists in
-- another domain. The claim is a worker + DB-time lease row; the response
-- carries the verified source copies (exact recorded keys) the worker must
-- read and re-verify BEFORE writing the destination at its exact
-- per-incarnation key.
CREATE FUNCTION pfh.repair_claim(
  p_worker_id TEXT, p_limit INT, p_lease_ttl_ms BIGINT
) RETURNS SETOF JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
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
  INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
  VALUES ('repair', p_worker_id, v_now, '{}'::jsonb)
  ON CONFLICT (worker_kind, worker_id) DO UPDATE
    SET last_beat_db_ms=EXCLUDED.last_beat_db_ms;
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
$$;

-- Records a verified repair: the worker read a verified source copy (exact
-- key + hash), wrote the destination at its exact per-incarnation key, and
-- read THAT back verified. Fenced by the current incarnation.
CREATE FUNCTION pfh.repair_receipt(
  p_worker_id TEXT, p_tenant TEXT, p_kind TEXT, p_digest TEXT,
  p_incarnation BIGINT, p_failure_domain TEXT, p_claim_epoch BIGINT,
  p_storage_key TEXT, p_size BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  o pfh.objects;
  rl pfh.repair_leases;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_object_identity(p_tenant, p_kind, p_digest);
  IF p_storage_key IS NULL OR length(p_storage_key) NOT BETWEEN 1 AND 1024
     OR p_size IS NULL OR p_size < 0 THEN
    RAISE EXCEPTION 'repair receipt requires exact storage key and size' USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.scope_locks(ARRAY['pfh-object:'||p_tenant||E'\x01'||p_kind||E'\x01'||p_digest]);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'object % not registered', p_digest USING ERRCODE='PF007';
  END IF;
  IF o.incarnation <> p_incarnation OR o.state IN ('deleting','tombstoned') THEN
    RAISE EXCEPTION 'repair receipt for superseded incarnation % (current %, state %)',
      p_incarnation, o.incarnation, o.state USING ERRCODE='PF001';
  END IF;
  IF o.size <> p_size THEN
    RAISE EXCEPTION 'repair size % contradicts registered size %', p_size, o.size
      USING ERRCODE='PF002';
  END IF;
  SELECT * INTO rl FROM pfh.repair_leases
  WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
    AND incarnation=p_incarnation AND failure_domain=p_failure_domain
  FOR UPDATE;
  IF NOT FOUND OR rl.worker_id IS DISTINCT FROM p_worker_id
     OR rl.claim_epoch <> p_claim_epoch OR rl.expires_db_ms <= v_now THEN
    RAISE EXCEPTION 'repair receipt claim is stale for %/%/%',
      p_digest, p_incarnation, p_failure_domain USING ERRCODE='PF001';
  END IF;
  INSERT INTO pfh.object_copies (
    tenant_id, kind, digest, incarnation, failure_domain, storage_key, size,
    state, first_verified_db_ms, last_verified_db_ms)
  VALUES (p_tenant, p_kind, p_digest, p_incarnation, p_failure_domain,
          p_storage_key, p_size, 'present', v_now, v_now)
  ON CONFLICT (tenant_id, kind, digest, incarnation, failure_domain) DO UPDATE
    SET storage_key=EXCLUDED.storage_key, size=EXCLUDED.size, state='present',
        last_verified_db_ms=v_now, verify_attempts=0, next_verify_db_ms=0,
        verify_claim_worker_id=NULL, verify_claim_expires_db_ms=NULL,
        absence_receipt=NULL;
  DELETE FROM pfh.repair_leases
  WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
    AND incarnation=p_incarnation AND failure_domain=p_failure_domain
    AND worker_id=p_worker_id AND claim_epoch=p_claim_epoch;
  -- A fully repaired quarantined object returns to live once no failed
  -- copies remain.
  IF o.state = 'quarantined'
     AND NOT EXISTS (
       SELECT 1 FROM pfh.object_copies q
       WHERE q.tenant_id=p_tenant AND q.kind=p_kind AND q.digest=p_digest
         AND q.incarnation=o.incarnation AND q.state='present'
         AND q.verify_attempts > 0) THEN
    UPDATE pfh.objects SET state='live', updated_db_ms=v_now
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
  END IF;
  RETURN jsonb_build_object('digest', p_digest, 'repaired', TRUE,
                            'failureDomain', p_failure_domain);
END;
$$;

-- ─── GC sweep authority (fenced, crash-reclaimable, ABA-safe) ────────────────

-- An object is a ROOT iff reachable from: upload intents of live cuts, the
-- closures (user AND recovery) of ready cuts that are unreleased-consumed or
-- serving-pinned or whose commit is referenced by a branch head, snapshot,
-- child commit, or live generation base — or whose OLD base commit a live
-- serving pin still names. Reachability is exact and normalized — never
-- inferred from manifest JSON, never truncated.
CREATE FUNCTION pfh.object_is_root(p_tenant TEXT, p_kind TEXT, p_digest TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM pfh.upload_intents ui
    JOIN pfh.history_cuts hc ON hc.id=ui.cut_id
    WHERE ui.tenant_id=p_tenant AND ui.kind=p_kind AND ui.digest=p_digest
      AND hc.state IN ('pending','materializing'))
  OR EXISTS (
    SELECT 1 FROM pfh.cut_objects co
    JOIN pfh.history_cuts hc ON hc.id=co.cut_id
    WHERE co.tenant_id=p_tenant AND co.kind=p_kind AND co.digest=p_digest
      AND hc.state='ready'
      AND (EXISTS (SELECT 1 FROM pfh.cut_consumers cc
                   WHERE cc.cut_id=hc.id AND cc.released_db_ms IS NULL)
        OR EXISTS (SELECT 1 FROM pfh.serving_base_pins sp
                   WHERE sp.cut_id=hc.id AND sp.released_db_ms IS NULL)
        OR EXISTS (SELECT 1 FROM pfh.serving_base_pins sp
                   JOIN pfh.pft2_commits oldp ON oldp.commit_id=sp.old_base_commit_id
                   WHERE oldp.cut_id=hc.id AND sp.released_db_ms IS NULL)
        OR EXISTS (SELECT 1 FROM pfh.pft2_commits pc
                   JOIN public.commits cm ON cm.id=pc.commit_id
                   WHERE pc.cut_id=hc.id
                     AND (EXISTS (SELECT 1 FROM public.branches b
                                  WHERE b.head_commit_id=cm.id)
                       OR EXISTS (SELECT 1 FROM public.snapshots s
                                  WHERE s.commit_id=cm.id)
                       OR EXISTS (SELECT 1 FROM public.commits child
                                  WHERE child.parent_commit_id=cm.id)
                       OR EXISTS (SELECT 1 FROM pfj.journal_generations jg
                                  WHERE jg.base_commit_id=cm.id
                                    AND jg.status IN ('active','suspended','retiring'))))));
END;
$$;

CREATE FUNCTION pfh.sweep_preview(p_limit INT)
RETURNS TABLE (tenant_id TEXT, kind TEXT, digest TEXT, size BIGINT)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_limit INT := LEAST(GREATEST(COALESCE(p_limit,100),1),1000);
BEGIN
  RETURN QUERY
    SELECT o.tenant_id, o.kind, o.digest, o.size FROM pfh.objects o
    WHERE o.state IN ('live','intended','reclaiming')
      AND NOT pfh.object_is_root(o.tenant_id, o.kind, o.digest)
    ORDER BY o.updated_db_ms
    LIMIT v_limit;
END;
$$;

-- Claims ONE sweepable object under a worker + epoch + DB-time lease and
-- durably enters 'deleting': from this instant every new reference/upload
-- must observe the tombstone intent and bump the incarnation
-- (pfh.object_intend does exactly that). A 'deleting' object whose lease
-- expired (crashed sweeper) is re-claimable; the stale sweeper's completion
-- is fenced by claim epoch + reclaim generation.
CREATE FUNCTION pfh.sweep_claim(
  p_worker_id TEXT, p_min_age_ms BIGINT, p_lease_ttl_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
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
  INSERT INTO pfh.worker_heartbeats (worker_kind, worker_id, last_beat_db_ms, facts)
  VALUES ('gc', p_worker_id, v_now, '{}'::jsonb)
  ON CONFLICT (worker_kind, worker_id) DO UPDATE
    SET last_beat_db_ms=EXCLUDED.last_beat_db_ms;
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
$$;

-- Completion proves EVERY claimed copy absent: the per-domain absence
-- receipts must cover the exact set of copies the claim entered 'deleting'
-- (domain AND exact storage key), each attesting confirmedAbsent. A bumped
-- incarnation, advanced reclaim generation, stale claim epoch, or a
-- late-arriving root resurrects instead of finalizing. Tombstones are
-- permanent.
CREATE FUNCTION pfh.sweep_complete(
  p_worker_id TEXT, p_tenant TEXT, p_kind TEXT, p_digest TEXT,
  p_incarnation BIGINT, p_reclaim_generation BIGINT, p_claim_epoch BIGINT,
  p_absence JSONB
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  o pfh.objects;
  v_now BIGINT := pfh.now_ms();
  v_uncovered BIGINT;
  v_bad BIGINT;
BEGIN
  PERFORM pfh.require_txn_settings();
  PERFORM pfh.require_object_identity(p_tenant, p_kind, p_digest);
  IF p_absence IS NULL OR jsonb_typeof(p_absence) <> 'array'
     OR pg_column_size(p_absence) > 8192 THEN
    RAISE EXCEPTION 'per-copy absence receipts are required' USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.scope_locks(ARRAY['pfh-object:'||p_tenant||E'\x01'||p_kind||E'\x01'||p_digest]);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'object % not registered', p_digest USING ERRCODE='PF007';
  END IF;
  IF o.incarnation <> p_incarnation OR o.reclaim_generation <> p_reclaim_generation
     OR o.sweep_claim_epoch <> p_claim_epoch OR o.state <> 'deleting' THEN
    -- A writer re-intended (incarnation bumped), another sweeper reclaimed
    -- the expired lease, or the claim is stale: the object is resurrected /
    -- untouched and the metadata row stands.
    RETURN 'resurrected';
  END IF;
  IF pfh.object_is_root(p_tenant, p_kind, p_digest) THEN
    UPDATE pfh.objects SET state='live', sweep_worker_id=NULL,
      sweep_claim_expires_db_ms=NULL, updated_db_ms=v_now
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
    UPDATE pfh.object_copies SET state='present'
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
      AND incarnation=p_incarnation AND state='deleting';
    RETURN 'resurrected';
  END IF;
  -- Every claimed 'deleting' copy must have an exact matching absence
  -- receipt (domain + exact key + confirmedAbsent) — and no receipt may name
  -- a copy that was not claimed.
  SELECT COUNT(*) INTO v_uncovered
    FROM pfh.object_copies oc
    WHERE oc.tenant_id=p_tenant AND oc.kind=p_kind AND oc.digest=p_digest
      AND oc.incarnation=p_incarnation AND oc.state='deleting'
      AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(p_absence) a
        WHERE a->>'failureDomain'=oc.failure_domain
          AND a->>'storageKey'=oc.storage_key
          AND (a->>'confirmedAbsent')::BOOLEAN IS TRUE);
  IF v_uncovered > 0 THEN
    RAISE EXCEPTION 'sweep completion is missing % per-copy absence proofs', v_uncovered
      USING ERRCODE='PF011';
  END IF;
  SELECT COUNT(*) INTO v_bad
    FROM jsonb_array_elements(p_absence) a
    WHERE NOT EXISTS (
      SELECT 1 FROM pfh.object_copies oc
      WHERE oc.tenant_id=p_tenant AND oc.kind=p_kind AND oc.digest=p_digest
        AND oc.incarnation=p_incarnation
        AND oc.failure_domain=a->>'failureDomain'
        AND oc.storage_key=a->>'storageKey');
  IF v_bad > 0 THEN
    RAISE EXCEPTION 'sweep completion names % unclaimed copies', v_bad USING ERRCODE='PF008';
  END IF;
  UPDATE pfh.object_copies SET
    state='absent',
    absence_receipt=jsonb_build_object('workerId', p_worker_id, 'dbTimeMs', v_now::TEXT)
  WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
    AND incarnation=p_incarnation AND state='deleting';
  UPDATE pfh.objects SET state='tombstoned', sweep_worker_id=NULL,
    sweep_claim_expires_db_ms=NULL, updated_db_ms=v_now
  WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
  RETURN 'swept';
END;
$$;

CREATE FUNCTION pfh.sweep_release(
  p_worker_id TEXT, p_tenant TEXT, p_kind TEXT, p_digest TEXT,
  p_incarnation BIGINT, p_reclaim_generation BIGINT, p_claim_epoch BIGINT,
  p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  o pfh.objects;
  v_now BIGINT := pfh.now_ms();
BEGIN
  PERFORM pfh.require_txn_settings();
  IF p_reason NOT IN ('storage_failed','aborted') THEN
    RAISE EXCEPTION 'sweep release reason % is unknown', p_reason USING ERRCODE='PF008';
  END IF;
  PERFORM pfh.scope_locks(ARRAY['pfh-object:'||p_tenant||E'\x01'||p_kind||E'\x01'||p_digest]);
  SELECT * INTO o FROM pfh.objects
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest FOR UPDATE;
  IF FOUND AND o.state='deleting' AND o.incarnation=p_incarnation
     AND o.reclaim_generation=p_reclaim_generation
     AND o.sweep_claim_epoch=p_claim_epoch THEN
    UPDATE pfh.objects SET state='reclaiming', sweep_worker_id=NULL,
      sweep_claim_expires_db_ms=NULL, updated_db_ms=v_now
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest;
    UPDATE pfh.object_copies SET state='present'
    WHERE tenant_id=p_tenant AND kind=p_kind AND digest=p_digest
      AND incarnation=p_incarnation AND state='deleting';
  END IF;
  RETURN jsonb_build_object('digest', p_digest, 'released', TRUE);
END;
$$;

-- ─── Audits (pure, zero-argument, STABLE, bounded, untruncated) ──────────────

CREATE FUNCTION pfh.restore_audit() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_now BIGINT := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_policy pfh.history_policies;
  v_bounds_ok BOOLEAN := TRUE;
  v_roots_ok BOOLEAN := TRUE;
  v_refs_ok BOOLEAN := TRUE;
  v_copies_ok BOOLEAN := TRUE;
  v_pins_ok BOOLEAN := TRUE;
  v_cut_count BIGINT;
  v_object_count BIGINT;
  v_root_set TEXT;
  v_freshness BIGINT;
  v_required BIGINT;
  v_scrub_fresh BOOLEAN;
BEGIN
  SELECT * INTO v_policy FROM pfh.history_policies WHERE singleton_key='history';
  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'v',2,'ok',FALSE,'historyPolicyEpoch','0','dbTimeMs',v_now::TEXT,
      'rootSetSha256','', 'checks', jsonb_build_object(
        'boundsAdmitted',FALSE,'rootsValid',FALSE,'objectReferencesValid',FALSE,
        'copyReceiptsValid',FALSE,'servingPinsValid',FALSE,'workerFresh',FALSE));
  END IF;
  v_freshness := (v_policy.policy->>'maxLastVerifiedAgeMs')::BIGINT;
  SELECT COUNT(*) INTO v_required
    FROM jsonb_array_elements_text(v_policy.policy->'requiredFailureDomains');

  SELECT COUNT(*) INTO v_cut_count FROM pfh.history_cuts;
  SELECT COUNT(*) INTO v_object_count FROM pfh.objects;
  IF v_cut_count > 100000 OR v_object_count > 5000000 THEN
    v_bounds_ok := FALSE;
  END IF;

  v_scrub_fresh := EXISTS (
    SELECT 1 FROM pfh.worker_heartbeats hb
    WHERE hb.worker_kind='scrub'
      AND hb.last_beat_db_ms >= v_now - (v_policy.policy->>'maxWorkerHeartbeatAgeMs')::BIGINT)
    OR NOT EXISTS (SELECT 1 FROM pfh.object_copies WHERE state='present');

  IF v_bounds_ok THEN
    -- Roots: every ready cut names an existing pft2 commit AND recovery
    -- anchor whose closures contain their own roots.
    v_roots_ok := NOT EXISTS (
      SELECT 1 FROM pfh.history_cuts hc
      WHERE hc.state='ready'
        AND (hc.result_commit_id IS NULL
          OR hc.recovery_anchor_id IS NULL
          OR NOT EXISTS (SELECT 1 FROM pfh.pft2_commits pc
                         WHERE pc.commit_id=hc.result_commit_id AND pc.cut_id=hc.id)
          OR NOT EXISTS (SELECT 1 FROM pfh.recovery_anchors ra
                         WHERE ra.id=hc.recovery_anchor_id AND ra.cut_id=hc.id)
          OR NOT EXISTS (
              SELECT 1 FROM pfh.pft2_commits pc
              JOIN pfh.cut_objects co
                ON co.cut_id=hc.id AND co.closure='user'
               AND co.digest='sha256:'||pc.root_digest
              WHERE pc.cut_id=hc.id)
          OR NOT EXISTS (
              SELECT 1 FROM pfh.recovery_anchors ra
              JOIN pfh.cut_objects co
                ON co.cut_id=hc.id AND co.closure='recovery'
               AND co.digest='sha256:'||ra.recovery_root_digest
              WHERE ra.cut_id=hc.id)));

    -- Object references: every closure member (BOTH closures, no
    -- truncation) of a ready cut is a registered non-tombstoned object of
    -- the same tenant.
    v_refs_ok := NOT EXISTS (
      SELECT 1 FROM pfh.cut_objects co
      JOIN pfh.history_cuts hc ON hc.id=co.cut_id AND hc.state='ready'
      LEFT JOIN pfh.objects o
        ON o.tenant_id=co.tenant_id AND o.kind=co.kind AND o.digest=co.digest
      WHERE o.digest IS NULL OR o.state IN ('deleting','tombstoned'));

    -- Copy receipts: every object referenced by a ready cut is unquarantined
    -- with fresh verified copies in EVERY required failure domain at its
    -- live incarnation. The check itself is unconditional; worker liveness
    -- is reported separately so a dead scrubber cannot silently green this.
    v_copies_ok := NOT EXISTS (
      SELECT 1 FROM (
        SELECT DISTINCT co.tenant_id, co.kind, co.digest FROM pfh.cut_objects co
        JOIN pfh.history_cuts hc ON hc.id=co.cut_id AND hc.state='ready') refs
      JOIN pfh.objects o
        ON o.tenant_id=refs.tenant_id AND o.kind=refs.kind AND o.digest=refs.digest
      WHERE o.state='quarantined'
         OR v_required > (
           SELECT COUNT(*) FROM pfh.object_copies oc
           WHERE oc.tenant_id=o.tenant_id AND oc.kind=o.kind AND oc.digest=o.digest
             AND oc.incarnation=o.incarnation
             AND oc.state='present'
             AND oc.last_verified_db_ms >= v_now - v_freshness));

    -- Serving pins: every live pin references a ready cut and its anchor.
    v_pins_ok := NOT EXISTS (
      SELECT 1 FROM pfh.serving_base_pins sp
      LEFT JOIN pfh.history_cuts hc ON hc.id=sp.cut_id
      LEFT JOIN pfh.recovery_anchors ra ON ra.id=sp.anchor_id
      WHERE sp.released_db_ms IS NULL
        AND (hc.id IS NULL OR hc.state <> 'ready' OR ra.id IS NULL OR ra.cut_id <> hc.id));
  ELSE
    v_roots_ok := FALSE; v_refs_ok := FALSE; v_copies_ok := FALSE; v_pins_ok := FALSE;
  END IF;

  -- The exact root set hash covers EVERY live root row (cuts, pins,
  -- consumers) with no LIMIT: within the admitted bounds nothing truncates.
  SELECT encode(pg_catalog.sha256(convert_to(COALESCE(string_agg(line, E'\n'), ''),'UTF8')),'hex')
    INTO v_root_set
    FROM (
      SELECT 'cut'||E'\x01'||hc.id||E'\x01'||COALESCE(hc.result_commit_id,'')
             ||E'\x01'||COALESCE(hc.recovery_anchor_id,'') AS line
      FROM pfh.history_cuts hc WHERE hc.state IN ('pending','materializing','ready')
      UNION ALL
      SELECT 'pin'||E'\x01'||sp.adoption_id||E'\x01'||sp.old_base_commit_id
             ||E'\x01'||COALESCE(sp.old_anchor_id,'')
      FROM pfh.serving_base_pins sp WHERE sp.released_db_ms IS NULL
      UNION ALL
      SELECT 'consumer'||E'\x01'||cc.consumer_kind||E'\x01'||cc.consumer_id
      FROM pfh.cut_consumers cc WHERE cc.released_db_ms IS NULL
      ORDER BY line) roots;

  RETURN jsonb_build_object(
    'v',2,
    'ok', v_bounds_ok AND v_roots_ok AND v_refs_ok AND v_copies_ok AND v_pins_ok
          AND v_scrub_fresh,
    'historyPolicyEpoch', v_policy.policy_epoch::TEXT,
    'requiredFailureDomains', v_policy.policy->'requiredFailureDomains',
    'dbTimeMs', v_now::TEXT,
    'rootSetSha256', v_root_set,
    'checks', jsonb_build_object(
      'boundsAdmitted', v_bounds_ok,
      'rootsValid', v_roots_ok,
      'objectReferencesValid', v_refs_ok,
      'copyReceiptsValid', v_copies_ok,
      'servingPinsValid', v_pins_ok,
      'workerFresh', v_scrub_fresh));
END;
$$;

CREATE FUNCTION pfh.history_freshness_audit() RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_now BIGINT := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_policy pfh.history_policies;
  v_oldest BIGINT;
  v_due BIGINT;
  v_quarantined BIGINT;
  v_scrub_fresh BOOLEAN;
  v_materializer_fresh BOOLEAN;
  v_gc_fresh BOOLEAN;
  v_window BIGINT;
BEGIN
  SELECT * INTO v_policy FROM pfh.history_policies WHERE singleton_key='history';
  IF NOT FOUND THEN
    RETURN jsonb_build_object('v',2,'ok',FALSE,'dbTimeMs',v_now::TEXT,
                              'reason','policy_missing');
  END IF;
  v_window := (v_policy.policy->>'maxWorkerHeartbeatAgeMs')::BIGINT;
  SELECT MIN(last_verified_db_ms) INTO v_oldest
    FROM pfh.object_copies WHERE state='present';
  SELECT COUNT(*) INTO v_due FROM pfh.object_copies
    WHERE state='present'
      AND last_verified_db_ms < v_now - (v_policy.policy->>'maxLastVerifiedAgeMs')::BIGINT;
  SELECT COUNT(*) INTO v_quarantined FROM pfh.objects WHERE state='quarantined';
  v_scrub_fresh := EXISTS (
    SELECT 1 FROM pfh.worker_heartbeats
    WHERE worker_kind='scrub' AND last_beat_db_ms >= v_now - v_window)
    OR NOT EXISTS (SELECT 1 FROM pfh.object_copies WHERE state='present');
  v_materializer_fresh := EXISTS (
    SELECT 1 FROM pfh.worker_heartbeats
    WHERE worker_kind='materializer' AND last_beat_db_ms >= v_now - v_window)
    OR NOT EXISTS (
      SELECT 1 FROM pfh.history_cuts WHERE state IN ('pending','materializing'));
  v_gc_fresh := EXISTS (
    SELECT 1 FROM pfh.worker_heartbeats
    WHERE worker_kind='gc' AND last_beat_db_ms >= v_now - v_window)
    OR NOT EXISTS (SELECT 1 FROM pfh.objects WHERE state='deleting');
  RETURN jsonb_build_object(
    'v',2,
    'ok', v_scrub_fresh AND v_materializer_fresh AND v_gc_fresh
          AND v_due = 0 AND v_quarantined = 0,
    'dbTimeMs', v_now::TEXT,
    'historyPolicyEpoch', v_policy.policy_epoch::TEXT,
    'oldestVerifiedDbMs', CASE WHEN v_oldest IS NULL THEN NULL ELSE v_oldest::TEXT END,
    'overageCopies', v_due,
    'quarantinedObjects', v_quarantined,
    'scrubWorkerFresh', v_scrub_fresh,
    'materializerFresh', v_materializer_fresh,
    'gcFresh', v_gc_fresh);
END;
$$;

-- Trigger function carries no caller surface.
REVOKE ALL ON FUNCTION pfh.inode_namespaces_monotone() FROM PUBLIC;

-- The journal owner's replaced freeze trigger and its conversion finalizer
-- verify pfh proof rows; grant it exactly SELECT on those (owner-only DDL,
-- so it must happen in this section).
GRANT SELECT ON TABLE pfh.adoptions, pfh.conversions, pfh.history_cuts
TO portablefs_journal_owner;

RESET ROLE;

-- ═══ SECTION C: journal-owner primitives (pfj) ════════════════════════════════
SET LOCAL ROLE portablefs_journal_owner;

-- Exact head capture under the append lock order: sorted exclusive branch
-- advisory lock, then (managed) the generation head row FOR UPDATE — the very
-- lock pfj.journal_append holds while advancing next_seq/tip_digest — or
-- (legacy, no live generation) the branch row FOR UPDATE that serializes
-- against legacy manifest commits. Locks persist to transaction end, so the
-- caller's pfh inserts commit atomically with the captured tuple. The
-- response includes the generation's CUMULATIVE backlog counters at this
-- exact boundary — the O(1) adoption subtrahend.
CREATE FUNCTION pfj.history_head_capture(
  p_tenant_id TEXT, p_volume_id TEXT, p_branch_name TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_branch RECORD;
  g pfj.journal_generations;
BEGIN
  PERFORM pfj.scope_locks(ARRAY[
    pfj.branch_lock_key(p_tenant_id, p_volume_id, p_branch_name)]);
  SELECT b.id, b.branch_mode, b.head_commit_id, v.tenant_id AS tenant_id
    INTO v_branch
    FROM public.branches b
    JOIN public.volumes v ON v.id=b.volume_id
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name
    FOR UPDATE OF b;
  IF NOT FOUND OR v_branch.tenant_id IS DISTINCT FROM p_tenant_id THEN
    RAISE EXCEPTION 'branch %/% not found', p_volume_id, p_branch_name
      USING ERRCODE='PF007';
  END IF;
  IF v_branch.branch_mode = 'retired' THEN
    RAISE EXCEPTION 'branch % is retired', v_branch.id USING ERRCODE='PF001';
  END IF;
  SELECT * INTO g FROM pfj.journal_generations
    WHERE branch_id=v_branch.id AND status IN ('active','suspended','retiring')
    LIMIT 1;
  IF FOUND THEN
    g := pfj.lock_generation(g.id);
    RETURN jsonb_build_object(
      'sourceKind','managed_journal',
      'branchId', v_branch.id,
      'generationId', g.id,
      'journalEpoch', g.epoch::TEXT,
      'recordCodec', g.record_codec,
      'controlCodec', g.control_codec,
      'baseCommitId', g.base_commit_id,
      'baseSeq', g.base_seq::TEXT,
      'baseDigest', g.base_digest,
      'cutSeqExclusive', g.next_seq::TEXT,
      'cutDigest', g.tip_digest,
      'backlogBytes', g.backlog_bytes::TEXT,
      'backlogRecords', g.backlog_records::TEXT);
  END IF;
  IF v_branch.branch_mode NOT IN ('legacy_manifest','migrating') THEN
    RAISE EXCEPTION 'branch % mode % has no live generation to capture',
      v_branch.id, v_branch.branch_mode USING ERRCODE='PF001';
  END IF;
  IF v_branch.head_commit_id IS NULL THEN
    RAISE EXCEPTION 'branch % has no head commit to pin', v_branch.id
      USING ERRCODE='PF007';
  END IF;
  RETURN jsonb_build_object(
    'sourceKind','legacy_manifest',
    'branchId', v_branch.id,
    'headCommitId', v_branch.head_commit_id);
END;
$$;

-- Bounded immutable reads of the captured prefix. Shared branch advisory +
-- generation FOR SHARE order the read against retire (trim of a pfj3 prefix
-- remains fail-closed in 013 regardless).
CREATE FUNCTION pfj.history_read_records(
  p_generation_id TEXT, p_from_seq BIGINT, p_to_seq_exclusive BIGINT,
  p_max_records INT, p_max_bytes BIGINT
) RETURNS TABLE (seq BIGINT, payload BYTEA, record_hash TEXT, chain_digest TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_limit INT := LEAST(GREATEST(COALESCE(p_max_records,256),1),1024);
  v_budget BIGINT := LEAST(GREATEST(COALESCE(p_max_bytes,16777216),1),67108864);
  v_emitted INT := 0;
  r RECORD;
BEGIN
  IF p_from_seq IS NULL OR p_from_seq < 0 OR p_to_seq_exclusive IS NULL
     OR p_to_seq_exclusive < p_from_seq THEN
    RAISE EXCEPTION 'history read range is invalid' USING ERRCODE='PF008';
  END IF;
  PERFORM pfj.branch_lock_for_generation(p_generation_id, FALSE);
  SELECT * INTO g FROM pfj.journal_generations WHERE id=p_generation_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation % not found', p_generation_id USING ERRCODE='PF007';
  END IF;
  IF p_to_seq_exclusive > g.next_seq THEN
    RAISE EXCEPTION 'history read beyond the journal head' USING ERRCODE='PF008';
  END IF;
  IF p_from_seq < g.physical_trimmed_seq THEN
    RAISE EXCEPTION 'history read below the physically trimmed prefix' USING ERRCODE='PF008';
  END IF;
  FOR r IN
    SELECT jr.seq, jr.payload, jr.record_hash, jr.chain_digest, jr.payload_bytes
    FROM pfj.journal_records jr
    WHERE jr.generation_id=g.id AND jr.seq >= p_from_seq AND jr.seq < p_to_seq_exclusive
    ORDER BY jr.seq
    LIMIT v_limit
  LOOP
    IF v_emitted > 0 AND v_budget < r.payload_bytes THEN EXIT; END IF;
    v_budget := v_budget - r.payload_bytes;
    v_emitted := v_emitted + 1;
    seq := r.seq;
    payload := r.payload;
    record_hash := r.record_hash;
    chain_digest := r.chain_digest;
    RETURN NEXT;
  END LOOP;
END;
$$;

-- O(1) adoption base advance: verifies the exact old base tuple, advances
-- base seq/digest/commit, and SUBTRACTS the captured cumulative backlog —
-- all under the exact append lock order; the freeze trigger (replaced below)
-- independently verifies the 'applying' proof row including the backlog
-- deltas. Returns the pinned runtime facts for the serving pin.
CREATE FUNCTION pfj.history_adopt_base(p_adoption_id TEXT) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  a RECORD;
  g pfj.journal_generations;
BEGIN
  SELECT * INTO a FROM pfh.adoptions WHERE id=p_adoption_id AND state='applying';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'adoption % is not applying', p_adoption_id USING ERRCODE='PF011';
  END IF;
  PERFORM pfj.branch_lock_for_generation(a.generation_id, TRUE);
  g := pfj.lock_generation(a.generation_id);
  IF g.base_seq IS DISTINCT FROM a.old_base_seq
     OR g.base_digest IS DISTINCT FROM a.old_base_digest THEN
    RAISE EXCEPTION 'adoption % expected base %/% but generation is at %/%',
      p_adoption_id, a.old_base_seq, a.old_base_digest, g.base_seq, g.base_digest
      USING ERRCODE='PF002';
  END IF;
  IF a.new_base_seq > g.next_seq THEN
    RAISE EXCEPTION 'adoption % advances beyond the head', p_adoption_id
      USING ERRCODE='PF010';
  END IF;
  IF g.backlog_bytes < a.subtract_backlog_bytes
     OR g.backlog_records < a.subtract_backlog_records THEN
    RAISE EXCEPTION 'adoption % backlog subtraction underflows (%/% below %/%)',
      p_adoption_id, g.backlog_bytes, g.backlog_records,
      a.subtract_backlog_bytes, a.subtract_backlog_records
      USING ERRCODE='PF010';
  END IF;
  UPDATE pfj.journal_generations SET
    base_seq=a.new_base_seq,
    base_digest=a.new_base_digest,
    base_commit_id=a.new_base_commit_id,
    backlog_bytes=backlog_bytes-a.subtract_backlog_bytes,
    backlog_records=backlog_records-a.subtract_backlog_records,
    updated_at=pfj.now_ms()
  WHERE id=a.generation_id;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'writerFence', g.writer_fence::TEXT,
    'managerEpoch', CASE WHEN g.manager_epoch IS NULL THEN NULL ELSE g.manager_epoch::TEXT END,
    'authorityRuntimeId', g.authority_runtime_id,
    'authorityRuntimeSeq', CASE WHEN g.authority_runtime_seq IS NULL THEN NULL
                                ELSE g.authority_runtime_seq::TEXT END));
END;
$$;

-- Conversion finalize. Under the exclusive branch lock: the old PFR1/PFC1
-- generation must be suspended, exactly drained to the cut (next_seq and tip
-- digest equal the cut tuple), and writer-free; then it retires, the branch
-- head moves to the verified PFT2 commit, and the mode flips to
-- managed_journal — one transaction, re-verified by the replaced triggers.
-- A no-journal legacy branch converts without drain: the pinned head must
-- simply still be the branch head.
CREATE FUNCTION pfj.history_conversion_finalize(p_conversion_id TEXT) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  cv RECORD;
  cut RECORD;
  g pfj.journal_generations;
  v_branch RECORD;
  v_lease RECORD;
  v_now BIGINT := pfj.now_ms();
BEGIN
  SELECT * INTO cv FROM pfh.conversions WHERE id=p_conversion_id AND state='finalizing';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'conversion % is not finalizing', p_conversion_id USING ERRCODE='PF011';
  END IF;
  SELECT * INTO cut FROM pfh.history_cuts WHERE id=cv.final_cut_id AND state='ready';
  IF NOT FOUND OR cut.result_commit_id IS NULL THEN
    RAISE EXCEPTION 'conversion % final cut is not ready', p_conversion_id
      USING ERRCODE='PF011';
  END IF;
  PERFORM pfj.scope_locks(ARRAY[
    pfj.branch_lock_key(cv.tenant_id, cv.volume_id, cv.branch_name)]);
  SELECT b.id, b.branch_mode, b.head_commit_id INTO v_branch
    FROM public.branches b WHERE b.id=cv.branch_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'conversion branch % is gone', cv.branch_id USING ERRCODE='PF007';
  END IF;
  IF cut.source_kind = 'managed_journal' THEN
    g := pfj.lock_generation(cut.generation_id);
    IF g.record_codec <> 'pfr1' THEN
      RAISE EXCEPTION 'conversion requires a legacy pfr1 generation' USING ERRCODE='PF005';
    END IF;
    IF g.status <> 'suspended' THEN
      RAISE EXCEPTION 'conversion requires an exactly suspended generation (status %)',
        g.status USING ERRCODE='PF011';
    END IF;
    IF g.next_seq IS DISTINCT FROM cut.cut_seq_exclusive
       OR g.tip_digest IS DISTINCT FROM cut.cut_digest THEN
      RAISE EXCEPTION 'generation head %/% no longer equals the final cut %/%',
        g.next_seq, g.tip_digest, cut.cut_seq_exclusive, cut.cut_digest
        USING ERRCODE='PF002';
    END IF;
    IF g.lease_id IS NOT NULL THEN
      SELECT l.id, l.released_at, l.expires_at INTO v_lease
        FROM public.leases l WHERE l.id=g.lease_id;
      IF FOUND AND v_lease.released_at IS NULL AND v_lease.expires_at > v_now THEN
        RAISE EXCEPTION 'conversion refuses to finalize under a live writer lease'
          USING ERRCODE='PF001';
      END IF;
    END IF;
    UPDATE pfj.journal_generations SET
      status='retired', capability_hash=NULL, updated_at=v_now
    WHERE id=g.id;
  ELSE
    IF v_branch.head_commit_id IS DISTINCT FROM cut.source_head_commit_id THEN
      RAISE EXCEPTION 'branch head moved since the conversion pin (% vs %)',
        v_branch.head_commit_id, cut.source_head_commit_id USING ERRCODE='PF002';
    END IF;
  END IF;
  IF v_branch.branch_mode NOT IN ('legacy_manifest','migrating') THEN
    RAISE EXCEPTION 'branch % mode % cannot finalize a conversion',
      cv.branch_id, v_branch.branch_mode USING ERRCODE='PF001';
  END IF;
  -- One UPDATE: head + mode together (both guards re-verify: journal owner +
  -- finalizing conversion row + no nonterminal generation).
  UPDATE public.branches SET
    branch_mode='managed_journal',
    head_commit_id=cut.result_commit_id,
    updated_at=v_now
  WHERE id=cv.branch_id;
END;
$$;

-- Replace the 012 freeze trigger: identical invariants, plus the ONE new
-- structurally-proven edge — an adoption base advance (with its exact O(1)
-- backlog subtraction) on a pfj3 generation. physical_trimmed_seq and the
-- legacy cut fields stay frozen for pfj3: trim remains fail-closed in 013
-- until recovery anchors, restore verification, serving pins, and the signed
-- drill policy prove safety end to end.
CREATE OR REPLACE FUNCTION pfj.journal_generations_freeze() RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  -- 013_managed_history revision of the 012 freeze.
  IF NEW.record_codec IS DISTINCT FROM OLD.record_codec
     OR NEW.control_codec IS DISTINCT FROM OLD.control_codec THEN
    RAISE EXCEPTION
      'journal generation codecs are immutable; conversion is retire + new generation'
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
    IF NEW.physical_trimmed_seq IS DISTINCT FROM OLD.physical_trimmed_seq
       OR NEW.cut_operation_id IS DISTINCT FROM OLD.cut_operation_id
       OR NEW.cut_status IS DISTINCT FROM OLD.cut_status THEN
      RAISE EXCEPTION
        'legacy cut/trim/rotate is not defined for a PFJ3 generation (trim stays fail-closed in 013)'
        USING ERRCODE='PF005';
    END IF;
    IF NEW.base_seq IS DISTINCT FROM OLD.base_seq
       OR NEW.base_digest IS DISTINCT FROM OLD.base_digest
       OR NEW.base_commit_id IS DISTINCT FROM OLD.base_commit_id THEN
      -- The ONLY admitted base advance: performed by the journal owner
      -- (inside pfj.history_adopt_base) AND matched by exactly one
      -- 'applying' adoption proof row for this generation and this exact
      -- old/new tuple INCLUDING the backlog subtraction. Rows, not
      -- settings, authorize.
      IF current_user <> 'portablefs_journal_owner'
         OR NEW.base_seq IS NULL OR NEW.base_seq < OLD.base_seq
         OR NOT EXISTS (
           SELECT 1 FROM pfh.adoptions a
           WHERE a.generation_id = OLD.id
             AND a.state = 'applying'
             AND a.old_base_seq = OLD.base_seq
             AND a.old_base_digest = OLD.base_digest
             AND a.new_base_seq = NEW.base_seq
             AND a.new_base_digest = NEW.base_digest
             AND a.new_base_commit_id = NEW.base_commit_id
             AND OLD.backlog_bytes - NEW.backlog_bytes = a.subtract_backlog_bytes
             AND OLD.backlog_records - NEW.backlog_records = a.subtract_backlog_records) THEN
        RAISE EXCEPTION
          'PFJ3 base advance requires an exact applying adoption proof row'
          USING ERRCODE='PF011';
      END IF;
    ELSIF NEW.backlog_bytes < OLD.backlog_bytes
       OR NEW.backlog_records < OLD.backlog_records THEN
      -- Backlog only shrinks through an adoption base advance.
      RAISE EXCEPTION 'PFJ3 backlog regression without a base advance'
        USING ERRCODE='PF010';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION pfj.journal_generations_freeze() FROM PUBLIC;

-- History-owner read access to generation facts (adoption pins, fenced pin
-- release, status echo).
GRANT SELECT ON TABLE pfj.journal_generations TO portablefs_history_owner;

-- The history owner is the ONLY caller of the four primitives.
GRANT EXECUTE ON FUNCTION
  pfj.history_head_capture(TEXT,TEXT,TEXT),
  pfj.history_read_records(TEXT,BIGINT,BIGINT,INT,BIGINT),
  pfj.history_adopt_base(TEXT),
  pfj.history_conversion_finalize(TEXT)
TO portablefs_history_owner;

REVOKE ALL ON FUNCTION
  pfj.history_head_capture(TEXT,TEXT,TEXT),
  pfj.history_read_records(TEXT,BIGINT,BIGINT,INT,BIGINT),
  pfj.history_adopt_base(TEXT),
  pfj.history_conversion_finalize(TEXT)
FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION D: grants + postconditions ═══════════════════════════════════════

-- The branch guard trigger (SECURITY INVOKER) reads pfh.conversions as
-- whatever role fired the UPDATE; the metadata/migration user evaluates it
-- for legacy manifest head moves.
DO $$
BEGIN
  EXECUTE format('GRANT USAGE ON SCHEMA pfh TO %I', CURRENT_USER);
  EXECUTE format('GRANT SELECT ON TABLE pfh.conversions, pfh.adoptions TO %I', CURRENT_USER);
END
$$;

-- Worker surface (claim-fenced; no tables). Exactly 28 functions — the
-- postcondition audits this DIRECT grant count via aclexplode.
GRANT EXECUTE ON FUNCTION
  pfh.cut_claim(TEXT,INT,BIGINT),
  pfh.cut_heartbeat(TEXT,BIGINT,TEXT,BIGINT,JSONB),
  pfh.cut_retry(TEXT,BIGINT,JSONB,BIGINT),
  pfh.cut_fail(TEXT,BIGINT,JSONB),
  pfh.cut_read_page(TEXT,BIGINT,BIGINT,INT,BIGINT),
  pfh.object_intend(TEXT,BIGINT,JSONB),
  pfh.object_copy_receipt(TEXT,BIGINT,TEXT,BIGINT,TEXT,TEXT,BIGINT),
  pfh.cut_objects_add(TEXT,BIGINT,TEXT,TEXT[]),
  pfh.cut_mark_ready(TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT),
  pfh.object_locate(TEXT,TEXT,TEXT),
  pfh.legacy_blob_locate(TEXT,BIGINT,TEXT),
  pfh.legacy_chain_prepare(TEXT,BIGINT),
  pfh.legacy_chain_apply_page(TEXT,BIGINT,INT),
  pfh.legacy_assign_ords(TEXT,BIGINT,INT),
  pfh.legacy_assign_inos(TEXT,BIGINT,INT),
  pfh.legacy_tree_hash_verify(TEXT,BIGINT,TEXT),
  pfh.legacy_entries_page(TEXT,BIGINT,BIGINT,INT),
  pfh.legacy_import_cursor_put(TEXT,BIGINT,JSONB),
  pfh.legacy_import_cursor_get(TEXT,BIGINT),
  pfh.worker_beat(TEXT,TEXT[],JSONB),
  pfh.scrub_claim(TEXT,INT),
  pfh.scrub_receipt(TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,BIGINT,BOOLEAN,BIGINT,TEXT),
  pfh.repair_claim(TEXT,INT,BIGINT),
  pfh.repair_receipt(TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,BIGINT,TEXT,BIGINT),
  pfh.sweep_preview(INT),
  pfh.sweep_claim(TEXT,BIGINT,BIGINT),
  pfh.sweep_complete(TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,BIGINT,JSONB),
  pfh.sweep_release(TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TEXT)
TO portablefs_history_worker;

-- The history-worker deployment may drive the loop with the SAME admin DSN
-- the repository uses (the migration user already owns every public table,
-- so this grant subtracts nothing); a hardened deployment uses a LOGIN role
-- granted portablefs_history_worker instead and skips this.
-- Explicit direct membership (see the owner GRANT above for why a bare,
-- unguarded, idempotent GRANT is correct: pg_has_role would skip it for a
-- superuser migration user and hide the direct edge the role-graph audit
-- requires).
DO $$
BEGIN
  EXECUTE format('GRANT portablefs_history_worker TO %I', CURRENT_USER);
END
$$;

-- Metadata/caller surface (the volume-api repository's admin DSN role).
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfh.cut_create(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB),
    pfh.cut_status(TEXT,TEXT),
    pfh.cut_cancel(TEXT,TEXT,TEXT,TEXT),
    pfh.consumer_attach(TEXT,TEXT,TEXT,TEXT),
    pfh.consumer_release(TEXT,TEXT,TEXT),
    pfh.inode_namespace_issue(TEXT,TEXT,TEXT,TEXT),
    pfh.conversion_begin(TEXT,TEXT,TEXT,TEXT,TEXT),
    pfh.conversion_status(TEXT,TEXT),
    pfh.conversion_attach_final_cut(TEXT,TEXT,TEXT),
    pfh.conversion_finalize(TEXT,TEXT,TEXT,TEXT),
    pfh.conversion_abort(TEXT,TEXT,TEXT,TEXT,JSONB),
    pfh.conversion_retry(TEXT,TEXT,TEXT,TEXT),
    pfh.cut_adopt(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT),
    pfh.serving_pin_ack(TEXT,TEXT,BIGINT,TEXT),
    pfh.serving_pin_release_fenced(TEXT),
    pfh.object_locate(TEXT,TEXT,TEXT),
    pfh.pft2_commit_provenance(TEXT,TEXT),
    pfh.resource_operation_get(TEXT,TEXT,TEXT),
    pfh.resource_operation_compact(BIGINT,INT),
    pfh.install_history_policy(TEXT,BIGINT),
    pfh.history_freshness_audit(),
    pfh.restore_audit()
    TO %I', CURRENT_USER);
END
$$;

-- Auditor surface: exactly the two pure zero-argument STABLE audits.
GRANT EXECUTE ON FUNCTION
  pfh.restore_audit(),
  pfh.history_freshness_audit()
TO portablefs_history_auditor;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  -- commit_kind exists with the frozen default.
  SELECT column_default INTO v_rec FROM information_schema.columns
    WHERE table_schema='public' AND table_name='commits' AND column_name='commit_kind';
  IF NOT FOUND OR v_rec.column_default NOT LIKE '%manifest_v1%' THEN
    RAISE EXCEPTION '013 postcondition: commits.commit_kind default manifest_v1 is missing';
  END IF;
  -- No pre-existing commit was reclassified.
  SELECT COUNT(*) INTO v_count FROM public.commits WHERE commit_kind <> 'manifest_v1';
  IF v_count > 0 THEN
    RAISE EXCEPTION '013 postcondition: % commits are not manifest_v1 at migration time', v_count;
  END IF;
  -- Replaced triggers still exist and carry the 013 revisions.
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='journal_generations_freeze')
     OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='portablefs_branch_guard') THEN
    RAISE EXCEPTION '013 postcondition: a replaced guard trigger is missing';
  END IF;
  IF position('013_managed_history revision' IN pg_get_functiondef(
       'public.portablefs_branch_guard()'::regprocedure)) = 0 THEN
    RAISE EXCEPTION '013 postcondition: branch guard was not replaced by 013';
  END IF;
  IF position('013_managed_history revision' IN pg_get_functiondef(
       'pfj.journal_generations_freeze()'::regprocedure)) = 0 THEN
    RAISE EXCEPTION '013 postcondition: journal freeze was not replaced by 013';
  END IF;
  -- Every pfh function: owned by the history owner with a pinned search_path;
  -- the audits are STABLE and zero-argument.
  FOR v_rec IN
    SELECT p.proname, pg_get_userbyid(p.proowner) AS owner,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh'
  LOOP
    IF v_rec.owner <> 'portablefs_history_owner' THEN
      RAISE EXCEPTION '013 postcondition: pfh.% is owned by %', v_rec.proname, v_rec.owner;
    END IF;
    IF v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '013 postcondition: pfh.% has no pinned search_path', v_rec.proname;
    END IF;
  END LOOP;
  FOR v_rec IN
    SELECT p.proname, p.provolatile, p.pronargs FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pfh' AND p.proname IN ('restore_audit','history_freshness_audit')
  LOOP
    IF v_rec.provolatile <> 's' OR v_rec.pronargs <> 0 THEN
      RAISE EXCEPTION '013 postcondition: pfh.% must be STABLE with zero arguments',
        v_rec.proname;
    END IF;
  END LOOP;
  -- No PUBLIC execute anywhere in pfh (aclexplode over DIRECT ACL entries;
  -- proacl NULL would mean the built-in default that includes PUBLIC —
  -- the owner-level default-privileges revoke makes it non-NULL).
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    LEFT JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh'
      AND (p.proacl IS NULL OR (acl.grantee = 0 AND acl.privilege_type='EXECUTE'));
  IF v_count > 0 THEN
    RAISE EXCEPTION '013 postcondition: % pfh functions are PUBLIC-executable', v_count;
  END IF;
  -- Exact worker ACL: the worker executes exactly 28 pfh functions (DIRECT
  -- grants) and holds no table privileges anywhere.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh'
      AND acl.grantee = 'portablefs_history_worker'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 28 THEN
    RAISE EXCEPTION '013 postcondition: worker EXECUTE surface is % (want 28)', v_count;
  END IF;
  SELECT COUNT(*) INTO v_count
    FROM information_schema.table_privileges
    WHERE grantee='portablefs_history_worker';
  IF v_count > 0 THEN
    RAISE EXCEPTION '013 postcondition: worker holds % table privileges', v_count;
  END IF;
  -- Exact auditor ACL: exactly the two audits, by DIRECT grant.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname IN ('pfh','pfj','pfm','public')
      AND acl.grantee = 'portablefs_history_auditor'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count <> 2 THEN
    RAISE EXCEPTION '013 postcondition: auditor EXECUTE surface is % (want 2)', v_count;
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_proc p
      JOIN pg_namespace n ON n.oid=p.pronamespace
      JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
      WHERE n.nspname='pfh' AND p.proname='restore_audit'
        AND acl.grantee='portablefs_history_auditor'::regrole
        AND acl.privilege_type='EXECUTE')
     OR NOT EXISTS (
      SELECT 1 FROM pg_proc p
      JOIN pg_namespace n ON n.oid=p.pronamespace
      JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
      WHERE n.nspname='pfh' AND p.proname='history_freshness_audit'
        AND acl.grantee='portablefs_history_auditor'::regrole
        AND acl.privilege_type='EXECUTE') THEN
    RAISE EXCEPTION '013 postcondition: auditor grants do not name the two audits';
  END IF;
  -- The authority role gained NOTHING in pfh.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE n.nspname='pfh'
      AND acl.grantee = 'portablefs_authority'::regrole
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '013 postcondition: authority role can execute % pfh functions', v_count;
  END IF;
  -- The corrected 012 grant is present.
  IF NOT has_column_privilege('portablefs_journal_owner',
       'public.branches', 'branch_mode', 'UPDATE') THEN
    RAISE EXCEPTION '013 postcondition: journal owner branch_mode UPDATE grant is missing';
  END IF;
  -- Legacy work paths compare bytewise.
  SELECT collation_name INTO v_rec FROM information_schema.columns
    WHERE table_schema='pfh' AND table_name='legacy_work_entries' AND column_name='path';
  IF NOT FOUND OR v_rec.collation_name IS DISTINCT FROM 'C' THEN
    RAISE EXCEPTION '013 postcondition: legacy_work_entries.path must be COLLATE "C"';
  END IF;
  -- Lineage: 014/015 remain absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations
             WHERE id LIKE '014%' OR id LIKE '015%') THEN
    RAISE EXCEPTION '013 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
