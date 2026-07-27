-- 017_history_maintenance: read surface for the journal-bounding maintenance
-- loop (backlog threshold scan + unreleased serving-pin scan).
--
-- PFJ3 generations are admission-bounded (012: data quota plus the fixed
-- control reserve) and RESUMED — never rotated — across child restarts, so a
-- branch's backlog persists for its lifetime. The ONLY admitted shrink is
-- history-cut adoption (013: pfh.cut_adopt -> pfj.history_adopt_base), which
-- advances the base tuple and subtracts the captured cumulative backlog in
-- O(1). Without a driver calling that machinery, every managed branch's
-- backlog grows until the quota bricks its writes.
--
-- The volume-api's maintenance loop is that driver. Its MUTATIONS already
-- exist and stay unchanged (cut_create / cut_status / cut_adopt /
-- serving_pin_release_fenced, granted to the metadata caller role by 013).
-- What the caller role lacks is a READ surface to decide WHERE to drive:
-- pfj.journal_generations and pfh.serving_base_pins are owner-private
-- tables. This migration adds exactly two SECURITY DEFINER read projections:
--
--   pfj.generations_past_threshold(percent, limit)
--       live (active/suspended) PFJ3 generations whose cumulative backlog
--       has reached the given percent of the generation quota — bytes OR
--       records, whichever crosses first. Bounded, worst-first.
--   pfh.serving_pins_unreleased(limit)
--       adoption serving pins with no released_db_ms. The loop offers each
--       to pfh.serving_pin_release_fenced, which releases ONLY on provable
--       durable supersession (advanced writer fence, terminal generation,
--       released/expired writer lease) — refusal is the expected answer for
--       a live pinned runtime and stays a typed PF011.
--
-- Both are STABLE single-statement reads: no locks beyond MVCC row reads, no
-- mutation, no advisory keys — the append lock order is never entered, so
-- the scan can run on every volume-api replica concurrently without touching
-- live write latency. All external BIGINTs serialize as canonical decimal
-- TEXT (same discipline as every pfj/pfh projection).
--
-- SECURITY MODEL (extends 009/013; same discipline): each function is owned
-- by the schema's owner role (portablefs_journal_owner / _history_owner),
-- carries a pinned search_path, loses PUBLIC EXECUTE through the owner-level
-- default-privileges revoke installed by 009/013, and is EXECUTE-granted to
-- the migration user (the volume-api repository's admin DSN role) exactly
-- like the 013 caller surface. The authority, worker, and auditor roles gain
-- nothing.
--
-- ERROR SQLSTATES: shared PF0xx vocabulary (PF008 invalid argument).

-- ─── Preflight ────────────────────────────────────────────────────────────────
DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='016_pooler_timeouts'
  ) THEN
    RAISE EXCEPTION '017 preflight: 016_pooler_timeouts receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '018%'
  ) THEN
    RAISE EXCEPTION '017 preflight: a later migration receipt exists';
  END IF;
  IF to_regclass('pfj.journal_generations') IS NULL THEN
    RAISE EXCEPTION '017 preflight: the 012 PFJ3 generation table is missing';
  END IF;
  IF to_regclass('pfh.serving_base_pins') IS NULL THEN
    RAISE EXCEPTION '017 preflight: the 013 serving pin table is missing';
  END IF;
END;
$preflight$;

-- ═══ SECTION A: journal-owner backlog projection (pfj) ════════════════════════
SET LOCAL ROLE portablefs_journal_owner;

-- Live PFJ3 generations whose backlog has reached p_backlog_percent of the
-- generation quota (bytes OR records — whichever ratio crosses first),
-- worst-first. Percent arithmetic stays in BIGINT multiplication form
-- (backlog*100 >= quota*percent): no division, no overflow inside int64 for
-- any realistic quota. The projected backlogPercent is display-only and
-- floor-divided; a zero/absent quota (structurally impossible via
-- journal_claim_v3's COALESCE defaults, but never trusted) projects as 100.
-- Retiring/retired generations are deliberately excluded: their prefix is
-- owned by the 013 conversion/retire machinery, not by recovery adoption.
CREATE FUNCTION pfj.generations_past_threshold(
  p_backlog_percent INT, p_limit INT
) RETURNS SETOF JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,256),1),1024);
BEGIN
  IF p_backlog_percent IS NULL
     OR p_backlog_percent < 1 OR p_backlog_percent > 100 THEN
    RAISE EXCEPTION 'backlog threshold percent must be in 1..100'
      USING ERRCODE='PF008';
  END IF;
  RETURN QUERY
    SELECT jsonb_build_object(
      'tenantId', g.tenant_id,
      'volumeId', g.volume_id,
      'branchId', g.branch_id,
      'branchName', b.name,
      'generationId', g.id,
      'journalEpoch', g.epoch::TEXT,
      'status', g.status,
      'baseSeq', g.base_seq::TEXT,
      'nextSeq', g.next_seq::TEXT,
      'backlogBytes', g.backlog_bytes::TEXT,
      'backlogRecords', g.backlog_records::TEXT,
      'quotaBacklogBytes', g.quota_backlog_bytes::TEXT,
      'quotaBacklogRecords', g.quota_backlog_records::TEXT,
      'backlogPercent', GREATEST(
        CASE WHEN g.quota_backlog_bytes > 0
          THEN (g.backlog_bytes * 100) / g.quota_backlog_bytes ELSE 100 END,
        CASE WHEN g.quota_backlog_records > 0
          THEN (g.backlog_records * 100) / g.quota_backlog_records ELSE 100 END))
    FROM pfj.journal_generations g
    JOIN public.branches b ON b.id = g.branch_id
    WHERE g.record_codec = 'pfj3'
      AND g.status IN ('active','suspended')
      AND (g.backlog_bytes * 100 >= g.quota_backlog_bytes * p_backlog_percent
           OR g.backlog_records * 100 >= g.quota_backlog_records * p_backlog_percent)
    ORDER BY GREATEST(
        CASE WHEN g.quota_backlog_bytes > 0
          THEN (g.backlog_bytes * 100) / g.quota_backlog_bytes ELSE 100 END,
        CASE WHEN g.quota_backlog_records > 0
          THEN (g.backlog_records * 100) / g.quota_backlog_records ELSE 100 END) DESC,
      g.id
    LIMIT v_limit;
END;
$$;
REVOKE ALL ON FUNCTION pfj.generations_past_threshold(INT,INT) FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION B: history-owner serving-pin projection (pfh) ════════════════════
SET LOCAL ROLE portablefs_history_owner;

-- Unreleased adoption serving pins, oldest-first. Each pins the pre-adoption
-- base as a GC root until the pinned runtime is provably superseded; the
-- sweep offers every row to pfh.serving_pin_release_fenced and treats its
-- PF011 refusal (runtime still live) as the normal answer.
CREATE FUNCTION pfh.serving_pins_unreleased(p_limit INT) RETURNS SETOF JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_limit INT := LEAST(GREATEST(COALESCE(p_limit,256),1),1024);
BEGIN
  RETURN QUERY
    SELECT jsonb_build_object(
      'adoptionId', sp.adoption_id,
      'tenantId', sp.tenant_id,
      'generationId', sp.generation_id,
      'cutId', sp.cut_id,
      'writerFence', sp.writer_fence::TEXT,
      'createdDbMs', sp.created_db_ms::TEXT)
    FROM pfh.serving_base_pins sp
    WHERE sp.released_db_ms IS NULL
    ORDER BY sp.created_db_ms, sp.adoption_id
    LIMIT v_limit;
END;
$$;
REVOKE ALL ON FUNCTION pfh.serving_pins_unreleased(INT) FROM PUBLIC;

RESET ROLE;

-- ═══ SECTION C: grants + postconditions ═══════════════════════════════════════

-- Metadata/caller surface (the volume-api repository's admin DSN role), the
-- exact 013 grant pattern.
DO $$
BEGIN
  EXECUTE format('GRANT EXECUTE ON FUNCTION
    pfj.generations_past_threshold(INT,INT),
    pfh.serving_pins_unreleased(INT)
    TO %I', CURRENT_USER);
END
$$;

-- ─── Postconditions (exact ACL audit via DIRECT grants) ──────────────────────
DO $post$
DECLARE
  v_rec RECORD;
  v_count BIGINT;
BEGIN
  -- Both projections exist, owned by their schema owners, search_path pinned,
  -- and STABLE (pure reads; the planner may cache them inside one snapshot).
  FOR v_rec IN
    SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner) AS owner,
           p.provolatile,
           COALESCE(array_to_string(p.proconfig,';'),'') AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE (n.nspname='pfj' AND p.proname='generations_past_threshold')
       OR (n.nspname='pfh' AND p.proname='serving_pins_unreleased')
  LOOP
    IF (v_rec.nspname='pfj' AND v_rec.owner <> 'portablefs_journal_owner')
       OR (v_rec.nspname='pfh' AND v_rec.owner <> 'portablefs_history_owner') THEN
      RAISE EXCEPTION '017 postcondition: %.% is owned by %',
        v_rec.nspname, v_rec.proname, v_rec.owner;
    END IF;
    IF v_rec.config NOT LIKE '%search_path%' THEN
      RAISE EXCEPTION '017 postcondition: %.% has no pinned search_path',
        v_rec.nspname, v_rec.proname;
    END IF;
    IF v_rec.provolatile <> 's' THEN
      RAISE EXCEPTION '017 postcondition: %.% must be STABLE',
        v_rec.nspname, v_rec.proname;
    END IF;
  END LOOP;
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE (n.nspname='pfj' AND p.proname='generations_past_threshold')
       OR (n.nspname='pfh' AND p.proname='serving_pins_unreleased');
  IF v_count <> 2 THEN
    RAISE EXCEPTION '017 postcondition: expected exactly 2 projections, found %', v_count;
  END IF;
  -- No PUBLIC execute on either (aclexplode over DIRECT ACL entries; the
  -- owner-level default-privileges revokes from 009/013 make proacl non-NULL).
  SELECT COUNT(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    LEFT JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE ((n.nspname='pfj' AND p.proname='generations_past_threshold')
           OR (n.nspname='pfh' AND p.proname='serving_pins_unreleased'))
      AND (p.proacl IS NULL OR (acl.grantee = 0 AND acl.privilege_type='EXECUTE'));
  IF v_count > 0 THEN
    RAISE EXCEPTION '017 postcondition: % maintenance projections are PUBLIC-executable', v_count;
  END IF;
  -- The restricted roles gained NOTHING here.
  SELECT COUNT(DISTINCT p.oid) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN LATERAL aclexplode(p.proacl) acl ON TRUE
    WHERE ((n.nspname='pfj' AND p.proname='generations_past_threshold')
           OR (n.nspname='pfh' AND p.proname='serving_pins_unreleased'))
      AND acl.grantee IN (
        'portablefs_authority'::regrole,
        'portablefs_history_worker'::regrole,
        'portablefs_history_auditor'::regrole)
      AND acl.privilege_type='EXECUTE';
  IF v_count > 0 THEN
    RAISE EXCEPTION '017 postcondition: a restricted role can execute a maintenance projection';
  END IF;
  -- Lineage: 018 remains absent.
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '018%') THEN
    RAISE EXCEPTION '017 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
