-- 021_volume_retirement: receipted volume retirement (DELETE /v1/volumes/:id).
--
-- volumes.retired_at is the retirement receipt: NULL = live, non-NULL = the
-- instant the volume left service. Retirement is a METADATA fact, enforced at
-- the shared tenant+volume resolution layer (volumeTenant and the joined
-- session/lease/snapshot/commit resolvers treat a retired volume as absent),
-- so every per-volume plane answers the same non-enumerating 404 the moment
-- the flip commits: attach, lease renewal, exec/grep, branch and snapshot
-- create/list, the commit/status/head/wait-head/tree/file/manifest-diff
-- reads, activate-journal, and forks FROM the volume's snapshots. Live
-- authorities are NOT force-detached: their leases/credentials simply stop
-- renewing and expire. Storage reclamation (blobs/history objects) is
-- deliberately deferred — this migration deletes nothing.
--
-- The flip itself is one atomic conditional UPDATE (retired_at IS NULL), so a
-- concurrent second retire loses the race and observes the volume as absent
-- (404). Exactly-once retirement across retries is the hosted control plane's
-- operation ledger, not this layer.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='020_cut_root_high_water'
  ) THEN
    RAISE EXCEPTION '021 preflight: 020_cut_root_high_water receipt is missing; the checked lineage must be a gap-free prefix';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '022%'
  ) THEN
    RAISE EXCEPTION '021 preflight: a later migration receipt exists';
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='volumes' AND column_name='retired_at'
  ) THEN
    RAISE EXCEPTION '021 preflight: volumes.retired_at already exists';
  END IF;
END;
$preflight$;

-- Nullable, no default: every existing and every newly created volume is live.
ALTER TABLE public.volumes ADD COLUMN retired_at TIMESTAMPTZ;

DO $post$
DECLARE
  v_column information_schema.columns%ROWTYPE;
BEGIN
  SELECT * INTO v_column FROM information_schema.columns
  WHERE table_schema='public' AND table_name='volumes' AND column_name='retired_at';
  IF NOT FOUND THEN
    RAISE EXCEPTION '021 postcondition: volumes.retired_at is missing';
  END IF;
  IF v_column.data_type <> 'timestamp with time zone'
     OR v_column.is_nullable <> 'YES'
     OR v_column.column_default IS NOT NULL THEN
    RAISE EXCEPTION '021 postcondition: volumes.retired_at must be a nullable timestamptz with no default';
  END IF;
  IF EXISTS (SELECT 1 FROM public.volumes WHERE retired_at IS NOT NULL) THEN
    RAISE EXCEPTION '021 postcondition: no volume may be born retired by this migration';
  END IF;
  IF EXISTS (SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '022%') THEN
    RAISE EXCEPTION '021 postcondition: later migration receipts must not exist';
  END IF;
END;
$post$;
