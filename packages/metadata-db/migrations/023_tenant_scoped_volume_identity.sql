-- 023_tenant_scoped_volume_identity
--
-- A public volume id is unique inside its authenticated tenant, not across a
-- deployment. The previous volumes(id) primary key leaked another tenant's
-- namespace through VOLUME_ALREADY_EXISTS and made an organization-local
-- control-plane name impossible to represent faithfully.
--
-- This migration makes (tenant_id,id) the root key and carries tenant_id onto
-- every public child that stores volume_id. Composite foreign keys make an
-- accidental unqualified/cross-tenant association impossible in the database,
-- while tenant-leading indexes keep every API lookup O(log n).

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations
    WHERE id='022_retire_cut_cleanup'
  ) THEN
    RAISE EXCEPTION '023 preflight: 022_retire_cut_cleanup receipt is missing';
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='branches'
      AND column_name='tenant_id'
  ) THEN
    RAISE EXCEPTION '023 preflight: public child tenant columns already exist';
  END IF;
END;
$preflight$;

-- Backfill while volumes.id is still globally unique. No guessed/default
-- tenant is ever written.
ALTER TABLE public.commits ADD COLUMN tenant_id TEXT;
ALTER TABLE public.branches ADD COLUMN tenant_id TEXT;
ALTER TABLE public.attach_sessions ADD COLUMN tenant_id TEXT;
ALTER TABLE public.leases ADD COLUMN tenant_id TEXT;
ALTER TABLE public.snapshots ADD COLUMN tenant_id TEXT;
ALTER TABLE public.packs ADD COLUMN tenant_id TEXT;
ALTER TABLE public.path_delegations ADD COLUMN tenant_id TEXT;
ALTER TABLE public.commit_receipts ADD COLUMN tenant_id TEXT;

UPDATE public.commits c SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=c.volume_id;
UPDATE public.branches b SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=b.volume_id;
UPDATE public.attach_sessions s SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=s.volume_id;
UPDATE public.leases l SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=l.volume_id;
UPDATE public.snapshots s SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=s.volume_id;
UPDATE public.packs p SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=p.volume_id;
UPDATE public.path_delegations d SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=d.volume_id;
UPDATE public.commit_receipts r SET tenant_id=v.tenant_id
  FROM public.volumes v WHERE v.id=r.volume_id;

DO $backfill$
BEGIN
  IF EXISTS (SELECT 1 FROM public.commits WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.branches WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.attach_sessions WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.leases WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.snapshots WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.packs WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.path_delegations WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM public.commit_receipts WHERE tenant_id IS NULL) THEN
    RAISE EXCEPTION '023 backfill: a public volume child has no owning tenant';
  END IF;
END;
$backfill$;

ALTER TABLE public.commits ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.branches ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.attach_sessions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.leases ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.snapshots ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.packs ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.path_delegations ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE public.commit_receipts ALTER COLUMN tenant_id SET NOT NULL;

-- Remove every dependency on the old global key before replacing it.
ALTER TABLE public.branches DROP CONSTRAINT branches_volume_id_fkey;
ALTER TABLE public.attach_sessions DROP CONSTRAINT attach_sessions_volume_id_fkey;
ALTER TABLE public.leases DROP CONSTRAINT leases_volume_id_fkey;
ALTER TABLE public.snapshots DROP CONSTRAINT snapshots_volume_id_fkey;
ALTER TABLE public.packs DROP CONSTRAINT packs_volume_id_fkey;
ALTER TABLE public.path_delegations DROP CONSTRAINT path_delegations_volume_id_fkey;
ALTER TABLE public.commit_receipts DROP CONSTRAINT commit_receipts_volume_id_fkey;
ALTER TABLE pfj.journal_generations DROP CONSTRAINT journal_generations_volume_id_fkey;
ALTER TABLE pfj.opstate DROP CONSTRAINT opstate_volume_id_fkey;

ALTER TABLE public.volumes DROP CONSTRAINT volumes_pkey;
ALTER TABLE public.volumes
  ADD CONSTRAINT volumes_pkey PRIMARY KEY (tenant_id,id);

ALTER TABLE public.branches DROP CONSTRAINT branches_volume_id_name_key;
ALTER TABLE public.branches
  ADD CONSTRAINT branches_tenant_volume_name_key
  UNIQUE (tenant_id,volume_id,name);
ALTER TABLE public.branches
  ADD CONSTRAINT branches_tenant_volume_id_key
  UNIQUE (tenant_id,volume_id,id);
ALTER TABLE public.branches
  ADD CONSTRAINT branches_volume_id_id_key
  UNIQUE (volume_id,id);

ALTER TABLE public.branches
  ADD CONSTRAINT branches_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.commits
  ADD CONSTRAINT commits_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.attach_sessions
  ADD CONSTRAINT attach_sessions_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.leases
  ADD CONSTRAINT leases_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.snapshots
  ADD CONSTRAINT snapshots_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.packs
  ADD CONSTRAINT packs_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.path_delegations
  ADD CONSTRAINT path_delegations_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE public.commit_receipts
  ADD CONSTRAINT commit_receipts_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id);
ALTER TABLE pfj.journal_generations
  ADD CONSTRAINT journal_generations_tenant_volume_fkey
  FOREIGN KEY (tenant_id,volume_id)
  REFERENCES public.volumes(tenant_id,id) ON DELETE CASCADE;

-- A branch id is server-minted and globally unique, but volume ids are not.
-- Bind every row that carries all three coordinates to the same composite
-- branch identity. The commit relation is deferred because volume/branch
-- creation deliberately inserts the initial commit before its branch row.
ALTER TABLE public.commits
  ADD CONSTRAINT commits_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id)
  DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE public.attach_sessions
  ADD CONSTRAINT attach_sessions_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id);
ALTER TABLE public.leases
  ADD CONSTRAINT leases_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id);
ALTER TABLE public.snapshots
  ADD CONSTRAINT snapshots_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id);
ALTER TABLE public.path_delegations
  ADD CONSTRAINT path_delegations_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id);
ALTER TABLE public.commit_receipts
  ADD CONSTRAINT commit_receipts_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id);
ALTER TABLE pfj.journal_generations
  ADD CONSTRAINT journal_generations_tenant_volume_branch_fkey
  FOREIGN KEY (tenant_id,volume_id,branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id);
ALTER TABLE public.volumes
  ADD CONSTRAINT volumes_tenant_default_branch_fkey
  FOREIGN KEY (tenant_id,id,default_branch_id)
  REFERENCES public.branches(tenant_id,volume_id,id)
  DEFERRABLE INITIALLY DEFERRED;

-- opstate is already bound to a globally unique branch id. Prove volume
-- coherence without adding an otherwise redundant tenant column.
ALTER TABLE pfj.opstate
  ADD CONSTRAINT opstate_volume_branch_fkey
  FOREIGN KEY (volume_id,branch_id)
  REFERENCES public.branches(volume_id,id) ON DELETE CASCADE;

-- Tenant-leading hot paths replace volume-only indexes. Entity-id indexes and
-- globally unique server-minted ids remain unchanged.
DROP INDEX public.commits_by_volume_created;
CREATE INDEX commits_by_tenant_volume_created
  ON public.commits(tenant_id,volume_id,created_at,id);
DROP INDEX public.snapshots_by_volume_created;
CREATE INDEX snapshots_by_tenant_volume_created
  ON public.snapshots(tenant_id,volume_id,created_at,id);
CREATE INDEX packs_by_tenant_volume
  ON public.packs(tenant_id,volume_id,id);
CREATE INDEX path_delegations_by_tenant_volume
  ON public.path_delegations(tenant_id,volume_id,branch_id);
CREATE INDEX commit_receipts_by_tenant_volume
  ON public.commit_receipts(tenant_id,volume_id);
CREATE INDEX journal_generations_by_tenant_volume_branch
  ON pfj.journal_generations(tenant_id,volume_id,branch_id,epoch DESC);

-- The previous volume-only FK on opstate required volumes(id) to be unique.
-- Its composite branch FK now supplies both integrity and cascade.

-- Forward-rewrite the checked lineage's owner functions. pg_get_functiondef
-- keeps the complete, security-reviewed bodies intact; every replacement is
-- exact and asserted, so a lineage drift aborts rather than installing a
-- partial tenant qualification.
SET LOCAL ROLE portablefs_journal_owner;
DO $journal_functions$
DECLARE
  v_sigs TEXT[] := ARRAY[
    'pfj.generation_binding_check()',
    'pfj.generation_binding_check()',
    'pfj.generation_binding_check()',
    'pfj.generation_binding_check()',
    'pfj.generation_binding_check()',
    'pfj.journal_head(text,text,text)',
    'pfj.journal_head(text,text,text)',
    'pfj.journal_bound_head(text,text,text,bigint,bigint,text,text)',
    'pfj.journal_bound_head(text,text,text,bigint,bigint,text,text)',
    'pfj.journal_claim_core(text,text,text,text,text,text,bigint,text,text,text,bigint,bigint,text,text,bigint,bigint,text,text)',
    'pfj.journal_claim_core(text,text,text,text,text,text,bigint,text,text,text,bigint,bigint,text,text,bigint,bigint,text,text)',
    'pfj.branch_provisioning(text,text,text,bigint,bigint,text,text)',
    'pfj.branch_provisioning(text,text,text,bigint,bigint,text,text)',
    'pfj.branch_mode_transition(text,text,text,text,text)',
    'pfj.branch_mode_transition(text,text,text,text,text)',
    'pfj.history_head_capture(text,text,text)'
  ];
  v_olds TEXT[] := ARRAY[
    'WHERE v.id = NEW.volume_id;',
    'SELECT b.volume_id INTO v_branch_volume FROM public.branches b WHERE b.id = NEW.branch_id;',
    'SELECT c.volume_id INTO v_commit_volume FROM public.commits c WHERE c.id = NEW.base_commit_id;',
    'FROM public.attach_sessions s WHERE s.id = NEW.attach_session_id;',
    'FROM public.leases l WHERE l.id = NEW.lease_id;',
    'WHERE b.volume_id = p_volume_id AND b.name = p_branch_name AND v.tenant_id = p_tenant_id;',
    'JOIN public.volumes v ON v.id = b.volume_id',
    'WHERE v.id=p_volume_id FOR SHARE;',
    'WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;',
    'WHERE v.id=p_volume_id FOR SHARE;',
    'WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR UPDATE;',
    'WHERE v.id=p_volume_id FOR SHARE;',
    'WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;',
    'WHERE v.id=p_volume_id FOR SHARE;',
    'WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR UPDATE;',
    'JOIN public.volumes v ON v.id=b.volume_id
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name'
  ];
  v_news TEXT[] := ARRAY[
    'WHERE v.tenant_id = NEW.tenant_id AND v.id = NEW.volume_id;',
    'SELECT b.volume_id INTO v_branch_volume FROM public.branches b
    WHERE b.tenant_id = NEW.tenant_id AND b.volume_id = NEW.volume_id
      AND b.id = NEW.branch_id;',
    'SELECT c.volume_id INTO v_commit_volume FROM public.commits c
    WHERE c.tenant_id = NEW.tenant_id AND c.volume_id = NEW.volume_id
      AND c.id = NEW.base_commit_id;',
    'FROM public.attach_sessions s
      WHERE s.tenant_id = NEW.tenant_id AND s.volume_id = NEW.volume_id
        AND s.id = NEW.attach_session_id;',
    'FROM public.leases l
      WHERE l.tenant_id = NEW.tenant_id AND l.volume_id = NEW.volume_id
        AND l.id = NEW.lease_id;',
    'WHERE b.tenant_id = p_tenant_id AND b.volume_id = p_volume_id AND b.name = p_branch_name AND v.tenant_id = p_tenant_id;',
    'JOIN public.volumes v
      ON v.tenant_id = b.tenant_id AND v.id = b.volume_id',
    'WHERE v.tenant_id=p_tenant_id AND v.id=p_volume_id FOR SHARE;',
    'WHERE b.tenant_id=p_tenant_id AND b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;',
    'WHERE v.tenant_id=p_tenant_id AND v.id=p_volume_id FOR SHARE;',
    'WHERE b.tenant_id=p_tenant_id AND b.volume_id=p_volume_id AND b.name=p_branch_name FOR UPDATE;',
    'WHERE v.tenant_id=p_tenant_id AND v.id=p_volume_id FOR SHARE;',
    'WHERE b.tenant_id=p_tenant_id AND b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;',
    'WHERE v.tenant_id=p_tenant_id AND v.id=p_volume_id FOR SHARE;',
    'WHERE b.tenant_id=p_tenant_id AND b.volume_id=p_volume_id AND b.name=p_branch_name FOR UPDATE;',
    'JOIN public.volumes v ON v.tenant_id=b.tenant_id AND v.id=b.volume_id
    WHERE b.tenant_id=p_tenant_id AND b.volume_id=p_volume_id AND b.name=p_branch_name'
  ];
  v_oid REGPROCEDURE;
  v_def TEXT;
  v_next TEXT;
  i INTEGER;
BEGIN
  FOR i IN 1..array_length(v_sigs,1) LOOP
    v_oid := to_regprocedure(v_sigs[i]);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION '023 journal rewrite: function % is missing', v_sigs[i];
    END IF;
    v_def := pg_get_functiondef(v_oid);
    v_next := replace(v_def, v_olds[i], v_news[i]);
    IF v_next=v_def THEN
      RAISE EXCEPTION '023 journal rewrite: expected source not found in %', v_sigs[i];
    END IF;
    EXECUTE v_next;
  END LOOP;
END;
$journal_functions$;
RESET ROLE;

SET LOCAL ROLE portablefs_manager_owner;
DO $manager_functions$
DECLARE
  v_oid REGPROCEDURE := to_regprocedure('pfm.require_scope_tenant(text,text)');
  v_def TEXT;
  v_next TEXT;
BEGIN
  IF v_oid IS NULL THEN
    RAISE EXCEPTION '023 manager rewrite: pfm.require_scope_tenant is missing';
  END IF;
  v_def := pg_get_functiondef(v_oid);
  v_next := replace(
    v_def,
    'FROM public.volumes v WHERE v.id = p_volume_id;',
    'FROM public.volumes v
    WHERE (''t:'' || v.tenant_id) = p_tenant_key
      AND v.id = p_volume_id;');
  IF v_next=v_def THEN
    RAISE EXCEPTION '023 manager rewrite: expected ownership source not found';
  END IF;
  EXECUTE v_next;
END;
$manager_functions$;
RESET ROLE;

SET LOCAL ROLE portablefs_history_owner;
DO $history_functions$
DECLARE
  v_sigs TEXT[] := ARRAY[
    'pfh.conversion_begin(text,text,text,text,text)',
    'pfh.pft2_fork_commit_install(text,text,text,text,text,text)',
    'pfh.pft2_fork_commit_install(text,text,text,text,text,text)',
    'pfh.pft2_fork_commit_install(text,text,text,text,text,text)',
    'pfh.volume_fork_from_cut(text,text,text,text,text,text)',
    'pfh.volume_fork_from_cut(text,text,text,text,text,text)',
    'pfh.volume_fork_from_cut(text,text,text,text,text,text)',
    'pfh.volume_fork_from_cut(text,text,text,text,text,text)',
    'pfh.volume_fork_from_cut(text,text,text,text,text,text)',
    'pfh.volume_fork_from_cut(text,text,text,text,text,text)',
    'pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)',
    'pfh.cut_mark_ready(text,bigint,text,bigint,text,bigint,text,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)',
    'pfh.serving_base_prove(text,text,text,bigint,text,text,text)'
  ];
  v_olds TEXT[] := ARRAY[
    'FROM public.branches b JOIN public.volumes v ON v.id=b.volume_id
    WHERE b.volume_id=p_volume AND b.name=p_branch_name;',
    'FROM public.volumes v WHERE v.id=p_dest_volume_id;',
    'WHERE br.id=p_dest_branch_id AND br.volume_id=p_dest_volume_id;',
    'WHERE id=p_dest_commit_id AND volume_id=p_dest_volume_id;',
    'IF EXISTS (SELECT 1 FROM public.volumes WHERE id=v_volume) THEN',
    'id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,',
    'VALUES (v_commit_id, v_volume, v_branch_id, c.result_commit_id,',
    'id, volume_id, name, head_commit_id, created_at, updated_at, branch_mode)',
    'VALUES (v_branch_id, v_volume, p_branch_name, v_commit_id, v_now, v_now,',
    'UPDATE public.volumes SET default_branch_id=v_branch_id WHERE id=v_volume;',
    'id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,',
    'v_commit_id, c.volume_id, c.branch_id,',
    'JOIN public.volumes v ON v.id=c.volume_id
    WHERE c.id=p_commit_id AND c.volume_id=g.volume_id AND v.tenant_id=p_tenant;'
  ];
  v_news TEXT[] := ARRAY[
    'FROM public.branches b JOIN public.volumes v
      ON v.tenant_id=b.tenant_id AND v.id=b.volume_id
    WHERE b.tenant_id=p_tenant AND b.volume_id=p_volume AND b.name=p_branch_name;',
    'FROM public.volumes v
    WHERE v.tenant_id=p_tenant AND v.id=p_dest_volume_id;',
    'WHERE br.tenant_id=p_tenant AND br.id=p_dest_branch_id AND br.volume_id=p_dest_volume_id;',
    'WHERE tenant_id=p_tenant AND id=p_dest_commit_id AND volume_id=p_dest_volume_id;',
    'IF EXISTS (SELECT 1 FROM public.volumes WHERE tenant_id=p_tenant AND id=v_volume) THEN',
    'id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,',
    'VALUES (v_commit_id, p_tenant, v_volume, v_branch_id, c.result_commit_id,',
    'id, tenant_id, volume_id, name, head_commit_id, created_at, updated_at, branch_mode)',
    'VALUES (v_branch_id, p_tenant, v_volume, p_branch_name, v_commit_id, v_now, v_now,',
    'UPDATE public.volumes SET default_branch_id=v_branch_id
    WHERE tenant_id=p_tenant AND id=v_volume;',
    'id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,',
    'v_commit_id, c.tenant_id, c.volume_id, c.branch_id,',
    'JOIN public.volumes v
      ON v.tenant_id=c.tenant_id AND v.id=c.volume_id
    WHERE c.tenant_id=p_tenant AND c.id=p_commit_id
      AND c.volume_id=g.volume_id;'
  ];
  v_oid REGPROCEDURE;
  v_def TEXT;
  v_next TEXT;
  i INTEGER;
BEGIN
  FOR i IN 1..array_length(v_sigs,1) LOOP
    v_oid := to_regprocedure(v_sigs[i]);
    IF v_oid IS NULL THEN
      RAISE EXCEPTION '023 history rewrite: function % is missing', v_sigs[i];
    END IF;
    v_def := pg_get_functiondef(v_oid);
    v_next := replace(v_def, v_olds[i], v_news[i]);
    IF v_next=v_def THEN
      RAISE EXCEPTION '023 history rewrite: expected source not found in %', v_sigs[i];
    END IF;
    EXECUTE v_next;
  END LOOP;
END;
$history_functions$;
RESET ROLE;

DO $post$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint c
    JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
    WHERE n.nspname='public' AND r.relname='volumes'
      AND c.conname='volumes_pkey' AND c.contype='p'
      AND pg_catalog.pg_get_constraintdef(c.oid)
        = 'PRIMARY KEY (tenant_id, id)'
  ) THEN
    RAISE EXCEPTION '023 postcondition: composite volumes primary key missing';
  END IF;
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_constraint
    WHERE conname IN (
      'commits_tenant_volume_branch_fkey',
      'attach_sessions_tenant_volume_branch_fkey',
      'leases_tenant_volume_branch_fkey',
      'snapshots_tenant_volume_branch_fkey',
      'path_delegations_tenant_volume_branch_fkey',
      'commit_receipts_tenant_volume_branch_fkey',
      'journal_generations_tenant_volume_branch_fkey',
      'volumes_tenant_default_branch_fkey'
    )
  ) <> 8 THEN
    RAISE EXCEPTION '023 postcondition: tenant/volume/branch integrity set incomplete';
  END IF;
  IF EXISTS (
    SELECT id FROM public.volumes
    GROUP BY tenant_id,id HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION '023 postcondition: duplicate tenant-local volume id';
  END IF;
END;
$post$;
