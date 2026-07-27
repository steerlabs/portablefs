-- 015_runtime_credentials.sql — manager-minted runtime READ credentials.
--
-- WHY: a managed production child (the per-branch VCS authority) must talk to
-- the volume API as the tenant that owns its volume — for the writer-lease
-- attach, session detach, lease renewal, and content reads during cold
-- replay and serving. A statically configured tenant token can only ever
-- represent ONE tenant, so any volume owned by a different tenant is
-- invisible to the child (the ownership guard answers 404) and the authority
-- can never start. Multi-tenant deployments (any control plane that
-- provisions per-organization tenants) hit this immediately.
--
-- THE MODEL (ported from the reference deployment): the manager generates a
-- random credential secret per child start, the database stores only its
-- SHA-256 bound to the EXACT live authority runtime (pfm.authority_runtimes
-- row) of the scope, and the child receives the raw secret through a private
-- 0600 file (VOLUME_API_TOKEN_FILE) it re-reads on change. The manager
-- re-mints on a timer; resolution fails closed on expiry or revocation. The
-- credential is READ-ONLY at the API layer except the child's own volume's
-- authority lifecycle — the volume API enforces that shape per request.
--
-- The auth_epoch / admission_epoch columns pin the credential to the tenant
-- lifecycle facts it was minted against. This repository does not (yet)
-- install a lifecycle plane, so both are always 1 and resolution requires
-- exactly 1 — a future lifecycle migration narrows resolution without
-- reshaping this table or its callers.

-- ═══ Credential rows (public; owned by the migration/app principal) ═════════

-- The token secret never reaches the database: rows carry its SHA-256 only,
-- plus the exact runtime and epoch facts the credential is bound to.
CREATE TABLE public.runtime_read_credentials (
  credential_hash TEXT PRIMARY KEY CHECK (credential_hash ~ '^[0-9a-f]{64}$'),
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
  volume_id TEXT NOT NULL CHECK (length(volume_id) BETWEEN 1 AND 256),
  branch_name TEXT NOT NULL CHECK (length(branch_name) BETWEEN 1 AND 256),
  manager_epoch BIGINT NOT NULL CHECK (manager_epoch >= 1),
  authority_runtime_seq BIGINT NOT NULL CHECK (authority_runtime_seq >= 1),
  authority_runtime_id TEXT NOT NULL CHECK (length(authority_runtime_id) BETWEEN 1 AND 256),
  auth_epoch BIGINT NOT NULL CHECK (auth_epoch >= 1),
  admission_epoch BIGINT NOT NULL CHECK (admission_epoch >= 1),
  minted_db_ms BIGINT NOT NULL,
  expires_db_ms BIGINT NOT NULL,
  revoked_db_ms BIGINT
);
CREATE INDEX runtime_read_credentials_by_tenant
  ON public.runtime_read_credentials (tenant_id);
CREATE INDEX runtime_read_credentials_by_volume
  ON public.runtime_read_credentials (volume_id);

-- Resolution: NULL on any mismatch — unknown hash, revocation, DB-time
-- expiry, or an epoch binding this deployment cannot verify (only epoch 1
-- exists before a lifecycle plane is installed). Fail-closed by shape: a
-- caller that cannot prove liveness gets nothing, never a stale identity.
CREATE FUNCTION public.runtime_credential_resolve(p_credential_hash TEXT)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT := floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::BIGINT;
  c public.runtime_read_credentials;
BEGIN
  IF p_credential_hash IS NULL OR p_credential_hash !~ '^[0-9a-f]{64}$' THEN
    RETURN NULL;
  END IF;
  SELECT * INTO c FROM public.runtime_read_credentials
    WHERE credential_hash = p_credential_hash;
  IF NOT FOUND OR c.revoked_db_ms IS NOT NULL OR c.expires_db_ms <= v_now THEN
    RETURN NULL;
  END IF;
  IF c.auth_epoch <> 1 OR c.admission_epoch <> 1 THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'tenantId', c.tenant_id, 'volumeId', c.volume_id, 'branchName', c.branch_name,
    'readOnly', TRUE, 'expiresDbMs', c.expires_db_ms::TEXT);
END;
$$;
REVOKE ALL ON FUNCTION public.runtime_credential_resolve(TEXT) FROM PUBLIC;
DO $grant$
BEGIN
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION public.runtime_credential_resolve(TEXT) TO %I',
    CURRENT_USER);
END;
$grant$;

-- The pfm mint function (SECURITY DEFINER, manager-owner) inserts into and
-- re-reads this public table.
GRANT SELECT, INSERT ON public.runtime_read_credentials TO portablefs_manager_owner;

-- ═══ Mint (pfm; owned by portablefs_manager_owner) ══════════════════════════

DO $$
BEGIN
  EXECUTE format('GRANT portablefs_manager_owner TO %I', CURRENT_USER);
END
$$;
SET LOCAL ROLE portablefs_manager_owner;

-- Mint one short-lived runtime read credential, bound to the live manager
-- claim and the LIVE authority runtime of the scope at mint time. The secret
-- never arrives: p_credential_hash is its SHA-256. TTL 60s..1h.
CREATE FUNCTION pfm.runtime_credential_mint(
  p_manager_epoch BIGINT,
  p_manager_runtime_id TEXT,
  p_manager_capability TEXT,
  p_credential_hash TEXT,
  p_tenant_id TEXT,
  p_volume_id TEXT,
  p_branch_name TEXT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_ttl_ms BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_runtime pfm.authority_runtimes;
BEGIN
  PERFORM pfm.require_txn_settings();
  IF p_credential_hash IS NULL OR p_credential_hash !~ '^[0-9a-f]{64}$'
     OR p_tenant_id IS NULL OR length(p_tenant_id) NOT BETWEEN 1 AND 256
     OR p_volume_id IS NULL OR length(p_volume_id) NOT BETWEEN 1 AND 256
     OR p_branch_name IS NULL OR length(p_branch_name) NOT BETWEEN 1 AND 256
     OR p_ttl_ms IS NULL OR p_ttl_ms < 60000 OR p_ttl_ms > 3600000 THEN
    RAISE EXCEPTION 'runtime credential mint arguments are invalid' USING ERRCODE = 'PF008';
  END IF;
  v_now := pfm.require_manager(p_manager_epoch, p_manager_runtime_id, p_manager_capability);
  -- The credential binds the EXACT live runtime of the scope (FOR SHARE
  -- serializes against a concurrent begin/end committing under us). The
  -- managed tenant namespace is canonical: t:<metadata tenant id>.
  SELECT * INTO v_runtime FROM pfm.authority_runtimes
    WHERE tenant_key = 't:' || p_tenant_id AND volume_id = p_volume_id
      AND branch_name = p_branch_name AND state = 'live'
    FOR SHARE;
  IF NOT FOUND
     OR v_runtime.runtime_seq IS DISTINCT FROM p_authority_runtime_seq
     OR v_runtime.runtime_id IS DISTINCT FROM p_authority_runtime_id
     OR v_runtime.manager_epoch IS DISTINCT FROM p_manager_epoch THEN
    RAISE EXCEPTION 'runtime credential does not bind the live authority runtime of %/%/%',
      p_tenant_id, p_volume_id, p_branch_name USING ERRCODE = 'PF001';
  END IF;
  BEGIN
    INSERT INTO public.runtime_read_credentials (
      credential_hash, tenant_id, volume_id, branch_name,
      manager_epoch, authority_runtime_seq, authority_runtime_id,
      auth_epoch, admission_epoch, minted_db_ms, expires_db_ms)
    VALUES (
      p_credential_hash, p_tenant_id, p_volume_id, p_branch_name,
      p_manager_epoch, p_authority_runtime_seq, p_authority_runtime_id,
      1, 1, v_now, v_now + p_ttl_ms);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'runtime credential hash already exists' USING ERRCODE = 'PF002';
  END;
  RETURN jsonb_build_object(
    'tenantId', p_tenant_id, 'volumeId', p_volume_id, 'branchName', p_branch_name,
    'managerEpoch', p_manager_epoch::TEXT,
    'authorityRuntimeSeq', p_authority_runtime_seq::TEXT,
    'authEpoch', '1', 'admissionEpoch', '1',
    'mintedDbMs', v_now::TEXT, 'expiresDbMs', (v_now + p_ttl_ms)::TEXT);
END;
$$;
REVOKE ALL ON FUNCTION pfm.runtime_credential_mint(
  BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pfm.runtime_credential_mint(
  BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,BIGINT) TO portablefs_manager;

RESET ROLE;
