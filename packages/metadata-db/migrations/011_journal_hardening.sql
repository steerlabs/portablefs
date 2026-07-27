-- Managed live-journal bridge and the only portablefs_authority SQL surface.
-- Normal writes append durably and become readable immediately; no global
-- freeze, drain, checkpoint, or shutdown phase participates in persistence.

SET LOCAL ROLE portablefs_journal_owner;

CREATE FUNCTION pfj.scope_locks(p_keys TEXT[]) RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE v_key BIGINT;
BEGIN
  FOR v_key IN
    SELECT DISTINCT hashtextextended(k,0)
    FROM unnest(p_keys) AS u(k) ORDER BY 1
  LOOP
    PERFORM pg_advisory_xact_lock(v_key);
  END LOOP;
END;
$$;

CREATE FUNCTION pfj.require_durable_primary() RETURNS void
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  PERFORM pfm.require_durable_primary();
END;
$$;

CREATE FUNCTION pfj.require_manager_binding(
  g pfj.journal_generations,
  p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,
  p_authority_runtime_id TEXT,
  p_authority_capability TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_branch_name TEXT;
  v_binding JSONB;
BEGIN
  SELECT b.name INTO v_branch_name FROM public.branches b
    WHERE b.id=g.branch_id AND b.volume_id=g.volume_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal generation branch is gone' USING ERRCODE='PF007';
  END IF;
  v_binding:=pfm.verify_authority_binding(
    't:'||g.tenant_id,g.volume_id,v_branch_name,
    p_manager_epoch,p_authority_runtime_seq,p_authority_runtime_id,
    p_authority_capability);
  IF COALESCE((v_binding->>'managed')::BOOLEAN,FALSE) THEN
    IF g.manager_epoch IS DISTINCT FROM p_manager_epoch
       OR g.authority_runtime_seq IS DISTINCT FROM p_authority_runtime_seq
       OR g.authority_runtime_id IS DISTINCT FROM p_authority_runtime_id THEN
      RAISE EXCEPTION 'journal generation is bound to a different runtime'
        USING ERRCODE='PF001';
    END IF;
  ELSIF g.manager_epoch IS NOT NULL OR g.authority_runtime_seq IS NOT NULL
        OR g.authority_runtime_id IS NOT NULL THEN
    RAISE EXCEPTION 'managed journal binding appeared on an unmanaged scope'
      USING ERRCODE='PF001';
  END IF;
  RETURN v_binding;
END;
$$;

CREATE FUNCTION pfj.durability_facts() RETURNS JSONB
LANGUAGE sql SECURITY DEFINER VOLATILE
SET search_path=pg_catalog,pg_temp
AS $$ SELECT pfm.durability_evidence() $$;

-- Cheap read-only heartbeat. No receipt, mutation, capability echo, or hash
-- material is produced. ONE pfj calling convention: like every other
-- authority-facing pfj function this takes the RAW tenant id and derives the
-- manager scope key ('t:'||tenant_id) internally — the only caller (the vcs
-- child's manager-lease guard) passes its raw VCS_TENANT_ID. A derived-key
-- parameter here would make every grounding probe miss the runtime rows and
-- answer PF001 for a perfectly live binding, fencing the child seconds
-- after spawn.
CREATE FUNCTION pfj.authority_lease_facts(
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
DECLARE v_binding JSONB;
BEGIN
  v_binding:=pfm.verify_authority_binding(
    't:'||p_tenant_id,p_volume_id,p_branch_name,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,p_authority_capability);
  IF NOT COALESCE((v_binding->>'managed')::BOOLEAN,FALSE) THEN
    RAISE EXCEPTION 'authority heartbeat requires a managed binding'
      USING ERRCODE='PF001';
  END IF;
  RETURN v_binding;
END;
$$;

CREATE FUNCTION pfj.journal_bound_head(
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
  v_branch_id TEXT;
  v_binding JSONB;
  v_now BIGINT;
  v_lease_live BOOLEAN:=FALSE;
  v_generation_found BOOLEAN:=FALSE;
  g pfj.journal_generations;
  v_lease RECORD;
BEGIN
  PERFORM pfj.scope_locks(ARRAY[
    jsonb_build_array('pfj-scope',p_tenant_id,p_volume_id,p_branch_name)::TEXT]);
  SELECT v.tenant_id INTO v_tenant FROM public.volumes v
    WHERE v.id=p_volume_id FOR SHARE;
  IF NOT FOUND OR v_tenant<>p_tenant_id THEN
    RAISE EXCEPTION 'volume is not owned by tenant' USING ERRCODE='PF007';
  END IF;
  SELECT b.id INTO v_branch_id FROM public.branches b
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='PF007';
  END IF;
  SELECT * INTO g FROM pfj.journal_generations
    WHERE branch_id=v_branch_id
      AND status IN ('active','suspended','retiring')
    FOR SHARE;
  v_generation_found:=FOUND;
  v_binding:=pfm.verify_authority_binding(
    't:'||p_tenant_id,p_volume_id,p_branch_name,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,p_authority_capability);
  IF NOT COALESCE((v_binding->>'managed')::BOOLEAN,FALSE) THEN
    RAISE EXCEPTION 'bound head requires a managed authority'
      USING ERRCODE='PF001';
  END IF;
  IF NOT v_generation_found THEN RETURN NULL; END IF;
  v_now:=pfj.now_ms();
  IF g.lease_id IS NOT NULL THEN
    SELECT l.released_at,l.expires_at,l.fencing_token INTO v_lease
      FROM public.leases l WHERE l.id=g.lease_id FOR SHARE;
    v_lease_live:=FOUND AND v_lease.released_at IS NULL
      AND v_lease.expires_at>v_now
      AND v_lease.fencing_token=g.writer_fence;
  END IF;
  RETURN pfj.generation_json(g)||jsonb_build_object(
    'writerLeaseLive',v_lease_live,'dbTimeMs',v_now::TEXT,
    'requestAuthorityRuntimeSeq',v_binding->'authorityRuntimeSeq');
END;
$$;

-- Public mutation/read functions follow.

CREATE FUNCTION pfj.journal_claim(
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
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  v_now BIGINT;
  v_tenant TEXT;
  v_fingerprint TEXT;
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
  v_capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  v_fingerprint:=encode(sha256(convert_to(jsonb_build_array(
    'portablefs-journal-claim-v5',p_tenant_id,p_volume_id,p_branch_name,
    p_attach_session_id,p_lease_id,p_fencing_token::TEXT,p_holder_id,
    p_authority_instance_id,v_capability_hash,p_manager_epoch::TEXT,
    p_authority_runtime_seq::TEXT,p_authority_runtime_id,
    p_expected_base_commit_id,p_quota_backlog_bytes::TEXT,
    p_quota_backlog_records::TEXT)::TEXT,'UTF8')),'hex');
  PERFORM pfj.scope_locks(ARRAY[
    jsonb_build_array('pfj-claim',p_tenant_id,p_volume_id,p_branch_name)::TEXT,
    jsonb_build_array(
      'pfj-claim-receipt',p_tenant_id,p_volume_id,p_branch_name,p_operation_id)::TEXT]);
  -- Canonical row-lock order begins with volume then branch.
  SELECT v.tenant_id INTO v_tenant FROM public.volumes v
    WHERE v.id=p_volume_id FOR SHARE;
  IF NOT FOUND OR v_tenant<>p_tenant_id THEN
    RAISE EXCEPTION 'volume is not owned by tenant' USING ERRCODE='PF007';
  END IF;
  SELECT b.id,b.head_commit_id INTO v_branch FROM public.branches b
    WHERE b.volume_id=p_volume_id AND b.name=p_branch_name FOR SHARE;
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
    IF v_receipt.request_fingerprint<>v_fingerprint THEN
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
  -- After the generation: attach session then public lease.
  SELECT s.id,s.status,s.mode,s.holder_id INTO v_session
    FROM public.attach_sessions s
    WHERE s.id=p_attach_session_id AND s.volume_id=p_volume_id
      AND s.branch_id=v_branch.id FOR SHARE;
  SELECT l.id,l.fencing_token,l.expires_at,l.released_at,
         l.exclusive,l.holder_id,l.attach_session_id INTO v_lease
    FROM public.leases l
    WHERE l.id=p_lease_id AND l.attach_session_id=p_attach_session_id
      AND l.branch_id=v_branch.id AND l.volume_id=p_volume_id FOR SHARE;
  -- Manager claim/runtime locks are always last.
  v_binding:=pfm.verify_authority_binding(
    't:'||p_tenant_id,p_volume_id,p_branch_name,p_manager_epoch,
    p_authority_runtime_seq,p_authority_runtime_id,p_capability);
  PERFORM pfj.require_durable_primary();
  -- The durability probe may outlive a manager deadline. Reverify the exact
  -- binding afterwards and use its post-lock database-time sample.
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
    INSERT INTO pfj.journal_generations(
      id,tenant_id,volume_id,branch_id,epoch,record_codec,control_codec,
      base_commit_id,base_seq,base_digest,next_seq,tip_digest,
      physical_trimmed_seq,status,backlog_bytes,backlog_records,
      quota_backlog_bytes,quota_backlog_records,writer_fence,
      attach_session_id,lease_id,holder_id,authority_instance_id,
      capability_hash,manager_epoch,authority_runtime_seq,
      authority_runtime_id,claimed_at,created_at,updated_at)
    VALUES (
      'jgen_'||replace(gen_random_uuid()::TEXT,'-',''),
      p_tenant_id,p_volume_id,v_branch.id,v_epoch,'pfr1','pfc1',
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
      claimed_at=v_now,updated_at=v_now
      WHERE id=g.id RETURNING * INTO g;
    GET DIAGNOSTICS v_count=ROW_COUNT;
    IF v_count<>1 THEN
      RAISE EXCEPTION 'journal claim lost its generation' USING ERRCODE='PF010';
    END IF;
  END IF;
  v_response:=pfj.generation_json(g)||jsonb_build_object(
    'operationId',p_operation_id,'created',v_created,'resumed',v_resumed);
  INSERT INTO pfj.journal_claim_receipts(
    tenant_id,volume_id,branch_id,operation_id,generation_id,
    request_fingerprint,writer_fence,writer_capability_hash,response,created_at)
  VALUES (
    p_tenant_id,p_volume_id,g.branch_id,p_operation_id,g.id,
    v_fingerprint,p_fencing_token,v_capability_hash,v_response,v_now);
  RETURN v_response||jsonb_build_object(
    'current',TRUE,'replayed',FALSE);
END;
$$;

CREATE FUNCTION pfj.journal_check_append_quota(
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
  p_additional_bytes BIGINT,
  p_additional_records BIGINT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
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
    'backlogBytes',g.backlog_bytes::TEXT,
    'backlogRecords',g.backlog_records::TEXT,
    'quotaBacklogBytes',g.quota_backlog_bytes::TEXT,
    'quotaBacklogRecords',g.quota_backlog_records::TEXT,
    'remainingBytes',
      (g.quota_backlog_bytes-g.backlog_bytes-p_additional_bytes)::TEXT,
    'remainingRecords',
      (g.quota_backlog_records-g.backlog_records-p_additional_records)::TEXT);
END;
$$;

CREATE FUNCTION pfj.journal_append(
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
  i INT;
BEGIN
  PERFORM pfj.require_txn_settings();
  -- Receipt replay intentionally precedes live writer/runtime validation so an
  -- ambiguous committed append remains answerable after expiry. The immutable
  -- per-writer capability still authenticates that replay, so reject malformed
  -- capability structure before deriving or comparing its hash. In
  -- particular, SQL's three-valued `stored_hash <> NULL` must never authorize.
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
    IF p_payloads[i] IS NULL OR octet_length(p_payloads[i])<5 THEN
      RAISE EXCEPTION 'append payload is truncated' USING ERRCODE='PF008';
    END IF;
    IF octet_length(p_payloads[i])>8388608 THEN
      RAISE EXCEPTION 'append record exceeds 8 MiB' USING ERRCODE='PF004';
    END IF;
    IF substring(p_payloads[i] FROM 1 FOR 4)<>'\x50465231'::BYTEA THEN
      RAISE EXCEPTION 'append record is not PFR1' USING ERRCODE='PF005';
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
    'pfj-append-group-v2',p_generation_id,p_epoch::TEXT,p_lease_id,
    p_fencing_token::TEXT,p_record_codec,p_control_codec,p_first_seq::TEXT,
    v_count::TEXT,v_payload_facts,to_jsonb(p_record_hashes),p_end_tip
  )::TEXT,'UTF8')),'hex');
  v_capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  g:=pfj.lock_generation(p_generation_id);
  -- Exact durable receipt is checked before live lease/runtime validation so an
  -- ambiguous append remains recoverable after the original writer expires.
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
      'currentCut',pfj.generation_json(g)->'cut');
  END IF;
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    p_record_codec,p_control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
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
  IF g.backlog_bytes>g.quota_backlog_bytes
     OR g.backlog_records>g.quota_backlog_records THEN
    RAISE EXCEPTION 'journal backlog accounting is corrupt'
      USING ERRCODE='PF010';
  END IF;
  IF v_total_bytes>g.quota_backlog_bytes-g.backlog_bytes
     OR v_count>g.quota_backlog_records-g.backlog_records THEN
    RAISE EXCEPTION 'journal backlog quota exceeded'
      USING ERRCODE='PF003',
            DETAIL=jsonb_build_object(
              'backlogBytes',g.backlog_bytes::TEXT,
              'backlogRecords',g.backlog_records::TEXT,
              'quotaBacklogBytes',g.quota_backlog_bytes::TEXT,
              'quotaBacklogRecords',g.quota_backlog_records::TEXT,
              'additionalBytes',v_total_bytes::TEXT,
              'additionalRecords',v_count::TEXT)::TEXT;
  END IF;
  -- Verify every caller hash and the complete chain before the HA sample/write.
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
  -- Lease/runtime validity is sampled after the potentially slow HA probe.
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    p_record_codec,p_control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  v_now:=pfj.now_ms();
  v_chain:=g.tip_digest;
  FOR i IN 1..v_count LOOP
    v_seq:=p_first_seq+i-1;
    v_hash:=pfj.chain_step(pfj.zero_digest(),p_payloads[i]);
    v_chain:=pfj.chain_step(v_chain,p_payloads[i]);
    INSERT INTO pfj.journal_records(
      generation_id,seq,payload,payload_bytes,record_hash,chain_digest,created_at)
    VALUES (
      g.id,v_seq,p_payloads[i],octet_length(p_payloads[i]),
      v_hash,v_chain,
      v_now);
  END LOOP;
  UPDATE pfj.journal_generations SET
    next_seq=p_first_seq+v_count,tip_digest=p_end_tip,
    backlog_bytes=backlog_bytes+v_total_bytes,
    backlog_records=backlog_records+v_count,
    updated_at=v_now
    WHERE id=g.id RETURNING * INTO g;
  GET DIAGNOSTICS v_rows=ROW_COUNT;
  IF v_rows<>1 THEN
    RAISE EXCEPTION 'append lost its locked generation' USING ERRCODE='PF010';
  END IF;
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
  -- Keep every structured tombstone, but only the newest 1024 response bodies.
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
    'currentCut',pfj.generation_json(g)->'cut');
END;
$$;

-- Live journal reads are ordinary filesystem reads. They require the same
-- exact writer/runtime proof as append, but never require a cut or snapshot.
CREATE FUNCTION pfj.journal_read_page(
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
    -- Progress guarantee: the first record is returned even when it exceeds
    -- the requested byte budget; subsequent records respect the budget.
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

CREATE FUNCTION pfj.journal_record_hashes(
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

-- Exact suspension is an explicit handoff primitive, not the normal
-- persistence path. The durable receipt is checked before current lease
-- validation so an ambiguous successful suspend can always be recovered.
CREATE FUNCTION pfj.journal_suspend_exact(
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
  PERFORM pfj.require_durable_primary();
  -- Revalidate all time-sensitive proofs after the durability probe.
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

CREATE FUNCTION pfj.opstate_get(
  p_generation_id TEXT,p_epoch BIGINT,p_capability TEXT,p_lease_id TEXT,
  p_fencing_token BIGINT,p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,p_authority_runtime_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_row RECORD;
BEGIN
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
  SELECT o.doc,o.version,o.updated_at INTO v_row
    FROM pfj.opstate o
    WHERE o.volume_id=g.volume_id AND o.branch_id=g.branch_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN jsonb_build_object(
    'doc',v_row.doc,'version',v_row.version::TEXT,
    'updatedAt',v_row.updated_at::TEXT);
END;
$$;

CREATE FUNCTION pfj.opstate_put(
  p_generation_id TEXT,p_epoch BIGINT,p_capability TEXT,p_lease_id TEXT,
  p_fencing_token BIGINT,p_manager_epoch BIGINT,
  p_authority_runtime_seq BIGINT,p_authority_runtime_id TEXT,
  p_expected_version BIGINT,p_doc JSONB
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
  g pfj.journal_generations;
  v_now BIGINT;
  v_version BIGINT;
BEGIN
  PERFORM pfj.require_txn_settings();
  IF p_expected_version IS NULL OR p_expected_version<0 THEN
    RAISE EXCEPTION 'opstate expected version must be non-negative'
      USING ERRCODE='PF008';
  END IF;
  IF p_doc IS NULL THEN
    RAISE EXCEPTION 'opstate document required' USING ERRCODE='PF008';
  END IF;
  IF octet_length(p_doc::TEXT)>16777216 THEN
    RAISE EXCEPTION 'opstate document exceeds 16 MiB' USING ERRCODE='PF004';
  END IF;
  g:=pfj.lock_generation(p_generation_id);
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    g.record_codec,g.control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  PERFORM pfj.require_durable_primary();
  PERFORM pfj.require_writer(
    g,p_epoch,p_capability,p_lease_id,p_fencing_token,
    g.record_codec,g.control_codec);
  PERFORM pfj.require_manager_binding(
    g,p_manager_epoch,p_authority_runtime_seq,
    p_authority_runtime_id,p_capability);
  v_now:=pfj.now_ms();
  IF p_expected_version=0 THEN
    BEGIN
      INSERT INTO pfj.opstate(volume_id,branch_id,doc,version,updated_at)
      VALUES (g.volume_id,g.branch_id,p_doc,1,v_now);
    EXCEPTION WHEN unique_violation THEN
      RAISE EXCEPTION 'opstate already exists' USING ERRCODE='PF002';
    END;
    RETURN jsonb_build_object('version','1','updatedAt',v_now::TEXT);
  END IF;
  IF p_expected_version=9223372036854775807::BIGINT THEN
    RAISE EXCEPTION 'opstate version exhausted' USING ERRCODE='PF004';
  END IF;
  UPDATE pfj.opstate SET
    doc=p_doc,version=version+1,updated_at=v_now
    WHERE volume_id=g.volume_id AND branch_id=g.branch_id
      AND version=p_expected_version
    RETURNING version INTO v_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'opstate version conflict' USING ERRCODE='PF002';
  END IF;
  RETURN jsonb_build_object(
    'version',v_version::TEXT,'updatedAt',v_now::TEXT);
END;
$$;

-- Least-authority surface. Snapshot/cut/trim/retire and diagnostic helpers
-- stay owner-only; the live authority gets only the ordinary journal APIs,
-- exact handoff, opstate CAS, heartbeat, and durability diagnostics.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pfj FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pfj FROM portablefs_authority;
REVOKE ALL ON ALL TABLES IN SCHEMA pfj FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pfj FROM portablefs_authority;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pfj FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pfj FROM portablefs_authority;

GRANT EXECUTE ON FUNCTION
  pfj.journal_claim(
    TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT,TEXT,TEXT,
    BIGINT,BIGINT,TEXT,TEXT,BIGINT,BIGINT),
  pfj.journal_bound_head(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT),
  pfj.journal_check_append_quota(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,TEXT,TEXT,
    BIGINT,BIGINT,TEXT,BIGINT,BIGINT),
  pfj.journal_append(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,TEXT,TEXT,
    BIGINT,BIGINT,TEXT,BIGINT,BYTEA[],TEXT[],TEXT),
  pfj.journal_read_page(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,
    BIGINT,BIGINT,TEXT,BIGINT,INT,BIGINT),
  pfj.journal_record_hashes(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,
    BIGINT,BIGINT,TEXT,BIGINT,BIGINT),
  pfj.journal_suspend_exact(
    TEXT,BIGINT,TEXT,TEXT,BIGINT,TEXT,TEXT,
    BIGINT,BIGINT,TEXT,TEXT,TEXT,BIGINT,TEXT),
  -- pfj.opstate_get/opstate_put are DELIBERATELY not an authority surface:
  -- a managed child's durable lifecycle truth is the manager's pfm receipts
  -- plus the journal's receipted exact suspension, and local/self-host mode
  -- uses the file opstate store. The functions remain defined (owner-only)
  -- for the external HistoryCut lane.
  pfj.authority_lease_facts(TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT),
  pfj.durability_facts()
TO portablefs_authority;

RESET ROLE;
