package histworker

// Every SQL statement the worker executes lives in this ONE file, so a
// rename or signature change in the pfh migration is a mechanical one-file
// integration. All statements call pfh SECURITY DEFINER functions; the
// worker role holds zero table privileges.
const (
	sqlWorkerBeat = `SELECT pfh.worker_beat($1, $2, $3::jsonb)`

	sqlCutClaim     = `SELECT * FROM pfh.cut_claim($1, $2, $3)`
	sqlCutHeartbeat = `SELECT pfh.cut_heartbeat($1, $2, $3, $4, $5::jsonb)`
	sqlCutRetry     = `SELECT pfh.cut_retry($1, $2, $3::jsonb, $4)`
	sqlCutFail      = `SELECT pfh.cut_fail($1, $2, $3::jsonb)`

	sqlCutReadPage = `SELECT seq, payload, record_hash, chain_digest
	 FROM pfh.cut_read_page($1, $2, $3, $4, $5)`

	sqlObjectIntend           = `SELECT pfh.object_intend($1, $2, $3::jsonb)`
	sqlObjectCopyReceipt      = `SELECT pfh.object_copy_receipt($1, $2, $3, $4, $5, $6, $7)`
	sqlObjectCopyReceiptBatch = `SELECT pfh.object_copy_receipt_batch($1, $2, $3::jsonb)`
	sqlCutObjectsAddFromBase  = `SELECT pfh.cut_objects_add_from_base($1, $2)`
	sqlCutObjectsAdd     = `SELECT pfh.cut_objects_add($1, $2, $3, $4)`
	sqlCutMarkReady      = `SELECT pfh.cut_mark_ready(
	   $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`

	sqlObjectLocate      = `SELECT pfh.object_locate($1, $2, $3)`
	sqlObjectLocateBatch = `SELECT pfh.object_locate_batch($1, $2, $3)`
	sqlLegacyBlobLocate  = `SELECT pfh.legacy_blob_locate($1, $2, $3)`

	sqlLegacyChainPrepare   = `SELECT pfh.legacy_chain_prepare($1, $2)`
	sqlLegacyChainApplyPage = `SELECT pfh.legacy_chain_apply_page($1, $2, $3)`
	sqlLegacyAssignOrds     = `SELECT pfh.legacy_assign_ords($1, $2, $3)`
	sqlLegacyAssignInos     = `SELECT pfh.legacy_assign_inos($1, $2, $3)`
	sqlLegacyTreeHashVerify = `SELECT pfh.legacy_tree_hash_verify($1, $2, $3)`
	sqlLegacyEntriesPage    = `SELECT ord, path, kind, mode, uid, gid, size, mtime_ms, ctime_ms,
	        atime_ms, executable, assigned_ino, nlink, link_target,
	        blob_digest, blob_size, compression, packed, chunks, comparable_key
	 FROM pfh.legacy_entries_page($1, $2, $3, $4)`
	sqlLegacyImportCursorPut = `SELECT pfh.legacy_import_cursor_put($1, $2, $3::jsonb)`
	sqlLegacyImportCursorGet = `SELECT pfh.legacy_import_cursor_get($1, $2)`

	sqlScrubClaim = `SELECT tenant_id, kind, digest, incarnation, failure_domain,
	        storage_key, size, last_verified_db_ms, claim_epoch, claim_expires_db_ms
	 FROM pfh.scrub_claim($1, $2)`
	sqlScrubReceipt = `SELECT pfh.scrub_receipt($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	sqlRepairClaim   = `SELECT * FROM pfh.repair_claim($1, $2, $3)`
	sqlRepairReceipt = `SELECT pfh.repair_receipt($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	sqlRetentionRelease = `SELECT pfh.retention_release($1)`

	sqlSweepClaim    = `SELECT pfh.sweep_claim($1, $2, $3)`
	sqlSweepComplete = `SELECT pfh.sweep_complete($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`

	sqlRehomeLive        = `SELECT pfh.rehome_live($1)`
	sqlRehomeCopyPage    = `SELECT pfh.rehome_copy_page($1, $2)`
	sqlRehomeCopyReceipt = `SELECT pfh.rehome_copy_receipt($1, $2, $3, $4, $5, $6)`
	sqlSweepRelease      = `SELECT pfh.sweep_release($1, $2, $3, $4, $5, $6, $7, $8)`
)
