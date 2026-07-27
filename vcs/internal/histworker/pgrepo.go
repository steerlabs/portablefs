package histworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/steerlabs/portablefs/vcs/internal/historycut"
)

// pgRepository is the production Repository over one pgx pool. The pool is
// the worker's ONLY database attachment: sources, receipts, claims, and
// publication all flow through it, and its DSN is the restricted history
// worker role.
type pgRepository struct {
	pool *pgxpool.Pool
}

// OpenRepository connects with the worker DSN. maxConns bounds the pool.
func OpenRepository(ctx context.Context, dsn string, maxConns int32) (Repository, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("histworker: worker DSN does not parse: %w", err)
	}
	if maxConns < 1 {
		maxConns = 4
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &pgRepository{pool: pool}, nil
}

func (r *pgRepository) Close() { r.pool.Close() }

func marshalJSON(v any) (string, error) {
	if v == nil {
		return "null", nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("histworker: marshal: %w", err)
	}
	return string(raw), nil
}

func (r *pgRepository) WorkerBeat(ctx context.Context, workerID string, kinds []string, facts any) (int64, error) {
	factsJSON, err := marshalJSON(facts)
	if err != nil {
		return 0, err
	}
	var raw []byte
	if err := r.pool.QueryRow(ctx, sqlWorkerBeat, workerID, kinds, factsJSON).Scan(&raw); err != nil {
		return 0, mapPgError(err)
	}
	var out struct {
		DbTimeMs string `json:"dbTimeMs"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("histworker: worker beat decode: %w", err)
	}
	return parseInt64(out.DbTimeMs, "worker beat db time")
}

func (r *pgRepository) ClaimCuts(ctx context.Context, workerID string, limit int, leaseTTLMs int64) ([]CutClaim, error) {
	rows, err := r.pool.Query(ctx, sqlCutClaim, workerID, limit, leaseTTLMs)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []CutClaim
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		claim, err := DecodeCutClaim(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, claim)
	}
	return out, mapPgError(rows.Err())
}

func (r *pgRepository) HeartbeatCut(ctx context.Context, cutID string, claimEpoch int64, workerID string, leaseTTLMs int64, progress any) error {
	progressJSON, err := marshalJSON(progress)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, sqlCutHeartbeat, cutID, claimEpoch, workerID, leaseTTLMs, progressJSON)
	return mapPgError(err)
}

func (r *pgRepository) RetryCut(ctx context.Context, cutID string, claimEpoch int64, errDoc any, backoffMs int64) error {
	doc, err := marshalJSON(errDoc)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, sqlCutRetry, cutID, claimEpoch, doc, backoffMs)
	return mapPgError(err)
}

func (r *pgRepository) FailCut(ctx context.Context, cutID string, claimEpoch int64, errDoc any) error {
	doc, err := marshalJSON(errDoc)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, sqlCutFail, cutID, claimEpoch, doc)
	return mapPgError(err)
}

func (r *pgRepository) ReadJournalPage(ctx context.Context, cutID string, claimEpoch int64, fromSeq uint64, maxRecords int, maxBytes int64) ([]historycut.PageRecord, error) {
	rows, err := r.pool.Query(ctx, sqlCutReadPage, cutID, claimEpoch, int64(fromSeq), maxRecords, maxBytes)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []historycut.PageRecord
	for rows.Next() {
		var rec historycut.PageRecord
		var seq int64
		if err := rows.Scan(&seq, &rec.Payload, &rec.RecordHash, &rec.ChainDigest); err != nil {
			return nil, err
		}
		rec.Seq = uint64(seq)
		out = append(out, rec)
	}
	return out, mapPgError(rows.Err())
}

func (r *pgRepository) IntendObjects(ctx context.Context, cutID string, claimEpoch int64, objects []ObjectIntent) (map[string]int64, error) {
	payload, err := marshalJSON(objects)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if err := r.pool.QueryRow(ctx, sqlObjectIntend, cutID, claimEpoch, payload).Scan(&raw); err != nil {
		return nil, mapPgError(err)
	}
	var bindings []struct {
		Digest      string `json:"digest"`
		Incarnation string `json:"incarnation"`
	}
	if err := json.Unmarshal(raw, &bindings); err != nil {
		return nil, fmt.Errorf("histworker: intent bindings decode: %w", err)
	}
	out := make(map[string]int64, len(bindings))
	for _, b := range bindings {
		inc, err := parseInt64(b.Incarnation, "intent incarnation")
		if err != nil {
			return nil, err
		}
		out[b.Digest] = inc
	}
	return out, nil
}

func (r *pgRepository) RecordCopyReceipt(ctx context.Context, cutID string, claimEpoch int64, digest string, incarnation int64, failureDomain, storageKey string, size int64) error {
	_, err := r.pool.Exec(ctx, sqlObjectCopyReceipt,
		cutID, claimEpoch, digest, incarnation, failureDomain, storageKey, size)
	return mapPgError(err)
}

func (r *pgRepository) AddCutObjects(ctx context.Context, cutID string, claimEpoch int64, closure string, digests []string) error {
	_, err := r.pool.Exec(ctx, sqlCutObjectsAdd, cutID, claimEpoch, closure, digests)
	return mapPgError(err)
}

func (r *pgRepository) MarkCutReady(ctx context.Context, ready ReadyFacts) error {
	control := nullableText(ready.ControlRootDigestHex)
	controlSize := nullableInt(ready.ControlRootDigestHex, ready.ControlRootSize)
	orphan := nullableText(ready.OrphanIndexDigestHex)
	orphanSize := nullableInt(ready.OrphanIndexDigestHex, ready.OrphanIndexSize)
	_, err := r.pool.Exec(ctx, sqlCutMarkReady,
		ready.CutID, ready.ClaimEpoch,
		ready.RootDigestHex, ready.RootSize,
		ready.RecoveryRootDigestHex, ready.RecoveryRootSize,
		control, controlSize, orphan, orphanSize,
		ready.InodeNamespace, ready.NextLocal, ready.MaxInoSeen,
		ready.UserObjectCount, ready.UserObjectBytes,
		ready.RecoveryObjectCount, ready.RecoveryObjectBytes,
		ready.RootMaxInoSeen)
	return mapPgError(err)
}

func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(gate string, v int64) any {
	if gate == "" {
		return nil
	}
	return v
}

func (r *pgRepository) LocateObject(ctx context.Context, tenantID, kind, digest string) (*ObjectLocation, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx, sqlObjectLocate, tenantID, kind, digest).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	return DecodeObjectLocation(raw)
}

func (r *pgRepository) LocateLegacyBlob(ctx context.Context, cutID string, claimEpoch int64, digest string) (*LegacyBlobLocation, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx, sqlLegacyBlobLocate, cutID, claimEpoch, digest).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	return DecodeLegacyBlobLocation(raw)
}

func (r *pgRepository) LegacyChainPrepare(ctx context.Context, cutID string, claimEpoch int64) error {
	_, err := r.pool.Exec(ctx, sqlLegacyChainPrepare, cutID, claimEpoch)
	return mapPgError(err)
}

// stepDone decodes the {done: bool} progress envelope of a paged step.
func (r *pgRepository) stepDone(ctx context.Context, sql, cutID string, claimEpoch int64, page int) (bool, error) {
	var raw []byte
	if err := r.pool.QueryRow(ctx, sql, cutID, claimEpoch, page).Scan(&raw); err != nil {
		return false, mapPgError(err)
	}
	var out struct {
		Done bool `json:"done"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, fmt.Errorf("histworker: step progress decode: %w", err)
	}
	return out.Done, nil
}

func (r *pgRepository) LegacyChainApplyPage(ctx context.Context, cutID string, claimEpoch int64, maxOps int) (bool, error) {
	return r.stepDone(ctx, sqlLegacyChainApplyPage, cutID, claimEpoch, maxOps)
}

func (r *pgRepository) LegacyAssignOrds(ctx context.Context, cutID string, claimEpoch int64, page int) (bool, error) {
	return r.stepDone(ctx, sqlLegacyAssignOrds, cutID, claimEpoch, page)
}

func (r *pgRepository) LegacyAssignInos(ctx context.Context, cutID string, claimEpoch int64, page int) (bool, error) {
	return r.stepDone(ctx, sqlLegacyAssignInos, cutID, claimEpoch, page)
}

func (r *pgRepository) LegacyVerifyTreeHash(ctx context.Context, cutID string, claimEpoch int64, treeHash string) error {
	_, err := r.pool.Exec(ctx, sqlLegacyTreeHashVerify, cutID, claimEpoch, treeHash)
	return mapPgError(err)
}

func (r *pgRepository) LegacyEntriesPage(ctx context.Context, cutID string, claimEpoch int64, afterOrd int64, limit int) ([]historycut.LegacyEntry, error) {
	rows, err := r.pool.Query(ctx, sqlLegacyEntriesPage, cutID, claimEpoch, afterOrd, limit)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []historycut.LegacyEntry
	for rows.Next() {
		var (
			e           historycut.LegacyEntry
			mode        int64
			uid, gid    int64
			size        int64
			assignedIno *int64
			linkTarget  *string
			blobDigest  *string
			blobSize    *int64
			chunks      []byte
			comparable  string
		)
		if err := rows.Scan(&e.Ord, &e.Path, &e.Kind, &mode, &uid, &gid, &size,
			&e.MtimeMs, &e.CtimeMs, &e.AtimeMs, &e.Executable, &assignedIno,
			&e.Nlink, &linkTarget, &blobDigest, &blobSize, &e.Compression,
			&e.Packed, &chunks, &comparable); err != nil {
			return nil, err
		}
		e.Mode = uint32(mode)
		e.UID = uint32(uid)
		e.GID = uint32(gid)
		e.Size = uint64(size)
		if assignedIno != nil {
			e.AssignedIno = uint64(*assignedIno)
		}
		if linkTarget != nil {
			e.LinkTarget = *linkTarget
		}
		if blobDigest != nil {
			e.BlobDigest = *blobDigest
		}
		if blobSize != nil {
			e.BlobSize = *blobSize
		}
		e.ChunksJSON = chunks
		e.Synthetic = comparable == "synthetic-parent"
		out = append(out, e)
	}
	return out, mapPgError(rows.Err())
}

func (r *pgRepository) LegacyPutImportCursor(ctx context.Context, cutID string, claimEpoch int64, cursor json.RawMessage) error {
	_, err := r.pool.Exec(ctx, sqlLegacyImportCursorPut, cutID, claimEpoch, string(cursor))
	return mapPgError(err)
}

func (r *pgRepository) LegacyGetImportCursor(ctx context.Context, cutID string, claimEpoch int64) (json.RawMessage, error) {
	var cursor []byte
	err := r.pool.QueryRow(ctx, sqlLegacyImportCursorGet, cutID, claimEpoch).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	return cursor, nil
}

func (r *pgRepository) ClaimScrubCopies(ctx context.Context, workerID string, limit int) ([]ScrubCopy, error) {
	rows, err := r.pool.Query(ctx, sqlScrubClaim, workerID, limit)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []ScrubCopy
	for rows.Next() {
		var c ScrubCopy
		if err := rows.Scan(&c.TenantID, &c.Kind, &c.Digest, &c.Incarnation,
			&c.FailureDomain, &c.StorageKey, &c.Size, &c.LastVerifiedMs,
			&c.ClaimEpoch, &c.ClaimExpiresMs); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapPgError(rows.Err())
}

func (r *pgRepository) RecordScrubReceipt(ctx context.Context, workerID string, c ScrubCopy, ok bool) error {
	var size, key any
	if ok {
		size, key = c.Size, c.StorageKey
	}
	_, err := r.pool.Exec(ctx, sqlScrubReceipt,
		workerID, c.TenantID, c.Kind, c.Digest, c.Incarnation,
		c.FailureDomain, c.ClaimEpoch, ok, size, key)
	return mapPgError(err)
}

func (r *pgRepository) ClaimRepairs(ctx context.Context, workerID string, limit int, leaseTTLMs int64) ([]RepairClaim, error) {
	rows, err := r.pool.Query(ctx, sqlRepairClaim, workerID, limit, leaseTTLMs)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []RepairClaim
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		claim, err := DecodeRepairClaim(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, claim)
	}
	return out, mapPgError(rows.Err())
}

func (r *pgRepository) RecordRepairReceipt(ctx context.Context, workerID string, claim RepairClaim, storageKey string) error {
	_, err := r.pool.Exec(ctx, sqlRepairReceipt,
		workerID, claim.TenantID, claim.Kind, claim.Digest, claim.Incarnation,
		claim.MissingDomain, claim.ClaimEpoch, storageKey, claim.Size)
	return mapPgError(err)
}

func (r *pgRepository) ClaimSweep(ctx context.Context, workerID string, minAgeMs, leaseTTLMs int64) (*SweepClaim, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx, sqlSweepClaim, workerID, minAgeMs, leaseTTLMs).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	return DecodeSweepClaim(raw)
}

func (r *pgRepository) CompleteSweep(ctx context.Context, workerID string, claim *SweepClaim, absences []AbsenceReceipt) (string, error) {
	payload, err := marshalJSON(absences)
	if err != nil {
		return "", err
	}
	if absences == nil {
		payload = "[]"
	}
	var outcome string
	err = r.pool.QueryRow(ctx, sqlSweepComplete,
		workerID, claim.TenantID, claim.Kind, claim.Digest,
		claim.Incarnation, claim.ReclaimGeneration, claim.ClaimEpoch, payload,
	).Scan(&outcome)
	if err != nil {
		return "", mapPgError(err)
	}
	return outcome, nil
}

func (r *pgRepository) ReleaseSweep(ctx context.Context, workerID string, claim *SweepClaim, reason string) error {
	_, err := r.pool.Exec(ctx, sqlSweepRelease,
		workerID, claim.TenantID, claim.Kind, claim.Digest,
		claim.Incarnation, claim.ReclaimGeneration, claim.ClaimEpoch, reason)
	return mapPgError(err)
}

func (r *pgRepository) RehomeLive(ctx context.Context, limit int) ([]RehomeRef, error) {
	var raw []byte
	if err := r.pool.QueryRow(ctx, sqlRehomeLive, limit).Scan(&raw); err != nil {
		return nil, mapPgError(err)
	}
	return DecodeRehomeLive(raw)
}

func (r *pgRepository) RehomeCopyPage(ctx context.Context, rehomeID string, limit int) ([]RehomeCopyItem, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx, sqlRehomeCopyPage, rehomeID, limit).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	return DecodeRehomeCopyPage(raw)
}

func (r *pgRepository) RehomeCopyReceipt(ctx context.Context, workerID, rehomeID, digest string, size int64, failureDomain, storageKey string) error {
	_, err := r.pool.Exec(ctx, sqlRehomeCopyReceipt,
		rehomeID, workerID, digest, size, failureDomain, storageKey)
	return mapPgError(err)
}

func parseInt64(s, what string) (int64, error) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("histworker: %s %q is not an integer", what, s)
	}
	return v, nil
}
