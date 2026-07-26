// Package opstate is the authority's durable lifecycle-saga store: operation
// receipts (checkpoint barriers, quiesce, lease release) keyed by caller-supplied
// operation ids, the quiesced marker, the durable lease-release fact, and the
// exact checkpoint intent covering an in-flight backend commit. It exists so a
// lost response, a crash, or a restart can always be reconciled from disk: the
// file lives next to the WAL (the same durability domain as the data it
// describes), the VCS reloads and validates it on startup, and the authority
// manager reads it directly as a fallback when the VCS process that executed an
// operation is already gone.
//
// Receipts are non-forgetful: a completed operation is either present verbatim
// or replaced by an explicit expiry tombstone — a retried operation id is never
// silently re-executed after pruning. Every mutation is persisted atomically
// (temp file + fsync + rename + directory fsync) before it returns, and the file
// is validated on load (schema, duplicates, fingerprints, transitions); a store
// that fails validation is an error, never silently discarded.
//
// The file format is a stable, versioned JSON contract shared with the
// TypeScript authority manager (apps/authority-manager reads it): camelCase
// field names, version 2.
package opstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"sync"
)

// FileSuffix is appended to the WAL path to name the store, so the store is
// scoped to exactly one WAL (two dev processes sharing a temp dir can never
// clobber each other's operation state). The authority manager derives the
// same path — `<role>.wal` + this suffix inside the role directory — to read
// results of operations executed by a VCS process that has since exited.
const FileSuffix = ".opstate.json"

// OperationStore is the durable lifecycle/checkpoint operation state consumed
// by the lifecycle controller, the checkpointer, and startup reconciliation.
// Implementations:
//
//   - *Store (this package): the local file store next to the WAL — the
//     dev/self-host implementation, sharing the WAL's durability domain.
//   - remotejournal.OpStore: the production implementation persisting
//     the same versioned JSON contracts in the metadata database, so a managed
//     authority never opens (or creates) a local opstate file.
//
// Every method keeps the file store's semantics: receipts are non-forgetful
// (present verbatim, tombstoned, or closed by a retention floor — never
// silently forgotten), mutations are durable before they return, and
// validation failures are errors rather than discarded state.
type OperationStore interface {
	Healthy() error
	Operation(id string) (Operation, bool)
	Tombstone(id string) (Tombstone, bool)
	RecordOperation(op Operation) error
	UnknownExpired(volumeID, branch, instanceID string) (bool, error)
	Quiesced() *QuiesceMarker
	SetQuiesced(m QuiesceMarker, op Operation) error
	LeaseRelease() *LeaseReleaseFact
	SetLeaseReleased(f LeaseReleaseFact, op Operation) error
	ClearQuiescedForForeignInstance(instanceID string) error
	CheckpointIntent() *CheckpointIntent
	PutCheckpointIntent(i CheckpointIntent) error
	ResolveCheckpointIntent(operationID, resolution string, atMs int64) error
	FinalizeCheckpointIntent(operationID string, atMs int64) error
}

// CurrentVersion is the on-disk schema version. Version 1 (an early un-shipped
// draft without fingerprints or tombstones) is rejected, not migrated.
const CurrentVersion = 2

// maxOperations bounds the retained completed-operation history. Operations
// pruned past the bound leave an explicit tombstone (see maxTombstones), so a
// late retry is told its receipt EXPIRED instead of silently re-executing.
const maxOperations = 128

// maxTombstones bounds the explicit-expiry receipts. Dropping a tombstone closes
// its exact authority generation through a RetentionFloor: unknown operation
// ids in that generation then fail VCS_OPERATION_EXPIRED instead of ever being
// treated as new. This is the only exact bounded policy possible for opaque,
// caller-selected ids without retaining every id forever.
const maxTombstones = 4096

// maxRetentionFloors bounds authority-generation retirement metadata. Reaching
// the bound flips the global fail-closed floor instead of forgetting a floor.
// Authority instance ids are unique generations, so a healthy deployment
// normally retains one floor at most; the global fallback handles malformed or
// adversarially churned stores without weakening exactness.
const maxRetentionFloors = 64

// maxStoreBytes bounds startup allocation before JSON decoding. The bounded
// receipt/tombstone model is comfortably below this ceiling even with maximum
// identifier lengths.
const maxStoreBytes = 16 << 20

const (
	maxIDBytes          = 256
	maxBranchBytes      = 128
	maxFingerprintBytes = 128
	maxHashBytes        = 256
)

// Operation kinds.
const (
	KindCheckpoint   = "checkpoint"
	KindEvict        = "evict"
	KindQuiesce      = "quiesce"
	KindReleaseLease = "release-lease"
)

func knownKind(k string) bool {
	return k == KindCheckpoint || k == KindEvict || k == KindQuiesce || k == KindReleaseLease
}

// Operation is one completed (successful) lifecycle operation. Failures are
// deliberately NOT recorded: an operation id whose attempt failed may be
// retried and succeed later; only success is immutable. Fingerprint is the
// canonical request fingerprint (kind + fence + normalized request); a reused
// id with a different fingerprint is a conflict, enforced here and by callers.
type Operation struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	Fingerprint         string `json:"fingerprint"`
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	AuthorityInstanceID string `json:"authorityInstanceId,omitempty"`
	HeadCommitID        string `json:"headCommitId,omitempty"`
	TreeHash            string `json:"treeHash,omitempty"`
	Committed           bool   `json:"committed"`
	MutationCount       int64  `json:"mutationCount"`
	ByteCount           int64  `json:"byteCount"`
	CompletedAtMs       int64  `json:"completedAtMs"`
	// State is the operation result state, not a live controller observation.
	// Persisting it makes a lost-response replay byte-stable even after a later
	// lifecycle transition or process restart.
	State string `json:"state,omitempty"`
	// Exact live-journal drain proof (KindEvict only). AppliedLSN is the first
	// sequence not yet applied, matching workfs.LiveRevision. The custom JSON
	// codec below writes every uint64 as a decimal string so JavaScript readers
	// never round a random 64-bit epoch/generation.
	WALEpoch            uint64 `json:"-"`
	AppliedLSN          uint64 `json:"-"`
	CoherenceGeneration uint64 `json:"-"`
	WALPoisoned         bool   `json:"-"`
	// Managed-remote evicts only: the exact receipted pfj.journal_suspend_exact
	// step-down facts. JournalNextSeq/JournalTipDigest are the database's own
	// committed head at suspension; both are present exactly when
	// JournalSuspended is true. Absent for file-WAL evictions.
	JournalSuspended bool   `json:"-"`
	JournalNextSeq   uint64 `json:"-"`
	JournalTipDigest string `json:"-"`
	// Lease-release facts (KindReleaseLease only).
	LeaseID       string `json:"leaseId,omitempty"`
	LeaseReleased bool   `json:"leaseReleased,omitempty"`
}

// operationJSON is the stable cross-language wire representation. Pointers
// distinguish an absent non-evict field from the required string "0" applied
// LSN on an empty live journal and force walPoisoned=false to remain explicit.
type operationJSON struct {
	ID                  string  `json:"id"`
	Kind                string  `json:"kind"`
	Fingerprint         string  `json:"fingerprint"`
	VolumeID            string  `json:"volumeId"`
	Branch              string  `json:"branch"`
	AuthorityInstanceID string  `json:"authorityInstanceId,omitempty"`
	HeadCommitID        string  `json:"headCommitId,omitempty"`
	TreeHash            string  `json:"treeHash,omitempty"`
	Committed           bool    `json:"committed"`
	MutationCount       int64   `json:"mutationCount"`
	ByteCount           int64   `json:"byteCount"`
	CompletedAtMs       int64   `json:"completedAtMs"`
	State               string  `json:"state,omitempty"`
	WALEpoch            *string `json:"walEpoch,omitempty"`
	AppliedLSN          *string `json:"appliedLsn,omitempty"`
	CoherenceGeneration *string `json:"coherenceGeneration,omitempty"`
	WALPoisoned         *bool   `json:"walPoisoned,omitempty"`
	JournalSuspended    *bool   `json:"journalSuspended,omitempty"`
	JournalNextSeq      *string `json:"journalNextSeq,omitempty"`
	JournalTipDigest    *string `json:"journalTipDigest,omitempty"`
	LeaseID             string  `json:"leaseId,omitempty"`
	LeaseReleased       bool    `json:"leaseReleased,omitempty"`
}

func (op Operation) MarshalJSON() ([]byte, error) {
	w := operationJSON{
		ID: op.ID, Kind: op.Kind, Fingerprint: op.Fingerprint,
		VolumeID: op.VolumeID, Branch: op.Branch, AuthorityInstanceID: op.AuthorityInstanceID,
		HeadCommitID: op.HeadCommitID, TreeHash: op.TreeHash, Committed: op.Committed,
		MutationCount: op.MutationCount, ByteCount: op.ByteCount, CompletedAtMs: op.CompletedAtMs,
		State: op.State, LeaseID: op.LeaseID, LeaseReleased: op.LeaseReleased,
	}
	if op.Kind == KindEvict {
		epoch := strconv.FormatUint(op.WALEpoch, 10)
		lsn := strconv.FormatUint(op.AppliedLSN, 10)
		generation := strconv.FormatUint(op.CoherenceGeneration, 10)
		poisoned := op.WALPoisoned
		w.WALEpoch, w.AppliedLSN, w.CoherenceGeneration, w.WALPoisoned = &epoch, &lsn, &generation, &poisoned
		if op.JournalSuspended {
			suspended := true
			nextSeq := strconv.FormatUint(op.JournalNextSeq, 10)
			tip := op.JournalTipDigest
			w.JournalSuspended, w.JournalNextSeq, w.JournalTipDigest = &suspended, &nextSeq, &tip
		}
	}
	return json.Marshal(w)
}

func (op *Operation) UnmarshalJSON(raw []byte) error {
	var w operationJSON
	if err := decodeStrict(raw, &w); err != nil {
		return fmt.Errorf("opstate: decode operation: %w", err)
	}
	*op = Operation{
		ID: w.ID, Kind: w.Kind, Fingerprint: w.Fingerprint,
		VolumeID: w.VolumeID, Branch: w.Branch, AuthorityInstanceID: w.AuthorityInstanceID,
		HeadCommitID: w.HeadCommitID, TreeHash: w.TreeHash, Committed: w.Committed,
		MutationCount: w.MutationCount, ByteCount: w.ByteCount, CompletedAtMs: w.CompletedAtMs,
		State: w.State, LeaseID: w.LeaseID, LeaseReleased: w.LeaseReleased,
	}
	if w.WALEpoch != nil {
		value, err := parseDecimalUint64("walEpoch", *w.WALEpoch)
		if err != nil {
			return err
		}
		op.WALEpoch = value
	}
	if w.AppliedLSN != nil {
		value, err := parseDecimalUint64("appliedLsn", *w.AppliedLSN)
		if err != nil {
			return err
		}
		op.AppliedLSN = value
	}
	if w.CoherenceGeneration != nil {
		value, err := parseDecimalUint64("coherenceGeneration", *w.CoherenceGeneration)
		if err != nil {
			return err
		}
		op.CoherenceGeneration = value
	}
	if w.WALPoisoned != nil {
		op.WALPoisoned = *w.WALPoisoned
	}
	if w.JournalSuspended != nil {
		op.JournalSuspended = *w.JournalSuspended
	}
	if w.JournalNextSeq != nil {
		value, err := parseDecimalUint64("journalNextSeq", *w.JournalNextSeq)
		if err != nil {
			return err
		}
		op.JournalNextSeq = value
	}
	if w.JournalTipDigest != nil {
		op.JournalTipDigest = *w.JournalTipDigest
	}
	if op.Kind == KindEvict && (w.WALEpoch == nil || w.AppliedLSN == nil || w.CoherenceGeneration == nil || w.WALPoisoned == nil) {
		return fmt.Errorf("opstate: evict operation %q is missing its complete live-revision proof", op.ID)
	}
	if op.Kind != KindEvict && (w.WALEpoch != nil || w.AppliedLSN != nil || w.CoherenceGeneration != nil || w.WALPoisoned != nil) {
		return fmt.Errorf("opstate: non-evict operation %q carries evict-only revision fields", op.ID)
	}
	if op.JournalSuspended && (w.JournalNextSeq == nil || op.JournalTipDigest == "") {
		return fmt.Errorf("opstate: evict operation %q claims a journal suspension without its exact nextSeq/tipDigest", op.ID)
	}
	if !op.JournalSuspended && (w.JournalNextSeq != nil || w.JournalTipDigest != nil) {
		return fmt.Errorf("opstate: operation %q carries journal step-down facts without journalSuspended", op.ID)
	}
	return nil
}

func parseDecimalUint64(field, value string) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("opstate: %s must be a canonical unsigned decimal string", field)
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("opstate: %s must be a canonical unsigned decimal string", field)
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("opstate: invalid %s %q: %w", field, value, err)
	}
	return parsed, nil
}

func (op Operation) validate() error {
	switch {
	case op.ID == "" || len(op.ID) > maxIDBytes:
		return fmt.Errorf("opstate: operation has an invalid id length")
	case !knownKind(op.Kind):
		return fmt.Errorf("opstate: operation %q has unknown kind %q", op.ID, op.Kind)
	case op.Fingerprint == "" || len(op.Fingerprint) > maxFingerprintBytes:
		return fmt.Errorf("opstate: operation %q has no fingerprint", op.ID)
	case op.VolumeID == "" || len(op.VolumeID) > maxIDBytes || op.Branch == "" || len(op.Branch) > maxBranchBytes || len(op.AuthorityInstanceID) > maxIDBytes:
		return fmt.Errorf("opstate: operation %q is missing its volume/branch fence", op.ID)
	case op.CompletedAtMs <= 0:
		return fmt.Errorf("opstate: operation %q has no completion time", op.ID)
	case op.MutationCount < 0 || op.ByteCount < 0:
		return fmt.Errorf("opstate: operation %q has negative counts", op.ID)
	}
	switch op.Kind {
	case KindCheckpoint:
		if op.HeadCommitID == "" || len(op.HeadCommitID) > maxIDBytes || op.TreeHash == "" || len(op.TreeHash) > maxHashBytes || (op.State != "" && op.State != "serving") {
			return fmt.Errorf("opstate: checkpoint operation %q has invalid head/tree/state", op.ID)
		}
		return op.validateNoEvictOrLeaseFields()
	case KindQuiesce:
		if op.HeadCommitID == "" || len(op.HeadCommitID) > maxIDBytes || op.TreeHash == "" || len(op.TreeHash) > maxHashBytes || (op.State != "" && op.State != "quiesced") {
			return fmt.Errorf("opstate: quiesce operation %q has invalid head/tree/state", op.ID)
		}
		return op.validateNoEvictOrLeaseFields()
	case KindEvict:
		if op.WALEpoch == 0 || op.CoherenceGeneration == 0 {
			return fmt.Errorf("opstate: evict operation %q has incomplete live-revision identity", op.ID)
		}
		if op.State != "evicted" && op.State != "quiesced" {
			return fmt.Errorf("opstate: evict operation %q has invalid result state %q", op.ID, op.State)
		}
		if op.HeadCommitID != "" || op.TreeHash != "" || op.Committed || op.MutationCount != 0 || op.ByteCount != 0 || op.LeaseID != "" || op.LeaseReleased {
			return fmt.Errorf("opstate: evict operation %q makes checkpoint/lease claims", op.ID)
		}
		if op.JournalSuspended && op.JournalTipDigest == "" {
			return fmt.Errorf("opstate: evict operation %q claims a journal suspension without its tip digest", op.ID)
		}
		if !op.JournalSuspended && (op.JournalNextSeq != 0 || op.JournalTipDigest != "") {
			return fmt.Errorf("opstate: evict operation %q carries journal step-down facts without journalSuspended", op.ID)
		}
	case KindReleaseLease:
		if op.HeadCommitID == "" || len(op.HeadCommitID) > maxIDBytes || op.TreeHash == "" || len(op.TreeHash) > maxHashBytes || op.LeaseID == "" || len(op.LeaseID) > maxIDBytes || !op.LeaseReleased || (op.State != "" && op.State != "quiesced") {
			return fmt.Errorf("opstate: lease-release operation %q has invalid head/tree/lease/state", op.ID)
		}
		if op.WALEpoch != 0 || op.AppliedLSN != 0 || op.CoherenceGeneration != 0 || op.WALPoisoned ||
			op.JournalSuspended || op.JournalNextSeq != 0 || op.JournalTipDigest != "" ||
			op.Committed || op.MutationCount != 0 || op.ByteCount != 0 {
			return fmt.Errorf("opstate: lease-release operation %q carries unrelated claims", op.ID)
		}
	}
	return nil
}

func (op Operation) validateNoEvictOrLeaseFields() error {
	if op.WALEpoch != 0 || op.AppliedLSN != 0 || op.CoherenceGeneration != 0 || op.WALPoisoned ||
		op.JournalSuspended || op.JournalNextSeq != 0 || op.JournalTipDigest != "" ||
		op.LeaseID != "" || op.LeaseReleased {
		return fmt.Errorf("opstate: %s operation %q carries unrelated revision/lease fields", op.Kind, op.ID)
	}
	return nil
}

// Tombstone is the explicit expiry record left when a completed operation is
// pruned past the retention bound: a retry of that id is answered "expired"
// (ErrExpired at the caller) rather than silently re-executed.
type Tombstone struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	Fingerprint         string `json:"fingerprint"`
	VolumeID            string `json:"volumeId,omitempty"`
	Branch              string `json:"branch,omitempty"`
	AuthorityInstanceID string `json:"authorityInstanceId,omitempty"`
	ExpiredAtMs         int64  `json:"expiredAtMs"`
}

// RetentionFloor closes an authority generation after at least one of its
// tombstones was compacted. Existing receipts/tombstones remain replayable, but
// every unknown id in this exact fence is expired. Rotating to a fresh unique
// authorityInstanceId opens a new generation without retaining an unbounded id
// set for the old one.
type RetentionFloor struct {
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	AuthorityInstanceID string `json:"authorityInstanceId,omitempty"`
	ClosedAtMs          int64  `json:"closedAtMs"`
}

// QuiesceMarker records that this authority (volume@branch served from this WAL
// directory, under the given instance id) has been quiesced: its final state is
// committed as HeadCommitID and it must never admit writes again. A writable
// VCS start over the same WAL directory refuses to serve while a marker for its
// own identity is present.
type QuiesceMarker struct {
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	AuthorityInstanceID string `json:"authorityInstanceId,omitempty"`
	OperationID         string `json:"operationId"`
	HeadCommitID        string `json:"headCommitId"`
	TreeHash            string `json:"treeHash"`
	CompletedAtMs       int64  `json:"completedAtMs"`
}

// LeaseReleaseFact is the durable proof that this quiesced authority's exact
// write lease was released at the backend (the release call returned success).
// The manager treats this fact — not process exit codes — as the lease-release
// proof a public quiesce needs before it may succeed.
type LeaseReleaseFact struct {
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	AuthorityInstanceID string `json:"authorityInstanceId,omitempty"`
	LeaseID             string `json:"leaseId,omitempty"`
	OperationID         string `json:"operationId"`
	ReleasedAtMs        int64  `json:"releasedAtMs"`
}

// CheckpointIntent is the exact record of a backend commit the checkpointer is
// about to dispatch (persisted BEFORE the request leaves the process): the
// stable commit operation id, the expected head it commits over, the canonical
// tree hash and request hash, the WAL watermark the pass snapshotted, and the
// counts. After a lost response, a crash, or a restart the intent is reconciled
// against the backend head: if the commit landed, the head is adopted and the
// WAL is compacted through EXACTLY this watermark; if it did not land, the
// records are still in the WAL and the next pass recommits them. Resolution and
// ResolvedAtMs are the persisted backend-outcome fact. LocalFinalizedAtMs is a
// second, deliberately later receipt: it is persisted only after the WAL prefix
// covered by a landed commit has been compacted locally. Keeping these as two
// ordered facts closes both checkpoint crash windows:
//
//   - landed but not finalized => startup compacts the exact cut before replay;
//   - finalized => startup must not compact that cut again after an empty WAL
//     has restarted its LSN namespace and accepted newer writes.
//
// A landed-but-unfinalized intent cannot be replaced by a newer intent.
type CheckpointIntent struct {
	OperationID              string `json:"operationId"`
	ExpectedHeadCommitID     string `json:"expectedHeadCommitId"`
	TreeHash                 string `json:"treeHash"`
	CanonicalRequestHash     string `json:"canonicalRequestHash"`
	AuxiliaryBlobDigestsHash string `json:"auxiliaryBlobDigestsHash,omitempty"`
	WALWatermark             uint64 `json:"walWatermark"`
	MutationCount            int64  `json:"mutationCount"`
	ByteCount                int64  `json:"byteCount"`
	CreatedAtMs              int64  `json:"createdAtMs"`
	Resolution               string `json:"resolution,omitempty"`
	ResolvedAtMs             int64  `json:"resolvedAtMs,omitempty"`
	LocalFinalizedAtMs       int64  `json:"localFinalizedAtMs,omitempty"`
}

// Pending reports whether the intent covers a dispatch whose outcome has not
// been reconciled yet.
func (i *CheckpointIntent) Pending() bool { return i != nil && i.Resolution == "" }

// Landed reports whether the durable backend outcome proves this commit is the
// branch history. Only landed outcomes require local WAL finalization.
func (i *CheckpointIntent) Landed() bool {
	return i != nil && (i.Resolution == "committed" || i.Resolution == "committed-reconciled")
}

// NeedsLocalFinalization reports whether startup (or the next checkpoint pass)
// must compact the landed commit's exact WAL cut before replay/progress.
func (i *CheckpointIntent) NeedsLocalFinalization() bool {
	return i.Landed() && i.LocalFinalizedAtMs == 0
}

func knownCheckpointResolution(resolution string) bool {
	return resolution == "committed" || resolution == "committed-reconciled" ||
		resolution == "not-committed" || resolution == "rejected" || resolution == "superseded"
}

type state struct {
	Version          int               `json:"version"`
	Operations       []Operation       `json:"operations"`
	Tombstones       []Tombstone       `json:"tombstones,omitempty"`
	RetentionFloors  []RetentionFloor  `json:"retentionFloors,omitempty"`
	RejectAllUnknown bool              `json:"rejectAllUnknown,omitempty"`
	Quiesced         *QuiesceMarker    `json:"quiesced,omitempty"`
	LeaseRelease     *LeaseReleaseFact `json:"leaseRelease,omitempty"`
	CheckpointIntent *CheckpointIntent `json:"checkpointIntent,omitempty"`
}

// validate enforces the store's invariants on load: schema version, per-record
// field validity, no duplicate ids (across operations AND tombstones), and
// legal saga transitions (a lease-release fact requires the quiesced marker;
// the marker's operation must still be answerable — as a receipt or an explicit
// tombstone).
func (st *state) validate(path string) error {
	if st.Version != CurrentVersion {
		return fmt.Errorf("opstate: %s has unsupported version %d (want %d)", path, st.Version, CurrentVersion)
	}
	if len(st.Operations) > maxOperations {
		return fmt.Errorf("opstate: %s holds %d live receipts (maximum %d)", path, len(st.Operations), maxOperations)
	}
	if len(st.Tombstones) > maxTombstones {
		return fmt.Errorf("opstate: %s holds %d tombstones (maximum %d)", path, len(st.Tombstones), maxTombstones)
	}
	if len(st.RetentionFloors) > maxRetentionFloors {
		return fmt.Errorf("opstate: %s holds %d retention floors (maximum %d)", path, len(st.RetentionFloors), maxRetentionFloors)
	}
	if st.RejectAllUnknown && len(st.RetentionFloors) != 0 {
		return fmt.Errorf("opstate: %s combines the global retention floor with redundant scoped floors", path)
	}
	seen := make(map[string]string, len(st.Operations)+len(st.Tombstones))
	operations := make(map[string]Operation, len(st.Operations))
	for _, op := range st.Operations {
		if err := op.validate(); err != nil {
			return fmt.Errorf("%w (in %s)", err, path)
		}
		if prev, dup := seen[op.ID]; dup {
			return fmt.Errorf("opstate: %s holds duplicate records for operation %q (%s)", path, op.ID, prev)
		}
		seen[op.ID] = "operation"
		operations[op.ID] = op
	}
	for _, ts := range st.Tombstones {
		if ts.ID == "" || len(ts.ID) > maxIDBytes || ts.Fingerprint == "" || len(ts.Fingerprint) > maxFingerprintBytes || !knownKind(ts.Kind) || ts.ExpiredAtMs <= 0 ||
			len(ts.VolumeID) > maxIDBytes || len(ts.Branch) > maxBranchBytes || len(ts.AuthorityInstanceID) > maxIDBytes {
			return fmt.Errorf("opstate: %s holds a malformed tombstone %+v", path, ts)
		}
		// Version-2 files created before scoped floors may have all three scope
		// fields absent. Accept that legacy tuple conservatively; partial scopes are
		// corruption and a dropped legacy tombstone creates the global floor.
		scopeFields := 0
		if ts.VolumeID != "" {
			scopeFields++
		}
		if ts.Branch != "" {
			scopeFields++
		}
		if ts.AuthorityInstanceID != "" {
			scopeFields++
		}
		if scopeFields != 0 && (ts.VolumeID == "" || ts.Branch == "") {
			return fmt.Errorf("opstate: %s holds a partially scoped tombstone %+v", path, ts)
		}
		if prev, dup := seen[ts.ID]; dup {
			return fmt.Errorf("opstate: %s holds duplicate records for operation %q (%s + tombstone)", path, ts.ID, prev)
		}
		seen[ts.ID] = "tombstone"
	}
	floorSeen := make(map[string]struct{}, len(st.RetentionFloors))
	for _, floor := range st.RetentionFloors {
		if floor.VolumeID == "" || len(floor.VolumeID) > maxIDBytes || floor.Branch == "" || len(floor.Branch) > maxBranchBytes || len(floor.AuthorityInstanceID) > maxIDBytes || floor.ClosedAtMs <= 0 {
			return fmt.Errorf("opstate: %s holds a malformed retention floor %+v", path, floor)
		}
		key := retentionScope(floor.VolumeID, floor.Branch, floor.AuthorityInstanceID)
		if _, duplicate := floorSeen[key]; duplicate {
			return fmt.Errorf("opstate: %s holds duplicate retention floors for %s@%s instance %q", path, floor.VolumeID, floor.Branch, floor.AuthorityInstanceID)
		}
		floorSeen[key] = struct{}{}
	}
	if st.Quiesced != nil {
		m := st.Quiesced
		if m.VolumeID == "" || len(m.VolumeID) > maxIDBytes || m.Branch == "" || len(m.Branch) > maxBranchBytes ||
			len(m.AuthorityInstanceID) > maxIDBytes || m.OperationID == "" || len(m.OperationID) > maxIDBytes ||
			m.HeadCommitID == "" || len(m.HeadCommitID) > maxIDBytes || m.TreeHash == "" || len(m.TreeHash) > maxHashBytes || m.CompletedAtMs <= 0 {
			return fmt.Errorf("opstate: %s holds a malformed quiesced marker %+v", path, m)
		}
		op, ok := operations[m.OperationID]
		if !ok {
			return fmt.Errorf("opstate: %s quiesced marker names operation %q with no live receipt", path, m.OperationID)
		}
		if op.Kind != KindQuiesce || op.VolumeID != m.VolumeID || op.Branch != m.Branch ||
			op.AuthorityInstanceID != m.AuthorityInstanceID || op.HeadCommitID != m.HeadCommitID ||
			op.TreeHash != m.TreeHash || op.CompletedAtMs != m.CompletedAtMs {
			return fmt.Errorf("opstate: %s quiesced marker does not exactly match its receipt %+v", path, m)
		}
	}
	if st.LeaseRelease != nil {
		if st.Quiesced == nil {
			return fmt.Errorf("opstate: %s holds a lease-release fact without a quiesced marker (illegal transition)", path)
		}
		f := st.LeaseRelease
		if f.VolumeID == "" || len(f.VolumeID) > maxIDBytes || f.Branch == "" || len(f.Branch) > maxBranchBytes ||
			len(f.AuthorityInstanceID) > maxIDBytes || f.OperationID == "" || len(f.OperationID) > maxIDBytes ||
			f.LeaseID == "" || len(f.LeaseID) > maxIDBytes || f.ReleasedAtMs <= 0 {
			return fmt.Errorf("opstate: %s holds a malformed lease-release fact %+v", path, f)
		}
		m := st.Quiesced
		if f.VolumeID != m.VolumeID || f.Branch != m.Branch || f.AuthorityInstanceID != m.AuthorityInstanceID {
			return fmt.Errorf("opstate: %s lease-release fact crosses the quiesced identity", path)
		}
		op, ok := operations[f.OperationID]
		if !ok || op.Kind != KindReleaseLease || !op.LeaseReleased || op.LeaseID != f.LeaseID ||
			op.VolumeID != f.VolumeID || op.Branch != f.Branch || op.AuthorityInstanceID != f.AuthorityInstanceID ||
			op.HeadCommitID != m.HeadCommitID || op.TreeHash != m.TreeHash {
			return fmt.Errorf("opstate: %s lease-release fact does not exactly match its receipt", path)
		}
	}
	if st.CheckpointIntent != nil {
		i := st.CheckpointIntent
		if i.OperationID == "" || len(i.OperationID) > maxIDBytes || len(i.ExpectedHeadCommitID) > maxIDBytes ||
			i.TreeHash == "" || len(i.TreeHash) > maxHashBytes || i.CanonicalRequestHash == "" || len(i.CanonicalRequestHash) > maxHashBytes ||
			len(i.AuxiliaryBlobDigestsHash) > maxHashBytes || i.CreatedAtMs <= 0 || i.MutationCount < 0 || i.ByteCount < 0 {
			return fmt.Errorf("opstate: %s holds a malformed checkpoint intent %+v", path, i)
		}
		if i.Resolution == "" && i.ResolvedAtMs != 0 {
			return fmt.Errorf("opstate: %s holds a pending checkpoint intent with a resolution time %+v", path, i)
		}
		if i.Resolution != "" && (!knownCheckpointResolution(i.Resolution) || i.ResolvedAtMs <= 0) {
			return fmt.Errorf("opstate: %s holds an invalid checkpoint outcome %+v", path, i)
		}
		if i.LocalFinalizedAtMs != 0 {
			if !i.Landed() || i.LocalFinalizedAtMs <= 0 {
				return fmt.Errorf("opstate: %s holds an illegally finalized checkpoint intent %+v", path, i)
			}
		}
	}
	return nil
}

func retentionScope(volumeID, branch, instanceID string) string {
	return volumeID + "\x00" + branch + "\x00" + instanceID
}

func (st *state) scopeClosed(volumeID, branch, instanceID string) bool {
	if st.RejectAllUnknown {
		return true
	}
	want := retentionScope(volumeID, branch, instanceID)
	for _, floor := range st.RetentionFloors {
		if retentionScope(floor.VolumeID, floor.Branch, floor.AuthorityInstanceID) == want {
			return true
		}
	}
	return false
}

// ErrFingerprintMismatch is returned when an operation id is reused with a
// different canonical request (kind, fence, or normalized body).
type ErrFingerprintMismatch struct {
	ID           string
	ExistingKind string
}

func (e *ErrFingerprintMismatch) Error() string {
	return fmt.Sprintf("opstate: operation id %q was already used for a different %s request", e.ID, e.ExistingKind)
}

// ErrReceiptMismatch reports an attempt to mutate the successful result under
// an existing id/fingerprint. Successful receipts are immutable: exact replay
// is a no-op, while changed content is never silently upserted.
type ErrReceiptMismatch struct {
	ID string
}

func (e *ErrReceiptMismatch) Error() string {
	return fmt.Sprintf("opstate: operation id %q already has a different immutable result", e.ID)
}

// ErrStorePoisoned fences every subsequent store mutation/admission after a
// persistence result became ambiguous (the target was renamed but directory
// durability failed). Reopening reconciles whichever complete image survived.
type ErrStorePoisoned struct{ Cause error }

func (e *ErrStorePoisoned) Error() string {
	return fmt.Sprintf("opstate: store is poisoned after an ambiguous durable write: %v", e.Cause)
}

func (e *ErrStorePoisoned) Unwrap() error { return e.Cause }

type persistFunc func(path string, candidate *state) (targetReplaced bool, err error)

// Store is the durable operation-state store. All methods are safe for
// concurrent use; every mutation is atomically persisted (temp file + fsync +
// rename + directory fsync) before it returns.
type Store struct {
	mu       sync.Mutex
	path     string
	st       state
	poisoned error
	persist  persistFunc
}

// PathFor is the store path for the WAL at walPath.
func PathFor(walPath string) string {
	return walPath + FileSuffix
}

// Open loads and validates the store at path, tolerating a missing file (fresh
// store). A present-but-undecodable or invalid file is an error: silently
// discarding recorded operation results could turn a retried quiesce into a
// duplicate execution.
func Open(path string) (*Store, error) {
	s := &Store{path: path, st: state{Version: CurrentVersion, Operations: []Operation{}}, persist: persistState}
	if info, err := os.Stat(path); err == nil && info.Size() > maxStoreBytes {
		return nil, fmt.Errorf("opstate: %s is %d bytes (maximum %d)", path, info.Size(), maxStoreBytes)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("opstate: stat %s: %w", path, err)
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opstate: open %s: %w", path, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxStoreBytes+1))
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("opstate: read %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("opstate: close %s after read: %w", path, err)
	}
	if len(raw) > maxStoreBytes {
		return nil, fmt.Errorf("opstate: %s exceeds the %d-byte limit", path, maxStoreBytes)
	}
	var st state
	if err := decodeStrict(raw, &st); err != nil {
		return nil, fmt.Errorf("opstate: decode %s: %w", path, err)
	}
	original := cloneState(st)
	if st.Operations == nil {
		st.Operations = []Operation{}
	}
	// Older version-2 writers could exceed the intended bounds with repeated
	// terminal ids or tombstones. Compact them into the new exact floor model
	// before validation and durably rewrite once; checkpoint/quiesce receipts and
	// their canonical marker/fact remain protected.
	prune(&st, retentionTimestamp(&st))
	if err := st.validate(path); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(original, st) {
		if _, err := persistState(path, &st); err != nil {
			return nil, fmt.Errorf("opstate: persist bounded version-2 normalization: %w", err)
		}
	}
	s.st = st
	return s, nil
}

// Healthy reports whether it is safe to make lifecycle decisions from this
// Store. Controllers call it before receipt lookup so an ambiguous local write
// can never be mistaken for an absent/new operation.
func (s *Store) Healthy() error {
	if s == nil {
		return errors.New("opstate: nil store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthLocked()
}

func (s *Store) healthLocked() error {
	if s.poisoned != nil {
		return &ErrStorePoisoned{Cause: s.poisoned}
	}
	return nil
}

// Operation returns the recorded successful operation for id.
func (s *Store) Operation(id string) (Operation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, op := range s.st.Operations {
		if op.ID == id {
			return op, true
		}
	}
	return Operation{}, false
}

// Tombstone returns the expiry tombstone for id, if its receipt was pruned.
func (s *Store) Tombstone(id string) (Tombstone, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ts := range s.st.Tombstones {
		if ts.ID == id {
			return ts, true
		}
	}
	return Tombstone{}, false
}

// RecordOperation validates and upserts a completed operation, then persists
// before returning. Reusing an id with a different fingerprint fails with
// ErrFingerprintMismatch — a receipt is immutable per canonical request.
func (s *Store) RecordOperation(op Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(func(candidate *state) error {
		_, err := upsert(candidate, op)
		return err
	})
}

// UnknownExpired reports whether an absent operation id belongs to a closed
// authority generation. Exact recorded ids and tombstones must be checked first.
func (s *Store) UnknownExpired(volumeID, branch, instanceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.healthLocked(); err != nil {
		return false, err
	}
	return s.st.scopeClosed(volumeID, branch, instanceID), nil
}

// Quiesced returns the quiesced marker, if any.
func (s *Store) Quiesced() *QuiesceMarker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Quiesced == nil {
		return nil
	}
	m := *s.st.Quiesced
	return &m
}

// SetQuiesced records the quiesced marker together with its operation in one
// atomic persist, so a crash can never leave the marker without the retryable
// operation result (or vice versa).
func (s *Store) SetQuiesced(m QuiesceMarker, op Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(func(candidate *state) error {
		if candidate.Quiesced != nil && *candidate.Quiesced != m {
			return fmt.Errorf("opstate: immutable quiesced marker already records operation %q", candidate.Quiesced.OperationID)
		}
		candidate.Quiesced = &m
		_, err := upsert(candidate, op)
		return err
	})
}

// LeaseRelease returns the durable lease-release fact, if the exact lease of
// this quiesced authority was proven released.
func (s *Store) LeaseRelease() *LeaseReleaseFact {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.LeaseRelease == nil {
		return nil
	}
	f := *s.st.LeaseRelease
	return &f
}

// SetLeaseReleased records the lease-release fact together with its operation
// receipt in one atomic persist. It is an illegal transition before quiesce.
func (s *Store) SetLeaseReleased(f LeaseReleaseFact, op Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(func(candidate *state) error {
		if candidate.Quiesced == nil {
			return fmt.Errorf("opstate: lease release recorded before quiesce (illegal transition)")
		}
		if candidate.LeaseRelease != nil && *candidate.LeaseRelease != f {
			return fmt.Errorf("opstate: immutable lease-release fact already records operation %q", candidate.LeaseRelease.OperationID)
		}
		candidate.LeaseRelease = &f
		_, err := upsert(candidate, op)
		return err
	})
}

// ClearQuiescedForForeignInstance removes a quiesced marker (and its dependent
// lease-release fact) left by a PREVIOUS authority instance (different instance
// id) so a freshly provisioned authority can reuse the same work directory. A
// marker belonging to instanceID itself is kept — that is exactly the
// resurrection the marker exists to prevent. Operation receipts and tombstones
// are retained: ids are globally unique and late retries must stay answerable.
func (s *Store) ClearQuiescedForForeignInstance(instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.healthLocked(); err != nil {
		return err
	}
	m := s.st.Quiesced
	if m == nil {
		return nil
	}
	if instanceID == "" || m.AuthorityInstanceID == instanceID {
		return nil
	}
	return s.mutateLocked(func(candidate *state) error {
		candidate.Quiesced = nil
		candidate.LeaseRelease = nil
		return nil
	})
}

// CheckpointIntent returns the current checkpoint intent (pending or resolved).
func (s *Store) CheckpointIntent() *CheckpointIntent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.CheckpointIntent == nil {
		return nil
	}
	i := *s.st.CheckpointIntent
	return &i
}

// PutCheckpointIntent durably records the exact commit about to be dispatched.
// It refuses to overwrite a still-PENDING intent or a LANDED intent whose local
// WAL cut is not finalized. Either state must be reconciled first, or the only
// durable description of an ambiguous dispatch / required compaction could be
// forgotten.
func (s *Store) PutCheckpointIntent(i CheckpointIntent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(func(candidate *state) error {
		if cur := candidate.CheckpointIntent; cur != nil {
			if cur.OperationID == i.OperationID {
				if *cur != i {
					return fmt.Errorf("opstate: checkpoint intent %q cannot be overwritten with different content or an earlier phase", i.OperationID)
				}
				return nil
			}
			if cur.Pending() {
				return fmt.Errorf("opstate: checkpoint intent %q is still pending; reconcile it before dispatching %q", cur.OperationID, i.OperationID)
			}
			if cur.NeedsLocalFinalization() {
				return fmt.Errorf("opstate: checkpoint intent %q landed but its WAL cut is not finalized; finalize it before dispatching %q", cur.OperationID, i.OperationID)
			}
		}
		candidate.CheckpointIntent = &i
		return nil
	})
}

// ResolveCheckpointIntent persists the reconciliation fact for the current
// intent. Resolving an already-resolved or absent intent is a no-op only when
// the operation id matches; anything else is a caller bug surfaced loudly.
func (s *Store) ResolveCheckpointIntent(operationID, resolution string, atMs int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !knownCheckpointResolution(resolution) || atMs <= 0 {
		return fmt.Errorf("opstate: invalid checkpoint resolution %q at %d", resolution, atMs)
	}
	return s.mutateLocked(func(candidate *state) error {
		cur := candidate.CheckpointIntent
		if cur == nil || cur.OperationID != operationID {
			return fmt.Errorf("opstate: no checkpoint intent %q to resolve", operationID)
		}
		if cur.Resolution != "" {
			if cur.Resolution != resolution {
				return fmt.Errorf("opstate: checkpoint intent %q already resolved as %q, cannot change it to %q", operationID, cur.Resolution, resolution)
			}
			return nil
		}
		cur.Resolution = resolution
		cur.ResolvedAtMs = atMs
		return nil
	})
}

// FinalizeCheckpointIntent durably records that local WAL compaction for this
// landed checkpoint completed. Callers MUST invoke it only after exact-prefix
// compaction succeeds; the store enforces that a landed backend outcome already
// exists. It is idempotent for retry-after-crash handling.
func (s *Store) FinalizeCheckpointIntent(operationID string, atMs int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if atMs <= 0 {
		return fmt.Errorf("opstate: checkpoint intent %q has invalid local finalization time %d", operationID, atMs)
	}
	return s.mutateLocked(func(candidate *state) error {
		cur := candidate.CheckpointIntent
		if cur == nil || cur.OperationID != operationID {
			return fmt.Errorf("opstate: no checkpoint intent %q to finalize", operationID)
		}
		if !cur.Landed() {
			return fmt.Errorf("opstate: checkpoint intent %q cannot be finalized before a landed outcome", operationID)
		}
		if cur.LocalFinalizedAtMs != 0 {
			return nil
		}
		cur.LocalFinalizedAtMs = atMs
		return nil
	})
}

func upsert(st *state, op Operation) (bool, error) {
	if err := op.validate(); err != nil {
		return false, err
	}
	if ts, ok := tombstone(st, op.ID); ok {
		return false, fmt.Errorf("opstate: operation %q expired at %d and cannot be re-recorded (%s)", op.ID, ts.ExpiredAtMs, ts.Kind)
	}
	for i := range st.Operations {
		if st.Operations[i].ID == op.ID {
			if st.Operations[i].Fingerprint != op.Fingerprint {
				return false, &ErrFingerprintMismatch{ID: op.ID, ExistingKind: st.Operations[i].Kind}
			}
			if st.Operations[i] != op {
				return false, &ErrReceiptMismatch{ID: op.ID}
			}
			return false, nil
		}
	}
	// Retention floors are enforced at controller admission, not here: an
	// operation admitted just before a concurrent completion closes the floor
	// must still be allowed to persist its exact result after its side effect.
	// No new operation reaches this completion path once UnknownExpired reports
	// the floor.
	st.Operations = append(st.Operations, op)
	prune(st, op.CompletedAtMs)
	return true, nil
}

func tombstone(st *state, id string) (Tombstone, bool) {
	for _, ts := range st.Tombstones {
		if ts.ID == id {
			return ts, true
		}
	}
	return Tombstone{}, false
}

// prune bounds full receipts, retaining only the exact quiesce/release receipts
// referenced by the saga markers. Every other old result becomes a tombstone.
// When the bounded tombstone set rolls over, the dropped tombstone's authority
// generation is closed by a floor; opaque ids from it can never execute again.
func prune(st *state, nowMs int64) {
	if len(st.Operations) > maxOperations {
		sort.SliceStable(st.Operations, func(i, j int) bool {
			if st.Operations[i].CompletedAtMs == st.Operations[j].CompletedAtMs {
				return st.Operations[i].ID < st.Operations[j].ID
			}
			return st.Operations[i].CompletedAtMs < st.Operations[j].CompletedAtMs
		})
		kept := make([]Operation, 0, maxOperations)
		over := len(st.Operations) - maxOperations
		for _, op := range st.Operations {
			protected := (st.Quiesced != nil && st.Quiesced.OperationID == op.ID) ||
				(st.LeaseRelease != nil && st.LeaseRelease.OperationID == op.ID)
			if over > 0 && !protected {
				st.Tombstones = append(st.Tombstones, Tombstone{
					ID: op.ID, Kind: op.Kind, Fingerprint: op.Fingerprint,
					VolumeID: op.VolumeID, Branch: op.Branch, AuthorityInstanceID: op.AuthorityInstanceID,
					ExpiredAtMs: nowMs,
				})
				over--
				continue
			}
			kept = append(kept, op)
		}
		st.Operations = kept
	}
	if len(st.Tombstones) > maxTombstones {
		sort.SliceStable(st.Tombstones, func(i, j int) bool {
			if st.Tombstones[i].ExpiredAtMs == st.Tombstones[j].ExpiredAtMs {
				return st.Tombstones[i].ID < st.Tombstones[j].ID
			}
			return st.Tombstones[i].ExpiredAtMs < st.Tombstones[j].ExpiredAtMs
		})
		drop := len(st.Tombstones) - maxTombstones
		for _, ts := range st.Tombstones[:drop] {
			addRetentionFloor(st, ts, nowMs)
		}
		st.Tombstones = append([]Tombstone(nil), st.Tombstones[drop:]...)
	}
}

func retentionTimestamp(st *state) int64 {
	var latest int64 = 1
	for _, op := range st.Operations {
		if op.CompletedAtMs > latest {
			latest = op.CompletedAtMs
		}
	}
	for _, ts := range st.Tombstones {
		if ts.ExpiredAtMs > latest {
			latest = ts.ExpiredAtMs
		}
	}
	if latest < int64(^uint64(0)>>1) {
		latest++
	}
	return latest
}

func addRetentionFloor(st *state, ts Tombstone, nowMs int64) {
	if ts.VolumeID == "" || ts.Branch == "" {
		st.RejectAllUnknown = true
		st.RetentionFloors = nil
		return
	}
	want := retentionScope(ts.VolumeID, ts.Branch, ts.AuthorityInstanceID)
	for i := range st.RetentionFloors {
		if retentionScope(st.RetentionFloors[i].VolumeID, st.RetentionFloors[i].Branch, st.RetentionFloors[i].AuthorityInstanceID) == want {
			if nowMs > st.RetentionFloors[i].ClosedAtMs {
				st.RetentionFloors[i].ClosedAtMs = nowMs
			}
			return
		}
	}
	if len(st.RetentionFloors) >= maxRetentionFloors {
		st.RejectAllUnknown = true
		st.RetentionFloors = nil
		return
	}
	st.RetentionFloors = append(st.RetentionFloors, RetentionFloor{
		VolumeID: ts.VolumeID, Branch: ts.Branch, AuthorityInstanceID: ts.AuthorityInstanceID, ClosedAtMs: nowMs,
	})
}

func cloneState(in state) state {
	out := in
	if in.Operations != nil {
		out.Operations = append([]Operation{}, in.Operations...)
	}
	if in.Tombstones != nil {
		out.Tombstones = append([]Tombstone{}, in.Tombstones...)
	}
	if in.RetentionFloors != nil {
		out.RetentionFloors = append([]RetentionFloor{}, in.RetentionFloors...)
	}
	if in.Quiesced != nil {
		value := *in.Quiesced
		out.Quiesced = &value
	}
	if in.LeaseRelease != nil {
		value := *in.LeaseRelease
		out.LeaseRelease = &value
	}
	if in.CheckpointIntent != nil {
		value := *in.CheckpointIntent
		out.CheckpointIntent = &value
	}
	return out
}

func (s *Store) mutateLocked(change func(*state) error) error {
	if err := s.healthLocked(); err != nil {
		return err
	}
	candidate := cloneState(s.st)
	if err := change(&candidate); err != nil {
		return err
	}
	if reflect.DeepEqual(candidate, s.st) {
		return nil
	}
	if err := candidate.validate(s.path); err != nil {
		return err
	}
	replaced, err := s.persist(s.path, &candidate)
	if err != nil {
		if replaced {
			s.poisoned = err
			return &ErrStorePoisoned{Cause: err}
		}
		return err
	}
	s.st = candidate
	return nil
}

// persistState writes candidate atomically: temp file in the same directory,
// fsync, rename over the target, fsync the directory. targetReplaced is true
// only after rename, allowing Store to distinguish a definite pre-commit error
// from an ambiguous directory-durability result that must poison admission.
func persistState(path string, candidate *state) (targetReplaced bool, err error) {
	raw, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return false, fmt.Errorf("opstate: encode: %w", err)
	}
	if len(raw)+1 > maxStoreBytes {
		return false, fmt.Errorf("opstate: encoded state is %d bytes (maximum %d)", len(raw)+1, maxStoreBytes)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("opstate: temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		cleanup()
		return false, fmt.Errorf("opstate: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return false, fmt.Errorf("opstate: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return false, fmt.Errorf("opstate: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return false, fmt.Errorf("opstate: rename: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return true, fmt.Errorf("opstate: open dir after replace: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return true, fmt.Errorf("opstate: fsync dir after replace: %w", err)
	}
	return true, nil
}

func decodeStrict(raw []byte, target any) error {
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("object member name is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return fmt.Errorf("duplicate JSON object member %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closeToken, err := decoder.Token()
			if err != nil || closeToken != json.Delim('}') {
				return fmt.Errorf("invalid JSON object close: %v", err)
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closeToken, err := decoder.Token()
			if err != nil || closeToken != json.Delim(']') {
				return fmt.Errorf("invalid JSON array close: %v", err)
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

var _ OperationStore = (*Store)(nil)
