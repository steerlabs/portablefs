package writeback

import (
	"context"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Remote is the authority surface the engine drives. Every method rides
// fsproto v8 coordination in production and accepts the engine lifetime
// context. Exact release resolves a sent identity to a durable outcome;
// forced teardown locally aborts the protocol client, then joins the engine's
// release workers before closing the WAL.
type Remote interface {
	// DelegationAcquire asks the authority to delegate scope to this mount's
	// stream. The authority applies the adaptive policy and either grants
	// (server epoch plus, for an existing directory, the authoritative
	// children snapshot) or denies — the caller then executes write-through
	// and backs off. The outcome must be DEFINITE: the implementation
	// resolves a sent-but-unanswered request (replaying the identical exact
	// identity) instead of returning an ambiguous error, for as long as the
	// context lives.
	//
	// If local reply completion (for example replay-snapshot seeding) fails
	// after the authority's grant is already known, the implementation
	// returns that Granted reply together with the error. Engine then
	// definitely releases the uninstalled epoch before reporting failure.
	DelegationAcquire(ctx context.Context, scope, writebackID string) (AcquireReply, error)

	// ReleaseDelegation releases the caller's grant after a full drain.
	// Same exactness contract as DelegationAcquire: the outcome is resolved,
	// never guessed.
	ReleaseDelegation(ctx context.Context, scope, epoch string) error

	// Flush ships one dense run of ONE LANE of the mount stream. The records
	// carry their lane sequences; the authority verifies density and the lane's
	// chained digest, enforces a data batch's namespace dependency, applies,
	// and advances that lane's durable watermark in the same transaction.
	Flush(ctx context.Context, req FlushRequest) (FlushReply, error)

	// FlushResolved is the recovery-only flush surface. Once a request may
	// have reached the authority, it must keep resolving the identical
	// idempotent batch until its outcome is known or the recovery session is
	// terminalized. Unlike the live flusher, recovery may not leave an
	// authority mutation running after Open releases the store lock.
	FlushResolved(ctx context.Context, req FlushRequest) (FlushReply, error)

	// StreamState reads the stream's durable watermark and digest.
	StreamState(ctx context.Context, writebackID string) (StreamState, error)

	// Rebind atomically fences the stream's dead holder session and rebinds
	// its recovery scopes to the caller's session after verifying stream
	// identity and EVERY LANE's watermark + digest. Typed conflicts are returned
	// in the reply. The claim covers all lanes because a stream born after the
	// lane boundary has a permanently-zero legacy watermark: verifying only that
	// pair would verify nothing about it.
	Rebind(ctx context.Context, writebackID string, scopes []RebindScope, mark StreamState) (RebindReply, error)

	// Discard releases the stream's recovery scopes as an audited data-loss
	// decision. It has the same resolved-until-terminal contract as Rebind and
	// FlushResolved.
	Discard(ctx context.Context, writebackID string, scopes []RebindScope) error

	// SupportsLanes reports whether the connected authority keeps a per-lane
	// durable watermark (fsproto FeatureWritebackLanes). It gates the ONE
	// irreversible decision lanes involve — opening a stream's laned era — and
	// nothing else: a stream that has not opened it keeps writing the legacy
	// single stream, which every authority understands. It is deliberately NOT
	// consulted per flush; a capability that could change mid-stream would make
	// the WAL's own framing ambiguous.
	SupportsLanes() bool
}

// AcquireReply is the authority's adaptive decision for one scope.
type AcquireReply struct {
	Granted bool
	Epoch   string

	// Exists/Self report the scope path's current object, when it exists.
	Exists bool
	Self   Entry

	// HasChildren carries the authoritative children snapshot for an
	// existing-directory grant. A duplicate replay of a lost grant reply
	// omits it; the caller re-seeds with one readdir under the held grant.
	HasChildren bool
	Children    []Entry
}

// StreamLane names one independently-applicable lane of the write-back stream.
// The values are the wire values (fsproto Request.WBLane / pfc2.StreamLane);
// this package does not import either, so they are restated here and pinned by
// TestStreamLaneValuesMatchTheWire.
type StreamLane uint8

const (
	// StreamLaneLegacy is the single total-order stream every pre-round-7 WAL
	// is written in. A stream leaves it once, at the upgrade boundary, and
	// never returns; it is not a runtime fallback.
	StreamLaneLegacy StreamLane = 0
	// StreamLaneNamespace carries namespace and attribute records whose apply
	// order depends on nothing outside the namespace lane.
	StreamLaneNamespace StreamLane = 1
	// StreamLaneData carries bulk write payloads — and any namespace record
	// whose scope still holds unapplied bulk data, so that a record which must
	// apply AFTER pending data rides the lane that already orders it.
	StreamLaneData StreamLane = 2

	streamLaneCount = 3
)

func (l StreamLane) String() string {
	switch l {
	case StreamLaneLegacy:
		return "legacy"
	case StreamLaneNamespace:
		return "namespace"
	case StreamLaneData:
		return "data"
	default:
		return "invalid"
	}
}

// FlushScope is one contiguous run in a mixed-scope mount-stream flush.
// Through is the last LANE sequence covered by the run.
type FlushScope struct {
	Scope   string
	Epoch   string
	Through uint64
}

// FlushRequest is one dense run of one lane of the mount stream. ScopeRuns map
// every record to the exact live delegation that authorizes it.
type FlushRequest struct {
	WritebackID string
	Lane        StreamLane
	// NSRequired is a data-lane batch's namespace dependency: the namespace
	// lane watermark its records were admitted behind. The authority holds the
	// batch until its namespace watermark covers it. Zero on every other lane.
	NSRequired uint64
	PrevDigest [32]byte
	EndDigest  [32]byte
	// Records carry their LANE sequences in Seq.
	Records   []wal.Record
	ScopeRuns []FlushScope
}

// FlushReply reports the flushed lane's durable authority watermark.
type FlushReply struct {
	Through uint64
	Status  int32 // fsproto status: 0 OK; ESTALE fence; EINVAL corrupt-class
}

// StreamState is the authority's durable stream view: the legacy single-stream
// position plus each lane's independent one.
type StreamState struct {
	Exists      bool
	Through     uint64
	Digest      [32]byte
	NSThrough   uint64
	NSDigest    [32]byte
	DataThrough uint64
	DataDigest  [32]byte
}

// LaneThrough reads one lane's durable watermark.
func (s StreamState) LaneThrough(lane StreamLane) uint64 {
	switch lane {
	case StreamLaneNamespace:
		return s.NSThrough
	case StreamLaneData:
		return s.DataThrough
	default:
		return s.Through
	}
}

// LaneDigest reads one lane's durable chain digest.
func (s StreamState) LaneDigest(lane StreamLane) [32]byte {
	switch lane {
	case StreamLaneNamespace:
		return s.NSDigest
	case StreamLaneData:
		return s.DataDigest
	default:
		return s.Digest
	}
}

// RebindScope names one delegation the recovering stream claims.
type RebindScope struct {
	Scope string
	Epoch string
}

// RebindReply reports typed recovery conflicts; empty means the rebind
// committed and the stream may drain.
type RebindReply struct {
	Conflicts []ConflictDetail
}

// ConflictDetail is one typed recovery conflict (never silently merged).
type ConflictDetail struct {
	Scope string `json:"scope"`
	Epoch string `json:"epoch"`
	Kind  string `json:"kind"` // SCOPE_DISCARDED, SCOPE_MISSING, HOLDER_CHANGED, DIGEST_MISMATCH, BRANCH_REPLACED
}

func (c ConflictDetail) String() string {
	return fmt.Sprintf("%s %q@%s", c.Kind, c.Scope, c.Epoch)
}

// ErrConflict wraps a typed recovery conflict: the WAL stays intact and
// exportable; nothing merges or discards without an explicit operator
// decision.
var ErrConflict = errors.New("writeback: recovery conflict")

// ErrFenced marks a definite authority fence of the mount session: the
// stream parks durably and recovers on the next attach.
var ErrFenced = errors.New("writeback: session fenced")
