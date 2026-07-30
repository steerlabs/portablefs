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
	DelegationAcquire(ctx context.Context, scope, writebackID string) (AcquireReply, error)

	// ReleaseDelegation releases the caller's grant after a full drain.
	// Same exactness contract as DelegationAcquire: the outcome is resolved,
	// never guessed.
	ReleaseDelegation(ctx context.Context, scope, epoch string) error

	// Flush ships one dense same-scope run of the mount stream. The records
	// carry their global stream sequences; the authority verifies density and
	// the chained stream digest, applies, and advances the durable watermark
	// in the same transaction.
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
	// identity and digest. Typed conflicts are returned in the reply.
	Rebind(ctx context.Context, writebackID string, scopes []RebindScope, through uint64, digest [32]byte) (RebindReply, error)

	// Discard releases the stream's recovery scopes as an audited data-loss
	// decision. It has the same resolved-until-terminal contract as Rebind and
	// FlushResolved.
	Discard(ctx context.Context, writebackID string, scopes []RebindScope) error
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

// FlushScope is one contiguous run in a mixed-scope mount-stream flush.
// Through is the last global stream sequence covered by the run.
type FlushScope struct {
	Scope   string
	Epoch   string
	Through uint64
}

// FlushRequest is one dense global run of the mount stream. ScopeRuns map
// every record to the exact live delegation that authorizes it.
type FlushRequest struct {
	WritebackID string
	PrevDigest  [32]byte
	EndDigest   [32]byte
	// Records carry their global stream sequences in Seq.
	Records   []wal.Record
	ScopeRuns []FlushScope
}

// FlushReply reports the stream's durable authority watermark.
type FlushReply struct {
	Through uint64
	Status  int32 // fsproto status: 0 OK; ESTALE fence; EINVAL corrupt-class
}

// StreamState is the authority's durable stream view.
type StreamState struct {
	Exists  bool
	Through uint64
	Digest  [32]byte
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
