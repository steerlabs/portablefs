package writeback

import (
	"context"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Remote is the authority surface the engine drives. Every method rides
// fsproto v6 exact envelopes in production and is context-aware: the engine
// bounds each attempt and cancels in-flight work on force-close, so a late
// reply can never act against a closed WAL.
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

	// StreamState reads the stream's durable watermark and digest.
	StreamState(ctx context.Context, writebackID string) (StreamState, error)

	// Rebind atomically fences the stream's dead holder session and rebinds
	// its recovery scopes to the caller's session after verifying stream
	// identity and digest. Typed conflicts are returned in the reply.
	Rebind(ctx context.Context, writebackID string, scopes []RebindScope, through uint64, digest [32]byte) (RebindReply, error)

	// Discard releases the stream's recovery scopes as an audited data-loss
	// decision.
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

// FlushRequest is one dense same-scope run of the mount stream.
type FlushRequest struct {
	WritebackID string
	Scope       string
	Epoch       string
	PrevDigest  [32]byte
	EndDigest   [32]byte
	// Records carry their global stream sequences in Seq.
	Records []wal.Record
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
