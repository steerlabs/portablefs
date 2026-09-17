package writeback

import (
	"context"
	"errors"
	"syscall"
	"time"
)

const (
	DefaultMaxBytes   = 64 << 20
	DefaultMaxEntries = 10_000
	MaxPayload        = 1 << 20
)

var (
	ErrClosed  = errors.New("writeback: stopped")
	ErrLost    = errors.New("writeback: buffered data lost")
	ErrInvalid = errors.New("writeback: invalid argument")
	ErrPending = errors.New("writeback: retirement has unapplied entries")
)

type Identity [16]byte

type Kind uint8

const (
	Write Kind = iota + 1
	Truncate
	SetAttr
)

type State uint8

const (
	Accepted State = iota + 1
	Applied
	Visible
	Durable
	Lost
)

// Attributes mirrors the optional fields of SetAttrRequest. Values whose Has
// bit is false are ignored. Now flags resolve once to time.Now at admission. Combining a Now flag
// and its explicit HasTime bit is invalid. Resolution before buffering keeps
// retries and the local attribute overlay on the same timestamp.
type Attributes struct {
	Mode, UID, GID                                       uint32
	Size, ATimeNS, MTimeNS                               int64
	HasMode, HasUID, HasGID, HasSize, HasATime, HasMTime bool
	ATimeNow, MTimeNow                                   bool
	// CTime is overlay-only; it is never sent as a user SETATTR value.
	CTimeNS  int64
	HasCTime bool
}

// Cut is an immutable mount-local accepted-sequence snapshot. Use only cuts
// returned by this Buffer. Zero denotes the empty cut, not "flush everything".
type Cut struct {
	Sequence     uint64
	LossSequence uint64
}

// WriteOptions preserves transport ownership and privilege effects across buffering.
// Flags is opaque to the buffer. KillPrivileges describes the corresponding
// relative mode change for the local overlay; later chmod records still win.
type WriteOptions struct {
	Flags          uint32
	LockOwner      uint64
	KillPrivileges bool
}

// Entry is one immutable transport operation. Token is stable across retries.
// First and Last bound the accepted operations represented by this operation;
// they are mount-local, not Authority sequences. Data is borrowed for the call.
type Entry struct {
	Token, First, Last, Generation uint64
	Kind                           Kind
	Offset                         int64
	Data                           []byte
	Attributes                     Attributes
	WriteOptions                   WriteOptions
}

// Flusher applies one operation, returning its nonzero Authority sequence.
// Calls for an identity are serialized; disjoint identities run concurrently.
// The implementation must deduplicate Token (scoped to this Buffer/session),
// including calls that return errors after applying. It must arrange eventual
// visibility and durability notifications, including when the buffer is full.
// A returned error retains the operation for retry; permanent rejection must
// call Drop. No buffer lock is held while Flush executes.
type Flusher interface {
	Flush(context.Context, Identity, Entry) (uint64, error)
}

// FlushCycleObserver optionally coalesces frontend work after an identity's
// background flush cut. It runs outside all buffer locks, once per cycle.
// It does not order frontend publication after admission; frontends must
// retain a separate boundary for work published after the flush completes.
type FlushCycleObserver interface {
	FlushCycleCompleted(context.Context, Identity)
}

type Options struct {
	// InitialLossSequence carries the mount counter across an epoch replacement.
	InitialLossSequence uint64
	MaxBytes            int64
	MaxEntries          int
	// MaxFlushIdentities bounds the worker pool used by FlushAll. Zero uses
	// 16. Explicit identity flushes (recall/fsync) bypass that pool.
	MaxFlushIdentities int
	// Zero uses one second. A negative interval disables the timer for tests;
	// cap-triggered and explicit flushing remain enabled.
	FlushInterval time.Duration
}

type Stats struct {
	WaitingAdmissions          int
	Bytes                      int64
	Entries                    int
	Accepted, Applied, Visible int
	LossSequence               uint64
}

type DropReport struct {
	Errno        syscall.Errno
	Identity     Identity
	Reason       string
	Bytes        int64
	Entries      int
	LossSequence uint64
}

// Fetch returns bytes starting at off. Short reads (with nil or io.EOF) denote
// EOF; other errors propagate. Read never changes the returned storage.
type Fetch func(context.Context, int64, int) ([]byte, error)
