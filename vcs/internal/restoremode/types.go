// Package restoremode implements the authority side of PortableFS restore.
//
// The durable map contains only stored chunks named by the hydrator's drain
// order. Whole-hole chunks are already canonical sparse zeroes in the
// materialized namespace and therefore need neither a bit nor a fetch. An
// entry is complete when every stored chunk for that entry is durably marked.
// Read recalls are intentionally memory-only until drain or a user mutation
// first fdatasyncs the inode; this prevents a later, unrelated map fsync from
// making a lazy mark durable ahead of its base bytes.
package restoremode

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// A recall past RecallLimit queues inside fetchChunk rather than failing;
	// only a deadline that expires while queued or fetching surfaces, as
	// ErrRecallDeadline.
	ErrRecallDeadline = errors.New("restoremode: recall deadline exceeded")
	ErrBlocked        = errors.New("restoremode: restore blocked")
	ErrCorrupt        = errors.New("restoremode: restore corrupt")
	ErrProtocol       = errors.New("restoremode: hydrator protocol violation")
)

const (
	ReadyFilename     = "restore-namespace-ready.json"
	BindingsFilename  = "restore-bindings"
	MapFilename       = "restore-map.bin"
	ProgressFilename  = "restore-progress.json"
	ConvergedFilename = "restore-converged.json"
	HydratorSocket    = "hydrator.sock"
	QuiesceProof      = "quiesce-proof.json"
	QuiesceRequest    = "quiesce-request.json"
)

// Store is the authority-owned write path used by recall and drain. The
// implementation binds entry indices to descriptor-held inodes before Mode is
// published, so no pathname is resolved while applying archive bytes.
type Store interface {
	LogicalSize(entry uint32) (int64, error)
	PWrite(entry uint32, off int64, data []byte) error
	Fdatasync(entry uint32) error
	RestoreMtime(entry uint32) error
	Linked(entry uint32) (bool, error)
	// DiscardUnlinked drops an entry only after no authority item or open
	// capability can make its unlinked inode reachable again.
	DiscardUnlinked(entry uint32) (bool, error)
}

type Config struct {
	StateRoot      string
	VolumeID       string
	AuthorityEpoch uint64
	Store          Store
	Bindings       *Bindings

	RecallDeadline   time.Duration
	RecallLimit      int
	PoolSize         int
	DrainWorkers     int
	DrainHysteresis  time.Duration
	ProgressInterval time.Duration
	MaxEntries       uint32
	MaxStoredChunks  uint64
	MaxFrameBytes    uint32
	Now              func() time.Time

	// OnDurableMark is a test/diagnostic hook invoked after the map fsync. It
	// never participates in correctness and production leaves it nil.
	OnDurableMark func(entry, chunk uint32, userModified bool)
	disableDrain  bool
	drainStart    <-chan struct{}
}

func (c *Config) defaults() {
	if c.RecallDeadline == 0 {
		c.RecallDeadline = 20 * time.Second
	}
	if c.RecallLimit == 0 {
		c.RecallLimit = 16
	}
	if c.PoolSize == 0 {
		c.PoolSize = 8
	}
	if c.DrainWorkers == 0 {
		c.DrainWorkers = 4
	}
	if c.DrainHysteresis == 0 {
		c.DrainHysteresis = 5 * time.Second
	}
	if c.ProgressInterval == 0 {
		c.ProgressInterval = 3 * time.Second
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 1 << 24
	}
	if c.MaxStoredChunks == 0 {
		c.MaxStoredChunks = 1 << 28
	}
	if c.MaxFrameBytes == 0 {
		c.MaxFrameBytes = 16<<20 + 64<<10
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

func (c Config) validate() error {
	if c.StateRoot == "" || c.VolumeID == "" || c.Store == nil {
		return errors.New("restoremode: state root, volume ID, and store are required")
	}
	if c.RecallDeadline <= 0 || c.RecallDeadline >= 30*time.Second {
		return errors.New("restoremode: recall deadline must be positive and below the authority write timeout")
	}
	if c.RecallLimit <= 0 || c.PoolSize <= 0 || c.DrainWorkers <= 0 || c.DrainWorkers > c.PoolSize ||
		c.DrainHysteresis <= 0 || c.ProgressInterval <= 0 || c.MaxEntries == 0 || c.MaxStoredChunks == 0 || c.MaxFrameBytes < 1024 {
		return errors.New("restoremode: invalid bounded runtime configuration")
	}
	return nil
}

type chunkKey struct {
	entry uint32
	chunk uint32
}

type Extent struct {
	Offset uint64
	Data   []byte
}

type Chunk struct {
	Extents []Extent
	Bytes   uint64
}

type State string

const (
	StateHealthy State = ""
	StateBlocked State = "blocked"
	StateCorrupt State = "corrupt"
)

type stateError struct {
	base   error
	detail string
}

func (e *stateError) Error() string { return fmt.Sprintf("%v: %s", e.base, e.detail) }
func (e *stateError) Unwrap() error { return e.base }

func recallContext(parent context.Context, deadline time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, deadline)
	return ctx, cancel
}
