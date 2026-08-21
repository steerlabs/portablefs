package restoremode

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const chunkLockShards = 4096

const (
	drainBackoffInitial = time.Second
	drainBackoffMaximum = 30 * time.Second
)

type Mode struct {
	cfg      Config
	ready    readyRecord
	bindings *Bindings
	client   *hydratorClient

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	initMu      sync.RWMutex
	initialized bool
	info        InfoPage
	stored      map[chunkKey]struct{}
	storedEntry map[uint32][]chunkKey
	hmap        *hydrationMap
	entryLocks  []sync.RWMutex
	chunkLocks  [chunkLockShards]sync.Mutex

	stateMu       sync.RWMutex
	state         State
	stateDetail   string
	converged     atomic.Bool
	recalls       chan struct{}
	recalledBytes atomic.Uint64
	drainedBytes  atomic.Uint64
	lastRecallNS  atomic.Int64
	drainCancelMu sync.Mutex
	drainCancels  map[uint64]context.CancelFunc
	drainCancelID atomic.Uint64
	closeOnce     sync.Once
}

func Open(ctx context.Context, cfg Config) (*Mode, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if filepath.Clean(cfg.StateRoot) != cfg.StateRoot || !filepath.IsAbs(cfg.StateRoot) {
		return nil, errors.New("restoremode: state root must be an absolute clean path")
	}
	var ready readyRecord
	if err := readStrictJSON(filepath.Join(cfg.StateRoot, ReadyFilename), &ready); err != nil {
		return nil, fmt.Errorf("read restore ready marker: %w", err)
	}
	volumeUUID, volumeErr := parseUUID(ready.VolumeID)
	attemptUUID, attemptErr := parseUUID(ready.Attempt)
	if ready.Version != 1 || ready.VolumeID != cfg.VolumeID || volumeErr != nil || attemptErr != nil ||
		formatUUID(volumeUUID) != ready.VolumeID || formatUUID(attemptUUID) != ready.Attempt || ready.SealedEpoch == 0 ||
		ready.Entries == 0 || ready.Entries > uint64(cfg.MaxEntries) || ready.WrittenUnix <= 0 {
		return nil, errors.New("restoremode: ready marker does not match this volume")
	}
	bindings := cfg.Bindings
	var err error
	if bindings == nil {
		bindings, err = LoadBindings(filepath.Join(cfg.StateRoot, BindingsFilename), cfg.MaxEntries)
		if err != nil {
			return nil, err
		}
	}
	if ready.Entries != uint64(bindings.Len()) {
		return nil, errors.New("restoremode: ready marker and bindings entry counts differ")
	}
	modeCtx, cancel := context.WithCancel(ctx)
	m := &Mode{cfg: cfg, ready: ready, bindings: bindings,
		client: newHydratorClient(filepath.Join(cfg.StateRoot, HydratorSocket), cfg.PoolSize, cfg.MaxFrameBytes),
		ctx:    modeCtx, cancel: cancel, recalls: make(chan struct{}, cfg.RecallLimit), entryLocks: make([]sync.RWMutex, bindings.Len()),
		drainCancels: make(map[uint64]context.CancelFunc)}
	bootstrapCtx, bootstrapCancel := recallContext(modeCtx, cfg.RecallDeadline)
	err = m.bootstrap(bootstrapCtx)
	bootstrapCancel()
	if err != nil {
		m.noteFailure(err)
	}
	m.wg.Add(2)
	go m.bootstrapAndHealthLoop()
	go m.progressLoop()
	return m, nil
}

func (m *Mode) Bindings() *Bindings { return m.bindings }

// Active is the converged fast-path check. Once false, callers avoid identity
// derivation as well as every map, lock, and hydrator operation.
func (m *Mode) Active() bool { return m != nil && !m.converged.Load() }

func (m *Mode) Entry(identity [16]byte) (uint32, bool) {
	if m == nil || m.converged.Load() {
		return 0, false
	}
	return m.bindings.Entry(identity)
}

func (m *Mode) ChunkSize() uint32 {
	m.initMu.RLock()
	defer m.initMu.RUnlock()
	return m.info.ChunkSize
}

func (m *Mode) bootstrap(ctx context.Context) error {
	m.initMu.RLock()
	initialized := m.initialized
	m.initMu.RUnlock()
	if initialized || m.converged.Load() {
		return nil
	}
	info, err := m.client.info(ctx, m.cfg.MaxStoredChunks)
	if err != nil {
		return err
	}
	switch {
	case info.FormatVersion != 1:
		return fmt.Errorf("%w: INFO format version %d is unsupported", ErrCorrupt, info.FormatVersion)
	case info.VolumeID != m.cfg.VolumeID:
		return fmt.Errorf("%w: INFO volume ID does not match the restore marker", ErrCorrupt)
	case info.SealedEpoch != m.ready.SealedEpoch:
		return fmt.Errorf("%w: INFO sealed epoch does not match the restore marker", ErrCorrupt)
	case info.Attempt != m.ready.Attempt:
		return fmt.Errorf("%w: INFO attempt does not match the restore marker", ErrCorrupt)
	case info.ChunkSize == 0:
		return fmt.Errorf("%w: INFO chunk size is zero", ErrCorrupt)
	case info.EntryCount != uint32(m.bindings.Len()):
		return fmt.Errorf("%w: INFO entry count does not match restore bindings", ErrCorrupt)
	case info.DrainCount != uint64(len(info.Order)) || info.DrainCount > info.ChunkCount || info.DrainCount > m.cfg.MaxStoredChunks:
		return fmt.Errorf("%w: INFO drain count is inconsistent or exceeds the configured bound", ErrCorrupt)
	}
	stored := make(map[chunkKey]struct{}, len(info.Order))
	storedEntry := make(map[uint32][]chunkKey)
	for _, pair := range info.Order {
		key := chunkKey{entry: pair[0], chunk: pair[1]}
		if key.entry >= info.EntryCount {
			return fmt.Errorf("%w: drain entry out of range", ErrCorrupt)
		}
		if _, duplicate := stored[key]; duplicate {
			return fmt.Errorf("%w: duplicate drain chunk", ErrCorrupt)
		}
		size, err := m.cfg.Store.LogicalSize(key.entry)
		if err != nil {
			return fmt.Errorf("%w: resolve restored entry %d: %v", ErrCorrupt, key.entry, err)
		}
		chunks := uint64(0)
		if size > 0 {
			chunks = (uint64(size) + uint64(info.ChunkSize) - 1) / uint64(info.ChunkSize)
		}
		if uint64(key.chunk) >= chunks {
			return fmt.Errorf("%w: drain chunk outside materialized logical size", ErrCorrupt)
		}
		stored[key] = struct{}{}
		storedEntry[key.entry] = append(storedEntry[key.entry], key)
	}
	hmap, err := openHydrationMap(filepath.Join(m.cfg.StateRoot, MapFilename), info.ChunkSize, m.bindings.Digest(),
		m.cfg.MaxStoredChunks+uint64(m.bindings.Len()), m.cfg.OnDurableMark)
	if err != nil {
		return fmt.Errorf("%w: open hydration map: %v", ErrCorrupt, err)
	}
	m.initMu.Lock()
	if m.initialized {
		m.initMu.Unlock()
		_ = hmap.Close()
		return nil
	}
	m.info, m.stored, m.storedEntry, m.hmap, m.initialized = info, stored, storedEntry, hmap, true
	m.initMu.Unlock()
	m.clearBlocked()
	if !m.cfg.disableDrain {
		m.wg.Add(1)
		go m.drain()
	}
	return nil
}

func (m *Mode) bootstrapAndHealthLoop() {
	defer m.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if m.converged.Load() {
			return
		}
		m.initMu.RLock()
		initialized := m.initialized
		m.initMu.RUnlock()
		ctx, cancel := recallContext(m.ctx, minDuration(m.cfg.RecallDeadline, 5*time.Second))
		var err error
		if initialized {
			err = m.client.health(ctx)
		} else {
			err = m.bootstrap(ctx)
		}
		cancel()
		if err == nil {
			m.clearBlocked()
			backoff = time.Second
		} else {
			m.noteFailure(err)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (m *Mode) noteFailure(err error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.state == StateCorrupt {
		return
	}
	if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrProtocol) {
		m.state, m.stateDetail = StateCorrupt, err.Error()
		return
	}
	m.state, m.stateDetail = StateBlocked, err.Error()
}

func (m *Mode) clearBlocked() {
	m.stateMu.Lock()
	if m.state == StateBlocked {
		m.state, m.stateDetail = StateHealthy, ""
	}
	m.stateMu.Unlock()
}

func (m *Mode) ContentError() error {
	if m == nil || m.converged.Load() {
		return nil
	}
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	switch m.state {
	case StateBlocked:
		return &stateError{base: ErrBlocked, detail: m.stateDetail}
	case StateCorrupt:
		return &stateError{base: ErrCorrupt, detail: m.stateDetail}
	default:
		return nil
	}
}

func (m *Mode) EnsureHydrated(ctx context.Context, identity [16]byte, offset, length uint64) error {
	if m == nil || m.converged.Load() || length == 0 {
		return nil
	}
	if err := m.ContentError(); err != nil {
		return err
	}
	entry, ok := m.bindings.Entry(identity)
	if !ok {
		return nil
	}
	keys, err := m.keysForRange(entry, offset, length)
	if err != nil || len(keys) == 0 {
		return err
	}
	m.preemptDrain()
	recallCtx, cancel := recallContext(ctx, m.cfg.RecallDeadline)
	defer cancel()
	for _, key := range keys {
		lock := m.chunkLock(key)
		lock.Lock()
		_, err := m.hydrateLocked(recallCtx, key, false, true)
		lock.Unlock()
		if err != nil {
			err = namedRecallError(recallCtx, err)
			if !errors.Is(err, ErrRecallDeadline) {
				m.noteFailure(err)
			}
			return err
		}
	}
	return nil
}

func (m *Mode) WithAttrLock(identity [16]byte, fn func() error) error {
	if m == nil || m.converged.Load() {
		return fn()
	}
	entry, ok := m.bindings.Entry(identity)
	if !ok {
		return fn()
	}
	m.entryLocks[entry].RLock()
	defer m.entryLocks[entry].RUnlock()
	return fn()
}

// Write serializes recall, drain, and a user write through the same chunk
// state locks. Every stored chunk in the requested range is durably hydrated
// before apply, so the accepted range cannot affect restore map state.
func (m *Mode) Write(ctx context.Context, identity [16]byte, offset uint64, length uint32, apply func() (int, int64, error)) (int, int64, error) {
	// A zero-length write is a POSIX no-op: it moves no bytes and no mtime,
	// so it must not record the entry as user-modified — that record would
	// permanently suppress archived-mtime restoration for an untouched file.
	if m == nil || m.converged.Load() || length == 0 {
		return apply()
	}
	entry, ok := m.bindings.Entry(identity)
	if !ok {
		return apply()
	}
	keys, err := m.keysForRange(entry, offset, uint64(length))
	if err != nil {
		return 0, 0, err
	}
	m.preemptDrain()
	locks := m.lockKeys(keys)
	defer unlockLocks(locks)
	if len(keys) != 0 {
		recallCtx, cancel := recallContext(ctx, m.cfg.RecallDeadline)
		for _, key := range keys {
			if _, err := m.hydrateLocked(recallCtx, key, true, true); err != nil {
				cancel()
				err = namedRecallError(recallCtx, err)
				if !errors.Is(err, ErrRecallDeadline) {
					m.noteFailure(err)
				}
				return 0, 0, err
			}
		}
		cancel()
	}
	// A failed apply can conservatively suppress archived mtime restoration;
	// recording the user mutation before apply keeps later hydration invisible.
	if err := m.hmap.markDurable(nil, &entry); err != nil {
		return 0, 0, err
	}
	// An assigned append can move beyond its requested range, but not into a
	// cold stored chunk outside keys: restore starts at the sealed EOF, and a
	// truncate durably marks the removed tail before a later append can reuse it.
	m.entryLocks[entry].Lock()
	n, assigned, applyErr := apply()
	m.entryLocks[entry].Unlock()
	return n, assigned, applyErr
}

func (m *Mode) Truncate(ctx context.Context, identity [16]byte, oldSize, newSize int64, apply func() error) error {
	if m == nil || m.converged.Load() {
		return apply()
	}
	entry, ok := m.bindings.Entry(identity)
	if !ok {
		return apply()
	}
	m.preemptDrain()
	m.initMu.RLock()
	keys := append([]chunkKey(nil), m.storedEntry[entry]...)
	m.initMu.RUnlock()
	locks := m.lockKeys(keys)
	defer unlockLocks(locks)
	if newSize > 0 && newSize < oldSize && uint64(newSize)%uint64(m.ChunkSize()) != 0 {
		boundary := chunkKey{entry: entry, chunk: uint32(uint64(newSize) / uint64(m.ChunkSize()))}
		if m.isStored(boundary) {
			recallCtx, cancel := recallContext(ctx, m.cfg.RecallDeadline)
			_, err := m.hydrateLocked(recallCtx, boundary, true, true)
			cancel()
			if err != nil {
				err = namedRecallError(recallCtx, err)
				if !errors.Is(err, ErrRecallDeadline) {
					m.noteFailure(err)
				}
				return err
			}
		}
		if err := m.hmap.markDurable(nil, &entry); err != nil {
			return err
		}
	}
	m.entryLocks[entry].Lock()
	if err := apply(); err != nil {
		m.entryLocks[entry].Unlock()
		return err
	}
	if err := m.cfg.Store.Fdatasync(entry); err != nil {
		m.entryLocks[entry].Unlock()
		return err
	}
	var beyond []chunkKey
	for _, key := range keys {
		if uint64(key.chunk)*uint64(m.ChunkSize()) >= uint64(max64(newSize, 0)) {
			beyond = append(beyond, key)
		}
	}
	err := m.hmap.markDurable(beyond, &entry)
	m.entryLocks[entry].Unlock()
	return err
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func namedRecallError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrRecallDeadline
	}
	return err
}

func (m *Mode) keysForRange(entry uint32, offset, length uint64) ([]chunkKey, error) {
	m.initMu.RLock()
	defer m.initMu.RUnlock()
	if !m.initialized {
		return nil, ErrBlocked
	}
	if length == 0 {
		return nil, nil
	}
	end := offset + length
	if end < offset {
		return nil, errors.New("restoremode: byte range overflow")
	}
	first, last := offset/uint64(m.info.ChunkSize), (end-1)/uint64(m.info.ChunkSize)
	if last > math.MaxUint32 {
		return nil, errors.New("restoremode: chunk index overflow")
	}
	keys := make([]chunkKey, 0, last-first+1)
	for chunk := first; chunk <= last; chunk++ {
		key := chunkKey{entry: entry, chunk: uint32(chunk)}
		if _, stored := m.stored[key]; stored {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *Mode) isStored(key chunkKey) bool {
	m.initMu.RLock()
	defer m.initMu.RUnlock()
	_, stored := m.stored[key]
	return stored
}

func (m *Mode) hydrateLocked(ctx context.Context, key chunkKey, durable, demand bool) (uint64, error) {
	if durable && m.hmap.isDurable(key) || !durable && m.hmap.isHydrated(key) {
		return 0, nil
	}
	if m.hmap.isHydrated(key) {
		if err := m.cfg.Store.Fdatasync(key.entry); err != nil {
			return 0, err
		}
		return 0, m.hmap.markDurable([]chunkKey{key}, nil)
	}
	chunk, err := m.fetchChunk(ctx, key)
	if err != nil {
		return 0, err
	}
	m.entryLocks[key.entry].Lock()
	err = m.installFetchedChunkLocked(key, chunk, durable)
	m.entryLocks[key.entry].Unlock()
	if err != nil {
		return 0, err
	}
	m.clearBlocked()
	if demand {
		m.recalledBytes.Add(chunk.Bytes)
	}
	return chunk.Bytes, nil
}

// fetchChunk is the single admission point for hydrator fetches. The recall
// semaphore is acquired here — innermost, after every chunk and entry lock —
// so RecallLimit bounds concurrent hydrator I/O and nothing else: a saturated
// volume queues fetches (bounded by the caller's recall deadline) instead of
// failing reads, and a slot holder only ever performs socket I/O, so no
// lock-ordering cycle through the semaphore can exist.
func (m *Mode) fetchChunk(ctx context.Context, key chunkKey) (Chunk, error) {
	m.stateMu.RLock()
	corrupt := m.state == StateCorrupt
	detail := m.stateDetail
	m.stateMu.RUnlock()
	if corrupt {
		return Chunk{}, &stateError{base: ErrCorrupt, detail: detail}
	}
	select {
	case m.recalls <- struct{}{}:
		defer func() { <-m.recalls }()
	case <-ctx.Done():
		return Chunk{}, ctx.Err()
	}
	return m.client.fetch(ctx, key, m.ChunkSize())
}

// installFetchedChunkLocked runs with the entry lock held.
func (m *Mode) installFetchedChunkLocked(key chunkKey, chunk Chunk, durable bool) error {
	chunkStart := uint64(key.chunk) * uint64(m.ChunkSize())
	for _, extent := range chunk.Extents {
		start := chunkStart + extent.Offset
		if err := m.cfg.Store.PWrite(key.entry, int64(start), extent.Data); err != nil {
			return err
		}
	}
	if !m.hmap.isModified(key.entry) {
		if err := m.cfg.Store.RestoreMtime(key.entry); err != nil {
			return err
		}
	}
	if durable {
		if err := m.cfg.Store.Fdatasync(key.entry); err != nil {
			return err
		}
		if err := m.hmap.markDurable([]chunkKey{key}, nil); err != nil {
			return err
		}
	} else {
		m.hmap.markLazy(key)
	}
	return nil
}

// UserMutation protects a user-visible metadata mutation whose mtime must win
// over every later invisible hydration write. The durable bit is installed
// before apply while the inode hydration lock excludes attribute readers.
func (m *Mode) UserMutation(identity [16]byte, apply func() error) error {
	if m == nil || m.converged.Load() {
		return apply()
	}
	entry, ok := m.bindings.Entry(identity)
	if !ok {
		return apply()
	}
	m.initMu.RLock()
	initialized := m.initialized
	hmap := m.hmap
	m.initMu.RUnlock()
	if !initialized {
		return ErrBlocked
	}
	m.entryLocks[entry].Lock()
	defer m.entryLocks[entry].Unlock()
	if err := hmap.markDurable(nil, &entry); err != nil {
		return err
	}
	return apply()
}

func (m *Mode) chunkLock(key chunkKey) *sync.Mutex {
	index := (uint64(key.entry)*0x9e3779b185ebca87 ^ uint64(key.chunk)) % chunkLockShards
	return &m.chunkLocks[index]
}

func (m *Mode) lockKeys(keys []chunkKey) []*sync.Mutex {
	indices := make([]int, 0, len(keys))
	seen := make(map[int]struct{}, len(keys))
	for _, key := range keys {
		index := int((uint64(key.entry)*0x9e3779b185ebca87 ^ uint64(key.chunk)) % chunkLockShards)
		if _, exists := seen[index]; !exists {
			seen[index] = struct{}{}
			indices = append(indices, index)
		}
	}
	sort.Ints(indices)
	locks := make([]*sync.Mutex, len(indices))
	for i, index := range indices {
		locks[i] = &m.chunkLocks[index]
		locks[i].Lock()
	}
	return locks
}

func unlockLocks(locks []*sync.Mutex) {
	for i := len(locks) - 1; i >= 0; i-- {
		locks[i].Unlock()
	}
}

func (m *Mode) preemptDrain() {
	m.lastRecallNS.Store(m.cfg.Now().UnixNano())
	m.drainCancelMu.Lock()
	for _, cancel := range m.drainCancels {
		cancel()
	}
	m.drainCancelMu.Unlock()
}

func (m *Mode) drain() {
	defer m.wg.Done()
	if m.cfg.drainStart != nil {
		select {
		case <-m.cfg.drainStart:
		case <-m.ctx.Done():
			return
		}
	}
	var next atomic.Uint64
	workers := m.cfg.DrainWorkers
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			backoff := drainBackoffInitial
			for {
				if m.isCorrupt() {
					return
				}
				index := next.Add(1) - 1
				m.initMu.RLock()
				if index >= uint64(len(m.info.Order)) {
					m.initMu.RUnlock()
					return
				}
				pair := m.info.Order[index]
				m.initMu.RUnlock()
				key := chunkKey{entry: pair[0], chunk: pair[1]}
				for {
					if m.isCorrupt() {
						return
					}
					if !m.waitDrainHysteresis() {
						return
					}
					ctx, cancel := context.WithCancel(m.ctx)
					cancelID := m.drainCancelID.Add(1)
					m.drainCancelMu.Lock()
					m.drainCancels[cancelID] = cancel
					m.drainCancelMu.Unlock()
					lock := m.chunkLock(key)
					lock.Lock()
					linked, err := m.cfg.Store.Linked(key.entry)
					var fetched uint64
					complete := linked
					if err == nil && linked {
						fetched, err = m.hydrateLocked(ctx, key, true, false)
					} else if err == nil {
						complete, err = m.cfg.Store.DiscardUnlinked(key.entry)
						if err == nil && complete {
							err = m.hmap.markDurable([]chunkKey{key}, nil)
						}
					}
					lock.Unlock()
					cancel()
					m.drainCancelMu.Lock()
					delete(m.drainCancels, cancelID)
					m.drainCancelMu.Unlock()
					if errors.Is(err, context.Canceled) && m.ctx.Err() == nil {
						continue
					}
					if err != nil {
						m.noteFailure(err)
						if errors.Is(err, ErrCorrupt) || m.isCorrupt() {
							return
						}
						if !m.waitDrainHysteresis() {
							return
						}
						if !m.waitDrainBackoff(backoff) {
							return
						}
						backoff = minDuration(backoff*2, drainBackoffMaximum)
						continue
					}
					backoff = drainBackoffInitial
					if !complete {
						timer := time.NewTimer(100 * time.Millisecond)
						select {
						case <-m.ctx.Done():
							timer.Stop()
							return
						case <-timer.C:
						}
						continue
					}
					if linked {
						m.drainedBytes.Add(fetched)
					}
					break
				}
			}
		}()
	}
	wg.Wait()
	if m.ctx.Err() == nil && !m.isCorrupt() {
		_ = m.commitConverged()
	}
}

func (m *Mode) isCorrupt() bool {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state == StateCorrupt
}

func (m *Mode) waitDrainBackoff(wait time.Duration) bool {
	timer := time.NewTimer(wait)
	select {
	case <-m.ctx.Done():
		timer.Stop()
		return false
	case <-timer.C:
		return true
	}
}

func (m *Mode) waitDrainHysteresis() bool {
	for {
		last := time.Unix(0, m.lastRecallNS.Load())
		wait := m.cfg.DrainHysteresis - m.cfg.Now().Sub(last)
		if m.lastRecallNS.Load() == 0 || wait <= 0 {
			return m.ctx.Err() == nil
		}
		timer := time.NewTimer(minDuration(wait, 100*time.Millisecond))
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

func (m *Mode) commitConverged() error {
	m.initMu.RLock()
	for key := range m.stored {
		if !m.hmap.isDurable(key) {
			m.initMu.RUnlock()
			return errors.New("restoremode: drain ended before every stored chunk was durable")
		}
	}
	m.initMu.RUnlock()
	record := convergedRecord{Version: 1, VolumeID: m.cfg.VolumeID, AuthorityEpoch: m.cfg.AuthorityEpoch, Attempt: m.ready.Attempt,
		DrainedBytes: m.drainedBytes.Load(), DrainedChunks: uint64(len(m.stored)), WrittenUnix: m.cfg.Now().Unix()}
	if err := writeAtomicJSON(filepath.Join(m.cfg.StateRoot, ConvergedFilename), record); err != nil {
		return err
	}
	m.converged.Store(true)
	_ = m.client.Close()
	return nil
}

func (m *Mode) progressLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.ProgressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			_ = m.writeProgress()
		}
	}
}

func (m *Mode) writeProgress() error {
	m.stateMu.RLock()
	state := m.state
	m.stateMu.RUnlock()
	marked, total := uint64(0), uint64(0)
	initialized := false
	m.initMu.RLock()
	initialized = m.initialized
	if initialized {
		total = uint64(len(m.stored))
		for key := range m.stored {
			if m.hmap.isDurable(key) {
				marked++
			}
		}
	}
	m.initMu.RUnlock()
	permille := uint32(0)
	if total == 0 && initialized {
		permille = 1000
	} else if total != 0 {
		permille = uint32(marked * 1000 / total)
	}
	return writeAtomicJSON(filepath.Join(m.cfg.StateRoot, ProgressFilename), progressRecord{Version: 1, ProgressPermille: permille, State: state,
		RecalledBytes: m.recalledBytes.Load(), DrainedBytes: m.drainedBytes.Load(), UpdatedUnix: m.cfg.Now().Unix()})
}

func (m *Mode) Close() error {
	if m == nil {
		return nil
	}
	var result error
	m.closeOnce.Do(func() {
		m.cancel()
		m.wg.Wait()
		_ = m.writeProgress()
		result = m.client.Close()
		m.initMu.Lock()
		if m.hmap != nil {
			result = errors.Join(result, m.hmap.Close())
		}
		m.initMu.Unlock()
	})
	return result
}
