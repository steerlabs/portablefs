package hydrator

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// PackObjectName is the pinned last key component of pack object index. Keys
// are derived, never carried: the manifest names how many packs there are and
// nothing more.
func PackObjectName(index int) string { return fmt.Sprintf("pack-%06d", index) }

const (
	// MaxDrainPairs bounds the in-memory drain order at 8 Mi pairs, 64 MiB. At
	// the default 8 MiB chunk that is a 64 TiB volume; a larger one is refused
	// rather than silently making this process the cell's largest allocation.
	MaxDrainPairs = 8 << 20

	// FrameCacheBytes is the decoded-frame budget. Small files share frames, so
	// one fetched frame usually answers many chunk fetches; caching it turns a
	// directory-sized burst of recalls into one ranged GET.
	FrameCacheBytes = 64 << 20

	// HealthCacheDuration is how long a HEALTH probe result is reused. The
	// probe is a HeadObject of the manifest — cheap, but not free, and the
	// authority may probe often.
	HealthCacheDuration = 30 * time.Second
)

// Server is the serve-mode hydrator: a stateless fetch, verify, and decode
// oracle over one sealed manifest. It holds no volume state, touches no
// filesystem, and never writes anything the authority owns.
type Server struct {
	client    *archivestore.Client
	manifest  *archive.Manifest
	config    LaunchConfig
	packKeys  []string
	chunkSize uint64

	drain         []DrainPair
	priorityCount uint64
	info          Info

	cache  *frameCache
	health *healthCache
	logf   func(string, ...any)
}

// NewServer prepares the serve-mode state: the pack keys, the drain order in
// pack order, and the INFO reply. Everything expensive is computed once, here,
// so a fetch is a cache lookup or one ranged GET and nothing else.
func NewServer(client *archivestore.Client, manifest *archive.Manifest, config LaunchConfig,
	logf func(string, ...any)) (*Server, error) {

	if client == nil || manifest == nil {
		return nil, fmt.Errorf("%w: a server needs a store client and a manifest", ErrInvalid)
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	keys := make([]string, len(manifest.Header.Packs))
	for index := range keys {
		key, err := client.KeyFor(config.VolumeID, config.SealedEpoch, config.Attempt, PackObjectName(index))
		if err != nil {
			return nil, err
		}
		keys[index] = key
	}
	manifestKey, err := ManifestKey(client, config)
	if err != nil {
		return nil, err
	}
	drain, priority, err := drainOrder(manifest)
	if err != nil {
		return nil, err
	}
	server := &Server{
		client:        client,
		manifest:      manifest,
		config:        config,
		packKeys:      keys,
		chunkSize:     uint64(manifest.Header.ChunkSizeBytes),
		drain:         drain,
		priorityCount: priority,
		cache:         newFrameCache(FrameCacheBytes),
		health:        &healthCache{client: client, key: manifestKey},
		logf:          logf,
	}
	server.info = Info{
		FormatVersion:        manifest.Header.FormatVersion,
		VolumeID:             manifest.Header.VolumeID,
		SealedEpoch:          manifest.Header.SealedEpoch,
		Attempt:              manifest.Header.Attempt,
		ChunkSizeBytes:       manifest.Header.ChunkSizeBytes,
		EntryCount:           uint32(len(manifest.Entries)),
		ChunkCount:           manifest.ChunkCount(),
		LogicalBytes:         manifest.Header.LogicalBytes,
		LogicalInodes:        manifest.Header.LogicalInodes,
		SealedAllocatedBytes: manifest.Header.SealedAllocatedBytes,
		SealedInodes:         manifest.Header.SealedInodes,
		PriorityPackIndex:    manifest.Header.Priority.PackIndex,
		PriorityPackOffset:   manifest.Header.Priority.PackOffset,
		DrainCount:           uint64(len(drain)),
		PriorityDrainCount:   priority,
		PageSize:             DrainPageSize,
	}
	return server, nil
}

// drainOrder is the sequence the authority drains in: every stored chunk of
// every distinct inode, in pack order, so the sweep is sequential over the pack
// objects rather than seeking per file.
//
// Two exclusions are deliberate. A chunk that stores nothing lies wholly inside
// a hole and is born hydrated, so it is not in the drain order at all. A
// hardlink group appears once, under the entry that materialized the inode: the
// hydration map is keyed by inode identity, so draining the group's other names
// would be writing the same inode's bytes twice.
func drainOrder(manifest *archive.Manifest) ([]DrainPair, uint64, error) {
	type ordered struct {
		pair        DrainPair
		packIndex   uint32
		packOffset  uint64
		innerOffset uint64
		inPriority  bool
	}
	boundary := manifest.Header.Priority
	pairs := make([]ordered, 0, manifest.ChunkCount())
	plan := manifest.NamespacePlan()
	for {
		step, ok := plan.Next()
		if !ok {
			break
		}
		if step.Type != archive.TypeRegular || !step.Creates() {
			continue
		}
		entry := &manifest.Entries[step.Index]
		for chunkIndex, chunk := range entry.Chunks {
			if !chunk.Stored() {
				continue
			}
			if len(pairs) >= MaxDrainPairs {
				return nil, 0, fmt.Errorf("%w: the drain order exceeds %d chunks", ErrInvalid, MaxDrainPairs)
			}
			frame := manifest.Frames[chunk.FrameIndex]
			pairs = append(pairs, ordered{
				pair:        DrainPair{EntryIndex: step.Index, ChunkIndex: uint32(chunkIndex)},
				packIndex:   frame.PackIndex,
				packOffset:  frame.PackOffset,
				innerOffset: chunk.InnerOffset,
				inPriority: frame.PackIndex < boundary.PackIndex ||
					(frame.PackIndex == boundary.PackIndex && frame.PackOffset+frame.CompressedLength <= boundary.PackOffset),
			})
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		left, right := pairs[i], pairs[j]
		if left.packIndex != right.packIndex {
			return left.packIndex < right.packIndex
		}
		if left.packOffset != right.packOffset {
			return left.packOffset < right.packOffset
		}
		if left.innerOffset != right.innerOffset {
			return left.innerOffset < right.innerOffset
		}
		if left.pair.EntryIndex != right.pair.EntryIndex {
			return left.pair.EntryIndex < right.pair.EntryIndex
		}
		return left.pair.ChunkIndex < right.pair.ChunkIndex
	})
	out := make([]DrainPair, len(pairs))
	priority := uint64(0)
	counting := true
	for index, entry := range pairs {
		out[index] = entry.pair
		if counting && entry.inPriority {
			priority++
		} else {
			counting = false
		}
	}
	return out, priority, nil
}

// Serve listens on the volume's state-directory socket and answers the pinned
// protocol until the context is cancelled.
//
// The socket is created inside the state directory, which is private to the
// service identity, and is chmodded to 0600 immediately: the authority is the
// only peer, and it reaches the socket through its own state bind.
func (s *Server) Serve(ctx context.Context, socketPath string) error {
	if err := removeStaleSocket(socketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("hydrator: listen: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("hydrator: restrict socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	var connections sync.WaitGroup
	permits := make(chan struct{}, MaxConnections)
	defer connections.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("hydrator: accept: %w", err)
		}
		select {
		case permits <- struct{}{}:
		default:
			// At the connection cap the newest connection is refused
			// immediately rather than queued: the authority's pool is small and
			// bounded, so reaching the cap means the other side is leaking, and
			// a refused connect is a visible failure rather than a stall.
			s.logf("refused a connection at the %d connection cap", MaxConnections)
			_ = connection.Close()
			continue
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer func() { <-permits }()
			s.handle(ctx, connection)
		}()
	}
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hydrator: inspect socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s exists and is not a socket", ErrInvalid, path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("hydrator: remove stale socket: %w", err)
	}
	return nil
}

// handle serves one connection: one request in flight, replies in order, and no
// state carried between requests. A protocol violation ends the connection,
// because a stream whose framing is in doubt cannot be resynchronized.
func (s *Server) handle(ctx context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	for {
		kind, payload, err := ReadFrame(connection)
		if err != nil {
			if errors.Is(err, ErrProtocol) {
				_ = WriteFrame(connection, TypeErr, EncodeError(ErrorInvalid, err.Error()))
			}
			return
		}
		if err := s.respond(ctx, connection, kind, payload); err != nil {
			return
		}
	}
}

func (s *Server) respond(ctx context.Context, connection net.Conn, kind MessageType, payload []byte) error {
	switch kind {
	case TypeInfo:
		if len(payload) != 0 {
			return WriteFrame(connection, TypeErr, EncodeError(ErrorInvalid, "INFO takes no payload"))
		}
		return WriteFrame(connection, TypeInfoOK, s.info.Encode())

	case TypeInfoNext:
		cursor, err := DecodeCursor(payload)
		if err != nil {
			return WriteFrame(connection, TypeErr, EncodeError(ErrorInvalid, err.Error()))
		}
		page, err := s.page(cursor)
		if err != nil {
			return WriteFrame(connection, TypeErr, EncodeError(ErrorInvalid, err.Error()))
		}
		return WriteFrame(connection, TypeDrainPage, page.Encode())

	case TypeFetch:
		entryIndex, chunkIndex, err := DecodeFetch(payload)
		if err != nil {
			return WriteFrame(connection, TypeErr, EncodeError(ErrorInvalid, err.Error()))
		}
		chunk, class, err := s.Fetch(ctx, entryIndex, chunkIndex)
		if err != nil {
			s.logf("fetch entry %d chunk %d: %s: %v", entryIndex, chunkIndex, class, err)
			return WriteFrame(connection, TypeErr, EncodeError(class, err.Error()))
		}
		return WriteFrame(connection, TypeChunk, chunk.Encode())

	case TypeHealth:
		if err := s.health.probe(ctx); err != nil {
			return WriteFrame(connection, TypeErr, EncodeError(ErrorBlocked, err.Error()))
		}
		return WriteFrame(connection, TypeHealthOK, nil)

	default:
		return WriteFrame(connection, TypeErr, EncodeError(ErrorInvalid, "unknown message type "+kind.String()))
	}
}

// page returns one bounded page of the drain order. A cursor past the end is a
// valid request with an empty answer, which is how a drain loop learns it is
// finished without a special case.
func (s *Server) page(cursor uint64) (DrainPage, error) {
	if cursor > uint64(len(s.drain)) {
		return DrainPage{}, fmt.Errorf("%w: drain cursor %d is past the %d pair order", ErrProtocol, cursor, len(s.drain))
	}
	end := cursor + DrainPageSize
	if end > uint64(len(s.drain)) {
		end = uint64(len(s.drain))
	}
	return DrainPage{
		Cursor: cursor,
		Pairs:  s.drain[cursor:end],
		More:   end < uint64(len(s.drain)),
	}, nil
}

// Fetch resolves one chunk: locate its frame in the manifest, fetch that frame's
// compressed bytes with one ranged GET, decompress, verify the slice digest,
// and return the plaintext with the extent map that says where it belongs.
//
// The error class is the contract's: a store failure is blocked and clears
// itself when the store returns, a digest or frame failure is corrupt and is a
// data-integrity event, and a request the manifest cannot answer is invalid.
func (s *Server) Fetch(ctx context.Context, entryIndex, chunkIndex uint32) (Chunk, ErrorClass, error) {
	if int(entryIndex) >= len(s.manifest.Entries) {
		return Chunk{}, ErrorInvalid, fmt.Errorf("entry %d does not exist", entryIndex)
	}
	entry := &s.manifest.Entries[entryIndex]
	if entry.Type != archive.TypeRegular {
		return Chunk{}, ErrorInvalid, fmt.Errorf("entry %d is a %s, not a regular file", entryIndex, entry.Type)
	}
	if int(chunkIndex) >= len(entry.Chunks) {
		return Chunk{}, ErrorInvalid, fmt.Errorf("entry %d has no chunk %d", entryIndex, chunkIndex)
	}
	chunk := entry.Chunks[chunkIndex]
	if !chunk.Stored() {
		// A chunk wholly inside a hole. The reply is empty and valid: there is
		// nothing to write, and the authority marks it hydrated.
		return Chunk{}, 0, nil
	}
	content, class, err := s.frame(ctx, chunk.FrameIndex)
	if err != nil {
		return Chunk{}, class, err
	}
	end := chunk.InnerOffset + chunk.Length
	if end < chunk.InnerOffset || end > uint64(len(content)) {
		return Chunk{}, ErrorCorrupt, fmt.Errorf("chunk slice runs past frame %d", chunk.FrameIndex)
	}
	slice := content[chunk.InnerOffset:end]
	digest := sha256.Sum256(slice)
	if subtle.ConstantTimeCompare(digest[:], chunk.SliceDigest[:]) != 1 {
		return Chunk{}, ErrorCorrupt, fmt.Errorf("entry %d chunk %d does not match its manifest digest", entryIndex, chunkIndex)
	}
	return Chunk{Extents: chunk.Extents, Data: slice}, 0, nil
}

func (s *Server) frame(ctx context.Context, index uint32) ([]byte, ErrorClass, error) {
	if content, ok := s.cache.get(index); ok {
		return content, 0, nil
	}
	if int(index) >= len(s.manifest.Frames) {
		return nil, ErrorInvalid, fmt.Errorf("frame %d does not exist", index)
	}
	frame := s.manifest.Frames[index]
	if int(frame.PackIndex) >= len(s.packKeys) {
		return nil, ErrorInvalid, fmt.Errorf("frame %d names pack %d", index, frame.PackIndex)
	}
	if frame.CompressedLength == 0 || frame.CompressedLength > s.maxFrameBytes() {
		return nil, ErrorCorrupt, fmt.Errorf("frame %d is %d compressed bytes", index, frame.CompressedLength)
	}
	compressed, err := s.readRange(ctx, s.packKeys[frame.PackIndex], frame.PackOffset, frame.CompressedLength)
	if err != nil {
		return nil, ErrorBlocked, err
	}
	content, err := archive.DecodeFrame(frame, compressed)
	if err != nil {
		return nil, ErrorCorrupt, fmt.Errorf("frame %d: %w", index, err)
	}
	s.cache.put(index, content)
	return content, 0, nil
}

// maxFrameBytes is the largest compressed frame this manifest can legitimately
// contain: one chunk's worth of content plus the small constant a zstd frame
// adds around incompressible data.
func (s *Server) maxFrameBytes() uint64 { return s.chunkSize*2 + (1 << 20) }

func (s *Server) readRange(ctx context.Context, key string, offset, length uint64) ([]byte, error) {
	if offset > uint64(1<<62) || length > uint64(1<<62) {
		return nil, fmt.Errorf("%w: range does not fit a signed offset", ErrInvalid)
	}
	stream, err := s.client.GetObjectRange(ctx, key, int64(offset), int64(length))
	if err != nil {
		return nil, err
	}
	defer func() { _ = stream.Close() }()
	payload := make([]byte, length)
	if _, err := io.ReadFull(stream, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// frameCache is a byte-budgeted LRU of decoded frames. Small files share
// frames, so one entry commonly answers many fetches; the budget is what keeps
// that from being unbounded.
//
// Two connections that miss on the same frame at the same time both fetch it.
// That is deliberate: single-flighting here would add a lock held across a
// network round trip, and the duplicate is one extra ranged GET, while the
// state machine that must not race — the hydration map — lives in the
// authority, not here.
type frameCache struct {
	mutex   sync.Mutex
	budget  uint64
	used    uint64
	order   *list.List
	entries map[uint32]*list.Element
}

type cacheEntry struct {
	index   uint32
	content []byte
}

func newFrameCache(budget uint64) *frameCache {
	return &frameCache{budget: budget, order: list.New(), entries: make(map[uint32]*list.Element)}
}

func (c *frameCache) get(index uint32) ([]byte, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	element, ok := c.entries[index]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(element)
	return element.Value.(*cacheEntry).content, true
}

func (c *frameCache) put(index uint32, content []byte) {
	if uint64(len(content)) > c.budget {
		return
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if element, ok := c.entries[index]; ok {
		c.order.MoveToFront(element)
		return
	}
	element := c.order.PushFront(&cacheEntry{index: index, content: content})
	c.entries[index] = element
	c.used += uint64(len(content))
	for c.used > c.budget {
		oldest := c.order.Back()
		if oldest == nil {
			return
		}
		evicted := c.order.Remove(oldest).(*cacheEntry)
		delete(c.entries, evicted.index)
		c.used -= uint64(len(evicted.content))
	}
}

// healthCache answers HEALTH with a cheap HeadObject of the manifest, reusing
// the result for a bounded window. The authority also learns the store's health
// from its fetches; this probe exists so a volume with no traffic still reports
// honestly.
type healthCache struct {
	client *archivestore.Client
	key    string

	mutex   sync.Mutex
	checked time.Time
	err     error
}

func (h *healthCache) probe(ctx context.Context) error {
	h.mutex.Lock()
	if !h.checked.IsZero() && time.Since(h.checked) < HealthCacheDuration {
		err := h.err
		h.mutex.Unlock()
		return err
	}
	h.mutex.Unlock()

	_, err := h.client.HeadObject(ctx, h.key)

	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.checked = time.Now()
	h.err = err
	return err
}
