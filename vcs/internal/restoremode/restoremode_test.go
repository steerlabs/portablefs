package restoremode

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type fakeStore struct {
	mu            sync.Mutex
	sizes         map[uint32]int64
	data          map[uint32][]byte
	events        []string
	linked        bool
	mtimeRestores int
}

func newFakeStore(sizes map[uint32]int64) *fakeStore {
	return &fakeStore{sizes: sizes, data: make(map[uint32][]byte), linked: true}
}

func (s *fakeStore) event(value string) {
	s.mu.Lock()
	s.events = append(s.events, value)
	s.mu.Unlock()
}
func (s *fakeStore) LogicalSize(entry uint32) (int64, error) {
	size, ok := s.sizes[entry]
	if !ok {
		return 0, os.ErrNotExist
	}
	return size, nil
}
func (s *fakeStore) PWrite(entry uint32, off int64, data []byte) error {
	s.write(entry, off, data, "pwrite")
	return nil
}
func (s *fakeStore) write(entry uint32, off int64, data []byte, event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	need := int(off) + len(data)
	if len(s.data[entry]) < need {
		grown := make([]byte, need)
		copy(grown, s.data[entry])
		s.data[entry] = grown
	}
	copy(s.data[entry][off:], data)
}
func (s *fakeStore) bytes(entry uint32) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data[entry]...)
}
func (s *fakeStore) Fdatasync(uint32) error { s.event("fdatasync"); return nil }
func (s *fakeStore) RestoreMtime(uint32) error {
	s.mu.Lock()
	s.events = append(s.events, "mtime")
	s.mtimeRestores++
	s.mu.Unlock()
	return nil
}
func (s *fakeStore) Linked(uint32) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.linked, nil
}
func (s *fakeStore) DiscardUnlinked(uint32) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.linked, nil
}

type fakeHydrator struct {
	listener     net.Listener
	info         InfoPage
	chunks       map[chunkKey]Chunk
	mu           sync.Mutex
	fetches      map[chunkKey]int
	blockFetch   chan struct{}
	fetchStarted chan struct{}
	nextError    error
	fetchError   error
	healthError  error
	closed       chan struct{}
}

func startFakeHydrator(t *testing.T, root string, info InfoPage, chunks map[chunkKey]Chunk) *fakeHydrator {
	t.Helper()
	listener, err := net.Listen("unix", filepath.Join(root, HydratorSocket))
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHydrator{listener: listener, info: info, chunks: chunks, fetches: make(map[chunkKey]int), fetchStarted: make(chan struct{}, 16), closed: make(chan struct{})}
	go h.serve()
	t.Cleanup(func() { h.Close() })
	return h
}
func (h *fakeHydrator) serve() {
	defer close(h.closed)
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		go h.conn(conn)
	}
}
func (h *fakeHydrator) conn(conn net.Conn) {
	defer conn.Close()
	for {
		typ, payload, err := readHydratorFrame(conn, 16<<20+64<<10)
		if err != nil {
			return
		}
		switch typ {
		case FrameInfo:
			raw, _ := MarshalInfoPage(h.info)
			_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameInfoOK, raw)
		case FrameInfoNext:
			if len(payload) != 8 {
				return
			}
			cursor := binary.LittleEndian.Uint64(payload)
			if cursor >= uint64(len(h.info.Order)) {
				_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameError, mustProtocolError(ErrorInvalid, "cursor outside drain order"))
				continue
			}
			end := cursor + uint64(h.info.PageSize)
			if end > uint64(len(h.info.Order)) {
				end = uint64(len(h.info.Order))
			}
			raw, _ := marshalDrainPage(drainPage{Cursor: cursor, Order: h.info.Order[cursor:end], More: end < uint64(len(h.info.Order))})
			_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameDrainPage, raw)
		case FrameHealth:
			h.mu.Lock()
			err := h.healthError
			h.mu.Unlock()
			if err != nil {
				_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameError, errorPayload(err))
			} else {
				_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameHealthOK, nil)
			}
		case FrameFetch:
			if len(payload) != 8 {
				return
			}
			key := chunkKey{binary.LittleEndian.Uint32(payload[:4]), binary.LittleEndian.Uint32(payload[4:])}
			h.mu.Lock()
			h.fetches[key]++
			nextErr := h.nextError
			h.nextError = nil
			if nextErr == nil {
				nextErr = h.fetchError
			}
			block := h.blockFetch
			h.mu.Unlock()
			select {
			case h.fetchStarted <- struct{}{}:
			default:
			}
			if block != nil {
				select {
				case <-block:
				case <-time.After(10 * time.Second):
					return
				}
			}
			if nextErr != nil {
				_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameError, errorPayload(nextErr))
				continue
			}
			raw, _ := MarshalChunk(h.chunks[key], h.info.ChunkSize)
			_ = writeHydratorFrame(conn, 16<<20+64<<10, FrameChunk, raw)
		default:
			return
		}
	}
}
func mustProtocolError(class byte, msg string) []byte {
	raw, _ := MarshalProtocolError(class, msg)
	return raw
}
func errorPayload(err error) []byte {
	if errors.Is(err, ErrCorrupt) {
		return mustProtocolError(ErrorCorrupt, err.Error())
	}
	return mustProtocolError(ErrorBlocked, err.Error())
}
func (h *fakeHydrator) Close() { _ = h.listener.Close(); <-h.closed }

func (h *fakeHydrator) fetchCount(key chunkKey) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fetches[key]
}

func (h *fakeHydrator) setFetchError(err error) {
	h.mu.Lock()
	h.fetchError = err
	h.mu.Unlock()
}

func writeBindingsAndReady(t *testing.T, root, volume string, identities [][16]byte) {
	t.Helper()
	body := append([]byte(nil), bindingsMagic...)
	body = binary.LittleEndian.AppendUint32(body, bindingsVersion)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(identities)))
	for i, id := range identities {
		var index [4]byte
		binary.LittleEndian.PutUint32(index[:], uint32(i))
		body = append(body, index[:]...)
		body = append(body, id[:]...)
	}
	sum := sha256.Sum256(body)
	body = append(body, sum[:]...)
	if err := os.WriteFile(filepath.Join(root, BindingsFilename), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicJSON(filepath.Join(root, ReadyFilename), readyRecord{Version: 1, VolumeID: volume, SealedEpoch: 7, Attempt: "abcdefab-cdef-cdef-cdef-abcdefabcdef", Entries: uint64(len(identities)), WrittenUnix: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
}

func openTestMode(t *testing.T, store *fakeStore, info InfoPage, chunks map[chunkKey]Chunk, mutate func(*Config)) (*Mode, *fakeHydrator, [16]byte) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "pfs-rm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	identity := [16]byte{1, 2, 3}
	writeBindingsAndReady(t, root, info.VolumeID, [][16]byte{identity})
	hydrator := startFakeHydrator(t, root, info, chunks)
	cfg := Config{StateRoot: root, VolumeID: info.VolumeID, Store: store, RecallDeadline: 500 * time.Millisecond, ProgressInterval: 20 * time.Millisecond, DrainHysteresis: 20 * time.Millisecond}
	if mutate != nil {
		mutate(&cfg)
	}
	mode, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	mode.initMu.RLock()
	initialized := mode.initialized
	mode.initMu.RUnlock()
	if !initialized {
		t.Fatalf("restore bootstrap did not initialize: %v", mode.ContentError())
	}
	t.Cleanup(func() { _ = mode.Close() })
	return mode, hydrator, identity
}

func testInfo(order ...[2]uint32) InfoPage {
	return InfoPage{
		FormatVersion: 1, VolumeID: "12345678-1234-1234-1234-123456789abc", SealedEpoch: 7,
		Attempt: "abcdefab-cdef-cdef-cdef-abcdefabcdef", ChunkSize: 4, EntryCount: 1,
		ChunkCount: uint64(len(order)), LogicalBytes: 8, LogicalInodes: 1, StoredBytes: 8,
		SealedInodes: 1, DrainCount: uint64(len(order)), PriorityDrainCount: uint64(len(order)),
		PageSize: 8192, Order: order,
	}
}

func TestInfoHeaderRoundTrip(t *testing.T) {
	want := testInfo([2]uint32{0, 0})
	raw, err := MarshalInfoPage(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalInfoPage(raw)
	if err != nil {
		t.Fatal(err)
	}
	got.Order = want.Order
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("INFO round trip = %+v, want %+v", got, want)
	}
}

func TestBindingsRejectsBrokenSealAndNonCanonicalIndex(t *testing.T) {
	root := t.TempDir()
	identity := [16]byte{1}
	writeBindingsAndReady(t, root, "v", [][16]byte{identity})
	path := filepath.Join(root, BindingsFilename)
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(path, raw, 0o600)
	if _, err := LoadBindings(path, 10); err == nil {
		t.Fatal("broken seal accepted")
	}
	binary.LittleEndian.PutUint32(raw[bindingHeaderBytes:bindingHeaderBytes+4], 2)
	sum := sha256.Sum256(raw[:len(raw)-sha256.Size])
	copy(raw[len(raw)-sha256.Size:], sum[:])
	_ = os.WriteFile(path, raw, 0o600)
	if _, err := LoadBindings(path, 10); err == nil {
		t.Fatal("non-canonical index accepted")
	}
}

func TestBindingsHardlinkAliasesResolveToMaterializingEntry(t *testing.T) {
	root := t.TempDir()
	identity := [16]byte{1, 2, 3}
	writeBindingsAndReady(t, root, "v", [][16]byte{identity, identity})
	bindings, err := LoadBindings(filepath.Join(root, BindingsFilename), 10)
	if err != nil {
		t.Fatal(err)
	}
	if entry, ok := bindings.Entry(identity); !ok || entry != 0 {
		t.Fatalf("hardlink identity resolved to %d, %v; want materializing entry 0", entry, ok)
	}
}

func TestLazyReadMarkIsLostOnCrashButDurableMarkReplays(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, MapFilename)
	digest := sha256.Sum256([]byte("bindings"))
	key := chunkKey{entry: 3, chunk: 7}
	m, err := openHydrationMap(path, 4096, digest, 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.markLazy(key)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openHydrationMap(path, 4096, digest, 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.isHydrated(key) {
		t.Fatal("lazy read mark survived restart without a durability barrier")
	}
	if err := restarted.markDurable([]chunkKey{key}, nil); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	replayed, err := openHydrationMap(path, 4096, digest, 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	if !replayed.isDurable(key) {
		t.Fatal("fdatasync-preceded durable mark did not replay")
	}
}

func TestWriteRecallDurabilityOrderingAndMtime(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, _, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Offset: 0, Data: []byte("base")}}}}, func(c *Config) {
		c.disableDrain = true
		c.OnDurableMark = func(_, _ uint32, user bool) {
			if user {
				store.event("mark-user")
			} else {
				store.event("mark-chunk")
			}
		}
	})
	fdatasyncsAtApply := 0
	n, _, err := mode.Write(context.Background(), identity, 1, 1, func() (int, int64, error) {
		store.mu.Lock()
		for _, event := range store.events {
			if event == "fdatasync" {
				fdatasyncsAtApply++
			}
		}
		store.mu.Unlock()
		store.event("apply")
		return 1, -1, nil
	})
	if err != nil || n != 1 {
		t.Fatalf("write=%d,%v", n, err)
	}
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	store.mu.Unlock()
	want := []string{"pwrite", "mtime", "fdatasync", "mark-chunk", "mark-user", "apply"}
	if len(events) != len(want) {
		t.Fatalf("events=%v want=%v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events=%v want=%v", events, want)
		}
	}
	if fdatasyncsAtApply != 1 {
		t.Fatalf("fdatasyncs before apply = %d, want hydration install only", fdatasyncsAtApply)
	}
}

func TestFullChunkWriteHydratesBeforeShortApplyAndDrainPreservesPrefix(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	key := chunkKey{0, 0}
	startDrain := make(chan struct{})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{
		key: {Extents: []Extent{{Data: []byte("abcd")}}},
	}, func(c *Config) { c.drainStart = startDrain; c.DrainWorkers = 1 })
	n, _, err := mode.Write(context.Background(), identity, 0, 4, func() (int, int64, error) {
		if !mode.hmap.isDurable(key) || !mode.hmap.isModified(0) {
			t.Fatal("apply ran before the chunk and user-modified records were durable")
		}
		store.write(0, 0, []byte("XY"), "apply")
		return 2, -1, nil
	})
	if err != nil || n != 2 {
		t.Fatalf("write = (%d, %v)", n, err)
	}
	if got := string(store.bytes(0)); got != "XYcd" {
		t.Fatalf("bytes after short write = %q, want XYcd", got)
	}
	if got := hydrator.fetchCount(key); got != 1 {
		t.Fatalf("write fetches = %d, want 1", got)
	}
	close(startDrain)
	waitForRestoreMode(t, 2*time.Second, "short-write drain convergence", func() bool { return mode.converged.Load() })
	if got := hydrator.fetchCount(key); got != 1 {
		t.Fatalf("drain refetched the durable chunk: %d", got)
	}
	if got := string(store.bytes(0)); got != "XYcd" {
		t.Fatalf("acked prefix after drain = %q, want XYcd", got)
	}
}

func TestWriteHydrationFailureNeverApplies(t *testing.T) {
	t.Run("hydrator error", func(t *testing.T) {
		store := newFakeStore(map[uint32]int64{0: 4})
		key := chunkKey{0, 0}
		mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{key: {}}, func(c *Config) { c.disableDrain = true })
		hydrator.mu.Lock()
		hydrator.nextError = ErrBlocked
		hydrator.mu.Unlock()
		applied := false
		n, assigned, err := mode.Write(context.Background(), identity, 0, 4, func() (int, int64, error) {
			applied = true
			return 4, -1, nil
		})
		if n != 0 || assigned != 0 || !errors.Is(err, ErrBlocked) || applied {
			t.Fatalf("write = (%d, %d, %v), applied=%v", n, assigned, err, applied)
		}
	})

	t.Run("recall deadline", func(t *testing.T) {
		store := newFakeStore(map[uint32]int64{0: 4})
		key := chunkKey{0, 0}
		mode, _, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{key: {}}, func(c *Config) {
			c.disableDrain = true
			c.RecallLimit = 1
			c.RecallDeadline = 50 * time.Millisecond
		})
		mode.recalls <- struct{}{}
		defer func() { <-mode.recalls }()
		applied := false
		n, assigned, err := mode.Write(context.Background(), identity, 0, 4, func() (int, int64, error) {
			applied = true
			return 4, -1, nil
		})
		if n != 0 || assigned != 0 || !errors.Is(err, ErrRecallDeadline) || applied {
			t.Fatalf("write = (%d, %d, %v), applied=%v", n, assigned, err, applied)
		}
	})
}

func TestWriteBeyondStoredRangeDurablyMarksEntryModified(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	key := chunkKey{0, 0}
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{key: {}}, func(c *Config) { c.disableDrain = true })
	n, _, err := mode.Write(context.Background(), identity, 8, 2, func() (int, int64, error) { return 2, -1, nil })
	if err != nil || n != 2 {
		t.Fatalf("write = (%d, %v)", n, err)
	}
	if got := hydrator.fetchCount(key); got != 0 {
		t.Fatalf("beyond-range fetches = %d, want 0", got)
	}
	replayed, err := openHydrationMap(filepath.Join(mode.cfg.StateRoot, MapFilename), mode.ChunkSize(), mode.bindings.Digest(), 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	if !replayed.isModified(0) {
		t.Fatal("entry-modified record did not replay")
	}
}

func TestMultiChunkWriteHydratesEveryOverlappingColdChunk(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	first, second := chunkKey{0, 0}, chunkKey{0, 1}
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{
		first:  {Extents: []Extent{{Data: []byte("abcd")}}},
		second: {Extents: []Extent{{Data: []byte("efgh")}}},
	}, func(c *Config) { c.disableDrain = true; c.RecallLimit = 1 })
	if _, _, err := mode.Write(context.Background(), identity, 2, 4, func() (int, int64, error) {
		store.write(0, 2, []byte("WXYZ"), "apply")
		return 4, -1, nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []chunkKey{first, second} {
		if got := hydrator.fetchCount(key); got != 1 || !mode.hmap.isDurable(key) {
			t.Fatalf("chunk %+v fetches=%d durable=%v", key, got, mode.hmap.isDurable(key))
		}
	}
	if got := string(store.bytes(0)); got != "abWXYZgh" {
		t.Fatalf("file bytes = %q, want abWXYZgh", got)
	}
}

func TestWriteRecallWaitsForAdmissionBeforeApply(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	key := chunkKey{0, 0}
	mode, _, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{
		key: {Extents: []Extent{{Data: []byte("abcd")}}},
	}, func(c *Config) { c.disableDrain = true; c.RecallLimit = 1 })
	mode.recalls <- struct{}{}
	applyErr := errors.New("short pwrite")
	applied := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, _, err := mode.Write(context.Background(), identity, 0, 4, func() (int, int64, error) {
			close(applied)
			store.write(0, 0, []byte("XY"), "apply")
			return 2, -1, applyErr
		})
		result <- err
	}()
	select {
	case <-applied:
		t.Fatal("apply ran before recall admission")
	case err := <-result:
		t.Fatalf("write returned before recall admission: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	<-mode.recalls
	select {
	case err := <-result:
		if !errors.Is(err, applyErr) {
			t.Fatalf("write error = %v, want apply error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not resume after recall admission")
	}
	if !mode.hmap.isDurable(key) || string(store.bytes(0)) != "XYcd" {
		t.Fatal("recall was not durable before the short apply")
	}
}

func TestConcurrentRecallIsSingleFlight(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("base")}}}}, func(c *Config) { c.disableDrain = true; c.RecallLimit = 32 })
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); err != nil {
				t.Errorf("recall: %v", err)
			}
		}()
	}
	wg.Wait()
	hydrator.mu.Lock()
	fetches := hydrator.fetches[chunkKey{0, 0}]
	hydrator.mu.Unlock()
	if fetches != 1 {
		t.Fatalf("fetches=%d want 1", fetches)
	}
}

// A recall past RecallLimit queues rather than failing: the cap bounds
// concurrent hydrator fetches, and a wake burst is expected load, not an
// error an application should ever see. Only a deadline that expires while
// queued or fetching surfaces, as ErrRecallDeadline.
func TestRecallCapQueuesAndDeadlineIsNamed(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{{0, 0}: {}, {0, 1}: {}}, func(c *Config) { c.disableDrain = true; c.RecallLimit = 1; c.RecallDeadline = 80 * time.Millisecond })
	hydrator.mu.Lock()
	hydrator.blockFetch = make(chan struct{})
	hydrator.mu.Unlock()
	first := make(chan error, 1)
	go func() { first <- mode.EnsureHydrated(context.Background(), identity, 0, 4) }()
	<-hydrator.fetchStarted
	// A second recall for a DIFFERENT chunk queues behind the held slot and
	// shares its fate: the slot never frees, so it names the deadline too.
	second := make(chan error, 1)
	go func() {
		second <- mode.EnsureHydrated(context.Background(), identity, 4, 4)
	}()
	select {
	case err := <-second:
		t.Fatalf("queued recall returned before the deadline: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := <-first; !errors.Is(err, ErrRecallDeadline) {
		t.Fatalf("deadline=%v", err)
	}
	if err := <-second; !errors.Is(err, ErrRecallDeadline) {
		t.Fatalf("queued recall=%v", err)
	}
	// Once the hydrator recovers, a queued recall completes instead of failing.
	hydrator.mu.Lock()
	close(hydrator.blockFetch)
	hydrator.blockFetch = nil
	hydrator.mu.Unlock()
	if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); err != nil {
		t.Fatalf("recall after recovery = %v", err)
	}
}

func TestRecallSaturationDoesNotBlockSessionKeepAlive(t *testing.T) {
	authority, err := volumeserver.New("12345678-1234-1234-1234-123456789abc", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := authority.AttachActiveForTest(1, volumeserver.PeerIdentity{1}, volumeserver.Authorization{
		Access: volumeserver.AccessRead, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeStore(map[uint32]int64{0: 8})
	// The deadline is deliberately far beyond the test's lifetime: the proof
	// below is structural, not timed. The parked fetch never completes until
	// this test releases it, so if the session lane shared anything with
	// recall admission, Resume would hang here forever and the suite timeout
	// would name this test — no wall-clock assertion is needed, and none
	// could be honest on a loaded runner.
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {}}, func(c *Config) {
		c.disableDrain = true
		c.RecallLimit = 1
		c.RecallDeadline = 20 * time.Second
	})
	hydrator.mu.Lock()
	hydrator.blockFetch = make(chan struct{})
	hydrator.mu.Unlock()
	blocked := make(chan error, 1)
	go func() { blocked <- mode.EnsureHydrated(context.Background(), identity, 0, 4) }()
	<-hydrator.fetchStarted
	// A second recall queues behind the held slot; the queue lives entirely
	// inside restore mode, so the authority's session lane stays free.
	queued := make(chan error, 1)
	go func() { queued <- mode.EnsureHydrated(context.Background(), identity, 0, 4) }()
	if err := authority.Resume(credential); err != nil {
		t.Fatalf("keepalive during recall saturation = %v", err)
	}
	// Resume returned while the fetch was still parked, so it provably never
	// waited behind recall admission: both recalls are still in flight.
	if len(blocked) != 0 || len(queued) != 0 {
		t.Fatal("recalls completed while the hydrator was parked")
	}
	hydrator.mu.Lock()
	close(hydrator.blockFetch)
	hydrator.blockFetch = nil
	hydrator.mu.Unlock()
	if err := <-blocked; err != nil {
		t.Fatalf("blocking recall after release = %v", err)
	}
	if err := <-queued; err != nil {
		t.Fatalf("queued recall after release = %v", err)
	}
	if err := authority.Resume(credential); err != nil {
		t.Fatalf("session did not survive saturated recall: %v", err)
	}
}

func TestCorruptStateIsStickyAndUniform(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {}}, func(c *Config) { c.disableDrain = true })
	hydrator.mu.Lock()
	hydrator.nextError = ErrCorrupt
	hydrator.mu.Unlock()
	if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("recall=%v", err)
	}
	hydrator.mu.Lock()
	hydrator.healthError = nil
	hydrator.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	if err := mode.ContentError(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("sticky state=%v", err)
	}
}

func TestDrainConvergesAndWritesProgress(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, _, _ := openTestMode(t, store, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("abcd")}}}, {0, 1}: {Extents: []Extent{{Data: []byte("efgh")}}}}, nil)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(mode.cfg.StateRoot, ConvergedFilename)); err == nil && mode.converged.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("convergence record not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(mode.cfg.StateRoot, ProgressFilename)); err != nil {
		time.Sleep(30 * time.Millisecond)
		_, err = os.Stat(filepath.Join(mode.cfg.StateRoot, ProgressFilename))
		if err != nil {
			t.Fatal(err)
		}
	}
	var progress progressRecord
	if err := readStrictJSON(filepath.Join(mode.cfg.StateRoot, ProgressFilename), &progress); err != nil {
		t.Fatal(err)
	}
	if progress.Version != 1 || progress.ProgressPermille != 1000 || progress.State != StateHealthy || progress.DrainedBytes != 8 {
		t.Fatalf("progress = %+v", progress)
	}
	var converged convergedRecord
	if err := readStrictJSON(filepath.Join(mode.cfg.StateRoot, ConvergedFilename), &converged); err != nil {
		t.Fatal(err)
	}
	if converged.VolumeID != mode.cfg.VolumeID || converged.Attempt != mode.ready.Attempt || converged.DrainedChunks != 2 || converged.DrainedBytes != 8 {
		t.Fatalf("convergence = %+v", converged)
	}
}

func TestDrainBacksOffAndConvergesAfterRecovery(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	key := chunkKey{0, 0}
	startDrain := make(chan struct{})
	mode, hydrator, _ := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{
		key: {Extents: []Extent{{Data: []byte("base")}}},
	}, func(c *Config) { c.drainStart = startDrain; c.DrainWorkers = 1 })
	hydrator.setFetchError(ErrBlocked)
	close(startDrain)
	select {
	case <-hydrator.fetchStarted:
	case <-time.After(time.Second):
		t.Fatal("drain did not make its first fetch attempt")
	}
	time.Sleep(200 * time.Millisecond)
	if got := hydrator.fetchCount(key); got != 1 {
		t.Fatalf("drain fetch attempts during initial backoff = %d, want 1", got)
	}
	hydrator.setFetchError(nil)
	waitForRestoreMode(t, 2*time.Second, "drain recovery and convergence", func() bool { return mode.converged.Load() })
	if got := hydrator.fetchCount(key); got != 2 {
		t.Fatalf("drain fetch attempts through recovery = %d, want 2", got)
	}
	if got := string(store.bytes(0)); got != "base" {
		t.Fatalf("drained bytes = %q, want base", got)
	}
}

func TestCorruptFailureHaltsDrain(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	key := chunkKey{0, 0}
	startDrain := make(chan struct{})
	mode, hydrator, _ := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{
		key: {Extents: []Extent{{Data: []byte("base")}}},
	}, func(c *Config) { c.drainStart = startDrain; c.DrainWorkers = 1 })
	hydrator.mu.Lock()
	hydrator.nextError = ErrCorrupt
	hydrator.mu.Unlock()
	close(startDrain)
	select {
	case <-hydrator.fetchStarted:
	case <-time.After(time.Second):
		t.Fatal("drain did not make its corrupt fetch attempt")
	}
	waitForRestoreMode(t, time.Second, "corrupt restore state", func() bool {
		return errors.Is(mode.ContentError(), ErrCorrupt)
	})
	time.Sleep(150 * time.Millisecond)
	if got := hydrator.fetchCount(key); got != 1 {
		t.Fatalf("drain continued fetching after corruption: %d attempts", got)
	}
	if _, err := os.Stat(filepath.Join(mode.cfg.StateRoot, ConvergedFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt drain wrote convergence record: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- mode.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close corrupt restore mode: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close hung after corrupt drain halted")
	}
}

func TestTruncateZeroIsFetchFreeAndShorteningRecallsBoundary(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{
		{0, 0}: {Extents: []Extent{{Data: []byte("abcd")}}},
		{0, 1}: {Extents: []Extent{{Data: []byte("efgh")}}},
	}, func(c *Config) { c.disableDrain = true })
	if err := mode.Truncate(context.Background(), identity, 8, 6, func() error { store.event("truncate-six"); return nil }); err != nil {
		t.Fatal(err)
	}
	hydrator.mu.Lock()
	boundaryFetches := hydrator.fetches[chunkKey{0, 1}]
	hydrator.mu.Unlock()
	if boundaryFetches != 1 {
		t.Fatalf("shortening boundary fetches = %d, want 1", boundaryFetches)
	}
	if err := mode.Truncate(context.Background(), identity, 6, 0, func() error { store.event("truncate-zero"); return nil }); err != nil {
		t.Fatal(err)
	}
	hydrator.mu.Lock()
	totalFetches := hydrator.fetches[chunkKey{0, 0}] + hydrator.fetches[chunkKey{0, 1}]
	hydrator.mu.Unlock()
	if totalFetches != 1 {
		t.Fatalf("O_TRUNC zero fetched base chunks: total fetches = %d", totalFetches)
	}
}

func TestUserModifiedSuppressesLaterMtimeRestore(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, _, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("abcd")}}}, {0, 1}: {Extents: []Extent{{Data: []byte("efgh")}}}}, func(c *Config) { c.disableDrain = true })
	if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mode.Write(context.Background(), identity, 0, 1, func() (int, int64, error) { return 1, -1, nil }); err != nil {
		t.Fatal(err)
	}
	if err := mode.EnsureHydrated(context.Background(), identity, 4, 4); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	restores := store.mtimeRestores
	store.mu.Unlock()
	if restores != 1 {
		t.Fatalf("mtime restores=%d want 1", restores)
	}
}

func TestDrainLosesRaceToWholeChunkWrite(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	startDrain := make(chan struct{})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("base")}}}}, func(c *Config) { c.drainStart = startDrain })
	hydrator.mu.Lock()
	hydrator.blockFetch = make(chan struct{})
	block := hydrator.blockFetch
	hydrator.mu.Unlock()
	close(startDrain)
	select {
	case <-hydrator.fetchStarted:
	case <-time.After(time.Second):
		t.Fatal("drain did not fetch")
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := mode.Write(context.Background(), identity, 0, 4, func() (int, int64, error) { store.event("apply-user"); return 4, -1, nil })
		done <- err
	}()
	select {
	case <-hydrator.fetchStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not recall after preempting drain")
	}
	close(block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	store.mu.Unlock()
	applied := false
	for i, event := range events {
		if event == "apply-user" {
			applied = true
		}
		if event == "pwrite" && applied {
			t.Fatalf("late drain pwrite at %d after user write: %v", i, events)
		}
	}
	if !applied || !mode.hmap.isDurable(chunkKey{0, 0}) {
		t.Fatalf("write did not apply over a durable chunk: %v", events)
	}
}

func TestBlockedStateAutoClearsOnHealth(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 4})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("base")}}}}, func(c *Config) { c.disableDrain = true })
	hydrator.mu.Lock()
	hydrator.nextError = ErrBlocked
	hydrator.mu.Unlock()
	if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked recall=%v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for mode.ContentError() != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := mode.ContentError(); err != nil {
		t.Fatalf("blocked state did not clear: %v", err)
	}
}

func TestBlockedStateRefusesAlreadyHydratedContentUniformly(t *testing.T) {
	store := newFakeStore(map[uint32]int64{0: 8})
	mode, hydrator, identity := openTestMode(t, store, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{
		{0, 0}: {Extents: []Extent{{Data: []byte("abcd")}}},
		{0, 1}: {Extents: []Extent{{Data: []byte("efgh")}}},
	}, func(c *Config) { c.disableDrain = true })
	if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); err != nil {
		t.Fatal(err)
	}
	hydrator.mu.Lock()
	hydrator.nextError = ErrBlocked
	hydrator.mu.Unlock()
	if err := mode.EnsureHydrated(context.Background(), identity, 4, 4); !errors.Is(err, ErrBlocked) {
		t.Fatalf("cold blocked recall = %v", err)
	}
	if err := mode.EnsureHydrated(context.Background(), identity, 0, 4); !errors.Is(err, ErrBlocked) {
		t.Fatalf("already hydrated read during blocked state = %v", err)
	}
}

func waitForRestoreMode(t *testing.T, within time.Duration, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
