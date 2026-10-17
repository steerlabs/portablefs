package restoremode

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type hydrationMtimeStore struct {
	*fakeStore
	writeErr, restoreErr error
	wrote, resume        chan struct{}
}

func (s *hydrationMtimeStore) PWrite(entry uint32, off int64, data []byte) error {
	if err := s.fakeStore.PWrite(entry, off, data); err != nil {
		return err
	}
	s.mu.Lock()
	s.mtime = 999
	s.mu.Unlock()
	if s.wrote != nil {
		close(s.wrote)
		<-s.resume
	}
	return s.writeErr
}
func (s *hydrationMtimeStore) RestoreMtime(entry uint32, nanos int64) error {
	if s.restoreErr != nil {
		return s.restoreErr
	}
	return s.fakeStore.RestoreMtime(entry, nanos)
}

func TestHydrationPreservesCurrentMtimeAfterEveryUserChange(t *testing.T) {
	for _, change := range []string{"write", "timestamp", "truncate", "unlink-open"} {
		t.Run(change, func(t *testing.T) {
			store := &hydrationMtimeStore{fakeStore: newFakeStore(map[uint32]int64{0: 8})}
			mode, _, identity := openTestMode(t, store.fakeStore, testInfo([2]uint32{0, 0}, [2]uint32{0, 1}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("abcd")}}}, {0, 1}: {Extents: []Extent{{Data: []byte("efgh")}}}}, func(c *Config) { c.disableDrain = true; c.Store = store })
			setMtime := func() error { store.mu.Lock(); store.mtime = 123456789; store.mu.Unlock(); return nil }
			switch change {
			case "write":
				_, _, err := mode.Write(t.Context(), identity, 0, 1, func() (int, int64, error) { return 1, 0, setMtime() })
				if err != nil {
					t.Fatal(err)
				}
			case "truncate":
				if err := mode.Truncate(t.Context(), identity, 8, 8, setMtime); err != nil {
					t.Fatal(err)
				}
			case "unlink-open":
				store.mu.Lock()
				store.linked = false
				store.mu.Unlock()
				if err := setMtime(); err != nil {
					t.Fatal(err)
				}
			case "timestamp":
				if err := mode.UserMutation(identity, setMtime); err != nil {
					t.Fatal(err)
				}
			}
			if err := mode.EnsureHydrated(t.Context(), identity, 4, 4); err != nil {
				t.Fatal(err)
			}
			if got, _ := store.Mtime(0); got != 123456789 {
				t.Fatalf("logical mtime=%d", got)
			}
		})
	}
}

func TestHydrationMtimeRestoredOnPartialWriteAndLockedThroughObservation(t *testing.T) {
	for _, writeErr := range []error{nil, syscall.ENOSPC} {
		t.Run(errorName(writeErr), func(t *testing.T) {
			store := &hydrationMtimeStore{fakeStore: newFakeStore(map[uint32]int64{0: 4}), writeErr: writeErr, wrote: make(chan struct{}), resume: make(chan struct{})}
			store.mtime = 123
			mode, _, identity := openTestMode(t, store.fakeStore, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("data")}}}}, func(c *Config) { c.disableDrain = true; c.Store = store })
			done := make(chan error, 1)
			go func() { done <- mode.EnsureHydrated(context.Background(), identity, 0, 4) }()
			select {
			case <-store.wrote:
			case <-time.After(time.Second):
				t.Fatal("hydration did not write")
			}
			sample := make(chan int64, 1)
			go func() {
				_ = mode.WithAttrLock(identity, func() error { mtime, _ := store.Mtime(0); sample <- mtime; return nil })
			}()
			select {
			case mtime := <-sample:
				t.Fatalf("transient mtime escaped: %d", mtime)
			case <-time.After(20 * time.Millisecond):
			}
			close(store.resume)
			if err := <-done; !errors.Is(err, writeErr) {
				t.Fatalf("hydrate=%v, want %v", err, writeErr)
			}
			if got := <-sample; got != 123 {
				t.Fatalf("observed mtime=%d", got)
			}
		})
	}
}

func errorName(err error) string {
	if err == nil {
		return "success"
	}
	return err.Error()
}

func TestHydrationMtimeRestoreFailurePermanentlyStopsSamplesAndDrain(t *testing.T) {
	store := &hydrationMtimeStore{fakeStore: newFakeStore(map[uint32]int64{0: 4}), restoreErr: syscall.EPERM}
	var failures atomic.Int32
	mode, _, identity := openTestMode(t, store.fakeStore, testInfo([2]uint32{0, 0}), map[chunkKey]Chunk{{0, 0}: {Extents: []Extent{{Data: []byte("data")}}}}, func(c *Config) {
		c.disableDrain = true
		c.Store = store
		c.OnStorageFailure = func(err error) {
			if errors.Is(err, syscall.EIO) {
				failures.Add(1)
			}
		}
	})
	if err := mode.EnsureHydrated(t.Context(), identity, 0, 4); !errors.Is(err, syscall.EIO) {
		t.Fatalf("hydrate=%v", err)
	}
	for range 2 {
		called := false
		if err := mode.WithAttrLock(identity, func() error { called = true; return nil }); !errors.Is(err, syscall.EIO) || called {
			t.Fatalf("sample=%v, called=%v", err, called)
		}
	}
	if failures.Load() != 1 || !mode.isCorrupt() {
		t.Fatalf("failure callbacks=%d, corrupt=%v", failures.Load(), mode.isCorrupt())
	}
}
