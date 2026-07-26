package workfs

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// TestConcurrentReadersAndWriters stresses the RWMutex tree lock: 8 readers
// (stat/readdir/open+read, RLock) run concurrently with 4 writers
// (create/write/chmod/remove, exclusive Lock). It must stay race-clean (run with
// -race) and leave the seeded files intact — parallel reads must never observe or
// cause a corrupt tree.
func TestConcurrentReadersAndWriters(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	const seeds = 50
	for i := 0; i < seeds; i++ {
		f, err := fs.Create(fmt.Sprintf("seed%02d", i))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(fmt.Sprintf("content-%02d", i)))
		_ = f.Close()
	}

	stop := make(chan struct{})
	var readers, writers sync.WaitGroup
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func(r int) {
			defer readers.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				name := fmt.Sprintf("seed%02d", (r+n)%seeds)
				_, _ = fs.Stat(name)
				_, _ = fs.ReadDir("")
				if f, err := fs.Open(name); err == nil {
					_, _ = io.ReadAll(f)
					_ = f.Close()
				}
			}
		}(r)
	}
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for k := 0; k < 300; k++ {
				name := fmt.Sprintf("w%d-%d", w, k)
				if f, err := fs.Create(name); err == nil {
					_, _ = f.Write([]byte("scratch"))
					_ = f.Close()
				}
				_ = fs.Chmod(name, 0o600)
				_ = fs.Remove(name)
			}
		}(w)
	}
	writers.Wait()
	close(stop)
	readers.Wait()

	for i := 0; i < seeds; i++ {
		if got := readFile(t, fs, fmt.Sprintf("seed%02d", i)); got != fmt.Sprintf("content-%02d", i) {
			t.Fatalf("seed%02d corrupted under concurrency: %q", i, got)
		}
	}
}

// slowBlobs adds latency to each backend Blob fetch, modelling a slow/remote object
// store, so a test can prove concurrent writers fetch base blocks in PARALLEL (warmed
// outside fs.mu) rather than serializing on a backend round-trip held under the lock.
type slowBlobs struct {
	data    map[string][]byte
	delay   time.Duration
	mu      sync.Mutex
	fetches int
}

func (b *slowBlobs) Blob(_ context.Context, d string) ([]byte, error) {
	time.Sleep(b.delay)
	b.mu.Lock()
	b.fetches++
	b.mu.Unlock()
	v, ok := b.data[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return append([]byte(nil), v...), nil
}

// TestConcurrentPartialWritesDoNotSerializeOnBackendFetch: N writers each do a
// read-modify-write (partial overwrite) of a DISTINCT backed file whose base must be
// fetched from a slow backend. With the base fetch warmed outside fs.mu, the fetches
// run in parallel and the whole batch finishes in roughly one fetch latency — not N.
func TestConcurrentPartialWritesDoNotSerializeOnBackendFetch(t *testing.T) {
	const N = 20
	blobs := &slowBlobs{data: map[string][]byte{}, delay: 50 * time.Millisecond}
	var entries []backend.Entry
	for i := 0; i < N; i++ {
		base := []byte(fmt.Sprintf("base-bytes-for-file-%02d-padding-padding-padding", i))
		d := digestOf(base)
		blobs.data[d] = base
		entries = append(entries, backend.Entry{
			Path: fmt.Sprintf("f%02d", i), Kind: "file", Mode: 0o644,
			Size: int64(len(base)), BlobDigest: d,
		})
	}
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(entries, blobs, w)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Partial overwrite at offset 2 → block 0 is a read-modify-write → base fetch.
			if err := fs.writeAt(fmt.Sprintf("f%02d", i), 2, []byte("XY")); err != nil {
				t.Errorf("write f%02d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Per-write serialized-under-lock fetching would be N*50ms = 1s. Warmed-in-parallel
	// should be a small multiple of one fetch latency.
	if elapsed > time.Duration(N/4)*blobs.delay {
		t.Fatalf("partial writes serialized on the backend fetch: %v for %d writes (want ~1 fetch latency)", elapsed, N)
	}
	t.Logf("lock-off-fetch: %d concurrent read-modify-writes (50ms backend each) in %v", N, elapsed)

	// Correctness: each file reflects the overwrite over its preserved base.
	for i := 0; i < N; i++ {
		got := readFile(t, fs, fmt.Sprintf("f%02d", i))
		want := fmt.Sprintf("baXY-bytes-for-file-%02d-padding-padding-padding", i)
		if got != want {
			t.Fatalf("f%02d = %q, want %q (read-modify-write corrupted)", i, got, want)
		}
	}
}
