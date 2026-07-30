package workfs

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
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

// gatedBlobs holds every backend Blob fetch at a shared barrier. Reaching the
// barrier with all writers proves directly that base reads run in parallel
// outside fs.mu; a fetch performed under that lock would prevent the remaining
// writers from ever entering Blob.
type gatedBlobs struct {
	data       map[string][]byte
	want       int
	allStarted chan struct{}
	release    chan struct{}

	mu      sync.Mutex
	fetches int
}

func newGatedBlobs(want int) *gatedBlobs {
	return &gatedBlobs{
		data:       map[string][]byte{},
		want:       want,
		allStarted: make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (b *gatedBlobs) Blob(ctx context.Context, d string) ([]byte, error) {
	b.mu.Lock()
	b.fetches++
	if b.fetches == b.want {
		close(b.allStarted)
	}
	b.mu.Unlock()

	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	v, ok := b.data[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return append([]byte(nil), v...), nil
}

// TestConcurrentPartialWritesDoNotSerializeOnBackendFetch: N writers each do a
// read-modify-write (partial overwrite) of a DISTINCT backed file whose base must be
// fetched from a gated backend. With the base fetch warmed outside fs.mu, every fetch
// reaches the barrier concurrently. If the fetch ran under fs.mu, only one writer
// could reach the barrier and the test would fail before releasing it.
func TestConcurrentPartialWritesDoNotSerializeOnBackendFetch(t *testing.T) {
	const N = 20
	blobs := newGatedBlobs(N)
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

	select {
	case <-blobs.allStarted:
		close(blobs.release)
	case <-time.After(5 * time.Second):
		close(blobs.release)
		wg.Wait()
		blobs.mu.Lock()
		started := blobs.fetches
		blobs.mu.Unlock()
		t.Fatalf("backend fetches did not overlap: %d of %d reached the barrier", started, N)
	}
	wg.Wait()
	t.Logf("lock-off-fetch: all %d concurrent read-modify-writes reached the backend barrier", N)

	// Correctness: each file reflects the overwrite over its preserved base.
	for i := 0; i < N; i++ {
		got := readFile(t, fs, fmt.Sprintf("f%02d", i))
		want := fmt.Sprintf("baXY-bytes-for-file-%02d-padding-padding-padding", i)
		if got != want {
			t.Fatalf("f%02d = %q, want %q (read-modify-write corrupted)", i, got, want)
		}
	}
}
