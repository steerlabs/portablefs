package workfs

// Truncate-shrink must permanently discard the shrunk-away bytes of an
// immutable base: a later regrow exposes a hole (zeros), never the old base
// content. The visible base is capped at the shrink point (monotone), which
// readBlocks, the writeBlocks read-modify-write, and every checkpoint
// materialization all gate on.

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// recordingRanger serves 'B' bytes for an immutable base and records the
// highest offset it was ever asked to serve.
type recordingRanger struct {
	mu     sync.Mutex
	maxEnd int64
}

func (r *recordingRanger) ReadRangeAt(_ context.Context, p []byte, off int64) (int, error) {
	r.mu.Lock()
	if end := off + int64(len(p)); end > r.maxEnd {
		r.maxEnd = end
	}
	r.mu.Unlock()
	for i := range p {
		p[i] = 'B'
	}
	return len(p), nil
}

func (r *recordingRanger) maxServedEnd() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxEnd
}

func TestTruncateShrinkCapsVisibleBase(t *testing.T) {
	ranger := &recordingRanger{}
	fs := &FS{cache: content.NewCache(1 << 20)}
	n := &inode{
		ino: 2, kind: "file", size: 8192,
		source: content.Source{Size: 8192, Ranger: ranger},
	}

	fs.truncateBlocks(n, 4096)
	if n.source.Size != 4096 {
		t.Fatalf("visible base after shrink = %d, want 4096", n.source.Size)
	}
	fs.truncateBlocks(n, 8192) // regrow: the discarded range is a hole now
	if n.source.Size != 4096 {
		t.Fatalf("visible base after regrow = %d, want 4096 (cap is monotone)", n.source.Size)
	}

	buf := make([]byte, 8192)
	if _, err := fs.readBlocks(n, buf, 0); err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:4096], bytes.Repeat([]byte{'B'}, 4096)) {
		t.Fatal("surviving base prefix must still serve base bytes")
	}
	if !bytes.Equal(buf[4096:], make([]byte, 4096)) {
		t.Fatal("regrown range resurrected old base bytes; POSIX requires zeros")
	}
	if end := ranger.maxServedEnd(); end > 4096 {
		t.Fatalf("read fetched base bytes beyond the shrink cap (through %d)", end)
	}

	// A partial write inside the regrown hole must read-modify-write against
	// ZEROS, not against resurrected base content.
	if err := fs.writeBlocks(n, 6000, []byte("XY")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := fs.readBlocks(n, buf, 0); err != nil && err != io.EOF {
		t.Fatalf("read after write: %v", err)
	}
	if !bytes.Equal(buf[4096:6000], make([]byte, 6000-4096)) ||
		string(buf[6000:6002]) != "XY" ||
		!bytes.Equal(buf[6002:], make([]byte, 8192-6002)) {
		t.Fatal("write into the regrown hole leaked base bytes around it")
	}
	if end := ranger.maxServedEnd(); end > 4096 {
		t.Fatalf("write fetched base bytes beyond the shrink cap (through %d)", end)
	}
}

func TestTruncateShrinkRegrowIsZeroOnLazyBaseAndReplay(t *testing.T) {
	// A real lazy PFT2 base file, shrunk and regrown through durable managed
	// rows: the live tree, a cold-replayed tree, and every read path agree
	// the regrown range is zeros.
	const size = 10_000
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		{Op: wal.OpWrite, Path: "f", Data: bytes.Repeat([]byte{'A'}, size)},
	})
	log := newFakeEntryLog()
	fs, _ := newLazyFS(t, base, log)

	commitTree(t, fs, wal.Record{Op: wal.OpTruncate, Path: "f", Size: 5000})
	commitTree(t, fs, wal.Record{Op: wal.OpTruncate, Path: "f", Size: size})

	want := append(bytes.Repeat([]byte{'A'}, 5000), make([]byte, size-5000)...)
	if got := lazyReadFile(t, fs, "f"); got != string(want) {
		t.Fatalf("live read after shrink+regrow diverges at %d", firstDiff([]byte(got), want))
	}

	// Cold replay of the same durable journal over the same immutable base
	// must reproduce the hole exactly (the shrink cap is part of replayed
	// truncate semantics, not live-only state).
	replayed, _ := newLazyFS(t, base, log)
	if got := lazyReadFile(t, replayed, "f"); got != string(want) {
		t.Fatalf("cold replay resurrects shrunk base bytes at %d", firstDiff([]byte(got), want))
	}
}
