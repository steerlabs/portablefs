package checkpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/treehash"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// fakeClient mirrors production: one object is both the workfs blob reader (Blob)
// and the checkpoint committer (PutBlob/Version/Commit), sharing one blob store —
// so a blob uploaded at checkpoint is readable afterward.
type fakeClient struct {
	blobs       map[string][]byte
	commitTree  string
	commitEntry []backend.ManifestEntry
	committed   bool
}

func (f *fakeClient) Blob(_ context.Context, d string) ([]byte, error) {
	v, ok := f.blobs[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return v, nil
}
func (f *fakeClient) PutBlob(_ context.Context, digest string, data []byte) error {
	f.blobs[digest] = append([]byte(nil), data...)
	return nil
}
func (f *fakeClient) Version() string { return "portablefs-v1" }
func (f *fakeClient) Commit(_ context.Context, treeHash string, entries []backend.ManifestEntry, _, _ int64) (string, error) {
	f.committed = true
	f.commitTree = treeHash
	f.commitEntry = entries
	return "cmt_new", nil
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func toHashEntries(es []backend.ManifestEntry) []treehash.Entry {
	out := make([]treehash.Entry, len(es))
	for i, e := range es {
		te := treehash.Entry{Path: e.Path, Kind: e.Kind, Mode: e.Mode, Size: e.Size, Executable: e.Executable, LinkTarget: e.LinkTarget}
		if e.Blob != nil {
			te.Blob = &treehash.Blob{Digest: e.Blob.Digest, Size: e.Blob.Size, Compression: e.Blob.Compression, Packed: e.Blob.Packed}
		}
		for _, c := range e.Chunks {
			te.Chunks = append(te.Chunks, treehash.Chunk{Digest: c.Digest, Size: c.Size, Offset: c.Offset})
		}
		out[i] = te
	}
	return out
}

// assertAllocatorSidecarOnly verifies the post-checkpoint WAL invariant. A
// successful checkpoint compacts every user mutation, but deliberately keeps
// one internal OpControl snapshot containing the monotonic inode allocator.
// Removing that last record would let a deleted high-water inode be reused
// after restart.
func assertAllocatorSidecarOnly(t *testing.T, w *wal.WAL) {
	t.Helper()
	recs, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Op != wal.OpControl {
		t.Fatalf("post-checkpoint WAL = %+v, want one allocator/control snapshot", recs)
	}
}

func TestCheckpointUploadsCommitsAndCleans(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{"d-a": []byte("AAA")}}
	base := []backend.Entry{{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 3, BlobDigest: "d-a", BlobSize: 3, BlobCompression: "none"}}
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(base, cli, w)
	if err != nil {
		t.Fatal(err)
	}

	bf, _ := fs.Create("b.txt")
	_, _ = bf.Write([]byte("new file"))
	_ = bf.Close()
	af, _ := fs.OpenFile("a.txt", os.O_RDWR, 0)
	_, _ = af.Seek(0, io.SeekStart)
	_, _ = af.Write([]byte("ZZZ"))
	_ = af.Close()

	head, err := Run(context.Background(), fs, cli)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if head != "cmt_new" || !cli.committed {
		t.Fatalf("head=%q committed=%v", head, cli.committed)
	}
	if string(cli.blobs[shaHex("ZZZ")]) != "ZZZ" || string(cli.blobs[shaHex("new file")]) != "new file" {
		t.Fatal("dirty content not uploaded as content-addressed blobs")
	}
	if len(cli.commitEntry) != 2 {
		t.Fatalf("manifest entries = %d, want 2", len(cli.commitEntry))
	}
	if recomputed := treehash.Compute(toHashEntries(cli.commitEntry)); recomputed != cli.commitTree {
		t.Fatalf("treeHash %s != recomputed %s", cli.commitTree, recomputed)
	}
	for _, e := range fs.Snapshot().Entries {
		if e.Kind == "file" && e.Dirty {
			t.Fatalf("%s still dirty after checkpoint", e.Path)
		}
	}
	assertAllocatorSidecarOnly(t, w)
	rf, _ := fs.Open("a.txt")
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if string(got) != "ZZZ" {
		t.Fatalf("a.txt after checkpoint = %q, want ZZZ", got)
	}
}

func TestCheckpointNoOpWhenClean(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	w, _ := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	fs, _ := workfs.New(nil, cli, w)
	head, err := Run(context.Background(), fs, cli)
	if err != nil {
		t.Fatal(err)
	}
	if head != "" || cli.committed {
		t.Fatalf("clean checkpoint should be a no-op: head=%q committed=%v", head, cli.committed)
	}
}

// TestCheckpointConcurrentWritesNoLoss: a checkpoint (Snapshot → MaterializeFull → Commit →
// MarkClean, which installs source + clears dirty blocks) running CONCURRENTLY with a stream of
// page writes must lose NOTHING. The authority's block store (inode.source + inode.blocks) must
// reconstruct EXACTLY what a sequential flat-array application of the same writes yields.
// Deterministic, no-Docker regression for the SQLite-handoff partial row loss (the same flushed
// records produced 200 rows in the session's flat overlay but 18X in this block store).
func TestCheckpointConcurrentWritesNoLoss(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, cli, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "app.db", Mode: 0o644}}, ""); err != nil {
		t.Fatal(err)
	}

	const page = 4096
	const npages = 4 // app.db stays in a single 4 MiB block (like a small SQLite DB)
	ref := make([]byte, 0)
	applyToRef := func(off int64, data []byte) {
		end := off + int64(len(data))
		if int64(len(ref)) < end {
			ref = append(ref, make([]byte, end-int64(len(ref)))...)
		}
		copy(ref[off:end], data)
	}
	truncRef := func(size int64) {
		if int64(len(ref)) > size {
			ref = ref[:size]
		} else {
			ref = append(ref, make([]byte, size-int64(len(ref)))...)
		}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() { // hammer the checkpointer concurrently with the writes
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = Run(context.Background(), fs, cli)
			}
		}
	}()
	wg.Add(1)
	go func() { // concurrent reader: stress readBlocks' lock-free base fetch vs the source install
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if rf, err := fs.Open("app.db"); err == nil {
					_, _ = io.ReadAll(rf)
					_ = rf.Close()
				}
			}
		}
	}()

	// SQLite's DELETE-journal churns the file: full + PARTIAL page writes (read-modify-write) and
	// TRUNCATES every transaction. Mix them so the checkpoint's source-install + clear races the
	// RMW base-read and the truncate.
	for i := 0; i < 4000; i++ {
		switch i % 9 {
		case 7:
			sz := int64(((i % npages) + 1) * page)
			if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpTruncate, Path: "app.db", Size: sz}}, ""); err != nil {
				t.Errorf("apply truncate %d: %v", i, err)
			}
			truncRef(sz)
		default:
			off := int64((i % npages) * page)
			ln := page
			if i%3 == 0 { // partial-page write -> read-modify-write path
				ln, off = 100, off+50
			}
			data := bytes.Repeat([]byte{byte(i*7 + 1)}, ln)
			if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: "app.db", Offset: off, Data: data}}, ""); err != nil {
				t.Errorf("apply write %d: %v", i, err)
			}
			applyToRef(off, data)
		}
	}
	close(stop)
	wg.Wait()

	// One final checkpoint then read back: the reconstruction must equal the flat reference.
	_, _ = Run(context.Background(), fs, cli)
	rf, err := fs.Open("app.db")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if !bytes.Equal(got, ref) {
		first := -1
		for i := 0; i < len(ref) && i < len(got); i++ {
			if got[i] != ref[i] {
				first = i
				break
			}
		}
		t.Fatalf("block store diverged from flat reference: len got=%d want=%d, first diff at byte %d (page %d): got=%d want=%d — a write was lost to the checkpoint race",
			len(got), len(ref), first, first/page, got[first], ref[first])
	}
}
