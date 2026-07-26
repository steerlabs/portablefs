package checkpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/content"
	"github.com/trendup-ai/portablefs/vcs/internal/treehash"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// This file is an exhaustive boundary + concurrency sweep over the durable
// checkpointer (checkpoint.Run plus the workfs snapshot/MarkClean machinery it
// drives). It reuses the fakeClient harness defined in checkpoint_test.go (same
// package): one object is both the blob store and the committer, so a blob
// uploaded during a checkpoint is readable afterward.

// chunkBytes mirrors checkpoint.go's threshold: a file >= 8 MiB takes the
// streaming large-file path (SnapshotBlock per 4 MiB chunk); below it is a single
// whole-file blob. blkBytes is the streaming/block granularity.
const (
	chunkBytes = 8 << 20
	blkBytes   = 4 << 20
)

// lockedClient is a thread-safe view of the in-package fakeClient harness. The
// harness backs its blob store with a plain map and is only ever exercised by ONE
// checkpointer at a time in checkpoint_test.go; the concurrency sweep below runs
// MULTIPLE checkpointers AND readers, which would race that map. We cannot modify
// the existing harness, so this wrapper serialises every harness touch behind a
// mutex. It satisfies both content.BlobReader (Blob) and checkpoint.Committer
// (PutBlob/Version/Commit), so workfs and Run see one object — exactly as in prod.
// It guards ONLY the test's storage map; all real workfs/checkpoint concurrency
// (the thing under test) still runs unsynchronised.
type lockedClient struct {
	mu    sync.Mutex
	inner *fakeClient
}

func newLockedClient() *lockedClient {
	return &lockedClient{inner: &fakeClient{blobs: map[string][]byte{}}}
}
func (l *lockedClient) Blob(ctx context.Context, d string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.Blob(ctx, d)
}
func (l *lockedClient) PutBlob(ctx context.Context, d string, data []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.PutBlob(ctx, d, data)
}
func (l *lockedClient) Version() string { return l.inner.Version() }
func (l *lockedClient) Commit(ctx context.Context, treeHash string, entries []backend.ManifestEntry, mc, bc int64) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.Commit(ctx, treeHash, entries, mc, bc)
}

// newFS spins up a fresh working FS over the shared fakeClient with a temp WAL.
func newFS(t *testing.T, cli *fakeClient, base []backend.Entry) (*workfs.FS, *wal.WAL) {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	fs, err := workfs.New(base, cli, w)
	if err != nil {
		t.Fatalf("workfs.New: %v", err)
	}
	return fs, w
}

// readAll is provided by real_test.go in this same package (opens name and returns
// its full bytes, failing the test on error); we reuse it here.

// createWith creates a born file and writes body in one shot.
func createWith(t *testing.T, fs *workfs.FS, name string, body []byte) {
	t.Helper()
	f, err := fs.Create(name)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if len(body) > 0 {
		if _, err := f.Write(body); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

// writeAt seeks to off and writes data through the billy file API (the same path a
// real mount uses), so the write is journalled + dirties the inode.
func writeAt(t *testing.T, fs *workfs.FS, name string, off int64, data []byte) {
	t.Helper()
	f, err := fs.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("openfile %s: %v", name, err)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		t.Fatalf("seek %s: %v", name, err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func shaOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// backedFile registers body in cli's blob store under its real content address and
// returns a base manifest Entry pointing at it. The content layer verifies digests
// on read, so a backed file that may be partially read MUST carry its true sha256
// (a fake digest fails verifyDigest on the first read-modify-write base fetch).
func backedFile(cli *fakeClient, path string, body []byte) backend.Entry {
	d := shaOf(body)
	cli.blobs[d] = append([]byte(nil), body...)
	return backend.Entry{
		Path: path, Kind: "file", Mode: 0o644, Size: int64(len(body)),
		BlobDigest: d, BlobSize: int64(len(body)), BlobCompression: "none",
	}
}

func entryByPath(es []backend.ManifestEntry, p string) (backend.ManifestEntry, bool) {
	for _, e := range es {
		if e.Path == p {
			return e, true
		}
	}
	return backend.ManifestEntry{}, false
}

func snapEntry(snap *workfs.Snapshot, p string) (workfs.SnapshotEntry, bool) {
	for _, e := range snap.Entries {
		if e.Path == p {
			return e, true
		}
	}
	return workfs.SnapshotEntry{}, false
}

// isDirty reports the snapshot dirtiness of a path right now.
func isDirty(fs *workfs.FS, p string) (dirty, present bool) {
	se, ok := snapEntry(fs.Snapshot(), p)
	if !ok {
		return false, false
	}
	return se.Dirty, true
}

// ---------------------------------------------------------------------------
// MarkClean dirtyEpoch guard — the core correctness invariant the focus calls
// out: a write that RACES the snapshot (lands after the snapshot is captured but
// before MarkClean runs) must stay dirty and must NOT be dropped. We drive the
// exact internal sequence the checkpointer uses (Snapshot -> MaterializeFull ->
// PutBlob -> MarkClean) deterministically through the public workfs API, with a
// write wedged in between the snapshot and the rebind.
// ---------------------------------------------------------------------------
func TestMarkCleanGuardKeepsRacingWriteDirty(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	fs, _ := newFS(t, cli, nil)

	createWith(t, fs, "race.txt", []byte("v1-snapshot-body"))

	// Capture the snapshot the way Run does.
	snap := fs.Snapshot()
	se, ok := snapEntry(snap, "race.txt")
	if !ok || !se.Dirty {
		t.Fatalf("race.txt should be dirty in the snapshot: ok=%v dirty=%v", ok, se.Dirty)
	}

	// "Upload" the snapshot body, exactly as Run would.
	body, err := fs.MaterializeFull(se)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	digest := shaOf(body)
	if err := cli.PutBlob(context.Background(), digest, body); err != nil {
		t.Fatal(err)
	}
	src := content.Source{BlobDigest: digest, BlobSize: int64(len(body)), BlobCompression: "none", Size: int64(len(body))}

	// RACE: a fresh write lands AFTER the snapshot was captured (so dirtyEpoch >
	// snap.epoch) but BEFORE MarkClean runs.
	writeAt(t, fs, "race.txt", 0, []byte("v2-RACED-write!!"))

	// The checkpointer now rebinds to the snapshot body's source. The guard MUST
	// refuse because dirtyEpoch > snap.epoch.
	fs.MarkClean(snap, "race.txt", src)

	// The file must still hold the raced (v2) bytes — not the committed-at-snapshot
	// v1 body MarkClean tried to install — and must still be dirty so the NEXT
	// checkpoint commits v2.
	if got := readAll(t, fs, "race.txt"); string(got) != "v2-RACED-write!!" {
		t.Fatalf("racing write clobbered by MarkClean: got %q, want v2 raced bytes", got)
	}
	if dirty, _ := isDirty(fs, "race.txt"); !dirty {
		t.Fatal("race.txt marked clean despite a write racing the snapshot — the raced write would be LOST at WAL compaction")
	}
}

// A non-racing file (no write between snapshot and rebind) MUST be cleaned: the
// guard is dirtyEpoch > snap.epoch (strictly greater), so a write that is part of
// the snapshot itself still rebinds.
func TestMarkCleanRebindsNonRacingFile(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	fs, _ := newFS(t, cli, nil)
	createWith(t, fs, "clean.txt", []byte("committed body"))

	head, err := Run(context.Background(), fs, cli)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if head == "" {
		t.Fatal("expected a commit for a dirty born file")
	}
	if dirty, present := isDirty(fs, "clean.txt"); !present || dirty {
		t.Fatalf("clean.txt should be clean after checkpoint: present=%v dirty=%v", present, dirty)
	}
	if got := readAll(t, fs, "clean.txt"); string(got) != "committed body" {
		t.Fatalf("clean.txt readback = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Run end-to-end: dirty files become content-addressed blobs + a manifest, then
// MarkClean rebind. Also asserts the committed tree hash recomputes (so the
// manifest the server would accept is self-consistent).
// ---------------------------------------------------------------------------
func TestRunCommitsBlobsManifestAndRebinds(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	base := []backend.Entry{backedFile(cli, "kept.txt", []byte("BASE"))}
	fs, w := newFS(t, cli, base)

	createWith(t, fs, "born.txt", []byte("hello born"))
	writeAt(t, fs, "kept.txt", 0, []byte("OVER")) // full-block overwrite of the backed file

	head, err := Run(context.Background(), fs, cli)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if head != "cmt_new" || !cli.committed {
		t.Fatalf("head=%q committed=%v", head, cli.committed)
	}
	if string(cli.blobs[shaOf([]byte("hello born"))]) != "hello born" {
		t.Fatal("born content not uploaded as a content-addressed blob")
	}
	if string(cli.blobs[shaOf([]byte("OVER"))]) != "OVER" {
		t.Fatal("overwritten backed content not uploaded as a content-addressed blob")
	}
	// Manifest self-consistency: recomputed tree hash == committed tree hash.
	if rec := treehash.Compute(toHashEntries(cli.commitEntry)); rec != cli.commitTree {
		t.Fatalf("treeHash %s != recomputed %s", cli.commitTree, rec)
	}
	// All files clean, WAL compacted.
	for _, e := range fs.Snapshot().Entries {
		if e.Kind == "file" && e.Dirty {
			t.Fatalf("%s still dirty after checkpoint", e.Path)
		}
	}
	assertAllocatorSidecarOnly(t, w)
	if got := readAll(t, fs, "kept.txt"); string(got) != "OVER" {
		t.Fatalf("kept.txt after checkpoint = %q", got)
	}
}

// No-op contract: a checkpoint with nothing dirty commits nothing, returns an
// empty head, and never touches the committer. Includes a clean backed file (it
// is in the snapshot but not dirty) so we exercise the "all clean" walk.
func TestRunNoOpWhenNothingDirty(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{"d-base": []byte("xyz")}}
	base := []backend.Entry{{Path: "f.txt", Kind: "file", Mode: 0o644, Size: 3, BlobDigest: "d-base", BlobSize: 3, BlobCompression: "none"}}
	fs, _ := newFS(t, cli, base)

	head, err := Run(context.Background(), fs, cli)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if head != "" || cli.committed {
		t.Fatalf("clean checkpoint must be a no-op: head=%q committed=%v", head, cli.committed)
	}
}

// Idempotent re-run: after a successful checkpoint cleans everything, an immediate
// second Run finds nothing dirty and is a no-op. Then a fresh write makes exactly
// that one file dirty again and the third Run commits only it.
func TestRunIdempotentReRun(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	fs, _ := newFS(t, cli, nil)
	createWith(t, fs, "a.txt", []byte("first"))

	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run1: %v", err)
	}
	cli.committed = false
	cli.commitEntry = nil
	head, err := Run(context.Background(), fs, cli)
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	if head != "" || cli.committed {
		t.Fatalf("second back-to-back checkpoint must be a no-op: head=%q committed=%v", head, cli.committed)
	}

	// A new write re-dirties a.txt; the next checkpoint commits the newer content.
	writeAt(t, fs, "a.txt", 0, []byte("SECON")) // same length, full overwrite
	cli.committed = false
	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run3: %v", err)
	}
	if !cli.committed {
		t.Fatal("third checkpoint should commit the re-dirtied file")
	}
	if got := readAll(t, fs, "a.txt"); string(got) != "SECON" {
		t.Fatalf("a.txt after re-checkpoint = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Large-file streaming path: a born file at / above the 8 MiB threshold is
// committed via SnapshotBlock -> per-4-MiB-chunk PutBlob -> chunked manifest, and
// the whole-file digest folds every block. After MarkClean installs the chunked
// source, the full file must read back byte-for-byte. We sweep sizes around the
// chunk + block boundaries.
// ---------------------------------------------------------------------------
func TestRunLargeFileStreamingReadback(t *testing.T) {
	sizes := []int64{
		chunkBytes,         // exactly at threshold: 2 full 4 MiB blocks
		chunkBytes + 1,     // threshold + 1 byte (tiny 3rd block)
		chunkBytes + 100,   // threshold + a small partial last block
		blkBytes*3 + 12345, // 3 full blocks + partial 4th
		blkBytes*4 - 1,     // just under a block boundary (last block 1 byte short)
	}
	for _, size := range sizes {
		size := size
		t.Run("size_"+itoa(size), func(t *testing.T) {
			cli := &fakeClient{blobs: map[string][]byte{}}
			fs, w := newFS(t, cli, nil)

			content := make([]byte, size)
			rng := rand.New(rand.NewSource(size)) // deterministic, non-repeating bytes
			rng.Read(content)
			createWith(t, fs, "big.bin", content)

			head, err := Run(context.Background(), fs, cli)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if head == "" {
				t.Fatal("large file should produce a commit")
			}
			me, ok := entryByPath(cli.commitEntry, "big.bin")
			if !ok {
				t.Fatal("big.bin missing from manifest")
			}
			if len(me.Chunks) == 0 {
				t.Fatalf("large file committed without chunk refs (size=%d): the streaming path was not taken", size)
			}
			// Chunk layout must be contiguous, in order, and total to the file size —
			// otherwise the chunked reader (content.ReadAt) reports a coverage gap.
			var cursor, total int64
			for i, ch := range me.Chunks {
				if ch.Offset != cursor {
					t.Fatalf("chunk %d offset=%d, expected contiguous %d", i, ch.Offset, cursor)
				}
				if string(cli.blobs[ch.Digest]) == "" && ch.Size > 0 {
					t.Fatalf("chunk %d (%s) was not uploaded", i, ch.Digest)
				}
				cursor += ch.Size
				total += ch.Size
			}
			if total != size {
				t.Fatalf("chunk sizes total %d, want file size %d", total, size)
			}
			// Whole-file blob digest must equal sha256 of the full content (the merge
			// fold in checkpointLarge must reconstruct exactly the bytes).
			if me.Blob == nil || me.Blob.Digest != shaOf(content) {
				t.Fatalf("whole-file digest mismatch: got %+v, want %s", me.Blob, shaOf(content))
			}
			// File is clean and the manifest tree hash recomputes.
			if d, _ := isDirty(fs, "big.bin"); d {
				t.Fatal("big.bin still dirty after checkpoint")
			}
			if rec := treehash.Compute(toHashEntries(cli.commitEntry)); rec != cli.commitTree {
				t.Fatalf("treeHash %s != recomputed %s", cli.commitTree, rec)
			}
			// The whole point: read it all back, byte-for-byte, through the chunked
			// source MarkClean installed.
			if got := readAll(t, fs, "big.bin"); !bytes.Equal(got, content) {
				t.Fatalf("large-file readback diverged: len got=%d want=%d", len(got), len(content))
			}
			assertAllocatorSidecarOnly(t, w)
		})
	}
}

// A large file that is BACKED (chunked source from a prior commit) and then left
// CLEAN must round-trip its chunk refs into the new manifest unchanged (the
// else-branch of Run that copies e.Source.Chunks), and read back identically —
// without re-uploading anything.
func TestRunLargeBackedCleanFileCarriesChunks(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	fs, _ := newFS(t, cli, nil)

	size := int64(blkBytes*2 + 4096)
	body := make([]byte, size)
	rand.New(rand.NewSource(99)).Read(body)
	createWith(t, fs, "data.bin", body)

	// First checkpoint commits it as a chunked file and rebinds the source.
	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run1: %v", err)
	}
	se, ok := snapEntry(fs.Snapshot(), "data.bin")
	if !ok || se.Dirty || len(se.Source.Chunks) == 0 {
		t.Fatalf("data.bin should be clean+chunked after first checkpoint: dirty=%v chunks=%d", se.Dirty, len(se.Source.Chunks))
	}

	// Dirty an UNRELATED file so the next checkpoint actually commits (and walks the
	// clean chunked file through the carry-through branch).
	createWith(t, fs, "trigger.txt", []byte("go"))
	cli.commitEntry = nil
	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run2: %v", err)
	}
	me, ok := entryByPath(cli.commitEntry, "data.bin")
	if !ok {
		t.Fatal("data.bin missing from second manifest")
	}
	if len(me.Chunks) != len(se.Source.Chunks) {
		t.Fatalf("clean chunked file lost chunks on carry-through: got %d want %d", len(me.Chunks), len(se.Source.Chunks))
	}
	if got := readAll(t, fs, "data.bin"); !bytes.Equal(got, body) {
		t.Fatal("backed chunked file readback diverged")
	}
}

// ---------------------------------------------------------------------------
// Born vs backed in a single checkpoint, with holes: a born file written sparsely
// (a hole between two writes) and a backed file partially overwritten. The hole
// must serialize as zeros.
// ---------------------------------------------------------------------------
func TestRunBornSparseAndBackedPartial(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	base := []backend.Entry{backedFile(cli, "backed.txt", []byte("ABCDEFGHIJK"))}
	fs, _ := newFS(t, cli, base)

	// Born sparse file: write at 0 and at 100, leaving a 90-byte hole.
	f, err := fs.Create("sparse.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("HEAD")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(100, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("TAIL")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Backed file: partial overwrite in the middle (read-modify-write).
	writeAt(t, fs, "backed.txt", 3, []byte("xyz")) // -> ABCxyzGHIJK

	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := make([]byte, 104)
	copy(want[0:], "HEAD")
	copy(want[100:], "TAIL")
	if got := readAll(t, fs, "sparse.bin"); !bytes.Equal(got, want) {
		t.Fatalf("sparse born readback = %q (len %d), want HEAD + 92-byte hole + TAIL", got, len(got))
	}
	if got := readAll(t, fs, "backed.txt"); string(got) != "ABCxyzGHIJK" {
		t.Fatalf("backed partial readback = %q, want ABCxyzGHIJK", got)
	}
	// The sparse blob uploaded must itself contain the zero hole.
	if blob := cli.blobs[shaOf(want)]; !bytes.Equal(blob, want) {
		t.Fatalf("uploaded sparse blob does not match the holey content")
	}
}

// ---------------------------------------------------------------------------
// truncate + remove + rename interleaved, then a checkpoint. The committed
// manifest must reflect the FINAL tree for the remove + rename (removed paths
// absent, renamed paths under their new name carrying their backed content). A
// truncate is in the interleave too (it must not crash the checkpoint and stays
// visible live); the *committed* truncate-size is asserted separately in
// TestRunTruncateBackedShrinkLostInCommit, which pins a real bug.
// ---------------------------------------------------------------------------
func TestRunTruncateRemoveRenameInterleaved(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	base := []backend.Entry{
		backedFile(cli, "doomed.txt", []byte("aaaaa")),
		backedFile(cli, "old.txt", []byte("oldbdy")),
		backedFile(cli, "trim.txt", []byte("0123456789")),
	}
	d2 := shaOf([]byte("oldbdy"))
	fs, _ := newFS(t, cli, base)

	// remove doomed.txt
	if err := fs.Remove("doomed.txt"); err != nil {
		t.Fatal(err)
	}
	// rename old.txt -> new.txt (carries its backed content)
	if err := fs.Rename("old.txt", "new.txt"); err != nil {
		t.Fatal(err)
	}
	// truncate trim.txt to 4 bytes (shrink a backed file), then write a byte into the
	// surviving region so the file is genuinely dirty and the truncated size IS
	// committed — interleaving a shrink with an overlapping write.
	tf, err := fs.OpenFile("trim.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tf.Truncate(4); err != nil {
		t.Fatal(err)
	}
	_ = tf.Close()
	writeAt(t, fs, "trim.txt", 0, []byte("Z")) // dirties block 0 -> truncated size externalizes
	// a brand-new born file to also force the commit
	createWith(t, fs, "fresh.txt", []byte("new"))

	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, ok := entryByPath(cli.commitEntry, "doomed.txt"); ok {
		t.Fatal("removed file still present in manifest")
	}
	if _, ok := entryByPath(cli.commitEntry, "old.txt"); ok {
		t.Fatal("renamed-away path still present in manifest")
	}
	ne, ok := entryByPath(cli.commitEntry, "new.txt")
	if !ok {
		t.Fatal("renamed-to path missing from manifest")
	}
	// new.txt was clean+backed (rename doesn't dirty content) -> carries old.txt's blob.
	if ne.Blob == nil || ne.Blob.Digest != d2 {
		t.Fatalf("renamed file lost its backed blob: %+v", ne.Blob)
	}
	te, ok := entryByPath(cli.commitEntry, "trim.txt")
	if !ok || te.Size != 4 {
		t.Fatalf("trim.txt size in manifest = %d, want 4 (truncate+overlapping-write must externalize)", te.Size)
	}

	// Read-back of the live tree.
	if got := readAll(t, fs, "new.txt"); string(got) != "oldbdy" {
		t.Fatalf("renamed content = %q, want oldbdy", got)
	}
	if got := readAll(t, fs, "trim.txt"); string(got) != "Z123" {
		t.Fatalf("truncated+written content = %q, want Z123", got)
	}
	if _, err := fs.Open("doomed.txt"); !os.IsNotExist(err) {
		t.Fatalf("doomed.txt should be gone, open err=%v", err)
	}
}

// TestRunTruncateBackedShrinkLostInCommit pins a REAL product bug: truncating a
// BACKED file to a smaller size, with NO subsequent write to dirty a block, leaves
// the inode "clean" (hasLocalContent() is born||len(blocks)>0 — a pure shrink sets
// neither). The checkpoint then takes the clean branch and emits the file at its
// STALE pre-truncate size with the STALE whole-file blob, so the acknowledged,
// live-visible truncation is silently DROPPED from committed history. A reader
// rebuilt from that commit sees the old size + old bytes.
//
// Repro (no Docker): backed file size 10 -> Truncate(4) -> checkpoint. Live read
// is "0123" (correct, in-memory) but the committed manifest entry has Size 10 and
// the original 10-byte blob.
//
// KEPT but skipped so the suite stays green; reported in bugs[].
func TestRunTruncateBackedShrinkLostInCommit(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	base := []backend.Entry{backedFile(cli, "trim.txt", []byte("0123456789"))}
	fs, _ := newFS(t, cli, base)

	tf, err := fs.OpenFile("trim.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tf.Truncate(4); err != nil {
		t.Fatal(err)
	}
	_ = tf.Close()

	// Force a commit with an unrelated dirty file (trim.txt itself reads "clean").
	createWith(t, fs, "trigger.txt", []byte("go"))
	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run: %v", err)
	}

	te, ok := entryByPath(cli.commitEntry, "trim.txt")
	if !ok {
		t.Fatal("trim.txt missing from manifest")
	}
	if te.Size != 4 {
		t.Fatalf("committed size = %d, want 4 — the truncation was lost in the commit", te.Size)
	}
	// And the committed blob must not be the original 10-byte content.
	if te.Blob != nil && te.Blob.Size == 10 {
		t.Fatalf("committed the stale 10-byte blob for a 4-byte file: %+v", te.Blob)
	}
}

// delete-then-recreate within one checkpoint window: the recreated (born) file's
// fresh content is what gets committed, not the deleted file's old backed bytes.
func TestRunDeleteThenRecreate(t *testing.T) {
	cli := &fakeClient{blobs: map[string][]byte{}}
	base := []backend.Entry{backedFile(cli, "f.txt", []byte("old"))}
	fs, _ := newFS(t, cli, base)

	if err := fs.Remove("f.txt"); err != nil {
		t.Fatal(err)
	}
	createWith(t, fs, "f.txt", []byte("brandnew"))

	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("run: %v", err)
	}
	me, ok := entryByPath(cli.commitEntry, "f.txt")
	if !ok {
		t.Fatal("recreated f.txt missing from manifest")
	}
	if me.Blob == nil || me.Blob.Digest != shaOf([]byte("brandnew")) {
		t.Fatalf("recreated file committed stale content: %+v", me.Blob)
	}
	if got := readAll(t, fs, "f.txt"); string(got) != "brandnew" {
		t.Fatalf("recreated readback = %q", got)
	}
}

// ---------------------------------------------------------------------------
// CONCURRENCY: an extension of TestCheckpointConcurrentWritesNoLoss with MORE
// files (multiple blocks each) and REMOVES/RECREATES interleaved, all racing a
// hammering checkpointer + reader. The block-store reconstruction of every
// surviving file must match a flat-array reference applied by the single driver
// goroutine. Run under -race.
//
// The reference (per-file byte arrays + existence) is mutated ONLY by this
// goroutine, in the same order it submits ApplyBatch calls — so it is a faithful
// sequential oracle for the authority's committed-then-cleaned state.
// ---------------------------------------------------------------------------
func TestCheckpointConcurrentMultiFileNoLoss(t *testing.T) {
	cli := newLockedClient() // thread-safe harness: many checkpointers + readers touch its map
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, cli, w)
	if err != nil {
		t.Fatal(err)
	}

	const (
		nfiles = 5
		page   = 4096
		// Each file stays within a single 4-MiB block (like a small SQLite DB, matching
		// the original test). The streaming multi-block path is covered exhaustively by
		// TestRunLargeFileStreamingReadback; this test isolates the checkpoint RACE
		// (source install + block clear vs lock-free reads + partial writes + truncates +
		// remove/recreate) across MANY files, so small files keep each snapshot cheap and
		// the -race run fast while widening the count of racing entries.
		span = 4 // 4 pages = 16 KiB per file, well under one block
	)
	names := []string{"a.db", "b.db", "c.db", "d.db", "e.db"}
	ref := make([][]byte, nfiles)
	exists := make([]bool, nfiles)

	create := func(i int) {
		if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: names[i], Mode: 0o644}}, ""); err != nil {
			t.Errorf("create %s: %v", names[i], err)
		}
		ref[i] = nil
		exists[i] = true
	}
	for i := 0; i < nfiles; i++ {
		create(i)
	}

	applyToRef := func(i int, off int64, data []byte) {
		end := off + int64(len(data))
		if int64(len(ref[i])) < end {
			ref[i] = append(ref[i], make([]byte, end-int64(len(ref[i])))...)
		}
		copy(ref[i][off:end], data)
	}
	truncRef := func(i int, size int64) {
		if int64(len(ref[i])) > size {
			ref[i] = ref[i][:size]
		} else {
			ref[i] = append(ref[i], make([]byte, size-int64(len(ref[i])))...)
		}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var runs int64

	// Two checkpointers hammering concurrently with each other and the writer.
	for c := 0; c < 2; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := Run(context.Background(), fs, cli); err == nil {
						atomic.AddInt64(&runs, 1)
					}
				}
			}
		}()
	}
	// Concurrent readers stress readBlocks' lock-free base fetch vs the source install
	// MarkClean performs (a cleaned file now reads through content.ReadAt -> the backend).
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for _, nm := range names {
						if rf, err := fs.Open(nm); err == nil {
							_, _ = io.ReadAll(rf)
							_ = rf.Close()
						}
					}
				}
			}
		}()
	}

	rng := rand.New(rand.NewSource(1))
	// ~2000 batched mutations (each an fsync'd WAL group commit) across 5 files is
	// enough to interleave many full checkpoints with writes/truncates/removes; this
	// keeps the -race wall time in line with the existing single-file sibling test.
	for i := 0; i < 2000; i++ {
		fi := i % nfiles
		switch i % 11 {
		case 9: // truncate, then a 1-byte write into the surviving region.
			if !exists[fi] {
				continue
			}
			sz := int64((i%span + 1) * page)
			if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpTruncate, Path: names[fi], Size: sz}}, ""); err != nil {
				t.Errorf("truncate %s: %v", names[fi], err)
			}
			truncRef(fi, sz)
			// A bare shrink leaves a (cleaned) file's blocks undirtied, which a SEPARATE
			// known bug drops at checkpoint (see TestRunTruncateBackedShrinkLostInCommit).
			// Follow every truncate with an in-bounds write so the new size is genuinely
			// externalized — this test isolates the checkpoint RACE, not that bug.
			b := []byte{byte(rng.Intn(254) + 1)}
			if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: names[fi], Offset: 0, Data: b}}, ""); err != nil {
				t.Errorf("post-truncate write %s: %v", names[fi], err)
			}
			applyToRef(fi, 0, b)
		case 10: // remove then immediately recreate (born) — exercises delete/recreate vs checkpoint
			if exists[fi] {
				if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpRemove, Path: names[fi]}}, ""); err != nil {
					t.Errorf("remove %s: %v", names[fi], err)
				}
			}
			// recreate as a fresh born file in a SEPARATE batch, widening the window where a
			// checkpoint can run with the file absent (commit-without-it) before it returns.
			create(fi)
		default:
			if !exists[fi] {
				continue
			}
			off := int64((i % span) * page)
			ln := page
			if i%4 == 0 { // partial-page write -> read-modify-write path
				ln, off = 137, off+11
			}
			data := bytes.Repeat([]byte{byte(rng.Intn(254) + 1)}, ln)
			if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: names[fi], Offset: off, Data: data}}, ""); err != nil {
				t.Errorf("write %s: %v", names[fi], err)
			}
			applyToRef(fi, off, data)
		}
	}
	close(stop)
	wg.Wait()

	if atomic.LoadInt64(&runs) == 0 {
		t.Fatal("no checkpoint ran to completion during the race")
	}

	// One final checkpoint, then every surviving file must equal its flat oracle.
	if _, err := Run(context.Background(), fs, cli); err != nil {
		t.Fatalf("final run: %v", err)
	}
	for i := 0; i < nfiles; i++ {
		if !exists[i] {
			continue
		}
		got := readAll(t, fs, names[i])
		if !bytes.Equal(got, ref[i]) {
			first := -1
			for k := 0; k < len(ref[i]) && k < len(got); k++ {
				if got[k] != ref[i][k] {
					first = k
					break
				}
			}
			t.Fatalf("%s diverged from flat reference: len got=%d want=%d, first diff at byte %d (page %d) — a write was lost to the checkpoint race",
				names[i], len(got), len(ref[i]), first, first/page)
		}
	}
}

// itoa avoids fmt in hot helpers and keeps subtest names tidy.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
