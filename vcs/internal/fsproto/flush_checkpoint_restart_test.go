package fsproto

// This file proves the highest-risk corruption edge of the write-back flush
// protocol across checkpoint + restart: a resent flush batch must NEVER
// double-apply after the authority comes back.
//
// On an exact-session authority the per-session flush watermark is a
// REPLICATED CONTROL record (ctlKindWatermark) that rides the same WAL as the
// mutations it covers, and checkpointing preserves control history across
// compaction (the control snapshot appended by CompactWAL). So the invariant
// has two halves, both covered here:
//
//  1. WAL-preserving restart (crash/upgrade/promotion — the WAL is the
//     durability layer and survives): the watermark is rebuilt from control
//     records/snapshots on replay, and a resent batch dedupes exactly.
//  2. Manifest-only rebuild (catastrophic rebuild from the backend: fresh WAL,
//     no control state): the watermark is GONE. Under the fail-closed posture
//     (VCS_REQUIRE_EXACT_SESSIONS=1) a flush without a live authenticated
//     mount session is fenced ESTALE and applies NOTHING — double-apply is
//     impossible; the mount keeps its records and an operator resolves the
//     rebuild. (The permissive default trades this fence for compatibility;
//     see docs/failure-modes.md.)
//
// The legacy hidden-file watermark (.portablefs-<id>) is exercised separately:
// an exact authority MIGRATES off it (the first flush dedupes against the
// file, then retires it in the same atomic batch as the control watermark).

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/checkpoint"
	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// ckptClient is the one object that is BOTH the workfs blob reader (Blob) and the
// checkpoint committer (PutBlob/Version/Commit), sharing a single blob store — the
// exact production shape, and a mirror of checkpoint_test.go's fakeClient. Because
// the blob map is shared, a blob uploaded at checkpoint is readable by the freshly
// reloaded authority FS afterward.
type ckptClient struct {
	blobs   map[string][]byte
	entries []backend.ManifestEntry // the last committed manifest (captured)
}

func newCkptClient() *ckptClient { return &ckptClient{blobs: map[string][]byte{}} }

func (c *ckptClient) Blob(_ context.Context, d string) ([]byte, error) {
	v, ok := c.blobs[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return append([]byte(nil), v...), nil
}
func (c *ckptClient) PutBlob(_ context.Context, digest string, data []byte) error {
	c.blobs[digest] = append([]byte(nil), data...)
	return nil
}
func (c *ckptClient) Version() string { return "portablefs-v1" }
func (c *ckptClient) Commit(_ context.Context, _ string, entries []backend.ManifestEntry, _, _ int64) (string, error) {
	// Capture the committed manifest verbatim; this is the durable state a
	// catastrophic rebuild would reload from the backend.
	c.entries = append([]backend.ManifestEntry(nil), entries...)
	return "cmt_new", nil
}

// manifestToEntries flattens committed backend.ManifestEntry records into the
// backend.Entry shape workfs.New rebuilds its base tree from (mirrors the
// canonical wire→Entry mapping the real authority uses on startup).
func manifestToEntries(es []backend.ManifestEntry) []backend.Entry {
	out := make([]backend.Entry, 0, len(es))
	for _, e := range es {
		ent := backend.Entry{
			Path: e.Path, Kind: e.Kind, Mode: e.Mode, Size: e.Size,
			MtimeMs: e.MtimeMs, CtimeMs: e.CtimeMs, AtimeMs: e.AtimeMs,
			Executable: e.Executable, LinkTarget: e.LinkTarget,
			UID: e.UID, GID: e.GID, Ino: e.Ino,
		}
		if e.Blob != nil {
			ent.BlobDigest = e.Blob.Digest
			ent.BlobSize = e.Blob.Size
			ent.BlobCompression = e.Blob.Compression
			ent.BlobPacked = e.Blob.Packed
		}
		for _, ch := range e.Chunks {
			ent.Chunks = append(ent.Chunks, backend.Chunk{Digest: ch.Digest, Size: ch.Size, Offset: ch.Offset})
		}
		out = append(out, ent)
	}
	return out
}

// manifestEntry returns the committed manifest entry for path, and whether it exists.
func manifestEntry(es []backend.ManifestEntry, path string) (backend.ManifestEntry, bool) {
	for _, e := range es {
		if e.Path == path {
			return e, true
		}
	}
	return backend.ManifestEntry{}, false
}

// TestFlushWatermarkSurvivesCheckpointAndWALRestart: the watermark must ride
// the control WAL across checkpoint + WAL-preserving restart, and a resend of
// the pre-checkpoint batch must dedupe (no revert), even though the manifest
// no longer carries any hidden watermark file.
func TestFlushWatermarkSurvivesCheckpointAndWALRestart(t *testing.T) {
	const session = "sess1"
	cli := newCkptClient()
	walPath := filepath.Join(t.TempDir(), "wal1.log")

	w1, err := wal.Open(walPath)
	if err != nil {
		t.Fatalf("open wal1: %v", err)
	}
	fs1, err := workfs.New(nil, cli, w1)
	if err != nil {
		t.Fatalf("new workfs1: %v", err)
	}
	deleg := delegation.New()
	s1 := NewServer(fs1, fs1, deleg)

	if r := s1.dispatch(&Request{Op: OpMkdir, Path: "work", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir work: status %d", r.Status)
	}
	if granted, _ := deleg.Checkout("work", "M"); !granted {
		t.Fatal("checkout work by M should grant")
	}

	batch1 := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "work/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "work/a", Data: []byte("hello")},
	}
	if r := s1.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: batch1}); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("flush batch1: status=%d appliedThrough=%d, want OK/1", r.Status, r.AppliedThrough)
	}
	// Discriminator write BEFORE the checkpoint: advances file -> "world" and
	// watermark -> 3, so a later double-apply of batch1 is observable as a REVERT.
	batch2 := []wal.Record{{Seq: 2, Op: wal.OpWrite, Path: "work/a", Data: []byte("world")}}
	if r := s1.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: batch2}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("flush batch2: status=%d appliedThrough=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s1, "work/a"); got != "world" {
		t.Fatalf("after batch2 work/a=%q, want world", got)
	}

	// The exact authority records the watermark as REPLICATED CONTROL STATE.
	if epoch, through, ok := fs1.FlushWatermark(session); !ok || epoch != 0 || through != 3 {
		t.Fatalf("control watermark = (%d,%d,%v), want (0,3,true)", epoch, through, ok)
	}
	// And the legacy hidden file must NOT exist (nothing to leak into manifests).
	if r := s1.dispatch(&Request{Op: OpGetattr, Path: watermarkPath(session)}); r.Status != ENOENT {
		t.Fatalf("hidden watermark file should not exist on an exact authority: status=%d", r.Status)
	}

	// --- CHECKPOINT: commits the manifest; control history survives compaction
	// via the appended control snapshot (that is the property under test).
	if _, err := checkpoint.Run(context.Background(), fs1, cli); err != nil {
		t.Fatalf("checkpoint.Run: %v", err)
	}
	if cli.entries == nil {
		t.Fatal("checkpoint did not commit a manifest")
	}
	if _, ok := manifestEntry(cli.entries, watermarkPath(session)); ok {
		t.Fatalf("manifest must NOT carry a hidden watermark file on an exact authority")
	}

	// --- WAL-PRESERVING RESTART: reopen the SAME WAL; workfs.New replays the
	// control records (or their snapshot) and rebuilds the watermark.
	if err := w1.Close(); err != nil {
		t.Fatalf("close wal1: %v", err)
	}
	w2, err := wal.Open(walPath)
	if err != nil {
		t.Fatalf("reopen wal: %v", err)
	}
	fs2, err := workfs.New(manifestToEntries(cli.entries), cli, w2)
	if err != nil {
		t.Fatalf("rebuild workfs from manifest+wal: %v", err)
	}
	s2 := NewServer(fs2, fs2, delegation.New())

	if got := readFile(t, s2, "work/a"); got != "world" {
		t.Fatalf("restarted work/a=%q, want world", got)
	}
	if epoch, through, ok := fs2.FlushWatermark(session); !ok || epoch != 0 || through != 3 {
		t.Fatalf("restarted control watermark = (%d,%d,%v), want (0,3,true) — "+
			"the watermark did NOT survive the checkpointed WAL", epoch, through, ok)
	}

	// --- RESEND batch1 (Seqs 0,1 < watermark 3): must dedupe, never revert.
	r := s2.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: batch1})
	if r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("resend after restart: status=%d appliedThrough=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s2, "work/a"); got != "world" {
		t.Fatalf("CORRUPTION: resend after checkpoint+restart reverted work/a to %q, want world", got)
	}
}

// TestManifestOnlyRebuildFailsClosedForFlush: rebuilding an authority from
// ONLY the committed manifest (fresh WAL — catastrophic recovery) loses the
// replicated control state, including flush watermarks. Under the fail-closed
// posture a flush arriving without a live authenticated mount session is
// fenced ESTALE and applies NOTHING — never double-applied against the reset
// watermark. (The mount keeps its records; an operator resolves the rebuild.)
func TestManifestOnlyRebuildFailsClosedForFlush(t *testing.T) {
	const session = "sess1"
	cli := newCkptClient()

	w1, err := wal.Open(filepath.Join(t.TempDir(), "wal1.log"))
	if err != nil {
		t.Fatalf("open wal1: %v", err)
	}
	fs1, err := workfs.New(nil, cli, w1)
	if err != nil {
		t.Fatalf("new workfs1: %v", err)
	}
	deleg := delegation.New()
	s1 := NewServer(fs1, fs1, deleg)

	if r := s1.dispatch(&Request{Op: OpMkdir, Path: "work", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir work: status %d", r.Status)
	}
	if granted, _ := deleg.Checkout("work", "M"); !granted {
		t.Fatal("checkout should grant")
	}
	batch1 := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "work/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "work/a", Data: []byte("hello")},
	}
	if r := s1.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: batch1}); r.Status != OK {
		t.Fatalf("flush batch1: status=%d", r.Status)
	}
	if r := s1.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: []wal.Record{
		{Seq: 2, Op: wal.OpWrite, Path: "work/a", Data: []byte("world")},
	}}); r.Status != OK {
		t.Fatalf("flush batch2: status=%d", r.Status)
	}
	if _, err := checkpoint.Run(context.Background(), fs1, cli); err != nil {
		t.Fatalf("checkpoint.Run: %v", err)
	}

	// Manifest-only rebuild: FRESH empty WAL, no control state, no sessions.
	wFresh, err := wal.Open(filepath.Join(t.TempDir(), "wal-fresh.log"))
	if err != nil {
		t.Fatalf("open fresh wal: %v", err)
	}
	fsFresh, err := workfs.New(manifestToEntries(cli.entries), cli, wFresh)
	if err != nil {
		t.Fatalf("rebuild from manifest only: %v", err)
	}
	sFresh := NewServer(fsFresh, fsFresh, delegation.New())
	sFresh.SetRequireExactSessions(true) // fail-closed posture (VCS_REQUIRE_EXACT_SESSIONS=1)

	if got := readFile(t, sFresh, "work/a"); got != "world" {
		t.Fatalf("rebuilt work/a=%q, want world", got)
	}
	if _, _, ok := fsFresh.FlushWatermark(session); ok {
		t.Fatal("manifest-only rebuild unexpectedly recovered a control watermark")
	}

	// The straggler resend arrives with NO attached mount session (a fresh
	// authority knows no sessions): it must be fenced, not double-applied.
	r := sFresh.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: batch1})
	if r.Status != ESTALE {
		t.Fatalf("flush into a manifest-only rebuild: status=%d, want ESTALE (fail closed)", r.Status)
	}
	if got := readFile(t, sFresh, "work/a"); got != "world" {
		t.Fatalf("fenced flush must apply NOTHING: work/a=%q, want world", got)
	}
}

// TestLegacyFileWatermarkMigration: an exact authority inheriting a legacy
// hidden-file watermark (written by an old authority) must dedupe against it
// on the first flush, then retire the file and record the control watermark in
// the SAME atomic batch. Subsequent flushes never consult the file again.
func TestLegacyFileWatermarkMigration(t *testing.T) {
	const session = "sessL"
	wm := watermarkPath(session)
	cli := newCkptClient()

	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	fs, err := workfs.New(nil, cli, w)
	if err != nil {
		t.Fatalf("new workfs: %v", err)
	}
	deleg := delegation.New()
	s := NewServer(fs, fs, deleg)

	if r := s.dispatch(&Request{Op: OpMkdir, Path: "work", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir: status %d", r.Status)
	}
	if granted, _ := deleg.Checkout("work", "M"); !granted {
		t.Fatal("checkout should grant")
	}
	// Seed the file "work/a" and a LEGACY watermark file claiming through=3
	// (epoch 0), exactly as an old authority would have left them.
	if err := fs.MutateAs(wal.Record{Op: wal.OpCreate, Path: "work/a", Mode: 0o644}, ""); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	if _, _, err := fs.WriteAtAs("work/a", 0, []byte("world"), 0o644, ""); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	var wmBytes [16]byte
	binary.BigEndian.PutUint64(wmBytes[0:8], 0)
	binary.BigEndian.PutUint64(wmBytes[8:16], 3)
	if err := fs.MutateAs(wal.Record{Op: wal.OpCreate, Path: wm, Mode: 0o600}, ""); err != nil {
		t.Fatalf("seed wm create: %v", err)
	}
	if _, _, err := fs.WriteAtAs(wm, 0, wmBytes[:], 0o600, ""); err != nil {
		t.Fatalf("seed wm write: %v", err)
	}

	// Resend of already-covered records (Seqs 0,1 < 3): dedupes off the FILE.
	batch1 := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "work/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "work/a", Data: []byte("hello")},
	}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: batch1}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("resend against legacy file: status=%d through=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "work/a"); got != "world" {
		t.Fatalf("resend reverted work/a to %q, want world", got)
	}

	// A NEW record (Seq 3): applies, records the control watermark, and
	// retires the legacy file — all in one atomic batch.
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: session, Owner: "M", Records: []wal.Record{
		{Seq: 3, Op: wal.OpWrite, Path: "work/a", Data: []byte("again")},
	}}); r.Status != OK || r.AppliedThrough != 3 {
		t.Fatalf("migrating flush: status=%d through=%d, want OK/3", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "work/a"); got != "again" {
		t.Fatalf("migrating flush content=%q, want again", got)
	}
	if epoch, through, ok := fs.FlushWatermark(session); !ok || epoch != 0 || through != 4 {
		t.Fatalf("control watermark after migration = (%d,%d,%v), want (0,4,true)", epoch, through, ok)
	}
	if _, err := fs.Lstat(wm); err == nil {
		t.Fatalf("legacy watermark file must be removed by the migrating flush")
	}
}
