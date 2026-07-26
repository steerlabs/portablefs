package fstransition

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// memStore is a minimal content-addressed sink+fetcher for commit/reopen
// round-trips (fstransition cannot use the historycut spool: import cycle).
type memStore struct {
	objects map[pft2.Ref][]byte
}

func newMemStore() *memStore { return &memStore{objects: map[pft2.Ref][]byte{}} }

func (s *memStore) put(ref pft2.Ref, data []byte) error {
	s.objects[ref] = append([]byte(nil), data...)
	return nil
}
func (s *memStore) PutNode(ref pft2.Ref, encoded []byte) error { return s.put(ref, encoded) }
func (s *memStore) PutPack(ref pft2.Ref, data []byte) error    { return s.put(ref, data) }
func (s *memStore) Fetch(_ context.Context, ref pft2.Ref) ([]byte, error) {
	data, ok := s.objects[ref]
	if !ok {
		return nil, fmt.Errorf("missing object %s", ref.Hex())
	}
	return data, nil
}

// TestEngineSetTxSurvivesCheckpointSwap drives ONE engine across a
// commit/reopen transaction boundary — exactly the checkpoint a long
// materializing fold performs — and proves the engine's transaction-
// independent state (orphans, xattrs, allocator watermarks) carries over
// while every tree read resolves through the NEW transaction.
func TestEngineSetTxSurvivesCheckpointSwap(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{Tx: editor})
	if err != nil {
		t.Fatal(err)
	}

	preSwapCell := bytes.Repeat([]byte{0xA5}, pft2.CellBytes)
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpCreate, Path: "keep", Mode: 0o644, Ino: 2, TsMs: 10})
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpWrite, Path: "keep", Data: preSwapCell, TsMs: 11})
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpSetxattr, Path: "keep", XattrName: "user.pre", Data: []byte("early"), TsMs: 12})
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpCreate, Path: "victim", Mode: 0o600, Ino: 3, TsMs: 13})
	if out := applyOne(t, engine, ctx, wal.Record{Op: wal.OpRemove, Path: "victim", TsMs: 14}); out.OrphanIno != 3 {
		t.Fatalf("victim did not park: %+v", out)
	}

	// Checkpoint: commit, reopen on the committed root + orphan index, and
	// rebind the SAME engine.
	res, err := editor.Commit(ctx, store, store)
	if err != nil {
		t.Fatal(err)
	}
	if res.OrphanIndex == nil {
		t.Fatal("parked orphan missing from the committed orphan index")
	}
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: store}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	editor2, err := pft2.NewEditor(ctx, reader, res.OrphanIndex, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	engine.SetTx(editor2)

	// Post-swap: path and ino resolution go through the NEW transaction;
	// the xattr map, orphan set, and watermarks survived the swap.
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpWrite, Path: "keep", Offset: pft2.CellBytes, Data: []byte("tail"), TsMs: 20})
	if out := applyOne(t, engine, ctx, wal.Record{Op: wal.OpRemovexattr, Path: "keep", XattrName: "user.pre", TsMs: 21}); out.Err != nil {
		t.Fatalf("pre-swap xattr lost across SetTx: %+v", out)
	}
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpSetxattr, Path: "keep", XattrName: "user.post", Data: []byte("late"), TsMs: 22})
	if out := applyOne(t, engine, ctx, wal.Record{Op: wal.OpReap, Ino: 3, TsMs: 23}); out.Err != nil || !out.Changed {
		t.Fatalf("pre-swap orphan not reapable across SetTx: %+v", out)
	}
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpCreate, Path: "late", Mode: 0o644, Ino: 4, TsMs: 24})
	applyOne(t, engine, ctx, wal.Record{Op: wal.OpRename, Path: "keep", NewPath: "moved", TsMs: 25})

	if engine.MaxInoSeen() != 4 {
		t.Fatalf("watermark = %d, want 4", engine.MaxInoSeen())
	}
	if got := engine.Orphans(); len(got) != 0 {
		t.Fatalf("orphan set = %v after reap", got)
	}
	rows := engine.Xattrs()
	if len(rows) != 1 || rows[0].Ino != 2 || rows[0].Name != "user.post" || string(rows[0].Value) != "late" {
		t.Fatalf("xattr rows = %+v", rows)
	}

	res2, err := editor2.Commit(ctx, store, store)
	if err != nil {
		t.Fatal(err)
	}
	if res2.OrphanIndex != nil {
		t.Fatal("reaped orphan survived into the second commit")
	}

	// The final tree merges both transactions' effects.
	reader2, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: store}, res2.Root)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := pft2.NewEditor(ctx, reader2, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := probe.GetDirEntry(ctx, pft2.RootIno, "keep"); err != nil || ok {
		t.Fatalf("rename source survived: ok=%v err=%v", ok, err)
	}
	moved, ok, err := probe.GetDirEntry(ctx, pft2.RootIno, "moved")
	if err != nil || !ok || moved.Ino != 2 {
		t.Fatalf("moved = %+v ok=%v err=%v", moved, ok, err)
	}
	meta, ok, err := probe.GetInode(ctx, 2)
	if err != nil || !ok || meta.Size != pft2.CellBytes+4 {
		t.Fatalf("meta = %+v ok=%v err=%v", meta, ok, err)
	}
	first, err := probe.ReadCell(ctx, 2, 0)
	if err != nil || !bytes.Equal(first, preSwapCell) {
		t.Fatalf("pre-swap content lost: err=%v", err)
	}
	second, err := probe.ReadCell(ctx, 2, pft2.CellBytes)
	if err != nil || string(second[:4]) != "tail" {
		t.Fatalf("post-swap content lost: err=%v", err)
	}
	if _, ok, err := probe.GetOrphanInode(ctx, 3); err != nil || ok {
		t.Fatalf("victim still parked: ok=%v err=%v", ok, err)
	}
}
