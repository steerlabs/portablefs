package pft2

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestEditorStagedCellBytesAccounting proves StagedCellBytes reports exactly
// the retained staged nonzero cell bytes the MaxStagedCellBytes limit
// enforces: coalesced overwrites never double-count, holes and shrinks
// release bytes, and the cap trips only when RETAINED bytes would exceed it.
// Checkpointing folds place commit boundaries on this reading.
func TestEditorStagedCellBytesAccounting(t *testing.T) {
	ctx := context.Background()
	editor, err := NewEditor(ctx, nil, nil, EditorLimits{MaxStagedCellBytes: 3 * CellBytes})
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.PutInode(ctx, Inode{Ino: RootIno, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	if err := editor.PutInode(ctx, Inode{Ino: 9, Kind: FileKindRegular, Mode: 0o644, Nlink: 1}); err != nil {
		t.Fatal(err)
	}
	if got := editor.StagedCellBytes(); got != 0 {
		t.Fatalf("metadata-only staging reports %d cell bytes", got)
	}

	cell := func(b byte) []byte { return bytes.Repeat([]byte{b}, CellBytes) }
	for i, b := range []byte{1, 2, 3} {
		if err := editor.WriteCell(ctx, 9, uint64(i)*CellBytes, cell(b)); err != nil {
			t.Fatal(err)
		}
	}
	if got := editor.StagedCellBytes(); got != 3*CellBytes {
		t.Fatalf("staged %d, want %d", got, 3*CellBytes)
	}
	// Coalesced overwrite of an already-staged cell retains no extra bytes.
	if err := editor.WriteCell(ctx, 9, 0, cell(7)); err != nil {
		t.Fatal(err)
	}
	if got := editor.StagedCellBytes(); got != 3*CellBytes {
		t.Fatalf("overwrite double-counted: %d", got)
	}
	// A fourth DISTINCT nonzero cell would exceed the cap: typed refusal,
	// accounting unchanged.
	if err := editor.WriteCell(ctx, 9, 3*CellBytes, cell(8)); !errors.Is(err, ErrTransactionLimit) {
		t.Fatalf("cap breach = %v, want ErrTransactionLimit", err)
	}
	if got := editor.StagedCellBytes(); got != 3*CellBytes {
		t.Fatalf("failed write changed accounting: %d", got)
	}
	// Zeroing a staged cell releases its bytes and frees cap headroom.
	if err := editor.ZeroCell(ctx, 9, CellBytes); err != nil {
		t.Fatal(err)
	}
	if got := editor.StagedCellBytes(); got != 2*CellBytes {
		t.Fatalf("hole did not release: %d", got)
	}
	if err := editor.WriteCell(ctx, 9, 3*CellBytes, cell(8)); err != nil {
		t.Fatal(err)
	}
	// Shrinking scrubs staged cells at/beyond the new size (grow first so
	// the truncate actually shrinks: writes alone never move the size).
	if err := editor.SetFileSize(ctx, 9, 4*CellBytes); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetFileSize(ctx, 9, CellBytes); err != nil {
		t.Fatal(err)
	}
	if got := editor.StagedCellBytes(); got != CellBytes {
		t.Fatalf("shrink retained %d, want %d", got, CellBytes)
	}
}
