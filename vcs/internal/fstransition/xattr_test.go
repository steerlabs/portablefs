package fstransition

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

func newXattrEngine(t *testing.T) (*Engine, context.Context) {
	t.Helper()
	ctx := context.Background()
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	next := uint64(2)
	engine, err := New(Config{Tx: editor, Alloc: func() (uint64, error) {
		ino := next
		next++
		return ino, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return engine, ctx
}

func applyOne(t *testing.T, e *Engine, ctx context.Context, r wal.Record) Outcome {
	t.Helper()
	outs, err := e.Apply(ctx, r)
	if err != nil {
		t.Fatalf("apply %v %q: %v", r.Op, r.Path, err)
	}
	if len(outs) != 1 {
		t.Fatalf("apply %v: %d outcomes", r.Op, len(outs))
	}
	return outs[0]
}

func engineXattrMap(e *Engine, ino uint64) map[string]string {
	out := map[string]string{}
	for _, row := range e.Xattrs() {
		if row.Ino == ino {
			out[row.Name] = string(row.Value)
		}
	}
	return out
}

// TestEngineXattrTransitions covers the pure engine semantics: set (create,
// overwrite, empty value), remove, remove-missing (ENODATA), the per-inode
// total bound (ENOSPC), ino-vs-path addressing, and reap cleanup.
func TestEngineXattrTransitions(t *testing.T) {
	e, ctx := newXattrEngine(t)
	applyOne(t, e, ctx, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644, Ino: 2})

	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("v1")}); out.Err != nil || !out.Changed {
		t.Fatalf("set: %+v", out)
	}
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("v2")}); out.Err != nil {
		t.Fatalf("overwrite: %+v", out)
	}
	// Ino-addressed set (a rename-proof handle op), plus an empty value.
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Ino: 2, XattrName: "user.empty"}); out.Err != nil {
		t.Fatalf("ino-addressed set: %+v", out)
	}
	if got := engineXattrMap(e, 2); got["user.a"] != "v2" || len(got) != 2 {
		t.Fatalf("state = %v", got)
	}

	// Remove-missing is a deterministic ENODATA outcome, not an engine fault.
	out := applyOne(t, e, ctx, wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.gone"})
	if !errors.Is(out.Err, syscall.ENODATA) || out.Changed {
		t.Fatalf("remove-missing: %+v", out)
	}
	if !IsDeterministicOutcome(out.Err) || !BenignEnvlessOutcome(wal.OpRemovexattr, 0, out.Err) {
		t.Fatalf("ENODATA must classify deterministic+benign")
	}
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.a"}); out.Err != nil || !out.Changed {
		t.Fatalf("remove: %+v", out)
	}

	// Missing target: ENOENT.
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "missing", XattrName: "user.a", Data: []byte("v")}); !errors.Is(out.Err, ErrNotExist) {
		t.Fatalf("set on missing: %+v", out)
	}

	// Per-inode total bound: two 64 KiB values exceed the 128 KiB budget
	// once names are counted; the second set is a deterministic ENOSPC.
	full := bytes.Repeat([]byte{0x01}, wal.MaxXattrValueBytes)
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.fill1", Data: full}); out.Err != nil {
		t.Fatalf("fill1: %+v", out)
	}
	out = applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.fill2", Data: full})
	if !errors.Is(out.Err, syscall.ENOSPC) {
		t.Fatalf("total bound: %+v", out)
	}
	if !IsDeterministicOutcome(out.Err) || !BenignEnvlessOutcome(wal.OpSetxattr, 0, out.Err) {
		t.Fatalf("ENOSPC must classify deterministic+benign")
	}
	// Overwriting the SAME large name stays within budget (replacement, not sum).
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.fill1", Data: full[:16]}); out.Err != nil {
		t.Fatalf("overwrite large: %+v", out)
	}

	// Orphan-parked inodes keep xattrs (ino addressing); reap destroys them.
	applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.keep", Data: []byte("k")})
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpRemove, Path: "f"}); out.Err != nil || out.OrphanIno != 2 {
		t.Fatalf("remove parks: %+v", out)
	}
	if out := applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Ino: 2, XattrName: "user.parked", Data: []byte("p")}); out.Err != nil {
		t.Fatalf("set on parked orphan: %+v", out)
	}
	if got := engineXattrMap(e, 2); got["user.keep"] != "k" || got["user.parked"] != "p" {
		t.Fatalf("parked state = %v", got)
	}
	applyOne(t, e, ctx, wal.Record{Op: wal.OpReap, Ino: 2})
	if got := engineXattrMap(e, 2); len(got) != 0 {
		t.Fatalf("reaped inode kept xattrs: %v", got)
	}
}

// TestEngineXattrSeedAndRows: base-anchored rows seed the engine, fold with
// journal records, and come back deterministically sorted from Xattrs().
func TestEngineXattrSeedAndRows(t *testing.T) {
	e, ctx := newXattrEngine(t)
	applyOne(t, e, ctx, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644, Ino: 2})
	e.SeedXattr(2, "user.z", []byte("base-z"))
	e.SeedXattr(2, "user.a", []byte("base-a"))
	applyOne(t, e, ctx, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.m", Data: []byte("live")})
	applyOne(t, e, ctx, wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.z"})

	rows := e.Xattrs()
	var names []string
	for _, r := range rows {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "user.a,user.m" {
		t.Fatalf("rows = %v", names)
	}
	if string(rows[0].Value) != "base-a" || string(rows[1].Value) != "live" {
		t.Fatalf("row values = %q, %q", rows[0].Value, rows[1].Value)
	}
}
