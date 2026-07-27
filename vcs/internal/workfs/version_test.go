package workfs

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func TestVersionIncrementsPerMutationAndGenerationStable(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	g := fs.Generation()
	if g == 0 {
		t.Fatal("generation must be a nonzero process nonce")
	}
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "a", Mode: 0o644}}, "M"); err != nil {
		t.Fatal(err)
	}
	v1, ok := fs.Version("a")
	if !ok || v1 == 0 {
		t.Fatal("a must have a nonzero version after create")
	}
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: "a", Data: []byte("hi")}}, "M"); err != nil {
		t.Fatal(err)
	}
	v2, _ := fs.Version("a")
	if v2 <= v1 {
		t.Fatalf("version must strictly increase per mutation: v1=%d v2=%d", v1, v2)
	}
	if fs.Generation() != g {
		t.Fatal("generation must be stable across mutations within one FS")
	}
}

func TestParentVersionBumpsOnNameMutation(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	before, ok := fs.ParentVersion("missing")
	if !ok {
		t.Fatal("root parent version should be available")
	}
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "a", Mode: 0o644}}, "M"); err != nil {
		t.Fatal(err)
	}
	after, ok := fs.ParentVersion("missing")
	if !ok {
		t.Fatal("root parent version should remain available")
	}
	if after <= before {
		t.Fatalf("root parent version did not bump on create: before=%d after=%d", before, after)
	}
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpMkdir, Path: "d", Mode: 0o755}}, "M"); err != nil {
		t.Fatal(err)
	}
	dBefore, ok := fs.ParentVersion("d/missing")
	if !ok {
		t.Fatal("directory parent version should be available")
	}
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "d/child", Mode: 0o644}}, "M"); err != nil {
		t.Fatal(err)
	}
	dAfter, _ := fs.ParentVersion("d/missing")
	if dAfter <= dBefore {
		t.Fatalf("directory parent version did not bump on child create: before=%d after=%d", dBefore, dAfter)
	}
}

// TestWriteAtReturnsItsOwnVersionUnderConcurrency is the regression for the concurrent-
// same-path-write hazard: WriteAt must return the version THIS write produced, never a
// sibling writer's. If two concurrent writers ever got the same (latest) version back, one
// would suppress the other's invalidation and serve stale data. Distinct versions prove each
// write got its own identity.
func TestWriteAtReturnsItsOwnVersionUnderConcurrency(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.WriteAt("p", 0, []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	const G = 16
	got := make([]uint64, G)
	var wg sync.WaitGroup
	for i := 0; i < G; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, v, werr := fs.WriteAt("p", 0, []byte{byte('a' + i)}, 0o644)
			if werr != nil {
				t.Errorf("write %d: %v", i, werr)
				return
			}
			got[i] = v
		}(i)
	}
	wg.Wait()
	seen := map[uint64]bool{}
	for i, v := range got {
		if v == 0 || seen[v] {
			t.Fatalf("write %d returned a zero/duplicate version %d — a concurrent writer's version leaked in", i, v)
		}
		seen[v] = true
	}
}

func TestPublishCarriesVersionOwnerGen(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	sub, unsub := fs.Subscribe()
	defer unsub()
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "a", Mode: 0o644}}, "writerM"); err != nil {
		t.Fatal(err)
	}
	select {
	case invs := <-sub:
		if len(invs) != 1 {
			t.Fatalf("create must publish exactly one invalidation, got %d: %+v", len(invs), invs)
		}
		inv := invs[0]
		if inv.Path != "a" || inv.Owner != "writerM" || inv.Gen != fs.Generation() || inv.Version == 0 {
			t.Fatalf("bad invalidation %+v (want path=a owner=writerM gen=%d version!=0)", inv, fs.Generation())
		}
	default:
		t.Fatal("expected one invalidation for the create")
	}
}
