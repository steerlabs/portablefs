package fsproto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// lstatHookFS wraps a workfs authority and runs a hook the instant before every Lstat, so a test can
// deterministically land a mutation in the miss window. Embedding *workfs.FS promotes all of billy's
// methods plus the Versioned/ParentVersioned/HandleStore surfaces the server type-asserts, so the
// wrapper is a drop-in authority.
type lstatHookFS struct {
	*workfs.FS
	hook func(name string)
}

func (f *lstatHookFS) Lstat(name string) (os.FileInfo, error) {
	if f.hook != nil {
		f.hook(name)
	}
	return f.FS.Lstat(name)
}

// TestGetattrMissSamplesParentVersionBeforeLstat pins C1: the parent-directory version stamped onto a
// cacheable ENOENT must be sampled BEFORE the Lstat, not after. A concurrent create that lands during
// the Lstat bumps the parent version; if the server samples the parent AFTER the Lstat it stamps the
// negative at the SAME version the create's own invalidation carries, which lets a client serve the
// negative forever (nothing ever advances the parent again). Sampling BEFORE stamps the pre-create
// version, so the create's invalidation strictly advances the client past the negative and evicts it.
func TestGetattrMissSamplesParentVersionBeforeLstat(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	hooked := &lstatHookFS{FS: inner}
	deleg := delegation.New()
	s := NewServer(hooked, inner, deleg)

	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755}); r.Status != OK {
		t.Fatalf("seed mkdir: status %d", r.Status)
	}

	// Parent version of "d" BEFORE any racing create.
	before, ok := inner.Version("d")
	if !ok {
		t.Fatal("d must have a version")
	}

	// The instant the miss's Lstat("d/x") runs, land a create of a DIFFERENT child "d/y". That bumps
	// d's version (parent stamping) while leaving "d/x" absent, reproducing "a create wins during the
	// miss window". Guard so the create's own internal Lstats don't recurse.
	var fired bool
	hooked.hook = func(name string) {
		if name == "d/x" && !fired {
			fired = true
			if r := s.dispatch(&Request{Op: OpCreate, Path: "d/y", Mode: 0o644}); r.Status != OK {
				t.Errorf("in-window create: status %d", r.Status)
			}
		}
	}

	miss := s.dispatch(&Request{Op: OpGetattr, Path: "d/x"})
	if miss.Status != ENOENT {
		t.Fatalf("d/x must miss: status %d", miss.Status)
	}
	if !fired {
		t.Fatal("hook never fired; the Lstat window was not exercised")
	}

	after, ok := inner.Version("d")
	if !ok {
		t.Fatal("d must still have a version")
	}
	if after <= before {
		t.Fatalf("precondition: in-window create must advance d's version (before=%d after=%d)", before, after)
	}

	// The wire carries parentVersion+1. Sample-before ⇒ before+1; the buggy sample-after would report
	// after+1 (the create's version), which is exactly the version the create's invalidation carries.
	if miss.ParentVersion != before+1 {
		t.Fatalf("negative stamped at post-create parent version: got ParentVersion=%d want %d (before=%d after=%d)",
			miss.ParentVersion, before+1, before, after)
	}
}
