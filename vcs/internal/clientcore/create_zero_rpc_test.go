package clientcore

import (
	"context"
	"fmt"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestDelegatedCreateStormZeroAuthorityRPCs is the acceptance test for the
// 4-creates/s incident: once a write-back session holds the subtree, the full
// kernel create shape — lookup (proving ENOENT), create, write, post-write
// getattr — for NEW names issues ZERO authority round trips. Only the eventual
// flush_batch talks to the authority.
func TestDelegatedCreateStormZeroAuthorityRPCs(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:  "wb-zero-rpc",
		WALDir: t.TempDir(),
	})

	// Acquiring the delegation (checkout) and creating the dirs may round-trip.
	if _, st := v.Mkdir(ctx, "w", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir w: %d", st)
	}
	if _, st := v.Mkdir(ctx, "w/pkg", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir w/pkg: %d", st)
	}

	rpc0 := opCount(v)
	const files = 200
	for i := 0; i < files; i++ {
		p := fmt.Sprintf("w/pkg/mod%04d.js", i)
		if _, st := v.Lookup(ctx, p); st != fsproto.ENOENT {
			t.Fatalf("pre-create lookup %s: %d, want ENOENT", p, st)
		}
		a, st := v.Create(ctx, p, 0o644)
		if st != fsproto.OK {
			t.Fatalf("create %s: %d", p, st)
		}
		n := NewNodeState(InoOf(p), a.Ino != 0)
		if _, st := v.Write(ctx, p, n, 0, []byte("payload")); st != fsproto.OK {
			t.Fatalf("write %s: %d", p, st)
		}
		if _, st := v.Getattr(ctx, p, n); st != fsproto.OK {
			t.Fatalf("getattr %s: %d", p, st)
		}
	}
	if got := opCount(v) - rpc0; got != 0 {
		t.Fatalf("delegated create storm issued %d authority RPCs, want 0 (beyond the eventual flush_batch)", got)
	}

	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// An independent write-through observer proves the storm actually landed.
	observer := dialCore(t, addr, Options{Owner: "observer"})
	data, st := observer.Read(ctx, "w/pkg/mod0199.js", NewNodeState(0, false), 0, 16)
	if st != fsproto.OK || string(data) != "payload" {
		t.Fatalf("observer read after flush: %q st=%d", data, st)
	}
}

// TestDelegatedLookupSeedsListingOnce pins the seed-on-miss behavior for a
// PRE-EXISTING directory: the first undecidable lookup under a held dir costs
// one readdir, after which lookups (hits, proven misses) and creates of new
// names are local; adopting an existing file costs exactly its content fetch.
func TestDelegatedLookupSeedsListingOnce(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	seed := dialCore(t, addr, Options{Owner: "seeder"})
	if _, st := seed.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("seed mkdir: %d", st)
	}
	a, st := seed.Create(ctx, "d/existing", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := seed.Write(ctx, "d/existing", n, 0, []byte("keep")); st != fsproto.OK {
		t.Fatalf("seed write: %d", st)
	}
	// The peer goes away entirely (a pre-existing directory populated by
	// someone no longer mounted): its delegation drains + releases, so "d"
	// is free and uncontended for the mount below.
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	v := dialCore(t, addr, Options{
		Owner:  "wb-seed-once",
		WALDir: t.TempDir(),
	})
	// First write acquires the delegation for d (checkout + probe RPCs allowed).
	if _, st := v.Create(ctx, "d/trigger", 0o644); st != fsproto.OK {
		t.Fatalf("trigger create: %d", st)
	}
	// First undecidable lookup under the held dir seeds via one readdir.
	if _, st := v.Lookup(ctx, "d/nope"); st != fsproto.ENOENT {
		t.Fatalf("lookup d/nope: %d, want ENOENT", st)
	}

	rpc0 := opCount(v)
	if _, st := v.Lookup(ctx, "d/nope2"); st != fsproto.ENOENT {
		t.Fatalf("lookup d/nope2: %d, want ENOENT", st)
	}
	if a, st := v.Lookup(ctx, "d/existing"); st != fsproto.OK || a.Kind != "file" {
		t.Fatalf("lookup d/existing: %+v st=%d", a, st)
	}
	if _, st := v.Create(ctx, "d/newfile", 0o644); st != fsproto.OK {
		t.Fatalf("create d/newfile: %d", st)
	}
	if got := opCount(v) - rpc0; got != 0 {
		t.Fatalf("post-seed lookups/creates issued %d RPCs, want 0", got)
	}

	// Adopt (O_CREAT on the existing file) must preserve its content.
	if _, st := v.Create(ctx, "d/existing", 0o644); st != fsproto.OK {
		t.Fatalf("adopt create: %d", st)
	}
	data, st := v.Read(ctx, "d/existing", NewNodeState(InoOf("d/existing"), false), 0, 16)
	if st != fsproto.OK || string(data) != "keep" {
		t.Fatalf("adopted content = %q st=%d, want keep", data, st)
	}
}
