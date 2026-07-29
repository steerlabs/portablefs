package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// waitLookup polls until lookup of path on v returns want (OK/ENOENT) or the
// deadline passes, returning the last status. Push invalidation is async, so
// coherence assertions poll instead of sleeping a fixed guess.
func waitLookup(t *testing.T, v *Volume, path string, want Status) Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var st Status
	for {
		_, st = v.Lookup(context.Background(), path)
		if st == want || time.Now().After(deadline) {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNegativeCacheSubdirTwoClientCoherence is the two-client coherence proof
// for the version-gated negative cache in a SUBDIRECTORY (the npm probe shape:
// missing children of existing dirs). Client A caches ENOENT for dir/pkg/x;
// client B then creates that exact file; A must observe it via B's push
// invalidation — the create bumps the parent directory's version, which is the
// gate the stored negative is ordered against.
func TestNegativeCacheSubdirTwoClientCoherence(t *testing.T) {
	addr := serveCore(t)
	a := dialCore(t, addr, Options{NegativeCache: true, Owner: "client-a"})
	b := dialCore(t, addr, Options{Owner: "client-b"})
	watchInvalidationsForTest(t, a) // A must receive B's invalidations

	ctx := context.Background()
	if _, st := b.Mkdir(ctx, "dir", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir dir: %d", st)
	}
	if _, st := b.Mkdir(ctx, "dir/pkg", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir dir/pkg: %d", st)
	}
	// A must observe the dirs before probing, else the negative isn't cacheable.
	if st := waitLookup(t, a, "dir/pkg", fsproto.OK); st != fsproto.OK {
		t.Fatalf("A never saw dir/pkg: %d", st)
	}

	// A probes the missing name repeatedly: first probe fills the negative,
	// repeats are served from cache (no authority round-trips).
	if _, st := a.Lookup(ctx, "dir/pkg/x.json"); st != fsproto.ENOENT {
		t.Fatalf("initial probe: %d, want ENOENT", st)
	}
	cached := opCount(a)
	for i := 0; i < 5; i++ {
		if _, st := a.Lookup(ctx, "dir/pkg/x.json"); st != fsproto.ENOENT {
			t.Fatalf("cached probe %d: %d, want ENOENT", i, st)
		}
	}
	if got := opCount(a) - cached; got != 0 {
		t.Fatalf("cached ENOENT probes cost %d authority ops, want 0", got)
	}

	// B creates the exact probed name. A's cached negative MUST be evicted by
	// the push invalidation (parent version advances); A then sees the file.
	if _, st := b.Create(ctx, "dir/pkg/x.json", 0o644); st != fsproto.OK {
		t.Fatalf("B create: %d", st)
	}
	if st := waitLookup(t, a, "dir/pkg/x.json", fsproto.OK); st != fsproto.OK {
		t.Fatalf("A still sees ENOENT for dir/pkg/x.json after B's create: %d (stale negative outlived the invalidation)", st)
	}
}

// TestNegativeCacheSiblingCreateInvalidatesSubdirNegative: a create of a
// SIBLING name must also invalidate a cached negative in the same directory
// (the parent version gate is per-directory, not per-name). The re-probe may
// round-trip again — correctness first — and must still be ENOENT.
func TestNegativeCacheSiblingCreateInvalidatesSubdirNegative(t *testing.T) {
	addr := serveCore(t)
	a := dialCore(t, addr, Options{NegativeCache: true, Owner: "client-a"})
	b := dialCore(t, addr, Options{Owner: "client-b"})
	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()
	if _, st := b.Mkdir(ctx, "sib", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if st := waitLookup(t, a, "sib", fsproto.OK); st != fsproto.OK {
		t.Fatalf("A never saw sib: %d", st)
	}
	if _, st := a.Lookup(ctx, "sib/missing.txt"); st != fsproto.ENOENT {
		t.Fatalf("probe: %d", st)
	}

	if _, st := b.Create(ctx, "sib/other.txt", 0o644); st != fsproto.OK {
		t.Fatalf("B create sibling: %d", st)
	}
	// A must see the sibling (fresh readdir-visible name)...
	if st := waitLookup(t, a, "sib/other.txt", fsproto.OK); st != fsproto.OK {
		t.Fatalf("A never saw sib/other.txt: %d", st)
	}
	// ...and the still-missing name stays a correct ENOENT (never a false hit,
	// never an error) after the parent version advanced past the stored negative.
	if _, st := a.Lookup(ctx, "sib/missing.txt"); st != fsproto.ENOENT {
		t.Fatalf("sib/missing.txt after sibling create: %d, want ENOENT", st)
	}
}
