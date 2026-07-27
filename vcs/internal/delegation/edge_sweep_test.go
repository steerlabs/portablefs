package delegation

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustCheckout asserts a Checkout is granted.
func mustCheckout(t *testing.T, m *Manager, p, owner string) {
	t.Helper()
	if ok, by := m.Checkout(p, owner); !ok {
		t.Fatalf("Checkout(%q, %q) should grant, got denied (held by %q)", p, owner, by)
	}
}

// mustDeny asserts a Checkout is denied and returns the reported holder.
func mustDeny(t *testing.T, m *Manager, p, owner, wantHolder string) {
	t.Helper()
	ok, by := m.Checkout(p, owner)
	if ok {
		t.Fatalf("Checkout(%q, %q) should be DENIED, but it was granted", p, owner)
	}
	if by != wantHolder {
		t.Fatalf("Checkout(%q, %q) denied by %q, want holder %q", p, owner, by, wantHolder)
	}
}

// canonical mirrors the package-private clean() so tests can assert that two
// spellings of a path land in the same delegation slot via the public API.
func canonical(p string) string { return strings.Trim(path.Clean("/"+p), "/") }

// ---------------------------------------------------------------------------
// Basic lifecycle: Checkout then Checkin, re-checkout after Checkin.
// ---------------------------------------------------------------------------

func TestLifecycle_CheckoutThenCheckin(t *testing.T) {
	m := New()

	mustCheckout(t, m, "svc/api", "A")

	// While held by A, B is denied and learns A holds it.
	mustDeny(t, m, "svc/api", "B", "A")

	// A checks in cleanly.
	if !m.Checkin("svc/api", "A") {
		t.Fatal("A Checkin should succeed for a path it holds")
	}

	// HeldBy now reports no owner.
	if o, at := m.HeldBy("svc/api"); o != "" || at != "" {
		t.Fatalf("after checkin HeldBy = (%q,%q), want empty", o, at)
	}

	// Re-checkout after checkin succeeds — for the original owner...
	mustCheckout(t, m, "svc/api", "A")
	if !m.Checkin("svc/api", "A") {
		t.Fatal("second A Checkin should succeed")
	}
	// ...and for a different owner once it is free.
	mustCheckout(t, m, "svc/api", "B")
	if o, _ := m.HeldBy("svc/api"); o != "B" {
		t.Fatalf("HeldBy = %q after B re-checkout, want B", o)
	}
}

// Idempotent repeat: the same owner re-checking out the same path many times
// stays granted and does not create duplicate state that blocks its own checkin.
func TestSameOwnerReCheckoutIsIdempotent(t *testing.T) {
	m := New()
	for i := 0; i < 100; i++ {
		mustCheckout(t, m, "a/b/c", "owner-1")
	}
	// A different owner is still locked out.
	mustDeny(t, m, "a/b/c", "owner-2", "owner-1")
	// One checkin fully releases it (no shadow copies left behind).
	if !m.Checkin("a/b/c", "owner-1") {
		t.Fatal("Checkin should succeed after repeated re-checkout")
	}
	if o, _ := m.HeldBy("a/b/c"); o != "" {
		t.Fatalf("path still held by %q after single checkin of an idempotent re-checkout", o)
	}
}

// ---------------------------------------------------------------------------
// Overlapping-subtree denial in BOTH directions; siblings allowed.
// ---------------------------------------------------------------------------

func TestOverlap_ParentHeldDeniesChild(t *testing.T) {
	m := New()
	mustCheckout(t, m, "work", "A")

	// Direct child, deep descendant, and the exact path are all denied to B.
	mustDeny(t, m, "work/build", "B", "A")
	mustDeny(t, m, "work/build/out/obj/x", "B", "A")
	mustDeny(t, m, "work", "B", "A")

	// The same owner is NOT blocked by its own ancestor checkout.
	mustCheckout(t, m, "work/build", "A")
}

func TestOverlap_ChildHeldDeniesParent(t *testing.T) {
	m := New()
	mustCheckout(t, m, "work/build/out", "A")

	// B holding an ancestor would cover A's child — denied in the reverse direction.
	mustDeny(t, m, "work/build", "B", "A")
	mustDeny(t, m, "work", "B", "A")
	mustDeny(t, m, "", "B", "A") // root would cover everything, including A's path.

	// A's own ancestor checkout is permitted (same owner).
	mustCheckout(t, m, "work", "A")
}

func TestOverlap_SiblingsAllowed(t *testing.T) {
	m := New()
	mustCheckout(t, m, "work/build/a", "A")

	// Siblings under the same parent: no coverage relationship -> granted.
	mustCheckout(t, m, "work/build/b", "B")
	mustCheckout(t, m, "work/build/c", "C")

	// A path that shares a textual prefix but is NOT a subtree must be allowed.
	// "work/build/a" vs "work/build/aa": "aa" is not a child of "a".
	mustCheckout(t, m, "work/build/aa", "D")
	// And the reverse: holding "...aa" must not deny "...a".
	if !m.Checkin("work/build/a", "A") {
		t.Fatal("checkin work/build/a")
	}
	mustCheckout(t, m, "work/build/a", "A") // re-take, "aa" must not cover it

	// Disjoint top-level trees never conflict.
	mustCheckout(t, m, "data/raw", "E")
	mustCheckout(t, m, "logs", "F")
}

// Prefix-but-not-subtree, asserted directly through the public API in both
// directions: "a" must never be treated as an ancestor of "ab".
func TestPrefixNotSubtree_NoFalseConflict(t *testing.T) {
	m := New()

	mustCheckout(t, m, "a", "A")
	// "ab" only shares the literal prefix "a"; it is a different top-level entry.
	mustCheckout(t, m, "ab", "B")
	mustCheckout(t, m, "abc", "C")

	// Reverse direction: hold the longer one first, then the shorter.
	m2 := New()
	mustCheckout(t, m2, "abc", "A")
	mustCheckout(t, m2, "ab", "B")
	mustCheckout(t, m2, "a", "C")

	// Deeper variant: "x/ab" must not be covered by "x/a".
	m3 := New()
	mustCheckout(t, m3, "x/a", "A")
	mustCheckout(t, m3, "x/ab", "B")
}

// ---------------------------------------------------------------------------
// Double-checkout by another owner is denied and returns the current holder.
// ---------------------------------------------------------------------------

func TestDoubleCheckout_ReturnsHolder(t *testing.T) {
	m := New()
	mustCheckout(t, m, "repo/pkg", "holder")

	// Exact, descendant, and ancestor all surface "holder" as heldBy.
	for _, p := range []string{"repo/pkg", "repo/pkg/sub", "repo"} {
		ok, by := m.Checkout(p, "intruder")
		if ok || by != "holder" {
			t.Fatalf("Checkout(%q) = (%v,%q), want (false,holder)", p, ok, by)
		}
	}
}

// ---------------------------------------------------------------------------
// Checkin when not held / by wrong owner / on a free path.
// ---------------------------------------------------------------------------

func TestCheckin_NotHeld(t *testing.T) {
	m := New()

	// Checkin on a path nobody holds.
	if m.Checkin("nope", "A") {
		t.Fatal("Checkin of an unheld path should return false")
	}

	// Wrong owner: B cannot release A's checkout, and A still holds it after.
	mustCheckout(t, m, "shared", "A")
	if m.Checkin("shared", "B") {
		t.Fatal("Checkin by a non-owner should return false")
	}
	if o, _ := m.HeldBy("shared"); o != "A" {
		t.Fatalf("after failed foreign checkin, holder = %q, want A", o)
	}

	// Checkin of a DESCENDANT of A's held path is not a held key -> false,
	// and must not release the ancestor checkout.
	if m.Checkin("shared/inner", "A") {
		t.Fatal("Checkin of a descendant (not the held key) should return false")
	}
	if o, at := m.HeldBy("shared/inner"); o != "A" || at != "shared" {
		t.Fatalf("HeldBy(shared/inner) = (%q,%q), want (A, shared)", o, at)
	}

	// Double checkin: second release of an already-released path returns false.
	if !m.Checkin("shared", "A") {
		t.Fatal("first Checkin should succeed")
	}
	if m.Checkin("shared", "A") {
		t.Fatal("second Checkin of the same path should return false")
	}
}

// ---------------------------------------------------------------------------
// Root vs nested paths.
// ---------------------------------------------------------------------------

func TestRoot_CoversEverythingAndBlocks(t *testing.T) {
	m := New()

	// A holds the root.
	mustCheckout(t, m, "", "root-owner")

	// Every nested path is denied to anyone else, reporting the root owner.
	for _, p := range []string{"a", "a/b", "deep/nested/path", "/", "."} {
		mustDeny(t, m, p, "other", "root-owner")
	}

	// HeldBy of any path resolves to the root holder, at "" (the root key).
	if o, at := m.HeldBy("a/b/c"); o != "root-owner" || at != "" {
		t.Fatalf("HeldBy under root = (%q,%q), want (root-owner, \"\")", o, at)
	}

	// Root owner releases via any spelling that canonicalizes to root.
	if !m.Checkin("/", "root-owner") {
		t.Fatal("Checkin of root via \"/\" should succeed (canonicalizes to root key)")
	}
	if o, _ := m.HeldBy("anything"); o != "" {
		t.Fatalf("after root checkin, HeldBy = %q, want empty", o)
	}
}

func TestRoot_DeniedWhenAnyNestedHeld(t *testing.T) {
	m := New()
	mustCheckout(t, m, "a/b", "A")
	// Taking the root would cover A's nested checkout -> denied.
	mustDeny(t, m, "", "B", "A")
	mustDeny(t, m, "/", "B", "A")
	mustDeny(t, m, ".", "B", "A")
}

// ---------------------------------------------------------------------------
// Path canonicalization: distinct spellings hit the same delegation slot.
// ---------------------------------------------------------------------------

func TestCanonicalization_EquivalentSpellings(t *testing.T) {
	// Each group: all spellings must be treated as the SAME path.
	groups := [][]string{
		{"", "/", ".", "//", "/.", "a/.."},
		{"work/build", "/work/build", "work/build/", "work//build", "./work/build", "work/./build", "work/x/../build"},
		{"a/b/c", "a/b/c/", "//a//b//c//", "a/b/c/d/.."},
	}

	for gi, g := range groups {
		// Sanity: every spelling in the group canonicalizes identically.
		want := canonical(g[0])
		for _, s := range g {
			if got := canonical(s); got != want {
				t.Fatalf("group %d: canonical(%q)=%q, want %q (test premise broken)", gi, s, got, want)
			}
		}

		// Checkout via the first spelling; all other spellings must be seen as
		// the same held path by a different owner (denied, holder == A).
		m := New()
		mustCheckout(t, m, g[0], "A")
		for _, s := range g[1:] {
			ok, by := m.Checkout(s, "B")
			if ok || by != "A" {
				t.Fatalf("group %d: Checkout(%q,B) = (%v,%q), want (false,A) — spelling not canonicalized", gi, s, ok, by)
			}
			// Same owner via the alternate spelling is idempotent-granted.
			if ok, _ := m.Checkout(s, "A"); !ok {
				t.Fatalf("group %d: same-owner Checkout(%q,A) should grant", gi, s)
			}
		}

		// Checkin via a DIFFERENT spelling than checkout must still release it.
		last := g[len(g)-1]
		if !m.Checkin(last, "A") {
			t.Fatalf("group %d: Checkin(%q,A) should release the slot opened via %q", gi, last, g[0])
		}
		if o, _ := m.HeldBy(g[0]); o != "" {
			t.Fatalf("group %d: slot still held by %q after cross-spelling checkin", gi, o)
		}
	}
}

// Path traversal: a "../" prefix is clamped at the root by path.Clean, so it
// cannot escape the volume. We assert the observable consequence: "../x" and
// "x" address the same delegation slot.
func TestCanonicalization_TraversalClampedToRoot(t *testing.T) {
	m := New()
	mustCheckout(t, m, "../../etc/passwd", "A") // clamps to "etc/passwd"
	// The clamped, in-volume spelling refers to the very same slot.
	mustDeny(t, m, "etc/passwd", "B", "A")
	if o, at := m.HeldBy("etc/passwd"); o != "A" || at != "etc/passwd" {
		t.Fatalf("HeldBy(etc/passwd) = (%q,%q), want (A, etc/passwd)", o, at)
	}
}

// ---------------------------------------------------------------------------
// Delete-then-recreate / handoff sequencing through ReleaseOwner.
// ---------------------------------------------------------------------------

func TestReleaseOwner_DropsAllAndFreesForOthers(t *testing.T) {
	m := New()
	mustCheckout(t, m, "p/one", "A")
	mustCheckout(t, m, "p/two", "A")
	mustCheckout(t, m, "q", "B")

	m.ReleaseOwner("A")

	// A's paths are free; B's survives.
	if o, _ := m.HeldBy("p/one"); o != "" {
		t.Fatalf("p/one still held by %q after ReleaseOwner(A)", o)
	}
	if o, _ := m.HeldBy("p/two"); o != "" {
		t.Fatalf("p/two still held by %q after ReleaseOwner(A)", o)
	}
	if o, _ := m.HeldBy("q"); o != "B" {
		t.Fatalf("q held by %q, want B (unaffected by ReleaseOwner(A))", o)
	}

	// Now a previously-denied owner can take an overlapping ancestor.
	mustCheckout(t, m, "p", "C")

	// ReleaseOwner on an unknown owner is a harmless no-op.
	m.ReleaseOwner("ghost")
	if o, _ := m.HeldBy("p/one"); o != "C" {
		t.Fatalf("after no-op ReleaseOwner(ghost), p/one held by %q, want C", o)
	}
}

// ---------------------------------------------------------------------------
// CONCURRENCY — run under -race.
// ---------------------------------------------------------------------------

// hasOverlap reports whether two canonical paths cover one another in either
// direction (i.e. they belong to the same exclusive subtree).
func hasOverlap(a, b string) bool { return covers(a, b) || covers(b, a) }

// invariantNoTwoHoldersOfOverlap walks the live registry and fails if any two
// distinct owners hold overlapping subtrees. This is the core safety property.
func invariantNoTwoHoldersOfOverlap(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	type kv struct{ path, owner string }
	var all []kv
	for p, o := range m.held {
		all = append(all, kv{p, o})
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[i].owner == all[j].owner {
				continue
			}
			if hasOverlap(all[i].path, all[j].path) {
				t.Fatalf("INVARIANT VIOLATED: %q held by %q overlaps %q held by %q",
					all[i].path, all[i].owner, all[j].path, all[j].owner)
			}
		}
	}
}

// Many goroutines race Checkout/Checkin on a small set of OVERLAPPING paths.
// At every moment the registry must never contain two distinct owners of
// overlapping subtrees. Each goroutine only checks in what it actually got, so
// the manager's own correctness is what keeps the invariant.
func TestConcurrent_OverlappingPaths_NoDoubleGrant(t *testing.T) {
	m := New()

	// Deliberately overlapping ladder of paths: root, ancestor, descendants,
	// plus a couple of siblings.
	paths := []string{
		"",        // root — covers all
		"a",       // ancestor of a/*
		"a/b",     //
		"a/b/c",   //
		"a/b/c/d", //
		"a/x",     // sibling subtree under a
		"a/x/y",   //
		"z",       // disjoint top-level
	}

	const owners = 8
	const itersPerOwner = 4000

	var wg sync.WaitGroup
	var grants int64
	for o := 0; o < owners; o++ {
		wg.Add(1)
		owner := fmt.Sprintf("owner-%d", o)
		go func(seed int) {
			defer wg.Done()
			r := uint64(seed*2654435761 + 1) // cheap LCG, no shared rand state
			for i := 0; i < itersPerOwner; i++ {
				r = r*6364136223846793005 + 1442695040888963407
				p := paths[int(r>>33)%len(paths)]
				if ok, _ := m.Checkout(p, owner); ok {
					atomic.AddInt64(&grants, 1)
					// Hold briefly, then release exactly what we took.
					if !m.Checkin(p, owner) {
						t.Errorf("owner %s failed to check in %q it had just been granted", owner, p)
						return
					}
				}
			}
		}(o + 1)
	}
	wg.Wait()

	// The registry must be empty (every grant was paired with a checkin) and,
	// trivially, free of overlap violations.
	invariantNoTwoHoldersOfOverlap(t, m)
	if o, at := m.HeldBy(""); o != "" {
		t.Fatalf("registry not empty after balanced checkin/checkout: HeldBy(\"\")=(%q,%q)", o, at)
	}
	if grants == 0 {
		t.Fatal("expected at least some grants under contention")
	}
	t.Logf("balanced run: %d total grants across %d owners", grants, owners)
}

// Two owners contend for the SAME overlapping subtree, each holding before
// releasing. A concurrent auditor goroutine checks the invariant continuously
// mid-flight (for as long as the workers run), so a momentary double-grant
// would be caught. Worker iteration counts are bounded so the test terminates
// quickly under -race.
func TestConcurrent_HoldWhileContended_InvariantHolds(t *testing.T) {
	m := New()
	paths := []string{"proj", "proj/sub", "proj/sub/leaf", ""}

	var workersLeft int32 = 3
	var fail int32 // set by any goroutine that detects a violation, halts the rest
	var wg sync.WaitGroup

	const itersPerWorker = 5000

	// Workers: grab an overlapping path, hold it (do a little work), then release.
	worker := func(owner string, seed int) {
		defer wg.Done()
		defer atomic.AddInt32(&workersLeft, -1)
		r := uint64(seed*40503 + 7)
		for i := 0; i < itersPerWorker && atomic.LoadInt32(&fail) == 0; i++ {
			r = r*6364136223846793005 + 1442695040888963407
			p := paths[int(r>>33)%len(paths)]
			if ok, _ := m.Checkout(p, owner); ok {
				// Busy hold: a non-trivial window where a buggy manager could
				// let a second owner in.
				sink := 0
				for k := 0; k < 200; k++ {
					sink += k
				}
				_ = sink
				if !m.Checkin(p, owner) {
					t.Errorf("%s could not release %q it held", owner, p)
					atomic.StoreInt32(&fail, 1)
					return
				}
			}
		}
	}

	for i, name := range []string{"alpha", "beta", "gamma"} {
		wg.Add(1)
		go worker(name, i+1)
	}

	// Auditor: snapshot-and-verify the no-overlap invariant for as long as any
	// worker is still running. Bounded by the workers, so it always terminates.
	wg.Add(1)
	go func() {
		defer wg.Done()
		type kv struct{ path, owner string }
		for atomic.LoadInt32(&workersLeft) > 0 && atomic.LoadInt32(&fail) == 0 {
			m.mu.Lock()
			var all []kv
			for p, o := range m.held {
				all = append(all, kv{p, o})
			}
			m.mu.Unlock()
			for i := 0; i < len(all); i++ {
				for j := i + 1; j < len(all); j++ {
					if all[i].owner != all[j].owner && hasOverlap(all[i].path, all[j].path) {
						t.Errorf("AUDIT: overlap by distinct owners: %q@%s vs %q@%s",
							all[i].path, all[i].owner, all[j].path, all[j].owner)
						atomic.StoreInt32(&fail, 1)
						return
					}
				}
			}
		}
	}()

	wg.Wait()
}

// Stress ReleaseOwner racing against Checkout/Checkin/HeldBy. Mixing a bulk
// release with fine-grained ops is a classic place for map-mutation races; -race
// guards the data race and the invariant guards the logic.
func TestConcurrent_ReleaseOwner_RacesCheckoutCheckin(t *testing.T) {
	m := New()
	owners := []string{"o0", "o1", "o2", "o3"}
	paths := []string{"r", "r/a", "r/a/b", "r/c", "s", "s/t", ""}

	var wg sync.WaitGroup
	const iters = 6000

	// Checkout/Checkin churners.
	for i, owner := range owners {
		wg.Add(1)
		go func(owner string, seed int) {
			defer wg.Done()
			r := uint64(seed*2246822519 + 3)
			for n := 0; n < iters; n++ {
				r = r*6364136223846793005 + 1442695040888963407
				p := paths[int(r>>33)%len(paths)]
				if ok, _ := m.Checkout(p, owner); ok {
					m.Checkin(p, owner) // may already be gone via ReleaseOwner; fine.
				}
			}
		}(owner, i+1)
	}

	// Bulk releasers, each periodically dropping all of one owner's holds.
	for _, owner := range owners {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			for n := 0; n < iters; n++ {
				m.ReleaseOwner(owner)
			}
		}(owner)
	}

	// HeldBy readers, exercising the read path concurrently.
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			x := uint64(seed*97 + 11)
			for n := 0; n < iters; n++ {
				x = x*6364136223846793005 + 1442695040888963407
				_, _ = m.HeldBy(paths[int(x>>33)%len(paths)])
			}
		}(r + 1)
	}

	wg.Wait()
	invariantNoTwoHoldersOfOverlap(t, m)
}
