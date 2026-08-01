package cli

import (
	"sync"
	"testing"
	"time"
)

// ── FINDING 5 (ROUND 11): CREDENTIAL DELIVERY MUST BE ORDERED ────────────────
//
// setToken ordered the SOURCE under its own lock and then installed after
// unlocking, which loses the order for everything below it. Two rotations
// overlap — T2 blocks between the unlock and its install while T3 stores and
// installs — and T2's install lands LAST. The source says T3; the data plane
// offers T2's credential under the newest generation's tag; verification then
// faithfully verifies the wrong credential and latches a verdict about it; and
// nothing repairs that, because from every layer's point of view the
// installation succeeded. Atomicity inside Client.InstallCredential cannot
// help — the order was already lost above it.

// gatedInstaller records every installation and can be held inside one of them,
// which is how the overlap is made deterministic rather than hoped for.
type gatedInstaller struct {
	mu       sync.Mutex
	installs []installedPair
	holdFor  string
	entered  chan struct{}
	release  chan struct{}
}

func (g *gatedInstaller) InstallCredential(token string, expiresAtMs int64) {
	g.mu.Lock()
	hold := token == g.holdFor
	g.mu.Unlock()
	if hold {
		g.mu.Lock()
		g.holdFor = ""
		g.mu.Unlock()
		close(g.entered)
		<-g.release
	}
	g.mu.Lock()
	g.installs = append(g.installs, installedPair{token, expiresAtMs})
	g.mu.Unlock()
}

func (g *gatedInstaller) last() (installedPair, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.installs) == 0 {
		return installedPair{}, 0
	}
	return g.installs[len(g.installs)-1], len(g.installs)
}

// TestOverlappingRotationsNeverDeliverAnObsoleteCredential is the interleaving.
func TestOverlappingRotationsNeverDeliverAnObsoleteCredential(t *testing.T) {
	tokens := &sessionTokenSource{token: "t1", expiresAtMs: 111}
	plane := &gatedInstaller{
		holdFor: "t2",
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	tokens.bindDataPlane(plane, "t1", 111)

	rotations := sync.WaitGroup{}
	rotations.Add(1)
	go func() {
		defer rotations.Done()
		tokens.setToken("t2", 222)
	}()

	select {
	case <-plane.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first rotation never reached the data plane")
	}

	// The lease keeper rotates again while the first delivery is in flight.
	rotations.Add(1)
	go func() {
		defer rotations.Done()
		tokens.setToken("t3", 333)
	}()
	// Let the second rotation get as far as it can on its own.
	time.Sleep(200 * time.Millisecond)
	close(plane.release)
	rotations.Wait()

	if token, expiresAtMs := tokens.get(); token != "t3" || expiresAtMs != 333 {
		t.Fatalf("source state = (%q, %d), want the newest rotation", token, expiresAtMs)
	}
	last, n := plane.last()
	if last != (installedPair{"t3", 333}) {
		t.Fatalf("the data plane's newest installed credential is %v after %d "+
			"install(s), want (t3, 333): a rotation that was overtaken installed its "+
			"OWN credential last, so the mount offers a superseded token under the "+
			"newest generation's tag and verification proves the wrong credential",
			last, n)
	}
}

// TestBindRacingARotationLandsOnTheCurrentCredential is the same reversal on
// the other path the finding names: the bind used to install from its own read
// of the source, a second unordered writer into the same data plane.
func TestBindRacingARotationLandsOnTheCurrentCredential(t *testing.T) {
	tokens := &sessionTokenSource{token: "t1", expiresAtMs: 111}
	plane := &gatedInstaller{entered: make(chan struct{}), release: make(chan struct{})}
	close(plane.release)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); tokens.setToken("t2", 222) }()
	go func() { defer wg.Done(); tokens.bindDataPlane(plane, "t1", 111) }()
	wg.Wait()

	last, n := plane.last()
	if n == 0 {
		t.Fatal("a data plane bound across a rotation was left holding a superseded seed")
	}
	if last != (installedPair{"t2", 222}) {
		t.Fatalf("the data plane's newest installed credential is %v, want (t2, 222)", last)
	}
}

// TestSequentialRotationsStillReachEveryDataPlane is the regression guard: the
// ordering machinery must not swallow ordinary deliveries.
func TestSequentialRotationsStillReachEveryDataPlane(t *testing.T) {
	tokens := &sessionTokenSource{token: "t1", expiresAtMs: 111}
	first := &gatedInstaller{entered: make(chan struct{}), release: make(chan struct{})}
	second := &gatedInstaller{entered: make(chan struct{}), release: make(chan struct{})}
	tokens.bindDataPlane(first, "t1", 111)
	tokens.bindDataPlane(second, "t1", 111)

	tokens.setToken("t2", 222)
	tokens.setToken("t3", 333)

	for name, plane := range map[string]*gatedInstaller{"first": first, "second": second} {
		plane.mu.Lock()
		got := append([]installedPair(nil), plane.installs...)
		plane.mu.Unlock()
		want := []installedPair{{"t2", 222}, {"t3", 333}}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("%s data plane received %v, want %v", name, got, want)
		}
	}
}
