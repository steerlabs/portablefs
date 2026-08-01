package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestRefreshNeverClobbersAnAcknowledgedLocalExtension is the FABRICATION test.
//
// applyKernelRefresh used to write the SAMPLED size into the item registry
// before arming its provenance window, unconditionally:
//
//	current.attr.Size = size
//
// That write is the daemon's composed view of the file — the same field the
// window predicate consults to decide whether a size-set means anything, and
// the same field the Internal arm answers the upcall from. Writing the sample
// into it does not observe a fact, it MANUFACTURES one.
//
// The interleaving the audit found:
//
//	the refresh samples S from the authority
//	a local write is ACKNOWLEDGED and publishes N > S into the registry
//	applyKernelRefresh overwrites the registry back to S and arms
//	the ftruncate(S) upcall sees a composed size of S, classifies Internal,
//	and is answered from the fabricated attributes
//
// Both halves of the damage follow: the kernel adopts S for a vnode whose real
// size is N (the extension's newer bytes vanish from every read), and the
// ambiguity guard — whose whole job is to notice that a local write moved the
// size — is disarmed by the very code it exists to catch.
//
// The refresh must instead PROVE its sample is still current before it changes
// anything: the item must still be the one that was sampled, and nothing may
// have published a newer composed size in between. When that proof fails there
// is no ftruncate at all — the pass returns kernelRefreshRetry and the caller's
// convergence loop re-samples against the state that actually exists.
func TestRefreshNeverClobbersAnAcknowledgedLocalExtension(t *testing.T) {
	const (
		sampledSize  = int64(5)
		extendedSize = int64(8)
	)
	item := pfslocal.Item{ItemID: 31, ItemGeneration: 1}
	live := &itemRecord{
		item: item,
		path: "f",
		attr: fsproto.Attr{Kind: "file", Size: sampledSize},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: live}}

	// The refresh's own snapshot, taken under a.mu before the sample — exactly
	// what refreshKernelItemStateComposedModeContext hands to applyKernelRefresh.
	snapshot := &itemRecord{item: live.item, path: live.path, attr: live.attr}

	// ... and now a local write is acknowledged and published. This is an
	// ordinary registerHandleAttrLocked/registerLocked install; by the time the
	// refresh gets to apply its sample, the daemon already knows the file is
	// longer than the sample says.
	a.mu.Lock()
	live.attr.Size = extendedSize
	a.mu.Unlock()

	truncated := false
	a.testRefreshKernelFile = func(_, _ string, _ uint64, _ int64, _ func() (func(), error)) (kernelRefreshOutcome, error) {
		truncated = true
		return kernelRefreshApplied, nil
	}

	outcome, err := a.applyKernelRefresh("", "f", snapshot, sampledSize, refreshApplyFence{observedSize: snapshot.attr.Size})

	a.mu.RLock()
	composed := a.items[item.ItemID].attr.Size
	a.mu.RUnlock()
	if composed != extendedSize {
		t.Fatalf("the refresh overwrote the composed size with its own stale "+
			"sample: registry says %d, the acknowledged local write made it %d. "+
			"A sample is an observation, never a licence to rewrite newer state",
			composed, extendedSize)
	}
	if truncated {
		t.Fatalf("the refresh issued its ftruncate(%d) against an item a local "+
			"write had already extended to %d: the kernel would adopt the stale "+
			"size and the extension's bytes would disappear from every read",
			sampledSize, extendedSize)
	}
	if outcome != kernelRefreshRetry {
		t.Fatalf("applyKernelRefresh = (%v, %v), want kernelRefreshRetry: a "+
			"superseded sample is not a settled pass, and the caller must "+
			"re-sample rather than declare the kernel converged", outcome, err)
	}
}

// TestExplicitTimestampSetIsNeverAnsweredAsRefreshBookkeeping is the TIMESTAMP
// hole.
//
// The provenance predicate accepted any size-set that carried no ownership,
// mode or flag group — and said nothing at all about MtimeMs/AtimeMs. So an
// application that set a size AND explicit times inside an open window was
// answered Internal: the size was a no-op, and the timestamps the application
// asked for were silently dropped on the floor. They never reached the
// authority, no error was reported, and the ctime ordering every other observer
// derives from that mutation never happened.
//
// ftruncate(2) asks the kernel for a SIZE. The daemon's own refresh therefore
// never carries an explicit timestamp, so a size-set that does cannot be the
// daemon's request. It cannot simply be forwarded either: while this daemon is
// inside its own syscall for the same (item, size), a request the daemon cannot
// positively attribute must not be sent to the authority — that is the leg that
// destroys data. The only answer that is safe for both candidates is a refusal.
func TestExplicitTimestampSetIsNeverAnsweredAsRefreshBookkeeping(t *testing.T) {
	const refreshSize = int64(64)
	item := pfslocal.Item{ItemID: 32, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "dir/file",
		attr: fsproto.Attr{Kind: "file", Size: refreshSize},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: rec}}

	var (
		handlerClass  refreshClass
		admissionSkip bool
	)
	a.testRefreshKernelFile = func(_, p string, _ uint64, _ int64, armTruncate func() (func(), error)) (kernelRefreshOutcome, error) {
		defer mustArmRefreshWindow(t, armTruncate)()
		size := uint64(refreshSize)
		mtime := int64(1_700_000_000_000)
		timed := &pfslocal.SetAttrRequest{Item: item, Size: &size, MtimeMs: &mtime}
		handlerClass = a.classifyExpectedTruncate(p, timed)
		admissionSkip = a.internalRefreshPending(timed)
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, refreshSize, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}

	if handlerClass == refreshClassInternal {
		t.Fatalf("a size-set carrying an EXPLICIT mtime was answered as the " +
			"daemon's own refresh bookkeeping: the application's timestamps " +
			"never reach the authority and it is told the call succeeded")
	}
	if handlerClass != refreshClassAmbiguous {
		t.Fatalf("classifyExpectedTruncate = %v, want refreshClassAmbiguous: "+
			"the request cannot be the daemon's (ftruncate asks for a size, not "+
			"a timestamp) and must not be forwarded on an unproven claim while "+
			"the daemon is inside its own syscall for the same (item, size)",
			handlerClass)
	}
	if !admissionSkip {
		t.Fatalf("admission paced a request the handler answers locally: the " +
			"two call sites must reach the identical verdict for the identical " +
			"request")
	}
}

// TestFrozenRefreshVerdictSurvivesAWindowThatClosesUnderAdmission is the
// RECLASSIFICATION hole, and it is the one that turns the daemon's own refresh
// into a real truncate.
//
// The dispatcher classifies provenance in PHASE 1, holding nothing: a request
// the window claims bypasses admission entirely (no transition token, no
// metadata pacing) because it is answered locally and appends nothing to the
// write-back stream. The request then suspends in phase 2 waiting to activate
// into the publication set — and the daemon's own ftruncate window, which is
// pinned for exactly the extent of one syscall, can close while it waits.
//
// The handler then classified the request AGAIN, from scratch, found no window,
// called it an application mutation, and executed a real Setattr against the
// authority — under the frontend mirrors, and with NO admission behind it. The
// request that reached the authority was the daemon's own refresh.
//
// Phase 1's verdict is the verdict. It is frozen into the operation context and
// the handler consumes it; a request that was never classified as an
// application mutation can never become one under the locks.
func TestFrozenRefreshVerdictSurvivesAWindowThatClosesUnderAdmission(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	cli := vol.Client()

	if _, st, err := cli.Create("f", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("create f st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("f", 0, []byte("hello"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed write st=%d err=%v", st, err)
	}
	seeded, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("getattr f st=%d err=%v", st, err)
	}
	const sampledSize = uint64(5)
	if uint64(seeded.Size) != sampledSize {
		t.Fatalf("seeded size = %d, want %d", seeded.Size, sampledSize)
	}

	a := newAttach("att_frozen_verdict", "key", ensureAttachRequest{
		VolumeID: "vol-frozen-verdict", Branch: "main",
		MountPath: "/Volumes/FrozenVerdict",
	}, privateTestDir(t))
	a.vol = vol
	a.restoreItemsLocked([]persistedItemRecord{{
		Path: "f", ItemID: seeded.Ino, ItemGeneration: 1,
		AuthorityIno: true, Kind: "file",
	}})
	rec := a.itemByPath("f")
	if rec == nil {
		t.Fatal("item f was not registered")
	}

	// The daemon is inside its own ftruncate(f, 5): the window is pinned for
	// exactly that syscall's extent, exactly as applyKernelRefresh arms it.
	a.mu.Lock()
	a.expectedTruncateSeq++
	armedSeq := a.expectedTruncateSeq
	a.expectedTruncates = map[string]expectedTruncate{"f": {
		itemID:   rec.item.ItemID,
		size:     int64(sampledSize),
		pinned:   true,
		deadline: time.Now().Add(truncateNoteTTL),
		seq:      armedSeq,
	}}
	a.mu.Unlock()

	// PHASE 1. The upcall of the daemon's own refresh is classified holding
	// nothing, and bypasses admission because it is answered locally.
	size := sampledSize
	upcall := &pfslocal.SetAttrRequest{Item: rec.item, Size: &size}
	opCtx, settle, admitEno, classified := a.admitRequest(context.Background(), upcall, false)
	defer settle()
	if admitEno != 0 {
		t.Fatalf("admission refused the daemon's own refresh upcall: eno=%d", admitEno)
	}
	if classified {
		t.Fatalf("the daemon's own refresh upcall was admitted as an application " +
			"mutation: it publishes state the authority has already applied and " +
			"must not be paced against the metadata lane")
	}

	// The request now waits to activate into the publication set. The daemon's
	// ftruncate(2) returns in the meantime and retires its own window.
	a.retireExpectedTruncate("f", armedSeq)

	// A concurrent writer extends the file past the sampled size. These are the
	// bytes a forwarded refresh destroys.
	if _, st, err := cli.Write("f", int64(sampledSize), []byte("+++"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("extending write st=%d err=%v", st, err)
	}

	// PHASE 3.
	_, handlerEno := a.setattr(opCtx, upcall)

	after, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify getattr st=%d err=%v", st, err)
	}
	if after.Size != int64(sampledSize)+3 {
		t.Fatalf("the daemon's OWN refresh upcall reached the authority and "+
			"truncated the file to %d bytes (handler eno=%d): a request phase 1 "+
			"classified as daemon bookkeeping was reclassified under the locks "+
			"as an application mutation and executed with no admission behind it",
			after.Size, handlerEno)
	}
}
