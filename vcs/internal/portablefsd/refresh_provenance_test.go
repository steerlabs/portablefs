package portablefsd

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func sizeSetAttr(item pfslocal.Item, size uint64) *pfslocal.SetAttrRequest {
	return &pfslocal.SetAttrRequest{Item: item, Size: &size}
}

// mustArmRefreshWindow opens the provenance window a test's fake ftruncate is
// standing in for. The arm may refuse — it is atomic with installing the sampled
// size as the composed view, so it declines when the sample can no longer be
// proved current — and a test that expects to be INSIDE a window must fail
// loudly rather than silently assert against a window that was never opened.
func mustArmRefreshWindow(t *testing.T, arm func() (func(), error)) func() {
	t.Helper()
	disarm, err := arm()
	if err != nil {
		t.Fatalf("the refresh declined to open its provenance window: %v", err)
	}
	return disarm
}

// consumedInternal is the boolean the handler's classification used to be:
// "answered locally as the daemon's own refresh". It is a test convenience so
// the provenance assertions read as they always did; the handler itself needs
// the third verdict (refreshClassAmbiguous) that this collapses away.
func consumedInternal(a *attach, p string, req *pfslocal.SetAttrRequest) bool {
	return a.classifyExpectedTruncate(p, req) == refreshClassInternal
}

// TestCompetingApplicationTruncateCannotStealRefreshProvenance is the exact
// same-item same-size race the marker protocol exists to survive.
//
// The daemon pins a refresh marker for (item, size) and enters its own
// ftruncate. An APPLICATION ftruncate for the SAME item and the SAME size
// reaches the dispatcher first. Under a single-use marker that application
// request CONSUMES the daemon's provenance, and the daemon's own upcall — the
// one the pin was installed for — then arrives markerless and is classified as
// an application mutation, sent to the authority, and truncates whatever a
// concurrent write appended past the sampled size.
//
// Provenance is a property of the PINNED WINDOW, not of a token some other
// request can spend. While the window is open every (item, size) setattr is
// daemon bookkeeping, and the marker is retired only by the refresh that
// installed it.
func TestCompetingApplicationTruncateCannotStealRefreshProvenance(t *testing.T) {
	item := pfslocal.Item{ItemID: 9, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "dir/file",
		attr: fsproto.Attr{Kind: "file", Size: 64},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: rec}}

	const refreshSize = int64(64)
	var (
		appAdmitted  bool
		appConsumed  bool
		selfAdmitted bool
		selfConsumed bool
	)
	a.testRefreshKernelFile = func(_, p string, _ uint64, size int64, armTruncate func() (func(), error)) (kernelRefreshOutcome, error) {
		// Inside the daemon's own synchronous ftruncate: the pin is held.
		defer mustArmRefreshWindow(t, armTruncate)()

		// 1. A competing APPLICATION ftruncate(item, refreshSize) — byte
		//    identical on the wire — reaches the dispatcher first.
		appReq := sizeSetAttr(item, uint64(refreshSize))
		appAdmitted = a.internalRefreshPending(appReq)
		appConsumed = consumedInternal(a, rec.path, appReq)

		// 2. The daemon's OWN upcall for this very ftruncate arrives after it.
		//    It must still be recognised as daemon bookkeeping; anything else
		//    sends a truncate the application never asked for to the authority.
		selfReq := sizeSetAttr(item, uint64(refreshSize))
		selfAdmitted = a.internalRefreshPending(selfReq)
		selfConsumed = consumedInternal(a, rec.path, selfReq)
		return kernelRefreshApplied, nil
	}

	if outcome, err := a.applyKernelRefresh("", rec.path, rec, refreshSize, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}

	// The competing application truncate is answered locally as a no-op: the
	// pinned window's documented, accepted cost (an mtime bump the remote edit
	// has already superseded). What it must NEVER do is spend the provenance.
	if !appAdmitted || !appConsumed {
		t.Fatalf("competing truncate inside the pinned window: admitted=%v consumed=%v, want both true",
			appAdmitted, appConsumed)
	}
	if !selfAdmitted {
		t.Fatal("the daemon's own refresh upcall was not classified as an internal refresh at admission")
	}
	if !selfConsumed {
		t.Fatal("the daemon's own refresh upcall was treated as an APPLICATION truncate: " +
			"a competing same-size application truncate stole the refresh marker")
	}

	// The refresh has returned, so the window is closed and a later
	// application truncate to the same size is a real mutation again.
	if a.internalRefreshPending(sizeSetAttr(item, uint64(refreshSize))) {
		t.Fatal("refresh window stayed open after the refresh returned")
	}
	if consumedInternal(a, rec.path, sizeSetAttr(item, uint64(refreshSize))) {
		t.Fatal("a post-refresh application truncate was suppressed")
	}
}

// TestHardLinkAliasTruncateCannotStealRefreshProvenance is the same race
// arriving through a different NAME for the same inode. The marker is keyed by
// path, so the alias takes the item-scan arm; that arm must not spend the
// pinned window either.
func TestHardLinkAliasTruncateCannotStealRefreshProvenance(t *testing.T) {
	item := pfslocal.Item{ItemID: 11, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "dir/primary",
		attr: fsproto.Attr{Kind: "file", Size: 32},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: rec}}

	const refreshSize = int64(32)
	var aliasConsumed, selfConsumed bool
	a.testRefreshKernelFile = func(_, _ string, _ uint64, _ int64, armTruncate func() (func(), error)) (kernelRefreshOutcome, error) {
		// Model the real refresh: the window is armed for exactly the extent of
		// the ftruncate(2) this hook stands in for.
		defer mustArmRefreshWindow(t, armTruncate)()
		aliasConsumed = consumedInternal(a, "dir/alias", sizeSetAttr(item, uint64(refreshSize)))
		selfConsumed = consumedInternal(a, rec.path, sizeSetAttr(item, uint64(refreshSize)))
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, refreshSize, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}
	if !aliasConsumed {
		t.Fatal("alias truncate inside the pinned window was not recognised as the open refresh window")
	}
	if !selfConsumed {
		t.Fatal("a hard-link alias truncate stole the refresh marker from the daemon's own upcall")
	}
}

// TestRealTruncateInsideAPinnedWindowStillReachesTheAuthority pins the other
// half of the contract: a pinned window is provenance for its OWN (item, size)
// only. A truncate to a different size, or one carrying a real attribute
// group, is an application mutation and must pass through — and must not
// destroy the pin, which belongs to the refresh that installed it.
func TestRealTruncateInsideAPinnedWindowStillReachesTheAuthority(t *testing.T) {
	item := pfslocal.Item{ItemID: 13, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "dir/file",
		attr: fsproto.Attr{Kind: "file", Size: 100},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: rec}}

	mode := uint32(0o600)
	var shorter, withMode, self bool
	a.testRefreshKernelFile = func(_, _ string, _ uint64, _ int64, armTruncate func() (func(), error)) (kernelRefreshOutcome, error) {
		defer mustArmRefreshWindow(t, armTruncate)()
		shorter = consumedInternal(a, rec.path, sizeSetAttr(item, 7))
		modeReq := sizeSetAttr(item, 100)
		modeReq.Mode = &mode
		withMode = consumedInternal(a, rec.path, modeReq)
		self = consumedInternal(a, rec.path, sizeSetAttr(item, 100))
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 100, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}
	if shorter {
		t.Fatal("a truncate to a different size was suppressed by the refresh window")
	}
	if withMode {
		t.Fatal("a mode-bearing setattr was suppressed by the refresh window")
	}
	if !self {
		t.Fatal("a real truncate racing the pinned window destroyed the daemon's own provenance")
	}
}

// TestRefreshProvenancePredicatesAgree pins the invariant the two call sites
// depend on: admission (internalRefreshPending) and the setattr handler
// (consumeExpectedTruncate) must answer the SAME question about a pinned
// window. A request one calls bookkeeping and the other calls an application
// mutation is exactly how a refresh becomes a data-destroying truncate.
func TestRefreshProvenancePredicatesAgree(t *testing.T) {
	item := pfslocal.Item{ItemID: 17, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "dir/file",
		attr: fsproto.Attr{Kind: "file", Size: 5},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: rec}}

	var disagreements int
	a.testRefreshKernelFile = func(_, _ string, _ uint64, _ int64, armTruncate func() (func(), error)) (kernelRefreshOutcome, error) {
		defer mustArmRefreshWindow(t, armTruncate)()
		for i := 0; i < 8; i++ {
			req := sizeSetAttr(item, 5)
			if a.internalRefreshPending(req) != consumedInternal(a, rec.path, req) {
				disagreements++
			}
		}
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 5, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}
	if disagreements != 0 {
		t.Fatalf("admission and the setattr handler disagreed on provenance %d times", disagreements)
	}
}
