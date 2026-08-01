package portablefsd

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func sizeSetAttr(item pfslocal.Item, size uint64) *pfslocal.SetAttrRequest {
	return &pfslocal.SetAttrRequest{Item: item, Size: &size}
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
	a.testRefreshKernelFile = func(_, p string, _ uint64, size int64) (kernelRefreshOutcome, error) {
		// Inside the daemon's own synchronous ftruncate: the pin is held.

		// 1. A competing APPLICATION ftruncate(item, refreshSize) — byte
		//    identical on the wire — reaches the dispatcher first.
		appReq := sizeSetAttr(item, uint64(refreshSize))
		appAdmitted = a.internalRefreshPending(appReq)
		appConsumed = a.consumeExpectedTruncate(rec.path, appReq)

		// 2. The daemon's OWN upcall for this very ftruncate arrives after it.
		//    It must still be recognised as daemon bookkeeping; anything else
		//    sends a truncate the application never asked for to the authority.
		selfReq := sizeSetAttr(item, uint64(refreshSize))
		selfAdmitted = a.internalRefreshPending(selfReq)
		selfConsumed = a.consumeExpectedTruncate(rec.path, selfReq)
		return kernelRefreshApplied, nil
	}

	if outcome, err := a.applyKernelRefresh("", rec.path, rec, refreshSize); outcome != kernelRefreshApplied || err != nil {
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
	if a.consumeExpectedTruncate(rec.path, sizeSetAttr(item, uint64(refreshSize))) {
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
	a.testRefreshKernelFile = func(string, string, uint64, int64) (kernelRefreshOutcome, error) {
		aliasConsumed = a.consumeExpectedTruncate("dir/alias", sizeSetAttr(item, uint64(refreshSize)))
		selfConsumed = a.consumeExpectedTruncate(rec.path, sizeSetAttr(item, uint64(refreshSize)))
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, refreshSize); outcome != kernelRefreshApplied || err != nil {
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
	a.testRefreshKernelFile = func(string, string, uint64, int64) (kernelRefreshOutcome, error) {
		shorter = a.consumeExpectedTruncate(rec.path, sizeSetAttr(item, 7))
		modeReq := sizeSetAttr(item, 100)
		modeReq.Mode = &mode
		withMode = a.consumeExpectedTruncate(rec.path, modeReq)
		self = a.consumeExpectedTruncate(rec.path, sizeSetAttr(item, 100))
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 100); outcome != kernelRefreshApplied || err != nil {
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
	a.testRefreshKernelFile = func(string, string, uint64, int64) (kernelRefreshOutcome, error) {
		for i := 0; i < 8; i++ {
			req := sizeSetAttr(item, 5)
			if a.internalRefreshPending(req) != a.consumeExpectedTruncate(rec.path, req) {
				disagreements++
			}
		}
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 5); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}
	if disagreements != 0 {
		t.Fatalf("admission and the setattr handler disagreed on provenance %d times", disagreements)
	}
}
