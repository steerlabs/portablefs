package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestRefreshWindowCannotDiscardARealApplicationTruncate is the OTHER half of
// the provenance contract, and the one the pinned window used to get wrong.
//
// A pinned window claims (item, size) unconditionally. That is safe for the
// daemon and unsafe for the application, and this is the interleaving:
//
//	the refresh samples size S and enters its ftruncate (window armed for S)
//	a LOCAL WRITE extends the inode to N > S
//	the application issues a REAL ftruncate(item, S)
//
// The application's request is byte-identical to the daemon's on the wire, so
// the window swallowed it: ftruncate(2) returned SUCCESS, the bytes S..N
// survived, and getattr kept reporting N. Silent data retention against an
// explicit application request.
//
// The window's claim is only sound while the size it names is still the item's
// size. Once a local write moves it, suppressing and forwarding are OPPOSITE
// answers and nothing distinguishes the two candidates, so the daemon refuses
// with EINTR — safe for the daemon's own ftruncate (kernelRefreshRetry) and
// safe for the application (the documented interrupted-syscall outcome, whose
// retry lands on a closed window and mutates for real).
func TestRefreshWindowCannotDiscardARealApplicationTruncate(t *testing.T) {
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
	const sampledSize = int64(5)
	if seeded.Size != sampledSize {
		t.Fatalf("seeded size = %d, want %d", seeded.Size, sampledSize)
	}

	a := newAttach("att_refresh_intent", "key", ensureAttachRequest{
		VolumeID: "vol-refresh-intent", Branch: "main",
		MountPath: "/Volumes/RefreshIntent",
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

	var (
		appEno      int32
		appReply    *pfslocal.SetAttrReply
		sizeInside  int64
		selfOutcome kernelRefreshOutcome
	)
	a.testRefreshKernelFile = func(_, p string, _ uint64, size int64, armTruncate func() func()) (kernelRefreshOutcome, error) {
		// Inside the daemon's own ftruncate(2): the provenance window is armed
		// for exactly this call's extent.
		disarm := armTruncate()
		defer disarm()

		// A LOCAL WRITE extends the inode past the sampled size. The frontend
		// learns the new size the same way attach.write does: the post-write
		// authority attributes are registered against the item's path.
		if _, st, err := cli.Write("f", sampledSize, []byte("+++"), 0o644); err != nil || st != fsproto.OK {
			t.Errorf("extending local write st=%d err=%v", st, err)
		}
		extended, st, err := cli.Getattr("f")
		if err != nil || st != fsproto.OK {
			t.Errorf("post-write getattr st=%d err=%v", st, err)
		}
		a.mu.Lock()
		a.registerLocked("f", *extended)
		sizeInside = a.items[rec.item.ItemID].attr.Size
		a.mu.Unlock()

		// The APPLICATION now issues a real ftruncate(item, sampledSize).
		// Byte-identical to the daemon's own upcall; semantically the opposite.
		sz := uint64(sampledSize)
		appReply, appEno = a.setattr(context.Background(), &pfslocal.SetAttrRequest{
			Item: rec.item,
			Size: &sz,
		})
		return kernelRefreshApplied, nil
	}

	selfOutcome, err = func() (kernelRefreshOutcome, error) {
		return a.applyKernelRefresh("", "f", rec, sampledSize)
	}()
	if selfOutcome != kernelRefreshApplied || err != nil {
		t.Fatalf("apply kernel refresh = (%v, %v)", selfOutcome, err)
	}
	if sizeInside != sampledSize+3 {
		t.Fatalf("the frontend's composed size inside the window = %d, want %d "+
			"(the test did not reproduce the local extend)", sizeInside, sampledSize+3)
	}

	// THE DEFECT: the request was answered from the window as a no-op, so the
	// application saw success and nothing changed.
	if appEno == 0 {
		after, st, err := cli.Getattr("f")
		if err != nil || st != fsproto.OK {
			t.Fatalf("verify getattr st=%d err=%v", st, err)
		}
		if after.Size != sampledSize {
			t.Fatalf("an application ftruncate(f, %d) inside the daemon's refresh "+
				"window returned SUCCESS (reply=%v) without mutating anything: the "+
				"file is still %d bytes. A byte-identical application request must "+
				"not be suppressed on (item, size, window) alone",
				sampledSize, appReply, after.Size)
		}
	}
	if appEno != darwinEINTR {
		t.Fatalf("application truncate inside a semantically dead refresh window "+
			"answered eno=%d, want EINTR (%d): the daemon cannot prove provenance "+
			"here and must refuse rather than guess", appEno, darwinEINTR)
	}
	after, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify getattr st=%d err=%v", st, err)
	}
	if after.Size != sampledSize+3 {
		t.Fatalf("the refused truncate mutated the authority anyway: %d bytes, want %d",
			after.Size, sampledSize+3)
	}

	// The window has closed with the refresh. The application's RETRY is now an
	// ordinary truncate and must reach the authority.
	sz := uint64(sampledSize)
	if _, eno := a.setattr(context.Background(), &pfslocal.SetAttrRequest{
		Item: rec.item,
		Size: &sz,
	}); eno != 0 {
		t.Fatalf("the application's retry after the window closed failed: eno=%d", eno)
	}
	final, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("final getattr st=%d err=%v", st, err)
	}
	if final.Size != sampledSize {
		t.Fatalf("the application's truncate never took effect: %d bytes, want %d",
			final.Size, sampledSize)
	}
}

// TestRefreshWithNoTruncateArmsNoWindow pins the counting half: the daemon
// issues at most ONE ftruncate per refresh, and none at all when the kernel's
// vnode size already matches. A refresh that makes no syscall has no claim to
// make, so no application size-set may be answered from it — the window used
// to stay pinned across the whole refresh, including its O(file size)
// mmap/msync sweep.
func TestRefreshWithNoTruncateArmsNoWindow(t *testing.T) {
	item := pfslocal.Item{ItemID: 21, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "dir/file",
		attr: fsproto.Attr{Kind: "file", Size: 64},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: rec}}

	var pendingInside, consumedInside bool
	a.testRefreshKernelFile = func(_, _ string, _ uint64, _ int64, _ func() func()) (kernelRefreshOutcome, error) {
		// The vnode size already matched: no ftruncate, so armTruncate is never
		// called and no window exists.
		req := sizeSetAttr(item, 64)
		pendingInside = a.internalRefreshPending(req)
		consumedInside = consumedInternal(a, rec.path, req)
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 64); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("applyKernelRefresh = (%v, %v)", outcome, err)
	}
	if pendingInside || consumedInside {
		t.Fatalf("a refresh that issued no ftruncate still claimed provenance "+
			"(admission=%v handler=%v): an application truncate would be "+
			"answered as bookkeeping for a syscall that was never made",
			pendingInside, consumedInside)
	}
}
