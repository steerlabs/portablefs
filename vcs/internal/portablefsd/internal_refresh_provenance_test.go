package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// TestInternalRefreshCannotBecomeAnApplicationTruncate is the data-loss test.
//
// The daemon refreshes a stale kernel vnode by ftruncate(2)-ing it to the
// AUTHORITATIVE size through its own mount. That syscall produces an FSKit
// setattr upcall which the daemon must recognise as its own and answer locally.
// Recognition used to be a wall-clock TTL on the marker — and a wall clock says
// nothing about who issued a request. The upcall travels the frontend
// dispatcher, where metadata-lane admission can park it for a full admission
// budget; when that park outran the TTL the handler reclassified the daemon's
// own no-op as an APPLICATION truncate and sent it to the authority. Every byte
// a concurrent writer had appended past the sampled size was destroyed.
//
// The interleaving below is exactly that one: sample at 5, a concurrent write
// extends the file to 8, admission holds the upcall past the marker's TTL, and
// the upcall then arrives. The file must still be 8 bytes.
func TestInternalRefreshCannotBecomeAnApplicationTruncate(t *testing.T) {
	// Compress the sweeper bound so the admission delay under test can outlast
	// it in milliseconds instead of seconds. Provenance must not depend on it.
	restore := truncateNoteTTL
	truncateNoteTTL = 10 * time.Millisecond
	t.Cleanup(func() { truncateNoteTTL = restore })

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
	attr, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("getattr f st=%d err=%v", st, err)
	}
	const sampledSize = int64(5)
	if attr.Size != sampledSize {
		t.Fatalf("seeded size = %d, want %d", attr.Size, sampledSize)
	}

	a := newAttach("att_internal_refresh", "key", ensureAttachRequest{
		VolumeID: "vol-internal-refresh", Branch: "main",
		MountPath: "/Volumes/InternalRefresh",
	}, privateTestDir(t))
	a.vol = vol
	a.restoreItemsLocked([]persistedItemRecord{{
		Path: "f", ItemID: attr.Ino, ItemGeneration: 1,
		AuthorityIno: true, Kind: "file",
	}})
	rec := a.itemByPath("f")
	if rec == nil {
		t.Fatal("item f was not registered")
	}

	var (
		upcallReply *pfslocal.SetAttrReply
		upcallEno   int32
	)
	a.testRefreshKernelFile = func(_ string, p string, _ uint64, size int64) (kernelRefreshOutcome, error) {
		// Inside the daemon's own ftruncate(2). Everything below models what the
		// kernel and the dispatcher do while that syscall is outstanding.
		if p != "f" || size != sampledSize {
			t.Errorf("refresh addressed path=%q size=%d, want f/%d", p, size, sampledSize)
		}
		// A concurrent writer extends the file past the sampled size. This is the
		// data the reinterpretation destroyed.
		if _, st, err := cli.Write("f", sampledSize, []byte("+++"), 0o644); err != nil || st != fsproto.OK {
			t.Errorf("concurrent extending write st=%d err=%v", st, err)
		}
		// The dispatcher's metadata admission parks the upcall past the marker's
		// TTL. Nothing about that delay changes who issued the request.
		time.Sleep(3 * truncateNoteTTL)
		sz := uint64(sampledSize)
		upcallReply, upcallEno = a.setattr(context.Background(), &pfslocal.SetAttrRequest{
			Item: rec.item,
			Size: &sz,
		})
		return kernelRefreshApplied, nil
	}

	if outcome, err := a.applyKernelRefresh("", "f", rec, sampledSize); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("apply kernel refresh = (%v, %v)", outcome, err)
	}
	if upcallEno != 0 || upcallReply == nil {
		t.Fatalf("the daemon's own refresh upcall failed: eno=%d reply=%v", upcallEno, upcallReply)
	}

	after, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify getattr st=%d err=%v", st, err)
	}
	if after.Size != sampledSize+3 {
		t.Fatalf("the authority's file is %d bytes, want %d: an internal coherence "+
			"refresh was reinterpreted as an application truncate after its marker "+
			"aged out under admission, destroying the %d bytes a concurrent writer "+
			"had committed past the sampled size",
			after.Size, sampledSize+3, 3)
	}
	data, st, err := cli.Read("f", 0, 64)
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify read st=%d err=%v", st, err)
	}
	if string(data) != "hello+++" {
		t.Fatalf("file content = %q, want %q", string(data), "hello+++")
	}
}

// TestInternalRefreshBypassesMutationAdmission pins the other half of the fix:
// a daemon-originated refresh is coherence bookkeeping, not an application
// mutation, so it never enters the pre-lock mutation classifier at all. Pacing
// it would throttle an operation that neither caused the metadata backlog nor
// can help drain it — and the park is what let its meaning change underneath it.
func TestInternalRefreshBypassesMutationAdmission(t *testing.T) {
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
	attr, st, err := cli.Getattr("f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("getattr f st=%d err=%v", st, err)
	}

	a := newAttach("att_refresh_admission", "key", ensureAttachRequest{
		VolumeID: "vol-refresh-admission", Branch: "main",
		MountPath: "/Volumes/RefreshAdmission",
	}, privateTestDir(t))
	a.vol = vol
	a.restoreItemsLocked([]persistedItemRecord{{
		Path: "f", ItemID: attr.Ino, ItemGeneration: 1,
		AuthorityIno: true, Kind: "file",
	}})
	rec := a.itemByPath("f")
	if rec == nil {
		t.Fatal("item f was not registered")
	}

	size := func(v uint64) *uint64 { return &v }
	refresh := &pfslocal.SetAttrRequest{Item: rec.item, Size: size(5)}
	application := &pfslocal.SetAttrRequest{Item: rec.item, Size: size(2)}

	// With no marker pinned, BOTH requests are application mutations.
	if _, settle, eno, classified := a.admitMutation(context.Background(), refresh, false); !classified || eno != 0 {
		settle()
		t.Fatalf("without a pinned marker a size setattr was not classified "+
			"(classified=%v eno=%d)", classified, eno)
	} else {
		settle()
	}

	a.testRefreshKernelFile = func(string, string, uint64, int64) (kernelRefreshOutcome, error) {
		// Inside the daemon's own syscall: the marker is pinned.
		if !a.internalRefreshPending(refresh) {
			t.Error("a pinned refresh marker did not answer the provenance test")
		}
		_, settle, eno, classified := a.admitMutation(context.Background(), refresh, false)
		settle()
		if classified || eno != 0 {
			t.Errorf("the daemon's own refresh entered mutation admission "+
				"(classified=%v eno=%d); it publishes already-applied state and "+
				"must never be paced against the metadata lane",
				classified, eno)
		}
		// A real application truncate to a DIFFERENT size is not this refresh and
		// must still be classified.
		_, settle, eno, classified = a.admitMutation(context.Background(), application, false)
		settle()
		if !classified {
			t.Errorf("an application truncate was mistaken for the daemon's own "+
				"refresh (eno=%d)", eno)
		}
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", "f", rec, 5); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("apply kernel refresh = (%v, %v)", outcome, err)
	}

	// The syscall has returned: the pin is gone and the marker with it.
	if a.internalRefreshPending(refresh) {
		t.Fatal("a refresh marker outlived the syscall that installed it")
	}
}

// TestExpectedTruncateMarkerIsRetiredBySequence proves the marker's identity is
// the installing refresh's own sequence number, so one pass never retires a
// successor another pass installed for the same path.
func TestExpectedTruncateMarkerIsRetiredBySequence(t *testing.T) {
	a := &attach{expectedTruncates: map[string]expectedTruncate{}}
	a.expectedTruncateSeq = 7
	first := expectedTruncate{itemID: 3, size: 11, pinned: true, seq: 7}
	a.expectedTruncates["f"] = first

	// A successor for the same path replaces it.
	a.expectedTruncateSeq = 8
	second := expectedTruncate{itemID: 3, size: 12, pinned: true, seq: 8}
	a.expectedTruncates["f"] = second

	// The first pass's retire must not remove the second pass's marker.
	a.retireExpectedTruncate("f", first.seq)
	if got, ok := a.expectedTruncates["f"]; !ok || got.seq != second.seq {
		t.Fatalf("marker after stale retire = (%v, %v), want the seq-8 successor", got, ok)
	}
	a.retireExpectedTruncate("f", second.seq)
	if _, ok := a.expectedTruncates["f"]; ok {
		t.Fatal("the installing pass failed to retire its own marker")
	}
}
